use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const AUDIENCE: &str = "kalvium.safeagent";
pub const CAPABILITIES: [&str; 3] = ["processes", "displays", "overlays"];
const MAX_TTL_MS: u64 = 900_000;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Payload {
    pub v: u32,
    pub audience: String,
    pub session_id: String,
    pub agent_instance_id: String,
    pub challenge: String,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub const PREFLIGHT_PURPOSE: &str = "assessment-preflight";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreflightPayload {
    pub v: u32,
    pub purpose: String,
    pub audience: String,
    pub preflight_id: String,
    pub assessment_slug: String,
    pub agent_instance_id: String,
    pub challenge: String,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug)]
pub struct PreflightGrant {
    pub payload: PreflightPayload,
    deadline: Instant,
}

impl PreflightGrant {
    pub fn current(&self, wall: u64, now: Instant) -> bool {
        wall >= self.payload.issued_at && wall < self.payload.expires_at && now < self.deadline
    }
}

type Keys = BTreeMap<String, VerifyingKey>;

fn parse_keys(config: &str) -> Result<Keys, &'static str> {
    let mut keys = Keys::new();
    for entry in config.split(',') {
        let (id, encoded) = entry.split_once(':').ok_or("AUTH_CONFIG_INVALID")?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("AUTH_CONFIG_INVALID");
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "AUTH_CONFIG_INVALID")?
            .try_into()
            .map_err(|_| "AUTH_CONFIG_INVALID")?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "AUTH_CONFIG_INVALID")?;
        if key.is_weak() || keys.insert(id.to_owned(), key).is_some() {
            return Err("AUTH_CONFIG_INVALID");
        }
    }
    Ok(keys)
}

pub fn validate_key_config(config: &str) -> Result<(), &'static str> {
    parse_keys(config).map(|_| ())
}

pub struct AuthContext {
    pub instance_id: String,
    pub challenge: String,
    keys: Result<Keys, &'static str>,
    challenge_deadline: Instant,
    consumed: bool,
    grant: Option<(Payload, Instant)>,
}

impl AuthContext {
    pub fn new() -> Result<Self, &'static str> {
        Self::with_config(option_env!("SAFEAGENT_AUTH_PUBLIC_KEYS").unwrap_or(""))
    }

    fn with_config(config: &str) -> Result<Self, &'static str> {
        let mut random = [0u8; 48];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| "RANDOM_UNAVAILABLE")?;
        Ok(Self {
            instance_id: URL_SAFE_NO_PAD.encode(&random[..16]),
            challenge: URL_SAFE_NO_PAD.encode(&random[16..]),
            keys: parse_keys(config),
            challenge_deadline: Instant::now() + CHALLENGE_TTL,
            consumed: false,
            grant: None,
        })
    }

    pub fn readiness(&self) -> &'static str {
        match &self.keys {
            Ok(_) => "ready",
            Err(code) => code,
        }
    }

    pub fn authorize(
        &mut self,
        auth: &Authorization,
        wall: u64,
        now: Instant,
    ) -> Result<(), &'static str> {
        if self.consumed {
            return Err("CHALLENGE_REUSED");
        }
        if now >= self.challenge_deadline {
            return Err("CHALLENGE_EXPIRED");
        }
        let bytes = self.verify(auth)?;
        let payload: Payload =
            serde_json::from_slice(&bytes).map_err(|_| "INVALID_AUTHORIZATION")?;
        self.accept_monitoring(payload, wall, now)
    }

    fn verify(&self, auth: &Authorization) -> Result<Vec<u8>, &'static str> {
        let keys = self.keys.as_ref().map_err(|code| *code)?;
        let key = keys.get(&auth.key_id).ok_or("INVALID_SIGNATURE")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&auth.payload)
            .map_err(|_| "INVALID_SIGNATURE")?;
        let signature = URL_SAFE_NO_PAD
            .decode(&auth.signature)
            .map_err(|_| "INVALID_SIGNATURE")?;
        let signature = Signature::from_slice(&signature).map_err(|_| "INVALID_SIGNATURE")?;
        key.verify_strict(&bytes, &signature)
            .map_err(|_| "INVALID_SIGNATURE")?;
        Ok(bytes)
    }

    fn accept_monitoring(
        &mut self,
        payload: Payload,
        wall: u64,
        now: Instant,
    ) -> Result<(), &'static str> {
        if payload.v != 2
            || payload.audience != AUDIENCE
            || !crate::valid_request_id(&payload.session_id)
        {
            return Err("INVALID_AUTHORIZATION");
        }
        if payload.agent_instance_id != self.instance_id || payload.challenge != self.challenge {
            return Err("CHALLENGE_MISMATCH");
        }
        if payload.capabilities.len() != CAPABILITIES.len()
            || !CAPABILITIES.iter().all(|c| {
                payload
                    .capabilities
                    .iter()
                    .filter(|p| p.as_str() == *c)
                    .count()
                    == 1
            })
        {
            return Err("UNSUPPORTED_CAPABILITY");
        }
        if payload.issued_at > wall
            || payload.expires_at <= wall
            || payload.expires_at <= payload.issued_at
            || payload.expires_at - payload.issued_at > MAX_TTL_MS
        {
            return Err("AUTH_EXPIRED");
        }
        let deadline = now + Duration::from_millis(payload.expires_at - wall);
        self.grant = Some((payload, deadline));
        self.consumed = true;
        Ok(())
    }

    pub fn preflight(
        &mut self,
        auth: &Authorization,
        wall: u64,
        now: Instant,
    ) -> Result<PreflightGrant, &'static str> {
        if self.consumed {
            return Err("CHALLENGE_REUSED");
        }
        if now >= self.challenge_deadline {
            return Err("CHALLENGE_EXPIRED");
        }
        let bytes = self.verify(auth)?;
        let payload: PreflightPayload =
            serde_json::from_slice(&bytes).map_err(|_| "INVALID_AUTHORIZATION")?;
        if payload.v != 3
            || payload.purpose != PREFLIGHT_PURPOSE
            || payload.audience != AUDIENCE
            || !crate::valid_request_id(&payload.preflight_id)
            || payload.assessment_slug.trim().is_empty()
            || payload.assessment_slug.len() > 200
        {
            return Err("INVALID_AUTHORIZATION");
        }
        // Exact comparison to generated canonical base64url also rejects alternate encodings.
        if payload.agent_instance_id != self.instance_id || payload.challenge != self.challenge {
            return Err("CHALLENGE_MISMATCH");
        }
        if payload.capabilities.len() != CAPABILITIES.len()
            || !CAPABILITIES.iter().all(|c| {
                payload
                    .capabilities
                    .iter()
                    .filter(|p| p.as_str() == *c)
                    .count()
                    == 1
            })
        {
            return Err("UNSUPPORTED_CAPABILITY");
        }
        if payload.issued_at > wall
            || payload.expires_at <= wall
            || payload.expires_at <= payload.issued_at
            || payload.expires_at - payload.issued_at > 60_000
        {
            return Err("AUTH_EXPIRED");
        }
        let deadline = now + Duration::from_millis(payload.expires_at - wall);
        // Never store this grant: a failed probe must not enable another snapshot.
        self.consumed = true;
        Ok(PreflightGrant { payload, deadline })
    }

    pub fn authorized(&self, wall: u64, now: Instant) -> Option<&Payload> {
        self.grant
            .as_ref()
            .filter(|(p, deadline)| wall >= p.issued_at && wall < p.expires_at && now < *deadline)
            .map(|(p, _)| p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};

    fn fixture() -> (AuthContext, SigningKey, Value) {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).unwrap();
        let key = SigningKey::from_bytes(&seed);
        let ctx = AuthContext::with_config(&format!(
            "test:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        ))
        .unwrap();
        let payload = json!({"v":2,"audience":AUDIENCE,"sessionId":"12345678-1234-4234-8234-123456789abc",
            "agentInstanceId":ctx.instance_id,"challenge":ctx.challenge,"capabilities":CAPABILITIES,
            "issuedAt":1000,"expiresAt":901000});
        (ctx, key, payload)
    }

    fn sign(key: &SigningKey, bytes: &[u8]) -> Authorization {
        Authorization {
            key_id: "test".into(),
            payload: URL_SAFE_NO_PAD.encode(bytes),
            signature: URL_SAFE_NO_PAD.encode(key.sign(bytes).to_bytes()),
        }
    }

    fn preflight_fixture() -> (AuthContext, SigningKey, Value) {
        let (ctx, key, mut payload) = fixture();
        payload.as_object_mut().unwrap().remove("sessionId");
        payload["v"] = json!(3);
        payload["purpose"] = json!(PREFLIGHT_PURPOSE);
        payload["preflightId"] = json!("12345678-1234-4234-8234-123456789abc");
        payload["assessmentSlug"] = json!("assessment");
        payload["expiresAt"] = json!(61000);
        (ctx, key, payload)
    }

    fn preflight_request(key: &SigningKey, payload: &Value) -> Value {
        json!({"protocolVersion":2,"requestId":"12345678-1234-4234-8234-123456789abc",
            "challenge":"correlation-only","command":"preflight",
            "authorization":sign(key, &serde_json::to_vec_pretty(payload).unwrap())})
    }

    #[test]
    fn preflight_is_one_shot_even_on_probe_failure_and_never_authorizes_monitoring() {
        for failed in [false, true] {
            let (ctx, key, payload) = preflight_fixture();
            let now = Instant::now();
            let mut connection = crate::Connection { auth: Ok(ctx) };
            let mut request = preflight_request(&key, &payload);
            let reply = connection.handle_with_clock(
                &serde_json::to_vec(&request).unwrap(),
                || {
                    let mut caps = crate::probes::capabilities();
                    if failed {
                        caps.displays.status = crate::probes::Status::Error;
                    }
                    (caps, crate::probes::group_applications(["Discord.exe"]))
                },
                || (1000, now),
            );
            assert_eq!(reply.ok, !failed);
            if failed {
                assert_eq!(reply.error.as_ref().unwrap().code, "PROBE_FAILED");
            }
            assert_eq!(reply.purpose, Some(PREFLIGHT_PURPOSE));
            assert_eq!(
                reply.preflight_id.as_deref(),
                payload["preflightId"].as_str()
            );
            assert_eq!(reply.assessment_slug.as_deref(), Some("assessment"));
            assert!(reply.session_id.is_none());
            assert_eq!(reply.auth_state.as_deref(), Some("unauthorized"));
            for command in ["preflight", "authorize", "check"] {
                request["command"] = json!(command);
                if command == "check" {
                    request.as_object_mut().unwrap().remove("authorization");
                }
                let reply = connection.handle_with_clock(
                    &serde_json::to_vec(&request).unwrap(),
                    || panic!("reused preflight scanned"),
                    || (1000, now),
                );
                assert_eq!(
                    reply.error.unwrap().code,
                    if command == "check" {
                        "UNAUTHORIZED"
                    } else {
                        "CHALLENGE_REUSED"
                    }
                );
            }
        }
    }

    #[test]
    fn preflight_rejects_malformed_scope_binding_time_and_missing_config() {
        for (field, value, code) in [
            ("v", json!(2), "INVALID_AUTHORIZATION"),
            ("purpose", json!("monitoring"), "INVALID_AUTHORIZATION"),
            ("audience", json!("other"), "INVALID_AUTHORIZATION"),
            (
                "preflightId",
                json!("12345678-1234-4234-8234-123456789ABC"),
                "INVALID_AUTHORIZATION",
            ),
            ("assessmentSlug", json!(" "), "INVALID_AUTHORIZATION"),
            (
                "assessmentSlug",
                json!("x".repeat(201)),
                "INVALID_AUTHORIZATION",
            ),
            ("sub", json!("student"), "INVALID_AUTHORIZATION"),
            (
                "sessionId",
                json!("12345678-1234-4234-8234-123456789abc"),
                "INVALID_AUTHORIZATION",
            ),
            ("agentInstanceId", json!("other"), "CHALLENGE_MISMATCH"),
            ("challenge", json!("other"), "CHALLENGE_MISMATCH"),
            (
                "capabilities",
                json!(["processes", "processes", "overlays"]),
                "UNSUPPORTED_CAPABILITY",
            ),
            ("issuedAt", json!(1001), "AUTH_EXPIRED"),
            ("expiresAt", json!(1000), "AUTH_EXPIRED"),
            ("expiresAt", json!(61001), "AUTH_EXPIRED"),
        ] {
            let (mut ctx, key, mut payload) = preflight_fixture();
            payload[field] = value;
            assert_eq!(
                ctx.preflight(
                    &sign(&key, &serde_json::to_vec(&payload).unwrap()),
                    1000,
                    Instant::now()
                )
                .unwrap_err(),
                code,
                "{field}"
            );
            assert!(!ctx.consumed);
        }
        let (mut ctx, key, payload) = preflight_fixture();
        let auth = sign(&key, &serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            ctx.preflight(&auth, 1000, ctx.challenge_deadline)
                .unwrap_err(),
            "CHALLENGE_EXPIRED"
        );
        ctx.keys = parse_keys("");
        assert_eq!(
            ctx.preflight(&auth, 1000, Instant::now()).unwrap_err(),
            "AUTH_CONFIG_INVALID"
        );
    }

    #[test]
    fn preflight_cross_purpose_and_connection_isolation() {
        let (mut ctx, key, payload) = preflight_fixture();
        let auth = sign(&key, &serde_json::to_vec(&payload).unwrap());
        let now = Instant::now();
        assert_eq!(
            ctx.authorize(&auth, 1000, now),
            Err("INVALID_AUTHORIZATION")
        );
        let (mut other, _, _) = preflight_fixture();
        other.keys = ctx.keys.clone();
        assert_eq!(
            other.preflight(&auth, 1000, now).unwrap_err(),
            "CHALLENGE_MISMATCH"
        );
        let (_, _, mut monitoring) = fixture();
        monitoring["agentInstanceId"] = json!(ctx.instance_id);
        monitoring["challenge"] = json!(ctx.challenge);
        let monitoring = sign(&key, &serde_json::to_vec(&monitoring).unwrap());
        assert_eq!(
            ctx.preflight(&monitoring, 1000, now).unwrap_err(),
            "INVALID_AUTHORIZATION"
        );
        ctx.authorize(&monitoring, 1000, now).unwrap();
        assert_eq!(
            ctx.preflight(&auth, 1000, now).unwrap_err(),
            "CHALLENGE_REUSED"
        );
        assert!(ctx.authorized(1000, now).is_some());
    }

    #[test]
    fn preflight_expiry_during_probe_discards_and_consumes() {
        for expired in [0, 1, 2] {
            let (ctx, key, payload) = preflight_fixture();
            let now = Instant::now();
            let mut connection = crate::Connection { auth: Ok(ctx) };
            let bytes = serde_json::to_vec(&preflight_request(&key, &payload)).unwrap();
            let end = match expired {
                0 => (61000, now),
                1 => (1000, now + Duration::from_secs(60)),
                _ => (999, now),
            };
            let mut times = [(1000, now), end].into_iter();
            let reply = connection.handle_with_clock(
                &bytes,
                || {
                    (
                        crate::probes::capabilities(),
                        crate::probes::group_applications(["Discord.exe"]),
                    )
                },
                || times.next().unwrap(),
            );
            assert_eq!(reply.error.unwrap().code, "AUTH_EXPIRED");
            assert!(reply.findings.is_empty());
            assert!(reply.preflight_id.is_some());
            assert!(reply.expires_at.is_none());
            assert_eq!(
                connection
                    .handle_with_clock(
                        &bytes,
                        || panic!("expired preflight rescanned"),
                        || (1000, now)
                    )
                    .error
                    .unwrap()
                    .code,
                "CHALLENGE_REUSED"
            );
        }
    }

    #[test]
    fn valid_signature_consumes_challenge_not_grant_and_replay_fails() {
        let (mut ctx, key, payload) = fixture();
        let auth = sign(&key, &serde_json::to_vec_pretty(&payload).unwrap());
        let now = Instant::now();
        ctx.authorize(&auth, 1000, now).unwrap();
        assert!(ctx.authorized(1001, now).is_some());
        assert_eq!(ctx.authorize(&auth, 1001, now), Err("CHALLENGE_REUSED"));
        assert!(ctx.authorized(1001, now).is_some());
        let (mut other, _, _) = fixture();
        other.keys = ctx.keys.clone();
        assert_eq!(other.authorize(&auth, 1001, now), Err("CHALLENGE_MISMATCH"));
    }

    #[test]
    fn signed_invalid_bindings_structure_scope_and_times_are_rejected() {
        for (field, value, code) in [
            ("v", json!(1), "INVALID_AUTHORIZATION"),
            ("audience", json!("other"), "INVALID_AUTHORIZATION"),
            ("sessionId", json!(""), "INVALID_AUTHORIZATION"),
            ("sessionId", json!("not-a-session"), "INVALID_AUTHORIZATION"),
            ("agentInstanceId", json!("other"), "CHALLENGE_MISMATCH"),
            ("challenge", json!("other"), "CHALLENGE_MISMATCH"),
            (
                "capabilities",
                json!(["processes"]),
                "UNSUPPORTED_CAPABILITY",
            ),
            (
                "capabilities",
                json!(["processes", "processes", "overlays"]),
                "UNSUPPORTED_CAPABILITY",
            ),
            (
                "capabilities",
                json!(["processes", "displays", "overlays", "unknown"]),
                "UNSUPPORTED_CAPABILITY",
            ),
            ("issuedAt", json!(1001), "AUTH_EXPIRED"),
            ("expiresAt", json!(1000), "AUTH_EXPIRED"),
            ("expiresAt", json!(901001), "AUTH_EXPIRED"),
            ("expiresAt", json!(u64::MAX), "AUTH_EXPIRED"),
            ("extra", json!(true), "INVALID_AUTHORIZATION"),
        ] {
            let (mut ctx, key, mut payload) = fixture();
            payload[field] = value;
            let auth = sign(&key, &serde_json::to_vec(&payload).unwrap());
            assert_eq!(
                ctx.authorize(&auth, 1000, Instant::now()),
                Err(code),
                "{field}"
            );
            assert!(ctx.grant.is_none());
        }
        let (mut ctx, key, payload) = fixture();
        let bytes = serde_json::to_string(&payload)
            .unwrap()
            .replacen('{', "{\"v\":2,", 1);
        assert_eq!(
            ctx.authorize(&sign(&key, bytes.as_bytes()), 1000, Instant::now()),
            Err("INVALID_AUTHORIZATION")
        );
    }

    #[test]
    fn exact_bytes_detached_signature_and_key_id_are_verified() {
        let (mut ctx, key, payload) = fixture();
        let bytes = serde_json::to_vec(&payload).unwrap();
        for variant in 0..5 {
            let mut auth = sign(&key, &bytes);
            match variant {
                0 => {
                    auth.payload =
                        URL_SAFE_NO_PAD.encode(serde_json::to_vec_pretty(&payload).unwrap())
                }
                1 => auth.signature = auth.payload.clone(),
                2 => auth.key_id = "unknown".into(),
                3 => {
                    let (_, other_key, _) = fixture();
                    auth = sign(&other_key, &bytes);
                }
                _ => auth.payload = "!invalid".into(),
            }
            assert_eq!(
                ctx.authorize(&auth, 1000, Instant::now()),
                Err("INVALID_SIGNATURE")
            );
        }
    }

    #[test]
    fn missing_malformed_duplicate_and_weak_key_config_fail_closed() {
        let (ctx, key, payload) = fixture();
        let good = format!(
            "test:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        );
        for config in [
            "".to_owned(),
            "bad".into(),
            "test:bad".into(),
            format!("{good},broken"),
            format!("{good},{good}"),
            format!("weak:{}", URL_SAFE_NO_PAD.encode([0u8; 32])),
        ] {
            assert!(parse_keys(&config).is_err());
        }
        let mut missing = ctx;
        missing.keys = parse_keys("");
        assert_eq!(
            missing.authorize(
                &sign(&key, &serde_json::to_vec(&payload).unwrap()),
                1000,
                Instant::now()
            ),
            Err("AUTH_CONFIG_INVALID")
        );
    }

    #[test]
    fn wall_and_monotonic_expiry_and_short_challenge_lifetime() {
        let (mut ctx, key, payload) = fixture();
        let auth = sign(&key, &serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            ctx.authorize(&auth, 1000, ctx.challenge_deadline),
            Err("CHALLENGE_EXPIRED")
        );
        let now = Instant::now();
        ctx.authorize(&auth, 2000, now).unwrap();
        assert!(ctx.authorized(2001, now).is_some());
        assert!(ctx.authorized(901000, now).is_none());
        assert!(ctx.authorized(999, now).is_none());
        assert!(ctx
            .authorized(2000, now + Duration::from_millis(899000))
            .is_none());
    }

    #[test]
    fn hello_reports_only_non_sensitive_config_readiness() {
        for config in ["", "malformed"] {
            let mut connection = crate::Connection {
                auth: Ok(AuthContext::with_config(config).unwrap()),
            };
            let request = serde_json::to_vec(&json!({"protocolVersion":2,
                "requestId":"12345678-1234-4234-8234-123456789abc",
                "challenge":"correlation-only","command":"hello"}))
            .unwrap();
            let reply = connection.handle_with_probe(&request, || panic!("hello scanned"));
            assert!(reply.ok);
            assert_eq!(reply.auth_readiness, Some("AUTH_CONFIG_INVALID"));
            assert!(reply.findings.is_empty());
            assert_eq!(reply.auth_state.as_deref(), Some("unauthorized"));
        }
        assert_eq!(fixture().0.readiness(), "ready");
    }

    #[test]
    fn expiry_during_probe_discards_findings_and_expired_grants_never_scan() {
        for monotonic in [false, true] {
            let (mut ctx, key, payload) = fixture();
            let now = Instant::now();
            ctx.authorize(
                &sign(&key, &serde_json::to_vec(&payload).unwrap()),
                1000,
                now,
            )
            .unwrap();
            let mut connection = crate::Connection { auth: Ok(ctx) };
            let request = serde_json::to_vec(&json!({"protocolVersion":2,
                "requestId":"12345678-1234-4234-8234-123456789abc",
                "challenge":"correlation-only","command":"check"}))
            .unwrap();
            let expired = if monotonic {
                (1001, now + Duration::from_millis(900000))
            } else {
                (901000, now)
            };
            let mut times = [(1000, now), expired].into_iter();
            let reply = connection.handle_with_clock(
                &request,
                || {
                    let findings = crate::probes::group_applications(["Discord.exe"]);
                    assert!(!findings.is_empty());
                    (crate::probes::capabilities(), findings)
                },
                || times.next().unwrap(),
            );
            assert_eq!(reply.error.unwrap().code, "AUTH_EXPIRED");
            assert!(reply.findings.is_empty());
            assert_eq!(reply.auth_state.as_deref(), Some("unauthorized"));
            assert!(reply.session_id.is_none());
            assert!(reply.expires_at.is_none());
            let reply = connection.handle_with_clock(
                &request,
                || panic!("expired grant scanned"),
                || expired,
            );
            assert_eq!(reply.error.unwrap().code, "UNAUTHORIZED");
        }
    }

    #[test]
    fn expiry_at_check_response_assembly_discards_observations() {
        for monotonic in [false, true] {
            let (mut ctx, key, payload) = fixture();
            let now = Instant::now();
            ctx.authorize(
                &sign(&key, &serde_json::to_vec(&payload).unwrap()),
                1000,
                now,
            )
            .unwrap();
            let mut connection = crate::Connection { auth: Ok(ctx) };
            let request = serde_json::to_vec(&json!({"protocolVersion":2,
                "requestId":"12345678-1234-4234-8234-123456789abc",
                "challenge":"correlation-only","command":"check"}))
            .unwrap();
            let expired = if monotonic {
                (1001, now + Duration::from_millis(900000))
            } else {
                (901000, now)
            };
            let mut times = [(1000, now), (1001, now), expired].into_iter();
            let reply = connection.handle_with_clock(
                &request,
                || {
                    let mut capabilities = crate::probes::capabilities();
                    capabilities.processes.status = crate::probes::Status::Available;
                    capabilities.displays.status = crate::probes::Status::Available;
                    capabilities.overlays.status = crate::probes::Status::Available;
                    let findings = crate::probes::group_applications(["Discord.exe"]);
                    assert!(!findings.is_empty());
                    (capabilities, findings)
                },
                || times.next().unwrap(),
            );
            assert!(times.next().is_none());
            assert!(!reply.ok);
            assert_eq!(reply.error.as_ref().unwrap().code, "AUTH_EXPIRED");
            assert!(reply.findings.is_empty());
            assert_eq!(
                serde_json::to_value(&reply.capabilities).unwrap(),
                serde_json::to_value(crate::probes::capabilities()).unwrap()
            );
            assert_eq!(reply.auth_state.as_deref(), Some("unauthorized"));
            assert_eq!(reply.authorized_capabilities, Some(vec![]));
            assert!(reply.session_id.is_none());
            assert!(reply.expires_at.is_none());
        }
    }

    #[test]
    fn authorized_connections_are_isolated_and_reconnect_requires_fresh_grant() {
        let (mut ctx, key, payload) = fixture();
        let config = format!(
            "test:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        );
        let now = Instant::now();
        let auth = sign(&key, &serde_json::to_vec(&payload).unwrap());
        ctx.authorize(&auth, 1000, now).unwrap();
        let mut first = crate::Connection { auth: Ok(ctx) };
        let request = serde_json::to_vec(&json!({"protocolVersion":2,
            "requestId":"12345678-1234-4234-8234-123456789abc",
            "challenge":"correlation-only","command":"check"}))
        .unwrap();
        for _ in 0..2 {
            let mut other = crate::Connection {
                auth: Ok(AuthContext::with_config(&config).unwrap()),
            };
            assert_eq!(
                other
                    .handle_with_clock(
                        &request,
                        || panic!("isolated connection scanned"),
                        || (1000, now)
                    )
                    .error
                    .unwrap()
                    .code,
                "UNAUTHORIZED"
            );
            assert_eq!(
                other.auth.as_mut().unwrap().authorize(&auth, 1000, now),
                Err("CHALLENGE_MISMATCH")
            );
            assert!(
                first
                    .handle_with_clock(
                        &request,
                        || (crate::probes::capabilities(), vec![]),
                        || (1000, now)
                    )
                    .ok
            );
        }
        drop(first);
        let mut reconnected = AuthContext::with_config(&config).unwrap();
        assert_eq!(
            reconnected.authorize(&auth, 1000, now),
            Err("CHALLENGE_MISMATCH")
        );
        let mut fresh = payload;
        fresh["agentInstanceId"] = json!(reconnected.instance_id);
        fresh["challenge"] = json!(reconnected.challenge);
        reconnected
            .authorize(&sign(&key, &serde_json::to_vec(&fresh).unwrap()), 1000, now)
            .unwrap();
        assert!(reconnected.authorized(1000, now).is_some());
    }

    #[test]
    fn hello_does_not_refresh_challenge_or_grant_and_preflight_v3_is_rejected() {
        let (ctx, key, mut payload) = fixture();
        let deadline = ctx.challenge_deadline;
        let mut connection = crate::Connection { auth: Ok(ctx) };
        let request = serde_json::to_vec(&json!({"protocolVersion":2,
            "requestId":"12345678-1234-4234-8234-123456789abc",
            "challenge":"correlation-only","command":"hello"}))
        .unwrap();
        let now = Instant::now();
        for _ in 0..2 {
            let reply =
                connection.handle_with_clock(&request, || panic!("hello scanned"), || (1000, now));
            assert_eq!(
                reply.agent_instance_id.as_deref(),
                payload["agentInstanceId"].as_str()
            );
            assert_eq!(
                reply.auth_challenge.as_deref(),
                payload["challenge"].as_str()
            );
            assert_eq!(
                connection.auth.as_ref().unwrap().challenge_deadline,
                deadline
            );
        }
        payload["v"] = json!(3);
        payload.as_object_mut().unwrap().remove("sessionId");
        payload["purpose"] = json!("assessment-preflight");
        payload["preflightId"] = json!("12345678-1234-4234-8234-123456789abc");
        payload["assessmentSlug"] = json!("test-assessment");
        payload["sub"] = json!("test-student");
        let ctx = connection.auth.as_mut().unwrap();
        assert_eq!(
            ctx.authorize(
                &sign(&key, &serde_json::to_vec(&payload).unwrap()),
                1000,
                now
            ),
            Err("INVALID_AUTHORIZATION")
        );
        assert!(ctx.grant.is_none());
        assert!(!ctx.consumed);
        let (_, _, mut valid) = fixture();
        valid["agentInstanceId"] = json!(ctx.instance_id);
        valid["challenge"] = json!(ctx.challenge);
        ctx.authorize(&sign(&key, &serde_json::to_vec(&valid).unwrap()), 1000, now)
            .unwrap();
        let grant_deadline = ctx.grant.as_ref().unwrap().1;
        let reply = connection.handle_with_clock(
            &request,
            || panic!("authorized hello scanned"),
            || (1001, now),
        );
        assert_eq!(reply.auth_state.as_deref(), Some("authorized"));
        assert!(reply.findings.is_empty());
        let ctx = connection.auth.as_ref().unwrap();
        assert!(ctx.consumed);
        assert_eq!(ctx.grant.as_ref().unwrap().1, grant_deadline);
        assert!(ctx.authorized(901000, now).is_none());
    }

    #[test]
    fn connection_gate_calls_no_probe_before_auth_and_allows_valid_grant() {
        let (ctx, key, mut payload) = fixture();
        payload["issuedAt"] = json!(crate::timestamp());
        payload["expiresAt"] = json!(crate::timestamp() + 60000);
        let mut connection = crate::Connection { auth: Ok(ctx) };
        let mut request = json!({"protocolVersion":2,"requestId":"12345678-1234-4234-8234-123456789abc","challenge":"correlation-only","command":"check"});
        let reply = connection.handle_with_probe(&serde_json::to_vec(&request).unwrap(), || {
            panic!("unauthorized probe")
        });
        assert_eq!(reply.error.unwrap().code, "UNAUTHORIZED");
        request["command"] = json!("authorize");
        request["authorization"] =
            serde_json::to_value(sign(&key, &serde_json::to_vec(&payload).unwrap())).unwrap();
        assert!(
            connection
                .handle_request(&serde_json::to_vec(&request).unwrap())
                .ok
        );
        request["command"] = json!("check");
        request.as_object_mut().unwrap().remove("authorization");
        let reply = connection.handle_with_probe(&serde_json::to_vec(&request).unwrap(), || {
            (crate::probes::capabilities(), vec![])
        });
        assert!(reply.ok);
        assert_eq!(reply.auth_state.as_deref(), Some("authorized"));
        assert_eq!(reply.session_id.as_deref(), payload["sessionId"].as_str());
        assert!(!crate::check().ok);
    }
}

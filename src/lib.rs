pub mod auth;
pub mod overlays;
pub mod probes;

use auth::{AuthContext, Authorization};
use probes::{Capabilities, Finding, Status};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    request_id: String,
    command: String,
    challenge: String,
    #[serde(default)]
    authorization: Option<Authorization>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolError {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightSupport {
    pub contract_version: u32,
    pub grant_version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    pub protocol_version: u32,
    pub request_id: Option<String>,
    pub challenge: Option<String>,
    pub agent_instance_id: Option<String>,
    pub auth_challenge: Option<String>,
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_support: Option<PreflightSupport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment_slug: Option<String>,
    pub ok: bool,
    pub agent_version: &'static str,
    pub auth_state: Option<String>,
    pub auth_readiness: Option<&'static str>,
    pub authorized_capabilities: Option<Vec<String>>,
    pub expires_at: Option<u64>,
    pub capabilities: Capabilities,
    pub findings: Vec<Finding>,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn base_reply() -> Reply {
    Reply {
        protocol_version: 2,
        request_id: None,
        challenge: None,
        agent_instance_id: None,
        auth_challenge: None,
        session_id: None,
        preflight_support: None,
        purpose: None,
        preflight_id: None,
        assessment_slug: None,
        ok: true,
        agent_version: VERSION,
        auth_state: Some("unauthorized".to_owned()),
        auth_readiness: None,
        authorized_capabilities: Some(Vec::new()),
        expires_at: None,
        capabilities: probes::capabilities(),
        findings: Vec::new(),
        observed_at: timestamp(),
        error: None,
    }
}

fn fail(mut reply: Reply, code: &'static str, message: &'static str) -> Reply {
    reply.ok = false;
    reply.error = Some(ProtocolError { code, message });
    reply
}

pub fn valid_request_id(id: &str) -> bool {
    id.len() == 36
        && uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

pub fn valid_challenge(challenge: &str) -> bool {
    (16..=128).contains(&challenge.len())
        && challenge.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Diagnostic metadata only; this entry point never performs observations.
pub fn check() -> Reply {
    fail(
        base_reply(),
        "UNAUTHORIZED",
        "Observations require an authorized native messaging connection.",
    )
}

pub struct Connection {
    auth: Result<AuthContext, &'static str>,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            auth: AuthContext::new(),
        }
    }
}

impl Connection {
    pub fn handle_request(&mut self, bytes: &[u8]) -> Reply {
        self.handle_with_probe(bytes, probes::scan)
    }

    fn handle_with_probe(
        &mut self,
        bytes: &[u8],
        scan: impl FnOnce() -> (Capabilities, Vec<Finding>),
    ) -> Reply {
        self.handle_with_clock(bytes, scan, || (timestamp(), Instant::now()))
    }

    fn handle_with_clock(
        &mut self,
        bytes: &[u8],
        scan: impl FnOnce() -> (Capabilities, Vec<Finding>),
        mut clock: impl FnMut() -> (u64, Instant),
    ) -> Reply {
        let mut reply = base_reply();
        if bytes.len() > MAX_REQUEST_BYTES {
            return fail(reply, "FRAME_TOO_LARGE", "Request exceeds 65536 bytes.");
        }
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return fail(reply, "INVALID_JSON", "Request must be valid UTF-8 JSON."),
        };
        reply.request_id = value
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|id| valid_request_id(id))
            .map(str::to_owned);
        reply.challenge = value
            .get("challenge")
            .and_then(Value::as_str)
            .filter(|c| valid_challenge(c))
            .map(str::to_owned);
        let request: Request = match serde_json::from_slice(bytes) {
            Ok(request) => request,
            Err(_) => return fail(reply, "INVALID_REQUEST", "Invalid request fields or types."),
        };
        if request.protocol_version != 2 {
            return fail(
                reply,
                "UNSUPPORTED_VERSION",
                "Only protocol version 2 is supported.",
            );
        }
        if !valid_request_id(&request.request_id)
            || !valid_challenge(&request.challenge)
            || (!matches!(request.command.as_str(), "authorize" | "preflight")
                && request.authorization.is_some())
        {
            return fail(
                reply,
                "INVALID_REQUEST",
                "Invalid correlation or authorization fields.",
            );
        }
        let ctx = match &mut self.auth {
            Ok(ctx) => ctx,
            Err(code) => return fail(reply, code, "Secure randomness unavailable; reconnect."),
        };
        match request.command.as_str() {
            "hello" => {
                reply.preflight_support = Some(PreflightSupport {
                    contract_version: 1,
                    grant_version: 3,
                });
                reply.auth_readiness = Some(ctx.readiness());
                reply.agent_instance_id = Some(ctx.instance_id.clone());
                reply.auth_challenge = Some(ctx.challenge.clone());
            }
            "authorize" => {
                let Some(auth) = request.authorization else {
                    return fail(
                        reply,
                        "INVALID_REQUEST",
                        "Detached authorization is required.",
                    );
                };
                let (wall, now) = clock();
                if let Err(code) = ctx.authorize(&auth, wall, now) {
                    return fail(reply, code, "Authorization rejected; reconnect for a fresh challenge if expired or consumed.");
                }
            }
            "preflight" => {
                let Some(auth) = request.authorization else {
                    return fail(
                        reply,
                        "INVALID_REQUEST",
                        "Detached authorization is required.",
                    );
                };
                let (wall, now) = clock();
                let grant = match ctx.preflight(&auth, wall, now) {
                    Ok(grant) => grant,
                    Err(code) => return fail(reply, code, "Preflight rejected; reconnect for a fresh challenge if expired or consumed."),
                };
                reply.purpose = Some(auth::PREFLIGHT_PURPOSE);
                reply.preflight_id = Some(grant.payload.preflight_id.clone());
                reply.assessment_slug = Some(grant.payload.assessment_slug.clone());
                (reply.capabilities, reply.findings) = scan();
                let (wall, now) = clock();
                reply.observed_at = wall;
                if !grant.current(wall, now) {
                    reply.capabilities = probes::capabilities();
                    reply.findings.clear();
                    return fail(
                        reply,
                        "AUTH_EXPIRED",
                        "Preflight expired during observation.",
                    );
                }
                reply.authorized_capabilities = Some(grant.payload.capabilities);
                reply.expires_at = Some(grant.payload.expires_at);
            }
            "check" => {
                let (wall, now) = clock();
                if ctx.authorized(wall, now).is_none() {
                    return fail(
                        reply,
                        "UNAUTHORIZED",
                        "A current authorization is required.",
                    );
                }
                (reply.capabilities, reply.findings) = scan();
                let (wall, now) = clock();
                reply.observed_at = wall;
                // Do not release observations if the grant expired during a probe.
                if ctx.authorized(wall, now).is_none() {
                    reply.capabilities = probes::capabilities();
                    reply.findings.clear();
                    return fail(
                        reply,
                        "AUTH_EXPIRED",
                        "Authorization expired during observation.",
                    );
                }
            }
            _ => {
                return fail(
                    reply,
                    "UNKNOWN_COMMAND",
                    "Supported commands are hello, authorize, check, preflight.",
                )
            }
        }
        let (wall, now) = clock();
        if let Some(grant) = ctx.authorized(wall, now) {
            reply.auth_state = Some("authorized".to_owned());
            reply.authorized_capabilities = Some(grant.capabilities.clone());
            reply.expires_at = Some(grant.expires_at);
            reply.session_id = Some(grant.session_id.clone());
        } else if request.command == "check" {
            reply.capabilities = probes::capabilities();
            reply.findings.clear();
            return fail(
                reply,
                "AUTH_EXPIRED",
                "Authorization expired during observation.",
            );
        }
        if [
            &reply.capabilities.processes,
            &reply.capabilities.displays,
            &reply.capabilities.overlays,
        ]
        .iter()
        .any(|c| c.status == Status::Error)
        {
            return fail(
                reply,
                "PROBE_FAILED",
                "At least one probe failed; inspect capability status and limitations.",
            );
        }
        reply
    }
}

pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

pub fn origin_allowed(origin: &str, configured_ids: &str) -> bool {
    let ids: Vec<_> = configured_ids.split(',').collect();
    if ids.is_empty() || ids.iter().any(|id| !valid_extension_id(id)) {
        return false;
    }
    let Some(id) = origin
        .strip_prefix("chrome-extension://")
        .and_then(|value| value.strip_suffix('/'))
    else {
        return false;
    };
    valid_extension_id(id) && ids.contains(&id)
}

pub fn approved_origin(origin: &str) -> bool {
    origin_allowed(
        origin,
        option_env!("SAFEAGENT_ALLOWED_EXTENSION_IDS").unwrap_or(""),
    )
}

fn write_reply(writer: &mut impl Write, reply: &Reply) -> io::Result<()> {
    let payload = serde_json::to_vec(reply)?;
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response exceeds native messaging limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_ne_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

// EOF between frames is a normal lifecycle event. Truncated/oversized frames
// receive one explicit error and end the stream; no untrusted length allocation.
pub fn messaging(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    let mut connection = Connection::default();
    loop {
        let mut header = [0u8; 4];
        loop {
            match reader.read(&mut header[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if let Err(error) = reader.read_exact(&mut header[1..]) {
            write_reply(
                writer,
                &fail(
                    base_reply(),
                    "MALFORMED_FRAME",
                    "Incomplete native message header.",
                ),
            )?;
            return Err(error);
        }
        let length = u32::from_ne_bytes(header) as usize;
        if length == 0 || length > MAX_REQUEST_BYTES {
            write_reply(
                writer,
                &fail(
                    base_reply(),
                    if length == 0 {
                        "MALFORMED_FRAME"
                    } else {
                        "FRAME_TOO_LARGE"
                    },
                    "Native message length must be 1..65536 bytes.",
                ),
            )?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid native message length",
            ));
        }
        let mut payload = vec![0; length];
        if let Err(error) = reader.read_exact(&mut payload) {
            write_reply(
                writer,
                &fail(
                    base_reply(),
                    "MALFORMED_FRAME",
                    "Incomplete native message payload.",
                ),
            )?;
            return Err(error);
        }
        write_reply(writer, &connection.handle_request(&payload))?;
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

struct Host(Child);
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn exchange(host: &mut Host, command: &str, authorization: Option<Value>) -> Value {
    let mut request = json!({"protocolVersion":2,"requestId":"12345678-1234-4234-8234-123456789abc",
        "challenge":"correlation-only","command":command});
    if let Some(auth) = authorization {
        request["authorization"] = auth;
    }
    let bytes = serde_json::to_vec(&request).unwrap();
    let input = host.0.stdin.as_mut().unwrap();
    input
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .unwrap();
    input.write_all(&bytes).unwrap();
    input.flush().unwrap();
    let output = host.0.stdout.as_mut().unwrap();
    let mut header = [0; 4];
    output.read_exact(&mut header).unwrap();
    let size = u32::from_ne_bytes(header) as usize;
    assert!(size <= safeagent::MAX_RESPONSE_BYTES);
    let mut reply = vec![0; size];
    output.read_exact(&mut reply).unwrap();
    serde_json::from_slice(&reply).unwrap()
}
fn key() -> SigningKey {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

// Opt-in: builds a separate binary with an ephemeral public key; no private key is persisted.
#[test]
#[ignore = "run explicitly; compiles isolated actual host binary"]
fn embedded_key_authorizes_binary_and_runtime_override_is_ignored() {
    let signer = key();
    let impostor = key();
    let target = std::env::temp_dir().join(format!("safeagent-auth-{}", OsRng.next_u64()));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(target.clone());
    let config = |key: &SigningKey| {
        format!(
            "test:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        )
    };
    assert!(Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--offline",
            "--bin",
            "safeagent",
            "--target-dir"
        ])
        .arg(&target)
        .env("SAFEAGENT_AUTH_PUBLIC_KEYS", config(&signer))
        .env(
            "SAFEAGENT_ALLOWED_EXTENSION_IDS",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .status()
        .unwrap()
        .success());
    let binary = target
        .join("debug")
        .join(format!("safeagent{}", std::env::consts::EXE_SUFFIX));
    let mut host = Host(
        Command::new(&binary)
            .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
            .env("SAFEAGENT_AUTH_PUBLIC_KEYS", config(&impostor))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let hello = exchange(&mut host, "hello", None);
    assert_eq!(hello["agentVersion"], "0.2.0");
    assert_eq!(hello["authReadiness"], "ready");
    assert_eq!(hello["ok"], true);
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let payload = serde_json::to_vec(&json!({"v":2,"audience":safeagent::auth::AUDIENCE,
        "sessionId":"12345678-1234-4234-8234-123456789abc", "agentInstanceId":hello["agentInstanceId"],
        "challenge":hello["authChallenge"],"capabilities":safeagent::auth::CAPABILITIES,
        "issuedAt":wall,"expiresAt":wall+60000})).unwrap();
    let auth = |key: &SigningKey| {
        json!({"keyId":"test", "payload":URL_SAFE_NO_PAD.encode(&payload),
        "signature":URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes())})
    };
    assert_eq!(
        exchange(&mut host, "authorize", Some(auth(&impostor)))["error"]["code"],
        "INVALID_SIGNATURE"
    );
    assert_eq!(
        exchange(&mut host, "authorize", Some(auth(&signer)))["ok"],
        true
    );
    let check = exchange(&mut host, "check", None);
    // Headless native runners may report probe failure, but must pass the authorization gate.
    assert_eq!(check["authState"], "authorized");
    assert_eq!(check["sessionId"], "12345678-1234-4234-8234-123456789abc");
    assert!(check["ok"] == true || check["error"]["code"] == "PROBE_FAILED");

    let mut preflight_host = Host(
        Command::new(&binary)
            .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let hello = exchange(&mut preflight_host, "hello", None);
    assert_eq!(
        hello["preflightSupport"],
        json!({"contractVersion":1,"grantVersion":3})
    );
    let payload = serde_json::to_vec_pretty(&json!({"v":3,"purpose":"assessment-preflight",
        "audience":safeagent::auth::AUDIENCE,"preflightId":"12345678-1234-4234-8234-123456789abc",
        "assessmentSlug":"test-assessment","agentInstanceId":hello["agentInstanceId"],
        "challenge":hello["authChallenge"],"capabilities":safeagent::auth::CAPABILITIES,
        "issuedAt":wall,"expiresAt":wall+60000}))
    .unwrap();
    let authorization = json!({"keyId":"test","payload":URL_SAFE_NO_PAD.encode(&payload),
        "signature":URL_SAFE_NO_PAD.encode(signer.sign(&payload).to_bytes())});
    assert_eq!(
        exchange(
            &mut preflight_host,
            "authorize",
            Some(authorization.clone())
        )["error"]["code"],
        "INVALID_AUTHORIZATION"
    );
    let reply = exchange(
        &mut preflight_host,
        "preflight",
        Some(authorization.clone()),
    );
    assert!(reply["ok"] == true || reply["error"]["code"] == "PROBE_FAILED");
    assert_eq!(reply["purpose"], "assessment-preflight");
    assert_eq!(reply["assessmentSlug"], "test-assessment");
    assert_eq!(reply["preflightId"], "12345678-1234-4234-8234-123456789abc");
    assert_eq!(reply["sessionId"], Value::Null);
    assert_eq!(reply["authState"], "unauthorized");
    assert_eq!(
        exchange(&mut preflight_host, "preflight", Some(authorization))["error"]["code"],
        "CHALLENGE_REUSED"
    );
    assert_eq!(
        exchange(&mut preflight_host, "check", None)["error"]["code"],
        "UNAUTHORIZED"
    );
}

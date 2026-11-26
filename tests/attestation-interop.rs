//! Cross-implementation checks: SafeAgent's DER encodings must be what Node.js crypto (the
//! Assessment API verifier) expects. Requires `node` on PATH; skipped with a message otherwise.

use safeagent::attestation::{p256_signature_der, p256_spki};
use std::process::Command;

fn vector() -> std::collections::HashMap<String, String> {
    include_str!("fixtures/p256-node-vector.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn spki_from_raw_point_matches_node_export() {
    let v = vector();
    assert_eq!(to_hex(&p256_spki(&hex(&v["xy"])).unwrap()), v["spki"]);
}

/// Runs Node's verifier; returns None when node is unavailable.
fn node_verify(spki: &[u8], message: &[u8], der: &[u8]) -> Option<bool> {
    let script = "const c=require('crypto');const [k,m,s]=process.argv.slice(1).map(h=>Buffer.from(h,'hex'));\
        try{process.stdout.write(String(c.verify('sha256',m,{key:k,format:'der',type:'spki',dsaEncoding:'der'},s)))}\
        catch(e){process.stdout.write('false')}";
    let out = Command::new("node")
        .args(["-e", script, &to_hex(spki), &to_hex(message), &to_hex(der)])
        .output()
        .ok()?;
    out.status.success().then(|| out.stdout == b"true")
}

#[test]
fn node_verifies_der_built_from_raw_and_rejects_tampering() {
    let v = vector();
    let spki = hex(&v["spki"]);
    let message = v["message"].as_bytes();
    let der = p256_signature_der(&hex(&v["raw_signature"])).unwrap();
    let Some(valid) = node_verify(&spki, message, &der) else {
        eprintln!("node not found: interop check NOT_RUN");
        return;
    };
    assert!(valid, "Node must accept the DER signature SafeAgent builds");
    // Altered payload, altered signature, wrong key, malformed encodings: all rejected.
    assert_eq!(
        node_verify(&spki, b"kalvium interop vectoR", &der),
        Some(false)
    );
    let mut flipped = der.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(node_verify(&spki, message, &flipped), Some(false));
    let mut other = hex(&v["xy"]);
    other.swap(0, 1);
    if let Some(wrong) = p256_spki(&other) {
        assert_eq!(node_verify(&wrong, message, &der), Some(false));
    }
    assert_eq!(
        node_verify(&spki, message, &der[..der.len() - 3]),
        Some(false)
    );
    assert_eq!(node_verify(&spki, message, b"\x30\x00"), Some(false));
}

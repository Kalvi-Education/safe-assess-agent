//! Result attestation (protocol.md "Result attestation"): self hash, parent check and signed
//! results with an OS-held P-256 device key. Additive to protocol v2.

use crate::signing::{Executable, Signature};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const GOOGLE_TEAM_ID: &str = "EQHXZ8M8AV";
pub const GOOGLE_SIGNER: &str = "Google LLC";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProtection {
    Tpm,
    SecureEnclave,
    Software,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Parent {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub key_protection: KeyProtection,
    pub install_public_key: Option<String>,
    pub self_hash: Option<String>,
    pub self_signer: Option<String>,
    pub parent: Parent,
}

/// SHA-256 hex of a file; None when unreadable.
pub fn file_sha256(path: &std::path::Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
}

fn image_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// Is this image genuine Google Chrome? Windows: signer `Google LLC` and `chrome.exe`.
/// macOS: Team ID `EQHXZ8M8AV` (main app or a Chrome helper).
pub fn is_chrome(image: &str, executable: &Executable) -> bool {
    let Signature::Signed(signer) = &executable.signature else {
        return false;
    };
    let name = image_name(image);
    if cfg!(target_os = "windows") {
        signer == GOOGLE_SIGNER && name == "chrome.exe"
    } else {
        signer == GOOGLE_TEAM_ID && name.starts_with("google chrome")
    }
}

/// Chrome may launch Windows hosts through `cmd.exe` (policy `NativeHostsExecutablesLaunchDirectly`).
/// `chain` is parent first, then grandparent: (image path, identity).
pub fn classify_parent(chain: &[(String, Option<Executable>)]) -> Parent {
    let Some((image, identity)) = chain.first() else {
        return Parent::Unknown;
    };
    let Some(identity) = identity else {
        return Parent::Unknown;
    };
    if is_chrome(image, identity) {
        return Parent::Trusted;
    }
    // Only the OS shell in System32/SysWOW64, signed "Microsoft Windows" (catalog-signed OS file).
    let lower = image.to_ascii_lowercase().replace('/', "\\");
    let in_system_dir = lower.ends_with("\\windows\\system32\\cmd.exe")
        || lower.ends_with("\\windows\\syswow64\\cmd.exe");
    let is_signed_cmd = in_system_dir
        && matches!(&identity.signature, Signature::Signed(s) if s == "Microsoft Windows");
    if cfg!(target_os = "windows") && is_signed_cmd {
        return match chain.get(1) {
            Some((grand, Some(grand_identity))) if is_chrome(grand, grand_identity) => {
                Parent::Trusted
            }
            Some((_, None)) | None => Parent::Unknown,
            _ => Parent::Untrusted,
        };
    }
    Parent::Untrusted
}

/// Dev-only escape hatch for local smoke tests. Release builds reject it in validate-auth-config.
pub fn any_parent_allowed() -> bool {
    option_env!("SAFEAGENT_ALLOW_ANY_PARENT") == Some("true")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedFinding<'a> {
    id: &'a str,
    category: &'a str,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedAttestation<'a> {
    key_protection: KeyProtection,
    self_hash: Option<&'a str>,
    self_signer: Option<&'a str>,
    parent: Parent,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedResult<'a> {
    v: u32,
    /// Domain separator: these bytes are only ever a SafeAgent observation result.
    domain: &'static str,
    purpose: &'a str,
    /// Outcome the reply claims; signed so unsigned outer fields cannot change the verdict.
    ok: bool,
    error_code: Option<&'a str>,
    auth_state: &'a str,
    preflight_id: Option<&'a str>,
    session_id: Option<&'a str>,
    challenge: &'a str,
    agent_instance_id: &'a str,
    agent_version: &'a str,
    observed_at: u64,
    capabilities: std::collections::BTreeMap<&'static str, &'a crate::probes::Status>,
    findings: Vec<SignedFinding<'a>>,
    attestation: SignedAttestation<'a>,
}

pub const RESULT_DOMAIN: &str = "kalvium.safeagent.result.v1";

pub struct ResultInput<'a> {
    pub purpose: &'a str,
    pub ok: bool,
    pub error_code: Option<&'a str>,
    pub auth_state: &'a str,
    pub preflight_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub challenge: &'a str,
    pub agent_instance_id: &'a str,
    pub observed_at: u64,
    pub capabilities: &'a crate::probes::Capabilities,
    pub findings: &'a [crate::probes::Finding],
    pub attestation: &'a Attestation,
}

/// Exact bytes to sign. Serialised once; consumers verify these bytes and never re-serialise.
pub fn result_bytes(input: &ResultInput) -> Option<Vec<u8>> {
    let caps = input.capabilities;
    let result = SignedResult {
        v: 1,
        domain: RESULT_DOMAIN,
        purpose: input.purpose,
        ok: input.ok,
        error_code: input.error_code,
        auth_state: input.auth_state,
        preflight_id: input.preflight_id,
        session_id: input.session_id,
        challenge: input.challenge,
        agent_instance_id: input.agent_instance_id,
        agent_version: crate::VERSION,
        observed_at: input.observed_at,
        capabilities: [
            ("processes", &caps.processes.status),
            ("displays", &caps.displays.status),
            ("overlays", &caps.overlays.status),
        ]
        .into_iter()
        .collect(),
        findings: input
            .findings
            .iter()
            .map(|f| SignedFinding {
                id: &f.id,
                category: f.category,
                count: f
                    .process_count
                    .or(f.window_count)
                    .or(f.display_count.map(|c| c as usize))
                    .unwrap_or(1),
            })
            .collect(),
        attestation: SignedAttestation {
            key_protection: input.attestation.key_protection,
            self_hash: input.attestation.self_hash.as_deref(),
            self_signer: input.attestation.self_signer.as_deref(),
            parent: input.attestation.parent,
        },
    };
    serde_json::to_vec(&result).ok()
}

/// A device key held by the OS. `sign` returns a DER ECDSA P-256 / SHA-256 signature.
pub trait DeviceKey {
    fn protection(&self) -> KeyProtection;
    fn public_key_spki(&self) -> Option<Vec<u8>>;
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>>;
}

pub struct NoKey;
impl DeviceKey for NoKey {
    fn protection(&self) -> KeyProtection {
        KeyProtection::Unavailable
    }
    fn public_key_spki(&self) -> Option<Vec<u8>> {
        None
    }
    fn sign(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Convert a raw P-256 point (X||Y, 64 bytes) to SubjectPublicKeyInfo DER.
pub fn p256_spki(xy: &[u8]) -> Option<Vec<u8>> {
    if xy.len() != 64 {
        return None;
    }
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04||X||Y }
    let mut der = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    der.extend_from_slice(xy);
    Some(der)
}

/// Convert a raw P-256 signature (r||s, 64 bytes, as CNG returns) to DER.
pub fn p256_signature_der(rs: &[u8]) -> Option<Vec<u8>> {
    if rs.len() != 64 {
        return None;
    }
    let integer = |bytes: &[u8]| {
        let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        let mut value = if trimmed.is_empty() { vec![0] } else { trimmed };
        if value[0] & 0x80 != 0 {
            value.insert(0, 0);
        }
        let mut out = vec![0x02, value.len() as u8];
        out.extend(value);
        out
    };
    let (r, s) = (integer(&rs[..32]), integer(&rs[32..]));
    let mut der = vec![0x30, (r.len() + s.len()) as u8];
    der.extend(r);
    der.extend(s);
    Some(der)
}

#[cfg(target_os = "windows")]
pub use crate::device_key_windows::open_device_key;

#[cfg(target_os = "macos")]
pub use crate::device_key_macos::open_device_key;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn open_device_key() -> Box<dyn DeviceKey> {
    Box::new(NoKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(signer: &str) -> Option<Executable> {
        Some(Executable {
            signature: Signature::Signed(signer.into()),
            company: None,
            original_filename: None,
            user_writable: false,
            is_self: false,
        })
    }

    #[test]
    fn parent_must_be_genuine_chrome() {
        let (chrome, signer) = if cfg!(target_os = "windows") {
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                GOOGLE_SIGNER,
            )
        } else {
            (
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                GOOGLE_TEAM_ID,
            )
        };
        assert_eq!(
            classify_parent(&[(chrome.into(), signed(signer))]),
            Parent::Trusted
        );
        // Renamed impostor with the right name but wrong or no signer.
        assert_eq!(
            classify_parent(&[(chrome.into(), signed("Evil Corp"))]),
            Parent::Untrusted
        );
        let unsigned = Executable {
            signature: Signature::Unsigned,
            company: None,
            original_filename: None,
            user_writable: true,
            is_self: false,
        };
        assert_eq!(
            classify_parent(&[(chrome.into(), Some(unsigned))]),
            Parent::Untrusted
        );
        // Signed by Google but not Chrome (e.g. an updater) is refused.
        assert_eq!(
            classify_parent(&[("/x/GoogleUpdater".into(), signed(signer))]),
            Parent::Untrusted
        );
        // A shell or script host is refused; unreadable identity is unknown, not trusted.
        assert_eq!(
            classify_parent(&[("/bin/zsh".into(), signed("Apple"))]),
            Parent::Untrusted
        );
        assert_eq!(classify_parent(&[(chrome.into(), None)]), Parent::Unknown);
        assert_eq!(classify_parent(&[]), Parent::Unknown);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_cmd_intermediary_requires_chrome_grandparent() {
        let cmd = r"C:\Windows\System32\cmd.exe".to_string();
        let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string();
        let ms = || signed("Microsoft Windows");
        assert_eq!(
            classify_parent(&[(cmd.clone(), ms()), (chrome.clone(), signed(GOOGLE_SIGNER))]),
            Parent::Trusted
        );
        assert_eq!(
            classify_parent(&[(cmd.clone(), ms()), (r"C:\x\powershell.exe".into(), ms())]),
            Parent::Untrusted
        );
        assert_eq!(classify_parent(&[(cmd.clone(), ms())]), Parent::Unknown);
        // An unsigned cmd.exe copy is refused even under Chrome.
        assert_eq!(
            classify_parent(&[(cmd, signed("Evil Corp")), (chrome, signed(GOOGLE_SIGNER))]),
            Parent::Untrusted
        );
    }

    #[test]
    fn p256_encodings_are_well_formed_der() {
        let spki = p256_spki(&[1u8; 64]).unwrap();
        assert_eq!(spki.len(), 91);
        assert_eq!(&spki[..2], &[0x30, 0x59]);
        assert!(p256_spki(&[1u8; 63]).is_none());
        // High bit set gets a 0x00 pad; leading zeros are trimmed.
        let mut rs = [0u8; 64];
        rs[0] = 0x80;
        rs[33] = 0x01;
        let der = p256_signature_der(&rs).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..5], &[0x02, 33, 0x00]);
        let s_at = 2 + 2 + 33;
        assert_eq!(&der[s_at..s_at + 2], &[0x02, 31]);
        assert_eq!(der[1] as usize, der.len() - 2);
        assert!(p256_signature_der(&[0u8; 10]).is_none());
    }
}

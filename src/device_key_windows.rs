//! Windows device key: per-user, non-exportable CNG ECDSA P-256 key. TPM (Platform Crypto
//! Provider) first, then the software KSP. The private key never leaves CNG.

use crate::attestation::{p256_signature_der, p256_spki, DeviceKey, KeyProtection, NoKey};
use sha2::{Digest, Sha256};
use windows::{
    core::{w, PCWSTR},
    Win32::Security::{
        Cryptography::{
            NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
            NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
            BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, CERT_KEY_SPEC,
            MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY,
            NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
            NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        },
        OBJECT_SECURITY_INFORMATION,
    },
};

const KEY_NAME: PCWSTR = w!("Kalvium SafeAgent Result Key");
/// CI-only key name so tests never touch a real installation's key.
#[cfg(test)]
const TEST_KEY_NAME: PCWSTR = w!("Kalvium SafeAgent CI Test Key");

struct CngKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    protection: KeyProtection,
    point: Vec<u8>,
}

impl Drop for CngKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
        }
    }
}

fn property(key: NCRYPT_KEY_HANDLE, name: PCWSTR) -> Option<Vec<u8>> {
    let mut size = 0u32;
    unsafe { NCryptGetProperty(key, name, None, &mut size, OBJECT_SECURITY_INFORMATION(0)) }
        .ok()?;
    let mut value = vec![0u8; size as usize];
    unsafe {
        NCryptGetProperty(
            key,
            name,
            Some(&mut value),
            &mut size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }
    .ok()?;
    value.truncate(size as usize);
    Some(value)
}

fn u32_property(key: NCRYPT_KEY_HANDLE, name: PCWSTR) -> Option<u32> {
    property(key, name).and_then(|b| {
        b.get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    })
}

fn public_blob(key: NCRYPT_KEY_HANDLE) -> Option<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        NCryptExportKey(
            key,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            None,
            &mut size,
            NCRYPT_FLAGS(0),
        )
    }
    .ok()?;
    let mut blob = vec![0u8; size as usize];
    unsafe {
        NCryptExportKey(
            key,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut size,
            NCRYPT_FLAGS(0),
        )
    }
    .ok()?;
    blob.truncate(size as usize);
    Some(blob)
}

/// Raw P-256 point if this key meets the policy (curve from the public blob, 256-bit,
/// non-exportable); otherwise the key is not used and nothing is signed with it.
fn acceptable_point(key: NCRYPT_KEY_HANDLE) -> Option<Vec<u8>> {
    let blob = public_blob(key)?;
    crate::attestation::cng_p256_point(
        &blob,
        u32_property(key, NCRYPT_LENGTH_PROPERTY),
        u32_property(key, NCRYPT_EXPORT_POLICY_PROPERTY),
    )
    .map(<[u8]>::to_vec)
}

fn open_in(provider_name: PCWSTR, protection: KeyProtection) -> Option<CngKey> {
    open_named(provider_name, protection, KEY_NAME)
}

fn open_named(provider_name: PCWSTR, protection: KeyProtection, name: PCWSTR) -> Option<CngKey> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut provider, provider_name, 0) }.ok()?;
    let mut key = NCRYPT_KEY_HANDLE::default();
    let opened = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    };
    if opened.is_err() {
        // Absent: create. Export policy defaults to none, so the private key is non-exportable.
        let created = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .and_then(|_| unsafe { NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) });
        if created.is_err() {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
            }
            return None;
        }
    }
    let mut candidate = CngKey {
        provider,
        key,
        protection,
        point: Vec::new(),
    };
    // Drop releases both handles when the key does not meet the policy.
    candidate.point = acceptable_point(candidate.key)?;
    Some(candidate)
}

impl DeviceKey for CngKey {
    fn protection(&self) -> KeyProtection {
        self.protection
    }

    fn public_key_spki(&self) -> Option<Vec<u8>> {
        p256_spki(&self.point)
    }

    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let digest = Sha256::digest(message);
        let mut signature = [0u8; 64];
        let mut size = 0u32;
        unsafe {
            NCryptSignHash(
                self.key,
                None,
                &digest,
                Some(&mut signature),
                &mut size,
                NCRYPT_SILENT_FLAG,
            )
        }
        .ok()?;
        p256_signature_der(signature.get(..size as usize)?)
    }
}

/// TPM first. The software key is only opened or created when no acceptable TPM key exists, so a
/// TPM device never accumulates a second (software) key.
pub fn open_device_key() -> Box<dyn DeviceKey> {
    if let Some(key) = open_in(MS_PLATFORM_CRYPTO_PROVIDER, KeyProtection::Tpm) {
        return Box::new(key);
    }
    match open_in(MS_KEY_STORAGE_PROVIDER, KeyProtection::Software) {
        Some(key) => Box::new(key),
        None => Box::new(NoKey),
    }
}

#[cfg(test)]
mod tests {
    //! Real CNG on the Windows CI runner (software KSP; hosted runners have no TPM).
    use super::*;
    use windows::Win32::Security::Cryptography::NCryptDeleteKey;

    #[test]
    fn software_ksp_key_round_trips_and_is_reused_not_recreated() {
        let first = open_named(
            MS_KEY_STORAGE_PROVIDER,
            KeyProtection::Software,
            TEST_KEY_NAME,
        )
        .expect("CNG software KSP must create an acceptable P-256 key");
        let spki = first.public_key_spki().expect("public key exports");
        assert_eq!(spki.len(), 91);
        let message = b"kalvium safeagent ci signing check";
        let signature = first.sign(message).expect("signs");
        // Reopening must return the same persisted key, not a new one.
        let again = open_named(
            MS_KEY_STORAGE_PROVIDER,
            KeyProtection::Software,
            TEST_KEY_NAME,
        )
        .expect("reopens");
        assert_eq!(again.public_key_spki(), Some(spki.clone()));
        drop(again);
        // Verify with Node (the Assessment API verifier) when available.
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let script = "const c=require('crypto');const [k,m,s]=process.argv.slice(1).map(h=>Buffer.from(h,'hex'));\
            process.stdout.write(String(c.verify('sha256',m,{key:k,format:'der',type:'spki'},s)))";
        if let Ok(out) = std::process::Command::new("node")
            .args(["-e", script, &hex(&spki), &hex(message), &hex(&signature)])
            .output()
        {
            assert_eq!(out.stdout, b"true", "Node must verify the CNG signature");
        }
        let key = first.key;
        std::mem::forget(first);
        unsafe {
            let _ = NCryptDeleteKey(key, 0);
        }
    }
}

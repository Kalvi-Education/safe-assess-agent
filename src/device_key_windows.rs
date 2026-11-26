//! Windows device key: per-user, non-exportable CNG ECDSA P-256 key. TPM (Platform Crypto
//! Provider) first, then the software KSP. The private key never leaves CNG.

use crate::attestation::{p256_signature_der, p256_spki, DeviceKey, KeyProtection, NoKey};
use sha2::{Digest, Sha256};
use windows::{
    core::{w, PCWSTR},
    Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB,
        BCRYPT_ECDSA_P256_ALGORITHM, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
        NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    },
};

const KEY_NAME: PCWSTR = w!("Kalvium SafeAgent Result Key");

struct CngKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    protection: KeyProtection,
}

impl Drop for CngKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
        }
    }
}

fn open_in(provider_name: PCWSTR, protection: KeyProtection) -> Option<CngKey> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut provider, provider_name, 0) }.ok()?;
    let mut key = NCRYPT_KEY_HANDLE::default();
    let opened = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            KEY_NAME,
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
                KEY_NAME,
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
    Some(CngKey {
        provider,
        key,
        protection,
    })
}

impl DeviceKey for CngKey {
    fn protection(&self) -> KeyProtection {
        self.protection
    }

    fn public_key_spki(&self) -> Option<Vec<u8>> {
        let mut size = 0u32;
        unsafe {
            NCryptExportKey(
                self.key,
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
                self.key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                Some(&mut blob),
                &mut size,
                NCRYPT_FLAGS(0),
            )
        }
        .ok()?;
        // BCRYPT_ECCKEY_BLOB header: magic (4) + cbKey (4), then X || Y.
        let xy = blob.get(8..8 + 64)?;
        p256_spki(xy)
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

pub fn open_device_key() -> Box<dyn DeviceKey> {
    if let Some(key) = open_in(MS_PLATFORM_CRYPTO_PROVIDER, KeyProtection::Tpm) {
        return Box::new(key);
    }
    match open_in(MS_KEY_STORAGE_PROVIDER, KeyProtection::Software) {
        Some(key) => Box::new(key),
        None => Box::new(NoKey),
    }
}

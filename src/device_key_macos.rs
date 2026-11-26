//! macOS device key: persistent ECDSA P-256 key in the Secure Enclave, stored in the
//! data-protection keychain. Needs a Developer ID signed build with a keychain entitlement; ad-hoc
//! and unsigned builds get errSecMissingEntitlement (-34018) and report `unavailable`.
//!
//! Deliberately no login-keychain fallback: a file-keychain key is bound to the creating binary's
//! code signature, so every unsigned rebuild or update would show the user a keychain password
//! prompt, which hangs a background Chrome-launched check. Unsigned results are untrusted anyway.

use crate::attestation::{DeviceKey, KeyProtection, NoKey};
use std::ffi::c_void;

type Ref = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(value: Ref);
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: Ref,
        value_callbacks: Ref,
    ) -> Ref;
    fn CFDataCreate(allocator: Ref, bytes: *const u8, length: isize) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    fn CFNumberCreate(allocator: Ref, kind: isize, value: *const c_void) -> Ref;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFBooleanTrue: Ref;
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecKeyCreateRandomKey(parameters: Ref, error: *mut Ref) -> Ref;
    fn SecKeyCopyPublicKey(key: Ref) -> Ref;
    fn SecKeyCopyExternalRepresentation(key: Ref, error: *mut Ref) -> Ref;
    fn SecKeyCreateSignature(key: Ref, algorithm: Ref, data: Ref, error: *mut Ref) -> Ref;
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    static kSecClass: Ref;
    static kSecClassKey: Ref;
    static kSecAttrKeyType: Ref;
    static kSecAttrKeyTypeECSECPrimeRandom: Ref;
    static kSecAttrKeySizeInBits: Ref;
    static kSecAttrTokenID: Ref;
    static kSecAttrTokenIDSecureEnclave: Ref;
    static kSecAttrIsPermanent: Ref;
    static kSecAttrApplicationTag: Ref;
    static kSecAttrKeyClass: Ref;
    static kSecAttrKeyClassPrivate: Ref;
    static kSecAttrAccessible: Ref;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: Ref;
    static kSecPrivateKeyAttrs: Ref;
    static kSecReturnRef: Ref;
    static kSecUseDataProtectionKeychain: Ref;
    static kSecUseAuthenticationUI: Ref;
    static kSecUseAuthenticationUIFail: Ref;
    static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: Ref;
}

const TAG: &[u8] = b"com.kalvium.safeagent.result-key";

/// Owns one CoreFoundation reference.
struct Cf(Ref);
impl Drop for Cf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

unsafe fn dictionary(pairs: &[(Ref, Ref)]) -> Cf {
    let keys: Vec<Ref> = pairs.iter().map(|(k, _)| *k).collect();
    let values: Vec<Ref> = pairs.iter().map(|(_, v)| *v).collect();
    Cf(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as isize,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    })
}

fn data(bytes: &[u8]) -> Cf {
    Cf(unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize) })
}

fn bytes(value: &Cf) -> Option<Vec<u8>> {
    if value.0.is_null() {
        return None;
    }
    let length = unsafe { CFDataGetLength(value.0) } as usize;
    let pointer = unsafe { CFDataGetBytePtr(value.0) };
    (!pointer.is_null()).then(|| unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

struct KeychainKey {
    key: Cf,
    protection: KeyProtection,
}

fn find() -> Option<Cf> {
    let tag = data(TAG);
    unsafe {
        let query = dictionary(&[
            (kSecClass, kSecClassKey),
            (kSecAttrApplicationTag, tag.0),
            (kSecAttrKeyClass, kSecAttrKeyClassPrivate),
            (kSecReturnRef, kCFBooleanTrue),
            (kSecUseDataProtectionKeychain, kCFBooleanTrue),
            (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
        ]);
        let mut found = std::ptr::null();
        (SecItemCopyMatching(query.0, &mut found) == 0 && !found.is_null()).then(|| Cf(found))
    }
}

fn create() -> Option<Cf> {
    let tag = data(TAG);
    let bits = 256i32;
    // kCFNumberSInt32Type = 3
    let size = Cf(unsafe { CFNumberCreate(std::ptr::null(), 3, (&bits as *const i32).cast()) });
    unsafe {
        let private = dictionary(&[
            (kSecAttrIsPermanent, kCFBooleanTrue),
            (kSecAttrApplicationTag, tag.0),
            (
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            ),
        ]);
        let parameters = dictionary(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeySizeInBits, size.0),
            (kSecPrivateKeyAttrs, private.0),
            (kSecUseDataProtectionKeychain, kCFBooleanTrue),
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
        ]);
        let mut error = std::ptr::null();
        let key = SecKeyCreateRandomKey(parameters.0, &mut error);
        if !error.is_null() {
            CFRelease(error);
        }
        (!key.is_null()).then(|| Cf(key))
    }
}

impl DeviceKey for KeychainKey {
    fn protection(&self) -> KeyProtection {
        self.protection
    }

    fn public_key_spki(&self) -> Option<Vec<u8>> {
        let public = Cf(unsafe { SecKeyCopyPublicKey(self.key.0) });
        if public.0.is_null() {
            return None;
        }
        let mut error = std::ptr::null();
        let raw = Cf(unsafe { SecKeyCopyExternalRepresentation(public.0, &mut error) });
        if !error.is_null() {
            unsafe { CFRelease(error) };
        }
        // External representation is the uncompressed point 04 || X || Y.
        let point = bytes(&raw)?;
        crate::attestation::p256_spki(point.get(1..65)?)
    }

    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let message = data(message);
        let mut error = std::ptr::null();
        // X9.62 message signing hashes with SHA-256 and returns DER.
        let signature = Cf(unsafe {
            SecKeyCreateSignature(
                self.key.0,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                message.0,
                &mut error,
            )
        });
        if !error.is_null() {
            unsafe { CFRelease(error) };
        }
        bytes(&signature)
    }
}

pub fn open_device_key() -> Box<dyn DeviceKey> {
    match find().or_else(create) {
        Some(key) => Box::new(KeychainKey {
            key,
            protection: KeyProtection::SecureEnclave,
        }),
        None => Box::new(NoKey),
    }
}

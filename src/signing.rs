//! Executable identity for running processes (D2 signer, D3 version info, D4 unverified).
//! Values stay in-process for catalog matching; only grouped findings leave the agent.

#[cfg(not(target_os = "windows"))]
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Valid Authenticode (embedded or catalog) signature; simple display name of the signer.
    Signed(String),
    /// Absent, broken or untrusted signature.
    Unsigned,
    /// The image could not be opened or verified; never treated as clean or unsigned.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Executable {
    pub signature: Signature,
    pub company: Option<String>,
    pub original_filename: Option<String>,
    pub user_writable: bool,
    pub is_self: bool,
}

impl Executable {
    pub fn unverified(&self) -> bool {
        !self.is_self && self.signature == Signature::Unsigned
    }
}

/// Heuristic, not an ACL check: user-profile download/desktop/document/temp folders and
/// the profile root. Per-user installs under AppData\Local\Programs are not flagged.
pub fn user_writable(path: &str, profile: Option<&str>, temp: Option<&str>) -> bool {
    let path = path.to_ascii_lowercase().replace('/', "\\");
    let under = |dir: &str| {
        let dir = dir.to_ascii_lowercase().replace('/', "\\");
        let dir = dir.trim_end_matches('\\');
        !dir.is_empty() && path.starts_with(&format!("{dir}\\"))
    };
    if temp.is_some_and(under) || path.contains("\\appdata\\local\\temp\\") {
        return true;
    }
    let Some(profile) = profile else { return false };
    let profile = profile.trim_end_matches(['\\', '/']);
    if ["downloads", "desktop", "documents"]
        .iter()
        .any(|folder| under(&format!("{profile}\\{folder}")))
    {
        return true;
    }
    under(profile) && !path[profile.len() + 1..].contains('\\')
}

#[cfg(target_os = "windows")]
pub use windows_impl::Identifier;

#[cfg(not(target_os = "windows"))]
#[derive(Default)]
pub struct Identifier {
    _private: (),
}

#[cfg(not(target_os = "windows"))]
impl Identifier {
    pub fn identify(&mut self, _pid: u32) -> Option<Rc<Executable>> {
        None
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{user_writable, Executable, Signature};
    use std::{collections::HashMap, rc::Rc};
    use windows::{
        core::{GUID, PCWSTR, PWSTR},
        Win32::{
            Foundation::{CloseHandle, BOOL, GENERIC_READ, HANDLE, HWND},
            Security::{
                Cryptography::{
                    Catalog::{
                        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
                        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
                        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
                    },
                    CertGetNameStringW, BCRYPT_SHA256_ALGORITHM, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                },
                WinTrust::{
                    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
                    WTHelperProvDataFromStateData, WinVerifyTrust,
                    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
                    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
                    WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE,
                    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
                },
            },
            Storage::FileSystem::{
                CreateFileW, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
                OPEN_EXISTING,
            },
            System::Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    // TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN:
    // no embedded signature, so the image may still be catalog-signed (most OS files).
    const NO_EMBEDDED_SIGNATURE: [u32; 3] = [0x800B_0100, 0x800B_0003, 0x800B_0001];

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    pub struct Identifier {
        by_path: HashMap<String, Rc<Executable>>,
        catalog_admin: Option<isize>,
        self_path: Option<String>,
        profile: Option<String>,
        temp: Option<String>,
    }

    impl Default for Identifier {
        fn default() -> Self {
            let mut admin = 0isize;
            let catalog_admin = unsafe {
                CryptCATAdminAcquireContext2(&mut admin, None, BCRYPT_SHA256_ALGORITHM, None, 0)
            }
            .ok()
            .map(|_| admin);
            Self {
                by_path: HashMap::new(),
                catalog_admin,
                self_path: std::env::current_exe()
                    .ok()
                    .map(|path| path.to_string_lossy().to_ascii_lowercase()),
                profile: std::env::var("USERPROFILE").ok(),
                temp: std::env::var("TEMP").ok(),
            }
        }
    }

    impl Drop for Identifier {
        fn drop(&mut self) {
            if let Some(admin) = self.catalog_admin {
                unsafe {
                    let _ = CryptCATAdminReleaseContext(admin, 0);
                }
            }
        }
    }

    impl Identifier {
        pub fn identify(&mut self, pid: u32) -> Option<Rc<Executable>> {
            let path = image_path(pid)?;
            let key = path.to_ascii_lowercase();
            if let Some(found) = self.by_path.get(&key) {
                return Some(found.clone());
            }
            let wide_path = wide(&path);
            let (company, original_filename) = version_strings(&wide_path);
            let executable = Rc::new(Executable {
                signature: self.signature(&wide_path),
                company,
                original_filename,
                user_writable: user_writable(&path, self.profile.as_deref(), self.temp.as_deref()),
                is_self: self.self_path.as_deref() == Some(key.as_str()),
            });
            self.by_path.insert(key, executable.clone());
            Some(executable)
        }

        fn signature(&self, path: &[u16]) -> Signature {
            let mut file = WINTRUST_FILE_INFO {
                cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: PCWSTR(path.as_ptr()),
                ..Default::default()
            };
            let data = WINTRUST_DATA {
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
                ..trust_data()
            };
            match verify(data) {
                (0, signer) => Signature::Signed(signer.unwrap_or_default()),
                (code, _) if NO_EMBEDDED_SIGNATURE.contains(&code) => self.catalog_signature(path),
                _ => Signature::Unsigned,
            }
        }

        fn catalog_signature(&self, path: &[u16]) -> Signature {
            let Some(admin) = self.catalog_admin else {
                return Signature::Unknown;
            };
            let Ok(handle) = (unsafe {
                CreateFileW(
                    PCWSTR(path.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    HANDLE::default(),
                )
            }) else {
                return Signature::Unknown;
            };
            let result = (|| {
                let mut hash = [0u8; 64];
                let mut length = hash.len() as u32;
                unsafe {
                    CryptCATAdminCalcHashFromFileHandle2(
                        admin,
                        handle,
                        &mut length,
                        Some(hash.as_mut_ptr()),
                        0,
                    )
                }
                .map_err(|_| Signature::Unknown)?;
                let hash = &hash[..length as usize];
                let catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin, hash, 0, None) };
                if catalog == 0 {
                    return Err(Signature::Unsigned);
                }
                let mut info = CATALOG_INFO {
                    cbStruct: size_of::<CATALOG_INFO>() as u32,
                    ..Default::default()
                };
                let found = unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) };
                unsafe {
                    let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                }
                found.map_err(|_| Signature::Unknown)?;
                let tag = wide(
                    &hash
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect::<String>(),
                );
                let mut member = WINTRUST_CATALOG_INFO {
                    cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                    pcwszMemberTag: PCWSTR(tag.as_ptr()),
                    pcwszMemberFilePath: PCWSTR(path.as_ptr()),
                    hMemberFile: handle,
                    pbCalculatedFileHash: hash.as_ptr() as *mut u8,
                    cbCalculatedFileHash: hash.len() as u32,
                    hCatAdmin: admin,
                    ..Default::default()
                };
                let data = WINTRUST_DATA {
                    dwUnionChoice: WTD_CHOICE_CATALOG,
                    Anonymous: WINTRUST_DATA_0 {
                        pCatalog: &mut member,
                    },
                    ..trust_data()
                };
                match verify(data) {
                    (0, signer) => Ok(Signature::Signed(signer.unwrap_or_default())),
                    _ => Err(Signature::Unsigned),
                }
            })();
            unsafe {
                let _ = CloseHandle(handle);
            }
            result.unwrap_or_else(|signature| signature)
        }
    }

    // Offline only: no revocation fetches, cache-only URL retrieval, no UI.
    fn trust_data() -> WINTRUST_DATA {
        WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        }
    }

    fn verify(mut data: WINTRUST_DATA) -> (u32, Option<String>) {
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let code = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        } as u32;
        let signer = (code == 0)
            .then(|| signer_name(data.hWVTStateData))
            .flatten();
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
        }
        (code, signer)
    }

    fn signer_name(state: HANDLE) -> Option<String> {
        unsafe {
            let provider = WTHelperProvDataFromStateData(state);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, BOOL(0), 0);
            if signer.is_null() {
                return None;
            }
            let cert = WTHelperGetProvCertFromChain(signer, 0);
            if cert.is_null() || (*cert).pCert.is_null() {
                return None;
            }
            let mut name = [0u16; 256];
            let length = CertGetNameStringW(
                (*cert).pCert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            );
            (length > 1).then(|| String::from_utf16_lossy(&name[..length as usize - 1]))
        }
    }

    fn image_path(pid: u32) -> Option<String> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        };
        unsafe {
            let _ = CloseHandle(process);
        }
        result.ok()?;
        Some(String::from_utf16_lossy(&buffer[..length as usize]))
    }

    fn version_strings(path: &[u16]) -> (Option<String>, Option<String>) {
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), None) };
        if size == 0 {
            return (None, None);
        }
        let mut block = vec![0u8; size as usize];
        if unsafe { GetFileVersionInfoW(PCWSTR(path.as_ptr()), 0, size, block.as_mut_ptr().cast()) }
            .is_err()
        {
            return (None, None);
        }
        let query = |sub: &str| -> Option<(*const u16, u32)> {
            let mut value = std::ptr::null_mut();
            let mut length = 0u32;
            let sub = wide(sub);
            let found = unsafe {
                VerQueryValueW(
                    block.as_ptr().cast(),
                    PCWSTR(sub.as_ptr()),
                    &mut value,
                    &mut length,
                )
            };
            (found.as_bool() && !value.is_null() && length > 0)
                .then_some((value as *const u16, length))
        };
        let Some((translation, length)) = query("\\VarFileInfo\\Translation") else {
            return (None, None);
        };
        if length < 4 {
            return (None, None);
        }
        let (language, codepage) = unsafe { (*translation, *translation.add(1)) };
        let string = |name: &str| {
            let (value, length) = query(&format!(
                "\\StringFileInfo\\{language:04x}{codepage:04x}\\{name}"
            ))?;
            let text = unsafe { std::slice::from_raw_parts(value, length as usize) };
            let text = String::from_utf16_lossy(text)
                .trim_end_matches('\0')
                .trim()
                .to_owned();
            (!text.is_empty()).then_some(text)
        };
        (string("CompanyName"), string("OriginalFilename"))
    }
}

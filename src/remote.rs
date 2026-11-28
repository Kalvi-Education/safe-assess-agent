//! Remote-session (D7) and installed remote-access service (D8) observations.
//! Only fixed catalog service names are queried; no service inventory is read or returned.

use crate::probes::Finding;

pub const CATEGORY: &str = "remote-desktop";

/// (finding id suffix, label, Windows service names, macOS launchd plist file names)
pub const SERVICES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "anydesk",
        "AnyDesk",
        &["AnyDesk"],
        &[
            "com.philandro.anydesk.service.plist",
            "com.philandro.anydesk.Helper.plist",
        ],
    ),
    (
        "teamviewer",
        "TeamViewer",
        &["TeamViewer"],
        &[
            "com.teamviewer.service.plist",
            "com.teamviewer.Helper.plist",
        ],
    ),
    (
        "rustdesk",
        "RustDesk",
        &["RustDesk"],
        &[
            "com.carriez.RustDesk_service.plist",
            "com.carriez.RustDesk_server.plist",
        ],
    ),
    // Getscreen: Linux unit `getscreen.me.service` confirmed from the vendor .deb. Windows service
    // and macOS launchd names are unconfirmed (need an installed copy) and intentionally empty.
    ("getscreen", "Getscreen.me", &[], &[]),
    (
        "chrome-remote-desktop",
        "Chrome Remote Desktop",
        &["chromoting"],
        &["org.chromium.chromoting.plist"],
    ),
    (
        "vnc",
        "VNC",
        &["tvnserver", "uvnc_service", "vncserver"],
        &["com.realvnc.vncserver.plist"],
    ),
    (
        "splashtop",
        "Splashtop",
        &["SplashtopRemoteService"],
        &["com.splashtop.streamer-daemon.plist"],
    ),
    ("parsec", "Parsec", &["Parsec"], &[]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Absent,
    Installed,
    Running,
    Unknown,
}

#[derive(Debug, Default)]
pub struct Observations {
    pub remote_session: Option<bool>,
    pub remote_control: Option<bool>,
    /// One entry per SERVICES row, in order.
    pub services: Vec<ServiceState>,
}

impl Observations {
    pub fn incomplete(&self) -> bool {
        self.services.len() != SERVICES.len()
            || self.services.contains(&ServiceState::Unknown)
            || (cfg!(target_os = "windows")
                && (self.remote_session.is_none() || self.remote_control.is_none()))
    }

    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut push = |id: String, label: String| {
            findings.push(Finding {
                id,
                category: CATEGORY,
                label,
                process_count: None,
                display_count: None,
                window_count: None,
            })
        };
        if self.remote_session == Some(true) {
            push("remote:session".into(), "Remote desktop session".into());
        }
        if self.remote_control == Some(true) {
            push(
                "remote:controlled".into(),
                "Session is being remotely controlled".into(),
            );
        }
        for ((id, label, _, _), state) in SERVICES.iter().zip(&self.services) {
            match state {
                ServiceState::Running => push(
                    format!("remote:service-running:{id}"),
                    format!("{label} remote-access service running"),
                ),
                ServiceState::Installed => push(
                    format!("remote:service-installed:{id}"),
                    format!("{label} remote-access service installed"),
                ),
                ServiceState::Absent | ServiceState::Unknown => {}
            }
        }
        findings
    }
}

#[cfg(target_os = "windows")]
pub fn scan() -> Observations {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "user32")]
    extern "system" {
        fn GetSystemMetrics(index: i32) -> i32;
    }
    #[repr(C)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
        fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
        fn QueryServiceStatus(service: Handle, status: *mut ServiceStatus) -> i32;
        fn CloseServiceHandle(handle: Handle) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
    }
    const SM_REMOTESESSION: i32 = 0x1000;
    const SM_REMOTECONTROL: i32 = 0x2001;
    const SC_MANAGER_CONNECT: u32 = 0x1;
    const SERVICE_QUERY_STATUS: u32 = 0x4;
    const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
    const SERVICE_STOPPED: u32 = 1;

    // GetSystemMetrics has no failure signal; 0 is a valid "not remote" answer.
    let mut observations = Observations {
        remote_session: Some(unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0),
        remote_control: Some(unsafe { GetSystemMetrics(SM_REMOTECONTROL) } != 0),
        services: Vec::new(),
    };
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        observations.services = vec![ServiceState::Unknown; SERVICES.len()];
        return observations;
    }
    for (_, _, names, _) in SERVICES {
        let mut state = ServiceState::Absent;
        for name in *names {
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let service = unsafe { OpenServiceW(manager, wide.as_ptr(), SERVICE_QUERY_STATUS) };
            let this = if service.is_null() {
                if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                    ServiceState::Absent
                } else {
                    ServiceState::Unknown
                }
            } else {
                let mut status = std::mem::MaybeUninit::<ServiceStatus>::zeroed();
                let queried = unsafe { QueryServiceStatus(service, status.as_mut_ptr()) } != 0;
                unsafe { CloseServiceHandle(service) };
                // An existing service whose state cannot be read is still installed.
                if queried && unsafe { status.assume_init() }.current_state != SERVICE_STOPPED {
                    ServiceState::Running
                } else {
                    ServiceState::Installed
                }
            };
            state = strongest(state, this);
        }
        observations.services.push(state);
    }
    unsafe { CloseServiceHandle(manager) };
    observations
}

#[cfg(target_os = "macos")]
pub fn scan() -> Observations {
    let mut dirs = vec![
        std::path::PathBuf::from("/Library/LaunchDaemons"),
        std::path::PathBuf::from("/Library/LaunchAgents"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(std::path::Path::new(&home).join("Library/LaunchAgents"));
    }
    let services = SERVICES
        .iter()
        .map(|(_, _, _, plists)| {
            plists
                .iter()
                .flat_map(|plist| dirs.iter().map(move |dir| dir.join(plist)))
                .map(|path| match path.try_exists() {
                    Ok(true) => ServiceState::Installed,
                    Ok(false) => ServiceState::Absent,
                    Err(_) => ServiceState::Unknown,
                })
                .fold(ServiceState::Absent, strongest)
        })
        .collect();
    // macOS remote/screen-sharing session state has no stable public API; left unobserved.
    Observations {
        remote_session: None,
        remote_control: None,
        services,
    }
}

/// Linux systemd unit names (without `.service`) per SERVICES row, same order.
#[cfg(target_os = "linux")]
const LINUX_UNITS: &[&[&str]] = &[
    &["anydesk"],
    &["teamviewerd"],
    &["rustdesk"],
    &["getscreen.me"],
    &["chrome-remote-desktop", "chrome-remote-desktop@"],
    &["x11vnc", "vncserver", "tigervncserver", "wayvnc", "xrdp"],
    &["SplashtopStreamer"],
    &["parsec"],
];

/// Unit file present in a systemd search path = installed. A `/proc/<pid>/comm` match
/// elsewhere reports Running; the unit directory cannot say whether it is started.
#[cfg(target_os = "linux")]
pub fn linux_unit_installed(dirs: &[&std::path::Path], unit: &str) -> ServiceState {
    let mut state = ServiceState::Absent;
    for dir in dirs {
        match dir.join(format!("{unit}.service")).try_exists() {
            Ok(true) => return ServiceState::Installed,
            Ok(false) => {}
            Err(_) => state = ServiceState::Unknown,
        }
    }
    state
}

/// SSH or an xrdp session marks a remote session. Local graphical sessions report `false`;
/// a missing variable never proves the session is local, so this is best-effort.
#[cfg(target_os = "linux")]
pub fn linux_remote_session(ssh_connection: bool, xrdp_session: bool) -> bool {
    ssh_connection || xrdp_session
}

#[cfg(target_os = "linux")]
pub fn scan() -> Observations {
    use std::path::Path;
    let dirs: [&Path; 3] = [
        Path::new("/etc/systemd/system"),
        Path::new("/lib/systemd/system"),
        Path::new("/usr/lib/systemd/system"),
    ];
    let services = LINUX_UNITS
        .iter()
        .map(|units| {
            units
                .iter()
                .map(|unit| linux_unit_installed(&dirs, unit))
                .fold(ServiceState::Absent, strongest)
        })
        .collect();
    let remote = linux_remote_session(
        std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some(),
        std::env::var_os("XRDP_SESSION").is_some(),
    );
    Observations {
        remote_session: Some(remote),
        remote_control: None,
        services,
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn scan() -> Observations {
    Observations::default()
}

pub fn strongest(a: ServiceState, b: ServiceState) -> ServiceState {
    use ServiceState::*;
    match (a, b) {
        (Running, _) | (_, Running) => Running,
        (Installed, _) | (_, Installed) => Installed,
        (Unknown, _) | (_, Unknown) => Unknown,
        _ => Absent,
    }
}

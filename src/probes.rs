use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Available,
    Unsupported,
    Error,
    NotChecked,
}

#[derive(Debug, Serialize)]
pub struct Capability {
    pub status: Status,
    pub limitation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub processes: Capability,
    pub displays: Capability,
    pub overlays: Capability,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub category: &'static str,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_count: Option<usize>,
}

const PROCESS_LIMITATION: &str = "Visible process names only; exact catalog matches are not verified identities or evidence of active use. Hidden, renamed, inaccessible and browser-hosted applications may be missed. No executable paths, arguments, PIDs or full process inventory are returned.";
const DISPLAY_LIMITATION: &str = "Active logical displays only; mirrors, virtual displays and physical monitors cannot be reliably distinguished. A single display does not exclude external capture.";

pub fn capabilities() -> Capabilities {
    let supported = cfg!(any(target_os = "macos", target_os = "windows"));
    Capabilities {
        processes: Capability {
            status: if supported {
                Status::NotChecked
            } else {
                Status::Unsupported
            },
            limitation: PROCESS_LIMITATION,
        },
        displays: Capability {
            status: if supported {
                Status::NotChecked
            } else {
                Status::Unsupported
            },
            limitation: DISPLAY_LIMITATION,
        },
        overlays: Capability {
            status: if supported {
                Status::NotChecked
            } else {
                Status::Unsupported
            },
            limitation: crate::overlays::LIMITATION,
        },
    }
}

// Exact executable basenames, not substring matches against private paths.
const APPLICATIONS: &[(&str, &str, &str, &[&str])] = &[
    ("anydesk", "remote-desktop", "AnyDesk", &["anydesk"]),
    (
        "teamviewer",
        "remote-desktop",
        "TeamViewer",
        &["teamviewer", "teamviewer_service", "teamviewer_desktop"],
    ),
    ("rustdesk", "remote-desktop", "RustDesk", &["rustdesk"]),
    (
        "chrome-remote-desktop",
        "remote-desktop",
        "Chrome Remote Desktop",
        &["remoting_host", "remotedesktophost"],
    ),
    (
        "vnc",
        "remote-desktop",
        "VNC",
        &["vncserver", "tvnserver", "winvnc"],
    ),
    (
        "rdp",
        "remote-desktop",
        "Remote Desktop client",
        &["mstsc", "msrdc"],
    ),
    (
        "cluely",
        "ai-assistant",
        "Cluely",
        &["cluely", "cluely helper", "cluely helper (renderer)"],
    ),
    (
        "interview-coder",
        "ai-assistant",
        "Interview Coder",
        &["interview-coder", "interviewcoder"],
    ),
    ("chatgpt", "ai-assistant", "ChatGPT", &["chatgpt"]),
    (
        "claude",
        "ai-assistant",
        "Claude",
        &["claude", "claude helper", "claude helper (renderer)"],
    ),
    ("ollama", "ai-assistant", "Ollama", &["ollama"]),
    (
        "lm-studio",
        "ai-assistant",
        "LM Studio",
        &["lm studio", "lmstudio"],
    ),
    (
        "obs",
        "screen-recorder",
        "OBS Studio",
        &["obs", "obs64", "obs32", "obs-studio"],
    ),
    ("sharex", "screen-recorder", "ShareX", &["sharex"]),
    ("loom", "screen-recorder", "Loom", &["loom", "loom helper"]),
    ("zoom", "communication", "Zoom", &["zoom", "zoom.us"]),
    (
        "discord",
        "communication",
        "Discord",
        &["discord", "discord helper", "discord helper (renderer)"],
    ),
    (
        "teams",
        "communication",
        "Microsoft Teams",
        &["teams", "ms-teams", "msteams"],
    ),
    (
        "slack",
        "communication",
        "Slack",
        &["slack", "slack helper", "slack helper (renderer)"],
    ),
    (
        "vscode",
        "editor",
        "Visual Studio Code",
        &["code", "code helper", "code helper (renderer)"],
    ),
    ("sublime", "editor", "Sublime Text", &["sublime_text"]),
];

pub fn group_applications<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<Finding> {
    let mut counts = [0usize; APPLICATIONS.len()];
    for name in names {
        let normalized = name.to_ascii_lowercase();
        let basename = normalized.strip_suffix(".exe").unwrap_or(&normalized);
        for (index, (_, _, _, aliases)) in APPLICATIONS.iter().enumerate() {
            if aliases.contains(&basename) {
                counts[index] += 1;
                break;
            }
        }
    }
    APPLICATIONS
        .iter()
        .zip(counts)
        .filter(|(_, count)| *count > 0)
        .map(|((id, category, label, _), count)| Finding {
            id: format!("application:{id}"),
            category,
            label: (*label).to_string(),
            process_count: Some(count),
            display_count: None,
            window_count: None,
        })
        .collect()
}

pub fn apply_display_result(
    capability: &mut Capability,
    result: Result<u32, &'static str>,
    findings: &mut Vec<Finding>,
) {
    match result {
        Ok(count) if count > 0 => {
            capability.status = Status::Available;
            capability.limitation = DISPLAY_LIMITATION;
            if count > 1 {
                findings.push(Finding {
                    id: "display:multiple-active".into(),
                    category: "display",
                    label: "Multiple active logical displays".to_string(),
                    process_count: None,
                    display_count: Some(count),
                    window_count: None,
                });
            }
        }
        Ok(_) => {
            capability.status = Status::Error;
            capability.limitation =
                "Display enumeration returned no active displays; display state is unknown.";
        }
        Err(message) => {
            capability.status = Status::Error;
            capability.limitation = message;
        }
    }
}

pub fn scan() -> (Capabilities, Vec<Finding>) {
    #[allow(unused_mut)]
    let mut caps = capabilities();
    #[allow(unused_mut)]
    let mut findings = Vec::new();
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        // sysinfo has no enumeration error result. An empty snapshot or absence of
        // our own process is treated as a failed probe, never a clean machine.
        let self_visible = system
            .processes()
            .contains_key(&sysinfo::Pid::from_u32(std::process::id()));
        if !self_visible || system.processes().is_empty() {
            caps.processes.status = Status::Error;
            caps.processes.limitation =
                "Process enumeration did not include this agent; process state is unknown.";
        } else {
            caps.processes.status = Status::Available;
            findings = group_applications(
                system
                    .processes()
                    .values()
                    .filter_map(|process| process.name().to_str()),
            );
        }
        apply_display_result(&mut caps.displays, display_count(), &mut findings);
        crate::overlays::apply(crate::overlays::scan(), &mut caps.overlays, &mut findings);
    }
    (caps, findings)
}

#[cfg(target_os = "macos")]
fn display_count() -> Result<u32, &'static str> {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGGetActiveDisplayList(max_displays: u32, displays: *mut u32, count: *mut u32) -> i32;
    }
    let mut count = 0;
    // CoreGraphics permits a null display array to query the active count.
    let result = unsafe { CGGetActiveDisplayList(0, std::ptr::null_mut(), &mut count) };
    if result == 0 {
        Ok(count)
    } else {
        Err("CoreGraphics display enumeration failed; display state is unknown.")
    }
}

#[cfg(target_os = "windows")]
fn display_count() -> Result<u32, &'static str> {
    use std::ffi::c_void;
    #[link(name = "user32")]
    extern "system" {
        fn EnumDisplayMonitors(
            hdc: *mut c_void,
            clip: *const c_void,
            callback: unsafe extern "system" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
                isize,
            ) -> i32,
            data: isize,
        ) -> i32;
    }
    unsafe extern "system" fn count_monitor(
        _: *mut c_void,
        _: *mut c_void,
        _: *mut c_void,
        data: isize,
    ) -> i32 {
        // EnumDisplayMonitors invokes the callback synchronously with our pointer.
        unsafe {
            *(data as *mut u32) += 1;
        }
        1
    }
    let mut count = 0u32;
    let result = unsafe {
        EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            count_monitor,
            (&mut count as *mut u32) as isize,
        )
    };
    if result != 0 {
        Ok(count)
    } else {
        Err("Windows display enumeration failed; display state is unknown.")
    }
}

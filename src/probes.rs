use crate::signing::{Executable, Signature};
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

const PROCESS_LIMITATION: &str = "Visible process names plus fixed-name remote-access service lookups and the Windows remote-session flag; exact catalog matches are not verified identities or evidence of active use. Hidden, renamed, inaccessible and browser-hosted applications may be missed; services that cannot be queried are not reported. No executable paths, arguments, PIDs, service inventory or full process inventory are returned.";
const DISPLAY_LIMITATION: &str = "Active logical displays only; mirrors, virtual displays and physical monitors cannot be reliably distinguished. A single display does not exclude external capture.";

pub fn capabilities() -> Capabilities {
    let supported = cfg!(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    ));
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
            status: if cfg!(any(target_os = "macos", target_os = "windows")) {
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
        "final-round-ai",
        "ai-assistant",
        "Final Round AI",
        &["final round ai", "finalroundai"],
    ),
    (
        "lockedin-ai",
        "ai-assistant",
        "LockedIn AI",
        &["lockedin ai", "lockedinai"],
    ),
    (
        "perplexity",
        "ai-assistant",
        "Perplexity",
        &["perplexity", "perplexity helper"],
    ),
    ("copilot", "ai-assistant", "Microsoft Copilot", &["copilot"]),
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
    // Assistive tools that register global hotkeys or keep clipboard history.
    // Reported as "editor" so existing HIBU/backend category contracts accept them.
    ("raycast", "editor", "Raycast", &["raycast"]),
    ("alfred", "editor", "Alfred", &["alfred"]),
    (
        "keyboard-maestro",
        "editor",
        "Keyboard Maestro",
        &["keyboard maestro", "keyboard maestro engine"],
    ),
    (
        "bettertouchtool",
        "editor",
        "BetterTouchTool",
        &["bettertouchtool"],
    ),
    (
        "autohotkey",
        "editor",
        "AutoHotkey",
        &["autohotkey", "autohotkey64", "autohotkeyu64"],
    ),
    (
        "powertoys",
        "editor",
        "PowerToys",
        &["powertoys", "powertoys.run"],
    ),
    ("maccy", "editor", "Maccy", &["maccy"]),
    ("paste", "editor", "Paste", &["paste"]),
    ("ditto", "editor", "Ditto", &["ditto"]),
    ("copyq", "editor", "CopyQ", &["copyq"]),
    // Automation runtimes: script-driven screen reading and input injection run on these.
    (
        "python",
        "editor",
        "Python runtime",
        &["python", "pythonw", "python3", "py"],
    ),
    ("nodejs", "editor", "Node.js runtime", &["node"]),
    // 0.2.4 catalog expansion (26 Nov 2026): student-facing apps that must not run during an assessment.
    ("parsec", "remote-desktop", "Parsec", &["parsecd", "parsec"]),
    (
        "splashtop",
        "remote-desktop",
        "Splashtop",
        &[
            "srstreamer",
            "strwinclt",
            "splashtop business",
            "splashtop streamer",
        ],
    ),
    (
        "ultraviewer",
        "remote-desktop",
        "UltraViewer",
        &["ultraviewer_desktop", "ultraviewer_service"],
    ),
    (
        "zoho-assist",
        "remote-desktop",
        "Zoho Assist",
        &["zohoassist", "zaservice", "zoho assist"],
    ),
    (
        "supremo",
        "remote-desktop",
        "Supremo",
        &["supremo", "supremoservice"],
    ),
    (
        "getscreen",
        "remote-desktop",
        "Getscreen.me",
        &["getscreen"],
    ),
    (
        "quick-assist",
        "remote-desktop",
        "Quick Assist",
        &["quickassist"],
    ),
    (
        "remote-utilities",
        "remote-desktop",
        "Remote Utilities",
        &["rutserv", "rfusclient"],
    ),
    (
        "dwservice",
        "remote-desktop",
        "DWService",
        &["dwagent", "dwagsvc"],
    ),
    (
        "nomachine",
        "remote-desktop",
        "NoMachine",
        &["nxserver", "nxplayer", "nxnode"],
    ),
    (
        "jump-desktop",
        "remote-desktop",
        "Jump Desktop",
        &["jump desktop", "jumpclient", "jump desktop connect"],
    ),
    (
        "screens",
        "remote-desktop",
        "Screens",
        &["screens 5", "screens for mac"],
    ),
    (
        "windows-app",
        "remote-desktop",
        "Windows App (Remote Desktop)",
        &["windows app", "microsoft remote desktop"],
    ),
    ("gemini", "ai-assistant", "Google Gemini", &["gemini"]),
    ("grok", "ai-assistant", "Grok", &["grok"]),
    ("deepseek", "ai-assistant", "DeepSeek", &["deepseek"]),
    ("poe", "ai-assistant", "Poe", &["poe.com", "poe-desktop"]),
    ("jan", "ai-assistant", "Jan", &["jan.ai", "jan-app"]),
    ("gpt4all", "ai-assistant", "GPT4All", &["gpt4all"]),
    ("msty", "ai-assistant", "Msty", &["msty"]),
    ("comet", "ai-assistant", "Perplexity Comet", &["comet"]),
    (
        "parakeet-ai",
        "ai-assistant",
        "Parakeet AI",
        &["parakeet ai", "parakeetai"],
    ),
    (
        "sensei-ai",
        "ai-assistant",
        "Sensei AI",
        &["sensei ai", "senseiai"],
    ),
    (
        "aiapply",
        "ai-assistant",
        "AIApply Interview Buddy",
        &["interview buddy", "aiapply"],
    ),
    (
        "grammarly",
        "ai-assistant",
        "Grammarly",
        &["grammarly", "grammarly desktop", "grammarlyforwindows"],
    ),
    ("notion-ai", "ai-assistant", "Notion", &["notion"]),
    ("cursor", "editor", "Cursor", &["cursor"]),
    (
        "windsurf",
        "editor",
        "Windsurf / Devin",
        &["windsurf", "devin"],
    ),
    ("zed", "editor", "Zed", &["zed"]),
    (
        "antigravity",
        "editor",
        "Google Antigravity",
        &["antigravity"],
    ),
    (
        "jetbrains",
        "editor",
        "JetBrains IDE",
        &[
            "idea64",
            "idea",
            "pycharm64",
            "pycharm",
            "webstorm64",
            "webstorm",
            "clion64",
            "goland64",
            "rider64",
            "datagrip64",
            "fleet",
        ],
    ),
    ("notepadpp", "editor", "Notepad++", &["notepad++"]),
    (
        "whatsapp",
        "communication",
        "WhatsApp",
        &["whatsapp", "whatsapp.root"],
    ),
    ("telegram", "communication", "Telegram", &["telegram"]),
    ("signal", "communication", "Signal", &["signal"]),
    ("messenger", "communication", "Messenger", &["messenger"]),
    ("skype", "communication", "Skype", &["skype"]),
    (
        "google-meet",
        "communication",
        "Google Meet",
        &["google meet"],
    ),
    (
        "webex",
        "communication",
        "Webex",
        &["webex", "ciscocollabhost", "atmgr"],
    ),
    ("element", "communication", "Element", &["element-desktop"]),
    ("viber", "communication", "Viber", &["viber"]),
    (
        "line",
        "communication",
        "LINE",
        &["line launcher", "lineapp"],
    ),
    ("wechat", "communication", "WeChat", &["wechat", "weixin"]),
    (
        "snagit",
        "screen-recorder",
        "Snagit",
        &["snagit32", "snagiteditor", "snagit"],
    ),
    (
        "camtasia",
        "screen-recorder",
        "Camtasia",
        &["camtasiastudio", "camtasia", "camrecorder"],
    ),
    ("bandicam", "screen-recorder", "Bandicam", &["bandicam"]),
    (
        "screenpal",
        "screen-recorder",
        "ScreenPal",
        &["screenpal", "screencast-o-matic"],
    ),
    (
        "cleanshot",
        "screen-recorder",
        "CleanShot X",
        &["cleanshot x"],
    ),
    ("greenshot", "screen-recorder", "Greenshot", &["greenshot"]),
    ("lightshot", "screen-recorder", "Lightshot", &["lightshot"]),
    (
        "xsplit",
        "screen-recorder",
        "XSplit",
        &["xsplit.core", "xsplitbroadcaster"],
    ),
    (
        "streamlabs",
        "screen-recorder",
        "Streamlabs",
        &["streamlabs obs", "streamlabs desktop"],
    ),
    (
        "manycam",
        "screen-recorder",
        "ManyCam (virtual camera)",
        &["manycam"],
    ),
    (
        "snap-camera",
        "screen-recorder",
        "Snap Camera (virtual camera)",
        &["snap camera"],
    ),
    ("autoit", "editor", "AutoIt", &["autoit3", "autoit3_x64"]),
    (
        "pulover",
        "editor",
        "Pulover's Macro Creator",
        &["macrocreator"],
    ),
    ("tinytask", "editor", "TinyTask", &["tinytask"]),
    (
        "power-automate",
        "editor",
        "Power Automate Desktop",
        &["pad.console.host", "pad.designer"],
    ),
    ("hammerspoon", "editor", "Hammerspoon", &["hammerspoon"]),
    ("espanso", "editor", "Espanso", &["espanso"]),
    ("textexpander", "editor", "TextExpander", &["textexpander"]),
    ("clipy", "editor", "Clipy", &["clipy"]),
    ("java", "editor", "Java runtime", &["java", "javaw"]),
    ("ruby", "editor", "Ruby runtime", &["ruby", "rubyw"]),
    ("deno", "editor", "Deno runtime", &["deno"]),
    ("bun", "editor", "Bun runtime", &["bun"]),
    (
        "powershell-ise",
        "editor",
        "PowerShell ISE",
        &["powershell_ise"],
    ),
    (
        "selenium",
        "editor",
        "Browser automation driver",
        &["chromedriver", "geckodriver", "msedgedriver"],
    ),
];

// Windows Authenticode signer / CompanyName, or macOS Developer Team ID, exact and
// case-insensitive. Catches renamed binaries (VM case 2). Microsoft- and Apple-signed tools
// cannot be told apart this way. Confirm values against real binaries before enforcement.
const PUBLISHERS: &[(&str, &[&str])] = &[
    (
        "anydesk",
        &["AnyDesk Software GmbH", "philandro Software GmbH"],
    ),
    (
        "teamviewer",
        &["TeamViewer Germany GmbH", "TeamViewer GmbH"],
    ),
    ("zoom", &["Zoom Video Communications, Inc."]),
    // macOS Team IDs below were read with `codesign -dv` from installed apps (26 Nov 2026).
    ("discord", &["Discord Inc.", "53Q6R32WPB"]),
    ("chatgpt", &["2DC432GLL2"]),
    ("lm-studio", &["D65G88RHWN"]),
    ("perplexity", &["7S8W4W365S"]),
    ("python", &["Python Software Foundation"]),
    ("nodejs", &["OpenJS Foundation"]),
    // macOS Team IDs from `codesign -dv` on installed apps (26 Nov 2026, Ayush's Mac).
    ("whatsapp", &["WhatsApp LLC", "WhatsApp Inc.", "57T9237FN3"]),
    (
        "telegram",
        &["Telegram FZ-LLC", "Telegram Messenger Inc", "6N38VWS5BX"],
    ),
    ("cursor", &["Anysphere Inc.", "VDXQ22DGB9"]),
    ("windsurf", &["Exafunction, Inc.", "83Z2LHX6XW"]),
    ("zed", &["Zed Industries, Inc.", "MQ55VZLNZQ"]),
    ("grammarly", &["Grammarly, Inc.", "W8F64X92K3"]),
    ("windows-app", &["UBF8T346G9"]),
    ("parsec", &["Parsec Cloud, Inc."]),
    ("splashtop", &["Splashtop Inc."]),
    ("ultraviewer", &["DucFabulous Co.,ltd"]),
    ("signal", &["Signal Messenger, LLC"]),
    ("webex", &["Cisco Systems, Inc."]),
    ("snagit", &["TechSmith Corporation"]),
    ("bandicam", &["Bandicam Company"]),
];

fn alias_index(name: &str) -> Option<usize> {
    let normalized = name.to_ascii_lowercase();
    let basename = normalized.strip_suffix(".exe").unwrap_or(&normalized);
    APPLICATIONS
        .iter()
        .position(|(_, _, _, aliases)| aliases.contains(&basename))
}

fn catalog_index(name: &str, executable: Option<&Executable>) -> Option<usize> {
    alias_index(name).or_else(|| {
        let executable = executable?;
        if let Some(index) = executable
            .original_filename
            .as_deref()
            .and_then(alias_index)
        {
            return Some(index);
        }
        let signer = match &executable.signature {
            Signature::Signed(signer) => Some(signer.as_str()),
            _ => None,
        };
        [signer, executable.company.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|publisher| {
                let (id, _) = PUBLISHERS.iter().find(|(_, names)| {
                    names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(publisher))
                })?;
                APPLICATIONS.iter().position(|(app, ..)| app == id)
            })
    })
}

pub fn group_applications<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<Finding> {
    group_processes(names.into_iter().map(|name| (name, None)))
}

/// Catalog matches by name, original filename or publisher, plus counts of unsigned
/// (other than SafeAgent itself) and user-writable-path processes for server-side
/// review; signature `Unknown` is never counted as unsigned.
pub fn group_processes<'a>(
    processes: impl IntoIterator<Item = (&'a str, Option<&'a Executable>)>,
) -> Vec<Finding> {
    let mut counts = [0usize; APPLICATIONS.len()];
    let (mut unsigned, mut user_writable) = (0usize, 0usize);
    for (name, executable) in processes {
        if let Some(index) = catalog_index(name, executable) {
            counts[index] += 1;
        }
        if let Some(executable) = executable.filter(|executable| !executable.is_self) {
            unsigned += usize::from(executable.unverified());
            user_writable += usize::from(executable.user_writable);
        }
    }
    let mut findings: Vec<Finding> = APPLICATIONS
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
        .collect();
    {
        for (id, label, count) in [
            ("executable:unsigned", "Unsigned programs running", unsigned),
            (
                "executable:user-writable-path",
                "Programs running from Downloads, Desktop, Documents or Temp",
                user_writable,
            ),
        ] {
            if count > 0 {
                findings.push(Finding {
                    id: id.into(),
                    category: "unverified",
                    label: label.into(),
                    process_count: Some(count),
                    display_count: None,
                    window_count: None,
                });
            }
        }
    }
    findings
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
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
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
            let mut identifier = crate::signing::Identifier::default();
            let identities: Vec<_> = system
                .processes()
                .iter()
                .filter_map(|(pid, process)| {
                    let name = process.name().to_str()?;
                    Some((name, identifier.identify(pid.as_u32())))
                })
                .collect();
            findings = group_processes(
                identities
                    .iter()
                    .map(|(name, executable)| (*name, executable.as_deref())),
            );
            // Unqueryable services stay unreported rather than failing the probe:
            // per-service ACLs vary and must not turn honest machines into PROBE_FAILED.
            findings.extend(crate::remote::scan().findings());
            findings.extend(crate::environment::finding(crate::environment::scan()));
        }
        apply_display_result(&mut caps.displays, display_count(), &mut findings);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        crate::overlays::apply(crate::overlays::scan(), &mut caps.overlays, &mut findings);
        // Linux: Wayland does not let ordinary clients list other apps' windows and X11 window
        // metadata is not read yet, so overlays stay explicitly unsupported (never clean, never
        // PROBE_FAILED).
        #[cfg(target_os = "linux")]
        {
            caps.overlays.status = Status::Unsupported;
            caps.overlays.limitation = "Overlay and capture-exclusion windows are not observable on Linux; this is not a clean result.";
        }
    }
    (caps, findings)
}

/// Connected DRM connectors (`status` file = "connected"). Works on X11 and Wayland.
#[cfg(target_os = "linux")]
fn display_count() -> Result<u32, &'static str> {
    let entries = std::fs::read_dir("/sys/class/drm")
        .map_err(|_| "Linux display enumeration failed; /sys/class/drm unavailable.")?;
    let mut count = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        // Connector directories look like card0-HDMI-A-1; skip card0 and renderD*.
        if !name.to_string_lossy().contains('-') {
            continue;
        }
        if let Ok(status) = std::fs::read_to_string(entry.path().join("status")) {
            count += u32::from(status.trim() == "connected");
        }
    }
    Ok(count)
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

use safeagent::{messaging, origin_allowed, probes, Connection, MAX_REQUEST_BYTES};
use serde_json::{json, Value};
use std::io::Cursor;

fn handle_request(bytes: &[u8]) -> safeagent::Reply {
    Connection::default().handle_request(bytes)
}

fn request(command: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocolVersion": 2,
        "requestId": "12345678-1234-4234-8234-123456789abc",
        "command": command,
        "challenge": "0123456789abcdef"
    }))
    .unwrap()
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_ne_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

fn decode(bytes: &[u8]) -> Value {
    let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    serde_json::from_slice(&bytes[4..4 + length]).unwrap()
}

#[test]
fn replies_preserve_correlation_and_do_not_claim_hello_scanned() {
    let reply = handle_request(&request("hello"));
    assert!(reply.ok);
    assert_eq!(
        reply.request_id.as_deref(),
        Some("12345678-1234-4234-8234-123456789abc")
    );
    assert_eq!(reply.challenge.as_deref(), Some("0123456789abcdef"));
    assert!(reply.observed_at > 0);
    assert!(reply.findings.is_empty());
    assert_ne!(
        reply.capabilities.processes.status,
        probes::Status::Available
    );
    assert_eq!(
        reply.capabilities.overlays.status,
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            probes::Status::NotChecked
        } else {
            probes::Status::Unsupported
        }
    );
    let check = handle_request(&request("check"));
    assert!(!check.ok);
    assert!(check.findings.is_empty());
    assert_eq!(check.error.as_ref().unwrap().code, "UNAUTHORIZED");
    assert_eq!(check.request_id, reply.request_id);
    assert_eq!(check.challenge, reply.challenge);
    assert!(check.observed_at >= reply.observed_at);
}

#[test]
fn hello_keeps_auth_binding_separate_from_correlation_and_connection_local() {
    let mut first = Connection::default();
    let hello = first.handle_request(&request("hello"));
    let repeated = first.handle_request(&request("hello"));
    let other = Connection::default().handle_request(&request("hello"));
    assert_eq!(hello.agent_instance_id, repeated.agent_instance_id);
    assert_eq!(hello.auth_challenge, repeated.auth_challenge);
    assert_ne!(hello.auth_challenge, hello.challenge);
    assert_ne!(hello.agent_instance_id, other.agent_instance_id);
    assert_ne!(hello.auth_challenge, other.auth_challenge);
    assert_eq!(hello.auth_challenge.unwrap().len(), 43);
    assert_eq!(hello.agent_instance_id.unwrap().len(), 22);
    assert_eq!(
        first
            .handle_request(&request("observe"))
            .error
            .unwrap()
            .code,
        "UNKNOWN_COMMAND"
    );
}

#[test]
fn frames_support_byte_at_a_time_reads() {
    struct SplitRead(Cursor<Vec<u8>>);
    impl std::io::Read for SplitRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = buffer.len().min(1);
            std::io::Read::read(&mut self.0, &mut buffer[..length])
        }
    }
    let mut input = SplitRead(Cursor::new(framed(&request("hello"))));
    let mut output = Vec::new();
    messaging(&mut input, &mut output).unwrap();
    assert_eq!(decode(&output)["ok"], true);
}

#[test]
fn unknown_command_is_an_explicit_correlated_error() {
    let reply = handle_request(&request("kill"));
    assert!(!reply.ok);
    assert_eq!(reply.error.unwrap().code, "UNKNOWN_COMMAND");
    assert!(reply.request_id.is_some());
}

#[test]
fn invalid_json_version_fields_and_bounds_are_rejected() {
    assert_eq!(handle_request(b"{").error.unwrap().code, "INVALID_JSON");
    for (key, value, code) in [
        ("protocolVersion", json!(1), "UNSUPPORTED_VERSION"),
        ("requestId", json!("not-a-uuid"), "INVALID_REQUEST"),
        ("challenge", json!("short"), "INVALID_REQUEST"),
        ("challenge", json!("a".repeat(129)), "INVALID_REQUEST"),
        ("challenge", json!("a b c d e f g h i"), "INVALID_REQUEST"),
        ("extra", json!(true), "INVALID_REQUEST"),
    ] {
        let mut input: Value = serde_json::from_slice(&request("hello")).unwrap();
        input[key] = value;
        assert_eq!(
            handle_request(&serde_json::to_vec(&input).unwrap())
                .error
                .unwrap()
                .code,
            code
        );
    }
    let duplicate = br#"{"protocolVersion":1,"protocolVersion":1,"requestId":"12345678-1234-4234-8234-123456789abc","challenge":"0123456789abcdef","command":"hello"}"#;
    assert_eq!(
        handle_request(duplicate).error.unwrap().code,
        "INVALID_REQUEST"
    );
}

#[test]
fn malformed_frames_fail_explicitly_and_end_stream() {
    for bytes in [vec![1, 0], framed(b"hello")[..6].to_vec(), vec![0, 0, 0, 0]] {
        let mut output = Vec::new();
        assert!(messaging(&mut Cursor::new(bytes), &mut output).is_err());
        assert_eq!(decode(&output)["error"]["code"], "MALFORMED_FRAME");
    }
}

#[test]
fn oversized_frame_is_rejected_before_reading_or_allocating_payload() {
    let mut output = Vec::new();
    let header = ((MAX_REQUEST_BYTES + 1) as u32).to_ne_bytes();
    assert!(messaging(&mut Cursor::new(header), &mut output).is_err());
    assert_eq!(decode(&output)["error"]["code"], "FRAME_TOO_LARGE");
    assert_eq!(
        handle_request(&vec![b' '; MAX_REQUEST_BYTES + 1])
            .error
            .unwrap()
            .code,
        "FRAME_TOO_LARGE"
    );
}

#[test]
fn eof_exits_and_invalid_json_does_not_desynchronize_next_frame() {
    let mut input = framed(b"{");
    input.extend(framed(&request("hello")));
    let mut output = Vec::new();
    messaging(&mut Cursor::new(input), &mut output).unwrap();
    assert_eq!(decode(&output)["error"]["code"], "INVALID_JSON");
    let offset = 4 + u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
    assert_eq!(decode(&output[offset..])["ok"], true);
    let mut empty = Vec::new();
    messaging(&mut Cursor::new([]), &mut empty).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn unsupported_and_probe_failure_are_distinct() {
    let mut capabilities = probes::capabilities();
    capabilities.overlays.status = probes::Status::Unsupported;
    let mut findings = Vec::new();
    probes::apply_display_result(&mut capabilities.displays, Err("OS failure"), &mut findings);
    assert_eq!(capabilities.displays.status, probes::Status::Error);
    assert_eq!(capabilities.overlays.status, probes::Status::Unsupported);
    assert!(findings.is_empty());
    probes::apply_display_result(&mut capabilities.displays, Ok(0), &mut findings);
    assert_eq!(capabilities.displays.status, probes::Status::Error);
    probes::apply_display_result(&mut capabilities.displays, Ok(2), &mut findings);
    assert_eq!(capabilities.displays.status, probes::Status::Available);
    assert_eq!(findings[0].display_count, Some(2));
}

#[test]
fn matching_groups_helpers_and_avoids_substring_false_positives() {
    let findings = probes::group_applications([
        "Discord.exe",
        "Discord Helper",
        "Discord Helper (Renderer)",
        "notdiscord",
        "coreparsecd",
        "OBS64.EXE",
    ]);
    assert_eq!(findings.len(), 2);
    let discord = findings
        .iter()
        .find(|finding| finding.id == "application:discord")
        .unwrap();
    assert_eq!(discord.process_count, Some(3));
    assert_eq!(discord.category, "communication");
}

#[test]
fn reports_hotkey_clipboard_and_ai_overlay_tools_by_exact_name() {
    let findings = probes::group_applications([
        "Raycast",
        "Maccy",
        "AutoHotkey64.exe",
        "Final Round AI",
        "Perplexity Helper",
        "raycastnotes",
        "pastebin",
    ]);
    let ids: Vec<&str> = findings.iter().map(|finding| finding.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "application:final-round-ai",
            "application:perplexity",
            "application:raycast",
            "application:autohotkey",
            "application:maccy",
        ]
    );
    let raycast = findings
        .iter()
        .find(|f| f.id == "application:raycast")
        .unwrap();
    assert_eq!(raycast.category, "editor");
    assert_eq!(raycast.label, "Raycast");
}

#[test]
fn origin_allowlist_is_strict_and_fail_closed() {
    let id = "abcdefghijklmnopabcdefghijklmnop";
    let origin = format!("chrome-extension://{id}/");
    assert!(origin_allowed(&origin, id));
    for config in [
        "",
        "*",
        "abcdefghijklmnopabcdefghijklmnop,",
        " abcdefghijklmnopabcdefghijklmnop",
    ] {
        assert!(!origin_allowed(&origin, config));
    }
    for origin in [
        format!("chrome-extension://{id}"),
        format!("chrome-extension://{id}/evil"),
        format!("https://{id}/"),
        "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".to_owned(),
    ] {
        assert!(!origin_allowed(&origin, id));
    }
}

#[test]
fn remote_observations_report_session_and_catalog_services_only() {
    use safeagent::remote::{strongest, Observations, ServiceState, CATEGORY, SERVICES};
    let mut services = vec![ServiceState::Absent; SERVICES.len()];
    services[0] = ServiceState::Running;
    services[1] = ServiceState::Installed;
    services[2] = ServiceState::Unknown;
    let observations = Observations {
        remote_session: Some(true),
        remote_control: Some(false),
        services,
    };
    let ids: Vec<_> = observations
        .findings()
        .into_iter()
        .map(|f| {
            assert_eq!(f.category, CATEGORY);
            assert!(f.process_count.is_none() && f.window_count.is_none());
            f.id
        })
        .collect();
    assert_eq!(
        ids,
        [
            "remote:session",
            "remote:service-running:anydesk",
            "remote:service-installed:teamviewer",
        ]
    );
    assert!(observations.incomplete());
    assert!(Observations::default().findings().is_empty());
    assert_eq!(
        strongest(ServiceState::Unknown, ServiceState::Installed),
        ServiceState::Installed
    );
    assert_eq!(
        strongest(ServiceState::Absent, ServiceState::Unknown),
        ServiceState::Unknown
    );
}

#[test]
fn renamed_binaries_match_by_original_filename_or_publisher() {
    use safeagent::signing::{Executable, Signature};
    let identity = |signature, company: Option<&str>, original: Option<&str>| Executable {
        signature,
        company: company.map(str::to_owned),
        original_filename: original.map(str::to_owned),
        user_writable: false,
        is_self: false,
    };
    let signed_anydesk = identity(
        Signature::Signed("AnyDesk Software GmbH".into()),
        None,
        None,
    );
    let stripped_anydesk = identity(Signature::Unsigned, Some("AnyDesk Software GmbH"), None);
    let renamed_obs = identity(Signature::Unknown, None, Some("obs64.exe"));
    let benign = identity(
        Signature::Signed("Spotify AB".into()),
        Some("Spotify AB"),
        None,
    );
    let findings = probes::group_processes([
        ("notes.exe", Some(&signed_anydesk)),
        ("helper.exe", Some(&stripped_anydesk)),
        ("video.exe", Some(&renamed_obs)),
        ("Spotify.exe", Some(&benign)),
        ("pythonw.exe", None),
    ]);
    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "application:anydesk",
            "application:obs",
            "application:python",
            "executable:unsigned",
        ]
    );
    assert_eq!(findings[0].process_count, Some(2));
}

#[test]
fn unverified_executables_are_counted_but_never_from_unknown_or_self() {
    use safeagent::signing::{Executable, Signature};
    let identity = |signature, user_writable, is_self| Executable {
        signature,
        company: None,
        original_filename: None,
        user_writable,
        is_self,
    };
    let unsigned = identity(Signature::Unsigned, true, false);
    let unknown = identity(Signature::Unknown, false, false);
    let agent = identity(Signature::Unsigned, true, true);
    let processes = [
        ("tool.exe", Some(&unsigned)),
        ("protected.exe", Some(&unknown)),
        ("safeagent.exe", Some(&agent)),
    ];
    let findings = probes::group_processes(processes);
    let summary: Vec<_> = findings
        .iter()
        .map(|f| (f.id.as_str(), f.category, f.process_count))
        .collect();
    assert_eq!(
        summary,
        [
            ("executable:unsigned", "unverified", Some(1)),
            ("executable:user-writable-path", "unverified", Some(1)),
        ]
    );
}

#[test]
fn user_writable_heuristic_covers_download_desktop_documents_temp_and_profile_root() {
    use safeagent::signing::user_writable;
    let profile = Some(r"C:\Users\student");
    let temp = Some(r"C:\Users\student\AppData\Local\Temp");
    for path in [
        r"C:\Users\student\Downloads\notes.exe",
        r"c:\users\STUDENT\desktop\x\y.exe",
        r"C:\Users\student\Documents\tool.exe",
        r"C:\Users\student\AppData\Local\Temp\a.exe",
        r"C:\Users\student\run.exe",
    ] {
        assert!(user_writable(path, profile, temp), "{path}");
    }
    for path in [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Users\student\AppData\Local\Programs\Microsoft VS Code\Code.exe",
        r"C:\Users\student\AppData\Local\Kalvium\SafeAgent\safeagent.exe",
        r"C:\Users\studentx\Downloads\a.exe",
    ] {
        assert!(!user_writable(path, profile, temp), "{path}");
    }
}

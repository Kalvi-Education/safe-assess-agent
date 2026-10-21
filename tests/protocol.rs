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

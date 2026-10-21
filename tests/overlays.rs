use safeagent::{
    overlays::{apply, Observations},
    probes::{capabilities, Status},
};

#[test]
fn mac_metadata_groups_properties_without_suppressing_system_windows() {
    let mut observations = Observations::default();
    observations.mac_window(Some(0), Some(1));
    observations.mac_window(Some(25), Some(0));
    observations.mac_window(Some(3), Some(0));
    observations.mac_window(Some(-1), Some(2));
    let mut caps = capabilities();
    let mut findings = Vec::new();
    apply(Ok(observations), &mut caps.overlays, &mut findings);
    assert_eq!(caps.overlays.status, Status::Available);
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|finding| finding.window_count == Some(2)));
    assert!(findings
        .iter()
        .all(|finding| finding.category == "overlay" && finding.process_count.is_none()));
}

#[test]
fn windows_requires_visible_topmost_and_layered_or_transparent() {
    let mut observations = Observations::default();
    observations.windows_window(false, Some(0x80008));
    observations.windows_window(true, Some(0x8));
    observations.windows_window(true, Some(0x80000));
    observations.windows_window(true, Some(0));
    observations.windows_window(true, Some(0x80008));
    observations.windows_window(true, Some(0x28));
    assert_eq!(observations.scanned, 5);
    assert_eq!(observations.elevated, 2);
    assert!(!observations.incomplete);
}

#[test]
fn missing_metadata_preserves_observations_but_never_reports_clean() {
    let mut observations = Observations::default();
    observations.mac_window(Some(3), None);
    observations.windows_window(true, None);
    let mut caps = capabilities();
    let mut findings = Vec::new();
    apply(Ok(observations), &mut caps.overlays, &mut findings);
    assert_eq!(caps.overlays.status, Status::Error);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].window_count, Some(1));
}

#[test]
fn unavailable_session_and_empty_enumeration_are_errors() {
    let mut caps = capabilities();
    let mut findings = Vec::new();
    apply(Err("API unavailable"), &mut caps.overlays, &mut findings);
    assert_eq!(caps.overlays.status, Status::Error);
    assert_eq!(caps.overlays.limitation, "API unavailable");
    apply(
        Ok(Observations::default()),
        &mut caps.overlays,
        &mut findings,
    );
    assert_eq!(caps.overlays.status, Status::Error);
    assert!(findings.is_empty());
}

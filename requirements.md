# SafeAgent requirements

Status: assessment-scoped **observation**, default off. Enforcement is deferred. Source implementation is not production rollout or end-to-end acceptance evidence.

## Scope and ownership

SafeAgent is a user-level Rust application in Nucleus targeting Windows x64 and macOS arm64/x64. Linux observations are unsupported; no Linux package is provided. HIBU remains in its existing repository. The observation demonstration requires **macOS**, with at least one real native signal; this does not certify the other targets. Existing browser enrollment remains authoritative for browser eligibility. Installing SafeAgent does not enroll a browser.

- REQ-1: Provide fresh version/capability information and bounded read-only checks over Chrome Native Messaging. Missing, unsupported, failed and disconnected observations must never become clean results.
- REQ-2: Validate wire protocol 2, command, correlation ID, challenge, exact configured HIBU origins and frame bounds. Require exact-byte Ed25519 grants bound to the native connection and full capability set: v2 for monitoring, separate v3 for one-shot preflight. No legacy unauthenticated fallback, shared embedded secret or device attestation claim. A device owner can fabricate observations.
- REQ-3: Minimize collection to capability states and grouped application/display/window findings. No raw process inventory, paths, titles, screenshots, answers, keystrokes, memory or hardware fingerprint; no process termination.
- REQ-4: Retain independent Windows/macOS installers, exact native-host registration, repair and uninstall. Label unsigned development artifacts. Signed releases fail closed without real identities and notarization/signing prerequisites; signing is not an authenticated auto-update system.
- REQ-5: Disclose collection before consent: assessment scope, signals, cadence, recipients, retention, limitations and how to stop. Show connectivity, versions, freshness, failures and manual remediation. Collection ends on explicit stop, assessment exit/end or session expiry; transport loss creates a coverage gap, never a penalty. Existing V1, flag-off, preview and Admissions behavior stays unchanged.
- REQ-6: HIBU claims a short-lived pairing capability directly from the backend and keeps its report capability private from the page. It uploads authenticated, bounded reports directly, rather than treating page-supplied findings as authoritative. Native Messaging permission and collection remain explicitly enabled local/Dev features; no unrelated browsing/background collection.
- REQ-7: The backend binds an authenticated eligible student to the exact assessment in a short-lived session, issues fresh challenges and a versioned observation policy, and durably stores events. Events retain UUID, ordered sequence, client occurrence and server receipt timestamps, detector/confidence, versions and explicit failures. Exact retries are idempotent; conflicting replay, unrelated ownership and expired/closed-session writes are rejected.
- REQ-8: Expose owner and authorized staff timelines separating detections from coverage gaps. Findings are client-reported observations, **not cheating verdicts**. Enforce retention/read ACL boundaries; document the purge operation and any deployment prerequisites honestly.
- REQ-9: Keep native releases independent of Yarn/Turbo/web deployment. No agent update during an assessment. Document actual supported-platform verification, installer privileges, uninstall, signing blockers and manual authenticated release/rollback procedures.

## Advisory preflight and cross-PR requirements

Native 0.2.0 implements v3 one-shot preflight over wire v2; it does not deliver
the companion Student, HIBU, Assessment backend or BOA integration. Those owners
must satisfy [design.md](design.md), not treat draft source or native tests as
certification:

- Persist explicit consent before native access. Everyday enrollment/unrelated
  browsing must never connect/probe or claim installed/ready status.
- Owning Student JWT, never HIBU authority, owns durable, atomic, idempotent
  preflight create/issue/complete. Bind assessment, consent/policy, native instance/
  challenge and expiry without creating an attempt or active monitoring session.
- Coordinate the exact strict native grant/reply and minimized result mapping;
  reject incompatible fields rather than weakening validation. Preserve explicit
  unavailable/error states and unknown counts.
- HIBU owns bounded same-port transport and disconnect/cancellation. Preflight
  consumes once even on failure; ongoing monitoring requires separate consent,
  a fresh port and a signed v2 grant.
- Local/Dev preflight is advisory only, never admission-blocking. Default-off
  integration and distribution access need independent owner approval/telemetry;
  packaging does not enable either.

## Explicit non-goals

No new assessment start/admission gate, life deduction, automatic submission, process blocking, continuous surveillance outside the consented session, kernel driver, trusted-device attestation or universal embedded HMAC key. A missing agent or observed application does not authorize enforcement. Future enforcement needs separate product/security approval and an admission/recovery contract with answer preservation; it is not an acceptance condition for observation.

## Acceptance evidence required

1. On macOS, consent and create an authenticated assessment session, claim it from real HIBU, start collection, obtain a fresh backend challenge and persist at least one real native signal plus HIBU reporting. Inspect the durable owner/staff timeline, not just the page response.
2. Show a real known signal and manual save-work/quit/recheck remediation. Show version, confidence, capability limitations and explicit probe failure/unsupported states without asserting that an empty scan proves safety.
3. Disconnect HIBU/native transport and demonstrate coverage loss/heartbeat gaps and recovery, not cheating or penalties. End/stop the session and prove subsequent collection/uploads stop; expiry must also reject writes.
4. Retry an identical event and confirm one stored event/same receipt; reject conflicting UUID/sequence, stale/replaced challenges, unrelated student/assessment access and expired/closed-session events. Exact retry after challenge expiry is allowed only while the session remains open.
5. Confirm consent refusal/stop and missing/outdated agent do not add enforcement. Verify unchanged V1, Layer 2 flag-off, preview and Admissions behavior and no collection on unrelated pages.
6. Verify Student-owned advisory preflight consent, issuance, completion/retry/expiry, exact native binding and reply mapping without starting monitoring. Show unavailable results without admission blocking and require fresh separate authorization for monitoring.
7. Record actual macOS demonstration and remaining Windows/Intel, browser-installation, signed installer/permissions/uninstall and retention-purge evidence separately. Native framed smoke or compilation alone does not prove the complete flow.

See [protocol.md](protocol.md) for the implemented native contract,
[design.md](design.md) for cross-app contracts, [tasks.md](tasks.md) for acceptance
gates, [internal-dev.md](internal-dev.md) for Dev distribution and
[release.md](release.md) for dormant production tooling.

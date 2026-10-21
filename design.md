# SafeAgent architecture and integration boundaries

## Scope and ownership

The native deliverable is consented, assessment-scoped **observation**, not
enforcement. Windows x64 and macOS arm64/x64 are packaging targets; Linux
observations are unsupported. [protocol.md](protocol.md) is the implemented wire
contract. The cross-app contracts below are integration requirements, not evidence
that other PRs are merged, deployed or compatible.

| Component | Responsibility |
| --- | --- |
| SafeAgent Rust host | Bounded framing, local signature verification, read-only probes and minimized replies |
| HIBU extension | Same-port correlation/timeouts, private reporting capability, authenticated upload and failure classification |
| Student/shared Assessment V2 UI | Disclosure, explicit consent, lifecycle/status and manual remediation |
| Assessment monitoring backend | Student/assessment entitlement, grant signing, challenges, durable events, retention and timeline ACLs |
| BOA reviewer | Separate client-reported detections from coverage gaps; no cheating judgments |
| Native packaging/workflows | Independent installers, Dev artifacts and separately gated production signing/publication |

Browser enrollment and existing Layer 1 capture remain separate authorities.
Installing the host does not enroll a browser, consent to collection or start
monitoring. V1, flag-off, preview and Admissions flows must remain unchanged.

## Native trust boundary

Chrome launches `com.kalvium.safeagent` as its user over framed stdin/stdout.
Manifest origins and compiled exact extension IDs restrict browser-mediated
access; a locally supplied origin is not proof of the caller. There is no
localhost listener, privileged daemon, native networking or shared embedded secret.
A device owner can replace the host or fabricate replies. Installer signing
establishes artifact provenance, not truthful observations or trusted device time.

Only reviewed Ed25519 public keys enter the binary. The backend retains private
grant-signing keys and authenticates entitlement/consent before issuance. Native
binds exact signed bytes to its fresh connection instance/challenge, full capability
set and expiry. Missing/invalid grants never probe. Authorization is connection-local;
disconnect/restart discards it. Wall and monotonic expiry limit accepted grants,
but there is no immediate backend revocation or tamper-proof local clock.

| Mode (wire protocol 2) | Native behavior |
| --- | --- |
| `hello` | Metadata only, configuration readiness and fresh-connection binding; never exam readiness |
| `authorize` + `check` | Signed v2 monitoring grant, repeated full snapshots until expiry/disconnect; maximum grant lifetime 15 minutes |
| `preflight` | Signed v3 `assessment-preflight` grant, one snapshot, maximum lifetime 60 seconds; consumed before probing even on failure, no reusable monitoring authority |

The full processes/displays/overlays scope must be disclosed; scans are not
selectively scoped. Minimized grouped findings are heuristics. Unsupported,
error and notChecked states are not clean results. Native stdout contains only
protocol frames; errors use bounded safe codes/messages. There is no persistent
runtime diagnostic logging or user-facing diagnostic-mode flag. Any future
persistent diagnostics need a separately approved allowlisted schema, bounds,
retention and explicit opt-in; never include grants, raw metadata or student content.

## Assessment monitoring integration requirements

The companion HIBU, Assessment backend, Student and BOA changes must jointly
satisfy this contract; native tests cannot certify them. Monitoring is separate
from pre-admission preflight:

```text
Consented Student setup → backend pending session + pairing token
HIBU claims directly → private report token → Student starts claimed session
HIBU same-port hello → backend signed v2 grant → authorize → check
HIBU authenticated events → durable backend receipt → owner/staff timeline
Student stop / assessment end or exit / expiry → collection ends
```

### API and persistence contract

Base path: `/api/v2/monitoring`; direct JSON responses, not a `data` wrapper.
Existing V2 enablement and `ASSESSMENT_V2_MONITORING_ENABLED=true` are required;
disabled returns 404. This is a companion backend flag, not native configuration.

| Route | Required authority and behavior |
| --- | --- |
| `POST /sessions` `{assessmentSlug}` | Owning eligible Student JWT; pending two-hour session without creating an attempt, policy `observation-v1`, 15-second heartbeat, single-use two-minute pairing token |
| `POST /sessions/:sessionId/claim` `{pairingToken}` | Exact extension Origin; return private reportToken and policy directly to HIBU, never the page |
| `POST /sessions/:sessionId/start` | Owning Student JWT; claimed session required, idempotent start |
| `POST /sessions/:sessionId/challenge` | Exact extension Origin + reportToken; active session, 60-second challenge and nextSequence; refresh replaces prior challenge |
| `POST /sessions/:sessionId/native-authorization` `{agentInstanceId, challenge}` | Same extension authority, active session and default-off signing gate; exact protocol v2 grant capped by session expiry and 15 minutes; not pre-admission authorization |
| `POST /sessions/:sessionId/events` | Same extension authority; freshness/order validation and durable eventUUID/sequence/receivedAt/duplicate receipt |
| `POST /sessions/:sessionId/stop` | Owning Student JWT; idempotent stop, reject subsequent events |
| `GET /sessions?assessmentSlug=...`, `GET /sessions/:sessionId/timeline` | Owner-only student access; list at most 50 retained sessions |
| `GET /review/sessions?assessmentSlug=...&studentId=...`, `GET /review/sessions/:sessionId/timeline` | Existing `isAuthorOrMentor` ACL; both list filters required |

Event envelope: `{eventUUID, sequence, challenge, occurredAt, type, detector,
confidence, payload}`. Sequence starts at 1 and is strictly ordered; eventUUID
identifies retries. Client occurrence must be within 60 seconds of server time.
Types: heartbeat, native_signal, hibu_signal, coverage_lost, coverage_restored.
Detector is nonempty and at most 80 characters; confidence is observed/reported/
unknown. Payload is a JSON object at most 4096 bytes, excluding screenshots and
answers; carry agent/extension/protocol versions and explicit failure reasons.
Versions and observations remain client claims, not attested facts.

Store policyVersion, `trust: client_reported`, server receivedAt and a canonical
SHA-256 retry digest. An identical retry returns its receipt even after challenge
expiry while the session remains open; conflicting UUID/sequence and all
closed/expired-session writes fail. Never expose the challenge in timelines.
Distinguish malformed (400), invalid capability (401), origin/ownership/eligibility
(403), disabled/missing (404), state/replay/order (409), and expiry (410).

Summaries expose ownership, pending/active/stopped/expired state, policy/cadence,
claimed state and ISO lifecycle timestamps (null when not yet started/stopped).
Timeline events and separate coverageGaps must show a `heartbeat_missing` gap
after 45 seconds since start/last heartbeat, bounded by the next heartbeat, stop,
expiry or now. Gaps and detections are not cheating verdicts.

## Consented advisory preflight (native implemented; integration proposed)

The separate native v3 command is implemented; durable Student-owned integration
is still an acceptance requirement. Starting monitoring just to obtain a v2 grant
is not a pre-admission solution. Coordinate the strict [payload and response](protocol.md#preflight-native-implemented-advisory-integration-not-implemented):
no `sub` or `sessionId` is accepted in v3. Hello advertises contract version 1 /
grant version 3. Do not relax parsing or fall back to unauthenticated scans.

- Everyday enrollment/unrelated browsing must never connect, probe or assert
  installed/ready status. Persist explicit assessment-scoped consent before any
  native access; no enrollment-triggered background polling.
- Owning Student JWT, never HIBU authority, must own proposed create/issue/complete
  operations. Recheck eligibility/policy, disclose the full scope and do not
  create/start an attempt or monitoring session.
- Proposed `POST /api/v2/assessments/:slug/preflight` accepts consent and an
  idempotency key. Durably bind student, assessment, consent/policy version,
  native instance/challenge and issuance. Atomically issue an idempotent
  `{preflightId, expiresAt, authorization}` receipt with at most 60-second lifetime,
  bounded by native challenge validity; reject conflicting retries.
- HIBU must own bounded same-port hello → Student-owned issuance → preflight →
  disconnect, with timeouts and navigation/stop cancellation. Ongoing monitoring
  needs a separately consented session, fresh port and v2 grant.
- Proposed `POST /api/v2/assessments/:slug/preflight/:preflightId/complete` accepts
  bounded minimized client-reported results via the owning Student JWT. Atomically
  transition issued → completed/failed; return identical retry receipts and reject
  conflicting, expired or reused completion. Define cancellation/rate limits and
  abandoned-record expiry without background collection.
- Coordinate reply/category-to-persisted-result mapping. Preserve verified binding,
  partial probe errors and expiry behavior from protocol.md. An empty finding list
  does not supply a numeric display count; unknown counts remain unavailable.
- Agree token delivery, consent retention, freshness/one-time consumption and
  revocation exposure before implementation. No grants/report secrets in page
  storage/logs. Backend owns any future admission transaction; local/Dev results
  remain advisory, unavailable visible and **never admission-blocking**.

## Storage, operations and future policy

Companion PostgreSQL session/event migrations must be applied before use; source
changes do not apply them. Dev retention is seven days: read exclusion and physical
DELETE/cascade purge are separate acceptance gates. Do not infer a deployed purge
scheduler. Limit reads to owners/authorized staff; never log pairing/report tokens,
grants or raw device diagnostics. Session expiry is not retention.

No Kubernetes, Redis queue, AI service or native network daemon is required.
[Internal Dev](internal-dev.md) owns unsigned packaging/private GCS instructions;
[release.md](release.md) owns dormant signed production tooling and lifecycle.
Packaging, hashes and native smoke do not certify installed compatibility.

See [requirements.md](requirements.md) and [tasks.md](tasks.md) for acceptance.
Future enforcement needs separately approved capability/blocker policy, admission
transaction, telemetry, privacy/security review and recovery preserving answers.
It is neither implemented here nor required for the observation demonstration.

# SafeAgent acceptance checklist

Scope: consented assessment **observation**, with advisory preflight and no
admission enforcement. Checked items below describe source implementation, not
installed-device, cross-app or production certification. Record fresh acceptance
evidence with reviewed revisions, commands, device matrix and artifact hashes;
do not use historical test totals as current certification.

## Native implementation

- [x] Standalone Rust host, bounded wire v2 framing, strict correlation/origin
  checks and metadata-only hello/CLI check: [protocol.md](protocol.md).
- [x] Embedded public-key verification for signed v2 monitoring; same-port full
  scope, challenge consumption, replay/expiry checks and connection-local authority.
- [x] Separate signed v3 one-shot preflight: consume before probing even on
  failure, no reusable monitoring grant; monitoring v2 behavior retained.
- [x] Minimized read-only Windows/macOS probes with explicit limitations; Linux
  capabilities unsupported. No agent networking, daemon or process termination.
- [x] Independent Windows/macOS packaging; CI, internal Dev provenance/private
  GCS tooling and default-off production signing/publication paths.

## Cross-PR acceptance still required

The HIBU, Assessment backend, Student/shared V2 UI and BOA reviewer owners must
verify [design.md](design.md) and [requirements.md](requirements.md) together.
Native code or another PR's source alone does not close these gates.

- [ ] Approved extension identity, embedded public-key ring and matching backend
  signer; compatible versions and exact signed positive/negative handshakes.
- [ ] Real consented macOS monitoring: Student session → HIBU claim → server
  start → same-port native authorization/check → authenticated durable receipts →
  owner/staff reviewer timeline containing a real signal.
- [ ] Durable Student-owned preflight consent/create/issue/complete, idempotency,
  expiry/reuse rejection and exact native reply mapping; no active monitoring
  prerequisite. Dev remains advisory; unavailable never blocks admission.
- [ ] Known signal/manual quit/recheck, partial errors/unsupported capabilities,
  missing/outdated host and authorization-specific guidance without enforcement.
- [ ] Native/HIBU disconnect, heartbeat coverage gaps and recovery; explicit stop,
  assessment exit/end and expiry stop collection/uploads and reject later writes.
- [ ] Exact retry receipt/deduplication; conflicting UUID/sequence, stale/replaced
  challenge, unrelated ownership and expired/closed-session writes rejected.
- [ ] Everyday enrollment/unrelated browsing never connects/probes or asserts
  native readiness; consent refusal and V1, flag-off, preview and Admissions
  flows remain free of new collection/enforcement.
- [ ] Owner/staff ACLs, separate detections/coverage gaps, seven-day Dev retention
  read exclusion and physical purge of eligible rows with event cascade. Record
  migration/purge deployment prerequisites separately.
- [ ] Bounded availability, disconnect, authorization rejection/expiry and
  distribution telemetry; no grants, signed URLs, raw findings or student content.

## Distribution and device acceptance still required

- [ ] Provision reviewed-main/environment controls and approved Dev public keys;
  run all three internal Dev packaging targets. If using GCS, separately approve
  WIF/IAM, create-only publication and exact catalog; test the authenticated
  allowlisted download handoff independently. See [internal-dev.md](internal-dev.md).
- [ ] Record OS/version/architecture/Chrome matrix for Windows x64, macOS arm64
  and macOS x64; macOS-only demonstration is not Windows/Intel certification.
- [ ] Disposable-device Chrome registration, permission limits, consented signed
  probes, install/upgrade/repair/uninstall and manual compatible rollback. Include
  Unicode Windows paths, multiple profiles, macOS all-user running-process guards
  and failed/interrupted installation. Never modify an active assessment.
- [ ] Production approval, real signing/notarization credentials, protected tags/
  environments, signed package verification and trusted artifact hashes before
  enabling the dormant [production workflow](release.md).

## Verification boundaries

- Cargo unit/integration tests cover parsing, signatures, binding, expiry,
  pre-auth gating and synthetic probe behavior; they are not browser/installer tests.
- `packaging/smoke-native.py` launches a real binary for metadata and unauthorized
  rejection, not authorized OS coverage.
- The opt-in `binary-authorization` test uses an isolated host and ephemeral
  in-memory signer; authorized probe failure is permitted. It does not register
  or install a host, certify integration or validate an OS/browser matrix.
- Python provenance/catalog tests use synthetic installers and mocked storage;
  they do not prove live GCS IAM, real packages or signed download URLs.
- Workflow definitions are not evidence of execution, environment provisioning,
  device installation, signing/notarization or production deployment.

Future enforcement, broad rollout and automatic updates require separate approved
scope. They are not observation acceptance criteria.

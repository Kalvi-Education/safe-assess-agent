# SafeAgent protocol v2

Host: `com.kalvium.safeagent`. Read-only local signals, **not trusted attestation**.
This runtime is incompatible with HIBU protocol v1. HIBU/backend signing and
handshake integration are NOT implemented here. Keep integration rollout
**default OFF** until both support v2 and an approved compatibility record exists.
Never fall back to legacy unauthenticated scanning.

## Cross-PR compatibility checkpoint

HIBU draft #22 at `5f679162381e37bc75bcd3b57dcdf1348b70e539` implements
v2 active-session integration, including same-port binding, full capabilities,
expiry and approved-version checks. This is source verification, not deployed
compatibility approval. Its unauthenticated Layer 3 check is refused; hello is
metadata only. Normal browser enrollment must not initiate either operation.

Native now implements a separate one-shot `preflight` command with the strict v3
payload below. Monitoring wire v2/payload v2 remains unchanged and permits repeated
checks until expiry. The earlier backend draft containing `sub` is incompatible.
Backend/HIBU owners must coordinate this exact new response before implementation;
durable consent/create/issue/complete remains a proposed target, not end-to-end
functionality. See [design.md](design.md#consented-advisory-preflight-native-implemented-integration-proposed).

## Build configuration

See `.env.example`. `SAFEAGENT_ALLOWED_EXTENSION_IDS` and
`SAFEAGENT_AUTH_PUBLIC_KEYS` are embedded at Cargo compile time (`option_env!`),
not read from the runtime environment. Cargo does not load dotenv files.
Export reviewed values before building; rebuild for key rotation. No private
keys belong in the repository, extension, binary, or native release environment.

Public key ring format: comma-separated `keyId:base64urlPublicKey` entries,
without whitespace. Key IDs are 1..64 ASCII alphanumeric, underscore or hyphen.
Keys are unpadded base64url encodings of 32-byte Ed25519 public keys. Empty,
malformed, duplicate-ID or weak-key configuration rejects ALL authorizations
(`AUTH_CONFIG_INVALID`); no placeholder/default key or runtime override exists.
Multiple keys allow deliberate rotation; retired keys require a new binary.

## Invocation and transport

- `safeagent --version`: version only.
- `safeagent check`: diagnostic metadata only, empty findings, `UNAUTHORIZED`,
  nonzero exit. This is NOT an observation or exam-readiness check.
- `safeagent messaging chrome-extension://ID/` or Chrome's direct origin argument:
  framed stdio. Windows also accepts `--parent-window=DECIMAL`.

Compiled extension IDs must each contain exactly 32 lowercase `a`..`p`
characters. Missing/malformed configuration denies all messaging. Manifest
origins must match the compiled allowlist. An origin argument is defense in
 depth, not authentication against a device owner who can forge arguments.

Frames are native-endian u32 byte length followed by UTF-8 JSON (little-endian
on supported targets). Requests: 1..65536 bytes; replies: at most 1048576 bytes.
Bounds are enforced before allocation. Partial reads are supported. Replies
flush individually; stdout is frames only. EOF between frames exits normally.
Truncated, zero-length or oversized frames emit one error and close the stream.
Invalid complete JSON/request frames permit the next frame. Each `messaging`
invocation owns a new connection context; no global authorization or unsafe
state. OS randomness failure returns `RANDOM_UNAVAILABLE` and never scans.

## Requests and correlation

```json
{"protocolVersion":2,"requestId":"12345678-1234-4234-8234-123456789abc","command":"hello","challenge":"client-correlation-123"}
```

Exactly `protocolVersion`, `requestId`, `command`, `challenge`, plus optional
`authorization` (absent/null except authorize or preflight). Unknown/duplicate fields fail.
`requestId` must be a canonical lowercase hyphenated UUID. Every command uses
16..128 printable non-space ASCII bytes for the client `challenge`. These two
fields are echoed solely for request correlation: **neither is the authorization
challenge**. Clients must match both and enforce response timeouts.

Commands are only `hello`, `authorize`, `check`, `preflight`. No streaming/observe command.

### hello

Metadata only; never probes. Includes `preflightSupport: {contractVersion: 1, grantVersion: 3}`
(omitted on other replies). `authReadiness` is `ready` when the embedded key
ring is valid, or the stable code `AUTH_CONFIG_INVALID` when absent/malformed.
Hello remains `ok: true` in either case: transport success is not authorization
readiness. No key IDs, key material or parser details are returned. Other commands
return `authReadiness: null`. Clients must require `ready` before requesting a
grant; missing/malformed config still rejects authorize and unauthenticated check.
Returns `agentInstanceId` (16 random bytes,
base64url) and `authChallenge` (32 independently random bytes, base64url).
Both are generated once per connection. Repeated hello neither rotates them,
refreshes the challenge TTL, nor revokes/extends a grant. The challenge expires
60 seconds after connection-context creation using `Instant`. Reconnect to get
a fresh challenge after expiry or consumption.

### authorize

The `authorization` object has exactly these fields:

```text
{"keyId":"<configured ID>","payload":"<unpadded base64url JSON bytes>","signature":"<unpadded base64url detached 64-byte Ed25519 signature>"}
```

Decoded payload schema (example values are illustrative, not a valid grant):

```json
{"v":2,"audience":"kalvium.safeagent","sessionId":"12345678-1234-4234-8234-123456789abc","agentInstanceId":"<hello agentInstanceId>","challenge":"<hello authChallenge>","capabilities":["processes","displays","overlays"],"issuedAt":1700000000000,"expiresAt":1700000900000}
```

The backend signs the **exact decoded payload bytes**, not its base64 text or a
re-serialized JSON representation. No canonicalization is required. The native
agent selects the configured key by ID and uses Ed25519 `verify_strict` before
parsing the signed JSON, rejecting unknown/duplicate payload fields and wrong
types. Envelope and payload are separate from the detached signature.

Bindings: `v` exactly 2; audience exactly `kalvium.safeagent`; `sessionId` a
canonical lowercase hyphenated UUID; instance and challenge exact matches to
this connection. Backend integration must authenticate the user, establish
session entitlement/consent, and sign the intended session; the native agent
cannot query that entitlement. Replies bind observations to the accepted
session ID; callers must check it against their intended session.

**Full-set only:** capabilities must contain exactly processes, displays and
overlays, each once (order irrelevant). Subsets, duplicates and unknown names
are rejected because the current scan is not selectively scoped. No capability
is scanned before successful authorization. Unsupported OS capabilities remain
unsupported, not a clean pass.

Times are unsigned Unix epoch milliseconds: `issuedAt <= now < expiresAt`,
`issuedAt < expiresAt`, and `expiresAt - issuedAt <= 900000` (15 minutes).
There is no future-clock skew allowance. At acceptance, an `Instant` deadline
is set to the remaining wall-clock lifetime. Each check must pass BOTH wall
and monotonic deadlines. Clock rollback cannot extend the accepted grant;
rollback before issuedAt also denies checks. Expiry during a probe discards its
findings. This is not a trusted clock on a hostile/modified device.

Successful authorization consumes the challenge once but leaves the grant
valid until expiry/disconnect. Invalid attempts grant nothing and do not consume
the challenge. Re-authorizing a consumed challenge fails (including replay).
There is no refresh command, durable token, global state or immediate backend
revocation. Reconnect and repeat the handshake for renewal.

### check

Requires a current grant; performs one full snapshot. Missing/expired grants
return `UNAUTHORIZED` without calling probes. Expiry during a probe returns
`AUTH_EXPIRED` with no findings. `PROBE_FAILED` retains authorized partial
observations with explicit per-capability errors. Findings never automatically
mean cheating. Connection close/process exit discards the grant.

### preflight (native implemented; advisory integration not implemented)

Uses the same detached envelope, embedded keys and exact-byte Ed25519 verification
as authorize, but accepts only this strict payload (no `sub` or `sessionId`):

```json
{"v":3,"purpose":"assessment-preflight","audience":"kalvium.safeagent","preflightId":"12345678-1234-4234-8234-123456789abc","assessmentSlug":"example-assessment","agentInstanceId":"<hello agentInstanceId>","challenge":"<hello authChallenge>","capabilities":["processes","displays","overlays"],"issuedAt":1700000000000,"expiresAt":1700000060000}
```

`preflightId` is a canonical lowercase hyphenated UUID. `assessmentSlug` is nonblank
and at most 200 UTF-8 bytes. Random instance/challenge must exactly match native's
canonical unpadded base64url values. Full-set capability validation is unchanged.
Grant lifetime is at most 60000 ms; the existing 60-second monotonic challenge
lifetime also applies. Wall and monotonic grant deadlines are checked before and
after observation, including rollback before issuedAt. Unknown/duplicate fields
are rejected. `authorize` rejects v3; `preflight` rejects v2.

An accepted preflight consumes the challenge BEFORE scanning, including probe
failure or expiry during observation. It stores no reusable authorization.
Subsequent authorize/preflight return CHALLENGE_REUSED; check returns UNAUTHORIZED.
Monitoring-authorized connections reject preflight with CHALLENGE_REUSED without
altering the existing monitoring grant. Invalid grants do not consume a challenge.
Reconnect for a separately consented retry; hello does not reset consumption.

Exact response is the existing `Reply` below plus these optional fields:
- `preflightSupport` only on hello, as above.
- `purpose: "assessment-preflight"`, `preflightId`, `assessmentSlug` only after
  successful preflight grant verification (including subsequent probe failure or
  expiry). Unverified/rejected requests omit all three; never echo untrusted binding.
- `sessionId: null`, `authState: "unauthorized"` always for preflight: no reusable
  monitoring authority. `agentInstanceId`, `authChallenge`, `authReadiness` are null.
- On valid in-time observation, `authorizedCapabilities` is the signed full set,
  `expiresAt` is the signed epoch-ms expiry, and `observedAt` is the post-probe time.
  `ok: true` unless a capability is error: then `ok: false`, `error.code: PROBE_FAILED`
  with partial findings preserved. Unsupported capabilities are not clean passes.
- On expiry during observation: `ok: false`, `error.code: AUTH_EXPIRED`, findings [],
  metadata-only capabilities, authorizedCapabilities [], expiresAt null; verified
  purpose/id/slug remain present. Pre-verification errors use ordinary base replies.
- No additional count/result summary fields. Findings retain the existing schema;
  an empty finding list does NOT supply a numeric display count. Unknown/zero
  counts must remain explicitly unavailable in any minimized HIBU/backend mapping,
  never synthesized as 0 or 1 from absence of findings.

Backend/HIBU must agree on this exact response and category-to-minimized-result
mapping before implementing their integration. Consent must be durably recorded
before native access; authenticated owning Student JWT (never HIBU) owns proposed
create/issue/complete operations. No active monitoring session is required.
Unavailable results must be visible and never block admission; local/dev is
advisory only, with no enforcement in this implementation.

## Replies

All replies contain:

- `protocolVersion: 2`, `agentVersion`, `ok`.
- `requestId`, `challenge`: valid client correlation echoed, otherwise null.
- `agentInstanceId`, `authChallenge`: hello only, otherwise null.
- `authState`: `unauthorized` or `authorized`; errors report unauthorized metadata
  for that response, without silently granting or extending access.
- `authorizedCapabilities`: full set for current successful grant, otherwise [].
- `sessionId`, `expiresAt`: accepted session and absolute expiry, otherwise null.
- `capabilities`: processes/displays/overlays, each with `status` and `limitation`.
  Status: available / unsupported / error / notChecked.
- `findings`: [] before authorization; authorized grouped findings contain id,
  category, label and optional processCount/displayCount/windowCount.
- `observedAt`: local epoch ms; metadata timestamp alone does NOT mean a scan.
- `error` only on failure: `{code, message}`.

Codes: INVALID_JSON, INVALID_REQUEST, UNSUPPORTED_VERSION, UNKNOWN_COMMAND,
MALFORMED_FRAME, FRAME_TOO_LARGE, PROBE_FAILED, UNAUTHORIZED, AUTH_EXPIRED,
INVALID_AUTHORIZATION, CHALLENGE_MISMATCH, CHALLENGE_REUSED, CHALLENGE_EXPIRED,
INVALID_SIGNATURE, UNSUPPORTED_CAPABILITY, AUTH_CONFIG_INVALID,
RANDOM_UNAVAILABLE.

## Observation scope and limitations

- Processes: sysinfo 0.33 enumerates visible names with optional CPU/memory/user/path/argument refresh disabled. Missing self-process or an empty snapshot is an error. sysinfo does not expose a comprehensive enumeration error: partial/inaccessible results can still be reported available. OS permissions, transient processes and non-UTF-8 names limit coverage.
- Processes: only exact case-insensitive matches in the compiled app catalog emit findings. No raw process inventory or termination command is returned. Matching names are unverified identities; renamed/new apps and browser-hosted assistance can be missed, and benign apps can share names. Findings neither prove active assistance nor assign automatic blocking severity.
- Displays: macOS uses CoreGraphics `CGGetActiveDisplayList`; Windows uses `EnumDisplayMonitors`. An API failure or zero displays is an error. More than one active logical display emits `display:multiple-active` with `displayCount`. One display emits no finding but does not prove absence of physical mirrors, external capture, virtual displays or secondary devices.
- Overlays: read-only visible window metadata enumeration. macOS uses `CGWindowListCopyWindowInfo` on-screen windows, reporting positive window layers and sharing-state zero. Windows uses `EnumWindows`, `IsWindowVisible` and `GetWindowLongW` extended styles, reporting topmost windows that are also layered or transparent. Findings are grouped as `overlay:elevated-window` and `overlay:sharing-restricted` with `windowCount`; the same macOS window may contribute to both groups. No owners, titles, PIDs or screenshots are returned. System/desktop windows are not blanket-suppressed, so legitimate menus, system UI and accessibility tools can be observed. These are potential overlay properties, not evidence of cheating, actual visibility to a person, or capture exclusion. macOS sharing state does not guarantee modern ScreenCaptureKit behavior; Windows capture affinity is not inspected. API failure, zero visible windows or missing required metadata marks the probe `error`, preserving partial observations. Permissions, other desktops/sessions, hidden windows and transient windows limit coverage; the probe never requests screen-recording permission or captures pixels.
- Other operating systems: process/display/overlay capabilities are unsupported, not a fake clean scan.

No raw process inventory, PIDs, paths, command lines, window titles, browser content, keystrokes or memory contents are returned. No processes are killed or altered. No privilege elevation, shell probes, remediation or network telemetry are performed. Findings are observations for policy review; callers must require their necessary capabilities and communicate remaining gaps.

## Security boundary

Chrome launches the host and owns its stdio connection; the manifest restricts which extensions Chrome permits to connect. SafeAgent also checks the supplied origin. **An origin argument is not proof of the caller:** a terminal process can launch the binary with an approved origin and its own pipes. Browser-owned pipes do not prevent this separate invocation.

The authorization handshake authorizes an assessment session, not an untampered machine. The backend retains the private signing key; the agent contains only verifying keys. Do not embed a shared private key or secret in the extension or binary. Authorization must be bound to an agent-generated challenge and the intended session. A student controlling the device can still patch the agent, steal local authorization material, terminate it or fabricate observations; signatures do not make these observations trusted attestation.

Keep least privilege and informed consent: no process killing, remediation, screenshots, raw process inventory or unrelated file access. Never collect or return file contents, keystrokes, browser content, window titles, command lines or memory contents.

## Migration attribution

This implementation was informed by the process-category/catalog and window-metadata concepts in `safeassess/prototypes/native-agent` (`src/process.rs`, `src/overlay.rs` and `signatures.json`), read from the existing sibling repository. It is a narrowed implementation inside the nucleus monorepo, not a wholesale import. Prototype path-substring signatures, blanket owner exclusions, capture-exclusion certainty claims, executable signer shell commands, broad raw diagnostics, networking, memory/input probes, HMAC attestation and remediation are intentionally not carried over. This monorepo's source/protocol and independent Cargo lockfile are authoritative.

## Verification and release gaps

`src/auth.rs` tests use ephemeral test signing keys, never committed private
keys. They cover success, exact-byte signatures, binding/schema/scope failures,
key configuration, replay, wall/monotonic expiry and pre-auth probe gating.
`tests/protocol.rs` covers framing, correlation, strict parsing and origin
handling; `tests/overlays.rs` covers metadata classification.
`packaging/smoke-native.py` verifies actual binary metadata and unauthorized
check rejection, NOT authorized platform probes. Run `cargo test --locked` and
`cargo clippy --locked --all-targets -- -D warnings`.

Still required before enablement: integrated runtime validation of backend
signing/entitlement and HIBU v2, controlled authorized OS probe tests on Windows x64/macOS arm64/x64,
real key provisioning/rotation, compatibility and consent UX, packaging/signing
verification and post-deploy rejection/expiry metrics. Do not claim these are
implemented or validated by native unit tests.

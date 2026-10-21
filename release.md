# SafeAgent release operations

For developer-only unsigned 0.2.0 packages, use [internal-dev.md](internal-dev.md).
That packaging path requires approved compiled public keys but no production
signing procurement. Its optional, separately gated private-GCS publication uses
OIDC/WIF, create-only version/commit paths and a catalog published last; see the
[exact Dev infra configuration and HIBU/Assessment proposal](internal-dev.md#optional-private-gcs-pilot--operator-provisioning-only).
It does not implement backend downloads, certify compatibility, enable production,
or install anything. Unsigned packages are for explicitly allowlisted Dev testers
only, never the ordinary student production flow below. The production workflow below is default-off unless the
repository variable `SAFEAGENT_PRODUCTION_RELEASE_ENABLED` is exactly `true`
(see `.env.example`); both signing and publication retain all existing gates.

## Purpose and verification boundary

This is intentional **future production tooling**, not an active release channel.
[safeagent-release.yml](.github/workflows/safeagent-release.yml) manually
signs/notarizes a protected version tag and separately publishes three approved
installers to GitHub Releases. It is independent of PR/main CI and reviewed-main
Internal Dev packaging/private GCS. Enabling Dev publication cannot enable this
workflow; neither path installs on devices or enables runtime enforcement.

Targets are Windows x64 and macOS arm64/x64. Linux observations and packaging are
unsupported. Target/runners/compilation do not certify an OS/browser matrix.
[Acceptance gates](tasks.md) remain separate: native tests/subprocess smoke do
not prove real Chrome registration, installed permissions/lifecycle, cross-app
signed handshakes, signing/notarization or production approval. Record fresh
revisions, commands, device versions and trusted hashes before claiming support.

Real organization-owned credentials and protected environments listed below
must be provisioned and authorized separately; source configuration does not
establish their availability.

## Authorization key release gate

The release workflow explicitly maps `vars.SAFEAGENT_AUTH_PUBLIC_KEYS` into the
sign job environment (GitHub variables are not automatically process env).
Before signing preparation, `cargo run --locked --example validate-auth-config`
validates that value with the runtime's exact key parser. Both signed-mode
builders repeat this gate before building/packaging/signing. Missing, malformed,
duplicate-ID and weak keys stop the release; publish depends on all sign jobs.
Unsigned development builds deliberately permit absent keys for rejection smoke.
The validator reads build-process env; the host reads only compiled keys.

Native CI explicitly runs `cargo test --locked --test binary-authorization -- --ignored`.
This test compiles an isolated host with an ephemeral public key and keeps its
private signer only in memory, then exercises framed hello → authorize → check.
It rejects a runtime-env replacement signer and accepts the embedded signer.
Headless probe failures are permitted only after proving the authorization gate
and session binding. No findings are printed. The test uses cached Cargo deps
(`--offline`) and starts no network service or installer.

## Student distribution and upgrade contract

HIBU is the detection and guidance layer, not an installer. Its organization-managed installation is a deployment prerequisite to verify, not evidence supplied by SafeAgent. HIBU must never launch an installer with elevation, write native registration itself or silently repair/update the host. Students or authorized IT operators run the approved signed package outside assessment windows.

### Registration prerequisites (reference only; no registration performed)

- Host name: `com.kalvium.safeagent`, manifest `type: stdio`, absolute binary path, exact `chrome-extension://<ID>/` entries in `allowed_origins`.
- macOS package: binary `/Library/Application Support/Kalvium/SafeAgent/safeagent`; manifest `/Library/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json`. Chrome's per-user alternative is `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json`; the package does not install there. Stale per-user registration must be considered during separately authorized validation.
- Windows package default: binary `%LOCALAPPDATA%\Kalvium\SafeAgent\safeagent.exe`; manifest `%LOCALAPPDATA%\Kalvium\SafeAgent\com.kalvium.safeagent.json`; default value of `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent` points to that manifest.
- Record the approved production HIBU extension ID from the intended Chrome profile and match both manifest and compile-time `SAFEAGENT_ALLOWED_EXTENSION_IDS`. CI's `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` is a test fixture, never production approval. Unpacked IDs must not be assumed stable across profiles/paths.
- Export reviewed `SAFEAGENT_AUTH_PUBLIC_KEYS` before Cargo compilation; runtime env/dotenv cannot replace embedded keys. The corresponding private grant signer stays backend-only. Rebuild/release to rotate the ring; signed builders reject missing/malformed keys.

### Assessment readiness flow (external integration target)

Normal browser enrollment must not connect/probe or assert installed/ready status.
Native one-shot preflight accepts strict signed v3 grants on wire v2; it rejects
legacy v1 and incompatible draft grants containing `sub`. HIBU/backend durable
pre-admission integration remains [proposed and uncertified](design.md#consented-advisory-preflight-native-implemented-integration-proposed).
The following flow is an external acceptance target, not an installed end-to-end claim.

1. After explicit assessment-setup consent (not ordinary enrollment), HIBU attempts `connectNative('com.kalvium.safeagent')` and a metadata-only compatibility/configuration-readiness check.
2. If compatible, obtain a Student-owned signed v3 preflight grant before one-shot observations. Do not start monitoring to obtain pre-admission authorization. Separately consented ongoing monitoring uses its own fresh port and v2 session grant. Transport success alone is not readiness.
3. Classify failure and present a specific action using the table below. Do not collapse every connection failure into “missing or corrupted.”
4. When installation or upgrade is appropriate, offer the approved, versioned Windows `.exe` or architecture-specific macOS `.pkg`, with publisher and required version information. Do not offer unsigned development artifacts or unvalidated Linux packages.
5. Tell the student to finish/leave assessments, fully quit Chrome including background processes, run the installer, reopen Chrome and return to **Check connection**. macOS installation requires Chrome closed across users; closing windows alone is insufficient.
6. Reconnect and repeat compatibility, authorization and capability checks. A download, installer exit or reported version alone does not admit the assessment.

The prompt must not trap the student or prevent leaving the page. Current local/Dev
preflight is advisory: failed or unavailable checks never block admission or
trigger penalties. Any future production enforcement needs separate approved
backend policy and recovery preserving answers; it is not enabled by signing or
publishing installers. Discover installation needs early, never modify the device
during an active exam.

| Failure class | Student/support action |
| --- | --- |
| Host unavailable / registration failure | Show the browser's safely classified connection failure; offer installation or approved repair when appropriate. Do not claim a missing binary is proven by a generic disconnect. |
| Incompatible agent/protocol | Display detected and required versions; offer an approved compatible package. |
| Authorization denied or expired | Re-authenticate or retry authorization as appropriate; contact support for policy denial. Do not recommend reinstall. |
| Required capability unsupported | Explain the unsupported environment and supported alternatives; reinstall is not a capability fix. |
| Probe error / unexpected disconnect | Offer a bounded retry and diagnostic guidance; do not label the device clean, cheating or corrupted. |

Connection failures must be classified by HIBU because an absent or crashed host cannot return agent error codes. Agent replies must provide stable protocol/auth/probe errors. Student wording and backend status mapping must preserve these distinctions.

### Package selection and compatibility

- Publish an approved compatibility record: HIBU version/extension ID, agent version range and protocol version, OS/architecture/browser matrix, required capabilities, exact package URL, expected publisher and trusted artifact hash. Version numbers in UX examples are illustrative, not approved releases.
- Select only organization-controlled HTTPS downloads from trusted configuration or approved HIBU links, never arbitrary URLs from agent output, query parameters or messages. Production tooling publishes GitHub Release assets. Private Dev GCS, scoped URL signing and the **unimplemented** authenticated download endpoint are documented separately in the [Dev handoff](internal-dev.md#hibu-and-assessment-handoff--proposal-not-implemented-endpoints); they are not the production student channel.
- Treat browser OS/architecture detection as a hint. When architecture is ambiguous, provide clear selection guidance rather than silently choosing the wrong macOS package.
- The backend owns accepted versions and assessment requirements; HIBU must not allow a stale embedded minimum version to override backend policy. A reported version is a compatibility signal, not binary attestation.
- Extension-ID changes require new binaries and matching manifests/installers. Coordinate HIBU identity/version transitions with approved agent releases before enforcement.

### Upgrade and repair acceptance criteria

Normal upgrades and same-version repair must work by running the approved installer over the existing installation, without manual uninstall. Keep binary location, host name and registration deterministic; do not expose custom destination selection. Rollback remains a separately approved procedure and may require uninstall.

Source inspection is not lifecycle certification. The Windows installer has a stable AppId, writes registration and replaces payload files, enforces the fixed default directory (including rejecting command-line overrides), and blocks prior non-default host registration for manual IT review/uninstall. Missing registration still requires inventory of prior custom installations; no automatic migration/deletion is attempted. Windows uses user confirmation, not the macOS running-process guard. The macOS package uses fixed system paths. Neither establishes a successful real-device upgrade by itself.

Before release, test old-to-new upgrade, same-version repair, multiple Chrome profiles/background processes, locked binaries, failed/interrupted installation and recovery, Unicode Windows paths, uninstall cleanup and supported rollback. Verify the manifest points to the installed binary and that real Chrome reconnects afterward. Never kill Chrome or an assessment to complete installation. IT-managed distribution must respect the same assessment safety window.

## Infrastructure prerequisites (not provisioned by source code)

- Enable GitHub Actions with Windows `windows-2022`, Apple Silicon `macos-14` and Intel `macos-15-intel` runners. Native CI runs on PR/main changes from the repository root; it uses Cargo only, with the independent committed lockfile. Windows images must provide Inno Setup 6 and Windows SDK `signtool`; macOS requires Xcode tools and Python 3. A missing tool fails the job rather than emitting a fake installer.
- Create **`safeagent-signing`** and **`safeagent-publishing`** GitHub environments. Require trusted reviewers, disallow self-review and administrator bypass where organization policy permits, and allow only protected `safeagent-v*` tags. Restrict who can create/update/delete these tags with a repository ruleset. Review the source and workflow at the tag before authorizing signing. GitHub environment protection is repository configuration, not something YAML can guarantee.
- Run the manual workflow **from the same protected tag** supplied in its `tag` input, not from a feature branch. It fails if the ref is unprotected, not a tag, mismatched, or not `safeagent-vMAJOR.MINOR.PATCH`. The tag must equal `Cargo.toml` version. No push/PR trigger can sign or publish.
- Signing jobs have read-only repository permission. Only the separately approved publishing job has `contents: write`, downloads the three successful signed-job artifacts from the same run and creates a GitHub Release with SHA-256 checksums. No deployment, device installation, auto-update, cloud bucket or service account is involved. An existing release causes publication to fail rather than replacing assets silently.
- Obtain real organization-owned Apple Developer ID Application **and** Developer ID Installer certificates, an App Store Connect notarization API key, and a Windows Authenticode code-signing certificate. Renew before expiration and revoke/rotate on compromise. Never check certificates/keys into git. Current Windows implementation requires an exportable password-protected PFX supported by `signtool`; a hardware-only/cloud-signing certificate requires an approved provider integration before release, not an unsigned fallback.

## `safeagent-signing` configuration

Environment variables (GitHub environment **vars**):

| Variable | Required value |
| --- | --- |
| `SAFEAGENT_ALLOWED_EXTENSION_IDS` | Explicit production Chrome extension ID(s), unique comma-separated 32-character lowercase `a`–`p` values; no wildcard or whitespace. This controls both the compiled runtime check and manifest. |
| `SAFEAGENT_AUTH_PUBLIC_KEYS` | Reviewed `keyId:base64urlPublicKey` ring, embedded at compile time; private keys remain backend-only. Signed builders reject missing/malformed configuration. |
| `WINDOWS_TIMESTAMP_URL` | Organization-approved RFC 3161 Authenticode timestamp endpoint. |
| `MACOS_SIGNING_IDENTITY` | Exact installed `Developer ID Application: … (TEAMID)` identity. |
| `MACOS_INSTALLER_IDENTITY` | Exact installed `Developer ID Installer: … (TEAMID)` identity. |

Environment **secrets**:

| Secret | Contents |
| --- | --- |
| `WINDOWS_CERTIFICATE_BASE64` | Base64 PFX including private key and certificate chain. |
| `WINDOWS_CERTIFICATE_PASSWORD` | Nonempty PFX password. |
| `MACOS_CERTIFICATES_BASE64` | Base64 P12 containing both Developer ID identities/private keys and required chain. |
| `MACOS_CERTIFICATES_PASSWORD` | Nonempty P12 password. |
| `MACOS_KEYCHAIN_PASSWORD` | Random nonempty temporary CI keychain password. |
| `APPLE_API_KEY_BASE64` | Base64 `.p8` notarization key. |
| `APPLE_API_KEY_ID` | API key identifier. |
| `APPLE_API_ISSUER_ID` | App Store Connect issuer UUID. |

Missing/invalid credentials fail closed. Windows signs and verifies the binary **and** installer with SHA-256 timestamping; macOS signs with hardened runtime, signs the installer, waits for an **Accepted** notarization result, staples, validates the ticket and assesses Gatekeeper before upload. There is no skip-signing switch in the release workflow. Temporary credentials are removed in cleanup; use ephemeral GitHub-hosted runners only. Do not enable shell tracing around signing steps. Signing/notarization contact their external services; the **agent runtime** does not.

Production extension identity must be finalized before building. CI's test-only
`UNSIGNED-DEV` artifacts cannot substitute for a production release. Blank inputs
in [.env.example](.env.example) are discovery placeholders, not credentials;
GitHub vars/secrets must be provisioned explicitly, not loaded from dotenv.

## Cross-app authorization release gate

The native runtime rejects v1 and unauthenticated observations. Keep companion
HIBU/backend rollout default OFF until signed positive/negative handshakes,
consent/entitlement, authorized platform probes, compatibility records and
observable rejection/expiry metrics pass. No legacy scan fallback is permitted.
Standalone `safeagent check` is metadata-only and exits nonzero; packaging smoke
verifies rejection, not observations. See [protocol.md](protocol.md) for exact
monitoring v2 and advisory preflight v3 grants and [tasks.md](tasks.md) for gates.

## Operator release checklist

1. Review protocol/application compatibility, release source, allowlist and dependency lockfile. Bump Cargo version and regenerate its lock metadata when needed. Complete all native-target CI tests. Record the approved extension version/ID and agent version together.
2. On disposable Windows x64, macOS arm64 and Intel macOS machines, install the matching approved test package outside any assessment and only if OS/organization policy permits it. Verify `--version`, standalone unauthorized JSON `check`, metadata `hello`, real Chrome signed v2 authorize/check and one-shot v3 preflight with explicit consent. Verify correlation, full capability limitations, replay/expiry rejection and denied origins. Missing/error/unsupported capabilities are not clean scans.
3. Test repair of a missing manifest, reinstall, uninstall, reinstall after uninstall, and rollback to the previous compatible package. On Windows include non-ASCII user profile paths; verify HKCU registration and no elevation/service. On macOS verify system `/Library` registration (not root's HOME), no daemon, and user-level runtime. Installation guard must reject running Chrome/SafeAgent on macOS; on Windows do not consent while an assessment/browser is active. Test repeated installs/uninstalls and confirm no unrelated files/registry entries are removed.
4. Create the reviewed protected version tag. Manually dispatch `safeagent-release.yml` at that tag, input the identical tag and approve signing. Inspect successful signature/notarization verification and artifact names. Download and test the signed packages on clean disposable devices; verify Windows Authenticode trust/SmartScreen behavior and macOS Gatekeeper installation, native messaging and lifecycle again. Timestamping/signature validity is not a promise that SmartScreen reputation warnings never appear.
5. Only after that evidence, a separate reviewer approves `safeagent-publishing`. Record reviewer, commit/tag, three artifact hashes, extension IDs, platform validation evidence and rollback version in the release record. GitHub Release publishing is manual and protected; it does not install on devices.
6. Distribute links through the approved product flow. Schedule upgrades outside assessments, never at exam launch or mid-exam. Keep the last compatible signed installers available. Device management must not use unattended update/repair/uninstall during assessment windows.

If notarization, signing, a native build, platform test or approval fails, stop release. Do not rename unsigned packages or publish a subset. After a publish failure inspect the release state before retrying; never overwrite signed assets with unreviewed outputs.

## Signed artifacts versus authenticated updates

There is **no auto-updater**, authenticated update feed, client-side release-manifest verification, enforced minimum-version/anti-downgrade state or automatic rollback in this implementation. Signing and notarization establish artifact publisher/integrity checks at distribution/installation; they do not authenticate observation contents, attest a device, or guarantee that a downloaded version is the currently approved one. Release SHA-256 files detect changes only when their source is trusted; a hash downloaded alongside an untrusted installer is not independent authentication.

Operators must obtain packages from the approved protected release, verify the expected publisher/signature (and macOS notarization), compare recorded trusted release hashes and confirm the selected version/protocol/extension IDs against the release record. Use approved links rather than arbitrary mirrors. Rollback is a manual, explicitly approved selection of the last compatible signed package outside assessments, not a self-healing client feature. Future automatic updates would need a separately designed authenticated metadata/trust-root, freshness and downgrade policy; none is claimed here.

## Installer permissions and removal

- **Windows:** ordinary-user installation under `%LOCALAPPDATA%\Kalvium\SafeAgent`, native host registration in `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent`; no elevated runtime/service. Remove through Settings → Apps or installed `unins000.exe` after ending assessments and closing Chrome.
- **macOS:** admin authorization installs into `/Library/Application Support/Kalvium/SafeAgent` and registers `/Library/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json` system-wide. Runtime remains the Chrome user's process, not root. Close Chrome for every user, then run `sudo bash '/Library/Application Support/Kalvium/SafeAgent/uninstall.sh' --confirm-no-active-assessment`; removal is limited to owned files/registration/receipt. Installer's early built-in Chrome application lookup gives guidance; the later `preinstall` guard rejects running Chrome/SafeAgent across users. Quit Chrome with Command-Q, not just window close, and close manually started SafeAgent normally. Neither check proves an assessment ended. If the later guard fails, read Installer's Window → Installer Log or `/var/log/install.log`; never bypass it.
- Installation does not confer comprehensive OS probe permissions. Restricted/partial visibility must remain explicit; no instruction to disable OS security, grant blanket permissions or equate a successful install with full coverage. Verify actual permission behavior and cleanup on every certified OS version.
- End observation and all assessments before install/repair/upgrade/rollback/uninstall. Native loss is a coverage gap, not a cheating verdict or trigger to submit answers. Installers share the production host name: a separate Chrome profile does not isolate Windows per-user or macOS system-wide registration. Use approved disposable devices and inventory existing registrations.

## Repair / incident rollback

Follow the [installer permissions and removal](#installer-permissions-and-removal) scope. Close Chrome for every affected user and confirm no active assessment. For normal repair, rerun the same approved installer without uninstalling. For an approved incident rollback, uninstall and reinstall the selected compatible version. Chrome does not support a separate command in the host manifest: its `path` is the real binary and the browser's origin argument selects messaging. Repair registration by rerunning the approved installer, not by granting wildcard origins. If keys or releases are compromised, pause distribution, revoke credentials, remove unsafe download links, communicate with operators and reissue properly signed packages under a new version. Do not attempt to repair or restart active exams automatically.

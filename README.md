# SafeAgent

Read-only native observation host for consented assessment setup and monitoring
through HIBU. Standalone Rust/Cargo project, independent of Yarn/Turbo and web
deployment. Chrome launches it as the browser user over Native Messaging stdio;
there is no daemon, updater or agent networking.

**Signals are best-effort client reports, not device attestation or cheating
verdicts.** No process termination, screenshots, raw process inventory or student
content collection. Unavailable/error/unsupported results must stay visible,
not become clean scans or automatic penalties.

## Current scope

- Version **0.2.x** (patch bumped per published build), wire protocol **2**. 0.2.2 adds signer/version-info matching, remote-session/service, VM and unverified-executable findings. 0.2.5 adds signed results (OS-held P-256 device key), self-reported build hash/signer and a Chrome parent check; see protocol.md "Result attestation". A valid signature proves which install produced a result, not that the agent is untampered. Monitoring requires a signed v2 grant
  on the same native port; advisory one-shot preflight uses a separate signed
  v3 grant. Legacy v1 and unauthenticated observations are rejected.
- `hello` is metadata-only. `ok: true` does not establish readiness;
  `authReadiness` separately reports `ready` or `AUTH_CONFIG_INVALID`.
  Standalone `safeagent check` returns unauthorized metadata and exits nonzero.
- Packaging targets: **Windows x64, macOS arm64 and macOS x64**. These are not
  a certified OS/browser support matrix. **Linux is unsupported**: all observation
  capabilities report unsupported and no Linux installer is provided.
- HIBU/backend/Student integration and installed-device compatibility require
  separate acceptance. Everyday browser enrollment must not connect or probe;
  assessment setup requires explicit consent. Local/Dev preflight is advisory,
  never admission-blocking. Production release remains **default off**.

## Documentation

| Document | Canonical purpose |
| --- | --- |
| [Protocol](protocol.md) | Implemented commands, signed grants, replies, probe limitations and trust boundary |
| [Architecture, security & validation](docs/native-messaging-architecture-security.md) | Twenty-question technical review, browser evidence, Linux feasibility and unvalidated release gates |
| [Design](design.md) | Component ownership and cross-PR integration requirements, not deployment certification |
| [Requirements](requirements.md) | Product scope, privacy constraints and acceptance cases |
| [Checklist](tasks.md) | Implemented native boundaries and remaining integration/device/release gates |
| [Internal Dev](internal-dev.md) | Unsigned local/Actions packages, optional private Dev GCS and proposed download handoff |
| [Release operations](release.md) | Intentional dormant production signing/publication path, installer lifecycle and rollback |
| [Threat model](docs/threat-model.md) | Technique classes, current signals and residual risk |
| [Signed results proposal](docs/protocol-v3-proposal.md) | Proposed install key + agent-signed results (not implemented) |
| [Key rotation and recovery](docs/key-rotation.md) | Ring rules, rotation, emergency revocation, recovery scopes and suspicious-signal handling |
| [Hardening plan](docs/security-hardening-plan.md) | Items 1-7, decisions, cross-repo contract |
| [Pilot release validation](docs/pilot-release-validation.md) | Single acceptance checklist: automated gates and post-packaging runtime tests |
| [Student update flow](docs/upgrade-flow.md) | In-place upgrade guarantees and the HIBu/backend update contract |
| [Configuration template](.env.example) | Build inputs and workflow configuration; not automatically loaded |

## Independent merge, packaging and pilot gates

See [readiness gates](docs/readiness-gates.md) for branch protection, environment
setup and evidence requirements. Merge success does not imply packaging or pilot
acceptance; neither manual gate is a required merge check.

- [Native CI](.github/workflows/safeagent-ci.yml): PR/main validation,
  test-only extension identity, native binaries and a test-only Windows harness;
  no installers or approved distribution.
- [Internal Dev](.github/workflows/safeagent-internal-dev.yml): manual
  reviewed-main packaging with the fixed Dev identity and approved public keys.
  Actions-only by default; private Dev GCS additionally requires explicit opt-in
  and its separate default-off flag/environment.
- [Pilot readiness](.github/workflows/safeagent-pilot.yml): default-off manual
  evidence verification and separate owner approval for an exact source/package
  run and bounded scope; no deployment or flag enablement.
- [Production release](.github/workflows/safeagent-release.yml): dormant
  manual protected-tag signing/notarization and separately approved GitHub Release
  publication. Its own default-off flag does not control CI or Internal Dev.

Export reviewed extension IDs and Ed25519 **public** keys before building, as
specified in [.env.example](.env.example). Cargo embeds them; runtime environment
changes cannot replace them. Backend private grant-signing keys never belong in
native builds. See [local builds and validation](internal-dev.md#local-builds-without-installation)
for commands; installation is a separate, explicitly authorized operation.

## Standalone checkout

Run Cargo and packaging commands from this repository root. This is a source-only
extraction from Nucleus; no monorepo history, local credentials or built installers
are included. The browser extension and Assessment API remain separate integrations.
GitHub environments, protected refs, signing secrets and cloud trust are not migrated
by copying workflow files: provision them for this repository before manual distribution.
Production signing and cloud publication remain default-off. On this public repository,
Actions artifacts and logs must be treated as public, including unsigned Dev packages.

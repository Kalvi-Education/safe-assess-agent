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

- Version **0.2.0**, wire protocol **2**. Monitoring requires a signed v2 grant
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
| [Design](design.md) | Component ownership and cross-PR integration requirements, not deployment certification |
| [Requirements](requirements.md) | Product scope, privacy constraints and acceptance cases |
| [Checklist](tasks.md) | Implemented native boundaries and remaining integration/device/release gates |
| [Internal Dev](internal-dev.md) | Unsigned local/Actions packages, optional private Dev GCS and proposed download handoff |
| [Release operations](release.md) | Intentional dormant production signing/publication path, installer lifecycle and rollback |
| [Configuration template](.env.example) | Build inputs and workflow configuration; not automatically loaded |

## Three independent workflows

- [Native CI](.github/workflows/safeagent-ci.yml): PR/main validation,
  test-only extension identity, unsigned artifacts; no approved distribution.
- [Internal Dev](.github/workflows/safeagent-internal-dev.yml): manual
  reviewed-main packaging with the fixed Dev identity and approved public keys.
  Actions-only by default; private Dev GCS additionally requires explicit opt-in
  and its separate default-off flag/environment.
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

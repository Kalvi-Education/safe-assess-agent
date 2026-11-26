# Grant-signing key rotation runbook

SafeAgent embeds Ed25519 **public** keys at compile time (`SAFEAGENT_AUTH_PUBLIC_KEYS`).
Private keys exist only in the Assessment API's secret store. No private key is ever placed
in this repository, a workflow variable, the binary or HIBu.

## Rules enforced by `cargo run --example validate-auth-config`

| Rule | Production (`release`) | Internal Dev (`--internal-dev`) |
|---|---|---|
| Key ID format | `prod-<purpose>-<YYYYMMDD>` | `dev-<purpose>-<YYYYMMDD>` |
| Other-channel keys | Rejected (`PRODUCTION_RING_CONTAINS_NON_PRODUCTION_KEY`) | Rejected |
| Keys per purpose | At most 2: current + next (`RING_EXCEEDS_CURRENT_PLUS_NEXT`) | Same |
| Dev extension ID | Rejected (`PRODUCTION_BUILD_CONTAINS_DEV_IDENTITY`) | Required, exactly |
| Malformed/duplicate/weak keys | Rejected (`AUTH_CONFIG_INVALID`) | Same |

Purposes in use: `preflight`, `monitoring`. Runtime: a key ID not in the ring returns
`INVALID_SIGNATURE` before any scan. A revoked key therefore yields "unavailable", never "clean".

## Scheduled rotation (every 6 months)

1. **Generate next.** The backend owner creates a new keypair in Secret Manager, as a new
   secret version. Record only the public key and the ID, e.g. `prod-preflight-20270701`.
2. **Ship both.** Set the ring to `current,next` in the `safeagent-signing` environment. Cut a
   SafeAgent patch release. The server keeps signing with `current`.
3. **Wait for adoption.** Check the agent version HIBu reports (backend telemetry) until at least
   N% of active installs (proposed 95%) run a build that contains `next`.
4. **Switch signing.** Change the Assessment API signing key ID to `next`. Old builds that lack it
   now get `INVALID_SIGNATURE`, and HIBu shows "update required" (see upgrade-flow.md).
5. **Drop old.** In the following release, the ring becomes `next` only (it is now current).

## Emergency revocation (suspected private-key leak)

1. Stop signing with the leaked key ID immediately: switch the server to `next`, or generate and
   ship a new key first if `next` is not yet deployed.
2. Release a SafeAgent build whose ring excludes the leaked ID. Raise
   `ASSESSMENT_V2_SAFEAGENT_VERSION` so HIBu prompts every student to update.
3. Treat results signed by the leaked key since the suspected leak time as untrusted for review.
4. Write an incident record in the private incident store, not in this public repository.

## Recovery scopes (signed results, 0.2.5+)

Three independent scopes. Never rotate a global key or force a mass upgrade because of one
unverified client signal. Every privileged action needs administrator approval and an audit entry.

| Scope | Trigger (confirmed, not suspected) | Action | Reuses |
|---|---|---|---|
| One installation | A device key is shown to produce false evidence | Revoke that install's P-256 public key server-side; require explicitly authorised fresh enrolment. **A reinstall does not create a new key** (CNG and Keychain keys survive uninstall) | Device enrolment / BOA |
| One agent release | A build or artifact is compromised | Remove its `binarySha256` from the approved set; publish a patched patch release; raise `ASSESSMENT_V2_SAFEAGENT_VERSION` | HIBu update-required flow, Internal Dev / GCS catalog |
| Backend grant key | The Ed25519 grant private key leaked | "Emergency revocation" above (current/next ring) | This runbook |

### Signals: suspicious until confirmed

The Assessment API classifies these and shows them in the Assessment Command Center for review.
None of them alone triggers a recovery action.

| Signal | Classification | Default handling |
|---|---|---|
| `resultSignature` invalid for the registered key | Suspicious; confirmed if reproduced | Result untrusted; Required mode: `device_check_untrusted` |
| `selfHash` not in the approved set / revoked build | Suspicious (could be a stale install) | `unverified-build`; HIBu prompts an update |
| Device key changed for a known student + device | Suspicious | Treat as new enrolment; needs approval |
| Replayed result (same preflight / non-increasing `observedAt`) | Confirmed manipulation attempt | Reject; flag the attempt for review |
| Monitoring gap or unexpected agent restart | Suspicious (crash, sleep, kill) | Flag the attempt; existing waiver/review path |
| `UNTRUSTED_PARENT` / `keyProtection: unavailable` | Suspicious or unsupported device | Unsigned result; proctor uses the L3 waiver |

## Tests

- `src/auth.rs` `rotation_ring_accepts_current_and_next_and_rejects_dropped_keys`
- `examples/validate-auth-config.rs` production and internal-dev ring tests
- VM suite S3 cases 3.9 (Dev key in a Prod build) and 3.10 (rotation end to end on Dev)

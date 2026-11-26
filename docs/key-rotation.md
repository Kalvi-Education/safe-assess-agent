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

## Tests

- `src/auth.rs` `rotation_ring_accepts_current_and_next_and_rejects_dropped_keys`
- `examples/validate-auth-config.rs` production and internal-dev ring tests
- VM suite S3 cases 3.9 (Dev key in a Prod build) and 3.10 (rotation end to end on Dev)

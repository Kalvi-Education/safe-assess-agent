# Proposal: signed results and install identity (not implemented)

Status: proposal for backend (nucleus-apps) and HIBu (hibu#33) review. Nothing here is
implemented in the native agent yet. Wire protocol 2 stays unchanged until all three agree.

## Goal

Replace `trust: client_reported` with `agent_signed`: the server stores a preflight result
only if it verifies a signature from a registered SafeAgent install over the exact result
bytes. This closes "page posts ready" and binds results to one install, build and challenge.
It does not prove the install is unmodified (see threat-model.md).

## Install key

- Algorithm: ECDSA P-256 / SHA-256. TPM and Secure Enclave keys are P-256 only.
- Windows: CNG `Microsoft Platform Crypto Provider` (TPM), non-exportable, per-user. Fallback
  `Microsoft Software Key Storage Provider` when no TPM.
- macOS: Secure Enclave via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`
  (requires a Developer ID signed build). Fallback: Keychain software key.
- Reported `keyProtection`: `tpm | secure-enclave | software`. The server may treat software
  keys as lower assurance. Created on first `register`; the agent never exports the private key.

## New commands (wire protocol 3)

1. `register`, carrying a server-signed grant `{v:4, purpose:"agent-registration", enrollmentId,
   agentInstanceId, challenge, issuedAt, expiresAt}`. The reply carries the `installPublicKey`
   (SPKI DER, base64url), `keyProtection` and `build`. The server binds the key to the device
   enrollment; one active key per enrollment and browser profile, and it can be revoked.
2. `preflight` (v3 grant, plus a required `nonce`: 32 random server bytes, base64url). The reply
   adds `resultSignature`.

## Signed result

The agent serialises this object once and signs its exact UTF-8 bytes. The bytes are returned
as `signedResult` (base64url) together with `resultSignature` (DER ECDSA, base64url):

```json
{"v":1,"preflightId":"…","assessmentSlug":"…","challenge":"…","nonce":"…",
 "agentInstanceId":"…","installKeyId":"<sha256 of SPKI, base64url>",
 "build":{"version":"0.2.2","sha256":"<own image hash>","signer":"<Authenticode/Team ID or null>"},
 "parent":{"signer":"Google LLC","name":"chrome.exe"},
 "capabilities":{…},"findings":[…],"observedAt":1700000000000}
```

- `build.sha256` is the agent's own image hash. The server checks it against the per-release
  allowlist published by the release workflow. An unknown build is stored as `unverified-build`.
- `parent` is the launching process signer. A missing or unexpected parent (not Chrome) is
  recorded, not hidden.
- The server verifies the signature, preflight, challenge, nonce, single use, expiry and that
  the key is active. Only then is the result stored as `agent_signed`.

## Backend changes (nucleus-apps)

- Registration grant issuance and key binding to the enrollment; revocation endpoint (BOA).
- Nonce in the preflight grant; verify `resultSignature` before storing; new trust values
  `agent_signed | unverified-build | client_reported`.
- Build allowlist per channel (Dev, Prod) sourced from release provenance.
- Telemetry: rate of unverified builds, non-Chrome parents, software keys and signature failures.

## HIBu changes (hibu#33)

- Pass `signedResult` and `resultSignature` through unmodified; never re-serialise.
- Accept new finding categories `unverified`. `remote-desktop` ids `remote:*` already fit.
- Drive `register` once per install and profile on consented assessment setup.

## Rollout

The flag defaults off on the server. Store both trust values during the pilot and enforce only
after the false-positive rate is measured. A revoked or unknown key is reported as "unavailable",
never "clean".

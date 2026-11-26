# SafeAgent 0.2.5 pilot release validation

Single source of truth for pilot acceptance. 0.2.5 is the first build with signed results,
self-report and the Chrome parent check (PR #10). Every row starts `NOT_RUN`. Record the actual
result and an evidence reference (log path, screenshot, run ID). Never mark a row from reading code.

Status values: `NOT_RUN` · `PASS` · `FAIL` · `BLOCKED` (reason in Actual) · `N/A` (reason in Actual).
Priority: **P0** blocks the pilot · **P1** must pass before student rollout · **P2** informational.

Primary failure to look for: **manipulated or fabricated evidence accepted as trusted by the
Assessment API.** Any reproduction of that is P0.

## Build under test

| Field | Value |
|---|---|
| Source SHA (merge commit on main) | _fill after merge_ |
| Internal Dev run ID | _fill_ |
| Windows installer SHA-256 / inner `safeagent.exe` SHA-256 | _from SHA256SUMS / provenance `binarySha256`_ |
| macOS arm64 / x64 pkg SHA-256 / inner binary SHA-256 | _fill_ |
| HIBu build | _fill_ |
| Assessment API build and flags | _fill_ |

All investigators and testers use **this exact build**. A rebuild is a new build under test.

## A. Pre-merge automated gates (PR #10)

| ID | Gate | Result |
|---|---|---|
| A1 | `cargo fmt --check` | see PR |
| A2 | `cargo test --locked` (macOS host) incl. attestation-interop with Node | see PR |
| A3 | `cargo test --test binary-authorization -- --ignored` | see PR |
| A4 | `cargo clippy --all-targets -D warnings`: host and `x86_64-pc-windows-msvc` | see PR |
| A5 | `python3 packaging/test-*.py` | see PR |
| A6 | Smoke test refuses a binary built with `SAFEAGENT_ALLOW_ANY_PARENT` | see PR |
| A7 | CI: Windows x64, macOS arm64, macOS x64 | see PR |
| A8 | Dependency advisories (`cargo audit`) | see PR |

Cross-compilation and clippy prove the code builds. **They are not runtime validation.**
Sections B onward are.

## B. Post-packaging runtime acceptance

Columns: ID · Priority · Platform · Prerequisites · Steps · Expected · Actual · Status · Evidence

### B1. Install, upgrade, rollback, uninstall

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| INS-01 | P0 | Win 10/11 x64 | Clean user, Chrome + HIBu | Install 0.2.5 | Install → Finish; HKCU host entry → `%LOCALAPPDATA%\Kalvium\SafeAgent\com.kalvium.safeagent.json`; Detect works without a Chrome restart | | NOT_RUN | |
| INS-02 | P0 | macOS arm64 | Clean Mac, Chrome + HIBu | Install the unsigned pkg (Open Anyway) | `/Library/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json` → `/Library/Application Support/Kalvium/SafeAgent/safeagent`; Detect works | | NOT_RUN | |
| INS-03 | P1 | macOS x64 | Intel Mac | As INS-02 | As INS-02 | | NOT_RUN | |
| UPG-01 | P0 | Win | 0.2.4 installed | Run the 0.2.5 installer interactively | Same AppId, same folder, one Apps entry, version 0.2.5; no uninstall step; Detect shows 0.2.5 | | NOT_RUN | |
| UPG-02 | P0 | Win | 0.2.4 installed | `/VERYSILENT /SUPPRESSMSGBOXES` under a 120 s timeout | Exit 0, no hang, one instance | | NOT_RUN | |
| UPG-03 | P0 | macOS | 0.2.4 installed | Install the 0.2.5 pkg | Same package ID; binary replaced in place; Detect shows 0.2.5 | | NOT_RUN | |
| UPG-04 | P0 | Win | 0.2.5 key created (KEY-01) | Reinstall 0.2.5, then install a later 0.2.x | `installPublicKey` unchanged (CNG key is per user, not in the install folder) | | NOT_RUN | |
| UPG-05 | P1 | Win/macOS | Check running | Start an upgrade during a check | Windows: safety page; macOS preinstall refuses while `safeagent` runs; the running check completes | | NOT_RUN | |
| UPG-06 | P1 | Win | — | Kill the installer mid-copy, then re-run it | Re-run completes; one instance; Detect works | | NOT_RUN | |
| UPG-07 | P1 | Win/macOS | 0.2.5 installed | Install 0.2.4 (approved rollback) | Installs; HIBu reports `update_required` once the backend minimum is 0.2.5; the backend never classifies a revoked version as trusted | | NOT_RUN | |
| UNI-01 | P1 | Win | Installed | Uninstall from Settings | HKCU key and manifest removed; Detect → not installed. CNG key remains (expected; see KEY-04) | | NOT_RUN | |
| UNI-02 | P1 | macOS | Installed | Run `uninstall.sh --confirm-no-active-assessment` | Files and manifest removed; Detect → not installed | | NOT_RUN | |
| OSW-01 | P1 | Win | Unsigned build | Download and run | SmartScreen "More info → Run anyway" shown; nothing disables Defender | | NOT_RUN | |
| OSW-02 | P1 | macOS | Unsigned build | Open the pkg | Gatekeeper block → Privacy & Security → Open Anyway; no SIP/Gatekeeper change requested | | NOT_RUN | |
| OSW-03 | P2 | Win | Standard (non-admin) user | Install | Per-user install succeeds without admin (current model; the admin/HKLM model is a follow-up) | | NOT_RUN | |

### B2. Device key lifecycle and cryptographic interoperability

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| KEY-01 | P0 | Win with TPM (the VM has vTPM) | Fresh user | First Detect | `hello.attestation.keyProtection = "tpm"`; `installPublicKey` present | | NOT_RUN | |
| KEY-02 | P0 | Win without TPM | vTPM disabled | First Detect | `keyProtection = "software"`; key works | | NOT_RUN | |
| KEY-03 | P0 | Win | KEY-01 done | Verify a preflight `resultSignature` over the decoded `signedResult` bytes with Node `crypto.verify('sha256', bytes, {key: spki, format:'der', type:'spki'}, sig)` | `true` | | NOT_RUN | |
| KEY-04 | P1 | Win | Key exists | Uninstall, then reinstall | Same `installPublicKey` (reinstall does **not** create a new key). Fresh enrollment needs an explicit server action | | NOT_RUN | |
| KEY-05 | P1 | Win | — | Plant an RSA or exportable key named "Kalvium SafeAgent Result Key" (TPM provider), then Detect | That key is not used; falls back to software or `unavailable`; never reported `tpm` | | NOT_RUN | |
| KEY-06 | P0 | macOS (unsigned) | — | Detect | `keyProtection = "unavailable"`, `installPublicKey = null`; **no Keychain password prompt**; results unsigned | | NOT_RUN | |
| KEY-07 | P1 | macOS | — | Check Keychain Access for `com.kalvium.safeagent` items | None created by unsigned builds | | NOT_RUN | |

### B3. Parent check and authorization negatives

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| PAR-01 | P0 | Win | Chrome + HIBu | Normal Check | `attestation.parent = "trusted"`; check runs | | NOT_RUN | |
| PAR-02 | P0 | Win | — | Record the real Chrome → host chain (direct vs `cmd.exe`) with Process Explorer | Matches the `classify_parent` model; note which | | NOT_RUN | |
| PAR-03 | P0 | Win | — | Repoint the HKCU manifest to a wrapper script that launches `safeagent.exe` (B11 reproduction) | Check returns `UNTRUSTED_PARENT`, findings `[]` | | NOT_RUN | |
| PAR-04 | P0 | macOS | Chrome + HIBu | Normal Check | `parent = "trusted"` (strict Team ID requirement on Chrome's executable) | | NOT_RUN | |
| PAR-05 | P0 | Win/macOS | — | Run the host from a terminal with a valid origin and pipe in hello + preflight | hello answers (metadata); preflight → `UNTRUSTED_PARENT` | | NOT_RUN | |
| PAR-06 | P1 | Win/macOS | Edge or Chromium installed | Point the Edge/Chromium manifest at SafeAgent and check | `UNTRUSTED_PARENT` (Chrome only) | | NOT_RUN | |
| AUT-01 | P0 | any | — | Forged grant (one byte changed) | `INVALID_SIGNATURE`, nothing scanned | | NOT_RUN | |
| AUT-02 | P0 | any | — | Replay a used preflight grant | `CHALLENGE_REUSED` | | NOT_RUN | |
| AUT-03 | P0 | any | — | Expired grant | Rejected, no findings | | NOT_RUN | |
| AUT-04 | P1 | any | — | `safeagent --build-info` on the packaged binary | `parentCheck=enforced` | | NOT_RUN | |

### B4. Result integrity and backend trust (needs Assessment API verification, cross-repo)

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| RES-01 | P0 | Dev API | Server verification deployed | Normal Check | Stored `trust: agent_signed` | | NOT_RUN | |
| RES-02 | P0 | Dev API | — | Change one finding inside `signedResult`, re-encode it, submit | Rejected or untrusted; never `agent_signed` | | NOT_RUN | |
| RES-03 | P0 | Dev API | — | Keep `signedResult`, change the outer `ok`/findings fields | The server uses only the signed bytes; outer fields are ignored | | NOT_RUN | |
| RES-04 | P0 | Dev API | — | Submit a result from preflight A for preflight B | Rejected (preflightId/challenge mismatch) | | NOT_RUN | |
| RES-05 | P0 | Dev API | — | Direct API fake with no signature (B13 reproduction) | Untrusted; in Required mode with the flag on → `device_check_untrusted` | | NOT_RUN | |
| RES-06 | P1 | Dev API | Monitoring session | Re-submit an earlier monitoring check | Rejected (non-increasing `observedAt` for the session) | | NOT_RUN | |
| RES-07 | P1 | Dev API | — | `selfHash` not in the published `binarySha256` set | `unverified-build`, not trusted | | NOT_RUN | |
| RES-08 | P0 | Dev API | macOS unsigned | Normal Check | Stored as unsigned / untrusted, with a visible reason; not blocked in advisory mode | | NOT_RUN | |
| RES-09 | P1 | Dev API | Waiver | Required mode, unsigned result, `logOnly` waiver | Check stored, not blocked | | NOT_RUN | |

### B5. Lifecycle, interruption and HIBu integration

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| LIF-01 | P0 | Win/macOS | Current HIBu | Detect + Check with 0.2.5 | HIBu accepts the reply with the extra fields (no `timeout` / `bridge_unavailable`) | | NOT_RUN | |
| LIF-02 | P0 | Win/macOS | — | Time the first Detect (key open + self-hash) | Under HIBu's 5 s hello timeout; record ms | | NOT_RUN | |
| LIF-03 | P1 | Win | Check running | Kill `safeagent.exe` | HIBu → unavailable/timeout; the next Check works | | NOT_RUN | |
| LIF-04 | P1 | Win/macOS | Monitoring | Repeated checks over 15 min | Each check signed; `observedAt` increases | | NOT_RUN | |
| LIF-05 | P1 | any | Managed Chrome profile (policy) | Detect + Check | Works; note the policies present | | NOT_RUN | |
| LIF-06 | P1 | any | Unmanaged profile | Detect + Check | Works | | NOT_RUN | |
| LIF-07 | P2 | any | — | `UNTRUSTED_PARENT` surfaced in HIBu | A specific student message (HIBu change) | | NOT_RUN | |

## C. Deferred until trusted signing

| ID | Test | Status |
|---|---|---|
| SIG-01 | Developer ID signed + notarised pkg: Gatekeeper passes without Open Anyway | NOT_RUN |
| SIG-02 | Signed macOS build: `keyProtection = "secure-enclave"`; signature verifies | NOT_RUN |
| SIG-03 | Authenticode-signed Windows build: `selfSigner` = organisation name | NOT_RUN |
| SIG-04 | Admin installer: HKLM + Program Files; Chrome `NativeMessagingUserLevelHosts=false` blocks an HKCU redirect | NOT_RUN |

## D. Independent adversarial review (after packaging)

Three investigators work independently on the **same immutable build** in the Dev environment:
native/runtime, crypto protocol/backend trust, and installer/release. Each finding needs
reproduction steps, evidence, a severity and the B-row it affects. A finding is valid only if
reproduced. Fixes are not built speculatively.

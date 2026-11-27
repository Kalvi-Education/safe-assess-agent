# SafeAgent 0.2.5 / 0.2.6 pilot release validation

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
| Version / wire protocol | 0.2.5 / 2 |
| Source SHA (main) | `5236be5fa611f422acc91fcede5bffca866b7af3` (combined CI run 45886533608: Windows x64, macOS arm64, macOS x64, Linux experimental, all success) |
| Internal Dev run | [45887877118](https://github.com/Kalvi-Education/safe-assess-agent/actions/runs/45887877118), `publish_to_dev_gcs=false` (publish job skipped by design); Actions artifacts only, 14-day retention |
| Channel / signing | `internal-dev`, `signatureStatus: unsigned`, not notarised; macOS binaries ad-hoc signed by the linker (no Team ID) |
| Embedded config | extension ID `lfmldljfbheedcddndbnfckfkhjmkekp`; key IDs `dev-preflight-20261016`, `dev-monitoring-20261016`; no `prod-` keys |
| Test bypass | `parentCheck=enforced` in provenance; macOS binaries: `--build-info` → `parentCheck=enforced`; no `SAFEAGENT_ALLOW_ANY_PARENT`, CI test extension ID, `unit-test` key or private key strings found |

| Artifact | Installer SHA-256 | Inner binary SHA-256 (`binarySha256`) | Verified |
|---|---|---|---|
| `safeagent-0.2.5-windows-x64.exe` | `22d9a185de2a6e6750009ebd237e072e9260ca157cc5a6d9808ffb0e3ab3532e` | `54f371b9937ed4c2bb051380c61edf38305bd2e8f69624a5d9075204022c35fb` | SHA256SUMS OK. **Inner hash and binary strings NOT_RUN**: innoextract 1.9 cannot read this Inno Setup 6 installer; verify on the Windows VM (`Get-FileHash` of the installed `safeagent.exe`) |
| `safeagent-0.2.5-macos-arm64.pkg` | `b051e33d811ad46b38a1aad54a3421619c2f4ec8126b1081799807334e716484` | `b5bebbbb7393c1327e96d37d82ad8484a8283979d606679db95200b2d9891c21` | SHA256SUMS OK; extracted binary hash matches; `--version` 0.2.5; manifest path and origin correct |
| `safeagent-0.2.5-macos-x64.pkg` | `5de310bb9543bac1d6dc79c17979c0112fe8be1554f633d5588973364253684a` | `593289d997f95cec3bdf1281991f9affda936090933be2e36133a4f8d59d2633` | SHA256SUMS OK; extracted binary hash matches; manifest correct (not executed: arm64 host) |
| Linux `.deb` | — | — | Excluded: experimental, native CI only, not in this run or any catalog |

| Integration | Build | Note |
|---|---|---|
| HIBu | `hibu#33` head `b0007a9` (manifest 1.7.10; Dev Testing 1.7.14 seen on devices) | Has no handling for `attestation` / `signedResult` / `resultSignature` / `UNTRUSTED_PARENT` yet. Its preflight validation does not exact-match top-level reply keys, so extra fields are expected to pass (verify LIF-01) |
| Assessment API | nucleus-apps `main` `3690a4fa3c` | **No signed-result verification exists**: B4 (RES-*) is BLOCKED until it ships |


### 0.2.6 (current candidate)

| Field | Value |
|---|---|
| Source SHA (main) | `0fcc6f2ef0c83b1e8d9e368c0105c904e138c40d` (PR #13: KEY-01 fix; CI 4/4 incl. real CNG on Windows runner) |
| Internal Dev run | [45946661365](https://github.com/Kalvi-Education/safe-assess-agent/actions/runs/45946661365), `publish_to_dev_gcs=false` |
| Windows x64 | installer `349b19f501eba937b1e433ec936fc741e41f7462c63f06550d217bfb95a51117`, binary `5855c5cb1562eefe6f9f16bb1a16351aca8a128ea21f785b16b0a0420db988ee` (installed hash verified on VM) |
| macOS arm64 | installer `67a858ac76082880198633a1a093bfa88057608a4ec715e136dea6e143efbedb`, binary `693f351302ba1689125b4a0a64e87da0d18cc2652f95c2e3ea74996b441deca2` (extracted, verified) |
| macOS x64 | installer `44a93fb63741050cd5141eba0c48e77249412a5c63dfb8b034567dccff31ceef`, binary `cab3dd342e76a462681a4f6cb564e397c36ad65ae4a57a612a3dc779cad2c60a` (extracted, verified) |
| Config | Dev extension `lfmld…`, keys `dev-preflight/monitoring-20261016`, `parentCheck=enforced`, no bypass/test strings |

0.2.5 is superseded by 0.2.6 (KEY-01). Rows below record evidence from both; the Mac ran 0.2.5,
the VM ran 0.2.5 then 0.2.6.

## Sign-off summary (27 Nov 2026)

| Area | Result |
|---|---|
| Packaging, provenance, embedded config, no bypass | PASS (both builds) |
| In-place upgrade Mac + Windows silent | PASS |
| macOS: no keychain prompt, no key, parent check on real Chrome | PASS |
| Windows: Chrome launch chain (via cmd.exe), Chrome + HIBu, no false positives on clean image | PASS |
| Windows software key: persist, reuse, Node-verified signature | PASS |
| Windows TPM key (KEY-01) | BLOCKED: needs a physical TPM laptop (GCE vTPM cannot export TPM public keys) |
| Local attacks: terminal launch, forged grant, HKCU wrapper, patched binary hash, weak key, VM/RDP | PASS (agent side) |
| Server-side trust: fake API post (B13), edited/replayed results, binary allowlist, key change | BLOCKED: Assessment API does not verify signed results yet |
| Not run | Fresh installs, rollback, uninstall, Edge/Chromium refusal, interruption, managed profile |

**Verdict:** the agent side is sound for an internal pilot. Signed results are **not yet trusted
evidence** until the Assessment API verifies them; until then 0.2.6 results remain `client_reported`.

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
| INS-02 | P0 | macOS arm64 | Clean Mac, Chrome + HIBu | Install the unsigned pkg (Open Anyway) | `/Library/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json` → `/Library/Application Support/Kalvium/SafeAgent/safeagent`; Detect works | Not fresh: upgraded from 0.2.4 (see UPG-03) | NOT_RUN |  |
| INS-03 | P1 | macOS x64 | Intel Mac | As INS-02 | As INS-02 | | NOT_RUN | |
| UPG-01 | P0 | Win | 0.2.4 installed | Run the 0.2.5 installer interactively | Same AppId, same folder, one Apps entry, version 0.2.5; no uninstall step; Detect shows 0.2.5 | | NOT_RUN | |
| UPG-02 | P0 | Win | 0.2.4 installed | `/VERYSILENT /SUPPRESSMSGBOXES` under a 120 s timeout | Exit 0, no hang, one instance | 0.2.4→0.2.5 and 0.2.5→0.2.6 `/VERYSILENT` exit 0 <120 s; same folder, HKCU unchanged, one Apps entry | PASS | VM 05:0xZ, 05:39Z; findings doc 27 Nov |
| UPG-03 | P0 | macOS | 0.2.4 installed | Install the 0.2.5 pkg | Same package ID; binary replaced in place; Detect shows 0.2.5 | 0.2.4→0.2.5: one receipt `com.kalvium.safeagent` 0.2.5, same path, binary = provenance hash, manifest unchanged | PASS | Mac 03:59Z; findings doc 27 Nov |
| UPG-04 | P0 | Win | 0.2.5 key created (KEY-01) | Reinstall 0.2.5, then install a later 0.2.x | `installPublicKey` unchanged (CNG key is per user, not in the install folder) | | NOT_RUN | |
| UPG-05 | P1 | Win/macOS | Check running | Start an upgrade during a check | Windows: safety page; macOS preinstall refuses while `safeagent` runs; the running check completes | | NOT_RUN | |
| UPG-06 | P1 | Win | — | Kill the installer mid-copy, then re-run it | Re-run completes; one instance; Detect works | | NOT_RUN | |
| UPG-07 | P1 | Win/macOS | 0.2.5 installed | Install 0.2.4 (approved rollback) | Installs; HIBu reports `update_required` once the backend minimum is 0.2.5; the backend never classifies a revoked version as trusted | | NOT_RUN | |
| UNI-01 | P1 | Win | Installed | Uninstall from Settings | HKCU key and manifest removed; Detect → not installed. CNG key remains (expected; see KEY-04) | | NOT_RUN | |
| UNI-02 | P1 | macOS | Installed | Run `uninstall.sh --confirm-no-active-assessment` | Files and manifest removed; Detect → not installed | | NOT_RUN | |
| OSW-01 | P1 | Win | Unsigned build | Download and run | SmartScreen "More info → Run anyway" shown; nothing disables Defender | | NOT_RUN | |
| OSW-02 | P1 | macOS | Unsigned build | Open the pkg | Gatekeeper block → Privacy & Security → Open Anyway; no SIP/Gatekeeper change requested | `spctl` rejects unsigned pkg; installed via Open Anyway | PASS | Mac |
| OSW-03 | P2 | Win | Standard (non-admin) user | Install | Per-user install succeeds without admin (current model; the admin/HKLM model is a follow-up) | | NOT_RUN | |

### B2. Device key lifecycle and cryptographic interoperability

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| KEY-01 | P0 | Win with TPM (the VM has vTPM) | Fresh user | First Detect | `hello.attestation.keyProtection = "tpm"`; `installPublicKey` present | 0.2.5: TPM key rejected (`ECDSA` name) → fixed in 0.2.6. 0.2.6 on GCE vTPM: TPM key signs but public export fails `0x80290407 TPM_E_PCP_INTERNAL_ERROR` → correctly falls back to `software` | BLOCKED | Needs a physical laptop with a hardware/firmware TPM; findings doc 27 Nov |
| KEY-02 | P0 | Win without TPM | vTPM disabled | First Detect | `keyProtection = "software"`; key works | VM (unusable vTPM) → `software`, persisted, same public key across runs | PASS | VM 05:39Z |
| KEY-03 | P0 | Win | KEY-01 done | Verify a preflight `resultSignature` over the decoded `signedResult` bytes with Node `crypto.verify('sha256', bytes, {key: spki, format:'der', type:'spki'}, sig)` | `true` | Windows CI runner: real CNG key sign → Node `crypto.verify` true; VM public key parses as P-256 in Node. End-to-end preflight signature NOT_RUN (needs Dev API grant) | PASS (partial) | CI run 45946224076 |
| KEY-04 | P1 | Win | Key exists | Uninstall, then reinstall | Same `installPublicKey` (reinstall does **not** create a new key). Fresh enrollment needs an explicit server action | | NOT_RUN | |
| KEY-05 | P1 | Win | — | Plant an RSA or exportable key named "Kalvium SafeAgent Result Key" (TPM provider), then Detect | That key is not used; falls back to software or `unavailable`; never reported `tpm` | | NOT_RUN | |
| KEY-06 | P0 | macOS (unsigned) | — | Detect | `keyProtection = "unavailable"`, `installPublicKey = null`; **no Keychain password prompt**; results unsigned | `keyProtection: unavailable`, `installPublicKey: null`; login keychain SafeAgent items 0 before/after; no prompt | PASS | Mac 03:59Z |
| KEY-07 | P1 | macOS | — | Check Keychain Access for `com.kalvium.safeagent` items | None created by unsigned builds | | NOT_RUN | |

### B3. Parent check and authorization negatives

| ID | P | Platform | Prerequisites | Steps | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|
| PAR-01 | P0 | Win | Chrome + HIBu | Normal Check | `attestation.parent = "trusted"`; check runs | | NOT_RUN | |
| PAR-02 | P0 | Win | — | Record the real Chrome → host chain (direct vs `cmd.exe`) with Process Explorer | Matches the `classify_parent` model; note which | `safeagent.exe` ← `C:\Windows\system32\cmd.exe` ← `chrome.exe` (every check) | PASS | VM session capture 05:10Z |
| PAR-03 | P0 | Win | — | Repoint the HKCU manifest to a wrapper script that launches `safeagent.exe` (B11 reproduction) | Check returns `UNTRUSTED_PARENT`, findings `[]` | Wrapper registered in HKCU: page "We couldn't save this check", all Not checked; wrapper never launched by Chrome; no scan. Exact Chrome→wrapper→agent chain not captured | PASS (outcome) | VM 06:05Z; ATK-05 |
| PAR-04 | P0 | macOS | Chrome + HIBu | Normal Check | `parent = "trusted"` (strict Team ID requirement on Chrome's executable) | `safeagent` launched directly by Chrome main (pid 8349); page "Scanned" | PASS | Mac 05:04Z |
| PAR-05 | P0 | Win/macOS | — | Run the host from a terminal with a valid origin and pipe in hello + preflight | hello answers (metadata); preflight → `UNTRUSTED_PARENT` | Mac and VM: hello ok (metadata), preflight/authorize `UNTRUSTED_PARENT`, check `UNAUTHORIZED`, findings 0, nothing signed | PASS | Mac 03:59Z; VM 06:00Z |
| PAR-06 | P1 | Win/macOS | Edge or Chromium installed | Point the Edge/Chromium manifest at SafeAgent and check | `UNTRUSTED_PARENT` (Chrome only) | | NOT_RUN | |
| AUT-01 | P0 | any | — | Forged grant (one byte changed) | `INVALID_SIGNATURE`, nothing scanned | Forged grant → refused before verification (`UNTRUSTED_PARENT` from terminal); no scan, findings 0 | PASS | VM 06:00Z |
| AUT-02 | P0 | any | — | Replay a used preflight grant | `CHALLENGE_REUSED` | | NOT_RUN | |
| AUT-03 | P0 | any | — | Expired grant | Rejected, no findings | | NOT_RUN | |
| AUT-04 | P1 | any | — | `safeagent --build-info` on the packaged binary | `parentCheck=enforced` | `--build-info` → `parentCheck=enforced` on packaged Mac and installed Windows binaries | PASS | Mac, VM |

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
| LIF-01 | P0 | Win/macOS | Current HIBu | Detect + Check with 0.2.5 | HIBu accepts the reply with the extra fields (no `timeout` / `bridge_unavailable`) | Mac (findings listed, Scanned) and VM (only RDP + VM findings, Scanned); HIBu accepts the new reply fields | PASS | Mac 05:04Z screenshot; VM 05:10Z screenshot |
| LIF-02 | P0 | Win/macOS | — | Time the first Detect (key open + self-hash) | Under HIBu's 5 s hello timeout; record ms | hello 34 ms (Mac, no key), 107–233 ms (VM, key open + self-hash) | PASS | under HIBu 5 s |
| LIF-03 | P1 | Win | Check running | Kill `safeagent.exe` | HIBu → unavailable/timeout; the next Check works | | NOT_RUN | |
| LIF-04 | P1 | Win/macOS | Monitoring | Repeated checks over 15 min | Each check signed; `observedAt` increases | | NOT_RUN | |
| LIF-05 | P1 | any | Managed Chrome profile (policy) | Detect + Check | Works; note the policies present | | NOT_RUN | |
| LIF-06 | P1 | any | Unmanaged profile | Detect + Check | Works | | NOT_RUN | |
| LIF-07 | P2 | any | — | `UNTRUSTED_PARENT` surfaced in HIBu | A specific student message (HIBu change) | | NOT_RUN | |

## E. Attack-surface sign-off (where students will actually try)

Each row is a real attack a student can attempt on their own laptop, ordered by likelihood × ease.
"Catch point" is where the attack must fail or be flagged. Expected outcomes are honest: some are
caught only once the Assessment API verifies signatures (marked **server**). Run on the Dev VM,
authorized, with the build under test. Status starts NOT_RUN; record evidence for every run.

| ID | Likelihood | Attack (what a student does) | Catch point | Expected today (0.2.6) | Status | Evidence |
|---|---|---|---|---|---|---|
| ATK-01 | Very high | Close the cheating app before Check, reopen after Begin | Monitoring (H5), not SafeAgent | Not caught by a one-time check (accepted gap) | NOT_RUN | |
| ATK-02 | Very high | Rename the cheating app's exe | SafeAgent signer/OriginalFilename match | Caught for signed apps (proven 0.2.4 AnyDesk); unsigned → "Unsigned programs" | NOT_RUN | |
| ATK-03 | High | Use a tool not in the catalog | Unsigned / user-folder rules, server review | Caught only if unsigned or in user folders | NOT_RUN | |
| ATK-04 | High | Post a fake "ready" to the API with own token (B13) | **server** signature verify | Accepted today (`client_reported`); must be rejected once API verifies | NOT_RUN | |
| ATK-05 | High | Wrapper registered in HKCU strips findings (B11) | SafeAgent parent check | HKCU wrapper: no clean result, Begin blocked; parent refusal proven by ATK-14. Chrome→wrapper chain to re-run | PASS (outcome) | VM 06:05Z |
| ATK-06 | Medium | Wrapper launched **by Chrome via cmd.exe** chain | SafeAgent parent check (grandparent) | `UNTRUSTED_PARENT` (parent is the wrapper, not System32 cmd.exe) | NOT_RUN | |
| ATK-07 | Medium | Edit `signedResult` (e.g. drop a finding) and relay | **server** exact-byte verify | Signed bytes cover findings; Node rejects altered payload (CI interop). Server rejection pending | PASS (agent) / BLOCKED (server) | CI |
| ATK-08 | Medium | Keep `signedResult`, edit outer `ok`/`findings` | **server** uses signed bytes only | Signed bytes carry ok/errorCode/authState (unit test). Server must ignore outer fields | PASS (agent) / BLOCKED (server) | CI |
| ATK-09 | Medium | Replay an old clean signed result for a new preflight | **server** preflightId/challenge binding | Fresh challenge/instance per connection; preflightId bound (unit test) | PASS (agent) / BLOCKED (server) | CI |
| ATK-10 | Medium | Replace `safeagent.exe` with a patched copy | **server** `selfHash` ∉ approved `binarySha256` | Patched binary runs, reports `selfHash` a4ad8598… ≠ published 5855c5cb…; restored | PASS (agent) / BLOCKED (server allowlist) | VM 06:00Z |
| ATK-11 | Medium | Patched agent that reports the real hash and signs clean | Residual (R1) | Not caught locally; server consistency + review only | NOT_RUN | |
| ATK-12 | Low | Plant a weak/exportable key under our CNG name | SafeAgent key policy | Policy rejects exportable / wrong length / P-384 / ECDH / malformed keys | PASS | CI unit test |
| ATK-13 | Low | Delete the device key between checks | **server** key change = new enrollment | Deleting keys produced a new public key (0.2.6 retest) | PASS (agent) / BLOCKED (server flag) | VM 05:39Z |
| ATK-14 | Low | Run the host from a terminal / script with a valid origin | SafeAgent parent check | Terminal launch: checks refused, findings 0, nothing signed | PASS | VM 06:00Z, Mac |
| ATK-15 | Low | Use another browser (Edge/Chromium) with HIBu | Parent check (Chrome only) + HIBu absent | `UNTRUSTED_PARENT` | NOT_RUN | |
| ATK-16 | Low | Clock moved forward/back | Grant wall + monotonic deadlines | Forged grant refused before any scan | PASS | VM 06:00Z |
| ATK-17 | Low | Run inside a VM / via remote desktop | VM + remote-session findings | "Remote desktop session" + "Running inside a virtual machine" reported | PASS | VM 05:10Z |
| ATK-18 | Low | Kill SafeAgent mid-check | HIBu timeout → unavailable | Not clean; Begin blocked in Required (proven 0.2.4 B10) | NOT_RUN | |
| ATK-19 | Very low | Kernel hook / modified OS lying to a genuine agent | Residual | Not caught (documented limit) | N/A | |
| ATK-20 | Very low | Second device / phone / helper in the room | Layer 1 + proctor | Out of SafeAgent scope | N/A | |

**Sign-off rule:** every High/Very-high row must be PASS or an explicitly accepted gap with an
owner. Rows marked **server** stay BLOCKED until the Assessment API verifies signed results;
SafeAgent's half (correct signed bytes, correct refusal) is verified now.

## F. Automated regression (runs in CI on every PR)

| Gate | Where | What it proves |
|---|---|---|
| Real CNG key create → reuse → sign → Node verify | Windows CI runner (software KSP) | Device-key path and verifier interop work on real Windows |
| CNG key policy (TPM `ECDSA` and KSP `ECDSA_P256` names; reject exportable, wrong length, P-384, ECDH, malformed) | all targets | KEY-01 regression |
| Parent classification (Chrome, cmd.exe intermediary, impostors, unknown) | all targets (Windows-specific on Windows) | ATK-05/06/14/15 logic |
| Signed bytes include outcome, binding, attestation; cross-connection difference | all targets | ATK-07/08/09 agent half |
| Node interop: SPKI and DER accepted; tampered/wrong key/malformed rejected | macOS/Linux with Node | Verifier contract |
| `--build-info` gate on the packaged binary | packaging | Test bypass cannot ship |

Hosted runners have no TPM; the TPM path is verified on the Dev VM (KEY-01).

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

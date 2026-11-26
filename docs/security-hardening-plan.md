# SafeAgent security hardening plan (items 1-3 shipped in 0.2.5)

Public document. No incident detail, no student data, no tool-specific evasion notes.

Goal: a result is trusted only if a genuine, unmodified SafeAgent, launched by Chrome, produced
it on a registered device for exactly this grant. In Required mode anything else is rejected and
flagged; it is never silently accepted. On a student-owned machine this raises cost and leaves
evidence; it does not prove the machine is clean (see "Not covered").

## Proven gaps this closes (Dev, 26 Nov 2026)

| ID | Gap | Closed by |
|---|---|---|
| B11 | A wrapper registered through the editable per-user native-host entry ran the real agent and removed findings; result stored as clean | 1, 2, 3, 4, 7 |
| B13 | A student called the preflight API directly with their own token and a made-up clean result; stored as `client_reported` | 1, 6, 7 |
| B15 | OS-level hooks hiding processes from a genuine agent | 5 (detection only, partial) |

## Build order and ownership

Each item is a small PR. Items 1-3 ship together. Rollout order: SafeAgent, HIBu, then the server flag.

| # | Change | Repo | Effort | Depends on |
|---|---|---|---|---|
| 1 | Signed results (protocol v3): device key, `register`, signed reply | safe-assess-agent (+ nucleus-apps verify) | 2-3 d | protocol spec first |
| 2 | Binary integrity: `selfHash`, `selfSigner`; server accepts published hashes | safe-assess-agent + release + nucleus-apps | 0.5-1 d | 1 |
| 3 | Parent check: refuse unless launched by signed Chrome | safe-assess-agent | 0.5 d | existing signer code |
| 4 | Registration the student cannot edit (Windows machine-wide) | safe-assess-agent packaging | 1 d + admin-install UX | VM test of lookup order |
| 5 | Integrity block: process count, baseline processes, vendor share, scan time | safe-assess-agent + nucleus-apps | 1 d | none |
| 6 | Server picks the challenge | nucleus-apps + hibu | 0.5 d | none |
| 7 | Server rejects unsigned results in Required mode behind a flag, default off | nucleus-apps | 0.5 d | 1-3 live on Dev |

Items 6 and 7 and the server half of 1, 2 and 5 are not in this repo. They are specified here
so the nucleus-apps and HIBu work has one contract.

## 1. Signed results (protocol v3)

- **Key algorithm:** ECDSA P-256 / SHA-256. TPM and Secure Enclave keys support P-256 only
  (Apple documents Secure Enclave as P-256 only), so v2's Ed25519 cannot be reused.
- **Windows:** CNG key in the `Microsoft Platform Crypto Provider` (TPM), per user, non-exportable.
  Fallback: `Microsoft Software Key Storage Provider`, non-exportable. Reported as
  `keyProtection: "tpm" | "software"`.
- **macOS:** Secure Enclave key (`kSecAttrTokenIDSecureEnclave`) needs a Developer ID signed
  build. Unsigned Dev builds fall back to a login-keychain software key (`keyProtection:
  "software"`). Reported as `"secure-enclave" | "software"`.
- **Never** write private keys to disk or return them. Public key only.
- **`register`** (new command): returns `installPublicKey` (SPKI DER, base64url), `keyProtection`,
  `selfHash`, `selfSigner`. The server binds the key to student + device on first check.
- **Signed reply:** every `preflight` and monitoring `check` reply carries `signedResult`
  (base64url of the exact UTF-8 bytes signed) and `resultSignature` (DER ECDSA, base64url).
  The signed bytes are the canonical serialisation of:

```json
{"v":3,"preflightId":"...","challenge":"...","agentInstanceId":"...","observedAt":0,
 "agentVersion":"0.2.5","capabilities":{},"findings":[],"integrity":{},"selfHash":"..."}
```

- Sign once, return the signed bytes; consumers never re-serialise.
- v2 replies keep working through version negotiation. Mismatch fails closed.
- No new dependency by default: use Windows CNG (`NCrypt*`) and macOS `Security.framework`
  through the existing system-API approach. P-256 verification on the server uses Node `crypto`.
- If CNG or Keychain access fails, report `keyProtection: "unavailable"` and sign nothing. The
  server treats an unsigned result as untrusted; the agent never falls back to a file key.

## 2. Binary integrity

- Compute SHA-256 of the running image (`current_exe`) at startup and report it as `selfHash`,
  plus `selfSigner` (Authenticode subject or Team ID, from the code in `signing.rs`).
- The release workflow publishes per-version, per-platform hashes of the **inner** binary in
  `provenance.json`. The server accepts only hashes published for the reported `agentVersion`.
- Unsigned Dev builds report `selfSigner: null`; the server's Dev channel allows that, Prod does not.
- This does not stop a patched agent that lies about its own hash. Hash reporting is only
  trustworthy together with signed releases and with item 3 (a genuine signed parent).

## 3. Parent check

- Resolve the parent process image (Windows toolhelp; macOS `proc_pidinfo`), verify its signature
  with the existing signer code, require Google Chrome: Authenticode subject "Google LLC" or
  macOS Team ID `EQHXZ8M8AV` (seen on the installed Chrome app).
- On mismatch: `ok:false`, `error.code: UNTRUSTED_PARENT`, no findings, and `parent` recorded in
  `integrity`.
- Chrome's process layout (browser process vs helper processes) must be verified on a real Windows
  Chrome before this ships. Tests use fixtures; the real topology is a VM test (V3 below).
- Chromium and Edge are not allowed unless explicitly added to the list.
- Limit: a wrapper that is itself launched by Chrome and spawns the agent as a child makes the
  parent the wrapper. That is caught here. A wrapper that replaces the registered host path is
  caught by 4 and, at the server, by 2.

## 4. Registration the student cannot edit (Windows)

- **Today:** HKCU `Software\Google\Chrome\NativeMessagingHosts\com.kalvium.safeagent` and
  `%LOCALAPPDATA%\Kalvium\SafeAgent`, no admin. A student can repoint it (B11).
- **Change:** register under HKLM and install to Program Files, with an admin installer, as the
  macOS package already does (`/Library/...`). Keep a per-user fallback only for Dev builds.
- **Chrome policy `NativeMessagingUserLevelHosts=false`** makes Chrome use system-level hosts only
  (confirmed from Chromium's policy template; supported on Chrome 34+, per-profile). It is the
  strongest control but needs a managed device or admin rights. Students on their own laptops
  would have to set it themselves, so treat it as an option for managed labs, not the default.
- **Unverified, test on the VM (V4):** Chrome's order when both HKCU and HKLM define the same host
  name, and whether a student can still shadow an HKLM entry through HKCU. If HKCU wins, item 4
  alone does not close B11 and the agent must report `manifestMatchesSelf` for the HKCU path too.
- The agent reads the registry entry for its own host name and reports
  `manifestMatchesSelf` (true only if the registered manifest points at this exact image).
- **UX cost:** a UAC prompt on install. Students without admin rights cannot install. This needs a
  decision on managed-lab vs BYOD, and a Linux/Mac equivalent statement.

## 5. Integrity block (no PII, counts only)

Fields in every signed result: `processCount`, `baselinePresent` (Windows: explorer, csrss,
winlogon, lsass; macOS: launchd, WindowServer, loginwindow), `vendorShare` (fraction of processes
signed by Microsoft/Apple), `scanMs`, `installAgeSec`, `manifestMatchesSelf`, `parent` verdict.

- The server turns these into `integrity_flags` (for example `no_baseline_processes`,
  `implausibly_few_processes`, `scan_too_fast`) and **flags for review; it does not auto-block**.
- Thresholds are set from measured golden machines, not guessed. Until measured, flags are
  recorded but not enforced.
- This detects crude hooks and replayed canned results. It does not defeat a kernel-level hook.

## 6. Server-chosen challenge (nucleus-apps + HIBu)

- Today the client sends `binding.challenge` (the agent's own `authChallenge`) at `issue`. The
  server only checks that it matches on retry.
- Change: the server also generates a `nonce`, includes it in the signed grant payload, and the
  agent folds it into the signed result. `complete` verifies the nonce and single use. The client
  cannot choose or predict it.
- Grant payload gains `nonce` (v4 grant), a protocol change agreed with the backend before coding.

## 7. Required-mode enforcement (nucleus-apps)

- Flag `ASSESSMENT_V2_LAYER3_SIGNED_RESULTS_REQUIRED`, **default off**, in `.env.example`.
- When on, Required-mode Begin and in-attempt status reject unsigned or invalid results with
  reason `device_check_untrusted`.
- Server checks, in order: signature valid for the registered device key; `selfHash` published
  for `agentVersion`; parent verdict ok; nonce matches; `manifestMatchesSelf`; then integrity flags.
- Store verdict and flags with each preflight and monitoring event; log
  `{module:'layer3', event:'result_rejected', reason, flags, agentVersion}`.
- Telemetry before trusting it: rate of rejected results by reason, per paper. Alert if more than
  X% of starters are rejected.
- Roll out Dev, then one pilot paper, then cohort. Per-paper opt-in.

## What this still does not stop

- Kernel-level hooks, or a modified OS that lies to a genuine, signed agent.
- A genuine agent inside a VM (VM detection catches common hypervisors only).
- A second device, a phone or another person (Layer 1 camera and proctors).
- A patched agent on the student's machine that can use that install's TPM key to sign false
  results. Signed results prove which install produced a result, not that the install is honest.
  Mitigations: signed releases plus a server hash allowlist, parent check, integrity flags,
  periodic in-attempt checks and human review.

## Validation required before enabling

- **V1** Reproduce B11 (wrapper) on the Dev Windows VM: result rejected `device_check_untrusted`.
- **V2** Reproduce B13 (direct API fake): rejected, no result stored as trusted.
- **V3** Golden clean Windows and macOS machines still pass; Chrome helper-process topology
  verified for the parent check.
- **V4** HKCU-vs-HKLM lookup order and whether HKCU can shadow an HKLM host.
- **V5** TPM key present vs absent (the VM has vTPM and Secure Boot): `keyProtection` reported
  correctly in both cases; signature verifies on the server.
- **V6** Scan time with the extra work stays under the 5 s bar.
- **V7** No change to Windows/macOS behaviour when signed results are disabled (v2 compatibility).
- State plainly what each did **not** cover.

## Decisions (Ayush, 26 Nov 2026)

1. **Windows install model:** admin installer (HKLM + Program Files) for everyone. Per-user install
   remains only for Dev builds.
2. **Chrome policy `NativeMessagingUserLevelHosts=false`:** push it through the same admin
   policy that force-installs HIBu. It makes Chrome ignore per-user hosts, so a student's HKCU
   entry cannot redirect the host whatever Chrome's HKCU/HKLM order is. Dev and test machines
   that install per-user need a separate policy group.
3. **Parent allowlist:** Chrome only. Edge and Chromium are refused (`UNTRUSTED_PARENT`); HIBu is
   not present there anyway.
4. **Key protection:** accept software-only keys at first, flagged, with enforcement configurable
   per assessment:

| Environment | Hardware-backed key | Software-only key |
|---|---|---|
| Development | Accept | Accept |
| Production pilot | Accept | Accept + flag |
| Regular assessments | Accept | Configurable |
| High-stakes assessments | Require | Reject |

5. **Override when a device cannot sign: not a SafeAgent concern.** The existing Layer 3 waiver
   in nucleus-apps (`_shared/layer3-waivers.js`, merged in #9075) covers it: a `logOnly` waiver
   still runs and stores the check but never blocks that student. SafeAgent only reports why
   signing failed (`keyProtection: "unavailable"`, `UNTRUSTED_PARENT`, re-registration needed) so
   the proctor can decide. Item 7's `device_check_untrusted` rejection must honour `logOnly` like
   the rest of Required mode.

## Windows install UX change (decision 1)

The admin installer shows a UAC prompt. The student guide and `docs/upgrade-flow.md` gain a
"Windows asks if this app may make changes: click **Yes**" step, shipped with the item 4 PR.

# Student update flow (SafeAgent side + HIBu/backend contract)

Goal: a student with an old SafeAgent gets "Update required", then three steps
(download, open, Detect again), with no uninstall, no Chrome restart and no engineer.

## What SafeAgent guarantees (0.2.2)

- `hello` returns `agentVersion` and needs no grant. It is the only input HIBu needs to
  decide "update required".
- **In-place upgrade, no uninstall.** Windows uses the same `AppId`, per-user location and
  HKCU registration, and the installer overwrites the binary. macOS uses the same package ID;
  the new `.pkg` replaces the binary. Chrome reads the manifest fresh on every launch, so no
  browser restart is needed.
- The Windows installer is two clicks: Install (the safety box is shown only on update), then
  Finish. The welcome, folder and ready pages are disabled.
- A stale Windows registration (the manifest file was deleted) is overwritten silently.
  `SA-REG` appears only when another live copy is registered elsewhere.
- Silent install, update and uninstall (`/VERYSILENT /SUPPRESSMSGBOXES`) never hang.
- Unsigned builds still show SmartScreen ("More info, then Run anyway") or Gatekeeper
  ("Open Anyway"). This goes away only after code signing (release.md).

## What HIBu does (hibu#33)

1. On Detect or preflight, if `hello.agentVersion` is older than `requiredVersion` from
   `GET /api/v2/safeagent/current` (or outside `approvedAgentVersions`), stop with reason
   `update_required`. HIBu already emits this; see `native-preflight.js`.
2. Open `safeagent-setup.html?reason=update` in a new tab, never replacing the assessment tab.
   The page already renders the `outdated` status ("installed X, needed Y").
3. Page copy, per OS:
   - **Windows:** 1) Download the update. 2) Open it; if Windows warns, click More info, then
     Run anyway. 3) Tick "I am not taking an assessment", click Install, then Finish.
   - **macOS:** 1) Download the update. 2) Open the .pkg; if blocked, go to System Settings,
     then Privacy & Security, then Open Anyway. 3) Continue, then Install.
   - Then: "Return to your assessment tab and press Detect SafeAgent." The page already
     auto-rechecks every 4 s and turns Ready by itself.
4. Do **not** tell students to uninstall first. Show removal steps only behind a
   "Still not working?" disclosure:
   - Windows: Settings, then Apps, then "Kalvium SafeAgent", then Uninstall; then install again.
   - macOS (admin, Chrome closed):
     `sudo bash '/Library/Application Support/Kalvium/SafeAgent/uninstall.sh' --confirm-no-active-assessment`
5. HIBu must accept finding category `unverified` (new in 0.2.2). Older HIBu fails the whole
   observation when this category appears.

## What the backend does (nucleus-apps `fix/safeagent-version-config`)

- Set `ASSESSMENT_V2_SAFEAGENT_VERSION=0.2.2` together with the source commit, **after** HIBu
  with `unverified` support is live. The public `/api/v2/safeagent/current` then makes every
  older install show "Update required".
- The download endpoint already serves the configured catalog and a 5-minute signed URL.

## Rollout order

hibu#33 (accepts `unverified`, update page copy), then the 0.2.2 Internal Dev package, then the
VM suites, then the backend version bump. Bumping the backend first would make 0.2.2 results
fail on old HIBu.

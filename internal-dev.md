# Internal Dev distribution — 0.2.0

Developer-only, manually initiated testing on explicitly approved machines. This
is not a student release, production approval, OS compatibility certification,
or HIBU/backend integration certification. Native supports signed v3 one-shot
preflight grants over wire protocol 2; monitoring remains signed v2. Unsigned
installers and signed authorization grants are independent concerns.

## Workflow purpose

[Native CI](.github/workflows/safeagent-ci.yml) validates PR/main changes
with a test identity and unsigned artifacts; it is not the distribution route.
[Internal Dev](.github/workflows/safeagent-internal-dev.yml) is manually
dispatched from protected main for reviewed-source packages with approved Dev
identity/keys. Actions-only is its default; private GCS requires the separate
opt-in below. The dormant [production workflow](release.md) is independent:
protected-tag signing/notarization and GitHub Release publication remain off.
None of these workflows installs a host or enables assessment enforcement.

## Provisioning and review gates

1. Merge reviewed source/workflow to protected `main`. Dispatch
   `safeagent-internal-dev.yml` **from protected main**, supplying a full lowercase
   40-character reviewed commit SHA reachable from main. Branch names, tags,
   unmerged PR heads and abbreviated SHAs are rejected. Main ancestry is not
   proof of human approval: repository owners must enforce PR review/rulesets
   and review the selected commit; this workflow does not invent approval.
2. Pre-create `safeagent-internal-dev`, restrict deployment branches to main,
   restrict dispatch/environment administration to trusted maintainers and set
   these environment **variables**, not secrets:
   - `SAFEAGENT_ALLOWED_EXTENSION_IDS=khafofcbffjkkeeldejiplkfpdfckeol`
   - `SAFEAGENT_AUTH_PUBLIC_KEYS`: approved Dev `keyId:base64urlPublicKey` ring
     in the format in `.env.example`. Confirm its matching signer with the
     backend owner. Only public keys enter the native build. No fixture fallback.
   Required reviewers/prevent-self-review are recommended where the private
   repository's GitHub plan supports them. If unavailable, record the independent
   review in the PR and restrict dispatch to authorized maintainers; do not claim
   an environment approval gate exists. Environment/ruleset provisioning is not
   performed by YAML. Do not dispatch until these controls are in place.
3. Each fresh hosted runner validates keys with the runtime parser before building.
   No signing credentials or production certificate procurement is needed.
   Ordinary local `--dev` builders still permit keyless diagnostic/rejection
   builds; **functional pilot distribution requires compiled approved keys**.
4. Download only the matching SHA/target Actions artifact from the successful
   run: Windows x64, macOS arm64 or macOS x64. Each contains one `UNSIGNED-DEV`
   installer, `provenance.json`, and `SHA256SUMS` for installer and provenance.
   Verify checksums and source/target/identity/key IDs before use. Provenance is
   a build record, not a cryptographic attestation or approval. It contains no
   signer secrets or test keys. Artifacts expire after 14 days. By default this
   remains Actions-only: no Release, GCS, deployment, automatic install or updater.
   The optional separately approved upload job below copies validated packages to
   private Dev GCS; it does not enable a download endpoint or product rollout.

## Authorized manual device test and cleanup

- Obtain machine-owner/IT permission, use disposable developer devices where
  possible, and record OS/architecture/Chrome/version and artifact hash. Never
  install/repair/remove during an assessment. Finish assessments and fully close
  Chrome, including background processes, first; never kill processes to proceed.
- Host name is shared with production: `com.kalvium.safeagent`. Windows HKCU
  registration affects every Chrome profile for that user; macOS system paths
  affect all users/profiles. Use a machine without a production host; don't assume
  a separate Chrome profile isolates an installer. Review existing system and
  per-user registrations for shadowing before any change.
- Run the matching installer manually only if approved OS/organization policy
  permits it. Unsigned Windows software may be blocked by SmartScreen/enterprise
  policy; unsigned/unnotarized macOS packages may be blocked by Gatekeeper.
  **No security-control bypass**, quarantine removal, policy disabling or
  universal unsigned-installability claim. If blocked, stop and ask IT; use an
  approved development execution route or later signed distribution instead.
- Windows uses the fixed `%LOCALAPPDATA%\Kalvium\SafeAgent` directory, no
  elevation, service or destination selection. `/DIR` overrides are rejected;
  previous non-default registration blocks installation before payload changes.
  Have authorized IT inspect and uninstall the prior custom installation first;
  never blindly move/delete its directory or registry entry. Inventory prior
  custom installs even if registration is missing. macOS uses the documented
  system-wide paths and its normal manual administrator installation flow.
- Reopen Chrome with the approved stable Dev extension identity. Metadata hello
  must report version 0.2.0 and ready configuration, but is not readiness evidence.
  Test consented signed preflight/monitoring only with separately approved matching
  integration and backend signer. Native tests do not certify that integration.
- Cleanup: finish assessment tests and close Chrome (all users on macOS). Use
  Windows Installed Apps / the installed uninstaller, or the packaged macOS
  `uninstall.sh` under `/Library/Application Support/Kalvium/SafeAgent` via the
  authorized administrator. Review its scope first. Do not delete unrelated
  profiles or registrations. Verify owned registration/files are removed and
  reconnect reports host unavailable. Record failures; no silent repair/rollback.
  Restore any previous installation only through a separately approved package.

## Optional private GCS pilot — operator provisioning only

These are provisioning instructions, not evidence of live infrastructure or a
successful publication. No service account key, public bucket, public ACL, signed
URL stored in metadata, or production release is needed. Storage URL signing and Ed25519 grant signing are
**different** responsibilities/keys.

### GitHub controls and exact variables

Pre-create `safeagent-internal-dev-publishing`, allow deployments only from
protected `main`, restrict environment/variable administration and dispatch to
trusted maintainers, and require independent approval/prevent self-review where
supported. Apply the private-repo GitHub plan limitations described above to this
second environment too. Without required reviewers, use documented independent
approval before dispatch; do not describe it as a technical approval gate. The
upload job still has OIDC available to its steps: review every workflow/dependency
and selected source commit before approval.

Repository variable (must be at repository scope because job `if` is evaluated
before environment vars are loaded):

| Variable | Value / blast radius |
| --- | --- |
| `SAFEAGENT_DEV_GCS_PUBLICATION_ENABLED` | Default unset/`false`; only exact `true` permits the optional upload job. Also requires manual input `publish_to_dev_gcs=true`. Does not enable backend/student access, runtime enforcement, or production. |

`safeagent-internal-dev-publishing` environment **variables**, no secrets:

| Variable | Exact configuration |
| --- | --- |
| `SAFEAGENT_DEV_GCP_PROJECT_ID` | Dev Google Cloud project ID |
| `SAFEAGENT_DEV_GCS_BUCKET` | Bare dedicated private bucket name, e.g. `PROJECT-safeagent-dev`; no `gs://`, path, dots or URL |
| `SAFEAGENT_DEV_WIF_PROVIDER` | `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/safeagent-dev-github/providers/github` |
| `SAFEAGENT_DEV_UPLOAD_SERVICE_ACCOUNT` | `safeagent-dev-uploader@PROJECT_ID.iam.gserviceaccount.com` |
| `SAFEAGENT_ALLOWED_EXTENSION_IDS` | Exactly `khafofcbffjkkeeldejiplkfpdfckeol`, same as packaging environment |
| `SAFEAGENT_AUTH_PUBLIC_KEYS` | Exactly the approved Dev ring in packaging environment, including order/encoding. Runtime parser validates Ed25519 keys; publication matches IDs AND SHA-256 of exact ring, not merely key names. |

No private Ed25519 keys in Actions. The matching Dev grant signer remains with
the backend owner. The expected version is explicitly 0.2.0; future versions
require code review, not arbitrary dispatch input. `.env.example` documents all
flags/variables; Cargo and Actions do not automatically load that file.

### GCP setup commands — user/infra owner to run after review

Substitute your real project, repository numeric IDs, backend runtime identity
and globally unique bucket name. Use a dedicated WIF pool/provider and dedicated
bucket. Do not run these commands from CI. They are **infra mutations**, provided
as instructions only. An existing managed setup should receive equivalent scoped
bindings after review, not be blindly recreated.

```bash
PROJECT_ID='YOUR_DEV_PROJECT'
PROJECT_NUMBER='YOUR_NUMERIC_PROJECT_NUMBER'
BUCKET='YOUR_PROJECT-safeagent-dev'
REGION='asia-southeast1'
OWNER='YOUR_GITHUB_OWNER'
REPO='safe-assess-agent'
OWNER_ID='YOUR_NUMERIC_GITHUB_OWNER_ID'
REPO_ID='YOUR_NUMERIC_GITHUB_REPOSITORY_ID'
POOL='safeagent-dev-github'
PROVIDER='github'
UPLOADER="safeagent-dev-uploader@${PROJECT_ID}.iam.gserviceaccount.com"
URL_SIGNER="safeagent-dev-url-signer@${PROJECT_ID}.iam.gserviceaccount.com"
BACKEND_READER='YOUR_DEV_BACKEND_RUNTIME_SA@YOUR_PROJECT.iam.gserviceaccount.com'

gcloud services enable storage.googleapis.com iam.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com --project="$PROJECT_ID"
gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT_ID" \
  --location="$REGION" --uniform-bucket-level-access --public-access-prevention

gcloud iam service-accounts create safeagent-dev-uploader --project="$PROJECT_ID"
gcloud iam service-accounts create safeagent-dev-url-signer --project="$PROJECT_ID"
gcloud iam workload-identity-pools create "$POOL" --project="$PROJECT_ID" \
  --location=global --display-name='SafeAgent Dev GitHub only'
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
  --project="$PROJECT_ID" --location=global --workload-identity-pool="$POOL" \
  --issuer-uri='https://token.actions.githubusercontent.com' \
  --attribute-mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id' \
  --attribute-condition="assertion.repository_owner_id == '$OWNER_ID' && assertion.repository_id == '$REPO_ID' && assertion.ref == 'refs/heads/main' && assertion.event_name == 'workflow_dispatch' && assertion.sub == 'repo:$OWNER/$REPO:environment:safeagent-internal-dev-publishing' && assertion.workflow_ref == '$OWNER/$REPO/.github/workflows/safeagent-internal-dev.yml@refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding "$UPLOADER" \
  --project="$PROJECT_ID" --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/attribute.repository_id/$REPO_ID"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$UPLOADER" --role=roles/storage.objectCreator \
  --condition="expression=resource.name.startsWith('projects/_/buckets/$BUCKET/objects/internal-dev/0.2.0/'),title=safeagent-dev-create-only"
```

The provider condition assumes GitHub's default environment `sub`; if the org
customizes OIDC subject templates, align the exact claim restriction before
use. Numeric repository/owner IDs prevent reuse after a repository name transfer.
Protect main through repository rulesets; the shell additionally checks
`GITHUB_REF_PROTECTED`. WIF does not itself establish source approval.

Uploader gets **only objectCreator**, scoped to the pilot prefix: no object get,
list, delete, admin, URL signing or Token Creator role. The Python Storage SDK
uploads known names without pre-reading/listing the bucket. Every request uses
`Blob.upload_from_string(..., if_generation_match=0, retry=None)`, the supported
GCS generation precondition. Do not replace it with unguarded `cp`, `rsync`, a
public ACL, or a skip-existing flag. WIF auth creates temporary ADC credentials
on the runner and cleans them up; no JSON service-account key is provisioned.

For the **future backend** exact-object reader and URL signer, the owner can
create a custom read-only role without list access. Both read only this prefix;
backend picks an approved catalog from server configuration, never a bucket
listing. Use the existing backend runtime service account, not a new key file:

```bash
gcloud iam roles create safeagentDevObjectReader --project="$PROJECT_ID" \
  --title='SafeAgent Dev exact-object reader' --permissions=storage.objects.get \
  --stage=GA
for SA in "$BACKEND_READER" "$URL_SIGNER"; do
  gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
    --member="serviceAccount:$SA" --role="projects/$PROJECT_ID/roles/safeagentDevObjectReader" \
    --condition="expression=resource.name.startsWith('projects/_/buckets/$BUCKET/objects/internal-dev/0.2.0/'),title=safeagent-dev-read-only"
done
gcloud iam service-accounts add-iam-policy-binding "$URL_SIGNER" \
  --project="$PROJECT_ID" --member="serviceAccount:$BACKEND_READER" \
  --role=roles/iam.serviceAccountTokenCreator
```

Token Creator is bound **only on the URL-signing service account**, never the
project or uploader. It includes `iam.serviceAccounts.signBlob` (and other token
permissions); if organization policy supports a signBlob-only custom role, prefer
that narrower equivalent. Backend uses IAM Credentials `signBlob` via an SDK
remote signer to produce GCS V4 **GET** signed URLs; WIF/ADC authentication alone
does not sign URLs. The URL signer needs object read permission for the signed
GET to work. It is not the Ed25519 preflight/monitoring grant signer. Never grant
`allUsers`/`allAuthenticatedUsers`; enforce Public Access Prevention and uniform
bucket IAM, and audit inherited project/org access for broader grants. No bucket
lifecycle or retention policy is applied here; owners must choose retention and
orphan cleanup procedures before pilot use.

### Dispatch, object layout and failure semantics

1. Ensure this reviewed workflow and scripts exist at the selected main commit.
   Set the repository upload flag only after infrastructure/gates are reviewed.
   Dispatch from protected main with `source_sha=<full reviewed SHA>` and
   `publish_to_dev_gcs=true`. Packaging-only remains the default.
2. All three matrix targets must succeed. The upload job downloads only artifacts
   from **this run**, requires all three exact target directories and exactly one
   intended installer + provenance + checksums in each. It recomputes hashes/sizes,
   checks version, target, fixed extension identity, public key ring fingerprint,
   full source/workflow commits, run ID/attempt and protocol declarations. Unknown
   files/fields, mismatches, partial sets and symlinks fail before cloud auth.
3. Review/approve the publishing environment **before that job starts**, including
   its validation steps (environment approval is not a post-validation pause).
   Only this job has `id-token: write`;
   all jobs have `contents: read`, none has repository write permission. It
   revalidates before uploading. Generated catalog has no URLs/credentials.
4. Immutable objects are:
   `internal-dev/0.2.0/<40-char-source-commit>/<rust-target>/<installer-name>`,
   plus that target's `provenance.json` and `SHA256SUMS` (nine objects total).
   The tenth/final object is `internal-dev/0.2.0/<commit>/catalog.json`.
   Names are `safeagent-0.2.0-windows-x64-UNSIGNED-DEV.exe`,
   `safeagent-0.2.0-macos-arm64-UNSIGNED-DEV.pkg`, and
   `safeagent-0.2.0-macos-x64-UNSIGNED-DEV.pkg`. No `latest` alias is written.
5. The schemaVersion 1 catalog records version/source/workflow/run, wire protocol
   2, preflight grant 3/support, development-only unsigned/unnotarized status,
   exact extension ID, key IDs/fingerprint and each target's OS/arch, expected
   filename, object path, size, SHA-256 and provenance/checksum paths/hashes.
   Hashes establish artifact consistency, **not** OS signing, attestation or
   compatibility approval. Approve an exact catalog path separately in backend
   configuration after inspection; its existence must not auto-enable access.

GCS is not transactional across ten objects. Catalog-last is the completeness
marker: no catalog is attempted until all nine object creates return success.
Consumers must never infer a release from a prefix listing or isolated installer.
On any conflict (HTTP 412), timeout or interrupted upload, stop; there is no
skip/overwrite or automatic retry. Earlier creates can leave **orphans**. A lost
response on catalog creation can leave a complete catalog despite a failed job:
inspect with a separately authorized operator, not the uploader. Disable/withhold
backend approval until exact paths/hashes and completeness are verified.

Rerunning a completed publication fails safely on the first existing object.
Rerunning only failed jobs also rejects artifacts from a different run attempt;
rerun **all jobs** if rebuilding. Prefer a newly reviewed source commit for a new
publication. A partial prefix may be removed only by an explicitly authorized
operator after confirming no approved catalog/consumers exist and recording the
orphans; the workflow cannot delete. Do not delete/recreate an approved release
at the same path or grant uploader read/delete just to simplify retries. Disabling
`SAFEAGENT_DEV_GCS_PUBLICATION_ENABLED` blocks new upload jobs, not already-running
jobs or already-issued URLs; cancel/revoke access separately during incidents.

## HIBU and Assessment handoff — proposal, not implemented endpoints

Suggested owner API: **`GET /api/v2/safeagent/distribution?platform=windows|macos&arch=x64|arm64`**.
Only Windows x64, macOS x64 and macOS arm64 are available; reject Windows arm64,
unknown combinations or ambiguous selection. Browser architecture is only a hint.
No HIBU/backend code is changed here; owners must approve the contract and
compatibility independently before exposing it.

- Require normal authenticated student/internal-tester identity, authorization
  for this assessment/setup flow, and an explicit **Dev-only tester allowlist**.
  Ordinary students and production contexts must not receive unsigned packages.
  Default the new route/rollout OFF; owners must document their own flag/env names.
- Server selects one approved immutable catalog and validates its schema, source,
  extension ID, protocol, signature status and approved compatibility matrix.
  Never accept a client bucket, path, catalog, arbitrary URL or version override.
  Return **only the selected package**, not storage credentials or all targets:
  `url` (temporary HTTPS GCS V4 GET URL), `expiresAt` (UTC), `sha256`, `filename`,
  `version: "0.2.0"`, `signatureStatus: "unsigned"`. Suggested TTL: five minutes.
  Send `Cache-Control: no-store`; do not persist/log signed URLs or include them
  in catalogs/analytics. They are bearer links reusable until expiry; revoke
  tester access stops new links, not previously issued links. Refresh through the
  authenticated endpoint after expiry, never persist a signed URL as package ID.
- Assessment owns entitlement/consent and signed grant issuance; HIBU owns failure
  classification, selection guidance and native connection UI. Verify compiled
  public keys against the actual Dev Ed25519 signer. Approve HIBU version/identity,
  wire v2 + preflight grant v3, monitoring grant v2, capabilities and OS/browser
  versions separately; native packaging and SHA verification do not certify these.

Real pilot user flow: user explicitly enters approved Dev setup/preflight and
consents; HIBU performs metadata compatibility check there, **not during normal
browsing/enrollment**. A generic native disconnect does not prove the host is
missing: absent registration, policy denial, crash, wrong origin and stale
registration can look similar. Offer bounded diagnostics; recommend download only
when installation/upgrade is appropriate. Authorization denial/expiry means
re-authenticate/re-authorize or contact support, **not reinstall**.

For an approved missing/incompatible host, call the authenticated API, show the
selected version/unsigned status/hash and download the installer over HTTPS.
User/IT manually finishes/leaves assessments, fully quits Chrome (all affected
users on macOS), runs the OS installer only if policy permits, then reopens Chrome
and explicitly consents to **Check connection** again. No HIBU silent install,
elevation, registration write, auto-update or OS-security bypass. Unsigned
Gatekeeper/SmartScreen blocks mean stop and contact IT. Installer completion or
hello version is not readiness: repeat compatibility, signed one-shot preflight,
authorization and capability checks. This pilot is **advisory**, not admission
or cheating enforcement; do not change assessment policy based on download or
connection results. Consent, E2E integration and device lifecycle evidence remain
owner acceptance gates.

Owner acceptance: test unauthorized/non-allowlisted/production requests denied,
all three valid selections, unsupported/ambiguous arch rejected, URL expiry and
refresh, no credential/URL logging, hash verification, unavailable vs auth-error
UX, Chrome reopen and consented v3 preflight. Record exact device/OS/browser/HIBU
versions, selected catalog and observed authorization errors. Keep distribution
access/denial, URL-signing failures and preflight rejection metrics observable
without recording URLs, grants or private findings. No live-cloud, real installer,
Windows/Intel device, signed URL or end-to-end validation is claimed by local tests.

## Local builds without installation

Run from the repository root. Export the reviewed public configuration in
[.env.example](.env.example) first; Cargo does not load it automatically. Extension
IDs are exact, unique comma-separated 32-character lowercase `a`–`p` values with
no spaces. Public keys are embedded at build time; runtime env cannot override
them. Keyless local Dev builds are only useful for metadata/rejection diagnostics.
A functional pilot needs approved keys and a compatible backend signer.

Prerequisites: Rust stable and target toolchain; Windows MSVC Build Tools,
Python 3 and Inno Setup 6; macOS Xcode command-line tools (`pkgbuild`,
`productbuild`, Python 3). These commands build unsigned packages, not install them:

```powershell
# On Windows x64
./packaging/build-windows.ps1 -ExtensionIds $env:SAFEAGENT_ALLOWED_EXTENSION_IDS
```

```bash
# On macOS, choose the target machine's architecture
rustup target add aarch64-apple-darwin x86_64-apple-darwin
bash packaging/build-macos.sh arm64 "$SAFEAGENT_ALLOWED_EXTENSION_IDS" --dev
bash packaging/build-macos.sh x64 "$SAFEAGENT_ALLOWED_EXTENSION_IDS" --dev
```

Output is `dist/*-UNSIGNED-DEV.exe` or `dist/*-UNSIGNED-DEV.pkg`. Local builds do
not create the reviewed-main Actions provenance/catalog or approved distribution.
Never rename them as signed packages or bypass Gatekeeper/SmartScreen to install.
Follow the [authorized device procedure](#authorized-manual-device-test-and-cleanup).

## Local validation (no cloud, installation or services)

Run from the repository root unless noted:

```bash
python3 -B packaging/test-internal-dev-provenance.py
python3 -B packaging/test-internal-dev-catalog.py
cargo fmt --check
cargo test --locked
cargo test --locked --example validate-auth-config
cargo test --locked --test binary-authorization -- --ignored
cargo clippy --locked --all-targets -- -D warnings
# From repository root, with actionlint installed:
actionlint .github/workflows/safeagent-ci.yml .github/workflows/safeagent-internal-dev.yml .github/workflows/safeagent-release.yml
```

After building with explicit IDs, run the subprocess smoke (use `python` and
`target/x86_64-pc-windows-msvc/release/safeagent` on Windows; substitute the x64
macOS target as needed):

```bash
python3 -B packaging/smoke-native.py target/aarch64-apple-darwin/release/safeagent
```

Keep `SAFEAGENT_ALLOWED_EXTENSION_IDS` equal to the compiled IDs. This verifies
Chrome-style/explicit messaging launch, framed metadata, unauthorized rejection
and denied origins, not authorized platform coverage or real Chrome registration.

For a downloaded **complete same-run** artifact set, preserve one directory per
Actions artifact name under `/path/to/artifacts`, then generate/validate locally
without a Google SDK, credentials or cloud calls:

```bash
# In the repository root; values must match the reviewed packaging run.
export SOURCE_SHA='FULL_40_CHARACTER_SOURCE_SHA'
export GITHUB_SHA='FULL_40_CHARACTER_WORKFLOW_SHA'
export GITHUB_RUN_ID='NUMERIC_RUN_ID'
export GITHUB_RUN_ATTEMPT='NUMERIC_RUN_ATTEMPT'
export SAFEAGENT_AUTH_PUBLIC_KEYS='APPROVED_KEY_ID:APPROVED_BASE64URL_PUBLIC_KEY'
export SAFEAGENT_ALLOWED_EXTENSION_IDS='khafofcbffjkkeeldejiplkfpdfckeol'
cargo run --locked --example validate-auth-config -- --internal-dev
python3 -B packaging/internal-dev-catalog.py --artifacts /path/to/artifacts \
  --catalog /path/outside-artifacts/catalog.json
```

Do not add `--publish` locally; publication belongs to the approved CI job.
The catalog validator checks the exact key-ring fingerprint/shape; the preceding
Rust validator is responsible for cryptographic public-key validation. Both run
in the workflow. Output must be outside the artifact root to retain its strict
three-directory shape on repeated validation.

Python tests use synthetic installer bytes and mocked storage, including a local
catalog CLI invocation with no Google SDK installed. They prove manifest/hash and
create-only ordering/failure behavior, not authentic installers or live GCS IAM.
The ignored Rust binary authorization test builds/runs an isolated host with an
ephemeral test signer; it does not install/register a host or start a service.

## Production stays off

Repository variable `SAFEAGENT_PRODUCTION_RELEASE_ENABLED` defaults to disabled
(unset/anything except exact `true`). It gates both production signing and
publication in addition to existing tag/version/environment protections. Set it
only after production approval and provisioned signing/publishing environments;
its blast radius is the manual signed release workflow, not runtime enforcement.
The internal workflow neither reads nor enables that flag. Production signing,
notarization, device lifecycle evidence and cross-app rollout gates remain open.

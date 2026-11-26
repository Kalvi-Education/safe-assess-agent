# Independent readiness gates

A successful merge is not packaging acceptance. A packaged installer is not
pilot approval. No workflow here installs software or enables backend rollout.

| Gate | Workflow | Required evidence | Does not prove |
| --- | --- | --- | --- |
| Merge | `safeagent-ci.yml` | Three native target test/build checks, synthetic packaging-tool tests, ephemeral-key authorization and binary smoke | Installer lifecycle, real hardware signals, backend integration |
| Packaging | `safeagent-internal-dev.yml` | Reviewed main SHA, approved public configuration, all three installers, provenance and checksums | Installed-device compatibility or pilot readiness |
| Pilot | `safeagent-pilot.yml` | Exact source/package run, device evidence, backend evidence, bounded scope and owner approval | Production readiness or deployment |

The signed production release workflow remains independent and default-off. Its
signing/publishing approvals do not replace pilot acceptance.

## Merge protection

Require the native matrix checks from `SafeAgent native CI` for Windows x64,
macOS arm64 and macOS x64 in the main branch ruleset. Do not require manually
dispatched packaging or pilot checks for merging. Verify the exact check names
from a real Actions run before configuring the ruleset.

Native CI builds binaries, not installers. It retains the Windows test-only
overlay harness artifact for manual investigation; that artifact is not a
package or device-test result. Hardware/backend acceptance can remain explicitly
open in [tasks.md](../tasks.md) while a technically sound PR merges.

## Packaging acceptance

Dispatch Internal Dev from protected main with the reviewed full source SHA.
Existing environment approvals, public-key validation, provenance and optional
private GCS publication controls remain unchanged. Packages live in that run's
artifacts; merge CI no longer produces installers.

Successful packaging establishes artifact creation only. Approvers must compare
installer hashes in device evidence with that run's provenance/checksums. The
pilot workflow verifies run identity and unexpired artifacts, not their contents
or device results. GCS publication is optional and not a pilot prerequisite.

## Pilot approval setup (repository administrator)

Before setting repository variable `SAFEAGENT_PILOT_APPROVAL_ENABLED=true`:

1. Create environment `safeagent-pilot` with required owner reviewers, prevent
   self-review, restrict deployment branches to protected main and disallow
   administrator bypass where supported.
2. Verify these protection features are actually available and enforced for this
   repository/plan. An environment name in YAML alone is not an approval gate.
   If protection cannot be enforced, leave the flag off.
3. Assign native/device and backend owners to review the evidence together.
   Keep links access-controlled; workflow inputs and summaries in this public
   repository must contain no credentials, grants, student identities or findings.

The flag defaults off when unset. It only enables this manual approval record;
its blast radius excludes deployment, installation, cloud publication and app
feature flags. Reverting it to false disables future approval runs, not a pilot
already enabled through external systems.

Dispatch `SafeAgent pilot readiness approval` from protected main with:

- The exact reviewed source SHA and a successful Internal Dev packaging run ID
  from this repository. All three matching artifacts must still be unexpired.
- HTTPS device evidence covering the intended OS/browser/architecture matrix,
  installer lifecycle, permission limits, positive/negative signed probes and
  exact installer hashes. Unsupported targets remain excluded from the scope.
- HTTPS backend evidence covering consent, matching signers, same-port handshakes,
  durable receipts, ownership, retries, disconnect/expiry/stop and no collection
  in unrelated or flag-off flows. Use [tasks.md](../tasks.md) for the full checklist.
- A bounded cohort/device scope, accountable owner, monitoring and rollback plan
  reference, without naming students in workflow inputs.

Review the evidence job summary **before** approving `safeagent-pilot`. HTTPS
syntax and artifact existence do not prove the contents are complete or true.
The workflow does not fetch evidence URLs or execute submitted source. Human
approval attests only to that run's exact source, packages and scope. Record a new
approval for changed inputs; never reuse it for a broader cohort.

After approval, external app owners perform any separately authorized rollout.
Watch authorization rejection/expiry, disconnects, coverage gaps, upload failures
and unavailable results; stop the pilot on privacy/consent violations or systemic
failure. Keep collection flags off until that external decision. There is no
native auto-rollout or enforcement added here.

## Validation boundaries

Workflow lint/static review is not an executed Actions run. Repository rulesets,
environments, reviewers, signing/cloud infrastructure, hardware tests and backend
integration must be provisioned and verified separately. Do not label this gate
setup or a successful approval job as completed deployment.

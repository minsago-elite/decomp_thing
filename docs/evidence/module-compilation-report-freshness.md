# Hosted module report freshness ordering

## Previous hosted attempt

Run [40273796946](https://github.com/minsago-elite/decomp_thing/actions/runs/40273796946), job `121412120727`, checked out merge commit `829034f722f5a64412d714ec889361c95557e658` (PR #1813 head `16e3b19cd209dc69d5c870c9ef583b9d2aaaa5b4` over #1800 head `6dac057d9681ea7c514d99a03da351d9487c0be4`). The report capture says:

- Worker deployment re-entry, provisioning, Java/runtime setup, scratch preparation, class and test compilation, hosted manifests, compiled-class evidence, and the 104-method/21-class inventory completed.
- The live Gradle task failed before JUnit started at `module-compilation-qualification.init.gradle:242`: `refusing existing hosted compiler test reports`.
- All 13 required cases are `not-started`, with no case records. XML verification and case reconciliation consequently fail with `report file membership differs`.
- Both owned scratch release commands succeeded. The attempt is a Gradle output-preparation ordering failure, not an outcome for the compiler or FD policy.

Artifacts from the attempt are retained locally under `.omo/a-series-20261026/qualifier-40273796946/`.

## Correction

The initialization script registers a no-output freshness prerequisite (originally `moduleCompilationLiveQualificationFreshness`, now consolidated with the parent's `moduleCompilerLivePreflight`). It checks the exact report path with `NOFOLLOW_LINKS`, so stale directories, files, and symlinks refuse before the Test task prepares its output directory. The live Test task depends on that prerequisite and no longer repeats the check in `doFirst` after output preparation.

The qualifier shell preflight remains in place. Follow-up commit `2ae6b9dbb994b38b294112ee8ea5a84fa81a9a58` covers the compiled inventory node as well as report paths. It now treats a symlink at either guarded report/index path as existing state, including a dangling symlink, and refuses before Gradle starts.

## Local verification

- `python3 scripts/test-module-compilation-qualification-freshness.py`: 3 Python controls passed. They preserve stale XML bytes on refusal, reject a symlinked report path, statically verify production task wiring, and run a real one-test Gradle `Test` task after the prerequisite to prove fresh report output is not rejected.
- `python3 scripts/test-module-compilation-qualification-routing.py`: 14 routing controls passed. The added control rejects a dangling `compiled-live-tests.json` symlink before any Gradle or operator command, leaves the symlink intact, and proves its target was not created.
- `bash -n scripts/qualify-contained-module-compilation.sh` and `git diff --check` passed.

Raw logs and source hashes are under `.omo/a-series-20261026/module-deployment-report-freshness/`.

## Remediation checkpoint (2026-10-27)

The non-destructive merge of parent #1800 at `8a714d3522358fdb80b7904f0934b649daa149f5`
keeps one production freshness prerequisite and the parent's stronger
`scripts/test-module-compilation-qualification-preflight.sh` workflow regression.
That fixture loads the actual production init script, executes a real one-test
Gradle `Test` task, preserves stale XML, and refuses empty directories and dangling
report links. The retained Python wiring control now checks the consolidated task
name; its copied miniature Gradle example is historical, not the required workflow
qualification. Routing controls additionally cover dangling report, inventory and
case paths. Local verification passed the production-init regression, 16 routing,
36 reconciliation, 3 quota-cleanup and 2 nonduplicative Python freshness controls.

Independent source inspection also found that stage/manifest ownership checks did
not compare each staged JAR's UID/GID. Re-entry now binds each member owner to its
already authenticated stage owner. A focused regression models consistent foreign
UID and GID observations without requiring privileged `chown`; both cases failed
before the fix and pass afterward, preserving all frozen manifest/member bytes on
refusal. All 16 deployment controls, including the actual repeated Gradle task,
pass. This does not change compiler limits, installed runtime authority, or the
required configured qualification cases.

Raw remediation logs and active YAML/Python LSP results are retained under
`.worktrees/review-remediation/evidence/prs/1813/live/`. Kotlin changes inherited
from the parent retain its 159-test focused evidence; full current-source builds,
bundled-Ghidra tests and configured containment remain Actions-owned gates.

## Final independent-review remediation (2026-10-27)

Independent review identified a second staged-member boundary: the metadata admitted
before hashing was not compared with the hash helper's later descriptor snapshot.
The verifier now requires the complete post-hash version (device, inode, mode,
link count, UID, GID, size, mtime and ctime) to equal that admission-time version,
as well as the final filename observation. A deterministic regression hashes the
actual unchanged bytes while modeling six transitions immediately after admission:
UID, GID, writable mode, link count, mtime and ctime. All six were accepted before
the correction and now refuse without altering frozen manifest/member bytes.
These are modeled interleavings, not an end-to-end privileged exploit demonstration.
All 18 deployment controls, including actual repeated Gradle invocation, pass.

The latest completed [qualification run 40437749681, job 121970424441](https://github.com/minsago-elite/decomp_thing/actions/runs/40437749681/job/121970424441)
reached JUnit at the previous child head `c03edaf754f006eceacc10715b3ca13a137183b3`:
104 tests, 91 failures and zero skips. All 91 failures contain the unsupported
foreign non-root compiler-owner refusal. The required case summary has five failed,
five not-started and three passed rows; this is not accepted qualification.
Artifact `12709593052` and its exact failure triage are retained in the evidence
directory below. This is not the earlier report-output preparation problem.

Non-destructive integration now includes parent #1800 at
`e8b03d6a84fd519f65b0829a1ab93a18676234fb` and upstream #1727's normal-completion
cleanup correction at `3bc38cd037fcd58fdc06c6f01575ca0f9e732f88`. The bounded,
digest-pinned owned compiler snapshot and read-only same-path alias retain ordinary
worker leases, noexec scratch, FD proof v2 and original resource/command policy.
Normal cleanup removes that staged executable only after proven process/scope
absence and scratch release. Foreign/unmapped ownership is not made trustworthy.
Fresh narrow artifact-assisted compilation of 39 changed Kotlin paths and 209 JUnit
methods passes with zero failures, errors or skips, including both-profile real
namespace/noexec regressions, foreign/substituted executable refusals, proof-tamper
controls and staged-executable cleanup. Unchanged dependencies are retained build
artifacts: this does **not** replace a full current-source build or authenticated
configured Make/Ninja qualification. Kotlin LSP is unavailable; active settled
Python/YAML LSP with an explicit workspace is clear on all supported changed paths.

Raw final-pass evidence uses `final-fix-*` names under
`.worktrees/review-remediation/evidence/prs/1813/live/`. #1827 remains open pending
actual hosted qualification and exact-head external code/security review. Parent
#1800/#1727 and #738's off-snapshot compiler-read integrity boundary remain separate
unresolved dependencies; no closure, acceptance or merge is claimed.

## Acceptance boundary

This correction is a qualification harness fix. The 13 actual configured Make/Ninja compiler, rollback, cancellation, refusal, cleanup, and retry cases still need to execute on a new exact-head hosted run with complete zero-skip XML and case evidence. The prior 13 `not-started` rows provide no compiler or FD-policy acceptance.

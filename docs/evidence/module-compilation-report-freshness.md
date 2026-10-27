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

## Acceptance boundary

This correction is a qualification harness fix. The 13 actual configured Make/Ninja compiler, rollback, cancellation, refusal, cleanup, and retry cases still need to execute on a new exact-head hosted run with complete zero-skip XML and case evidence. The prior 13 `not-started` rows provide no compiler or FD-policy acceptance.

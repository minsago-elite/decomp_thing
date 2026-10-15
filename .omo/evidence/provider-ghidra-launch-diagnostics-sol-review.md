# Ghidra export launch diagnostic source review

Verdict: **OKAY — proposed test-only diagnostic scope.** No blocking finding in the pinned delta. This is source/evidence review, not Kotlin compilation, executed diagnostic qualification, or a production fix/launch-cleanup approval.

## Exact inputs

Worktree: .claude/worktrees/wf_ce026d1b-c24-68. Source freeze build/provider-ghidra-launch-diagnostics/source-freeze.json SHA256634ee35585ed3d74c5ce70a73b63dec71602559ee2a30df5e627af54dbc69f7c. Current/proposed src/test/kotlin/decompengine/project/GhidraExportLaunchTest.kt SHA256d2c169b5fe61cb1e798704962594362a03bc005fb260562718390565f299729b; original/beforeff58510a97c132fb8517d32fe66c7faf647434ecf60406220bbc13ebc4aeaf5c; diff69cc3ce718a34989658ed13469b8ac1a594d21e82cc503ea9ad6e4f2a137935f.

All16 file entries in the supplied freeze, including baseline/proposed/live source, diagnostic evidence and five unchanged comparison files, were independently hash/size verified. No dependency drift among those supplied entries was observed. This review read source and existing evidence and calculated hashes only. It ran no tests/compiler/JVM/native/process/proc inspection/network/Git/remote/auth/model operation, created no process/session and edited no source. Only this additive report was written.

The completed495 binding receipt core-actual-source-bindings.json59db79c50da8855043b93f8197a128ead047139efa6f0fe482548e366922f6ae binds actual merge b8ebb93aadc83c2a84cfb64809f02fa9182330a4, tree01fe5f29a0658a114fdcd5709d788178a37789a3, head4952805b888db122580a1769203ae67252f972b9, and the six inspected original source files. Root's core-diagnosis.md186dc2ad785160be9163b65dbc662d6f5097842a038256db5750d3ac10ebeb89 remains the retained diagnosis; I did not acquire source/tree objects or rerun its artifact parsing.

## First failure and cleanup control flow

- The caller-interruption test:153–176 records the first caught body Throwable, then independently attempts the original release, caller join, worker cleanup, prior-evidence assertion and pool-idle check. finish rethrows the same first Throwable object after adding distinct secondary failures; no failure is translated to success.
- The two-abandoned-launchers test:180–239 independently attempts releases, each original conditional caller interruption and join, BOTH starters' assertLateWorkerReaped, every prior-evidence assertion and pool-idle check. A failure in starter0 cannot skip starter1, nor replace starter0's first failure. This satisfies the requested two-fixture cleanup reachability.
- BlockedStartedWorker.assertLateWorkerReaped:323–351 retains the first failed future/exit/aliveness assertion. Existing ensureStopped runs in the original acquired-handle finally and its failure is suppressed rather than replacing that assertion. If launched.get times out, no Process exists in that lexical scope; the code records stage1 and does not add a late lookup, acquisition or signal attempt.
- FixtureFailures:363–389 deduplicates repeated Throwable identities, records the first as primary, and adds later distinct failures via addSuppressed. Existing starter/caller exceptions are attached only after a body/cleanup failure has already occurred; expected cancellation/deadline exceptions alone do not make a previously passing test fail. Helpers never clear production sticky failure or convert unconfirmed cleanup to a pass.

## Bounded diagnostic content

FixtureState:391 uses RuntimeException(message.take(512),null,false,false): each owned-state record is at most512 characters and carries no new stack/cause/suppression tree. Fixed test populations bound records to at most2 workers and4 callers. Worker state:354–360 reads only owned atomic start stage/failure presence, latch counts, future completion/cancellation/exception flags and same-test-thread cleanup/stop flags. Caller state:417–420 reads only owned started/completed/interrupt-requested/failure-present flags. No raw command, environment, output, payload, authorization value or PID is converted to diagnostic text.

Existing exact exception objects retain their existing messages/stacks as requested; the512 cap applies to the newly authored state records, not to truncation/replacement of the primary Throwable. Caller/starter context is finite and identity-deduplicated. These local flag reads are snapshots and do not claim an atomic process lifecycle or cleanup success after observation.

## Scope and behavior preservation

Independent byte comparisons confirm the prefix containing all first three test method bodies/imports, the entire GatedExportFixture canonical-model block, and the complete companion-helper suffix are unchanged. The two changed test bodies plus BlockedStartedWorker/ExportCall fixture helpers contain the diagnostic-only delta. Existing ProcessBuilder, ProcessHandle, onExit, isAlive, waitFor, destroyForcibly and ready-byte read call sites/arguments remain; no process operation, late signaling path, host scan, extra wait, permit, deadline, grace or poison reset is introduced. Independent cleanup can reach original finite actions previously skipped by earlier throwables; it does not enlarge any individual allowance.

The new ExportCall.interrupt wrapper sets a local AtomicBoolean then performs the same thread.interrupt operation. Added caller start/completed flags and starter stage/caught-failure fields do not add asynchronous tasks or waiting. The raw pool-idle/ensureStopped/awaitIgnoringInterrupts helpers and canonical fixture remain byte-identical.

Five other inspected source files match the actual495 receipt unchanged:

| Path relative to repository root | SHA256 |
|---|---|
| .claude/worktrees/wf_ce026d1b-c24-68/src/test/kotlin/decompengine/project/GhidraExportLifecycleTest.kt | `9280384ab074089e785bfedf092682b993c04a73c2aa7f4a3527b4d6a3db552d` |
| .claude/worktrees/wf_ce026d1b-c24-68/src/test/kotlin/decompengine/project/GhidraProgramModelExporterTest.kt | `b3cccb580d9e09661790da8fb0f8aa4073f6e6d246214530ac0c6c879bf444b4` |
| .claude/worktrees/wf_ce026d1b-c24-68/src/test/kotlin/decompengine/project/GhidraSharedDeadlineTest.kt | `69c5669d9d24e1bd0edb42af34fd92b635a94b0f89cf8882298f626fe087d0dd` |
| .claude/worktrees/wf_ce026d1b-c24-68/src/main/kotlin/decompengine/analysis/BoundedAnalysisProcessLaunch.kt | `96ab543fd3e7263082a0918d5858ba948b82a0736d13b927100eac662bfe8a14` |
| .claude/worktrees/wf_ce026d1b-c24-68/src/main/kotlin/decompengine/project/ArchivalReconstruction.kt | `b16123c06ed7a6f57cde96259e535a7a5aa36a1f54cf02acc2103292f7a47e86` |

## Actual495 limits and next gate

The retained diagnosis identifies reported TimeoutException at OLD Launch309 launched.get(2s), before the process-exit wait at311. Thus those two stacks show an unpublished fixture handle within the allowance, not direct evidence that a published process could not exit. Unconditional cleanup previously could hide the earlier body failure and the first worker cleanup failure. Later evidence retains production's fatal refusal after an unconfirmed late-worker cleanup; the initiating owner/termination cause remains unknown.

The new stage/first-failure records can distinguish future handle-not-invoked/start-failed/not-published/ready/released and cleanup phases if another authorized test fails, but this source review does not show which branch occurred in495. It does not establish child-banner inheritance, timing, process visibility, native teardown or bundled Ghidra dependency causation. Root's actual-source binding resolves file provenance, not causation.

No production fix is claimed. Keep exact first failure, sticky refusal, all original deadlines and unknown cleanup semantics. Kotlin compilation and a separately authorized hosted check must qualify the diagnostics before interpreting new failure evidence or selecting a production correction. Root retains Git/remote/CI custody. Stop here.

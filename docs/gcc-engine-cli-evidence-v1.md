# GCC engine CLI contained-route evidence

This is a narrow source-contract record for issue #291, captured against source
revision `bf2501568f39ab52b23492dfc37839bb81895587`. It records repository facts
only; it is not a hosted execution receipt or a production qualification claim.

## Full-export policy consistency before worker admission

For a normal full-recovery export, the CLI authenticates its fixed structural input set and
reopens the retained compiler-engine policy before creating the operation coordinator. The
selected intent must name cc1, repeat the exact authenticated raw-profile digest and equal the
whole retained policy, including referenced inputs and planner/layout settings. A different
profile with similar artifacts or an unchanged digest alongside changed policy data is refused
before worker execution. Final full-export receipt/model/profile revalidation remains unchanged.

Five authored JSON-only controls cover exact copies, foreign profile identity, changed policy
data, foreign/missing/malformed selections and unbound expected policy. They create no profile
files, owner, native worker, host/controller context or credentialed request. They require their
own Actions evidence; this source change does not claim a completed export or causal timing data.

The checked serial profile, structural authority, resource ceilings and production target remain
unchanged. A proposed parallel/exporter-generation profile still needs its own reviewed structural
authority, deterministic fresh/resume and complete authenticated execution/scoring evidence. This
early consistency check supplies no profile admission, retry, release or scoring capability.

## Planner capture checkpoint handoff

The retained planner owner now passes its same-process admitted operation
deadline into output capture and assessment. Descriptor-bound reads request at
most 64 KiB per call and check between requests. The same callback reaches the
existing canonical model reader, module-plan text/entity traversal and exact
ownership checks. No phase receives a fresh clock. Existing entry points retain
their no-op compatibility delegation, and valid canonical bytes, provenance,
ownership, directory/file identity and incomplete/release-ineligible markers
retain their original meanings.

Six authored JVM methods cover exact-output compatibility, refusal at captured
handoffs, read-request boundaries, long plan text and interrupted ownership
traversal. Capture fixtures use repository-local temporary directories. These
methods await their own Actions qualification; no local subject run is claimed.

These cooperative checks alone do not preempt an indefinitely blocked native
read, charset conversion, general library JSON parsing, every sort/join,
allocation or rendering step. The next section bounds the owner's wait on them.

## Host capture budget and deadline-safe result publication (#982)

The planner owner runs output capture and assessment as one owned host step on a
dedicated thread, using its own duplicate of the pinned run directory. The owner
waits at most the operation deadline's remaining time. If the deadline passes, the
owner returns a bounded failure even when the step is blocked in a native read
that ignores interrupts or in one nonpreemptible library call. The step alone
closes its descriptors, so no timed-out caller closes an fd that a blocked
syscall still uses. It stops at its next checkpoint or when its syscall returns.
`close()` waits a short grace period for owned steps. If any step is still in
flight, it refuses to release disk and input ownership, which matches the
existing unproved cgroup-absence path.

Host memory for that step is held to the shared policy's `maximumResidentBytes`,
the same ceiling the planner cgroup receives. Capture starts only after cgroup
absence, so the host step never overlaps the worker. The step admits a 16 MiB
working reservation, each retained file at its exact size before allocation, and
128 bytes of assessment allocation per captured model, plan and metadata byte
before parsing. Local measurement of the current assessment found 55 to 77
allocated bytes per input byte, linear from 2,000 to 60,000 functions across
dense, code-bearing and bare models. At the checked 16 GiB policy, about 127 MiB
of captured input fits. Larger captures are refused rather than admitted without
proof. At every cooperative checkpoint, the thread's measured heap
allocation must stay within the admitted total. Measured allocation includes
garbage, so it is an upper bound on the heap the step can retain. Anything over
budget is refused with `GccBundledHostMemoryBudgetException` before the refused
allocation, or at the next checkpoint for measured growth. Planner stdout/stderr,
up to 64 MiB each, are now digested through a 64 KiB buffer instead of being
retained. The recorded sizes and SHA-256 values are unchanged. Allocation inside
one library call is seen only at the next checkpoint, and the JVM heap limit
remains the backstop. This is a host-phase budget, not a whole-process RSS
measurement.

`publishCliResult` publishes `result.json` through
`GccBundledDeadlineBoundPublication`. A fresh owner-only temporary is staged by
O_TMPFILE write/fsync, link and directory fsync, and each step is gated by the
deadline. A single `RENAME_NOREPLACE` may start only while at least one second
remains. The commit counts only if the deadline is still current when the rename
returns. The owner's existing post-publication checks then run, and acceptance
must still see a current deadline. Every failure removes the staged temporary and
revokes any committed target that still names this publication's inode. That
includes expiry during staging, a late rename, expiry before acceptance, and a
failed check. If the owner stops waiting first, the in-flight step revokes its
own commit when its syscall returns. A step that already finished is revoked by a
bounded cleanup step. An existing target or temporary is refused and left
untouched. The operation therefore reports success only for a result committed
and accepted before expiry, and a failed operation leaves no result or staging
residue.

No rename-based commit can stop a concurrent reader from seeing the name between
a late rename's return and its revocation. It also cannot survive process death
inside that window. Readers must keep requiring a successful CLI exit. The commit
reserve means that window opens only for a single rename slower than one second.
Only the planner CLI result uses this protocol. The full-export and native-call
CLI results keep their existing multi-file no-replace publication.

Focused JVM controls are in `GccBundledHostWorkTest`,
`GccBundledPlannerOutputCaptureTest` and `GccBundledDeadlineBoundPublicationTest`.
They cover a genuinely blocked FIFO read, budget refusal at admission and by
measurement, streamed logs, a blocked owned capture, and expiry or blocking at
every staging and commit point. These are local-component controls. They do not
qualify provisioned-host CLI wall time, peak RSS or real cc1/lto1 execution.

## Observed contract

- `Main.runGccEnginePlan` parses the immutable CLI selection and calls
  `GccBundledCliCommand.run`.
- `GccBundledCliCommand` commits `invocation.json`, builds the v2 operation intent
  from the retained profile and bundled deployment references, and enters
  `GccBundledOperationCoordinator.prepareNew`.
- Fresh execution calls `owner.execute()`. The checkpoint option calls
  `executeUntilCheckpoint` and `resume()` on that same retained owner. Both paths
  then call `owner.plan()` and `owner.publishCliResult()`.
- `GccBundledOperationCoordinator.plan()` requires this owner's completed export,
  rechecks the captured model, launches the planner through the contained
  systemd/cgroup boundary, and journals planner preparation, START, execution,
  and assessment.
- The published CLI result binds model, plan, request, export, planner execution,
  and planner assessment digests, while retaining `complete=false`,
  `releaseEligible=false`, and scratch disposition
  `retained; release and cold recovery unqualified`.

These facts preserve the bundled Ghidra Java-API route, authenticated input and
journal lineage, provenance-bound planner policy, and explicit unresolved status.

## Production gap

The repository still does not contain a successful provisioned-host fresh and
same-owner-resume receipt for genuine `cc1` and `lto1` inputs. The real-engine
runner remains opt-in and its own record keeps benchmark acceptance and release
eligibility false. The following gates therefore remain unavailable for #291:

- trusted bundled installation and dedicated scratch provisioning followed by
  actual installed-CLI execution;
- real fresh/resumed model and plan byte equivalence, including the separate
  cold-recovery question;
- whole-operation host-plus-worker wall/RSS/resource qualification and release;
- the parent #137 semantic-equivalence evidence and #55 scoring/benchmark
  evidence.

Until those gates produce retained evidence, this record supports the contained
route and its authority boundary only. It does not close #291 or its parent
issues.

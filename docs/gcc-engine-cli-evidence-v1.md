# GCC engine CLI contained-route evidence

This is a narrow source-contract record for issue #291, captured against source
revision `bf2501568f39ab52b23492dfc37839bb81895587`. It records repository facts
only; it is not a hosted execution receipt or a production qualification claim.

## Normal-CLI admission before START

`GccBundledCliCommand.admit` is the only pre-START path, and `run` uses it. It re-parses the argv,
binds the output, inputs and journal directory identities in `invocation.json`, authenticates the
selected engine, retained profile closure, Ghidra archive, bundled deployment and host containment
tools into the production intent, rechecks a full export's structural policy, and returns the
coordinator's prepared owner once the dedicated scratch lease is held. No worker has started then.

`GccBundledCliAdmissionTest` drives that path with genuine checked inputs: cc1 decoded from
`artifacts/gcc-cc1.stripped.xz`, the driver binary, the exporter-17 profile and the pinned archive.
The hosted oracle shard provisions the root-owned bundled runtime and a bounded ext4 slot. There,
fresh-plan, same-owner-resume and driver full-export selections each reach a prepared owner. Its
intent holds only authenticated identities and its journal has no START record. The owner refuses
every other selection, and an ordinary scratch directory is refused after the durable intent but
before any lease. On any host, an untrusted development runtime is refused before the journal or
lease. Genuine bytes substituted for another engine, or for the archive, are refused before staging.

This is admission evidence only. It does not run an export or the planner, and it does not
establish cold recovery (#981), whole-operation resource accounting (#982) or installed-CLI
execution (#984).

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
dedicated thread. Once the planner's lexical run-root borrow is revalidated, the
owner hands the step a kernel `F_DUPFD_CLOEXEC` duplicate of the pinned run-root
descriptor. That handoff does no path lookup or filesystem I/O. The owner
computes its wait from the operation deadline immediately before waiting. If the
deadline passes, the owner returns a bounded failure even when the step is
blocked in a native read or in one nonpreemptible library call. Abandonment never
interrupts the step: on JDK 21, `Thread.interrupt()` runs an NIO channel's close
on the interrupting thread, and that close waits for the blocked native operation
to retire. The step stops at its next checkpoint or when its syscall returns, and
it alone closes its descriptors. Run-root revalidation on a capture failure also
runs as tracked work. `close()` waits a short grace period for owned steps. If any
step is still in flight, it refuses to release disk and input ownership, which
matches the existing unproved cgroup-absence path.

Host memory for that step is held to the shared policy's `maximumResidentBytes`,
the same ceiling the planner cgroup receives. Capture starts only after cgroup
absence, so the host step never overlaps the worker. Before any allocation, the
step admits a 16 MiB working reservation. The model is admitted from its
authenticated size before it is copied, and each retained plan or metadata
buffer is admitted from its pinned file size before allocation. Each of these
also carries 128 bytes of assessment allocation per byte. Local measurement of
the current assessment found 55 to 77 allocated bytes per input byte, linear from
2,000 to 60,000 functions across dense, code-bearing and bare models. At the
checked 16 GiB policy, about 127 MiB of captured input fits. Larger captures are
refused rather than admitted without proof. At every cooperative checkpoint, the
thread's measured heap allocation must stay within the admitted total. Measured
allocation includes garbage, so it is an upper bound on the heap the step can
retain. Anything over budget is refused with `GccBundledHostMemoryBudgetException`.
Planner stdout/stderr, up to 64 MiB each, are digested through a 64 KiB buffer
instead of being retained, and the recorded sizes and SHA-256 values are
unchanged. Allocation inside one library call is seen only at the next
checkpoint, and the JVM heap limit remains the backstop. This is a host-phase
budget, not a whole-process RSS measurement.

`publishCliResult` completes every caller-side verification before publication,
including that its separately opened output descriptor is the directory recorded
in the invocation. `GccBundledDeadlineBoundPublication` then writes, fsyncs and verifies
`result.json` in an unnamed O_TMPFILE inode, with each step gated by the
deadline. It commits by linking that inode to `result.json` without replacement,
so no other writer's file can be published by this call. The link first tries
`AT_EMPTY_PATH`. Before Linux 6.10 an unprivileged process lacks
`CAP_DAC_READ_SEARCH`, and that call fails with `ENOENT` or `EPERM`. The link
then follows the held descriptor's own `/proc/self/fd/<n>` magic link with
`AT_SYMLINK_FOLLOW`, which names the same open inode. If that also fails, the
error names the procfs prerequisite and keeps the first errno. Every link
attempt, including an `EINTR` retry and the fallback, must still be admitted:
an abandoned step, or one with less than one second left, starts no further
attempt. After the link come only the directory sync it needs for durability,
the CLI's directory-binding recheck, and, last, a check inside the same owned
step. That check requires the authenticated output pathname to still reach the
pinned directory, and its `result.json` to be the prepared inode. It reads the
bytes through the same descriptor whose identity it checked. The commit counts
only if the deadline is still current when the link returns and again after
these checks.
If the link, sync or a check completes late, fails or outlasts the owner's wait,
the result is revoked: by the in-flight step when its syscall returns, or by a
bounded cleanup step when the step had already finished. Revocation keeps the
prepared inode's descriptor open. It moves the name without replacement to a
unique private name, compares that entry with the descriptor, and only then
unlinks it. Another writer's entry is renamed back without replacement and left
intact. If a third entry has meanwhile taken the name, that rename fails with
`EEXIST`. The other writer's entry then stays at its private name, and the
failure reports that path, with any later directory-sync failure attached. An
existing result is refused untouched.

The output directory's filesystem must support O_TMPFILE, as ext4, xfs, btrfs
and tmpfs do. overlayfs gained support only in Linux 6.10. Where it is missing,
publication fails before writing anything, and the error names that requirement.

Limits:

- No rename- or link-based commit can stop a concurrent reader from seeing the
  name between a late link's return and its revocation.
- A process that exits while a revocation step is still blocked leaves an
  unaccepted `result.json` behind. The in-tree reader requires CLI exit code 0
  before it opens the file (`GccBundledCliQualificationTest`), and that remains
  the consumer contract. Recording in-flight publication in the operation
  journal, so that recovery removes an unaccepted result first, is a follow-up.
  It would change the journal chain that cold recovery (#981) is also editing.
- A revocation that meets a recreated name leaves the other writer's entry at
  the reported private `.result.json.revoked-<random>` path for an operator.
- Revocation's private name narrows the replacement race to a deliberately
  targeted random name between its identity check and unlink. That residual is
  outside the directory's cooperative exclusive-owner contract.
- Only the planner CLI result uses this protocol. The full-export and
  native-call CLI results keep their existing multi-file no-replace publication.
- The hosted `kotlin-oracle` fixtures use one- and two-function models. They do
  not exercise the ~127 MiB admission ceiling, and no real cc1/lto1 model size
  has been measured against it.

Focused JVM controls are in `GccBundledHostWorkTest`,
`GccBundledPlannerOutputCaptureTest` and `GccBundledDeadlineBoundPublicationTest`.
They cover a blocked NIO FIFO read, a channel close that waits on its blocked
operation, and a duplicate closed when its pinned scope's exit check fails. They
cover budget refusal before allocation and by measurement, model copying after
admission, streamed logs, and a blocked owned capture. They also cover expiry or
a stall at every preparation, commit and post-sync point, a renamed output
directory, a replaced leaf, and competing writers before the commit and during
revocation, and a leaf replaced during the binding recheck. A late
`AT_EMPTY_PATH` failure after the commit reserve lapses must not start the
fallback. `LinuxFilesystemSyscallsTest` forces the `/proc` link fallback and
covers the `ENOENT`/`EPERM`/`EINTR` dispatch.
These are local-component
controls. They do not qualify provisioned-host CLI wall time, peak RSS or real
cc1/lto1 execution.

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

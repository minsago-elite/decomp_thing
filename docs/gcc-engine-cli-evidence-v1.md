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

## Later-invocation recovery of an interrupted plan

A later process recovers an interrupted `gcc-engine-plan` by repeating the original argv exactly
and adding `--recover-operation <operation-id>`. It must run from the same working directory.
`GccBundledCliCommand.recoveryIntent` rebuilds the retained `invocation.json` (v2) and requires
byte equality. The rebuild uses three inputs:

- that argv;
- the current output, inputs and journal directory identities;
- the working directory: the process cwd pinned with an O_PATH open of `.`, whose canonical path
  must name the same device, inode and mount.

Admission captures the working directory before creating any output child. A searchable but
unreadable working directory is therefore admitted, and a failed capture leaves `--output` empty
for a retry.

HotSpot's perf-data setup changes into `/tmp/hsperfdata_<user>` and cannot change back from an
unreadable directory. The installed POSIX start script therefore adds `-XX:-UsePerfData` only when
`[ -r . ]` fails, so ordinary launches keep `jps`, `jcmd` and `jstat` monitoring. The script also
exports the physical launch directory (`pwd -P`) as `LLM_BIN_PATCH_LAUNCH_DIRECTORY`. When that
variable is present, the pinned working directory must match it by canonical path, device and
inode, or it is refused. A direct `java` launch without the variable binds the kernel working
directory as captured. No pathname heuristic is used. It then re-derives the production intent from the current inputs and the
two staged controls, which it reuses but never rewrites.
`GccBundledOperationCoordinator.recoverInterrupted` then takes the journal-root,
operation-journal and scratch-mount locks without blocking, in `prepareNew`'s order. A lock that
is still held means the earlier owner is live, and recovery is refused before any record is
reused.

The journal must end at `analysis-state-captured.json`. Exactly one `recovery-adopted.json`, or
its complete atomic temporary, may follow it; any other residue is refused.

- **Record lineage:** every record is rebuilt from its own payload and must match byte for byte,
  and the journal intent must equal the re-derived intent.
- **Absence receipt:** the interrupted-execution record must carry unit, cgroup and process
  absence. The absence receipt must belong to this operation's own command:
  - the attachment names the definition's unit, cgroup, nonce and deployment closure;
  - the execution, interrupt authorization and HMAC-checked outcome all name that attachment's
    request and keeper;
  - the outcome is `INTERRUPTED`;
  - every receipt self-hash holds.
- **Output lineage:** the definition must be the one derived from the reacquired run root, and
  the fresh control directory must keep its recorded identity.
- **Checkpoint:** the stopped prefix and analysis state must match their durable assessment and
  manifest, and the interrupted unit must have no cgroup.

After those checks the coordinator publishes `recovery-adopted.json`, which `resume-prepared.json`
links to. It records:

- the later argv;
- the absence basis;
- the run-root identity;
- the resume allowance.

The journal builds that payload from verified stopped evidence alone. Fresh publication and
retained reuse go through one validator, which rebuilds every key and value and requires byte
equality: the absence assertions, the stopped worker absence record digest, the unit, the run
root, the lease evidence, and the operation and state identity. Two values come from the record
itself and are checked by rule. The recorded argv must be the intent's own CLI argv plus exactly
one `--recover-operation` selector naming this operation. It must also parse with the CLI's own
option parser as the original selection plus that selector. It must be empty for an operation
without a CLI invocation. The allowance must be whole seconds within the committed cap.
`resume-prepared.json` may not stage a resume definition above that adopted allowance.

A later owner can crash after adopting but before any resume record. The next owner then
revalidates and reuses that single adoption, or renames its complete temporary into place
without writing new bytes, under all three locks. Its recorded allowance stays the cap.
Histories that reached any resume record are refused. Resume, planning and `result.json` stay on
the original operation ID and intent digest. `result.json` reports `executionOwnership` as
`fresh-single-owner`, `same-owner-checkpoint-resume` or `later-invocation-recovery`.

The stopped commit samples the operation deadline immediately before
`analysis-state-captured.json` and records that snapshot. An operation whose deadline expired
first never commits a recoverable state. The resume allowance is a fresh deadline capped at that
snapshot's whole remaining seconds. Recovery validates the snapshot: it must come from the same
deadline as the execution receipt, and no earlier than it. Prefix and state capture after worker
exit are therefore charged. Idle time between invocations is not charged (#982). The locks
coordinate cooperating same-UID processes only. A same-owner `--resume-after-checkpoint` run is
still not cold recovery.

Evidence and limits:

- **Local journal and CLI tests** refuse each of these:
  - a live owner;
  - a changed intent, deployment, operation or working directory;
  - tampered or residual records;
  - an unproved worker absence;
  - an absence receipt for another command;
  - a self-consistent retained adoption, as either the final file or its `.atomic` temporary,
    that carries a foreign argv, absence digest, unit, run root, lease or allowance, or is
    missing lock or cgroup assertions;
  - a CLI argv without exactly one selector for this operation over the unchanged original, or one
    the CLI's own option parser rejects, such as a selector between an option and its value;
  - a resume definition staged above the adopted allowance;
  - a commit snapshot from another deadline, or one earlier than the execution receipt;
  - an allowance above the commit cap;
  - prepared, fresh, completed and resume-started histories;
  - a changed or reordered argv, or a finished output.

  They also reuse a published adoption, and complete an adoption temporary, with the original
  allowance. The CLI tests cover the launch path:

  - the real installed start script adds `-XX:-UsePerfData` only for an unreadable launch
    directory, and exports the physical launch directory;
  - the real installed GCC CLI admits an unreadable but searchable launch directory without a
    caller-supplied flag;
  - a working directory that differs from the exported launch directory is refused before any
    output exists;
  - a failed capture leaves `--output` usable for a retry.
- **`kotlin-oracle`, ext4 lease test:** it reacquires a crashed child process's active run, and
  refuses while any other holder has the mount. It fails, rather than skips, when
  `DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH` is set.
- **`kotlin-oracle`, admission test, genuine cc1:** a later invocation re-derives the identical
  intent. It is refused while the admitted owner is live, and again once that owner has closed
  without starting.
- **`kotlin-live`, authored-ELF test:**
  - one owner stops at a checkpoint, and recovery is refused while that owner is live;
  - a second owner adopts and closes before resuming;
  - a third owner reuses that adoption, resumes within the committed allowance and passes
    completed-run byte validation.
- No genuine cc1 or lto1 checkpoint has been recovered through the installed CLI (#984). A crash
  after a resume definition is staged but before its attachment still fails closed.

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

These cooperative checks do not preempt an indefinitely blocked native read,
charset conversion, general library JSON parsing, every sort/join, allocation or
rendering step. Serialized-byte admission is not aggregate host-plus-worker RSS
accounting. Final result publication is unchanged: a no-replace publication can
still commit after expiry before its outer check refuses. In-flight I/O
ownership, bounded cleanup, host memory and commit semantics remain open under
#982 and full parent #291. This handoff does not establish CLI/engine production
qualification or change native containment and oracle authority.

## Observed contract

- `Main.runGccEnginePlan` parses the immutable CLI selection and calls
  `GccBundledCliCommand.run`.
- `GccBundledCliCommand` commits `invocation.json`, builds the v2 operation intent
  from the retained profile and bundled deployment references, and enters
  `GccBundledOperationCoordinator.prepareNew`.
- Fresh execution calls `owner.execute()`. The checkpoint option calls
  `executeUntilCheckpoint` and `resume()` on that same retained owner. Both paths
  then call `owner.plan()` and `owner.publishCliResult()`. A later invocation with
  `--recover-operation` enters `recoverInterrupted` instead and then calls only
  `resume()`, `plan()` and `publishCliResult()`.
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

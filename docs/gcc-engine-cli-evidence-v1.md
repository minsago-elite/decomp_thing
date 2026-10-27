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

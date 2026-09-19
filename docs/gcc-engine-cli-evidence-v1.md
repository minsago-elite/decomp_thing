# GCC engine CLI contained-route evidence

This is a narrow source-contract record for issue #291, captured against source
revision `bf2501568f39ab52b23492dfc37839bb81895587`. It records repository facts
only; it is not a hosted execution receipt or a production qualification claim.

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

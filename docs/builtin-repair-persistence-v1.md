# Built-in repair receipt persistence v1

`RepairAgentInvocationDocument` gives the repair workflow one immutable document interface for ACP
schema-2 receipts and built-in invocation archives. The captured built-in adapter exports its terminal
journal after cleanup and attaches the immutable artifact to that invocation's receipt. The shared
workflow verifies its request/task/prompt and terminal outcome before submitting it to the graph.
Failure to export an artifact cannot produce a successful workflow acceptance.

`ModuleRevisionGraph` publishes the raw receipt before its pending assessment. Built-in artifacts use
`reports/repair-revisions/<attempt>.builtin-receipt.json`; ACP keeps its existing filename and encoding.
The common binding retains receipt SHA-256, schema, request/change hashes, terminal outcome, release
completeness and assessment state. Built-in bindings additionally carry a bounded `builtinArchive`
reference with the exact workflow/provider/source/stage identities and journal count/bytes/head hash.
The graph and history retain that reference independently of the immutable receipt file. Existing
ACP-only canonical graph and history encodings do not gain an extra null field.

Reload reconstructs the parent source revision from graph lineage, checks the reference's task,
prompt, parent and request commitments, checks the complete receipt hash, and runs the pure built-in
transcript verifier against the independently stored journal reference. Unknown reference fields,
numeric/string substitutions, excess counts and inconsistent artifact/reference types are rejected.
The metadata cannot claim built-in release completeness while that producer remains unqualified.

The descriptor-owned state store retains its exclusive publication and directory inventory checks.
If the immutable receipt is published but the pending graph write fails, recovery can adopt that
workflow-owned orphan after checking its task, prompt, accepted parent and complete transcript. This
recovery path derives the missing reference from the trusted immutable file; it is not a verifier for
arbitrary untrusted uploads. Existing graph bindings always supply the separate expected reference.
Two provider receipt files for one pending attempt are ambiguous and stop recovery. A recovered
attempt is rejected and never causes another provider call or candidate publication.

Project archive creation and independent extraction recognize both receipt formats. Rejected built-in
receipts, references and their exact history projections remain in the payload and are independently
verified. A changed reference fails even after the archive's outer checksums are recomputed. Accepted
contributions still require qualified ACP release facts; rejected built-in attempts do not create an
accepted source contribution or disappear from the evidence inventory.

Six `BuiltinRepairPersistenceTest` cases cover completed/refused/failed terminal persistence, exact
rejected history, artifact/reference/parent tampering, pre-publication failure and orphan recovery,
ambiguous provider artifacts, project archive round trips and independent tamper detection, and
bounded strict reference parsing. The real `TraceGuidedRepairTest` also proves that a completed
built-in candidate is recorded before it is rejected for missing release qualification. Core v10 adds
these six cases to the previous 122-case inventory.

Local verification: **235 cases, 229 passed, six live-terminal skips, zero failures/errors**. This
includes all 92 existing revision-graph cases, including ACP acceptance, recovery and archive checks:

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.repair.ModuleRevisionGraphTest' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' \
  --tests 'decompengine.project.AgentExecutionEvidenceTest' \
  --tests 'decompengine.repair.TraceGuidedRepairTest.built-in stage persists graph-bound evidence before rejecting unqualified completion' \
  --tests 'decompengine.repair.TraceGuidedRepairTest.ordinary ACP terminal outcomes persist immutable receipts before rejected repair history' \
  --console=plain
```

The six live-terminal skips require `/usr/bin/bwrap`, absent on this host. Core v10 is 128 cases
with 122 local passes and those six skips; the hosted required-boundary run must pass without skips.

This implements durable rejected invocation evidence for #75/#77. It does not close either issue.
The internal [captured factory provisioning](builtin-harness-provisioning-v1.md) now binds configured
provider/limit identity into the persisted reference. Operator selection, per-attempt checkpoint provisioning, suspended/torn-prefix
workflow artifacts, built-in acceptance through external compilation and every retained regression,
and comparative release qualification remain outstanding. Built-in `releaseComplete` remains false;
the existing acceptance gates have not been relaxed.


## Default-branch run-contract integration

Schema-3 repair runs keep the graph open for the whole run and retain provisional revisions as detached
inputs. Built-in invocation references now distinguish the accepted baseline from the full input
revision. Rejected built-in artifacts can accompany a fully validated release run, but a schema-1/2
history or an unresolved schema-3 run cannot become a release archive. The archive fixtures retain a
built-in rejection between a provisional ACP revision and final ACP acceptance, using the existing
synthetic validation-receipt fixture. They verify both independent archive extraction and provenance
after deleting private runtime files. They do not qualify a real validation provider or built-in acceptance.

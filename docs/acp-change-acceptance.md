# ACP changes and workflow acceptance

ACP changes use the shared `AgentFileChange` contract. A change report describes
observed bytes; the requesting workflow decides whether those bytes are an
acceptable revision after its policy and validation checks.

The former standalone `AcpChangeSetValidator` and its snapshot/change types had no
production or test callers. They have been removed. That helper supplied a
separate profile/allowlist policy, inferred moves from equal hashes, and did not
match the validation paths used by reconstruction or repair. Removing it changes
no production permission, supported operation, or acceptance decision. New code
must use the execution contract and the workflow boundaries described here rather
than recreate an independent validator that is not connected to acceptance.

## Execution observations

For an ordinary workspace invocation, `AcpAgentHarness` takes initial and final
regular-file snapshots for the request's declared path rules. It hashes file
contents incrementally and checks the request's cancellation and wall deadline.
The final snapshot is collected after process and sandbox cleanup. Its private
`WorkspaceSnapshot.diff` reports created, modified, or deleted files in canonical
root/path order and checks the corresponding `CREATE_FILE`, `WRITE_FILE`, or
`DELETE_FILE` operation against the exact `AgentAccessPolicy`.

There is no special evidence-path exemption in this diff. A profile role does
not grant permission by itself. A rename is not an independently authorized move:
the observed source deletion and destination creation require their respective
permissions. Filesystem callbacks and terminal operations remain subject to their
own contained execution boundaries before this final observation is made.

The final report is attached to the invocation-bound execution receipt. A
successful prompt stop reason does not remove failures in cleanup, final snapshot
collection, or the caller's later source/build/behavior validation.

## Captured repair

`CapturedRepairStagingAuthority` freezes the selected readable source bytes and
exact writable paths and checks its file, directory, and staging-byte budgets.
The ACP process sees an empty namespace anchor at
`/decomp-acp-captured/project`; this is not a mount of the canonical source tree.

`AcpCapturedRepairFilesystem` serves the captured source through text callbacks.
It permits replacement of existing staged files under exact read/write rules.
Each write reaches `BoundedRepairOutput` before becoming visible to a later read,
so source-file, patch-file, aggregate-patch, and logical-workspace limits apply
during the operation. After the session closes, its change report is derived from
the initial and final captured bytes. The ACP bridge exposes no create, delete,
move, or terminal capability in this workflow.

`TraceGuidedRepairLoop` independently reconciles the returned receipt and change
report with captured files. It requires a completed result and, for the production
path, release-complete ACP invocation evidence; canonical unique reported paths;
the exact staged file set; agreement between actual and reported changes; and
only authorized `MODIFIED` records with matching before/after hashes and byte
sizes. A removed captured file is rejected even though the lower-level mutation
sink can represent a deletion for other adapters.

`ModuleRevisionGraph.installCandidate` then checks the pending attempt's allowed
paths, current head, source/patch budgets, and preimages before storing candidate
blobs and installing the revision. Build and retained-regression assessment are
later workflow steps. The public generated-C production validation provider is
still unavailable; current tests using a host compiler are explicitly
`TEST_ONLY_NON_RELEASE`. Intermediate repair progress and fully accepted-head
semantics also remain separate open work under #65 and #49.

## Module reconstruction

The harness-backed module reconstructor in `SourceTree.kt` derives read-only
context files and one writable implementation path from the planned module. Its
request permits reading, creating, or modifying that target, not deleting it.
After the invocation, it requires exactly that reported path, the expected
created/modified kind, matching preimage and output hashes, and a consistent
reported size when supplied. A failed or interrupted invocation restores the
previous target bytes, or removes a newly created target.

`SourceTreeGenerator` applies the module/profile checks and compiler gate before
publishing an accepted checkpoint. It records invocation and compiler evidence
and restores the previous accepted checkpoint when a replacement is rejected.
The current module compiler receipt is local validation evidence, not a contained
production full-project build or complete behavioral-equivalence proof. Those
limits remain tracked by #64, #84 and the archive/release issues.

## Remaining scope of #63

This cleanup removes an unused competing policy path; it does not complete #63.
The actual workflow contracts still need the requested shared profile-driven
acceptance coverage, including an explicit supported-operation matrix and
consistent treatment of immutable evidence and source roles across entry points.

Ordinary workspace snapshotting currently visits regular files selected by the
path rules. It is not a complete independent inventory of every filesystem entry
or an authenticated descriptor snapshot of all workspace state. Its streaming
hash and deadline checks do not supply explicit aggregate file-count, byte, or
inode limits for that inventory. The separate filesystem/terminal containment
controls must not be presented as proof that these snapshot requirements are
complete. Any consolidation must retain the stricter captured-repair behavior
and preserve exact path, operation, revision, and evidence authority.

Creation, deletion, and move support in a general profile must be specified and
validated at the relevant acceptance boundary before a workflow exposes it.
Current module reconstruction and captured ACP repair deliberately have narrower
operation sets. Ordinary valid-edit checks at those existing boundaries remain
the relevant regression tests for removal of the unused helper.

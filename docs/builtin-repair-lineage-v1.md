# Built-in repair invocation lineage v1

The shared repair request now carries `AgentWorkflowIdentity`: a version, workflow kind, portable
durable task ID, accepted project revision SHA-256, and prompt SHA-256. `ModuleRevisionGraph` produces
this identity from its pending attempt after verifying the accepted source tree. The request binds
every field in its receipt digest. Older requests without the optional identity retain their exact
version-1 digest, including the existing archive compatibility vector. Identity grants no tool authority.

Schema-3 repair runs add `inputRevisionSha256` to workflow identity version 2. The accepted revision
identifies the canonical baseline, while input identifies the full source revision used by this attempt.
An input may be a detached provisional child; it never becomes an accepted revision merely because
an agent reads it. The graph reconstructs both from the parent chain and separately checks the
canonical source tree. Journal START, archive references, persistence, recovery and independent
archive verification retain both commitments. Historical identities without the input field retain
their exact version-1 digest and encoding. Neither identity is proof of full behavior validation.

`BuiltinRepairJournalFactory` can provision a fresh journal for each captured repair invocation.
It receives a private journal directory and configured provider/model identities. The adapter computes
the initial captured source snapshot from actual authority-supplied bytes, keeps the graph's full
accepted revision separately, and derives the stage digest from the immutable request and captured
snapshot. The receipt retains these portable identities without the operator's journal path.

The filename is a domain-separated hash of the durable task ID. Request changes, altered accepted
revisions, or a new factory instance cannot make an already used task overwrite or reopen its journal.
The existing exclusive creation, private directory, no-follow, lock, flush and size checks remain in
the journal implementation. Separate projects should use separate private journal directories. A new
attempt receives a new graph task ID. Resuming a prior task requires the explicit checkpoint protocol;
per-attempt provisioning currently supports fresh executions only and cannot be combined with the
caller-owned static checkpoint configuration.

The factory requires typed repair lineage before model or tool effects. Static journal configurations
also reject a supplied workflow identity that disagrees with their accepted revision or stage digest.
Invocation archive capture checks that task, workflow, prompt and revision match the request, so an
exporter cannot silently relabel a completed invocation. The pure archive verifier still requires
independently trusted expected identities and the journal commitment.

Five provisioning tests cover independent tasks, exclusive same-task admission after request changes,
missing/wrong workflow identity, contradictory static lineage, and bounded initial-source admission.
Two shared contract tests cover identity commitment and malformed identities. The initial provisioning
checkpoint used core v9 with 122 cases. The existing version-1 request digest vector remains covered.
A separate `TraceGuidedRepairTest` drives a scripted built-in edit through the real graph/request/stage
path and verifies graph lineage and unchanged accepted bytes. The subsequent
[receipt persistence integration](builtin-repair-persistence-v1.md) publishes its journal-backed artifact
before rejecting unqualified completion. Receipt capture exceptions reject the pending attempt; the enclosing repair run owns and closes
the graph handle. The test reopens the graph and checks the rejected attempt.

The initial provisioning checkpoint verified 137 selected cases: 131 passed and six live-terminal skips.
The current focused command also exercises receipt persistence; current counts are in its linked contract:

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' \
  --tests 'decompengine.project.AgentExecutionEvidenceTest' \
  --tests 'decompengine.repair.TraceGuidedRepairTest.built-in stage persists graph-bound evidence before rejecting unqualified completion' \
  --tests 'decompengine.repair.TraceGuidedRepairTest.ordinary ACP terminal outcomes persist immutable receipts before rejected repair history' \
  --console=plain
```

The wider run of all 36 `TraceGuidedRepairTest` cases plus the 15 lineage/contract cases had
43 passes and eight failures because `/usr/bin/bwrap` is absent on this host. Those behavior tests
remain unqualified locally; the required hosted lane must run with the configured sandbox boundary.

The internal [captured harness provisioning](builtin-harness-provisioning-v1.md) supplies configured
factory provenance for this path. Accepted archive lineage, operator selection, per-attempt checkpoint provisioning and comparative
compile/retained-regression qualification remain incomplete. Built-in invocation artifacts still report
`releaseComplete = false`; the workflow's acceptance gates remain in force.


Default-branch integration also preserves shared session request commitments and durable progress.
The shared ACP `sessionContinuation` protocol is unsupported by built-in execution and is rejected
before model, tool or journal effects. Explicit built-in checkpoint restoration remains a separate
protocol. Core v12 contains 151 cases, including shared session journal coverage, an unsupported
continuation test and a provisional-input persistence/reload test.


Local integration verification selected 295 cases: 289 passed, six existing live-terminal skips,
zero failures/errors. This includes all 151 core-v12 cases, 95 revision-graph cases, 17 run-semantics
cases and the shared factory/filesystem/receipt boundaries. Three additional ACP durable-session
reload/fallback/retry cases passed. The missing local containment runtime prevents treating the
six skips as required-host qualification; hosted core-v12 remains a separate gate.

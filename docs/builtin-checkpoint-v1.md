# Built-in checkpoint continuation v1

The optional `BuiltinCheckpointConfiguration` adds checkpoint publication and `resumeReceipt`
to `BuiltinAgentHarness`. It requires journal configuration and a trusted tool session implementing
`checkpointSnapshot`. That callback hashes the actual stage through `BuiltinWorkspaceSnapshot`;
the initial snapshot must match the workflow's configured source identity. Sorted root/path/size/
content-hash manifests distinguish source contents, namespace and file identity without persisting
source text in the checkpoint store.

The loop checkpoints immediately before its first model request and between fully completed tool
batches. The record binds the conversation and tool schemas, source/context hashes, original journal
identities, loop-limit fingerprint, usage, remaining wall-clock allowance and absolute expiry,
event sequence, prior state trace, used call IDs and canonical-action repetition counts. A digest of
the original checkpoint state detects redaction: altered text remains evidence and cannot silently
become restored model context. Remaining turns/tools/tokens/output bytes are derived from the bound
request/loop limits and restored usage; they do not reset.

After forcing a checkpoint record, the loop publishes an immutable commitment in a separate private
workflow directory outside tool authority. The commitment contains only version, record count,
byte count and head hash. Publication uses a fresh 0600 file and forces the file and directory.
There is no overwrite or automatic repair path. The reference's count/hash identifies that exact
commitment; the journal's exact length and head reject an earlier reference once execution advances.

The trusted checkpoint policy may return SUSPEND. This closes the tool session, preserves the journal
at the checkpoint and returns a shared CANCELLED result with a session reference. Built-in receipt
evidence distinguishes `SUSPENDED` and carries a typed checkpoint reference. It does not report a
completed model turn or an accepted source revision. Cleanup failure invalidates suspension and
records failure when storage remains available.

On explicit `resumeReceipt`, the loop:

1. Reads the private commitment and validates the complete journal against the expected immutable
   request and workflow identities. The journal must end at that exact checkpoint.
2. Acquires exclusive append authority and rechecks all inspected bytes under the retained lock.
   An active writer or intervening append is rejected; no source/model work is replayed.
3. Validates the checkpoint state digest, schema, limit fingerprint, correlated history and counters.
   Both remaining duration and absolute expiry constrain the original deadline, including downtime.
4. Opens the workflow-supplied stage and compares its actual source hash and registered tools with
   the checkpoint. Changed source or schemas stop before the provider runs.
5. Appends RESUME before making another request and continues from the saved conversation. Completed
   tool calls remain in history, and their IDs/repetition counts retain their original charges.

A failed precondition before RESUME closes the inspection handle without consuming the valid
checkpoint. The workflow can correct a source/schema/configuration mismatch and try again. Once
RESUME or any later record is persisted, the earlier reference cannot authorize another continuation.

A model/tool/validation intent after a checkpoint makes that earlier commitment unusable. There is
no fallback that truncates later records or replays indeterminate effects. A caught fatal unwind
releases the journal descriptor while preserving its exact crash prefix. If it happened immediately
after durable checkpoint publication, the workflow can recover using that separate commitment.
If it happened during an effect, that commitment fails the exact-tail check.

This is a continuation API for a workflow that can reopen verified staged bytes. It does not recover
missing source files from hashes, reconstruct redacted inputs, restore an absent process sandbox,
or reconcile an uncertain publication. Factory selection, archived source rehydration,
accepted/rejected revision events and archive verification remain required under #75 and C1/C2.
Private directory ancestors must be protected by the workflow, as for the journal boundary.
Clock fields are operational values; full live checkpoints are not claimed byte-identical across runs.

Ten tests cover a fresh invocation continuing a persisted stage without replaying its edit, consumed
references, source/schema/request/limit mismatches, turn/tool/token/repetition/call-ID conservation,
redacted context rejection, torn journal/extra intent/modified commitment rejection, recovery after
checkpoint publication interruption, canonical bounded snapshots, storage admission, expiry and
initial source identity. Local v5 selection reports 91 total, 85 passed, six live-terminal skips,
zero failures/errors. The hosted v5 result must be qualified separately.

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' --console=plain
```

The subsequent [captured-repair integration](builtin-captured-recovery-v1.md) now rehydrates supplied
candidate bytes through the shared bounded callbacks while preserving the original accepted base.
Checkpoint state schema 2 binds the trusted tool session's additional authority digest, including
captured repair quotas and effective sink paths. Schema-1 checkpoint states lack this binding and
are rejected. Durable archived source retrieval and workflow acceptance remain separate requirements.

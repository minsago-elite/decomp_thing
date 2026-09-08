# Durable cancellation acknowledgements

Tracking: [D2 cancellation #485](https://github.com/minsago-elite/decomp_thing/issues/485), supporting [D4 controls #180](https://github.com/minsago-elite/decomp_thing/issues/180).

The workflow store can atomically retain a cancellation acknowledgement alongside the transition to cancelling. The receipt records a domain-separated actor digest and request-key digest, the selected run, expected and applied versions, acknowledged state, and recording time. Raw session identities and request keys are not persisted. Attribution does not authorize a request.

Replay lookup precedes the version check and is scoped to the job, attempt and actor. An identical request returns the original receipt plus the current attempt, without rewriting storage. A reused key with a changed expected version conflicts. A receipt saying cancelling is not evidence that the attempt is still cancelling: it may now be cancelled, completed, or interrupted after restart. Callers must present the current state separately.

New commands require the current version. Queued/running attempts become cancelling; already cancelling or terminal attempts retain their state and version while recording the acknowledgement. The job retains at most 256 cancellation receipts. New keys are refused at capacity; old keys remain replayable and are never silently evicted. Receipt reclamation is not implemented.

The optional `cancellationReceipts` field is absent from older state and omitted when empty. Once receipts are stored, older readers that reject unknown fields will refuse that state; this does not claim downgrade compatibility. New readers validate the closed receipt structure and target identities. Publication uses the existing atomic workflow-state replacement, so uncertain outcomes must be reconciled by reopening the store before replay.

This checkpoint implements the store boundary. The service's worker signalling operation is not yet wired to these receipts, and no HTTP route or browser control is added. Service coordination must update the owned task to the current attempt version, preserve publication-failure handling, and avoid replaying worker signals. HTTP callers must authenticate and authorize before deriving the actor or looking up any receipt. Those integration and qualification requirements remain open.

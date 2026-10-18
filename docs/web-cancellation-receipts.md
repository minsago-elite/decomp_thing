# Durable cancellation receipts

The store records a cancellation acknowledgement in the same atomic publication
as a queued/running attempt becoming `cancelling`. The acknowledgement retains
the original request version, applied version, state and time. A replay returns
that acknowledgement alongside the current retained attempt before checking a
fresh version guard. It neither rewrites state nor acts on a later run.

Receipts use domain-separated actor and request-key digests scoped to the job and
run. Raw session identities and request keys are not stored. Attribution does
not authorize a request: the future shared HTTP mutation boundary must supply
the authenticated actor. A different actor or run is a different request scope;
the original key with changed intent conflicts. At 256 retained receipts per job,
new keys are refused while existing keys remain replayable. No key is evicted.

Old records without the optional receipt field remain readable. Invalid,
duplicate or foreign-target receipts refuse without rewriting stored evidence.
Accepted references, older terminal attempts, progress pins and diagnostic bytes
retain their existing identities. Candidate output is not acceptance evidence.

The retained implementation and original four storage controls are reused from
the cancellation checkpoints documented by the owning tracker. Additional inert
controls cover terminal acknowledgements with a prior accepted reference, pin
changes, actor/run/foreign-target guards, all five atomic publication fault
points, and legacy/malformed receipt records. The recovery verifier requires the
suite and captures repository-local fixture context.

Fault outcomes follow the store's existing commit boundary. Failures after the
temporary write or its fsync preserve known unchanged state. The pre-rename hook
already enters conservative uncertainty and poisons ownership, although that
injected failure leaves the old target without a receipt. A post-rename failure
retains the receipt for recovery. An ordinary exception after directory fsync
does not turn the committed acknowledgement into a failed admission.

The [owned service coordinator](web-attempt-cancellation.md) calls this command
before signalling an exact task and keeps running cancellation pending until its
adapter exits. Persisted `cancelling` is not worker termination or native cleanup
proof. Shared HTTP authorization, the current API route/schema, browser controls
and production-adapter qualification still need integration. Production adapters
remain unregistered.

# Browser cancellation controls

The attempt page exposes explicit cancellation status reads and version/key-bound requests. It identifies the selected attempt, displays specific server eligibility reasons, and separates the original acknowledgement from the server-reported current attempt state. A cancelling acknowledgement with a completed current attempt is displayed as completed, with no cancelled success toast. Verified current data replaces attempt details and aborts an outstanding older detail read.

Exactly one bounded cancellation intent is retained in sessionStorage per tab/deployment. It contains only job/run identifiers, expected version and request key, never credentials or workflow content. It is saved and read back before sending. Another attempt cannot replace it. Malformed or unavailable storage blocks new requests. Closing a tab loses this local recovery information; the server receipt remains independent.

Refresh, reconnect, hidden/offline transitions and unmount never replay work automatically. A retained intent requires an explicit status read and explicit retry with its original key/version. New-command ineligibility, including receipt capacity, does not suppress this replay choice. A new authenticated session may not recover an old session's acknowledgement; server concurrency checks still apply. A local discard requires a status read, does not undo server work, and invalidates editable eligibility until another read.

The controls remain mounted during attempt-detail refresh. Private-session loss unmounts the authenticated view and aborts transport; retained intent metadata survives for explicit reconciliation after reconnect. Late responses after abort are ignored. No polling or automatic mutations are introduced.

## Verification checkpoint

384 frontend tests, lint, typecheck and production frontend build passed. New component tests cover lost acknowledgements/remount, exact-token replay at capacity, cancel/complete reconciliation, hung transport abort, offline pause, foreign response refusal, another attempt's retained intent and explicit discard. Storage tests cover closed/bounded records, deployment isolation and unavailable storage. Initial six failures were invalid-data fixtures using a trailing slash in the normalized storage key; correcting the fixture keys produced the passing suite.

This is draft UI implementation on the cancellation API stack (#1021), tracked by #528/#180. Production workflow adapters remain unregistered. Packaged browser qualification, full session/restart integration and broader concurrent detail/read/worker races remain open. No JVM rerun for this frontend-only change; the parent retains 316 selected passing JVM tests. Retry/new-attempt and checkpoint-resume controls belong to #529 and are not implemented here.

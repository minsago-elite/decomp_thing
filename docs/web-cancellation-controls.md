# Browser cancellation controls

The attempt page exposes explicit cancellation status reads and version/key-bound requests. It identifies the selected attempt, displays specific server eligibility reasons, and separates the original acknowledgement from the server-reported current attempt state. A cancelling acknowledgement with a completed current attempt is displayed as completed, with no cancelled success toast. Verified current data replaces attempt details and aborts an outstanding older detail read.

Exactly one bounded cancellation intent is retained in sessionStorage per tab/deployment. It contains only job/run identifiers, expected version and request key, never credentials or workflow content. It is saved and read back before sending. Another attempt cannot replace it. Malformed or unavailable storage blocks new requests. Closing a tab loses this local recovery information; the server receipt remains independent.

Refresh, reconnect, hidden/offline transitions and unmount never replay work automatically. A retained intent requires an explicit status read and explicit retry with its original key/version. New-command ineligibility, including receipt capacity, does not suppress this replay choice. A new authenticated session may not recover an old session's acknowledgement; server concurrency checks still apply. A local discard requires a status read, does not undo server work, and invalidates editable eligibility until another read.

The controls remain mounted during attempt-detail refresh. Private-session loss unmounts the authenticated view and aborts transport; retained intent metadata survives for explicit reconciliation after reconnect. Late responses after abort are ignored. No polling or automatic mutations are introduced.

## Verification checkpoint

384 frontend tests, lint, typecheck and production frontend build passed. New component tests cover lost acknowledgements/remount, exact-token replay at capacity, cancel/complete reconciliation, hung transport abort, offline pause, foreign response refusal, another attempt's retained intent and explicit discard. Storage tests cover closed/bounded records, deployment isolation and unavailable storage. Initial six failures were invalid-data fixtures using a trailing slash in the normalized storage key; correcting the fixture keys produced the passing suite.

This is draft UI implementation on the cancellation API stack (#1021), tracked by #528/#180. Production workflow adapters remain unregistered. Packaged browser qualification, full session/restart integration and broader concurrent detail/read/worker races remain open. No JVM rerun for this frontend-only change; the parent retains 316 selected passing JVM tests. Retry/new-attempt and checkpoint-resume controls belong to #529 and are not implemented here.

## Session and detail-refresh integration

The next checkpoint exercises the actual API client, contract decoder, private-session observer, session state and attempt page together with injected HTTP responses. A cancellation 401 clears private data and credentials while preserving only the bounded intent. A changed-server bootstrap does not replay it; after an explicit read, a fresh session's stale replay is refused without changing its original key/version. Logout aborts a hung mutation; its late response cannot clear recovery metadata. A verified cancellation read/result aborts an older detail read and preserves the completed attempt's revision, usage and acceptance facts.

Explicit attempt refresh now invalidates cancellation eligibility as well as attempt details. If a request was in flight, refresh aborts local observation and retains its intent for a new read and explicit retry. This corrects a reproduced UI defect where a completed detail refresh left the prior eligible action visible (backend CAS still protected mutations). The failing regression is retained alongside the passing checkpoint.

These tests simulate server responses and instance replacement; they do not prove real process-restart or packaged-browser behavior. Full workflow/worker and packaged-browser qualification remains open.

# Shared session rejection

Tracking: [D4.4 #179](https://github.com/minsago-elite/decomp_thing/issues/179).

Private JSON and SSE transports in the application shell now report validated session rejection to the shared browser session. A correlated v1 error envelope with HTTP 401 and `SESSION_REQUIRED` or `SESSION_EXPIRED` clears credentials and publishes the corresponding session-required state. Existing session subscribers remove private views and abort their pending work. This includes job/history/attempt reads, activity, exploration evidence, uploads and progress-pin requests. Session bootstrap/exchange/logout keep their existing dedicated handling.

Each request captures the session generation at dispatch. A denial from before a refresh, sign-in, logout, peer invalidation or earlier accepted denial cannot clear a newer authenticated state. Requests issued without authenticated state confer no later invalidation authority. Disposed sessions ignore observations. Response bodies, credentials and request identifiers are not broadcast or stored by this mechanism.

Network failures, unvalidated HTTP 401 responses, HTTP 403 and unrelated error codes do not establish session loss. The change performs no automatic session check, sign-in, logout, mutation replay or peer notification. An explicit session check or fresh sign-in link remains the recovery path. A missing session does not establish that the server restarted.

Verification includes current/old-generation/disposed-session tests and transport/component integration for GET, SSE and guarded PUT rejection. Each integration case checks that sibling Runtime evidence and credentials disappear with exactly one private request and no gateway retries. Full D4.4 acceptance remains open for explicit restart signaling, shared connection recovery and conflicting multi-tab workflow commands; these tests do not qualify those scenarios.

[Retained evidence](evidence/web-shared-session-rejection-20260908/manifest.json) includes 349 passing frontend tests, the affected 23-test rerun, lint/build/package checks and 298 post-master-merge JVM tests. The first packaged browser run timed out waiting for an appended SSE observation; an identical-archive rerun passed with new failure-only diagnostics. Both reports are retained. The intermittent timeout is unresolved, and the browser journey does not directly exercise server-side session revocation.

## Packaged server-revocation qualification

The [follow-up browser report](evidence/web-browser-session-revocation-20260908/manifest.json) directly qualifies a private GET after server-side logout. One controlled tab starts without BroadcastChannel support, loads an authenticated attempt and its progress-pin policy, then retains its private view while another tab signs out. The original peer-notification checks still run for an ordinary tab.

After returning the unnotified tab to the foreground, one explicit pin-policy read receives HTTP 401 from the packaged server. Shared session state changes to required, removing the attempt details, activity and pin controls. A three-second observation window confirms no automatic follow-up requests or mutations. Workflow-state bytes remain identical, storage remains empty, and no browser exceptions occur. Installation preservation, shutdown and owned-work cleanup also pass.

This closes the prior real-browser qualification gap for GET rejection after logout. It does not establish expiration-timer behavior, explicit restart detection, every mutation/stream rejection path or conflicting workflow-command correctness. The earlier intermittent appended-SSE timeout remains unresolved; this run passes the unchanged assertion.

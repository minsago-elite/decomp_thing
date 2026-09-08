# Upload cleanup after local session loss

Tracking: [D4.4 #179](https://github.com/minsago-elite/decomp_thing/issues/179).

Session expiry and validated private-request session rejection now notify local invalidation subscribers. The upload view uses this existing callback to abort the upload and its progress read and clear displayed progress. Definitive session rejection during bootstrap and an already expired bootstrap receive the same local cleanup. Timer expiry also invalidates the old request generation.

This stops client observation without claiming the server discarded a transfer or unpublished a job. The selected file and retry ticket remain available; reconnecting alone sends no upload. An explicit retry reuses the same file and idempotency key. These local events do not broadcast peer logout.

[Evidence](evidence/web-session-upload-cleanup-20260908/manifest.json) retains three failing regressions before the fix and the passing 360-test frontend suite afterward. Lint, typecheck and production UI build passed. Tests use mocked transport and fake timers; actual browser expiry, worker lifetime and broader multi-tab workflow criteria remain open.

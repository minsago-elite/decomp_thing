# Upload progress cleanup on abort

Abort now clears the scheduled upload-progress timer immediately, without waiting for the upload promise to settle. The poll callback also checks component liveness and the abort signal before entering the API client. This covers an already queued callback as well as transports that ignore cancellation. Upload intent retention, server publication and workflow execution are unchanged.

Three deterministic fake-timer tests reproduce the old callback entering the progress client after unmount, definitive session expiry and explicit Stop transfer, while the injected upload never settles. All three fail before the fix and pass after it. The production client already refuses an aborted signal before fetching; these tests establish callback/timer cleanup, not previously observed network traffic after abort.

The investigation followed an intermittent existing upload test failure during the #1067 cancellation integration checkpoint. That suite had 388 passes and one extra progress-client invocation; the upload suite passed in isolation. The deterministic tests prove this queued-poll gap but do not establish it as the sole cause of the intermittent result. After the fix, all 392 frontend tests, lint, typecheck and production build passed.

Tracked by #526/#179. No JVM or packaged-browser rerun for this frontend change. Broader background-tab, real upload/session-expiry and multi-tab qualification remains open.

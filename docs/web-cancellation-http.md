# Authenticated cancellation HTTP boundary

Tracking: [D2 cancellation #485](https://github.com/minsago-elite/decomp_thing/issues/485), prerequisite for [D4 controls #180](https://github.com/minsago-elite/decomp_thing/issues/180).

`PUT /api/v1/jobs/{jobId}/runs/{runId}/cancellation` accepts only `{"action":"cancel"}`. The deployed base path prefixes the route. Authentication, origin, method, content type and CSRF checks precede command validation and receipt lookup. The request requires one strong run-version `If-Match` and one 16–128 character idempotency key. Query parameters and other conditional headers are rejected. JSON is bounded to 1024 bytes and cannot supply an actor, path, workflow or another target identity.

The server derives the actor from the authorized session and invokes the coordinated durable cancellation service. A stale fresh command returns 412; a key reused with different intent returns 409; receipt capacity returns 429 without evicting prior commands. Missing targets are 404 and unavailable/recovery-required service state is 503. A revoked session cannot retrieve a retained receipt.

A successful response has kind `cancellation` and contains:

- `current`: the selected attempt using the existing run contract, including its current version, state and acceptance observation.
- `acknowledgement`: original expected/applied versions, acknowledged state and recording time.
- `replayed`: whether an existing receipt supplied the acknowledgement.

The ETag is the **current** attempt version. An original cancelling acknowledgement can accompany a current cancelled, completed or interrupted attempt. HTTP 200 acknowledges command processing; it does not promise termination or acceptance. No actor/key digest or internal storage path is projected. A replay also sets `Idempotency-Replayed: true` and does not repeat the worker signal.

The generated client sends the closed command with explicit mutation headers and makes no automatic retry. Callers must retain the same expected version/key for an intentional retry of the same command; starting a different intent requires reading current state. A fresh browser session is a different actor and has no automatic access to a prior session's receipt.

Real HTTP tests use an inert registered adapter and an owned queued task through WebApiController. Service tests separately cover running workers, completion races, accepted-reference preservation and restart replay. This adds no production adapter registration, workflow start capability or browser cancellation control. Eligibility presentation and end-to-end running-worker HTTP/browser scenarios remain open before completing #485/#180.

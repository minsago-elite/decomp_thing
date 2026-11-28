# Explicit mutation recovery controls

An upload invalidated by a session change retires its active callback authority
before aborting transport. Local reconnection keeps the selected file and retry
identity available for an explicit retry. A late result or failure from the
retired request cannot navigate, overwrite the newer transfer state, or discard
its retry identity. Stopping a transfer still uses the existing aborted-result
message and recovery path.

`frontend/tests/mutation-reconnect.test.tsx` exercises the two implemented job
mutation controls through accessible buttons and visible outcomes:

- Duplicate upload clicks submit once. A local session disconnect/reconnect
  submits nothing automatically. An explicit retry retains the file and intent,
  uses a fresh transfer identifier, and remains pending when the old request
  succeeds or fails late. Only its confirmed response navigates to the job.
- Duplicate progress-pin clicks submit once. Reconnection requires an explicit
  fresh policy read, without replaying the pending mutation. An older reply
  cannot replace that policy. A later explicit change uses its latest version
  and a distinct intent, then verifies the resulting policy.

`frontend/tests/command-reconnect.test.tsx` covers the remaining job commands.
Its transport answers only when a test settles a call, and it rejects an
aborted call the way the real client does:

- Job organization (PATCH): repeated activation sends one change. Losing the
  connection aborts it. After reconnecting, nothing is sent until the person
  saves again. The status reports the abandoned change as unconfirmed instead
  of still saving. The explicit save uses a fresh intent with the same version
  guard, so an earlier write that did land is refused rather than applied twice.
- Attempt retry (POST): repeated activation sends one command. A connection
  failure keeps it retained. Reconnecting sends neither the command nor a read.
  An explicit replay, even if activated twice, sends it once with the same
  idempotency key and version.
- Job deletion (DELETE): repeated activation sends one request. Connection loss
  neither aborts nor repeats the accepted request. The controls stay inert until
  its single outcome is reported.

All responses, session callbacks, connection events and clock advances are
controlled in memory. Ten-second advances are virtual; no service, actual
browser, native process, auth provider or controller is started. These frontend
controls check command admission and retained identity; they do not replace
server-side durable idempotency tests or establish provider/release readiness.

Every prior test and contract fixture is retained. The changed complete source
requires its own ordinary Actions and automatic reviews before landing or
claiming completion.

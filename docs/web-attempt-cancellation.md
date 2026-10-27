# Owned workflow cancellation

The internal service command binds cancellation to the exact job, run and run
version. It records `cancelling` before signalling the owned task. The keyed
command uses the cancellation actor and receipt contract; replay returns the
original acknowledgement alongside the current attempt without another signal
or restoring an old task version. Terminal commands cannot act on a newer run.

A queued task is marked terminal only after its dispatch is suppressed under
the service monitor. Late executor delivery cannot execute it. A running worker
stays `cancelling` until its adapter invocation ends. Interrupting the worker is
a request, not a termination fact. A successful backend return wins its race
with cancellation, including when the owned cancellation interrupt remains set.
An interrupted invocation after an explicit request ends as `cancelled`.
Independent interruption without that request and service shutdown retain the
existing `interrupted` classification. The interrupt flag is cleared only around
atomic metadata publication and restored afterward.

An uncertain intent publication sends no cancellation signal, blocks further
mutations and prevents the worker from overwriting uncertain metadata. Running
work retains storage ownership until it exits; reopening reconciles retained
records without dispatch. Progress pins, keyed starts, older accepted references,
attempt identities and diagnostics keep their existing separate meanings.

The retained eight service methods are reused with repository-local fixture
evidence and current public job guards. Additional inert methods cover coexistence
with keyed starts/pins/restart and a successful return with its interrupt flag
still set. The recovery verifier requires this suite alongside the existing ones.

These are service state and ownership controls with inert adapters. They do not
qualify native process absence, cleanup or an accepted-publication attestation.
Production adapters remain unregistered. The current POST cancellation handler
uses the closed action contract and the shared session/Origin/CSRF mutation
capability. Its response retains original acknowledgement status while presenting
current run state. The separate HTTP methods are authored and await Actions;
browser behavior and production/runtime qualification remain unfinished. See
[the HTTP contract](web-api.md#errors-deadlines-and-concurrent-mutations).

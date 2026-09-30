# Controlled workflow fixtures (#605)

`ControlledWorkflowFixture` in the JVM test sources supplies a logical clock and
per-fixture job, run and version identities. Fresh factories replay the same
operation schedule with the same identities and timestamps. Reuse the factory
across store reopen so consumed IDs are not reused. `WorkflowFixtureClock`
shares its atomic instant with zone views, rejects negative advancement, and
advances only when the test asks; advancing time does not execute timers.

The injection points are internal constructors/factories. Public production
entry points continue to use the system UTC clock and random UUID identities.
The fixture executes no analyzer, model provider or native reconstruction tool.
Job uploads still pass through the real ELF validation and publication path;
input bytes are the existing synthetic ELF header, not a user binary.

`WebProgressCutoverTest` consumes these controls through the actual
`WebJobService`, `WorkflowAttemptStore`, `WebApiController` and loopback JVM HTTP
server. The existing atomic journal publication and bounded latch/barrier
schedule controls before/after/racing snapshot reads. Its SSE and polling tests
exercise replay, retention gaps and the exact 24-hour expiry boundary without
sleeping for workflow time. A fresh-scenario comparison checks stable job/run
identity, started-at time and public observation payloads after publication.
Session secrets and authenticated cursors remain real and random: comparisons
exclude opaque cursor bytes, and requests always use server-issued cursors.
Wall-time deadlines only bound a hung test; they do not select workflow order.

`frontend/tests/fixtures/workflow.ts` is a **mock transport** factory. It reuses
the generated-contract observation fixture, copies nested payloads for each
publication, assigns lossless deterministic sequences/cursors and samples an
injected clock (by default `Date.now`, controlled with Vitest fake timers).
Its connections publish, duplicate, reorder and close only on explicit test
commands. `workflow-fixture-mock.test.ts` checks late delivery, duplicate replay,
resume headers and identical fresh scenarios through the real frontend SSE
decoder with a mocked fetch. `activity-stream.test.tsx` reuses the same connection
controls for component races and uses a fixed fake-clock epoch. None of these
mock checks demonstrate server authentication, persistence or HTTP transport.

Run the layers separately:

```sh
./gradlew test --tests 'decompengine.web.ControlledWorkflowFixtureTest' \
  --tests 'decompengine.web.WebProgressCutoverTest'
npm --prefix frontend test -- tests/workflow-fixture-mock.test.ts \
  tests/activity-stream.test.tsx tests/event-stream.test.ts
```

Existing CI runs the frontend tests in **Frontend contracts and bundle** and JVM
web tests in **kotlin-core**. Check results against the PR head;
local substitute-toolchain results are supplemental. These fixtures extend the
outcome contracts (#604), reproducible datasets (#606), isolated Git/provider
fixtures (#607), and retained packaged-history evidence without replacing them.
They do not qualify live provider execution, production recovery, a packaged
browser journey, or the parent tracker as a whole.

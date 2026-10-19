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
schedule controls before/after/racing snapshot reads. Retained events keep their
first-publication timestamps when new events are appended, preserving cursor
anchors across clock advancement. Its SSE and polling tests
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

## Durable start receipt controls

`WorkflowStartReceiptTest` exercises the store's keyed admission using only the
existing authored ELF header and persisted lifecycle transitions. A start receipt
and its queued attempt use one atomic state publication. The stored key is a
job-scoped digest; it survives listener/session changes without storing the raw
request key. Intent includes the original request version, workflow, input and
harness identities, predecessor, and all declared limits. Replays select that
same retained attempt before CAS or active-attempt checks, including after
restart and after a later run starts. They never enqueue or execute work.

The controls cover competing identical/conflicting requests, every existing
atomic publication fault point, old unkeyed records and malformed/copied/duplicate
receipts. A completed candidate and a stored accepted reference keep their
different meanings. These are storage controls. Service queue admission, shared
HTTP mutation authorization and production adapter/acceptance integration still
need their own implementation and qualification; the receipt is no execution or
acceptance authority.

`DurableWebWorkflowStartTest` adds the service boundary with inert registered
adapters. It checks replay before capability/capacity/version admission, the
different initial public and storage version tokens, exact registered limits and
harness selection, accepted-input ownership, and bounded owned worker/queue
states. A committed start retains its run even if the executor immediately
refuses it; replay never submits that task again. Admission and terminal-write
faults preserve uncertainty and require recovery before further mutations.
Restart reconciliation, shutdown and replay do not dispatch work. Current
candidate output remains separate from the prior accepted-reference pointer.

`WebWorkflowStartControllerTest` exercises the versioned route through a real
local HTTP server with an injected inert service. It covers keyed replay after
later work and restart with registrations removed, owned queue and per-job
refusals, nullable harness identity, full unsigned limits, scheduler refusal and
publication uncertainty. Direct memory exchanges observe zero body consumption
for authorization/header/target refusals and bound oversized reads. Strict JSON
controls reject malformed UTF-8, duplicate/unknown fields, fixture wrappers and
command/path input. The benign recovery verifier requires this suite as well.

The internal service command is reached through the shared session/Origin/CSRF
capability. Production durable adapters remain unregistered; the existing default
405 refusals and unavailable bootstrap claims remain. Runtime capability and
accepted-publication integration still require their owning qualification. A
recorded receipt and an injected adapter are not production readiness, live
provider execution or acceptance attestation.

## Generating and selecting development fixtures

Use the exact Node/npm versions and locked installation in
[frontend development](../frontend/README.md#supported-tools-and-commands).
Python contract validation uses the pinned dependencies in
[`requirements/oracle-generation.txt`](../requirements/oracle-generation.txt).
Run the following commands from the repository root with those tools available;
keep caches, generated data and investigation output inside `build/`:

```sh
mkdir -p build/fixture-debug/tmp build/fixture-debug/cache build/fixture-debug/state
export TMPDIR="$PWD/build/fixture-debug/tmp"
export XDG_CACHE_HOME="$PWD/build/fixture-debug/cache"
export XDG_STATE_HOME="$PWD/build/fixture-debug/state"
export NPM_CONFIG_CACHE="$PWD/build/fixture-debug/cache/npm"
export GRADLE_USER_HOME="$PWD/build/fixture-debug/gradle"
export PYTHONDONTWRITEBYTECODE=1

python3 contracts/web/v1/verify.py
npm --prefix frontend run api:check
npm --prefix frontend run fixtures:check
DECOMP_DEV_BASE_PATH=/nested/ npm --prefix frontend run dev:fixtures
```

The last command serves the visibly simulated catalogue at
`http://127.0.0.1:5173/nested/__fixtures/`. The generator
[`frontend/dev/generate-fixtures.py`](../frontend/dev/generate-fixtures.py)
derives the running, failed, interrupted, unsupported and partial scenarios from
`contracts/web/v1/fixtures/`, validates the shared schema and semantic invariants,
and returns records to the development server in memory. Edit the shared fixture
or generator for an intentional scenario change. A schema change also needs the
reviewed generated-client update with `npm --prefix frontend run api:generate`;
`api:check` verifies the result without rewriting it. Preserve decimal-string
counts and explicit unavailable/unsupported values. Fixture mode uses no backend,
analyzer or model credential and rejects mutation requests.

Choose the smallest layer that exercises the behavior being changed:

| Layer | Source and focused check | What it exercises |
|---|---|---|
| Development contract and proxy | `frontend/tests/development.test.ts`; `npm --prefix frontend test -- tests/development.test.ts` | Schema drift, explicit fixture mode and the real Vite adapter against a benign synthetic HTTP upstream. |
| Ordered frontend observations | `frontend/tests/fixtures/workflow.ts` and the focused frontend command above | Explicit publication/reordering/disconnect controls through the frontend decoder and components. |
| Durable JVM observations | `ControlledWorkflowFixture` and the focused Gradle command above | Real store/controller/HTTP boundaries with controlled identities and time. |
| Reproducible large datasets | `scripts/generate-web-scale-fixtures.mjs` and its verifier | Fixed synthetic jobs, functions, source, events and Git records with an exact manifest; it does not execute a reconstruction. |
| Isolated Git/provider fixtures | [Git fixture contract](web-git-fixtures.md) | Owned disposable repositories and a loopback fake provider; no real remote or provider token. |
| Packaged browser | [Browser driver and package prerequisites](web-packaging.md#building-and-serving-the-embedded-ui) | The actual archived application and its embedded UI in an explicit browser mode. |

To generate the complete scale profile, choose an **absent** output directory:

```sh
node scripts/generate-web-scale-fixtures.mjs "$PWD/build/fixture-debug/scale-v1"
node scripts/verify-web-scale-fixtures.mjs "$PWD/build/fixture-debug/scale-v1"
```

The checked profile includes 10,000 jobs, 100,000 functions and a 64 MiB log. The
generator streams payloads, fixes IDs/timestamps and writes their byte counts and
SHA-256 values to `fixture-manifest.json`; the verifier streams the files again.
Existing output is refused. Preserve an incomplete directory for investigation
and select a new absent path for another attempt. These records supply workload
inputs; their generation is not a measured rendering or resource-budget pass.

## Investigating a packaged-browser failure

Start with a completed Actions attempt and its actual checkout, failing step and
ordinary log. Keep the ZIP, application JAR hash, UI build ID, browser/tool versions
and mode together. A development-server pass cannot replace an archived-UI
failure, and a report from another source or archive cannot qualify this attempt.

The packaged driver requires an already-built ZIP, the pinned Node/browser and
explicit JDK/Python paths. See [packaging](web-packaging.md) for tool provisioning
and each mode's contract. With reviewed tools and the work parent above available,
the direct session journey is:

```sh
node scripts/check-packaged-web-browser.mjs \
  --archive "$PWD/build/distributions/llm_bin_patch-0.1.0.zip" \
  --chrome "$PWD/build/web-test-browser/chrome" \
  --java-home /absolute/path/to/jdk --python /absolute/path/to/python3 \
  --work-parent "$PWD/build/fixture-debug" --mode session
```

`session` reads the packaged assets; `proxy` deliberately uses the checked-out
frontend and Vite against the packaged JVM. Normal Actions also select
`metadata`, `live` and `scale`; choose the failing step's mode when investigating
its behavior. `upgrade` additionally requires two separately qualified archives
with different manifest identities and the specified old lazy chunk absent from
the current inventory. The driver downloads no tools and sends no model prompt.
Its synthetic upload/metadata modes do not execute the uploaded ELF. Do not supply
model credentials, a real user job directory or a real Git remote for this work.

The driver prints `build/packaged-browser-*/report.json` and retains screenshots
in that same evidence directory. Inspect `status`, `error`, tool/build identities,
the relevant request/CSP observations and `applicationError`/`browserError`/
`viteError` when present. Argument or tool validation can fail before an evidence
directory exists; retain that step's ordinary error instead of inventing a report.
`failure.png` is best effort: capture requires an attached page with an empty
fragment and no visible handoff credential, and hides editable fields. A missing
screenshot does not change the recorded failure.

Check `shutdownConfirmed`, `workRetained` and `workCleanupConfirmed` independently
of the functional result. The normal driver removes only its marked work after
confirmed shutdown and retains the report/screenshots. `--keep-workdir` is an
explicit diagnostic choice that retains work; it does not prove cleanup. Preserve
an unconfirmed cleanup result for investigation. A sent signal or browser closure
alone is not proof that the owned JVM and optional Vite processes stopped.

## Retrieving Actions failure artifacts

The [CI workflow](../.github/workflows/ci.yml) uploads these named artifacts even
when their job fails, if the producing files exist. Artifacts currently expire
after 14 days; retrieve the exact completed run before expiry. With `RUN_ID` set
to its numeric Actions run ID and the repository-local cache paths above:

```sh
gh run download "$RUN_ID" --repo minsago-elite/decomp_thing \
  --name frontend-verification --dir "$PWD/build/fixture-debug/actions-$RUN_ID/frontend"
gh run download "$RUN_ID" --repo minsago-elite/decomp_thing \
  --name packaged-web-verification --dir "$PWD/build/fixture-debug/actions-$RUN_ID/packaged"
```

Download the artifact produced by the failing job. `frontend-verification` holds
toolchain/contract/component diagnostics and bundle reports;
`packaged-web-verification` holds packaged checks, browser reports/screenshots and
its retained JVM reports. The separate `packaged-browser-expiry-test-reports`
artifact contains the three-method expiry XML and its matching JSON selection
receipt. An early failure can leave an artifact or file absent: retain the step
and ordinary log as that attempt's evidence. Do not silently substitute the latest
run, a stale local file or another job's report.

GitHub read access may require the operator's normal GitHub authentication; it
does not require a model/provider credential. Use the named sanitized evidence,
not raw browser profiles, handoff URLs, cookies, headers or environment dumps.
After a demonstrated source correction, use normal commit-triggered Actions and
continue independent work during long runs. Preserve the original failed attempt
and any unverified cleanup. Scripted fixtures and one browser mode retain their
stated boundaries; full accessibility, adverse-condition, workflow and release
qualification stays with its owning issues.

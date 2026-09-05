# Frontend development

This workspace implements the D1 embedded workbench shell in
[#151](https://github.com/minsago-elite/decomp_thing/issues/151), with asset recovery
and build identity from #154/#157. The home and runtime
pages render with Preact, accessible navigation and error recovery. They do not
fetch private jobs or start workflows. The local session uses the versioned server API. Tool capability status remains
explicitly unavailable until the runtime capability view is connected. Runtime displays the non-secret build identity from the verified
server shell when that metadata is available.

## Supported tools and commands

Use **Node 24.20.0 and npm 11.19.0**. The root `.node-version`, package engines and
`packageManager` record the exact versions. Node 24.20.0 ships the selected npm.
Use an existing version manager that honors `.node-version`, or obtain the exact
[official Node distribution](https://nodejs.org/download/release/v24.20.0/) and
verify its [published checksums](https://nodejs.org/download/release/v24.20.0/SHASUMS256.txt)
before putting its `bin` directory on PATH. Repository commands do not download a
replacement runtime or silently use a different installed Node version.

From the repository root:

```sh
node --version
npm --version
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend run dev
```

The development server listens on `http://127.0.0.1:5173`. `npm --prefix frontend
run preview` serves the built shell on loopback for inspection. Neither server is
the production distribution or evidence that packaged JVM serving works. The default development command has no API backend. The explicit backend and
fixture modes below are the #155 development adapter; neither is enabled by a
production build.

Installation enforces exact engines and the lockfile. `.npmrc` disables package
lifecycle scripts: the reviewed Vite native dependency is supplied by its locked
platform package and needs no install script on the supported Linux x86-64 host.
All developer commands explicitly check the toolchain in their command body,
because `ignore-scripts` also suppresses npm's automatic pre/post hooks.

## Explicit API development modes

Use the same normalized base path on Vite and the JVM. These commands use a fixed
loopback frontend origin; changing ports uses `DECOMP_DEV_PORT`, not a Vite CLI
host/port override. Backend configuration is an explicit process environment value,
never a browser-exposed `VITE_*` variable or an environment-file credential.

```sh
# Terminal 1: normal JVM task, with the explicit development browser origin.
./gradlew -PfrontendNodeHome=/absolute/node-v24.20.0-linux-x64 run \
  --args='web --ui spa --host 127.0.0.1 --port 8000 --base-path /nested/ --dev-frontend-origin http://127.0.0.1:5173'

# Terminal 2: Preact HMR, same base path; no manual asset copy or rebuild per edit.
DECOMP_DEV_BACKEND_ORIGIN=http://127.0.0.1:8000 \
DECOMP_DEV_BASE_PATH=/nested/ npm --prefix frontend run dev:backend
```

Open `http://127.0.0.1:5173/nested/`. The JVM flag adds only the exact explicitly
configured loopback browser origin to its local access policy. Vite proxies
`/nested/api/**`, which contains API JSON, SSE/polling and artifact downloads.
It keeps request Host and Origin, cookies, CSRF/idempotency/conditional headers,
methods and bodies unchanged; it adds no forwarded authority headers. Responses
retain status, Set-Cookie, attachment/range/cache headers and streaming behavior.
Both processes enforce the expected Host/Origin pair. Vite has CORS disabled and
an exact fixed loopback listener; production does not accept a Vite origin unless
that separate server option is deliberately configured. Do not enable wildcard
CORS, rewrite Origin, or copy cookies/tokens into this configuration.

The proxy cannot create unimplemented endpoints. At the local-session checkpoint,
session exchange/logout, authenticated bootstrap and one job-detail read exist.
The shell uses only session/bootstrap; job collection, workflow and event/download
services remain owned by their D2/D4 issues. Synthetic upstream integration tests
verify those transport behaviors without claiming the JVM services already exist.
The session UI below uses this same proxy boundary. The adapter does not invent
a session, bypass backend authorization or retry a mutation.

For development without a JVM, native tools or models:

```sh
# Existing repository development dependency; use your Python virtual environment.
python3 -m pip install -r requirements/oracle-generation.txt
npm --prefix frontend run fixtures:check
DECOMP_DEV_BASE_PATH=/nested/ npm --prefix frontend run dev:fixtures
```

Open `http://127.0.0.1:5173/nested/__fixtures/` for the catalogue, or `/nested/`
for the shell. Every fixture page visibly says **SIMULATED DEVELOPMENT DATA**.
The catalogue loads job/run/report/poll responses on demand, reads one SSE event
and offers a harmless synthetic attachment. Nothing performs native analysis,
model calls, managed Git actions or real mutations. Fixture mode is read-only and
has no backend target; attempts to configure both modes fail.

The five scenarios cover running, failed, interrupted, unsupported report adapter
and partially populated evidence. Unsupported is a report/capability state, not an
invented job-status enum. Missing usage, result revisions and accepted evidence
remain unavailable. Counts preserve decimal strings beyond JavaScript's safe range.

At fixture startup, `dev/generate-fixtures.py` builds deterministic records from
`contracts/web/v1/fixtures/`, compiles the shared `contract.schema.json` with the
existing pinned `fastjsonschema==2.22.2` tool and applies `verify.py` invariants to
every response/event/error. It emits a schema digest and fails immediately on drift;
records are server memory, not checked-in generated client assets. A focused test
changes a required schema field and proves generation fails. This shared design
schema is also the source for the D2 DTO/client work; fixture validation alone does
not establish production DTO conformance.

Fixture transport deliberately implements one deterministic event per attempt and
no resumable journal: plain `/events` streams that event plus heartbeats until the
client disconnects; `?transport=poll` returns its matching page. Unknown query
parameters fail explicitly. Full cursor retention/reconnect behavior belongs to
D4. Fixture sessions are not a security model: bootstrap contains labeled synthetic
values, and all fixture mutation methods return 405.

`npm test` starts isolated real Vite and benign HTTP fixture servers to check
fetch/session headers, preserved JSON errors, incremental SSE, polling and download
headers. Strict Host/Origin failures stop before the backend. The production build
refuses `--mode backend`/`--mode fixtures`, never loads the development adapter,
and rejects dev/fixture modules and known development sentinels in emitted assets.
A sentinel build preserved the six prior production asset hashes and bundle sizes.
Chrome 149.0.7827.55 also loaded the actual `dev:fixtures` command at `/nested/`,
confirmed a Vite HMR connection and all five scenarios, and exercised fixture
fetch, one SSE event and the synthetic download without a runtime exception.
The retained local report is `build/dev-browser-fAG8pe/report.json`; this is
development-mode evidence, separate from the packaged browser gate.
No new npm dependency is needed by either development mode.

The real Vite adapter was also exercised against the packaged JVM's implemented
session/bootstrap endpoints in Chrome, with HMR connected, fragment removal,
cookie restoration, explicit logout and consumed-link denial. The backend's exact
UI build came from authenticated bootstrap 200 with no CORS allowance. That
pre-merge report is `build/proxy-browser-jroRhh/report.json`; artifact identities and
recreation with `scripts/check-packaged-web-browser.mjs --mode proxy` are in
[packaged browser evidence](../docs/web-packaging.md). The promoted driver also
passed against the merged Ghidra-containing ZIP with the official pinned Chrome
at `build/packaged-browser-elCmmT/report.json`. Proxy mode renders the checked-out
frontend through Vite and compares the authenticated backend build identity; the
separate `session` mode checks the packaged UI assets.

The #155 acceptance evidence is scoped as follows:

| Criterion | Verification |
| --- | --- |
| JVM + frontend HMR without manual copy | Documented explicit commands; real Vite-to-packaged-JVM session browser journey and HMR connected. |
| Session/origin, streaming/status/download preservation | Actual JVM session/bootstrap browser journey; `tests/development.test.ts` runs the real Vite proxy against a benign synthetic HTTP upstream for incremental SSE, polling, JSON errors and attachment headers. These transport tests do not claim future JVM workflow/event/download routes exist. |
| Explicit development boundary | Exact Host/Origin and unconfigured-mode rejection tests, CORS disabled, separate server flag, production dev-mode rejection and emitted-module/sentinel gates. |
| Five clearly simulated scenarios | Shared-schema fixture checks and Chrome fixture catalogue, fetch/SSE/download evidence at `build/dev-browser-fAG8pe/report.json`. |
| Schema drift fails | Shared production contract compilation plus semantic verification; regression changes a required schema property and rejects generation. |
| No fixtures/credentials/proxy endpoints in release | Production module/byte/sentinel gate; #155 sentinel build preserved all six prior production asset hashes. Later session payload measurement is recorded separately in `BUNDLE.md`. |


The Vite behavior used here is documented in its official
[server options](https://vite.dev/config/server-options) and
[plugin API](https://vite.dev/guide/api-plugin).

## Source and build boundaries

- `src/main.tsx` mounts the application and validates the configured base path.
- `src/app/` contains navigation, local brand SVG and route URL helpers.
- `src/routes/` contains home, missing-page and lazily loaded runtime views.
- `src/shared/` contains the native Preact render-error boundary and async wrapper.
- `src/api/` contains generated v1 contracts, strict decoding and bounded native fetch.
- `src/session/` removes bootstrap fragments and owns page-local session state.
- `src/styles/` contains local CSS; typography uses system fonts.
- `tests/` contains isolated component/state fixtures and never enters production.
- `dev/` contains the explicit server-only proxy configuration, shared-schema fixture
  generator and a development-only catalogue; production never imports these modules.
- `scripts/` checks tools and produces a deterministic bundle report.

Vite writes to `build/frontend/dist/`, with hashed resources in `assets/` and the
private build manifest in `.vite/manifest.json`. `index.html` is the manifest entry
key. `base: './'` keeps split imports relative to emitted files. The server will
resolve entry URLs from the manifest under `<basePath>/assets/ui/`, and set the
escaped `decomp-base-path` meta value for frontend route links. The supported base
path consists of slash-separated ASCII letters, digits, underscores and hyphens.
There is no inline script, `<base>` tag, CDN, telemetry or external font. Startup
makes one session-bootstrap read when no sign-in fragment is present; it neither
reads jobs nor starts workflows. The local SVG is emitted as a file rather than a data URL.

`vite.config.ts` sets an empty public environment-variable prefix list. Environment
files and `VITE_*` variables are not a mechanism for passing browser secrets or
runtime configuration. There is no `public/` passthrough folder. Source maps,
fixtures, test runners and developer tooling are excluded from production output.
Keep credentials outside this workspace; ignored environment files are still not
a suitable input to client code.

The architecture and trust contracts are in
[web architecture](../docs/web-architecture.md) and
[web trust](../docs/web-trust.md). Kotlin retains job, workflow, filesystem, archive
and Git authority. The frontend does not implement these services.

## Verification and bundle evidence

`npm test` exercises accessible shell landmarks, honest unavailable state,
separation of public views from session requests, route navigation/back, a direct nested-base link, missing routes,
error containment/retry, base-path validation, safe lazy-import recovery,
verified-shell build identity, strict API transport and page-local session state.
Type checking covers application,
tests and build configuration with strict options; lint checks typed promises and
prevents React compatibility imports. No `skipLibCheck` or ambient untyped shim
is used to hide dependency declaration problems.

A production build empties the output directory, builds split assets and writes
`build/frontend/bundle-report.json`. The report includes every output's SHA-256,
raw/gzip bytes, the initial static JS/CSS closure and bundler module ownership.
Composition metadata stays in `build/frontend/`, outside the served `dist/` tree.
Builds enforce the D1 initial limits of 50 KiB gzip JavaScript and 10 KiB gzip CSS,
reject production source maps/test/dev sentinels, and reject unexpected production
module owners. `BUNDLE.md` records the initial measured result. These measurements
do not establish packaged serving, browser performance or the full D-series gate.

## Dependency updates

Change exact direct versions and `package-lock.json` together. Under the pinned
Node/npm, use `npm --prefix frontend install --save-exact` for the reviewed version;
then prove a fresh `npm ci --ignore-scripts`, typecheck, lint, tests and production
build. Review license/provenance, advisories, install scripts, peer requirements,
transitive additions and the bundle delta. Record the result in the owning issue.
Do not add a React compatibility library, SSR import, global query cache, editor or
graph dependency without the architecture review described in #146.

The strict declaration gate selected Vitest **4.1.11** rather than the initially
proposed 5.0.0: the latter's published types referenced missing/inconsistent test
interfaces in this combination. `@types/babel__core` **7.20.5** supplies the preset's
published Babel types. Preact **10.29.8**, preact-iso **2.12.2** and
preact-render-to-string **6.7.0** are the declared runtime dependency set; the
prerender peer contributes no browser modules. All browser components use native
Preact. Runtime packages are MIT-licensed. `THIRD_PARTY_NOTICES.txt` contains their
notices plus the license for Vite-generated browser helpers; the distribution
packages this text separately from public UI assets.

## Local browser session

Open the local URL printed by `web --ui spa`. Its `#bootstrap=…` fragment carries
one short-lived, single-use credential. Startup removes the fragment with
`history.replaceState` before any API request and exchanges only its token in the
JSON session body. A malformed fragment is cleared and rejected; if the browser
cannot clear it, no session request is sent. Opening a fresh link in the same tab
also consumes its fragment. No token appears in rendered text, request URLs,
local/session storage or the frontend configuration.

Without a fragment, the public shell remains available and makes one read-only
bootstrap request. An existing HttpOnly cookie restores the session and CSRF value;
a 401 offers local sign-in guidance. CSRF remains in a page-local closure and never
enters the UI snapshot. The view does not infer workflow capability from session
success. Absolute expiry clears local authorization without a network request;
the JVM remains authoritative for idle expiry, restart, revocation and every action.

Check session is an explicit read-only action. Sign out sends one authorized
DELETE and clears the local CSRF value before sending it. If transport fails, the
UI says sign-out is unconfirmed; it never assumes revocation or retries the
mutation. Duplicate initialization/exchange/logout calls coalesce. A fresh link supersedes
an older session read; during a mutation, only the newest explicit link waits for
that mutation to settle. Failed fragment removal clears authorization, discards
queued credentials and blocks stale responses from restoring it. Expired or
consumed links require a fresh local link, and no old action is replayed after
session recovery. This is the SPA session slice of #161; it does not claim the legacy web
migration or remote-access profile is complete.

`api:generate` updates TypeScript contracts from the shared schema; `api:check`
fails if generated files drift. Typecheck and production build run the latter
before compiling. Session component/state tests cover fragment removal ordering,
expiry, duplicate calls, safe errors, unconfirmed logout and absence of credentials
from rendered state or browser storage. The isolated public App can still be
rendered without a session controller for component development.

## Asset recovery and build identity

All lazy routes use `shared/LazyRoute.tsx`. It consumes an import failure and
renders a stable unavailable view. The shell observes Vite's documented
`vite:preloadError` event and shows one persistent version notice. It waits for
an explicit Reload application action; it has no retry timer, persisted replay
queue or automatic navigation. Repeat failure notifications and button clicks
during reload do not request another reload. If browser navigation throws, the
notice directs the user to the browser's own Reload action.

The event observer leaves the rejection for the loader to handle. Suppressing
that event can make a failed Vite import resolve to `undefined`; the lazy wrapper
also recognizes that result so it cannot repeatedly suspend the router. Raw error
payloads, asset URLs and internal failure details are not rendered. The notice
preserves the surrounding shell and asks the user to copy unsaved input before
reloading. A network failure is not claimed to prove a new server version.
[Vite load-error contract](https://vite.dev/guide/build.html#load-error-handling).

Runtime reads `decomp-ui-build` and `decomp-application-version` meta elements
inserted by the packaged server from its verified manifest. It shows the full UI
SHA-256 build identifier and bounded application version as text. Missing,
malformed or duplicate metadata displays Unavailable. These values identify the
server that served this page; they do not prove that a later server restart is
running the same version, and they do not imply workflow capability availability.
No extra API call, environment value or browser storage supplies an identity.

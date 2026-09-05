# Frontend development

This workspace implements the D1 embedded workbench shell in
[#151](https://github.com/minsago-elite/decomp_thing/issues/151), with asset recovery
and build identity from #154/#157. The home and runtime
pages render with Preact, accessible navigation and error recovery. They do not
fetch private jobs or start workflows. Tool capability status remains explicitly unavailable until the versioned server
API is connected. Runtime displays the non-secret build identity from the verified
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
the production distribution or evidence that packaged JVM serving works. API
proxy/session integration belongs to #155; this shell does not have a proxy or
fixtures that could accidentally contact a live server.

Installation enforces exact engines and the lockfile. `.npmrc` disables package
lifecycle scripts: the reviewed Vite native dependency is supplied by its locked
platform package and needs no install script on the supported Linux x86-64 host.
All developer commands explicitly check the toolchain in their command body,
because `ignore-scripts` also suppresses npm's automatic pre/post hooks.

## Source and build boundaries

- `src/main.tsx` mounts the application and validates the configured base path.
- `src/app/` contains navigation, local brand SVG and route URL helpers.
- `src/routes/` contains home, missing-page and lazily loaded runtime views.
- `src/shared/` contains the native Preact render-error boundary and async wrapper.
- `src/styles/` contains local CSS; typography uses system fonts.
- `tests/` contains isolated component/state fixtures and never enters production.
- `scripts/` checks tools and produces a deterministic bundle report.

Vite writes to `build/frontend/dist/`, with hashed resources in `assets/` and the
private build manifest in `.vite/manifest.json`. `index.html` is the manifest entry
key. `base: './'` keeps split imports relative to emitted files. The server will
resolve entry URLs from the manifest under `<basePath>/assets/ui/`, and set the
escaped `decomp-base-path` meta value for frontend route links. The supported base
path consists of slash-separated ASCII letters, digits, underscores and hyphens.
There is no inline script, `<base>` tag, CDN, telemetry, external font or automatic
API request in the shell. The local SVG is emitted as a file rather than a data URL.

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

`npm test` exercises accessible shell landmarks, honest unavailable state, absence
of API calls, route navigation/back, a direct nested-base link, missing routes,
error containment/retry, base-path validation, safe lazy-import recovery and verified-shell build identity.
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

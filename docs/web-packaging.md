# Building and serving the embedded UI

The D1 frontend is an opt-in packaged preview. It currently provides the public
shell and runtime view, local browser sessions, and authenticated v1 bootstrap
and single-job metadata reads. Persistent job management and workflow actions
remain on the default legacy UI until the D-series parity and access-control gates
permit migration. The preview cannot upload or start a workflow.

Build with the pinned Node/npm versions in [.node-version](../.node-version) and
[the frontend workspace](../frontend/README.md). Node is a build dependency only.
On Linux, `bash scripts/install-frontend-node.sh /absolute/absent/node-toolchain`
installs the checksum-locked official archive into a fresh directory. The same
installer supplies the existing CI lanes and only the Docker build stage.
Use its `bin` directory on PATH, or select an installed official Node distribution:

```sh
./gradlew -PfrontendNodeHome=/absolute/path/to/node-v24.20.0-linux-x64 \
  jar installDist distZip distTar
```

`frontendNodeHome` must be an absolute installation root containing `bin/node` and
`bin/npm`. The actual Node/npm versions are checked on every build invocation;
missing or different tools fail with the expected versions and setup guidance.
`frontendInstall` runs `npm ci --ignore-scripts --no-audit --no-fund`. No dependency
lifecycle script or unpinned tool download is needed by the verified lockfile.

The task chain is `verifyFrontendToolchain → frontendInstall → frontendBuild →
generateFrontendAssetManifest → verifyFrontendAssets → stageFrontend →
processResources → jar`. Frontend source, configuration, scripts and lockfile are
declared inputs. Vite output, the independent asset manifest and staged resources
have distinct task owners so an unchanged build can reuse them. Staging uses Sync;
resource processing removes only the generated UI namespace before copying, so
deleted or renamed chunks cannot survive into the next JAR.

The generated resources are under `decompengine/web/ui/`. `asset-manifest.json`
binds the application version, entry script/CSS and every emitted resource's
length, media type and SHA-256 to one build ID. `index.html` and Vite's manifest are
private inputs. The server exposes only the inventoried public resource subset
under `/assets/ui/`. Node validation and Kotlin startup agree on names, media
types, count/byte limits and manifest identity. The scripts reject omitted,
duplicate, stale, changed or unexpected resources, including public source maps.

Ordinary distribution tasks include the final application JAR and frontend
third-party notices. The existing native-helper and BOOT/hosted-worker classpath
reference tasks continue after the final JAR bytes exist. Embedding UI resources
does not create a fat JAR or add `java -jar` support: use the installed launchers
with their dependency/helper distribution.

```sh
build/install/llm_bin_patch/bin/llm_bin_patch web --ui spa --port 8000
# Optional normalized path prefix:
build/install/llm_bin_patch/bin/llm_bin_patch web --ui spa --base-path /workbench/
```

The preview binds loopback. Its assets come from classloader streams, including
actual JAR entries, and need no frontend checkout, Node, CDN or external server at
runtime. App assets are immutable; mutable job data belongs outside the installed
distribution. Known shell URLs are `/` and `/runtime` relative to the configured
base path. Missing API/assets do not receive successful HTML. GET/HEAD and asset
ETag caching are supported; HTML has `no-store`. Missing or inconsistent packaged
assets fail startup before a socket is bound.

The SPA launcher prints a five-minute, single-use local session link. Its token
uses `#bootstrap=...`; the browser removes the fragment before an API request.
Session cookies are HttpOnly, SameSite=Strict and scoped to the configured base
path. CSRF stays in memory and is restored by an authenticated no-store bootstrap
read after reload. Logout is an explicit CSRF-protected request. No job or
workflow action follows session creation, navigation or refresh.

`POST /api/v1/session`, `DELETE /api/v1/session`, `GET /api/v1/bootstrap` and
`GET /api/v1/jobs/{jobId}` are implemented relative to the base path. Job DTOs
omit internal paths and raw status diagnostics, preserve unsigned ELF addresses,
and leave unknown run/acceptance identity null. Their ETag binds the current
metadata; it does not prove a reconstruction revision or acceptance. Bootstrap
identifies the actual application JAR by SHA-256, or reports `development` for
exploded classes. Workflow capabilities remain unavailable in this preview.

Host/Origin checks precede API dispatch, including namespace misses; private
responses require the same cookie boundary. The legacy UI has not yet migrated
to this session boundary and remains separate pending #161/#230. Explicit Vite
development uses `--dev-frontend-origin http://127.0.0.1:5173`, documented in
[frontend development](../frontend/README.md); normal SPA serving accepts only
its configured origin. A non-loopback proxy profile is not enabled by this flag.

Focused checks are:

```sh
./gradlew -PfrontendNodeHome=/absolute/path/to/node-v24.20.0-linux-x64 \
  testFrontendAssetManifest verifyAcpGateHelperDistribution \
  verifyLlvmBehaviorHelperDistribution verifyKotlinBootClasspathDistribution verifyPackagedWeb
./gradlew -PfrontendNodeHome=/absolute/path/to/node-v24.20.0-linux-x64 \
  test --tests 'decompengine.web.*' --tests 'decompengine.jobs.*'
```

The manifest tests include a split bundle and deliberately changed/omitted/
duplicate/stale resources. Kotlin adapter tests cover class directories and real
JAR streams, startup consistency, bounded streaming/disconnect cleanup,
GET/HEAD/conditional requests and private resource denial. Distribution checks
also compare the embedded JAR bytes across installDist/distZip/distTar. These are
packaging checks; full D3–D13 UI, workflow and release qualification remains in
the corresponding GitHub milestones.

`verifyPackagedWeb` uses Python 3.12+ as a test driver, creates temporary relocated
ZIP/TAR installations with read-only permissions and launches the normal POSIX
script with only required launcher utilities on PATH. It checks HTTP assets and
deep links, exact hashes, HEAD/304, private/unknown errors and bounded shutdown.
The JVM runtime does not invoke the test driver or Node. This HTTP smoke does not
replace browser-rendered checks.

The dependency-free [browser driver](../scripts/check-packaged-web-browser.mjs)
uses the pinned Node as a test process, Python for ZIP inspection, a JDK and an
explicit existing Chrome executable. It downloads no tools or packages:

```sh
/absolute/node-v24.20.0-linux-x64/bin/node scripts/check-packaged-web-browser.mjs \
  --archive /absolute/repository/build/distributions/llm_bin_patch-0.1.0.zip \
  --chrome /absolute/chrome --java-home /absolute/jdk
```

`--python /absolute/python3` overrides `/usr/bin/python3`. Only if the test
environment requires it, add `--no-sandbox`; the report records this browser-only
choice. The driver requires absolute tool/archive paths and never places its
Node/npm on the application's curated PATH. Reports, screenshots, browser profile
and relocated installation remain in ignored `build/packaged-browser-*`; the
driver prints the exact directory. Browser socket temporary directories use the
shorter `build/ct-*` prefix. The driver stops its owned JVM/browser processes on
success and failure. These directories can be removed after retaining evidence;
restore owner write permission recursively before removing the read-only install.

On 2026-09-05, Chrome 149.0.7827.55 passed the actual ZIP journey at `/nested/`
with application version `0.1.0`. The promoted driver reproduced that result once
with `--no-sandbox` in this container. These identities bind that checkpoint:

| Artifact | SHA-256 / build identity |
| --- | --- |
| `llm_bin_patch-0.1.0.zip` | `624d3cc20af3af4fcccdedc1788ae8224d5a6c193e4e039e1a764792654b0003` |
| Embedded `llm-bin-patch-0.1.0.jar` | `9a04efa05612484209d2f329477e8610f2d54b2cb6b8d7f9ec375e15bdeb03da` |
| UI build | `bb791a18dcf4940266028073f13469c9988fea578f6a5a10f200cbe897c02a55` |

The driver extracts the ZIP, removes installation write bits, snapshots every
installed file and starts the normal launcher from an unrelated directory. It
verifies rendered home, local icon/CSS, lazy Runtime navigation without document
reload, and exact UI/application identities from the embedded manifest. In a
second uncached tab, Chrome request interception returns 404 for only the Runtime
chunk. After five seconds there is one explicit recovery notice, no automatic
reload/retry and no mutation request. Removing interception and clicking Reload
application once restores Runtime with exactly one new document request. All
captured application requests remain same-origin, installed bytes stay unchanged,
and public browsing creates no job-data directory.

The successful retained report was `build/packaged-browser-jTpgqK/report.json`,
with `home.png`, `runtime.png` and `recovery.png` beside it. This is a D1 shell and
asset-recovery checkpoint, not complete D12 browser coverage, an actual two-version
server upgrade, authenticated workflow qualification or accessibility conformance.
The recovery screenshot also showed main-focus scrolling the notice title above
the viewport while leaving the reload button visible; broader focus/viewport
qualification belongs to #217. Later builds require fresh artifact identities.

Frontend byte reproducibility, deterministic JAR entries and native/runtime closure
identity are separate claims. Do not infer a reconstructed source archive's
integrity or behavior from a successful application packaging check. See
[the architecture](web-architecture.md), [delivery budgets](web-delivery.md) and
[parity contract](web-parity.md).

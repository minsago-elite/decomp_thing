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
uses the pinned Node as a test process, Python 3.11+ for ZIP inspection, a JDK and
an explicit existing Chrome executable. The driver downloads no tools or packages.
For the reviewed Linux x86-64 browser, run
`python3 scripts/install-web-test-browser.py /absolute/absent/chrome-install`.
The [browser lock](../scripts/web-test-browser.json) pins the official
version-specific archive, byte count, SHA-256 and inventory; installation does not
execute Chrome. Supply `/absolute/chrome-install/chrome` to the driver after
installing the browser's system libraries as described by CI. Browser provisioning
is test-only and adds nothing to the application distribution.


```sh
/absolute/node-v24.20.0-linux-x64/bin/node scripts/check-packaged-web-browser.mjs \
  --archive /absolute/repository/build/distributions/llm_bin_patch-0.1.0.zip \
  --chrome /absolute/chrome --java-home /absolute/jdk --mode session \
  --work-parent /absolute/scratch

# After npm --prefix frontend ci --ignore-scripts, run the same installed JVM
# behind the actual Vite development adapter and check browser session + HMR.
/absolute/node-v24.20.0-linux-x64/bin/node scripts/check-packaged-web-browser.mjs \
  --archive /absolute/repository/build/distributions/llm_bin_patch-0.1.0.zip \
  --chrome /absolute/chrome --java-home /absolute/jdk --mode proxy \
  --work-parent /absolute/scratch

python3 scripts/test-packaged-browser-install.py
```

`--mode public` is the default and checks home, lazy Runtime and missing-chunk
recovery. `session` includes that public journey and the authenticated journey
below. `proxy` starts Vite with the explicit backend origin and configures only
that loopback frontend origin on the JVM; it checks session restoration/logout
and an actual HMR connection. It does not substitute fixture responses.
`--python /absolute/python3` overrides `/usr/bin/python3`. Only if the test
environment requires it, add `--no-sandbox`; the report records this browser-only
choice. Application PATH contains only required launcher utilities and has no
Node/npm, even when the separate driver and Vite use Node.

The driver prints an ignored `build/packaged-browser-*` evidence directory with
`report.json` and screenshots. Requests in the report omit fragments and query
strings; no bootstrap token, cookie value or CSRF credential is recorded. Browser
profiles stay on the repository filesystem, with short `build/ct-*` socket paths.
The separate unique installation directory uses `--work-parent` (default
`build/`). Before extraction the [stdlib helper](../scripts/packaged-browser-install.py)
requires the ZIP's expanded bytes plus 64 MiB and its distinct paths/implicit
directories plus 1,024 free inodes. Choose a filesystem with that capacity and run
modes sequentially when only one large Ghidra extraction fits. It streams hashes
and retains archive execute bits on every regular file, including nested native
tools, while removing installation write bits; it does not guess from filenames.

After confirmed shutdown of its owned JVM, browser and optional Vite processes,
the driver removes its marked extraction, working directory, profile and sockets.
Reports and screenshots remain. `--keep-workdir` explicitly retains diagnostic
work. If shutdown or cleanup cannot be confirmed, the report fails and identifies
the remaining work; it never reports successful cleanup merely after sending a
signal. Cleanup checks the invocation's ownership marker and does not follow
external symlinks. DevTools connection setup and each request have a 15-second
deadline. On failure, the driver attempts `failure.png` only for an attached page
with an empty fragment and no visible handoff token; editable fields are hidden.
An unavailable or unsafe capture is skipped without replacing the primary failure.
Tiny helper regressions cover nested execute bits, cleanup ownership/symlinks and
resource rejection before extraction. A focused lifecycle check also verified an
actual nonresponding WebSocket handshake times out and a failed executable launch
has no process left to stop; these failure-path checks require no application build.

On 2026-09-05, Chrome 149.0.7827.55 passed both authenticated journeys against the
following **pre-merge session checkpoint**, application `0.1.0`, at `/nested/`:

| Artifact | SHA-256 / build identity |
| --- | --- |
| `llm_bin_patch-0.1.0.zip` | `b5813a85f7cb224e45d03a35b0893080456a425019e47365d282e035f3b608da` |
| Embedded `llm-bin-patch-0.1.0.jar` | `3a91968a94601a6aa38bca612cd2eeef8240e8bf2351138103020fbe46455d95` |
| UI build | `0568621730b941560737aa57653d6e5a5c2dca8d9ce8370350a7556bc8bdf039` |

The retained direct report is `build/packaged-browser-OgbK9x/report.json`, with
`home.png`, `runtime.png`, `recovery.png` and `authenticated-runtime.png`.
The real Vite report is `build/proxy-browser-jroRhh/report.json`, with its
`authenticated-runtime.png`; frontend port 44007 proxied JVM port 36507. Both
process sets stopped successfully. These runs used the temporary drivers whose
journeys are now available as tracked `session` and `proxy` modes above.

The direct journey snapshots a relocated read-only install and launches from an
unrelated cwd. Home renders its local icon/CSS; Runtime loads lazily without a
document reload and shows the manifest's exact UI/application identities. Chrome
intercepts only the Runtime chunk with 404. Five seconds later there is one
recovery notice, no automatic reload/chunk retry, and no mutation. One explicit
reload after removing interception restores Runtime with one document request.
The notice title remains inside the viewport, resolving the earlier public-only
checkpoint's focus-scroll observation; broader accessibility qualification remains
in #217. Startup without a token makes the expected unauthenticated bootstrap
read, and does not read private jobs or invoke native workflows.

The authenticated journey instruments fetch before application startup and proves
the fragment is empty before every first-page request. It checks one successful
session exchange, HttpOnly/SameSite=Strict/base-path cookie attributes, a GET-only
reload restoring the session, one explicit logout and subsequent denial after
reload. Reopening the consumed sign-in link is denied, with no automatic mutation
retry during five seconds. Browser local/session storage stays empty. Only the
explicit session exchanges/logout mutate anything; installed bytes are unchanged
and no job-data directory is created. Proxy mode repeats this against the real
JVM, observes HMR connected, and confirms authenticated bootstrap 200 with the
exact backend UI build and no Access-Control-Allow-Origin response header.

The Chrome executable was explicitly supplied from the preexisting local cache
`/home/june/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`, SHA-256
`2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`.
CDP reported Chrome/149.0.7827.55. Test-driver Node was 24.20.0, JDK came from
`/opt/openjdk-bin-21`, Python from `/usr/bin/python3`, and this container required
`--no-sandbox`. These facts describe an existing browser executable, not verified
provenance for a newly downloaded browser archive.

The earlier public-only report `build/packaged-browser-jTpgqK/report.json` binds
UI `bb791a18dcf4940266028073f13469c9988fea578f6a5a10f200cbe897c02a55`,
ZIP `624d3cc20af3af4fcccdedc1788ae8224d5a6c193e4e039e1a764792654b0003`
and JAR `9a04efa05612484209d2f329477e8610f2d54b2cb6b8d7f9ec375e15bdeb03da`;
those hashes are historical and do not identify the session checkpoint.
Later package builds need their own identities and reports. Browser evidence here
covers the D1 shell/recovery and local session boundary. It does not establish
D12 browser coverage, an actual two-version server upgrade, native workflow
qualification, the complete #161 legacy migration or accessibility conformance.

After the master/Ghidra merge, the promoted driver was run sequentially against a
new ZIP. These identities describe that merged package, with unchanged UI assets:

| Artifact | SHA-256 / build identity |
| --- | --- |
| `llm_bin_patch-0.1.0.zip` | `9479c0e4c13b5101651b28c1acfd5faf139eae1e66b29889695c3ebf6b9fc7e0` |
| Embedded `llm-bin-patch-0.1.0.jar` | `9e498290e7013a9552123eeccfd846efa342b29a7b513e16c59892f5415048e2` |
| UI build | `0568621730b941560737aa57653d6e5a5c2dca8d9ce8370350a7556bc8bdf039` |

The cached-browser `session` run passed at
`build/packaged-browser-fMiPZG/report.json`. The subsequent official pinned Chrome
`proxy` run passed at `build/packaged-browser-elCmmT/report.json` with real HMR,
authenticated bootstrap and the full session journey. The same pinned browser's
`session` run passed at `build/packaged-browser-u6h1zm/report.json`, including the
recovery title's viewport assertion. All runs confirmed process shutdown and
automatic cleanup, including the Ghidra-containing extraction on `/tmp`.
The expanded ZIP occupied 954,198,998 bytes; preflight required 1,021,307,862 bytes
and 7,767 free inodes, and the sequential runs fit without retaining duplicate
installations. The pinned browser's lock selects Chrome for Testing 149.0.7827.55,
revision `1625079`, archive size 185,646,494 bytes and SHA-256
`13113b963ac22fffdad898a677591028e4397c46c1daa9e61811258eed6e35b5`.
The actual binary was `/tmp/decomp-web-browser-pin-yp1jzpiy/installed/chrome`;
reports record its CDP version separately from the earlier cache provenance.

The merged archive checks also passed exact ZIP/TAR Ghidra bytes/execute modes
and ACP, LLVM and BOOT closure verification; the HTTP ZIP/TAR smoke passed.
The focused merged suite collected 121 tests: 118 passed and three skipped
(two opt-in Ghidra cases and one unavailable writable-noexec prerequisite).
A separate opt-in live Ghidra run passed all 33 tests across six CI classes with
zero skips. Those checks establish their respective packaging/runtime claims;
they do not turn browser session tests into native workflow qualification.

Frontend byte reproducibility, deterministic JAR entries and native/runtime closure
identity are separate claims. Do not infer a reconstructed source archive's
integrity or behavior from a successful application packaging check. See
[the architecture](web-architecture.md), [delivery budgets](web-delivery.md) and
[parity contract](web-parity.md).

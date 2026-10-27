# Building and serving the embedded UI

For one clean-checkout tool and cache setup, use
[repository-local frontend setup](#repository-local-frontend-setup-and-rebuilds).

The D1 frontend is an opt-in packaged preview. It currently provides the public
shell and runtime view, local browser sessions, and authenticated v1 bootstrap
and single-job metadata reads. Persistent job management and workflow actions
remain on the default legacy UI until the D-series parity and access-control gates
permit migration. The preview can upload ELF binaries and list and inspect jobs, but it cannot start a workflow;
see the [workbench user guide](workbench-user-guide.md) for what it does today.

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

For deterministic fixture generation, choosing a test layer, investigating a
packaged-browser failure and retrieving its exact Actions artifacts, use the
[fixture and failure investigation guide](web-workflow-fixtures.md#generating-and-selecting-development-fixtures).

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

# Use two separately qualified ZIPs; the driver does not generate either build.
/absolute/node-v24.20.0-linux-x64/bin/node scripts/check-packaged-web-browser.mjs \
  --mode upgrade --previous-archive /absolute/previous/distribution.zip \
  --archive /absolute/current/distribution.zip --chrome /absolute/chrome \
  --java-home /absolute/jdk --work-parent /absolute/scratch

python3 scripts/test-packaged-browser-install.py
/absolute/node-v24.20.0-linux-x64/bin/node scripts/test-packaged-browser-upgrade.mjs
```

`--mode public` is the default and checks home, lazy Runtime and missing-chunk
recovery. `session` includes that public journey and the authenticated journey
below. `proxy` starts Vite with the explicit backend origin and configures only
that loopback frontend origin on the JVM; it checks session restoration/logout
and an actual HMR connection. It does not substitute fixture responses.

`upgrade` keeps one browser tab and the previous entry module alive while replacing
the owned previous JVM with the current ZIP on exactly the same origin and
`/nested/` base path. It loads only the previous home first, verifies its embedded
build/application identities and confirms that Runtime has not been requested.
After confirmed JVM shutdown and unchanged-file/job-data checks, it removes the
previous marked extraction before preparing the current ZIP. Thus only one large
installation exists at a time; `--keep-workdir` retains only the final extraction.

The [pair gate](../scripts/packaged-browser-upgrade.mjs) requires different manifest
build IDs, exactly one Runtime lazy chunk in each inventory, and absence of the
previous Runtime path from the current inventory. A changed archive with the same
lazy path cannot qualify this test. The kept tab then navigates to Runtime and
must receive a real 404 from the replacement JVM. This mode uses no browser
request interception. Five seconds later it requires one visible version notice,
the previous build identity, no automatic chunk retry/document reload and no
mutation. One explicit Reload application action must load the current Runtime
chunk successfully and display the current build/application identities in the
same tab, with exactly one new document request. All application requests remain
on the original origin, both installations stay unchanged, and no job data is
created. This journey does not authenticate or exercise native/workflow mutations.

Upgrade reports bind separate `upgrade.previous` and `upgrade.current` ZIP/JAR/UI
identities, archive paths and resource budgets, plus the actual missing/current
lazy paths, replacement origin and cleanup state. Screenshots are
`upgrade-previous-home.png`, `upgrade-version-notice.png` and
`upgrade-current-runtime.png`. A passed report from a qualified pair is required
to claim this journey; the historical intercepted-chunk/session reports below do
not establish an actual two-version replacement. Pair-gate regressions reject
unchanged build identities, retained lazy paths and missing/ambiguous Runtime
inventories without generating application archives.

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

## SPA progress history retention

The SPA server now schedules bounded progress-journal cleanup by default. Existing unpinned terminal journals older than 24 hours can expire after startup; pin selected history from its attempt page to retain it. Unpinning does not reset the deadline or recover removed observations. Byte/count limits can omit older observations before timed cleanup. Legacy mode keeps periodic cleanup disabled.

The scan preserves active work, pending publication, durable pins and live writers, and coordinates with checked snapshot/artifact reads. It does not delete uploaded inputs, workflow metadata, source revisions or other reports. Runtime displays the enabled configuration and process-local scan counters sampled at the last session check. These are not disk accounting or proof that every eligible job has been visited. See [the production policy](web-progress-adapter.md#spa-production-retention-and-sampled-status).

## Repository-local frontend setup and rebuilds

For feature extension, use the [route/DTO/event/component workflow](web-architecture.md#route-and-contract-extension-workflow)
and the [Git adapter and identity contract](web-git-fixtures.md#git-adapter-extension-contract).

This path starts at a clean checkout on a Linux x86-64 build host with the normal
JVM build prerequisites available: JDK 21, Python 3.12+ with `venv` support and the
repository's C/native build tools. Ghidra is a bundled Java-API dependency supplied
by the normal build.
The frontend installer supplies the checksum-locked build-only Node distribution.
Run from the repository root and keep tools, caches and scratch there:

```sh
mkdir -p build/frontend-dev/tools build/frontend-dev/tmp \
  build/frontend-dev/cache build/frontend-dev/state
export TMPDIR="$PWD/build/frontend-dev/tmp"
export XDG_CACHE_HOME="$PWD/build/frontend-dev/cache"
export XDG_STATE_HOME="$PWD/build/frontend-dev/state"
export NPM_CONFIG_CACHE="$PWD/build/frontend-dev/cache/npm"
export PIP_CACHE_DIR="$PWD/build/frontend-dev/cache/pip"
export GRADLE_USER_HOME="$PWD/build/frontend-dev/gradle"
export PYTHONDONTWRITEBYTECODE=1

python3 -m venv "$PWD/build/frontend-dev/tools/python"
export PATH="$PWD/build/frontend-dev/tools/python/bin:$PATH"
python3 -m pip install --requirement requirements/oracle-generation.txt

bash scripts/install-frontend-node.sh "$PWD/build/frontend-dev/tools/node"
export PATH="$PWD/build/frontend-dev/tools/node/bin:$PATH"
node --version
npm --version

./gradlew -PfrontendNodeHome="$PWD/build/frontend-dev/tools/node" frontendInstall
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
./gradlew -PfrontendNodeHome="$PWD/build/frontend-dev/tools/node" \
  jar installDist distZip distTar
```

The installer requires its final destination to be absent and its parent to exist.
It verifies the official archive against
[`scripts/frontend-node-sha256.txt`](../scripts/frontend-node-sha256.txt), then checks
Node 24.20.0, bundled npm 11.19.0, `.node-version`, package engines and
`packageManager` before publishing the tool directory. An existing destination is
preserved; reuse an already verified installation by selecting its absolute root,
or choose a new absent path when intentionally installing another copy.

`frontendInstall` invokes `npm ci --ignore-scripts --no-audit --no-fund` with the
locked package files. The later distribution invocation reuses that task's declared
inputs/outputs when unchanged and builds the production UI through Gradle. Actual
type/lint/test results above remain distinct from reused build outputs. The
installed launcher is `build/install/llm_bin_patch/bin/llm_bin_patch`; ZIP/TAR output
is under `build/distributions/`. Node remains a development/build tool. The archived
application serves its inventoried UI from the application JAR.

The Python environment installs the pinned fixture/contract dependencies before
`npm test`. Frontend development tests invoke `python3` to generate schema-checked
fixtures, so keep this environment's `bin` on `PATH` for tests and fixture commands;
Node's package installation does not install these Python packages.

### Keep resources and runtime references together

The frontend task chain described above ends in `processResources → jar`. Its
owners are explicit: Vite owns `build/frontend/dist/`, manifest generation owns
`build/frontend/asset-manifest.json`, and `stageFrontend` synchronizes the reserved
generated resource tree. Gradle removes stale generated resources before copying
the new closure, while the manifest verifier rejects missing, duplicated or changed
assets. Rebuild through these tasks after a UI change.

The resulting application JAR also participates in authenticated runtime closures:

| Generated reference | Input owner and ordering |
|---|---|
| `generateKotlinBootClasspathReference` | `stageKotlinBootRuntime` stages the final application JAR and runtime dependencies after `jar`. |
| `generateLlvmHostedWorkerClasspathReference` | The same final staged JVM closure supplies the fixed LLVM worker reference. |
| `generateGccBundledGhidraReference` | The final JAR, bundled Ghidra tree and exporter source supply the Ghidra deployment reference. |

`installDist`, `distZip` and `distTar` depend on those references and the required
native-helper/checksum tasks. A UI-only JAR change therefore changes the closure's
application digest too. Keep installed JARs, embedded resources, helpers and
generated references from the same build checkpoint. Use the normal distribution
tasks to regenerate them from the final build outputs, then verify the installation:

```sh
./gradlew -PfrontendNodeHome="$PWD/build/frontend-dev/tools/node" \
  verifyGhidraDistributionArchives verifyAcpGateHelperDistribution \
  verifyLlvmBehaviorHelperDistribution \
  verifyKotlinBootClasspathDistribution verifyPackagedWeb
```

These checks cover their distribution/HTTP contracts. The
[fixture investigation guide](web-workflow-fixtures.md#investigating-a-packaged-browser-failure)
covers the separate actual-browser modes and exact-source evidence. Record which
commands executed, reused outputs, skipped cases and failed prerequisites. Production
workflow and release qualification retain their full separate acceptance scopes.

### Reproducible application JAR

The web server's `applicationBuildId` is the SHA-256 of the application JAR, so the JAR
must be byte-identical across Gradle invocations from unchanged source. Archive tasks
drop file timestamps and use a fixed entry order. The native helper producers compile
in a private, randomly named directory under `build/native/`. Their shipped records
(`analysis-native-io/build-v1.json` and
`oracle/native-helper/llvm-behavior-native-helper-deployment-reference-v1.json`)
replace that directory with the fixed token `${BUILD_ROOT}`. The recorded staged
source, output and `HOME`/`TMPDIR` are therefore `${BUILD_ROOT}/<name>`, `${BUILD_ROOT}/home`
and `${BUILD_ROOT}/tmp`. The installed verifiers require exactly those spellings, and
the checksum and deployment-reference bindings still tie the helper bytes to the record.
The records do keep the compiler's absolute executable path next to its SHA-256. That is
intentional: the path identifies the build host's toolchain, not the checkout, the user or
a per-build temporary directory. It is the same on every rebuild with that toolchain. Both
verifiers require the recorded compile command's argv[0] and the `--version` command to be
that path, so dropping it would weaken the binding between the measured compiler and the
recorded recipe. A different toolchain is a different input, and the JAR is expected to
change with it.

```sh
python3 scripts/check-reproducible-jar.py --gradle-arg=--offline
```

The script builds the JAR, then reruns resource generation and the JAR task. It fails
if the digests differ, naming the changed entries. It also fails if any entry embeds the
repository's absolute path, or a resource names a producer's private build directory. CI runs it in
the packaged web job.

### Updating dependencies and release metadata

For a frontend dependency change, update exact direct versions and
`frontend/package-lock.json` together under the pinned Node/npm. Follow
[the dependency update procedure](../frontend/README.md#dependency-updates), review
transitive packages, install scripts, license/provenance and the bundle delta, and
repeat locked installation, type/lint/component checks and production packaging.
A Node/npm update also changes `.node-version`, the frontend engines/package manager,
`scripts/install-frontend-node.sh` and its reviewed official archive checksums
together. Keep required CI tool selection aligned with those exact pins.

Release source maps are disabled in Vite and rejected by the bundle/inventory
gates. Fixture/dev/test modules stay outside the production payload. Preserve
`frontend/THIRD_PARTY_NOTICES.txt` for shipped runtime dependencies and Vite-generated
browser helpers; Gradle packages it as `docs/frontend-THIRD_PARTY_NOTICES.txt` in
the distribution, outside public UI assets. Review notices when shipped code or
dependencies change.

Record planned work, acceptance and verification status in the repository's
[GitHub milestones](https://github.com/minsago-elite/decomp_thing/milestones) and
[issues](https://github.com/minsago-elite/decomp_thing/issues), with exact source and
artifact identities. `ROADMAP.md` remains a deprecated migration pointer. The
[CI verification contract](ci.md#reporting-skipped-or-unrun-verification) explains
how to report incomplete checks without converting them into passing evidence.

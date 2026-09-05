# Building and serving the embedded UI

The D1 frontend is an opt-in packaged preview. It currently provides the public
shell and runtime view. Persistent jobs/workflows remain on the default legacy UI
until the D-series parity and access-control gates permit migration. The current
preview does not expose job APIs or start analysis.

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
The JVM runtime does not invoke the test driver or Node. Browser-rendered journeys
are separate D12 checks; this HTTP smoke does not replace them.

Frontend byte reproducibility, deterministic JAR entries and native/runtime closure
identity are separate claims. Do not infer a reconstructed source archive's
integrity or behavior from a successful application packaging check. See
[the architecture](web-architecture.md), [delivery budgets](web-delivery.md) and
[parity contract](web-parity.md).

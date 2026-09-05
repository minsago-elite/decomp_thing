# CI/CD Usage

`decomp_engine` is intended to be usable from CI as both a project under test and as a validation tool for generated C reconstruction artifacts.

## Project CI

Run the same checks as the repository workflow:

```bash
scripts/ci.sh
```

That command runs:

- `./gradlew --no-daemon test`

Gradle also builds the embedded frontend. CI provisions the exact Node 24.20.0 /
npm 11.19.0 distribution using `scripts/install-frontend-node.sh`; the installer
checks the reviewed official archive digest and repository version pins. Local
builds need the same toolchain on PATH. Node is a build dependency and is absent
from the application Docker runtime stage.

The independent **Frontend contracts and bundle** job runs on every push and pull
request. It uses a clean locked npm install, strict type checking, lint, component
and state tests, the versioned web schema's positive/negative fixtures, a production
bundle with size/dependency checks, and the manifest completeness/digest tests.
It also rejects changes to checked frontend or contract inputs produced by those
commands. No generated bundle, `node_modules`, or frontend dependency cache is
restored; Gradle packaging in the other jobs builds its own current bundle.

Run the frontend checks locally with the pinned tools:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
python3 -m pip install --requirement requirements/oracle-generation.txt
python3 contracts/web/v1/verify.py
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
frontend_version="$(node -p "require('./frontend/package.json').version")"
node scripts/web-asset-manifest.mjs build/frontend/dist "$frontend_version" --write build/frontend/asset-manifest.json
node scripts/web-asset-manifest.mjs build/frontend/dist "$frontend_version" --verify build/frontend/asset-manifest.json
node --test scripts/web-asset-manifest.test.mjs
```

The standalone manifest check uses the frontend package version; Gradle binds the
packaged inventory to the JVM application version. CI retains synthetic test
results, tool/lock/schema identities and bundle/manifest metadata as
`frontend-verification` for 14 days, including after failures. It does not upload
environment dumps, credentials, private source maps or generated job content.

This is the initial fast gate under [#227](https://github.com/minsago-elite/decomp_thing/issues/227),
which remains open until the required packaged-browser journey, expanded JVM API
contracts, browser/accessibility/scale qualification, Git integration and remote
operation gates are wired and evidenced. A schema fixture pass does not establish
an implemented endpoint. Branch-protection requirements are administered separately;
adding a workflow job alone does not prove that GitHub requires its result for merge.
The existing Kotlin, ACP, Clang, archival and oracle jobs retain their checks;
the manual LLVM source rebuild remains the optional expensive lane described below.

The test task first builds and verifies the same static ACP gate helper shipped by `installDist`; security-boundary
tests do not compile private helper copies. Distribution jobs should additionally run
`./gradlew --no-daemon verifyAcpGateHelperDistribution`.

Run the independent generated-C compatibility lane with LLVM/Clang:

```bash
DECOMP_TEST_CLANG=/absolute/path/to/clang scripts/validate-clang.sh
```

That gate compiles the single-file, archival, and vulnerability fixtures with
strict Clang warnings, proves the intentional uninitialized-use diagnostic,
requires AddressSanitizer and UndefinedBehaviorSanitizer findings, and builds a
generated multi-module project through an explicit `CC=clang` selection.

The repository workflow also runs the pinned Ghidra image against symbol-bearing and stripped large fixtures:

```bash
scripts/validate-archival-docker.sh
```

That heavier gate compiles both binaries, runs complete evidence-only source-tree reconstruction, requires non-empty global/string recovery, compares repeated stripped models and archives byte-for-byte, verifies every archive payload hash, and rebuilds the freshly extracted project.

Project planning is maintained in [GitHub milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues). `ROADMAP.md` is deprecated and is not generated or checked by CI.

## Source-aligned compiler oracles

The independent `GCC oracle model` and `LLVM oracle model` workflows verify
authenticated upstream releases, immutable toolchain/build records,
DWARF-rich and stripped ELF equivalence, deterministic function-recovery
ground truth, and checked behavior evidence. The LLVM lane fetches the binary
pair as ordinary release assets from the separate
`minsago-elite/decomp_thing-oracle-artifacts` repository. The checked release
lock authenticates the repository, non-moving tag, URLs, byte lengths, and
SHA-256 digests before either binary is installed in runner-temporary storage;
no binary is stored in this repository. The lane also rebuilds the Clang
toolchain recipe and checks its immutable base, Dockerfile, build-record
binding, platform, and every recorded live tool's exact executable bytes and
version output. The Docker image ID is retained as origin provenance rather
than used as a false layer-reproducibility claim.

The expensive source rebuild is intentionally manual. Run the `LLVM oracle
clean rebuild` workflow when the source lock, toolchain, flags, or artifact
pair changes; ordinary pushes and pull requests verify the already-reviewed
bytes. Exact LLVM commands and benchmark boundaries are documented in
`oracle/llvm/22.1.6/README.md`.

## Required CI Tools

Install these system tools before running the test suite:

- JDK 21
- Node 24.20.0 and npm 11.19.0 for frontend build tasks
- `gcc` and `make`
- static libc development objects for `/usr/bin/cc -static` (included by Ubuntu's `build-essential` dependency set)
- LLVM/Clang 18 for `scripts/validate-clang.sh`
- `bubblewrap`
- `binutils` for `strings`

Optional local integrations:

- Set `ANGR_PYTHON` to an angr-enabled Python executable to run the real symbolic argv/stdin integration test. The Docker image pins angr for production exploration; ordinary JVM tests use a deterministic process-adapter fixture.
- `ACP_CONFIG_FILE` selects the strict ACP v1 provisioning used by agent-backed workflows. Agent credentials remain in
  the named secret environment sources declared by that private configuration; they are not serialized into it.
- `BASE_URL`, `API_KEY`, and `MODEL` are deprecated compatibility inputs and are accepted only with exact
  `ACP_HARNESS=legacy-openai` or `--harness legacy-openai`. The pinned MVP fixture retains that explicit legacy path.
- Ghidra can be supplied through the Kotlin JVM adapter. Fast tests use a fake JVM entrypoint; the archival Docker CI job uses the pinned real Ghidra release and bundled exporter.

## GitHub Actions Consumer Example

Projects that want to run decompilation validation in CI can use the same dependency set:

```yaml
name: Decomp Validation

on:
  pull_request:

jobs:
  validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
      - run: |
          bash scripts/install-frontend-node.sh "$RUNNER_TEMP/frontend-node"
          echo "$RUNNER_TEMP/frontend-node/bin" >> "$GITHUB_PATH"
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            bubblewrap \
            binutils \
            build-essential
      - run: ./gradlew --no-daemon test
```

## CI Artifacts

Useful artifacts to retain:

- `frontend-verification` from the dedicated frontend job (component results and build/contract metadata)
- `build/reports/tests/test`
- `build/test-results/test`
- generated behavior reports under project `reports/`
- generated exploration reports such as `exploration.json`
- repair history reports such as `repair_history.json`
- archival `source-tree.zip`, `ARCHIVE_MANIFEST.sha256`, and `reports/archival_audit.json`

## Determinism Notes

The default CI path does not require external services. Tests exercise deterministic fakes for angr and the OpenAI-compatible API. Ghidra is additionally exercised in the pinned Docker gate so exporter API compatibility and stripped-binary determinism are verified against the production integration.

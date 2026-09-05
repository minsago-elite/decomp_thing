# CI/CD Usage

`decomp_engine` is intended to be usable from CI as both a project under test and as a validation tool for generated C reconstruction artifacts.

## Project CI

Run the same checks as the repository workflow:

```bash
scripts/ci.sh
```

That command runs:

- `./gradlew --no-daemon test`

The test task first builds and verifies the same static ACP gate helper shipped by `installDist`; security-boundary
tests do not compile private helper copies. Distribution jobs should additionally run
`./gradlew --no-daemon verifyAcpGateHelperDistribution`.

The independent `ACP contract` workflow runs every ACP and shared-agent regression suite
with `DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1`. Missing host capabilities fail this lane.
It provisions an empty, user-owned mode-0700 dedicated tmpfs with 64 MiB and 4,096
inodes for `DECOMP_TEST_ACP_QUOTA_TMPFS`, and unmounts it in an unconditional cleanup
step. The main Kotlin job provisions the same fixture. An existing mount is never
adopted, and cleanup does not use a lazy unmount.

On an already provisioned supported host, run `bash scripts/validate-acp-contract.sh`.
The gate rejects missing required suites, failures and skipped tests, and retains
JUnit XML plus `build/acp-contract-qualification/summary.json`. This qualifies the
scripted contract boundary; independent authenticated agents and full release
acceptance have their separate issue #67/#72 requirements. Ordinary local tests may
skip unavailable host integrations when the required-host flag is unset.

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
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            bubblewrap \
            binutils \
            build-essential
      - run: ./gradlew --no-daemon test
```

## CI Artifacts

Useful artifacts to retain:

- `build/reports/tests/test`
- `build/test-results/test`
- generated behavior reports under project `reports/`
- generated exploration reports such as `exploration.json`
- repair history reports such as `repair_history.json`
- archival `source-tree.zip`, `ARCHIVE_MANIFEST.sha256`, and `reports/archival_audit.json`

## Determinism Notes

The default CI path does not require external services. Tests exercise deterministic fakes for angr and the OpenAI-compatible API. Ghidra is additionally exercised in the pinned Docker gate so exporter API compatibility and stripped-binary determinism are verified against the production integration.

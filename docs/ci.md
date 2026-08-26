# CI/CD Usage

`decomp_engine` is intended to be usable from CI as both a project under test and as a validation tool for generated C reconstruction artifacts.

## Project CI

Run the same checks as the repository workflow:

```bash
scripts/ci.sh
```

That command runs:

- `./gradlew --no-daemon test`

The repository workflow also runs the pinned Ghidra image against symbol-bearing and stripped large fixtures:

```bash
scripts/validate-archival-docker.sh
```

That heavier gate compiles both binaries, runs complete evidence-only source-tree reconstruction, requires non-empty global/string recovery, compares repeated stripped models and archives byte-for-byte, verifies every archive payload hash, and rebuilds the freshly extracted project.

Project planning is maintained in [GitHub milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues). `ROADMAP.md` is deprecated and is not generated or checked by CI.

## Required CI Tools

Install these system tools before running the test suite:

- JDK 21
- `gcc` and `make`
- `bubblewrap`
- `binutils` for `strings`

Optional local integrations:

- Set `ANGR_PYTHON` to an angr-enabled Python executable to run the real symbolic argv/stdin integration test. The Docker image pins angr for production exploration; ordinary JVM tests use a deterministic process-adapter fixture.
- `BASE_URL`, `API_KEY`, and `MODEL` enable real OpenAI-compatible repair calls. Tests use a deterministic local compatible HTTP endpoint.
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

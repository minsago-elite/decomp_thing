# CI/CD Usage

`decomp_engine` is intended to be usable from CI as both a project under test and as a validation tool for generated C reconstruction artifacts.

## Project CI

Run the same checks as the repository workflow:

```bash
scripts/ci.sh
```

That command runs:

- `./gradlew --no-daemon test`

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
- Ghidra can be supplied through the Kotlin JVM adapter. Tests use a fake JVM entrypoint for deterministic CI.

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

## Determinism Notes

The default CI path does not require external services. Real integrations are behind explicit adapter boundaries, while tests exercise deterministic fakes for Ghidra, angr, and the OpenAI-compatible API. This keeps CI stable while preserving the production integration shape.

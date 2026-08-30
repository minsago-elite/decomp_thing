# decomp_engine

LLM-assisted binary-to-C reconstruction tooling for Linux x86-64 ELF binaries.

## Docker Environment

Create the local API configuration:

```bash
cp .env.example .env
```

Set `BASE_URL`, `API_KEY`, `MODEL`, and optional `REASONING_EFFORT` in `.env`, then build and verify the environment. Supported reasoning values are `none`, `minimal`, `low`, `medium`, `high`, and `xhigh`; leave it blank to omit the API field.

```bash
mkdir -p input output
docker compose build
docker compose run --rm llm-bin-patch doctor --output /output
```

The container includes JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, bubblewrap, Python, and a pinned angr installation. Input files are mounted read-only from `./input`; generated artifacts are written to `/output`. `doctor` exercises the compiler and sanitizer runtime, verifies the output mount is writable, and performs an authenticated `GET /models` preflight without printing the API key. Use `doctor --tools-only` when API connectivity is intentionally unavailable.

Compose runs analyzed binaries in the separate `binary-runner` service. That service receives no `.env`, has `network_mode: none`, a read-only root filesystem, no Linux capabilities, read-only input/output mounts, and only a narrow writable request volume. The application service does not add `SYS_ADMIN` or run as privileged. Outside Compose, binary execution requires a working bubblewrap user/network namespace and starts with a cleared, allowlisted environment.

Run the complete pinned c-vul acceptance flow deterministically and without credentials from a clean checkout:

```bash
git submodule update --init --recursive
scripts/validate-mvp-docker.sh benchmarks/fixtures/mvp-c-vul/fake-provider.env
```

The checked fake provider is an explicit MVP fixture, not reusable reconstruction logic or evidence of model quality. It is non-root, read-only, reachable only on an internal Compose network, accepts a bounded request body, and returns exactly the two fixture responses needed to exercise reconstruction and repair. The normal application and isolated binary-runner services still receive no fixture source. The same validation script also supports a real OpenAI-compatible model configuration:

```bash
git submodule update --init --recursive
cp .env.example .env
# Edit .env, then:
scripts/validate-mvp-docker.sh .env
```

The script uses the no-network, read-only `fixture-builder` profile with a bounded temporary filesystem to compile only `01_out_of_bounds_write.c` with pinned Clang flags into an isolated `binary_01` input directory. Fixture source is mounted read-only only in that builder and is absent from both runtime services. The script then runs `llm_bin_patch patch` through Compose and checks original CWE-787 evidence, isolated execution guarantees, exact `[03] Alexandria Stone` behavior, hashes, logs, secret redaction, and stable output layout. Successful runs contain `decompile/decompiled.c`, `patched_c/patched.c`, `patched_binary/patched_binary`, `evidence/`, `logs/`, and `summary/SUMMARY.md`; failed runs keep available evidence but never publish the final binary.

## Browser GUI

Start the local workbench and open `http://127.0.0.1:8000`:

```bash
./gradlew installDist
build/install/llm_bin_patch/bin/llm_bin_patch web
```

On supported Linux hosts, `installDist` also builds and verifies the production ACP sandbox gate helper at
`build/install/llm_bin_patch/libexec/decomp-acp-gate-helper`, with its content digest beside it. A static libc-capable
`/usr/bin/cc` is required; use `-PacpGateHelperCompiler=/absolute/path/to/cc` only when provisioning an explicit
alternative compiler. ACP configuration must pin the final installed helper and its final runtime manifest as
described in [docs/acp-v1-client.md](docs/acp-v1-client.md#production-gate-helper-artifact).

The GUI provides persistent ELF uploads, recent-job navigation, metadata inspection, background automatic exploration, archival source-tree reconstruction, live status refresh, source browsing, coverage and confidence evidence, repair history, and verified archive downloads. Uploaded binaries are only executed after selecting **Start automatic exploration**, using the same mandatory sandbox as the CLI. Job data defaults to `.decomp_engine/jobs`; change it with `--data-dir`.

For a non-Docker angr installation, set `ANGR_PYTHON` to the Python executable that can import angr before starting the GUI.

## Archival source-tree reconstruction

Generate a buildable multi-file project and deterministic ZIP bundle with Ghidra evidence and optional bounded LLM reconstruction:

```bash
export GHIDRA_HOME=/path/to/ghidra
export BASE_URL=https://api.example.com/v1
export API_KEY=...
export MODEL=...
llm_bin_patch reconstruct ./input/program --output ./output/program-source
```

Functions are assigned to deterministic modules before any LLM request. Each request may replace only its planned C file and is bounded by `--max-context-chars`. A module is accepted only when every owned function has attributable provenance and a non-placeholder definition using portable types. Failed, partial, oversized, and evidence-only results remain buildable when possible but are explicitly marked unresolved; pass `--evidence-only` to request the placeholder tree intentionally.

The output includes `source-tree/` for normal editing, `source-tree.zip` for archival, and `reconstruction.json` for automation. The tree contains shared types, module headers and implementations, a parallel incremental Makefile, the whole-program recovery model, module ownership plan, unresolved entities, per-module prompt budget, prompt hash, acceptance decision, source hash, confidence limitations, tool versions, and build logs. Checkpoints are reused only when their recorded source hash still matches, so an interrupted run preserves accepted module bytes. `ARCHIVE_MANIFEST.sha256` verifies the archive payload.

## Development

Initialize the pinned vulnerability fixture after cloning:

```bash
git submodule update --init --recursive
```

Run the full local CI suite:

```bash
scripts/ci.sh
```

Run the opt-in real-Ghidra adapter test after setting `GHIDRA_HOME`:

```bash
RUN_REAL_GHIDRA=true ./gradlew test --tests 'decompengine.mvp.GhidraDecompilerTest'
```

This executes the Kotlin/JVM test suite. Project planning and progress are tracked in [GitHub milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues). `ROADMAP.md` is deprecated and retained only as a migration pointer.

Trace-guided repair iterates over compile and behavior failures while retaining every regression input in `repair_history.json`:

```bash
llm_bin_patch repair ./original ./generated-project --max-iterations 5 --explore
```

With `--explore`, all automatically generated L4 inputs become persisted L3 regression cases and are re-run after every repair attempt.

Automatic exploration combines bounded symbolic argv/stdin execution, static string hints, and mutations. It writes generated cases, observed output signatures, exploration diagnostics, and an evidence-bounded confidence score to `exploration.json`:

```bash
llm_bin_patch explore ./binary --reports ./reports
```

See [docs/ci.md](docs/ci.md) for CI/CD requirements, GitHub Actions usage, and downstream validation guidance.

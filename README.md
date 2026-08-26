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

The current Compose service does not add `SYS_ADMIN` or run as privileged. Standard Docker therefore prevents nested bubblewrap mount namespaces. Use this environment only with the pinned, trusted MVP fixture until binary execution is moved to a separate no-network runner container.

## Browser GUI

Start the local workbench and open `http://127.0.0.1:8000`:

```bash
./gradlew installDist
build/install/llm_bin_patch/bin/llm_bin_patch web
```

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

Functions are assigned to deterministic modules before any LLM request. Each request may replace only its planned C file and is bounded by `--max-context-chars`. Without complete API configuration, the command emits recovered C where available and explicit buildable stubs otherwise; pass `--evidence-only` to request that behavior intentionally.

The output includes `source-tree/` for normal editing, `source-tree.zip` for archival, and `reconstruction.json` for automation. The tree contains shared types, module headers and implementations, a parallel incremental Makefile, the whole-program recovery model, module ownership plan, unresolved entities, per-module prompt and source hashes, confidence limitations, tool versions, and build logs. `ARCHIVE_MANIFEST.sha256` verifies the archive payload.

## Development

Initialize the pinned vulnerability fixture after cloning:

```bash
git submodule update --init --recursive
```

Run the full local CI suite:

```bash
scripts/ci.sh
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

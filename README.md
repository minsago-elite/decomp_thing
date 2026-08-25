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
docker compose run --rm llm-bin-patch doctor
```

The container includes JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, bubblewrap, Python, and a pinned angr installation. Input files are mounted read-only from `./input`; generated artifacts are written to `./output`.

The current Compose service does not add `SYS_ADMIN` or run as privileged. Standard Docker therefore prevents nested bubblewrap mount namespaces. Use this environment only with the pinned, trusted MVP fixture until binary execution is moved to a separate no-network runner container.

## Browser GUI

Start the local workbench and open `http://127.0.0.1:8000`:

```bash
./gradlew installDist
build/install/llm_bin_patch/bin/llm_bin_patch web
```

The GUI provides persistent ELF uploads, recent-job navigation, metadata inspection, background automatic exploration, live status refresh, coverage and confidence evidence, repair history, and report downloads. Uploaded binaries are only executed after selecting **Start automatic exploration**, using the same mandatory sandbox as the CLI. Job data defaults to `.decomp_engine/jobs`; change it with `--data-dir`.

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

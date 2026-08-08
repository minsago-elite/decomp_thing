# decomp_engine

LLM-assisted binary-to-C reconstruction tooling for Linux x86-64 ELF binaries.

## Docker Environment

Create the local API configuration:

```bash
cp .env.example .env
```

Set `BASE_URL`, `API_KEY`, and `MODEL` in `.env`, then build and verify the environment:

```bash
mkdir -p input output
docker compose build
docker compose run --rm llm-bin-patch doctor
```

The container includes JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, and bubblewrap. Input files are mounted read-only from `./input`; generated artifacts are written to `./output`.

The current Compose service does not add `SYS_ADMIN` or run as privileged. Standard Docker therefore prevents nested bubblewrap mount namespaces. Use this environment only with the pinned, trusted MVP fixture until binary execution is moved to a separate no-network runner container.

## Development

Initialize the pinned vulnerability fixture after cloning:

```bash
git submodule update --init --recursive
```

Run the full local CI suite:

```bash
scripts/ci.sh
```

This executes the Kotlin/JVM test suite. During MVP development, edit `ROADMAP.md` directly; roadmap generation and consistency tooling are disabled.

See [docs/ci.md](docs/ci.md) for CI/CD requirements, GitHub Actions usage, and downstream validation guidance.

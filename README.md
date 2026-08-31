# decomp_engine

LLM-assisted binary-to-C reconstruction tooling for Linux x86-64 ELF binaries.

## ACP setup (default)

ACP v1 is the standard agent path. Build the distribution, copy
[`config/acp-v1.example.json`](config/acp-v1.example.json) to a private mode-`0600` absolute path, and replace every
zero digest with a value measured during trusted provisioning. The credential-free template fixes the ordered agent
argv, disables parent-environment inheritance, and bounds protocol, filesystem, process, memory, CPU, file, and
runtime-closure use. Optional secret provenance is configured explicitly as described in the complete procedure at
[docs/acp-v1-client.md](docs/acp-v1-client.md#operator-provisioning-and-preflight).

```bash
./gradlew installDist
install -m 600 config/acp-v1.example.json /absolute/private/path/acp-v1.json
# Provision the pinned local agent, runtime closure, helper, and tool digests first.
export ACP_CONFIG_FILE=/absolute/private/path/acp-v1.json
build/install/llm_bin_patch/bin/llm_bin_patch doctor --workflow all --output ./output
```

Full `doctor` loads the same strict `AcpHarnessFactory` selection used by workflows, launches the production sandbox,
negotiates stable ACP v1 and all configured plus selected-workflow capabilities, and proves process-tree cleanup. It
does not create a session or send a model prompt. `doctor --tools-only` is explicitly agent-free and does not read or
resolve ACP configuration. The deprecated direct `GET /models` probe exists only behind exact
`--harness legacy-openai` opt-in.

### Docker qualification profile

Host-native execution under a dedicated service UID is the primary supported ACP deployment. Compose exposes an
explicit `acp-host` qualification profile for hosts that deliberately provide that same trust boundary. Copy
`.env.example` to a private `.env`, fill in absolute paths, and run the real initialize preflight:

```bash
mkdir -p input output
cp .env.example .env
chmod 600 .env
# Edit .env and finish config/acp-v1.example.json provisioning as documented.
docker compose --profile acp-host build llm-bin-patch binary-runner-acp
docker compose --profile acp-host run --rm --no-deps llm-bin-patch \
  doctor --workflow all --output /output
```

This profile is qualified only when the container runs as the dedicated, uncompromised host service UID and can see
that UID's live user-systemd bus, host PIDs, and cgroup-v2 hierarchy. The user bus and `/sys/fs/cgroup` are mounted
read-only. `userns_mode: host` deliberately disables Docker UID remapping for these two non-root services so the numeric
UID, user bus owner, and private runner volume share one honest host identity. The application has a read-only root,
drops every capability, sets `no-new-privileges`, uses no `SYS_ADMIN`, privileged mode, or seccomp bypass, and has
`network_mode: none`. Consequently the ACP agent must be a locally runnable, network-free native executable with an
explicitly mounted runtime closure. Remote or provider-backed agents do not work in the production outer-agent
namespace today. Rootless or remapped daemons may reject this host-namespace requirement. If user
`systemd-run --scope`, cgroup inspection, nested unprivileged user namespaces, or the Docker runtime's default seccomp
policy cannot satisfy the production boundary, `doctor` fails and that host is unqualified; do not weaken the profile
to make it pass.

The container includes JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, bubblewrap, Python, and a pinned angr
installation. Input files are mounted read-only from `./input`; generated artifacts are written to `/output`.
Analyzed binaries run in the separate `binary-runner`, which receives no agent or provider credentials, has no network,
a read-only root, no Linux capabilities, read-only input/output mounts, and only a narrow writable request volume. The
ACP profile uses its own `binary-runner-acp` and control volume built with the exact same dedicated UID/GID as the ACP
application; the deprecated legacy profile retains the separate local-UID runner.

Run the complete pinned c-vul acceptance flow deterministically and without credentials from a clean checkout:

```bash
git submodule update --init --recursive
scripts/validate-mvp-docker.sh benchmarks/fixtures/mvp-c-vul/fake-provider.env
```

The checked fake provider is an explicit, deprecated `legacy-openai` MVP fixture, not reusable reconstruction logic,
an ACP agent, or evidence of model quality. The script requires exact `ACP_HARNESS=legacy-openai`; the fixture is
non-root, read-only, reachable only on an internal Compose network, accepts a bounded request body, and returns exactly
the two fixture responses needed to exercise reconstruction and repair. The application and isolated binary-runner
services still receive no fixture source. This acceptance fixture has not yet migrated to ACP. The same script can use
a real OpenAI-compatible endpoint only through the explicit deprecated profile:

```bash
git submodule update --init --recursive
cp .env.legacy-openai.example .env.legacy-openai
# Keep this file private and edit the deprecated provider settings.
chmod 600 .env.legacy-openai
# Edit .env.legacy-openai, then:
scripts/validate-mvp-docker.sh .env.legacy-openai
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
export ACP_CONFIG_FILE=/absolute/private/path/acp-v1.json
llm_bin_patch reconstruct ./input/program --output ./output/program-source
```

Functions are assigned to deterministic modules before any LLM request. Each request may replace only its planned C file and is bounded by `--max-context-chars`. A module is accepted only when every owned function has attributable provenance and a non-placeholder definition using portable types. Failed, partial, oversized, and evidence-only results remain buildable when possible but are explicitly marked unresolved; pass `--evidence-only` to request the placeholder tree intentionally.

The output includes `source-tree/` for normal editing, `source-tree.zip` for archival, and `reconstruction.json` for automation. The tree contains shared types, module headers and implementations, a parallel incremental Makefile, the whole-program recovery model, module ownership plan, unresolved entities, per-module prompt budget, prompt hash, acceptance decision, source hash, confidence limitations, tool versions, and build logs. Checkpoints are reused only when their recorded source hash still matches, so an interrupted run preserves accepted module bytes. `ARCHIVE_MANIFEST.sha256` verifies the archive payload.

## Development

The required LLVM lanes validate the checked source/build/artifact manifest and
recompute both complete ELF files plus their exact twin-equivalence commitments
through the Kotlin/JVM `verifyLlvmOracleArtifacts` gate. The fixed command takes
no arguments and reads only an absolute `LLVM_ORACLE_ARTIFACT_ROOT` containing
the authenticated release layout:

```bash
LLVM_ORACLE_ARTIFACT_ROOT=/absolute/path/to/llvm-oracle-release \
  ./gradlew --no-daemon verifyLlvmOracleArtifacts
```

This gate authenticates one manifest boundary; it does not build LLVM, validate
a fresh container identity, generate downstream truth, score a reconstruction,
or authorize a Kotlin-only release by itself. The retained Python LLVM manifest
verifier is non-authoritative migration compatibility.

The required LLVM push/pull-request lane admits the checked Clang behavior
corpus, its complete 48-case report, and the 16-case diagnostic ownership
matrix through the Kotlin/JVM `verifyLlvmBehaviorReferenceEvidence` gate. That
gate also binds the behavior executable to the manifest's stripped artifact;
it exposes only authenticated immutable reference identities. It does not run
Clang, replay the historical sandbox, compare a reconstruction, score behavior,
or authorize a release. The retained Python offline checker is a compatibility
cross-check and is not authority for this admission.

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

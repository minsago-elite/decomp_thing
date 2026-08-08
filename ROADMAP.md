# MVP Roadmap

The MVP proves one complete path for small, symbol-bearing Linux binaries: decompile an input ELF into editable C, patch one evidenced memory-safety vulnerability, rebuild it, and verify the failing execution is fixed without breaking observed behavior.

This file is maintained directly during MVP development. Update the checklist and current phase when verified work lands.

## Current Status

- Current phase: **L1-L2 CLI vertical slice**
- Status: **in progress**
- Next target: complete the CLI against the pinned fixture while deriving reconstruction from the input binary, never from fixture source.

## MVP Scope

- Linux x86-64 ELF.
- Small, dynamically linked, symbol-bearing Linux x86-64 ELF programs with no external files, arguments, or interactive input.
- The pinned `01_out_of_bounds_write.c` binary is the acceptance fixture, not a hard-coded reconstruction template.
- One automatically observed default execution plus a memory-safety finding confirmed on rebuilt code with sanitizers.
- Generated C source, patched C source, rebuilt binary, and validation report.
- Human approval before applying a generated security patch; `--yes` permits CI automation.
- A CLI-first workflow that streams progress and tool output while the job is running.
- A reproducible Docker environment with no host dependencies beyond Docker and Git.
- A provider-neutral OpenAI-compatible LLM client configured through `.env`.

## Docker Environment

The MVP ships with a pinned `Dockerfile` and `compose.yaml` that install and configure:

- JDK 21 and the Gradle wrapper runtime.
- Headless Ghidra and its JVM classpath.
- GCC, Make, binutils, AddressSanitizer, and UndefinedBehaviorSanitizer.
- bubblewrap for network-disabled execution of analyzed binaries.
- the built `llm_bin_patch` CLI and the initialized c-vul fixture.

The image runs as a non-root user. Input is mounted read-only at `/input`, output is mounted read-write at `/output`, and API credentials are supplied only at container runtime. Tool versions and the Ghidra download checksum are pinned so a clean image build is reproducible.

Example execution:

```bash
docker compose run --rm llm-bin-patch \
  patch /input/binary_01 --output /output
```

The CLI provides a `doctor` command that checks Java, Ghidra, GCC, sanitizers, binutils, bubblewrap, writable output, and LLM connectivity before a patch run.

## LLM Configuration

`compose.yaml` loads these values from an untracked `.env` file:

```dotenv
BASE_URL=https://api.example.com/v1
API_KEY=replace-me
MODEL=openai-compatible-model-name
REASONING_EFFORT=medium
```

- Commit `.env.example` with placeholders and ignore `.env` in Git.
- Treat `BASE_URL` as the API root and call the standard `POST {BASE_URL}/chat/completions` endpoint.
- Send `API_KEY` as a bearer token and `MODEL` as the request model without provider-specific translation.
- Send optional `REASONING_EFFORT` as `reasoning_effort`; omit the field when the value is blank for providers that do not support it.
- Depend only on the OpenAI-compatible chat-completions request and response fields used by the MVP.
- Replace OpenRouter-specific class names, errors, prompts, and documentation with provider-neutral names.
- Validate required configuration at startup and report actionable errors for invalid URLs, authentication failures, timeouts, rate limits, malformed responses, and unavailable models.
- Apply explicit connection and request timeouts with bounded retries for transient failures.
- Never write `API_KEY`, authorization headers, or full credential-bearing requests to stdout, stderr, logs, `SUMMARY.md`, image layers, or build history.
- Test against a deterministic local OpenAI-compatible fake server; keep real-provider smoke tests opt-in.

## CLI Contract

The MVP is operated through one command:

```bash
llm_bin_patch patch <input-elf> --output <directory>
```

- Print each phase as it starts: inspect, reconstruct, compile, reproduce, patch, and verify.
- Stream Ghidra, compiler, sanitizer, and validation output immediately instead of buffering it until completion.
- Send normal progress to stdout and warnings or errors to stderr, flushing after every event.
- Mirror the streamed output into timestamped log files under the output directory.
- Prompt for human approval before applying the proposed source patch.
- Finish with a concise summary containing the result, output paths, and any residual risk.
- Return exit code 0 only when reconstruction, patching, recompilation, exploit blocking, and behavior validation all pass.

## Output Directory

Every successful run produces this stable minimum layout:

```text
<directory>/
|-- decompile/
|   `-- decompiled.c
|-- patched_c/
|   `-- patched.c
|-- patched_binary/
|   `-- patched_binary
|-- summary/
|   `-- SUMMARY.md
|-- logs/
```

- `decompile/decompiled.c` contains the editable C reconstructed from the input ELF before the security patch.
- `patched_c/patched.c` contains the approved patched source.
- `patched_binary/patched_binary` is the final executable that passed security and behavior validation.
- `logs/` contains the timestamped output streamed from analysis, compilation, sanitizers, and validation.
- `summary/SUMMARY.md` records the input and artifact hashes, executed phases, CWE-787 evidence, approved source change, build and hardening settings, validation results, output paths, and residual risks.
- A failed run must retain available logs and `summary/SUMMARY.md` with the failure phase, but must not present an unverified binary as `patched_binary/patched_binary`.

## Steps

1. **L1 Reconstruct:** produce meaningful editable C, compile it, and match required normal behavior.
2. **L2 Patch:** document the vulnerability, map it to the C source, apply an approved patch, and rebuild.
3. **L6 Verify and Deliver:** prove the exploit is blocked, normal behavior remains, and package the artifacts.

L3 through L5 are intentionally omitted from the MVP. Automated repair loops, automatic input exploration, and broad confidence benchmarking remain post-MVP work.

## Checklist

### Environment and API

- [x] Add a pinned Dockerfile containing JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, and bubblewrap.
- [x] Add `compose.yaml` with read-only input, writable output, `.env` loading, and a non-root runtime user.
- [x] Add `.env.example` containing `BASE_URL`, `API_KEY`, `MODEL`, and optional `REASONING_EFFORT`, and add `.env` to `.gitignore`.
- [x] Rename the OpenRouter client to a provider-neutral OpenAI-compatible client.
- [x] Remove the hard-coded OpenRouter endpoint and use `BASE_URL`, `API_KEY`, and `MODEL`.
- [ ] Add configuration validation, credential redaction, timeouts, bounded retries, and clear API error reporting.
- [ ] Add `llm_bin_patch doctor` and verify all required tools inside the container.
- [ ] Move binary execution to a separate no-network runner container without API credentials; do not grant the application container `SYS_ADMIN` or privileged mode.
- [x] Add deterministic OpenAI-compatible API contract tests without requiring an external service.
- [ ] Build the image from a clean checkout and run the pinned c-vul fixture end to end through Docker Compose.

### L1 Reconstruct

- [x] Provide the `llm_bin_patch patch` CLI entry point.
- [x] Stream phase changes and child-process output in real time while retaining logs.
- [ ] Build `binary_01` from the pinned c-vul source only as an acceptance input.
- [ ] Extract Ghidra decompiler output from the ELF without reading or copying fixture source.
- [ ] Ask the configured LLM to turn decompiler output into one standalone, meaningful C file.
- [x] Compile the reconstructed C.
- [ ] Produce `[03] Alexandria Stone` with exit code 0.

### L2 Patch

- [x] Reproduce the original CWE-787 stack buffer overflow with AddressSanitizer.
- [ ] Map the finding to reconstructed C.
- [ ] Apply and record a human-approved minimal patch.
- [x] Show the proposed diff and request approval through the CLI before applying it.
- [x] Compile the patched C with sanitizer and hardening flags.

### L6 Verify and Deliver

- [x] Verify the patched binary has no sanitizer error for the reproducer.
- [x] Verify the patched binary preserves `[03] Alexandria Stone` and exit code 0.
- [x] Write the original reconstructed C to `decompile/decompiled.c`.
- [x] Write the approved patched C to `patched_c/patched.c`.
- [x] Publish the validated executable as `patched_binary/patched_binary`.
- [ ] Write the full process summary and residual risks to `summary/SUMMARY.md`.
- [x] Retain timestamped analysis, build, sanitizer, and validation output under `logs/`.

## Definition of Done

The MVP is done only when a clean checkout can build the Docker image, load `BASE_URL`, `API_KEY`, and `MODEL` from `.env`, and run `llm_bin_patch patch` through Docker Compose without host-installed Java, Ghidra, or C tooling. The command must process the acceptance binary without consulting its source file, emit observable progress before completion, pass every validation check, and produce `decompile/decompiled.c`, `patched_c/patched.c`, `patched_binary/patched_binary`, and `summary/SUMMARY.md`. A fixture-source copy, provider-specific dependency, leaked credential, buildable `return 0` skeleton, buffered output shown only at completion, unverified patched binary, or patch that changes observed normal output does not count.

## Post-MVP

- L3: automate compile and behavior repair loops.
- L4: generate validation inputs automatically.
- L5: expand to stripped, optimized, PIE, file-I/O, and libc-heavy binaries.

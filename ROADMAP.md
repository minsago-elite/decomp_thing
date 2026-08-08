# MVP Roadmap

The MVP proves one complete path: reconstruct one supported vulnerable ELF into editable C, patch one evidenced vulnerability, rebuild it, and verify that the exploit is blocked without breaking required behavior.

This file is maintained directly during MVP development. Update the checklist and current phase when verified work lands.

## Current Status

- Current phase: **L1 Reconstruct**
- Status: **in progress**
- Next target: reconstruct the pinned `01_out_of_bounds_write.c` binary into meaningful editable C.

## MVP Scope

- Linux x86-64 ELF.
- One fixture: `benchmarks/fixtures/c-vul/src/01_out_of_bounds_write.c` from the pinned `c-vul` submodule.
- One expected behavior: print `[03] Alexandria Stone` and exit successfully.
- One exploit reproducer: run the original fixture with AddressSanitizer and observe a stack buffer overflow.
- Generated C source, patched C source, rebuilt binary, and validation report.
- Human approval before applying a generated security patch.
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
```

- Commit `.env.example` with placeholders and ignore `.env` in Git.
- Treat `BASE_URL` as the API root and call the standard `POST {BASE_URL}/chat/completions` endpoint.
- Send `API_KEY` as a bearer token and `MODEL` as the request model without provider-specific translation.
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
|-- decompiled/
|   `-- reconstructed.c
|-- patched/
|   `-- patched_binary
|-- logs/
`-- SUMMARY.md
```

- `decompiled/reconstructed.c` contains the editable C reconstructed from the input ELF before the security patch.
- `patched/patched_binary` is the final executable that passed security and behavior validation.
- `logs/` contains the timestamped output streamed from analysis, compilation, sanitizers, and validation.
- `SUMMARY.md` records the input and artifact hashes, executed phases, CWE-787 evidence, approved source change, build and hardening settings, validation results, output paths, and residual risks.
- A failed run must retain available logs and `SUMMARY.md` with the failure phase, but must not present an unverified binary as `patched/patched_binary`.

## Steps

1. **L1 Reconstruct:** produce meaningful editable C, compile it, and match required normal behavior.
2. **L2 Patch:** document the vulnerability, map it to the C source, apply an approved patch, and rebuild.
3. **L6 Verify and Deliver:** prove the exploit is blocked, normal behavior remains, and package the artifacts.

L3 through L5 are intentionally omitted from the MVP. Automated repair loops, automatic input exploration, and broad confidence benchmarking remain post-MVP work.

## Checklist

### Environment and API

- [x] Add a pinned Dockerfile containing JDK 21, headless Ghidra, GCC, Make, binutils, sanitizers, and bubblewrap.
- [x] Add `compose.yaml` with read-only input, writable output, `.env` loading, and a non-root runtime user.
- [x] Add `.env.example` containing `BASE_URL`, `API_KEY`, and `MODEL`, and add `.env` to `.gitignore`.
- [x] Rename the OpenRouter client to a provider-neutral OpenAI-compatible client.
- [x] Remove the hard-coded OpenRouter endpoint and use `BASE_URL`, `API_KEY`, and `MODEL`.
- [ ] Add configuration validation, credential redaction, timeouts, bounded retries, and clear API error reporting.
- [ ] Add `llm_bin_patch doctor` and verify all required tools inside the container.
- [ ] Move binary execution to a separate no-network runner container without API credentials; do not grant the application container `SYS_ADMIN` or privileged mode.
- [x] Add deterministic OpenAI-compatible API contract tests without requiring an external service.
- [ ] Build the image from a clean checkout and run the pinned c-vul fixture end to end through Docker Compose.

### L1 Reconstruct

- [ ] Provide the `llm_bin_patch patch` CLI entry point.
- [ ] Stream phase changes and child-process output in real time while retaining logs.
- [ ] Build `binary_01` from the pinned c-vul source.
- [ ] Reconstruct meaningful editable C from the ELF.
- [ ] Compile the reconstructed C.
- [ ] Produce `[03] Alexandria Stone` with exit code 0.

### L2 Patch

- [x] Reproduce the original CWE-787 stack buffer overflow with AddressSanitizer.
- [ ] Map the finding to reconstructed C.
- [ ] Apply and record a human-approved minimal patch.
- [ ] Show the proposed diff and request approval through the CLI before applying it.
- [ ] Compile the patched C with sanitizer and hardening flags.

### L6 Verify and Deliver

- [ ] Verify the patched binary has no sanitizer error for the reproducer.
- [ ] Verify the patched binary preserves `[03] Alexandria Stone` and exit code 0.
- [ ] Write the original reconstructed C to `decompiled/reconstructed.c`.
- [ ] Publish the validated executable as `patched/patched_binary`.
- [ ] Write the full process summary and residual risks to `SUMMARY.md`.
- [ ] Retain timestamped analysis, build, sanitizer, and validation output under `logs/`.

## Definition of Done

The MVP is done only when a clean checkout can build the Docker image, load `BASE_URL`, `API_KEY`, and `MODEL` from `.env`, and run `llm_bin_patch patch` through Docker Compose without host-installed Java, Ghidra, or C tooling. The command must run `roadmap/benchmarks/vulnerability_remediation.json` end to end for `01_out_of_bounds_write.c`, emit observable progress before completion, pass every validation check, and produce `decompiled/reconstructed.c`, `patched/patched_binary`, and `SUMMARY.md`. A provider-specific OpenRouter dependency, leaked credential, buildable `return 0` skeleton, buffered output shown only at completion, analyzer warning without the sanitizer reproducer, unverified patched binary, or patch that changes the expected badge output does not count.

## Post-MVP

- L3: automate compile and behavior repair loops.
- L4: generate validation inputs automatically.
- L5: expand to stripped, optimized, PIE, file-I/O, and libc-heavy binaries.

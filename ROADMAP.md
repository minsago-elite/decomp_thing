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

The MVP is done only when `llm_bin_patch patch` runs `roadmap/benchmarks/vulnerability_remediation.json` end to end for `01_out_of_bounds_write.c`, emits observable progress before the command finishes, passes every validation check, and produces `decompiled/reconstructed.c`, `patched/patched_binary`, and `SUMMARY.md`. A buildable `return 0` skeleton, buffered output shown only at completion, an analyzer warning without the sanitizer reproducer, an unverified patched binary, or a patch that changes the expected badge output does not count.

## Post-MVP

- L3: automate compile and behavior repair loops.
- L4: generate validation inputs automatically.
- L5: expand to stripped, optimized, PIE, file-I/O, and libc-heavy binaries.

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

## Steps

1. **L1 Reconstruct:** produce meaningful editable C, compile it, and match required normal behavior.
2. **L2 Patch:** document the vulnerability, map it to the C source, apply an approved patch, and rebuild.
3. **L6 Verify and Deliver:** prove the exploit is blocked, normal behavior remains, and package the artifacts.

L3 through L5 are intentionally omitted from the MVP. Automated repair loops, automatic input exploration, and broad confidence benchmarking remain post-MVP work.

## Checklist

### L1 Reconstruct

- [ ] Build `binary_01` from the pinned c-vul source.
- [ ] Reconstruct meaningful editable C from the ELF.
- [ ] Compile the reconstructed C.
- [ ] Produce `[03] Alexandria Stone` with exit code 0.

### L2 Patch

- [x] Reproduce the original CWE-787 stack buffer overflow with AddressSanitizer.
- [ ] Map the finding to reconstructed C.
- [ ] Apply and record a human-approved minimal patch.
- [ ] Compile the patched C with sanitizer and hardening flags.

### L6 Verify and Deliver

- [ ] Verify the patched binary has no sanitizer error for the reproducer.
- [ ] Verify the patched binary preserves `[03] Alexandria Stone` and exit code 0.
- [ ] Package sources, binaries, diff, build logs, validation results, and residual risks.

## Definition of Done

The MVP is done only when `roadmap/benchmarks/vulnerability_remediation.json` passes end to end for `01_out_of_bounds_write.c`. A buildable `return 0` skeleton, an analyzer warning without the sanitizer reproducer, or a patch that changes the expected badge output does not count.

## Post-MVP

- L3: automate compile and behavior repair loops.
- L4: generate validation inputs automatically.
- L5: expand to stripped, optimized, PIE, file-I/O, and libc-heavy binaries.

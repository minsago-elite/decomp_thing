# MVP Roadmap

The MVP proves one complete path: reconstruct one supported vulnerable ELF into editable C, patch one evidenced vulnerability, rebuild it, and verify that the exploit is blocked without breaking required behavior.

Progress is evidence-backed in `roadmap/progress.json`. Run `./gradlew roadmapUpdate` after changing progress and `./gradlew roadmapCheck` in CI.

## Current Status

<!-- roadmap:summary:start -->
- Current maturity level: `L1`
- Current milestone: Reconstruct
- Current status: `active`
- Next failing gate: one supported vulnerable ELF is reconstructed into meaningful editable C
- Latest generated report: `roadmap/reports/latest.json`
<!-- roadmap:summary:end -->

## MVP Scope

- Linux x86-64 ELF.
- One fixture: stack buffer overflow.
- One normal-input corpus and one exploit reproducer.
- Generated C source, patched C source, rebuilt binary, and validation report.
- Human approval before applying a generated security patch.

## Steps

1. **L1 Reconstruct:** produce meaningful editable C, compile it, and match required normal behavior.
2. **L2 Patch:** document the vulnerability, map it to the C source, apply an approved patch, and rebuild.
3. **L6 Verify and Deliver:** prove the exploit is blocked, normal behavior remains, and package the artifacts.

L3 through L5 are intentionally omitted from the MVP. Automated repair loops, automatic input exploration, and broad confidence benchmarking remain post-MVP work.

## Progress

<!-- roadmap:progress:start -->
| Level | Name | Status | Passing Gates | Blocking Gate |
|---|---|---:|---:|---|
| L1 | Reconstruct | active | 0/3 | one supported vulnerable ELF is reconstructed into meaningful editable C |
| L2 | Patch | pending | 0/3 | the vulnerability has a reproducible finding and maps to reconstructed source |
| L6 | Verify and Deliver | pending | 0/3 | the original exploit reproduces and the patched binary blocks it |
<!-- roadmap:progress:end -->

## Definition of Done

The MVP is done only when `roadmap/benchmarks/vulnerability_remediation.json` passes end to end. A buildable `return 0` skeleton, an analyzer warning without a reproducer, or a patch that breaks valid behavior does not count.

## Post-MVP

- L3: automate compile and behavior repair loops.
- L4: generate validation inputs automatically.
- L5: expand to stripped, optimized, PIE, file-I/O, and libc-heavy binaries.

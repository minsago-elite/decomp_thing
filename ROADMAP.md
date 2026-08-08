# Self-Documenting Roadmap

This roadmap tracks progress toward a recompilable, behaviorally equivalent C reconstruction tool for Linux x86-64 ELF binaries that can remediate evidenced vulnerabilities and produce a validated replacement binary.

Progress is intentionally evidence-backed. Human-readable milestone docs live under `roadmap/milestones/`, while machine-readable state lives in `roadmap/progress.json`. Run `./gradlew roadmapUpdate` to regenerate summaries and `./gradlew roadmapCheck` in CI to reject stale or unsupported progress claims.

For the MVP, implementation proceeds from L2 directly to a constrained L6 workflow. L3 through L5 remain documented but are deferred until the end-to-end reconstruction, patching, recompilation, and validation path works on the MVP fixtures.

## Current Status

<!-- roadmap:summary:start -->
- Current maturity level: `L6`
- Current milestone: Vulnerability Remediation
- Current status: `active`
- Next failing gate: vulnerability findings include reproducible evidence, affected behavior, and CWE classification
- Latest generated report: `roadmap/reports/latest.json`
<!-- roadmap:summary:end -->

## Maturity Model

L0 through L6 describe increasing practical confidence. L6 is the strongest practical target for this project, not a universal proof that every possible input behaves identically or that every vulnerability has been removed.

- L0: Skeleton - accept a binary and create a visible job.
- L1: Recompilable Output - generate a buildable C project.
- L2: Simple Behavioral Match - match process I/O for simple binaries.
- L3: Trace-Guided Repair - use runtime diffs and OpenRouter patches to improve output.
- L4: Automatic Exploration - generate validation inputs automatically.
- L5: High-Confidence Reconstruction - pass a broad benchmark suite with honest confidence reporting.
- L6: Vulnerability Remediation - find evidenced vulnerabilities, patch reconstructed source, rebuild it, and validate security and behavioral regressions.

MVP execution order: `L1 -> L2 -> L6`. Deferred levels retain their existing evidence and will be reactivated after the MVP path is demonstrated end to end.

## Progress

<!-- roadmap:progress:start -->
| Level | Name | Status | Passing Gates | Blocking Gate |
|---|---|---:|---:|---|
| L0 | Skeleton | complete | 4/4 | none |
| L1 | Recompilable Output | complete | 6/6 | none |
| L2 | Simple Behavioral Match | complete | 5/5 | none |
| L3 | Trace-Guided Repair | deferred | 5/5 | none |
| L4 | Automatic Exploration | deferred | 5/5 | none |
| L5 | High-Confidence Reconstruction | deferred | 3/6 | benchmark suite passes across stripped, optimized, PIE, non-PIE, stdin, argv, file, and libc-heavy examples |
| L6 | Vulnerability Remediation | active | 0/7 | vulnerability findings include reproducible evidence, affected behavior, and CWE classification |
<!-- roadmap:progress:end -->

## Benchmark Summary

Benchmark definitions live under `roadmap/benchmarks/`.

- `simple_cli.json`: hello-world and argv-style programs.
- `stdin_programs.json`: stdin-driven programs.
- `file_io.json`: programs that read and write files.
- `stripped_optimized.json`: stripped, optimized, PIE, non-PIE, and libc-heavy cases.
- `vulnerability_remediation.json`: end-to-end vulnerability evidence, source patching, recompilation, and security and behavior regressions.

The latest generated summary is written to `roadmap/reports/latest.json`.

## Known Blockers

- No reconstruction engine exists yet.
- High-confidence reconstruction has not started yet.
- Broad benchmark execution beyond simple L2-L4 fixtures has not started yet.
- Vulnerability detection, finding-to-source mapping, security patch generation, and exploit regression validation have not started yet.
- L3 trace-guided repair, L4 automatic exploration, and L5 broad confidence work are deferred for the MVP.

## Updating Progress

After implementing a feature or adding benchmark evidence:

```bash
./gradlew roadmapUpdate
./gradlew roadmapCheck
```

The update command rewrites `roadmap/progress.json`, `roadmap/reports/latest.json`, and the generated sections in this file. The check command fails if the roadmap is stale, malformed, or claims a completed level while any required gate is not passing.

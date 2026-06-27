# Self-Documenting Roadmap

This roadmap tracks progress toward a recompilable, behaviorally equivalent C reconstruction tool for Linux x86-64 ELF binaries.

Progress is intentionally evidence-backed. Human-readable milestone docs live under `roadmap/milestones/`, while machine-readable state lives in `roadmap/progress.json`. Run `python -m decomp_engine.roadmap update` to regenerate summaries and `python -m decomp_engine.roadmap check` in CI to reject stale or unsupported progress claims.

## Current Status

<!-- roadmap:summary:start -->
- Current maturity level: `L2`
- Current milestone: Simple Behavioral Match
- Current status: `complete`
- Next failing gate: none
- Latest generated report: `roadmap/reports/latest.json`
<!-- roadmap:summary:end -->

## Maturity Model

L0 through L5 describe increasing practical confidence. L5 is the strongest practical target for this project, not a universal proof that every possible input behaves identically for every possible environment.

- L0: Skeleton - accept a binary and create a visible job.
- L1: Recompilable Output - generate a buildable C project.
- L2: Simple Behavioral Match - match process I/O for simple binaries.
- L3: Trace-Guided Repair - use runtime diffs and OpenRouter patches to improve output.
- L4: Automatic Exploration - generate validation inputs automatically.
- L5: High-Confidence Reconstruction - pass a broad benchmark suite with honest confidence reporting.

## Progress

<!-- roadmap:progress:start -->
| Level | Name | Status | Passing Gates | Blocking Gate |
|---|---|---:|---:|---|
| L0 | Skeleton | complete | 4/4 | none |
| L1 | Recompilable Output | complete | 6/6 | none |
| L2 | Simple Behavioral Match | complete | 5/5 | none |
| L3 | Trace-Guided Repair | pending | 0/5 | Failed validation cases produce structured diffs |
| L4 | Automatic Exploration | pending | 0/5 | angr creates candidate argv/stdin cases |
| L5 | High-Confidence Reconstruction | pending | 0/6 | benchmark suite passes across stripped, optimized, PIE, non-PIE, stdin, argv, file, and libc-heavy examples |
<!-- roadmap:progress:end -->

## Benchmark Summary

Benchmark definitions live under `roadmap/benchmarks/`.

- `simple_cli.json`: hello-world and argv-style programs.
- `stdin_programs.json`: stdin-driven programs.
- `file_io.json`: programs that read and write files.
- `stripped_optimized.json`: stripped, optimized, PIE, non-PIE, and libc-heavy cases.

The latest generated summary is written to `roadmap/reports/latest.json`.

## Known Blockers

- No reconstruction engine exists yet.
- Broad benchmark execution beyond L2 fixtures has not started yet.
- L3 trace-guided repair has not started yet.

## Updating Progress

After implementing a feature or adding benchmark evidence:

```bash
python -m decomp_engine.roadmap update
python -m decomp_engine.roadmap check
```

The update command rewrites `roadmap/progress.json`, `roadmap/reports/latest.json`, and the generated sections in this file. The check command fails if the roadmap is stale, malformed, or claims a completed level while any required gate is not passing.

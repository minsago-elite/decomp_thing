# L1: Recompilable Output

Goal: produce a buildable C project from an analyzed ELF.

Required gates:

- Ghidra analysis runs.
- Initial C project is generated.
- `make` completes for simple binaries.
- Build logs are captured.
- Generated artifact layout is stable.

Acceptance evidence should include a generated project fixture with `Makefile`, `src/`, `include/`, `reports/`, and a successful build report.

# Resumable Ghidra program-model export

Whole-program export is staged through durable records under
`analysis/reports/program_model.json.export/`. Each accepted function is written and forced to disk atomically only
after its referenced global and type records are durable. The final `program_model.json` is assembled in address order
by streaming those records; the Ghidra script never retains all decompiled C bodies in memory.

`analysis/reports/program_model.json.progress.json` reports the current phase, completed and total function counts,
recovered, partial, and failed counts, the number of checkpoints reused by this invocation, and the current function. A failed or
timed-out function becomes a normal model record with `status: failed`; its bounded diagnostic is retained separately
under `program_model.json.export/failures/`, so one bad function cannot abort the remaining export.

## Resume procedure and bounds

Run the same reconstruction command again with the same binary and output directory. The checkpoint identity binds the
records to the input SHA-256, exact exporter SHA-256 and version, Ghidra language, and compiler specification. Accepted function records
are reused without invoking the decompiler again. A mismatched binary or exporter is rejected instead of mixing
evidence; start a new output directory when intentionally changing either.

The reference GCC-driver budget is one 10-minute invocation and 4 GiB peak RSS. The Kotlin process adapter enforces the
10-minute wall-clock ceiling and leaves completed records resumable on timeout. A benchmark profile supplies the exact
analyzer identity and resource envelope instead of relying on a workstation default. The A10 cc1/lto1 profile binds
NSA's Ghidra 12.1.3 release archive (569,445,154 bytes; SHA-256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`) and allows 30 minutes and 16 GiB for
authenticated export plus ownership planning. Ghidra's `analyzeHeadless` launcher caps its Java heap independently;
the Kotlin monitor measures the JVM and its complete descendant process tree against the profile ceiling.
Each function decompilation has a 60-second timeout, and export is deliberately single-function staged so its live C
body memory is bounded by the largest individual function rather than the complete program.

To test crash recovery, terminate the reconstruction container during the decompilation phase, retain the output
volume, and rerun the identical command. The `reused` progress count must be nonzero, the completed total must be
monotonic, and the final model must be byte-identical to an uninterrupted export of the same binary.

The A10 production entry point is deliberately agent-free and JVM-owned:

```bash
llm_bin_patch gcc-engine-plan cc1 /path/to/gcc-cc1.stripped \
  --profile oracle/gcc/16.2.0/compiler-engines.json \
  --ghidra-archive /path/to/ghidra_12.1.3_PUBLIC_20260817.zip \
  --ghidra-home /path/to/ghidra_12.1.3_PUBLIC \
  --output /path/to/cc1-plan
```

The command authenticates the profile and all of its source/build/toolchain and ELF-manifest bindings, authenticates
the exact stripped binary and Ghidra archive, proves every installed Ghidra file byte and tree member against that
archive, runs the bundled exporter, assigns functions, globals, and types exactly
once with the deterministic planner, and publishes self-hashed `compiler_engine_plan_evidence.json`. ACP receives this
evidence read-only only in later implementation or repair phases; an agent cannot author or certify it.

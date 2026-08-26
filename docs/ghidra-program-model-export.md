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
records to the input SHA-256, exporter version, Ghidra language, and compiler specification. Accepted function records
are reused without invoking the decompiler again. A mismatched binary or exporter is rejected instead of mixing
evidence; start a new output directory when intentionally changing either.

The reference GCC-driver budget is one 10-minute invocation and 4 GiB peak RSS. The Kotlin process adapter enforces the
10-minute wall-clock ceiling and leaves completed records resumable on timeout. The pinned Ghidra 12.0.4
`analyzeHeadless` launcher caps its Java heap at 2 GiB; the remaining 2 GiB is the allowance for native/runtime overhead.
Each function decompilation has a 60-second timeout, and export is deliberately single-function staged so its live C
body memory is bounded by the largest individual function rather than the complete program.

To test crash recovery, terminate the reconstruction container during the decompilation phase, retain the output
volume, and rerun the identical command. The `reused` progress count must be nonzero, the completed total must be
monotonic, and the final model must be byte-identical to an uninterrupted export of the same binary.

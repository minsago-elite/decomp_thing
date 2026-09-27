# Clang diagnostic fidelity matrix v1

This note records the checked contract currently available for issue #121. It is
evidence for the matrix and normalization boundary; it is not a candidate
execution result or a release decision.

## Authenticated checked inputs

The matrix generator reads the checked corpus at
`oracle/llvm/22.1.6/behavior-corpus.json` and validates it before deriving the
matrix. The corpus is schema version `1`, has ID
`clang-22-1-6-driver-behavior`, and contains 48 ordered cases, 16 of which are
diagnostic cases. The matrix is schema version `1` with ID
`clang-22.1.6-diagnostics-v1`.

The checked binding values are:

| Binding | SHA-256 |
| --- | --- |
| Corpus | `acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b` |
| Matrix canonical payload | `fc8145038141fca072d506391b4d93311aa3842ea6bfa088285c5dce7943ed3b` |

`matrixSha256` is recomputed over the canonical matrix without its own hash;
`corpusSha256` is recomputed from the canonical validated corpus. The generator
and validator are `oracle/clang_diagnostic_matrix.py`. The focused test also
regenerates the checked matrix byte-for-byte and rejects a mutated observation
hash.

## Case and field contract

The 16 diagnostic cases are:

`assemble-invalid`, `diagnostic-color-always`, `diagnostic-color-never`,
`diagnostic-error-limit`, `diagnostic-fixit`, `diagnostic-invalid-option`,
`diagnostic-missing-include`, `diagnostic-syntax`,
`diagnostic-template-backtrace`, `diagnostic-warning-option`,
`driver-missing-linker`, `link-undefined-symbol`, `pch-reuse-wrong-target`,
`preprocess-malformed-macro`, `response-file-recursion`, and
`target-unsupported-aarch64`.

Each matrix row binds the expected exit status and exact stdout/stderr hashes,
and assigns an owning Clang subsystem. Each row has deterministic mismatch IDs
for `exitCode`, `order`, `stderr`, and `stdout`. The checked rows cover
assembler, color, caret/ranges, fatal errors, fix-its, limits, notes, option
provenance, preprocessing, templates, warnings, target selection, and related
driver/linker cases.

The policy fixes locale `C` and terminal behavior to `non-tty-no-width`. It
forbids normalization of diagnostic wording, identifiers, line/column values,
option names, ordering, and severity. Path replacement is permitted only for
the exact authenticated workspace/oracle roots. Every checked diagnostic
stdout/stderr field currently declares an empty normalization list, so the
stored bytes remain the comparison contract.

The corpus separately fixes the inherited environment, argv, files/stdin,
exit status, stream bytes, and artifact observations. This matrix note does
not expand those observations or infer them from a reconstruction.

## Authority and unresolved production gates

The Kotlin reference-evidence path authenticates the corpus, reference report,
matrix, manifest, sandbox, and retained observations. Candidate assessment is
explicitly `non-authoritative-caller-supplied-observations-v1` with
`releaseEligible=false`; its reserved `order` IDs are not inferred from
stderr. Candidate execution admission remains a pre-START receipt: it does
not launch a candidate or publish candidate observations.

Therefore this checked contract does not yet provide:

- an authenticated candidate runner and captured candidate diagnostic bytes;
- live verification of field-specific normalization, diagnostic ordering, or
  template backtrace ordering;
- repeated clean reference/candidate replay with durable mismatch publication;
- hosted clean-build/ACP lineage for the admitted candidate; or
- a fail-closed release decision for #121 or milestone A15.

Those are unresolved states, not passing results. This slice does not invoke
Ghidra or alter the bundled Ghidra Java/API boundary; production analysis must
continue to use the bundled isolated worker and must not require `GHIDRA_HOME`
or an external `analyzeHeadless` installation. ACP remains unable to author,
replace, score, or certify oracle truth.

The parent tracker and child issues #867, #868, #869, and #870 remain open.

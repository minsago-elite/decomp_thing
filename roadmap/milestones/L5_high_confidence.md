# L5: High-Confidence Reconstruction

Goal: strongest practical version of project maturity.

Required gates:

- benchmark suite passes across stripped, optimized, PIE, non-PIE, stdin, argv, file, and libc-heavy examples.
- generated project recompiles reproducibly.
- behavior matches on all benchmark-generated cases.
- unresolved functions/globals are explicitly reported.
- confidence score and limitations are shown honestly.
- no claim of universal equivalence unless formally proven for that specific binary.

L5 does not mean all possible binaries are perfectly reconstructed. It means the tool has broad evidence, produces recompilable artifacts, explains residual uncertainty, and avoids overstating equivalence.

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

## Honest limitations

- Reconstruction produces behavior comparisons on the sandboxed cases that were actually exercised. It never claims equivalence for inputs or environments that were not tested.
- Sandboxed execution is mandatory (bubblewrap). Network namespace isolation (`bwrap --unshare-net`) is applied when the host permits it; when it is unavailable, reports record `networkIsolated: false` rather than silently dropping the guarantee. Filesystem isolation (`--ro-bind`, `--die-with-parent`) remains mandatory in all environments.
- The `reports/unresolved.json` artifact explicitly states that unresolved external symbols do not imply behavioral equivalence.
- Confidence scores are bounded by input breadth, source breadth, output coverage, and sandbox status, and are surfaced alongside the evidence rather than as a universal claim.

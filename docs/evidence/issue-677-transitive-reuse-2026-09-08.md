# Issue #677: transitive invalidation and interrupted reuse

This record captures the existing local contract exercised by
`SourceTreeTest.interface changes invalidate transitive consumers and resume preserves completed revisions`.

The four module fixture is `leaf -> middle -> root` plus an unrelated module.
Changing `leaf`'s interface causes reconstruction calls for `leaf`, `middle`,
and `root`; an interruption at `root` leaves the completed `leaf` and `middle`
revisions available; the next run calls `root` only; and the unrelated
checkpoint bytes remain unchanged. The test also recomputes the recorded
source and checkpoint SHA-256 values and requires the local generated-C build
to succeed.

This is evidence for the bounded `SourceTreeGenerator` checkpoint contract.
It does not qualify production execution: the reconstructor is scripted, the
compiler gate is a local host subprocess, and no authenticated external-agent
restart, contained production compiler, bundled Ghidra analysis, or measured
behavior/coverage gate is exercised here. Existing provenance checks and
explicit unresolved states remain authoritative; this record adds no reuse or
trust decision.

Focused verification passed on 2026-09-08 with:

```text
./gradlew test --tests 'decompengine.project.SourceTreeTest.interface changes invalidate transitive consumers and resume preserves completed revisions'
BUILD SUCCESSFUL
```

Broad tests and production qualification were not run for this slice.

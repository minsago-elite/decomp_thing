# GCC repeatability evidence boundary

This is the small #727 evidence slice recorded from repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`. It records the checked driver
observation and the bounds that a future repeated integrated run must preserve;
it does not claim that the integrated reconstructed workflow is qualified.

## Checked observation

The GCC 16.2.0 profile contains one canonical behavior corpus and one retained
evidence report. The corpus has 14 cases and the report records all 14 as
`passed`. The report is bound to the exact corpus, stripped driver, OCI image,
and Docker control client below:

| input | path | identity |
| --- | --- | --- |
| corpus | `oracle/gcc/16.2.0/behavior-corpus.json` | SHA-256 `bcc1a14ca8c54f94106c943f0bc5698cb9af3151b7bf20a49ae3c8828baaad0e` |
| retained report | `oracle/gcc/16.2.0/behavior-corpus-evidence.json` | SHA-256 `9dcf787aea232615a1ff8721144b86bc1f5e9a2a7068fa9e9280db0bc4ad6803` |
| executable | GCC driver in the corpus | 2,349,296 bytes; SHA-256 `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |
| OCI image | report sandbox | `sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248` |
| control client | report sandbox | Docker 29.7.2; SHA-256 `e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13` |

The corpus clears inherited environment and fixes `HOME`, `LANG`, `LC_ALL`,
`PATH`, `SOURCE_DATE_EPOCH`, `TMPDIR`, and `TZ`. It declares no normalizations.
Its per-case bounds are 5 seconds of CPU and wall time, 512 MiB memory, 64
processes, 64 open files, 2 MiB file and artifact output, 256 KiB per standard
stream, and a 16 MiB/512-entry workspace. The sandbox is network-disabled,
read-only-root, capability-dropped, no-new-privileges, and private PID/IPC with
authenticated cgroup bounds.

This is an exact bounded driver reference observation. The checked report has
no repetition count or per-run resource sample, and the driver corpus does not
include reconstructed `cc1`/`lto1` candidates. Therefore it does not establish
repeatability, candidate equivalence, or integrated workflow completion.

## Unavailable production gates

The engine profile binds `cc1` and `lto1` budgets and provenance, but the
reconstruction archives are not checked in. The retained local engine inventory
is explicitly read-only with `benchmarkAccepted=false`,
`productionVerified=false`, and `releaseEligible=false`; it also records no
ext4 scratch mount. The contained GCC operation remains a pre-START/diagnostic
boundary: it has no accepted engine execution, export, clean rebuild, fresh vs
resumed comparison, or release transition.

The integrated production gate remains unresolved until #725 and #726 provide
authenticated reconstructed driver/engine identities and exact candidate
observations. Any future repeat must retain those identities, exact argv and
environment, all streams and artifacts, exit/signal/timeout/subprocess facts,
resource observations, and source-revision provenance for every repetition.

Analysis must continue through the application-bundled Ghidra Java APIs; an
external `GHIDRA_HOME` or `analyzeHeadless` installation cannot create oracle or
candidate authority. Kotlin/JVM retains oracle comparison and release authority;
candidate output cannot resolve missing, failed, or unavailable evidence.

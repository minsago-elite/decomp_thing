# Resumed-analysis profiling matrix (#1833)

The matrix collector measures bundled-Ghidra analysis without invoking an agent
or changing accepted source. Run it only from a checkout where the run-history
and per-input workspace integration is present on the tested source.

```sh
./gradlew installDist
python3 scripts/profile-1833-matrix.py \
  --cli build/install/llm_bin_patch/bin/llm_bin_patch \
  --evidence-dir "build/1833-matrix-$(date -u +%Y%m%dT%H%M%SZ)"
```

The evidence directory must be new and remain beneath `build/`. The default is
three independent fresh outputs per pinned fixture, followed by three complete
resume invocations on each output. It also runs a shared-output input switch
(`large_project_mtu` → `large_project` → `large_project_mtu`) and a profile
switch (Make → Ninja → Make). Use `--repetitions 2` through `5` to adjust the
sample count. Inputs are checked against `benchmarks/archival/manifest.json` or
the retained GCC driver SHA-256 before any analysis starts.

Each successful invocation must produce one complete closed run history, a
successful `runs list` and `runs replay`, a correlated timing sidecar with
complete parent/worker coverage, and a terminal exporter progress record. The
collector retains those records, command output, `reconstruction.json` and
archive hashes when present, plus application JAR, JDK, Ghidra-manifest, host,
and input pins. `timing-summary.json` reports per-phase min/median/max across
the collected samples. The CLI process tree receives a 4-GiB per-file limit;
after each invocation the collector stops if the observed workspace exceeds
4 GiB total. Each run history is independently bounded to 256 MiB.

The report deliberately says `partial-evidence-collected`. This evidence-only
matrix does not establish partial-work interruption, exporter/tool
invalidation, source/header/interface invalidation, receipt or
compiler-validation invalidation, or compiler acceptance. Those cells must run through the normal reconstruction and
configured compiler acceptance path before #1833 can close or a reduction can
be proposed. The collector does not set `GHIDRA_HOME` or invoke an external
`analyzeHeadless` installation.

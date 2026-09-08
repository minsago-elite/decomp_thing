# Profile-selected Doctor diagnostics

Doctor resolves toolchain diagnostics from the registered reconstruction adapter.
The compiler version probe and authored sanitizer sample use the selected
`compiler-driver`. The build version probe uses `build-executable` and the
adapter's Make or Ninja policy. Generic Doctor code retains Java, binutils,
Python/angr, bundled Ghidra, output, bubblewrap and agent diagnostics.

```sh
build/install/llm_bin_patch/bin/llm_bin_patch doctor --tools-only \
  --profile generated-c-ninja-v1 --output ./output
```

`--profile` also works with full Doctor and its existing harness/workflow options.
It selects the reconstruction toolchain; it does not replace ACP workflow
capability selection. Profile names are exact built-in catalog identifiers.
Unknown or missing profile values produce usage exit code 2 before inspection.
Existing diagnostic failures retain exit code 1, and successful reports retain
exit code 0. Tools-only mode remains independent of agent configuration.

The JVM overload is:

```kotlin
val report = Doctor().inspect(
    DoctorOptions(outputDir, toolsOnly = true),
    ReconstructionProfiles.named("generated-c-ninja-v1"),
)
```

An optional `hostSafetyLimits` parameter admits the requested profile budgets.
Before any command, temporary sample or output write, Doctor performs host
admission, resolves the closed adapter registry and prepares its diagnostic
policy. Preparation requires the adapter's matching build system and exactly one
compiler and build executable. Profile data cannot register diagnostic code.

## Compatibility

The existing Doctor constructor, `inspect(DoctorOptions)`, option/report data
classes and probe interfaces remain available. The one-argument inspection now
delegates through `ReconstructionProfiles.default`, explicitly bound to the
existing Make descriptor. Its compiler changes from hardcoded `gcc` to that
profile's `cc`. This includes the Dockerfile's existing bare tools-only command.
Labels change from `GCC`/`GCC sanitizers` to `C compiler`/`C sanitizers`; build
labels are `Make` or `Ninja`. Existing checks retain relative order. A
`reconstruction profile` check follows the output-directory check and records the
selected identifier and canonical digest.

The sanitizer sample still compiles and runs only the authored
`int main(void) { return 0; }` program with the adapter's fixed C11,
AddressSanitizer and UBSan flags. A compile failure skips execution. Diagnostics
retain the first nonblank compiler/runtime output line and actionable remediation.
Temporary samples are cleaned after success or failure; sanitizer cancellation
propagates after cleanup. Arbitrary project compiler flags are not applied to the
standalone sample, so passing it does not prove a project will build.

Bundled Ghidra still initializes through the application's Java API probe.
Production inspection does not use `GHIDRA_HOME` or an external `analyzeHeadless`.
Agent provisioning, isolated preflight and authenticated oracle boundaries are
unchanged.

## Verification and remaining work

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.doctor.DoctorTest' \
  --tests 'decompengine.doctor.DoctorInvocationTest' \
  --tests 'decompengine.doctor.ProfiledDoctorTest' \
  --tests 'decompengine.doctor.BoundedCommandProbeTest' \
  --tests 'decompengine.doctor.DoctorProbeBudgetTest'
python3 -B -m unittest discover -s tests -p test_generic_leakage.py -v
python3 -B scripts/check-generic-leakage.py --json
```

All 19 selected JVM tests and 15 neutrality unit tests pass, with no failures,
errors or skips. The JVM tests use recording command/connectivity probes and ordinary
authored strings. They cover selected commands, parser forwarding, configuration
admission before effects, useful failures and sanitizer cleanup/cancellation.
They do not execute a real compiler, analyzed program, ACP agent or network probe.
The installed CLI's missing/unknown profile error paths both return 2 with usage
text and create no output directory. All 55 original public JVM
declaration/descriptor pairs across Doctor, its option/report/probe types and the
profile registry are retained. Additions are the profile-aware overload, its
default-argument bridge and the registry's explicit default getter.

Every owned Doctor command probe now uses a monotonic wall-clock and output
allowance. Toolchain version and sanitizer probes share the selected profile's
build phase limits, while bundled Ghidra preparation and its worker use the
export phase ceiling; each group remains below the default host ceiling.
Timeouts and output exhaustion are reported explicitly, and cancellation
terminates observed child processes, closes owned streams and reports incomplete
cleanup. Legacy injected `CommandProbe` callbacks are checked before and after
their call and their returned UTF-8 output is charged, but the callback itself
owns its execution and allocation.

The focused tests use benign authored commands and an authored empty C `main`;
they do not qualify a production compiler, analyzed program, ACP agent or
network probe. Process-handle discovery cannot prove containment of a child
that escapes before observation, so production qualification and broader
consumer migration remain open under [#84](https://github.com/minsago-elite/decomp_thing/issues/84).

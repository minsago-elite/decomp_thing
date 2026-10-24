# GCC exporter generation 17

Generation 17 is the first exporter generation that carries both master's schema-4 referenced-data byte evidence
(introduced with exporter 13) and the cc1 throughput, retry and diagnostic changes that were developed on a separate
line (exporters 12–16 there). The two lines reused the numbers 12 and 13 for different changes, so the merged exporter
takes the next unused number rather than claiming either.

## What changed

- `ExportProgramModel.java` combines both lines: the schema-4 byte evidence of exporter 13, plus the parallel
  decompiler/analysis coordinator, per-function timing and phase-observation lines, the bounded decompiler retry, and
  two performance changes that were verified for exact byte parity on the earlier schema. **The parity of the parallel
  path with the serial path for schema-4 byte evidence is covered by the existing exporter tests but has not been
  re-measured on a full cc1 run.**
- Controls, following the per-generation convention used for exporters 12 and 13:

| File | Role |
|---|---|
| `oracle/gcc/compiler-engines-exporter17.schema.json` | Closed schema for this generation. |
| `oracle/gcc/16.2.0/compiler-engines-exporter17.json` | The checked default. **Serial**: no `fullRecoveryCc1Throughput` policy. |
| `oracle/gcc/16.2.0/compiler-engines-exporter17-parallel.json` | The explicit parallel runtime-6 profile. Identical to the default except for the `fullRecoveryCc1Throughput` block. |
| `oracle/gcc/16.2.0/structural-full-export-profile-exporter17.json` | Structural full-export profile; binds the serial default. |

Exporter 11, 12 and 13 profiles remain as historical evidence; loading them as current controls fails the schema check.

## Serial default and the explicit parallel profile

The default stays serial on purpose. A qualification run of the parallel cc1 export refuses to start unless it is given
a profile with a `fullRecoveryCc1Throughput` policy and runtime invocation version 6 ("cc1 parallel qualification
requires an explicit reviewed runtime6 profile; checked serial default is unqualified"). The parallel profile is that
explicit file. Approving it is a review decision, made by merging it through the normal pull-request review; this
document does not make it reviewed.

The policy is fixed by the schema: four processors, four analysis threads, four decompiler workers, runtime invocation
version 6. The diagnostics policy (runtime invocation version 7) is present in both profiles.

## Wall-clock budget and the CPU allowance

The contained command's aggregate CPU allowance is derived from the wall-clock budget (`aggregateCpuSeconds` is the
wall seconds plus a cleanup reserve, so a 9,000 s budget gave 9,358 CPU-seconds). Throughput changes concurrency, not
that derivation. Both `fullRecoveryCc1ExportWallClockSeconds` and the diagnostics `wallClockSeconds` are therefore
**14,400 s**, which gives about 14,758 CPU-seconds. This is a maximum, not a target; the 1,800 s reference export
budget and the 16 GiB memory bound are unchanged.

Measured on hosted runners with the lineage code, diagnostic-only and unscored:

- Three full-length runs on the same code needed between about 8,900 CPU-seconds (a complete export of all 50,228
  functions, 48.5 minutes wall) and a slower-runner extrapolation of about 13,000. Hosted runner speed varies by roughly
  30–50% between runs, which is the reason for headroom.
- The old 9,358 allowance stopped two of three runs at about half of the functions.
- **The 30-minute reference criterion is not met**: even the fast run took 48.5 minutes, with import and analysis alone
  at 22.9 minutes.

## What this does not establish

- No qualified cc1 model exists yet. The dispatch route `operation=cc1-full-export` (GCC oracle model workflow) runs the
  qualification-mode export with the parallel profile; until it has completed and been independently reviewed, results
  are diagnostic and release-ineligible.
- The Python compatibility tooling for this generation is limited to loading and validating the profile; it does not
  regenerate or score anything.

## Changing the exporter again

The exporter SHA-256 is the digest of the script bytes and is bound by the profile, the structural profile, the schema
inventory, the driver profile pin in `GccCompilerEngineProfile.kt`, the driver structural pins in
`GccDriverStructuralProfile.kt` and several test pins. Any change to `ExportProgramModel.java` requires a new generation
number and regenerating all of them together.

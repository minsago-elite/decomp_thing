# Metadata and export-profile scale evidence contract

Status: `observed-partial`, with production qualification unresolved.

This slice binds the retained scale record to the claims it can support. The
authoritative measurement data is
[`metadata-scale-2026-09-08.json`](metadata-scale-2026-09-08.json). Its
`sourceBaseCommit` and `sourceSha256` fields provide provenance for the
implementation and probe sources; this summary does not replace those
identities.

## Supported observation

The record contains one fresh JVM observation for each authored sparse ELF
input of 1 MiB, 64 MiB, and 1 GiB. All three are at or below the existing 1 GiB
input ceiling and completed successfully with `-Xmx64m`:

| Input | Analyzer time | Probe maximum RSS |
| --- | ---: | ---: |
| 1 MiB | 429 ms | 93,620 KiB |
| 64 MiB | 216 ms | 101,872 KiB |
| 1 GiB | 1,452 ms | 104,988 KiB |

Each observation reports 65,600 charged metadata-read bytes, the fixed 8 MiB
modeled-metadata reservation, zero section/symbol/name visits, and the
`generated-c-make-v1` profile with its requested 600,000 ms export allowance
and 4 GiB resident-memory allowance. The bounded metadata reader, shared
elapsed allowance, profile binding, and bounded report publication remain the
implementation contracts described in
[`bounded-elf-metadata.md`](../bounded-elf-metadata.md),
[`shared-analysis-deadline.md`](../shared-analysis-deadline.md), and
[`bounded-report-publication.md`](../bounded-report-publication.md).

This establishes observed handling of these authored input sizes under the
recorded limits. It does not establish a throughput or timing guarantee.

## Explicit unresolved gates

The evidence record deliberately retains `productionExportExecuted: false` and
`productionScaleQualified: false` for every case. The following states remain
unresolved:

| Gate | State | Reason |
| --- | --- | --- |
| Real bundled Ghidra export at supported scale | `unavailable` | The probe uses an injected no-op exporter returning an empty model. |
| Metadata and recovered-model complexity | `unqualified` | The fixtures have no section/symbol/name visits and no recovered functions, globals, or types. |
| Whole-parent production RSS | `unqualified` | RSS is the fresh probe's child-JVM observation; the Python parent, recovered model, and downstream reports are outside that measurement. |
| Shared in-flight deadline completion | `unresolved` | Dependency [#1066](https://github.com/minsago-elite/decomp_thing/issues/1066) remains open; cooperative checks do not preempt blocked native I/O or establish a hard aggregate cleanup bound. |
| Real Ghidra/compiler/ACP and hosted production qualification | `unavailable` | Those production integrations were not run by this authored local probe. |
| Repository neutrality gate | `failing` | The retained verification reports the known 80 findings; this slice does not reinterpret them as qualification. |

The observation therefore remains evidence for the bounded metadata/profile
contract, with the production and complexity claims unresolved. It preserves
the bundled Java-API Ghidra boundary, authenticated input/model identity and
profile provenance; no receipt, report, or local observation grants oracle
authority or converts an unresolved state into success.

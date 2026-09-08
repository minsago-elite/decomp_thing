# Bounded ELF metadata inspection

`GhidraJvmAnalyzer` uses `BoundedElfMetadataReader` after program export instead
of loading the complete input into a byte array. The reader retains one pinned
input, authenticates its bytes, reads the ELF header and first dynamic symbol
table through separate 64 KiB record/string windows, and verifies the input again
before returning. It preserves the existing Linux pinned-file admission rules;
there is no plain-path fallback when that admission fails.

The returned input digest must match `programModel.inputSha256` before the
analyzer publishes its summary. `ghidra_analysis.json` records that digest, input
size, effective metadata limits and usage counters. The analyzer's public
constructors, analysis method and `GhidraAnalysis` data-class descriptors remain
compatible, including the no-argument JVM constructor.

The wrapper starts its elapsed timer before export. Selected profile budgets can
lower its existing timeout and modeled metadata ceiling; metadata does not receive
a fresh elapsed allowance after export. Worker execution retains its own configured
limits. An injected analyzer is checked after it returns; the wrapper cannot
preempt an arbitrary injected function. The standalone reader also checks its
own elapsed time, including initial and terminal authentication.

## Limits and accounting

These are default host ceilings that explicit reader limits may lower:

| Resource | Ceiling |
| --- | ---: |
| Input file | 1 GiB |
| Section-header table count | 131,072 |
| Dynamic symbols scanned | 2,000,000 |
| Undefined symbols retained | 100,000 |
| Individual raw name, excluding NUL | 16 KiB |
| Cumulative name-byte visits | 64 MiB |
| Retained raw name bytes | 16 MiB |
| Modeled metadata | 64 MiB |
| Charged metadata reads | 256 MiB |
| Parse work units | 100,000,000 |
| Elapsed time | 600,000 ms |

The memory model reserves 8 MiB for fixed working buffers, then charges 256 bytes
per retained record plus four times its raw name length before decoding or list
insertion. A ceiling below the fixed reservation is rejected at budget binding.
The model includes defensive list copies; it is not a whole-JVM RSS guarantee and
does not account for the already recovered program model or downstream reports.

Section, symbol and name-byte visits consume parse work. Repeated name visits
count even when cached. Metadata reads conservatively charge logical requested
bytes plus cache refill bytes. Full authentication hashing is separate: it reads
at most two admitted file lengths through bounded buffers. The section-table
ceiling permits up to two additional charged header visits for extended-count
and linked-table lookup. Cancellation and elapsed checks run between bounded
operations; they do not interrupt a blocked native I/O call.

## Compatibility and verification

The reader preserves ELF32/ELF64 and either byte order, metadata labels and raw
header counts. A zero section-table offset retains empty-inventory behavior for
existing authored header fixtures. Ordinary symbol tables do not supply dynamic
imports. The first dynamic table supplies undefined, named symbols, retaining
kind, binding, size, duplicates and relative order within each kind. Name decoding
retains the existing UTF-8 replacement behavior. Returned lists are unmodifiable.
Both readers now use the unsigned ELF32 `st_size` field; the byte-array reader
previously reported entry size instead. Resource failure never returns a partial
successful inventory.

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.binary.BoundedElfMetadataReaderTest' \
  --tests 'decompengine.binary.ElfSymbolInventoryReaderTest' \
  --tests 'decompengine.analysis.GhidraJvmMetadataInspectionTest' \
  --tests 'decompengine.project.ProfiledReconstructionPipelineTest' \
  --tests 'decompengine.project.ReconstructionPipelineTest.Ghidra analysis delegates to the program model adapter and captures report' \
  --tests 'decompengine.project.ReconstructionPipelineTest.initial C project layout is stable' \
  --tests 'decompengine.project.ReconstructionPipelineTest.reconstruction pipeline generates buildable project' \
  --tests 'decompengine.project.ReconstructionPipelineTest.unresolved symbol report is emitted' \
  --tests 'decompengine.project.GhidraExportBudgetBindingTest' \
  --tests 'decompengine.analysis.GhidraJvmExportBudgetTest'
```

The 27 selected tests use ordinary authored files/models and local fixture builds.
They cover the four ELF class/order combinations, dynamic inventory fields,
small explicit resource budgets, cancellation, terminal elapsed checks, digest
binding and the shared wrapper timeout. A 1 MiB padded fixture demonstrates fixed
metadata windows while authentication still hashes the whole file. The 1 GiB
ceiling preserves admitted scale; these fixtures do not qualify production-sized
artifacts or whole-parent resource use.

The analyzer summary and downstream unresolved-symbol/generated-file reports now
use [bounded streaming and per-file atomic publication](bounded-report-publication.md).
Their independent limits do not establish complete phase resource bounds,
whole-parent RSS, production execution authority or release qualification; those
remaining criteria stay open in
[#84](https://github.com/minsago-elite/decomp_thing/issues/84).

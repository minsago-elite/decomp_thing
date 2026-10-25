# Diagnostic cc1 analyzer comparisons

The manual `GCC oracle model` operation `cc1-analysis-throughput` measures the
existing bundled Ghidra diagnostic analysis lane. It does not select a production
analyzer profile, produce a decompiled program model, or satisfy the full-export
30-minute/16-GiB qualification. Production remains the isolated bundled Java-API
worker; this diagnostic lane does not introduce an external Ghidra prerequisite.

Each variant now retains `function-census.json` beside `headless.log`. The census
contains every discovered function entry, sorted as unsigned 64-bit addresses,
the input SHA-256, image base, language/compiler selection, and the exact disabled
analyzers. Its entry digest is SHA-256 over canonical `0x...` addresses, each
followed by a newline. The capture refuses duplicate entries, more than one
million entries, more than 32 MiB of output, missing input identity, a cancelled
capture, or an existing output. Publication exposes only the complete file.

Analyzer selection validates the complete request before changing any option and
checks effective boolean values. `Decompiler Switch Analysis - One Time` is a
timing-table label, not a selectable option. The `no-switch` variants select only
the real `Decompiler Switch Analysis` option. The post-analysis census independently
checks each requested option; a script error cannot produce a successful census.

The dependent hosted comparison job downloads all five same-run censuses,
authenticates both cc1 ELF twins and their manifest dependencies, then reports the
complete added/removed entry lists for every variant. It also examines all defined
ELF `STT_FUNC` symbols and emitted DWARF subprogram starts in the authenticated rich
ELF, using the existing generic DWARF entry/range rules. The report preserves all
raw physical starts, their symbol/DWARF origins, and scan/omission counts with
explicit bounds. It annotates which added/removed entries occur in that raw
physical population. There are no name-based or policy exclusions.

These raw physical facts are **not a reviewed source-function oracle**. The report
always records `reviewedAccuracy.status: unavailable`, `releaseEligible: false`,
and `productionProfileSelected: false`. Compiler-generated physical starts remain
included. A full reviewed cc1 oracle, production structural admission, decompilation
quality, ownership, resource receipts and fresh/resumed equivalence remain required
before choosing a throughput profile.

## Offline replay

Retain each downloaded census in a separate directory and run:

```bash
mkdir -p build/analysis-comparison/tmp
TMPDIR="$PWD/build/analysis-comparison/tmp" python3 -B scripts/compare-gcc-analysis-variants.py \
  --baseline build/censuses/baseline/function-census.json \
  --variant no-switch=build/censuses/no-switch/function-census.json \
  --rich-artifact input/gcc-cc1.full \
  --stripped-artifact input/gcc-cc1.stripped \
  --output build/analysis-comparison/entry-comparison.json
```

Install the exact `requirements/oracle-generation.txt` dependencies for the raw
ELF/DWARF comparison. If both artifact arguments are omitted, only census deltas
and checked manifest metadata are compared; the result explicitly says
`inputVerification: manifest-metadata-only` and supplies no physical reference.
Every report retains the byte length and SHA-256 of the exact census/manifest
snapshots read. Crossed inputs, bases, language/compiler selections, option sets,
unsorted or duplicate addresses, mismatched counts/digests and out-of-executable
entries are refused. Replaying unchanged bytes is deterministic. Existing output
is never overwritten.

## Historical evidence limitation

Run [39873334124](https://github.com/minsago-elite/decomp_thing/actions/runs/39873334124)
retained only `headless.log`, not actual entry lists or Ghidra projects. The
baseline artifact `12468651145` has SHA-256
`e023680a837631569e24203d83f5bf162832e6f71b6b3b2e8aea736b36345d64`;
the no-switch artifact `12467812967` has SHA-256
`3ca31e3c2409478a1c39c021475f3cf9a5378fdc3366dca1cad92b7f341e4b23`.
Both downloaded ZIP digests match GitHub metadata. Their 50,856/50,879 counts and
differing entry hashes establish that the populations differ, but cannot identify
which entries changed or whether any added start is correct. The no-switch log
also explicitly reports that the `- One Time` option was not found, followed by
the old script's incorrect `disabled` line. Fresh censuses are required; the
missing historical entry lists cannot be reconstructed from those hashes.

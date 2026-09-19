# GCC oracle accuracy coverage

`oracle/gcc/16.2.0/accuracy-coverage.json` is the bounded evidence record for
issue #45. It is generated from the authenticated GCC 16.2.0 manifest and
function oracle by:

```bash
python3 scripts/report-gcc-accuracy-coverage.py \
  --output /tmp/gcc-accuracy-coverage.json
cmp /tmp/gcc-accuracy-coverage.json \
  oracle/gcc/16.2.0/accuracy-coverage.json
```

The checked oracle contains 12,844 function records: 3,284 scoreable starts,
140 reviewed compiler-generated exclusions, and 9,420 inline-only exclusions.
Its stripped-surviving symbol population is six aliases. The manifest, source
lock, build record, rich artifact, stripped artifact, function oracle, and
exclusion profile are retained with their byte lengths and SHA-256 values.

The record does not claim issue completion. No current recovered model or
production symbol-identity report is retained. The documented historical
function score is preserved as `historical-unattested` because its schema-v1
model/exporter provenance was not authenticated. Authenticated GCC call truth,
recovered call sites, and production structural replay are `unavailable`; the
current production replay registry is intentionally empty.

The next measurable boundary is `gcc-structural-replay-call-edge-v1`, owned by
#40/#681. It requires a bundled Ghidra JVM exporter/loader receipt bound to the
same stripped artifact and function mapping, plus oracle-derived internal,
external, indirect, unknown, and unobservable call facts. `GHIDRA_HOME` and an
external `analyzeHeadless` installation are not accepted as substitutes.

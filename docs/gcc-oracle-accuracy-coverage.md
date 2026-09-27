# GCC oracle accuracy coverage

`oracle/gcc/16.2.0/accuracy-coverage.json` is the bounded evidence record for
issue #45. It is generated from the authenticated GCC 16.2.0 manifest and
function oracle by:

```bash
mkdir -p build/gcc-accuracy-coverage
python3 scripts/report-gcc-accuracy-coverage.py \
  --output build/gcc-accuracy-coverage/accuracy-coverage.json
cmp build/gcc-accuracy-coverage/accuracy-coverage.json \
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

## Raw driver interface observations

`BoundedDwarfInterfaceFactScanner` reads source interface facts from the rich
ELF through the bounded DWARF reader. It retains declaration and origin
locators, parameter order, variadic observations, and the reachable raw type
graph. Missing, unsupported, and ambiguous facts keep their evidence states;
the scanner does not synthesize prototypes or infer ABI classes.

`GccDriverDwarfInterfaceEvidence` binds these observations to the checked
driver pair, manifest, function oracle, exclusions, source and build records,
toolchain reproduction lock, and target descriptor. Candidate declarations
join the reviewed physical function population by exact executable RVA.
Names do not establish identity. Every reviewed oracle record remains in the
denominator, including the compiler-generated and inline-only exclusions.

The **GCC oracle model** workflow has a separate **Retained GCC driver DWARF
interfaces** job. It runs on manual dispatch or on ordinary PR events when
the PR has the `qualify:driver-dwarf-interfaces` label. Adding the label alone
does not start a run; a subsequent commit or manual dispatch does. This job
uses the checked driver artifacts without rebuilding GCC. Manual dispatch
runs only this job. It retains evidence and test reports in the
`gcc-driver-dwarf-interfaces` Actions artifact.

For an equivalent local qualification with the pinned frontend toolchain
available:

```bash
DECOMP_REQUIRE_GCC_DWARF_INTERFACES=true ./gradlew --no-daemon test \
  --tests 'decompengine.oracle.fulltree.BoundedDwarfInterface*Test' \
  --tests 'decompengine.oracle.gcc.GccDriverDwarfInterfaceEvidenceTest'
```

Generated files stay under `build/gcc-driver-dwarf-interfaces/` by default.
This is a raw observation and denominator capture. Normalized ABI signature
coverage remains zero, and `complete`, `scored`, `productionVerified`, and
`releaseEligible` remain false. Global facts, target-specific ABI
classification, recovered-model identity joins, and production scoring still
require their own authenticated evidence. A successful raw capture alone
does not complete #692 or #680.

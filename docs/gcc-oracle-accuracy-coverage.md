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

## Driver interface observations and ABI coverage

`BoundedDwarfInterfaceFactScanner` reads source interface facts from the rich
ELF through the bounded DWARF reader. It retains declaration and origin
locators, parameter order, variadic observations, the reachable raw type
graph, and variable candidates with their scope and storage observations.
Raw location expressions remain distinct from interpreted addresses or TLS
offsets. Missing, unsupported, and ambiguous facts keep their evidence states.

`GccDriverDwarfInterfaceEvidence` binds these observations to the checked
driver pair, manifest, function oracle, exclusions, source and build records,
toolchain reproduction lock, and target descriptor. Candidate declarations
join the reviewed physical function population by exact executable RVA.
Names do not establish identity. All 12,844 reviewed oracle records remain
in the evidence population: 3,284 scored physical functions and 9,560
explicitly excluded compiler-generated or inline-only records.

The separate SysV AMD64 projection derives source ABI facts only when the
raw observations and its versioned target rules provide enough evidence.
It records the rule profile and its hash alongside the typed projection.
Unknown aggregate layout, alignment, or C++ passing behavior remains
unresolved. The rules follow the
[x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/raw/master/x86-64-ABI/low-level-sys-info.tex)
and [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf).

Global candidates join retained ELF object observations using proved storage
addresses or TLS offsets, sizes, and storage domains. Symbol names alone do
not establish a match. Unmatched symbols, local variables, and unresolved
candidates remain visible in the coverage record.

Evidence is a bounded bundle: `evidence.json` binds ordered canonical shards
by path, kind, record count, byte length, and SHA-256. Raw functions, types,
globals, and derived records are partitioned without dropping denominator
entries. Each shard and the complete bundle have explicit resource limits;
the general JSON parser limits remain unchanged. Qualification compares the
whole bundle across repeated captures and checks tampered or missing parts.
Raw `types` shards contain headers with ordered `childLocators`; separate
`typeChildren` records bind each full child to its parent type. Joining those
records in the declared order recovers the original type facts, including
unsupported children and their evidence, without requiring one large type
to fit in a single shard. The shard metadata declares attribute fallbacks
for promoted name, size, encoding, and type facts: a promoted field is
omitted only when its full value and evidence equal that attribute. An
explicit promoted field takes precedence, preserving differing or missing
attributes without loss.

The driver profile separately bounds the retained fact model at 1 GiB using
fixed record/container allowances and UTF-16 string payload sizes. This is
a deterministic resource model, not an RSS measurement. Encoded publication
still has independent limits of 512 MiB, 16 million JSON nodes, and 256
shards; each shard is limited to 8 MiB and 100,000 nodes. The driver profile
allows type graph depth 128 within the scanner's existing hard ceiling;
the generic default remains 64. The traversal-work bound remains enforced.

The **GCC oracle model** workflow has a separate **Retained GCC driver DWARF
interfaces** job. It runs on manual dispatch or on ordinary PR events when
the PR has the `qualify:driver-dwarf-interfaces` label. Adding the label alone
does not start a run; a subsequent commit or manual dispatch does. This job
uses the checked driver artifacts without rebuilding GCC. Manual dispatch
runs only this job. It retains evidence and test reports in the
`gcc-driver-dwarf-interfaces` Actions artifact. The opt-in qualification always
executes instead of reusing cached test results and gives the test JVM an
8 GiB heap for repeated captures. That heap limit is not an aggregate RSS
qualification.

For an equivalent local qualification with the pinned frontend toolchain
available:

```bash
DECOMP_REQUIRE_GCC_DWARF_INTERFACES=true ./gradlew --no-daemon test \
  --tests 'decompengine.oracle.fulltree.BoundedDwarf*Test' \
  --tests 'decompengine.oracle.fulltree.FullTreeElfObjectLayoutTest' \
  --tests 'decompengine.oracle.structural.DwarfSysvAmd64*Test' \
  --tests 'decompengine.oracle.gcc.GccDriverDwarf*Test'
```

Generated files stay under `build/gcc-driver-dwarf-interfaces/` by default.
The resulting coverage measures observable oracle facts. Recovered-model
accuracy still requires authenticated candidate types, identity joins, and
production scoring. `complete`, `scored`, `productionVerified`, and
`releaseEligible` remain false. Qualification success alone does not establish
90% function or global recovery and does not complete #692 or #680.

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
locators, parameter order, variadic observations, the raw type graph within
its declared traversal scope, and variable candidates with their scope and
storage observations.
Raw location expressions remain distinct from interpreted addresses or TLS
offsets. Missing, unsupported, and ambiguous facts keep their evidence states.

`GccDriverDwarfInterfaceEvidence` binds these observations to the checked
driver pair, manifest, function oracle, exclusions, source and build records,
toolchain reproduction lock, and target descriptor. Candidate declarations
join the reviewed physical function population by exact executable RVA.
Names do not establish identity. All 12,844 reviewed oracle records remain
in the evidence population: 3,284 scored physical functions and 9,560
explicitly excluded compiler-generated or inline-only records.

The driver selects the scanner's `abi-layout` type graph scope. It expands
function return and parameter types, global types, and the references needed
for by-value layouts, including aliases, array elements, members, and bases.
Pointer and reference pointees and non-layout child references retain their
validated target IDs, evidence, and explicit reasons for deferred expansion.
All raw child records remain present. A deferred target expands if it is
also an independently required by-value root. Depth checks follow only the
edges selected for expansion. Pointer representation may be known while
pointee layout remains unresolved; missing required by-value layout remains
unresolved. The scanner's default scope remains `full-references`.

The separate SysV AMD64 projection derives source ABI facts only when the
raw observations and its versioned target rules provide enough evidence.
It records the rule profile and its hash alongside the typed projection.
Unknown aggregate layout, alignment, or C++ passing behavior remains
unresolved. The rules follow the
[x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/raw/master/x86-64-ABI/low-level-sys-info.tex)
and [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf).

The projector identity is `dwarf-sysv-amd64-lp64-projection-v3`. This semantic
correction rejects a complete aggregate when its byte size is not divisible by
its explicit alignment, preserving the raw observation as unresolved ABI
evidence. The rule profile records this in `aggregateRules` and is bound by
SHA-256 `021b9e246e8c0cd250dbd660e03b0baba41338ba4c23e0fe4831fc11570c35df`.
The evidence bundle schema and provider remain version 2 because their wire
shape is unchanged. The pinned GCC census rows were unchanged by this
correction; the projector version and rule-profile hash still identify the
updated semantics.

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
shards; each shard is limited to 8 MiB and 100,000 nodes. Type graph depth is
limited to the scanner's default 64. The traversal-work bound remains enforced.

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

## Merged census evidence and post-merge boundary

PR [#1456](https://github.com/minsago-elite/decomp_thing/pull/1456) was
independently reviewed at candidate head
`5818d52c5a554eb21b95bdb2d2b77030aa68e0f3`, based on
`e9b1d817e3a3b129cac390827f26f1dd1820deff`. The qualification artifact's
`source-revision.txt` identifies its producer as synthetic merge
`99c9041da130b99fd961e0aa0e33c8ce2725c362` (base first, candidate head
second). The PR was squash-merged as `378a2266ac4a793e5a8c23f740e95741c7326c54`.
That merge SHA is a different revision from both the reviewed candidate and
the synthetic artifact producer.

All five required workflows passed for the reviewed PR candidate:

| Workflow | Run |
| --- | ---: |
| [Full CI](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200371) | 37140200371 |
| [Built-in core](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200374) | 37140200374 |
| [ACP contract](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200395) | 37140200395 |
| [LLVM oracle](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200361) | 37140200361 |
| [GCC oracle](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200393) | 37140200393 |

The retained GCC qualification artifact is
[11280580825](https://github.com/minsago-elite/decomp_thing/actions/runs/37140200393).
Its archive SHA-256 is
`8d9811c2777f22013e59c7384511ffdc00496783a649fd08b6c6bc3b7ceffdf7`; the
contained evidence SHA-256 is
`738b2f3f77626762659788bfb9c9a81f35970bf9acb7f77a41aba20eccdfac08`. It
records provider `gcc-driver-dwarf-interface-evidence-v2` and wire schema 2,
scanner v2, and projector
`dwarf-sysv-amd64-lp64-projection-v3` with rule-profile SHA-256
`021b9e246e8c0cd250dbd660e03b0baba41338ba4c23e0fe4831fc11570c35df`.
The pinned GCC source revision is
`78d4ac73dd391005b895a6148cd9831e28e1208b`.

The audited bundle contained 90 parts, 307,013,611 bytes, and 8,145,070 JSON
nodes. Its 8,884 type headers and 40,765 ordered child rows joined exactly.
The retained record counts were: 2,846 functions; 8,884 types; 40,765
`typeChildren`; 24,231 globals; 703 object symbols; 7 stripped objects;
7,231 projected types; 2,846 projected functions; 24,231 projected global
types; 12,844 oracle functions; 2 unmatched functions; and 25,628 derived
global-projection records.

These are source-observation and projection counts, not recovered-accuracy
scores. The reviewed function population is 12,844 oracle rows: 3,284 physical
functions plus 9,560 explicit exclusions. Of the 3,284 physical functions,
2,245 had observable source facts and 1,039 remained unresolved. The 24,231
`globals` rows are raw global observations; there is no reviewed global oracle
denominator in this artifact, and neither these rows nor the derived
`globalProjection` rows establish global recovery accuracy. The evidence does
not set `complete`, `scored`, `productionVerified`, or `releaseEligible` to
true.

No Actions workflow ran on merge SHA
`378a2266ac4a793e5a8c23f740e95741c7326c54`. Its squash commit message
inherited a `[skip ci]` directive, so the push event was skipped. The five
workflow runs above and the GCC qualification artifact are pre-merge evidence;
they are not post-merge checks. Post-merge verification remains pending until a
normal, non-skipping default-branch push has completed on its exact resulting
SHA. Record that SHA and its push run IDs here only after those runs complete;
do not attribute them to `378a2266ac4a793e5a8c23f740e95741c7326c54`.

Issue [#1463](https://github.com/minsago-elite/decomp_thing/issues/1463) tracks
that post-merge boundary. This reference is documentation only; a native
parent/sub-issue relationship has not been established. The evidence above
does not close #692 or #876 and grants no production or release authority.

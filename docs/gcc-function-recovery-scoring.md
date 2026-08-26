# Function-boundary and name scoring

Issue #39 adds a deterministic scoring boundary between a schema-v1 program
model and a reviewed DWARF/symbol oracle. The matching, normalization, metrics,
and report implementation live in `oracle/function_recovery.py`; its contracts
are the generic `oracle/function-recovery-oracle.schema.json` and
`oracle/function-recovery-score.schema.json`. The compatibility command lives
under the GCC oracle tooling because GCC is the current C-program benchmark,
not because the core assigns GCC-specific meaning to functions or names.
`oracle/gcc/score_function_recovery.py` is only the GCC artifact-manifest/ELF
adapter and compatibility import surface.

A reviewed production oracle is checked in at
`oracle/gcc/16.2.0/function-recovery-oracle.json`. Its generic exporter is
`oracle/function_recovery_oracle.py`; the GCC adapter contributes only manifest
authentication, artifact paths, and the exact-RVA review data in
`function-recovery-exclusions.json`. The inputs under
`tests/oracle/fixtures/function_recovery/` remain contract fixtures, not
production measurements. The unchecked in-memory API is fixture-only.

## Deterministic oracle generation

Install the exact generation-only dependencies from
`requirements/oracle-generation.txt`, then regenerate to a disposable path:

```bash
python3 -m pip install -r requirements/oracle-generation.txt
python3 scripts/generate-gcc-function-recovery-oracle.py \
  --manifest oracle/gcc/16.2.0/oracle-manifest.json \
  --exclusions oracle/gcc/16.2.0/function-recovery-exclusions.json \
  --output /tmp/function-recovery-oracle.json
cmp oracle/gcc/16.2.0/function-recovery-oracle.json \
  /tmp/function-recovery-oracle.json
```

The adapter verifies one bounded manifest snapshot against coherent private,
bounded snapshots of every source/build/evidence/artifact dependency. The
generator hashes and inspects those same staged twin snapshots; it does not
reopen the manifest artifact paths after verification. Before publication it
validates the result against a stable bounded snapshot of the closed JSON Schema
and the scorer's semantic loader. The checked file is 12,558,460 bytes
with SHA-256
`b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae`.
It contains 3,284 scoreable physical starts, 140 reviewed compiler-generated
RVA exclusions, and 9,420 explicit null-RVA inline-only exclusions.

The reviewed GCC profile classifies 80 cold partitions, 42 transactional
clones, 7 distinct optimization clones or partitions, 10 static-initialization
wrappers, and one lambda conversion wrapper. These classifications are data,
not generic name rules. In
particular, co-located local aliases remain aliases of a scoreable physical
function. Another C program can provide a different manifest and reviewed RVA
profile without changing extraction or scoring semantics.

Generation bounds each logical `.debug_ranges`/`.debug_rnglists` section to 16
MiB and each decoded list to 250,000 entries, in addition to the artifact,
symbol, DIE, function, alias, evidence, name, and locator limits enforced by the
generic normalizer. Pyelftools 0.33 materializes a selected range list eagerly;
the generator therefore checks the declared logical section size before DWARF
loading, checks the resulting list length, and converts allocation failure into
a concise generation error. This is an explicit availability bound, not a claim
that the dependency exposes a lazy range-list iterator.

## One-command report

Run the fixture proof from the repository root:

```bash
python3 scripts/score-gcc-function-recovery.py \
  --oracle tests/oracle/fixtures/function_recovery/oracle.json \
  --rich-model tests/oracle/fixtures/function_recovery/rich-model.json \
  --rich-model-image-base 0x400000 \
  --stripped-model tests/oracle/fixtures/function_recovery/stripped-model.json \
  --stripped-model-image-base 0x500000 \
  --json-output /tmp/function-score.json
```

The command prints a seven-line human summary and atomically writes stable-key
JSON conforming to `oracle/function-recovery-score.schema.json`. The JSON contains
per-entity exact matches, bounded near misses and signed deltas, false
positives, false negatives, ignored exclusions, name results, matching
ambiguity evidence, address-base evidence, and every ratio denominator for both
twins. It contains no timestamp or host path, so unchanged inputs produce
byte-identical output.

For a production run, supply the rich/stripped
`analysis/reports/program_model.json` files and run:

```bash
python3 scripts/score-gcc-function-recovery.py \
  --oracle oracle/gcc/16.2.0/function-recovery-oracle.json \
  --artifact-manifest oracle/gcc/16.2.0/oracle-manifest.json \
  --rich-model /path/to/rich/program_model.json \
  --rich-model-image-base 0x400000 \
  --stripped-model /path/to/stripped/program_model.json \
  --stripped-model-image-base 0x400000 \
  --json-output /tmp/function-recovery-score.json
```

The adapter hashes one bounded manifest snapshot and verifies those exact bytes
against private, stable, size-bounded snapshots of the source lock, build
record, signing evidence, and artifacts. It then binds the
function oracle's identity, artifact hashes, ELF type, ELF image base, and
executable `PT_LOAD/PF_X` ranges to the manifest before reading either model.

Schema-v1 program models do not record a controlled exporter identity, loader
identity, or authenticated image-base provenance. A production-scope run
therefore fails closed unless each explicit model base equals the corresponding
manifest-derived ELF image base, and every normalized model start must land in
an executable range. Even after those checks, the report deliberately says
`artifact-verified-model-unattested` and `productionVerified: false`; it is not
an authenticated production measurement. Fixture scope may use a different
explicit base to test relocation. A future program-model schema with controlled
exporter and loader metadata can support a stronger status.

The production measurement used rich and stripped model bytes with SHA-256
`6c5205da2e61528745b70f867bc3d5f0db296ee52fa8ea322927347b4082683a`
and `1d277f2fa111e307e41283fe6b5e0efe158787d29b2605ebaafb7bf025798f5d`.
It produced an 18,957,069-byte report with SHA-256
`5acc1f525e203c51689946b30f8073373d2707e62cb6ee4e394173ae28369a71`:

- rich boundaries: precision 3283/3288, recall 3283/3284, F1 6566/6572,
  3,283 exact, 0 near, 5 false positives, and 1 false negative;
- stripped boundaries: precision 3268/3272, recall 3268/3284, F1 6536/6556,
  3,268 exact, 0 near, 4 false positives, and 16 false negatives;
- rich exact-name recovery: 2665/3284; stripped exact-name recovery: 6/3284.

The deterministic allocation-free entity-detail preflight estimate was
27,510,966 bytes; its fixed per-record charges are intentionally a heuristic,
while the canonical encoder independently enforces the exact 64 MiB output
ceiling. The result still reports `artifact-verified-model-unattested` and
`productionVerified: false` for the schema-v1 provenance reason above.

Reproducing that measurement needs these exact inputs:

- a reviewed function oracle conforming to
  `oracle/function-recovery-oracle.schema.json`, with `scope: production`, the
  SHA-256 of the exact artifact manifest, and rich/stripped artifact metadata
  copied from that manifest;
- the rich and stripped `analysis/reports/program_model.json` exports from the
  corresponding artifacts;
- the two explicit program-model image bases. For production schema-v1 these
  must exactly equal the manifest-derived ELF image bases (the ET_EXEC GCC
  benchmark currently uses its ELF base for both);
- the exact artifact manifest passed through `--artifact-manifest`.

The command above enforces all four bindings before scoring.

## Oracle construction boundary

`oracle/function-recovery-oracle.schema.json` is a closed, versioned normalization
format. A production exporter/reviewer must reconcile these facts from the
DWARF-rich binary before scoring:

- each emitted `DW_TAG_subprogram` contributes one start. An address-class
  `DW_AT_entry_pc` is absolute; a constant-class value is added to the function
  base (`DW_AT_low_pc`, otherwise the first non-empty range). Missing or
  unsupported entry forms fail closed. Without an entry PC, the start is
  `DW_AT_low_pc`, otherwise the first non-empty range in producer order. A
  discontiguous range list does not invent extra functions;
- defined ELF `STT_FUNC` symbols contribute their exact RVAs, and all facts at
  one RVA become one physical function record;
- aliases at one start stay in that record and do not inflate the boundary
  denominator;
- every alias has its own DWARF/symbol evidence and per-twin availability, so
  one RVA can have both a surviving dynamic alias and a removed static alias;
- each availability is `surviving`, `removed`, or `not-observable`, based on
  metadata present in that artifact;
- inline-only DIEs are explicit `inlined` exclusions with a null RVA;
- emitted clones, cold partitions, thunks, and other generated entities are
  excluded only through reviewed `compiler-generated` records.

The scorer never infers exclusions from names. A recovery exactly at an
explicit compiler-generated RVA is reported as ignored; a merely nearby start
is scored normally. Scoreable and excluded records cannot share an RVA.

Every scoreable alias must be `surviving` in the rich twin and either
`surviving` or `removed` in the stripped twin. `not-observable` is reserved for
excluded records. This prevents availability edits from shrinking a name
denominator while leaving the boundary denominator unchanged.

Oracle starts are RVAs relative to the manifest-derived ELF image base. Model
normalization is exactly:

```text
recovered RVA = program-model address - explicit program-model image base
```

There is no page masking, nearest-base search, or automatic relocation repair.
Addresses and bases are canonical lowercase hexadecimal without leading
zeroes. Underflow, duplicate normalized starts, or a start outside an
executable artifact range is an error.

## Metric definitions

Exact addresses are fixed first. On the remaining address-ordered sets, the
scorer chooses a one-to-one, order-preserving assignment whose deltas are no
greater than `nearMissBytes`. It first maximizes match cardinality, then
minimizes total absolute byte distance, then chooses the lexicographically
lowest `(oracle RVA, recovered RVA)` sequence. Recovered names never participate
in boundary assignment. The report records the objective and every unselected
edge that can participate in another equally optimal ordered assignment, so a
stable tie is not mistaken for certainty.

Fixing exact matches first is intentional even where discarding an exact edge
could create more near pairs. Bounded true positives are exact matches plus the
selected near misses:

```text
precision = bounded true positives / scored recovered starts
recall    = bounded true positives / scoreable oracle starts
F1        = 2 TP / (2 TP + FP + FN)
```

Exact-address and near-miss rates use the scoreable oracle-start count. Every
ratio retains its integer numerator and denominator plus a six-decimal value;
an empty denominator is JSON `null`, never a fabricated success.

Names use exact UTF-8 comparison against the aliases on the selected boundary
match. Overall scoring accepts any observable alias. `surviving` and `removed`
subtotals use the matched alias's individual availability; a physical function
with aliases in both categories belongs to both category denominators. Missing
boundaries remain `missingBoundary` in every applicable name denominator.

## Resource and verification boundaries

Inputs must be bounded regular-file snapshots. The loader rejects symlinks,
duplicate JSON keys, non-finite or over-magnitude JSON numbers, oversized JSON,
manifest, supporting, and artifact files, excessive function/alias/evidence/model
entity counts, excessive matching matrices or ambiguity evidence, and reports
over the output byte limit. Snapshot and report construction avoid unbounded
intermediate copies, translate memory exhaustion to a concise scoring failure,
and publish the principal operative limits in the report.

Near matching uses dynamic programming with at most `maxMatchingCells` cells
(currently 20,000,000). The suffix objective uses compact 16-bit cardinality
and 32-bit distance arrays, about six bytes per cell (roughly 120 MB at the
published ceiling), plus four linear-width rows and bounded Python match and
ambiguity bookkeeping. Inputs that would cross the cell bound fail before the
matrix is allocated.

Run the mutation-focused suite with:

```bash
python3 -m unittest tests.oracle.test_gcc_function_recovery -v
```

It exercises per-alias availability, exact-first matching, nearest and
overlapping candidates, stable ties and ambiguity, exclusions, denominators,
address bases and ranges, schema mutations, resource limits, deterministic
bytes, and positive/negative production-manifest integration including a
manifest pathname replacement after snapshot. The broader adapter suite also
exercises DWARF form handling plus source/schema/artifact mutation during
generation:

```bash
python3 -m unittest discover -s tests/oracle -v
```

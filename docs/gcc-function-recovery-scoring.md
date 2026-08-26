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

No reviewed production function-oracle/program-model pair is checked in yet.
The inputs under `tests/oracle/fixtures/function_recovery/` use
`scope: fixture`; their metrics prove the scorer contract only and are not a
measurement of GCC, a compiler, or a decompiler. The unchecked in-memory API is
fixture-only. A production-scope file run is rejected unless it is bound to a
verified artifact manifest, and schema-v1 still cannot authenticate the
program-model export itself.

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

For a production run, supply the reviewed production oracle and rich/stripped
`analysis/reports/program_model.json` files, the two explicit model bases, and:

```text
--artifact-manifest oracle/gcc/16.2.0/oracle-manifest.json
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

The current production handoff therefore needs these exact inputs:

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

With those files, use the same command above, replace the fixture paths, add
`--artifact-manifest`, and set the two model-base arguments. There is no
checked-in production function-oracle exporter in this checkpoint: DWARF and
symbol reconciliation remains a reviewed data-generation step rather than a
claim made by the scorer.

## Oracle construction boundary

`oracle/function-recovery-oracle.schema.json` is a closed, versioned normalization
format. A production exporter/reviewer must reconcile these facts from the
DWARF-rich binary before scoring:

- emitted `DW_TAG_subprogram` entries and ELF `STT_FUNC` symbols become one
  physical function record per RVA;
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
manifest pathname replacement after snapshot. The broader adapter suite is:

```bash
python3 -m unittest discover -s tests/oracle -v
```

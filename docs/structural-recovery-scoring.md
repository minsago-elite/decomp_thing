# Structural recovery scoring

The structural scorer compares normalized interfaces, calls, globals, and type
facts without parsing a program-specific naming convention. Its reusable
contracts are:

- `oracle/target-abi.schema.json`, an explicit target and ABI vocabulary;
- `oracle/structural-oracle.schema.json`, the normalized truth facts;
- `oracle/recovered-structure.schema.json`, recovered claims plus complete
  exporter, loader, target, normalization-profile, image-base, input-binary,
  boundary-score, and identity-map provenance;
- `oracle/structural-identity-map.schema.json`, independently reviewed mappings
  for identities outside the function-boundary contract; and
- `oracle/structural-score.schema.json`, the deterministic report.

The implementation is `oracle/structural_recovery.py`. The fixture command is
`scripts/score-structural-recovery.py`. A benchmark adapter may authenticate
production inputs, but it must not change normalization, outcome, or metric
semantics.

## Stable identities, not name matching

Function entities are joined only through the exact and near selections already
recorded by the function-boundary score report. The scorer does not run another
address assignment and never compares a recovered name to choose an entity.
Internal-call endpoints are recovered function IDs and are translated through
that same selected mapping. The boundary adapter also imports the complete
scored universes: false negatives remain valid oracle identities, false
positives remain valid recovered identities, and reviewed exclusions stay
outside scoring. A structural function or endpoint absent from those universes,
an ignored excluded recovery, or a selected mapping whose oracle identity is
also in the exclusion set is rejected. The structural oracle must contain
exactly the scored oracle universe (exact, near, and false-negative functions),
and the recovered model must contain exactly the scored recovered universe
(exact, near, and false-positive functions). Omitting a difficult function is a
contract failure, not denominator reduction. The adapter verifies that near
assignment is name-independent and that its partitions, counts, and distance
objective agree before exposing the generic mapping projection.

Call facts use this stable slot:

```text
call:<caller-local site RVA>:<internal|external|indirect>
```

The containing function supplies the caller identity. The site RVA and endpoint
kind identify the fact independently of its claimed endpoint. Global-reference
facts similarly use `global-ref:<site RVA>`.

Global and type entities have separate oracle and recovered IDs. They are joined
only by an identity-map artifact with an explicit oracle locator, recovered
locator, and verifier description for every pair. The generic scorer does not
fall back to equal names or layouts. Production use must authenticate and replay
the mapping verifier; an unverified pair stays unbound. An unbound recovered
entity claim is fabricated, while the unmatched oracle fact remains
recovered-unknown. A well-formed but unmapped call, global, or type reference is
contradicted and cannot receive ABI-equivalent credit. Mapping failure is an
internal tagged state, never a string in the user-controlled value namespace.

Recovered facts never contain an oracle fact ID. Within a separately mapped
entity, facts align by a dimension-specific stable slot: fixed interface and
global fields, parameter index, aggregate member index and property, or enum
enumerator slot. Oracle fact IDs and recovered fact IDs remain separate in every
report row.

## Closed source normalization

Source projections are meaningful only under the explicitly bound
`normalizationProfile` object: profile ID, version, and configuration SHA-256
must match exactly between the oracle and recovered-model provenance, and that
binding is repeated in the report. Producer/exporter identities are not a
substitute for this shared contract. Scorer v1 accepts exactly
`structural-source-normalization` version `1` with configuration digest
`4385f86a45a39e55a8f9f072e5563720f4775edbb53d8d4c290f9f232982ae80`.
That is the SHA-256 of the stable-key, compact ASCII JSON encoding of the
checked `NORMALIZATION_PROFILE_CONFIGURATION` document in
`oracle/structural_recovery.py`, not an opaque producer-chosen hash. All three
formal schemas constrain the same tuple. The profile uses language-neutral
tagged projections. Adapters cannot put source declarations, local display
names, or ad hoc prose in scored values:

- prototypes use `prototype:<canonical-shape-token>`;
- calling conventions use `convention:<descriptor-declared-ID-or-alias>`;
- parameter, return, global, member, enum-underlying, and typedef types use
  `type-token:<canonical-token>` or `type-entity:<stable-entity-id>`;
- internal calls, external calls, indirect calls, and global references use
  `function:<id>`, `external:<id>`, `signature:<id>`, and `global:<id>`;
- storage uses `static-rva:<hex>`, `tls-offset:<hex>`,
  `external-storage:<id>`, or `register:<id>`;
- linkage is one of `internal`, `external`, `weak`, `common`, `unique`, or
  `none`; and
- aggregate kind is one of `record`, `overlay`, `variant`, or `sequence`.

Identifiers and tokens are bounded ASCII. Language-specific parsing belongs in
an explicit, digest-bound normalization profile that emits these forms; a
different ID, version, or configuration digest is incompatible, even if its
tokens happen to have the same spelling. A profile cannot alter scorer equality
or outcome rules.

## Covered dimensions

The v1 dimension vocabulary is closed:

- function prototype, calling convention, variadic state, parameter ABI class,
  and return ABI class;
- internal, external, and indirect calls;
- global references, storage, linkage, and type;
- aggregate kind, size, alignment, member offset, and member type;
- enum underlying ABI class and enumerator value; and
- typedef target.

Each fact has a canonical source projection and an optional ABI projection. ABI
projections have a closed shape: calling convention, ordered ABI classes, size,
alignment, and variadic state. Convention IDs and class tokens must exist in the
selected descriptor. The checked `oracle/targets/sysv-amd64-v1.json` is one data
instance; the scorer has no branch for that descriptor ID, architecture, object
format, register set, or class vocabulary.
The descriptor address width bounds image bases, function RVAs, call/reference
slots, and address-bearing storage values. The current #39 loader is an ELF
report adapter isolated in a projection step; it rejects another descriptor
object format rather than leaking format-specific fields into generic scoring.
Its `function-recovery-score-elf` adapter ID, version, and object format are
visible in report provenance and its ID/version are bound by the recovered-model
attestation.

## Evidence lattice

Every oracle fact is either `observable` with a value or
`oracle-unobservable` with no value. Every recovered fact is either `recovered`
with a value or `recovered-unknown` with no value. The comparison emits exactly
one of these outcomes for every oracle fact:

- `exact`: the source and ABI projections are identical;
- `abi-equivalent`: source projections differ, but an explicitly allowed,
  non-null ABI projection is identical;
- `recovered-unknown`: the mapped claim is absent or explicitly unknown;
- `oracle-unobservable`: the truth source declares that the fact cannot be
  observed, regardless of a recovered claim; or
- `contradicted`: a mapped concrete claim is neither exact nor ABI-equivalent.

An extra recovered fact emits `fabricated` without consuming an oracle fact.
This preserves a six-state evidence lattice without allowing missing evidence to
look correct.

Every concrete comparison row carries the recovered value, its normalized
oracle-identity projection, and a nullable reference-mapping verification bit.
The bit is null for values without an identity reference, true for a mapped
function/global/type reference, and false for an unmapped reference. The
semantic validator reconstructs the entity mapping from the unique report rows,
recomputes that projection and the outcome, and rejects changes to the outcome,
normalized value, or mapping bit even if all metrics were updated to match the
forgery. Rows without a concrete comparison carry null comparison bindings.

ABI equivalence is deliberately dimension-specific. It is available only for
calling conventions, parameter and return classes, global types, aggregate
member types, enum underlying classes, and typedef targets. Prototype spelling,
variadic state, all calls and references, storage, linkage, aggregate
kind/size/alignment/member offsets, and enumerator values are exact or
contradicted. Irrelevant ABI fields are rejected rather than ignored. Mechanical
projections must agree with their source values: a variadic boolean must match
the ABI boolean, a size or alignment must match its ABI value, and a calling
convention spelling must resolve through a descriptor-declared alias to its
canonical convention ID.

## Denominators

Each entity, each dimension (including dimensions absent from both inputs), and
the aggregate report all of the following:

```text
oracleDenominator    = every oracle fact, including unobservable facts
recoveredDenominator = every recovered fact record, including explicit unknown,
                       unobservable matches, contradictions, and fabrications
credit numerator     = exact + ABI-equivalent
credit denominator   = oracleDenominator
claim precision      = credit / recoveredDenominator
```

The outcome counts partition the oracle denominator after excluding only
`fabricated`, which has no oracle fact. `observableOracleCount` and
`unobservableOracleCount` are separate. Neither recovered-unknown nor
oracle-unobservable receives credit. A zero denominator has a JSON `null` ratio,
not a manufactured success. Emitting all closed v1 dimensions with zero/null
metrics prevents omission from hiding a weak or unsupported category.

## Provenance and production trust

The recovered model payload binds all of these fields:

- input binary SHA-256 and byte size;
- exporter ID, version, executable digest, and configuration digest;
- loader ID, version, executable digest, configuration digest, and image base;
- target descriptor ID and digest;
- normalization-profile ID, version, and configuration digest;
- selected function-boundary report digest and twin; and
- identity-map payload digest (with independent replay verification required in
  production).

The loader cross-checks those fields against the structural oracle, the actual
descriptor bytes, the actual boundary-report bytes and selected artifact, and
the actual identity-map bytes. Repeating only the expected binary hash is not a
valid model.

There are two attestation envelope kinds. Both bind the canonical complete model
payload; an adapter-replay envelope additionally binds the digest of its
external replay-evidence receipt. `fixture-digest` is a deterministic
integrity check for tests. It is always reported as `fixture-digest-only` and
`productionVerified: false`; anyone can recompute it. `adapter-replay` is
reserved for a benchmark adapter that authenticates and replays a concrete,
digest-pinned exporter and loader invocation plus its independent mapping
verification. The generic fixture entry point refuses production-scoped input.
A production adapter must fail closed if the replay receipt or any bound tool,
configuration, target, base, binary, boundary report, mapping, or model byte
differs. A schema-valid self-assertion is never production evidence.

Root scope and envelope kind are discriminated in both input schemas: fixtures
must use `fixture-digest`, and production inputs must use `adapter-replay` with a
non-null replay-evidence digest. Reports use literal verification names.
`payloadDigestVerified` and `identityMapPayloadDigestVerified` describe only
digest checks; fixture reports say `fixture-payload-digest-only` and keep
`adapterReplayVerified` and `productionVerified` false. Only a production
adapter may emit the `adapter-replay-verified` variant with those booleans true.
The score schema can represent that production variant, but schema validity and
self-asserted booleans do not authenticate it. The checked semantic validator is
fixture-only and explicitly refuses production-scoped reports. A future
production entry point must separately verify a trusted replay receipt tied to
the evidence digests, adapters, tools, configurations, checked normalization
profile bytes, and payload before it may validate or publish a production
report.

No checked production report should be published until its recovered model and
adapter replay receipt exist. An oracle derived from a rich binary is not a
substitute for independently recovered evidence.

## Determinism and resource limits

Each input is a bounded regular-file snapshot, and scoring additionally enforces
an aggregate byte budget across the descriptor, oracle, boundary report,
identity map, and recovered model. Symlinks, duplicate JSON keys,
non-finite numbers, floating-point input facts, over-magnitude or overlong
numeric tokens,
unsupported dimensions, duplicate entity/fact/slot identities, excessive text,
and excessive per-document or scorer-wide entity, fact, mapping, or evidence
counts fail closed. Every
schema object is closed, and semantic validation additionally enforces the
dimension-to-entity, slot, source type, and ABI projection rules.

The scorer sorts entities, facts, and dimension metrics, emits no timestamp or
host path, uses stable-key JSON, and enforces an exact encoded output-byte
ceiling. Before constructing result rows it also caps their maximum cardinality
and applies a conservative estimate to the duplicated identifiers, values, and
evidence those rows can contain. Unchanged byte inputs regenerate the same
report bytes.

The score schema requires all twenty dimensions. Before encoding or writing a
fixture report, the reference semantic validator recomputes every entity,
dimension, and aggregate metric; checks outcome/identity/value nullability;
checks every closed nested header, the literal policy and limit values,
duplicated provenance and normalization-profile bindings; and enforces fixture
verification consistency. It requires the digest-bound target descriptor as a
separate argument, then applies the same entity/dimension, slot, normalized
source, ABI projection, calling-convention, class-vocabulary, address-width,
and ELF projection-adapter checks used for inputs. It never promotes a
schema-valid production self-assertion. It also enforces unique entity and fact
identities, unique fact slots, canonical entity/fact ordering, header counts,
and aggregate report fact/evidence caps before metric recomputation. A
standalone fixture report remains an integrity artifact rather than
authenticated proof of source completeness; the input-backed scoring path
supplies that proof through the exact universes and digest bindings.

These application limits bound accepted work and report growth; they are not a
hard process-memory proof. JSON decoding retains Python object overhead, and the
complete accepted report is constructed before the final exact encoded-size
check. A production adapter must therefore also apply an OS-enforced memory and
wall-time limit around verification and scoring.

Given an existing function-boundary report, run the checked neutral fixture as:

```bash
python3 scripts/score-structural-recovery.py \
  --target-abi oracle/targets/sysv-amd64-v1.json \
  --oracle tests/oracle/fixtures/structural_recovery/oracle.json \
  --boundary-score /path/to/function-boundary-score.json \
  --boundary-twin rich \
  --identity-map tests/oracle/fixtures/structural_recovery/identity-map.json \
  --recovered-model tests/oracle/fixtures/structural_recovery/recovered.json \
  --json-output /tmp/structural-score.json
```

The fixture is bound to the byte-identical boundary report generated by the
function-recovery fixtures. The test suite constructs that report through the
generic function scorer, verifies its digest, runs the command twice, validates
all five schemas, and compares output bytes:

```bash
python3 -m unittest tests.oracle.test_structural_recovery -v
```

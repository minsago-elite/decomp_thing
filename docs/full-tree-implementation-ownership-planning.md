# Historical full-tree implementation-ownership planning

`FullTreeImplementationOwnership.assessHistoricalA13V2` is a bounded Kotlin/JVM
planning projection for issue #113. It joins the authenticated full-tree planning
inventory to the published historical A13-v2 function truth and function baseline.
The result assigns each emitted source-owned function to the exact compilation-unit
module already authenticated by `FullTreePlanningInventoryControl`.

This checkpoint is deliberately **non-authoritative**. The output records
`status: non-authoritative`, `releaseEligible: false`, and
`historicalFunctionTruthFormat: inline-only-v1`. It cannot generate or authenticate
new function truth, authorize A14 reconstruction, or certify a release. In
particular, the locked historical format is the contract from `62d3f75`: function
records do not contain `emissionKind`, and inline-only records contain
`observationIds` rather than the later `observationDieOffsets`. Inputs using the
live `nonEmitted` / coalesced format from #119 and #123 fail closed instead of being
silently interpreted as historical evidence.

## What is checked

The Kotlin implementation reauthenticates the planning inventory from its raw
scope, source lock, artifact manifest, build record, inventory, and source-inventory
paths. It then streams the canonical historical index, every truth shard, the
ownerless exclusions, and the baseline. No Python module or process participates.

The general assessment API does not rederive those historical truth and baseline
bytes from their ELF and observation inputs. Their configuration, index, file, and
report digests prove internal consistency, not that an arbitrary caller-supplied pair
is the published historical pair. Exact identity of the frozen pair is asserted by
the opt-in parity test. This is another reason the assessment remains explicitly
non-authoritative.

The assessment verifies:

- canonical JSON bytes, exact per-file byte counts and SHA-256 bindings, index and
  baseline report hashes, and fixed historical configuration identities;
- exact shard coverage and compilation-unit membership from the authenticated
  planning inventory;
- strict function/RVA and inline identity ordering, global uniqueness, owner and
  ownership-candidate membership, and rejection of source-only owners;
- owner-to-shard agreement, while retaining cross-shard ownership candidates only
  as historical evidence rather than duplicate definitions;
- stripped-ELF survival evidence for every scored function and exact agreement with
  every baseline missing record and per-shard metric;
- the scored, recovered, missing, owned-excluded, ownerless-excluded, and historical
  inline-only population equations; and
- distinct normalized paths and physical files, non-symlink inputs, trusted POSIX
  permissions, stable directory identities, and a terminal digest/registry reread.

Java NIO cannot bind an open descriptor back to a pathname. As with the existing
full-tree control plane, a file owner that can replace bytes and restore the same
identity, metadata, permissions, and digest during the assessment remains a
cooperating trust principal. The implementation does not claim same-UID exclusion.

## Output and limits

All 2,150 authenticated source modules are retained, including modules with zero
emitted implementations. Each module has exact recovered, missing, excluded, and
historical inline-only counts plus domain-separated SHA-256 commitments. Commitment
components use unsigned big-endian 32-bit UTF-8 length framing, so concatenation and
multiplicity are unambiguous. The 2,325 source-only paths and eight ownerless ELF
exclusions receive separate commitments and are never assigned to a catch-all
module.

The supplied historical function records carry the ownership assignments projected
here; they do not prove include or link dependencies. Therefore the output says
`not-inferred-from-historical-function-evidence` and emits no dependency edges. It
does not claim that the real graph is empty. Shared-header inference, dependency
derivation, cycle checks, build-graph emission, clean compilation, and archive
publication remain outstanding acceptance criteria for #113 and later A14 issues.

The immutable v1 maxima are:

- 1 MiB truth index and 64 MiB baseline;
- 512 MiB per truth shard and 3 GiB across the checked inputs;
- 10,000 truth shards, 3,000,000 emitted implementations, and 3,000,000 historical
  inline-only declarations;
- 1,000,000 source modules, 10,000,000 charged work units, and 64 MiB canonical
  output.

Callers may lower these ceilings. The parser streams top-level entity arrays and
materializes only one bounded entity at a time; the published historical truth is
about 2.15 GiB uncompressed and its largest shard is about 398 MiB. Index descriptor
totals and charged work units are bounded before any truth shard is traversed, then
reconciled against the streamed populations.

The long parity test is opt-in:

```sh
DECOMP_A14_HISTORICAL_FUNCTION_TRUTH_ROOT=/path/to/llvm-full-tree-function-truth-v3 \
DECOMP_A14_HISTORICAL_FUNCTION_BASELINE=/path/to/llvm-full-tree-function-baseline-v3.json \
./gradlew test --tests \
  'decompengine.oracle.fulltree.FullTreeImplementationOwnershipTest.locked historical A13 v2 projection reproduces exact planning populations'
```

ACP remains a read-only downstream consumer. It cannot author, validate, score, or
publish this planning assessment.

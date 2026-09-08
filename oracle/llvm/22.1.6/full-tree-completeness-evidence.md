# A13 full-tree completeness evidence

This is a small, checked-in contract slice for #120. It records the identity and
count relationships that are already present in the repository's authenticated
scope, compilation-unit inventory, source inventory, source lock, and artifact
manifest. Its status is **unresolved**; it does not certify full-tree
completeness or authorize scoring.

## Checked bindings

The five input files have these SHA-256 identities in this worktree:

| Input | SHA-256 | Role |
| --- | --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` | scope, explicit prefix maps, and oracle identities |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` | canonical DWARF compilation-unit and shard inventory |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` | source/generated/TableGen population report |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` | authenticated source identity |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` | authenticated artifact-manifest identity |

The scope and DWARF inventory agree on oracle id
`clang-llvm-full-tree-22.1.6`, source-lock identity, rich-artifact identity
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, and the
artifact-manifest identity above. The inventory also binds to the scope hash.
The source inventory binds to the same scope, source lock, and inventory index
(`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`).

## Reconciled facts

- The canonical DWARF inventory contains 2,150 compilation units in 57 shards:
  2,149 handwritten units and one generated unit.
- The source inventory contains 4,474 candidate translation units: 2,149
  linked units and 2,325 explicit source-only units. It records 1 generated
  compilation unit, 1,666 TableGen inputs, and 21 disabled projects.
- The checked source-inventory validator requires every handwritten and generated
  DWARF unit identity to be represented in its corresponding source population
  and requires source entries to be ordered and unique by path. A source-only
  unit retains a reason code and shard assignment; it is not silently treated as
  missing emitted code.
- Debug path normalization is bounded by the three prefix maps in
  `full-tree-scope.json`; this record introduces no alternate path policy.

These facts establish a source/CU inventory contract only. They do not establish
that every emitted function or global RVA has exactly one truth record and shard,
or that every manifest member was present in a production run.

## Production gap

No fresh production reconciliation was run for this slice. This worktree does
not retain the locked source archive, the rich/stripped full-tree ELF inputs, or
the all-shard function/call/data worker output trees and execution receipts
needed to rederive and independently join source, DWARF, ELF, truth, and
manifest populations. The checked `full-tree-release-evidence.json` is retained
provenance and reports a producer-side `complete: true` result, but it is not
treated here as independent #120 completeness evidence.

The following gates therefore remain unresolved: exactly-one ownership for every
emitted function/global RVA, missing/duplicate/stale/merged-shard detection
against the manifest, omission and duplication adversarial production checks,
and two complete runs with randomized worker completion order producing identical
bytes. Any future production qualification must keep source/artifact hashes and
authenticated oracle inputs bound, use the isolated bundled-Ghidra worker path
without `GHIDRA_HOME` or an external `analyzeHeadless`, and preserve explicit
unresolved/excluded populations.

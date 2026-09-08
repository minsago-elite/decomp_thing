# Full-tree accuracy baseline contract

This is the narrow evidence slice for issue [#108](https://github.com/minsago-elite/decomp_thing/issues/108).
It records the baseline shape and the production gates that are still unavailable. It does not
create a score, certify a reconstruction, or promote the checked historical report to release
authority.

## Snapshot

The facts below are read from the repository at commit `bf2501568f39ab52b23492dfc37839bb81895587`.
The scope and inventory are bound by these SHA-256 values:

| Input | Value |
| --- | --- |
| scope | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| inventory | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| inventory index | `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d` |
| release report self-hash | `0b806fa10d19110bfa8b877f7c532867d082944f56a6441e46df753d2e5f9ffc` |

The checked inventory contains 2,150 compilation units in 57 shards. The checked report retains
the following aggregate baseline fields; `excluded` is preserved outside the scoring denominator,
and `missing` and `fabricated` remain separate outcomes.

| Dimension | Denominator | Exact/recovered | Partial | Missing | Excluded | Fabricated |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| functions | 267,944 | 78,103 | — | 189,841 | 9 | 0 |
| calls | 708,535 | 671,455 | 37,080 | 0 | 813,142 | 0 |
| data: globals | 13,732 | 7 | 13,724 | 1 | 15,658 | 0 |
| data: types | 261,232 | 261,232 | 0 | 0 | 358,505 | 0 |
| data: ABI objects | 5,656 | 5,329 | 327 | 0 | 0 | 0 |

These values are a provenance-bound historical artifact snapshot, not measured current recovered
accuracy. The source files are `oracle/llvm/22.1.6/full-tree-release-evidence.json`,
`oracle/llvm/22.1.6/full-tree-scope.json`, and `oracle/llvm/22.1.6/full-tree-inventory.json`.

## Contract for a future gate

A production baseline may be accepted only when all of the following are present in the same
authenticated run lineage:

1. The source lock, rich/stripped artifacts, scope, inventory, configuration, and run identities
   are bound to the baseline bytes.
2. Every required shard is present, including empty shards, with deterministic ownership and
   per-dimension denominators.
3. Each dimension preserves exact, partial, missing, excluded, and fabricated populations where
   that schema supports them. Mismatch IDs are stable across runs and unexplained regression or
   shard disappearance fails closed.
4. The recovered candidate is independently produced and scored against raw-derived truth. A
   candidate name, hash, self-consistent truth document, ACP output, or Python compatibility
   fixture cannot supply expected oracle facts.
5. The report retains canonical machine bytes and a concise human summary from the same run, with
   source, artifact, configuration, candidate, tool, and runtime provenance.

The current schemas establish the data shape for the function, call, and data dimensions. They do
not, by themselves, establish independent candidate production, complete truth, aggregate worker
lifecycle, or release authority.

## Gate status

| Gate | Status | Evidence boundary |
| --- | --- | --- |
| Canonical scope and stable shard universe | recorded | #109 records 2,150 CUs and 57 shards with source and artifact bindings. |
| Per-shard baseline fields and persistent mismatch shape | recorded | `oracle/full-tree-*-baseline.schema.json` requires shard metrics and mismatch identities. |
| Independent recovered-model scoring for every required subsystem | unavailable | #830 remains open; the checked report's recovered/missing fields are historical evidence and do not prove current reconstructed accuracy. |
| Complete raw function/call/data/type/ABI truth and shard completeness | unavailable | #119, #120, #123, #128, and #129 remain open. |
| Kotlin-only authoritative production generation and release composition | unavailable | #136 remains open; current Kotlin migration receipts explicitly retain no release authority. |
| Aggregate scratch lease, lifecycle, and recovery authority | unavailable | #138 remains open; cooperative fixture limits are not the required ext4 authority. |
| Current repeated full-tree production runs and regression qualification | unavailable | No current-head production release gate is claimed by this snapshot; historical deterministic fixtures remain differential evidence. |
| Current human summary paired with canonical release report | unavailable | #832 remains open; this document is a contract/status record, not that summary. |

`unavailable` means that the gate has no accepted production evidence in this slice. It must not be
converted to zero, exact, complete, or passed by a consumer.

## Boundary invariants

This contract does not change the analysis or trust architecture. Production analysis continues to
use the bundled Ghidra application through its Java API worker; it must not require `GHIDRA_HOME` or
an external `analyzeHeadless` installation. ACP remains a read-only candidate producer, and oracle
truth, scoring, and release decisions remain Kotlin-owned authorities. No gate here grants a
candidate lease, downstream scoring authority, or release authority.

The implementation and evidence described by this document remain unresolved until the unavailable
gates above have current, authenticated, independently reproducible evidence.

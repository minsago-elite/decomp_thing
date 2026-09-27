# Full-tree repair scheduler contract v1

This is the narrow evidence slice for issue [#125](https://github.com/minsago-elite/decomp_thing/issues/125).
It binds the existing authenticated shard-run identity to the existing repair revision and validation
identity. It does not implement a full-tree scheduler, certify a candidate, or claim a production
multi-shard repair trial.

## Snapshot

The facts below were read from repository commit `bf2501568f39ab52b23492dfc37839bb81895587`.
The source commitments for the two existing authorities are:

| Existing authority | Path | SHA-256 |
| --- | --- | --- |
| bounded shard schema | `oracle/bounded-shard-index.schema.json` | `5aca060d537835bca7e250b7050145588920a51eb56bf16a2fe53f4960de7b9f` |
| bounded shard runner | `oracle/bounded_shards.py` | `8217dc8067479a859a012001ba6ef4179abbd532e917a1284f6f64585ded2de0` |
| repair run state | `src/main/kotlin/decompengine/repair/RepairRunState.kt` | `8902211428ea45619e2f70b01dc72ca6711ae79e7f2726a886787e0382659a81` |
| repair revision graph | `src/main/kotlin/decompengine/repair/ModuleRevisionGraph.kt` | `8fb30ebd98ac91e4431dd5a2b8f3679d20a333611ff99dda18d566d3864d72b6` |

## Existing facts

The bounded shard contract already supplies the durable identity needed at a scheduler boundary:

- inputs are sorted by `shardId`, duplicate identifiers are rejected, and each input carries a
  SHA-256 commitment;
- `run.json` records the run ID, schema version, bounds, shard IDs, and input commitments;
- each checkpoint binds `shardId`, `inputSha256`, `runSha256`, output size and output digest;
- a complete index is published only after every shard has reconciled, and index loading rechecks
  the run contract, ordered shard set, checkpoint identities, and output bytes; and
- an existing complete checkpoint is reused without rerunning that shard, while an interrupted run
  has no complete index and can resume from retained checkpoints.

These properties are exercised by `tests/oracle/test_bounded_shards.py`, including reordered input,
interruption/resume, changed contracts, and changed checkpoint output.

The repair authority already supplies the acceptance identity that a scheduler must preserve:

- `RepairRunState` retains the run status, canonical baseline, accepted and provisional heads,
  regression-corpus digest, attempt accounting, deadline, and unresolved evidence;
- `ModuleRevisionGraphSnapshot` retains the profile and dependency-index commitments, revision
  lineage, provisional head, fully accepted head, and durable run records; and
- `RepairValidationProof` binds source revision, profile, dependency index, regression corpus,
  original/rebuilt binaries when applicable, runtime, evidence, cleanup, and assurance. A fully
  accepted run requires an accepted head; a complete shard index alone cannot provide acceptance.

## Contract slice

Until the scheduler schema is implemented by #885, a repair work item has one safe identity at the
existing boundary:

```text
(repairRunId, shardId, shardInputSha256, runSha256)
```

`shardId`, `shardInputSha256`, and `runSha256` must come from the authenticated bounded shard run.
The repair graph's profile/index/source/corpus commitments and any ACP receipt identity remain
separate bindings; matching names or a newly produced shard file cannot substitute for them.

Scheduling completion therefore has two distinct states:

1. shard evidence is complete and replayable under the bounded shard contract; and
2. repair evidence is accepted only when the revision graph records the matching validated head
   and proof. Rejected, interrupted, exhausted, unsupported, and unobservable work remains
   unresolved evidence and does not advance the accepted head.

This is a boundary contract grounded in the existing files above. It is not a scheduler state
schema, diagnostic ownership algorithm, improvement ordering, budget ledger, or resume protocol.

## Unavailable production gates

The following gates remain unavailable in this slice:

| Gate | Status | Reason |
| --- | --- | --- |
| canonical full-tree ownership and dependency plan | unavailable | #113 remains open; this slice has no authenticated full-tree repair shard ownership or root-failure order. |
| stable diagnostic index and measured convergence | unavailable | #121, #886, and #888 remain open; no scheduler-owned root/cascade index or oscillation evidence is claimed. |
| cumulative shard/run accounting before external work | unavailable | #889 remains open; existing bounded shard limits do not constitute model-call, token, rebuild, patch, or wall-time reservation accounting. |
| authenticated ACP identity across scheduler restart | unavailable | #68, #72, and #891 remain open; this record does not authorize legacy transport fallback or replay a completed external call. |
| Kotlin/JVM semantic scheduler validation | unavailable | #890, #136 remain open; the existing repair graph validates its own bindings but is not a full-tree scheduler receipt validator. |
| bounded production multi-shard repair and archive replay | unavailable | #893, #115, and #138 remain open; checked fixtures and host-process tests are not production qualification. |

`unavailable` is an explicit unresolved state. It must not be converted into zero work, a passed
gate, an accepted stub, or release authority.

The trust boundary remains unchanged: production analysis uses the bundled Ghidra application
through its Java APIs and isolated workers, without `GHIDRA_HOME` or an external `analyzeHeadless`
installation. ACP output is candidate evidence consumed read-only. Kotlin/JVM validation, scoring,
oracle truth, and release decisions remain authoritative outside the ACP boundary.

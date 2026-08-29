# LLVM 22.1.6 A13 full-tree evidence

Scope `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` covers 2,150 compilation units in 57 shards. All observation and truth pairs are byte-deterministic, and data reconciliation reports zero unexplained entities.

| Dimension | Authenticated result |
| --- | ---: |
| Scored function RVAs | 267,944 |
| Unique inline-only functions | 988,799 |
| Call edges | 1,521,677 |
| Direct internal calls | 790,081 |
| External calls | 12,420 |
| Unresolved indirect calls | 719,176 |
| Canonical globals | 15,666 |
| Canonical aggregate types | 619,737 |
| ABI objects | 5,656 |
| ABI slots | 153,538 |

| Baseline | Exact/recovered | Partial | Missing | Excluded | Fabricated |
| --- | ---: | ---: | ---: | ---: | ---: |
| Functions | 78,103 | — | 189,841 | 9 | 0 |
| Calls | 671,455 | 37,080 | 0 | 813,142 | 0 |
| Data: globals | 7 | 13,724 | 1 | 15,658 | 0 |
| Data: types | 261,232 | 0 | 0 | 358,505 | 0 |
| Data: abiObjects | 5,329 | 327 | 0 | 0 | 0 |

Machine report SHA-256: `02e74c5f72fe71585c7cc24e49a2668ee5bd41c7190bfcaf3b91e06b5e2b9ddc`

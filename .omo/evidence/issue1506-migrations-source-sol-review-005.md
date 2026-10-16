# Issue #1506 migration source review — freeze 005 — GPT-6.1 Sol

Verdict: **CLEAR** for the exact offline migration source/evidence candidate below. The depth and early duplicate-field allocation findings are resolved in this candidate, and all eight captured review concerns have matching source fixes. This is source acceptance only: required hosted checks, automatic thread resolution, full archival workflow and merge remain pending/root-owned gates. No complete #1506 closure or full-path/native qualification is asserted.

## Exact scope and identities

| Artifact | SHA256 |
| --- | --- |
| 19-path source-freeze005 | `5b687e4efa6b1172e3ed007d7cdf05e4d1e3269b8f3e36ab94e19a71644c77bc` |
| Current migration receipt | `a04e062d58073329b448c51c0ee1f032415b2d3b1406acb007c7ebb8cf665541` |
| Corrected Python admission source | `eabc557ac3e177d3465b0e26bce1ef6cbf629f29ae075758dbdac5bb81b7e00b` |
| Captured eight-thread PR #1509 review | `992ae552881126b003cc2dd0c4bd09940d4e737071dc2711af3c7861b6758ae6` |
| Final neutrality019 log | `07289604c43bf13471b85561a7462d4d01a7d7cc5dee3fd23d8b9f4fba0d0207` |
| Preserved003 ITERATE report | `5f3f7c65167980a23203267e4e02c53550d3b1a5d90cb347e1d3032a57a04476` |

Base/captured review head: `8da009f6305c4c89931e47accd589f5d6a23c01c`. I independently verified all19 source files, all23 file bindings in the current receipt and all13 bound evidence files; each digest matches. The same guards passed again immediately before writing this report. Review evidence is excluded from the source-input inventory, avoiding a circular binding. Only this new report was written; the earlier003 ITERATE file remains unchanged.

No source edits, Git/remote/Actions operations, native commands, original candidate/runtime, model/provider/authentication, credentials, privileged operations, acquisitions or descendants were used. No production function or test suite was executed by this reviewer. Inspection used captured/local source, static AST/literal analysis and retained verification files.

## Resolution of the003 allocation finding

`oracle/referenced_data_bytes.py` now decodes each object key, verifies its closed vocabulary, and rejects a repeated decoded key **before scanning that key's value**. Seen-key sets are allocated only for evidence/window/origin/segment frames and the containing boundaries. Evidence vocabularies contain at most five keys; root.globals and global.byteEvidence boundary vocabularies contain exactly one key each. Ordinary generic keys are not added to an unbounded new scanner set. Thus repeated evidence fields or containing arrays/objects cannot bypass admission by waiting for the completed JSON pairs hook.

The same decoded-key comparison catches escaped spellings, including an escaped character in a repeated hex key and escaped root/global boundary names. The retained new test covers all four evidence roles plus both boundaries, asserting the specific early duplicate diagnostic before an intentionally malformed million-byte suffix. That diagnostic cannot originate from successful whole-document JSON decoding. Repeated small duplicate fields are also refused at the second decoded key by the same branch. The existing duplicate-aware JSON decoder remains as general syntax/duplicate fallback, separately demonstrated by fallback018 evidence.

Depth admission still checks the generic frame count before push, with exact32/one-over33 controls. Root-object admission, bounded strings/keys/numbers, per-global32 windows, per-window256 segments/bytes, model4096 windows and65536 requested bytes remain. Original F1 malformed-large-suffix window/segment/aggregate cases, Reader/byte BOM cases and exact aggregate boundaries remain covered. Admission protects downstream JSON token/tree allocation after a caller supplies the bounded input payload; it does not claim that the caller's file-byte storage disappears.

## All eight captured concerns

1. **Remaining Kotlin exporter11 callers — addressed.** Coordinator, planner-worker, CLI-command and CLI-intent-builder tests now open the checked exporter12 profile. The production active profile remains exporter12. Remaining old-name references inspected are explicit historical validation/rejection cases or inert test path metadata, not an ordinary loader still opening exporter11.
2. **Python exporter schema dispatch — addressed.** The loader dispatches exact integer11/12 to their separate closed schemas, refusing Boolean/string/unsupported versions and unknown fields. Active/default command selection uses exporter12; historical11 remains inspectable through its own schema and provenance bindings. There is no schema-fallback-on-validation-failure path.
3. **Module checkpoints — already addressed in the base generation, retained.** SourceTree still permits model schemas1/2/3 while preserving input/profile/fingerprint identity and current-schema reuse checks. That component's source hash matches the prior013 binding. Its older explicit resume evidence remains historical; this report does not relabel it as a new test run.
4. **Function-recovery scorer — addressed.** Schema3 accepts the new global field only after closed byte-evidence validation and aggregate charging; malformed/mixed historical evidence and scored extraction assessments reject. Input artifact identity is preserved. Tests compare schema3 function projection with the prior rich/stripped projections; raw bytes do not alter that function metric or mint assessment authority. Lexical admission occurs before the existing strict JSON decoder, now including early duplicates.
5. **Repair indexer — addressed.** Schema1/2/3 entity key sets remain closed. Schema3 evidence is validated and budgeted while historical evidence remains absent. Repair uses the shared strict checkpointed parser: bounded64KiB reads, depth32, early Jackson duplicate rejection and eager per-evidence budget checks precede later tree retention. Negative controls cover duplicate basis, extra fields, guessed basis, width overflow, false assessment and window33 before malformed large payload.
6. **Archival contract — addressed in source/admission tests.** The actual script's embedded admission prefix expects schema3 and uses the bounded strict decoder before closed evidence validation. It checks unassessed extraction data and retains the existing model/archive equality and evidence-only obligations. Tests exercise that actual prefix with schema3 positives and schema2/malformed/duplicate negatives. Full Docker reconstruction was not run locally; that workflow remains a separate gate.
7. **Stale validation receipt — addressed.** The current receipt's source/profile/test/evidence digests match. The initial receipt is preserved byte-identically under `oracle/gcc/historical/` at SHA256 `df324e6f5bd654d2c41e4b3961b1abff24b61c7dc954d852b601db3c5becac85` and explicitly labeled historical. Current receipt deliberately omits its own/future commit identity; this external source freeze binds it. Superseded001–004 freezes/receipt snapshots remain identified as unapproved history.
8. **Recovery-population schema — addressed.** Model schema enum1/2/3 and its registered inventory digest match. State remains unassessed and assessed IDs remain forbidden; Boolean/string/unsupported model versions have negative controls. No score/ABI/release authority follows from admitting schema3.

## Retained verification and compatibility

- Final Python017:42 tests, zero failures/skips across the three complete affected classes. The new early duplicate cases cover plain and escaped keys before malformed large suffixes. Fallback018 separately confirms the general strict decoder hook. The retained harness bounds existing public-key/tiny-ELF subprocess fixtures, disables GPG autostart/online lookup, and contains HOME/tmp/XDG below the repository; no target program or model/provider execution is claimed.
- Kotlin009:53 tests across seven classes, zero failures/errors and two preexisting opt-in skips. Current Kotlin production/test source hashes are identical to003, so this retained run remains applicable; no new Kotlin run is invented.
- Correct structural canonical-streaming011:9/9, zero failures/skips, separately counted. The receipt explicitly gives no coverage credit to the earlier wrongly named project-package selector.
- Neutrality019:zero findings in722 files. Shell/embedded syntax and diff checks are source-owner retained assertions; this reviewer did not run shell/Git commands or a Docker workflow.

Only the current receipt, Python byte-admission module and its test module differ from003. Exporter source remains SHA256 `4546507e7d20a6eb1ac766edcfc7d8041b4f2a294e35232902f8bda1e667512b`; active exporter12 profiles retain `06aea1f695ba41b9e3c9ef162dde5e405100ba14e67d9b1fde207d411746947a` and `9810f32c57f8d62081208ff831664f29b38ab1733e1bd8340ad3b6fbce07b19b`. Historical11 profiles are unchanged. Source-freeze013 remains immutable historical8da evidence; because the shared admission implementation has since changed, it is not claimed as current whole-tree authority.

## Remaining gates

The003 ITERATE conclusion remains correct for003; this CLEAR applies only to005. No approval is retroactively assigned to the first20-path inventory or001–004 candidates. Root owns checkpoint/push, required hosted checks, automatic review resolution, full archival qualification, issue status and merge. No full suite, full-path capture/repair/archival deployment qualification, measured candidate efficacy, original experiment rerun, model/authentication release, or oracle/ABI/scoring/production authority is granted by this review.

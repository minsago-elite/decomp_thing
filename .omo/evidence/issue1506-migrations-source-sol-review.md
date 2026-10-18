# Issue #1506 migration source review — freeze 003 — GPT-6.1 Sol

Verdict: **ITERATE** for migration source-freeze003. The Python duplicate-field allocation gap below prevents approval. Superseded migration candidates001/002 were not approved either.

## Exact reviewed handoff

- Base/captured PR #1509 head: `8da009f6305c4c89931e47accd589f5d6a23c01c`.
- 19-path source-freeze003 SHA256: `6e74b7b4a2f43d35e6adc876a195543d7a4226379deca9b50ed1a55ce9a29134`.
- Handoff implementation receipt SHA256: `b4b4542862bc94b3dd1498b09d8dcb1c99c4026026de9d36ff0ec745005d498b`.
- Python byte-evidence source SHA256: `d86f2639f27ff840fa1711e5e32abffdad97718c588a4d5e28e324e63164cb2d`.

At the stopped003 handoff I independently verified all19 frozen source files, all23 receipt file bindings and all12 bound evidence hashes. I read all eight exact captured automatic review texts. Retained XML independently totals53 Kotlin tests across seven classes, zero failures/errors and two existing opt-in skips; the correct structural canonical-streaming class separately has9/9 passes. The earlier wrong project-package selector is explicitly excluded. The retained Python log has41/41 passes. No full-suite or hosted pass is inferred.

The author resumed correction after this finding was sent. A final live-source equality guard detected that the mutable sources/receipt no longer match003 and stopped before making a stale current-source claim. This report therefore describes the exact previously verified003 handoff, not the later moving tree. Any replacement requires a fresh stable freeze and review.

Only this report was written. No source/Git/remote/Actions/native/provider/model/authentication/credential/privileged/acquisition execution or mutations were performed; no descendants were spawned. No production function or test suite was executed by this reviewer. Assessment used local captured evidence and static source.

## Blocking finding — duplicate-key rejection follows forbidden allocation

In `oracle/referenced_data_bytes.py`, lexical key admission checks membership in the permitted field-name set but keeps no per-object set/count of keys already seen. Repeated permitted keys pass. A single segment may therefore contain arbitrarily many small repeated `hex` fields while consuming only one window, one segment and one requested-length charge; each individual string remains below its scalar cap.

The archival decoder uses `json.loads(..., object_pairs_hook=unique_fields)`. That hook receives the completed object's pairs list: duplicate rejection follows allocation of all repeated pairs. The scorer's existing duplicate-aware decoder has the same late-hook property, and its new lexical prepass does not close this path. A large forbidden repeated-field list can consequently allocate up to the coarse512MiB document ceiling before rejection. Depth32 and array/window/segment counters do not bound this single-object field multiplicity.

The new small archival duplicate-wire test proves semantic rejection, not rejection at the second key before value/pair construction. Semantic duplicate collapse is fixed in003; early duplicate-field allocation is not. No large payload or execution probe was needed to establish the source branch and completed-pairs hook behavior.

Required correction: retain a bounded set of decoded keys for closed evidence/window/origin/segment objects and reject repetition before scanning the repeated key's value. Escaped spellings of the same key must compare after decoding. Retain strict decoder duplicate checks as fallback and inspect the containing global byteEvidence boundary. Add a repeated-permitted-key followed by deliberately malformed/large suffix test asserting the early duplicate reason, plus repeated-small-field coverage. Rebind source/tests/receipt/evidence in a new stable freeze. Do not relabel003 as approved.

## Eight captured findings and the rest of003

1. **Kotlin exporter11 callers:** the four affected coordinator/planner/CLI/intent-builder classes now select exporter12. Remaining old-name references inspected are deliberate historical tests or inert path metadata, not an ordinary checked-profile loader.
2. **Python profile schema dispatch:** exact integer11/12 selects the corresponding closed schema. Boolean/string/unsupported versions and unknown fields reject; historical and active provenance/derived-record tests remain.
3. **Module checkpoints:** the earlier base-generation fix still admits model schemas1/2/3 while retaining input/profile/fingerprint identity and reuse checks. That component's earlier evidence is historical, not a new migration run.
4. **Function-recovery scorer:** schema3 retains the function projection and checks closed bounded global byte evidence, input identity and unassessed status; historical mixed evidence rejects. Its early Python admission still has the blocking finding above.
5. **Repair indexer:** schema1/2/3 key sets remain closed; schema3 evidence is validated/charged without assessment authority. It now uses the strict checkpointed parser with bounded chunks, eager budgets and early Jackson duplicate rejection. Retained negatives include duplicate basis keys, guessed basis, over-limit length, extra fields, scored assessment and window33 before malformed large suffix.
6. **Archival validation:** the actual embedded admission prefix selects schema3 and validates byte evidence. Strict decoding fixes duplicate collapse, and root/depth guards are present; full Docker reconstruction was not run. Its Python preallocation gap remains blocking.
7. **Evidence receipt:** current003 bindings matched at handoff. The initial receipt is preserved byte-identically under `oracle/gcc/historical/` at SHA256 `df324e6f5bd654d2c41e4b3961b1abff24b61c7dc954d852b601db3c5becac85`, explicitly historical. Source013 remains the8da generation, not current whole-tree authority.
8. **Recovery population:** enum1/2/3 and the registered inventory digest match; state remains unassessed and assessed IDs remain forbidden. Invalid Boolean/string/unsupported versions have controls.

The earlier generic-stack gap is fixed before frame push in both Python and shared Kotlin admission. Exact32/one-over33, original F1 window/segment/aggregate/scalar, byte/Reader BOM and exact-bound regressions are retained. The exporter remains SHA256 `4546507e7d20a6eb1ac766edcfc7d8041b4f2a294e35232902f8bda1e667512b`; active exporter12 and historical11 profile hashes remain unchanged. These sound subclaims do not remove the blocking duplicate allocation path.

## Remaining gates

Provide a newly stopped source/evidence freeze after correcting early duplicate admission. Relevant hosted checks, complete archival workflow, automatic review resolution, Git checkpoint, issue closure and production/native qualification remain root-owned gates. No new measurement, original candidate rerun, model/authentication call, oracle/ABI/scoring/release authority or merge is authorized.

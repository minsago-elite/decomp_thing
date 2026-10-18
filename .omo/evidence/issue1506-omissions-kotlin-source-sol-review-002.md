# Issue1506 Kotlin omission correction002 independent source rereview

Verdict: **CLEAR_SCOPED** — the typed validation allocation-order defect R1 from freeze001 is corrected in held freeze002. This approves the narrow source correction and carries forward the prior source findings for the unchanged eleven files. It is not compilation, executed test evidence, a complete current-generation composition, hosted qualification, or issue acceptance.

## Exact authority and history

Worktree `.claude/worktrees/issue-1506-referenced-bytes`.

- New thirteen-file freeze `build/issue1506-omissions-kotlin/source-freeze-002.json`: `b7b9f00e281042dff440ee88f9becc729454fe4fa46d9f1a831276dce9218e8e`.
- New handoff: `5ece3568d111835ea9f6e94ea294bdc00d57306126fc5a0c335faee33f6a9f40`.
- New five textual assertions: `99e549eff2ab09a5a8412e370569b890de85d9dade7bf8a616dae498c14a25da`.
- Prior freeze001: `a68d5f03ee77962d7bf60aa17f772b61034090dfbd63d4d26e83ad8c2ca0dfcf`; prior handoff `0a98b6f16284caaae2a46538318fc4ac79a935e436a817202dbc00464b4ca8fd`; prior textual assertions `dec385960e2a603113e1971d102b347d2ac88484e6f186bc0811ec59bb4ee76f`.
- Prior independent ITERATE report `.omo/evidence/issue1506-omissions-kotlin-source-sol-review-001.md` remains byte-identical: `83e2034e47884a18e609cc2886cb63721bfa0c1e98235993f0d0676fd67c2704`.
- Approved plan binding remains `ffe2d3ab9e3e6faada6db862c9d9583d97877f4d725d5f9d96c55a18d58a463d`.

Independently verified all13 current file sizes/digests against002 and compared both manifests: only the validator and focused test changed; all11 other file digests are exactly001. As an additional static delta check, moving the cardinality line back in an in-memory string reproduces the exact001 validator digest; removing only the new test block reproduces the exact001 test digest. No old file/evidence/report was rewritten.

## R1 source correction

`src/main/kotlin/decompengine/project/ReferencedDataByteEvidence.kt:38–40` now validates supported evidence generation and the common window-size range first. The range is unchanged:1..32 for v1,0..32 for v2. For size33 or larger it fails solely from size inspection, before:

- v1 omission-list admission (:41), or v2 reason distinct/order/aggregate processing (:43–47);
- the v2 per-origin `map`/`distinct` allocation (:48);
- `any`, full-window distinct, sort/comparator or per-window segment work (:50–53).

The public `Budget.charge` route still calls validate first (:27–28); typed `RecoveredProgramModel` construction calls that budget, and render/prompt validation delegates to the same corrected function. Thus no per-window identity allocation is performed before the global cap on those routes. Wire parse caps and model budgets remain unchanged. The correction only moves the existing requirement; it does not change accepted historical1/2/3 bytes, v2 reason semantics, nullable model4 pairing, the public API, or any numeric cap.

Validator002 SHA256: `1bb4d0deab70c19097c328e2d534593ace5db4a2982573655eb8a18bb0dac645` (12,578 bytes).

## Authored lazy-list control (not executed)

`src/test/kotlin/decompengine/project/ReferencedDataByteEvidenceTest.kt:219–237` defines a constant-size33 `AbstractList`. Both `get` and `iterator` increment one access counter and throw immediately. For each generation1 and2, the test expects the cardinality IllegalArgumentException and asserts zero accesses. An accidental return to map/iteration before the cap would throw a different failure and increment the counter, so this is a relevant short-circuit control. Existing32-window acceptance and v2 origin conflict controls remain unchanged. This review inspected the test source only; zero accesses is the assertion and source-derived expectation, not a newly observed executed result.

Focused test002 SHA256: `46b5ba418241d9723d404840f752d28b0f1a6bc91e0ec16b77670be50a6262b7` (17,705 bytes).

## Scope and outstanding composition

No new blocker is identified in this exact two-file correction. The previous report's source analysis of generation pairing, required nullable key, closed omissions, early lexical/streaming array limits, unchanged checkpoint parser and Archival delegation, repair, prompt bounds, fingerprints, stale checkpoint refusal, and unassessed authority applies to the eleven byte-identical files. Their old cross-owner snapshots remain historical observations; this rereview does not promote them to the current complete exporter13/profile/Python/schema/receipt generation.

Kotlin syntax/type checking and actual focused test execution are still pending. So are the final composed source freeze, exporter-specific eligible/noneligible/null/cutoff obligations, complete Python/population/inventory migration, unchanged4096-function/held512 interruption/resume evidence, and separately authorized hosted qualification. No model, ABI, scoring, behavior, acquisition or trial authority is added by this scoped result.

Review operations: source/manifest/history reads and Python-B in-memory digest comparisons only. No source edits, test execution, JVM, compiler/native tools, Git, remote/CI, auth or model execution. Only this additive report was written.

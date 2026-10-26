# Exporter13 profile/capture/planning/resume independent source review002

Verdict: **ITERATE** — one authored planning control cannot reach its asserted failure boundary. No production migration defect found in the inspected paths. This is source-only review of another owner’s nineteen-file slice; I authored the separate shared Kotlin contract and do not claim independent review of that contract.

## Exact held scope

Freeze `build/issue1506-profile13-migration/source-freeze-002.json`, SHA256 `5257d80831112b5fef385e2efa45da43899e7e080fa3b6cee560365380bdc432`: all19 file hashes/sizes independently matched before report creation. Exporter dependency `a607b41b7c0cb7d871ca5c92c674b42602284d9d12570746054b38382603d265` matches actual source. Active compiler profile `0d2c6f571b1ee7a977b2baf496823186da3fa95c97ede358e2c4ef75403927ca`, full profile `1075cd580b0a5bc872149633c1aa95a30b08b9da2f2e9feb689352571032b615`; JSON metadata/source/fixed pins agree. Historical12 compiler/full profiles and unchanged4096/held512 contained-test source match the exact freeze commitments. No edits to held files or test execution.

## R1 — historical-evidence planning negative constructs an invalid typed model first

`src/test/kotlin/decompengine/oracle/gcc/GccCompilerEnginePlanningTest.kt:49–60`, historical=true branch, sets a global evidence schemaVersion1 inside an otherwise schemaVersion4 model via `current.copy(...)`. The typed `RecoveredProgramModel` initializer (`ProgramModel.kt:54–58`, shared contract outside this independent slice) rejects this mixed pairing immediately with IllegalArgumentException. The diagnostic service invokes the analyzer inside its inner try, then rethrows nonbudget analyzer failures unchanged (`GccCompilerEnginePlanning.kt:87–100`); its outer catch also rethrows unchanged (:191–193). The control instead requires GccCompilerEnginePlanningException and the later producer-specific “supplied byte evidence schema2” message. Those assertions cannot be satisfied by this branch. This is established from source, not a claimed executed failure.

Keep the generic-null negative reaching the producer gate. Make the historical negative assert the actual typed rejection boundary, or supply a valid historical model3/evidence1 and assert the service model4 generation guard. Do not weaken typed pairing or wrap unrelated analyzer exceptions merely to satisfy this test. Preserve publication-absence assertions. Freeze a new source generation and rereview before qualification.

## Migration checks

- Active compiler profile loader selects registered closed `gcc/compiler-engines-exporter13` schema. Schema envelope1 stays1 and exporter const13 is exact. Bundled exporter source bytes and pinned Ghidra archive are checked; profile dependencies/source-lock/build manifests remain authenticated. The schemaVersion3 at GccCompilerEngineProfile.kt:425 is the derived **build record**, not model normalization; retaining it avoids unrelated receipt/schema churn.
- Structural active profile/default paths now name compiler-engines-exporter13 and structural-full-export-profile-exporter13. Hard pins at GccDriverStructuralProfile.kt:213/:220 match actual bytes; full profile binds compiler profile, exporter13/source, Ghidra archive and full recovery mode. Historical11/12 schema registrations remain alongside13, and explicit historical profile schema/hash tests remain; old profiles cannot authorize current loading.
- Full capture model verifier and prefix detector both use canonical model4 (:256/:484); exporter state envelope2 still requires exporter13 (:423). Exact global closed keys include evidence; requireFullGlobalRecord(:569) uses shared4/v2 parsing and requires nonnull at the actual eligible bundled producer boundary. Pretty-record comparison(:824) commits complete canonical evidence including collectionOmissions; global budgets remain aggregate.
- Planning checks actual input SHA, model4 and every emitted global supplied evidence2 (:102–110), before plan/model assessment publication. Generic nullable parsing is not globally disabled; producer-specific rejection lives in this benchmark diagnostic service.
- Resume requires exporter13 (:266/:1829), reconstructs canonical model4 prefix (:630), validates each global exact fields and nonnull pairedv2 (:1276/:1287/:1310), charges aggregate budgets and retains closed statuses/unassessed authority. Complete global record bytes are semantic fingerprint inputs, so omission mutations affect commitments. Exact record canonicalization includes full evidence via shared renderer; omission metadata is not dropped.
- Other receipt versions remain scoped: exporter state2, semantic state1, progress1, existing full-profile envelope1. No blanket schema bump found. Canonical model digest/profile/exporter identities prevent reusing old12/model3 state by merely relabeling it.
- Authored full-capture controls exercise null/v1 refusal and empty aggregate omission preservation; resume controls reconstruct two-batch retained/fresh outputs, compare exact model bytes/semantic commitments, and mutate reasons/model generation. Profile tests reject previous exporter version and authenticate explicit historical11/12 hashes. Active coordinator, worker, CLI intent/command and bundled Ghidra fixture paths select13. These are source observations, not executed outcomes.

## Composition and remaining gates

The separate shared Kotlin002 contract, exporter interrupted/cutoff correctness, Python/archival/population schema/inventory, scripts/docs/current receipts and all transitive generation bindings need their own held composition review. This review does not establish their independent correctness or runtime qualification. Generic model4 null remains valid by contract; the inspected eligible bundled producer boundaries correctly require suppliedv2. No synthetic origin/cutoff or ABI/prototype workaround is added here.

Compilation, all affected focused classes and historical/early-allocation regressions remain unrun. The unchanged4096-function fixture must still reach held512, interrupt and resume under separately authorized contained qualification. Original model/prompt replay, provider/auth/model/CI/native qualification and full issue acceptance remain open. No JVM/compiler/Ghidra/native/auth/model/network/Git/remote actions were performed for this review. Only this new report was written.

## Exact reviewed source pins

- `src/main/kotlin/decompengine/oracle/gcc/GccCompilerEngineProfile.kt` — `b011aef1ae7b80b0b875102174693a0b2fd007b9fb515c3c56e5cd0a2c2f2053` (34113 bytes).
- `src/main/kotlin/decompengine/oracle/gcc/GccDriverStructuralProfile.kt` — `4aea2857720ed3f0a6825b4ef192c2f41dbf40e9e58c28ec46d0a2ef8814b787` (38626 bytes).
- `src/main/kotlin/decompengine/oracle/gcc/GccCompilerEnginePlanning.kt` — `c51b2f33b86b480fc63bfff9c8a4be03606d7ce6f1a44cfa6b0f16b0225e2eef` (28326 bytes).
- `src/main/kotlin/decompengine/oracle/gcc/GccBundledFullExportCapture.kt` — `8aa32e03265860746a8e9de9455336361fe771f05eb7e54750df47930b022b68` (52239 bytes).
- `src/main/kotlin/decompengine/oracle/gcc/GccCompilerEngineResumeEvidence.kt` — `771ca24ffa0857932f736fed1f85a77319c2db28e30741400fff2c410cb740a0` (84686 bytes).
- `src/main/kotlin/decompengine/oracle/core/OracleSchemas.kt` — `0753d3cae99f5b5dc3522ba7c5376101efa5c5fd4fea2de999510f6288345cee` (17884 bytes).
- `oracle/gcc/compiler-engines-exporter13.schema.json` — `5b8c6b6a6a48c15be8f4966bee0466313766854f9e380a98898a9274bc554725` (4772 bytes).
- `oracle/gcc/16.2.0/compiler-engines-exporter13.json` — `0d2c6f571b1ee7a977b2baf496823186da3fa95c97ede358e2c4ef75403927ca` (2630 bytes).
- `oracle/gcc/16.2.0/structural-full-export-profile-exporter13.json` — `1075cd580b0a5bc872149633c1aa95a30b08b9da2f2e9feb689352571032b615` (420 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccCompilerEngineProfileTest.kt` — `f3f11ea81320163e81d18fc97a91a06d90d87fa39ab155c743210b31fda0f6cf` (16213 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccDriverStructuralProfileTest.kt` — `1d2b495e38758aedc4f827073ecffcbe6c06109ee3aab86e4bae4227639877d3` (22461 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccCompilerEnginePlanningTest.kt` — `9816e69fe12a0321b65d7f8cc2e64e729751dc68d5398db559abe7ebe9a3b851` (18375 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledFullExportCaptureTest.kt` — `98c5a8faf3d7c29018b26e4d7f1c2cce82875b469815947a71a28afe18e42c7c` (73737 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccCompilerEngineResumeEvidenceValidationTest.kt` — `62f7413544bc0b90b6541379186a07d1ea7613113f53e66ad262830ad0f07f10` (101196 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledPlannerWorkerTest.kt` — `984780fe13c345b133b2ba538c21b052670ff374e1d8f6a1a3c8f2ee578b8d50` (11619 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledOperationCoordinatorTest.kt` — `3e83c0828312cb9cdd713ccbe7216d6c8f86a84c6576365b3f38adf837afadfd` (41000 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledCliIntentBuilderTest.kt` — `66335fb53568193f8498d82f3d0f07b98004599bd1a6d9cf6abb3591aba9ccba` (7007 bytes).
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledCliCommandTest.kt` — `3083e72097e2f7d28ac6eb7a3e7d3c6f476d4830f0aa0cdc1d319cb648c30acb` (15304 bytes).
- `src/test/kotlin/decompengine/analysis/BundledGhidraTest.kt` — `3b94264d3228dff4c55a1a6848b74871cf7d40609cb71aa28ce70573fed158d4` (27215 bytes).

## Additive003 rereview — CLEAR for this independent source slice

Reviewed new exact freeze003 SHA256 `ccf85456a84f26b18ead62323b56d4e40bfe2f0bd61b6b98cf359597a6ee2174`. All19 current source hashes/sizes match; exactly the planning test changed from002, now SHA256 `38089822d195a7da0b6bb8eba0df13a6bd954b4e750fb2aa0218922385a91e36`. Other18 source bytes, actual exporter dependency, active profiles/fixed pins, historical12 profiles and unchanged4096/held512 fixture match002. The original review above is retained as an exact byte prefix (prior SHA256 `4c8687c4c1e55f9140847fd9989741339e5b97c1ce9e522d9c7b7b7925330266`).

R1 is resolved. `GccCompilerEnginePlanningTest.kt:46–62` separately constructs valid model4/null; typed construction permits null and the service reaches its explicit producer evidence2 guard. The historical case (:66–82) changes model and nested evidence together to3/v1, retaining the valid single real unknown-width window, unknown_access_width reason and empty collection omissions from the fixture. Shared typed pairing/validation therefore permits construction; the service then reaches the model4 generation guard and its asserted GccCompilerEnginePlanningException/message. Both tests continue to require no published plan assessment. No weakening of typed validation, production exceptions, profile or ABI behavior was made.

Terminal scoped verdict: **CLEAR** for the corrected nineteen-file profile/capture/planning/resume source migration. This is independent review of that owner's slice only; the separately authored shared Kotlin contract is not self-certified. All composition gaps and remaining qualification gates stated above remain. No compilation, test, JVM/compiler/Ghidra/native/auth/model/Git/remote execution; only this additive review text was written. Actions remain primary compile/runtime qualification, and textual/source reasoning is not executed test evidence.

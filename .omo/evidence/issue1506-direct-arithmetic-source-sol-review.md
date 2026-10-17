# Independent source review: issue1506 finite direct arithmetic

Verdict: **CLEAR for source freeze001 only.** No blocking source defect found in the exact finite FLOAT_ADD/FLOAT_MULT correction. Corrected original-input replay, hosted verification and review/merge remain separate gates. This report grants no candidate/model trial, oracle/ABI/scoring, production or release authority, and does not close #1506/#1517.

Reviewer: GPT-6.1 Sol, independent of author; no descendants. Static source, retained XML/log and hash inspection only. No original reanalysis/export, frozen evaluator/candidate, native target program, helper, provider/model/auth, credential, acquisition, Git, remote or Actions execution. Only this new report was written inside the repository. Author source was stopped.

## Exact authority and bindings

Worktree: `/home/june/decomp_thing/.claude/worktrees/issue-1506-referenced-bytes`; supplied parent `42efc8c5c55999ee27228fd7f676411b53e43449`. This is a source freeze review, not an independently refreshed Git/remote-head claim.

| Artifact | SHA256 |
| --- | --- |
| `build/issue1506-direct-arithmetic/source-freeze-001.json` | `5afafd2fdc9a72857ac6feddd9987fc20926cef235d739b8012d8ad6644f3b0e` |
| Adjacent `review-handoff.md` | `3804f33bba684d67ed7e568beb7427ef180aa11facf1f33998ae3d7d3f5bc210` |
| `oracle/gcc/issue1506-implementation-validation.json` | `ffaf4088b5a3bcf0d4cf04cb57dbba2b79a0693fba1fb61aea89a9b328ad66eb` |
| Archived `oracle/gcc/historical/issue1506-migration005-validation.json` | `a04e062d58073329b448c51c0ee1f032415b2d3b1406acb007c7ebb8cf665541` |
| Root `.omo/evidence/issue1517-original-retained-db-diagnosis-sol.md` | `76dd3aad5d8db677f52f74f8eb90ac6cdea1f5ff3c2952eb02043b04917b10fd` |
| Root retained diagnosis `output/retained-db-probe.txt` | `aa7656d899b5a1f575c9709106d2d4a1282850adf6cc06ee89c27e265344389a` |
| Original primary REFUSAL report | `d36ef5d7e7c8f9206efc47173ad7ed1763b323e5e1bc35df581f9c593bc1c98f` |

All 12 freeze file digests, 11 current receipt file bindings,35 evidence digests and two historical profile hashes match their actual current bytes. The original REFUSAL report hash was independently checked and remains unchanged. Root diagnosis report and retained raw probe hashes match the receipt references. No private declarations, names, types or cases are reproduced here.

The previous migration005 receipt is archived byte-identically. All18 nonreceipt paths in freeze005 remain unchanged, including strict Python schema dispatch/decoded duplicate guards, scorer, archival script, shared admission, canonical repair and their migration tests. The prior005 review remains SHA256 `b13afd256e57e54223b8de46750448b218da1d73577a0b50963a4fba14b32ac0`; its scope and earlier003 ITERATE are not rewritten.

## Finite p-code policy — CLEAR

`ExportProgramModel.java:909–951` admits only FLOAT_ADD and FLOAT_MULT as new direct value-read operations. It requires exactly two inputs and a nonnull output, checks each input width equals output width, and matches only a memory varnode whose complete Address equals the reference target. Address equality preserves address-space identity; constant-space or another RAM-space varnode at the same numeric offset cannot establish the association. Either semantic value slot is supported. These operations consume their input values, so the matched varnode size is evidence of the direct read width, without inferring a source-language object/type/initializer.

An output directly aliasing the target refuses. Each matching input increments the whole-instruction association count, which must finish at exactly one with positive width. Two matching inputs, multiple matching operations or a COPY plus arithmetic association therefore remain unknown, even if widths agree. Mismatched sizes refuse immediately. Wrong arity/null output takes the conservative unsupported-operation branch; matching target memory operands in unreviewed opcodes refuse. No generic arithmetic allowlist, constant-to-pointer interpretation or control-flow destination inference was added. Existing dynamic LOAD/STORE pointer refusal remains.

The current exporter was compared directly with the diagnosis's immutable old source reference, whose hash is `4546507e7d20a6eb1ac766edcfc7d8041b4f2a294e35232902f8bda1e667512b`. The entire diff is the finite helper/comment and one guarded arithmetic branch. Existing LOAD/STORE/COPY logic, byte-address checks, complete/missing segment rendering, candidate/window/requested-byte accounting, cancellation, deduplication and first-owner/publication logic are byte-for-byte unchanged by this correction. No hard bound or negative control was relaxed.

The existing `pcode_direct_read` origin accurately describes these semantic direct reads. Wire schema3 and exporter version12 remain unchanged, while the exact source digest distinguishes this implementation. Documentation now states the full finite policy, conservative unknown cases and explicit separation of byte availability from initializer/type/object or oracle authority. No undeclared width-basis/schema field was added.

## Authored fixture and retained regressions

`ReferencedBytesProbe.java:217–239` exercises both value slots for each new opcode, exact target/address-space identity, constant-space mismatch, unequal widths, duplicate input associations, read/write alias and multiple operations. Unreviewed FLOAT_SUB/FLOAT_DIV/INT_MULT/BRANCH/CALL remain unknown. Existing LOAD/STORE/COPY/dynamic/unsupported controls, missing/partial/unmapped/uninitialized/unreadable memory, cancellation and bound controls remain. Positive/negative source assertions agree with the reviewed implementation.

`ControlledByteListingProbe.java:29–76` uses the actual bundled ProgramDB and SLEIGH disassembly of three authored MOVSD/ADDSD/MULSD instructions. It verifies their raw COPY/FLOAT_ADD/FLOAT_MULT opcode, creates distinct referenced targets and intentionally defines one-byte00h listing data. It then invokes the actual exporter prepass/rendering and checks three distinct records, exact instruction/reference origins, requested length8, available leading-zero bytes, and unchanged one-byte listing/initializer. This is authored actual-API coverage, not a proxy-only positive and not natural original-input analysis. The fixture deliberately rolls its transaction back; it does not rewrite an original database.

The retained JUnit XML set has five full classes,34 tests,0 failures/errors/skips:

| Class | Tests |
| --- | ---: |
| GhidraReferencedBytesExporterTest |1 |
| GccCompilerEngineProfileTest |10 |
| GccDriverStructuralProfileTest |9 |
| ReferencedByteEvidenceAdmissionTest (F1) |9 |
| GeneratedCByteEvidencePromptTest (F2) |5 |

This is an actual retained Gradle/JUnit run, distinct from the reflection-only verification used for another PR. `focused-002.log` SHA256 `fea98ed44ed16db9b1f04d0d235527b0887784c9276d795af94a25a12e65f75a` records success. Five XML digests are bound in the current receipt and independently checked. F1 retains early admission/BOM/window/segment/aggregate rejection; F2 retains exact incremental UTF8/prompt bounds. No claim is made that every migration005 class, complete Gradle suite, wrapper, archival path or hosted lane reran here.

The test harness uses bundled Java APIs; production is not redirected to an external GHIDRA_HOME/analyzeHeadless installation. Its fixture subprocesses have60second timeouts plus5second final waits, repository-local tmp/home/preferences/JNA, disabled PerfData and removal of JVM option/classpath/GHIDRA_HOME overrides. This is bounded trusted authored-fixture execution, not candidate containment qualification. The staged bundle's actual classpath inventory is203 JARs, all independently length/hash verified against `public-api-classpath.json` SHA256 `d5cc24b5da55ac4415281a51e715b2d99fcb440b2d67951f2a04a4582a5fe22d`. This whole-bundle harness inventory is distinct from the diagnosis's153 selected Framework/Features JARs; neither count supersedes the other's scope.

The initial focused001 javac failure is retained and hash-bound: duplicate local test variable, before fixture execution. It is not counted as a passing fixture. The final probe/controlled-listing pass logs and emitted exporter/probe classes are all current receipt-bound. Documentation checks are retained; final neutrality004/006 reports are byte-identical, SHA256 `7d971b7d68285f9cb21f9c3356ecb1a1add7803670327dd6014265dd3a2c8e5d`,0 findings in722 files/8565841bytes. This review did not rerun those checks or infer complete CI qualification from them.

## Exporter/profile identity and stale-state refusal

The current exporter hashes to `6874e17183348605cd23927e2ad993c402ba0ebd32caa9a1010058abc3fff79e`. Compiler exporter12 profile SHA256 is `f8a487df5b35168a1a1212a95c9f40e84a299969005e1a9ffd7383a1db26ed19`; full-export profile SHA256 is `011f49895f66c4af2692eeaac6bb514a96761ed864f2b0051b533bda3fead06f`. Both profile fields match the actual exporter; full-export profile also binds the actual compiler profile digest. GccDriverStructuralProfile's fixed constants and positive test expectations match these exact bytes.

`GccCompilerEngineProfile.kt:282–299` requires exporter12/planning identity and hashes the actual bounded bundled exporter resource against the profile, so a stale same-version source digest cannot silently authorize current implementation. `GccDriverStructuralProfile.kt:382–400` checks the exact full-export profile bytes and compiler/exporter/version/Ghidra cross-bindings. Existing snapshot/capture/intent checks are preserved; no fallback to old unsuffixed profiles was added. Retained profile tests cover current positive identities, historical11 refusal, changed version refusal, control-plane substitutions and full capture/intent/receipt binding controls. This review statically proves the digest refusal for old12; it does not invent a newly executed old12-specific test.

Historical unsuffixed profiles remain byte-identical at their prior pinned hashes. Current source/schema/profile hardcoding does not by itself prove that an old saved model was freshly exported or that the original REFUSAL is corrected. The new receipt explicitly limits its success to authored controls and leaves separate original replay pending, avoiding retroqualification of old evidence.

## Original diagnosis and disposition

The retained root diagnosis establishes195 stored instructions and four matching direct arithmetic reads with width8, with independently proved image-base/file/memory association and natural one-byte00h listing data. It identifies why COPY-only recognition refused the original. That read-only diagnosis and the earlier REFUSAL are evidence of the defect, not a corrected exporter pass. This review has not rerun the original or promoted the authored ProgramDB listing to natural original evidence.

**CLEAR** permits the root custodian's next checkpoint/review and separately authorized exact corrected-original replay. That replay must independently verify original bytes, mapping, exporter identity and complete evidence/capture/parser/prompt/resume bindings before a stronger qualification claim. Required hosted CI and automatic/independent review remain root gates; no merge/issue closure or model trial follows from this report.

## Exact12-file source inventory

| Path | SHA256 |
| --- | --- |
| `docs/referenced-data-byte-evidence.md` | `38feedaa8f4c27d9a22080f5ca5e702fa9a139820dc87d963a0e8a1eaf2d2af8` |
| `oracle/gcc/16.2.0/compiler-engines-exporter12.json` | `f8a487df5b35168a1a1212a95c9f40e84a299969005e1a9ffd7383a1db26ed19` |
| `oracle/gcc/16.2.0/structural-full-export-profile-exporter12.json` | `011f49895f66c4af2692eeaac6bb514a96761ed864f2b0051b533bda3fead06f` |
| `oracle/gcc/historical/issue1506-migration005-validation.json` | `a04e062d58073329b448c51c0ee1f032415b2d3b1406acb007c7ebb8cf665541` |
| `oracle/gcc/issue1506-implementation-validation.json` | `ffaf4088b5a3bcf0d4cf04cb57dbba2b79a0693fba1fb61aea89a9b328ad66eb` |
| `src/main/kotlin/decompengine/oracle/gcc/GccDriverStructuralProfile.kt` | `139eb9b2f90d44b66391630b8045165f4d7ba9568fba849ba4a36e30cdb67204` |
| `src/main/resources/ghidra_scripts/ExportProgramModel.java` | `6874e17183348605cd23927e2ad993c402ba0ebd32caa9a1010058abc3fff79e` |
| `src/test/kotlin/decompengine/oracle/gcc/GccCompilerEngineProfileTest.kt` | `67ce362d7782fd5ffd222d4d251ed2eea3b81fd3f983fc041ce6f6d076d834a3` |
| `src/test/kotlin/decompengine/oracle/gcc/GccDriverStructuralProfileTest.kt` | `fc0ca9fa41a0f51191dcc04732c0f619b2f62e49470085d59fa171326ec4e3f4` |
| `src/test/kotlin/decompengine/project/GhidraReferencedBytesExporterTest.kt` | `eec102cb26321316fbd5d352be2365c69a0102498f1122b59a07498976a9083e` |
| `src/test/resources/ghidra/ControlledByteListingProbe.java` | `514c46474ed7a0f948ede56e5dfa3482250999a4a295db19ca94b8ff71ad8e24` |
| `src/test/resources/ghidra/ReferencedBytesProbe.java` | `2d5257f17cb9cbff6b4582c1cc8f56f4abbfd2384af0d32fc00e881a6d4e6ac5` |

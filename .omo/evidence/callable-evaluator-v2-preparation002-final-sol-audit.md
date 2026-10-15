# Issue #1507 final preparation-002 and archive acceptance — GPT-6.1 Sol

Verdict: **CLEAR** for the complete evaluator preparation/source checkpoint at the exact bindings below. All five live acceptance criteria now have matching local evidence, including actual creation and independent integrity verification of preparation-002. Issue #1507 remains OPEN pending the PR, required CI, automatic reviews and merge. This report establishes neither merged/released behavior nor measured model-candidate efficacy or production qualification.

Independent static/hash audit on 2026-10-14 after rereading the live [issue #1507](https://github.com/minsago-elite/decomp_thing/issues/1507) and milestone 16 scope. No source, archive, frozen artifact, earlier report, Git/GitHub or CI mutation occurred. No frozen source import/execution, compiler/helper/candidate execution, original candidate rerun, authenticated model call or authentication release occurred. Python syntax compilation and AST/code-object comparisons were performed only in memory without executing source or writing bytecode. Only this new report was written. Private expected declarations, names, types, values, cases and observations are omitted.

## Exact authority and archive bindings

| Artifact | Identity |
| --- | --- |
| Actual preparation-002 freeze | SHA256 `87be4f2e2c82a9ef6ca65a270f313b02924413245b693c40a4bc92ddd0977309` |
| Bound preflight-009 matrix | SHA256 `2100c5d13175d2187d4a86ed334165db79bef42490bc115ac1822d39a77d823e` |
| Canonical complete 1,725-file preflight inventory | SHA256 `d63752d0de1d103677c1b2fa76a6bdf06227320ffdd520bf6c004fdbf662debd` |
| Bound corrected implementation OKAY | SHA256 `0119b01cdc63e2f0fbcb65f54add2b45c07b8ea5af44838120c4c96eb0a84915` |
| Bound distinct pre-freeze CLEAR | SHA256 `12eb1d6ebc1b511e10b20e1289d05cc0e43a32c055b042b598fdb3e758d72188` |
| Separate post-create integrity CLEAR | SHA256 `89387ae993ea5fb20580a64f054e1281e29904f9327819c42900a851a0f19d0d` |
| Public redacted checkpoint receipt | SHA256 `a38502c0157f52210734a2732619ac552648d226250f6ba73ad9c881c7944cd7` |
| Exact 14-file source archive map | SHA256 `0da2aa7a4c35814b249039da47621a07b8ff6e9cf87cfdce097dfd9ca294a204` |
| Complete 17-file public archive map | SHA256 `8fef5a6a4e1743eb36db5a203493a23e20c7af9258d96d71bb5213682f1a17e8` |
| Source archive checkpoint commit | Git `e422d3a364b5c0f4f45196deaeb6b041bc0daa6b` |

The worktree is `.claude/worktrees/callable-evaluator-v2-evidence`; the public archive is `oracle/acp/callable-evaluator-v2/`. Canonical map digests use SHA256 of UTF-8 `json.dumps(pathToFileSha256, sort_keys=True, separators=(',', ':'))`. The source map uses the receipt's 14 repository-relative `archivePath` keys; the public map uses all 17 paths relative to the archive root, including README, receipt and safe integrity audit.

I independently compared all 1,746 sealed artifact files with the freeze's complete path/hash inventory, including absence of unlisted files. The entire 1,725-file frozen preflight matches the approved inventory and original preflight-009. All 276 execution dependencies and 74,066 external dependency hashes match; all 2,379 preparation paths retain prescribed sealed modes and none is a symlink. Both independent review copies match their separate approved hashes. The frozen visible prompt/manifest exactly matches the frozen profile; this check uses sealed artifacts rather than substituting current mutable profile files.

Every archived source was compared with its exact sealed source/snapshot and receipt digest, the current original, and the committed Git blob. All 14 match. The archive contains exactly those 14 source files plus the README, public receipt and safe integrity audit; no private fixtures, raw observations, full private reviews, binaries or generated private controls were added. The receipt and safe audit also match committed bytes. The archive is explicitly non-live and does not claim relocation or a portable qualification suite. Future use requires a new isolated namespace, separately restored private inputs and revalidated pinned tools; external tools were not copied into the freeze.

## EOF warning and execution completeness

The sealed `bounded_runtime.py` ends with two newline bytes: one final extra blank line. There is no literal EOF identifier or trailing executable statement. Its final AST node is a function definition. Removing only the extra final newline produces an identical AST and byte-identical marshalled compiled code object. Thus the reported blank-at-EOF format warning has no Python import or execution semantics; no source correction or new freeze is required for it.

All eight frozen execution Python sources and all eleven archived Python sources statically compile. The frozen execution modules' 47 import statements resolve to frozen sibling modules or the Python standard library; the process gate is an explicit child entry point and is not imported as a library. The legacy CLI source/case constants in `bounded_runtime.py` are not referenced by its runtime functions and do not contain callable oracle inputs. This resolves the concrete EOF concern without treating hash identity alone as proof of executability. The existing same-byte 20-test and 30-control evidence covers the reviewed original execution context; this static check does not add a relocated runtime qualification.

## All five acceptance criteria

1. **“Design a new versioned evaluator using actual AST declaration identities and layout evidence for named/anonymous typedef records and aliases. Reject unresolved/cyclic/unsupported forms explicitly; do not guess equivalence from spelling or source position alone.”**

   **Satisfied at this checkpoint.** The sealed helper resolves typedef edges, canonical declarations and definitions in one ASTContext and obtains size/alignment/field offsets from actual AST layout. Diagnostic spelling does not determine record identity. Local declaration IDs bind within-AST provenance; cross-translation-unit comparison uses reviewed structural descriptors and target/data-layout identity with GCC type/layout assertions. Named, anonymous and alias controls pass; unresolved, cyclic, unsupported and bounded cases refuse explicitly. The helper source is unchanged from the reviewed identity implementation and is exactly bound into preparation-002 and the archive.

2. **“State the exact candidate compiler/link/export contract in the visible prompt/manifest and enforce the same reviewed profile. Verify required public symbols without an unstated visibility condition.”**

   **Satisfied at this checkpoint.** The exact frozen profile is disclosed by the matching prompt/manifest and supplies the executed preprocessing, compile and link arguments. Compiler identity, target, flags, environment, limits, export/default-visibility contract and helper isolation environment are explicit. Recorded commands match. ELF export checks precede load and check required symbol kind, binding, visibility, definition and object constraints. Candidate compiler work and AST probing are isolated with the declared toolchain/helper mounts and no raw-host probe fallback; trusted expected probing has separate work.

3. **“Add compatible anonymous/named/aliased controls and retain incompatible layout/parameter/callback/varargs/missing-export/unsupported-attribute controls. No incompatible or unknown interface is called. Keep bounded runtime cleanup and behavior-mutant detection.”**

   **Satisfied at this checkpoint.** The bound current matrix is 30/30, including five compatible controls and the listed incompatible/refused categories. All refused interfaces/private-include attempts have zero launches/calls. The earlier independent acceptance verified actual retained sentinel denial for raw and preprocessed inputs, including preprocessing-success/compile-failure/probe-attempt refusal; the exact evidence is now copied and bound into preparation-002. All 56 isolated helper receipts, 264 runtime outcomes and 523 managed execution records remain bound. The 523 unique scopes comprise 28 top-level plus 495 control/descriptor records; reference observations are counted once. Behavior mutation, overinvocation, load failure, abnormal runtime, timeout, overflow and cleanup checks remain. Twenty focused tests pass separately; no historical or test executions are pooled into these control counts.

4. **“Freeze new evaluator/prompt/fixture/control bindings and independent preflight evidence before any new authenticated model trial. Do not edit the original attempt13 package, candidate or primary result; distinguish any later exploratory re-evaluation.”**

   **Satisfied at this checkpoint, completing the prior pending artifact gate.** Actual preparation-002 exists, binds the exact evaluator/prompt/fixture/control/preflight/toolchain inputs plus distinct implementation and acceptance reviews, and passes both its separate post-create integrity audit and this independent complete rehash. It records zero model calls, no authentication release and no trial authorization. All 3,637 historical file hashes still match the original preservation inventory. Preparation-001's original freeze, all 1,544 artifacts and sealed modes are unchanged; it remains superseded and semantically unusable. No historical candidate was executed or result reinterpreted.

5. **“Report compile/link/export/load/admission/behavior separately, including unknown/refused cases. Use no pooled success rate with prior CLI fixtures, no unsupported ABI/structural score and no production authority.”**

   **Satisfied at this checkpoint.** The bound evaluator/report schema separates preprocess, compile, link, exports, declaration/GCC admission, load and behavior, retaining unknown/refused/not-attempted cases. Nonadmitted cases have zero calls and null behavior rate. Callable evidence is separate from prior CLI/exploratory results. ABI accuracy remains unassessed, structural score null, and factory/provider/filesystem qualification false. Compatible control results establish evaluator controls, not model efficacy.

## Preserved history and remaining workflow

The original ITERATE report remains byte-for-byte SHA256 `7f646d5b1368b1b48bc2213e01012b3abc11f051aa58b871ca722802f9bc1860`; the bound pre-freeze CLEAR remains SHA256 `12eb1d6ebc1b511e10b20e1289d05cc0e43a32c055b042b598fdb3e758d72188`. The old freeze remains SHA256 `b322bf5a3506ba1e7b400ed6dff5acc3f293d022f8f49332f5b8881ab29e0595`. Preservation does not retroactively restore preparation-001's acceptance.

The complete local evaluator/checkpoint acceptance is CLEAR. Keep #1507 OPEN until its focused PR, required CI, automatic review resolution and merge satisfy repository policy. This report grants no merge, release, issue/milestone closure or authenticated trial authority. Adequate stripped-binary input bytes remain separately unbound for a useful later callable trial; #238/#964 and B1 production acceptance are not supplied by this evaluator checkpoint. No measured ACP candidate success/behavior/ABI result is claimed.

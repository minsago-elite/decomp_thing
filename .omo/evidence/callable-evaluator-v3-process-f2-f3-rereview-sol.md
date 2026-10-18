# Scoped A4 F2/F3 source rereview

Verdict: **CLEAR_SCOPED — F2 and F3 only.** Both prior findings are corrected in this exact held source generation. **F1 remains open and unimplemented.** The evaluator as a whole remains ITERATE; this is not full A4/#1507 acceptance, a usable-worker proof, a final composition, native qualification, a preparation seal, or trial/release authority.

Reviewer: GPT-6.1 Sol, independent of author; no descendants. Root retains source/Git/remote custody. Only this additive report was written. Python -B pure inspection/tests used fastjsonschema2.22.2 and an audit hook denying subprocess/system/exec/spawn/fork events. No actual evaluator build/run path, compiler/helper/native/real target/private fixture, model/auth/credential, Git/remote/Actions or CI polling was executed. The historical evaluator functions were not executed by this rereview.

## Exact held authority and preservation

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Artifact | SHA256 |
| --- | --- |
| `build/acp-decomp-effectiveness/callable-library-v3/static-process-correction-001/held-correction-receipt.json` | `b29384491d2212e6196da822cb7fb72601b967979907cb9b139945970ca22a8e` |
| Adjacent correction `report.md` | `8bc1d86224e99389aa6dd3fc25fe4e0d7df65663419953172d7857625f5fe20c` |
| Adjacent `run_correction_tests.py` | `f5fe25490364f512db3d8937dcffa0144c8899b77416867e98805d0fd6bff6ae` |
| Adjacent `tests-009.log` | `ef315e83d560828275d196865ad87b3e70e1639b7a149e6b2864d495b2fe57da` |
| Adjacent `test-results.json` | `ce8c88356ec08efabf0229d083f94d46695fa17a6614918b2ce9324b5710fb51` |
| Adjacent `template-baseline-copy.json` | `9777b16b9b6b123fca4c2731630e8f2f55217f0ed16d02dab4245e6d512596a0` |
| Preserved prior process ITERATE report | `366dc08e40fd2663080e07d714fd0648e94b9e2e91e600139f9e2b8a214b78ee` |

All20 owned path digests match:13public and7current trusted-template paths. Private bytes were only hashed, not printed/published or executed. The five correction evidence bindings above and both prior review hashes match. Three historical receipt files remain byte-identical at84333404/5f3e4dc4/f2ea345c; the historical/provisional snapshot is not relabeled as current qualification. Original process report bytes remain exactly366dc08e and were not appended or replaced.

A5 bounded traversal/copy/preparation changes are outside this scoped semantic verdict and belong to the independent A5 reviewer. Hashing their held files does not approve their behavior. F1's unchanged scope-gate source remains SHA256 `2514c327cb86ddb2e9aba1fe46f036dcc15ff4292dd72ca92c931f13bfec1dcc`.

## F2 — missing/malformed raw streams: CLEAR_SCOPED

`evaluate_candidate_v3.process_observation` no longer substitutes empty bytes for absent stdout/stderr. It retrieves each raw stream without a byte default, requires both to be bytes before completed=true, and normalizes absent/malformed streams to null hex. Each actually available byte stream is independently preserved. compare_process returns unknown whenever actual completion is false; it cannot manufacture an exact empty match from missing capture fields.

The report schema permits null stdoutHex/stderrHex for incomplete process evidence, but completed=true conditionally requires actual strings in both fields. All other positive completion proofs and explicit negative timeout/overflow/infrastructure flags remain required by normalization. Explicitly captured b'' is a bytes value, normalizes to empty hex, and remains a legitimate complete stream. This fixes the missing-versus-empty distinction without treating incomplete capture as candidate failure or deleting available partial bytes.

Independently verified both missing keys separately and malformed None/string/bytearray/integer/object/boolean cases for each stream. Every such case became unknown/completed=false; the valid opposite stream survived exactly. Explicit empty stdout with known stderr matched correctly. A complete report tampered to contain null stdoutHex refused schema validation. The targeted report regression also verifies24unknown processes,0completed, null processBehaviorRate and preserved available stderr. No empty denominator inflation was observed in these corrected cases.

## F3 — load/API closure: CLEAR_SCOPED

The load object is now a closed observation with required status/value only: status enum[unverified,not-attempted], value const null, additionalProperties=false. It is no longer the generic process phase object accepting passed/failed/refused/unknown. The emitter produces unverified/null when runtime requests exist, not-attempted/null otherwise.

`validate_exchange('report',...)` checks the exact load object against recomputed runtimeRequestCount after scenario/admission/counter validation. Thus a valid admitted/requested report cannot claim not-attempted load activity, and a refused/no-request report cannot claim unverified attempted activity. Unsupported load statuses, numeric values, and reason/evidence or other extra fields refuse. The emitted object and imported exchange contract agree.

Existing per-scenario load/API entry/completion/callback observation invariants remain exact unverified/null for admitted scenarios and not-attempted/null otherwise. API entry/completion/callback counts, API coverage/rate and formal structural score remain null. Targeted tests verified load-status tampering under both admission states and numeric API aggregate rejection. Additional independent checks rejected numeric per-scenario load/API/callback values and extra load claims. No trusted semantic event channel or independently authenticated load success was introduced.

## Verification and honest limits

Author's retained correction evidence records46focused pure tests,0failures/errors/skips. Its runner and final log/result bytes are bound above; this rereview inspected those records but did not rerun the entire46 or approve the A5 portion from that count. Earlier failed logs remain historical.

Independently executed exactly three current focused test methods with native launch audit denial:

1. `ProcessResults.test_each_missing_or_malformed_stream_is_unknown_not_empty_match`.
2. `SchemaMigration.test_missing_raw_stream_report_remains_unknown_without_empty_fabrication`.
3. `SchemaMigration.test_load_phase_and_api_claims_refuse_for_both_admission_states`.

All3passed,0failures/skips. An additional23bounded pure checks exercised stream types/presence/preservation, explicit empty matching, completed-null-stream refusal, all four per-scenario numeric internal observation refusals and load value/extra-field rejection. No source/test files were edited and all20held hashes were rechecked unchanged afterward.

The original high finding F1 is explicitly excluded: cgroup scope admission still precedes usable wrapped-worker proof. Fixing raw stream completeness and schema load vocabulary does not prove bubblewrap setup/caller execution or prevent a post-admission wrapper failure from being treated as a completed comparison. Do not remove the original overall ITERATE or claim all24native scenarios qualified from this scoped verdict. Fresh all-held composition, separately reviewed F1 design/implementation, native controls/preflight, machine closure, full acceptance and final seal remain gated.

## Exact F2/F3 source pins

| Path | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py` | `732f51df72b0bb6da1f4636c637c814cd8171df5e402f30a52613c91dfa18b5f` |
| `oracle/acp/callable-evaluator-v3/source/contracts/report-schema.json` | `5b37781b46bda1f1cbb9c10c5d569b397972c8e032ac356e52ddf855fdb89d3e` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_process_results.py` | `55b76c0c22416d0d82ddd7c4fe3b5d0778d8d33df555a9fe3742500ed6a8ae7b` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_schema_migration.py` | `3e8539eb7322ba575c295a15d8d82d9f85ba0f7201eebbdd1e242c7ae305ea8d` |

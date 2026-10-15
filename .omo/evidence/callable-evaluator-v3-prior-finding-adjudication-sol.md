# PR1514 prior-eight finding adjudication — observed source only

2026-10-14; read-only inspection. No tests/imports, native/qualification, model/auth, Git/remote operations or thread mutations. Root holds release authority. This is an observation of individually hashed current files, **not a stable current composition or native qualification**; runtime/evaluator files may be edited by their owners immediately afterward.

Input thread bodies: root `build/active-review-checkpoint/current-head-review-20261014/graphql.json`, SHA256 `8edcf7eb0c47b2efea238d68c90b82286ffaaa0700163a1e3e185bf59ae365bd`. All eight are unresolved in that captured GraphQL response. Original comments concern immutable historical v2 paths; the corrections below exist in the v3 successor, not retroactive repairs of v2 receipts or executions. Do not mark historical results qualified.

## Disposition

| Thread suffix | Adjudication against observed v3 source | Exact source anchors and retained evidence |
| --- | --- | --- |
| sMTPv | **Source defect corrected.** Same-layout identity collapse/split cannot pass by ordinary structural equality. | interface_gate_v3.py:293–300 uses both forward and reverse identity maps across roots, with compared-pair tracking. Retained207 log contains `test_distinct_equal_layout_records_cannot_collapse` and `test_repeated_identity_cannot_split` (lines5,15), both ok. Identity review's additive rereview is CLEAR for corrected A1, not C++ execution. |
| sMTPy | **Original forged-marker authority removed; requested authenticated load/API events remain OPEN.** Do not describe this as implementing a trusted semantic event channel. | evaluate_candidate_v3.py:143–150 compares exact stdout/stderr/termination;153–160 emits unverified/null load/API/callback observations. Marker bytes are neither removed nor authority. Retained207 `test_marker_bytes_are_never_stripped_or_authority` line91 is ok; process F2/F3 review explicitly confirms no trusted semantic channel introduced. New exec/terminal proof authenticates worker lifecycle, not API entry. Source mitigation is real; full thread wording's stronger channel remedy is not fulfilled. |
| sMTP2 | **Static resolver/API defect corrected; complete actual implicit-GCC-input qualification remains OPEN.** Not sufficient to close the full toolchain-capture demand. | pin_environment.py:25–49 rebuilds link/monitor/inspection closures with shared resolver and exact equality. link_inputs.py:570–605 expands recorded dry-run, scripts/specs/configuration/search selections and requires all four startup names plus libc/libgcc selections. Retained207 `test_full_static_closure` line59 and `test_startup_library_tools_specs_content_changes` line75 are ok; A3 revision2 review CLEAR is explicitly static, not authentic complete native inventory. Supplied recorded input completeness cannot prove actual GCC consumption, headers, link trace or loader choice. Status remains static-recording-unqualified. |
| sMTP8 | **Source defect corrected.** Integer rank/kind retained independently of width. | interface_gate_v3.py:14–20 maps exact kinds including long-long;219–222 validates builtinKind;409 reconstructs that spelling. Retained207 `test_same_width_distinct_integer_kinds_refused` line24 is ok, plus builtin test11 covers exact spellings in generated fields/arguments/returns/callbacks. A1 corrected review covers this distinction. |
| sMTQD | **Source defect corrected.** Equality compares expected completed termination, including nonzero exit and signal, rather than demanding zero runtime exit. | evaluate_candidate_v3.py:143–150 compares termination; completion is authenticated separately. Retained207 `test_exact_nonzero_and_signal_completed_termination` line87 and schema `test_nonzero_reference_binds_actual_selected_preparation_and_raw_receipts` line121 are ok. Compile/link zero-exit requirements are separate admission rules. |
| sMTQI | **Source defect corrected.** Descriptor/file limits are disclosed and enforced from immutable public profile. | contracts/candidate-build-profile.json:60–61 declares64 descriptors/16777216 file bytes; build_contract.py:79–81 names both RLIMIT mappings; bounded_runtime.py:581–588 requires exact profile limits and applies them. Retained207 `test_complete_rlimits_are_disclosed_and_applied_exactly_without_host_policy` line33 is ok. A2 review CLEAR is static/mock evidence, not actual native limit enforcement qualification. |
| sMTQN | **Source defect corrected.** Missing receipt/incomplete observation remains unknown; aggregate unknown is not automatically candidate failure. | evaluate_candidate_v3.py:143–146 returns unknown on incomplete process;183–193 retains unknown count and unknown behavior unless a known mismatch exists. Retained207 `test_all_unknown_and_all_matched_and_refusal` line82 and `test_known_mismatch_survives_unknown` are ok; launcher-failure controls also retained. This does not claim a new current runtime integration run. |
| sMTQR | **Source defect corrected.** Each GCC side starts unknown, exceptions affect that side, final status requires both passed and retains partial checks. | evaluate_candidate_v3.py:507–526 initializes expected/candidate unknown, catches per-side failure, recomputes aggregate, and retains checks. Retained207 `test_incomplete_expected_gcc_keeps_declaration_and_both_checks` line89 is ok. Thus a completed expected side cannot fabricate candidate completion. |

## Exact observed current pins

Paths relative to `oracle/acp/callable-evaluator-v3/source/`. The last column is a byte-hash comparison with retained public207 inputs.json, not execution of current files. A DIFFERS value means207 must not be cited as testing that entire new file version; the report uses inspected current code plus the specifically retained regression evidence only.

| File | Observed SHA256 | Compared with207 |
| --- | --- | --- |
| `interface_gate_v3.py` | `9238e9bcb93a0ef188a8defb8393b5a5f1b90cb7c40b43e7fa2ac04dfad92c54` | same |
| `record_identity_probe.cpp` | `0cc97a9eeb4eda5bb09f2a600eabee867299b756fe8364f02deeb7d77e85cb57` | same |
| `evaluate_candidate_v3.py` | `6c326c36bd7aead6e1702a262e39dc585226f87cd4734fb9ee67f6bc409fdad6` | DIFFERS |
| `bounded_runtime.py` | `914fd4188b0619af732b9816f1a3cadbd78ef043598e68dfde463fae423cc11f` | DIFFERS |
| `build_contract.py` | `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85` | same |
| `contracts/candidate-build-profile.json` | `c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f` | same |
| `toolchain-001/pin_environment.py` | `fb650456d802e5dd5195668a1efc8a88ef914cb59582c8b58ea54b7aa6181e82` | same |
| `toolchain-001/link_inputs.py` | `a1fb0950e2500747a5f01c6319d45a522323ecbcc33b535e7ef262241f338f1e` | same |
| `toolchain-001/monitor_inputs.py` | `0cab347a7874162840bdda8b0dc138782657ddaf592b8e3a51b3c59c731838d1` | DIFFERS |
| `tests/test_identity_graph.py` | `0a48ee2f00e97c4f3be079443b711dc82b65f266fd872994324b104b2d3bdbf2` | same |
| `tests/test_builtin_types.py` | `3ebce53833f421ff51a7fc539c0d8ce67c8d9aae64eaf14ff48c6cfedcdbf0a8` | same |
| `tests/test_process_results.py` | `0036eeab129a41babda3b83c5a0143d53cdc5582b09db5d0fecfaaafeb51aa4a` | same |
| `tests/test_profile_limits.py` | `1aabc8724a1b81b6f0e0e82e5547dd168b98a735c69f44ebd0e99a2d853a6e83` | same |
| `tests/test_link_inputs.py` | `08e1083786da646f9c4214a093cef2a81b6c3ec5ddcfcd0512b6c3e18b39f471` | DIFFERS |

## Evidence authority and limits

Retained public207: `build/v3-composed-static-20261014-r3/inputs.json` SHA `ee7954954683512aad616a6367e2b5721c44019847b5a181af3cd6462e04fe2b`; `combined.log` SHA `7d15574a6fcd8b4885a7a3ba99054e17cdfaf7dba1133275fd4cc7d6ec50443e`. Existing independent integration review verified207 distinct ok test IDs, zero skips/errors/failures/forbidden attempts for its42-file snapshot. This adjudication inspected log text and source; it did not rerun those tests. Later PLT and DSO-role changes have separate bounded pure evidence and do not convert207 into a new composition.

Component reports read (each includes its historical restrictions and any additive terminal correction):
- `.omo/evidence/callable-evaluator-v3-identity-source-sol-review.md`: `431c07f363289b07653d8fb3dd1e0fe942e9ae68d136c3343a0b26db0ec93cbb`.
- `.omo/evidence/callable-evaluator-v3-link-inputs-source-sol-review.md`: `09bed49b182468826213c0f760aa543b79d272a7d9149c71a3eedefa32e46d39`.
- `.omo/evidence/callable-evaluator-v3-profile-source-sol-review.md`: `fe2b3839c1f0dffb219a9e71a3fdd04603f094e01b3ea1b9061534c201a8a5ae`.
- `.omo/evidence/callable-evaluator-v3-process-f2-f3-rereview-sol.md`: `6deca383f9ec5805bdc184d2434bb0f3bddc0b0c91ce6f6865d4fdf86f4148a9`.
- `.omo/evidence/callable-evaluator-v3-static-integration-20261014-r3-sol-review.md`: `1e3f092cc0f0382dc973e7e84b22a0395d66fb819c5f00be0ac6961777acfddc`.

Conservative closure recommendation: six source regression findings (sMTPv/sMTP8/sMTQD/sMTQI/sMTQN/sMTQR) are substantively corrected in the successor with specific retained pure controls. sMTPy's false-marker claim is corrected but its stronger authenticated semantic-event goal remains open; sMTP2's source capture mechanism is corrected but complete actual inventory qualification remains open. GitHub resolution is root's decision and must explain v3 supersession and these remaining gates. No thread was resolved or replied to here.

End-of-report rehash: all listed pins unchanged during this observation window; no future stability claim.

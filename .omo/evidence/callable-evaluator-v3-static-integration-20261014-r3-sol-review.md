# Public static integration r3 — independent Sol review

## Terminal: CLEAR for exact test correction and retained public207 composition

Read-only source/evidence review,2026-10-14. No tests, compiler, JVM, native/qualifier/process experiments, source edits, Git or remote operations performed. This is local public static qualification of the bound source snapshot, not a hosted rerun, compiled-C claim, native/full24 qualification or candidate/seal authority. Compile-only001/002 evidence remains separate.

## Bound inputs

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`. Source prefix: `oracle/acp/callable-evaluator-v3/source/`. Retained run prefix: `build/v3-composed-static-20261014-r3/`.

| Input | SHA256 |
| --- | --- |
| r3 inputs.json | ee7954954683512aad616a6367e2b5721c44019847b5a181af3cd6462e04fe2b |
| r3 combined.log | 7d15574a6fcd8b4885a7a3ba99054e17cdfaf7dba1133275fd4cc7d6ec50443e |
| r3 integrity-after.json | 312fa9d495b997be3f988667de82786c30e214c69f0f7e51232801d6f7cc7d98 |
| r3 public/build/callable-evaluator-v3-static-ci/result.json | 726f4de979f90b29b852b94bb40f98f84b310fc469dac04fc022979b7c4f9d19 |
| tests/test_runtime_worker_proof.py | 5e8c7e192c43986e441e17ed4e198212f4b6254adf3f70d18fd7a35ecdf20426 |
| build/v3-4a07-static-portability-correction/source-freeze.json | 40f5f41e9d26ae522f7786e3dc60f00d9428de5eed5d138d40362cfd50216832 |
| toolchain-001/monitor_inputs.py | 82ce234cc994c25ca2b1eb77875172a6837e2baca15c945d4766b1e96dd7ab28 |
| tests/test_link_inputs.py | cc19b7fc11ce66264e1a02d0a8c6d3036330594eae664f8c9ed898ed445533aa |
| .omo/evidence/callable-evaluator-v3-x86-plt-metadata-source-sol-review.md | 18ecad309bcc698b5dbf4423bf047a38c9dd6fcdf2495986ea959016cdacde97 |

Independently matched SHA256 and size for every one of the42 source files to inputs.json, and byte equality for every corresponding public-stage copy. Root integrity-after records42 inputs, no changes, exit0, elapsed18.156577789020957 seconds. Comparison with r2 finds exactly the three changed paths listed above, matching inputs.changedSourcePaths. No production runtime, contract/profile, gate, execution inventory or runner drift is hidden by this report. Portability freeze's18 evidence files also match hashes and lengths. Its older sourceInputs differ from r3 only at the two explicitly accepted A3 paths; it is not misrepresented as the final global source freeze.

## Actual hosted error addressed

Preserved diagnosis `build/v3-4a07-hosted-static-diagnosis/diagnosis.md` SHA256 `a896d7ba620eff086cf5c9d51fec19cda24f4727899ece88769d616abc7bd8cd` binds head4a07 and synthetic merge5d012088,204 tests/one error. Its failing pure method called `probe_command`, which called execution-side `build_contract.profile()` and rejected the runner's GCC identity.

The textual delta in `test_existing_probe_and_runtime_mapping_semantics_are_retained` is only the scoped mock around the real probe-command/recipe-parser call: `interface_gate_v3.profile` delegates to `build_contract.load_profile`, `build_contract.digest` raises if host-tool hashing is attempted, and `assert_called_once_with()` requires the declared profile seam. Independently compared ASTs with that one method removed: identical. The actual command constructor and runtime recipe parser still run; original worker argv, target, chdir and all-RO assertions remain, as do subsequent runtime/phase mapping assertions. This removes precisely the accidental host-tool identity dependency rather than changing the contract under test.

Production `build_contract.py` remains `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85`; its execution-side path/hash guard at94–100 is unchanged. The fixed candidate profile remains `c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f`; production runtime remains accepted003 `604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07`. No mode, native visibility, bound or identity relaxation appears.

## Actual retained public execution

Parsed the retained log accounting for unittest's wrapped docstring line:207 distinct test IDs, all `ok`, including the exact previously failing recipe method. Log terminates `Ran207 tests in17.703s`, `OK`. Result.json independently reports207,0 failures/errors/skips/forbidden attempts and no forbidden events, fastjsonschema2.22.2, Python3.14.8. All12 explicit modules are present with counts:

`identity20, builtin6, contracts3, probe-isolation2, profile16, link34, process14, schema32, runtime11, worker-exec55, consumers11, inventory3`.

The three additions are the separately reviewed A3 metadata controls, increasing link31 to34. The runner's explicit module list and NativeDeny implementation are unchanged from reviewed r2; `qualify_worker_exec.py` is a sealed source input, not an auto-discovered or executed native suite. A3 acceptance here is limited to the exact independent18ecad review: metadata-envelope acceptance does not establish runtime dependency graph or operational/native success; its separately documented libc-interpreter readiness blocker remains.

## Public staging and retained history

Observed all42 expected public source files. Outside them, the staged source contains only an empty generated0600 `exec-proof-receipts/64c6a4b35442419b9309a46699570c7b/worker-proof.jsonl`, SHA256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; this is inert test state, not authenticated worker evidence or a copied input. Outside the source subtree the stage contains only the generated static result. No symlinks, private/expected/history/preservation directory or environment/machine pin payload was observed. The unchanged authored public historical_counterexamples.py remains public fixture code, not private history.

Prior r2 review remains `.omo/evidence/callable-evaluator-v3-static-integration-20261014-r2-sol-review.md`, SHA256 `03f30697ecd5d2f272a4ca01442d252081ed39e44c088cf4eedeba26b67a194b`. Historical hosted error and the portability author's failed custom11-method harness observation remain preserved; neither is relabeled a pass. Root's subsequent actual fresh207 run supplies the new composed evidence. Required CI at the next head and every independent native/closure/full24/final-seal gate remain outstanding where applicable.

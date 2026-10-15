# Strict consumer002 corrective peer rereview

Verdict: **OKAY — scoped consumer002 source correction.** The two findings from prior review75a5345907faf6f767ea55138894353bc9bfc29a632f9aeb8acc48a69ee83f97 are resolved at the consumer/producer-contract level described below. This is not independent approval of the runtime author's implementation, whole composition, native capability, preparation or trial release. Runtime003 is separately reviewed by its independent owner. No new blocking consumer finding was found.

## Exact reviewed checkpoint and preservation

Consumer manifest15c657fcbb2c20279c9df52a96262ef65ebd8e67373ebf3bf841cda3d9e33180, under build/acp-decomp-effectiveness/callable-library-v3/static-process-f1-002 in this evaluator worktree. All six immutable source-freeze copies and live source bytes independently match the manifest. Only evaluator and two test modules differ from001; the two exchange schemas and CURRENT prepare template remain exact prior bytes.

I read source/evidence and calculated hashes only. No tests, native/process/worker/CLI/preparation/qualification, Git/remote/auth/model/network operation was run. No private source/caller/cases were read or moved. The only new file is this report; runtime003 and all existing freezes are unchanged. Prior consumer001 manifest53f3539b02b2fe8724e6cfc0ead11fb0ff5254cb4e6bdf8c0ba5a3d068b6f797, its runner/result/log, and prior review75a53459 were rehashed unchanged.

| Path relative to evaluator worktree | SHA256 |
|---|---|
| oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py | `ff929649380c8c58ffb81a34088bfe95931b1609856e8edb7551f6d5e105999c` |
| oracle/acp/callable-evaluator-v3/source/tests/test_process_results.py | `0036eeab129a41babda3b83c5a0143d53cdc5582b09db5d0fecfaaafeb51aa4a` |
| oracle/acp/callable-evaluator-v3/source/tests/test_schema_migration.py | `4442b565f5b63c5130b8804f4d47c559dcfc2cb86f77bdc7ac31d5ee975e0cb2` |
| oracle/acp/callable-evaluator-v3/source/contracts/report-schema.json | `3251ec9868217cb58117205582d6b921d34fea80ed01ffb50ec74b1473fbd724` |
| oracle/acp/callable-evaluator-v3/source/contracts/reference-observations-schema.json | `e880d87f286452f24391df36277954bc6ca1a9355ad31380990fcc774f19b4f8` |
| build/acp-decomp-effectiveness/callable-library-v3/templates-current/prepare_v3.py | `29064349ffe37979773aaaf203d8445fed3902dc9fc711986f4969a64389a9b9` |

## Prior F2: independently selected current reference inputs — resolved

The new required validated_observations(path,caller,preparation) argument is selected by the coordinator, not observation JSON. evaluate passes its existing independently supplied visible/preparation directory. CURRENT prepare still constructs caller at output/caller, reference SO at output/reference/libcandidate.so, observations at output/reference-observations.json, and passes that output as visible. There is no new candidate-selected fallback.

At evaluate_candidate_v3.py:321 onward, preparation must be canonical and inside BASE; caller and observation path must equal the fixed preparation names. The expected library is derived as preparation/reference/libcandidate.so before reading receipt metadata. Caller/SO are bounded-admitted through freeze_v3.admit_files with a two-file/shared32MiB scope rooted at that preparation, using existing nofollow/nonblocking regular-file/parent identity/hash machinery. The independently admitted rows provide exact dev/inode/mode/SHA, rather than trusting caller-supplied pin text.

Reload requires metadata's exact caller/library paths and hashes to match those independently selected records, and requires current original.c and exact current candidate profile hashes. Every normalized reference row still requires protected proof/controller completion, correct scenario identity/family, bounded streams, matching raw retained receipt hash and normalized equality. _bound_runtime_inputs additionally compares each row's complete caller/SO pin with the admitted current records and binds caller target dev/inode/hash. After all24 rows, the inputs are re-admitted and must equal the full initial records, detecting changes during replay.

The old nonexistent-SO positive is removed from the actual reference reload test. The held replacement test creates real authored caller/SO files and real bounded pin-reader metadata. It covers raw receipt drift, changed caller/source, missing SO, unchanged SO bytes at a distinct allocated inode, refreshed valid input identities, changed SO bytes, a supplied nonexistent path, wrong independently selected preparation and stale profile. These are parser/filesystem fixtures, not real exec proof. Wrong current path, missing file, physical identity, bytes, mode or generation cannot be repaired by merely changing receipt.libraryPath to a self-consistent value.

General validate_exchange fixtures remain synthetic and structural. They do not authenticate arbitrary JSON as real kernel evidence or replace validated_observations with an independently selected context. The author explicitly retains this trust boundary and the final qualified-machine/preparation gate remains unchanged.

## Prior F1: actual mounted input-pin producer/consumer seam — resolved conditionally on independently accepted runtime003

The exact47-test dependency is runtime604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07 and runtime proof-test7ea3ee8f13dadbaf3e16f99cca6517b1465574544638ab3f13ddbb8cd95d5ff3, matching runtime003's held manifest74ed6295aa471cf0a591f8f217266d074b607b97f8a33aa07a79e9c305ae150e. Producer _prepare_launch now includes actual explicit regular recipe-mount sources in the common _pin_files batch; caller/SO are not excluded as mere non-executable inputs. Consumer required fields remain genuine actual input rows and are not synthesized during consumption.

The focused runner includes the single runtime-owned test_actual_prepare_launch_pins_all_explicit_recipe_files_for_consumer. It calls actual _prepare_launch and actual bounded _pin_files on authored mounted inputs and passes produced caller/SO rows to this consumer with a separate actual pin-reader admission map. It checks runtime SO and source/header rows plus unchanged-byte new-inode, changed and missing SO. Mocking is confined to fixed monitor/tool metadata selection and the two fixed host launch-tool inventory entries; no SO/source/header row is injected. This directly addresses the earlier fixture-only gap, while making no claim about actual native ELF loading, C monitoring, complete toolchain provenance or capability.

This consumer review accepts that interface contract and the source/evidence showing its actual producer use. It does not substitute for the independent runtime003 cleanup/pin/monitor rereview or native qualification.

## Preserved F1 boundaries

Raw proof replay/shared completion still requires exact normalized worker wait status and SHA, complete controller/scope/capture/wait/cleanup/absence facts, runtime phase and declared profile. Failed launcher transport, missing/malformed/tampered proof, absent streams, timeout/overflow, provisioning-only and unknown cleanup remain unknown. Worker termination is not launcher status; normal139 remains distinct from signal11. Behavior equality still uses exact streams plus normalized termination, excluding per-attempt IDs/hashes.

Dedicated private per-phase leaves, exact RO source/header/intermediate overlays, fixed /work compiler operands and unchanged contained caller/reference/runtime routes remain. No controller/BASE/output tree is newly worker-writable and no direct host candidate fallback is introduced. Schemas remain closed; internal API/load/callback claims stay unverified. Runtime/source/environment hashes retained in JSON are correlation data; trusted receipt-store/source checkpoint/admitted generation and final qualified-machine gates remain necessary authority. No static recording is upgraded by this review.

## Retained evidence and dependency drift

Existing47 focused pure controls report0 failures/errors/skips/forbidden attempts with before/after source inventory equality; I did not rerun them. Evidence hashes independently match:

- run_focused.py1669c9ca2b00f62fa503c4f87eaf679465f741481f30e8cbe9168e32f6a11f0d
- test-result.json5cd8183dec40da9ce96c13e2bfad579a56882fe80af522425098caa1d0d25c31
- focused-tests.log1b5224f906f1ba8f233c58d3742594c6e9660939b016901cf4dc89e848d64c79
- author report28e3b63af5abfaa8114ee133282b8a13a501739467501db600f314653895f383

Later qualifier/test changes are separately observed below. The retained47 run does not cover those current bytes, and this review does not approve those separate source corrections:

```json
{
  "oracle/acp/callable-evaluator-v3/source/tests/qualify_worker_exec.py": {
    "current": "755298604542ce98ee3e8e9529808e27d09e824adb0e4950d0a45810d78d45eb",
    "tested": "6975b1d6166154370b05dcf596500282adb9eb11ae390aa7da61ce7ac7ac08ec"
  },
  "oracle/acp/callable-evaluator-v3/source/tests/test_worker_exec_proof.py": {
    "current": "5b16d52f2c2f6c2f986438c48eac21ebb87cdae4b1b7e3fe1ecd5f210a0663c3",
    "tested": "470d7248f5b93b64cee91b18c127d4a7eebd2ca5b8c3dec9ce17d0aa13dd3426"
  }
}
```

Stop after this source rereview. Root owns composition inventory, Git/remote, independent acceptance and any future explicitly authorized native controls. Existing source-only/qualified-machine/trial boundaries remain in force.

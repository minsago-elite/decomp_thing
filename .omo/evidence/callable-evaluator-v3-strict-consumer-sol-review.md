# F1 strict consumer peer review

Verdict: **ITERATE** — two source-backed integration/binding defects below. This review does not authorize native execution or qualification.

Reviewed frozen consumer manifest53f3539b02b2fe8724e6cfc0ead11fb0ff5254cb4e6bdf8c0ba5a3d068b6f797 in build/acp-decomp-effectiveness/callable-library-v3/static-process-f1-001. All six source-freeze copies and their live counterparts matched the declared pins at review. I read source and existing evidence only; I ran no tests, native/worker/CLI/preparation/qualification, Git/remote/auth/model/network operation, and read or moved no private source/caller/cases. The only new file is this review.

## F1 — P1: real launch receipts omit the SO pin required by these consumers

Consumer evaluate_candidate_v3.py:301–316 requires each completed runtime process launchInputPins to contain both the caller and library exact path/hash. validate_exchange invokes this for completed reference/report processes at21–49. CURRENT prepare_v3.py:49–64 uses a separate reference/libcandidate.so input, then immediately validates the completed observations.

But the exact tested runtime dependency bounded_runtime.py122bbf6cc0c64dd3286cd1b685f00a53429e58dd6ba93249bb33c9b2c91bb610, _prepare_launch:588–607, builds its common pin list from target caller, bwrap, monitor, fixed source/policy files and monitor runtime dependencies. It never adds the regular-file recipe mounts other than the target executable. The reference/candidate SO mounted at /library.so by runtime_command:232–238 is not the caller or a reachable dependency of the independent monitor. A genuine otherwise completed runtime therefore has no libraryPath entry, and the consumer refuses it with runtime input file binding missing or changed. Reference preparation cannot complete its positive path under this producer/consumer composition.

The pure fixture masks this exact gap: tests/test_process_results.py:27 explicitly invents a synthetic SO pin before deriving the receipt's launch-pin digest. Those authored fixtures test the consumer but cannot demonstrate that the real producer emits its required input closure.

Required correction: the runtime owner must admit and pin every actual explicit regular-file recipe input, including source/header/intermediate/helper/library inputs as applicable, under the shared existing bounds before launch and revalidate the same admitted inputs after cleanup. Keep exact RO mounts and do not fabricate library rows in consumers or fixtures as a production repair. A pure producer/consumer control must construct the actual _prepare_launch recipe with an authored SO and show that the resulting genuine prepared inventory satisfies the consumer, including changed/replaced/missing input refusal. Native execution remains separately gated.

## F2 — P1: reference reload never authenticates the current reference SO

validated_observations:319–345 verifies actual current original.c, caller path/bytes and profile, plus each retained raw reference receipt hash and normalized equality. It does not verify that value.libraryPath exists, belongs to the expected reference preparation, or has actual bytes equal to value.librarySha256. _bound_runtime_inputs:301–316 compares this supplied library path/hash only with another supplied pin row. It validates the caller target identity specially but establishes no independently expected SO identity.

This omission is explicit in the held positive test tests/test_schema_migration.py:89–104: it writes the authored caller and raw receipts but sets libraryPath to /synthetic/libcandidate.so, creates no such SO, and expects validated_observations to accept24 rows. The fixture's synthetic library hash/pin is enough. This is source-backed behavior, not a newly executed counterexample.

Consequently stale/missing/reference-from-another-preparation SO metadata can remain accepted by the reload path whenever its normalized/raw receipt metadata agrees. An existing caller/original.c/profile check does not establish which shared library generated the oracle process observations. The fix must bind an independently expected reference SO admitted record (canonical preparation path, actual bytes/identity or authenticated sealed inventory mapping) and current source/profile generation before accepting reference observations. Refuse missing, changed, wrong-generation and relocated SO inputs; preserve valid nonzero/signal worker behavior. Replace the nonexistent synthetic-SO positive with an authored real file/admitted record and negative variants. No private fixture execution is needed for these controls.

Related boundary to make explicit during correction: workerProofBindings environment/source/parser/manifest/launch-config hash strings are retained, but the shared structural binding predicate only checks their syntax/internal relationships; consumer _bound_runtime_inputs checks profile and caller/library rows. It does not compare those provenance hashes against an independently expected preparation closure. Do not describe raw JSON replay alone as authentication of arbitrary report files. The reviewed admission/inventory/source checkpoint must supply that authority; a self-consistent hash string or protected-file boolean copied into JSON cannot self-upgrade it. Final sealing currently remains blocked by freeze_v3.require_qualified_pin, so this review makes no claim of an existing qualified production bypass.

## Checks that are correctly preserved

- _proof_replays:80 and observation_complete:128 replay the bounded raw proof and shared completion predicate; claimed term/exit/hash disagreement, missing controller facts, provisioning-only, bad wrapper, timeout/overflow and unknown cleanup do not become completed behavior.
- Runtime phase is required for scenario observations, and run:241 additionally checks requested phase and exact current profile hash. Launcher status is separate from worker wait normalization; behavior comparison uses streams and normalized termination, not attempt/PID/proof-hash equality. Per-attempt changes are permitted only for independent completed observations, as intended.
- new_worker_leaf:255 and compile_sequence:278 use private dedicated leaves and exact RO source/header/intermediate overlays with unchanged /work compiler operands. CURRENT caller build:36–43, reference compilation:45–49 and runtime:55–56 use contained routes. There is no direct host candidate fallback. Leaves are retained rather than erased under uncertain worker absence.
- Schemas close the process/proof/binding objects, bound proof hex and pin counts, require exact completed controller fields, and keep unknown normalized termination null. API/load/internal activity remains unverified. These structural controls do not repair F1/F2.

## Evidence and scope

The retained46-test result reports0 failures/errors/skips/forbidden attempts. I verified its evidence hashes and did not rerun it:

- run_focused.py6030809df1060d7a0ba50e79874fddf8fe3818317fd68ca497e0bde953a7518c
- test-result.jsonac97667cf6128d0402a564041b548bd3bc93178a80465b0910904238bfb245b2
- focused-tests.log852c2f89e92769b4db5d484568fc8ddedbdb33fced426e4d54461938d5617d2c
- author report6310ecb09292c3bc3346728696200f3871c1d3fa3a8708790157be3da12fc457

Six exact reviewed sources:

| Path relative to evaluator worktree | SHA256 |
|---|---|
| oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py | 5470048943eea8b7198334a4b4ae431ea245a26c844f4e136350a81e9277cd86 |
| oracle/acp/callable-evaluator-v3/source/tests/test_process_results.py | 6947bcbb7111d36a2b6583a2de73197a2263ff7a816d6a54f18fbc89f325072b |
| oracle/acp/callable-evaluator-v3/source/tests/test_schema_migration.py | f16684101f99e1c3d2a899a4e48fb731a23f158f929995dd129bb9237b14a26e |
| oracle/acp/callable-evaluator-v3/source/contracts/report-schema.json | 3251ec9868217cb58117205582d6b921d34fea80ed01ffb50ec74b1473fbd724 |
| oracle/acp/callable-evaluator-v3/source/contracts/reference-observations-schema.json | e880d87f286452f24391df36277954bc6ca1a9355ad31380990fcc774f19b4f8 |
| build/acp-decomp-effectiveness/callable-library-v3/templates-current/prepare_v3.py | 29064349ffe37979773aaaf203d8445fed3902dc9fc711986f4969a64389a9b9 |

Post-test dependency movements observed at review are separate from those frozen consumer bytes. These current bytes were not exercised by the retained46-test run:

```json
{
  "oracle/acp/callable-evaluator-v3/source/tests/qualify_worker_exec.py": {
    "current": "6975b1d6166154370b05dcf596500282adb9eb11ae390aa7da61ce7ac7ac08ec",
    "tested": "07e7a4da85ff2e22183b5309a973489a1e7120358faba4a933e704185927dc2c"
  },
  "oracle/acp/callable-evaluator-v3/source/tests/test_worker_exec_proof.py": {
    "current": "470d7248f5b93b64cee91b18c127d4a7eebd2ca5b8c3dec9ce17d0aa13dd3426",
    "tested": "5dca4e16dc8ce684723acc71ef0eef75d2be3a9317b40a8d129f05620a4745fa"
  }
}
```

The process/schema source checkpoint is not a whole-composition or native qualification. Keep all existing freezes/evidence unchanged. Correct F1 in the runtime owner's additive generation and F2 in the consumer owner's additive generation, then independently review both and run only the authorized finite pure composition. Stop before any native release.

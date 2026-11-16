# Clang fixture and OCI reference checkpoint

Refs issue1480; runtime closure thread remains open because retained probe dependencies are not included. Acquisition and strict expiry refusal remain unchanged.

## bounded-summary.md

SHA256 `b518ed510501b9e1438f67fde72e72b61c72a675709fe5e6207bd6184a4dad10`

# Bounded correction freeze

Standalone verify-probe accepts optional --fixture defaulting to the reviewed fixture, reads regular bounded evidence, requires selected bytes to equal the pinned fixture and emits fixtureSha256. Missing/changed selected fixture refuses before report output.

OCI producer and verifier share canonical reference name. Verifier rejects missing, changed, renamed, extra and wrong-type annotation maps even with recomputed outer archive identity.

Added independent runtime-closure omission regression with a matching successful package control. The adversarial record and loader report are self-consistently rehashed and validate before package-time actual dependency replay rejects omission. Discovery is mocked for inert offline evidence. This does not establish retained probe closure: current production roots exclude PROBE_BINARY_IN_ROOT and rsuIG remains unresolved.

Verification: all 179 offline tests pass in 5.010 seconds; git diff --check passes. Old HEAD/current controls show standalone fixture and annotation regressions fail old source and pass current source. Logs: bounded-offline-tests.log; bounded-old-current-controls.log. No privilege, acquisition/native qualification or Git/GitHub mutation.

Frozen SHA256:
- provisioner: 34961c31067396f99a584336094216a777f2a9c9d9b14ab6ca6fa5c55fd37a5c
- tests: 297db450d37b4f7c0b4836fe210d0fb0fc90bb2259579b745350b620f0cfad82

Broad plan Revision 2 is design-only and awaits independent rereview. Host identity/package payload/loader production execution remains fail-closed; acquisition pause and current-clock expiry refusal are preserved.

## focused-sol-review.md

SHA256 `e023f51d382b6ab086858903cbf59102a4a5efa68896d06e2d396c797501edd9`

# Focused independent code/evidence review

Verdict: CLEAR for standalone fixture identity and canonical OCI reference annotation. Runtime omission regression is bounded evidence; full runtime-closure thread remains unproved.

Exact SHA256 freeze:

- Script: `34961c31067396f99a584336094216a777f2a9c9d9b14ab6ca6fa5c55fd37a5c`
- Tests: `297db450d37b4f7c0b4836fe210d0fb0fc90bb2259579b745350b620f0cfad82`

Reviewed dirty diff, relevant command/validator/helper paths and worker old/current controls. Independently reran all three focused tests after the runtime positive control was added: 3 passed, no failures/errors/skips, 0.401 seconds. Output is in `focused-sol-tests.log`. Worker `bounded-old-current-controls.log` demonstrates fixture/annotation tests fail on the previous implementation and pass on the current one. `git diff --check` independently passed. No source/Git/GitHub mutations or privileged/native/bootstrap/acquisition execution occurred.

## Standalone fixture — CLEAR for rsfo7

`verify-probe` defaults to the recipe fixture and accepts explicit paths only when captured regular-file bytes exactly match the captured recipe fixture. Those selected bytes supply fixtureSha256 alongside source/binary fields. Evidence reader uses bounded no-follow regular-file reading; missing/changed fixture rejects before output publication. Tests verify complete default/explicit successful output and missing/changed rejection. This binds the report fixture and does not claim independent execution or loader snapshot protection. No scoped findings.

## Canonical OCI annotation — CLEAR for rsuIK

Producer and verifier share OCI_REFERENCE_NAME. Verifier requires exact annotation-map equality, rejecting missing, renamed, changed, extra and wrong-type annotations even after outer archive identity is recomputed. Test contains a successful canonical control. Existing duplicate JSON rejection remains active. No scoped findings.

## Runtime omission regression — partial evidence only; do not resolve rsuIG

The test first successfully packages a matching inert fixture, removes its output, then shortens runtime entries and rebuilds manifest and loader projection. It explicitly validates the shortened record/report before packaging. The real verify_recorded_runtime_closure helper rejects the mismatch before probe execution or output. This proves comparison wiring with a positive setup control.

runtime_dependencies remains mocked to return prior complete entries. The test therefore does not prove real ldd discovery, complete roots, symlink/target or changed-byte replay, extra-row rejection, or real execution isolation. FRONTEND_RUNTIME_ROOTS still contains both drivers and two API libraries, with no retained probe. No runtime production change is present. Follow-up must settle complete roots and exercise real discovery/parser over inert filesystem fixtures and controlled rootfs_run outputs, with positive and mutation controls. No native authenticated closure qualification follows from this test.

Broader plan remains ITERATE; host-tool immutability, authenticated payload exception policy and loader snapshot protocol remain unresolved. Acquisition pause and strict expiry refusal remain unchanged.


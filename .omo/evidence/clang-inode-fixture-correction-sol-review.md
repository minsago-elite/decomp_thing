# Independent Clang inode fixture correction source review

Verdict: **CLEAR** for the exact narrow test-only correction. No blocking defect found. Full234-test/hosted CI and broader Clang qualification remain separate gates. Acquisition pause, expiry/trust policy and production publication checks are unchanged.

Reviewer: GPT-6.1 Sol, independent of root's implementation; no descendants. Source/evidence/hash/AST inspection only. No tests rerun; no privilege/native/target/compiler, acquisition, credential/auth/model, Git/remote/Actions/CI polling or source changes. Only this additive report was written. Root retains source/Git/remote custody.

## Exact reviewed bytes

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-59`.

| Input | SHA256 |
| --- | --- |
| Current `oracle/clang/18.1.3/test_provisioning.py` | `bd40e2e05217a535f7deb5943e058f16b87765fb553ed269fa85eb707e25b138` |
| Unchanged production `scripts/oracle/provision_clang_18_1_3.py` | `f5bb2417c845802a782ec23b749674b3ac879109e3f4b1c90f233055e1e9e65d` |
| Exact e376 hosted test baseline captured in root diagnosis | `90b81628592a9e56617500fab462988533b91de9f4b8a5888bf38c7ceb47750a` |
| Root prior diagnosis `build/clang-e376-hosted-diagnosis/diagnosis.md` | `9680603938f0ef0587a9cee7ecd8f5b6255118bf832bcc9c2dca9f08c63c8081` |
| `build/clang-inode-fixture-correction/focused-test.log` | `ddad58b8c0c1d451fbdc62e1eaf25af52922904d62723ac247984655b25741a1` |
| Adjacent `result.json` | `46ec05e1fed6cdbecd5143809e381c0d8466c9970f539fffc2eeb7b3ec461dbe` |

All bindings were independently checked. The whole production file equals the exact hosted baseline digest; there is no production fallback, guard/message or acquisition/trust change. Full textual comparison of the test file shows only the replacement setup and new same-inode case inside the existing publication regression. AST comparison confirms other existing function definitions are unchanged; the only altered existing definitions are this test and its nested substitution helper. The prior diagnosis and hosted evidence remain unchanged.

## Distinct replacement case

At test_provisioning.py:3069–3077, the fixture retains the published file while creating a separate staged same-size attacker file, sets its final0444mode, and asserts distinct device/inode before os.replace. Both files coexist when the identity assertion is made, so the new fixture cannot accidentally recycle an already freed inode as the old unlink/immediate-recreate sequence did. Atomic replacement then presents the distinct inode at the destination path.

The exact inode-guard refusal assertion remains at3088–3089, rather than broadening the regex to hide whichever guard happened to fire. Source original-byte and replacement attacker-byte assertions remain at3090–3091. The modeled root-owned stat/fstat behavior is retained; no privileged publication or ownership manipulation is required by this local fixture.

## Separate same-inode byte guard

At3093–3107, the new case creates its own authenticated source/destination, invokes the existing simulated publication, then writes equal-length attacker bytes through r+b without unlinking or truncating the inode. It restores0444mode and explicitly asserts unchanged device/inode/size. This deterministically isolates the content guard from the metadata guard.

At3117–3120 it requires the exact changed-bytes ProvisionError and preserves assertions that the source remains original while the destination contains the tampered bytes. Thus both independent production refusal paths are meaningfully covered: distinct-inode replacement and same-inode/same-size mutation. The new test does not treat the expected refusal as accepted publication and does not weaken root UID, mode, type, parent identity, hash, EOF or descriptor cleanup checks.

## Retained focused result and limits

The retained actual unittest invokes the one existing publication regression, now including both controls. Log/result agree:1test,0failures/errors/skips, and the receipt binds the exact test/production digests above. Root reports the inline harness installed subprocess/exec/spawn/fork/system audit denial before import; result.json records no native events. This review inspected the result and source without rerunning the harness. A complete independently retained runner script is not supplied, so this report does not inflate the receipt into broader execution qualification.

The entire234-test suite was not repeated locally. Required Actions at the next exact pushed head must still exercise it and all required reviews must resolve before merge. A passed mocked publication fixture does not prove privileged/rootfs/native/toolchain compatibility, runtime/OCI reproducibility or release qualification. The previously paused acquisition and strict expired/signature/fingerprint rejection remain intact because production source is byte-identical.

**CLEAR** means this exact test-only fix addresses the diagnosed filesystem-allocation dependence and is suitable for root's next normal checkpoint/CI gate. It grants no source mutation, remote action or additional execution authority from the reviewer.

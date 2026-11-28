# Clang/master composition — independent Sol review

**CLEAR for the reviewed staged merge composition only.** No whole-project execution, final-head CI, native/toolchain acquisition or overall Clang host/payload/loader qualification is granted. Root retains merge/commit/push custody; new-head required CI and automatic review remain gates.

## Exact reviewed state

Worktree `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-59` remains in merge, with:

- HEAD/Clang: `33aec5e437172a3f1364a9ed70fb74f40ae5d536`.
- MERGE_HEAD/master: `7898a6b3009d2a47bc33be4aafc4b970db079029`.
- Merge base: `76aac4a317a3efba2f00d5880386bb51a4d30147`.
- SHA256 of exact `git ls-files --stage -z` bytes: `635a42e3ada86653ec4fc8f718312f30cba8338c7f9c671ac76a7fcd90699ce3`.
- Root receipt `build/clang-remaining-review/master-composition-verification.json`: `b48a64a4272a427abad210f6b3a36eb855c9e45a30259d331972647c8ae1cfe2`.

The index has58 staged changes relative to Clang HEAD, no unmerged stage entries and no unstaged tracked change. Existing untracked evidence is preserved. This report is not staged.

## Independent full-index preservation check

Compared every tracked path's Git mode/blob identity across base, both parents and stage0, without creating Git objects or replaying the merge. Of2112 paths:2019 identical between both parents;55 master-only changes;35 Clang-only changes;3 changed on both branches. Every identical/one-sided path exactly matches the required parent's mode/blob, including additions and absent paths. **Zero unexpected losses or substitutions.** All35 Clang-only paths remain exact Clang HEAD; every master-only change is retained.

The only three both-changed files are `AcpAgentHarness.kt`, `AcpAgentHarnessTest.kt` and `fake_acp_v1_agent.py`; each staged blob exactly equals master. Read both base→Clang changes and Clang→index deltas: accounted stdout EOF/reader retention and uncooperative readiness controls remain; master additionally retains its accepted cancellation diagnostics/checkpoints and cooperative readiness acknowledgement. The sole conflict decision75→79 preserves master's actual complete test set. No reviewed Clang behavior was discarded to choose that count. Master’s existing RequestedAcpCancellation visibility is imported unchanged, not a new composition relaxation.

## Reflected-test inventory and authority pins

Independently rehashed all five reflected test classes and verified index=working file=exact master:

| Class | SHA256 | Source @Test count |
|---|---|---:|
| AcpAgentHarnessTest | `9df9b2e0efa0cd77dbe36630a409279291ba3bf0797c8ffbcbb8f75caf583cf5` |45|
| AcpPermissionPolicyTest | `5f6c9425a548974f607b00d19af01baa49cb59154270d4b3389cc16ea7fc376d` |5|
| AcpSandboxPolicyTest | `b78ea085115e6a7aceec10f47dc1ad3e15bd362325c03cb7c8a2bbe3a03d62b8` |4|
| AcpTerminalBrokerTest | `d2247fb8003c6564b891d5c45a05970b9a013d5f884c7023be741a194b319c97` |6|
| LinuxBubblewrapBoundaryTest | `b9bf75b3d3d1a4e9f475cfff87ce54bc2f96cd2d726dee4fa15d6acccbe87cdb` |19|

Total79 source annotations agrees with the reflection guard at AcpAgentHarnessTest:469. Its exact five-class selector and void-return assertion remain. This source count is **not** a newly executed reflection/JUnit proof.

Production Harness SHA256 `eadc59762696f89860c0804ac976ad549c261bcf13b052474a00826d66c85e19`; Terminal SHA256 `3d81b455fb526f10546a6faca893bcf10bcb1a9dd82e4b69b08b984e275f019c`. Both staged blobs equal master exactly. `AGENTS.md` SHA256 `4a2ab001977778cdef9b7e154e2d4f51b129f13b802f14bea4f9704579e3553a` also equals master; no instruction changes were introduced.

## Existing Clang checkpoint preserved

All four working/staged source files independently match both Clang HEAD and the reviewed journal/transport pins:

- `scripts/oracle/clang_18_1_3_journal.py`: `7a41958f96c4843d894f945c83976a3b2787d3c4b8bf066ec304d2b076e2b7a4`.
- `oracle/clang/18.1.3/test_journal.py`: `e53ddfb5b0da31de27c11025c7b0c73992cec9e2a1137a68a19caa3f2ece1c91`.
- `scripts/oracle/clang_18_1_3_transport.py`: `b6563082935f7d1602d09aa796a9379d67582ca8d18cc11326499ff232f80a41`.
- `oracle/clang/18.1.3/test_transport.py`: `ab3f3a84a347311aea3fb5b81a51b8da17defa228e1a25074dae8d9c889f7385`.

`journal-v2-freeze.json` hashes `3e7679742e665a9a5d545eb78ebe3163c37dc04a19a38da12118a94330f675ba`; `transport-v2-rev2-freeze.json` hashes `7d98ce4f0654aae2257dd8496b8b2bec641bf81dd5eff1401e7cc942becf7ff6`; root checkpoint receipt hashes `b6185b0ba4f435a6ec7fe2163d5cd73dea118249d7ddc4cb940983233518abb4`. Prior independent journal review `ae98f26a1d04d47f11ee29f5a25584858a5856fbd3fdcb63bbaeede5e9b47158` is byte-preserved. Retained logs report13 journal and14 transport passes; this review ran neither again.

The prior J1 ITERATE and its terminal narrow CLEAR remain historical evidence, with active lifetime binding and durable reopened-job reconciliation retained. Installed deployment/peer/source lifetime authentication, physical quota, trusted marker/post-intent reconciliation, helper ownership, actual acquisition/runtime/OCI/reproducibility and full host/payload/loader acceptance remain unproved. Strict acquisition pause and expiry refusal are not lifted by importing master.

## Method and limitation

Read-only source/evidence/Git-object/index/status checks and inert Python -B hashes only. No source/index/Git/remote/Actions/auth/model/native/target changes or executions, no descendants, no live execution session. Only this report was written. This is a conflict/preservation review; it does not repeat the already-reviewed broad master changes or claim fresh full composed CI qualification. Revalidate exact index/parents if root changes the composition before committing.

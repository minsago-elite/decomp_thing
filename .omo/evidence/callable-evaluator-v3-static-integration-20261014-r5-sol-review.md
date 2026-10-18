# Independent Sol integration review: public static r5

**Verdict: CLEAR for this exact public-only composed static checkpoint.** Retained r5 is228 tests across13 modules, zero failures/errors/skips/forbidden attempts. No blocking finding in the fixture-only correction or composed evidence. This is not native qualification, actual candidate acceptance, hosted CI qualification or a seal.

## Exact reviewed evidence

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`. R5 root: `build/v3-composed-static-20261014-r5/`.

| R5 artifact | SHA256 |
|---|---|
| `inputs.json` | `4d30b6502b40e5109472abf0535aa9ba5af9935ad8efdb88d8ee31491233ad03` |
| `integrity-after.json` | `bd0759b90d6ef0462c5bc905eabb2618b06e759d231498c781f46c5f110c72dc` |
| `combined.log` | `dfbade1528421237eb8714a68d1b18c68bf31d8499ba28190369e023cecdb4e8` |
| `public/build/callable-evaluator-v3-static-ci/result.json` | `fd9723bdff47a3ac5870f1275ab87a278597ab05f3efd7393ea6f62a604d788e` |

Fixture002 freeze `build/runtime-admission-receipt-fixture-correction-002/source-freeze.json`: `e7645065f89af14f52aec692bd00093c9ffcd56333c482c58ec0d4fe9b5b9544`. Changed test `tests/test_profile_limits.py`: `7399f911bbf3c68070592b77990d09e06f00a35be3cae08c5470598fa718e3f9`.

## Independent integrity and accounting checks

- Rehashed all43 current source inputs and their43 staged public counterparts against `inputs.json`, repeatedly including immediately before this review write. Every size/hash matches. Catalog paths are unique and the r4/r5 catalogs have the same43 relative paths.
- Compared every r4→r5 input fingerprint: only `tests/test_profile_limits.py` changes. Production runtime `038379a2840db54fedfc872de04c637980b387f5ad0b561772abf00f3f5d14fe`, gate `60d2ee157cd7b4a04124c22279a4c219a93c0f2b510f72ce2bfbd759ffba190a` and runtime-test `f766b6d5c426c533b584b4cabadf5072ccf9e6cc37cccba02e5c281b8e21e45d` remain the independently cleared source. No runtime refusal was relaxed to make r5 pass.
- Rehashed all fixture-freeze evidence, preserved r4 evidence and unchanged production/runtime-test pins. R4 remains226 tests, zero failures, **four errors**, no skips/forbidden attempts; its result/log/integrity are preserved, not relabeled passed.
- Parsed actual test IDs from both composed logs: r5 has228 unique IDs; per-module counts exactly equal the result JSON and sum228. Every r4 test remains, with exactly the two named fixture controls added. R5 profile18/runtime19/candidate-leaf8 counts are present. The13 nonempty required modules match the runner catalog.
- Root's r5 integrity receipt records exit0, source/stage unchanged and43 files. The actual combined log ends `Ran 228 tests` / `OK`, consistent with the result. Python3.14.8 and fastjsonschema2.22.2 are reported; these are this run's observations, not machine-input/native qualification.

## Why the fixture correction is valid

R4's four errors were complete mocked worker/provisioning/cleanup paths reaching the real receipt reclaimer with an incomplete simulated directory. The retained old-fixture reproduction has verified284-byte proof and positive absence facts, then explicit `receipt inventory incomplete` refusal with no deletion. This is not evidence to remove production checks.

Fixture002 now constructs the same owned empty0700 Python-cache/device/inode metadata as real prepare, and private0600 gate/admit files as real admission. Synthetic pipe labels are moved away from real opened-file descriptors. The read dispatcher consumes fake stream buffers only for those labels; other descriptor reads pass through the saved real `os.read`, allowing the real bounded receipt re-read. Kernel/process/launch operations stay mocked. Production proof consumption, close and reclamation predicates run unchanged; there is no forced success or reclamation skip.

Independently AST-compared all16 original test methods between retained before/after: all bodies and assertions are identical. Only fixture helpers and two added methods change. The new positive control requires report FD closed, exact directory actually removed, expected worker/provisioning distinction and preserved proof/public behavior bytes. The new negative deliberately removes `admit` and requires real refusal, no deletion, directory retention, infrastructure unknown and preserved already established worker absence/termination/raw facts. Thus success is not achieved by hiding incomplete layouts.

The runner's coordinator-owned change adds `test_candidate_leaf_lifecycle` to MODULES. It is included in this43-input composition and its eight controls actually execute according to the log; no private template/package inclusion follows. This review does not claim ownership of that runner edit.

## Scope and remaining gates

Retained public runner installs NativeDeny before imports/test execution, retains its audit hook and records zero unexpected forbidden attempts after its explicit synthetic guard self-check. The passing228 are source-only synthetic controls with mocked native/kernel operations and authored repository fixtures. They are not228 native scenarios and do not discharge original24 semantic positives/mutants, actual machine-input closure, native monitor/bwrap qualification, hidden-source isolation, hosted qualification or final immutable preparation/seal ordering.

No tests, native/tool/qualifier processes, source changes, packages, auth/model, Git or remote operations were performed during this review. Existing failed logs and all reviewed source remain untouched. Only this additive Markdown review is written; root retains commit/remote/execution custody.

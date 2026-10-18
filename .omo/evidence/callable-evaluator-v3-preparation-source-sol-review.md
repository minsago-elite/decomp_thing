# Independent A5 preparation/seal/template source review — GPT-6.1 Sol

Terminal: **ITERATE** on the held A5 source checkpoint. One concrete resource-bound defect remains in inventory/copy preparation. The existing static qualification gate is correctly fail closed; no actual final seal is currently possible. This report does not claim a composed source freeze, native preflight, historical candidate result, complete #1507 acceptance or preparation approval.

Reviewer is independent of the source author, uses GPT-6.1 Sol only and spawned no descendants. Root retains sole Git/remote custody. No source edits, Git/remote/CI/native/compiler/helper/candidate/model/auth/credential operations, package acquisition or actual preparation seal occurred. New write: only this report. Narrow in-memory synthetic checks extracted two pure functions from held source; no composed imports or private oracle execution was used.

## Exact bindings and scope

Held outer receipt: `build/acp-decomp-effectiveness/callable-library-v3/static-process/held-a4-a5-receipt.json`, **5805 bytes**, SHA256 **`84333404410efdaeaa6d4c38b43887139d519fca2c59a9c1e827dc92dec0316f`**. All **20** owned paths were independently hashed; all matched before inspection and again at report creation. Thirteen public files and seven trusted template/support paths are distinguished by that receipt. The scope here is freeze/preparation schema and the seven trusted paths; A4 process/report semantics were reviewed separately.

Approved plan: `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`. A1 corrected scoped review `431c07f363289b07653d8fb3dd1e0fe942e9ae68d136c3343a0b26db0ec93cbb` is preserved. A2's scoped limits review is not a full runtime qualification; A3/A4 composition remains pending. Original provisional source checkpoint `f2ea345c19f9a45ac1a4ec66763871a36cdeaac887ecb7e7d38a4a900bc872dc`, source-evidence receipt `5f3e4dc4ef7b206e67ddb68eeab160c03ca6149ae50f74b112ee3b5185fa4edc` and outer addendum `97cce65b70eb323b96498edddf43e432461a88e6f66d8bb4caa00d0a96e5de6e` remain historical/provisional, not substitutes for a final all-held snapshot.

Paths below are worktree-relative. Hashing private files did not print their bytes; this report omits private declarations, values, inputs and expected observations.

| A5 reviewed file | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/freeze_v3.py` | `aaa3b29b7f35b3b90dd77dfeb8b6fb63504d9092937a366278e6e1bbe93389ca` |
| `oracle/acp/callable-evaluator-v3/source/contracts/preparation-schema.json` | `513eb1c2099182081f256e992cc3899e5998879d75d388f922daba74510ad850` |
| `build/acp-decomp-effectiveness/callable-library-v3/prepare_v3.py` | `92ee79c79261a068e0cfc190a827418711f385449f814677f33cc3d74a738c7a` |
| `build/acp-decomp-effectiveness/callable-library-v3/generate_controls_v3.py` | `f1278ee5e8e12826645b4375224a2e23c527563ac8fce21c9971bcbf4cac286d` |
| `build/acp-decomp-effectiveness/callable-library-v3/preservation-manifest.json` | `1810cca1765dce0331da198c0a037ac9c0e241fbd516751dddde3e2fcc0760c2` |
| `build/acp-decomp-effectiveness/callable-library-v3/private/caller.c` | `4a2ac0c0d3d271c9bba3c1a3c8dd9ff11a56d2527de6b2b893efd8527618498f` |
| `build/acp-decomp-effectiveness/callable-library-v3/private/cases.json` | `af3a0eb6b53f933145f13794a1fe8b11ea9e59fbec8a94c909b20a4db822ada3` |
| `build/acp-decomp-effectiveness/callable-library-v3/private/original.c` | `dda77e7efbd187a8336da71844b5ba6f279e9dc111cb04e5969522bd4ded46c8` |
| `build/acp-decomp-effectiveness/callable-library-v3/private/original.h` | `151ed89b74cdcb9378264a5bd56140046cf215da6acb2adfb48d956d6f77043b` |

## Blocking A5 finding: limits apply after whole-tree enumeration/allocation

`freeze_v3.py:13–20` implements `inventory` as:

```python
for path in sorted(root.rglob('*')):
    if path.is_file():
        total += path.stat().st_size
        if len(files) >= 20000 or total > 536870912:
            raise ValueError('inventory resource bound exceeded')
```

`sorted` consumes and retains the complete recursive enumeration before the first count/byte test. Thus the 20000-file/512-MiB checks do not bound enumeration memory or traversal work. Nonfile entries have no charged limit. The function is invoked on the candidate/control preflight tree at line 100 **before** `require_qualified_pin` refuses static pins, and again around final copy checks. The current refusal-to-seal gate does not make inventory itself bounded.

A pure test of this exact AST-extracted function used 50000 synthetic sortable entries, a constant digest stub and no real files/native imports:

| Synthetic case | Observed result |
| --- | --- |
| 50000 one-byte files | All 50000 yielded before the first `is_file` check; only afterward raised `inventory resource bound exceeded`. |
| 50000 nonfile entries | All 50000 yielded before first check; returned empty inventory with no traversal refusal. |

This demonstrates ordering of work and allocation, not an executed large filesystem attack or measured production RSS. The defect remains at smaller or larger file limits because the entire iterator is materialized first.

Required correction: enumerate with explicit charged traversal/entry and file/byte budgets before unbounded collection or hashing; enforce depth/entry work where directory growth is otherwise unchecked. Preserve deterministic inventory semantics by sorting only the bounded admitted population or using an equivalently bounded traversal. Refuse unsupported tree kinds and symlink-following before copying rather than relying on a late post-copy mismatch; `shutil.copytree(..., symlinks=False)` at line 116 can otherwise follow a tree that the initial inventory did not recursively account for. Reserve/check copy population and aggregate bytes before materializing output. Align the admitted final inventory with the preparation schema's 10000-artifact bound, or explicitly reserve separate preflight/final scopes so a larger preflight cannot consume work and then fail only after copying.

Add exact/one-over synthetic entry/file/byte/depth cases and a proof that an oversized iterator is stopped before complete enumeration; include unsupported/symlink tree refusal using authored repository-local fixtures. This is a narrow source fix. No actual native preflight, universal filesystem tracer or historical package replay is needed to verify it.

## Sealing and qualification behavior inspected

The key current authority guard is correct: `require_qualified_pin:49–54` rejects `static-recording-unqualified` and then rejects every other status because typed qualified machine closure is explicitly unavailable at this checkpoint. The reviewer extracted and called only this pure guard with:

- A static pin plus `Native qualification: **QUALIFIED**` text: refused as static-only.
- An invented qualified status plus the same text: refused because reviewed typed machine closure is absent.

A Markdown qualification claim cannot produce a seal through this source. This is an honest incomplete Phase B capability, not production qualification and not permission to patch the guard to accept a status string. A future typed machine closure integration needs its own exact source/evidence review, including A3's actual API and revalidation. The currently unreachable Markdown review/qualification and copy branch is not thereby qualified as a complete production sealer.

The intended order otherwise follows the plan: exact source checkpoint and execution bindings; complete source population/hash checks; helper schema/binary copy checks; exact policy/control coverage and candidate receipt hash checks; recomputed scenario/accounting; preflight inventory; qualified machine closure and revalidation; exact independent implementation/preflight and distinct acceptance artifacts; preservation; copies; full output/hash verification; then final JSON and readonly sealing. Missing/stale checkpoint or bound source/helper/control data refuses before output creation. Public-source execution cannot seal because a trusted v3 build copy is required. Independent reviews remain human/control-plane evidence, not a claim that matching strings authenticate independence by themselves.

`preparation-schema.json` is closed version 3 with false/null no-trial/no-model/no-production fields, exact reviewed bindings and explicit `externalDependenciesRequireReverification`. It labels preservation narrowly. Final copy verification compares the complete expected map and rechecks the preflight and toolchain, rather than merely trusting a producer file count. The resource issue above must be fixed before those checks can be described as bounded.

## Trusted templates and preserved scenario/control scope

All seven trusted paths in the held receipt are exclusively under the build namespace. No private caller/source/header/cases or coordinator/generator was copied into the public v3 source archive by this checkpoint. They must remain trusted-only in later copies and release packaging.

The new cases metadata contains exactly 24 sequential IDs. `prepare_v3.py:48–50` checks both IDs and the full family sequence against the evaluator's required family sequence before generating observations. The new caller retains one native loader path, resolves the six required public symbols and contains none of the three old diagnostic marker strings. Source inspection and metadata/hash checks support preservation of the scenario/caller contract; no private scenario value was published or executed. The current source pins, not a new historic candidate result, bind this work.

The generator's finite policy retains five compatible identity/alias controls, the real behavior mutant and overinvocation/abnormal/timeout/overflow cases, all original layout/parameter/callback/varargs/export/attribute refusals and private-include controls. It adds constructor marker/early-exit and constructor-crash controls. The matrix consumer does not use old marker counts or marker-absence predicates. Positive controls require all 24 process comparisons matched with no unknown rows; mutants need a known mismatch; refused/unknown interface controls require zero runtime requests and 24 admission-refused rows. None of this proves native results have already occurred.

Fresh references are produced in the new generation under the same caller/runner/profile. A completed nonzero reference is not discarded solely for being nonzero; the coordinator uses process completeness and stores the raw receipt digest (`prepare_v3.py:51–61`). Both reference/candidate raw-byte preservation and process-completion classification still depend on the reviewed A4 corrections; A5 does not certify those inherited predicates.

## Shared A4 blockers and historical preservation limits

The independent parallel A4 review is ITERATE, report `.omo/evidence/callable-evaluator-v3-process-source-sol-review.md`, SHA256 `366dc08e40fd2663080e07d714fd0648e94b9e2e91e600139f9e2b8a214b78ee`. Its three findings are material to future A5 preflight: scope admission precedes a usable wrapped-worker proof, absent raw stream keys can become empty exact matches, and an unsupported passed load phase is accepted. I coordinated that handoff and did not duplicate its process-math/native review. No accepted matrix or completed-process label in this held source can override those findings. The present typed-qualification hard gate prevents actual seal; composed native qualification must wait.

The preservation manifest contains **nine locked template input paths**, not a complete inventory of preparations 001/002, attempt13/candidate/results and prior archives. `verify_preservation` checks that map, and the output honestly says `preservationScope:locked-template-inputs-only`. That scoped fact must not be promoted to full historical preservation. Existing complete historical preservation evidence and unchanged-package checks remain required before full acceptance; this review did not read old private oracle content or rerun any historical candidate. No source mutation of historical packages was observed or performed here. Keep the semantic withdrawal and all earlier physical preparations/reports intact.

## Verification and disposition

The retained author receipt reports 29 owned pure tests and 75 observed shared tests. Those counts are source-test observations, not native, composed or preparation qualification. I read the relevant schema migration/sealing tests and source, hashed all held paths, and performed only the four pure checks above against AST-extracted `inventory`/`require_qualified_pin`. No global current dependency set was asserted or imported. A3 revision-2 review and A4 corrections remain separate work.

**Final disposition: ITERATE** on held receipt `84333404410efdaeaa6d4c38b43887139d519fca2c59a9c1e827dc92dec0316f`. Fix the inventory/traversal/copy resource ordering and return a new exact owned-file hold. Preserve the static-qualification hard refusal, the full accepted-matrix/review-before-final-seal order, all private boundary restrictions, and the original physical/history evidence. Native/compiler/helper qualification, real typed machine closure, corrected composed process semantics, full independent acceptance, final preparation and CI remain open.

# Independent Sol plan review: GCC source/build ownership inventory

Terminal verdict: **ITERATE**.

Reviewed plan: `.omo/plans/gcc-source-build-ownership-inventory.md`

Exact SHA-256: `c48fa34e6bd5135cb429f672b1bb152a5c3e48e47b2902de5c7e304efcfd0608`.

| Supporting snapshot | SHA-256 |
| --- | --- |
| `build/gcc-source-build-ownership-planning/inputs.json` | `08d782eb3eae097985b2805549b0c5ecf9549c701c9436ad8926ea761f273c39` |
| `build/gcc-source-build-ownership-planning/local-input-locations.json` | `4209f57beb707a9c5b907489e2083bcc99ed361d45f0c1bd080a2c3ed2e98d1c` |

This review covers the complete seven acceptance criteria and trusted-oracle separation clause of the supplied live #1513 snapshot (OPEN, A6 milestone 10). One production-qualification gate requires correction before approval. Only this report was written. No source, Git, remote, Actions, authentication, model, acquisition, build, JVM or native operation was performed for this review.

## Blocking correction: remove the unconditional three-build gate

Plan lines 51, 71, 75, 79 and 103 require a fresh unobserved clean baseline and two separately captured clean builds, with all three reproducing the pinned pair. This is stronger and substantially more expensive than #1513 acceptance criterion 6, which requires actual pinned-driver production evidence and **two deterministic replays**. The criterion does not require three fresh full builds.

No concrete remaining risk in this plan justifies making all three production builds mandatory. A complete authenticated captured build already has to reproduce the exact locked rich/stripped bytes and independently prove its action/input/object/link/owner closure. A fresh unobserved build would add another output-equality observation, while lacking the captured provenance needed to compare action closures. A second production capture would test cross-run build/instrumentation variation, which is distinct from the required deterministic evidence replay. Neither can substitute for a qualified complete collector, versioned inputs or independent ownership reconciliation.

**Required correction:** make one qualified authenticated actual build/capture that reproduces the complete pinned pair the production evidence gate, followed by two independent deterministic reconstructions/replays from the authenticated raw evidence with the existing separate Kotlin verifier. Both replays must fully reauthenticate/read/rederive the relations and totals; repeated summary-hash comparison is insufficient. Exercise supported process scheduling, generated inputs, file versions and instrumentation noninterference on proportional authored collector fixtures. Require another full capture or unobserved driver baseline only when a specific failure, instability or unresolved observation justifies it, and record that reason before running it. Update all five affected passages and the acceptance mapping consistently.

This correction does not weaken any source/tool/runtime/collector admission, full pair equality, complete action/dependency/object/link/CU/declaration/use coverage, resource, isolation or independent-verifier gate. The offline contract/parser checkpoint remains startable while the plan's production repeat policy is corrected.

## Acceptance coverage

| #1513 requirement | Reviewed coverage |
| --- | --- |
| Closed source/TU/build/role/variant identities | Lines 31–41 and step 1 define separate file/action/compile/object/link/ownership relations, content/role identity preimages, raw execution multiplicity and a reviewed schema/profile gate. Path-derived A13 IDs are explicitly rejected for repeated compile variants. |
| Complete authenticated compile/object/link inventory | Steps 2–3 require admitted exact source/runtime, original commands, effective descendant environments, immutable consumed versions, generated/header/tool closures, archive order/member multiplicity, link selection/discard/provider evidence and action reconciliation. Compdb/log integrity is not execution authority. |
| Physical-CU/declaration/required-use ownership | Step 4 reconstructs object/archive-to-final DWARF and relocation contributions, all 111 final CUs and every relevant physical obligation. Split/type/supplementary/LTO/generated/header/external cases need actual support or affirmative absence proof. Occurrence ownership and nominal equality remain separate. |
| Exact retained pair and independent complete totals | Steps 2–5 require full rich/stripped identity, manifest agreement, positive complete owner coverage and separate file/action/object/CU/declaration/use totals. A different or merely code-equivalent pair cannot replace the pinned artifacts. Missing/extra/duplicate/conflicting joins and membership-changing owner ambiguity block completion. |
| Canonical bounded Kotlin authority | Separate versioned canonical relations, raw receipts, policy/implementation/review roots and independently implemented Kotlin verification are required. Existing LLVM-scoped verifiers are not relabeled as GCC authority. The proposed budgets have explicit aggregate accounting, lower existing-authority limits and refusal gates. |
| Actual qualification, repeats and meaningful negatives | Actual retained evidence, two deterministic replays, authored mechanism fixtures, semantic/input substitution controls, exact/one-over bounds, independent review and required CI are covered. The additional unconditional baseline plus two captures is the blocking excess identified above. |
| Immutable independent pre-score handoff | Step 6 freezes ownership separately from candidate models, nominal identity, ledger completeness, model admission, scores and release authority. Changed owner/variant policy requires a new version and qualification. #692/#46 retain their full acceptance. |
| Trusted oracle/source isolation | Step 5 requires enforceable namespace/mount/descriptor/transport restrictions and actual authored-canary include/macro/probe/environment/log/prompt/archive/web/child-process controls through existing isolation owners. Neither visibility flags nor successful compilation suffice. |

No acceptance item is replaced by the already cleared physical source-obligation/scalar diagnostic checkpoint. That checkpoint supplies useful authenticated coordinates and observations, with no source-TU, semantic denominator, model or seal authority.

## Inputs and exact source checks

I independently compared all seven snapshot input blobs with both exact Git objects, `fae856cec8f7dc8df6fe6bfd92075651966da2ca` and `05b073fc8378bd2faaf0ee4163cf055ba61e11da`. All 14 byte lengths/hashes match, and embedded contents match where retained. These include the source lock, build record, reproduction lock, Dockerfile, historical rebuild runner, artifact-verification documentation and workflow.

The available worktree root `.claude/worktrees/gcc-observable-abi-ledger/oracle/gcc/16.2.0/` contains regular, non-symlink files that I independently hashed:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `artifacts/gcc-driver.full` | 20,713,760 | `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` |
| `artifacts/gcc-driver.stripped` | 2,349,296 | `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |
| `oracle-manifest.json` | 60,269 | `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| `source-lock.json` | 3,953 | `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc` |
| `build-record.json` | 3,910 | `f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637` |
| `toolchain-reproduction.json` | 1,568 | `5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de` |

Source archive/signature and OCI/runtime availability are accurately limited: the plan has cache metadata and bounded local-directory observations, not authenticated payload availability or a daemon/image result. It does not interpret the `510c` image ID as a pull URI. Expiry/missing payloads go through the existing authorized acquisition owner; neither a guessed checkout nor a different source generation can substitute.

The inspected exact source supports the cited capability limitations:

- `oracle/gcc/rebuild_oracle.py:257–265` only accepts the historical build-record image ID. Its `:310–358` reproduces configure/compile/install/stage/strip and checks the full manifest. The plan correctly requires a new Kotlin bridge rather than loosening that equality or promoting the Python runner to new authority.
- `oracle/gcc/toolchain_reproduction.py:143–218` authenticates recipe/build-record bindings and the inspected image's platform, ID, creation value, canonical Config hash and ordered rootfs diff IDs. `:221–228` maps only the approved observed image to the historical origin. `docs/gcc-oracle-artifact-verification.md:109–127` expressly preserves distinct image identities and the unavailable original Config limitation.
- `LlvmSourceArchiveMaterializer.kt:55–84,275–337` supplies descriptor-bound acquisition/signature/archive patterns, while `LlvmBuildEnvironment.kt:163–169,413–469` distinguishes reproduced-image admission, historical origin, fixed production verification and test seams. These are useful patterns with LLVM-scoped contracts, as the plan states.
- `FullTreeClangCompdbReconciliationControl.kt:72–95` only integrity-validates caller-supplied input; `FullTreeClangHeaderTrace.kt:35–40,98` does not prove physical/compiler authenticity. `FullTreeInventoryControl.kt:136–145,204–206` enforces unique paths and derives IDs from paths. These cannot supply GCC variant-aware execution/ownership by association.

## Toolchain bridge and provenance assessment

The plan correctly keeps original `sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248` and effective approved reproduction `sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511` distinct. The checked reproduction lock additionally fixes canonical Config SHA-256 `a37cfb8bb642cf983412ee578635f3e18be03a2326ceb7955fb9565300b87a5f`, creation value and all nine ordered diff IDs. Actual tool bytes/version outputs and exact binary reproduction remain necessary. Matching an image tag, caller inspect JSON or a historical digest alone cannot admit execution.

The build arrays, virtual directories, prefix map, environment, `-j4 all-gcc`, staging and stripping in step 2 agree with the build record. The unchanged build record remains a historical origin document; the new receipt must separately bind the effective runtime/reproduction route. No assertion that the original and reproduced Config blobs are identical is introduced.

The planned object/link/DWARF route is sound as a gated implementation approach: retain pre-link evidence, use actual link inputs/order and selection, independently replay supported relocations/merging, and require exact output bytes for the separate diagnostic link replay. A map alone is not treated as declaration ownership or nominal identity. Unsupported actual transformations leave the relation incomplete rather than manufacturing source/TU matches from names, paths, addresses or layouts.

At the step-1 schema gate, maintain the distinction already implied by the action/contribution/provider relations: linker-generated headers/padding/sections have an explicit producer/provider disposition; merged debug strings and other shared output storage may have several input-contribution edges. Step 3's “unique proved contribution” must mean unambiguous accounted contribution records, not an invented one-input-object-per-output-byte rule. Declaration occurrence ownership is established through the separately proven object/compile graph, not ownership of a merged string byte. No implementation or production proof is claimed by this plan.

## Capture qualification and startability

The initial offline deliverable is concretely startable with the retained small locks/recipes and authored raw action/object/CU fixtures. Closed parsers/profile/ID preimages, authority-bearing construction/refusal rules and independent validators do not require the source archive, an image daemon or a native collector. Missing production inputs do not prevent that first checkpoint, and fixtures cannot satisfy its later real-evidence gates.

The collector is explicitly a **proposed, unqualified dependency**. The plan chooses syscall/process observation, defines the stopped-root/descendant/exec/file-version/completion boundary, rejects weak log substitutions, and requires qualification before production capture. It does not claim that existing compdb/header facilities or an unidentified native binary already provide execution authority. Actual collector selection, source/binary/config/kernel/runtime admission and capability review remain necessary.

Collector qualification should be proportional to the complete dependency/version provenance required here: authored process/compiler/archive/link/generated/response fixtures establish the supported mechanism; the actual qualified captured build must reproduce the pinned pair and deliver its complete authenticated closure. The two required deterministic replays then establish evidence reconstruction determinism. The contract need not support every Linux I/O mechanism. Unsupported asynchronous I/O, mutable mappings, descriptor transfers, races or escapes may instead be explicitly denied/refused under the qualified profile; they cannot silently disappear from the consumed-input set. Drop/overflow/incomplete completion or unversioned consumed data must reject the handoff. This is a closed supported operation, not a requirement to prove universal tracing of arbitrary programs.

Budget sufficiency remains a production gate rather than an empirical claim. The proposed caps do not increase existing profiles; effective limits remain the lower admitted authorities, with aggregate nested reservations and all repeated parsing/index/string/event/output work charged. If actual compilation/capture/relocation evidence cannot fit or be observed completely, the plan calls for a precise blocked profile/capability review rather than partial completion or arbitrary artifact splitting.

## Model independence and authority limits

Oracle-side construction and independent verification in steps 1–5 must remain independent of recovered-model existence/content. The phrase “ownership comparisons/validation” at line 97 is read in its recovery/isolation context as **validation/comparison of candidate recovery against oracle ownership**, after that candidate is frozen. It must not gate the oracle verifier itself on a candidate or reveal original source/build evidence to acquisition. Steps 5/6 and the immutable independently frozen handoff already require that separation. No circular recovered-model authority is approved.

The plan preserves genuine missing authority: actual source/runtime/capture admission, exact repeated reproduction, complete object-to-final/occurrence-owner evidence, isolation controls, Kotlin qualification and bounded resource receipts. Nominal/ODR/alias truth remains with its semantic owners; occurrence ownership cannot certify it. #692 still needs complete semantic populations, required type closure, genuine stripped-model binding, independent totals and its own seal/qualification. #1513 cannot close on all-unresolved placeholders, physical census counts, source visibility flags or diagnostic ledger results.

No other blocking contradiction or unstartable first checkpoint was found. The complete issue scope remains covered. Short read/hash/source checks were sufficient for this planning review; no implementation tests or expensive qualification were needed.

Review history: the first report bytes (`74f6791197e8cc1fa460a28b5bc0c8c1d157750beed67f9a37b806607b5171db`) accepted the extra repeated-build gate. The coordinator's explicit Actions-efficiency constraint prompted the above recheck against criterion 6; this revision supersedes that initial OKAY. No plan bytes were changed by this reviewer.

Final terminal verdict: **ITERATE** for plan SHA-256 `c48fa34e6bd5135cb429f672b1bb152a5c3e48e47b2902de5c7e304efcfd0608` — remove the unconditional three-full-build gate while preserving one complete authenticated production capture and two independent deterministic evidence replays.

## Corrected plan re-review — final verdict OKAY

This appended review supersedes the initial ITERATE only for the corrected plan below. The initial findings, plan hashes and review history above are preserved.

| Re-reviewed artifact | Binding |
| --- | --- |
| `.omo/plans/gcc-source-build-ownership-inventory.md` | **34,911 bytes**; SHA-256 `58f817f0cae0d7c1ea2e41491d2a6eef575011857889c224fc0c2582e071668d` |
| Previous reviewed plan | SHA-256 `c48fa34e6bd5135cb429f672b1bb152a5c3e48e47b2902de5c7e304efcfd0608` |
| Initial terminal ITERATE report, before this append | SHA-256 `bb4d819b1394ab38c4114482cbaba748ad263889822557417dac0865ebbbb0c4` |

I read the corrected plan and checked its repeated-build, replay, model, contribution, acceptance and resource passages for consistency. Both supporting snapshot hashes remain unchanged. No source, Git, remote, acquisition, JVM, native, model or authentication operation was performed; only this report was updated.

**The sole blocking finding is resolved.** Lines 51, 71, 75, 79 and 103 consistently require one complete authenticated actual capture reproducing the exact rich/stripped pair. Line 69 binds the original recipe to that one production build. There is no remaining unconditional unobserved driver baseline or second full captured rebuild. Extra full builds require a recorded concrete remaining failure, instability or unresolved observation and the evidence they are expected to resolve. The separate exact-input diagnostic link replay at line 53 remains a focused provenance operation, not another complete GCC build.

Step 5 at line 95 now defines both required deterministic replays precisely: fresh verifier workspaces/indexes; full raw-input authentication, reading and rederivation on each pass; supported visitation/completion-order variation; identical canonical semantic bytes/digests and conservation totals; distinct receipts; and charging both complete passes to the admitted operation/aggregate budgets. Cached producer conclusions, a reused derived database or repeated summary-hash comparisons cannot substitute. The acceptance mapping at line 131 and publication step at line 103 agree with this gate.

The related clarifications also resolve the previously noted execution interpretations:

- Line 79 explicitly assigns linker-synthesized headers/padding/sections to supported linker producers and permits several proved input-contribution edges for merged output. It prohibits one invented input-object owner per byte. Declaration occurrence ownership continues through independently proved compile/object provenance.
- Line 97 explicitly permits oracle construction and independent verification before a recovered model exists, forbids dependence on candidate content/partition, and defers only candidate comparisons/validation/scoring until that candidate is frozen. No circular model authority or model-acquisition requirement is introduced.

The correction preserves all seven #1513 acceptance criteria and trusted-source isolation. Exact source/build/toolchain/pair identities, the `510c` historical-origin/`807f` approved-reproduction distinction, complete action/input/version/object/link/CU/declaration/use coverage, positive owner decisions, separate nominal/ODR authority, independent Kotlin validation, hidden-source canary controls, immutable pre-score handoff and all resource/refusal gates remain intact. The bound table at lines 109–120 is retained; both verifier passes are explicitly charged rather than treated as free replay work.

The ptrace/process collector remains an explicitly unqualified dependency requiring admission and proportional authored qualification before production capture. The policy concerns the supported actual build operation and complete consumed-input provenance; it grants no universal tracing authority or permission to omit unsupported paths. Missing capture/source/runtime/object/ownership/isolation evidence still blocks the full handoff. The first offline Kotlin contract/parser/refusal checkpoint remains startable with the retained small inputs and authored fixtures.

No blocking contradiction remains in this corrected plan. Approval permits progressing through those reviewed implementation gates; it does not claim implementation, actual collector qualification, a production ownership relation, #692 semantic populations/model binding/sealing, scoring or issue closure.

Final terminal verdict: **OKAY** for corrected plan SHA-256 `58f817f0cae0d7c1ea2e41491d2a6eef575011857889c224fc0c2582e071668d`.

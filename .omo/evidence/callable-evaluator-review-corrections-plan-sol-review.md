# Independent full-plan review: callable evaluator corrections

Verdict: **ITERATE** for the complete correction plan. The static correction checkpoint is startable; runtime completion is not yet an executable selected design. No implementation or new execution is demanded by this planning review.

Reviewed plan: `.omo/plans/callable-evaluator-v2-automatic-review-corrections.md`, SHA256 **`ec26548c4cbb92e0f4d97a2258e415468503304ef540c83c3f5e4a80abc6e30b`**.

GPT-6.1 Sol only; independent of this plan's author; no descendants. This review read retained evidence and immutable Git source and created only this report. No source/Git/remote/Actions/native/helper/privileged/acquisition/auth/model/credential execution or mutation occurred. The separate #1506 implementation/migration was not reviewed here.

## Exact scope and evidence

- PR #1514 captured head: `aab1938d4e99ec960841259fa56bc28c89df0161`.
- `build/active-review-checkpoint/pr1514-review-threads.json`: SHA256 `dda869059f3c313f4ea378bbeb1f925480a8d610df9863490590685302a28ef4`; eight unresolved threads, no pagination remainder.
- Semantic addendum: `.omo/evidence/callable-evaluator-v2-preparation002-semantic-addendum-sol.md`, SHA256 `95fa437bbda338e3b7e4f4dba3eb6409b20edb0f7e167e347b4e21d27b02833c`. Its withdrawal of complete semantic acceptance is appropriate. Preparation-002 integrity does not close any semantic finding.
- Retained full #1507 acceptance payload: `build/acp-decomp-effectiveness/callable-library-v1/roadmap-followups/callable-evaluator-payload.json`, SHA256 `8c36cef8011d1441ce2794e53e710700d4210fc88b6296807b3896ac76febb8d`. The actual file was read; its five full criteria agree with the semantic addendum and retained original issue/review evidence. Current OPEN/ready status is taken from the provided capture/plan, not a new live request.
- Physical preparation-001 `freeze.json`: SHA256 `b322bf5a3506ba1e7b400ed6dff5acc3f293d022f8f49332f5b8881ab29e0595` (10808068 bytes); preparation-002: SHA256 `87be4f2e2c82a9ef6ca65a270f313b02924413245b693c40a4bc92ddd0977309` (10842992 bytes). Both freeze files were read and hashed; this is not another complete recursive preparation integrity audit.


Source references below bind the exact PR head, not the stale root checkout. Archived source hashes independently checked:

| Path under `oracle/acp/callable-evaluator-v2/source/` | SHA256 |
| --- | --- |
| `evaluate_candidate_v2.py` | `d7a06b9f519838676b3f76db8396b33260fcde684d1c0322cb22986d896115af` |
| `interface_gate_v2.py` | `ec4441ecdc29d9e47b0bf5a73869d5ed890dcc48f4c4e66cd803b6c0514b31a9` |
| `record_identity_probe.cpp` | `d3e9e57991933f4a629422816fd9ead9a651303eb8d858d76f4ec5755cc93447` |
| `build_contract.py` | `f01353fd58771ed006c85081519ad97378d7b52e2fbdd458c3120fe6ff6eb8c5` |
| `bounded_runtime.py` | `428c8670fdc4581a613df84a7e0475cea5c8bba34b816749d50122c37887e92a` |
| `toolchain-001/pin_environment.py` | `5016428822cd5a910395a01da118eecf558db17d03e352fcb63f3b8d260ab6ff` |
| `contracts/candidate-build-profile.json` | `3aace398485f3d4f07d6edaa30c4d7604c85ef8585727657c0ebdd34ce1c1d13` |
| `contracts/report-schema.json` | `86b670ace28e03b20a2ea452b4c0d60f3a0171ecc5611f4b5e077808f897d6c7` |
| `freeze_v2.py` | `c4fdaf28e47cbd0adc55348889d6f406ff0f77704c64ee915c37bd5a111456c1` |

The local, non-archived preparation coordinator `build/acp-decomp-effectiveness/callable-library-v2/prepare_v2.py` was also read: SHA256 `892e93c416287e27b761a5c699915b280f379b0a8e1e3103179005e908e167c4`. It is material to the reference/cohort/matrix migration, not an interchangeable archived execution source.

## Required plan corrections

### 1. Select the runtime evidence contract before prescribing a new guest loader/ABI capability

**Blocking for complete-plan approval.** Plan lines 9–15 and 33–37 make a new bounded x86 guest executor, external ELF loader and five-export/callback bridge the proposed mandatory route, while expressly identifying no engine, implementation/API, pinned dependency or usable qualified execution environment. “Root must select” is an honest blocker, not an executable runtime implementation work package. Naming an architecture does not establish support for this GCC/target/default dynamic closure, loader constructors, relocation/TLS/library behavior, mutable exported state, aggregate/variadic calling, callback/context effects, process outcomes and syscall/output semantics. The plan correctly refuses permanent all-unknown completion, but has not established that its proposed engine can produce the required positive evidence.

The reviewed source supplies reusable **containment/process receipt** mechanisms, AST admission, compile/link/export checks and bounded output comparison. It supplies no candidate-isolated callable semantic monitor. Repository searches at the exact head found no implemented Unicorn/QEMU/p-code guest evaluator or general dynamic ELF/ABI bridge. Ghidra's application dependency is not evidence that this runtime exists. The exact-head own-child ptrace fixture `src/test/kotlin/decompengine/analysis/AnalysisIoHelperNativeTest.kt:335–522` (30362 bytes; SHA256 `695dbb97f5d59f55540bd67e7eee3588996121f4bfef97a633228d4eab3e71a2`) reuses useful wait/register/syscall/cleanup patterns but tests a parked analysis-I/O helper and injected forbidden syscalls. It does not prove callable load/entry/callback authority or support a drop-in runtime replacement. No source execution was used to infer otherwise.

The word **minimum** at line 9 also conflates the issue's required acceptance with the plan's stronger internal event metric. The five #1507 criteria require actual AST admission; an exact disclosed compiler/link/export contract; compatible/incompatible controls, no incompatible/unknown interface called, cleanup and mutant detection; preserved/frozen independent preflight; and honest separate phases including unknown/refused. They do not independently specify exact hostile-program API-entry/completion counts, an externally implemented loader or host-owned callback dispatch. Those additional claims need a justified measurement contract, not an automatically expanded universal runtime project.

Required revision: define each reported event and the evidence actually needed before choosing the implementation. Distinguish parent-issued scenario request, kernel-evidenced process creation, completed process outcome/output, loader return, actual export entry, return/completion, and callback observation. A process launch/exit/output receipt can authentically report **process observations**; its stdout/stderr remain candidate behavior, not an authenticated loader/API event. Source admission can prove that a refused interface is never handed to the runtime; do not substitute a candidate stderr marker for that decision. Do not present process creation as export entry.

A potentially smaller native route is to retain positive completed-process scenario behavior and remove/mark unverified the unsupported internal event/count claims, with explicit denominators and no invented zeros. Whether that fully satisfies callable-control acceptance must be explicitly reviewed against all five criteria and the real compatible/mutant controls; it is not approved merely by this suggestion. It must not rewrite all behavior unknown or quietly remove required ABI/scenario coverage. If the chosen claim remains trusted exact export/callback entry/completion, retain the stronger authority requirement and identify a concrete bounded engine/monitor plus pinned supported contract before runtime source work is declared startable.

Whichever route is selected, show the exact existing capability to reuse, missing seam, first finite public synthetic prototype/control, unchanged or explicitly versioned target/build/loader semantics, and qualification/refusal gates. An inherited descriptor, secret marker, worker RPC or observed PC alone cannot authenticate a higher-level call event in candidate-shared memory. For a guest bridge, even a guest jump to a valid trampoline must not independently increment a host callback count; require the validated active call/callback context. No arbitrary full VM implementation or perpetual unsupported result is an acceptable completion substitute.

### 2. Include the enforced core-file bound in the visible exact profile

**Blocking acceptance omission.** Plan line 27 fixes only NOFILE and FSIZE. Exact-head `bounded_runtime.py:54–59` explicitly sets `RLIMIT_CORE=(0,0)` as well as CPU/AS/NOFILE/FSIZE; the current profile and `build_contract.py:8–10` omit core. The semantic addendum's finding 6 expressly calls this out. Following the plan verbatim leaves the same full-contract criterion incomplete.

Required revision: add a disclosed zero core-file bound with explicit soft/hard equality, derive or validate enforcement from the same profile, and add the matching disclosure/validator/runner fixture. Audit all explicitly enforced process/cgroup/tmpfs/output/deadline limits by phase so that fixing the two bot-mentioned examples does not leave an undocumented third bound. This is a finite comparison against the existing launcher, not a demand for universal host-policy enumeration.

### 3. Separate source checkpoint freezing from final accepted preparation sealing

**Blocking ordering ambiguity.** Plan line 37 says “Freeze before independent preflight.” Exact-head `freeze_v2.py:15–32` requires an already accepted preflight matrix, matching execution hashes, an implementation review bound to the complete matrix/inventory/toolchain/helper, and a distinct acceptance review **before** it can create the final preparation. The coordinator currently uses the old v2 observations and exact marker counts (`prepare_v2.py:44–74`); the report schema still requires Boolean `candidateCalled`, nonnegative `recordedCallCount`, and scenario states with no unknown (`contracts/report-schema.json:5–20`). The proposed runtime/status semantics therefore require an explicit coordinator/schema migration too.

Required revision: state an unambiguous sequence: new mutable implementation generation → digest-frozen source/profile/fixture/control inputs for the preflight → authorized public/fixture controls plus complete receipts → independent source/preflight and acceptance review → final new preparation seal → separate integrity audit. A source checkpoint freeze before preflight is reasonable; do not call it the final accepted preparation. If reviewers audit after the final physical copy too, retain that as the additional post-copy integrity/acceptance gate rather than replacing the required prior preflight.

Name the changed report/helper/profile/reference/matrix schema generation and its migration rules, update the coordinator/reference generation and visible renderer consistently, and make partial/unknown nullable event fields representable. Preserve the existing schema/archive/preparation bytes as historical generations. A new preparation directory number by itself does not version changed result meaning.

## Full finding and acceptance coverage

| Captured finding | Assessment of proposed correction |
| --- | --- |
| Identity graph, `MTPv` | Step 2 is source-grounded and startable: bidirectional identity mapping, rooted nodes, exact GCC binding and split/collapse controls. Preserve alias desugaring and repeated-node positive cases; an already visited DAG node is not an active cycle. No unsafe actual candidate call is inferred from the old comparator defect. |
| Forged markers, `MTPy` | Removing marker authority/stripping is necessary; step 6's architecture remains unselected and overstates the minimum metric. Correct as finding 1 above. Preserve candidate bytes verbatim on both reference and candidate paths. |
| Link closure, `MTP2` | Step 4 is appropriate: exact configured link resolution, actual harmless-link inventory and revalidation of search/scripts/selections. Do not require tracing every OS operation beyond what complete encountered resolution needs; dry-run or `ldd` alone is not closure. Actual compiler execution remains separately authorized. |
| Builtin kind, `MTP8` | Step 3 fixes the real width/rank loss. Plain char, signed/unsigned kinds, qualifiers and supported/refused Boolean/extended types are finite and testable; positive long-long and same-width negatives are needed. |
| Reference exit, `MTQD` | Step 5 correctly compares completed exit/output and separates signal/timeout/infrastructure. Migrate the reference generator as needed; its present zero-exit-only cohort cannot itself prove nonzero-reference coverage. |
| Hidden limits, `MTQI` | NOFILE/FSIZE are covered, CORE is not. Correct finding 2 above. |
| Lost unknown, `MTQN` | Step 5's scenario and aggregate unknown propagation is correct. Preserve partial receipts without converting missing completion into candidate failure or an exercised-call denominator. Update schema/coordinator under finding 3. |
| Partial assertion pass, `MTQR` | Step 5 correctly starts unknown and records each side independently. Include failure before expected preprocessing, after expected completion and before candidate binding; keep declaration refusal/no-call behavior. |

All five full criteria remain required. AST identity/builtin changes address criterion 1; complete visible limits/link/export closure address criterion 2; positive/negative ABI controls, preserved 24 scenarios, actual behavior mutant and cleanup address criterion 3; preserved original attempt13 and both sealed preparations plus new independent source/preflight/seal evidence address criterion 4; truthful separate phases, outcomes and metric denominators address criterion 5. No pooled CLI rate, ABI/structural score or production authority is granted. Nothing here reviews or waives #1506/238/964.

## Concrete next startable deliverable

Proceed, through the sole source custodian, with a **new isolated correction source checkpoint** for steps 2–5: node-referenced identity/builtin descriptors and GCC bindings; closed profile including CORE/NOFILE/FSIZE; exact link-input resolver contract and inert resolution fixtures; completed/unknown phase state machines; and updated closed report/reference/matrix schemas. Pin the plan, exact source baseline, changed sources/schemas and unit evidence. Pure descriptor/state/schema fixtures can be reviewed without executing a candidate; native helper/compiler/link inventories remain gated. Source checkpoint review must not be labelled a corrected preparation or complete #1507 acceptance.

In parallel as a plan task, close the runtime measurement decision and finite capability-selection gate in finding 1. Preserve all 24 scenarios, five exported functions plus mutable state, struct argument/return, variadic and callback/context behavior, all original incompatible/unsupported controls, and positive mutant detection. A new runtime/loader contract requires full equivalence and positive controls; a process-observation contract requires truthful reduced claims and an explicit full-acceptance review, not fake call certainty.

Preserve physical preparation-001/002, original attempt13/candidate/result and existing archive maps byte for byte. Record their semantic supersession through new addenda/receipts and live status metadata. Publish corrections in a new versioned source/archive namespace with clear relocation/qualification limits and exact original versus corrected hashes; do not silently replace the historical byte-identical archive. Resolve each thread only after its concrete corrected-source/evidence review; required CI/reviews/merge and later authenticated trial authority remain separate.

**Final disposition: ITERATE.** Correct the three plan defects above, retain the safe static work package, and return a newly pinned plan for full review. No universal guest runtime, source implementation or new qualification run was required to perform this review.

## Coordinator direction received before terminal delivery

Root selected the narrower contract for the next revised specification: retain real AST-compatible control execution, mutant detection and all 24 native **process outcome** comparisons; use OS-owned launch/exit/cleanup facts and preserve candidate stdout/stderr as behavior. Specific loader/API-entry/completion/callback observations remain unverified/null without independent proof. A launch must never count as an API entry. A new schema/profile must distinguish the process denominator from API coverage and keep ABI/structural scores null. This direction does not approve the alternative or complete #1507: the revised exact specification and all five criteria/eight findings/full controls still require independent review. It removes no criterion and does not require all behavior to remain unknown.


---

# Terminal independent rereview — revised process contract

Verdict: **OKAY** for revised plan SHA256 **`be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`** and its bounded static source checkpoint. This approves the plan, not source implementation, native qualification, full #1507 acceptance, a final preparation, merge or trial.

The original plan remains exact SHA256 `ec26548c4cbb92e0f4d97a2258e415468503304ef540c83c3f5e4a80abc6e30b` at the named original-plan path. The complete initial ITERATE report is preserved as the byte-exact prefix of this report: SHA256 `c3488e2d60b040e479a9bab45fc305f7d7fe13c822f6e16e6fae2e3620b11469`. No prior finding, preparation, archive or semantic withdrawal was overwritten. This rereview read the entire revised specification, checked the three prior blockers and their interactions against the exact source/criteria already pinned above, and ran no evaluator/helper/candidate, compiler, native, auth/model, remote or CI operation. Only this report was appended.

## Three prior blockers resolved

1. **Proportionate, selected runtime evidence.** The plan now keeps the existing native GCC/caller/bubblewrap/systemd route and all 24 scenarios. No unselected emulator or external dynamic loader is a prerequisite. It distinguishes a controller request, Popen launcher creation, kernel-verified owned scope, completed wrapped-process observation and verified cleanup. It expressly avoids equating a launcher PID with caller exec or a library export entry. Wrapper/setup/containment/capture/cleanup failures remain unknown when a usable observation is not established. Positive compatible native process behavior and mutant mismatches are required; an all-unknown positive cohort cannot pass.

   Both reference and candidate streams are preserved verbatim and remain untrusted behavior. Old marker-like strings have no event authority and are not stripped. Specific load/API-entry/completion/callback events have unverified/null values without independent proof; declined runtime admission records no runtime request, not a fabricated internal zero-call measurement. The new process denominator, completion/24 disclosure, unknown/refused counts and null API coverage make the narrower claim explicit. Completed termination comparisons include nonzero references and discriminate signals, deadlines, output limits and incomplete capture. An incomplete/truncated receipt cannot become an exact match. Aggregate behavior passes only for 24 completed matching observations; known mismatch and unknown remain separately represented.

   This is consistent with #1507's five criteria as a plan: actual compatible native controls, mutant detection, refused/unknown declaration admission, cleanup and honest separated outcomes are preserved. It makes no claim that finite process-output agreement proves every internal API invocation, callback count or general function equivalence. It does not restore the earlier marker-derived acceptance or supply an API/ABI/structural score. No FD, shared secret, candidate marker, worker RPC or PC-only event channel was accepted as authentication.

2. **Complete finite disclosed bounds.** Section A2 now includes CORE soft=hard=0, NOFILE soft=hard=64 and FSIZE soft=hard=16777216, plus the finite audit of actual process/cgroup/deadline/capture/tmpfs/helper limits by phase. It preserves CPU RLIMIT versus aggregate CPU distinctions and directs a side-effect-free profile loader or validated equality to avoid the existing circular import. Profile/visible rendering, mutation tests and mocked `setrlimit` values are concrete. The source review must verify this exact equality; the plan does not falsely claim it already holds in old v2.

3. **Source freeze, preflight, acceptance and seal ordering.** Section C now distinguishes a digest-frozen source checkpoint from a final accepted preparation. The order is fixed inputs → authorized full matrix/receipts → independent implementation/preflight and distinct full-acceptance review → new immutable preparation copy/seal → separate post-copy integrity audit. This agrees with the reviewed `freeze_v2.py:15–32` seam. Section A5 explicitly migrates the coordinator, reference generator, matrix predicates and complete source/schema/support inventory. Changed helper/profile/visible/report/reference/matrix/execution-binding/preparation exchanges have new version-3 closed schemas; v2 input is rejected rather than reinterpreted.

## Full scope and executable next checkpoint

All eight findings have named source changes, tests and later real qualification evidence: identity graph/bindings; exact builtin kind; complete implicit link closure; CORE/NOFILE/FSIZE disclosure; reference termination comparison; lost infrastructure unknown; incomplete GCC-side assertions; and removal of marker authority/stripping. Source baseline and concrete v3 output files are named, including a new finite link-input resolver over recorded search/script/response fixtures. Actual exact-driver dry-run and controlled harmless-link inventory remain necessary later; no dry-run or `ldd` alone certifies the closure.

The six named pure unittest files and individual `python3 -B` commands make Section A immediately startable after custodian implementation authorization. They cover graph/builtin/profile/link/process/schema/coordinator cases, mock native paths, keep caches/temp inside the repository, and use AST syntax checks rather than source execution or bytecode generation. Native helper/compiler/candidate execution belongs to Section B after source review and separate authorization. The prescribed synthetic constructor/in-call marker, wrapper/scope failure, partial receipt, cleanup, nonzero-reference and drift controls are finite and proportionate.

All five #1507 criteria remain mapped to evidence. In particular, real compatible named/anonymous/alias controls must yield all 24 matching native process observations; the admitted behavior mutant must yield a completed mismatch; all original incompatible layout/parameter/callback/varargs/export/attribute controls remain, with refused/unknown interfaces receiving no runtime request or launch. Struct values/returns, mutable state, variadic and callback/context scenarios are retained. No implicit default-library removal, weaker build flag, API-coverage claim or unrelated #1506/238/964 acceptance is introduced.

## Implementation and acceptance limits

- The new public `oracle/acp/callable-evaluator-v3/source/` is a corrected **public-source archive**. The copied private caller/fixture/scenario/reference material and preparation/control coordinators belong in the trusted `build/acp-decomp-effectiveness/callable-library-v3/` execution namespace as applicable. The plan's “new source tree plus coordinator/support copies” ownership is not authorization to publish private inputs, original declarations, expected values or raw observations. Root was notified of this concrete handoff distinction. Preserve the existing oracle/private isolation and public-archive exclusions during source review.
- Source review must check that schema count invariants and reducers derive requests/launches/scopes/completed process outcomes separately, that partial wrapper receipts cannot self-certify completion, and that legacy marker-derived matrix assertions do not survive under renamed fields. The later full-acceptance reviewer must inspect actual receipts and positive controls; plan wording alone is not evidence.
- Preserve physical preparations 001/002, attempt13/candidate/result, old public archive bytes/maps and withdrawal `95fa437bbda338e3b7e4f4dba3eb6409b20edb0f7e167e347b4e21d27b02833c`. New versioning does not rewrite historical success claims as corrected measurements. A new generation remains unqualified until its full gates pass.

**Final disposition: OKAY on `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`.** The three initial plan findings are resolved. Keep #1507 open; retain the semantic withdrawal until corrected source, the complete native preflight, independent full acceptance, final seal/integrity and required CI/review workflow actually satisfy their gates. No authenticated trial or source/native execution is authorized by this rereview.

# Issue #1507 semantic acceptance correction — GPT-6.1 Sol

Verdict: **ITERATE**. Preparation-002 and its source archive remain byte-intact, but their evaluator semantics do not satisfy full #1507 acceptance. **This addendum withdraws and supersedes my earlier claim that all five criteria were achieved at the local checkpoint.** That complete-acceptance claim in report SHA256 `46c80279b8d372d1b63204349af74c14046cc18b6cb6432faf767c4baf9b59e7` was too broad. Its valid integrity findings remain evidence; they do not establish semantic correctness. Preserve all prior report and freeze bytes as history.

Independent source reassessment on 2026-10-14 against all eight captured automatic review texts and the full live #1507 criteria. Captured PR #1514 head is `aab1938d4e99ec960841259fa56bc28c89df0161`. The capture has eight unresolved threads, no pagination remainder, SHA256 `dda869059f3c313f4ea378bbeb1f925480a8d610df9863490590685302a28ef4`. The eight affected public source/profile/schema files match their exact preparation-002 copies, so these findings concern the sealed evaluator itself, not a different live implementation.

No frozen evaluator, helper, candidate, original fixture, model/provider/authentication or native tool execution occurred. No source, Git/remote state, CI, credential, privileged or acquisition mutation occurred; no descendants were spawned. One read-only GitHub issue refresh and local Git metadata inspection occurred before I corrected my interpretation of this task's stricter no-Git/no-remote-operations limit; subsequent review used only local files. No authored execution probe was necessary: the source branches and retained GCC specs provide the evidence below. Only this new addendum was written. Private expected declarations, values, cases and observations are omitted.

## Eight findings independently assessed

### 1. Record-identity relationships — supported, with a final-admission qualification

Thread `PRRT_kwDOTCeevs6sMTPv`; `record_identity_probe.cpp:90–91`, `interface_gate_v2.py:13,95`.

Record declaration IDs appear in provenance, but the recursively inlined interface descriptors contain layout/fields without record-node references. `compare_descriptors` compares only those descriptors and target/data layout. It ignores provenance. Therefore it cannot distinguish two separate same-layout record declarations from two uses of one declaration, nor preserve the reverse same-versus-distinct relationship. AST-based lookup within each translation unit is present; identity-graph comparison between interfaces is missing. This directly defeats the claimed full identity contract.

The automatic text's broad implication that a simple collapse necessarily passes final admission is **not established** by the current code. `layout_assertions` itself selects the first structurally equal GCC type binding. For an expected interface using two distinct same-layout by-value records, that selection can reconstruct both as one record type and fail the expected GCC self-check. Thus the existing pipeline can false-refuse a legitimate expected interface rather than call the collapsed candidate. This additional loss of identity does not repair the comparator; it shows why both comparison and GCC-expression binding need identity-aware nodes. Do not claim an actual unsafe call or frozen-candidate reproduction from this static finding.

Required correction: compare rooted canonical record/enum identity graphs under a consistent bijection, preserving same/distinct relationships while correctly desugaring aliases. Bind GCC assertions to exact declaration nodes/use sites. Add both distinct-to-shared and shared-to-distinct controls with identical layouts, including nested/callback use, and a legitimate distinct-record positive control. Spellings and arbitrary per-AST numeric IDs are not cross-unit equivalence proofs.

### 2. Candidate-forgeable load/call markers — supported

Thread `PRRT_kwDOTCeevs6sMTPy`; `evaluate_candidate_v2.py:106–112`.

Load success, executed/call counts and the runtime denominator are inferred by searching candidate-shared stderr. Candidate library code, including constructors, executes in that caller process and can write those bytes or exit before the caller returns from loading. The evaluator also globally removes marker bytes before comparing stderr. Consequently a candidate can forge reported load/call events and have some of its own stderr removed from comparison. The existence of authored controls with consistent marker counts does not authenticate these events against candidate code.

This establishes unreliable event/count reporting without needing private expected outputs or claiming that an actual frozen candidate achieved false matches. Constructor exit can prevent API invocation while forged marker text still reports calls. A second pipe, hidden descriptor number, or secret token in the same untrusted address space is not automatically a trusted channel: the candidate can share that process's descriptor/memory authority. The design must establish an event boundary candidate code cannot forge, or explicitly report such events as unverified and refuse unsupported measurements. Add adversarial constructor/marker-output/early-exit controls before claiming trusted call counts.

### 3. Incomplete implicit GCC link-input closure — supported

Thread `PRRT_kwDOTCeevs6sMTP2`; `toolchain-001/pin_environment.py:8–18`.

The pin generator asks GCC for only selected startup objects/libgcc files, inventories headers/tools/runtime libraries, and merges helper dependencies. It does not enumerate the actual configured link closure. The retained, already-frozen GCC `-dumpspecs` output selects `crti.o`, `crtn.o` and `-lc`; the command enables ordinary startup/default libraries. Yet the frozen 74,066-path dependency map contains no `crti.o`, `crtn.o`, `libc.so` linker script or `libc_nonshared.a`. Pinning the libc shared runtime through tool `ldd` is not equivalent to pinning these link-time inputs.

Thus every listed path can rehash correctly while an implicit link input changes outside that map. The earlier large dependency count proves equality only for the enumerated set, not completeness. A corrected exact profile must derive and bind the full resolved link closure, including startup objects, scripts, default libraries, search/selection and relevant driver configuration, and revalidate the same resolution before later execution. No new GCC invocation was used for this assessment.

### 4. Exact builtin integer type lost — supported

Thread `PRRT_kwDOTCeevs6sMTP8`; `record_identity_probe.cpp:61`, `interface_gate_v2.py:89`.

Integer descriptors retain bits and signedness without builtin kind/rank. On this LP64 target, `long` and `long long` share width/sign but are incompatible C types. The assertion generator reconstructs every 64-bit signed/unsigned integer as `long`/`unsigned long`, so an otherwise identical expected/candidate `long long` interface fails its own expected GCC check. The comparator also cannot distinguish those builtin types. Plain `char` versus explicitly signed/unsigned character types and Boolean types deserve the same exact-kind audit; width alone is not C type identity.

This is a real supported-projection/false-refusal defect, not proof the current private fixture uses that type. Preserve canonical builtin identity and reconstruct it exactly, or explicitly refuse unsupported builtin kinds before claiming a supported descriptor. Add same-type positive and same-width/different-kind negative controls.

### 5. Reference nonzero exit status ignored — supported; current prepared cohort is narrower

Thread `PRRT_kwDOTCeevs6sMTQD`; `evaluate_candidate_v2.py:112`.

`validated_observations` accepts an integer reference exit status, but behavior comparison never uses it: any candidate exit other than zero becomes runtime-failed, while zero plus matching output can match. Therefore a validated nonzero reference observation is not compared correctly.

The retained preparation generator separately requires reference runs to have status passed (`prepare_v2.py:47`), and its `run` defines passed as exit zero. This makes the accepted authored reference cohort zero-exit by construction. It does **not** establish nonzero reference support, and I do not claim existing frozen observations contained such cases. The validator/evaluator contract is broader than the prepared evidence. Correct behavior matching must compare the complete admitted reference exit/stdout/stderr outcome, with separate infrastructure/signal/unknown handling, and add nonzero-reference controls rather than awarding unproved general support.

### 6. Undisclosed enforced resource limits — supported

Thread `PRRT_kwDOTCeevs6sMTQI`; `bounded_runtime.py:55,58–59`, `contracts/candidate-build-profile.json`, `build_contract.py:8–10`.

The launcher enforces descriptor limit 64 and per-file size limit 16 MiB, but neither appears in the visible profile/prompt/manifest or its fixed-bound checks. The explicitly enforced core-file limit zero is also absent. These inherited process limits can affect compilation/linking despite a candidate meeting the displayed contract. This is an actual exact-contract omission, analogous in principle to the issue's original undisclosed visibility condition. Disclose every explicitly enforced build/runtime limit and verify profile equality against enforcement, retaining clear phase/outcome attribution. No limit-exhaustion program was executed.

### 7. Infrastructure-unknown rewritten as candidate/runtime failure — supported

Thread `PRRT_kwDOTCeevs6sMTQN`; `evaluate_candidate_v2.py:103–104,118`.

`run` returns unknown with no result when setup fails before a bounded receipt exists. The scenario branch replaces that with runtime-failed, and the aggregate behavior phase becomes failed. Thus an unexecuted infrastructure/setup failure is attributed to candidate behavior; caller-launch requests are also incremented before successful process creation. The nested runtime unknown, and any aggregate load unknown, do not correct the scenario runtime-failed and aggregate behavior failed labels. Propagate unknown/setup outcomes into scenario, load, behavior, attempted-versus-observed counts and denominators. Separately classify evidenced candidate timeout/overflow/failure rather than collapsing every exception into one category. Add inert setup-fault controls with no actual candidate process.

### 8. Partial GCC assertion phase falsely marked passed — supported, fail-closed admission retained

Thread `PRRT_kwDOTCeevs6sMTQR`; `evaluate_candidate_v2.py:80–87`.

The phase starts as passed before either side completes. If assertion construction or execution raises on either side, the outer handler changes declarations to unknown but leaves GCC assertions passed and can retain only a partial/empty checks object. A supported helper descriptor with an unreachable GCC spelling/binding can take this route. This misreports an incomplete phase as successful.

The same handler sets declarations accepted false/unknown, so the demonstrated exception path still prevents overall admission. This finding is about false phase evidence, not proof of an incompatible call. Start the phase as incomplete/unknown and mark passed only after both required sides complete; preserve completed checks and mark the unfinished side/phase unknown on exception. Cover exceptions before and between sides and explicit side failures.

## Corrected mapping to the full #1507 criteria

1. **Actual AST identities/layout for named/anonymous/alias records; explicit unresolved/cyclic/unsupported refusal.** Lookup and layout extraction remain implemented, but identity relationships are erased during comparison/assertion binding and builtin type identity is incomplete (findings 1/4). **Full criterion not satisfied.**
2. **Exact visible compiler/link/export contract enforced, with no unstated visibility condition.** Displayed command/profile equality and default export visibility remain true, but explicit resource limits are hidden and the reviewed link-input binding is incomplete (findings 3/6). **Full criterion not satisfied.**
3. **Compatible and incompatible controls, no incompatible/unknown calls, cleanup and mutant detection.** The 30 retained authored controls and bounded cleanup evidence remain historical observations, but do not cover the identity/builtin cases or authenticate candidate-shared marker counts. The existing GCC exception route still refuses admission; it is not evidence that all other identity cases are safe. **Complete control/admission/measurement acceptance is unproved (findings 1/2/4).**
4. **Freeze evaluator/prompt/fixture/control and independent preflight before a new authenticated trial; preserve original attempt13/candidate/result.** Preparation-002's bytes, bindings, sealing and historical preservation remain intact. I reverified all 1,746 copied artifact hashes. However it freezes semantically defective sources and an incomplete external-input inventory; historical CLEAR reviews cannot qualify it for a later measured trial. **Integrity/preservation subclaims stand; corrected-evaluator acceptance remains gated.** Preserve preparations 001/002 and create a newly reviewed source/preflight/pin/freeze namespace after correction; do not mutate either sealed preparation.
5. **Separate compile/link/export/load/admission/behavior, including unknown/refused; no pooled score or unsupported authority.** Phase fields and false/null authority flags remain, but forged marker evidence, ignored reference exits, lost infrastructure unknown and partial GCC pass make some phase/count/outcome claims unreliable (findings 2/5/7/8). **Full criterion not satisfied.** No pooled CLI score, ABI score, structural score or production authority is supplied by this addendum.

## Preserved facts, correction and next gate

Preparation-002 freeze remains SHA256 `87be4f2e2c82a9ef6ca65a270f313b02924413245b693c40a4bc92ddd0977309`; separate integrity audit remains `89387ae993ea5fb20580a64f054e1281e29904f9327819c42900a851a0f19d0d`. The original ITERATE report `7f646d5b1368b1b48bc2213e01012b3abc11f051aa58b871ca722802f9bc1860`, pre-freeze CLEAR `12eb1d6ebc1b511e10b20e1289d05cc0e43a32c055b042b598fdb3e758d72188` and final checkpoint CLEAR `46c80279b8d372d1b63204349af74c14046cc18b6cb6432faf767c4baf9b59e7` remain byte-identical. Their earlier broad semantic acceptance is superseded by this ITERATE assessment. The prior host-filesystem probe fix and harmless blank-at-EOF finding remain valid; neither resolves these additional defects.

Keep #1507 OPEN; do not merge PR #1514 with unresolved findings or release a trial on preparation-002. Green CI for the existing archive/tests cannot establish absent semantic controls. A separate design/source owner must address these findings, retain failed/adversarial evidence, obtain fresh independent full-scope acceptance and new immutable preparation, and complete required CI/review workflow. This report does not authorize a model/authentication call, original candidate rerun, new measurement, issue closure, merge or production release.

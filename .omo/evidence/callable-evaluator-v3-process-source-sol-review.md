# Independent A4 v3 process-source review

Verdict: **ITERATE**. The held A4 source fixes marker authority and several accounting defects, but wrapper/setup failure can still be counted as completed candidate behavior, missing streams can become an exact empty match, and the report validator permits a false passed load phase. These source defects must be corrected and independently rereviewed before A4 CLEAR. No full #1507 acceptance, native qualification, final preparation seal or trial authority follows.

Reviewer: GPT-6.1 Sol; independent of implementation, no descendants. Root alone owns source/Git/remote actions. Only this new report was written. Inspection and three bounded pure synthetic checks used Python -B and fastjsonschema2.22.2 with an audit hook rejecting subprocess, system, exec, spawn and fork events. No compiler/helper/native/candidate, original/private fixture, model/provider/authentication, credential, acquisition, Git, remote, Actions or CI polling was executed. Private source/caller/scenario contents were not printed or copied into this report.

## Exact held authority and scope

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Binding | SHA256 |
| --- | --- |
| Revised process plan `.omo/plans/callable-evaluator-v2-automatic-review-corrections.md` | `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d` |
| `build/acp-decomp-effectiveness/callable-library-v3/static-process/held-a4-a5-receipt.json` | `84333404410efdaeaa6d4c38b43887139d519fca2c59a9c1e827dc92dec0316f` |
| Adjacent original `source-evidence-checkpoint.json` | `5f3e4dc4ef7b206e67ddb68eeab160c03ca6149ae50f74b112ee3b5185fa4edc` |
| Adjacent provisional-composition addendum | `97cce65b70eb323b96498edddf43e432461a88e6f66d8bb4caa00d0a96e5de6e` |
| Provisional35-file execution snapshot | `f2ea345c19f9a45ac1a4ec66763871a36cdeaac887ecb7e7d38a4a900bc872dc` |

All20 outer-held owned path digests match:13public files and7trusted build-only paths. Original receipt, provisional execution snapshot and addendum digests also match. Private bytes were only hashed, not executed or published. This report owns the A4 evaluator/process contract, report/reference/matrix/execution-bindings/visible-manifest schemas, scope gate and relevant four tests. A5 freeze/preparation/generator/private-template semantics are assigned to the independent A5 reviewer and are not approved here.

The35-file execution snapshot and75-test composition are explicitly provisional observations. They are preserved, not promoted to a current all-held source freeze. A3 revision2 is separately changing/reviewing its held state; a future final composition and its tests require fresh exact bindings. This report does not treat earlier A1/A2/A3 reviews or mutable support copies as substitutes for current composition review.

## Blocking findings

### F1 — Post-admission wrapper/setup failure enters the behavior denominator (high)

`scope_gate.py:17–28` writes the gate PID/start record and waits for admission **before** os.execv of the supplied wrapper. `bounded_runtime.py:175–179` places this gate outside/before bubblewrap. At219–221 the parent verifies that gate's cgroup limits and sets scopeVerified/scopeAdmitted. This proves the host Python gate is admitted; it does not prove bubblewrap's namespace/mount setup or caller exec succeeded.

If bubblewrap fails after admission (for example namespace setup, mount setup or caller exec failure), stdout/stderr EOF, normal nonzero launcher termination and successful cleanup still take the ordinary success path at232–239. infrastructureFailure remains its initialized false; the special infrastructure failure branch at243–245 only addresses an unverified scope plus AssertionError. No independent wrapper-ready/usable-worker evidence is retained.

`evaluate_candidate_v3.py:42–66` consumes those flags as completed=true and compares the wrapper failure's bytes/exit as a candidate process outcome. This increases completedScenarioProcessCount and may yield mismatched, or even matched against a similarly failed reference. The revised plan explicitly requires unusable wrapper/worker outcomes to remain infrastructure unknown. Cgroup admission alone does not establish that boundary.

Bounded pure proof used only authored synthetic bytes and a receipt with the exact flags emitted by the success path after a post-gate wrapper failure: exit1, complete capture/wait/cleanup, infrastructureFailure=false. compare_process returned **mismatched**, completed=true, infrastructureFailure=false. Static source establishes why this receipt is reachable; no actual wrapper was launched by the review.

Required correction: retain trustworthy evidence that the intended wrapped worker is usable, independently of candidate-controlled output, and make absent/failed wrapper setup unknown. Do not parse stderr markers or promote the parent-issued admission request to proof of caller/API entry. Preserve all output bytes, termination and cleanup facts even when comparison is unknown. Add mocked pre/post-admission wrapper failure cases; later separately authorized native qualification must exercise real wrapper faults.

### F2 — Absent raw stdout/stderr silently become empty complete streams (medium)

`evaluate_candidate_v3.py:52` uses result.get('stdout',b'') and result.get('stderr',b''). A partial receipt with either stream field absent is indistinguishable from a captured empty stream. The complete predicate at47–50 does not require those fields.

Pure proof: start with an otherwise complete synthetic receipt and delete both raw stream keys; compare against a complete empty-stream reference. The result was **matched**, completed=true, stdoutHex='', stderrHex=''. That is false exact evidence and denominator inflation for a missing capture payload. The current bounded_run ordinarily supplies fields; the partial-receipt comparison API nevertheless promises fail-closed unknown handling and is expressly tested as a public pure contract.

Required correction: require presence/type of both raw streams before completed comparison. Missing or malformed stream evidence must refuse or normalize to unknown while retaining genuinely available partial bytes. Add separate missing-stdout and missing-stderr regressions; an actual explicitly empty byte stream must remain valid.

### F3 — Report exchange accepts unsupported load success (medium)

The report schema gives phases.load the unrestricted common phase status set including passed/failed/refused. `validate_exchange` verifies aggregate behavior and admission but never enforces the selected load-phase policy. The emitter at237 correctly writes unknown when admitted and not-attempted otherwise; the consumer contract does not enforce it.

Pure proof: construct the existing valid all-matched synthetic report fixture, change only phases.load.status from unknown to **passed**, and call validate_exchange('report',value). It accepted the document despite all internal load/API observations remaining unverified/null. The selected contract forbids separately authenticated load success; a closed schema that accepts that claim is not sufficient migration validation.

Required correction: enforce phases.load.status==unknown for admitted reports and not-attempted for refused reports, in schema/semantic validation as appropriate, and reject passed/failed/refused load assertions under this process-only contract. Add roundtrip/tamper checks for both admitted/refused cases. This finding concerns imported exchange validation; it does not claim the current normal emitter itself produces passed load status.

## Supported corrections and remaining limits

- stdout/stderr are converted directly to hex with no marker stripping. Constructor/in-call marker text has no load/API authority. Exact complete comparison uses both streams and a termination kind/value, including nonzero codes and signal discrimination. A known nonzero compiler result remains a failed phase; an equal nonzero reference process may match.
- The evaluator preserves24ordered IDs and the declared family population. Admission requires all six pre-runtime phases passed. Refused or unknown interface admission produces zero runtime requests and24admission-refused scenario entries. Requested runtime is not API entry.
- Internal load/API entry/completion/callback observations remain null/unverified when requested, null/not-attempted otherwise. API counts/rates and formal structural score remain null; ABI is unassessed and production authority is false. This is materially better than marker-derived certainty, subject to F3 consumer validation.
- The reducer keeps a known mismatch as aggregate failed alongside unknown rows. Otherwise any unknown prevents passed; passed requires all24matched. processBehaviorRate uses matched/completed and is null with zero completed denominator; processCoverage discloses completed/24. F1/F2 still permit incorrect completion classification before that otherwise-correct math.
- Missing explicit positive proof, timeout, output overflow, incomplete wait/capture or failed cleanup prevent completion. Raw partial bounded bytes remain retained. Actual containment/cleanup/worker-start qualification has not been performed by these synthetic tests and is not established by boolean fixtures alone.
- GCC assertion side receipts start unknown and are independently evaluated/retained. A missing expected binding leaves the GCC aggregate unknown while preserving passed declaration evidence and completed candidate-side checks. Runtime admission stays false. Known completed side failure is retained even when aggregate is unknown because another side is incomplete. Declaration/compile/link evidence is not overwritten by later GCC uncertainty.
- Reference validation binds fixture/caller hashes, exact24IDs/families, each raw process-receipt digest and normalized process fields. It does not reuse v2 observations. Completed nonzero reference receipts are allowed. These are structural/static source properties; actual trusted reference regeneration belongs to A5 and native qualification.
- Changed exchanges are closed/version3; legacy marker counters/extra nested claims/version2 refuse. Report semantic checks recompute counts, scenario population, admission and evidence-hash references. Visible manifest/profile binding and namespace/helper isolation depend on A2/A3 source and later actual qualification; inert mount-shape tests do not establish host-read or FD escape resistance.

## Retained tests and independent pure counterexamples

The outer receipt records29owned pure tests and75composed tests. `all-tests-008.log`, SHA256 `d3052c7d9268051d71b610943a99d540a2976c7c2f0c56b887a0a417bdfea76e`, actually records75passes. It is provisional and does not cover F1/F2/F3. Older individually named schema logs have fewer tests and must not be combined with later counts as a new final run. The runner prohibits native launch audit events, uses repository-local scratch and pins fastjsonschema2.22.2. No complete suite was rerun by this review.

The independent inline Python -B check first verified all outer-held digests, imported only public evaluator/test-fixture modules, installed a native-launch denial audit hook, then used authored synthetic receipts. Results:

| Pure control | Observed result | Required contract |
| --- | --- | --- |
| Post-gate wrapper failure receipt | completed=true, mismatched, infrastructureFailure=false | unknown; excluded from completed denominator |
| Both raw stream fields absent | completed=true, matched against empty reference | unknown/refusal, no exact empty match |
| Imported report changed to load passed | validator accepts | reject unsupported load authority |

These controls invoke no evaluate/build/helper/private fixture path and create no candidate or subprocess. The evidence is the source-backed pure counterexample, not a claimed native wrapper reproduction.

## Disposition

**ITERATE** for this held A4 generation. Preserve original/provisional receipts and create new source/checkpoint bindings after fixes. Independently rereview the wrapper boundary, partial capture and load-phase exchange constraints; then run a fresh all-held pure composition after A3/A5 stop. No current75-pass/provisional snapshot can become a final composition by relabeling.

Full #1507 criteria, all eight prior semantic findings, actual compatible/mutant/negative24-scenario controls, exact machine/link closure, distinct full preflight/acceptance reviews, a new seal, post-copy integrity and required CI remain separate gates. Existing preparation001/002 and the semantic withdrawal remain unchanged. Nothing here authorizes native execution, original/private candidate work, authentication or a model trial.

## Reviewed A4 source pins

Paths below are relative to this worktree; these are actual outer-held hashes. The six-schema migration also includes preparation-schema, whose A5 semantics are deferred.

| Path | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/contracts/execution-bindings-schema.json` | `934a0caff077d6ef7ff7af9db9c307906f5f34ba0d005611f55fbbf4dd71cd2f` |
| `oracle/acp/callable-evaluator-v3/source/contracts/matrix-schema.json` | `6904b45a7bed18ab05a04cc129fef4bedc9ca9048c46d7663f69bb9dd9d92891` |
| `oracle/acp/callable-evaluator-v3/source/contracts/reference-observations-schema.json` | `bca996f2caa9fa20ddc18e9048eaeb6d1dc2fe1b843db78af005f43cd9d32f90` |
| `oracle/acp/callable-evaluator-v3/source/contracts/report-schema.json` | `30ef77305ff036d05d0b8d69eee5e0ec8f7ef0f2c823937f2ad8709d457f1067` |
| `oracle/acp/callable-evaluator-v3/source/contracts/visible-manifest-schema.json` | `9c205507cd995ff90f1e3c7fd4e3f674de25e06d5e5b5de003e517467d7d5ed2` |
| `oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py` | `40dd84136ed4018b916eb5b461ed0ebb97a0701f0b724056d58f683a97d330fa` |
| `oracle/acp/callable-evaluator-v3/source/scope_gate.py` | `2514c327cb86ddb2e9aba1fe46f036dcc15ff4292dd72ca92c931f13bfec1dcc` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_contracts.py` | `1b68e37791a6a2ec1c1a979a3d40864d613e74d89e478e22ff2e58f3fa62c1f6` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_probe_isolation.py` | `ad2cb644fdf0bed5a026b846f2a68630c31694949407e8b02a6f38eb0b0de7fe` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_process_results.py` | `7ab2961834694dd2e61fa41d895c98ee56602102c8790466a83c727876bf92dd` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_schema_migration.py` | `59c16be70547e99576e777c2430d060efdcb9fb1df7664fec1a00b42ec366274` |

Context bounded_runtime.py SHA256 `64720b07db2ce08c98002cb21a13f9d3056c982a2e2540f8c474f2c3e62b9c20` was read to trace the actual scope ordering; it is an A2 support input outside the20-owned A4/A5 set, not retroactively bound by this held receipt. Root/A2 must bind any required runtime change in the next generation.

# Independent public static integration review —20261014 r2

**CLEAR for the exact root integration delta and retained public-only204-test composition below.** This approves the sealing source inventory, explicit static-suite wiring and test-only staging adaptation. It does not claim C compiled, native monitor/qualifier execution, private/full24 qualification, accepted preparation, candidate/API authority or release. Root retains checkpoint/Git/remote and later execution custody.

## Exact evidence and source binding

Evidence root: worktree `callable-evaluator-v2-evidence/build/v3-composed-static-20261014-r2/`.

| Evidence | SHA256 |
|---|---|
| inputs.json | `c50da7abeed6eeba6422909e96d33c2fde21fe49e6c4c90356c6d60e832624a2` |
| combined.log | `8abdde7f05c44eba8922ae05956ab7329699c62ae6fb502d2efc5002334dd6e8` |
| integrity-after.json | `4cffee44863e5e0976068e66acd9f0bc3a46db23db9546a24d35deeb1f512dc2` |
| public/build/callable-evaluator-v3-static-ci/result.json | `465677ad80146b7912b2406e48db0561acd9318648ca8ad1abb2e692c9cafbca` |

Independently recomputed all42 input byte lengths/hashes at both current source and staged source: every entry matches. `integrity-after.json` records42 files and no changedInputs. The retained result's12 module counts sum exactly204; the combined log records204 tests with OK. Result reports0 failures/errors/skips/forbidden attempts, Python3.14.8 and fastjsonschema2.22.2. These are retained execution artifacts inspected by this reviewer; no suite was rerun. The log does not carry per-module OS origin attestations; the source/stage byte equality and staged result location are the binding inspected here, not a stronger kernel provenance claim.

Relevant delta pins (under source `oracle/acp/callable-evaluator-v3/source/`):

| Source | SHA256 |
|---|---|
| freeze_v3.py | `da9206ef2017a0c688a06bece094a57517ac5cbb4947fa4811ee8980b6fbdfa2` |
| tests/run_static_tests.py | `30bea0fb1ff8cbc588189504b8a3c220d66dfeff8a525110611620ef13e18efd` |
| tests/test_execution_source_inventory.py | `54d513ec76e5e5197dd0e7b2ebe11dbb1b7f484887ff6a1b71b4a7d0c2342909` |
| tests/test_runtime_worker_proof.py | `69ec77c1aab32c78eaed49652b8f5cba4b23aff629b991233593626184ea5bb4` |
| bounded_runtime.py | `604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07` |

Production runtime remains the separately accepted003 **604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07**. It has no production delta here. Monitor/parser/A1/consumer/A3/qualifier input identities are all bound by the42-row inputs.json; this integration review does not substitute for their scoped implementation reviews.

## Sealing inventory delta

Compared the retained portability source baseline `build/acp-decomp-effectiveness/callable-library-v3/static-ci-portability/public-only-staging-001/.../source/freeze_v3.py` SHA256 **2f1b7735bf57ab9f13c12e55166e67864610e8be90ae46bacf563256bc762505** against current source. The complete textual delta is confined to execution_source_paths; every other function/class/body and top-level bound is unchanged.

`execution_source_paths:306–341` remains a fixed, nonrecursive lexical inventory. It now includes monitor C at the source root, and explicitly selects qualifier/surrogate C plus the static runner/support at the tests leaf. A separate fixed tests/fixtures leaf selects only historical_counterexamples.py. Existing root Python, contracts JSON and toolchain Python scopes include the parser, proof schema, builder and monitor_inputs. The required set uses exact relative paths instead of basenames and explicitly requires those machinery/support paths plus all three new runtime/proof/consumer test modules. A missing required file cannot be silently sealed or satisfied by a same-basename file elsewhere.

The three formerly omitted imported support files are `tests/run_static_tests.py`, `tests/static_test_support.py`, and `tests/fixtures/historical_counterexamples.py`. The latter is a hash-pinned authored public model of withdrawn defects, not a copy of historical private oracle source/truth. Inspection confirms it contains only minimal public process/schema/inventory models; static_test_support AST-loads the exact expected function set from its bounded pinned bytes.

Enumeration charges every yielded directory/entry, including ignored entries, before selection; shared TreeBudget limits remain20000 nodes,512MiB payload and depth64. File/directory/type/population limits remain the same. Symlink/special kinds refuse before selection; admitted files must be regular; directory identity is rechecked. The added leaf does not recursively traverse private/fixture trees. Root-to-directory no-follow FD walking, bounded file admission, source identity checks, complete CopyPlan reservation before output, exclusive no-follow writes, post-copy revalidation and missing-source refusal are unchanged.

The unchanged production freeze path requires checkpoint keys exactly equal execution_source_paths, hashes/admit_files each source, copies each under artifacts/execution and checks inventory/bytes again afterward (`freeze:428–431,473,481–484`). Thus added paths reach the execution seal rather than merely entering a test-side list. The existing private lexical scope is unchanged; its presence does not mean this public static stage copied private data. Qualification/seal authority gates remain unchanged and static machine pins still cannot self-promote.

The new three-method inventory suite uses authored temporary files, verifies positive selection/unselected exclusion, removes each required member and requires sealing refusal, and substitutes a symlink and requires unsupported-kind refusal. It exercises the actual source selector, not the full production seal or a native launch. Existing bounded admission/copy tests supply the unchanged lower-level behavior; no new resource/budget weakening appears in this delta.

## Explicit public test wiring and native exclusion

Compared retained runner baseline **e4f6ef488819f2633d98579457efdc086da29075998fc6c0326ca534b9573b2c** with current **30bea0fb1ff8cbc588189504b8a3c220d66dfeff8a525110611620ef13e18efd**. Its only byte delta adds four exact module names; guard and execution bodies are unchanged. The suite now explicitly imports these12 modules and refuses any empty module:

| Module | Actual retained methods |
|---|---|
| test_identity_graph | 20 |
| test_builtin_types | 6 |
| test_contracts | 3 |
| test_probe_isolation | 2 |
| test_profile_limits | 16 |
| test_link_inputs | 31 |
| test_process_results | 14 |
| test_schema_migration | 32 |
| test_runtime_worker_proof | 11 |
| test_worker_exec_proof | 55 |
| test_worker_proof_consumers | 11 |
| test_execution_source_inventory | 3 |

There is no test-file glob/discovery that would launch qualify_worker_exec.py. Pure tests may import its definitions/source, but its native entry remains behind explicit invocation and the guard; the C harness/monitor are inventoried, not compiled by this gate. NativeDeny is installed before test loading and rejects declared process/network/signal/resource-policy paths with remembered swallowed-attempt accounting. Its three synthetic self-tests reset their own counters before actual suite accounting. Zero recorded attempts is evidence for that declared guard, not proof of all conceivable effects or native capability.

## Test-only69ec staging adaptation

Full byte comparison with the runtime003 frozen test **7ea3ee8f13dadbaf3e16f99cca6517b1465574544638ab3f13ddbb8cd95d5ff3** shows one method-only change: the fixed monitor provisioner test uses its actual repository-owned temporary leaf and mocks _repository_root to the explicit staged repository context, while _run_scoped remains inert. This allows a public layout without .git; actual production repository discovery and provision_worker_monitor policy are unchanged. The test retains fixed source/compiler argv/output-name/phase/channel-free assertions and no native call occurs. No unrelated production predicate or test expectation is relaxed.

Prior failed staging remains separate at `build/v3-composed-static-20261014/`: result **770dd2218aabbb9bcdeecb1fac4645d1df46cded5fd4a870ce6c6cdf57cd731b**, combined log **ec7592683cbb5b94c62a7eaa9b96ce635b805793ed9bb161074f6603b61753b1**. It discovered204 with0 failures and1 error,0 skips/attempts; the trace is the old test's nonexistent path derived through the enclosing repository rather than its staged leaf. It is not success evidence and has not been erased or relabeled.

## Public-only staging and generated artifacts

The staged source contains every one of the42 declared public inputs and no missing declared input. Direct checks confirm no source private/, expected/ or history/ tree; no preservation-manifest.json, environment-pin.json, helper-pin.json or worker-exec-monitor.json was copied. The only extra staged-source file observed after tests is an empty0600 synthetic `exec-proof-receipts/0b95c276a7f54b45b715ab06c8a2ea0f/worker-proof.jsonl`, SHA256 **e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855**. It is generated inert-test state, not a copied input or authenticated/native receipt. Consequently42 denotes the verified source-input inventory, not the entire post-test filesystem population. No cleanup was performed by this reviewer.

No actual private expected/native history bytes were inspected or copied by this review. Only the explicitly public authored historical fixture is intentionally included as imported support. The current source and staged inputs were all stable at the final observation.

## Disposition

No blocking finding in this integration scope. Root can use this review for its source checkpoint decision, subject to existing project CI/review requirements. Guarded public static204 completion does not establish source-to-binary C correspondence, local/hosted primitive native execution, real ptrace/proc/report-denial/cgroup/loader behavior, full24 matrix/control/mutant acceptance or immutable production sealing. Those remain separately authorized gates.

Read-only source/evidence/AST/hash inspection and this additive report only. No tests, compiler/C/JVM/native/proc/process/Git/remote/CI/auth/model execution, source writes, private acquisition, existing artifact deletion or descendant. Earlier reviews remain unchanged.

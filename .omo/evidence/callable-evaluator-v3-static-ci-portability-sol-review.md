# Callable evaluator v3 static CI portability review (Sol)

Verdict: **CLEAR for the eight frozen portability paths and the exact public-only staged component result.** No blocking defect was found in that component. The current composed evaluator and any future preparation seal remain **unqualified**, including the three missing execution-inventory support paths described below. This verdict does not waive that gate.

Review used read/hash/JSON/AST inspection only. No test suite, source module import, native/compiler/helper/candidate, CI, Git, remote, auth/model, credential or network execution was performed. Only this report was written.

## Exact binding

The held freeze is `build/acp-decomp-effectiveness/callable-library-v3/static-ci-portability/freeze.json`, SHA256 `07eacaf1ce838d6a793789c6dec500752197b4fc33df3430ca6bb7394bab1ded`. Producer report SHA256 is `7172f421e84343dd03f2698cbcd72a471390e9ba26de8334697cb4810e29121e`. All eight owned path lengths and hashes match current bytes; all seven owned Python files parse as AST without importing them.

| Owned path | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/tests/static_test_support.py` | `eb087c83ae48c239a87422e39a9a1b399bf3a4c41c480c6da8c5465dcf7a4449` |
| `oracle/acp/callable-evaluator-v3/source/tests/run_static_tests.py` | `e4f6ef488819f2633d98579457efdc086da29075998fc6c0326ca534b9573b2c` |
| `oracle/acp/callable-evaluator-v3/source/tests/fixtures/historical_counterexamples.py` | `57dd58f2fdfb292defdbd31561e78fdc4120b2a102efd4e3b9af7cc31b3b0c1b` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_process_results.py` | `a570cfbbce926152a37540cf60a728e198ffaf7db42b82587967f5691f07bee4` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_schema_migration.py` | `9cc902726d21f0197da988d39172942a011e1e9a908ad176754939a41999b948` |
| `oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py` | `83bc72cdfc662ae89b353e9b9f8d00b2dc83ba13d3b8d5339443b378f8361d67` |
| `build/acp-decomp-effectiveness/callable-library-v3/templates-current/prepare_v3.py` | `5d019cf1f9811f7befda9f2aaeb29bbef26b5f919530cc2e6ec733ea0d171f0f` |
| `.github/workflows/ci.yml` | `406fe443ca9dd85966466f6282e333dbbfbf7c8fb2b9b85fdc340aa7f7df7975` |

## Three meaningful counterexamples — CLEAR

The historical fixture expressly identifies itself as an authored minimal model of wrong behavior and disclaims byte identity with the withdrawn full modules. It names old public logic hashes as provenance, not private declarations or expected native data. Its exact source hash is checked before AST loading. The loader admits exactly four named function definitions and executes only those definitions with explicit pure synthetic bindings; the pinned fixture has no imports, decorators or top-level IO/native/coordinator execution.

The three comparisons retain independent, observable wrong outcomes:

- **Missing streams:** with otherwise complete synthetic process proof and absent stdout/stderr fields, the historical projection defaults to empty bytes and reports matched. Actual current compare_process reports unknown and does not fabricate empty streams. This difference is not a copied assertion of the current implementation.
- **Load phase:** the historical projection permits an ordinary shape/status `passed` load claim while the actual current closed report rejects it. The old projection also rejects an invented status, so it is not an unconditional acceptance stub. Reusing the pure current summarizer for unrelated accounting does not erase this deliberately different load-phase decision.
- **Inventory work:** the historical projection materializes/sorts all fifty synthetic entries before its tiny file/byte limits refuse. Its counterexample checks fifty yielded entries. A separate actual current streaming admission control records four yields/three stats at the equivalent bounded frontier, before payload reads. These exercise work-before-limit versus stopping during iteration, without using a real old/private population.

The fixtures model these specific historical semantics; this review does not claim to have executed the full original historical modules. Tests no longer need ignored evaluator/freeze copies or a trusted coordinator to reproduce those wrong outcomes.

## Shared predicate and import boundary — CLEAR

The all-unknown positive-control regression calls actual public `control_passed`; it does not reimplement that policy inside the test. Matching, mismatched, unknown and refused/build-state controls remain distinct. The shared function documents that reports must already satisfy closed schema/accounting and grants no native authority.

After removing only the new docstring, the public FunctionDef AST hashes to `dd48ca2e510214f3fc019de334a278d3fa85b23171fb31b0c16f2284e3cb067d`, exactly matching the prior-policy AST digest in `trusted-import-delta.json`. The trusted template imports this exact public predicate and has no duplicate control_passed definition. This verifies the retained policy-equivalence attestation; no ignored coordinator was imported or run by this review or by the public staged test dependency set.

The guarded runner installs its audit hook and default process/policy/PID/signal mocks at line86, before package version resolution and before loading any of the eight test modules at line101. The top-level support import precedes the hook, but that exact reviewed support module only imports standard library modules and computes/validates declared path layout; it imports no test/production module and launches no operation. All test/production imports occur under the guard.

Permanent audit denial covers the listed process, socket/network, resource-limit and signal operations. Three synthetic audit events exercise refusal without requesting real side effects. Unexpected attempts increment a bounded recorded counter before raising, and a swallowed exception still causes the final gate to fail. Individual tests can install positive local mocks for pure runner/resource-policy behavior; a real audited operation remains denied. The gate rejects empty suites, failures, errors, skips and unexpected denied attempts. This is a trusted static-test guard, not a native containment or arbitrary malicious-extension security qualification.

`static_temp` uses only three enumerated fixture areas below the source-derived repository root and rejects resolved paths escaping it. Process/schema tests create their own parents; runner sets tempfile.tempdir/TMPDIR and disables bytecode before module loading. The staged tests' synthetic directories named private are authored temporary fixtures, not ignored/private source inputs.

## Public-only staged proof — CLEAR, component only

`staging-inputs.json`, SHA256 `a6cde8a18ac69bf8836dff31754f2fe5051ab0bb6d3ae8d42691f7fd5ea8269d`, records exactly32 public files totaling323,484 bytes. Every staged file independently matches its recorded hash/length and stays within the staging root. The only current file outside that input allowlist is generated `build/callable-evaluator-v3-static-ci/result.json`; no ignored historical module, coordinator, original private declarations/caller/cases or observations file is a staged input.

The pinned log, SHA256 `ef4d6b43087966068f0c0881a3aa6178a92fdf63833a5d697b25fe344a7e6e75`, records99 tests in2.079s, OK. Structured result SHA256 `eb7d2b0ffffaf9ed8ea69521b2d02b5481ab1814cbe30e7a66b293ea43626bae` agrees: identity20, builtin6, contracts3, probe-isolation2, profile10, link17, process11, schema30; zero failures/errors/skips/forbidden attempts. Counts sum to99. This audit did not rerun them.

The CI delta invokes the guarded Python-B runner with pipefail, after the existing requirements installation, and always retains its result/log artifact. New static TMPDIR/pip-cache/evidence paths are below github.workspace/build. Requirements remain pinned and setup-python remains3.12. The observed staged pass is Python3.14.8 with fastjsonschema2.22.2; actual GitHub Python3.12 execution is still unobserved. No CI pass is inferred from the local receipt.

## Current drift and mandatory integration gate

The freeze's changedSinceStaging list correctly describes two shared files at its creation. At review time, the owned eight paths and all staged32 inputs remain pinned, but **nine unowned live files** differ from the staged snapshot: bounded_runtime.py, build_contract.py, interface_gate_v3.py, candidate-build-profile.json, toolchain-001/build_helper.py, link_inputs.py, pin_environment.py, pin_helper.py and tests/test_identity_graph.py. These are concurrent component changes, not edits by this reviewer. The99-pass claim applies to the exact staged snapshot, never to those current composed bytes.

The inspected execution_source_paths implementation still scans tests nonrecursively with a test*.py filter. It therefore excludes all three new support inputs:

- `tests/static_test_support.py`
- `tests/run_static_tests.py`
- `tests/fixtures/historical_counterexamples.py`

**A future trusted execution snapshot/preparation seal must not be accepted until root integrates these exact paths, including the fixture hierarchy, into the bounded inventory/copy/binding contract and verifies the fresh composed generation.** Checked-in public CI can access them directly; that fact does not repair a trusted preparation snapshot that omits them. This known gate remains required and is not waived by the component CLEAR. No unowned inventory source was edited here.

No driver/link inventory, native machine closure, helper/caller/compiler execution, 24-scenario observations, accepted preparation, hidden-input isolation or model-trial authority follows from this static component. Current composed evaluator qualification and its required integration review remain separate. Work ends with this scoped source/artifact review.

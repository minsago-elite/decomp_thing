# Callable evaluator v3 A2 profile/runtime source review — CLEAR

Terminal verdict: **CLEAR for the four frozen A2 files and the stated static scope.** No blocking A2 source finding was identified. The end-of-review shared-helper drift described below prevents treating the old receipt as a current live dependency closure. This does not clear mutable A1/A3/A4 integration, a global source freeze, native enforcement, or an evaluator/model trial.

## Reviewed binding and method

Reviewed `build/acp-decomp-effectiveness/callable-library-v3/static-profile/freeze.json`, SHA256 `887e15b22b6340b5b50129c722da3874b8dc35dbd5fc8212494758aab4c6f209`. All nine manifest pins matched their file sizes/hashes, and all six source/dependency snapshots matched their corresponding live files. The five Python files were independently parsed with `ast.parse`; no reviewed module was imported or executed. The profile's immutable fields were independently compared with the literal embedded `_IMMUTABLE` contract and matched exactly.

| Frozen A2 file | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/bounded_runtime.py` | `64720b07db2ce08c98002cb21a13f9d3056c982a2e2540f8c474f2c3e62b9c20` |
| `oracle/acp/callable-evaluator-v3/source/build_contract.py` | `a80a964f83c5d06dfbf2d544d923e649a89457aceab7a3cd49abe65a58310c3f` |
| `oracle/acp/callable-evaluator-v3/source/contracts/candidate-build-profile.json` | `a9bf4e71ac228ed703ad288c0baccad6e3173fb5101bfa97dd31fcfcd0157d4b` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_profile_limits.py` | `a8abb7c0eda2d7d85607ffa93775356804c6cdbf0105af2da1637a7151b8f0da` |

Read-only AST dependencies are `scope_gate.py` SHA256 `2514c327cb86ddb2e9aba1fe46f036dcc15ff4292dd72ca92c931f13bfec1dcc` and `toolchain-001/build_helper.py` SHA256 `14622c130eded95016e4f8c9be63054fa60efc97244d473b58c6912c7cd75c51`. Their use here is static source evidence, not helper or scope execution.

The coordinator supplied the approved be68 A2 scope. No Git command was executed. As an independent retained-file comparison, v2 `oracle/acp/callable-evaluator-v2/source/contracts/candidate-build-profile.json`, SHA256 `3aace398485f3d4f07d6edaa30c4d7604c85ef8585727657c0ebdd34ce1c1d13`, has identical target/environment/commands/exports/analysisIsolation values and identical values for all eleven pre-existing bound keys. This is a comparison to those exact retained v2 bytes, not a claim to have reconstructed a historical commit diff.

## Static acceptance results

The profile discloses all finite runtime/supervisor/helper limits in one closed schema-3 contract. It preserves the reviewed compiler argv, flags, environment and isolation values. Core size 0, CPU 30 seconds, address space 2 GiB, open files 64 and file size 16 MiB are represented as soft=hard per-process RLIMITs. `bounded_runtime.py:71` obtains those same immutable values, refuses altered limit dictionaries, and applies precisely those five limits in the pre-exec hook. CPU is explicitly per process; the cgroup receipt declares aggregateCpuLimit null and aggregateCpuLimitEnforced false. There is no invented aggregate CPU budget.

`execution_bounds` at runtime line 41 validates finite positive deadlines, integer output caps, known phases and each phase ceiling. It supplies the same values to capture, stdin admission, polling, waits and cleanup. Runtime line 151 uses the resulting bound record rather than separate numeric policy. Managed launches request tasks 32, memory 512 MiB and swap 0; admission checks actual cgroup files and identity before writing the gate's admit byte. This is source-level verification of the requested/checking logic, not observed kernel enforcement.

The visible helper build remains 60 wall seconds with 1 MiB per stream; candidate compiler phases remain 30 seconds with 64 KiB per stream. The helper AST dependency passes the declared helperBuildSeconds/helperOutputBytesPerStream values into bounded_run. The helper retains the same 30-second per-process CPU RLIMIT. Scope admission uses the profile's declared five-second deadline and 0.01-second poll. Other helper graph/isolation phase enforcement belongs to the separately owned integration and is not globally qualified by this review.

`build_contract.py:74–81` loads and validates bounded local JSON only. It rejects duplicate keys, oversized input, nonfinite JSON values, extra keys, changed immutable fields and bool/int policy substitutions. The loader performs no tool resolution, subprocess call, resource-limit change or helper build. Execution-side GCC byte identity checks are separate in `profile` and `_visible_snapshot`. The one profile snapshot used by visible rendering binds both the full JSON prompt text and manifest digest. `verify_visible` checks both artifacts against that validated snapshot. Import dependencies are acyclic: bounded_runtime imports build_contract; build_contract imports only standard-library modules; gate/helper dependencies point toward those modules, not back from them.

## Runtime observations and failure honesty

The new observation fields describe launcher creation, PID identity, scope verification/admission, capture, wait and cleanup separately. They do not assert evaluator/API success. A Popen exception propagates before a launcher receipt is created; missing launch evidence remains unknown rather than fabricated.

After launch, incomplete capture, timeout and parent verification failures raise with an attached bounded receipt. The receipt preserves bounded stdout/stderr as untrusted bytes and uses exitCode null on these exception paths. A managed launcher that exits before a verified scope cannot return normally: the post-wait assertion enters the failure path. The additive infrastructureFailure flag is affirmative only for parent-side AssertionError while managed scope is unverified. Numeric exit codes and stderr marker strings do not set it. A false flag is not proof that failure was candidate behavior.

Cleanup and stream-close exceptions also raise. The attached receipt records cleanupVerified false, even if a real launcher exit code was already observed. A consumer must not equate that numeric launcher exit with a successful process/evaluator run. Successful cleanup updates the separate root-reaped and absence facts; partial capture remains partial. No cleanup failure path becomes a normal return through the runtime API. The separate A4 aggregation/report owner must preserve these distinctions, and its mutable output was not accepted or frozen here.

## Existing verification and limits

The pinned producer log `tests.log`, SHA256 `7a8878bee5faee3c6644436b810dc5bc340964cc6ef0cadcb880e7ff05ff7432`, records ten pure mocked tests passing. `command-receipt.json`, SHA256 `8a818b21d2fca7e1fa2c0e97d9d7f023ef6c22c2299c1b9d6cd27d418a0ad2ec`, supplies the exact producer command/environment and explicitly limits the claim to standard-library mocks/AST checks. Its test source guards subprocess, host resource changes, pidfd and signals, and tests profile mutation, phase bounds, rendering, scope failure, partial output, timeout and cleanup failure. This reviewer inspected those controls and their pinned receipt; the tests were not rerun, so there is no new independent test-execution claim.

Only read/hash/JSON/AST comparisons and this new report were performed. No source, fixture, preparation, old candidate/result or earlier database evidence was changed. No native compiler/helper/candidate, model/auth/credentials, database, CLI workflow, CI, Git, remote or network operation was executed. All source assertions above are limited to the exact pins; mutable A1/A3 currently at ITERATE and mutable A4 remain outside this CLEAR. Integration, successful managed/kernel/native execution, complete evaluator qualification and original-input/model trials require their own frozen review and authorization.

## End-of-review dependency drift

At the final hash check, all four owned A2 files, scope_gate.py, the freeze, producer log, command receipt and README remained unchanged. The frozen six source/dependency snapshots also remain unchanged. The live shared `toolchain-001/build_helper.py` changed from frozen SHA256 `14622c130eded95016e4f8c9be63054fa60efc97244d473b58c6912c7cd75c51` to `c891ae9f2ba0ad33d75c56d7c9de3423934458345af45c6b2ea8fecd19fed7f4` during this review. The initial all-nine live-pin match was true at initial inspection; it is not a claim of a final all-nine live-pin match.

The observed delta adds an interface_gate_v3 `_complete_execution` import/check, uses load_profile, and supplies phase='helper-build'. Those live integration changes and their transitive dependency behavior were not accepted as part of this four-file A2 review. The prior producer test log still binds the exact old frozen dependency snapshot, not this new live helper or the mutable combined source tree. The coordinator was notified. A new integrated freeze/test/review is required for that live closure; no change to the four reviewed A2 pins is requested by this scoped verdict.

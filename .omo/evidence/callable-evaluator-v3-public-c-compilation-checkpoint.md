# Public evaluator C compilation checkpoint — 2026-10-14

Both fixed public C sources compiled successfully. Neither output was executed.

| Output | Bytes | SHA256 |
| --- | ---: | --- |
| worker_exec_monitor | 30,520 | `8b2e0ddd6f902155a00b3653cd495ba29a3a960563c3dd70ad9b0ff18675eb2f` |
| barrier-harness | 16,448 | `f8c34f973ef881af28b27d172918a69b3275b71518ef37114bc490e222e9966a` |

The exact result is retained at `build/acp-decomp-effectiveness/callable-library-v3/compile-only-rebind-002/output/result.json`, SHA256 `98502ccbd8f69a34d4b6ec2f5196001ce365c8d911e554695b574c9857ad386c`. Both files have ELF magic. Monitor C source remains `746277d7d06a3a0a3ac660743d92d4c4eb7da48e1fb325c7464c4d7c94633e93`; surrogate source remains `2d7c4e90d7ecece6aa0f85f8214b73a3a294579afebc03e5db7ea739503b8d6e`. The accepted runtime remains `604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07`.

The fixed monitor builder used the channel-free trusted provisioning route. Its receipt SHA256 is `18b2f6cc11cf17e2e9e802740484f84fddb2d09b47880e0d14733bb8a2a33e1c`: launcher creation, kernel scope verification/admission, capture, wait, cleanup, root reap and final kernel absence are true; exit is zero; timeout, output overflow and infrastructure failure are false. Provisioning-only is true; worker-exec and worker-termination verification are false.

Both outer controller stages captured complete output, returned zero, reaped their direct child and verified private process-group absence. Each stage sent its one recorded owned-group SIGKILL before the first reap, as the compile-only controller specifies. This is not intervention-free execution evidence. The separate inner monitor-build receipt supplies its managed-scope cleanup evidence; outer-group cleanup alone would not prove it.

Setup002 manifest is `f055d39f308b0ff98661427ffa2286dfca72e57218a42a37f257a08d8dfe61ee`. Independent setup review is `.omo/evidence/callable-evaluator-v3-compile-only-rebind002-sol-review.md`, SHA256 `a2d8c7d90938964abbea4447dab05a200308c3bb2e950410ac75936760565cbd`. Unexecuted setup001 and its deadline finding remain preserved separately.

The provisioning manifest remains explicitly unqualified with an empty dependency list. The 58 observed tool/header/runtime pins and 51 absent candidates do not establish a complete effective compiler or loader closure. The controller enforces per-file limits and checks bounded output inventory; it does not enforce a hard aggregate disk quota.

Native qualification, complete environment binding, source-to-native execution evidence, the private 24-scenario matrix and final sealing remain pending. The existing qualifier rebuilds its harness; any future claim that it exercised the prebuilt surrogate must bind and compare that new output. No candidate, model/authentication trial, API-entry evidence or production authority is supplied by this checkpoint.

# Provider cleanup operation diagnostic — independent source review

Verdict: **CLEAR for this exact diagnostic delta.** No concrete cleanup operation or TLS fix is established. Kotlin regression and actual qualification remain unexecuted.

## Exact scope

Worktree `.claude/worktrees/wf_ce026d1b-c24-68`; freeze `build/provider-c04-cleanup-operation/freeze.json` SHA256 `f36ccfae6de62d08bb209f06aa7f0f8260a1215102f7613fc49a35d6414258bd`.

- Broker SHA256 `6e44817191e15546d92b731e0ff4d1b8375db71e04ed543eae92992bcde44ffe`.
- TLS fixture SHA256 `f6dbc965213f794c93e99075da475465010c99cbb2b12e8bc9c56c2e280cefc1`.
- Broker regression SHA256 `1285a3e73e8bf316471b96e865ab3a42e5e9abda124b6605434fd63e5559ebb4`.

All11 frozen source/evidence hashes and sizes independently matched before and after review. Only the three named source files belong to this delta. Other owners' projection/archive or production files were not edited or approved here.

## Source findings

1. **Closed, owner-local storage.** The added enum has exactly five fixed operations. Private `ProviderHttpAttempt.firstCleanupFailure` stores only that enum in an AtomicReference. `recordCleanupFailure` accepts no Throwable, message, stack, request, authority, path, body or credential; it performs compareAndSet(null, operation) before the existing sticky cleanupFailed.set(true). Later failures/successes do not reset either fact. Concurrent selection means the first successful CAS, not a globally ordered physical exception.
2. **Cleanup behavior preserved.** Cancel still closes raw, cancels the future and finishes queued ownership. Final cleanup still closes raw, immediate connection, TLS and response in that order, clears closed references/request/receiver, selects the same callback from the same resource/outcome checks and sets execution finished in the same finally. Exceptions remain swallowed by the same runCatching/onFailure sites; no exception object/cause is retained by the new state. resourcesClosed and all lifecycle/deadline/admission logic are unchanged. Independent reversal of only the enum/field/helper and five diagnostic call substitutions reproduced the entire prior Broker bytes exactly (prior SHA256 `9bcb01a14be5cde023565d864ac1246cce10632dc05bc735f52a39d688b3334a`).
3. **Bounded diagnostic only.** The existing TLS failure diagnostic reads this private field and emits only enum.name or NONE. It adds no getter, public owner access, network selector or authority surface. Existing metadata-only observation, maximum four owner rows,2048-character suppressed diagnostic cap and fallback diagnostic remain. No Throwable.toString/message/stack or transport input was added. Existing primary-failure preservation and diagnostic-unavailable handling are unchanged.
4. **Meaningful but unexecuted control.** The new Kotlin regression constructs an inert owner/unconnected throwing Socket, calls cancel, then failing final close and successful retry. It asserts the first operation remains CANCEL_RAW_CLOSE, sticky failure prevents resourcesClosed/completed success, and request bytes are erased. It does not dispatch a request or identify the failing operation in the actual TLS scenarios. Compilation/execution is still required; source inspection is not a passing Kotlin test.

## Native capsule composition

Independently inspected the unchanged tracked selector in `AcpProviderNativeDnsContractTest.kt:737–771` and checker `scripts/verify-acp-provider-dns.py:27`. The selector includes only AcpProviderNativeDns/AcpProviderDns/NativeNamespace/ProviderDns prefixes and the four explicit observer roots (including their generated nested classes). AcpProviderBroker, ProviderHttpAttempt and the new AcpProviderCleanupOperation match none of these roots/prefixes and are not referenced by the observer source. Checker roots remain synchronized. Therefore the new enum does not add a dependency to that reduced capsule graph by source inspection. TLS fixture diagnostics use the ordinary main classpath; normal compilation must include the new enum there. No reduced capsule was built or run.

Observed selector/checker hashes (outside this delta's frozen authority):

- Native selector source: `c7ed189813be1a42b88a554fddb20b67aff19550659e6b41e04587b8c2d9cc8b`.
- Checker source: `ab6ed5c5086c8d96d5e33eb771b9b3726e2b0be9ca77706d5f5a95c914624b36`.

## Evidence and remaining gates

Retained check-result.json SHA256 `56f40943f26fe3950c768faa403dcc7237cae0beeb883c1094f24b3de2f6a51a` records five catch-site checks, exact reverse comparison and25 modeled finite label sequences. This is static/model evidence, not concurrency testing or product execution. I independently rechecked the full reverse comparison and pins; I did not run the authored check script or Kotlin test.

No actual throwing operation was observed, no four-scenario TLS repair/pass is claimed, and no R9 execution or qualification is authorized by this review. Root retains compilation, actual operation diagnosis, native/TLS cleanup and other lifecycle release gates. No source/test/JVM/compiler/native/network/auth/model/Git/remote execution occurred; only this new review was written.

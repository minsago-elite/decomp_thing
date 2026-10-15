# TLS refused-port fixture correction — independent Sol review

**CLEAR**, limited to the single frozen test-source correction and retained short controls. No production/provider/native qualification or historical hosted-cause attribution is granted. Root owns Git/remote operations and current-head required CI/review gates remain.

## Exact source and evidence

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

- `src/test/kotlin/decompengine/acp/AcpProviderCredentialFreeTlsFixtureTest.kt`: `6dc0fad3a61a197705e656c0e118ee7b1a74dbf7ac975a2b213e73adcdc824fc`.
- `build/provider-tls-refused-port-correction/source-freeze.json`: `3a0708a1804d2d304dca5a095a708152ffcfb0b967894bf1d46994666f488202`.
- Handoff: `4e9882a930c83d9c0f9ac1beb6a6439cf649809f425af119d70104493b4b6d40`.
- Verification: `5e552e0406f33c25ec869c740e071e1b85b0bf2f6392e1ce09ab915df2d8ea2a`.

All12 frozen evidence hashes and all33 current main/test source bindings in the verification were independently rehashed successfully. Source delta is confined to the refused-connection test; no new annotated test or production edit is introduced.

## Source assessment

At line402 the refused endpoint reservation remains open inside `use` while `RawTlsFixture` constructs and immediately binds its own listener. Both bind127.0.0.1; with the reservation held, line412 asserts distinct port numbers. The reservation closes at line413, before fallback start and before backend request dispatch. Thus the requested first endpoint is refused rather than a live dummy listener, and fallback cannot accidentally be that endpoint because it already owns a different port. Exceptional paths retain automatic reservation closure.

The original denial assertions remain: terminal failure, second reflected `connectOnce` rejected with the exact sanitized IOException and no nested cause, second socket unconnected and localPort−1 before network I/O, fallback counter0 and released bytes0. Existing other test controls requiring exactly one approved attempt are unchanged. `closeRawVerified` still closes the broker and verifies backend transport/executor/future termination, closes the listener/all accepted sockets, awaits executor termination, checks socket census and the shared cleanup deadline. No retry, timeout increase, unexpected-connection allowance or denial relaxation was added.

## Retained verification and limits

Read-only inspection confirms the actual old-order forced-reuse overlay failed exactly expected0/actual1 in533ms, after the earlier second-connect denial checks. The corrected actual fixture discovered/started/passed1 test with zero skips/aborts/failures in293ms. Main/test/compiler results and actual class-origin records bind the retained private compile outputs; selected Broker/Core/policy classes came from the freshly compiled main closure, selected corrected test from its fresh test output. These are retained author executions, not reviewer reruns.

The forced overlay demonstrates a realizable test ownership defect capable of producing that counter symptom. Historical hosted port numbers were not retained, so the actual hosted cause remains UNKNOWN. This does not establish production fallback or universal network authority. Existing broader source reviews and historical evidence remain untouched.

Review performed source/evidence/hash reads only; no loopback/native/provider/auth/model execution, dependency acquisition, Actions or Git/remote mutation, and no descendants/live sessions. Only this report was written.

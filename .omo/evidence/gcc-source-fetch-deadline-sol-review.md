# Independent Sol review: GCC source fetch absolute deadlines

**Verdict: CLEAR for the held #89 source correction.** No blocking finding in this deadline/cache/authentication scope. Source remains unqualified for real network/alarm behavior pending root-controlled verification; this review does not close #89.

## Reviewed pins

Worktree: `/home/june/decomp_thing/.claude/worktrees/gcc-source-build-ownership`.

| Artifact | SHA256 |
|---|---|
| `build/gcc-fetch-deadline-correction-001/freeze.json` | `d63a77751c13d798b77938f5c9546bdfccbf4d6cde107e21a8742560730202a7` |
| `scripts/fetch-gcc-oracle-source.py` | `75afc7c10a3d132677be921d2caf1c2aadf333c647f25ea977be534742164c5f` |
| `tests/oracle/test_fetch_gcc_oracle_source.py` | `7cadf809b9f70f39c62f44511b8d03b439ade775951dc2316d69d8bb9a331c0c` |

Freeze declares base `8a1e088069dd41d44c188605130c9c5c621b03bd`. All freeze-listed files/current sources/snapshots were independently rehashed. Read full script, source delta, tests, driver, retained log/results and the locked-file verifier. Sources were parsed as syntax only. No fetcher/test, network, real signal/alarm, compiler/native/JVM, acquisition, auth/model, Git or remote operation was run. Only this additive review is written.

## Source findings

- **One total end, bounded attempts:** `FetchClock`46–67 captures120 seconds before cache verification/SSL setup and never renews that total. Each attempt's20-second end is capped by it; `check()` tests total before attempt. Retry setup and min(1second,remaining-total) sleep at210–213 consume the same original total. Endpoints, two attempts per endpoint and numeric limits are unchanged.
- **Blocking network paths:** main-thread alarm covers opener/DNS/connect/TLS/headers, rather than relying solely on socket inactivity timeouts. `read_chunk`95–108 checks remaining time, shortens the actual HTTP socket timeout and uses `read1`; its dedicated `FetchDeadline` derives from `VerificationError`, not socket `OSError`/urllib timeout. The dedicated catch precedes ordinary endpoint/validation failures. An attempt timeout may retry within the original total; a total timeout cannot become endpoint success. Unsupported transport shape refuses.
- **No late return counted as success:** cache verification/output, opener, reads/writes/flush/fsync, response cleanup, locked-file verification, atomic link/contested-cache verification, staging cleanup and success output all remain under the active clock and/or immediate following checks. Successful outer guard exit also checks the deadline after cancelling its timer and restoring the previous handler. A late body/verification/publication/cleanup/teardown result cannot return the artifact successfully.
- **Alarm ownership/restoration:**69–92 rejects unsupported/non-main-thread use and any preexisting active/periodic ITIMER_REAL before changing its state. It saves the previous SIGALRM disposition, installs the dedicated handler, disarms/restores on entry-arm failure and restores via `finally` on exit; it does not suppress an active exception. The supported contract is an otherwise unused alarm in the Unix main thread, not safe coexistence with another concurrent SIGALRM/ITIMER_REAL owner.
- **Cache integrity retained:** existing files are locked-byte verified; download writes remain exclusive in a temporary directory. A staged artifact is verified before no-overwrite hard-link publication. FileExists verifies the winner instead of replacing it. A valid target published just before lateness may remain while the invocation fails; neither a verified existing target nor a concurrent corrupt target is unlinked/overwritten to simulate cleanup. Retrying does not promote unchecked bytes.
- **Endpoint/authentication unchanged:** official candidate URL construction, HTTPS final-URL requirement, identity content encoding, declared length/maximum-body checks and locked digest validation remain. Main still loads/validates the exact lock and invokes complete `verify_source_release` after signature/archive fetches. No fallback trust relaxation, new signing authority, revision substitution or successful-parser authority was added.

## Retained verification and limits

`pure-results.json`/`pure.log` record14 deterministic controls, zero failures/errors/skips/forbidden attempts, unchanged source hashes before/after. Original fallback/all-endpoint failure/corrupt bytes/cache reuse tests remain. New controls cover slow-progress read1 and shrinking socket limits; late opener/response cleanup/verification/cache reuse/publication/fsync/output; direct invocation of the fake alarm handler; contested corrupt cache; capped total sleep; preexisting alarm/non-main-thread refusal; restoration and late successful teardown. Every timer/signal API is mocked; no real alarm was armed or signal delivered. Review did not rerun them.

The implementation/report explicitly avoid a universal preemption claim for uninterruptible kernel operations or C code deferring Python signals. Late observations refuse success; pure controls do not qualify real stdlib socket/SSL/alarm delivery. The120-second total is per `fetch_artifact` call, not an aggregate two-artifact CLI plus signature/archive verifier budget. Existing final provenance verification remains outside that newly guarded fetch call. These are disclosed scope limits, not silently increased limits or discharged hosted gates. Relevant clean root-controlled CI/verification and roadmap evidence remain required before any closure/release claim.

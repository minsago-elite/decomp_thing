# #1508 private-control concurrency implementation handoff

Exact worktree base: `05b073fc8378bd2faaf0ee4163cf055ba61e11da`. Approved plan SHA256: `59b20924924ca96edfe838fb3977854c4b518a70fce3e683bee2a2502abd525a`.

Current #1508 and #238 were read from GitHub: both OPEN in milestone 16. No Git or GitHub state was mutated by the source worker. This source addresses only the private-control concurrency correction. Required hosted ACP contract and the separate reviewed DNS-B port/composed qualification remain coordinator gates.

## Exact final source

- `src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt`: `bf0075a4178db1f2ed02ecf770e581a69482ea01f7cd43b42a053cbee79e6868`.
- `src/test/kotlin/decompengine/acp/LinuxBubblewrapBoundaryTest.kt`: `62484cddbad86f8daa9d9d2e1afaea734b92045ed8bf105085ae51647bd72305`.
- Harness worker's `src/test/kotlin/decompengine/acp/AcpAgentHarnessTest.kt`: `e53470f516de3c82d1f26021b72893b0087d25d89946fa9a1ef013f0588548c4`.

## Ownership contract

The existing private-control registry monitor protects control publication, exact deletion proof, lifecycle state, scope root leases, reconciliation, descriptor exclusion decisions and scope lifetime detach. Each control object is its nonforgeable record identity; lifecycle is LIVE or PROVED_DELETED. A fresh object token replaces the epoch on each transaction change, avoiding numeric wraparound. Scope membership may remove only that exact proved-deleted record. Refresh retains unchanged identities, owns at most 128 new descriptors transiently, validates the complete live set, and commits one replacement map. Failed refresh closes newly opened descriptors and preserves the original map for retry/close.

A scope independently owns its file/directory root descriptor and original mount event descriptor. Scope root admission/control capture/publication is one registry transaction. Active root leases reject new namespace/physical overlap, including recursive descendant bind mounts using the shared authenticated physical-coverage helper. Root rename/replacement fails admission closed. Scope owner exemption is pinned to the admitted control object. Slow physical checks remain for bind aliases; fast eligibility is recomputed over the refreshed set and disabled for a same-filesystem control on another mount or a descendant source mount. Original mount events are sticky/fatal and finish still compares full mount tables.

The registry monitor covers the descriptor-bound drain, quarantine rename, unlink and link-count/name-absence proofs. Only after all proofs does the record transition/remove and the epoch advance. Failed cleanup remains LIVE and retains prior failure provenance, including after later exact remediation. Only the control's obsolete method monitor was removed; PinnedPrivateTree.deleteAndProve retains its original synchronization with unlinkExactRoot. Hashing, copies, process/callback bodies and waits occur outside this monitor.

Creation retains pre-mkdir epoch notification and publication atomicity. An unpinned/unproved initialization cleanup sets one bounded sticky registry poison guard; subsequent scope/authority/control admission fails closed. The unresolved entry remains in place. There is no automatic poison collector or speculative remediation. Proven deletion/remediation of an ordinary LIVE record preserves prior cleanup failure status.

128 active controls, 128 host staging roots and 128 active manifest scopes remain explicit ceilings. Persistent scope ownership is at most 128 * (128 controls + root + mount event) = 16,640 descriptors, plus existing registry/staging ownership. One transaction can transiently own at most 128 additional refresh descriptors. This bound is not an assertion of host FD availability; real low-RLIMIT allocation rollback is tested. Retired records are held only by bounded previous scope snapshots and ordinary owners, without an accumulating tombstone list.

Private null transaction observation hooks and an optional UUID test value exercise actual locked boundaries; no new production configuration or provider authority is introduced. All test temporary files/logs/evidence are repository-contained.

## Final verification

Production compile passed. Final focused command:

```sh
./gradlew --no-daemon test -x stageFrontend \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.manifest scopes reconcile bounded disjoint churn and retain failed cleanup protection' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.unproved partial control creation poisons all later authority admission without descriptor leaks' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.private controls reject native bind aliases and late callback exposure without denying disjoint grants' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.live boundary hides host data isolates network and launches concurrently through static helpers' \
  --tests 'decompengine.acp.AcpAgentHarnessTest.overlapping receipts retain their own request prompt and provider evidence'
```

BUILD SUCCESSFUL in 1m 14s. Boundary 4/4 and harness 1/1 passed with zero skipped/error/failure outcomes. `git diff --check` passed. `-x stageFrontend` excludes the unrelated frontend staging dependency because the environment has Node 26.11.1/npm 11.20.0 rather than repository pins Node 24.20.0/npm 11.19.0; the normal initial test command reported this mismatch. This is focused JVM/native evidence, not complete packaged-frontend verification.

- `final-focused-boundary-tests.xml`: SHA256 `9623c11a649d6c8ea84bc0b3c2c2fff9c4cc62c15e0b97aea098fca509a0cd6e`, 4/4, 37.416s.
- `final-focused-harness-overlap.xml`: SHA256 `455ad6e71ed38a9fd2af32408d032302e32b41301d2cb910253d9ca7a9e3f148`, 1/1, actual overlapping callbacks, 3.128s.

The deterministic scope test proves two admitted scopes pause concurrently outside the registry monitor; retained deletion, 140 historical registrations, persistent additions and exact stable digests; descriptor recovery; failed replacement cleanup and unchanged replacement bytes; 128 scope/control admission ceilings before extra FD ownership; root moved/replaced refusal; actual lock-held publication/pre-quarantine/post-unlink transaction pauses with peer thread BLOCKED until release; failure on the second refresh retain releasing the first temporary FD; same-path A/B replacement retaining independent mode checks; and cancellation-safe close.

The isolated failure probe enforces real reduced RLIMIT_NOFILE during partial scope admission and verifies FD recovery, then injects post-mkdir/pre-pin failure and verifies retained unresolved entry, sticky poison, rejection by manifest/path/descriptor/new-control authorities and no leaked FDs.

The native bind probe passes real same-filesystem and tmpfs cross-filesystem nested subtree leases in both admission orders, denial before mkdir, persistent cross-mount refresh with fast=false, existing hostile mode/rename/replacement controls, full 4096-file integrity and scale, real 64MiB hash/copy byte equality, disjoint churn during hash/copy, partial-copy cancellation cleanup, mount move/restore event fatality and bind-root relocation denial. Native probe completed 32.008s within its unchanged 45s deadline. Live static-helper concurrent launch completed 2.602s. Harness barriers hold exactly two callbacks before either receipt can complete, then require successful receipts, authorized edits, invocation-bound cleanup and canary preservation.

Intermediate retained evidence includes the initial passed transaction/poison tests and an obsolete source-replacement diagnostic assertion failure. That failure still rejected replacement correctly; the pinned root now detects the pathname change before the old descriptor fast-path message. The assertion accepts the two exact identity refusal messages and retains exception, replacement-byte and FD checks. Mount restore's stack seam was updated from checkpoint to checkpointLocked after the helper refactor; its mutation and fatal-event assertions remain.

## Review and historical limits

Independent source review re-audited exact production hash and found no further blocking source findings after restoring the tree synchronization. Final CLEAR artifact: `.omo/evidence/acp-private-control-concurrency-source-sol-review.md`; the reviewer independently verified the final source, test and XML hashes. No provider/model/authentication call or production qualification was performed. Retained 9cfc diagnosis remains exact historical evidence; earlier fae lower cause remains UNKNOWN. No diagnosis is retroactively attributed to fae.

Port only registry/lifecycle, scope/root coverage and corresponding tests to staged DNS-B by symbols. Preserve DNS invocation leases, dispatch ownership, duplicate-bind revocation, guardian corrections and unsupported-runtime refusal. This standalone source is not composed DNS-B qualification.

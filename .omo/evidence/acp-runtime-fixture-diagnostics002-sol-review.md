# Independent delta rereview — shared ACP fixture diagnostics002

**CLEAR for this exact test-only002 correction delta.** Both findings from001 are resolved in source. This is not compilation/test/native qualification, identification of the historical failure cause, or production approval. Root retains port/Git/remote custody and should preserve all001 evidence.

## Exact binding and preservation

| Input | SHA256 |
| --- | --- |
| 002 freeze.json | `c166d04440dcd1cbd14afe4cc6301b2bde6a903df5613c8cd8b5666461764f72` |
| 002 source.diff | `6100074a789052d91e9a004c3165b0326141ec0661ac3609b0ea1ce8a74b13eb` |
| wt59 LinuxBubblewrapBoundaryTest.kt | `41e826bc6a42ccfed2d07c94c49b21bb829b005bfabb78657d500b0bb5cb0e69` |
| wt59 AcpAgentHarnessTest.kt | `c8798199c6cfc64864741eb76c51bb71532bb15ae13099baaec66b05a7a522b5` |
| Preserved001 freeze.json | `38c490fd6aff0a876891d1c1db149b350f6b09eb51e66e24e7c70ee5d2921e75` |
| Preserved001 sol-review.md (ITERATE) | `d203bbe69a83a885cdcfef2def8bfa102bcaf98b5eef887b64b58c91f74e37c0` |

Independently recomputed all seven002 freeze rows: current sources, before copies and evidence lengths/hashes match. Both before copies have the exact reviewed001 source hashes. Regenerating the two unified diffs from those copies/live002 sources produces byte-identical source.diff; hence reverting this minimal delta reconstructs001 exactly. All five retained non-live-source rows of001 remain unchanged. The original001 report remains ITERATE; this additive report does not rewrite it or present its old collector-ownership wording as current.

## F1 resolved — target match retained with unknown ownership

Boundary's matching `/proc/<pid>/fd` target now adds a normal snapshot map entry: `kind=collector-target ownership=UNATTRIBUTED identity=unknown`. The former `continue` that excluded that FD is removed. Therefore the FD participates in union/delta/full snapshot rows; a pre-existing FD to that same directory is no longer presented as proven diagnostic ownership. Summary names explicitly say collectorTargetFdsUNATTRIBUTED. Missing observations say not-observed, not collector-at-enumeration.

The same single target query/match is reused; no metadata query, scan, opener, process query or cleanup step was added. The identity remains unknown rather than fabricating dev/inode/hash for that branch. This is an acceptable narrow resolution of001: it records a directory-target observation, not proof of a self FD, leak owner, closure, or ABA absence.

## F2 resolved — diagnostic failure cannot bypass the intended assertion

Harness's diagnostic construction, including arbitrary Throwable cause getter traversal, is now enclosed in try/catch(Throwable). Failure yields only the fixed literal diagnostic-unavailable. The strict `assertEquals(VERIFIED, invocation.cleanupDisposition, cleanupContext)` remains immediately after the expression, outside that catch. Thus unavailable diagnostic evaluation still reaches the original assertion; the assertion itself is not swallowed or converted to success. No thrown message/stack/name is added to the fallback. No wait, signal, process observation or teardown operation was introduced.

## Unchanged scope and limits

Exact before/after diff inspection confirms only the two findings' classifications/labels and diagnostic fallback changed. Boundary21/Harness45 @Test annotations and the existing reflection-count assertion81 are unchanged. Original raw FD before/after count sample sites and strict equality remain unchanged, as do cleanup VERIFIED, deadlines, failure propagation and all other test bodies.

Bounds remain two metadata snapshot sites,128 entries each,4096 target characters before encoding,16KiB ASCII rendering; cleanup six cause nodes,11 fixed allowlisted type strings, eight PID samples and4096 added diagnostic characters. No raw target, descriptor contents, stderr, exception messages, auth/request/prompt content or new host/process scan is introduced by this correction. No obvious new syntax/type/import problem is apparent from this small source delta; Kotlin compilation and exception behavior were not executed.

Only this new002 sol-review.md was written. Source/hash/diff inspection used Python -B, with no tests/compiler/JVM/native execution, proc/process-state reads, Git/remote/CI/network/auth/model operation or descendant. Current002 source/evidence pins were checked again before writing. This scoped CLEAR supports root's source-port decision; it does not qualify historical or future fixture execution. Historical descriptor/cleanup cause remains unknown.

# Independent review — shared ACP fixture diagnostics001

**ITERATE: two diagnostic correctness findings.** Correct these in a separate002 generation before porting. This review neither identifies the historical FD/cleanup cause nor approves production/native behavior. No source changes or tests were performed by this reviewer.

## Exact reviewed generation

Freeze `38c490fd6aff0a876891d1c1db149b350f6b09eb51e66e24e7c70ee5d2921e75` binds author wt59 sources:

| File | Before SHA256 | Reviewed001 SHA256 |
| --- | --- | --- |
| LinuxBubblewrapBoundaryTest.kt | `62484cddbad86f8daa9d9d2e1afaea734b92045ed8bf105085ae51647bd72305` | `38644433442ac3a03be09c0c7f3c64860d05d07a2c9f081ad969a90a8ebedb6a` |
| AcpAgentHarnessTest.kt | `45448eb823366f30d9ca4ed18230e73a5a22f9278d063d93e2f5b8f3b70c9483` | `0b797786d2d36e35da54527178583538436349ebe20766246d9681879ef54082` |

Initially independently checked all seven freeze rows against live files and regenerated exact two-file unified diff, obtaining byte-identical source.diff SHA256 `8db83d0e8782a44a4e20ce51dcae2ba5b1fc8cb3b092a0db3297305f202e2281`. Boundary21/Harness45 @Test annotations and explicit reflection guard81 are unchanged. Expected/actual raw FD count equality and cleanup VERIFIED assertion remain strict. Inspection finds no new process launch/query/signal/wait, cleanup policy, deadline or production-source delta. No obvious unresolved added import/type/syntax issue found; Kotlin compilation/discovery/runtime are not verified.

After preliminary findings, root assigned author002 corrections and the live sources changed while this report was being finalized. This report remains about001: independently applying the unchanged frozen unified diff in memory to the frozen before copies reconstructs both exact001 source hashes above. All five non-live-source freeze rows still match at final observation. Later live hashes are recorded below as drift only, not included in this verdict.

## F1 — matching the collector directory target does not prove collector ownership

**Boundary probeFdSnapshot:729–744, especially741–743.** `readSymbolicLink(path) == root.toRealPath()` matches any FD to the same `/proc/<pid>/fd` directory, not just descriptors created by this Files.list call. A pre-existing/new independent descriptor to that directory is indistinguishable by this check. Nevertheless it is added to collectors and skipped from normal dev/inode/mode/target-hash rows; delta formatting calls it collector-at-enumeration. Observing it while the collector stream is open does not prove that stream owns it.

A directory-FD leak is a relevant counterexample: the raw count still fails, but the new diagnostic can misattribute/omit the very descriptor explaining the difference. This does not weaken test pass/fail; it makes the new ownership statement unsupported.

**Minimum correction:** classify such matches as collector-target/unattributed or another explicit unknown-ownership state, preferably retaining normal bounded metadata rows. Distinguish target equality from authenticated self FD identity; do not exclude a potentially relevant delta as proven collector overhead. Stronger self identification would need stronger evidence, without extra scans. Keep128 entries/two sites/16KiB and raw equality unchanged.

## F2 — diagnostic cause access can mask the intended cleanup assertion

**Harness cleanupFailureDiagnostic:2698–2703, called2734–2737.** The diagnostic is evaluated before the existing VERIFIED assertEquals without a protected fallback. `current.cause` invokes a Throwable cause getter; AgentExecutionException accepts unrestricted Throwable? cause (AgentExecution.kt394–398). A cause with a getter that throws escapes the helper and prevents the original cleanup assertion from executing. Six-node/cycle bounds do not make getter invocation nonthrowing. This is a source-level counterexample, not an assertion that this happened in the actual hosted failures.

**Minimum correction:** guard diagnostic construction with a fixed unavailable fallback, then always execute the unchanged VERIFIED assertion. Any diagnostic bookkeeping failure must remain secondary. Do not catch/swallow the assertion, emit throwable messages/stacks, promote unavailable to VERIFIED, or change cleanup/failure handling, waits or limits.

## Other inspected properties and limits

FD enumeration visits at most128 entries per snapshot and closes Files.list through use. Symlink/Unix attribute queries do not open/read target contents; no raw target path or exception message is rendered. Text is admitted at4096 characters before UTF-8 hashing. Two target/attribute observations detect visible change but do not prove absence of ABA. Unknown/truncated/not-observed and count-versus-snapshot separation are explicit. Appends are checked before growth, with footer room within16KiB ASCII. The finite metadata-operation count is not a demonstrated wall-time bound.

The cleanup helper uses existing receipt metadata only: fixed enums/booleans/counters and at most8 numeric PIDs. AcpExecutionEvidence.kt111–117 confirms completeness contains three booleans. No stderr, request, prompt, arbitrary exception text or target content is read/rendered. Cause traversal has at most6 identity-distinct nodes and11 fixed allowlisted class strings; unknown types become other, unknown tail/suppressed/EOF/timing facts remain explicit. Root's shorthand six classes means six chain nodes, not the actual allowlist size. Added text is capped4096 characters; the pre-existing context prefix lies outside that added-text bound.

Type sources inspected in wt59:

- AgentExecution.kt `d704702adfdc850344551140b2d8d225be963d1db620d583f8fba792e205a640`.
- AcpExecutionEvidence.kt `a8831d9648e20fb920cc1f073b723fb5db755f5a910b81e5990d2e7a2897a007`.
- AcpProcessConfiguration.kt `6dfca77dafa90ee0426050dc3a6b9344c7f3483c73612ec7bf068db2498fe81a`.

## Disposition and custody

Two minimal002 corrections and delta-only rereview are needed before port. Keep001 source/diff/evidence immutable. No FD tolerance, poison reset, longer deadline, cleanup rewrite or native qualification follows. The historical descriptor ownership/initiating cleanup failure remain unknown.

Only this new sol-review.md was written. Python -B source/hash/diff inspection only; no tests/JVM/Kotlin/compiler/native execution, proc/process-state query, auth/model/credential-content read, Git/remote/CI/network action or descendant. Reading authored source strings naming proc paths is not a host proc scan. Root retains port/Git custody.

### Later live drift, excluded from001 verdict

- LinuxBubblewrapBoundaryTest.kt `41e826bc6a42ccfed2d07c94c49b21bb829b005bfabb78657d500b0bb5cb0e69`.
- AcpAgentHarnessTest.kt `c8798199c6cfc64864741eb76c51bb71532bb15ae13099baaec66b05a7a522b5`.

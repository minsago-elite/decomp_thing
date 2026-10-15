# Independent provider capacity and FD diagnostic source review

**Terminal verdict: CLEAR, scoped to the exact held source/evidence composition below.** No blocking source finding remains. Actual native DNS cancellation/deadline, namespace visibility/destruction, the FD leak reproduction and hosted required checks remain pending. This is not production Task6 or global qualification.

Independent GPT-6.1 Sol review, 2026-10-14. No descendants. Source authors held their work. Only this report was written. No compiler/JVM/JUnit/native process, namespace/proc probe, resolver/provider/auth/model, CI, Git or remote operation was launched by this reviewer. Verification used repository file/hash inspection, source/diff reading and inert Python arithmetic/digest checks. No implementation was edited.

## Exact composition and evidence integrity

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

| Held input | SHA256 |
| --- | --- |
| `build/provider-diagnostic-instrumentation/freeze.json` | `3887250c8e970c136c391169e87869f2a9d875b3d596a86c3981dc19e561f9e0` |
| `build/provider-native-capacity/freeze.json` | `097a985e6e1c91d3689af1e8feeb8fd8bdd432a3657f50d320c7a3d9e1c39235` |
| Accepted `native-capacity-proposal.md` | `c3681eb9b099ef6e3a3e22e8c952437853d939836c7942008f0c9e4dd4641a48` |
| Current `AcpProviderNativeDnsContractTest.kt` | `c8eae9c9a9bbb112d732a10e2f29a1d534aa4ab6c1170fd95691a728f7612f44` |
| Current `NativeDnsObserverCapacityTest.kt` | `2f43d218676c72e1e32fe5223be53cf674d327e642d73dea294cf5fa31d1dc24` |
| Current `NativeDnsObserverDiagnosticTest.kt` | `548a4e9c359d1d55e52e73aa276fe7c1a282469f2301f27363dce9d9eaf28706` |
| Current `LinuxBubblewrapBoundaryTest.kt` | `1ce1fe37da601e14a6e54c6d2881e3eb37665dca7ca4d753236504f8eaf0ba78` |
| Current `AcpAgentHarnessTest.kt` | `25c27bca44afe41b14ed64cfc9e1f3fed1f03289ef6fa82b36bafe6f3a7cdaf7` |

All19 pins/byte sizes in the newer freeze match. In the older16-pin freeze, the sole current-path mismatch is the intentionally superseded Native DNS source. Its retained47794-byte copy and `before-native-capacity.kt` both bind original `02265536e625494c190c1ac55e4aed87c9ff48fc8dc903742294db10842a89ec`. Thus the first freeze is not misrepresented as an entirely current source freeze. All its other pins match, and the newer freeze explicitly binds the held FD freeze and unchanged FD source. Recomputing the unified diff from that original to current Native DNS source reproduces the frozen18001-byte `native-source.diff` exactly (`ec9d65a1b96e852f9641b69c571c0135bee0467de99aa423464e5db93b1257b9`).

The final verification receipt `758c80e05e51ce45da0827b39d3ee05194445585986cc960f1489d612a7dfd49` binds exact command vectors, current source inputs, environment, compiler/runtime dependencies and output classes. Independently rehashed all6622 dependency files and40 output classes: unchanged. The verifier-script and Java executable hashes match the receipt. Each final log hash matches its run receipt. Historical `new-seven.log` is not used as final evidence.

## Visibility and primary failure semantics

`AcpProviderNativeDnsContractTest.kt:598` retains the namespace equality check and accumulates every observed member in a set. It no longer materializes an unbounded process list. The set is returned only after complete iterator exhaustion; an exception never returns a partial or fabricated empty set. At each namespace-scan entry, `scanComplete` becomes false; only full completion marks it true. Persistence errors propagate when there is no earlier failure and are suppressed on the exact earlier Throwable otherwise (`:639–645`). This summary remains diagnostic, not standalone absence authority.

The unchanged classifier at `:499` refuses unknown credentials and any UID or GID intersection. The denied branch observes starttime, authenticated target credentials and starttime again (`:622–627`). Missing/unreadable/invalid or changed identity becomes unknown. Such observations always throw `POSSIBLE_OWNED_VISIBILITY` with bounded PID/kind/phase, independently of diagnostic storage (`:628–633`). A full detail buffer, budget failure or sidecar IO error cannot replace that typed primary: the diagnostic failure is attached. Budget failures during denied identity reads retain their category and gain the observed PID/kind/phase. Historical arbitrary IllegalStateException still renders `STATE_FAILURE`; its cause is not retroactively invented.

Aggregation is reached only for `DISTINCT_CREDENTIALS` with nonnull authenticated stable target/starttime and the unchanged disjointness predicate (`:575–586`). The accumulator is a diagnostic helper, not the visibility classifier. It may retain unknown detail rows, but the calling branch still throws; retained-row deduplication never bypasses that refusal. Namespace members are neither dropped nor reclassified by aggregation. Unknown extra FD-retention errors now refuse rather than becoming false.

`nativeKeepPrimaryFailure` preserves exact object identity. The outer and top-level failure properties retain fixed enum/scalar fields without arbitrary exception, environment or packet content. A failed sidecar write is diagnostic suppression; it cannot certify cleanup. Fixed primary/cleanup categories remain separate.

## Resource and deadline assessment

The admitted ceilings are finite and are not raised from an earlier observer limit:16 retained detail rows,768 printable ASCII characters per row,16384 overflow observations,32-byte rolling digest, full visibility output at most16KiB;128 scans,4096 PID/FD entries per scan,16384 cumulative PID/FD visits,32768 charged operations, and32MiB proc-text payload per active case/JVM budget. Host case entry and each fresh outer JVM create their case budget; polling does not reset it.

The32768 counter is a **logical operation counter**, not a literal exact kernel syscall count. It charges each iterator hasNext/next, namespace helper, text-read admission and diagnostic metadata helper. For example, `nativeNamespace` performs two attribute reads, and readNBytes may issue multiple reads. Those calls have fixed bounded multiplicity and per-file bounds. No syscall trace or hard IO-preemption result is claimed.

Budget methods check before count increments and before iterator/namespace/text work. Non-numeric proc entries still consume iterator work. Numeric PIDs are charged before namespace inspection/member insertion. `/proc/self/fd` uses the same cumulative budget and only returns false at EOF; true means a known retained handle was actually found. Per-file proc reads retain65536 bytes plus the single overflow sentinel. The requested allocation is `min(remaining,65536)+1`; completion charges actual read bytes before parsing, and exhaustion throws. Counters cannot wrap under their fixed maxima. Scan refusal is not absence proof.

The original absolute `endMillis` is threaded into each scan/operation/read and unchanged across polling. Text completion rechecks it; the original30-second end, reserved execution/cleanup schedule and await/stop/join semantics remain. A clock check does not interrupt a blocked kernel operation, and this change does not claim otherwise. Existing root/descendant stopping, outer blackhole close/join, host namespace/loopback checks, verified-only private-tree removal and final receipt publication remain mandatory in the exact diff.

Overflow uses `SHA256(previousDigest || big-endian32(length) || observation)` and a checked count, without an overflow collection. Retained duplicates keep old behavior; duplicate overflow observations count again. Independently recomputed the golden `ab`,`c` digest as `41a3b2f67b62adf8f5bfadba2834a9f059ffc16a9a6dbde740c4469401dd14e0`. The maximal16-row visibility rendering under declared bounds is12471 bytes, below16KiB. Digest order/framing and observations are diagnostic commitments, not unique-PID counts or visibility proofs.

## Outer stages and FD diagnostics

The six new outer stages precede the exact existing operations: query state, inner proof read, blackhole join, namespace scan, namespace-membership assertion and proof write (`AcpProviderNativeDnsContractTest.kt:365–385`). The original query/marker/membership/proof predicates remain. A stage identifies the next/reached operation; it does not turn earlier unproven facts into success. `OUTER_CLEANUP` remains the bounded observer phase within these more precise stage labels. Native success markers are unchanged.

`LinuxBubblewrapBoundaryTest.kt:735–761` adds only a diagnostic snapshot/diff. Enumeration admits at most256 names using a257-entry sentinel; the stream closes before identities are resolved. Targets are bounded/sanitized, disappearing descriptors are omitted, identity failures are marked unavailable, and whole-snapshot failure becomes `SNAPSHOT_UNAVAILABLE`. The diff includes changed/reused/added FD numbers, at most8 changes and320 characters per side. With the bounded input maps, a conservative rendering ceiling is5403 characters, below6000. No diagnostic identity is substituted for descriptor-count authority.

Before snapshot precedes the unchanged baseline count; the unchanged after count precedes the after snapshot. The exact equality remains at `:995`, with the bounded diff only attached to its message and fixed child output. No expected FD count or namespace admission/cleanup predicate is relaxed. Real cause identification still needs a new authorized reproduction; diagnostic source cannot name the historical leaked descriptor.

## What the retained execution establishes

The empty-output512MiB Kotlin compile succeeded (log `598bd05d065f633442b4a5e7470bdfdcc83f6994ef092ceee93b651f1af24b98`). It freshly compiles Native DNS, the existing six controls, the new eight controls, the current Boundary source and the allowlisted runner. Current output classes are first on both compilation and execution classpaths. Repository-local tmp/home/preferences settings and disabled performance-data/attach flags are recorded. The only warning is the retained boxed-Long reflection warning.

The final existing-six log `c2e5b52a52084bcd7f959a7301961348b45c2fa18ba7fbe75c6d10c275c06a2d` reports6/6 pass; new-eight `15126387ee538a13a6c89f39b17da7f0e23d660c41f56544f3c4890b84b9e048` reports8/8 pass, without skips. Existing six are inert classification/diagnostic controls but one retains its established proc-self metadata lookup. New eight use injected observations/clocks and cover aggregation, unknown overflow/primary preservation, framing/order/counter limits, byte/work/scan/deadline limits, unstable identity and bounded typed rendering. They do not execute a namespace observer or native DNS fixture. This reviewer did not rerun either group or access proc.

Inventory log `2db2c630151cb524d333667e0deb71ae4dea4b8fdaef7687ea09f85573d83eed` reflects46+5+4+6+22=83 actual methods, requiring void returns. Current source annotation counts independently agree. The fresh Boundary class supplies22; the other four inventory classes come from explicitly pinned prior dependency bytecode. The Harness source changes its expected inventory to83; no count is waived. This was an inventory, not execution of all83 tests, nor a fresh compile of the Harness source. The synthetic FD formatter test is included in freshly compiled Boundary source but was not separately selected/executed by the retained14-test runner. The original diagnostic receipt correctly remains historical evidence of static-only checks at its own checkpoint.

All eight retained hosted failure/visibility sidecars remain hash-bound in the first freeze. They record16 detailed denied decisions and the broad historical stage only; they do not establish the17th identity, full scan completion or a diagnostic-capacity-only root cause. No upload/cleanup defect or native success is invented from them.

**Final disposition: CLEAR for the two exact held components as composed above.** Native/hosted qualification and complete composed verification remain root-owned future gates. No provider call, authentication, model run, production runtime closure, issue closure or release is authorized by this scoped review.

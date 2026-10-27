# Independent staged DNS base-merge source review

**CLEAR_SCOPED for the exact staged merge.** No blocking conflict-resolution defect found. Review binds DNS parent `49477fe382d3817464cf138ab7c475018955dfb1` and provider merge parent `c04f3794e7a833943b36dd7206e141ea954b1dca`. Read-only index inspection finds no unmerged entries; reviewed source bytes equal the index and worktree. This is not compilation or Actions/native qualification.

## Exact source pins

| File under src/ | SHA256 |
| --- | --- |
| main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt | `5e37b86ce25dea78ee85922166100ac987f30508aea9f89f9603ef7f94a3e752` |
| main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt | `16e8b7e668928bb426a278db5b3c6ed863f7de565b616ea80a56cece66c62c6c` |
| test/kotlin/decompengine/acp/LinuxFilesystemSyscallsTest.kt | `09a49b8938364a4c3d75165525cacd5d5cec3ffd951d4cf428743f66977cce0b` |
| test/kotlin/decompengine/acp/AcpAgentHarnessTest.kt | `4a47d6907115821c933ce155cd0e80948ddbfff89c703be2bbb715bd84fdd90f` |
| test/kotlin/decompengine/acp/LinuxBubblewrapBoundaryTest.kt | `655504d5037cb12bb6b20d4d7ff131b26314d4968985fd1a3d62ffebcd9040f6` |

Main, syscalls and syscall test are byte-identical to the provider parent; the reviewed CandidateA production implementation is not manually changed by this merge. Prior source reviews remain scoped to their own recorded evidence.

## Conflict-resolution findings

- **Harness:** relative to DNS parent, the complete file differs only by `assertEquals(82, acpTestMethods.size,...)` becoming83. Provider base changes, including its new Boundary test, account for that increment. Independent static annotation inventory is **83 =46 Harness +5 Permission +4 Sandbox +6 Terminal +22 Boundary**. The original DNS historical JVM constructor test and cleanup diagnostic helper are retained. This is not reflective test discovery.
- **Boundary:** independently compared both helper bundles. Provider's `privateControlDescriptorSnapshot` / `privateControlDescriptorDiff` plus its `@Test` are byte-identical to provider base. DNS's `ProbeFdSnapshot` / `probeFdSnapshot` / `probeFdDelta` are byte-identical to DNS parent. No duplicate function/type or leftover conflict marker appears. Original method/class boundaries and the added test's braces remain coherent in the inspected hunks.
- Native nested-admission assertion keeps strict before/after descriptor-count equality and uses the newer `ProbeFdSnapshot` / `probeFdDelta` hashed metadata only on mismatch. The unused old `beforeNestedIdentities` sampling call is removed; the old helper/test remain. `Files.list(...).use` closes each collector stream before returning. The collector's own proc target stays explicitly unattributed; unknown observations do not become closed-FD evidence. No FD tolerance, successful-cleanup assumption or deadline increase is introduced by this resolution.
- Relative to DNS parent, Boundary additionally receives the provider base's existing timeout-tail/cleanup diagnostic and corrected reflective cleanup signature. These are exactly parent changes, not a new conflict adaptation. Main's corresponding signature is the exact provider-base implementation.

## Scope and authority preservation

The index differs from provider base in exactly **18 paths before this additive review**: four DNS contract/input/ELF/profile production files, two DNS input/profile tests, the two generic fixtures, and ten DNS plan/review artifacts. For reproducible binding, SHA256 of the compact sorted JSON mapping these18 paths to their index-blob SHA256 values is `53b16424825652797cb0346b6495324ec905f798a53000be051edd068ff03601` (UTF-8, separators comma/colon, no final newline).

All six tracked `AcpProviderDns*` production files are byte-identical to DNS parent: ApprovalContracts, BuildInput, ElfInspection, Process, RuntimeContext and RuntimeProfile. All four corresponding DNS test files (BuildInput, Process, RuntimeContext, RuntimeProfile) are also byte-identical to DNS parent. Process and RuntimeContext additionally match provider base. `requireApproved` remains the same unconditional unavailable-profile refusal; no approved runtime profile, issuer, context admission or native-qualified state is created. Provider generation4/host-CA and other parent changes enter as base bytes; this review does not independently requalify those wider parent changes.

Root may checkpoint this coherent source merge. Exact-head required CI/Actions, actual test execution and native/DNS runtime qualification remain gates; the source review does not establish them. Only source/index reads, comparisons, hashes and static annotation counting were performed. No source/index/Git/remote mutation, tests, compiler/JVM/native/auth/model execution or CI polling. Only this additive review was written.

# Provider archived identity omission — independent source review

Verdict: **CLEAR_SCOPED** for the frozen archive-only generation-4 source correction addressing `PRRT_kwDOTCeevs6sSr_R`. No source blocker found. Compilation, Kotlin tests, hosted checks, provider qualification and release remain unproved by this review.

Reviewed by GPT-6.1 Sol, with no descendants. Only source/data/hash inspection was performed; no compiler, JVM, tests, native/provider/auth/model, Git or remote execution. Only this report was written.

## Exact scope

Worktree: `.claude/worktrees/wf_ce026d1b-c24-68`.
Freeze: `build/provider-fc52-hosted-diagnosis/archived-identity-omission/freeze.json`, SHA-256 **1ed53d8205edb398eb162c8f76d63891bfc0a87bc847330257cb386b7530f53b**.

Independently matched all ten live owned files to their frozen source copies and exact byte counts/digests; matched all ten retained before-files and all four evidence artifacts. Scope is four main files, five tests and one document. The 11 reported preservation checks are source/hash/text checks, not executed Kotlin tests. The exact main source pins are:

- `src/main/kotlin/decompengine/acp/AcpProviderExecutionEvidence.kt`: `a6686c2e7b20f472571a09711f278e6586dc3a3eb91b4718bc3a16206f990dbe`
- `src/main/kotlin/decompengine/acp/AcpExecutionEvidence.kt`: `3e17b7eb2e68b791f4f2a7bf6e9e9a991359cfe58f02533a1a1a18a502960b63`
- `src/main/kotlin/decompengine/project/AgentExecutionEvidence.kt`: `c65d96f74a553f5f81bb7e5a1dc6f4b013c154cce845ce2a1d647ac3f00064c7`
- `src/main/kotlin/decompengine/repair/ModuleRevisionGraph.kt`: `516b98ed79557facc0003a6eb1664cf3ca16401aa8509ce470abe090487219d9`

## Findings

| Contract | Independent source conclusion |
| --- | --- |
| Omission is archive-only | `AcpProviderExecutionEvidence.kt:221,253` removes only the two archive snapshot strings and their digest-format checks. `AgentExecutionEvidence.kt:2303,2421` omits them from both projection and reconstruction. There is no placeholder, replacement digest or new issuance/admission input. The `authority` enum remains a nonqualifying fixture classification. |
| Explicit closed generation | `AcpExecutionEvidence.kt:148,270` selects invocation generation 4 only when provider transport is attached; provider-absent generation 2 and complete-evidence generation 1 stay unchanged. `AgentExecutionEvidence.kt:232,404,469,489,2435` consistently selects/reads outer 4, requires inner 4, rejects 3 explicitly, and accepts only 2 or 4. Full/compact writers at 302/332 share the same transport projection. |
| Missing/extra fields still refuse | Root keys are exact at `AgentExecutionEvidence.kt:473`; request/provider/lifecycle/outcome shapes remain exact. `parseProviderTransport` reconstructs the bounded contract, then requires exact recursive JSON equality against the closed projection at 2429. Added removed-key fields at transport, descriptors or request-row depth therefore fail, as do inconsistencies in derived booleans. Existing receipt JSON bounds/duplicate handling are unchanged. |
| Owner/model/profile commitments remain | `AcpProviderExecutionEvidence.kt:253–315` retains model/profile/request/invocation/session/turn, request ordering, aggregate bytes/usage, token/deadline limits, revocation and cleanup checks. Profile matching and factory issuer/consumer commitments remain. `AcpExecutionEvidence.kt:162–193` still consumes the exact factory-owned permit once, freezes attachment, forbids complete archive evidence, and enforces provenance and sticky cleanup. The invocation file differs from its retained before-copy only in the generation literal. |
| Strict archive verification remains nonrelease | `AgentExecutionEvidence.kt:2434–2511` keeps fixed credential-free profile/factory/protocol/session/request/token/deadline and process cleanup checks. `releaseComplete`, `adapterQualified`, and `providerCostCancellationProven` remain false in the immutable contract. Removal of the two unprovable strings cannot create operational authority or turn fixture receipts into release evidence. |
| Repair/current consumers are coherent | `ModuleRevisionGraph.kt:73–89` reads only receipt 2/4. Binding metadata at 1380 admits historical 3 and current 4 only pending/rejected and nonrelease. Persistence/recovery/replay at 2195,3034–3051,3111–3128 use strict verification plus actual version, digest, prompt/request/result/outcome pairing. Accepted/provisional/release gates at 1394,3029,3156 remain 2-only. |
| Historical behavior is explicit refusal, not upgrade | Schema-3 receipt bytes are rejected before content qualification with an explicit unqualified reason at `AgentExecutionEvidence.kt:469`. There is no rewrite or automatic 3→4 transformation. A graph requiring legacy contents refuses replay; metadata-only compatibility does not qualify those contents. Web strict validation consequently marks such legacy receipt contents corrupt rather than silently upgrading them. A legacy nonqualifying inspector is not implemented or claimed. |
| Other version consumers do not need a change | Global source search found no additional provider-snapshot constructors outside the shared parser (test fixtures are updated). `TraceGuidedRepair.kt:902,1940,2020`, `RepairHistoryPresentation.kt:20`, `RepairEvidenceArtifacts.kt:24`, and `MvpPatchWorkflow.kt:528` preserve/delegate the actual receipt version rather than imposing 3. `UploadServer.kt:864–875` delegates strict validation and checks actual receipt version against the exact historical binding. Graph/history schema 3 is a different format and remains 3. |
| Release archive remains closed | The unchanged `RepairAcpEvidenceArchiveVerifier.kt:471` requires receipt version 2, including rejected-node receipt handling; adding version 4 creates no new release path. Oracle release/lineage consumers found in the source search still pin 2. |

## Negative controls and preservation

The two new authored methods at `AgentExecutionEvidenceTest.kt:157,183` are meaningful source controls, not assertions mirroring a version constant. The first renders both full and forced-compact receipts, checks omission, inserts both removed names at four depths with digest/null/canary values, calls the real strict verifier for refusal, checks no canary echo, and verifies the unchanged baseline is nonrelease. Its existing mutation helper at 404 actually descends into the populated request array. The second constructs explicitly labeled historical parser data with both outer/inner 3 and both old fields, calls the strict verifier, checks the specific historical-unqualified refusal, and asserts its byte array remains unchanged. This is authored historical data, not an executed compatibility proof against an actual archived receipt.

Existing commitment/cleanup/budget/unknown-field mutation controls remain at 316–378; v2 golden control source and provider-absent rendering paths remain unchanged. Repair tests now specify actual current-4 publication, durable recovery, replay/cross-pair refusal and 3/4 promotion refusal. The archive and web tests update the shared fixture and exact binding version. Keeping the existing `AcpProviderExecutionEvidenceV3Test` class name preserves class-based selection. None of these Kotlin controls was compiled or run in this correction; no runtime pass count is inferred.

Independently verified unchanged recorded hashes for operational policy (`eb1f0b1772b7ff792ddc97c3b4874e668fe44a26e411d96b5d86e3ec74a05b75`), qualification (`3b2c73d049ca9e687c35e2b70f4c48f5124138018ccc86a74ca5cb10f4c1c60a`), broker (`9bcb01a14be5cde023565d864ac1246cce10632dc05bc735f52a39d688b3334a`) and factory (`17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557`). The exact owned diff contains no authority registry, TLS trust, broker wire protocol, operational policy or profiling edits. Existing operational channel policy-digest comparison is retained; archive omission does not remove it.

Supplementary inspected consumer snapshots (outside the ten-file freeze, observed during this read-only review):

- `src/main/kotlin/decompengine/project/RepairAcpEvidenceArchiveVerifier.kt`: `d31dd40151df2f4832ddafa347adf93f5d71784914bdc048d5853df1ca633dcd`
- `src/main/kotlin/decompengine/web/UploadServer.kt`: `bbbb768af04e5f238ded6703c7c9989ea536cb4010b9b3f72fe908fac21c0efe`
- `src/main/kotlin/decompengine/repair/TraceGuidedRepair.kt`: `e09ab9e763fb0a39d36624901c029689e21da9998d83be77dd22d3ceb3dee57c`
- `src/main/kotlin/decompengine/repair/RepairHistoryPresentation.kt`: `d5efca6186aeefbed04b196b0c0f947fc3d055b3d5e18fc34dcf0aa80b6b3165`
- `src/main/kotlin/decompengine/web/RepairEvidenceArtifacts.kt`: `287c8ed1a27afe6adb879458e2a5ff123c4580c60410afc90c396cc67b9fa707`
- `src/main/kotlin/decompengine/mvp/MvpPatchWorkflow.kt`: `cbdfac90f3ccd4f4617644f8a9bae4c8e3b37f2f26a846bff73fbd584fcc6b2d`
- `src/main/kotlin/decompengine/acp/AcpProviderBrokerProtocol.kt`: `7b97f12d8b310d0ef2ca09c14a5f41396c3cbcfd67e35170648838234792edee`

## Gate

The narrow correction can proceed to root's checkpoint and fresh hosted verification. Source inspection supports coherent omission/version dispatch and continued nonrelease authority boundaries. It does not prove compilation, serialized byte roundtrips, actual graph crash recovery, native cleanup, protected provider authority, historical artifact qualification or full issue acceptance. Root retains source/Git/remote/execution custody. Existing R9 evidence and prior failures are not requalified by this correction.

# Independent exporter13 active test-fixture source review

## Terminal verdict: CLEAR — source correction only

No blocking defect found in the exact four-file correction frozen by source-freeze-001.json. It coherently updates current producer fixtures/expectations to exporter13/model4/evidence2 and preserves the behavioral and refusal assertions. This resolves the diagnosed source-level generation mismatches; it does not establish that the previously unreached bundled behavior now passes.

## Exact reviewed inputs

Worktree `/home/june/decomp_thing/.claude/worktrees/issue-1506-referenced-bytes`.

| Input | SHA256 |
|---|---|
| build/issue1506-8097-active-fixture-correction/source-freeze-001.json |612e6a8b064a14b37c33d54a0cb0b6a6157e1dda6d2957734d8353e43a132a5a|
| scope.md |36ea9d65d2205e8ae5d2a90494f362f2b5bc1305b92fe6c2b72c3a1a446beca3|
| GccBundledNativeCallCaptureTest.kt (17,359B) |36ed4c4a2230406b59560bc544eb56e337617fc2d593fdab2dd47e19bc2ff39b|
| GhidraProgramModelExporterTest.kt (16,952B) |2e07fdb4488e56d5803b24be873765ec8c93f1d6a75f72e692aa21281857a610|
| RecoveredCallSitesTest.kt (14,178B) |fa19a49d2069fe4dc26a601d491a756f9ff9c975b995603dc7d95e09750f37b4|
| ReferencedDataBytesRealGhidraTest.kt (6,600B) |a60c82e9dc88804b822d06131e92da0eb96b42d9b3b6f4125b6456d72942e1a1|
| before.json |a655d7729c2f92523440713e91b3f9ea38e56849c3251842309cdd6ce4973b3d|
| static-checks.json |90d0f473abc67a8f2a896a5d39b4e32230edab8bc3d696a422a3c66da7c3c006|
| source-diff.patch |55965032ac90a952ae12e5c7e324ef517f8d536b5d518464c369df6a1a67920e|
| authored-model.json |bc71edad67ea730b19dee8b9f02b5bf14093d320724c3fb4b733850ac5fef636|
| authored-state.json |52e0fbb5ee81a85cb4ca80d2f5e515a4e08eea362085829af7a7a37fe3454c95|
| authored-progress.json |7b48eaec1fa1f4bf947a590eb0701c81732645661c4d1e3260d5441d9defdb02|

All source sizes/hashes, before copies and freeze-linked evidence hashes verified. Each before copy also matches its entry in the retained actual8097 merge source receipt (build/issue1506-8097-hosted-diagnosis/source-bindings.json), bound to merge883154ad5b6793ca78c9664656c6d4c6fd40950a/treecc82d9204fa2c392b314842e4baf3bff30e7edb2. Review read the complete four-file diff and surrounding original/current assertions, public authored JSON, and relevant production producer/capture contracts. It does not claim an independently composed freeze of other owners' mutable sources.

## Failed and previously unreached branches

1. **Six native capture fixtures:** only producer generation literals change at GccBundledNativeCallCaptureTest203–204: model3→4 and exporter12→13. Exporter-state envelope2, progress1, native sidecar/census/manifest/result schema1, function records, public authored input/exporter/archive hashes, permissions, paths and empty globals/types remain unchanged. This matches GccBundledFullExportCapture's exporter13 state check423 and canonical model4 prefix256/484. Public JSON parses as model4/state2/exporter13/progress1, matching input binding, one recovered/unassessed function and zero partial/failed/reused; no byte evidence/global is invented for emptyglobals. The fixture remains authored diagnostic data, not a claim of native production capture or authenticated real tool output.

2. **Native controlled assertions remain present:** all six method bodies are unchanged: independent RAM ordinal resolution, invalid RAM binding/target/census refusal, zero-call functions/thunks, complete/scored/releaseEligible=false, production-authority refusal using Any(), immutable snapshots, linked/hardlinked/public/extra member refusal, identical-byte/inode replacement refusal, aggregate byte overflow, cancellation before result marker and durable commit behavior. No production authentication rule is edited to admit the fixture.

3. **Real full/planning reuse:** GhidraProgramModelExporterTest197/245 now expects4 and checks emitted globals' supplied evidence2. Canonical reader equality, existing record bytes, deliberate removal/resume, reused counts, output bytes, input substitution refusal and diagnostics remain unchanged. Schema4's parser permits nullable evidence generally, but this current exporter specifically fills referenced-global evidence or throws when its origin is absent (ExportProgramModel1172–1174); checking evidence2 on these current real exports is coherent and does not fabricate evidence. These `all` checks do not independently establish nonempty global coverage; they do not replace the dedicated eight-byte fixture's nonempty exact-access checks.

4. **Later historical planning rejection:**263 requires active exporter13;264–269 separately derive historical12 and11 from the original captured priorState, write each, require IllegalArgumentException, and preserve both rejected state bytes and original model bytes. The second case is not accidentally derived from the already-mutated12 string. The original11 refusal is retained and12 refusal is added. There is no production fallback, reuse acceptance for historical state, or reset of a refused result.

5. **Real callsites:** current-model assertion186 becomes4 and supplied evidence2 is checked; the test name now describes model4. Canonical equality across two exports, callsite artifact/input binding, repeated direct targets and distinct instruction RVAs, indirect target-null, direct tail counts, instruction bytes and retry refusal with unchanged bytes remain unchanged. Sidecar schema1 and historical authored callsite fixtures are not bulk-migrated. Returning a model4 is not treated as proof that any later callsite assertion passes.

6. **Real eight-byte fixture:** full model4 at72; every emitted global must supply evidence2 and explicitly empty collectionOmissions74–76; planning model4 at91. The three leading-zero payloads, one-byte ELF symbol declarations, independent symbol/VMA/program-header/file-byte inspection, stripping, exact expected access addresses, requestedLength8/nonempty windows, pcode_direct_read origin, exact referenceAddress, available state and complete segment hex remain unchanged79–85. Full/planning exact evidence equality92–93 and product prompt evidence rendering97–99 remain unchanged. No span-containment substitution, relaxed length/address, omitted reference allowance or guessed exporter outcome is introduced. If these checks fail when reached, bounded actual-window diagnostics are still needed; the old schema-only failure established no window defect.

## Preservation and evidence limits

The fake historical external-adapter helper is byte-identical; neither its intended old-model fixture nor unrelated schema1 records was relabeled as current. Runtime command lines, native input recipes, opt-in conditions, time limits and failure assertions are unchanged. Only the named four test files are covered by this diff/review; disjoint root changes in AcpAgentHarness are outside the source approval.

The retained12 preservation/JSON checks are text/data assertions. This reviewer independently checked their relevant source relationships and hash bindings, without executing the author checklist, importing project modules, or running Kotlin/JVM/native/compiler tests. No compilation, Ghidra analysis, readelf/gcc/strip, prompt execution, model/auth action, Git, remote or CI operation occurred. The only new write is this report; frozen source was rehashed before writing.

**Required next gate:** fresh hosted compilation and bundled qualification must execute the six now-admissible controlled native-capture cases, real reuse/invalidation, callsite checks and exact eight-byte/full-planning/prompt checks. CLEAR grants only the coherent test-source correction at the hashes above; it does not close issue1506 or qualify any historical failed run as fixed at runtime.

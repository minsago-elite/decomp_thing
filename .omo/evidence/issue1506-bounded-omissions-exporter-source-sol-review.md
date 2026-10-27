# Issue1506 bounded omission exporter — independent source review

Terminal: **ITERATE**. One P2 cancellation-propagation correction is required in the frozen exporter slice. This is a source-only verdict; no Java/Kotlin compilation, JVM/Ghidra/native execution, authored controls, 4096-function fixture, CI, Git/remote, auth/model or source mutation was performed. Only this report was written. No global migration or qualification approval is granted.

## Exact reviewed generation

Worktree: `/home/june/decomp_thing/.claude/worktrees/issue-1506-referenced-bytes`.

- Source manifest `build/issue1506-bounded-omissions-exporter/source-freeze-001.json`: `a5d24c38e78308b69dfd0030629c1922e0c30d5bdd609740a1f05d130198a8be`.
- ExportProgramModel.java: `c6352a0daa1e37c6a0a99231f187437e47710a323a656f83af9f4bdbf515de1c`.
- ReferencedBytesProbe.java: `e04a62f0c7ac9d5d4a36f40c938406a9e0446be021b051dd3e2b9d7def65a635`.
- GhidraReferencedBytesExporterTest.kt: `5c23d81aac4fcb192281222841134fcc17d2d36fd82319bd74bba51089d28ca6`.
- Approved root omission plan: `ffe2d3ab9e3e6faada6db862c9d9583d97877f4d725d5f9d96c55a18d58a463d`; additive OKAY plan review: `2c4cd456313ce65cd432f66336e75d46efd22ded28347a7c16ffe0eb74b78ca4`.
- Pinned bundled SoftwareModeling-src.zip: `fed5e47f0578b04597ead75fef77e2316a0458b9dbeeb1eb2cfa3d01472411b3`.
- Unchanged ControlledByteListingProbe.java: `514c46474ed7a0f948ede56e5dfa3482250999a4a295db19ca94b8ff71ad8e24`.
- Unchanged GccBundledContainedExecutionTest.kt: `12572bce5fa4aa193b55de939c3a8a6cbc50845945672710904679a5e8fdf9f9`.

Owned source and dependency hashes were checked against the manifest before and after inspection; approved root plan/review bytes were checked. The 45 recorded checks are lexical/text checks only and were read, not rerun or promoted into behavior evidence.

## R1 — P2: propagate thread-only interruption through the actual global export caller

New `globalAt` at exporter1157–1172 calls `checkByteCancellation`, which throws InterruptedException when either monitor cancellation OR the Java thread interrupt flag is set (903–907). Production `exportFunction` calls globalAt inside its data-reference try block (1214), then catches Exception (1228–1232). `rethrowInfrastructureFailure` at841–845 only rethrows monitor cancellation, IOException or PlanningIntegrityException. With `monitor.isCancelled()==false` and `Thread.currentThread().isInterrupted()==true`, the InterruptedException is therefore swallowed and represented as failed/partial function recovery instead of propagating cancellation. The subsequent planning/full function loops at1295,2199,2354 check only monitor cancellation, so they do not repair this exception-class downgrade. Later IO might independently fail on interrupt; that is not guaranteed propagation of this cancellation path and must not be its correctness mechanism.

The authored fallback cancellation test at ReferencedBytesProbe244–249 invokes private globalAt directly and uses a cancelled monitor. It bypasses exportFunction's catch and never exercises thread-only cancellation, explaining why its source presence does not close this defect.

Smallest correction: make the infrastructure rethrow boundary preserve InterruptedException and the thread interrupt flag as infrastructure cancellation (or explicitly rethrow this exception before recovery classification), preserving the interrupt flag. Add an authored inert production-call-path control that enters exportFunction with monitor false and a thread-only interrupt at globalAt/fallback, asserts InterruptedException escapes instead of returning FunctionExport, and clears the authored test's interrupt state in finally. Retain existing monitor/sort/prepass/fallback controls and failure/integrity behavior. No runtime test is authorized by this review; source controls should be frozen and independently reviewed before later qualification.

## Supported source properties and limits of this review

- Bundled ReferenceManager.java270–277 promises forward references ordered by from address from the inclusive start. ReferenceDBManager.java1011–1012 creates FromRefIterator;1757–1813 advances source addresses and per-source RefList iterators. BigRefListV0.java305–306 returns RefIterator, not getAllRefs. RefType.java492 returns byte, consistent with Byte.compare. This supports the chosen application-side streaming loop and source-boundary stop. It does not prove all internal Ghidra database allocation/analysis work is bounded by the application's reference counter.
- referenceBatch1010–1036 retains at most the remaining allowance, rejects an oversized instruction batch before any width/byte inference, and uses one nonretained overflow lookahead. Batch sorting is bounded and target/normalized operand/stable kind ordered. Same-key comparator ties cannot change retained metadata under the fixed-snapshot policy. Raw admitted API references, including filtered/duplicate entries, charge the unchanged65536work ceiling; this is intentionally different from old data-reference-only accounting.
- Collector checks representable spaces/addresses, supported width and addNoWrap before retention. Exact retained origin identity is target+instruction+normalized operand; conflicting width/basis refuses. Duplicate retained origins reuse snapshots before window/byte charges and reads. Local32 cap skips do not drain payload capacity; model4096 and requested65536 caps are checked before new state/record/byte reads. Unknown width consumes one window and zero bytes. Width256 and other conservative inference/read/space policies are byte-identical to the exporter12 baseline according to the frozen textual comparison; no expanded arithmetic authority is inferred.
- The first real aggregate/work cutoff stops the prepass. Retained globals all receive the same finalized aggregate reason; a local bit precedes it. Unseen eligible globals use constant-size uncached fallback only when that actual cutoff flag exists; a lookup miss without cutoff remains an integrity failure. No omitted-ID map, omitted count or fabricated byte span is introduced. globalAt derives metadata from the same fixed analyzed Data/base and lookup record, supporting same-global canonical equality across normal reconstruction and planning/full paths.
- Collection, duplicate scans, bounded sorting, retained rendering, byte reads and fallback have explicit cancellation checks. Prepass exceptions propagate outside recovery classification. The specific later production catch gap above is the remaining blocker; unchanged p-code inference/internal API work still relies on surrounding per-reference checks and worker deadlines and is not claimed separately preemptible.
- The authored controls cover local exact/one-over, duplicate/conflict, reordered same-instruction references, cold-global capacity, whole-window aggregate crossing, exact/overflow work batch, true/false fallback, unknown width and monitor/sort/render cancellation. They have not been executed in this review. The unchanged held512 checkpoint and4096 authored functions remain at the manifest-pinned contained-execution test; neither fixture nor interruption acceptance was relaxed. Their actual authorized hosted interrupt/resume and fresh-equivalence outcome remains required.

After R1, freeze corrected owned sources and source controls for independent rereview. Other Kotlin/Python/schema/profile/prompt/capture migrations, compilation, actual Ghidra behavior, hosted4096/held512 qualification and issue closure remain separate root-owned gates.


---

## Additive exporter002 R1 rereview

Terminal: **CLEAR for R1 and this exporter source slice only**. Frozen manifest `b8dcfd20e4c8d34450e07a250a3713df648718e8541d0e2d724707e02d8b56ef`, exporter `a607b41b7c0cb7d871ca5c92c674b42602284d9d12570746054b38382603d265`, probe `b3826e8d609ce47049d1f5604681e864b98160fbadc6ba3d8f1aa50e7e4bf473`, Kotlin control `664d42792bc6e841e7ec7d456c4ceec7ff9e46f0f498fc59345e86fcf029f223`. Current/frozen source and preserved prior artifact/dependency hashes were checked. The preceding review remains unchanged.

Production rethrowInfrastructureFailure now restores the interrupt flag and rethrows the original InterruptedException; an already interrupted thread also propagates other caught failures. Existing monitor/IO/integrity rethrow conditions remain. This closes the actual exportFunction catch downgrade without changing collector admission/cutoff policy.

The new authored control invokes actual exportFunction with an uncancelled monitor, injects the thread interrupt while obtaining the instruction references, reaches globalAt, and requires InterruptedException to escape before later type recovery. It asserts the flag is preserved and clears only its own authored interrupt in finally. Additional source controls cover a cleared-flag InterruptedException, a current-flag ordinary exception, existing IO/integrity/monitor propagation and ordinary noncancelled recovery. The Kotlin test requires the new production-catch marker. These are source-inspected controls, NOT executed controls.

No concrete remaining R1 blocker found. No tests, compilation, JVM/Ghidra/native, Git/remote/auth/model or source mutation was performed. Other migrations and actual bundled/hosted4096/held512 interrupt-resume qualification remain root-owned future gates; this does not globally approve integration, claim behavior qualification or close the issue.

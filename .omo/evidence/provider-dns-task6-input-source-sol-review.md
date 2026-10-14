# Task6 inert input-contract independent Sol source review

**Terminal verdict: ITERATE on exact freeze `d7ddcdbbed7076e5a72ae8fe83e90271a8b4dda8d55b16096bcb591dfdff83c7`.** Two reproduced correctness/budget findings block acceptance of this inspector checkpoint. Existing unavailable authority remains intact; these are not claims of a usable production bypass.

Review worktree: `/home/june/decomp_thing/.claude/worktrees/provider-dns-task6-runtime`, baseline `c25f37d69333ae9829bbb18e1aadc498b68f7305` plus frozen additions. Sole source-review report ownership is this file; ignored bounded review scratch is `build/provider-dns-task6-input-sol-review/`. No source/Git/remote mutation, Actions dispatch, acquisition, Docker/native/JVM runtime-candidate execution, authentication/model call or descendant agent was performed. Live read-only GitHub issue reads and inert host-compiler/JUnit/Java fixture probes were used. Explicit scratch/log/cache/JVM state paths are repository-contained.

## Verified scope and identities

Live #1510/#958 both remain OPEN in milestone16; their current issue bodies were read and retained as bounded `issue-1510.json` / `issue-958.json` in review scratch. #1510 still requires actual supported runtime/native closure, protected real issuer/composition, lifetime/cleanup, adversarial/native proof and hosted independent review. No acceptance box is inferred complete.

Verified all six plan/audit/review inputs, all37 frozen source hashes, both preserved-v1 hashes and all four harness hashes. Approved plan remains `0c72f8dd58f2f45ee3f88e410131821a37f95e5a67d73c464bc5f9b994c803c5`; independent plan review remains `e7bcd9460d8ea51127e6c44f5475d66bdb993e4d72d46505f2830ac3c3b7d280`. Frozen source and input hashes remained unchanged after review checks.

| Artifact | SHA256 |
| --- | --- |
| `build/provider-dns-task6-input-contract/checkpoint-freeze.json` | `d7ddcdbbed7076e5a72ae8fe83e90271a8b4dda8d55b16096bcb591dfdff83c7` |
| `build/provider-dns-task6-input-contract/verification.json` | `2d7346f43627185d673567de8029c9dd0995ea321fa468c20142546154574bfc` |
| `build/provider-dns-task6-input-contract/handoff.md` | `1d2e15cf6a6536d5666ac461b782df5bdc5bf37bb382afeea5ae7093a11e2eb0` |
| `AcpProviderDnsBuildInput.kt` | `db6f236b30158104bea1f07ff2136b1f62ee5911156bcc3a92073c146ecb1555` |
| `AcpProviderDnsApprovalContracts.kt` | `a5d18b422dbde47d86a49ea74d018ea857e0857027dd2d5a3e2dc71f112df0b4` |
| `AcpProviderDnsElfInspection.kt` | `768723ecec506a1901b32ac847196d052b28fa6933215a59cf7c36ecc8775ee7` |
| `AcpProviderDnsBuildInputTest.kt` | `df9028d82ae774d4e086f78dd988e2c2c00f917e6b9dfcf0f67c1a077012cb63` |

Source basenames above are under `src/main/kotlin/decompengine/acp/`, except the test under `src/test/kotlin/decompengine/acp/`.

## Blocking findings

### R1 — PT_DYNAMIC is read from a file offset without binding its loaded address

**Anchors:** `AcpProviderDnsElfInspection.kt:43–45,53,60–68`; relevant positive fixture `AcpProviderDnsBuildInputTest.kt:337–346`.

The reader captures `PT_DYNAMIC` as `(p_offset,p_filesz)` at line53 and later scans those raw bytes at lines65–68. It reads `p_vaddr` at line43 but never requires the complete dynamic-table virtual range to map uniquely through a PT_LOAD to the same file range. Its `mapped()` helper validates downstream string/version references but is not used for PT_DYNAMIC itself. Consequently an inconsistent ELF can present a harmless file-offset dynamic table to the inspector while its dynamic virtual address identifies different loaded metadata; even a completely unmapped dynamic address is accepted. This defeats the inspector's observed dependency/provider map before any later semantic review.

**Inert reproduction:** `InertElfMappingProbe.java` reflects only the existing synthetic `elf()` fixture, changes PT_DYNAMIC p_vaddr at file136, and calls the frozen compiled inspector. Baseline offset256/vaddr0x400100 is accepted. For vaddr0x400300 it writes a different dynamic table at file768 containing STRTAB/STRSZ and `DT_NEEDED` for existing `libfixture.so`; inspector still reports an empty needed list. For unmapped vaddr0x900000 it also reports success. No ELF/native candidate is executed.

Observed output in `elf-probe-1.log`:

```text
dynamicVaddr=0x400100 accepted needed=[] soname=null
dynamicVaddr=0x400300 accepted needed=[] soname=null
dynamicVaddr=0x900000 accepted needed=[] soname=null
```

**Required correction:** retain PT_DYNAMIC virtual address and validate its entire file-backed range against the unique applicable PT_LOAD mapping before reading dynamic entries. Require that mapping to agree exactly with PT_DYNAMIC p_offset/size, or reject the form; do not choose one inconsistent representation silently. Reject unmapped/ambiguous dynamic ranges. Add inert controls for split benign-file/changed-virtual tables, unmapped and ambiguous/overlapping mappings, plus a valid consistent table. These checks concern real dynamic-table interpretation; full relocation/native execution remains separately unqualified.

### R2 — Aggregate metadata is charged after the blob has been opened/read/copied

**Anchors:** `AcpProviderDnsBuildInput.kt:90–96,108–113,425–431`; current eventual-failure test at `AcpProviderDnsBuildInputTest.kt:108–117`.

`readMetadata()` checks only the descriptor's per-object ceiling before invoking `blobs()` and buffering the full descriptor. The remaining aggregate metadata budget is charged by `metadata(bytes)` afterward. A caller-narrowed valid aggregate limit can therefore be exhausted by the root while the reader still opens and reads the complete next metadata object before rejecting. This violates the checkpoint's required pre-read/allocation aggregate budget boundary. The stream does close correctly; this is a budget-order defect, not a resource-leak claim. The default parser's existing per-object ceiling limits the overshoot, but does not make the aggregate contract accurate.

**Inert reproduction:** `InertMetadataBudgetProbe.java` uses a tiny valid root index and correctly hashed100-byte manifest descriptor, with `Limits.metadata` exactly equal to root index length. The frozen inspector opens the manifest and reads all100bytes before aggregate rejection. Output in `metadata-probe-1.log`:

```text
metadata budget consumed by root; further opens=1 bytesRead=100 manifestBytes=100 closes=1
```

**Required correction:** check/reserve each descriptor's known size against remaining aggregate metadata before calling the blob provider or allocating/copying its bytes, with a single accounting path to avoid double charge. Reject an already impossible descriptor without opening/reading it. Add zero-open/zero-read assertions for exhausted/one-over aggregate metadata, plus exact-bound successful inspection and stream closure on later failures. Keep hashing, exact descriptor length and immutable root-copy semantics.

## Evidence and independent checks

Every copied dependency/compiler/class/resource object in the dependency manifest was recomputed:5477files,151,927,406bytes. All compiled output manifests and their actual579 main/11test/1runner files matched. All four compile/test log hashes matched the freeze. This supports the focused source/JUnit receipt; it does not establish a full application Gradle/Actions or packaged runtime build.

The exact frozen34 selected controls were independently rerun through the frozen classpath/runner:34 succeeded, zero failures/skips/aborts. Existing controls assert eventual rejection and therefore do not expose R1/R2. Both probes compile against and call that same verified inert classpath. Commands, source, bounded logs, issue snapshots and repository-contained JVM environment are hashed by `build/provider-dns-task6-input-sol-review/review-artifacts.json`, SHA256 `bd90fe64be4c3a67a62eaeef2beba8c94473a098e2db3d7d96c0256b1d0d6efd`. Independent logs are `independent-controls.log`, `elf-probe-1.log` and `metadata-probe-1.log` in that directory. Compiler identities remain host inert verification inputs only, not DNS toolchain/source authority.

## Reviewed constraints that remain intact

- v1 runtime/test source bytes remain `1778f5c656eb1842570f3ee0d3638bc25b046ce469cd952bb38296612595d566` / `5261a1f2d72de5a278b130490cd577a808dec61d64e5e740d216456ca2fbd931`; `requireApproved` still always throws. New objects are explicitly candidates/observations; production paths do not consume these new helpers. Caller-supplied recognized-root candidates/signature hashes do not authenticate a signature or grant network/runtime/issuer authority.
- OCI selection verifies descriptor/diffID bytes, exact selected linux/amd64 metadata and bounded streams; it does not run/extract archive paths onto the host. Overlay links remain typed objects; regular payload coordinates bind direct layer bytes and explicit source metadata. No SONAME-link or ambient-host-library resolution was added. Unsupported actual OCI/PAX/Docker/other forms still refuse; compatibility with unacquired55fb remains unknown.
- A/I/M/P/E/F/Q schema direction separates input identity, runtime/policy cores, detached reviews, final-artifact observation and external qualification. Unknown fields, explicit downstream/self-reference fields, changed subjects and unrecognized candidate roots are rejected. It remains structural syntax/cross-binding: file closure, source/patch relationships, signature authentication, actual embedded resource observation and deployment decisions still need their own reviewed evidence.
- Raw ELF version/provider observations are not JVM/NSS/dlopen/source-semantic proof. No real source/OCI acquisition, hard disk/container quota enforcement, two-build assembly, actual loader launch, resolver/operator permission, nonempty selector, descriptor-pinned runtime capture, protected real issuer/HTTP composition or native cleanup qualification exists here. The production16MiB non-module/256MiB aggregate limits were not widened. The complete plan's source lock, engine/resource accounting and dedicated observable Actions gates remain necessary.

Fix R1/R2, add the stated inert controls, refreeze source/evidence and obtain independent re-review. This source-only checkpoint cannot complete #1510/#958/#238 or any A-series/release qualification.


---

# R1/R2 correction re-review — terminal ITERATE

**Current terminal verdict: ITERATE on corrected freeze `976fbdac950c8d5d5f73310165b86803476fe7ebba393e967fb4968c45ac528e`.** R2 is resolved. R1's original split-offset/unmapped/file-overlap cases are corrected, but its complete loaded-range ambiguity requirement still misses overlapping zero-filled PT_LOAD memory. The original ITERATE report above remains byte-for-byte unchanged as this report's prefix; the correction lane's `initial-independent-review.md` separately preserves the exact original `d7807fbd078bff3bd4b47570107bae6d70b212dcb58c4dbeb39fec19dc3e454b` bytes. No source acceptance or production approval is granted.

## Exact corrected evidence

Recomputed current freeze, handoff, verification, all37 source pins, all6 plan/audit/review input pins and all4 harness pins. All5477 copied dependency/compiler/class/resource files (151,927,406bytes), actual579main/16test/1runner output files and all compile/test log hashes match their manifests/freeze. Preserved v1 source/test hashes remain unchanged. Current source hashes were rechecked after the inert probe.

| Corrected artifact | SHA256 |
| --- | --- |
| `build/provider-dns-task6-input-corrections/checkpoint-freeze.json` | `976fbdac950c8d5d5f73310165b86803476fe7ebba393e967fb4968c45ac528e` |
| `build/provider-dns-task6-input-corrections/handoff.md` | `93c3d05365742b70969e5ab222dc78de50372d4e40d3c46a2e57c039af37fc35` |
| `build/provider-dns-task6-input-corrections/verification.json` | `a002e4fc5550b6c108b8ae7b720d778e1560bb61da3956089ece88d6cb9c3b0f` |
| `AcpProviderDnsBuildInput.kt` | `d11841d1b24ce6ac193deab502066a0c0ea9f96a8bc446bf7fe82d837eecd282` |
| `AcpProviderDnsElfInspection.kt` | `7a1609f27d7cc485c3e812158ef80e789d3ad76b34a48d18eeaa009e063ce3ef` |
| unchanged `AcpProviderDnsApprovalContracts.kt` | `a5d18b422dbde47d86a49ea74d018ea857e0857027dd2d5a3e2dc71f112df0b4` |
| `AcpProviderDnsBuildInputTest.kt` | `dce9573d6cf9788158efc48a3e00b50ddc5ce09bc95819fd24a93659b5603f40` |
| `old-regression-proof.json` in correction lane | `373715489daa91dc4623c2a23dc0206d9fc47e6405f8702f5791ad5ae43fc01f` |
| `old-regression-controls.log` in correction lane | `614c78db45f34cd01a2924ca2369c7b01e59902904132c59d7b8f190f975a0a7` |

The retained corrected JUnit receipt reports42/42 successful, zero failed/skipped/aborted:30Stage1 plus12preserved v1. The old-failure receipt selects the eight new controls against the exact original d7dd compiled source and reports8/8 failed, expected exit1. The new controls and command/classpath ordering were inspected; these are meaningful regressions for the cases they cover. A further entire42-control rerun was unnecessary after verifying unchanged actual inputs/outputs/logs; this re-review ran only the new focused inert ambiguity probe below.

## R2 resolved

`AcpProviderDnsBuildInput.kt:77,85` rejects a root larger than the aggregate metadata cap before copying it. Lines92–96 reserve aggregate metadata through one accounting path; `readMetadata` calls that reservation at109 before provider invocation/read/allocation at110. Root is accounted once at114; there is no later double charge. Exact descriptor size/hash verification and `.use` stream ownership remain. Tests181–220 now assert zero provider opens/reads when root exhausts the budget or manifest would exceed it by one, exact-budget successful inspection, and rejection before config open while closing the admitted manifest. Source and old-fail/new-pass evidence resolve the original R2 finding.

## R1 partly corrected; remaining blocking loaded-memory overlap

The corrected `AcpProviderDnsElfInspection.kt:53,71–73` retains PT_DYNAMIC offset/address/size and requires the requested virtual range to map exactly to the same file offset before parsing. Line45 checks virtual-range overflow, and lines61–67 reject unmapped/truncated/full or partial **file-backed** overlaps. The original split table, unmapped address and file-overlap regressions are addressed.

However, `Load` still retains only offset/address/**p_filesz** at30/52. Its p_memsz value is read/bounded at44–45 but discarded from the load record. `mapped()` considers only `load.length > 0` and the file-backed range at63–65. It therefore ignores a second load's zero-filled memory tail, including a load with p_filesz0. That memory can overlap a dynamic/string/version range which the inspector otherwise attributes uniquely to another segment. This still violates R1's complete loaded-range ambiguity refusal, even though the expected source bytes are individually file-backed by one load.

**Inert frozen-code evidence:** `build/provider-dns-task6-input-corrections-sol-review/InertLoadMemoryOverlapProbe.java` uses the existing synthetic ELF byte fixture and corrected verified classpath. It adds a second PT_LOAD whose p_offset/p_vaddr have matching page-relative coordinates and whose file-backed portion ends before the dynamic range (or has zero bytes), but whose p_memsz includes16bytes of that range. No ELF/native input is executed. All three variants are accepted:

```text
secondLoadFileSize=0 memorySize=16 dynamicBssOverlap=16 accepted needed=[]
secondLoadFileSize=8 memorySize=24 dynamicBssOverlap=16 accepted needed=[]
secondLoadFileSize=16 memorySize=32 dynamicBssOverlap=16 accepted needed=[]
```

This is a static mapping ambiguity finding, not a claim that the fixture was loaded or that a current production execution path is exploitable. The approved narrow policy should reject such ambiguous layouts rather than infer loader behavior from the chosen file view.

**Required correction:** retain separate file-backed size and complete PT_LOAD memory size. Use the full checked memory interval to detect any second segment intersecting a requested metadata virtual range, including BSS-only or partial zero-fill overlaps; require the sole chosen mapping to supply the complete requested bytes from its file-backed interval and retain the exact PT_DYNAMIC offset equality check. Add inert failures for zero-file-size BSS overlap and a nonempty segment whose BSS tail overlaps, plus a valid non-overlapping BSS layout. Preserve address-overflow guards and existing file/total-memory bounds. A source/receipt refreeze and independent re-review remain required.

Probe source, class, exact compile/run vectors, repository-owned JVM environment and bounded output are hashed in `build/provider-dns-task6-input-corrections-sol-review/review-artifacts.json`, SHA256 `85b26402f0043b8229b31804242b131d1be058f8bdf0c2a5caaaf41ec1e64c1e`. Output is `memory-overlap-probe-1.log`. No candidate/source/runtime acquisition, native/privilege/provider/auth/model/Git/remote/Actions operation, source edit or descendant agent was performed.

The initial d7dd freeze, d780 review and all preserved scope limitations remain in force. Actual OCI/source authority, matching-source semantics, resource/engine enforcement, runtime assembly, resolver/deployment permission, nonempty production selection, protected real issuer/composition and hosted/native cleanup qualification remain unavailable/unproved. Inert source checks cannot mint those authorities or complete #1510/#958/#238.


---

# Full PT_LOAD memory-range correction re-review — terminal CLEAR

**Current terminal verdict: CLEAR for the inert source checkpoint at exact freeze `bc02098369c738534b2741ad9dad3ecb322004f7395d0301e77dc9d407fdb3d6`.** R1, including BSS-only and partial memory-tail ambiguity, and R2 are resolved. No remaining blocking source finding was identified within this frozen inert inspection/candidate-contract scope. This supersedes the earlier source verdicts only for this exact corrected freeze. It grants no actual source/runtime/network/issuer authority or production/native qualification.

All preceding review bytes are preserved unchanged: this report's pre-append SHA256 was `f6c60f772bb4ec9ad5611530a611857517996be2468f1f9d93a2ea48920619f3`, also retained as this correction lane's `initial-independent-review.md`. The initial d780 review and original d7dd freeze, followed by976f correction and its ITERATE, remain historical evidence rather than retroactively passing checkpoints.

## Exact verified corrected inputs

| Artifact under `build/provider-dns-task6-input-memory-correction/` | SHA256 |
| --- | --- |
| `checkpoint-freeze.json` | `bc02098369c738534b2741ad9dad3ecb322004f7395d0301e77dc9d407fdb3d6` |
| `handoff.md` | `bedc5d94704bd5f5892e5832dc3fc4155311d9c55886967ddb546a41c517cdb5` |
| `verification.json` | `d9b5ddaca8244ca308b3a04c0d6e6e58ea5f32de135b46d97e6eb518b02dc64d` |
| `old-regression-proof.json` | `e6c0e6f82670373bcd337bcf4f32cdf79ab1c99cfe1d023d5ba74c8f68294c40` |
| `old-regression-controls.log` | `764189983df5a639c639219a4a25534e05c4df18995d005d76dcd53e9f605de6` |
| `reproduce_old.py` | `ff0771d32f4349a5ad0b426807af79d87cfaa93c2e0edb4c42a68ccdb412e1a2` |
| `initial-independent-review.md` | `f6c60f772bb4ec9ad5611530a611857517996be2468f1f9d93a2ea48920619f3` |

The current ELF source is `6e0ca290e5836947a7dae251f1166c5252585a7c9d5c3328710dc6ebcea8c78f`; current test is `dfee9a562f32b42de7cb12bbc2a2df18c0f572c8e6b114440b4975bf7148139c`. Only those two source pins differ from976f. BuildInput remains `d11841d1b24ce6ac193deab502066a0c0ea9f96a8bc446bf7fe82d837eecd282`; ApprovalContracts remains `a5d18b422dbde47d86a49ea74d018ea857e0857027dd2d5a3e2dc71f112df0b4`.

All37 current source pins,6 plan/audit/review inputs,4 harness pins and2 preserved-v1 pins were recomputed successfully. All5477 dependency/compiler/resource files (151,927,406bytes), actual579main/16test/1runner outputs and all compile/test log hashes match their manifests/freeze. The976f compiled main579files were also rechecked unchanged, supporting the exact prior-code classpath used by the old regression receipt. Current source pins were rechecked before this append. Approved input plan remains0c72f8dd; no parent source policy or approved plan scope was relaxed.

## R1 resolved, including memory-tail ambiguity

`AcpProviderDnsElfInspection.kt:30,52` now retains separate PT_LOAD file-backed length and complete memory size. Lines63–65 find intersections using each nonempty full p_memsz interval; `.single()` rejects any second segment intersecting the requested metadata range, including a zero-file-size load or a BSS tail. Lines66–68 separately require that the sole selected load fully file-back the requested bytes and yield a valid file range. PT_DYNAMIC equality with its declared p_offset remains at71–73. The virtual overflow check at45, requested-range check at61 and aggregate memory accounting at51 are retained.

The overlap predicate uses half-open intervals: a second load starting exactly at the requested range end is not an intersection. The final three controls at test487–510 directly exercise this distinction: BSS-only overlap is rejected; nonempty8/16-byte file segments with overlapping16-byte zero-fill tails are rejected; zero/nonzero-file-size loads beginning at dynamic interval end0x400150 remain accepted. These are the specific missing cases from the prior review, without rejecting a merely adjacent BSS range.

The old-code regression selects those three tests against exact preserved976f output: both rejection tests fail because the old inspector accepted the ambiguous fixtures, while the positive non-overlap control passes. The corrected full source/test/runner receipt reports45/45 pass (33Stage1 +12preserved v1), zero skips/aborts/failures. The earlier split-offset, unmapped/full/partial-file-overlap and complete-file-backing controls remain selected. This establishes meaningful old-fail/new-pass regression evidence for the identified static mapping defects, not actual ELF loading or native qualification.

## R2 and authority boundaries remain unchanged

BuildInput still checks root aggregate capacity before independent copy at77/85, reserves known metadata size at92–96, and reserves each descriptor at109 before provider open/read/copy at110. Root is charged once at114. The root-exhaustion, one-byte-short/exact-budget and config-not-opened/prior-stream-closed controls remain in the successful45-test set. No post-read aggregate charging was restored.

Unchanged runtime/test v1 hashes remain `1778f5c656eb1842570f3ee0d3638bc25b046ce469cd952bb38296612595d566` / `5261a1f2d72de5a278b130490cd577a808dec61d64e5e740d216456ca2fbd931`; `requireApproved` still unconditionally refuses. No selector, walker, runtime16MiB/256MiB ceiling, real permit issuer or HTTP composition source changed in this correction. A/I/M/P/E/F/Q and signature/root fields remain candidate declarations and structural cross-bindings only; no caller hash, constructor or review fixture supplies authority.

The first author verification attempt stopped before tests due to an external baseline JUnit service-provider resource mismatch. Its receipt at `initial-stale-external-dependency/verification.json`, SHA256 `0ea89543992731b394e9853419e05a137f34ed7c7cc51db848887af8f5d61668`, remains preserved and was verified. The final run uses owned copied prior-reviewed dependency bytes; its45-test passing receipt, actual dependencies and outputs were verified separately. The failed pre-test attempt is neither erased nor represented as a passing run.

## Limits of this CLEAR

This was read-only source/evidence inspection plus this owned report append. No extra inert execution was necessary after inspecting the corrected predicates and verifying actual frozen inputs/outputs/old-failure logs. No acquisitions, native/ELF/runtime-candidate execution, provider/auth/model/credential/network operation, Git/remote/Actions mutation, CI polling, source edit or descendant agent was performed in this re-review.

CLEAR applies to this bounded inert checkpoint only. The actual Temurin graph/payload and matching source/patch identities, authenticated signatures, source-semantic JVM/NSS/dlopen closure, runtime compatibility/two-build assembly, hard resource/engine enforcement, operator resolver/deployment permission, app-committed nonempty runtime selection, descriptor-pinned capture, protected real issuer/composition and required observable hosted/native cleanup evidence remain unapproved or unproved. #1510/#958/#238 and production/release acceptance require their full respective gates. Root retains sole Git/remote custody.

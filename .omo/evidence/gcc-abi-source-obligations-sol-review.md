# Independent Sol source review: ABI source obligations and scalar enrichment

Terminal verdict: **CLEAR for corrected checkpoint v2 only**.

Reviewed worktree: `/home/june/decomp_thing/.claude/worktrees/gcc-observable-abi-ledger`.

| Binding | Exact SHA-256 |
| --- | --- |
| Corrected `build/gcc-abi-ledger-checks/revision2/checkpoint-freeze.json` | `288759d6647a153598552287d4e33e7da6c05028d5fb4ffa33c93a2b5ae94832` |
| Corrected `revision2/commands.json` | `1c50012708630034112abfc8e9f032b6e3b32bf86c162d5742c01ab8e3ac4ecc` |
| `FullTreeDwarfSupport.kt` | `fbac2520b8ff825cb2eb661067dd2a8cc9b08ce1fef3f6a37d42ea8a9f3a3598` |
| `AbiPopulationSourceObligations.kt` | `5ddd261d887742e108abcd8b35ad81a2861c2732ffbf94aa0695c873d543f334` |
| `AbiPopulationSourceVerifier.kt` | `736a385409528f1e92ed00e1652b06feeea9bab7539294663831cd59747bb178` |
| `AbiPopulationScalarEnrichment.kt` | `55835f586540070aff09687dec0e81f30a6a17d88da365b302354ddb608fdeb2` |

The corrected freeze also pins the three test files, documentation, logs and verification script. I independently checked all **88** transitive source/evidence/runner/class-output pins, including 67 fresh class files; all lengths and hashes match. The original freeze `36b5a33df9801d809bdb1b0380273b4c19e969eb36c89d6007d9c48d098c463e` is preserved and expressly superseded. Its initial source/evidence pins matched when first inspected; **v1 was not cleared**.

## Scope and independence

I did not author implementation code. Source changes and final verification were performed by the source owner after findings were sent to the coordinator and owner. My only writes are this report and bounded independent fixture receipts under `.omo/evidence/gcc-abi-source-obligations-sol-scratch/`. No source, Git, remote, Actions, authentication or model settings were changed by this reviewer.

This review covers physical source obligations, independent reconciliation of those obligations, and scalar observations against parsed source records. It does not approve a semantic function/global/shared-type population, source-TU/build ownership, nominal identity, member/type closure, a recovered model, a seal, scoring or production resource qualification. Approved full plan `7a246d9737e3049cc28a5c0635b36ec30ef04ddac4d9a7a6816be1d9689e24f2` and admission contract `a1bb057e138aa52a486f6df5d9301d32f8421519efd4dd7eaf49bf999416a692` remain the completion requirements.

## Initial findings and verified corrections

1. **Payload allocation preceded the configured limit.** At original scalar hash `f54c250585164852763646cbc7e6e19dea0d0e8d2efb67b2f079b67674f0fe94`, producer lines 39/45 and verifier lines 108/116 read `raw.bytes` before checking the stricter scalar byte bound. The shared payload getters defensively copied the entire parser payload first. The corrected support methods at `FullTreeDwarfSupport.kt:294` and `:319` check private payload size before copying; producer and independent verifier use them. Returned arrays remain defensive copies. The adversarial fixture measures rejection allocation for preexisting 8 MiB inline/expression payloads in both paths and also checks that returned copies cannot mutate retained data. **Resolved.**
2. **Reference state/form/operand reconciliation was incomplete.** At original verifier hash `f399e13e76f005a8a99dfffe36de5b73b62347d3b50b50e328308b8b35bf7bde`, target membership was checked only when a source row claimed `retained-target`; other states could bypass that check, and ref4 operands were limited only by Long addition. Corrected producer/verifier enforce observed direct ref4 with 32-bit operand width and retained-target presence. Unsupported, missing, out-of-range or invented state claims refuse this policy rather than claim verified coverage. Independent membership still reconstructs the CU-relative target from the operand and requires the exact locator. Explicit refusal is appropriate for this retained input, which has no such unresolved states; future support requires a reviewed policy/capability, not relabeling. **Resolved.**
3. **The binary-search index lacked a global ordering proof.** Original first-pass ordering reset at each CU and checked starts rather than complete physical attribute spans. Corrected `AbiPopulationSourceVerifier.kt:25–58` rejects overlapping/reordered DIE attribute spans and overlapping CU coordinates before index use. Its ordered index and CU-owner check then support target membership. Fixtures include within-unit attribute overlap, cross-unit overlap and an oversized ref4 target. This does not establish CU terminal-byte or semantic member completeness. **Resolved.**
4. **Forwardness was treated as completed sibling interpretation.** Original producer marked retained siblings `interpretationRequired=false`, while the verifier checked only target forwardness; an edge to a node's own child could therefore be represented as interpreted. Corrected obligations require interpretation for every typed reference, including siblings, and the verifier rejects a forged completed flag. Full sibling scope semantics remain an explicit later obligation. Stored cycle flags do not establish semantic validity or identity. **Resolved.**
5. **Some diagnostic allocations preceded their input bounds.** The retained replay main originally called unbounded `Files.readAllBytes` on the census before its pinned hash check. It now checks the known 26,503-byte size, reads at most 26,504 bytes and verifies exact size/hash. Reference-state and target-character checks precede fingerprinting, and fingerprint text is character-bounded before UTF-8 allocation. **Resolved.**
6. **Original logs lacked a concrete execution binding.** The corrected command receipt pins runners, classpath files and fresh class outputs and records exact compiler/test/replay arguments and outcomes. Fresh output precedes cached dependencies, including the freshly compiled support wrappers. The Kotlin module name is explicit for cached internal-method linkage. This strengthens the local evidence binding without qualifying the cached dependency build or an exact-head Gradle/Actions run. **Resolved for this diagnostic checkpoint.**

## Code assessment

The source verifier independently enumerates its tag/reference-role table rather than invoking producer classification. Two authenticated source passes reconstruct coordinates, ancestry, owner membership, ordered references, form/operand consistency and source/proposed-row conservation. It rejects missing, extra, reordered or forged obligations and compares replay fingerprints. It deliberately does not treat producer cycle bits as semantic facts. It also does not authenticate arbitrary input sequences itself: the retained test main supplies pinned ZIP/census/part replay, and a future production caller still needs the existing authenticated source boundary.

The scalar verifier does not invoke `observe()`. It checks ordinal, locator, duplicate-name order, attribute/form metadata, typed values, lowercase exact byte encoding and absent versus unsupported/uncaptured values against parser records. Signed/wide constants, indices and section/list references retain their distinct representations. It is an independent projection comparison against a shared typed parser, not an independent DWARF decoder or proof that ignored payloads are observable semantic truth.

Primitive index allocation, row/reference counts, per-row reference lists and copied scalar payloads have explicit bounded inputs. No canonical artifact or admitted aggregate resource profile is produced here. No remaining blocking code finding was found in this corrected scope.

## Verification evidence and limits

The retained v2 logs and exact command receipt show:

- Seven changed Kotlin files compiled together with cached Kotlin 2.4.0 and existing worktree dependencies; fresh outputs come first. All four recorded command exit codes are zero. Compile warnings concern existing unnecessary non-null assertions.
- **9 source + 4 scalar fixtures pass**, including omission/duplication/order/role/target/parent, unknown tags, ref4/state rejection, overlap, sibling interpretation and allocation/copy controls.
- One actual retained positive replay reconciles **696,357 DIE rows and 800,159 references**; one fresh authenticated rich-input positive replay observes **111 CUs, 2,782,106 attributes and 33,900 uncaptured/unsupported observations**. These are not retained adversarial controls; that count remains zero.
- Rich parser consumption is **3,795,244 / 100,000,000 parser steps**. Scalar payload size is **150,654,197 characters**, not canonical artifact bytes. The per-CU 64 MiB retained charge is modeled, not measured RSS.
- Two-pass verifier consumption is **2,993,032 row/edge visits**; the diagnostic's third builder pass gives **4,489,548 visits**. These omit parser/decoder work, binary-search comparisons, hashing, string work, canonical processing and output. They must not be added to the earlier 4,193,523-step canonical work and presented as one qualified 5,000,000-step profile.
- The retained neutrality log reports **zero findings**. No exact-head Gradle build, Actions qualification, complete aggregate deadline/disk/memory profile or RSS claim exists.

I independently reran only the **13 frozen inert fixtures** to verify the corrections, using the pinned fresh classes. All passed. Reviewer execution explicitly set repository-local `GRADLE_USER_HOME`, `TMPDIR`, JVM temporary and JNA temporary paths and disabled JVM performance-data output. The exact arguments, environment and log hashes are retained in `.omo/evidence/gcc-abi-source-obligations-sol-scratch/fixture-rerun.json` (SHA-256 `65608bffb70d47305d0fa142b8552e0b109834f6a7949f24832bb1c2f65031ea`); no full replay or broad qualification was repeated by this reviewer. The retained rich/physical replay results above are attributed to the inspected, hash-pinned owner logs.

The complete authenticated source-TU/build/declaration-use relation, semantic entry/storage/alias/ODR identity, required nominal/member/import/deferred closure, current stripped-model admission and final aggregate resource profile remain absent. All corresponding authority flags in the corrected freeze are false. This checkpoint cannot close #692 or enable #693/#694 scoring.

Final terminal verdict: **CLEAR** for corrected freeze SHA-256 `288759d6647a153598552287d4e33e7da6c05028d5fb4ffa33c93a2b5ae94832`, with command receipt SHA-256 `1c50012708630034112abfc8e9f032b6e3b32bf86c162d5742c01ab8e3ac4ecc` and the exact source hashes above.

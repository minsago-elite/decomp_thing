# Independent source review: PR1516 environment and planning-worker corrections

Verdict: **CLEAR for the exact frozen source correction only.** No blocking source defect found. Exact-head Gradle configuration/task graph, JUnit-engine discovery, required hosted CI and automatic-review disposition remain pending. This does not complete #1513 or qualify source/build ownership, runtime admission, capture, isolation, model binding or release.

Reviewer: GPT-6.1 Sol, independent of author; no descendants. Read-only source/evidence/hash inspection, with only this new report written. No tests, Gradle, frozen evaluator/candidate, native helper, acquisition, credentials, provider/model/authentication, Git, remote or Actions operations were executed by this review.

## Authority and exact pins

Worktree: `/home/june/decomp_thing/.claude/worktrees/gcc-source-build-ownership`. Supplied integration head: `10c8eab15867e80481a9c05ec899fe1043575765`; no new Git-status/head claim is inferred. Author stopped at the reviewed generation.

| Artifact | SHA256 |
| --- | --- |
| `build/gcc-source-build-ownership-review-corrections/source-freeze.json` | `6c59d14d6cee351c7489b9a9ffe138d2a59184bf53a43af0ec3c22528eda07d7` |
| Adjacent `REPORT.md` | `1a7fd459c87cfc7f3029b0fe0a62d7c6f9b5bc499382d4937611b721525efc80` |
| Adjacent `commands.json` | `2047ad22b8e6bb55c989b4c60614543423a9bd9fa7c1efc07f9a67e182becdd5` |
| Adjacent `source.patch` | `0db6adbc3115c7d5756de10efb18d486571c3b9fabd33c6a16a1a480bb91f1b7` |
| Adjacent `pre-execution-freeze.json` | `ce4c6b6c4146c2117d60367c62b29cb94f092db567d8eac141abd4572932948f` |
| Original first checkpoint `build/gcc-source-build-ownership-checks/checkpoint-freeze.json` | `5621be2b76bfcebfa518ba9c84eddd358b1cc6022262da7e51df3714dfe46087` |
| Root `build/gcc-source-build-ownership-hosted-diagnosis/diagnosis.md` | `85d56d4356c59c257ca3640fe254268135f279cc9ae3f57f9dae4991c6e011f4` |
| Root diagnosis `reviews.json` | `975b5bad20ebf2ef5f5667a11d54938340594c03d0a29d4e950a83159bdcb6d6` |

All 10 final sourcePins, four unchangedPins, 13 evidencePins, 40 freshClassPins and all 13 pre-execution source pins were independently length/hash checked. All 14 command-receipt source bindings match current files. The original checkpoint remains byte-identical. The source patch contains exactly seven changed paths; unchanged context is separately pinned below. All 4145 dependency records were independently checked at both original and copied locations: 106254401 bytes per copy. Neither matching metadata nor local assertion success is substituted for hosted qualification.

The completed hosted diagnosis binds run38528428936/job115734224185 and PR1516 head10c8. Captured review thread `PRRT_kwDOTCeevs6sNSlJ` is the single unresolved P2 in that capture; its full text was read. No current remote thread or issue status is claimed. The captured #1513 planning scope and prior independent plan/source reviews remain the broader authority: this correction is a narrow PR checkpoint, not closure of their full requirements.

## Environment retention policy — source correction CLEAR

`GccSourceBuildOwnershipActionReceipt.kt:74–77` admits exactly nine case-sensitive keys: `PATH`, `LANG`, `LC_ALL`, `TZ`, `SOURCE_DATE_EPOCH`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`. There is no wildcard or name blacklist. Schema `properties.environment.propertyNames.enum` agrees exactly; inventory hashes match the actual schema bytes; docs state the same closed policy and its limitations.

`parseObservation` validates the schema at line86, then independently checks all environment keys before typed value mapping at lines120–124. Canonical encoding and candidate identity derivation occur later at lines167–172, after all admission checks. Unknown keys cannot return a partial receipt or retained canonical result. The strict bounded generic parser necessarily reads a finite supplied document first; this is not a claim of zero allocation or erasure of rejected input bytes.

Schema failures inherit IllegalArgumentException. `GccSourceBuildOwnershipInputs.kt:152–157` discards the exception/cause and emits a fixed bounded-document message; the explicit typed key refusal also uses a fixed message. Neither path interpolates supplied names or values, logs them, or returns a rejected canonical object. The existing byte/node/UTF8/duplicate/unknown-field limits, immutable output copies, variant identities and constant-false authority properties remain intact.

The two added tests (`ActionReceiptTest.kt:121–149`) preserve all nine allowed values and exact canonical bytes, and reject four reported names (`GITHUB_PAT`, `API_KEY`, `DOCKER_AUTH_CONFIG`, `AWS_ACCESS_KEY_ID`), existing `ACCESS_TOKEN`, an unknown build key and lowercase `cppflags`. Every rejection checks absence of both key/value from the returned diagnostic and a null cause. Their retained execution is confirmed below. Source membership closes arbitrary naming variants beyond the enumerated canaries. An allowed flag value could itself contain sensitive contents; neither code nor docs falsely promises a value classifier. Adding another real build variable requires a reviewed contract amendment.

This supports the actual automatic finding and fixes its cause. The old broader blacklist acceptance is historical and does not establish the new retention policy merely by preserving its checkpoint hash.

## CI resident-budget failure and required fresh worker — source correction CLEAR

The captured failure is an explicit production diagnostic refusal above2147483648 process-resident bytes, not a proven OOM or ownership-parser allocation regression. The old shared core test JVM permits2GiB Java heap while monitoring the whole process and descendants; JVM heap is not total RSS. Actual peak and allocating source remain unknown. The correction neither attributes that peak to the new tests nor claims a measured universal RSS bound.

`build.gradle.kts:1558–1562` excludes the whole planning class from the shared non-live `test` worker and makes that task depend on `gccCompilerEnginePlanningIsolated`. The new task at1568–1586 selects the whole class, including all seven present methods and future methods; fails on no matching tests; excludes ci-live tags; uses one fork with `forkEvery=1`; and disables up-to-date/cache reuse. A Gradle Test task runs in its own worker; the selected class has seven ordinary @Test methods and no lifecycle, disabled or live-tag annotations. The local retained assertion runner independently enforces count7, with one unique log entry per method. This is not presented as proof that a JUnit engine has discovered them.

The task receives the same staged native/runtime/checksum/classpath setup through `configureOracleTestRuntime`. Its final `maxHeapSize="512m"` follows that shared setup, so the existing two environment-controlled8g assignments cannot override it. No later Test-wide heap override exists in the reviewed script. Production monitor, positive/resume and negative deadline/substitution/progress tests, and their2GiB fixture cap are unchanged.

Required routing follows source wiring: standard JVM `check` includes `test`; local/full non-live test and core test depend on the isolated class; unchanged `scripts/ci.sh` invokes `test` in full/core with fail-fast propagation. Live routing remains ci-live-only and adds no isolated dependency. The existing `kotlin` aggregate requires the matrix job result to be success. Thus the task is not an optional standalone command or a shared exclusion without replacement. Actual Kotlin DSL compilation/task graph remains a CI gate.

The complete workflow patch adds only two paths, HTML and XML for this task, to the existing `if: always()` test-report artifact. Reports remain retained even when the earlier execution step fails. No job/check replacement, skip, monitor disablement, cap increase, exception suppression or production planning edit was introduced. `scripts/ci.sh`, planning production source and planning test were also compared byte-for-byte with the diagnosis's captured hosted source files and match.

## Retained verification and limits

The author freshly compiled source and actual annotated tests using cached copied Kotlin2.4.0, then invoked their methods reflectively, with source-first classpath, explicit credential-free child environment, repository-contained scratch/home/cache/JNA/prefs, bounded heap and90second timeout per child. Both runners instantiate one test per annotated method, propagate invocation/assertion failures and enforce exact counts. No lifecycle annotations in the planning class are bypassed. Commands, runners, emitted classes and log bytes are pinned; all command steps exited0. This review inspected these records and did not replay them.

| Retained evidence | Actual result | SHA256 |
| --- | --- | --- |
| `tests.log` |28 unique annotated methods passed,0 skipped:18 ownership +10 schema catalog/inventory | `00527bd1e2cf5f266eaa536feeb0a7ac2dbde8634584ee7d5453908d04820d2a` |
| `planning-tests.log` |7 unique annotated methods passed once in a separate512MiB assertion JVM,0 skipped | `e8a0bcbc7ac52a04452ce3fbffaebb267c3c91e4a383ff50ef9845e9e6617588` |
| `dependency-snapshot.json` |4145 exact dependency records, checked before/after by author and independently rehashed here | `0f31b1f5bf35381a25d9686d7621f7d394ed45583bfe1582a0fb1f4b7d53a221` |
| `task-mapping.json` |Static source mapping, explicitly not an executed Gradle graph | `a927311e4c15b702391a5845e900dcfd49f0ef5827d9c955a9007dbca6916459` |

All seven planning names in task-mapping equal the retained passing methods, including positive authenticated-input/resume/determinism, historical exporter refusal, input substitution, legacy completion, model substitution, completed-progress validation and running wall-clock deadline. Ownership tests retain input/profile/variant/response/bounds/immutability/authority negative controls. The two new environment methods explain28 rather than the historical26 ownership/schema methods. These are method counts, not individual assertion counts or JUnit-engine results. The planning assertion JVM elapsed1.026seconds; no hosted RSS measurement is inferred. The author's reported diff check is retained as a statement, not independently rerun via Git here.

Remaining required gates are exact-head Gradle DSL/task graph and JUnit discovery, hosted full/core required checks with the new report artifacts, and review-thread resolution through root's normal source/Git/remote custody. A failure there requires diagnosis; this source CLEAR does not preapprove a skip, raised budget or weakened monitor. The broader original source/build ownership plan remains incomplete and no candidate trial, capture, model, production or release authorization follows.

## Frozen source inventory

The following exact source bindings were rechecked immediately before writing this report:

| Path | Bytes | SHA256 |
| --- | ---: | --- |
| `build.gradle.kts` | 96134 | `608b7dd6a6c685c22c3ab3539823a13b5655a21473fce3ba0021081f91e5ce2b` |
| `scripts/ci.sh` | 777 | `f9a78668cae5131e40b68f8271c7634b76a4e7028da031565aee79a6fceb5093` |
| `.github/workflows/ci.yml` | 17853 | `6d4de92425f0e422319ba687bb144e25ca95935ab0218dbb1dcda5a0d0eada2b` |
| `docs/gcc-source-build-ownership-input-checkpoint.md` | 9931 | `9f9a18401dd9cdbbdb8d70aadea265fec8bf383e341591fb806d7c2a12be233a` |
| `oracle/kotlin-schema-inventory-v1.json` | 24372 | `1144d250455d8170eb148af7c93050f13b37954cb77c3f01b0574e9be05a8d90` |
| `oracle/gcc/source-build-ownership-action-receipt-v1.schema.json` | 10268 | `c2a4547c7d852e89b84c9aabc9d29b4879330e1638308a7ad2dd796912bf76bf` |
| `src/main/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipActionReceipt.kt` | 12742 | `3fd6157bc5881eff2c7a45796542285f5e2551130d9a84daf0545b7b28d11461` |
| `src/test/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipActionReceiptTest.kt` | 15915 | `85f289223dbcf092d3b11066e0e848630f9c7f4a26466118ff6876de7dcdcb44` |
| `src/main/kotlin/decompengine/oracle/gcc/GccCompilerEnginePlanning.kt` | 28101 | `c3cbbec7ebf61ef4c74245258fec0401c37fbf54cd82e1758229e54bb6cbb894` |
| `src/test/kotlin/decompengine/oracle/gcc/GccCompilerEnginePlanningTest.kt` | 16650 | `92f3be0d03ce55f204a07ec0a2b35044ff8b1ab03d58046519a00358ea764f39` |

Unchanged proposed profile: `oracle/gcc/16.2.0/source-build-ownership-profile-v1.json`,4155bytes, SHA256 `3753c9eeefaaeed5982328012f750cf8c1967aeafb02cc4729c59abd07c48906`. Prior independent plan/source reports and all earlier artifacts were read without modification. Root retains sole source/Git/remote/CI and merge custody.

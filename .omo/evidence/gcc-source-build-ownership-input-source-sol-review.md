# Independent source review: GCC ownership offline inputs (#1513)

Terminal: **CLEAR for this offline parser checkpoint only.** No blocking source defect found in the exact frozen scope. This review does not mark #1513, plan Step 1 in full, source/runtime/collector admission, production ownership, isolation, #692 populations, or qualification complete.

Reviewer: GPT-6.1 Sol; independent of implementation; no descendants. Source, Git, remote, Actions, acquisition, credentials, native capture and model state were not mutated. Only this review and repository-local inert replay evidence were added.

## Exact reviewed checkpoint

Worktree: `/home/june/decomp_thing/.claude/worktrees/gcc-source-build-ownership`.

- `build/gcc-source-build-ownership-checks/checkpoint-freeze.json`: **12522 bytes**, SHA256 `5621be2b76bfcebfa518ba9c84eddd358b1cc6022262da7e51df3714dfe46087`.
- Approved full plan: `.omo/plans/gcc-source-build-ownership-inventory.md`, 34911 bytes, SHA256 `58f817f0cae0d7c1ea2e41491d2a6eef575011857889c224fc0c2582e071668d`.
- Plan review pin: `fdc207928d9b6d2914bdf2f4129fb8ae53ed738224e749bcd99c55b6cb8f4001`.
- Provided integration base: `cc6d5ee6d47f8550e2d94c2fa9372ea81218e886`.
- Relevant #1513 snapshot: root repository `build/gcc-source-build-ownership-planning/inputs.json`, observed OPEN/A6 with seven acceptance criteria and trusted-oracle separation. Its full inventory/ownership/replay/isolation requirements were read alongside the plan. No live-status mutation or new network request was needed for this narrow checkpoint review.

All **49 frozen entries** were independently hashed and length-checked: 12 source/schema/profile/docs/catalog files, 10 evidence files, 27 freshly compiled classes. All matched before review completion and after the inert replay. All **4145 dependency records** were checked against both original and repository-copied locations, including exact lengths and SHA256s. Matching receipts were not accepted as a substitute for checking their bytes.

### Twelve source pins

| Path | Bytes | SHA256 |
| --- | ---: | --- |
| `docs/gcc-source-build-ownership-input-checkpoint.md` | 9314 | `2d66f650ec2b6e8b713bbf1951205f0979ae4a2bff7e2a918d027644d65a41d8` |
| `oracle/gcc/16.2.0/source-build-ownership-profile-v1.json` | 4155 | `3753c9eeefaaeed5982328012f750cf8c1967aeafb02cc4729c59abd07c48906` |
| `oracle/gcc/source-build-ownership-action-receipt-v1.schema.json` | 9959 | `afb8f983142c6a389e9aec159c1f5d831905032c29d8438a8abfb4d16740427d` |
| `oracle/gcc/source-build-ownership-profile-v1.schema.json` | 5442 | `d4fa1183fb3988291aa41fb5353247eefd02edd784ccfdb4b2cf680b0c9e3a02` |
| `oracle/kotlin-schema-inventory-v1.json` | 24372 | `bbe5f55de3b10c5de81bab8f6631394672f1bbfd7b8d315575a638e0d71258cb` |
| `src/main/kotlin/decompengine/oracle/core/OracleSchemas.kt` | 17903 | `8efb41a1ecc11a32632a31a22fea0519e4ff272e09cd8e30bd64c16bbe648074` |
| `src/main/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipActionReceipt.kt` | 12516 | `536d7d60f1e76658b865c6b9ea8112d2d8a67d9ab7925266528f1678155868f3` |
| `src/main/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipInputs.kt` | 9985 | `fb1ab5d859120fcdced7be31145ed99fd0616a78947c3d682f12ebfe438f7d58` |
| `src/main/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipProfile.kt` | 9321 | `dea3d37ae1ee1c35fb3c247be155a80dda1ab3a855d9fa2e6618e0a421e02181` |
| `src/test/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipActionReceiptTest.kt` | 14221 | `98e64acdeffe7e6d91e2a9bb770bac6d9fd22ac22c0b2e187e846fbeda1bca44` |
| `src/test/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipInputsTest.kt` | 4681 | `4e6c01236d6395d313bf69ae2cb93915ede4df08207d36a49b8769999459b4e4` |
| `src/test/kotlin/decompengine/oracle/gcc/GccSourceBuildOwnershipProfileTest.kt` | 4681 | `c527c84892304458b2e9b7afcf062145bd09bf5f9e943b6c82724ae6a070c9e6` |

## Source conclusions

### Strict finite input admission and immutable results

`GccSourceBuildOwnershipProfile.kt:71–120` and `GccSourceBuildOwnershipActionReceipt.kt:74–169` use the existing strict bounded `OracleJson` parser before schema and typed validation. `OwnershipJson.limits` (`Inputs.kt:97–104`) fixes depth 32, number spelling length 32, per-string and aggregate decoded-string bytes no greater than the bounded document, and caller-lowerable nodes/bytes. `OracleJson.kt:68–82` checks raw input length **before** its defensive copy and strict UTF-8 decoding. Its parser rejects duplicate keys, malformed Unicode/UTF-8, invalid numbers and unknown JSON syntax; typed/schema checks refuse missing/unknown fields and unsupported closed vocabulary. No permissive reparse bypass was introduced.

Profile input is at most 65536 bytes. Explicit metadata observation (`Inputs.kt:42–63`) requires exactly the five checked roles, validates per-input/aggregate lengths before each defensive copy, then checks immutable-copy length and digest before interpretation. Limits are caller-lowerable only: **131072 bytes per metadata item and 262144 bytes aggregate**. It does not follow pin filenames or load adjacent files. Recipe bytes are intentionally opaque, exactly hashed metadata rather than interpreted shell authority.

Action defaults and hard maxima are **8388608 record bytes; 100000 JSON nodes; 16384 argv words; 4096 environment entries; 4096 input claims and separately 4096 output claims; 256 ordered response records** (`ActionReceipt.kt:11–26`). Field checks enforce argv/environment values up to 65536 UTF-8 bytes, target up to 256 bytes, scoped paths up to 4096 bytes, nonnegative bounded integer claims, canonical lower-case digests and the environment-name policy. Collection-size checks precede typed mapping/copying. Global raw/decoded node/string bounds apply while parsing the full JSON tree before those tighter per-field checks; this is finite tree ingestion, not a streaming or zero-allocation guarantee for a rejected field.

Response `bytes` is no greater than half the effective record ceiling (4194304 at the default maximum); actual total representation also has to fit the entire record. Exact ordinal, count-times-two hex length and lower-case hex checks precede raw `ByteArray` construction (`ActionReceipt.kt:136–151`). The resulting bytes must hash to the claimed digest and match a response-kind input claim with the same path/count/hash. No recursive response expansion or compiler-consumption claim exists. The global record/node/decoded-string budgets bound aggregate responses; the profile's proposed production response depth 16 is not falsely presented as implemented command expansion.

Path checking rejects traversal, empty segments, absolute/unscoped paths, backslashes, colon, ASCII controls and DEL. Input/output claims reject duplicate paths within each respective relation instead of silently collapsing versions. Valid deep paths use bounded segment logic rather than a recursive path regex. All wire-derived strings and file claims are immutable values; collections are defensively copied into unmodifiable wrappers, encoded bytes are privately owned, and `canonicalBytes()` returns a new copy. There is no exposed mutable byte array or collection to alter an accepted identity.

These checks establish the finite per-observation parser contract. They do not qualify total CPU/RSS/disk, repeated observations, aggregate multi-shard processing or the future production operation ceilings. No allocation measurement or production resource qualification was inferred from the unit checks.

### Exact metadata generations and honest candidate identities

`Profile.kt:24–68,82–118` fixes the source revision, five exact historical metadata pins, separate original `510c` and proposed reproduction `807f` identities, exact rich/stripped hashes, ten mandatory gates, one captured build plus two independent evidence replays, and proposed resource ceiling table. Caller-supplied rehashed pins cannot replace that checked generation. `Inputs.kt:64–92` derives source/archive/runtime/pair observations only after all exact input hashes pass, and constructs a domain-separated canonical metadata-set digest.

The historical image ID remains an origin observation, not a pull URI or available runtime; `807f` remains the proposed effective reproduction route requiring actual bridge evidence. This agrees with the full plan. Neither matching metadata nor successful supplied action exit code creates source authentication, image/rootfs/tool verification, a build execution receipt, or exact-pair reproduction evidence.

`ActionReceipt.kt:80–108` binds profile and metadata-set generations, accepts only the closed historical/proposed runtime claims with `claimState=unverified` and a null bridge receipt. `:122–135` requires an exact source input claim for source/generator compilation and a compile phase. `:162–169` hashes the complete canonical supplied observation with separate action/compile candidate domains. Configuration, command, environment, target, source, output/object and runtime variants remain represented. Object field visitation order cannot change identity. Generator compilation has no source-TU compile candidate; source-only cannot be asserted as an action-owner role.

Those digests remain descriptors of untrusted observations. The source and docs explicitly prevent their use as execution multiplicity, final TU/build owner IDs, object/link proof, physical-CU owners, nominal/ODR equality or semantic denominator rows. Actual stable identity derivation and independent ownership reconciliation are still required by the approved plan. No circular model-selected partition or source/model answer exposure is introduced by these three classes.

### No self-promotion; schema registry is additive

Both schemas and typed constructors fix all supplied authority flags to false. Completion stays `not-authenticated`, `closureComplete=false`, collector receipt null, and bridge receipt null. Public result properties supply false constants rather than trusting input booleans. The profile is `proposed-offline-only` and never approved. Constructors are private; no factory accepts an authenticated receipt/capability. A later production authority-bearing API needs its own review and real qualified evidence; setting a flag true cannot promote these types.

The shared catalog addition is exactly the two new names at `OracleSchemas.kt:350–351`. Comparison with the provided integration base preserves **all 78 prior inventory records byte-for-field** and changes no existing schema identity. Inventory totals become 80 schemas/76 shared entries (previously 78/74), with historical starting count unchanged at 43. New inventory hashes exactly match the two frozen schema files. Existing catalog loading still checks bundled bytes against the inventory and exposes no caller-selectable filesystem/remote schema. The JSON schemas intentionally perform shape validation while typed validators additionally enforce canonical path bytes, exact source/response bindings, byte lengths and authority restrictions; these are documented complementary checks.

## Verification and retained failure history

The author's final `commands.json` SHA256 is `cc38334e0bfea1041d5e0c80709ba1a8adea08361fff4c45d1c859a16a1175d0`. It records successful fresh compilation of four changed main sources and four test sources using copied/hash-pinned cached Kotlin 2.4.0, explicit module name `dev_decompengine_llm_bin_patch` and friend path. The fresh output directory precedes cached application classes in the runtime classpath; new `OracleSchemas` and ownership classes are among the 27 pinned class files. Empty compile logs are accompanied by exit-code, argv, source, dependency and class evidence, rather than treated alone as proof.

`RunOwnershipTests.java` invokes actual JUnit-annotated methods and propagates assertion failures. The final retained log SHA256 is `01dc876def83e2d26f88d061250509eb929f3d40e5b2d884f119926f361f2600`: **26 methods, 16 new offline methods plus 10 existing schema methods, zero failures and no skipped methods**. These are method counts, not a count of individual assertions or JUnit-engine execution.

I independently replayed exactly those pinned assertion classes, with fresh reviewer-only repository-local tmp/JNA/home/prefs/cache/Gradle paths, `-XX:-UsePerfData`, bounded JVM heap and a cleared explicit environment. All **26 passed** again. Review evidence:

- `build/gcc-source-build-ownership-sol-review/tests.log`: 3710 bytes, SHA256 `01dc876def83e2d26f88d061250509eb929f3d40e5b2d884f119926f361f2600`.
- Adjacent `commands.json`: SHA256 `304ccfef87ce119e257480d3335769ee74841fc1066bfbfb3d91137b455f0ef3`; exact argv/environment/result recorded. No fresh compile or source edits were performed by the reviewer.

Inspected controls cover exact pinned metadata and complete role population, defensive snapshots, self-consistent hash substitution, all authority/gate promotion attempts, source/action binding, command/environment/configuration/target/object/runtime variation, response length/digest/order/input binding, unknown/missing/duplicate/invalid-UTF8/path/secret refusal, lowered exact/one-over byte/node/argv/env/file/response limits, long response hex and deep canonical paths, and the complete existing schema catalog/inventory. No claim is made that every proposed future production ceiling or collector edge case is tested here.

The earlier failed run is retained: `initial-failed-tests.log` SHA256 `f35a9a643f6f4f2daddc052c251a35785490511fd5441f52a76425feac3e8679`, with its exact command receipt SHA256 `ba3e1d5293f7d44bd8d460ddd1efc7d09a2280e01fa0040440a8e52d1ee59ba7`. It records eight successful methods then action-positive refusal. The final action schema now includes required `captureAuthenticated=false`, agrees with typed fields, and the previously failing positive method passes. Historical failure was preserved rather than rewritten as success.

## Remaining gates and disposition

**CLEAR** means this exact additive offline profile/metadata/observation parser checkpoint is suitable for its next reviewed implementation work. It is not the full source/archive verifier, lossless collector or independent ownership verifier. Missing actual signed source admission, authenticated runtime/reproduction bridge and live tools, qualified collector/file-version closure, exact-pair captured build, two fresh independent full raw-to-canonical replays, complete object/link/CU/declaration/use and nominal-language authority, hidden-source isolation controls, immutable ownership handoff, exact-head Gradle/Actions and automatic/independent reviews remain explicit. The full plan's one complete exact-pair capture plus two independent replays remains intact; no extra full build or universal tracing gate was added by this review.

No semantic entity population, shared-type completeness, TU ownership, model binding, seal, score, production verification or release eligibility follows. Keep #1513 and its dependent full acceptance work open.

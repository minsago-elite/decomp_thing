# Function truth v3 fixture evidence

This is fixture-only evidence. It does not qualify production behavior or authorize release,
scoring, or downstream use.

## Producer and schema identities

| Item | Identity |
| --- | --- |
| Producer policy | `full-tree-function-truth`, version `3` |
| V3 shard schema | `full-tree-function-truth-v3`, wire `schemaVersion: 2`, SHA-256 `81bc31d80ee00b32e39ae8d8154a8890ecf5d724322ac0d1eb4c303a0a547c43` |
| V3 index schema | `full-tree-function-truth-index-v3`, wire `schemaVersion: 2`, SHA-256 `250ecb435bdb1c98cedff2d39b8ccface0dd0d1de86b787cc1019c6d3da7c59f` |
| V3 configuration | SHA-256 `a59e80ed0cd440f07be4741892d75ba5a3514532a73ecb67bbc617b4d24a34c2` |
| Frozen V2 configuration | SHA-256 `17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5` |
| Frozen V2 shard schema | SHA-256 `b21be27d085c61c60cbaba11da1208b24c897c264001c790b0ca32b2ae24e5f7` |
| Frozen V2 index schema | SHA-256 `40a2c4d0c3a1b3317e010fd267b56e6ea3ec94620abd79c591b01bc6357e084f` |

The V3 policy pins the full-run anchor-claims reconciliation, at most 32 identity edges per
entity, the existing 32-entry reference-chain limit, typed source tuple v2 with declaration
column excluded from candidate hashing, and `unknown-null` for unproved template-pattern
relations. Candidate hashes do not prove identity. Source-entity census rows are physical and
non-scoreable; emitted function truth remains one row per emitted RVA.

## Compiler fixture inputs

The compiler-backed test builds the checked-in `inline-template-identity-v1` C++ fixture with
GCC, C++17, optimization, PIC, and DWARF 5. It maps both source and build paths with
`-fdebug-prefix-map` and links with `-Wl,--build-id=none` so repeated builds in one toolchain use
stable paths and bytes. GitHub Actions observed `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`
and GNU Binutils `readelf` 2.42; `compiler-input-v1.json` pins that compiler, `readelf`, and
linked-ELF tuple.

| Input | SHA-256 |
| --- | --- |
| `README.md` | `e21506a185caf9b1a1095ba15ab7053d341634fcafd2c347c7efff18dd2f8bc8` |
| `caller_one.cpp` | `3338aa393b18753a6aa4e59b8a2a3ffd0b296acaefa3bde7ad9a35108c6c7e55` |
| `caller_two.cpp` | `10ae558f7c11e5625b34b512098c64616e674cd7e3c2ecbae8ad61b533e61a52` |
| `include/identity_fixture.hpp` | `edb675d9ef5418a0b5e27ee468bb1c321e6366499475125533949ce3cf41fbd0` |
| `instantiate.cpp` | `ccd85bec46349ca4337102eb5dd9e1b37a9cae9b25d50cd4fdc0e9b9bec09aea` |
| `unique_pattern.cpp` | `78d954d860983fb6492aa156dda65a501a596f226c06407ca032aee66b12a68a` |
| Linked rich/stripped fixture ELF (observed) | `641ef1219d91f8593c0439de52265801912450e4afa216b52711f7b99cb1ce6b` (27,280 bytes) |

`readelf --debug-dump=info --wide` on that ELF showed concrete `template_pattern<int>` and
`template_pattern<long int>` DIE names and `DW_TAG_inlined_subroutine` records. Those names are
compiler evidence only; V3 leaves generic-pattern relations and resolved semantic identities
null without a validated proof.

## Runtime output evidence

The test writes a canonical full V3 output vector to
`build/test-results/test/full-tree-function-truth-v3-vector.json`; the repository's Kotlin test
workflow retains that directory as an artifact. The canonical checked-in output vector is
`compiler-output-v1.json`, SHA-256
`c1eb66bb2d797cfbcba254d706b290439ad84856a80635cc66e1b07a90a29e9e`. It was captured from the
exact-head Kotlin core runtime artifact for PR head `c8e1ddf497690f902112fac08c48ec00f3283c93`
(workflow run `37269432133`, artifact `11328069173`). That run reached the output-vector assertion
and failed only because this golden had not yet been checked in. The vector bytes were independently
parsed and canonicalized; its index artifact digest, logical index digest, count totals, compiler
input-vector digest, ELF digest, and V3 schema hashes all match their embedded values and checked-in
inputs. The exact-head Kotlin rerun after pinning this golden is required for final verification.

| Runtime evidence | Value |
| --- | --- |
| Compiler / binutils | `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`; GNU readelf 2.42 |
| Compiler input vector SHA-256 | `e432ff19b9fc0dbeb6cb42609b25cb40665cfef9a8929be2c1c56a094c151a8e` |
| Rich, stripped and linked ELF SHA-256 | `641ef1219d91f8593c0439de52265801912450e4afa216b52711f7b99cb1ce6b` (27,280 bytes) |
| Scope SHA-256 | `5ca8a4bb70ce9455434fa7d75be07e6af73c6bc4b67326675b7ad167ba6e4e86` |
| Inventory artifact SHA-256 | `e33526659292850c9a1f8f0377139658e6dd38bf1e0867667e0607bdc8c5ba87` |
| Observation-v2 index artifact SHA-256 | `810ce485dd4ed7e1c37112b3f2ad1d501c9cfd6ad165780bbeef65e4385bba43` |
| V3 index artifact SHA-256 | `90b5c5dccfca1c0403465e34719cea58de919d7290975c3a3f8ee9a33be319d9` |
| V3 logical index SHA-256 | `5b8b35ddf6d3c253563a543a9982a203515f8248b4a04f57047a06fdcf671be8` |
| V3 output bytes / database high-water | `280448` / `385024` |
| Full-run collision reconciliation | 42 candidates, 50 claims, 8 collision candidates; population SHA-256 `6ffbf092d4c42849bea78b69678a2960b7f687e6eba4105ddcafe6dec28ff646` |

The canonical count vector records 27 ELF RVAs, 21 DWARF/emitted and scored RVAs, 6 ELF-only
exclusions, 0 DWARF-only RVAs, 16 non-emitted observations collapsed to 13 unique truth rows,
and 45 physical source entities. The source census partitions those rows into 3 declaration-only,
10 inline-instance, 10 no-range-definition and 22 template-instance rows; template-pattern and
unresolved rows are zero. There are 16 emitted-RVA links and 29 non-scoreable census rows. The
vector also retains the complete per-kind, observability, disposition, collision, exclusion and
shard digests/counts. Generic-template pattern proof remains absent and null.

Verification command:

```sh
./gradlew test --tests decompengine.oracle.fulltree.FullTreeFunctionTruthSqliteV3Test
```

The local Gradle wrapper distribution could not be downloaded because `services.gradle.org` did
not resolve, so the runtime suite is verified through exact-head GitHub Actions instead. This
fixture-only evidence grants no production qualification, release authority or scoring permission.

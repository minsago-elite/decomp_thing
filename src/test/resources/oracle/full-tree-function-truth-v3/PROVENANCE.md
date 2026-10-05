# Function truth v3 fixture evidence

This is fixture-only evidence. It does not qualify production behavior or authorize release,
scoring, or downstream use.

## Producer and schema identities

| Item | Identity |
| --- | --- |
| Producer policy | `full-tree-function-truth`, version `3` |
| V3 shard schema | `full-tree-function-truth-v3`, wire `schemaVersion: 2`, SHA-256 `81bc31d80ee00b32e39ae8d8154a8890ecf5d724322ac0d1eb4c303a0a547c43` |
| V3 index schema | `full-tree-function-truth-index-v3`, wire `schemaVersion: 2`, SHA-256 `230ea7a9b402047b23a7c875af8c079881fa7a08d258306d7fa97d492a4ec6a5` |
| V3 configuration | SHA-256 `7b23de968c0038849bb75bca8ff0aa35e3e53645475ca0aab9800d4077b7426c` |
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
stable paths and bytes. The observed local compiler was `g++ (Debian 14.2.0-19) 14.2.0`; the
observed `readelf` was GNU Binutils 2.44.

| Input | SHA-256 |
| --- | --- |
| `README.md` | `e21506a185caf9b1a1095ba15ab7053d341634fcafd2c347c7efff18dd2f8bc8` |
| `caller_one.cpp` | `3338aa393b18753a6aa4e59b8a2a3ffd0b296acaefa3bde7ad9a35108c6c7e55` |
| `caller_two.cpp` | `10ae558f7c11e5625b34b512098c64616e674cd7e3c2ecbae8ad61b533e61a52` |
| `include/identity_fixture.hpp` | `edb675d9ef5418a0b5e27ee468bb1c321e6366499475125533949ce3cf41fbd0` |
| `instantiate.cpp` | `ccd85bec46349ca4337102eb5dd9e1b37a9cae9b25d50cd4fdc0e9b9bec09aea` |
| `unique_pattern.cpp` | `78d954d860983fb6492aa156dda65a501a596f226c06407ca032aee66b12a68a` |
| Linked rich/stripped fixture ELF (observed) | `381ce2bb68a29fd72cfcb3c24ea5bc91a8a863753f939518659d946fcee0ecd2` (27,040 bytes) |

`readelf --debug-dump=info --wide` on that ELF showed concrete `template_pattern<int>` and
`template_pattern<long int>` DIE names and `DW_TAG_inlined_subroutine` records. Those names are
compiler evidence only; V3 leaves generic-pattern relations and resolved semantic identities
null without a validated proof.

## Runtime output evidence status

The test writes a canonical full V3 output vector to
`build/test-results/test/full-tree-function-truth-v3-vector.json`; the repository's Kotlin test
workflow retains that directory as an artifact. The vector includes the rich/stripped ELF,
inventory, scope, observation-v2 index, V3 output index and shard digests, database high-water
mark, and exact score/census counts. These values are intentionally not guessed from the compiler
input hash. In this execution environment the Gradle wrapper distribution was not available
locally and its download failed because `services.gradle.org` could not be resolved; therefore the
Kotlin runtime suite has not run here. No V3 output digest or denominator count is claimed by this
report. Check the vector into this directory after collecting it from the exact-head Actions run.

The intended verification command is:

```sh
./gradlew test --tests decompengine.oracle.fulltree.FullTreeFunctionTruthSqliteV3Test
```

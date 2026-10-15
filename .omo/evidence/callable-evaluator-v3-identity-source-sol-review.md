# Independent A1 static identity source review — GPT-6.1 Sol

Terminal: **ITERATE** on the seven-file A1 checkpoint. Two concrete validation/bound mismatches remain. This is not a composed evaluator review, native qualification, full #1507 acceptance or preparation approval.

Reviewer did not author these changes and used no descendants. Root remains sole Git/remote custodian. No source fixes, Git/remote/CI operations, compiler/helper/candidate/native execution, model/auth/credential operations or dependency installation occurred. Only this report was created. The targeted check loaded the exact frozen Python gate into memory with inert stub dependencies; it did not import mutable runtime/profile modules or run composed tests.

## Exact binding and retained evidence

- Approved plan: `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`.
- Source baseline recorded by checkpoint: `aab1938d4e99ec960841259fa56bc28c89df0161`.
- Root evidence directory: `/home/june/decomp_thing/build/v3/static-identity/`.
- `manifest.json`: SHA256 **`e085258ddd0cac6373f61aae3811c431168ee499395f7a32bdc129f11d7a431a`**.
- `delta.patch`: SHA256 **`7a355ae50ecb3a8164056a8e91ffb1b9f5c9dbce686c4b78b827377a3ecdf797`**.
- `commands-results.json`: SHA256 `1da24b311d693453faef4ae4bc4b19d39a9ac574b154207fd9f6c29cffe853dd`.

All seven live owned files were independently compared byte for byte with the retained source snapshot and their manifest hashes; all matched. Other authors' dependencies are outside this freeze and were not treated as final or re-executed. The retained before/after receipts report equality of the dependency versions present during the author's checks; that is historical evidence, not a global composed-source freeze.

Paths below are relative to worktree `oracle/acp/callable-evaluator-v3/source/`:

| Owned file | Bytes | SHA256 |
| --- | ---: | --- |
| `record_identity_probe.cpp` | 12090 | `b378ea50d7f925aecb3dd757455aced849e45ca0b3aba38779ec68aa7b6dd4e1` |
| `interface_gate_v3.py` | 18536 | `f8d612b0c7e76bb513585898e95e11a7cb062a35071344cc8692706dc49e60e2` |
| `contracts/helper-schema.json` | 11586 | `eede8e02cf0a294c25aa752219172d4ff120fef42f7f29f8509647da81d27bf8` |
| `tests/test_identity_graph.py` | 11229 | `9a3a6a04542a6c67e01dec917b4bb6d34adc2616ab0157943665e4a8658b1e31` |
| `tests/test_builtin_types.py` | 3941 | `515f8401d2d709d65c33d4372d31e670fef2f40d812ea3e78a12f86365d62056` |
| `toolchain-001/build_helper.py` | 1805 | `14622c130eded95016e4f8c9be63054fa60efc97244d473b58c6912c7cd75c51` |
| `toolchain-001/pin_helper.py` | 2556 | `80e9bb36dd08163778b2f43f9595180e4d17a3b9d0792207653150825daafca9` |

The author retained 14 identity and 6 builtin pure tests passing, five Python AST parses and helper-schema JSON parsing. The receipt explicitly disclaims C++ compilation, native execution, external JSON Schema validation, semantic acceptance and model use. Those limitations are accurate and remain. I did not rerun the 20 tests against changing dependencies; three targeted isolated semantic checks below were sufficient to demonstrate the remaining risk.

## Blocking findings

### A1-1: Enum member bound is specified but not enforced by either producer or semantic validator

`contracts/helper-schema.json:512–517` limits `enum.values` to 4096 entries. In contrast:

- `record_identity_probe.cpp:119–125` iterates every enumerator, appends every value, and can emit `status:supported` without checking that cardinality. The helper's `nodes`/depth counter is charged by `type()`, not by this enumerator loop.
- `interface_gate_v3.py:87–97` validates value spelling/uniqueness but has no list-size check and does not charge enumerator visits to its descriptor budget.
- `probe():214–218` uses `json.loads` and `_validated_graph`; it does not invoke the schema's `maxItems` check.

A bounded 4097-enumerator descriptor, one enum node and one binding was compared with an identical copy using the exact frozen gate. It returned:

`{'accepted': True, 'status': 'passed', 'differences': [], 'targetEqual': True}`

The payload's enum members were `E0` through `E4096` with decimal values, its underlying type was supported `int`, and the enum was reachable from `acp_state`; the other required roots used supported scalar descriptors. It needed no unresolved identity, duplicate member, cycle, malformed value, oversized node table or native operation. The descriptor counter does not represent these member visits. This is a real discrepancy between the admitted Python contract and the declared finite schema; the source projection has the matching unchecked loop. It is not a demonstrated unbounded-host escape or executed native-helper result.

Required correction: enforce the declared finite enum-member ceiling in both producer and reader before appending/processing excess members, with an explicit refusal; keep its meaning consistent with the documented graph/member budgets. Do not merely increase the schema cap. Add exact/one-over inert member tests, and retain actual helper enumeration/refusal qualification as a later authorized native gate. A lower global graph budget is not a substitute unless member charging actually enforces it.

### A1-2: Closed raw helper shape is not enforced on the actual ingestion path

The supported raw schema requires exactly schemaVersion, target, dataLayout, status, diagnostics, interfaces, declarationNodes, provenance and gccTypeBindings, with `additionalProperties:false`. `_validated_graph():36–45` checks selected fields but never closes the root or validates the required diagnostics/provenance fields. `probe():214–220` returns a supported payload after this partial check, then appends trusted execution/input-binding metadata. No closed-schema validator is invoked there.

On a valid one-enum public fixture with an empty enum value list:

1. Adding `unexpectedRoot:true` still returned `accepted:True,status:passed`.
2. Removing both `diagnostics` and `provenance` still returned `accepted:True,status:passed`.

Both violate the checked-in raw helper schema. The diagnostic provenance need not become a comparison key; its presence/type/bounds and the closed exchange still need validation. This finding does not assert that the current trusted C++ emitter normally produces these malformed roots or that an incompatible library was called. It means the implemented ingestion/validation contract is weaker than the claimed closed v3 exchange.

Required correction: validate the raw helper payload's exact supported/refused/fixture shape and required types/declared finite collection bounds **before** comparison or adding trusted receipt metadata, using an existing qualified schema path or equivalent explicit typed checks. Avoid making a new external validator dependency an unexplained prerequisite. If validated/enriched receipts share `_validated_graph`, distinguish their allowed trusted metadata fields explicitly rather than leaving arbitrary root keys open. Preserve diagnostic-only provenance semantics; reject v2, unknown/missing fields and excessive collections without admitting a supported graph. Add direct `probe` ingestion fixtures with native calls mocked, not only schema-structure assertions.

## Targeted inert evidence method

The frozen `interface_gate_v3.py` snapshot was compiled/loaded as a Python module in memory. `bounded_runtime` was supplied an inert stub whose native runner raises immediately; `public_result` was an identity function and `digest` only hashed bytes. `build_contract.profile` was an inert dictionary provider. No actual imported runtime/profile file was used. The fixture contained the supported v3 roots, exact builtin descriptor, node/reference/binding and closed baseline fields described above. Calls were only to `compare_descriptors` with deep-copied in-memory dictionaries. All three malformed cases produced accepted/passed as recorded. The same seven live/snapshot hashes were checked before these probes and again while generating this report.

This is a focused semantic counterexample to the pure validator. It neither supplies C++ build evidence nor substitutes a forged helper receipt for authenticated execution. The retained 20 authored tests can all pass while these cases remain untested.

## Other inspected A1 behavior and scope

The main correction is otherwise coherent in this narrow static inspection:

- The helper emits canonical record/enum node references, resolving typedef presentations to those nodes; the comparator maintains forward and reverse maps across all required roots. Same-layout identity collapse and repeated-identity split are no longer ordinary descriptor equality.
- Active versus completed node tracking permits a repeated DAG while refusing an active cycle. Node keys, bindings, reachability, duplicate/conflicting identities and layout/field/qualifier facts receive explicit checks. Binding selection is by identity, with deterministic alias expression selection and assertions covering all retained expressions.
- Exact builtin kinds distinguish plain/signed/unsigned char and integer ranks including long versus long-long at equal widths. GCC spelling is closed; unsupported Boolean/extended kinds refuse instead of guessing from width. Qualifiers and pointer/pointee placement are retained in generated assertion text.
- Helper schemaVersion3 and old-version refusal are present. Support scripts have main guards and no compiler invocation at import. Build receipts name source/schema/binary hashes; the pinner checks that version/hash linkage. This is static source inspection, not proof of complete build/runtime dependency capture or native compiler/API compatibility.

No CLEAR is granted for code generation that has not been compiled, emitted descriptors that have not been run through a real helper, or an unavailable external schema validator. Keep their later gates explicit. Source/profile/process/link modules owned by others must be composed and re-frozen before integrated tests. No private caller/fixture/scenario/source/expected observations may be published through this public source checkpoint. Preparations 001/002, original attempt13 and all prior reports remain unchanged.

**Final disposition: ITERATE** at manifest `e085258ddd0cac6373f61aae3811c431168ee499395f7a32bdc129f11d7a431a` / delta `7a355ae50ecb3a8164056a8e91ffb1b9f5c9dbce686c4b78b827377a3ecdf797`. The source custodian can assign the narrow bound/raw-shape fixes after this review; the reviewer did not edit implementation. Re-review the corrected exact seven-file freeze and focused inert controls, then retain native/composed/full-acceptance gates from the approved plan.


---

# Independent rereview: A1 static identity correction 001

Terminal: **CLEAR for the corrected seven-file A1 static checkpoint only**. Both original validation findings are resolved. No remaining blocking defect found within this reviewed scope. This is not a global composed-source freeze, C++ build/native-helper qualification, complete validator/runtime qualification, full #1507 acceptance or final preparation approval.

Exact corrected manifest: **`6e0d5f225f9d20ba8b1e3e4f560b5d7ccfc97819f370c81c94f2fd98f43ed786`** (5450 bytes); correction delta: **`ef82294d113d90335582de7f487ead2bd281f77c6539ceae030ab9bbaa7891d6`** (42995 bytes); author report: `72e032933097713b25c63783ca6aa24253c89c7f5624345af085fa568f28008e`; command receipt: `43fe77976abab322f55fc157aa67628df7624492c761befb8c141dab59bb29fb`.

The complete original 10684-byte ITERATE report remains the byte-exact prefix, SHA256 `d717d8edc56ef7b77c5cec824e6ac12ef4d76542c12a751f45b39230ecac4478`. Initial manifest `e085258ddd0cac6373f61aae3811c431168ee499395f7a32bdc129f11d7a431a`, delta `7a355ae50ecb3a8164056a8e91ffb1b9f5c9dbce686c4b78b827377a3ecdf797` and their original source/evidence were preserved. The approved full plan remains `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`.

## Corrected exact source pins

All seven current owned files again match their new retained source snapshot and manifest hashes:

| File relative to v3 source root | SHA256 |
| --- | --- |
| `record_identity_probe.cpp` | `0cc97a9eeb4eda5bb09f2a600eabee867299b756fe8364f02deeb7d77e85cb57` |
| `interface_gate_v3.py` | `df51d9323c1dd920e40bd7e4853f00be6580a0b61ebd3be2ea0d71d031476fd5` |
| `contracts/helper-schema.json` | `2d0d222b4192332ae9ce9c9bcc70aab7bc0b9d5539103ac3c3b82c6292f038a4` |
| `tests/test_identity_graph.py` | `c0571e1b2733cc083d97d34e716ee278de0ef0c7ecd6e084d2b7c2af368ec826` |
| `tests/test_builtin_types.py` | `3ebce53833f421ff51a7fc539c0d8ce67c8d9aae64eaf14ff48c6cfedcdbf0a8` |
| `toolchain-001/build_helper.py` | `c891ae9f2ba0ad33d75c56d7c9de3423934458345af45c6b2ea8fecd19fed7f4` |
| `toolchain-001/pin_helper.py` | `8c5c34cdafe876d16e0cebf8fc435b246a8d54558b3cbd1e3a7858f9c815c7cd` |

The three import dependencies at the correction receipt also matched their retained identities when copied: bounded_runtime `64720b07db2ce08c98002cb21a13f9d3056c982a2e2540f8c474f2c3e62b9c20`, build_contract `a80a964f83c5d06dfbf2d544d923e649a89457aceab7a3cd49abe65a58310c3f`, and profile `a9bf4e71ac228ed703ad288c0baccad6e3173fb5101bfa97dd31fcfcd0157d4b`. They were copied for inert verification, not incorporated into a claim that other authors' final A2/A3/A4 integration is frozen or accepted.

## Original findings resolved

**A1-1 — enum members and unified work bound.** The C++ producer now checks the per-enum 4096 ceiling and increments its existing type/member work counter before attributes, value conversion or append. It reuses completed canonical enum nodes, avoiding repeated member enumeration through aliases/DAG references. The reader schema enforces the per-list ceiling, and `_validated_graph` charges enum-member visits to the same descriptor work budget before its semantic member walk. No second 4096 allowance was introduced.

The exact synthetic fixture has seven descriptor visits: 4089 members fits the unified 4096 budget, 4090 exceeds it, 4096 meets the necessary per-list schema ceiling but exceeds the global work budget, and 4097 fails the schema ceiling. This is explicitly documented rather than claiming that every 4096-member enum is admissible. The correction tests cover these boundaries. C++ enforcement was inspected statically; its actual compiled output/refusal remains a later native check.

**A1-2 — actual closed raw ingestion.** The gate now invokes the checked-in closed schema using the installed, version-checked fastjsonschema 2.22.2 Draft7 implementation, with defaults disabled. Both raw ingestion and graph validation use it. Supported, refused and fixture envelopes and nested descriptor/binding/provenance cases have closed shapes. Diagnostic provenance remains outside identity equality. Raw `execution`/`inputBindings` cannot enter through `probe` output; trusted enrichment is added only after validation and separately recognizes exactly that pair, validates their shape/completion and revalidates the remaining raw root. Unknown extra roots, missing diagnostics/provenance and nested unknown members now refuse.

The original three accepted counterexamples are retained in author evidence and now become unknown/not accepted. The correction does not rely on schema stubs, permissive root filtering or a schema file that is never invoked. Fixture-only output, v2 payloads, supported output with nonzero helper exit and inconsistent status/termination are not admitted as supported helper facts.

## Authorized phase/completion integration

The additional same-owned-path integration is appropriate and fail closed in this static review. Probe, ELF inspection and helper build use explicit named phases and profile ceilings. `_complete_execution` requires owned launcher identity, verified/admitted scope, complete capture/wait, cleanup/root reap/final absence and no timeout/output/infrastructure failure; a numeric exit alone is insufficient. Probe retains `bounded_result` when validation or completeness fails. Export inspection returns unknown/not accepted when either required readelf observation is incomplete. Build/pin admission also requires completed observations, with nonzero build still ineligible for pinning.

These checks consume controller-owned result facts. They do not authenticate candidate marker strings, establish native library entry/completion, or turn caller-supplied booleans into a new production execution authority. Runtime construction of those facts and final A2/A4 composition must retain their independent gates. Imports of support scripts remain inert; actual build and dependency-pinning subprocess operations were not run or qualified here.

The graph bijection, canonical aliases/GCC identity bindings, field/layout/qualifier handling, active-cycle versus completed DAG treatment and exact builtin mapping remain intact. The correction preserves long/long-long and plain/signed/unsigned-char distinctions, supported typedef presentations and explicit unsupported kind refusal. No private fixture, caller or scenario publication is authorized.

## Independent inert verification

I independently checked all seven source/snapshot pins; manifest/delta/report/command hashes; the three copied dependency identities; the exact Python binary; and all 11 pinned fastjsonschema source files plus three distribution metadata files. A reviewer-only repository-local copy was made at `build/v3/sol-a1-correction-rereview/` inside the worktree, containing the seven frozen sources, three exact dependency files and copied validator files/metadata. Tests imported those copies, not modules another author could be editing. Subprocess APIs were blocked for the control run; individual native paths were mocked as in the retained tests. No schema stub or package installation was used.

All **26 pure tests passed independently**: 20 identity/bound/schema/enrichment/completion checks and six builtin/assertion-text checks; zero failures/skips. The previously retained 20 checks remain within that set. Review artifacts:

- `build/v3/sol-a1-correction-rereview/tests.log`: SHA256 `e4813336e5dcbe6a2e300f81d9bb83df9a33119ec99f37896128e8fa36837c69`.
- Adjacent `commands.json`: SHA256 `2b6a180881e17cdc45a6ee4c0ad98c6943c88f076167c53b6f8a9fa402c7f4cd`; exact argv, cleared environment, input copy hashes and result are recorded.

These tests exercise real Draft7 schema validation, unknown/missing/nested roots, supported/refused/fixture separation, raw versus trusted enrichment, the unified enum budget, graph identity controls, exact builtin spellings, phase arguments, incomplete probe/export evidence and import-safe support. They do not compile generated C/C++, exercise the native helper, run a candidate, qualify a real readelf/compiler/link environment, or establish all dependencies of the external validator. The complete runtime/validator dependency qualification is still later work.

No Git/remote/CI/source/native/helper/compiler/candidate/auth/model operation occurred; only this report and the isolated pure-review copies/log/receipt were written. Initial reports, preparations 001/002 and attempt13 remain untouched.

**Final disposition: CLEAR for manifest `6e0d5f225f9d20ba8b1e3e4f560b5d7ccfc97819f370c81c94f2fd98f43ed786`, delta `ef82294d113d90335582de7f487ead2bd281f77c6539ceae030ab9bbaa7891d6`.** The original two source findings are resolved. Final composed-source review, actual C++ build/helper execution, full native controls, independent full acceptance and preparation/CI gates remain required.

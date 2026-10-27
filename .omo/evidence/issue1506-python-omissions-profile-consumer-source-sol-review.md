# Issue1506 Python omission, population and profile-consumer source review

Terminal: **CLEAR**, scoped to the exact frozen ten-file Python/population/profile-consumer slice below. No correction is required in that slice. This is independent source/artifact review, not composed migration, signature, native exporter, hosted interruption/resume or original-input qualification. The held exporter002 three-file slice was not edited.

Only this report was written. No project imports, tests, JVM/Ghidra/compiler/native/probe/GPG/CI/Git/remote/auth/model operation was run. Hash/JSON inspection used Python-B standard-library operations only; no submitted harness or application code was executed.

## Reviewed identity and preservation

Worktree: `/home/june/decomp_thing/.claude/worktrees/issue-1506-referenced-bytes`.

- Final freeze `build/issue1506-python-omissions/profile13-completion/freeze.json`: `fda5f7dadf886693cdbfebd02b1052ffda551add248d5195fbd3b4e96425a397`.
- Final handoff: `a43c8193d439a2f0577354395fc2d222065233e0bddded259214089c2e0769ae`.
- Prior seven-file freeze: `34d2f724ebe70380edb10e9f21c6de1f71fd9b81f9c002ed63a7384b96564b63`; all seven current source hashes still match it.
- All ten current sources and exact source-snapshot copies match the final freeze. All eighteen evidence-file hashes across the two freezes match. The six manifest-pinned historical files (11/12 schemas/profiles and cc1/lto1 build records) match. The historical full-export12 profile separately retains `011f49895f66c4af2692eeaac6bb514a96761ed864f2b0051b533bda3fead06f`.
- Current sources, evidence and dependency hashes were checked again after source inspection. Exporter002's three held source hashes also remain exact.

| Owned source | SHA256 |
| --- | --- |
| `oracle/function_recovery.py` | `fe8f48a8ddf62479aa28ec57db8bd885b19ad124aa2a2d7ecfb5426702aa2572` |
| `oracle/gcc/compiler_engines.py` | `5c674b3f2fc629a4973389c17dd42a3c04628d1694c8a44a785e49d5dcdc1b8f` |
| `oracle/kotlin-schema-inventory-v1.json` | `9f1daff7bb95226b5bcd322bb86d49fcce3961ef3508ad035d8224ded6199e3a` |
| `oracle/referenced_data_bytes.py` | `e4caec950f9d34d74e3b0f248de4cacfbe7ba05e820d80e6da4c35098e3c8a74` |
| `oracle/unassessed-recovery-population.schema.json` | `550079ced463886e1608be56c86ad1d16bad677106303f95417422da98d97164` |
| `scripts/generate-gcc-compiler-engine-build-records.py` | `c9fe494e1bbaa017d4662695f1c73bac44acdb80964f4393207be128c6b8f1d3` |
| `scripts/validate-archival-docker.sh` | `0718ccb6558a0af5725bfa1abede7ee2aa97926e67d56c4be051f8c5ea889fe6` |
| `tests/oracle/test_gcc_compiler_engines.py` | `34dae9b4f9e092d72513f80a3005dc4d1db01afde802316381f1b3f914ca8c67` |
| `tests/oracle/test_gcc_function_recovery.py` | `245e03845399151109612aab7207d9fa3b455989ab0051ae35d0a69e0a3831ef` |
| `tests/oracle/test_referenced_data_bytes.py` | `be9cb859488149e88ee8edcf56782b3598fbccd4a395e82f9f1ab1a13d4e01fc` |

Final read-only dependency binding is coherent: exporter `a607b41b7c0cb7d871ca5c92c674b42602284d9d12570746054b38382603d265`; compiler13 profile `0d2c6f571b1ee7a977b2baf496823186da3fa95c97ede358e2c4ef75403927ca`; full-export13 profile `1075cd580b0a5bc872149633c1aa95a30b08b9da2f2e9feb689352571032b615`; schema13 `5b8c6b6a6a48c15be8f4966bee0466313766854f9e380a98898a9274bc554725`. The actual JSON compiler profile binds exporter13/a607 and the full profile binds that same exporter and compiler-profile digest. This verifies artifact agreement, not runtime execution.

## Source invariants

### Closed generations, early admission and origin identity

`oracle/referenced_data_bytes.py:29–145` performs bounded lexical admission before evidence-tree allocation. It recognizes containing globals/byteEvidence boundaries independently of model-field order, detects decoded duplicate boundary/evidence keys before their values, accepts only object or exact bounded null at byteEvidence, and limits evidence depth, windows32/global and4096/model, requested bytes256/window and65536/model, segments256, and evidence strings/keys. The new omission array admits only scalar strings, at most2, with bounded string length. Unknown containers/keys in evidence refuse. The strict JSON decoder/pairs hook remains responsible for full syntax and duplicate fields throughout the document; admission alone is not represented as full model validation.

`validate_evidence` at161–237 retains historical v1's exact three evidence fields and identity behavior. V2 requires all four exact fields. Its omission list has closed ordered vocabulary global_window_limit, model_window_limit, model_requested_byte_limit, reference_work_limit; uniqueness, fixed order and at most one aggregate reason are enforced. Empty windows require an aggregate/work omission marker; local-only omission requires exactly32 windows. Retained unknown-width metadata independently determines unknown_access_width. The markers never waive ordinary window, byte, segment, availability, address/overflow, operand or model payload limits.

V2 identity is decoded full target address + instruction address + operand, after enforcing window start equals reference target. Width/basis/availability/payload cannot create a second identity. Thus duplicate or conflicting serialized origins refuse. V1 retains its previous wider identity tuple, preserving historical behavior. Serialized addresses are canonical default-space numeric addresses; this wire does not invent address-space information. True cutoff occurrence remains an authenticated producer/source claim, not something a shape validator can infer from an omission token.

### Generic null and the real scorer boundary

`oracle/function_recovery.py:819–884` dispatches only integer models1/2/3/4. Models1/2 keep the historical projection and forbid supplied byteEvidence fields; their pre-existing historical global/type projection behavior is not expanded into a new deep validator here. Model3 requires supplied nonnull v1; model4 requires the byteEvidence key and accepts either null or exact v2. Mixed generations and string/null impostors refuse.

Crucially, model4 null skips only validate_evidence. Closed ordinary global keys, id/name/address/type/initializer, extraction status and unassessed recovery status validate first. Type validation and all later function validation/input digest/RVA/projection checks still run. Null charges no payload but does not bypass ordinary validation or manufacture completeness/cutoff evidence. Globals/types are released before function processing, preserving the existing resource boundary. The source delta changes generation admission, not matching/scoring formulas or truth/ABI authority.

The authored scorer controls call actual load_program_model and score_files through the existing fixture wrapper for null, complete v2 and empty-cutoff v2. They compare actual function projection/report with historical fixtures and retain productionVerified=false; malformed ordinary globals, types, functions, status and generation mutations are negative controls. They are stronger than merely counting tests or restating the new condition, but their recorded runs are still authored public-fixture evidence, not original-input recovery evidence.

### Bundled archival producer and population schema

`scripts/validate-archival-docker.sh:84–96` requires active model4, nonnull evidence for emitted bundled globals, and validate_evidence(...schema_version=2). It keeps unassessed/extraction assertions. This producer boundary correctly remains stricter than generic nullable model4. The authored AST-prefix control executes this actual admission prefix, stopping before Docker/archive/native assertions; its pass cannot qualify those omitted stages.

The population schema changes only modelSchemaVersion enum1..4. Closed keys, schemaVersion1, state=unassessed, model binding, unique unassessed IDs and assessedEntityIds maxItems0 remain. Its actual digest is `550079ced463886e1608be56c86ad1d16bad677106303f95417422da98d97164`, exactly registered in the inventory. SchemaCount80/sharedCatalogCount76 and unique names agree. New schema13 is registered once with its actual5b8c digest; old11/12 entries and file digests remain. Current OracleSchemas.kt:350–352 also contains the separate13 catalog entry; that out-of-slice Kotlin file is an observed composition dependency, not approved by this ten-file verdict.

Population tests use authored documents and check versions1..4, reject5/bool/string, assessed state/nonempty assessed IDs/extra fields, and verify the registered digest. Python's function score report has no recovery-population output. Actual Kotlin model4 population output/schema validation is therefore a remaining composition gate, not a result furnished by those Python scorer tests.

### Profile dispatch and generator defaults

`oracle/gcc/compiler_engines.py:83–125` adds only version13's distinct schema mapping, preserving11/12 and strict integer dispatch. Canonical JSON, duplicate refusal, size/path/hash/provenance/source-lock checks, engine ordering, authenticated all-gcc command and derived build-record checks remain active. The production loader still calls real load_and_validate_lock; no signature bypass was added to production.

The generator defaults to compiler-engines-exporter13.json. Its existing explicit output-root and canonical atomic JSON-record generation are preserved; it describes build records and does not execute a compiler. The new authored control supplies a fresh repository-temp output root, verifies exact derived bytes and historical11/12/cc1/lto1 file hashes. It does not establish a new native build or authorize overwriting historical records. Five profile tests include historical11/12/new13 closed-schema dispatch, malformed versions/unknown fields, provenance/engine substitutions and generator default behavior.

## Recorded verification and limits

The original seven-file freeze records18 pure controls, unchanged. The intermediate combined23-control log records an earlier dependency generation. The final rebound log records exactly5 fresh profile controls on the final four dependencies, zero failures/errors/skips and no forbidden-action attempts. These are **18 retained unchanged controls plus5 fresh controls**, not23 freshly rerun controls after rebinding. This review inspected the guarded runners, logs and hash receipts without rerunning them.

The initial expanded run records5 denied subprocess.Popen/GPG attempts,5 failures and no native execution. It remains failed evidence. The later local pure harness mocks only `_verify_key_identity` and `_verify_detached_signature`; production schema/provenance/derived-record checks remain. Those mocks do not verify signatures/authentication, and the guarded runner's PASS is correctly scoped accordingly. Repository-temp environment/tempfile routing is explicit; no outside temporary destination was introduced by the new generator test.

Remaining root-owned gates: coherent frozen Kotlin canonical/prompt/repair/admission and profile/capture/resume composition; actual model4 population output validation; compilation and separately authorized runtime/native/signature/archival verification; unchanged4096-function held512 checkpoint/interruption/resume/fresh equivalence; CI/automatic review; and any later separately authorized original/model-to-prompt replay. Existing historical receipts and original evidence cannot be relabeled by this source review. No issue closure, full acceptance, ACP trial readiness, ABI/prototype recovery or assessment authority follows from CLEAR here.

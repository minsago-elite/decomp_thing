# Authenticated generic template evidence: design proposal

**Review artifact for the open design issue.** This document proposes a frozen, bounded contract and implementation issue set. It authorizes no producer, observation sink, truth projection, schema migration, or production qualification. The reviewed repository baseline is master commit `e5ff2c537c09eb3c048cba80a1ac53dcf00f2d6a` (merged PR #1469).

## Decision

Use a versioned Clang frontend evidence adapter as the first supported generic-template provider. It must run with the exact Clang frontend authenticated for the build action, over the authenticated source and build inputs, and record compiler-owned declaration relationships and typed template arguments. A separate raw-input validator replays that action and regenerates the evidence. The serialized frontend output is a transport artifact, never truth by virtue of its own digest.

DWARF remains the source of physical emitted-instance evidence. Frontend pattern facts and DWARF DIE facts have different physical locators and are not joined by names, mangling, candidate hashes, offsets, visitation order, or approximate coordinates. DWARF5 §2.23 explicitly says the format does not represent generic definitions, but represents each instantiation and its actual parameters; §3.3.7 and §5.7.7 make the same limitation for function and class templates. Therefore a missing frontend proof remains unknown. The GCC and Clang DWARF5 records inspected for #1469 show typed concrete instances but no generic-pattern-to-instance edge. The accepted ordinary `DW_AT_abstract_origin` edge in #1469 is inline evidence only.

The generic facts use a new `full-tree-generic-template-evidence-v1` schema/policy. They do not extend observation-v2 or truth-v3. When they are eventually projected, use additive observation-v3 and truth-v4 paths; keep observation-v1/v2 and truth-v2/v3 schemas, policies, digests, APIs, and migration vectors byte-for-byte unchanged. The generic source census remains separate from emitted-RVA score denominators.

## Evidence and feasibility

| Evidence inspected | What it supports | Limit |
| --- | --- | --- |
| Official DWARF5 §2.23, §3.3.7, §5.7.7 | Concrete template-instance DIEs and typed actual parameters can be retained. | No portable generic-definition DIE or mandatory pattern-to-instance link. |
| Merged #1469 at the reviewed baseline; source-identity producer/model and fixture report | Bounded artifact-bound DIE rows, ordered typed actuals, concrete candidate identities, unknown generic links, digest-bound scope/inventory, and existing no-partial-publication controls. | It intentionally has no source/frontend generic relation. |
| Clang LibTooling and AST API documentation | A `ClangTool` runs a `FrontendAction` with a compilation database; `FunctionDecl::getPrimaryTemplate`, `ClassTemplateSpecializationDecl::getSpecializedTemplateOrPartial`, and `getTemplateArgs` expose semantic links and typed actuals. | This is a Clang-specific interface. Its records still require authenticated inputs and raw replay. |
| Clang JSON compilation database specification | A command entry records the working directory, main source and compile command; the `arguments` vector is preferred over shell text. | A database describes a command; it does not attest that it ran or that its ambient files/environment were controlled. |
| Official GCC template-instantiation documentation | GCC may emit duplicate instances per translation unit and let the linker discard duplicates. | Emission/linker behavior is not a generic source identity relation. GCC is not a v1 frontend provider. |

The feasibility claim is deliberately narrow: Clang's semantic AST APIs offer direct template declaration pointers and ordered `TemplateArgument` values, so a bounded C++ `FrontendAction` can serialize those relationships without parsing names. PR #1469 already established that the selected C++ compiler fixtures contain the concrete-instance side of the evidence and that the DWARF side lacks the generic edge. The first implementation should exercise a pinned Clang 18.1.3 fixture profile (also used by #1469's recorded fixture matrix) and record the exact executable/runtime digests; version text alone is not authentication. No claim is made that GCC's frontend has equivalent stable API coverage, that any production build has been requalified, or that Clang and GCC ASTs are interchangeable.

Primary references: [DWARF5](https://dwarfstd.org/doc/DWARF5.pdf), [Clang LibTooling](https://clang.llvm.org/docs/LibTooling.html), [Clang JSON Compilation Database](https://clang.llvm.org/docs/JSONCompilationDatabase.html), [Clang `FunctionDecl`](https://clang.llvm.org/doxygen/classclang_1_1FunctionDecl.html), [Clang `ClassTemplateSpecializationDecl`](https://clang.llvm.org/doxygen/classclang_1_1ClassTemplateSpecializationDecl.html), and [GCC template instantiation](https://gcc.gnu.org/onlinedocs/gcc/Template-Instantiation.html).

## Trust inputs and authentication contract

The producer and validator accept only the following frozen input chain. Every digest below is SHA-256 over the exact canonical bytes or file bytes named; no caller-provided digest is accepted without rereading and validating its input.

1. **Source identity.** Reuse the authenticated scope, source lock, artifact manifest, source archive, source inventory, generated-file inventory/provenance, and the source-root path normalizer. Bind the Git source revision/tree identity, archive bytes, every translation-unit source blob, every generated source/header, and every opened include. Reject dirty, replaced, symlink-escaping, missing, or digest-mismatched inputs. A file outside the authenticated source/generated/toolchain closure makes that translation unit unsupported; it is not silently read from the host.
2. **Build action.** Reuse the authenticated build-record and compiler-action/compilation-database inputs. Select one unique action by authenticated `unitId` and exact argv digest. Canonicalize the argv as an ordered string array, working directory, main file, target triple, language mode, ordered `-D`/`-U` definitions, include search order, forced includes, response-file bytes, sysroot, resource directory, and PCH/module inputs. Prefer `arguments`; reject shell `command` entries unless they are parsed and then proven byte-for-byte equivalent to the selected argv policy. Bind a sorted, explicit environment allowlist; clear all other environment variables. Do not treat the repo's current Clang capture-input or Ninja prestart object as execution evidence: those objects are explicitly unexecuted.
3. **Frontend identity.** Bind a registered `clang-libtooling-cxx-v1` profile to compiler executable SHA-256, Clang/LLVM runtime and loaded-library closure digests, resource-header manifest digest, adapter source revision, adapter executable digest, adapter ABI/API version, target triple, and the existing toolchain reproduction/profile digest. `--version` output is diagnostic only. Reject an unregistered profile, a substituted executable/library, an implicit host `PATH` lookup, or a compiler different from the compiler authenticated for the build action. For v1, GCC, MSVC, clang-cl, and a Clang frontend substituted for a GCC-built artifact have capability `unsupported`, not a guessed fallback.
4. **Preprocessor/build context.** The execution receipt records the exact effective frontend argv after the versioned extraction-only adjustment, cwd, environment digest, actual ordered include/dependency closure with per-file hashes, generated inputs, and a deterministic preprocessor-context digest over active macros, include resolution, language/target options, and authenticated PCH/module inputs. Disable PCH/modules in v1 unless their exact artifacts and import closure are included in the authenticated profile. Unknown flags remain in the semantic-context digest; only the fixed v1 allowlist of codegen-only flags may be excluded from the source-semantic candidate. This keeps `-O0` and `-O2` facts comparable while binding both full action vectors.
5. **Executed frontend receipt.** The bounded isolated runner records action success, the authenticated compiler/profile/action digests, dependency digests observed by the frontend, preprocessor-context digest, evidence output digest/bytes, exit status, resource usage, and a deterministic action ID. A planned command, compile database row, stderr/stdout text, compiler version string, or producer-authored JSON is not an execution receipt. On any failed command, changed input, missing include, resource termination, or receipt mismatch, publish no partial facts.

The current Kotlin trust chain is a viable base: `FullTreeScopeControl` snapshots and validates the exact scope/source-lock/manifest/build-record bindings; `FullTreeSourceInventoryControl` checks the locked source archive and per-file inventory; `FullTreeFunctionObservationProducer.authenticateShardInputs` binds inventory and rich-artifact bytes; and the #1469 producer enforces authenticated per-shard and no-partial-output budgets. The gap is explicit: current `FullTreeClangCaptureInputControl` and Ninja prestart represent validated but unexecuted inputs. The first implementation issue must add a frontend execution receipt instead of upgrading either plan object by implication.

## Schema and identities

### New standalone wire contract

Add strict schema `oracle/full-tree-generic-template-evidence-v1.schema.json`, registry name `full-tree-generic-template-evidence-v1`, wire `schemaVersion: 1`, provider `clang-libtooling-cxx-v1`, and policy `{id: "full-tree-generic-template-evidence", version: 1}`. Its configuration digest binds only this schema and policy. All objects use `additionalProperties: false`; all arrays have canonical order; unknown fields, duplicate physical IDs, dangling local endpoints, invalid enums, invalid digest encodings, and count mismatches fail validation.

The envelope has exactly these sections:

- `bindings`: digests for scope, source lock, artifact manifest, build record, source archive/inventory, generated inputs, rich artifact/inventory, compilation database/action set, registered frontend profile, and policy configuration.
- `units`: one record per selected compile action, with `unitId`, action ID, source path/blob digest, full command digest, semantic-context digest, frontend-profile digest, ordered dependency file path/digests, and action receipt digest.
- `entities`: compiler-observed `primary-template`, `partial-specialization`, `explicit-specialization`, or `concrete-instantiation` declarations. Each includes a physical frontend locator; source spelling and expansion locations/raw name for evidence; kind (`class` or `function`); ordered formals; complete typed signature where applicable; specialization disposition; nullable semantic anchor candidate; and explicit status/reasons.
- `relationships`: typed directed edges between frontend physical IDs. The closed edge-kind set is `templated-declaration`, `redeclares`, `specializes-primary`, `instantiates-primary`, `instantiates-partial`, and `explicit-specializes`. Each edge carries its exact compiler API basis, selected target locator, and an ordered formal-to-actual binding vector. `templateArguments` retain recursive pack nesting and ordinals.
- `counts`: exact totals by entity kind, relationship kind, evidence status, and supported/unsupported reason.

The local graph is scoped to a single compile action. A target in another translation unit cannot be referenced by a fabricated local edge. Each concrete instance records the direct Clang declaration/specialization relation returned by the AST API, the immediate selected partial/primary template, and where applicable its primary-template ancestor as separate edges. Explicit specialization is distinct from implicit or explicit instantiation. The type/argument tree is tagged, ordered, and recursive; it never uses pretty-printed type strings as the relationship or as the sole type identity.

For v1, support only C++14 class/struct and function templates, primary declarations, class partial specializations, explicit specializations, explicit instantiations, observed implicit instantiations, overload sets, and packs. Formal kinds are type, integral/enum non-type, and template-template; actual kinds are type, integral/enum value, template name, and nested pack. The typed signature records result, ordered parameters, variadic bit, member cv/ref qualifiers, and calling convention. Each descriptor preserves qualifiers, signedness/bit width and value, parameter depth/index, pack position, and direct source-declaration references. Unsupported variable templates, class-valued/floating NTTPs, dependent/unresolved arguments, concepts/requires, modules, and unauthenticated PCH are retained only as bounded `unsupported` evidence with a reason and null candidate; they cannot yield a resolved relation. Expanding this set requires a new policy/schema version and fixtures.

### Physical locator versus semantic identity

- `frontendPhysicalId = SHA256(domain || actionId || recordOrdinal || entityKind)`. `actionId` binds the immutable source/build/frontend inputs; `recordOrdinal` is assigned from a deterministic source-ordered AST event stream. The outer execution receipt binds the complete evidence artifact digest, avoiding self-referential artifact hashes. This ID locates one observed frontend fact and changes when its action evidence changes.
- `semanticAnchorCandidateId` is nullable and hashes a domain-separated canonical tuple: source revision/tree and source blob digests, normalized repo-relative declaration path, language mode, enclosing lexical declaration chain, raw source name, entity kind, complete ordered formal descriptors, complete typed signature/actuals, and the v1 semantic preprocessor/target context digest. Raw compiler columns and build-machine absolute paths are retained as evidence but excluded from the candidate, matching the optional-column rule in #1466; line and normalized path remain required. Candidate equality never merges rows or proves identity.
- `resolvedSemanticIdentityId` is assigned only after raw rederivation, direct frontend canonical-declaration/relation evidence, and full-run collision reconciliation establish a single identity group. Equal candidate hashes from independent CUs, same-spelling overloads, repeated headers, or distinct source locations remain separate and ambiguous unless a compiler-provided direct identity/reference rule proves they are one declaration. The candidate hash is never a join key.
- Existing DWARF `sourceEntityId` remains an artifact/unit/section/CU/DIE-bound physical key; its `semanticAnchorCandidateId` remains the #1469 candidate. The frontend record is not joined to a DIE by name, demangling, offset, physical order, or candidate equality. Since portable DWARF has no generic-pattern reference, `dwarfSourceEntityId` is null unless a separately reviewed backend supplies direct validated evidence. Generic pattern evidence never creates or links an emitted-RVA denominator row in v1.

Canonical hashes use the repository's canonical JSON implementation with fixed UTF-8, explicit field names, sorted object keys, length-safe JSON string encoding, array order preserved where semantic, and domain/version prefixes. Omitted, unknown, unsupported, null, empty, and zero are distinct states. Raw spelling/locations are preserved next to normalized facts. Facts sort by `(unitId, actionId, physicalId)`; edges by `(sourcePhysicalId, targetPhysicalId, kind, formal/actual ordinals)`; descriptor arrays never sort.

## Bounds, failure behavior, and deterministic interface

The action interface consumes only validated typed registries and an authenticated immutable artifact root; it returns one immutable complete v1 result or a typed failure. It has no arbitrary path/output callback, no partial iterator that sinks can publish, and no ambient compiler selection. Production and raw-rederivation modes call the same strict input verifier but independently invoke the frontend over raw authenticated inputs. Candidate evidence is discarded before rederivation.

Use the smaller of caller limits and authenticated scope limits; do not raise any existing global, per-shard, DIE, function, parameter, serialization, or working-set bound. Freeze these additional ceilings in policy v1:

| Item | Hard ceiling | Admission and failure |
| --- | ---: | --- |
| Actions | Authenticated `wholeRun.compilationUnits` and existing worker ceiling | Reject before starting actions if the set exceeds either. |
| Evidence entities | Authenticated `perShard.entities` | Charge before retention; one over aborts the complete shard. |
| Formals or actual arguments per entity | 1,024 | Count nested pack leaves and nodes before retention; one over aborts. |
| Relationship edges per entity and relation walk | 32 each | Existing ceiling; one-over edge or chain aborts before publication. |
| Type descriptor depth / nodes per descriptor | 64 / 4,096 | Reject unsupported depth or node count; do not truncate. |
| One canonical entity row | `min(authenticated per-shard output bytes, 64 MiB)` | Reserve 2x row bytes for scratch before serialization. |
| Aggregate retained generic model | `min(perShard.maximumResidentBytes / 4, 3 × perShard output bytes, 64 MiB)` | Charge each retained contribution as 3x canonical bytes + 64 bytes, in the same source-identity working-set model; share, do not add to, the authenticated shard budget. |
| Aggregate evidence/observation output | Existing authenticated per-shard output bytes, additionally capped at 64 MiB for the standalone generic artifact | Preflight exact projected bytes; no partial file or receipt on one-over. |
| Frontend process | Existing selected contained-runner CPU, wall-time, memory, PID, FD, and output ceilings | Any process/resource failure aborts; no fallback to an unconstrained host compiler. |

If source locations, argument shapes, or types are syntactically readable but incomplete or conflicting, preserve bounded raw evidence and use `unknown`, `ambiguous`, or `unsupported`, with deterministic reason codes. If a declaration boundary, typed AST relation, or dependency closure cannot be established, abort that action. If a hard bound is exceeded, abort the shard before publishing any fact set. Exact-bound and one-over-bound behavior must be tested with lowered test limits for every row above.

## Ownership and compatibility

| Future owner | New files/contracts | Must not modify |
| --- | --- | --- |
| Frontend provenance unit | `FullTreeGenericTemplateFrontendProvenanceV1.kt`, `FullTreeGenericTemplateFrontendReceiptV1.kt`, `oracle/full-tree-generic-template-frontend-v1.schema.json`, a profile/policy registry, and its tests | Observation-v1/v2 and truth-v2/v3 contracts; #1467-owned v2 files. |
| Clang extractor unit | `FullTreeGenericTemplateEvidenceV1.kt`, `FullTreeGenericTemplateEvidenceProducer.kt`, a bounded `src/main/cpp/generic_template_frontend/` Clang `FrontendAction`, build task/runner integration, schema and fixture sources under `src/test/resources/oracle/generic-template-evidence-v1/` | Existing #1469 source-identity facts/physical locators; existing v1/v2/v3 semantics. |
| Observation integration unit | New `FullTreeFunctionObservationsV3.kt`, v3 in-memory and SQLite sinks, v3 publisher/receipt/validator, `oracle/full-tree-function-observations-v3.schema.json`, additive registry entries and v3 tests | All v1/v2 observation bytes/policies/entrypoints and #1467-owned v2 files. |
| Truth/rederivation unit | New `FullTreeFunctionTruthSqliteV4.kt`, shard/index v4 schemas, additive registry entries, fixture vectors and raw-source rederivation tests | All v2/v3 truth bytes/policies/entrypoints and #1468-owned v3 files. |

The new frontend evidence stays a separate `genericTemplates` collection in observation-v3, beside (not folded into) #1466 `sourceEntities`. Truth-v4 reports a distinct non-scoreable pattern/instance census. It cannot change emitted function/RVA, recall, or score denominators. A future exact frontend-to-DIE relation would be a separately versioned edge, with raw evidence; no such portable edge is specified here. Existing #1467 full-run collision handling still applies: compare the complete bounded relevant candidate population before v3 publication, retain colliding physical rows, and mark unproved repeats ambiguous. Truth-v4 reruns the full population from raw source/build/frontend inputs and rejects any changed fact, edge, ID, status, reason, category, or count.

## Proposed implementation issue bodies

These are drafts for independent review, not created issues. Assign IDs and native parent/dependency edges only after the design is accepted. Every issue remains fixture-only until a separate production-qualification decision. All implementation bodies must preserve #876, #123, and #692 as open until their own criteria pass; no body closes the original generic-pattern acceptance by itself.

### A. Authenticate bounded Clang frontend action inputs

**Outcome:** Add an authenticated, replayable provenance contract for the exact source, build action, and Clang frontend that may emit generic-template facts.

**Dependencies:** Merged #1469; existing authenticated full-tree scope/source inventory/build record; existing contained-runner and Clang action capture inputs. This unit must not claim the existing unexecuted capture/prestart is an execution receipt.

**Ownership:** Add the frontend profile, strict action/provenance v1 schemas, immutable Kotlin loaders/validators, canonical digests, and receipt types listed in the ownership table. Integrate only through new files and additive registries. An action is selectable only from the authenticated source/build plan by exact `unitId` and argv digest. Require Clang 18.1.3 fixture identity and exact executable/runtime/adapter hashes in fixture receipts; a version string is insufficient. Record actual include closure/preprocessor context and bind source/generated input bytes. Use the existing containment policy; do not add or increase authority/resource ceilings.

**Acceptance:**

- [ ] Strict schema and policy registration, canonical bytes, and digest tests reject unknown fields, duplicate actions, path escapes, absent dependencies, wrong source blob, altered argv/environment, changed compiler/library/adapter bytes, and mismatched source/build/manifest bindings.
- [ ] Receipt generation requires a successful isolated frontend action; a merely planned capture object, compiler stdout, forged receipt, missing include, altered header, or failed/resource-killed process cannot yield an authenticated receipt.
- [ ] Tests mutate each source/build/frontend binding independently and verify that raw-input loading rejects the mutation before evidence publication.
- [ ] Exact limits and one-over tests cover action count, dependency/receipt bytes, output bytes, worker count, and runner containment bounds; there is no partial receipt.
- [ ] The `arguments` vector, cwd, env allowlist, response files, macro/include order, target/language flags, generated files, toolchain closure and action-adjustment policy are all hash-bound.
- [ ] Existing capture-input/prestart schemas and no-process authority remain unchanged; fixtures are not described as production authentication.

### B. Extract a typed generic-template graph with Clang

**Outcome:** Implement `full-tree-generic-template-evidence-v1` by running a bounded Clang `FrontendAction` against inputs accepted by A and serializing direct compiler relationships and complete supported typed descriptors.

**Dependencies:** A; merged #1469 for source/DWARF boundary and bounded facts model. No dependency on observation or truth sinks.

**Ownership:** C++ frontend action/helper and Gradle build task; Kotlin producer and independent strict validator; schema, policy, canonicalizer; fixture sources/reports. Record provenance in every evidence envelope. Clang API declaration pointers establish only the edge documented by the specific frontend profile. Never associate unrelated declarations by rendered name.

**Acceptance:**

- [ ] Positive C++14 fixtures authenticate one primary pattern and distinct `int`/`long` concrete instances with ordered typed actuals; include class and function forms, explicit/implicit instantiation, primary and partial specialization, a true explicit specialization, overloaded templates, and type/non-type/template-template pack controls.
- [ ] Clang fixture assertions check direct AST edge kind/target and actual-argument shape before identity; a source-name-only or mangling-only match fails the assertion.
- [ ] Two separate TUs including the same header preserve separate physical frontend rows and equal candidate hashes as ambiguous; they are never merged by tuple/name. A macro/configuration change changes the authenticated context and is not silently coalesced.
- [ ] Source/header/compiler/argv/environment/frontend mutation, false pattern edge, altered formal/actual order/type, forged candidate/resolved ID, omitted overload, unsupported type, and self-consistent candidate mutation are rejected by rederivation.
- [ ] `-O0` and `-O2` runs retain equal source-semantic candidates for the same authenticated parse context, while full action receipts bind their distinct argv. Two identical runs and reversed worker/action visitation produce byte-identical canonical output.
- [ ] Every frozen bound has exact and one-over tests; malformed input and bound failures publish no partial evidence.
- [ ] GCC-produced objects, GCC AST guesses, DWARF DIE names/offsets, and unauthenticated AST JSON stay unsupported. Tests label actual compiler evidence and synthetic parser/control data separately.

### C. Publish generic-template facts in observation-v3

**Outcome:** Add a separately named observation-v3 path with in-memory/SQLite byte parity, full-run collision reconciliation, and a distinct non-scoreable `genericTemplates` collection.

**Dependencies:** B and merged #1467. If #1467 is still open, this is sequenced after its v2 contract is accepted and must not edit its owned files.

**Ownership:** New v3 schemas, policy/config digest, producer/validator, both sinks, publisher/receipt/validator, additive schema inventory/registry entries, tests, and fixture-only canonical vectors. The v3 path consumes authenticated v2 observation facts plus raw-rederivable frontend-evidence-v1 facts; v2 entrypoints remain frozen.

**Acceptance:**

- [ ] V3 strict schema/policy binds source/build/frontend receipts and contains generic patterns/instances/typed edges separately from `sourceEntities`; v1/v2 output and hashes remain byte-identical.
- [ ] Both sinks emit byte-identical canonical bytes for identical immutable fact streams; shuffled actions, source entities, hash maps and worker counts do not change output.
- [ ] Cross-shard candidate collisions retain every physical row and become ambiguous absent a direct validated relation. The full relevant bounded anchor population is reconciled before v3 publish; candidate equality never authorizes a join.
- [ ] A generic instance cannot add or link an emitted-RVA row through name, demangle, offset, candidate ID, or a guessed source relation. No new pattern or instance changes emitted denominators.
- [ ] Exact/one-over edge, reference, entity, resident/output, SQLite, serialized-byte, and row limits fail closed without a partial shard/publisher receipt.

### D. Project and independently rederive generic facts in truth-v4

**Outcome:** Add truth-v4 shard/index projection from authenticated observation-v3 and reject forged or self-consistent frontend/source relationships through raw-input rederivation.

**Dependencies:** C and merged #1468. Preserve the full existing v3 contract while adding a new path.

**Ownership:** New truth-v4 shard/index schemas, policy/config, SQLite path, raw-input rederiver, migration/registry entries and fixture vectors. Do not alter truth-v2/v3 files or their ownership.

**Acceptance:**

- [ ] Fresh truth generation and candidate validation independently reload the raw source archive, source/build manifests, compiler/runtime profile, action receipts, dependencies, and frontend adapter, rerun frontend extraction, then derive observation-v3 and truth-v4; candidate-supplied pattern/instance edges never become inputs to truth.
- [ ] Rehashed mutations to source revision/file, build args/macros/includes, frontend identity, physical locator, pattern/instance edge, formal/actual order/type, collision state, reason, category/count, or denominator disposition are rejected.
- [ ] Pattern and instance census counts reconcile to rederived observation facts; all remain non-scoreable and do not add emitted function/RVA records.
- [ ] Byte-identical duplicate generations pass; changed input bindings fail; exact/one-over bounds and old truth-v2/v3 compatibility vectors pass unchanged.

### E. Audit the original #876 acceptance after integration

**Outcome:** Re-audit #876's two original criteria against the merged #1466/#1467/#1468 and A–D evidence, separately from production qualification.

**Dependencies:** #1466/#1467/#1468 and A–D all merged with exact-head independent review and full required CI. No dependency issue is closed by this audit automatically.

**Acceptance:**

- [ ] Declaration-only and inline-only cases remain explicitly unobservable/non-scoreable and never enter emitted-RVA denominators.
- [ ] At least one authenticated source/frontend fixture proves a pattern-to-typed-instance relation with a direct AST relationship and complete source/build/frontend evidence; no compiler spelling/DWARF heuristic is involved.
- [ ] Physical DIE and frontend locators remain distinct from semantic identity; repeat headers/cross-CU collisions remain ambiguous without a validated identity edge.
- [ ] Raw rederivation, full-run collision reconciliation, sink parity, schema/version compatibility, exact/one-over resource tests, independent review, and fixture-only evidence labels all pass.
- [ ] Keep #876 open until this audit's entire acceptance is independently accepted. Keep #123 and #692 open and unchanged. This audit does not claim release or production qualification.

## Review gates and retained status

This document is the complete proposed design artifact; the issue drafts above are intentionally not scaffolded until independent design review accepts this contract. After acceptance, create the issues with the stated dependencies and exclusive ownership before implementation begins. Then implement and review each issue in dependency order. Keep #1470 open until design review and issue scaffolding are complete. Keep the original generic-pattern criterion on #876 open until issue E passes. Keep #123 and #692 open. No merge, paid compiler/service/runner/review, production operation, release qualification, or change to #742/PR #1462 is authorized by this design.

## Repository and implementation references inspected

- `AGENTS.md`: milestone/issue status is source of truth, plan with focused acceptance criteria, and do not merge while required checks/reviews are incomplete.
- No repository-local `.agents/skills` files were present in this checkout.
- At reviewed commit `e5ff2c537c09eb3c048cba80a1ac53dcf00f2d6a`: `FullTreeScopeControl.kt`, `FullTreeSourceInventoryControl.kt`, `FullTreeFunctionObservationProducer.kt`, `FullTreeClangCaptureInputControl.kt`, `FullTreeNinjaCompdbPrestartControl.kt`, `FullTreeSourceEntityIdentity.kt`, `FullTreeSourceEntityIdentityProducer.kt`, and merged PR #1469's fixture report.
- Related open requirements: [#1470](https://github.com/minsago-elite/decomp_thing/issues/1470), [#876](https://github.com/minsago-elite/decomp_thing/issues/876), [#1466](https://github.com/minsago-elite/decomp_thing/issues/1466), [#1467](https://github.com/minsago-elite/decomp_thing/issues/1467), and [#1468](https://github.com/minsago-elite/decomp_thing/issues/1468). PR #1469 is merged; it does not complete #1466 or #876.

# GCC ABI admission contract v1 — proposed closed policy

Status: **proposal for independent semantic review**, not an implemented or sealed population. This is work package 1 of the approved full-scope `gcc-observable-abi-population-ledger.md`; issue 692 and parent 46 remain open. It does not reduce that plan's function, global-storage, shared-type, recovered-model, independent-verifier or qualification requirements.

## Evidence and authority

- Producer: `fae856cec8f7dc8df6fe6bfd92075651966da2ca`; retained Actions run 38514717813, artifact 11872131041, ZIP SHA256 `d5d2cabf6b2640e7a71d91fe082009c52ad66fa4c92fe48a53ecc078838bcb8c`.
- Empirical census: `build/gcc-abi-policy-census/physical-census.json`, SHA256 `9cc51b702f6c354d51d0b16e7a90a9c74e169b84b7f59eb91670b9d2e938bff8`. Its pinned script verifies the ZIP and nine used canonical parts: one physical-unit shard and eight physical-DIE shards, 61,106,061 canonical bytes. It does not replay the original binary parser or independently recompute cycle flags.
- Semantic rule definitions and exact code anchors: `.omo/evidence/gcc-abi-identity-contract-source-audit.md`, closed registry **C01–C04, F01–F04, G01–G05, T01–T04**. These definitions are part of this proposal and must be pinned by digest at approval. Unknown rules cannot authorize identity, exclusion or unobservability.
- Current GitHub scope: `build/gcc-abi-policy-census/current-scope.json`, SHA256 `3bb2f632e54d4b5d95baa606934e3fbc08f6f0ea8e8902cf97041a59f47084e3`; issues 692, 46, 679 and 1506, and A7 milestone 11, are open. All 39 milestones were checked: 27 open, 12 closed, no closed milestone with open issues. This check does not replace the retained full-acceptance closure audit.

These are authenticated observations and proposed interpretation rules. They supply no new oracle authority, semantic denominator, recovered-model binding, score, production verification or release eligibility.

## Units and invariant

Keep physical witnesses, semantic entities, required facts, aliases, use edges, ambiguity alternatives and recovered mappings in separately counted relations. Every physical witness has one coverage decision. A decision may witness an entity, alias, declaration, dependency or positively irrelevant role; it is not automatically an entity. Excluding a raw automatic-local witness never proves an entity-level exclusion when other witnesses remain.

The proposed units are an independently callable emitted ABI entry with complete owned ranges; a semantic process/TLS storage object; and a nominal shared declaration with independently established required uses. Multiple clone/thunk entries can be distinct entities; multiple alias witnesses can belong to one entity only after proof. The shared predicate is use of the same T02-proven nominal declaration by at least two distinct **authenticated source translation-unit/build identities**, as defined below. All required nonshared declaration dependencies remain separately retained and reconciled. This fixed definition is normative for the registry's T01 and its use of the words "logical module"; the builder cannot substitute a chosen grouping.

### Fixed shared-use owner unit

One owner unit is one compilation-bearing source translation unit for the pinned linked target, enumerated in its complete authenticated source/build inventory. Its stable inventory ID must be bound to the build root, canonical source identity, compilation role, target, effective compile variant/command and linked object provenance. Reuse the exact A13 unit-ID and per-TU ownership vocabulary when its actual inventory applies; matching a physical DWARF CU offset or a source-path string alone is insufficient. Distinct linked compile variants require separate proven build identities; a source-only noncompiled record is retained for relevance/exclusion accounting and never becomes a use owner merely by existing. A generated translation unit needs authenticated generator/output/build provenance under the same rule.

Independently replay physical-CU, declaration and required-use ownership against that inventory. One TU may emit several physical DWARF units without becoming several owners. A merged/LTO unit may contain several TUs only when complete origin/build evidence separates their ownership; otherwise the relevant owner relation remains unresolved. Header declarations belong to their nominal identity and have per-compiling-TU use witnesses, rather than an invented owner for every header occurrence. External declarations and providers remain explicit dependencies; an unknown external use cannot manufacture a second owner. Any relevant split/generated/source-only/external ownership ambiguity that can change shared membership blocks closure.

`fulltree/FullTreeHeaderModulePlan.kt:20,34,40` at the pinned producer establishes this existing source-unit/per-TU/source-only vocabulary; its `:116` fixture-only authority limitation remains in force. The complete production relation required here is **not established** by that fixture or the current census. The owner relation must commit every admitted declaration/use, its exact authenticated ownership inputs and reviewed policy, with independently replayable joins. Freeze it with the oracle population before recovered-model mapping. A recovered candidate, generated-output partition or observed score cannot choose, split, merge or change these owner units or the shared population.

Stable IDs commit the artifact root, policy version, domain and proven witness set. Minimum-coordinate representative selection is deterministic naming after proof, not proof of equality. Equal names, starts, extents, bytes, layouts or candidate source anchors cannot establish semantic identity. Distinct physical DIEs alone cannot establish distinct semantic entities. Cardinality-changing ambiguity retains derived bounds and prevents completeness; an ambiguity component or SCC cannot become one denominator entity by convention.

## Complete observed tag obligation table

The census contains **696,357 non-null DIEs, 186,149 null records and 37 distinct non-null tags** across 111 CUs. Every row below is a coverage obligation, not an admitted entity count. Numeric tags are authoritative identifiers here; human labels require the corresponding supported decoder. The rule registry and fallback C04 govern interpretation. Any additional tag in a future input requires an explicit policy/version decision; it cannot inherit blanket irrelevance from a coarse scanner category.

| Tag | Actual rows | Required role and rules |
| --- | ---: | --- |
| `0x1` | 1,190 | Array declaration and bound dependencies; T01–T04 |
| `0x2` | 3,988 | Class declaration, identity, bases and children; T01–T04 |
| `0x4` | 1,316 | Enum declaration and enumerators; T01–T04 |
| `0x5` | 273,207 | Parameter owner/order/type, including pack/inline ownership; F02, T01, T03 |
| `0x8` | 14,265 | Imported declaration target/use and ownership; T01–T03, C04 |
| `0xa` | 164 | Label witness: prove no required identity/use role before irrelevance; C01, C03–C04 |
| `0xb` | 5,265 | Lexical scope and storage/inline ownership; F03, G01–G03 |
| `0xd` | 38,504 | Member declaration/layout/identity dependencies; T02–T04 |
| `0xf` | 14,782 | Pointer declaration and required pointee edges; T01–T04 |
| `0x10` | 12,916 | Reference declaration and referent edges; T01–T04 |
| `0x11` | 111 | CU/source-bound tree and coverage ownership; C01 |
| `0x13` | 8,036 | Struct declaration, identity and complete children; T01–T04 |
| `0x15` | 1,405 | Function-type declaration and parameter/return closure; T01–T04 |
| `0x16` | 13,147 | Typedef declaration identity and target; T01–T04 |
| `0x17` | 427 | Union declaration, overlap roles and children; T01–T04 |
| `0x18` | 686 | Unspecified-parameter/variadic owner and interpretation; F02, T03 |
| `0x1c` | 2,416 | Base/inheritance dependencies and layout/ownership; T02–T04 |
| `0x1d` | 45,384 | Inline instance/origin/owner and required declarations; F02–F03 |
| `0x21` | 1,203 | Subrange/bound dependencies; T03–T04 |
| `0x24` | 2,227 | Base-type declaration and explicit ABI facts; T01–T02 |
| `0x26` | 13,310 | Const declaration and target; T01–T04 |
| `0x28` | 37,073 | Enumerator owner/value/order facts; T03 |
| `0x2e` | 104,792 | All subprogram roles, entries, declarations and range obligations; F01–F04 |
| `0x2f` | 17,147 | Template type-parameter identity/use; F02, T02–T03 |
| `0x30` | 3,542 | Template value-parameter identity/value/use; F02, T02–T03 |
| `0x34` | 24,231 | Every variable's scope, declaration, storage and identity; G01–G05 |
| `0x36` | 118 | DWARF expression helper; resolve supported expression uses or prove irrelevance; G05, T03, C04 |
| `0x37` | 49 | Restrict declaration and target; T01–T04 |
| `0x39` | 2,152 | Namespace/source ownership; F02, G03, T02 |
| `0x3a` | 72 | Imported module and required declaration ownership/closure; T01–T03 |
| `0x3b` | 82 | Unspecified-type interpretation; T01–T02, C04 |
| `0x4106` | 19 | GNU template-template parameter interpretation; F02, T02–T03, C04 |
| `0x4107` | 3,552 | GNU template parameter pack, ordered actual/formal dependencies; F02, T02–T03, C04 |
| `0x4108` | 537 | GNU formal parameter pack, ordered child/owner dependencies; F02, T03, C04 |
| `0x42` | 3,368 | Rvalue-reference declaration and referent edges; T01–T04 |
| `0x48` | 15,591 | Call-site owner/origin witness; no automatic new callable identity; F01–F03, C04 |
| `0x49` | 30,083 | Call-site-parameter role and type/owner evidence; F02, T01, C04 |

The scanner's 4,108 `unknown` category rows are exactly the three GNU tags above. Calling them known or irrelevant without implementing the required semantic interpretation would not resolve their obligations. Other-known imports/template/call-site tags likewise need decisions.

## Complete observed reference obligation table

All **800,159 references** have declared/resolved form `0x13`, indirect depth zero, retained targets and independently checked source-CU-relative operands, target membership and target CU bounds. Missing, out-of-range and unsupported references are zero in this artifact; this is not support qualification for unobserved forms. Each reference keeps its source attribute ordinal and typed relation role. A reference can be structurally valid without proving semantic equality.

| Attribute | Actual edges | Required interpretation |
| --- | ---: | --- |
| `0x1` | 152,489 | Sibling/tree navigation witness; validate scope/tree relationship, never semantic alias |
| `0x18` | 14,337 | Import target and required-use/declaration closure; validate target role and owner |
| `0x1d` | 1,732 | Containing-type dependency; validate nominal/owner relation |
| `0x2f` | 5 | Referenced upper-bound dependency; preserve dynamic/unknown bound semantics |
| `0x31` | 146,566 | Abstract-origin derivation with concrete/inline/parameter role checks; not automatic emitted-entity equality |
| `0x47` | 13,933 | Specification/declaration relation with target-kind, ownership and compatibility proof |
| `0x49` | 377,104 | Type-use/closure edge with owner and required-role proof; not source identity by itself |
| `0x64` | 79,441 | Object-pointer parameter ownership, order and type evidence |
| `0x7f` | 14,552 | Call-origin relation and target-role proof; no new entity or alias by occurrence alone |

The retained 11,233 cycle bits partition by attribute: `0x1=887`, `0x1d=235`, `0x31=3,891`, `0x49=6,220`. These are **counted producer flags**, not an independent cycle proof and not counts of malformed identity chains. Semantic verification must recompute the relevant typed relation: valid pointer recursion, general reference cycles and invalid identity cycles have different meanings. SCC traversal never supplies nominal equality or one-entity-per-component counting.

## Completeness and compatibility gates

1. **Physical source conservation:** preserve every DIE, ordered reference and relevant ELF observation. The current proof checks all 696,246 non-root parent links, CU counts/ranges, child stacks and consistent null gaps. Individual null-marker bytes/positions and non-reference attribute values are absent from these rows. Current parser replay or new bounded authenticated rescan must supply any stronger tree/scalar proof relied upon. DIE `endOffset` ends its own attributes, not its subtree.
2. **Semantic enrichment:** retain typed declaration/origin edges and complete executable ranges/roles; scalar declaration/storage/layout facts; relevant ELF function and storage forms, alias/linker ownership; complete nominal/member/import/type-use closure and independent module ownership. Existing flattened origins, ABI_LAYOUT types and `one-raw-candidate` storage bindings cannot stand in for them. Unavailable authority remains a named capability gap in 692 or the existing owning dependency, with precise evidence; it cannot be reclassified as binary unobservability merely to seal.
3. **Separate truth and role:** each required fact uses exactly observable, unobservable, excluded or unresolved with a closed reviewed reason. Missing parser support is unresolved. Proposed deterministic entity summary: whole-entity positive exclusion first; otherwise unresolved identity or any unresolved applicable required fact yields unresolved; otherwise any unobservable applicable required fact yields unobservable; otherwise at least one observable applicable fact and complete remaining fact coverage yields observable. An in-scope entity with no applicable fact, missing fact rows, or only excluded facts is invalid and cannot seal. Individual excluded facts need positive nonapplicability proof. This summary never changes fact classifications, totals or score credit, and partly observable entities retain every observable fact. Witness exclusion alone is insufficient for whole-entity exclusion.
4. **Historical contracts:** reconcile all 12,844 function-oracle selections and every relevant physical function obligation. Preserve reviewed exclusions and legacy physical/RVA grouping as evidence; revalidate their applicability before semantic admission. `docs/gcc-function-recovery-scoring.md:161` defines physical starts, not new semantic equality. `docs/structural-recovery-scoring.md:50` requires authenticated identity-map replay; `:165` retains unobservable facts in the scorer's documented denominator. The new ledger cannot silently edit either contract or drop hard facts. Any necessary versioned scoring integration belongs to 693/694 after the oracle population is fixed.
5. **Bounds before implementation:** retain exact original limits and charge all decoded rows/edges, strings, indexes, canonical envelopes and repeated passes. The diagnostic used at most an 8,388,545-byte shard and a 5,570,856-byte primitive offset index, not a qualified resident-memory claim. Baseline policy already consumes 4,193,523/5,000,000 work; adding a whole census pass inside that same budget without optimization will not fit. A separate compact ledger artifact needs an explicitly charged aggregate profile and preflight; splitting artifacts/passes does not grant free work or increased limits.
6. **No early seal:** complete semantic cardinality and required closure must be independently reconstructed by a separate Kotlin verifier. Missing/extra/ambiguous recovery mappings remain visible. Current exporter11 requires null semantic-state binding; final admitted 1506 schema and 679's authenticated stripped-model/loader/exporter/target/state boundary remain explicit gates. No fixture, physical census or candidate JSON can satisfy them.

## Next concrete implementation decision

Independently review this closed table together with the C/F/G/T registry and full plan. Approve or correct the three counting units, module/shared predicate, fact-summary rule, typed reference prerequisites and exclusion provenance before builder implementation. Then implement bounded source-obligation/enrichment records and their independent verifier in the custodian's dedicated ledger worktree. Preserve diagnostic false/null authority until all full-scope gates pass. Qualification must include actual retained GCC function, global and type coverage plus admitted model binding; rare adversarial fixtures are reported separately. Two real capture/replays, exact-head required CI, automatic review completion and resolved findings remain mandatory before the issue can close.

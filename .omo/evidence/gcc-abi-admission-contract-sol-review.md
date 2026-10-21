# Independent Sol semantic review: GCC ABI admission contract

Terminal verdict: **ITERATE**.

| Reviewed artifact | Exact SHA-256 |
| --- | --- |
| `.omo/plans/gcc-observable-abi-admission-contract-v1.md` | `4f0f4027d69275b706ff14775db288a20bfdf54df8f26bbdac669f7a805bea91` |
| `.omo/evidence/gcc-abi-identity-contract-source-audit.md` | `dd4a76099448f91884e1c211c6942e8e2b3e972bbb657183fc678b32dcd4424e` |
| `build/gcc-abi-policy-census/admission-contract-freeze.json` | `1005e9f44f2272f5ac69ef92904ac59b42e56cf4651c4f1bb740a5ee3f3c66cc` |

Review scope is the proposed closed counting/admission policy and permission to begin bounded diagnostic/enrichment implementation, against full #692 and inherited #46 acceptance. This is not a request for completed implementation, real module authority, model admission, a seal or qualification. Only this review file was written. Source was read from exact `fae856cec8f7dc8df6fe6bfd92075651966da2ca` Git objects; supplied issue/current-scope snapshots were used without remote mutations or a qualification rerun. No source, Git, Actions, authentication or model settings were changed.

## Blocking correction: define the module unit used by the shared predicate

Contract line 18 and registry T01 (`gcc-abi-identity-contract-source-audit.md:50`) define shared as required use in at least two distinct **logical modules**, but do not define what one logical module is. Stable IDs, authenticated ownership inputs and a reviewed future mapping are necessary evidence requirements; they do not close the granularity policy. The same underlying declaration/use witnesses could be assigned to source translation units, source components or one linked-image module, yielding different shared-type counts while keeping stable IDs and authenticated provenance. The ban on candidate-selected partitioning prevents one source of denominator manipulation, but does not settle this independent policy choice.

This is a missing definition, distinct from the honestly disclosed absence of the actual ownership relation. The proposal calls for approval of counting units before builder implementation (line 97), and the approved full plan requires an authoritative definition of shared/cross-module use at its first gate. Approving an undefined module unit would defer a cardinality decision past that gate.

**Required correction before approving the closed semantic counting contract:** define the oracle module granularity and its owner/use roles explicitly. A source-grounded choice is authenticated source translation-unit/build identities and roles, with a complete, independently replayed relationship from physical DWARF CUs and declaration/use witnesses to those units. Account explicitly for split/multiple CUs per TU, generated units, source-only units, headers and external owners; unresolved ownership must remain an obligation and cannot prove nonshared status. A different granularity needs an equally explicit scope justification. Pin the definition and registry correction before semantic admission or denominator construction.

Relevant existing vocabulary is `src/main/kotlin/decompengine/oracle/fulltree/FullTreeHeaderModulePlan.kt:20` at `fae856ce`, where planning module IDs are exact A13 compilation-unit IDs; `:34` distinguishes source-only units, and `:40` describes per-TU header use. This is vocabulary and a potential seam only: `:116` expressly calls the checkpoint fixture-complete and non-authoritative. Do not equate its IDs with the 111 physical DWARF CU rows or claim this source supplies the missing GCC ownership authority.

The two-module threshold itself is acceptable as a derived **shared-use predicate** once its independent module unit is closed. It must not reduce the complete required declaration/type universe. Preserve every required nonshared, anonymous, primitive, wrapper, pointee, nested, inherited and imported declaration dependency with stable identity obligations, fact classifications and independently reconciled closure totals, irrespective of the shared label. This preserves #46's complete declaration artifact and #692's full population duties. Missing module authority must block shared-population completeness; it cannot relabel unknown sharing as nonshared or remove required declarations.

## Other policy findings

No additional blocking correction was found in the following portions:

- **Counting units and relations:** independently callable emitted ABI entries and semantic process/TLS storage objects are reasonable reviewed units. Declaration, inline, alias, raw-variable and selected-oracle witnesses remain separate evidence. Complete entry/range and storage identity proofs are prerequisites. Distinct DIEs, equal starts/extents, ambiguity components and SCCs cannot supply semantic cardinality. Cardinality-changing alternatives correctly retain bounds and block completion.
- **Typed rules:** C01–C04 and F/G/T prerequisites prohibit unknown rule IDs or absent evidence from authorizing merges or exclusions. Specification, abstract origin, type, import, object-pointer and call-origin relations require their own target/ownership semantics. The 11,233 raw cycle flags are explicitly not malformed-chain counts. Recomputing the relevant typed relation is required; valid recursive pointer graphs remain possible.
- **Truth versus role:** candidate/witness/irrelevant/coverage-unresolved roles are not additional truth classifications. Automatic-local exclusion concerns a raw witness and cannot exclude a semantic object with other relevant witnesses. The contract's entity summary at line 90 is deterministic and conservatively preserves unresolved identity/facts before unobservable/observable summaries; positive whole-entity exclusion must be separately proved. Partly observable fact totals remain available, so summary precedence does not silently remove scoreable facts.
- **Full type closure:** T02–T04 require nominal identity authority and complete child/member/base/enumerator/subrange/import obligations. ABI layout equivalence, successful projection, candidate source anchors and names cannot stand in for these proofs. No all-unresolved completion shortcut is authorized.
- **Historical compatibility:** the proposal correctly treats physical/RVA grouping as boundary evidence rather than semantic equality. Exact `docs/gcc-function-recovery-scoring.md:155–175` defines starts, physical records and reviewed compiler-generated exclusions. Exact `docs/structural-recovery-scoring.md:50–64` requires independent global/type mapping and `:165–184` retains all oracle facts, including unobservable facts, in its documented denominator. Contract line 91 preserves those contracts and defers any necessary versioned scorer integration to #693/#694 after population freeze.

## Startability and actual capability gaps

Bounded source-obligation and enrichment diagnostics can start without choosing a shared denominator or inventing authority. The observed 37-tag/9-reference tables give a finite coverage vocabulary. Keep physical coverage decisions, typed edges, candidate roles and unresolved obligations distinct, and keep semantic completeness, model binding and sealing false/null. Independent verification must reconstruct decisions rather than call the producer to bless its own summaries. The module-policy correction above is needed before the proposed semantic admission/counting contract is approved.

The disclosed source limitations are real. At exact `fae856ce`, `BoundedDwarfInterfaceFacts.kt:652–659` skips subprograms without `functionStart`; its physical row construction at `:626–644` does not retain scalar attribute payloads. `FullTreeSourceEntityIdentity.kt:478–484` requires semantic-resolution IDs to remain null. `BoundedDwarfObservationInventory.kt:495–519` retains null required member cardinality and false completeness. These support bounded authenticated enrichment/rescans and named capability blockers, not promotion of existing physical counts or ABI_LAYOUT projections into semantic populations.

Real stripped-model/exporter/state admission and independent identity-map replay remain separate gates. The contract accurately preserves exporter11's null semantic-state limitation and #1506/#679 dependencies. A candidate partition cannot supply the oracle module map. No new authority follows from the historical artifacts, this policy review or authenticated candidate JSON.

Resource limits are also not yet qualification evidence. The explicit 4,193,523/5,000,000 baseline leaves insufficient room for an unoptimized additional full census pass. The required preflight, charged decoded rows/edges/indexes/passes and aggregate bounded profile must precede full-scale implementation claims; a separate artifact does not grant free work. No expensive qualification rerun was needed to decide this policy issue.

Re-review is limited to closing the module-unit definition and preserving the complete required-type population while doing so; no implementation or actual ownership-map production is required for that policy correction.

Terminal verdict: **ITERATE** — contract SHA-256 `4f0f4027d69275b706ff14775db288a20bfdf54df8f26bbdac669f7a805bea91`, registry SHA-256 `dd4a76099448f91884e1c211c6942e8e2b3e972bbb657183fc678b32dcd4424e`, freeze SHA-256 `1005e9f44f2272f5ac69ef92904ac59b42e56cf4651c4f1bb740a5ee3f3c66cc`.

## Corrected contract re-review — final verdict OKAY

The initial ITERATE finding above applies to the preserved original proposal. This appended review supersedes that verdict for the corrected proposal only.

| Re-reviewed artifact | Exact SHA-256 |
| --- | --- |
| `.omo/plans/gcc-observable-abi-admission-contract-v1.md` | `a1bb057e138aa52a486f6df5d9301d32f8421519efd4dd7eaf49bf999416a692` |
| `.omo/evidence/gcc-abi-identity-contract-source-audit.md` (unchanged registry) | `dd4a76099448f91884e1c211c6942e8e2b3e972bbb657183fc678b32dcd4424e` |
| `build/gcc-abi-policy-census/admission-contract-freeze.json` | `064f7b6e8894e37c75501e40c319e42272abcd00622c616b8154fd2b46e9926d` |

I checked the exact correction against `build/gcc-abi-policy-census/admission-contract-initial.md`, whose bytes still hash to the originally reviewed `4f0f4027d69275b706ff14775db288a20bfdf54df8f26bbdac669f7a805bea91`. The preserved initial freeze still hashes to `1005e9f44f2272f5ac69ef92904ac59b42e56cf4651c4f1bb740a5ee3f3c66cc`. All six corrected-freeze pins match their recorded byte lengths and hashes. This was a short document/pin verification, not a source replay or production qualification.

**The sole prior blocker is resolved.** Corrected contract lines 18–26 define one owner as one authenticated compilation-bearing source translation-unit/build identity for the pinned linked target. The stable inventory binding includes source, build root, role, target, effective compile variant/command and linked object provenance. It normatively constrains T01's former “logical module” wording, so the builder cannot select a convenient grouping. Distinct build variants require independent proof rather than arbitrary labels.

The correction also closes the relationship to physical evidence: multiple physical CUs from one TU do not create multiple owners; LTO ownership requires complete origin/build evidence; generated units need generator/output/build provenance; source-only records do not become owners merely by existing; headers have nominal identity plus per-compiling-TU uses; and unknown external use cannot invent a second owner. Ownership ambiguities capable of changing shared membership block closure. All required nonshared declaration dependencies remain separately retained and reconciled. Thus the two-owner sharing predicate does not remove the complete required declaration/type universe or weaken #46/#692 scope.

The cited `FullTreeHeaderModulePlan.kt` remains vocabulary only, with its fixture/non-authoritative limitation explicit. The actual complete GCC ownership relation is still unestablished and must be independently replayed and frozen before recovered mappings. No candidate, output partition or observed score may define or change it. These are retained capability gates, not unresolved policy granularity.

Approval permits the planned bounded source-obligation/enrichment diagnostics and independent verifier implementation to begin under the corrected policy. It does not establish semantic entity totals, complete module/type/member authority, authenticated stripped-model binding, a seal, score, qualified resource use or issue completion. All earlier full-scope evidence, independent reconciliation, limits, capture/replay, CI and review gates remain required.

Final terminal verdict: **OKAY** — corrected contract SHA-256 `a1bb057e138aa52a486f6df5d9301d32f8421519efd4dd7eaf49bf999416a692`, registry SHA-256 `dd4a76099448f91884e1c211c6942e8e2b3e972bbb657183fc678b32dcd4424e`, corrected freeze SHA-256 `064f7b6e8894e37c75501e40c319e42272abcd00622c616b8154fd2b46e9926d`.

# Independent Sol review: GCC ABI population ledger plan

Verdict: **OKAY**

Reviewed plan: `.omo/plans/gcc-observable-abi-population-ledger.md`

Exact SHA-256: `7a246d9737e3049cc28a5c0635b36ec30ef04ddac4d9a7a6816be1d9689e24f2`

This is approval of the full #692 plan's scope, sequencing and acceptance gates. It is not approval of an implemented denominator, a recovered model, production authority, or issue closure. Review was read-only except for this report. I did not change source, Git state, issues, Actions, authentication or model settings, and did not run implementation tests. No network access was needed: the supplied issue/milestone snapshots and exact Git objects were sufficient. Qualification artifact numbers and counts remain attributed supplied evidence, not a new artifact audit.

## Scope and executability

The plan covers both acceptance criteria in `build/gcc-abi-ledger-planning/issue692.json` and their full inherited #46 scope. There is no narrowing to function regression compatibility, raw variables, surviving symbols, or an easier storage-binding table. Functions, semantic global storage and shared types each require independently reconstructed finite populations; reviewed admission, exclusions and aliases; fact-level classifications; authenticated rich/stripped identities; actual stripped recovered-model binding; and sealing before #693/#694 scoring (plan lines 9–17, 43–57, 63–80).

The next deliverable is startable without pretending the hard capabilities already exist: package 1 at line 63 produces the closed policy/schema proposal, bounded actual tag/reference and declaration/alias inventory, acceptance-to-rule matrix, semantic review and precise capability blockers. It explicitly requires shared/cross-module use and alias units to be authoritative before implementation. That is a substantive decision gate, not permission to silently choose an easier population. Packages 2–6 then identify deliverables and failure gates for normalization, required-type closure, model admission, independent reconciliation and retained-driver qualification. Planning approval does not require those implementations to exist now.

## Source checks supporting the plan

All source references below were read with `git show` at the exact named object, rather than from the stale working tree.

| Checked source | What it establishes for this review |
| --- | --- |
| `fae856ce:src/main/kotlin/decompengine/oracle/fulltree/BoundedDwarfObservationInventory.kt:299`, `:359`, `:386`, `:495` | Raw and inventory streams exist; roots cover captured function returns/parameter candidates and variables; reference derivation visits captured type nodes/children. Member completeness is affirmatively absent: required cardinality is null and complete is false. Plan lines 28, 53 and 65 correctly require new physical-child/origin and relevance proof rather than promoting these summaries. |
| `fae856ce:src/main/kotlin/decompengine/oracle/gcc/GccDriverDwarfGlobalProjection.kt:94`, `:124`, `:136`, `:143` | Every captured variable/symbol receives a source row; bindings report raw-candidate and extent conflicts, with name/type joins false. This cannot establish semantic storage identity. The plan makes that limitation explicit and adds the necessary source coverage and alias rules. |
| `fae856ce:src/main/kotlin/decompengine/oracle/gcc/GccDriverDwarfInterfaceEvidence.kt:496`, `:505`, `:516`, `:542` | Existing mapping selects executable raw candidates by RVA and reports projected ABI observability; it does not prove the complete source-callable partition. Plan line 47 separately requires every relevant physical subprogram and all 12,844 selections. |
| `fae856ce:src/main/kotlin/decompengine/oracle/structural/DwarfSysvAmd64InterfaceProjection.kt:130`, `:178`, `:248`, `:269` | ABI projection is explicitly profile-limited and preserves unknown cases. It cannot supply nominal shared-type identity or required population closure. The plan keeps these separate and does not turn successful ABI projection into a denominator. |
| `05b073fc:src/main/kotlin/decompengine/project/ProgramModel.kt:15`, `:27`, `:36`, `:43`, `:63`, `:222` | Functions/globals/types and IDs are present; schema 2 extraction remains recovery-unassessed. The plan can bind and reconcile all model domains while retaining missing/extra/ambiguous mappings without treating extraction labels as truth. |
| `05b073fc:src/main/kotlin/decompengine/oracle/gcc/GccBundledFullExportCapture.kt:149`, `:225`, `:407` | An authenticated full capture/assembly seam exists, but its present validator requires exporter 11/schema 2 and null semantic-state binding (`:421–440`). Plan lines 33–35 and 66 correctly make current-version capture/resume validation and semantic-state evidence a gate, rather than asserting the concurrent exporter 12 work is already admitted. |
| `05b073fc:src/main/kotlin/decompengine/oracle/structural/StructuralProductionReplayContract.kt:144` | An independent trusted anchor contains profile, twin, binary, target/oracle, normalization and boundary identities. This is a usable contract seam, not proof that the actual GCC production admission has happened. The plan explicitly gates the narrowly needed #679 capability. |
| `fae856ce:src/main/kotlin/decompengine/oracle/fulltree/BoundedDwarfObservationInventory.kt:37`, `oracle/fulltree/BoundedDwarfCanonicalShards.kt:15`, `oracle/gcc/GccDriverDwarfGlobalProjection.kt:21` | The stated default byte/node/work/shard limits agree with source. Inventory constructor work maxima and projection depth maxima are more permissive than defaults, making the plan's requirement to pin exact defaults material. A separate ledger artifact is not permission to evade combined processing bounds. |

The supplied #38/#44 snapshots support their stated historical closure boundaries. In particular, #44's dated export/resume evidence does not certify the current exporter, semantic state or stripped admission. The plan preserves that distinction. Open dependencies do not falsely become complete by association; genuinely missing capabilities must be handled in their owning issues before the gates that consume them.

## Critical gates preserved

- Physical DIE/reference and raw variable totals are inputs to a coverage proof, never entity denominators. Complete physical-to-semantic ownership, tag obligations, declaration/origin resolution and relevant deferred roots are required.
- Aggregate direct/inherited/nested/member coverage and required-type use closure must be positively reconstructed. Unsupported imports, missing relevant targets and cardinality holes block sealing; classifying every row unresolved cannot pass.
- Finite ambiguity may retain honest unknown facts, but ambiguity capable of changing entity totals leaves completion false unless a reviewed stable unit is justified. Nonzero observable populations for all three domains must have actual retained GCC support.
- The oracle population is committed before recovered-model mappings or scores can influence it. Actual stripped recovery runs through bundled Java Ghidra and isolated workers; rich evidence cannot manufacture candidate truth. Missing, extra and ambiguous recovered entries survive reconciliation.
- A separate Kotlin verifier reconstructs coverage, partitions, alias ownership, root/edge closure and totals from authenticated streams, rather than invoking the producer to bless its summaries. Seal/profile/model mismatches and downstream denominator edits must be rejected.
- Existing limits remain unchanged, with explicit aggregate preflight, bounded indexes/passes and failure on overflow. Two real captures/replays, retained full-bundle controls, independent audit, exact-head CI and resolved reviews precede completion.

No blocking source contradiction or unstartable first package was found. Semantic policy approval, type closure authority, current exporter/state admission, production replay and bounded full-scale execution remain deliberately unproved work with explicit stop gates; this review does not waive them.

Terminal verdict: **OKAY** — exact plan SHA-256 `7a246d9737e3049cc28a5c0635b36ec30ef04ddac4d9a7a6816be1d9689e24f2`.

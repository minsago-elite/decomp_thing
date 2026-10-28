# Independent Sol review: x86-64 PLT metadata, generation002

**Verdict: CLEAR for the exact held metadata-envelope correction and test main-guard relocation.** No blocking finding within this two-file delta. This grants no operational pin, native qualification, input-selection authority or qualifier execution release.

## Exact reviewed pins

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Input | SHA256 |
|---|---|
| `build/monitor-x86-plt-metadata-extension/generation-002/freeze.json` | `cb2bf9a7ecc34b1d2cc5c97d7621791269b969177169be15be06126b90e6da85` |
| `source/toolchain-001/monitor_inputs.py` | `82ce234cc994c25ca2b1eb77875172a6837e2baca15c945d4766b1e96dd7ab28` |
| Final `source/tests/test_link_inputs.py` | `cc19b7fc11ce66264e1a02d0a8c6d3036330594eae664f8c9ed898ed445533aa` |
| Preserved001 freeze | `42631ef4abc32cee6f707d2eb75ee7f32458593de2b8b81017317528f97c9cf8` |
| Preserved001 handoff | `9282a02f22a26f84b1c296899f4e5f22c88bb74a0d21a8be58c95d0cdf845f1d` |
| Unchanged underlying `link_inputs.py` | `a1fb0950e2500747a5f01c6319d45a522323ecbcc33b535e7ef262241f338f1e` |
| Retained primary investigation `build/monitor-x86-plt-metadata-investigation/report.md` | `862d9ec485413c93f17a750b097d7285da83c900f95a788d608786e95bf82bc3` |

Both freezes and every listed001/002 artifact hash were independently checked, together with current final sources, unchanged resolver and the exact known-libc hash. Source prefixes above are `oracle/acp/callable-evaluator-v3/`. No tests were rerun; review inspected source, controls and retained results. No source/test edit, compiler/loader/qualifier, proc, native tool, pin/profile, model, Git or remote operation occurred. Only this additive review is written.

## Required checks

| Property | Source/control result |
|---|---|
| Exactly three tags | `monitor_inputs.py:122–124` admits only `0x70000000`, `0x70000001`, `0x70000003`; no processor-range admission. |
| Unknowns/duplicates | Existing unknown-tag/singleton guards at133/136 precede interpretation. Controls cover every missing/duplicate member, `0x70000002`, `0x70000004` and unrelated `0x70001234`. |
| Optional complete group | Lines139–144 keep absent metadata valid and require the complete trio if present. Source explicitly describes completeness as a local supported-profile restriction, not universal ABI law. |
| Positive/power-of-two | Lines145–148 reject zero address/size/entry and non-power-of-two entry. No unjustified universal entry>=16 threshold was introduced. |
| Extent/alignment/wrap | Same predicate enforces size>=entry, size divisibility, address alignment and checked ELF64 end before mapping. Python arithmetic cannot wrap an invalid extent into admission. |
| Executable/file-backed | Lines149–152 reuse the exactly-one-full-range mapping predicate, then require PF_X on that same containing LOAD. Existing file-span and filesz<=memsz checks remain. Controls cover out-of-file, crossing-end, BSS-only, non-executable and multiple containing LOADs. |
| Closed scope/bounds | Diff changes only retained LOAD flags, exact allow-set members and finite envelope checks. Image/header/dynamic/string/graph/cache/input limits, result/status/schema, SONAME/NEEDED fields, strict selection flags and search/audit/filter refusals remain unchanged. |

The retained primary investigation cites merged psABI MR50 for PLT address/size/entry semantics and MR52 for power-of-two entry size. It separates local completeness/executable/file-backed policy from ABI requirements, acknowledges possible loader rewriting, and does not infer installed-loader behavior or instruction/relocation correctness. The implementation matches that limited contract; no dependency inference, RPATH/RUNPATH acceptance or authority upgrade appears.

## Retained verification and main guard

Generation002 results show34 pure tests, zero failures/errors/skips and zero denied audit attempts:31 prior methods plus three new methods with negative subcases. The old-parser control rejects the valid new synthetic group; current metadata parsing accepts it with unchanged graph result.

Generation002 moves only the existing `unittest.main` guard to the last AST node. Independently inspected diff and AST equivalence after removing the guard confirm no other test semantics changed. Retained guarded-main/import collection reports the same34 IDs, including all new methods; the001 direct-execution omission is fixed. Production parser bytes are unchanged from001.

Known libc `/usr/lib64/libc.so.6`,2,359,568 bytes, SHA `5b2c27f2c3fa8ed6090420fe8e3ac3d3eb5a5880ea00d2bbfdcab78937f96964`, is accepted by the new **ELF metadata function** in retained results. This removes the exact unsupported-tag refusal only; it does not prove runtime-graph/native success.

## Separate existing readiness blocker

Known-libc metadata includes `interpreter=/lib64/ld-linux-x86-64.so.2`. The unchanged `monitor_inputs.graph` rejects any non-root dependency with a non-null interpreter (`runtime dependency must not be another executable interpreter`). Therefore a real monitor→libc closure still refuses this exact libc after metadata correction. This predates the reviewed delta and requires a separate narrowly justified primary-source policy review and controls. It does not justify broadening the current correction or claiming graph success.

Absent fixed environment-pin/profile binding, authenticated actual compiler/header/link/loader selection evidence, root-authorized public primitive qualification, full24 native positives/mutants and hosted/final-seal gates remain separate. Preserve the compiled pair and dependency-empty provisioning-only record. Do not bypass the residual guard, fabricate dependencies, substitute libc/binaries or promote metadata acceptance into production authority.

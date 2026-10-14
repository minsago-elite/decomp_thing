# Provider P1 observer inventory checker source review

**Terminal: CLEAR_SCOPED.** No blocking finding in the two-file checker correction. This approves the explicit observer inventory parity correction; it does not qualify full production dependency closure or a new hosted/native run.

## Exact reviewed bindings

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `build/provider-86a-checker-correction/freeze.json` | 2662 | `fe0c7d1788bffca4f80ace1928ac76e09efebef82c076556c2b244de29f1c3e7` |
| `scripts/verify-acp-provider-dns.py` | 17291 | `ab6ed5c5086c8d96d5e33eb771b9b3726e2b0be9ca77706d5f5a95c914624b36` |
| `src/test/provider-dns/checker/test_verify_acp_provider_dns.py` | 17109 | `84f150b34068bcd134ef9928dec76fc33461490551d28792dc77e23df64680ca` |
| Retained pure test log | 316 | `9a6b9512b4faa54c63177d9959e9173d7aafc690e938b2c0d640b514d7679b2d` |
| Actual 86a inventory receipt | 7305 | `b3d5cfb8b37cd5c30089ad1c230bc27db7ffd7a8ec3be1506d8e53dfb0b05298` |

All 12 freeze entries were independently checked for exact size and SHA256, including both current source paths, their frozen copies, before files, deltas, receipt and evidence. Producer source inspected at `src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt` is 56,672 bytes, SHA256 `c7ed189813be1a42b88a554fddb20b67aff19550659e6b41e04587b8c2d9cc8b`. Its inert boundary test is 3,346 bytes, SHA256 `61e087fb73778d28cb205bf2f39705b897395dcd2b2a53fffb09d387be142bf1`.

## Source conclusions

1. **Exact selector parity.** Checker lines 28–29 enumerate only `NativeObserverBudget`, `NativeObserverBudgetOwner`, `NativeVisibilityAccumulator`, and `NativeObserverFailure`. Lines 100–102 require `.class`, admitting each exact root or its `$`-prefixed generated nested names. These are the same roots and predicate as native producer lines 737–740. The checker applies the added observer selection only to compiled **test** output (113–114), matching producer selection within the `AcpProviderNativeDns` test source root (750–758). Existing native/DNS/namespace prefixes are unchanged. This does not select all test classes or similarly named observer diagnostic tests.

2. **Mandatory roots remain independent of the supplied archive.** Checker lines 120–121 require every root `.class` in the independently constructed compiled inventory, mirroring producer lines 741–745 and its call at 760. Removing a root from both archive and compilation cannot redefine a smaller acceptable inventory. A nested substitute cannot satisfy root presence. Generated nested names are selected from actual compiled output; an arbitrary extra nested archive entry has no corresponding expected entry and fails.

3. **Exact source-bound denials remain.** `verify_control_closure` lines 133–145 reconstructs expected entries from compiled output before checking the retained archive. It requires equal entry sets, rejects duplicates, and compares every entry's bytes with current compilation. Therefore recomputing a receipt digest does not legitimize missing/extra/substituted bytecode. The generated worker commitment, separately resolved trusted stdlib equality (148–151), ordered closure digest (152–154), and per-case receipt digest equality (245–246) remain intact. No count, capability, cleanup, source/hash or XML acceptance condition was relaxed by this delta.

4. **Bounds are unchanged.** The scanner admits at most 8,192 class filenames per source directory using an 8,193-item sentinel; each selected source set is capped at 128 entries, each read at 1 MiB, and final compiled entries at 256 / 16 MiB (111–125). Archive input is capped at 16 MiB, entries at 1 MiB, and total declared expansion at 16 MiB before entry reads (134–145). This review does not expand those existing bounds or certify every other parser/resource path.

## Retained controls and actual 86a capsules

The retained receipt/log binds **28 passing inert Python tests**, four more test methods than the before file; I inspected them without rerunning tests. Added controls at test lines 119–167 cover: root/nested inventory acceptance; omission and byte tamper of each root and the generated nested entry even after receipt rehash; removal from both compilation and archive for each mandatory root; compiled unrelated/lookalike exclusion; and uncompiled nested archive extras. Existing tests retain missing/extra/duplicate entries, stale compilation, substituted bytes/stdlib/worker commitment, each case's closure, ordered digest, bounds, source/run/XML and cleanup denials. The logged duplicate-ZIP warning belongs to the intentional duplicate-entry refusal fixture.

Independently read the existing `build/provider-86a-hosted-diagnosis/required-contract.zip` in place: **5,751,891 bytes**, SHA256 `2b3a492d306ed9f81679dc518fa8ff046a06284811e4e5af09f5eee9a9d0ce12`. Reads were bounded to 64 MiB outer input / 8,192 outer entries, 16 MiB per inner archive and expansion, 256 inner entries / 1 MiB per entry. No extraction, new JAR, bulk class copy, checker execution or JVM launch occurred.

Both recorded `cancel-cb85f2e5-bbd1-4f52-a127-37ca8e4b938e/input/control.jar` and `deadline-cb85f2e5-bbd1-4f52-a127-37ca8e4b938e/input/control.jar` members are **123,394 bytes**, SHA256 `63b60af97b1d93de234a831a919914163780110e581ebb46f7c4f593e8867e9c`. Each has exactly **33 unique entries**, matching the inventory receipt. Independently applying the four-root/nesting predicate yields exactly five observer entries: all four root classes and `NativeObserverBudget$1.class`. Their five byte lengths and SHA256s match the pinned receipt for both capsules. This confirms the observed 86a inventory requiring the checker correction; it does not prove equality with a newly compiled current source tree.

## Scope and remaining gate

The frozen receipt explicitly sets `productionClosureQualified=false`; the checker returns `realProviderQualified=false` (256). The documented prior 15-edge production frontier remains unqualified. Inventory parity and observed retained capsule contents are established here; full runtime/production reachability, native behavior and fresh hosted qualification remain separate gates. I performed no source edits, tests, JVM/compiler/native/provider/auth/model runs, Git or remote operations. Only this additive review report was written.

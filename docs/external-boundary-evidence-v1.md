# A-series external boundary evidence slice v1 (#122)

This is one small, non-authoritative evidence slice for the external runtime,
system-library, and generated-input boundary. It joins the checked LLVM 22.1.6
source lock, build record, full-tree inventory, and planning inventory. It does
not close issue #122 or turn any of these files into a production receipt.

## Contract

The slice has the fixed disposition `evidence-only-unresolved`:

| Field | Value |
| --- | --- |
| `oracle` | `clang-driver-22.1.6` |
| `sourceRevision` | `fc4aad7b5db3fff421df9a9637605b9ca5667881` |
| `sourceLockSha256` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `buildRecordSha256` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `container` | `decomp-llvm-oracle-toolchain:22.1.6`, `linux/amd64`, `sha256:73285d9a2dad159a7171fe4bbcac7d97d285402955d8c6fb8b44b101cf2df550` |
| `releaseEligible` | `false` |
| `oracleAuthority` | `false` |

The build record declares these exact external tool identities for its recorded
CMake/Ninja build:

| Role | Path | Recorded version |
| --- | --- | --- |
| build generator | `/usr/bin/ninja` | `1.11.1` |
| build system | `/usr/bin/cmake` | `3.28.3` |
| compiler | `/usr/lib/llvm-22/bin/clang` | Ubuntu Clang `22.1.8` |
| linker | `/usr/lib/llvm-22/bin/lld` | Ubuntu LLD `22.1.8` |
| stripper | `/usr/lib/llvm-22/bin/llvm-objcopy` | Ubuntu LLVM `22.1.8` |

These are recorded identities, not a claim that the source version and every
runtime dependency have the same version. In particular, the record's Clang and
LLD versions are `22.1.8` while the oracle source identity is `22.1.6`.

The generated-input join is equally narrow and reproducible:

| Fact | Checked value |
| --- | --- |
| compilation-unit population | 2,150 total; 2,149 handwritten; 1 generated; 57 shards |
| generated unit ID | `cu-3da39408d5c2027c7eb363fc9bf9d3f3` |
| generated source path | `generated/tools/clang/tools/driver/clang-driver.cpp` |
| generated shard | `generated-tools-clang` |
| inventory/planning agreement | both records bind the same ID, path, shard, and `sourceKind: generated` |
| generated-table interpretation | none; the checked `TableGen inputs: 1,666` observation is not a generated-table provenance record |

The `generated/` path and shard family are also declared by the checked
full-tree scope. The inventory and planning files are therefore useful identity
evidence for this one generated source module, but they do not authenticate its
generator inputs or actions.

## Boundary dispositions

| Boundary | Disposition | Evidence or unresolved condition |
| --- | --- | --- |
| source and recorded build tool identities | declared for this slice | The source lock, build record, container identity, and five recorded tool identities are joined above. |
| external runtime | unresolved | The container digest identifies the recorded build environment; it does not describe a complete loader, runtime, or candidate-execution closure. |
| system libraries and external symbols | unresolved | No complete dynamic-import/provider ABI ledger, `DT_NEEDED` policy, sysroot identity, link map, or zero-unexplained-reference result is present in this slice. |
| generated tables and generator actions | unresolved | The one generated module is joined, but generated-file provenance, authenticated generator actions, and live CMake/Ninja edge evidence remain absent. |
| Ghidra execution | unchanged and outside this slice | Ghidra remains the bundled Java-API worker boundary. This document adds no `GHIDRA_HOME` or `analyzeHeadless` path and cannot authorize analysis. |
| ACP and oracle authority | unchanged and outside this slice | ACP remains a bounded candidate producer/operator. It cannot author or promote source locks, generated inputs, runtime facts, oracle truth, or release decisions. |

An unresolved disposition is retained as an unresolved state. It is not replaced
by a wildcard provider, host discovery, fallback symbol resolution, or an empty
generated-table claim.

## Unavailable production gates

This worktree does not provide fresh evidence for the following gates, so this
slice leaves them unavailable:

- a clean contained full-tree compile and link with complete link tracing;
- a complete external-symbol and system-library ledger with provider/ABI
  substitution checks;
- authenticated generator inputs and actions, generated-table completeness,
  and live CMake/Ninja edge replay; and
- an independently qualified production runtime execution and release decision.

The existing source/header planning contract records the generated snapshot as
integrity-verified but unreceipted, with generated-file provenance and
Ninja-generator provenance still blocking. The existing trust-boundary contract
also keeps ACP candidate evidence separate from Kotlin/JVM oracle authority.
Those existing contracts, plus the bundled-Ghidra boundary, are references for
the dispositions above; none is re-certified by this document.

## Reproducible inputs

The facts above come from these checked files at the revision where this slice
was prepared:

- [`source-lock.json`](../oracle/llvm/22.1.6/source-lock.json), SHA-256
  `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306`;
- [`build-record.json`](../oracle/llvm/22.1.6/build-record.json), SHA-256
  `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005`;
- [`full-tree-scope.json`](../oracle/llvm/22.1.6/full-tree-scope.json), SHA-256
  `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57`;
- [`full-tree-inventory.json`](../oracle/llvm/22.1.6/full-tree-inventory.json),
  SHA-256 `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306`;
- [`full-tree-planning-inventory.json`](../oracle/llvm/22.1.6/full-tree-planning-inventory.json),
  SHA-256 `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`;
- [`full-tree-source-header-dependency-planning.md`](full-tree-source-header-dependency-planning.md),
  for the existing unreceipted generated-snapshot disposition; and
- [`oracle-acp-trust-boundary.md`](oracle-acp-trust-boundary.md) and
  [`bundled-ghidra.md`](bundled-ghidra.md), for the existing authority and
  bundled-worker boundaries.

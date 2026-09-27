# GCC closed-toolchain admission evidence

This is the small #725 evidence slice recorded from repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`. It defines the admission boundary
without claiming that the reconstructed driver or engines have passed it.

## Bound inputs

The checked GCC benchmark is version `16.2.0`, target `x86_64-linux-gnu`, and
source revision `78d4ac73dd391005b895a6148cd9831e28e1208b`. These records are
bound by the following SHA-256 values:

| input | path | SHA-256 |
| --- | --- | --- |
| source identity | `oracle/gcc/16.2.0/source-lock.json` | `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc` |
| historical build | `oracle/gcc/16.2.0/build-record.json` | `f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637` |
| reproduced toolchain | `oracle/gcc/16.2.0/toolchain-reproduction.json` | `5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de` |
| engine profile | `oracle/gcc/16.2.0/compiler-engines.json` | `e0ca60b7e856e9330e45fd58e61828313e8dd824413ee0df7ef76ee5d2b47bdc` |

The engine profile contains exactly `cc1` and `lto1`. It binds the planning
exporter (`decompengine-ghidra-program-model`, version 10, recovery mode
`planning`), bundled Ghidra `12.1.3`, a 1,800-second export limit, and a
16-GiB export resident-memory limit. The profile names
`cc1-reconstruction.zip` and `lto1-reconstruction.zip`, but those files are not
checked into this repository. The checked engine files are build records and
oracle manifests; they are reference evidence, not reconstructed candidates.

## Closed invocation contract

An admitted candidate must use only executable paths, argument vectors, and
environment values bound by authenticated records. The checked build record
currently provides the exact `/usr/bin/make -j4 all-gcc`, `install-gcc`,
staging, and `x86_64-linux-gnu-strip --strip-all` invocations, plus SHA-256 and
version output for its recorded compiler, linker, and stripper. Any missing
role, path/hash drift, PATH lookup, or unrecorded invocation remains
unresolved.

Analysis runtime admission stays inside the bundled Ghidra Kotlin/JVM boundary
and its retained, authenticated runtime described in
[`gcc-compiler-engine-containment.md`](gcc-compiler-engine-containment.md) and
[`gcc-bundled-runtime-contract-v2.md`](gcc-bundled-runtime-contract-v2.md).
An external `GHIDRA_HOME` or external `analyzeHeadless` installation cannot
create candidate or oracle authority. Oracle verification and release
eligibility remain Kotlin/JVM-owned; candidate output cannot manufacture
reference truth, provenance, or a resolved result.

## Current result and unavailable production gates

`candidateStatus` is `unresolved` and `productionVerified` is `false`.
`local-engine-byte-inventory.json` is explicitly limited to read-only bytes and
states that authenticated process execution, root-owned deployment, runtime
closure, and benchmark execution are unavailable. The containment contract
also states that it does not prove an engine ran, resumed, or produced an
artifact; prepared-operation evidence remains `complete=false` and
`releaseEligible=false`.

The following gates therefore remain open for #725:

- authenticated reconstructed driver, `cc1`, and `lto1` archives with exact
  source and executable identities;
- a complete closed dependency closure covering assembler, linker, runtime, and
  every required installed tool;
- contained engine export, fresh/resumed equivalence, clean rebuild, and
  integrated driver/engine execution evidence; and
- the downstream authenticated behavior and release qualification gates.

This record preserves those states and does not promote the existing oracle
manifests, driver reference pair, planning fixtures, or local engine byte
inventory to reconstructed-toolchain admission.

# cc1/lto1 reconstruction production gate

Evidence for issue #56 at repository revision `bf2501568f39ab52b23492dfc37839bb81895587`
(2026-09-08). This is a repository-fact record, not a reconstructed engine release.

The checked `oracle/gcc/16.2.0/compiler-engines.json` binds both `cc1` and `lto1` to
the GCC source lock, base build record, toolchain reproduction record, engine build
records/manifests, stripped/full artifact identities, the bundled Ghidra archive, and
the deterministic planner. Those inputs establish benchmark provenance only.

The production source gate is **unresolved**. A release requires an authenticated
completed model and exact ownership plan for each engine, accepted ACP-backed source
bytes for every required implementation, and retained source manifest, receipts, and
explicit unresolved inventory. The repository retains no accepted `cc1` or `lto1`
reconstruction tree or reconstruction archive.

The production buildability gate is **unresolved**. Each accepted tree must be
independently extracted and cleanly configure/build/link with its declared dependencies,
then retain source, build, validation, and toolchain evidence plus repeated archive-byte
identity. `GeneratedCArchiveBuildPolicy` and its focused fixtures enforce the local
source-bound `build_contract.json` rules, including `-Werror`, stable source inputs,
reproducible path mapping, credential/cache absence, and artifact identity; fixture
success does not qualify either engine.

The current bundled-Ghidra containment contract remains non-authoritative and
`releaseEligible=false`; it does not authorize engine START, export, scoring, or release.
ACP remains a read-only consumer of authenticated plans, and cannot create or certify
oracle truth. No production claim is made until both gates have retained evidence.

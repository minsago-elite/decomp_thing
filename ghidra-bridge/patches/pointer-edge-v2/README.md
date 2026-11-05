# Disabled pointer-edge dependency checkpoint

This directory is a **disabled dependency patch**, not a runtime overlay or an activated profile.
`src/` contains 13 explicit sources; `diffs/` contains exact-base patches against the pinned release sources.
`verify.py` verifies the base archives, checks patch roundtrips, compiles with pinned JDK 21,
`-proc:none` and an empty sourcepath, and builds two identical throwaway module pairs under the NEW remediation evidence directory.
It permits exactly the 24 entries in `class-allowlist.json`, discards compiler-emitted `CategoryCache`,
and verifies every other original entry payload is unchanged. It never installs anything.

`contract-manifest.json` records E1/E2/E3, special IDs, factory authority, bounds, the negative-only
cross-package error-recording hook, test coverage, and mandatory later gates.
`source-manifest.json`, `recipe-manifest.json`, and `jdk21-pins.json` contain exact input pins.
The immutable observation has no public constructor and carries current facts, not persistent authority.

From the repository root:

```sh
# Pick a fresh child directory for each reproduction; old implementation/reviewer outputs are rejected.
export OWNED_POINTER_EVIDENCE="$PWD/build/orchestration/exporter-v20-pointer-dependency-remediation/reproduction-001"
/usr/bin/python3.14 -B ghidra-bridge/patches/pointer-edge-v2/verify.py
/usr/bin/python3.14 -B ghidra-bridge/patches/pointer-edge-v2/run-tests.py
/usr/bin/python3.14 -B ghidra-bridge/patches/pointer-edge-v2/mutation-controls.py
/usr/bin/python3.14 -B build/orchestration/exporter-v20-pointer-dependency-remediation/preservation.py
```

Tests execute real Java-only CREATE `ProgramDB`, `PointerDB`, listing, archive and adapter operations
in bounded isolated JVMs. Test reflection installs negative faults or reads counters; it is never
positive selected-object provenance. Unknown-Data/Pointer proxies are rejection controls only.
No analyzer, native decompiler, worker, Gradle, product or inference invocation is used.

See the [handoff](../../../build/orchestration/exporter-v20-pointer-dependency-remediation/HANDOFF.md).
All production profile/bridge/loader/identity, original native RED, full `binary_01`, and #1842 gates remain.

Origin remediation removes all exception-subtype policy exemptions. Only a newly allocated,
invocation-local policy exception is receipt-clean; dependency exceptions always latch.
The existing public listing helper returns null for bounded component refusal (negative-only).
Package-private nullable settings results preserve the original boolean wrapper and bounded reads.
No new public authority/factory or runtime class is added; the exact24-class closure remains.
Compiler/test JVMs have512MiB heap/256MiB metaspace and process-group timeouts; all outputs
are restricted to the new remediation root. Source/test run snapshots retain previous evidence.

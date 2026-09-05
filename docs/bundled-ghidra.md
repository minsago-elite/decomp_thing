# Bundled, directly linked Ghidra

Ghidra is an application dependency, not a separately installed prerequisite.
The `ghidra-bridge` Java subproject compiles against the pinned Ghidra 12.1.3
release. Its worker initializes `GhidraApplicationLayout` and calls
`HeadlessAnalyzer` APIs directly. It never invokes `AnalyzeHeadless.main`, a
reflective entry point, `support/analyzeHeadless`, or a shell launcher.

## Build and distribution

```bash
./gradlew installDist
./gradlew verifyGhidraDistributionArchives
build/install/llm_bin_patch/bin/llm_bin_patch doctor --tools-only
```

The first build authenticates the official 569,445,154-byte
`ghidra_12.1.3_PUBLIC_20260817.zip` against SHA-256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`.
The archive is cached under
`$GRADLE_USER_HOME/caches/decomp-ghidra/` (normally `~/.gradle/caches/decomp-ghidra/`).
Subsequent builds recheck its size and digest. Offline builders may provision
that exact archive in the cache and use `./gradlew --offline installDist` after
the other Gradle dependencies have been cached. Runtime analysis never downloads
Ghidra or falls back to a workstation installation.

The distribution contains `libexec/ghidra/decomp-ghidra-bridge.jar` and the full
release under `libexec/ghidra/ghidra_12.1.3_PUBLIC/`, including processor specifications,
native decompiler binaries, `LICENSE`, `bom.json`, and third-party license files.
ZIP/TAR packages and Docker use this same bundle. Ghidra's own launchers remain
unmodified release contents for provenance; application analysis does not run them.
Ghidra timestamps are normalized together to avoid accidental SLEIGH recompilation
when a distribution copy would otherwise make sources newer than compiled languages.
POSIX packaging removes group/other write access (including release Windows
executables originally marked mode 0666) without changing any archive file bytes.

Installed applications resolve the bundle relative to their application JAR, not
the current directory or `GHIDRA_HOME`. Gradle `run` and tests set the internal
`decompengine.ghidra.bundle` JVM property to the staged development bundle. This is
not an external-install fallback. Missing files, unexpected tree members, changed
file digests or an incompatible version fail with a reinstall/rebuild diagnostic.
The checksum inventory detects distribution corruption; it is not a signed
provenance root or an oracle authority capability.

## Worker and evidence boundaries

The worker has its own JVM and Ghidra-only classpath, avoiding Ghidra dependency
collisions and process-global state in the coordinator or authenticated Kotlin
BOOT/LLVM workers. Direct linking does not mean loading hostile analysis into the
coordinator JVM. Reconstruction retains its existing wall-clock and descendant-RSS
monitor, termination and resumable exporter checks. A separate JVM and RSS sampling
alone are not a kernel sandbox or cgroup receipt.

Patch decompilation, reconstruction, web reconstruction, doctor and the legacy
reconstruction pipeline use the bundled API worker. The old reflective adapter and
synthetic-on-missing-export fallback are removed. Real tests statically analyze
compiler-generated fixtures; they do not execute unknown challenge binaries.
An application-owned compiled script guard reports success only after every
requested exporter returns. Ghidra may log script/import errors without throwing
from `processLocal`; the worker therefore treats a missing guard completion as a
nonzero exit, even when a stale output from an earlier run already exists.

`gcc-engine-plan` authenticates the bundled release against an explicit original
`--ghidra-archive` provenance input; `--ghidra-home` is no longer accepted. The
archive input proves bytes and is not a separate runtime installation. This
diagnostic remains non-authoritative. Existing frozen A10 contained-launch
contracts still describe their historical authenticated launcher; migrating those
contracts and proving their new contained direct-API runtime is tracked in #235.
The [versioned bundled-runtime definition](gcc-bundled-runtime-contract-v2.md)
now binds the direct-API command and ordered classpath without reinterpreting
those historical receipts. It remains non-authoritative; the live BOOT controller
rejects it pending retained runtime authentication. This does not close A10/A13.

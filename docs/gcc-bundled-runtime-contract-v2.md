# GCC bundled Ghidra definition v2

The GCC containment definition now distinguishes the historical shell-launcher
preimage (schema 1) from the bundled Java-API worker preimage (schema 2). Neither
definition is a launch capability. Both retain the existing non-authoritative
assessment scope, with `startAuthorized=false` and `releaseEligible=false`.

## Runtime and command binding

Schema 2 uses provider `gcc-compiler-engine-containment-definition-v2` and adds
the closed `bundledRuntime` object to its request. That object identifies the
application bundle root and ordered classpath entries with exact paths, sizes
and SHA-256 digests. The bridge JAR leads the classpath, followed by sorted unique
library JARs under the pinned release's `Ghidra/**/lib` directories. Wildcards,
classpath separators inside paths, relative paths and writable-output overlap
are rejected. The declaration allows at most 512 entries, 128 MiB per entry,
2 GiB aggregate JAR bytes and 32-component paths.

The artifact population replaces `ghidra-analyze-headless` and
`exporter-classfile` with `ghidra-bridge-jar`, `ghidra-export-guard` and
`exporter-source`. The original release archive, bundle inventory, Java,
independent BOOT classpath and other tool/input roles remain explicit. Bridge
identity must agree with the first classpath entry; the inventory and compiled
export guard must occupy their exact bundle-relative locations. The archive
digest must match the application's pinned release. Runtime commitments include
both these artifacts and the complete declared ordered classpath, so changing a
library identity changes the request, runtime, binding and systemd unit identity.

The complete command is recomputed rather than accepting caller-selected JVM
options, scripts or exporter arguments. The ordinary application worker and this
definition share `GhidraWorkerCommand`: fixed JVM options, explicit classpath,
`BundledGhidraWorker`, release root, and the direct-API `analyze` operation. GCC
uses the exact engine path, analysis-state directory and source exporter, with
the exporter/source digest, release digest, planning mode and fixed output path.
The classpath is a single argv element, not a shell expression.

Real bundled library paths exceed schema 1's 16 KiB argv-component ceiling.
Schema 2 therefore permits a 64 KiB component while retaining the 64 KiB total
command-character bound and existing bounded strict-JSON limits. Schema 1 keeps
its original limits. Only fresh-empty analysis state is represented by this
version of the bundled command: saved-state resume is rejected because the
current direct-API operation imports and overwrites a project. It must not be
mislabelled as authenticated resumed analysis.

## Compatibility and authority

Schema 1 retains its explicit frozen artifact population, provider, command
validation and canonical encoding. The pre-migration fixture's canonical bytes
have SHA-256
`6e9603d0674e9eab27d8a253999992e51fe9e77b639e6bdcc661eb22adc51bce`;
the regression test compares against that independently captured value.
Readers reject cross-version fields, providers, role sets and commands rather
than silently reinterpreting an old receipt. Existing BOOT/absence receipt
formats remain unchanged and remain bound to their exact definition digest.

The live BOOT-only controller explicitly rejects schema 2 before opening its
declared runtime artifacts or contacting systemd. A self-consistent classpath
declaration or bundle checksum inventory does not authenticate deployed worker
code, the original release tree, native/data dependencies, or their lifetime.
No Ghidra JAR is added to the existing authenticated BOOT or LLVM classpath.

Issue #235 remains open for deployment-derived retained runtime authentication
and actual contained analysis through export and cleanup. The existing
archive-to-installation verifier is useful diagnostic evidence but closes its
file handles; its returned paths are not retained execution authority. The full
cc1/lto1 forced-interruption/resume equivalence proof remains separately required
by #137. This versioned definition does not complete either requirement.

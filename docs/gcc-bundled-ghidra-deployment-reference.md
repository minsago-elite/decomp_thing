# Independent bundled Ghidra deployment reference

`generateGccBundledGhidraReference` produces
`gcc-bundled-ghidra-reference-v1.json` from the authenticated staged application
bundle and the actual application JAR. The sidecar is installed beside that JAR
and included in ZIP/TAR distributions. It is deliberately outside the JAR, so
generation has no self-hashing dependency cycle and does not add Ghidra to the
BOOT or LLVM classpaths.

## Committed deployment description

The closed canonical reference binds the pinned original release size/digest and
version, every bundle directory and regular file, normalized distribution modes,
file sizes/hashes, the exact ordered worker classpath, bridge/guard locations,
and the application JAR's `ExportProgramModel.java` resource. Empty files and
directories are preserved. The domain-specific provider and schema are included
in the unsigned canonical bytes hashed by `closureSha256`.

The inventory is limited to 20,000 entries, 128 MiB per file, 2 GiB of file bytes,
32 path components, 4,096 UTF-8 bytes per path and 255 bytes per component. The
reference itself is limited to 8 MiB. Files have normalized modes 0644 or 0755;
directories and the bundle root have mode 0755. The ordered classpath contains
the bridge followed by every applicable library JAR in the complete inventory,
not an independently selectable subset. Empty-file digests must identify empty
bytes, and every non-root parent must be an explicit directory entry.

The decoder validates these semantics even after a caller recomputes the outer
hash. Its maps/lists are defensive immutable snapshots. Candidate matching binds
the raw v2 classpath and bridge, guard, inventory, original archive and source
exporter identities to this independent description. It permits relocation of
matching bundled bytes; matching is not a filesystem-authentication operation.

## Retained reference reader

`GccBundledGhidraDeploymentReference.open()` locates the sidecar relative to the
loaded application JAR, never from a containment request. Installed execution
rejects reference/root override properties. Class-directory Gradle tests use the
paired `decompengine.oracle.gcc.bundledGhidraReference` and
`decompengine.oracle.gcc.bundledGhidraRoot` test-TCB properties instead.

The reader pins the sidecar through `StableControlFile` and checks its canonical
bytes and identity until close. Installed execution also retains the application
JAR and reads the exact unique exporter resource directly from that JAR, so an
earlier classpath resource cannot shadow its provenance. The class-directory
development seam retains the Gradle classloader as its explicit resource TCB.

## Remaining executable-runtime boundary

This is a retained deployment **reference**, not a retained executable bundle.
The reader does not yet authenticate all files in the candidate native/data tree
or grant an executable mount, BOOT, START, output acceptance or release authority.
The live controller still rejects v2 definitions. Existing BOOT deployment
authentication remains independently required when composing the capabilities.

The next retained runtime must prefer the root-owned bundled directory already
shipped in a trusted installed distribution. If needed, a trusted provisioner may
copy those exact bundled bytes; this is not a separate Ghidra installation or
version. No automatic privilege escalation, mounting or quota changes are added.
Native code cannot be executed from the required noexec output lease. Complete
tree/root/executable-mount authentication and the eventual contained
START/export/absence handoff remain required by #235, with normal engine
interruption/resume fidelity still required by #137.

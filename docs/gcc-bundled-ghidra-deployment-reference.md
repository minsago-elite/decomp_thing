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

## Retained executable tree

`GccBundledGhidraRetainedRuntime.open()` composes that retained reference with the
exact candidate bundle. A root-owned bundled directory already shipped inside a
trusted installed distribution is usable directly; a separately installed Ghidra
version is neither required nor accepted. An explicit trusted provisioner may
instead create a matching root-owned copy of the application's bundled bytes.

Authentication opens the absolute ancestor chain one component at a time without
following links. Every ancestor must be a root-owned real directory without
group/world write permission. The retained bundle root must have its declared
0755 mode and remain disjoint from writable output. Its descriptor mount identity
must select one executable backing mount; `noexec`, nested and shadowing mounts
are rejected.

The complete tree is traversed through directory descriptors against the
independent reference, including native executables, processor/data files, empty
files and empty directories. Missing or extra entries, symbolic links, special
files, hard-linked files, non-root ownership, different modes and different
mounts are rejected. Every regular file's exact size and SHA-256 are checked with
bounded streaming reads. The reference's entry, depth and byte limits remain in
force; no full-tree byte buffer or per-file lifetime descriptor set is required.

The capability retains the root descriptor, deployment reference, mount facts and
an immutable per-entry metadata snapshot. Verification reopens the trusted root
chain, checks its retained identity and backing mount, and recaptures exact
membership, inode/owner/mode/mount identity, sizes, mtime and ctime. Contents are
hashed during initial admission rather than rehashed at every BOOT check.

This is the existing **root-administrator trust boundary**, not protection from
a hostile root administrator or privileged mount mutation. The provisioner owns
the integrity and provenance of the root-owned runtime, including exclusion of
previous untrusted writable handles; changing ownership alone is not such a
proof. The CI provisioner creates new root-owned files while copying rather than
chowning caller-owned inodes. User-owned or group/world-writable candidate trees
do not receive this root-trusted metadata-only lifetime treatment.

## Fresh BOOT integration

The live GCC controller acquires the retained bundle before opening remaining
declared artifacts or creating the journal. Its independently authenticated
Kotlin BOOT deployment remains required. The Ghidra reference commitment and
retained runtime identity are combined with that BOOT commitment under a distinct
v2 deployment-closure domain. Schema 1 keeps its original deployment digest.
No Ghidra JAR is added to the BOOT or LLVM classpath, and this checkpoint does not
mount or execute the declared Ghidra command inside the keeper namespace.

Existing input-verification checkpoints revalidate the retained bundle before
and after BOOT attachment. Cleanup instead uses the already captured immutable
closure and retained systemd/cgroup owner: a later runtime-verification failure
must not make whole-scope cleanup unreachable. Closing inputs independently
attempts every descriptor/reference release without first requiring a valid
runtime tree.

Fresh v2 BOOT admission and terminal absence do not grant START, execute Ghidra,
accept an export, restore saved analysis state, release an output lease or make a
result release-eligible. The BOOT owner remains cleanup-only. Actual contained
START/export/absence evidence remains required by #235, with normal engine
forced-interruption/resume fidelity still required by #137.

## Explicit CI provisioning

The Kotlin CI lane runs `scripts/ci-prepare-bundled-ghidra-runtime.sh` before JVM
checks. It builds `installDist` and makes a bounded descriptor-relative copy of
`build/install/llm_bin_patch/libexec/ghidra` into the unoccupied executable path
`/opt/decomp-ci-ghidra-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}/bundle`. This uses the
application build's already bundled dependency, not an external Ghidra installer
or runtime download. It exports `DECOMP_TEST_BUNDLED_GHIDRA_ROOT` and sets
`DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME=true`, so the hosted qualification cannot
silently skip a missing required runtime.

The always-run `scripts/ci-release-bundled-ghidra-runtime.sh` independently derives
that exact run/attempt path and verifies a root-owned marker bound to its device
and inode. Before recursive removal it validates bounded membership, ownership,
types and modes and rejects mounts under the target. Legitimate interrupted-copy
0600/0700 residue is supported; an unexpected, replaced or unmarked target is
refused rather than inferred to be disposable.

Privilege use is confined to these explicit CI provisioning/cleanup scripts.
The production application does not run sudo, provision copies, create mounts,
change quotas or make the mandatory noexec output lease executable. Passing
structural tests or a non-authoritative packaged Ghidra probe is not evidence
that the required hosted BOOT lifecycle or later contained analysis has passed.

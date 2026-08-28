# GCC 16.2.0 source lock

This directory pins the authoritative input for the source-aligned GCC driver
oracle. The 107 MB source archive is deliberately not stored in Git. Its
versioned format is documented by `../source-lock.schema.json`; the standard
library verifier enforces the closed schema and additional cross-field rules.
The lock records enough independent evidence to reject an altered download, a
different Git revision, an unexpected signer, or missing redistribution
notices.

This is a benchmark profile for one substantial C program. It does not make
GCC a special case in the reconstruction engine, and future program profiles
can supply the same kinds of artifact, structural, and behavior evidence.

## Locked provenance

- Release: GCC 16.2.0, announced by the GCC project on 2026-08-07.
- Canonical archive: `gcc-16.2.0.tar.xz` from `ftp.gnu.org`, exactly
  107,200,820 bytes with SHA-256
  `e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e`.
- Annotated Git tag: `releases/gcc-16.2.0`, tag object
  `1831ac03fd08e3400c16b29f21762e6b326a618d`, resolving to commit
  `78d4ac73dd391005b895a6148cd9831e28e1208b`. The retained tag payload and
  signature reproduce that Git object ID and verify with the release key.
- Release signer: GCC's published signing fingerprint
  `7F74F97C103468EE5D750B583AB00996FC26A641`, a signing subkey of primary
  key `13975A70E63C361C73AE69EF6EEB81F8981C74C7`.

The public key was retrieved from the Ubuntu OpenPGP keyserver. Trust is
anchored to the full fingerprint published by the GCC project in
`https://gcc.gnu.org/mirrors.html`, not to the keyserver. The exact vendored
key bytes and both fingerprints are locked.

The archive contains software under file-specific GNU licenses. The lock
retains exact hashes for its top-level GPLv2, GPLv3, LGPLv3, and GCC Runtime
Library Exception 3.1 texts. Individual source notices remain authoritative;
the runtime exception applies only where those notices invoke it.

## Verification

Python 3.10 or newer and GnuPG are required. The offline metadata gate checks
the closed schema, all cross-field relationships, annotated-tag object ID and
signature, the vendored key hash, and the primary/subkey fingerprints:

```bash
python3 scripts/verify-gcc-oracle-source.py --metadata-only
```

Fetch both immutable release files into a cache and run the complete gate:

```bash
python3 scripts/fetch-gcc-oracle-source.py /path/to/gcc-oracle-cache
```

The fetcher never replaces an existing mismatched artifact. Complete
verification checks exact byte lengths and SHA-256 hashes, verifies the
detached signature in an isolated GnuPG home with automatic key retrieval
disabled, and inspects the archive without extracting it. The archive root,
embedded Git revision, version/release markers, and all locked license texts
must match.

To verify previously downloaded files directly:

```bash
python3 scripts/verify-gcc-oracle-source.py \
  --archive /path/to/gcc-16.2.0.tar.xz \
  --signature /path/to/gcc-16.2.0.tar.xz.sig
```

Run the mutation-focused unit tests with:

```bash
python3 -m unittest discover -s tests/oracle -v
```

## Scope of this checkpoint

This lock anchors the adjacent production build record, retained DWARF-rich
driver and stripped twin, generated oracle manifest, and checked-in normalized
function-recovery oracle. It also anchors the checked, hermetic
`behavior-corpus.json` and deterministic `behavior-corpus-evidence.json`.
The generic function generator lives in
`oracle/function_recovery_oracle.py`; this directory supplies only the verified
artifact binding and reviewed exact-RVA exclusion profile. Regeneration is
documented in `docs/gcc-function-recovery-scoring.md` and is byte-compared in
the oracle test suite. The
[strict build and ELF verification procedure](../../../docs/gcc-oracle-artifact-verification.md)
documents clean reproduction and the CI gate. GCC remains one substantial C
benchmark, not an engine-specific code path.

## Driver behavior benchmark

The adjacent behavior corpus is a thin GCC 16.2.0 profile of the
[program-agnostic executable behavior contract](../../../docs/executable-behavior-corpus.md).
It does not add GCC semantics to the runner. The profile cross-binds the exact
stripped artifact (`3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4`)
and the exact build runtime image
(`sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248`)
to the already verified oracle manifest and build record.

The profile additionally authenticates the Docker 29.7.2 static distribution
used to run the dedicated daemon and control that image. Its client is
42,677,472 bytes with SHA-256
`e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13`,
and version output `Docker version 29.7.2, build a7dcaa6`. The upstream
`docker-29.7.2.tgz` at
`https://download.docker.com/linux/static/stable/x86_64/` has SHA-256
`803d433f226db4776e1768fd319fc6c6e4935a456acf84fcc0080818b854bc8f`.
CI also requires the archive's daemon version output
`Docker version 29.7.2, build 6a43e3d` and places the authenticated static
distribution first on the daemon launcher's `PATH`; runner-preinstalled
engine components cannot be selected accidentally.
The hosted rootless daemon is launched by Docker's matching
`docker-rootless-extras-29.7.2.tgz`, exactly 12,000,464 bytes with SHA-256
`15a5cb81f2c5cf15ea21427f2e8241eac0deb2221175f993b5e76926e705ec6a`.
CI separately hashes its launcher and RootlessKit binary, requires RootlessKit
3.0.2, and requires the live daemon to report Docker 29.7.2 before loading an
oracle image. On Ubuntu 24.04, the authenticated RootlessKit binary is placed
at `/usr/bin/rootlesskit` so the distribution AppArmor user-namespace profile
applies. The launcher is explicitly bound to Ubuntu's
`slirp4netns=1.2.1-1build2` with the builtin port driver and host loopback
disabled; CI verifies both the signed package version and live tool version.
Because every keeper, setup, target, and collector container is independently
required to use `network=none`, the dedicated daemon has no default bridge,
iptables/ip6tables management, forwarding, or masquerading. This is Docker's
documented no-network bootstrap configuration and avoids granting the daemon
unused firewall authority.
The checked generic engine profile exactly binds Docker Engine 29.7.2 and its
commit/API and component digest, Linux amd64 kernel
`7.1.8-gentoo-dist-hardened`, rootless mode, cgroup v2/systemd, overlay2, the
built-in seccomp profile, the local tmpfs-volume driver, and runc 1.4.3 by
commit and feature hash. A different client, server, kernel, runtime, or
weaker security mode fails closed before a benchmark case starts. These are
executor provenance values for this benchmark profile, not GCC behavior in
the generic runner.

Fourteen sorted cases cover version and target queries, help, invalid-option
and missing-input diagnostics, file and stdin preprocessing, file and stdin
compilation, assembly, linking, response files, and `COMPILER_PATH` program
search. Every case records its complete environment overlay, stdin and staged
files, exit status, byte-exact stdout/stderr, and all expected produced or
absent artifacts. The checked profile applies zero normalizations.

Each case runs the opaque driver as a non-root PID 1 with no target-visible
read/write host bind. A quota-backed tmpfs volume is retained by a checked
keeper, populated from read-only inputs by the profile's authenticated setup
command, and copied out by its authenticated bounded collector only after the
target container is gone. Before each keeper, setup, target, or collector role,
the image-bound pre-exec wrapper proves the live private cgroup-v2 limits and
all configured rlimits, then emits a fresh role-and-nonce-bound control frame
that the runner requires and removes. The nonce is absent after the role is
executed. The pre-exec/setup/keeper/collector argv are reviewed trusted
control-plane data in this thin profile; only the driver is treated as hostile.
These are upper bounds at the container-visible cgroup root: an authenticated
host ancestor may impose a stricter bound.

Only the GCC driver executable is part of the oracle pair; its matching
installed `cc1`, assembler, and linker tree is not. Compile-stage cases
therefore stage small, hashed deterministic companion programs as corpus
inputs. These cases measure the driver's observable option/response expansion,
program search, phase ordering, stdin/file handling, exit propagation, and
artifact orchestration. They deliberately do not claim to measure frontend
language semantics, optimization, assembler encoding, or system linking;
those require separate program-agnostic semantic/oracle dimensions.

After reproducing the locked image, regenerate candidate expectations and
compare them with the reviewed corpus:

```bash
export DOCKER=/absolute/path/to/docker-29.7.2/docker/docker
export DOCKER_HOST=unix:///absolute/path/to/blessed-rootless-docker.sock
python3 scripts/check-gcc-behavior-executor.py
python3 scripts/generate-gcc-behavior-corpus.py --output /tmp/behavior-corpus.json
cmp /tmp/behavior-corpus.json oracle/gcc/16.2.0/behavior-corpus.json
```

Run verification and compare the deterministic evidence:

```bash
python3 scripts/run-gcc-behavior-corpus.py \
  --json-output /tmp/behavior-corpus-evidence.json
cmp /tmp/behavior-corpus-evidence.json \
  oracle/gcc/16.2.0/behavior-corpus-evidence.json
```

The checked benchmark pair can also be cross-validated offline, without a
claim of live reproduction:

```bash
python3 scripts/check-behavior-corpus-evidence.py \
  --corpus oracle/gcc/16.2.0/behavior-corpus.json \
  --evidence oracle/gcc/16.2.0/behavior-corpus-evidence.json
```

The oracle workflow builds and authenticates the separately locked
deterministic reproduction before Python test discovery, while retaining the
historical image digest in the build record and artifact evidence. It then
downloads and hashes the locked control client and exports its absolute path
to a rootless test daemon. Generic adversarial cases derive and assert that
live daemon's exact profile. The checked GCC evidence is
regenerated and byte-compared only when the daemon, including kernel version,
matches this profile. Hosted Ubuntu emits an explicit skip notice rather than
claiming reproduction on a different kernel; its offline corpus/evidence,
schema, adapter, and provenance checks still run. A pinned VM/kernel job is
deferred infrastructure. `tests/oracle/test_gcc_behavior_corpus.py` checks
every acceptance category and proves that artifact or runtime substitution is
rejected.

The generic live adversarial fixtures run against the separately authenticated
reproduction image through `DECOMP_TEST_OCI_IMAGE_DIGEST`; they do not claim to
reproduce the checked GCC evidence. The production adapter continues to require
the historical digest and exact executor profile above, so that narrower live
comparison skips rather than silently substituting the reproduction identity.

That skip is deliberately narrow: only a well-formed executor that retains all
mandatory isolation capabilities but differs from an authenticated exact
profile field returns status 78. A client/image/runtime lookup failure, daemon
or control-plane failure, malformed response, missing security capability, or
other verifier error fails the workflow.

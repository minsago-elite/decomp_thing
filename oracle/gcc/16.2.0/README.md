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
driver and stripped twin, and generated oracle manifest. The
[strict build and ELF verification procedure](../../../docs/gcc-oracle-artifact-verification.md)
documents clean reproduction and the CI gate. Later benchmark checkpoints add
structural and behavior oracles without turning GCC into an engine-specific
code path.

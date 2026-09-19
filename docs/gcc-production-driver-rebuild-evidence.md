# GCC production driver clean rebuild evidence

This is a small evidence record for #705. Its status is **unresolved**: it
binds repository facts and the receipt contract, but does not claim that the
reconstructed production driver archive has been rebuilt or qualified.

## Repository facts available

The authenticated GCC oracle input is
[`oracle/gcc/16.2.0/source-lock.json`](../oracle/gcc/16.2.0/source-lock.json):

- source revision: `78d4ac73dd391005b895a6148cd9831e28e1208b`;
- source archive SHA-256:
  `e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e`;
- source-lock SHA-256:
  `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc`.

[`oracle-manifest.json`](../oracle/gcc/16.2.0/oracle-manifest.json) is
`c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` and
records the oracle pair, not reconstructed source output:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| rich GCC driver | 20,713,760 | `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` |
| stripped GCC driver | 2,349,296 | `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |

The checked build record binds the recorded configure, `make -j4 all-gcc`,
`install-gcc`, staging, and stripping argument arrays. It records the
`linux/amd64` toolchain image digest
`sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248`,
`LC_ALL=C`, `TZ=UTC`, and `SOURCE_DATE_EPOCH=1786060800`. The record hash is
`f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637`.

## Required production receipt

An accepted #705 receipt must bind the accepted #704 archive and source
manifest to the source/oracle identities above, then retain, for each fresh
independent root:

1. the exact recorded command, environment assumptions, and toolchain identity;
2. fresh extraction evidence with credentials and analysis caches absent and
   network access disabled;
3. source, build, and complete archive hashes;
4. measured resource use, compiler/link diagnostics, and cleanup outcome; and
5. an independent archive/hash verification result with every unavailable or
   unresolved entity preserved as unresolved.

The fixture-only `ArchivalBundleTest` and `StrictProjectBuildTest` establish
the reusable archive/build contract, but they do not produce this receipt for
the genuine GCC reconstruction. The oracle manifest and function oracle remain
authenticated oracle inputs; they cannot authorize reconstructed source,
agent receipts, or a production build claim.

## Production gap

No complete accepted reconstructed GCC driver tree, source manifest, or
production archive is retained in this checkout. Consequently the two-root
byte comparison, clean credential-free/cache-free/network-isolated rebuild,
exact rebuilt hashes, measured resource use, diagnostics, and independent
verification remain unavailable. These states are unresolved rather than
successful.

Any future production analysis must continue to use the bundled Ghidra Java
APIs in an isolated worker. This record adds no `GHIDRA_HOME` or external
`analyzeHeadless` prerequisite and does not weaken the authenticated oracle
boundary or provenance requirements.

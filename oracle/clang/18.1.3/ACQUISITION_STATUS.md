# Clang 18.1.3 acquisition status

Date of local probe: 2026-10-05 UTC

Repository base: `c36b8c3e814a49965e5bba65475e9010e5f6a1de`
Scope: issue #1480; this note is not a package lock, compatibility approval,
toolchain profile, or acceptance evidence. It records the local environment
result and bounded, short-lived public-runner metadata diagnostics; successful
acceptance would require its own authenticated build record and reports.

## Local environment result

The public Ubuntu Snapshot URL
`https://snapshot.ubuntu.com/ubuntu/20240425T000000Z/dists/noble/InRelease`
returned HTTP 403 in the local execution environment. This was an HTTP response,
not a tool or policy authorization denial; no tool explicitly denied
authorization. No alternate proxy, mirror, browser download, mutable archive
metadata, or other route was used. The local environment therefore did not
authenticate any Ubuntu package bytes.

The official LLVM downloads page links the 18.1.3 release to GitHub. Its
expanded asset listing contains the `llvm-project-18.1.3.src.tar.xz` archive,
the matching `.sig`, and an AArch64 Linux bundle; it lists no x86-64 Linux
bundle. The `345AD05D` text on the downloads page is attached to the separate
LLVM 11.0.1 legacy entry, so it is not evidence for the 18.1.3 signer. The
direct official asset URL
`https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.3/llvm-project-18.1.3.src.tar.xz.sig`
was denied by the web tool as a restricted URL. I did not retry it through
another route. The exact public-key bytes and full signer fingerprint remain
unverified. The contract currently names a key bundled for the 22.1.6 oracle,
which cannot authenticate the 2024 Clang 18.1.3 release. A direct public-key
lookup at
`https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x345AD05D` returned
HTTP 403. No alternate key source or proxy was used; upstream source signature
verification is therefore blocked and the configured key must not be treated
as valid provenance.

An independent review supplied the Tom Stellard key suffix
`A2C794A986419D8A` as a research lead. It is not a full fingerprint, key
material, or authenticated signature evidence. The 22.1.6 key was created after
the 18.1.3 release and remains invalid for this purpose.

The owned provisioning workflow performs the acquisition on a standard public
`ubuntu-24.04` Actions runner. This local run did not establish:

- signed Snapshot `InRelease` → `Sources`/`Packages` SHA-256 metadata chain;
- Ubuntu source version `1:18.1.3-1ubuntu1`, `.dsc`, payload checksums, and
  the exact pinned binary/development/runtime closure;
- comparison of all 34 accepted contract-relevant source files against the
  signed upstream `llvmorg-18.1.3` release;
- Clang C/C++ driver identities, the source-level inventory of 298 generated
  `LangOptions` macro fields/eight families and 28 manual members, selected
  runtime `LangOptions` checks, LibTooling API observations, resource closure,
  image identity, or two-clean-run reproducibility.

## Public runner result

Workflow run `37342422505` at PR head
`28e262d194ba459c6037cf541477e9f99e3a9161` ran on the standard
`ubuntu-24.04` public runner. Its diagnostic artifact is `11358579019`
(`sha256:b0f5bbc2a047f64892362acc8e0d363d5be436baf54d82b928c4e08fe3f4ea56`).
The acquisition step authenticated the pinned Snapshot `InRelease` files and
the `Sources`/`Packages` indexes against their signed Release SHA-256 tables.
The signed `noble` Release metadata is dated `2024-04-24 23:22:57 UTC`, has
primary signer fingerprint
`F6ECB3762474EDA9D21B7022871920D1991BC93C`, and SHA-256
`6b11738580bff56fc81a2f2bde71c5ef73d558ec100baeb15704772f873af6e2`.

For the pinned snapshot `20240425T000000Z`, the signed source-index coverage
and exact package row were:

| Index or record | Authenticated value |
| --- | --- |
| `noble/main/source/Sources.gz` | 1,713,100 bytes; SHA-256 `8c6f2e2477547f4f5b87f5d90483537080ad5971197783f71a3883f6da35b776` |
| `noble/universe/source/Sources.gz` | 24,276,536 bytes; SHA-256 `3efada3c84fe4d1ee4a12c2b57034431a25df383f28cdff87da41e6aedd01a5b` |
| `noble-updates` and `noble-security` source indexes | All four selected indexes were 40-byte empty indexes with SHA-256 `e7ab72b8f37c7c9c9f6386fb8e3dfa40bf6fe4b67876703c5927e47cb8664ce4` |
| Source record | One record: `llvm-toolchain-18`, version `1:18.1.3-1`, component `main`, directory `pool/main/l/llvm-toolchain-18` |

The source record's signed `Checksums-Sha256` field lists `llvm-toolchain-18_18.1.3-1.dsc` (8,313 bytes; `e02fd3dd4004a5751040d5fc597334e37049a14a9b685c628b7ecf88a2365b21`), `llvm-toolchain-18_18.1.3.orig.tar.xz` (155,361,864 bytes; `ddf2448d682adbfb4a57aa7ac45219cc00aef6ae9ce2fabd8598fa1cc97d26c4`), and `llvm-toolchain-18_18.1.3-1.debian.tar.xz` (162,568 bytes; `0afaf17d8eb52c0547c8d152a44e18fd762a4ee1cf6da99237c27d4509a14eb1`). These are authenticated index claims only; none of those payloads was downloaded in this run.

All five binary roots are also present in signed `noble` indexes, but their
versions are `1:18.1.3-1`, not the contract's `1:18.1.3-1ubuntu1`:

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| `clang-18` | 80,564 | `3d028a3b4c0b3dc942e043db94e153baedf5c384283181d274a5e915da1b5135` |
| `llvm-18-dev` | 45,055,372 | `fc651a70e29c3c8c6def331da592bc1009f909c015bbbb29b5d1be9e6fe460fa` |
| `libclang-18-dev` | 28,789,174 | `c13e1f232ece265646583993a6e679bf9825a86079e7abb34410ff08ff873b80` |
| `libclang-cpp18-dev` | 3,666 | `bb5dd4e7d65ca5fb6d5262823a14737d90eff3f72a3a289539d589a7c9f14bf7` |
| `libclang-cpp18` | 13,494,854 | `899e354d4719c31eb7829517a3ed8d6b64173590fb5c7fe7371ede469fbbe05d` |

Each binary `Source` field is `llvm-toolchain-18` without a source version.
The exact string selector is functioning as specified: it does not strip the
epoch or normalize Debian revisions. The pinned snapshot covers
`1:18.1.3-1`; it does not cover the contract's exact `1:18.1.3-1ubuntu1` source
or binary versions. This is a real pinned-version coverage mismatch, not an
epoch-only representation mismatch. No alternate snapshot or package version
has been substituted.

The run stopped before downloading the `.dsc`/source payload, verifying the
LLVM source signature, comparing distro patches against upstream, or entering
the compiler, loader, image, and reproducibility gates. Those gates remain
unverified.

## Public runner metadata-only candidate probe

Workflow run [37347524443](https://github.com/minsago-elite/decomp_thing/actions/runs/37347524443)
at PR head `8c70ed4e5998a0887a1f96b8222eb1e2a7de499d` completed successfully on
the standard `ubuntu-24.04` runner. The metadata-only job authenticated the
candidate Snapshot `20240615T000000Z`; it did not run the full qualification
job. The evidence report hash is
`0241bed24f4db5885459ca63a9e9e573df37948c416875506e2d640d24f5e537` and is
printed in the workflow logs. Artifact `11361630892` contains the report, three
signed `InRelease` files, and twelve signed-index files; its SHA-256 digest is
`dba68bc65d023d426c84675c980d7a649f4234585994a325705dac6354748268`. The
artifact is retained until `2026-10-06 17:20:42 UTC`.

| Suite | Signed Release date (UTC) | Primary signer | `InRelease` SHA-256 |
| --- | --- | --- | --- |
| `noble` | 2024-04-25 15:10:33 | `F6ECB3762474EDA9D21B7022871920D1991BC93C` | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` |
| `noble-updates` | 2024-06-14 23:59:46 | `F6ECB3762474EDA9D21B7022871920D1991BC93C` | `66623b91ab0e0d9ae6b70a3c190953d1a800073f6f316012c4a5ba97cba3f475` |
| `noble-security` | 2024-06-14 17:32:58 | `F6ECB3762474EDA9D21B7022871920D1991BC93C` | `6ad8e7ab9b76512e4caf95408621d8819ddf7e324bb00afc9cf4f1b54f5d323a` |

The signed source indexes report only `1:18.1.3-1` for
`llvm-toolchain-18`; the pinned source version `1:18.1.3-1ubuntu1` is absent.
Each of the five requested binary roots (`clang-18`, `llvm-18-dev`,
`libclang-18-dev`, `libclang-cpp18-dev`, and `libclang-cpp18`) likewise reports
only `1:18.1.3-1`, not the pinned `1:18.1.3-1ubuntu1`. The machine-readable
status is `source-exact-version-not-found`. The probe authenticated 48,315,356
bytes of signed metadata and downloaded zero package payload bytes. It fetched
no `.dsc`, source archive, or `.deb`; no source-patch compatibility audit or
compiler, loader, image, or reproducibility gate was attempted. This candidate
therefore cannot satisfy the fixed acquisition contract, and no package pin or
profile was changed.

The later workflow revision restores the full `qualify` job on pull requests
and leaves this disproven-candidate probe as a separately named manual
diagnostic. The skipped `qualify` result in run #10 predates that revision and
is not an acceptance pass.

Matching package version text is not compatibility or provenance evidence.
The bounded alternative remains a separately reviewed source build from the
exact signed upstream Clang 18.1.3 source on the same public runner class; that
alternative is not implemented or qualified here.

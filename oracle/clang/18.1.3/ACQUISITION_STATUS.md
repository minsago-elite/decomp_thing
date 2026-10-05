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

## Public runner metadata-only diagnostic: June 15 candidate

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

Run #10's skipped `qualify` result was a temporary workflow state and is not an
acceptance pass. Run #11 restored the full PR gate; it failed closed during
signed acquisition with zero exact source records for `1:18.1.3-1ubuntu1` and
observed version `1:18.1.3-1@noble/main`. Every compiler, loader, and image
step was skipped after that failure. At that revision the June 15 diagnostic
was manual-only.

## Public runner metadata-only diagnostic: July 2 candidate

Following the July 1 Ubuntu notice that the Noble fix was published in
`llvm-toolchain-18 1:18.1.3-1ubuntu1`, workflow [run #12](https://github.com/minsago-elite/decomp_thing/actions/runs/37349799547)
tested the specific Snapshot `20240702T000000Z` on `ubuntu-24.04`. Its separate
metadata diagnostic job succeeded with status `exact-contract-records-present`.
The report SHA-256 is
`62429b8b1301116f941285d155457ccfbf58718e5022e5c17129a2448f7332ad`. Artifact
`11362655050` contains the report, three signed `InRelease` files, and all
twelve signed indexes; its ZIP SHA-256 is
`3a80557fda54465a011487032df389ab5af568891b2bf44b16f47886a4ba3ddb`. The
artifact expires at `2026-10-06 17:39:13 UTC`.

All three `InRelease` files verified with primary signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C`:

| Suite | Signed Release date (UTC) | `InRelease` SHA-256 |
| --- | --- | --- |
| `noble` | 2024-04-25 15:10:33 | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` |
| `noble-updates` | 2024-07-01 23:14:08 | `622667146ddd72547790c378cc1c2668b4aff8d5577ec16b306ec42422b0bd20` |
| `noble-security` | 2024-07-01 09:51:15 | `81de4aba4045c691cbb11b423d0f731859106e385224c7039aa17e53df24a113` |

The exact source row is in signed `noble-updates/main/source/Sources.gz`
(104,595 bytes; SHA-256
`9b193031f58ccdf8477b7d2fb194504b305e816eeb2aac7408e21ec487a53a84`):
`llvm-toolchain-18`, version `1:18.1.3-1ubuntu1`, directory
`pool/main/l/llvm-toolchain-18`. Its signed `Checksums-Sha256` field records:

| Source file | Bytes | SHA-256 |
| --- | ---: | --- |
| `llvm-toolchain-18_18.1.3-1ubuntu1.dsc` | 8,420 | `1775aeccdacc7c5c016b1ddbb2e2ebe5ea1fd308b48e6f0511d256922fdf2537` |
| `llvm-toolchain-18_18.1.3.orig.tar.xz` | 155,361,864 | `ddf2448d682adbfb4a57aa7ac45219cc00aef6ae9ce2fabd8598fa1cc97d26c4` |
| `llvm-toolchain-18_18.1.3-1ubuntu1.debian.tar.xz` | 162,708 | `7063d88002765b53e8efd42e75d4027f873d78c0c4ec51817b92e17e1c327a08` |

The source index digest is the SHA-256 value signed in the
`noble-updates` Release. The exact binary records below are likewise covered
by the signed amd64 package indexes: `main/binary-amd64/Packages.gz` is 268,541
bytes with SHA-256
`fcf0527e4d18fe973f12d94533596b76f7443c13affa07559135358afbf0e831`, and
`universe/binary-amd64/Packages.gz` is 136,990 bytes with SHA-256
`6e2c7b5055fd2b0317cbc6b2c2a179ed8e33497f6cfcabeb1fd15190e0aa4709`.

The signed `noble-updates` amd64 package indexes authenticate all five exact
binary roots. `Source` is `llvm-toolchain-18` for every root; that field omits
the source version, while the exact source row above supplies it.

| Package | Component | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `clang-18` | `universe` | 80,040 | `628b16701014ef7ad648380b20ea74b90dd543857f933b3e34d2fc042783de25` |
| `llvm-18-dev` | `universe` | 45,109,568 | `1e68b8c3f788832c5c83d56a1b3dbbba1ee148407f61c873ed659bb373ae6388` |
| `libclang-18-dev` | `universe` | 28,788,538 | `c7575822ec648defe1b04d83a1d6b7779fc26da548c2453acfa120e26d47ed53` |
| `libclang-cpp18-dev` | `universe` | 3,664 | `dc0c194881c2300867c369380a457a6ec2ee8be6d3d182d0deec81a3f50182d6` |
| `libclang-cpp18` | `main` | 13,492,572 | `e91eda104813ee0468d145d010a4a4e142401f3f17f9a65596c66d416298d018` |

The source index and relevant binary-index SHA-256 values above match the
signed Release tables. The probe acquired 48,554,460 bytes of metadata and
zero package payload bytes; it downloaded no `.dsc`, source archive, or `.deb`.
This is signed index provenance only. Upstream signature verification, the
comparison of all 34 contract-relevant source files/patches, and every compiler,
loader, image, and reproducibility acceptance gate remain unverified. At the
time of this diagnostic the production contract remained pinned to
`20240425T000000Z`; the change to July 2 described below followed separate
review approval.

At the same head, the normal PR `qualify` job ran separately and failed closed
against that unchanged production pin: it found no exact source record for
`1:18.1.3-1ubuntu1`, only `1:18.1.3-1@noble/main`. This prevents the diagnostic
job's success from being mistaken for production qualification.

For pull requests, the workflow always runs both `qualify` and the separate
July 2 metadata diagnostic. Manual dispatch defaults to full qualification;
the metadata-only mode is an explicit diagnostic choice and is not a PR
acceptance path.

Matching package version text is not compatibility or provenance evidence.
The bounded alternative remains a separately reviewed source build from the
exact signed upstream Clang 18.1.3 source on the same public runner class; that
alternative is not implemented or qualified here.

## Approved production snapshot and fail-closed qualification

After the July 2 signed-index diagnostic, independent review approved
`20240702T000000Z` as the production snapshot. The contract and build-record
schema now pin that timestamp; the source package version and all five binary
root version pins remain exactly `1:18.1.3-1ubuntu1`. This approval uses signed
index provenance, not version text alone, and does not approve the distro
patches or source compatibility.

The full public-runner PR qualification remains a separate mandatory gate. Its
acquisition step has a fail-closed prerequisite before making any request to
the official LLVM 18.1.3 detached-signature URL that was denied in this
environment. When acquisition reaches that prerequisite it stops with the
exact URL, without trying that URL through Actions, a proxy, mirror, or another
route. Until the signature is accessible through an authorized path and
independently reviewed, the upstream source signature, complete 34-file source
audit, compiler/API probes, loader checks, image/rootfs identity, and two-run
reproducibility remain unverified. No image or build record from this PR may be
treated as accepted.

The qualification workflow retains the canonical rootfs tar only after its
build record is created. Before an artifact upload, `verify-record` checks the
tar byte count and SHA-256 against the record, while `verify-image` checks the
OCI layer's expanded bytes against the same rootfs identity. A successful
qualification will upload the rootfs tar as a one-day artifact for downstream
extraction; the image and provenance remain separate one-day artifacts. No
such accepted artifact is available until all preceding gates pass. B's
integration and the shared registry/inventory are outside this issue's owned
scope and were not changed or run.

# Clang 18.1.3 acquisition status

Date of local probe: 2026-10-05 UTC

Repository base: `c36b8c3e814a49965e5bba65475e9010e5f6a1de`
Scope: issue #1480; this note is not a package lock, compatibility approval,
toolchain profile, or acceptance evidence. It records the local environment
result only; a successful workflow artifact carries its own authenticated build
record and acceptance reports.

## Local environment result

The public Ubuntu Snapshot URL
`https://snapshot.ubuntu.com/ubuntu/20240425T000000Z/dists/noble/InRelease`
returned HTTP 403 in the local execution environment. This was an HTTP response,
not a tool or policy authorization denial; no tool explicitly denied
authorization. No alternate proxy, mirror, browser download, mutable archive
metadata, or other route was used. The local environment therefore did not
authenticate any Ubuntu package bytes.

The official LLVM downloads page identifies the 18.1 release signatures with
short key ID `345AD05D`, but the exact public-key bytes and full fingerprint
were not obtained. The contract currently names a key bundled for the 22.1.6
oracle, which cannot authenticate the 2024 Clang 18.1.3 release. A direct
public-key lookup at `https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x345AD05D`
returned HTTP 403. No alternate key source or proxy was used; upstream source
signature verification is therefore blocked and the configured key must not be
treated as valid provenance.

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

Workflow run `37339788139` at PR head
`ed16e335ea323c59a77f1ffd2ff0574775209404` ran on the standard
`ubuntu-24.04` public runner. It verified the pinned Snapshot `InRelease`
signatures and the signed Release SHA-256 references for the selected source
and binary indexes, then failed before downloading the source payload:

`expected a unique signed source record for llvm-toolchain-18=1:18.1.3-1ubuntu1; found 0 records`

The workflow's package closure, upstream source-signature check, patch
comparison and all compiler/image/profile gates were skipped. The failure does
not establish whether the package is absent from this pinned Snapshot or the
profile's source-record selection needs correction; no different snapshot or
source profile has been selected.

Matching package version text is not compatibility or provenance evidence.
The workflow rejects any difference in the 34 contract-relevant source files
before it provisions the toolchain. If that gate finds a difference, it emits
the full audit artifact and stops. The bounded alternative is a separately
reviewed source build from the exact signed upstream Clang 18.1.3 source on the
same public runner class; that alternative is not implemented or qualified here.

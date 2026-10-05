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

The owned provisioning workflow performs the acquisition on a standard public
`ubuntu-24.04` Actions runner. This local run did not establish:

- signed Snapshot `InRelease` → `Sources`/`Packages` SHA-256 metadata chain;
- Ubuntu source version `1:18.1.3-1ubuntu1`, `.dsc`, payload checksums, and
  the exact pinned binary/development/runtime closure;
- comparison of all 32 accepted contract-relevant source files against the
  signed upstream `llvmorg-18.1.3` release;
- Clang C/C++ driver identities, the 298 generated/eight-family and 28 manual
  `LangOptions` inventory, LibTooling API probe, resource closure, image
  identity, or two-clean-run reproducibility.

Matching package version text is not compatibility or provenance evidence.
The workflow rejects any difference in the 32 contract-relevant source files
before it provisions the toolchain. If that gate finds a difference, it emits
the full audit artifact and stops. The bounded alternative is a separately
reviewed source build from the exact signed upstream Clang 18.1.3 source on the
same public runner class; that alternative is not implemented or qualified here.

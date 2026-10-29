# Web workbench release artifacts and notes

This document covers [#665](https://github.com/minsago-elite/decomp_thing/issues/665) under
tracker [#232](https://github.com/minsago-elite/decomp_thing/issues/232). It explains how to
assemble a release directory from the normal Gradle distributions, how to check that every
published checksum and inventory entry matches the shipped bytes, and what the current `master`
build does and does not include. Issue and milestone status lives in GitHub. The release
acceptance decision belongs to [#668](https://github.com/minsago-elite/decomp_thing/issues/668).

Related guides: [backup and restore](web-backup-restore.md), [operations and support
bundles](web-operations.md), the [workbench user guide](workbench-user-guide.md) and
[packaging](web-packaging.md).

## What a release contains

The release unit is the Gradle application distribution, published both as
`llm_bin_patch-<version>.zip` and as `llm_bin_patch-<version>.tar`. Both archives contain the same
files with the same bytes and modes under `llm_bin_patch-<version>/`:

| Path | Role in `release-inventory.json` | Contents |
|---|---|---|
| `bin/llm_bin_patch`, `bin/llm_bin_patch.bat` | `launcher` | Gradle start scripts. The Unix launcher's `CLASSPATH` line is the JVM dependency closure. |
| `lib/llm-bin-patch-<version>.jar` | `application-jar` | Compiled application, plus the embedded UI under `decompengine/web/ui/` with its `asset-manifest.json`. |
| `lib/*.jar` (other) | `dependency-jar` | Runtime dependency closure. Every JAR is on the launcher class path, and every class-path entry is shipped. |
| `lib/*-reference-v1.json` | `runtime-reference` | Kotlin BOOT, LLVM hosted-worker and bundled-Ghidra deployment references, generated from the final JAR. |
| `libexec/ghidra/**` | `bundled-ghidra` | Hash-locked Ghidra 12.1.3 release, its `bundle.sha256`, licenses and `bom.json`, and the bridge JAR. See [bundled Ghidra](bundled-ghidra.md). |
| `libexec/*` (other) | `native-helper` | ACP gate, analysis I/O and LLVM behavior helpers with their `.sha256` files and build records, and the native oracle libraries. |
| `docs/frontend-THIRD_PARTY_NOTICES.txt` | `notice` | Notices for third-party code emitted into the browser application. |

This is a thin-JAR distribution. Use the installed launchers. `java -jar` is not supported.

## Assemble and verify a release directory

```sh
./gradlew installDist distZip distTar verifyPackagedWeb verifyGhidraDistributionArchives \
  verifyAcpGateHelperDistribution verifyLlvmBehaviorHelperDistribution \
  verifyKotlinBootClasspathDistribution
python3 scripts/release-artifacts.py assemble
python3 scripts/release-artifacts.py verify build/release/llm_bin_patch-<version> \
  --lockfile frontend/package-lock.json
```

The Gradle tasks are the existing distribution checks; [packaging](web-packaging.md#keep-resources-and-runtime-references-together)
describes them. `scripts/release-artifacts.py` adds no build step and runs nothing from the
distribution. `assemble` reads `build/distributions/` and writes
`build/release/llm_bin_patch-<version>/`:

| File | What it records |
|---|---|
| the two archives | Byte-for-byte copies of the built ZIP and TAR. |
| `release-inventory.json` | Every shipped file: relative path, size, SHA-256, mode and role, plus the launcher class path. |
| `ui-manifest.json` | The embedded UI manifest as read from inside the application JAR. |
| `frontend-dependencies.json` | Every non-development package in `frontend/package-lock.json`, with version, resolved URL, integrity and license, and whether it contributes browser modules. Also records per-chunk module owners (`chunkOwners`) and the lockfile's SHA-256, checked against the build-generated ownership anchor shipped inside the application JAR. |
| `frontend-THIRD_PARTY_NOTICES.txt` | The notices file as shipped in the distribution. |
| `release-record.json` | Version, the source binding, `applicationBuildId`, `uiBuildId`, archive sizes and digests, and the platform. |
| `SHA256SUMS` | `sha256sum -c`-compatible lines for every other file in the directory. |

The distribution does not record which commit it was built from, and the checkout running
`assemble` proves nothing about archives it did not build. The record's `source` is therefore
`{"revision": null, "binding": "unknown"}` unless `--source-revision <40-hex commit>` is passed.
A passed revision is recorded as `"binding": "asserted-by-assembler"`. That label is the
assembler's statement, not something the bytes confirm. CI passes the commit it checked out and
built in the same job. Binding the revision into the build itself waits on reproducible
application JARs ([#1789](https://github.com/minsago-elite/decomp_thing/issues/1789)).

`assemble` refuses to write a release when any of these is true:

- `build/frontend/bundle-composition.json` (or the `--bundle-composition` path) is missing.
  Without it, browser-module owners and notice coverage cannot be checked.
- The composition's chunks are not exactly the JavaScript files in the shipped UI manifest, or
  their owner sets differ from the shipped `assets/bundle-ownership-<sha256>.json` anchor. Vite
  generates that content-addressed asset from the page and worker module graph during the build;
  the embedded UI manifest hashes its bytes. The anchor also binds the exact lockfile SHA-256.
  Same-filename relabeling and a stale/foreign lockfile are refused, not just absent chunk names.
  Older archives without this anchor must be rebuilt before using this release verifier. The
  anchor contains package owners and a digest, never module/host paths; it is public build metadata.
- The ZIP and TAR ship different files, bytes or modes, or contain noncanonical member paths
  (absolute paths, dot/dot-dot or empty components, backslashes, drive prefixes or control characters).
  Paths are checked before directory entries are skipped and before the installation root is stripped.
- A UI resource in the application JAR differs from its manifest, the JAR contains an unlisted
  resource in the UI namespace, or the manifest's `buildId` does not hash its own contents.
- The launcher class path names a missing file, does not start with the application JAR, or a
  shipped JAR is outside it.
- A browser-module owner is not a locked runtime package.
- The shipped notices omit a browser-module package at its locked version.

`verify` trusts none of the records it checks. It recomputes `SHA256SUMS`, rejects any file in the
directory that `SHA256SUMS` does not list, and then reads both archives from their bytes. Every
member must match its inventory size, digest and mode, and no member may be missing or extra. It
repeats the application-JAR, UI, class-path and notice checks. It rejects records assembled
without browser-module owners, chunk owners that do not cover exactly the shipped UI's JavaScript,
owner flags that disagree with the chunk owners, coordinated owner-record edits that disagree with
the shipped anchor (even with regenerated checksums and without `--lockfile`), lockfile digests that
differ from the anchor, and source blocks other than the two bindings above. It also confirms that
`applicationBuildId` is the SHA-256 of the shipped application JAR, which is the value the running
server reports. With `--lockfile`, the recorded frontend packages and lockfile digest must equal
the current lockfile.

`tests/test_release_artifacts.py` (run with `python3 -B -m unittest tests.test_release_artifacts`)
covers these refusals with synthetic archives. CI's `web-packaged` job runs the unit tests,
then `assemble` and `verify` on the archives it has just built and checked.

## Recorded run on master

Run on 2026-10-26 from a clean worktree at `33c49f95`, Linux x86-64, OpenJDK 21.0.12.1, with
`./gradlew --offline installDist distZip distTar verifyGhidraDistributionArchives`, then
`assemble` and `verify`:

| Fact | Value |
|---|---|
| Shipped files (each archive) | 5,279: 1 application JAR, 31 dependency JARs, 2 launchers, 3 runtime references, 15 native-helper files, 5,226 bundled Ghidra files, 1 notice |
| Launcher class path | 32 JARs, application JAR first |
| `llm_bin_patch-0.1.0.zip` | 622,604,608 bytes, SHA-256 `38e43269f7d6647beadd995f631f711a7c33217e9222ddad133a187d01953702` |
| `llm_bin_patch-0.1.0.tar` | 976,211,456 bytes, SHA-256 `3200e2753abb3ef66f2cf3877259e949e61f156653eb689f6ac6c8236f0e8a25` |
| `applicationBuildId` | `e522133cf6f0a879e379087dfa1bdb1d62d66fdde11dfe37839f0f039d495fee` |
| `uiBuildId` | `8ae87961b642338c6a4353c600b2afe34d256ac8fdcc4ee9fd656a9d89806e16`, 21 UI resources |
| Frontend runtime packages | `preact` 10.29.8 and `preact-iso` 2.12.2 (browser modules); `preact-render-to-string` 6.7.0 (router peer, no browser modules); all MIT |
| `verify` | Passed: both archives, every inventory entry, the UI manifest inside the JAR, the class path, the notices and the lockfile |

These digests identify that one local build. They are not a published release. **The application
JAR is not reproducible across rebuilds:** a second `installDist` from the same tree produced
`applicationBuildId` `c3268a08…`, because the analysis I/O and LLVM helper build records embed the
randomized build directory, including build-host absolute paths. The UI build ID did not change.
[#1789](https://github.com/minsago-elite/decomp_thing/issues/1789) tracks this. Until it is
fixed, a release's checksums bind the bytes of one specific build and do not prove that the build
can be reproduced from source.

### Startup without Node or a network

`verifyPackagedWeb` ([`scripts/check-packaged-web.py`](../scripts/check-packaged-web.py)) already
starts relocated, read-only ZIP and TAR installations with Node and npm absent from `PATH`. For
this run, the released ZIP was also extracted read-only and started inside an empty network
namespace (`unshare -rn`, loopback only), with `PATH` limited to a directory of basic utilities
and `JAVA_HOME` set to a JDK 21. `command -v node` found nothing, and outbound HTTPS failed as
expected. `web --ui spa` served the shell with HTTP 200. The entry script
`/assets/ui/assets/index-CED0q5kT.js` was 140,127 bytes with SHA-256 `586f85fa…a095`, the same
digest as that resource in the JAR's `ui-manifest.json`. The UI is served from the JAR. At run
time it needs no Node, no CDN and no download.

## Platform requirements

| Requirement | Applies to |
|---|---|
| Linux x86-64 | The only qualified host. |
| JDK 21 | Running the launchers. The start scripts use `JAVA_HOME` or `java` on `PATH`. |
| A modern browser | The workbench UI. No plugin, Node or CDN. See [web delivery](web-delivery.md). |
| Node 24.20.0 and npm 11.19.0 | **Building only**: the pinned toolchain from [packaging](web-packaging.md). Never needed at run time. |
| Bundled Ghidra | Shipped in `libexec/ghidra`. Do not install Ghidra or set `GHIDRA_HOME`. A missing or changed bundled file is an availability failure of the distribution. |
| `doctor --tools-only` prerequisites | Analysis workflows only: C compiler, make, binutils, Python with angr, sanitizers, bubblewrap. See the [README](../README.md). |
| An agent harness (ACP or built-in provider) | Agent reconstruction and repair only. The UI reports it as the `harness` capability. |
| Git 2.36.0 or newer | Not needed by `master` today. The managed Git workspace PRs require it once they land. |

Known platform issue: Ghidra refuses project paths with a component that starts with a dot. This
includes the default `--data-dir .decomp_engine/jobs`. Until
[#1785](https://github.com/minsago-elite/decomp_thing/issues/1785) is fixed, pass a `--data-dir`
whose components do not start with a dot when you run analysis workflows.

## Release notes: what `master` implements

These notes describe `master` at `33c49f95` (application version 0.1.0). Features in open pull
requests are listed separately and are **not** part of this build.

**Implemented and shipped**

- One distribution with two browser interfaces. `web` defaults to the legacy server-rendered
  workbench. `web --ui spa` serves the embedded Preact workbench from the application JAR, with
  an optional `--base-path`.
- Local browser sessions on both interfaces. The launcher prints a single-use link, sessions use
  `HttpOnly; SameSite=Strict` cookies and CSRF tokens, and expiry is enforced.
- The SPA covers runtime and readiness status, streaming ELF upload with idempotent retry and
  progress, the job library (filters, paging, snapshots), job overview and attempt history.
  It shows recorded attempts' activity, progress pins, cancellation and recovery controls,
  recorded exploration and validation evidence, revision source browsing and file metadata, and
  downloads of eligible recorded artifacts.
- The SPA does not start workflows. The server reports the `workflows` capability as
  `unavailable` ("Workflow actions are unavailable in this preview.") and readiness as `degraded`.
  Exploration and reconstruction start only from the legacy workbench or the CLI.
- Durable workflow attempt storage with schema version 1, accepted-revision references and
  startup recovery of interrupted attempts.
- Legacy JSON compatibility for `GET /api/jobs/{id}` with a sanitized projection. See the
  [API contract](web-api.md#legacy-compatibility).

**Pending in open pull requests (not in this build)**

| Area | Pull requests |
|---|---|
| Workflow start from the SPA (durable adapters, launch form, harness selection, validation requests) | #1700, #1702, #1706, #1731 |
| Managed Git workspace: reads, commits, branches/worktrees, remotes/credentials, integration/conflicts, push, UI | #1701, #1705, #1708, #1760, #1765, #1767, #1734 |
| Optional GitHub pull-request capability | #1771 |
| Shared redaction, sensitive-action audit and scoped support-export preview | #1704 |
| Optional trusted reverse-proxy profile for remote access | #1780 |
| Source-archive verification, revision diffs, build-log ranges, scope bounds and observability | #1712, #1707, #1729, #1710, #1722, #1725 |

**Remote operation.** `master` binds to loopback only: `web --ui spa` refuses any other host with
"the SPA preview currently requires a loopback host". No authenticated remote profile is shipped.
The optional trusted reverse-proxy profile is pending in #1780 under
[#216](https://github.com/minsago-elite/decomp_thing/issues/216). Binding to a public address is
not a supported deployment.

**Unresolved A/B/C feature dependencies.** The parity contract
([release scope](web-parity.md#release-scope-and-feature-dependencies)) keeps these with their
original owners. Their absence can disable an action with an explanation. It never blocks browsing
existing jobs:

- ACP reconstruction and repair (#64, #65), normalized agent events (#69) and the ACP release gate (#72).
- Built-in reconstruction and repair (#76, #77), harness parity (#79) and the built-in benchmark gate (#83).
- A-series report producers and validators remain the only authority for the evidence the UI
  shows. A finished attempt is not a validated or accepted reconstruction.

**Not claimed by this build:** whole-distribution reproducibility (#1789), production Git or
GitHub operations, remote multi-user deployment, legacy UI removal
([#231](https://github.com/minsago-elite/decomp_thing/issues/231)) and the release acceptance
record ([#668](https://github.com/minsago-elite/decomp_thing/issues/668)).

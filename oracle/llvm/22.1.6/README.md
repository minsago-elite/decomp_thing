# LLVM 22.1.6 Clang oracle

This profile is the source-aligned Clang counterpart to the GCC oracle. It
pins the signed upstream LLVM 22.1.6 release, rebuilds a monolithic X86 Clang
driver in a closed Ubuntu/LLVM/CMake/Ninja environment, and checks in two
code-identical ELF artifact identities:

- `artifacts/clang-driver.full` retains zlib-compressed DWARF and `.symtab`;
- `artifacts/clang-driver.stripped` removes DWARF and static symbols without
  changing allocated sections, executable load bytes, ELF identity, or the
  GNU Build ID.

The binary files are not stored in this repository or in Git history. They are
ordinary release assets in the separate
[`minsago-elite/decomp_thing-oracle-artifacts`](https://github.com/minsago-elite/decomp_thing-oracle-artifacts)
repository under the non-moving `clang-llvm-22.1.6-v1` release tag.
`release-artifacts.json` locks that repository, tag, URLs, byte lengths, and
SHA-256 digests. The bounded fetcher downloads into a caller-selected temporary
root, rejects untrusted redirects or encodings, and installs a file only after
full verification.

`toolchain-reproduction.json` separates stable rebuild identity from Docker
layer identity. It locks the immutable Ubuntu base, Dockerfile bytes,
`SOURCE_DATE_EPOCH`, and historical build-record bytes. CI then checks every
live compiler, linker, stripper, CMake, and Ninja executable byte-for-byte and
compares its exact version output with `build-record.json`. The originating
image ID remains provenance for the checked artifacts; a fresh image ID is
informational because repository metadata can change otherwise equivalent
Docker layers.

## Scope

The build uses `-Oz -g2`, an X86-only target set, and full-DWARF zlib
compression. It intentionally disables LLVM tests, examples, bindings, RTTI,
assertions, and optional libraries that are not part of the driver benchmark.
The artifact still contains every linked monolithic Clang/LLVM function.
The hosted rebuild produced a 529,730,248-byte rich ELF and an
84,561,368-byte stripped ELF with GNU Build ID
`b10a1c569ff0ec7ce1f60c77fef8f4715558f30c`; each file remains below the
512 MiB per-artifact safety limit.

The function-recovery document is narrower: it scores emitted functions from
the 76 `clang/lib/Driver` and `clang/tools/driver/driver.cpp` compilation units,
plus driver-namespace and process-entry symbols. Inline-only DIEs are not
score records because they have no emitted start. This yields a practical,
driver-focused benchmark without raising the generic 20,000-function safety
limit for the monolithic binary's 269,944 emitted RVAs. The checked profile
contains 4,303 emitted functions and no exclusions.

Behavior cases run the stripped driver as an opaque mounted executable in the
same independently authenticated, rootless generic sandbox used by the GCC
profile. The build image proves how Clang was produced; the sandbox image
proves how observable behavior was recorded. These are deliberately separate
authorities.

The 48 sorted reference cases cover C17, C++20 templates, Objective-C,
syntax-only and module flags, preprocessing text and macro state, include
search/tracing, dependency files, PCH emission, LLVM IR, assembly and ELF
object emission, x86-64/i386 and explicitly unsupported target selection,
driver metadata, nested and recursive response files, assembler/linker
success and failure, and diagnostics for syntax, templates, warnings, fix-its,
color, fatal includes, and error limits. Inputs, argv, environment, exit code,
stdout/stderr, absent paths, and every emitted artifact byte are authenticated.
The corpus uses no output normalization. Two independent clean recordings must
be byte-identical before changed reference evidence is accepted.

The preprocessing state-machine cases additionally cover guarded include
cycles, framework lookup, malformed macro definitions, `#pragma once`, quoted
response-file paths, response-file stdin, exact valid-PCH reuse, and rejection
of a PCH built for the wrong target. PCH reuse is recorded in two passes: the
reference compiler first creates the authenticated PCH, its length and SHA-256
are verified, and only then is that exact artifact injected into the reuse
case.

## Full-tree structural evidence

The checked [A13 summary](full-tree-release-evidence.md) and canonical
`full-tree-release-evidence.json` bind the 2,150-unit, 57-shard production
pass to the source/artifact locks. The release gate independently validates
function, call, global/type, ELF, ABI, reconciliation, resource, determinism,
and per-shard baseline evidence before it writes either report. Run
`scripts/generate-llvm-full-tree-release-evidence.py --help` for the complete
reproduction interface; every large input is identified in the machine report
by byte length and SHA-256 rather than by a local path.

The complete canonical observation/truth shards are published under the
non-moving [`clang-llvm-22.1.6-a13-v2`](https://github.com/minsago-elite/decomp_thing-oracle-artifacts/releases/tag/clang-llvm-22.1.6-a13-v2)
release. `full-tree-release-assets.json` locks every asset URL, byte length,
and SHA-256 digest.

`full-tree-source-inventory.json` independently scans the locked upstream
archive and reconciles 4,474 candidate translation units with DWARF: all 2,149
handwritten linked units are present, 2,325 source-only units carry explicit
build/target exclusion reasons, the generated driver CU is separate, and
1,666 TableGen inputs plus 21 disabled projects remain visible.

## Verify

Source-lock, local key/tag evidence, bounded HTTPS acquisition, detached OpenPGP verification, and strict TAR/XZ
archive authentication now run in Kotlin/JVM. The fetcher requires explicit lock and output paths, publishes private
read-only cache files without replacement, and applies the same descriptor-bound verification to fresh and cached
bytes:

```sh
source_root="$(mktemp -d)"
./gradlew --no-daemon fetchLlvmSourceArchive \
  --args="--lock oracle/llvm/22.1.6/source-lock.json --output $source_root"
```

The retained `scripts/verify-llvm-oracle-source.py` and `scripts/fetch-llvm-oracle-source.py` entrypoints are legacy
Python compatibility only; they are not Kotlin/JVM oracle or release authority.

Release-asset lock, manifest, repository/tag/URL, byte-length, SHA-256, HTTPS, and no-replace publication authority now
run in Kotlin/JVM. The fetcher accepts an existing authenticated root or creates exactly one child beneath an existing
authenticated parent; it never recursively follows or creates missing ancestors. The retained
`scripts/fetch-llvm-oracle-artifacts.py` command is legacy compatibility only:

```sh
release_root="$(mktemp -d)"
./gradlew --no-daemon fetchLlvmReleaseArtifacts \
  --args="$release_root"
```

Stable recipe verification also runs in Kotlin/JVM. It strictly binds the checked reproduction lock to the exact
Dockerfile and historical build record, verifies every `FROM` reference plus platform and `SOURCE_DATE_EPOCH`, and
requires exactly one fresh linux/amd64 Docker-inspect identity. The fresh image digest is format- and platform-checked
but is not incorrectly equated with the metadata-derived historical origin digest. Save the inspect response in a
private trusted directory and run:

```sh
inspect_root="$(mktemp -d)"
docker image inspect decomp-llvm-oracle-toolchain:22.1.6 \
  > "$inspect_root/inspect.json"
./gradlew --no-daemon verifyLlvmToolchainReproduction \
  --args="--lock oracle/llvm/22.1.6/toolchain-reproduction.json --build-record oracle/llvm/22.1.6/build-record.json --inspect-json $inspect_root/inspect.json"
```

This gate authenticates stable recipe provenance only. Exact live tool bytes and version output remain the separate
in-container build-record gate below, which is still Python migration compatibility. The retained
`scripts/verify-toolchain-reproduction.py` command is also legacy compatibility only; its underlying Python module
remains a transitive helper of that unmigrated live build-record gate until the latter has Kotlin parity.

Full-tree scope, DWARF inventory, and source-inventory authority run through Kotlin/JVM. Invoke the stable Gradle
entrypoints, then compare their exact canonical bytes with the reviewed artifacts:

```sh
./gradlew --no-daemon verifyFullTreeScope
./gradlew --no-daemon generateFullTreeInventory \
  --args="--rich-artifact /tmp/llvm-oracle-release/artifacts/clang-driver.full --output /tmp/full-tree-inventory.json --workers 1"
cmp /tmp/full-tree-inventory.json \
  oracle/llvm/22.1.6/full-tree-inventory.json
./gradlew --no-daemon generateFullTreeSourceInventory \
  --args="--archive /tmp/llvm-oracle-source/llvm-project-22.1.6.src.tar.xz --inventory /tmp/full-tree-inventory.json --output /tmp/full-tree-source-inventory.json --workers 1"
cmp /tmp/full-tree-source-inventory.json \
  oracle/llvm/22.1.6/full-tree-source-inventory.json
```

Manifest, function-oracle, and behavior commands also remain Python migration-compatibility gates. They cannot
generate, validate, or certify a new Kotlin-only release:

```sh
python3 scripts/verify-llvm-oracle-artifacts.py \
  oracle/llvm/22.1.6/oracle-manifest.json \
  --artifact-root /tmp/llvm-oracle-release
cp -a oracle/llvm/22.1.6 /tmp/llvm-oracle-manifest
python3 scripts/create-llvm-oracle-manifest.py \
  --source-lock /tmp/llvm-oracle-manifest/source-lock.json \
  --build-record /tmp/llvm-oracle-manifest/build-record.json \
  --artifact-root /tmp/llvm-oracle-release \
  --output /tmp/llvm-oracle-manifest/oracle-manifest.generated.json
cmp /tmp/llvm-oracle-manifest/oracle-manifest.generated.json \
  oracle/llvm/22.1.6/oracle-manifest.json
python3 scripts/generate-llvm-function-recovery-oracle.py \
  --manifest oracle/llvm/22.1.6/oracle-manifest.json \
  --exclusions oracle/llvm/22.1.6/function-recovery-exclusions.json \
  --rich-artifact /tmp/llvm-oracle-release/artifacts/clang-driver.full \
  --stripped-artifact /tmp/llvm-oracle-release/artifacts/clang-driver.stripped \
  --output /tmp/llvm-function-oracle.json
cmp /tmp/llvm-function-oracle.json \
  oracle/llvm/22.1.6/function-recovery-oracle.json
python3 scripts/check-behavior-corpus-evidence.py \
  --corpus oracle/llvm/22.1.6/behavior-corpus.json \
  --evidence oracle/llvm/22.1.6/behavior-corpus-evidence.json
```

With the exact Docker executor profile available as `DOCKER` and
`DOCKER_HOST`, live replay is:

```sh
python3 scripts/check-llvm-behavior-executor.py
python3 scripts/generate-llvm-behavior-corpus.py \
  --output /tmp/llvm-behavior-corpus.json
cmp /tmp/llvm-behavior-corpus.json \
  oracle/llvm/22.1.6/behavior-corpus.json
python3 scripts/run-llvm-behavior-corpus.py \
  --json-output /tmp/llvm-behavior-evidence.json
cmp /tmp/llvm-behavior-evidence.json \
  oracle/llvm/22.1.6/behavior-corpus-evidence.json
```

## Rebuild

The manual `LLVM oracle clean rebuild` workflow remains the canonical compatibility reproduction of the historical
pair. Source acquisition is descriptor-bound Kotlin/JVM authority; its Python tool-capture and artifact-verification
steps remain compatibility gaps and cannot authorize a new Kotlin-only release. It constructs the pinned toolchain
image, fetches and authenticates
the upstream archive, disables network access for compilation, executes every
command recorded in `build-record.json`, and uploads the full/stripped pair,
tool records, and image digest for review. A rebuilt pair is not accepted
until it matches the separately released pair byte-for-byte and every
verification command above passes.

The required `LLVM oracle model` workflow runs source acquisition, scope, and inventory stages in Kotlin/JVM, while
retaining the explicitly non-authoritative Python compatibility gates for stages that do not yet have Kotlin
replacements. On every push and pull request it rejects recipe,
base-image, build-record, platform, tool-byte, or tool-version drift without
requiring a fresh image's metadata-derived ID to equal the originating ID.

Dispatch it from a clean `master`, wait for completion, and download the
short-lived review bundle with:

```sh
gh workflow run llvm-oracle-rebuild.yml --ref master
run_id="$(gh run list --workflow llvm-oracle-rebuild.yml --branch master \
  --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$run_id" --exit-status
gh run download "$run_id" --name llvm-oracle-rebuild \
  --dir /tmp/llvm-oracle-rebuild
sha256sum /tmp/llvm-oracle-rebuild/clang-driver.*
```

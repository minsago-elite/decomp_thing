# GCC oracle artifact verification

Issue #38 requires one source-aligned GCC driver in two forms: an unstripped,
DWARF-rich reference and a stripped twin with identical loaded code. The
source release is already pinned by
`oracle/gcc/16.2.0/source-lock.json`. This document describes the independently
verifiable build-record and ELF-manifest boundary that follows that source
lock.

GCC is the first large C benchmark profile, not a target-specific assumption
of the reconstruction engine. The artifact and scoring contracts measure
ordinary ELF/C recovery properties and are intended to admit additional
program profiles. GCC-specific source provenance, commands, and expected
behavior stay below `oracle/gcc/`; production reconstruction remains
program-agnostic.

The production build record, rich/stripped pair, and derived manifest are
checked in under `oracle/gcc/16.2.0/`. Local binaries built by the unit tests
remain deliberately small fixtures and are never substituted for that pair.

## Versioned formats

Three closed JSON formats are enforced by the standard-library verifier:

- `oracle/gcc/build-record.schema.json` describes the build environment and
  recipe. It binds the exact source-lock bytes and revision; an immutable
  Linux/amd64 container image digest; the complete controlled environment;
  out-of-tree source, build, and install paths; configure, compile, install,
  staging, and stripping argument vectors; output paths; and the exact bytes
  and version output of every recorded tool.
- `oracle/gcc/oracle-manifest.schema.json` describes the derived artifacts.
  It binds both input JSON files, complete artifact hashes, ELF headers,
  program headers, sections, GNU Build IDs, DWARF and symbol-table presence,
  and the full/stripped equivalence proof.
- `oracle/gcc/toolchain-reproduction.schema.json` keeps a current,
  independently checked reproduction identity separate from the historical
  image identity in the artifact build record. It locks the build-record and
  Dockerfile bytes, base image, platform, source date, reproduced OCI config,
  and every ordered rootfs diff ID.

The Python verifier treats every object as closed even when a JSON Schema
library is not installed. Duplicate keys, missing fields, extra fields,
noncanonical paths, source-lock drift, and malformed hashes are errors.
Artifact paths stay below the manifest directory and may not be symlinks.

The build record stores commands as argument arrays, never shell snippets.
The `stageFull` command uses `{full}` exactly once. The `strip` command uses
both `{full}` and `{stripped}` exactly once and must request `--strip-all` or
`-s`. A production build runner substitutes those placeholders with the
locked output paths without shell evaluation.

At minimum, `tools` has sorted, unique `compiler`, `linker`, and `stripper`
roles. Each tool record contains:

- an absolute path and exact version-command argument vector;
- the complete, exact version output;
- the executable byte length and SHA-256 hash.

The container tag and digest are separate fields. A tag is useful to humans;
only the `sha256:<64 lowercase hex>` digest identifies the environment. The
controlled variables must include `LC_ALL=C`, `TZ=UTC`, and a positive decimal
`SOURCE_DATE_EPOCH`. Secret-bearing environment variables are rejected.

## Verify the live build environment

Run this inside the exact container that will perform the build. Supply the
same independently resolved image digest used to start it:

```bash
python3 scripts/verify-gcc-oracle-build-record.py \
  --source-lock oracle/gcc/16.2.0/source-lock.json \
  --build-record oracle/gcc/16.2.0/build-record.json \
  --container-digest sha256:<reproduced-image-digest> \
  --reproduction-lock oracle/gcc/16.2.0/toolchain-reproduction.json
```

This gate validates the build record against the source lock, requires a
Linux x86-64 runtime, hashes the live tool executables, runs each absolute
version command under the recorded deterministic environment, and compares
its complete output. The caller supplies the image digest because a process
inside a container cannot securely infer the digest used by the outer
runtime.

Build the recorded toolchain image from the pinned Dockerfile frontend,
official GCC image, and Debian snapshot with a fixed source date:

```bash
docker buildx build \
  --no-cache \
  --platform linux/amd64 \
  --build-arg SOURCE_DATE_EPOCH=1786060800 \
  --load \
  --tag decomp-gcc-oracle-toolchain:16.2.0 \
  --file oracle/gcc/16.2.0/build-toolchain.Dockerfile \
  oracle/gcc/16.2.0

docker image inspect --format '{{.Id}}' decomp-gcc-oracle-toolchain:16.2.0
```

Authenticate the resulting inspect response against the reproduction lock:

```bash
docker image inspect decomp-gcc-oracle-toolchain:16.2.0 \
  | python3 scripts/verify-gcc-toolchain-reproduction.py \
      --lock oracle/gcc/16.2.0/toolchain-reproduction.json \
      --build-record oracle/gcc/16.2.0/build-record.json
```

The historical artifact origin remains
`sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248`.
Current no-cache hosted builds deterministically produce
`sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511`.
The separate lock approves that reproduction only when the Dockerfile and
build record have their exact checked hashes, all `FROM` instructions use the
locked base digest, the OCI config hashes exactly, and all nine ordered rootfs
diff IDs match. Any drift fails closed even if a mutable tag has the expected
name.

This does not relabel the historical artifacts or claim that the two OCI
config blobs are byte-identical. The original image config blob is not
available from hosted CI, so equality is established at the reproducible
recipe/rootfs and exact live tool-byte/version boundaries. The Dockerfile
itself has SHA-256
`8b0af79ba3426f49ba599eb0c7eea433c62ac5bb6ab5e7797f7d09d978f43543`.
The discarded download stage verifies exact Debian package hashes; the final
layer copies only the required headers, libraries, and notices and normalizes
all changed timestamps to `SOURCE_DATE_EPOCH`.

## Produce and verify the pair

The build must start from the already verified GCC 16.2.0 source archive and
run the argument vectors from the build record. Stage the linked `gcc` driver
as the full artifact before altering it. Derive the second artifact only by
running the recorded stripping command against that staged full artifact.

The rebuild driver performs that complete sequence without shell-evaluating
the recorded commands. It requires a nonexistent workspace, verifies the
signed archive and live image/tool identities first, clears the build
environment to the recorded allowlist, disables container networking, and
compares the regenerated manifest byte-for-byte with the checked-in one:

```bash
python3 scripts/fetch-gcc-oracle-source.py /tmp/gcc-oracle-cache
python3 scripts/rebuild-gcc-oracle.py \
  --source-cache /tmp/gcc-oracle-cache \
  --workspace /tmp/gcc-oracle-clean-build
```

Set `DOCKER=/path/to/docker` or pass `--docker /path/to/docker` when the CLI is
not named `docker`. The workspace is deliberately retained on failure for
inspection; choose a new path for every independent rebuild. The rebuild
runner requires Python 3.12 or newer so archive extraction always uses the
explicit PEP 706 `data` filter in addition to its own canonical-path and link
preflight.

Keep `source-lock.json`, `build-record.json`, the artifacts directory, and the
eventual manifest under the same version directory. Then create the manifest:

```bash
python3 scripts/create-gcc-oracle-manifest.py \
  --source-lock oracle/gcc/16.2.0/source-lock.json \
  --build-record oracle/gcc/16.2.0/build-record.json \
  --output oracle/gcc/16.2.0/oracle-manifest.json
```

Manifest creation is fail-closed: no output is accepted unless all pair gates
pass. A later verification recomputes every recorded field from disk:

```bash
python3 scripts/verify-gcc-oracle-artifacts.py \
  oracle/gcc/16.2.0/oracle-manifest.json
```

Both commands emit a short deterministic summary with the complete artifact
hashes, shared Build ID, executable-byte count, and executable-byte hash.
The checked-in manifest is formatted with sorted keys and stable indentation;
generating it again from unchanged inputs produces identical bytes.

## Facts derived from each ELF

The parser reads ELF bytes directly and supports ELF32/ELF64 and both byte
orders, including extended header counts. For the GCC oracle pair it requires
little-endian x86-64 ET_EXEC or ET_DYN artifacts. It records:

- complete file size and SHA-256;
- ELF class, encoding, ABI, type, machine, flags, entry point, and complete
  section/program-header table coordinates;
- every program header and a hash of its file-backed range;
- every section header, allocation/execution flags, and a content hash for
  every file-backed section (`SHT_NOBITS` records `null`);
- the GNU Build ID decoded from the ELF note;
- DWARF section names and static/dynamic symbol-table entry counts;
- the ordered indexes, total bytes, and aggregate SHA-256 of every nonempty
  `PT_LOAD` segment carrying `PF_X`.

The aggregate executable hash covers the complete file-backed executable-load
bytes, including alignment/padding within those segments—not only named
`.text` sections.

## Pair invariants

Manifest creation and verification require all of the following:

1. The full and stripped complete-file hashes differ, and the stripped file is
   smaller.
2. Their ELF identity and complete program-header layout are identical.
3. Each contains exactly one identical GNU Build ID.
4. At least one file-backed executable `PT_LOAD` exists, and every selected
   segment byte is identical.
5. Every allocated section has the same identity, address, size, linking
   fields, and contents.
6. The full artifact contains DWARF info, abbreviation, and line sections plus
   a static symbol table.
7. The stripped artifact contains neither DWARF sections nor a static symbol
   table.
8. Full-only, stripped-only, and changed common nonallocated sections are
   recorded as the explicit metadata delta.

A non-executable `PT_LOAD` often contains the ELF header. Stripping must change
section-table coordinates in that header, so the verifier records hashes for
all program-segment ranges but uses only program-header fields and
`PT_LOAD/PF_X` bytes for pair identity. Allocated sections are compared
separately. This distinguishes legitimate metadata removal from changed code
without silently ignoring loaded data.

## Tests

The test suite builds a tiny local ELF with debug information and a GNU Build
ID, derives a `--strip-all` twin, and exercises the same production verifier:

```bash
python3 -m unittest tests.oracle.test_gcc_oracle_artifacts -v
```

Mutation cases cover executable-load bytes, allocated data, Build IDs,
nonallocated DWARF bytes, incomplete stripping, complete artifact hashes,
source-lock binding, tool executable hashes, duplicate/unknown JSON fields,
and deterministic CLI output. Run the complete oracle test group with:

```bash
python3 -m unittest discover -s tests/oracle -v
```

## Recorded production result

Independent clean extractions and out-of-tree builds reproduced both files
byte-for-byte. The checked-in facts, all recomputed by the manifest verifier,
are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| DWARF-rich driver | 20,713,760 | `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` |
| stripped twin | 2,349,296 | `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |

Both files carry GNU Build ID
`df5e4869383c150bbb3aab0ebac4eacb1dcd07d0`. Their 1,096,393 file-backed
executable bytes have SHA-256
`0c2639a4c2e662205c79515424f1d4b28fb2d6602324ce10c0b575ca3d312499`.
The rich file has DWARF and a static symbol table; the stripped twin has
neither. The checked-in workflow fetches and fully verifies the exact signed
source release, rebuilds and authenticates the toolchain image, authenticates
the matching Docker 29.7.2 client and rootless extras before starting its
unprivileged daemon, and verifies the formal schemas, production manifest,
complete artifact hashes, and every recorded ELF relationship on pushes and
pull requests.

The executable pair is derived from GPL-licensed GCC sources. Exact source
bytes, signatures, signer identity, license texts, and the complete rebuild
recipe are identified by the adjacent lock and build record. Distributors of
the binaries must preserve the applicable notices and satisfy the source-code
provision obligations described there.

An installed distribution GCC—even one reporting version 16.2.0—is not a
substitute: downstream patches, PGO/LTO, stripping, and unavailable matching
build inputs prevent it from serving as this source-aligned benchmark oracle.

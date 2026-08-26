# GCC oracle artifact verification

Issue #38 requires one source-aligned GCC driver in two forms: an unstripped,
DWARF-rich reference and a stripped twin with identical loaded code. The
source release is already pinned by
`oracle/gcc/16.2.0/source-lock.json`. This document describes the independently
verifiable build-record and ELF-manifest boundary that follows that source
lock.

No GCC oracle binaries or production build record are checked in yet. The
local binaries built by the unit tests are deliberately small fixtures, not
the GCC oracle and not evidence that issue #38 is complete.

## Versioned formats

Two closed JSON formats are enforced by the standard-library verifier:

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
  --container-digest sha256:<immutable-image-digest>
```

This gate validates the build record against the source lock, requires a
Linux x86-64 runtime, hashes the live tool executables, runs each absolute
version command under the recorded deterministic environment, and compares
its complete output. The caller supplies the image digest because a process
inside a container cannot securely infer the digest used by the outer
runtime.

## Produce and verify the pair

The build must start from the already verified GCC 16.2.0 source archive and
run the argument vectors from the build record. Stage the linked `gcc` driver
as the full artifact before altering it. Derive the second artifact only by
running the recorded stripping command against that staged full artifact.

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

## Work still required for the real GCC pair

The model and verifier intentionally do not choose unreviewed production
values. Issue #38 still needs:

1. Select and lock the immutable build image, bootstrap compiler/binutils, GCC
   configuration, and exact build/install/staging commands in a real
   `oracle/gcc/16.2.0/build-record.json`.
2. Perform a clean out-of-tree build from the verified upstream archive at
   commit `78d4ac73dd391005b895a6148cd9831e28e1208b` and preserve the unmodified
   DWARF-rich driver.
3. Derive the stripped artifact only from that driver, run both verifier
   commands, and review the generated manifest.
4. Choose a repository/release storage mechanism suitable for the artifact
   sizes and redistribution obligations.
5. Add the retained pair to CI (or fetch it by immutable hash) and execute the
   live build-record and artifact-manifest gates there.

An installed distribution GCC—even one reporting version 16.2.0—is not a
substitute: downstream patches, PGO/LTO, stripping, and unavailable matching
build inputs prevent it from serving as the source-aligned oracle.

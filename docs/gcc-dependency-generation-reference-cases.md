# GCC preprocessing and dependency-generation references

`oracle/gcc/16.2.0/preprocessing-reference-evidence.json` (issue #709) and
`oracle/gcc/16.2.0/dependency-generation-reference.json` (issue #710), together
with the metadata and diagnostic record described below (issue #706), are
captured from real GCC 16.2.0 by `scripts/capture-gcc-preprocessing-reference.py`.

## Execution environment

Preprocessing and dependency-generation cases run the installed
`/usr/local/bin/gcc` and its `cc1`. All metadata cases run the oracle driver
described below instead. Every case runs inside the pinned
official image `docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0`
(config `sha256:103614947d5e…`), which is the base image of
`oracle/gcc/16.2.0/build-toolchain.Dockerfile`. The container has no network, a
read-only root filesystem, no capabilities and `no-new-privileges`; it sees only
a fresh per-case workspace. Preprocessing and dependency cases pass `-nostdinc`
so only staged include roots are searched, and `LC_ALL=C`, `TZ=UTC` and `SOURCE_DATE_EPOCH=1786060800` are
fixed. The script verifies the image config digest and records the driver and
`cc1` hashes, version and target triple.

Each case runs twice in separate workspaces; the capture fails unless stdout,
stderr, exit status and produced artifacts are byte-identical. No normalization
is applied.

## Cases

Preprocessing: file and stdin input (with and without `-x c`), quote,
bracket, `#include_next` and `-isystem` search, a missing header, command-line
and in-source macro definition/undefinition, `-dD` macro dumps, `#error`,
assembler-with-cpp by `-x` and by `.S` suffix, `.i` input, and `-x c` with `-o`.

Dependency generation: `-M` on the corpus `source.c`, `-M` versus `-MM` with a
system header, `-E -MD -MF` with both artifacts, `-MT` with `-MP`, `-MQ`
quoting, `-MG` for a missing header, and the missing-header diagnostic.

Metadata and diagnostics (`oracle/gcc/16.2.0/metadata-diagnostic-reference.json`,
issue #706): `--version`, `-dumpversion`, `-dumpfullversion`, `-dumpmachine`,
`-v`, `-print-search-dirs`, `-print-prog-name=cc1`, `-print-libgcc-file-name`,
`--help`, no input, a missing input file, `-o` without a filename, invalid `-x`,
`-std=` and `-march=` values, unrecognized long and `-f` options, a malformed C
source and a malformed link input. These cases do not pass `-nostdinc`.

Every metadata case records `driver: oracle` and runs
`oracle/gcc/16.2.0/artifacts/gcc-driver.stripped`, checked against
`oracle-manifest.json` and mounted read-only at `/oracle/install/bin/gcc`.
Its target, configuration and driver-only query output agree with
`behavior-corpus.json`.

The missing-file, invalid `-march` and malformed-source cases also mount the
original oracle's `cc1` read-only at its configured libexec path. The checked
`artifacts/gcc-cc1.stripped.xz` is a lossless XZ encoding (`lzma`, preset 6) of
`cc1-oracle-manifest.json`'s stripped artifact: 41,935,768 decoded bytes, SHA-256
`e51bf6e3f3300d31ce9713e2160c6fe5895d1e4914fb25562c3542b161427905`.
Extraction is bounded, rejects trailing bytes, and verifies the artifact,
build record and source lock before exposing the executable. The frontend and
driver must share the exact source revision and source-lock identity. This
provides the real original frontend for local and hosted reproduction without
an external artifact download.

The malformed-link case uses the oracle driver with the pinned image's real
`collect2` and `ld`. Its explicit `COMPILER_PATH` and `LIBRARY_PATH` are recorded,
as are both helper paths, resolved paths, sizes and hashes under `linkSupport`.
The original install tree and libgcc are not retained; driver-only queries have
no helper environment or mounts, so `-print-prog-name=cc1` and
`-print-libgcc-file-name` still report bare names and `-v` has no
`COLLECT_LTO_WRAPPER` line.

The record's `identitySubstitutions` lists the only differences a candidate may
show, each with patterns that bound the replaceable span: the driver basename in
diagnostic prefixes, the `--version` banner and the `--help` usage text; the
invocation `argv[0]` in the `-v` `COLLECT_GCC=` line; and the install prefix in
path output and the complete `--prefix=` configure argument in `-v`. The capture
re-runs every metadata case through a symlinked driver named `candidate-cc` and fails unless the driver-name substitutions account for
every difference. Substitutions match the original output only; replacement values
are not searched again. Earlier rules own overlapping spans, so an explicitly
substituted `argv[0]` remains independent of the configured install prefix even
when the invocation path contains the original prefix. Everything else must
match byte-for-byte.

## Reproduction

```sh
python3 scripts/capture-gcc-preprocessing-reference.py --runtime podman   # rewrite
python3 scripts/capture-gcc-preprocessing-reference.py --check            # compare
```

CI runs `--check` in the `preprocessing-reference` job of
`.github/workflows/gcc-oracle-model.yml` on dispatch, on master pushes, and on
pull requests labeled `qualify:preprocessing-reference`.

## Boundary

The preprocessing and dependency-generation records use the official image's
GCC 16.2.0 frontend. Every metadata case executes the manifest-verified oracle
driver; frontend-dependent metadata cases execute its manifest-verified original
`cc1`. The malformed-link case deliberately uses the pinned image's real linker
helpers, identified separately. These captures remain reference evidence:
authenticated Kotlin execution ownership, complete phase/runtime enforcement,
and comparison against an immutable reconstructed candidate remain required by
the parent workflow. No Ghidra analysis, `GHIDRA_HOME` fallback or
`analyzeHeadless` invocation is introduced, and no authority crosses the
oracle/candidate boundary.

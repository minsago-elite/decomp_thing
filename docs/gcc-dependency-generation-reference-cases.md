# GCC preprocessing and dependency-generation references

`oracle/gcc/16.2.0/preprocessing-reference-evidence.json` (issue #709) and
`oracle/gcc/16.2.0/dependency-generation-reference.json` (issue #710), together
with the metadata and diagnostic record described below (issue #706), are
captured from real GCC 16.2.0 by `scripts/capture-gcc-preprocessing-reference.py`.

## Execution environment

Every case runs the installed `/usr/local/bin/gcc` and its `cc1` inside the pinned
official image `docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0`
(config `sha256:103614947d5e…`), which is the base image of
`oracle/gcc/16.2.0/build-toolchain.Dockerfile`. The container has no network, a
read-only root filesystem, no capabilities and `no-new-privileges`; it sees only
a fresh per-case workspace. `-nostdinc` is passed so only staged include roots
are searched, and `LC_ALL=C`, `TZ=UTC` and `SOURCE_DATE_EPOCH=1786060800` are
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
source and a malformed link input. These cases do not pass `-nostdinc`. The
record's `identitySubstitutions` lists the only differences a candidate may
show: the driver program name in diagnostic prefixes and the install prefix in
path output. Everything else must match byte-for-byte.

## Reproduction

```sh
python3 scripts/capture-gcc-preprocessing-reference.py --runtime podman   # rewrite
python3 scripts/capture-gcc-preprocessing-reference.py --check            # compare
```

CI runs `--check` in the `preprocessing-reference` job of
`.github/workflows/gcc-oracle-model.yml` on dispatch, on master pushes, and on
pull requests labeled `qualify:preprocessing-reference`.

## Boundary

The frontend is the official image's GCC 16.2.0, not the byte-identical
`artifacts/gcc-driver.stripped` oracle driver, so these records establish real
GCC frontend semantics rather than oracle-artifact identity. Comparing a
reconstructed candidate driver against them remains downstream work. No Ghidra
analysis, `GHIDRA_HOME` fallback or `analyzeHeadless` invocation is introduced,
and no authority crosses the oracle/candidate boundary.

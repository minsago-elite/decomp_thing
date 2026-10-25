# GCC preprocessing and dependency-generation references

`oracle/gcc/16.2.0/preprocessing-reference-evidence.json` (issue #709) and
`oracle/gcc/16.2.0/dependency-generation-reference.json` (issue #710), together
with the metadata and diagnostic record described below (issue #706), are
captured from real GCC 16.2.0 by `scripts/capture-gcc-preprocessing-reference.py`.

## Execution environment

Preprocessing, dependency-generation and `image`-driver metadata cases run the
installed `/usr/local/bin/gcc` and its `cc1`; `oracle`-driver metadata cases run
the oracle driver described below instead. Every case runs inside the pinned
official image `docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0`
(config `sha256:103614947d5e…`), which is the base image of
`oracle/gcc/16.2.0/build-toolchain.Dockerfile`. The container has no network, a
read-only root filesystem, no capabilities and `no-new-privileges`; it sees only
a fresh per-case workspace. Preprocessing and dependency cases pass `-nostdinc`
so only staged include roots are searched, and `LC_ALL=C`, `TZ=UTC` and `SOURCE_DATE_EPOCH=1786060800` are
fixed. The script verifies the image config digest and records the driver and
`cc1` hashes, version and target triple.

Each case runs twice in separate workspaces; the capture fails unless stdout,
stderr, exit status and produced artifacts are byte-identical. Only the phase
orchestration record normalizes anything (driver temporary-file names, below).

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

Each metadata case records its `driver`. Driver-only cases (`oracle`) run
`oracle/gcc/16.2.0/artifacts/gcc-driver.stripped`, checked against
`oracle-manifest.json` and mounted read-only at its configured
`/oracle/install/bin/gcc`. Their target triple (`x86_64-pc-linux-gnu`), `-v`
configuration and search directories are therefore the oracle's own, and agree
with `behavior-corpus.json`. The oracle install tree is not retained, so
`-print-prog-name=cc1` and `-print-libgcc-file-name` report bare names, and `-v`
has no `COLLECT_LTO_WRAPPER` line. The missing-file, `-march=`,
malformed-source and malformed-link cases need `cc1`, `collect2` or `ld`. They
run the image's GCC (`image`), and their output names no target or prefix.

The record's `identitySubstitutions` lists the only differences a candidate may
show, each with patterns that bound the replaceable span: the driver basename in
diagnostic prefixes, the `--version` banner and the `--help` usage text; the
invocation `argv[0]` in the `-v` `COLLECT_GCC=` line; and the install prefix in
path output and the complete `--prefix=` configure argument in `-v`. The capture
re-runs every metadata case through a symlinked driver named `candidate-cc` and fails unless the driver-name substitutions account for
every difference. Everything else must match byte-for-byte.

Phase orchestration (`oracle/gcc/16.2.0/orchestration-phase-reference.json`,
issue #712): compile to assembly, compile to object (plain, `-pipe`,
`-save-temps`), assemble `.s`, preprocess-and-assemble `.S`, link one source,
two C sources, and mixed C plus assembly, the default `a.out` output, and
failure propagation from `cc1`, from `as` on a source file, from `as` after a
successful compile, and from the linker on an undefined symbol. Each repetition
runs `gcc -###` (the planned phases), `gcc -v` (the phases actually started; a
failing phase stops the rest) and the plain command (exit status, streams and
artifacts), then runs any linked program in the same sandbox and records its
exit status and output. `toolchain.phaseTools` records the path, resolved path
and hash of `cc1`, `as`, `collect2`, `ld`, `lto-wrapper` and `liblto_plugin.so`,
plus the binutils versions. Driver temporaries (`/tmp/ccXXXXXX.s` and so on)
come from `mkstemp`, so plans, traces and streams replace them with `<tmp-N>`
by order of first appearance; artifacts are never normalized. Every container
gets a tmpfs `/tmp`, so Docker and Podman pick the same temporary directory.
Each phase records its `argv` without the driver's trailing ` |` pipeline
connector; `stdoutPipedToNextPhase` says whether its output feeds the next
phase. These cases do not pass `-nostdinc`.

## Reproduction

```sh
python3 scripts/capture-gcc-preprocessing-reference.py --runtime podman   # rewrite
python3 scripts/capture-gcc-preprocessing-reference.py --check            # compare
```

CI runs `--check` in the `preprocessing-reference` job of
`.github/workflows/gcc-oracle-model.yml` on dispatch, on master pushes, and on
pull requests labeled `qualify:preprocessing-reference`.

## Boundary

The preprocessing and dependency-generation records, and the four `image`-driver
metadata cases, use the official image's GCC 16.2.0 frontend rather than the
byte-identical `artifacts/gcc-driver.stripped` oracle driver, so they establish
real GCC frontend semantics rather than oracle-artifact identity. The 15
`oracle`-driver metadata cases execute the manifest-verified oracle driver itself
and so describe oracle-artifact behavior. Comparing a
reconstructed candidate driver against them remains downstream work. No Ghidra
analysis, `GHIDRA_HOME` fallback or `analyzeHeadless` invocation is introduced,
and no authority crosses the oracle/candidate boundary.

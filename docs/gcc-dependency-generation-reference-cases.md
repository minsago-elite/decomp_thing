# GCC preprocessing and dependency-generation references

`oracle/gcc/16.2.0/preprocessing-reference-evidence.json` (issue #709) and
`oracle/gcc/16.2.0/dependency-generation-reference.json` (issue #710), together
with the metadata and diagnostic record described below (issue #706), are
captured from real GCC 16.2.0 by `scripts/capture-gcc-preprocessing-reference.py`.

## Execution environment

Preprocessing and dependency-generation cases run the installed
`/usr/local/bin/gcc` and its `cc1`. Metadata and phase-orchestration cases run the
manifest-pinned oracle driver and frontend described below. Every case runs inside the pinned
official image `docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0`
(config `sha256:103614947d5e…`), which is the base image of
`oracle/gcc/16.2.0/build-toolchain.Dockerfile`. The container has no network, a
read-only root filesystem, no capabilities and `no-new-privileges`. Host access
is restricted to a fresh per-case workspace and declared read-only oracle artifact
mounts. Preprocessing and dependency cases pass `-nostdinc`
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

Orchestration executes the original `gcc-driver.stripped` and manifest-pinned
`cc1`, mounted at their configured oracle paths. The cleared environment fixes
`PATH`, locale, timezone and source epoch. `COMPILER_PATH` selects the original
frontend directory first, then the pinned image's helper directory;
`LIBRARY_PATH` selects the pinned image's GCC and system runtime objects, and
`C_INCLUDE_PATH` explicitly supplies its builtin headers. The selected helpers,
library environment and include directory are part of the reference contract;
the original unretained install tree is not silently substituted.

Every container invocation first verifies the pinned image config, including
identity queries. The orchestration reference accepts only its fixed case
arguments and staged inputs. Unknown or malformed planned commands fail the
capture, and parsed phase executable paths must match the declared tool paths
or explicit `PATH` names. The complete verbose transcript is retained so its
reported phase observations can be independently parsed.

`toolchain.runtimeClosure` records the ELF bytes, interpreter, resolved loader
and transitive startup libraries for the driver and each phase tool, including
the linker plugin. The probe uses the pinned image's `readelf` and glibc loader
in `--list` mode; inspected programs are not started by the probe. Unexpected
interpreters, RPATH/RUNPATH, unresolved libraries and libraries outside image
roots fail capture. The kernel-provided vDSO is identified by name, not by an
image file hash. This inventory describes startup loading, not arbitrary later
`dlopen` activity.

Each produced executable has its own runtime closure tied to the captured
artifact hash. Execution uses a separate container with the workspace mounted
read-only; the launcher rechecks executable, interpreter and library bytes,
then starts only the declared output with the retained exact argv, cwd and
cleared environment. Launcher failure aborts capture, separately from a valid
nonzero program exit. Both repetitions must retain identical runtime identities
and behavior. The reference policy and probe source digest are recorded beside
the cases.

These checks establish the reference invocation contract. GCC's verbose report
does not independently observe internal `collect2` to `ld` execution or plugin
loading. Execution receipts and enforcement for an untrusted reconstructed
candidate belong to the downstream qualification in issues #713–#715; candidate
comparison is not a prerequisite for the reference declaration in #712. The
separate Kotlin-only release migration in #136 retains its authority boundary;
this reference capture does not itself certify a Kotlin-only release.

## Closed orchestration declaration

`orchestration-identity-contract.json` version 2 replaces the earlier mock-tool
declaration. It binds the original driver and frontend manifests, their source
and build inputs, the real reference capture, the source-defined case inventory,
phase executable identities, startup dependencies and exact required argument
vectors. The historical `behavior-corpus.json` and its forwarding observations
retain their original scope.

The verifier takes expected facts from the reviewed reference digest and current
repository-owned case definitions, not from a proposed contract. It reparses the
retained plan and verbose transcripts and requires the declared phases and pipe
edges to match. Verbose compiler commands may add only the documented positional
`-v` and `-version` flags; assembler commands may add `-v` immediately after the
executable, and linker arguments must match exactly. Failed cases may stop at a
nonempty prefix of the plan; successful cases must include every planned phase.
Unknown paths, additional arguments, reordered inputs, changed environment and
self-rehashed reference substitutions fail closed.

Verify the checked declaration with:

```sh
python3 -m oracle.gcc.orchestration_contract
```

Changing reference expectations requires a new reviewed real capture and live
replay before updating the separately pinned reference digest and regenerating
the declaration. This gate validates the reference declaration; downstream
candidate execution and acceptance remain separate.

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

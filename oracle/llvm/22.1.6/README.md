# LLVM 22.1.6 Clang oracle

This profile is the source-aligned Clang counterpart to the GCC oracle. It
pins the signed upstream LLVM 22.1.6 release, rebuilds a monolithic X86 Clang
driver in a closed Ubuntu/LLVM/CMake/Ninja environment, and checks in two
code-identical ELF artifacts:

- `artifacts/clang-driver.full` retains zlib-compressed DWARF and `.symtab`;
- `artifacts/clang-driver.stripped` removes DWARF and static symbols without
  changing allocated sections, executable load bytes, ELF identity, or the
  GNU Build ID.

The artifact files use Git LFS. Run `git lfs install` before cloning or use
`git lfs pull` after installing LFS. Verification rejects pointer files and
any artifact, source-lock, build-record, or manifest byte change.

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

## Verify

Install the exact Python generation dependencies, then run:

```sh
python3 -m pip install -r requirements/oracle-generation.txt
python3 scripts/verify-llvm-oracle-source.py --metadata-only
python3 scripts/fetch-llvm-oracle-source.py /tmp/llvm-oracle-source
python3 scripts/verify-llvm-oracle-artifacts.py \
  oracle/llvm/22.1.6/oracle-manifest.json
python3 scripts/create-llvm-oracle-manifest.py \
  --source-lock oracle/llvm/22.1.6/source-lock.json \
  --build-record oracle/llvm/22.1.6/build-record.json \
  --output /tmp/llvm-oracle-manifest.json
cmp /tmp/llvm-oracle-manifest.json \
  oracle/llvm/22.1.6/oracle-manifest.json
python3 scripts/generate-llvm-function-recovery-oracle.py \
  --manifest oracle/llvm/22.1.6/oracle-manifest.json \
  --exclusions oracle/llvm/22.1.6/function-recovery-exclusions.json \
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

The manual `LLVM oracle clean rebuild` workflow is the canonical clean-room
rebuild. It constructs the pinned toolchain image, fetches and authenticates
the upstream archive, disables network access for compilation, executes every
command recorded in `build-record.json`, and uploads the full/stripped pair,
tool records, and image digest for review. A rebuilt pair is not accepted
until manifest generation and every verification command above pass.

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

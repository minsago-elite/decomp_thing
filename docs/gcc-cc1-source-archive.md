# cc1 reconstruction archive evidence

Issue #1052 owns the cc1 source archive boundary. The focused verifier at
`scripts/verify-gcc-reconstruction-archive.py` consumes two accepted archive
outputs, authenticates the checked `compiler-engines.json` control plane, and
writes one bounded JSON receipt:

```sh
python3 scripts/verify-gcc-reconstruction-archive.py \
  --profile oracle/gcc/16.2.0/compiler-engines.json \
  --engine cc1 \
  --archive /evidence/cc1-reconstruction.zip \
  --repeat-archive /evidence/cc1-reconstruction-repeat.zip \
  --evidence /evidence/cc1-source-archive-evidence.json
```

The command binds the source lock, base and cc1 build records, toolchain
reproduction record, and cc1 oracle manifest to their checked SHA-256 values.
It then requires the source-tree manifest and program model to identify the
authenticated cc1 stripped artifact. Both archives must have the bounded
stored ZIP format and a complete `ARCHIVE_MANIFEST.sha256`. Each archive is
extracted into a new temporary directory, its recorded Make command is run
with a sanitized deterministic environment, and the rebuilt executable is
compared with the accepted build contract. The receipt retains archive,
source-revision, source/build/validation/toolchain, dependency, and executable
hashes for both runs.

This is an archive-boundary check. It does not authorize Ghidra execution and
does not convert the current non-authoritative planner output into a completed
reconstruction. A real cc1 qualification still needs a bundled-Ghidra fresh
reconstruction, the parent engine interruption/resume equivalence evidence,
and independently retained authenticated compiler/toolchain observations.
Until those fixtures are available, the receipt remains `complete=false` and
`releaseEligible=false`; it must be reported as evidence of clean extraction,
build, and byte reproduction only.

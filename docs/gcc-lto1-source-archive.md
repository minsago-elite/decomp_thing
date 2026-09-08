# lto1 source archive evidence

Issue #1053 owns the lto1 source archive boundary. The checked GCC control
plane already identifies the accepted lto1 input and the clean-build commands:

- `oracle/gcc/16.2.0/source-lock.json` authenticates the GCC 16.2.0 source
  archive, release tag, signer, and redistribution notices.
- `oracle/gcc/16.2.0/lto1-build-record.json` binds the lto1 build to that
  source lock, the declared container digest, tool versions, configure and
  Make commands, and the full/stripped output paths.
- `oracle/gcc/16.2.0/lto1-oracle-manifest.json` retains the accepted ELF pair
  and its source/build identities.

The clean input checkpoint can be reproduced with the existing bounded runner
after an authenticated source cache has been provisioned:

```sh
python3 scripts/rebuild-gcc-compiler-engines.py \
  --workspace /absolute/path/to/clean-workspace \
  --source-cache /absolute/path/to/authenticated-cache \
  --candidate-manifest-root /absolute/path/to/candidates
```

That command authenticates and stages the lto1 ELF twin. It does not create or
verify an lto1 reconstruction source archive. The complete archive extraction,
clean configure/build/link replay, repeated archive-byte comparison, and
retained source/build/validation/toolchain receipt remain unverified for this
issue. A future archive-boundary implementation must keep the bundled Ghidra
runtime and authenticated oracle boundaries intact; the checked lto1 ELF pair
alone cannot qualify the reconstructed archive.

# lto1 source archive evidence

Issue #1053 owns the lto1 source archive boundary. The checked GCC control
plane already identifies the accepted lto1 input and the clean-build commands:

- `oracle/gcc/16.2.0/source-lock.json` authenticates the GCC 16.2.0 source
  archive, release tag, signer, and redistribution notices.
- `oracle/gcc/16.2.0/lto1-build-record.json` binds the lto1 build to that
  source lock, the declared container digest, tool versions, configure and
  Make commands, and the full/stripped output paths.
- `oracle/gcc/16.2.0/lto1-oracle-manifest.json` binds the accepted ELF pair's
  identities to the pair's source/build identities: each artifact's path,
  size, and SHA-256 hash plus derived ELF metadata. It does not retain the
  pair; the lto1 ELF binaries are not checked in.

The clean-build commands are replayed through the checked rebuild entry
point:

```sh
python3 scripts/rebuild-gcc-compiler-engines.py \
  --workspace /absolute/path/to/clean-workspace \
  --source-cache /absolute/path/to/authenticated-cache \
  --candidate-manifest-root /absolute/path/to/candidates
```

That command authenticates and stages the lto1 ELF twin only where the
historical build runtime is already loaded, so it is an evidence pointer
rather than a reproducible checkpoint in a fresh environment. The runner
authenticates the tagged image against the build record's historical
`sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248`,
which is unpublished, while a fresh no-cache build of the pinned Dockerfile
reproduces the separately locked
`sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511`
that the gate rejects. Provisioning an authenticated source cache alone
therefore does not make the command runnable; the supported fresh-environment
toolchain gate is the `toolchain-reproduction.json` verification described
in `docs/gcc-oracle-artifact-verification.md`.

The runner is not bounded: it hardens each container (no network, read-only
root filesystem, dropped capabilities) but starts recorded commands without
execution timeouts or memory/CPU/PID limits.

That command does not create or verify an lto1 reconstruction source archive.
The complete archive extraction,
clean configure/build/link replay, repeated archive-byte comparison, and
retained source/build/validation/toolchain receipt remain unverified for this
issue. A future archive-boundary implementation must keep the bundled Ghidra
runtime and authenticated oracle boundaries intact; the checked lto1 ELF pair
alone cannot qualify the reconstructed archive.

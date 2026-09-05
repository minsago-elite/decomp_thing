# LLVM toolchain CI build attempts

The LLVM model and clean-rebuild workflows invoke
`bash scripts/ci-build-llvm-toolchain.sh` before observing and verifying the
rebuilt image identity. The wrapper changes orchestration only: the Dockerfile,
reproduction lock, pinned base image, LLVM package version, key digest, schema
contracts and recorded-origin bindings are unchanged. Both attempts retain
`--no-cache`, `linux/amd64`, the fixed source-date epoch and the same build context.
Image inspection and all existing Kotlin recipe/runtime and retained-tool gates
still run only after a successful build command.

## Observed failure

[LLVM run 33937071376](https://github.com/minsago-elite/decomp_thing/actions/runs/33937071376)
started at 01:44:50 UTC on 2026-09-05 and was cancelled at 02:30:04 UTC while
reproducing the image. Its log shows Ubuntu package downloads still in progress
more than 2,500 seconds into the Dockerfile's installation step. LLVM's package
index was fetched only near the cancellation; the required retained Clang/LLD
test step never ran. This is not evidence of retained-tool success or failure.
Another completed run, 33937272832, failed on an Ubuntu package-index size/hash
mismatch during a mirror update. Retrying that build requires a fresh index,
not disabling package authentication or accepting stale inconsistent metadata.

## Attempt policy

- Each Docker client invocation has a 900-second command deadline. GNU `timeout`
  sends INT, then KILL after a further 30 seconds if needed; the supported options
  and exit statuses are documented in the [GNU Coreutils manual](https://www.gnu.org/software/coreutils/manual/coreutils.html).
- A normally returned status 1 permits one more invocation of the unchanged
  recipe, after a five-second delay. It does not certify that the failure was
  transient or that a second build will succeed.
- A second failure is returned unchanged. Timeout, signal, kill and launcher
  statuses do not trigger another attempt. No caller arguments can change the
  recipe, platform, context or deadline.
- The model workflow's 45-minute job ceiling is unchanged. Plain build progress
  remains visible in CI rather than hiding the stalled installation phase.

The deadline bounds the Docker client invocation, not a retained BuildKit daemon
lease or a proof of container absence. In particular a timed-out client must not
be interpreted as verified daemon-side completion: the wrapper fails the step
and does not retry it. Runner/job teardown remains responsible for CI resources.
No contained oracle-worker budget, cleanup policy, scoring flag or release
authority is relaxed. The wrapper cannot repair a continuously unavailable or
slow package mirror; fresh hosted evidence is still required.

## Verification

`LlvmToolchainBuildScriptTest` executes the actual shell wrapper with controlled
command stubs and with real GNU `timeout` around an immediate Docker stub. It
checks exact argv, successful completion, a single retry, exhaustion, timeout/
signal/launcher failure propagation, argument rejection, unchanged frozen recipe
digests and preserved workflow gates. It does not build a Docker image or prove
that hosted networking has recovered.

```bash
bash -n scripts/ci-build-llvm-toolchain.sh
./gradlew test \
  --tests decompengine.oracle.provenance.LlvmToolchainBuildScriptTest \
  --tests decompengine.oracle.provenance.LlvmToolchainReproductionTest
```

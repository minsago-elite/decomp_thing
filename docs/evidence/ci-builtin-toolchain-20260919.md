# Built-in contract CI frontend toolchain checkpoint — 2026-09-19

The [built-in contract job on PR #1380](https://github.com/minsago-elite/decomp_thing/actions/runs/35418667734/job/105832101957) failed before running its contract suites. Gradle's `verifyFrontendToolchain` found runner Node 22.23.2/npm 10.9.8 instead of the repository's pinned Node 24.20.0/npm 11.19.0. The frontend and ACP jobs already install the checksum-verified build-only toolchain; the built-in contract job did not.

This change installs that same pinned toolchain before the built-in contract validator runs. It does not change runtime Node requirements or relax any contract test.

Local preflight in the isolated issue worktree:

- Bun 1.3.1 checked that the pinned installer and `GITHUB_PATH` export precede validation.
- Python YAML parsing confirmed the workflow step order.
- `bash -n scripts/install-frontend-node.sh` passed.
- With the previously installed pinned distribution on `PATH`, `npm --prefix frontend run toolchain` passed.
- `git diff --check` passed.

The complete hosted built-in contract job and broader #652 frontend/JVM/packaged-smoke criteria have not been qualified by this local preflight. A local Gradle wrapper attempt was blocked because its default cache lock under `/home/june/.gradle` is read-only in this sandbox; the direct pinned toolchain check above did pass.

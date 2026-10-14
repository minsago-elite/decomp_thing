# Copy buffer ownership 002 — independent source review

Verdict: **CLEAR_SCOPED** for the two deterministic buffer-lifetime wrappers. No source blocker found; compilation/native execution and performance are not established.

GPT-6.1 Sol. Read-only source/hash inspection; no tests/JVM/compiler/native/network/Git/remote operations. Only this report written; root retains custody.

## Exact pins

Canonical worktree `.claude/worktrees/acp-private-control-concurrency`:

- `build/acp-copy-buffer-ownership-002/source-freeze.json`: `c9849b8dcc3d407de932d8f6d761af8813c0630c566a8751988681692ed129aa`.
- `LinuxFilesystemSyscalls.kt`: `b44838d94597c152793298af0fc7ce4e642ceddf6a559945b772e6352eaf7470`.
- Handoff: `7e6fb5ee3b3b45c544f28b22b61caa1d5d43197e54dc3f48de140d042b82ec3d`.
- Composed diff: `ddffbf693d080b934ba7c238c40f3c1cea0e0307cc95cbc5191c4a6819ea0ccd`.

Independently removed each Memory.use wrapper and reversed only indentation in memory. Full source restores exact original `16e8b7e668928bb426a278db5b3c6ed863f7de565b616ea80a56cece66c62c6c`; reversing only the OutputStream wrapper restores descriptor-only001 `5b758000b35ce15eea833481efe57ec3d11e8fc83adaf8ebac96441097c8b365`. Historical001 freeze remains `f401e3aa5ae1498f69c8c9490061c840fe22c8a850c838f18af01994f2d40215`.

## Assessment

Both copyReadableTo overloads now nest their existing16KiB JNA Memory inside `.use`, within the existing readable-FD `.use` (lines439–455 and466–498). Kotlin use's finally closes Memory on nonlocal EOF return and read/write/fsync/overflow/budget/cancellation exceptions, before the outer readable FD closes. Buffer allocation remains once per file, without pooling/sharing across operations. OutputStream receives copied byte arrays; native destination writes complete synchronously before buffer release, and shared pointer views do not escape the loop.

Caller-owned OutputStream and destination/authorized descriptors are not newly closed. Existing readable FD ownership remains unchanged. Exact loop-body comparison preserves byte limits, partial-write handling, retry/error checks, fsync and every cancellation callback position. No new explicit lock, external callback, reentrant call or lock escape appears. Native cleanup now occurs deterministically at scope exit; standard use cleanup/suppression semantics apply if close itself fails, so no claim of identical hypothetical cleanup-failure behavior is made.

All code outside these wrappers is byte-identical to the reviewed source, including CandidateA syscall/ownership and callback amendment. No compilation, leak measurement, speedup, memory-pressure result or25-second failure fix is claimed. Root may checkpoint the narrow source correction and retain required qualification gates.

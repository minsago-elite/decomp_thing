# Candidate A ENOENT classification — independent source review

Verdict: **CLEAR_SCOPED** for the tiny classification correction. No source blocker found. No new fallback, retry, authority or runtime qualification is introduced.

GPT-6.1 Sol. Read-only source/hash inspection; no tests/compiler/JVM/native/CI/auth/network/Git/remote execution. Only this report written. Root retains checkpoint/cherry-pick/execution custody.

## Exact pins

Canonical worktree `.claude/worktrees/acp-private-control-concurrency`:

- Freeze `build/acp-prelaunch-candidate-a-enoent-classification/source-freeze.json`: `a947d2ac898b499cbf422c851b84f5972765fff113fd72ee6e44e46bd16208ef`.
- Handoff: `f7b13dbf0afc51fa70ce4de6ede5e69d14f7a0e67e5f3058020364fa220e62aa`.
- Boundary after: `a9f7257adb589cac451f05ae46b319a1cc8848d3e18e3473e751e1d00e5364ff`.
- Exact delta: `886e5434472788ccb193d88e1f8b3e8d44c5d0c331b20040695ac2f9f1f545fb`.

All match. Independently reversed only the ENOENT catch and two missing-root message substitutions; the complete Boundary reconstructs exact prior candidate `5d2bd5cc1b43662f5b6a4a2a89d9e30ef3cc338eefac81861349b66c015f1052`. Syscalls remains `16e8b7e668928bb426a278db5b3c6ed863f7de565b616ea80a56cece66c62c6c`; seven-method SyscallsTest remains `09a49b8938364a4c3d75165525cacd5d5cec3ffd951d4cf428743f66977cce0b`.

## Assessment

Boundary1954–1959 catches only LinuxSyscallException from constrained root lookup. ENOENT is wrapped in `IOException("private-control descriptor pathname changed during inspection", failure)` with the original errno-bearing cause; every other errno is rethrown as the same exception. It does not return null, loop, retry or enter fallback. The existing anchor finally at1978 still closes on this throw. Primitive ENOSYS fallback and shared eight-attempt policy remain unchanged.

The two strict/root-only missing-tail branches at1948/1968 now use the same existing pathname-change classification. Generic traversal, identity/type/mount checks, final-symlink refusal, callbacks/arguments, budgets and physical coordinates are untouched. Thus this restores diagnostic classification while preserving refusal behavior.

Inspected the existing hostile regular-root replacement control at BoundaryTest1385–1400 (current file SHA `96d3b2d24bb200ab0f02d54bc213095d8b9f435bb401275859f1a1b5adbe1d53`). It requires replacement to occur, an IOException in an established pathname-change category, replacement bytes preserved and descriptor count recovered. No assertion was relaxed by this patch. Root reports the prior hosted failure denied replacement correctly but failed this classification assertion, and all seven syscall controls passed. This review did not independently retrieve/requalify that run; later native-probe gates were not reached, and the failed aggregate remains failed.

The prior scoped source/port reviews and no-NEW-external-callback amendment remain applicable. Fresh exact-source qualification must establish this regression passes and continue through all later required native/hostile/overlap/fallback/cleanup gates. No full ACP/provider/full-closure pass, measured speedup, issue closure or additional execution is authorized by this source verdict.

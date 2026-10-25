# Contained module compilation

`ContainedModuleCompilationPolicy` compiles one exact module before current source
acceptance. It is selected by the generated-C Make and Ninja adapters. The policy
accepts the registered descriptors and their admitted budget variants. The complete
selected descriptor is bound through the request and proof; only budgets may vary.
Compiler flags, executable wrappers, layouts, and adapter configuration stay fixed.
The caller-selected host policy admits the budgets before planning; the compiler
applies its own fixed ceilings to the requested compilation limits.

The compiler sees a private snapshot containing the candidate `.c` file and declared
public/private `.h` interfaces. Other implementations and reports are absent. Snapshot
members have bounded stable reads, single-link regular-file checks, a sorted manifest,
and exact byte hashes. Undeclared files in the project compiler search roots are
rejected, including shadow system headers and precompiled-header sidecars. The search
inventory and bytes are checked again before START, after execution, and when the
live permit is consumed. No header or prior-source read permission is added to ACP.

The operator supplies `GENERATED_C_MODULE_COMPILE_CONFIG_FILE`, or a root-owned
`GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY` containing the fixed
`generated-c-make-v1.json` and `generated-c-ninja-v1.json` names. The two selectors
cannot be combined. Each closed configuration identifies one built-in profile, pins
Java and boundary helpers, worker JARs, the compiler executable, finite compiler/header
runtime directories, the user manager's expected cgroup, and a dedicated bounded ext4
scratch policy. Runtime/configuration ancestors must be canonical and root-owned.
The application does not install or acquire additional compiler authority implicitly.

The current worker limits compilation to 30 seconds, 2 MiB total retained diagnostics,
4096 snapshot files, 16 MiB per file, 128 MiB total input, and a 64 MiB object. The outer
scope applies 512 MiB memory, 128 tasks, CPU/wall and file limits, denied network, and
finite scratch. Requested profile limits can only narrow the worker limits. The
operation deadline includes preparation, execution, capture, and cleanup. Its whole-second
limit rounds down, never up; budgets below two seconds fail closed. Missing
runtime, missing enforcement, or uncertain cleanup cannot produce accepted evidence.

A nondumpable Java worker derives the command from the registered profile and invokes
the pinned compiler through the native bounded process helper. It retains the raw
exit or signal, bounded diagnostic hashes, and a regular ELF `ET_REL` object's bytes
and hash. Timeout/output failures have no claimed raw exit status; empty retained logs
in those cases mean no captured bytes were available, not that nothing was emitted.

The outer keeper authenticates its request, exact child outcome, and hashes computed
from actual stdout/stderr pipe bytes. Replacing a writable capture file with an
equal-length result cannot satisfy those hashes. Strict request version 3 uses protocol
version 2; older request versions preserve their original protocol bytes. A strict
scope records all `pids.events` and `memory.events` keys before START and again while
frozen with only the original authenticated keeper processes. Missing or changed keys,
regressing counters, or any enforcing limit event fail closed, including a handled task
refusal followed by exit zero. Unit, cgroup, and process absence are proven before
bounded descriptor-owned scratch removal and lease release.

Checkpoint schema 7 retains the exact worker request/result, runtime declaration,
keeper request/attachment/execution, disk lease, and cleanup bindings. These are
historical evidence when reopened. Only the live coordinator can issue an acceptance
permit after cleanup. Application-owned instance admission rejects a constructor-created
clone even with identical proof bytes; the permit rechecks the candidate/header snapshot
before use. Cached source
and ACP evidence are reused only after current identity checks and a fresh contained
compilation. Compiler-only retries do not rewrite an already accepted ACP session as
rejected. Failed compilation, unexpected runtime errors, and cancellation preserve a
previous accepted source, checkpoint, receipt, and manifest.

This proves module-object compilation against the recorded closure. It does not prove
whole-project linking, entrypoint correctness, recovered ABI truth, behavior, production
ACP execution, or release readiness. The public generated-C repair validator remains
behind its separate qualification guard.

The reusable `Contained module compilation` Actions workflow is a prerequisite of
the always-running ACP required gate on the same revision. The ACP gate explicitly fails
when that prerequisite fails or is skipped. Its original Make/Ninja archive positive
runs in the compiler lane; every other ACP control retains the no-skip contract.
The workflow uses the existing installed Java,
generated-C runtime, and ext4 scratch helpers. New project artifacts and reports remain
under `build/module-compilation-qualification` and `build/reports`. Its required tests
exercise valid compilation, source/header binding, rejection rollback, real compiler
cancellation, historical replay separation, and a handled task-limit refusal. A fresh compiled-method inventory must exactly match the XML class/method results,
with no omitted, skipped, duplicated, failed, or cached controls. Missing
configured authority fails the lane. Local protocol and
worker tests are useful implementation evidence; they do not replace that hosted run.

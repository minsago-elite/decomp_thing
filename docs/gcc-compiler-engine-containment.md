# GCC compiler-engine pre-START containment contract

The old `gcc-engine-plan` path is diagnostic only. Its schema-2 document is permanently marked
`authority=non-authoritative-caller-supplied-analyzer-v1`, `complete=false`, and
`releaseEligible=false`. Schema 2 is intentionally incompatible with the former schema-1
`complete=true` document. The service has no public JVM constructor, but even reflective or
same-module use can produce only the schema-2 non-release assessment. Its descendant-process RSS
sampling is not cgroup accounting and is not accepted as A10 resource evidence.

`GccCompilerEngineContainmentContract` is the next, deliberately non-authoritative Kotlin
checkpoint. It defines canonical bounded bytes for three ordered states:

1. `PREPARED` binds the exact command vector and environment; all benchmark, Ghidra, exporter,
   Java, bubblewrap, resource-limiter, systemd-control, and BOOT-keeper artifacts; fresh or
   manifest-bound resume state; an inode/mount-bound owner-only output lease; and wall-clock,
   memory, and PID budgets. `interrupted` and `fresh-control` runs require `fresh-empty` state;
   only a `resumed` run may use, and must use, `resume-manifest` state.
2. `UNIT_ATTACHED_AT_BOOT` binds one kernel boot, one systemd invocation, the exact derived user
   manager control-group path, descriptor identity for the cgroup-v2 leaf, exact controller and
   systemd policy, a binding-derived BOOT nonce, and pidfd-pinned identities for the scope leader,
   namespace init, and Kotlin BOOT keeper.
3. `TERMINAL_ABSENT` binds the cleanup policy: issue systemd `SIGKILL` to all processes only when
   the exact retained target still exists, refuse mutation if that name was replaced, and use the
   retained pidfds as the process backstop. The receipt claims outcomes only for the unit load state
   `not-found`, no same-name unit or cgroup candidate, the cgroup path absent and unpopulated, every
   receipt process's pidfd dead, and two independent absence sweeps. If the exact scope was already
   absent, no systemd kill is issued or claimed as a historical event.

The contract accepts fresh raw canonical bytes at every assessment boundary. It never accepts a
prior assessment as a capability. Every returned object says
`non-authoritative-caller-supplied-containment-bytes-v1`, `releaseEligible=false`, and
`startAuthorized=false`. The raw receipt renderers are visibly test-only and their bytes are
forgeable.

The Kotlin `GccCompilerEngineLiveContainmentController` is a narrower production BOOT checkpoint.
Its raw-path facade authenticates the definition and exact packaged JVM closure, launches the fixed
three-process keeper topology in a descriptor/pidfd-pinned systemd/cgroup-v2 scope, durably records
the attachment, and returns one opaque cleanup-only owner. Pre-attachment failure rollback is a
definition-bound, descriptor-relative durable state machine; terminal publication rechecks the
immutable definition and attachment bytes before and after writing absence. There is still no
START, compiler execution, export, scoring, output-lease release, ACP authority, Python authority,
or cold reopen of an attached/terminal operation.

The hosted CI job provisions this runtime with `scripts/ci-prepare-oracle-runtime.sh` before any
live containment test. It copies the setup-java JDK into a separate root-owned `/var/lib` directory,
sets the test JVM's `JAVA_HOME`, and makes the fixed system-library trees recursively root-owned
without group or world write permission. This provisioning is specific to the disposable trusted
runner image: a mutable toolcache JDK or an untrusted entry anywhere under `/usr/lib` cannot serve
as the live runtime trust root. Production runtime validation keeps the same fail-closed checks.

Supervisor, observer, and BOOT-keeper JVMs explicitly set both JNA and Java temporary paths to the
existing bounded run `tmp` directory. JNA's Linux home-cache fallback is not an admitted output:
the exact lease layout and unknown-residue rejection remain unchanged. The shared user-bus pin
retains the runtime directory's device, inode, mount, owner, mode, and extended metadata, plus the
exact socket identity. Ordinary runtime-directory membership changes may update its size or mtime
without replacing the bus; those two directory-content fields are not endpoint identity. Directory
replacement, permission/extended-metadata changes, and socket replacement still fail closed.

The live test captures failure-only journal diagnostics before retained-owner cleanup. Its exact
user-unit, current-boot, and start-time filters select at most 80 events in newest-first order, so
a long startup command cannot consume the 16 KiB capture before a later termination message.
The existing three-second collection limit and one-second forced-exit grace remain unchanged.
These diagnostics grant no lifecycle authority. In
[CI run 33937775172](https://github.com/minsago-elite/decomp_thing/actions/runs/33937775172),
the exact unit journal reports both `Scope reached runtime time limit` and result `timeout`.
Attachment returned after about 85.7 seconds, and the first subsequent BOOT revalidation found the
scope absent. On that evidence, only the long retained-owner live lifecycle fixture now explicitly
requests 300 seconds instead of 60 seconds. Its expected live receipt must bind exactly that budget;
memory and PID limits are unchanged. Other fixtures retain their 60-second default, unsupported
budgets still fail before journal creation, and no production maximum or admission rule changes.
Hosted rerun evidence is still required to establish that the complete live lifecycle passes.

The shared test-only journal collector also supports exact deterministic full-tree unit names.
Three production full-tree BOOT tests additionally sample four allowlisted protocol files through
a pinned run-root descriptor before worker failure cleanup can remove them. They retain only the
first observation of each file, at most 4 KiB each, for at most five minutes. Links, nonregular files,
non-read-only modes and oversized records are rejected. On failure, observed records and the bounded
journal snapshot are attached as a suppressed diagnostic, preserving the original failure. The
sampler never sends START, writes protocol files, changes cleanup or authorizes a transition. This
is best-effort test diagnosis, not authenticated oracle evidence or a production lifecycle observer.
The three full-tree failures in that CI run have no proven cause yet; their existing production
timeouts and containment limits remain unchanged rather than assuming the GCC diagnosis applies.

The seven diagnostic regressions and explicit-budget regression run without a live systemd scope:

```bash
./gradlew test \
  --tests decompengine.oracle.fulltree.LiveOracleBootDiagnosticsTest \
  --tests 'decompengine.oracle.gcc.GccCompilerEngineLiveContainmentControllerTest.long live lifecycle fixture*'
```

The expanded locally available selection passes 45 tests, including existing containment-contract,
systemd-feature, cleanup and non-live controller cases. An initial 47-test selection also included
two existing cases that require `/usr/bin/bwrap`; both failed at that missing prerequisite on this
host and are not counted as verified or silently skipped. The actual live lifecycle and the three
production full-tree BOOT tests still require the provisioned CI environment.

This checkpoint does **not** prove that either compiler engine ran, resumed, or produced any
artifact. Cooperative file locks, owner-only directories, and user-systemd naming also do not
exclude a hostile process with the same UID (or root); those principals remain part of the trusted
operating envelope. Only after separately reviewed START and later evidence transitions exist can
compiler output become oracle evidence.

ACP remains a read-only consumer of later authenticated plans. It cannot create, validate, score,
or release GCC oracle or containment truth.

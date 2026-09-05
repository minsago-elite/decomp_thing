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

This checkpoint does **not** prove that either compiler engine ran, resumed, or produced any
artifact. Cooperative file locks, owner-only directories, and user-systemd naming also do not
exclude a hostile process with the same UID (or root); those principals remain part of the trusted
operating envelope. Only after separately reviewed START and later evidence transitions exist can
compiler output become oracle evidence.

ACP remains a read-only consumer of later authenticated plans. It cannot create, validate, score,
or release GCC oracle or containment truth.

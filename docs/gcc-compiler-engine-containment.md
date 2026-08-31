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
3. `TERMINAL_ABSENT` requires a whole-control-group `SIGKILL` (`--kill-whom=all` semantics), the
   unit load state `not-found`, no same-name unit or cgroup candidate, the cgroup path absent and
   unpopulated, every receipt process's pidfd dead, and two independent absence sweeps.

The contract accepts fresh raw canonical bytes at every assessment boundary. It never accepts a
prior assessment as a capability. Every returned object says
`non-authoritative-caller-supplied-containment-bytes-v1`, `releaseEligible=false`, and
`startAuthorized=false`. There is no START, launch, attachment, cold-adoption, output publication,
lease release, scoring, release, ACP, or Python API. The receipt renderers are visibly test-only and
their bytes are forgeable.

This does **not** prove that either compiler engine ran, reached BOOT, was killed, resumed, stayed
inside a resource boundary, or produced any artifact. A future host-owned controller must reuse or
safely generalize the existing descriptor/pidfd-pinned systemd/cgroup-v2 implementation, durably
publish the binding and live attachment receipt under an owner-held journal/lease lock hierarchy,
and reobserve the same invocation and descriptors around every mutation. It must also acknowledge
that cooperative user-systemd naming is not kernel-enforced exclusion against a hostile same-UID
peer. Only after those authorities exist can a separately reviewed START transition be considered.

ACP remains a read-only consumer of later authenticated plans. It cannot create, validate, score,
or release GCC oracle or containment truth.

# Dedicated-disk preparation for bundled GCC analysis

`GccBundledOperationCoordinator.prepareNew` composes authenticated input files,
the independent BOOT deployment reference, the retained application-bundled
Ghidra tree, an external operation journal and a genuine dedicated-ext4 lease.
It returns an opaque `GccBundledPreparedOperation`, not a launch or result
capability. `complete`, `startAuthorized` and `releaseEligible` remain false.

This is separate from the historical path-based GCC BOOT controller. That
controller's caller-populated output directory and capacity checks are not
substitutes for dedicated disk authority. Its frozen definitions and BOOT-only
behavior are not silently promoted or rewritten.

## Intent before allocation

`GccBundledOperationIntent` snapshots the operation ID, cc1/lto1 work unit, fresh
run kind, exact artifact identities, bundled runtime/classpath, fixed environment,
process budgets and disk policy. The canonical schema-1 provider is
`gcc-bundled-operation-intent-v1`; SHA-256 of all canonical bytes is the request
identity. No output path, output inode, final command or systemd attachment is
invented before allocation.

The disk work unit uses the actual GCC engine ID. Its separate
`gcc-bundled-work-scope-v1` commitment binds the engine, benchmark-profile and
source-lock identities. It does not fabricate LLVM inventory or shard facts to
reuse the full-tree operation coordinator. The lower-level dedicated filesystem
authority is shared directly.

Intent encoding is bounded to 256 KiB. Artifact roles and paths are unique,
bundled bridge/guard/inventory/exporter declarations must agree, only fresh run
kinds are allowed, and wall budgets use whole seconds. Disk policy cannot exceed
the existing analysis envelope of 1 TiB and 2,000,000 inodes and requires at least
128 initially available inodes. These are admission ceilings, not measured A10
resource compliance; actual profile acceptance and execution remain separate.

## Durable preparation order

The coordinator first retains every declared input and the independent ordered
BOOT classpath, archive and bundled-runtime identities. Sources and classpaths
must stay outside both the journal root and provisioned scratch mount. Input
authentication does not create either journal or scratch members.

It then locks the external journal root and its unique operation directory before
acquiring the disk mount lock. The journal lives at
`.gcc-bundled-operation-<operation-id>` under the supplied private journal root.
Its immutable no-replace files are published in this order:

1. `intent.json`, before disk allocation.
2. `lease-evidence.json`, after the dedicated-ext4 authority grants a real lease.
3. `definition.json`, after its opaque deterministic run root creates private,
   empty `state`, `reports` and `tmp` directories through pinned descriptors.
4. `prepared.json`, binding the intent, lease evidence, exact final v2 definition
   and definition binding, plus the eagerly captured deployment commitment.

The final v2 command and output identity come from that actual allocated root.
This avoids the cycle in which a definition would need to commit to a not-yet-
created output inode in order to allocate it. The prepared record is self-hashed
under `gcc-bundled-prepared-operation-v1`. Detached records remain historical
descriptions rather than live lease ownership.

Journal reads revalidate exact bytes, inodes, permissions, names and stage
membership. Partial or unknown publication residue is preserved and rejected.
Ordinary-directory scratch rejection may leave an intent-only journal because
the journal-before-mount lock order is deliberate; it creates no lease or
prepared evidence. No cold adoption or retry through ambiguous residue exists.

## Lifetime and remaining execution boundary

The prepared owner retains inputs, both journal locks, the dedicated mount/lease
and the opaque run-root token. Revalidation checks the complete input/journal
bindings and exact empty run layout. Validation failures poison further use.
`close()` independently closes resources and **abandons the lease for recovery**;
it preserves every lease/run/journal member and is not successful release.

The deployment commitment binds BOOT classpath and Ghidra reference/runtime
identities. Preparation does not yet authenticate the complete Java/system/native
launch configuration or grant an executable namespace. A distinct authority-
backed keeper must retain that closure and consume this disk ownership before
any START. The current BOOT-only keeper still has no accepted START token.

Actual execution also requires durable start/exit/interruption records, bounded
project/export/temp writes, cgroup accounting, pinned output validation and exact
worker/cgroup absence. Run removal requires a separate after-absence bounded
cleanup/quarantine handoff; only record-only lease state can reach independently
authorized release. Ordinary recursive deletion or `abandonForRecovery` cannot
stand in for it. The A10 fresh/resumed cc1 and lto1 proofs and #235 remain open.

# Dedicated-disk preparation for bundled GCC analysis

`GccBundledOperationCoordinator.prepareNew` composes authenticated input files,
the independent BOOT deployment reference, the retained application-bundled
Ghidra tree, an external operation journal and a genuine dedicated-ext4 lease.
It returns an opaque `GccBundledPreparedOperation`. Preparation alone does not
authorize START; `complete`, `startAuthorized` and `releaseEligible` remain false.
Its one-shot `execute()` performs contained fresh-control admission.
`executeUntilCheckpoint(minimumCompletedFunctions)` admits a prepared INTERRUPTED
intent through the same retained containment boundary. Neither path supports
resume or release yet.

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

## Lifetime and execution boundary

The prepared owner retains inputs, both journal locks, the dedicated mount/lease
and the opaque run-root token. Revalidation checks the complete input/journal
bindings and exact empty run layout. Validation failures poison further use.
`close()` first retries any retained exact-process cleanup. If absence remains
unproved it retains the lease, inputs and journal for another cleanup attempt.
After absence, or if execution was never launched, it independently closes
resources and **abandons the lease for recovery**. It preserves every
lease/run/journal member and is not successful release.

The deployment commitment binds BOOT classpath and Ghidra reference/runtime
identities. Preparation does not authenticate the complete Java/system/native
launch configuration or grant an executable namespace. `execute()` additionally
authenticates that configuration and consumes a lexical descriptor borrow of the
retained ext4 run. The separate historical BOOT-only keeper remains unchanged.

## Contained fresh execution

`KotlinSystemdCgroupCommandLauncher` uses a distinct fixed Kotlin keeper inside
the existing authenticated systemd/cgroup-v2, prlimit and bubblewrap boundary.
The bundled direct-API child executes the exact definition argv and three-field
environment. Runtime provider `bundled-ghidra-java-api-runtime-v2` explicitly
binds `-Duser.home=<run>/tmp` and `-Djava.io.tmpdir=<run>/tmp`; provider v1 still
parses and preserves its original command but is not accepted for execution.
Provider v2 also binds one active JVM processor to match the single-CPU scope
quota and disables the child's JVM attachment mechanism.
The JDK, native libraries, bundled release, exporter and engine input are
read-only. Project, reports and temporary writes use the dedicated filesystem;
the journal, lease record and host systemd socket are absent from the sandbox.

The host sends a random 32-byte handshake key only through the keeper's stdin,
not through argv, environment or a file. Before any analyzed child exists, the
host authenticates BOOT and pins the exact three keeper-process identities and
pidfds. The journal durably publishes `attachment.json`, then
`start-authorized.json`, before the host delivers authenticated START. The latter
record means permission was durably recorded, not that a crashed worker must
have consumed it.

The keeper disables JVM attachment and sets/verifies Linux nondumpability before
spawning the child. This prevents the same-UID child from obtaining the key from
keeper memory or `/proc` descriptors. HMAC-SHA256 binds BOOT, START and the reaped
child's outcome to the request and nonce. File deletion or tampering remains a
possible denial of completion, never proof of success. Same-UID host principals
remain part of the controller trust boundary. Child stdout/stderr files are
diagnostics; authenticated byte counters do not authenticate those file contents.

After an authenticated successful outcome, the host verifies the same retained
keeper pidfds and exact cgroup population, freezes the cgroup, captures bounded
resource counters, kills the keeper and proves exact unit/cgroup/process absence.
It does not attempt protected `/proc` executable reads after nondumpability.
Failures retain cleanup-only ownership independently of mutable input or journal
validation. No unmanaged execution fallback exists.

After absence the journal adds `execution.json`. Descriptor-relative bounded
capture validates exporter state, progress, every expected planning checkpoint
and fragment, and the assembled model against exact input/exporter/archive
identities. `export-assessment.json` binds the resulting byte assessment.
These chained records still have `complete=false` and `releaseEligible=false`:
a successful fresh run is not A10 scoring, forced-resume equivalence, source
reconstruction or benchmark qualification.

The required CI fixture uses an authored benign ELF, a separate fixed 1-GiB
ext4 filesystem and the provisioned root-owned application bundle. It retains
bounded diagnostic evidence; missing prerequisites fail when
`DECOMP_REQUIRE_BUNDLED_GHIDRA_EXECUTION=true`. Ordinary local tests cannot stand
in for that privileged execution proof.

Run removal requires a separate after-absence bounded
cleanup/quarantine handoff; only record-only lease state can reach independently
authorized release. Ordinary recursive deletion or `abandonForRecovery` cannot
stand in for it. The A10 fresh/resumed cc1 and lto1 proofs and #235 remain open.

## Interrupted-prefix capture groundwork

`GccBundledExportCapture.captureInterruptedPrefix` reads a nonterminal planning
prefix through the retained run/reports directory descriptors, under per-file
and aggregate byte limits. It checks input/exporter/archive identities and the
existing Kotlin semantic/checkpoint commitments, and revalidates file identities,
metadata and exact batch membership. It requires at least one complete 512-function
batch, no reused records and no final model. Unfinished or extra batch members
are rejected and retained; this entrypoint does not delete or repair residue.

The returned `GccInterruptedPrefixAssessment` remains a non-authoritative byte
assessment. Calling it does not stop a process or prove absence. The contained
coordinator now connects this capture to authenticated checkpoint-triggered
interruption and durable interruption transitions. Same-owner resume and real
cc1/lto1 fresh/resumed model and ownership-plan comparisons remain required by
#137. Prefix-only fixtures do not qualify those lifecycle requirements.

## Authenticated keeper interruption primitive

The keeper accepts an opt-in `kotlin-contained-command-request-v2` with
`allowInterruption=true`. Default requests retain the exact v1 field set,
provider and canonical encoding. Neither v1 requests nor their outcome decoder
admit interruption. The host launcher defaults to v1 fresh-control requests. Its optional retained
interruption controller selects v2. The GCC prepared coordinator selects v2 only
for its explicit interrupted-intent entrypoint.

For a v2 request, the host may publish a mode-0400, no-replace
`contained-command.interrupt.json`. The `INTERRUPT` HMAC event binds the original
request digest, nonce and keeper PID using the stdin-only key. It cannot be
replayed as START or OUTCOME, or across another request, key or keeper. The
keeper authenticates the bounded record while its direct child is running,
requests forcible termination, reaps that child within five seconds and drains
its bounded output readers before publishing an authenticated `INTERRUPTED`
outcome. Malformed or forged control fails without an accepted outcome. Log
failure, output overflow and failure to reap still prevent accepted interruption.

`INTERRUPTED` cannot pass successful-execution validation. It records that an
authenticated request was observed while the child was live and that the child
was reaped; an exit racing termination does not prove which event caused death.
It does not prove a durable checkpoint, descendant/cgroup absence, safe project
reload, or resume equivalence. The host must compose those independent checks
and durable journal transitions before accepting an interrupted benchmark leg.
The local tests execute only an authored waiting JVM child, exercise valid and
forged requests, and are explicitly not containment or real-Ghidra evidence.

## Host interruption delivery and journal branch

`KotlinContainedCommandInterruption` binds once to a v2 request and snapshots a
bounded canonical policy. The launcher commits its policy digest and v2 provider
in the runtime closure before BOOT. During outcome polling, the host polls the
caller-owned trigger. A non-null bounded canonical trigger is committed with the
policy, request, keeper PID and interruption-token digest in an authorization
record. The durable-authorization callback must complete before token publication.
The launcher revalidates executable/runtime inputs immediately before no-replace
token publication. Authorization or delivery failure poisons the controller; it
does not retry a possibly delivered token. Reentrant delivery is rejected.

The caller supplies the trigger's semantics and durable journal owner. The
controller checks shape, size, bindings and sequencing; a caller-supplied trigger
is not independently authenticated Ghidra checkpoint evidence. Missing triggers,
early normal exit, malformed outcomes and undelivered interruption cannot yield
an interrupted result. An authenticated INTERRUPTED outcome still passes the
existing exact keeper-population, frozen accounting and unit/cgroup/process
absence checks before the launcher returns. The result uses the distinct
`kotlin-lease-contained-command-interrupted-v1` provider, including the authorization
record and digest; the ordinary execution provider and default request remain
unchanged. This does not bypass cleanup-only retention on failure.

The GCC journal now supports a separate START-authorized → interrupt-authorized →
interrupted-execution → interrupted-prefix-assessment branch. Each immutable
record commits its predecessor, payload and operation/intent bindings and retains
`complete=false` and `releaseEligible=false`. Completed-execution and interrupted
branches cannot be interchanged. Missing, altered or out-of-order records poison
the owner without removing residue.

The GCC coordinator supplies the bounded checkpoint trigger, journal callbacks
and post-absence prefix validation described below. Same-owner resume remains
unfinished. Hosted systemd/ext4 interruption and real compiler equivalence have
not been established by the local delivery/keeper/journal tests.

## Prepared GCC checkpoint-triggered interruption

`executeUntilCheckpoint` requires an INTERRUPTED fresh-analysis intent and a
positive threshold divisible by 512. It binds that threshold into the host policy
and polls state/progress through retained run/reports descriptors under byte
limits. Missing not-yet-published state/progress returns no trigger. Malformed,
linked, replaced or oversized records and mismatched input/exporter/archive
identities fail. Only fresh nonterminal planning progress at a full batch can
trigger; a completed export cannot substitute for interruption.

The exporter publishes planning progress after publishing and checking each
batch checkpoint. This progress observation requests interruption but does not
prove retained checkpoint completeness. Before token delivery the coordinator
revalidates retained inputs and disk ownership and durably publishes interruption
authorization. After the host proves the authenticated outcome and exact absence,
the coordinator records interrupted execution and performs full descriptor-bound
prefix validation. The resulting prefix must have the same analysis-state digest
and total and cannot precede the trigger. Additional fully committed batches may
have completed during token delivery. Unknown/unfinished residue or a final model
is rejected and retained, never silently removed to manufacture a valid prefix.

`GccBundledInterruptedOperation` snapshots the linked execution/prefix receipts;
`complete` and `releaseEligible` stay false. The prepared owner remains one-shot,
and close still abandons residue after independently proving absence. No project
reload, cold adoption, resumed invocation or successful lease release is added.
The focused tests cover progress admission, invocation/path/byte rejection,
forward-only prefix lineage, journal sequencing and host delivery. Provisioned
interruption and real compiler benchmarks still require executed evidence.

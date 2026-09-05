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
environment. The default runtime provider `bundled-ghidra-java-api-runtime-v3`
binds JVM home and temporary paths to `<run>/control-<digest>/tmp`, separate from
the shared project and reports. The digest is SHA-256 of UTF-8
`gcc-bundled-fresh-control-v1\n<absolute run path>` (with an actual newline).
This fresh-leg name is derived before command hashing and is bound in the
validated command, keeper request and runtime closure. The launcher creates it
only at execution, through the opaque lease-issued borrow; preparation leaves
it absent. A later resume leg will need a distinct name.

Provider v2 preserves its exact `<run>/tmp` command and legacy launcher layout;
provider v1 still parses unchanged but is not accepted for execution. Both v2
and v3 bind one active JVM processor to match the single-CPU scope quota and
disable the child's JVM attachment mechanism.
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

## Stopped analysis-state manifest

After an interrupted prefix is validated, `executeUntilCheckpoint` also captures
`state` through its retained directory descriptor. Capture streams file hashes,
commits paths, byte lengths, device/inode/mount identities, ownership, modes,
link counts and size/mtime/ctime metadata, and includes empty directories. It
rechecks every name, identity and metadata record before returning. Symlinks,
special files, hardlinked files, untrusted writes, foreign mounts and replaced
state roots fail without content changes or cleanup. Empty/no-data state cannot
supply a resume manifest.

Capture enforces entry/depth/path, logical-file-size, aggregate-byte and elapsed
wall-clock bounds. The prepared owner supplies its disk byte/inode ceilings and
wall budget, subject to the manifest's 32,768-entry, depth-32 and 64-MiB JSON
ceilings. Files are read with a fixed 64-KiB buffer; an oversized sparse file is
rejected from metadata before reading its holes. This is a bounded capture phase,
not proof of whole-run A10 aggregate resource compliance.

The external journal durably publishes `analysis-state-manifest.json` and then
`analysis-state-captured.json`, linking the full manifest digest/length/counts to
the interrupted-prefix record. A distinct manifest publication/read API permits
at most 64 MiB in owner-read-only mode; ordinary journal records retain their
one-MiB hard bound. The same no-replace, descriptor identity and residue rules
apply. A crash between manifest and receipt leaves an explicit staged residue;
this checkpoint provides no cold adoption of it.

`GccBundledInterruptedOperation` exposes defensive copies of the manifest and
its receipt. They describe historical captured bytes, not a live immutable-state
capability or successful resume. Same-owner resume still must revalidate this
manifest and establish a new durable control lifecycle while preserving prior
protocol evidence. No saved-project reload, recovery, release or real compiler
fresh/resumed equivalence is established by these fixtures.

## Per-execution control-directory groundwork

The command launcher has an optional `controlDirectoryName` of the form
`control-<64 lowercase hexadecimal characters>`. It creates that fresh directory below the
opaque lease-issued run-root borrow, using no-replace descriptor-relative
construction. Its private `state`, `reports`, and `tmp` children hold the keeper's
own control layout; the request and materialized classpath enter its `runtime`
child. Closing the adapter closes its child descriptor and preserves every file.
An existing name is never adopted or cleared, including partial construction
residue. Parent permissions and child identity/name/mount bindings are rechecked.

The request's working/control directory and the containing writable lease root
are separately committed in the runtime closure. The namespace binds the same
lease-owned writable root while making the selected control directory's runtime
read-only. This allows the command's project and export paths to remain at the
original run root while its keeper protocol and logs use a fresh child directory.
No arbitrary external writable directory is admitted: the optional directory is
exactly one child of the retained root. Its name is chosen before command hashing
so a JVM temporary path can refer to it without a circular hash dependency; the
request and runtime closure bind the chosen path. The default
layout and its runtime commitment remain unchanged when this option is absent.

This is not yet production resume. The GCC coordinator selects this layout for
the default v3 fresh or interrupted leg. Resume must bind/revalidate the prior
analysis state and export prefix, choose a fresh temporary directory for the
analysis JVM, and supply retained earlier control identities for protection during the next
execution. The directory tests establish separation, no-replace behavior and
identity checks only; they do not qualify the new namespace layout under hosted
systemd/ext4 execution.

The launcher accepts up to 256 prior control-directory identities alongside a
separate active control name. It verifies each prior directory against the pinned
lease-root descriptor before launch and after process absence, commits the sorted
identities in the runtime closure, and adds read-only subtree binds after the
writable root bind. The execution receipt returns the selected control-directory
identity for a later invocation. These identities attest directory bindings, not
the contents of prior protocol files; callers still must validate retained bytes.
Local tests cover identity replacement, permission changes, active-name exclusion,
and immutable mount membership. Kernel mount enforcement and complete resume
remain unqualified by these tests.

## Retained interrupted-state revalidation

After `executeUntilCheckpoint` completes both its journal writes and the lease's
post-execution validation, the same live owner retains the stopped result and
selected trigger. `requireInterruptedStateCurrent()` checks the held inputs,
journal and dedicated lease, then recaptures the analysis-state manifest and
export prefix through the lease-issued descriptor borrow. It requires exact
manifest bytes, counts and stopped-prefix commitments. A prefix that advanced
during stop delivery may be accepted at capture time; any advancement after
that captured boundary fails revalidation. A validation failure poisons the
owner. Calls before successful interruption or after close are rejected.

This method accepts no detached receipt or caller-selected checkpoint. It does
not authorize START, verify prior control-file contents, prove saved-project
semantic equivalence, or enable resume. The next execution must still establish
its separate control lifecycle and revalidate evidence before authorization.
Local tests exercise state content, metadata, membership and inode changes and
prefix advancement/regression; retained-owner execution still needs the hosted
systemd/ext4 environment.

## Explicit resume reanalysis definition

Runtime provider `bundled-ghidra-java-api-runtime-v4` is opt-in and resume-only.
It accepts a manifest-bound `RESUMED` definition whose original state path is
`<run>/state`. Its control name is SHA-256 of UTF-8
`gcc-bundled-resume-control-v1\n<absolute run path>\n<stopped manifest SHA-256>`
(with actual newlines), prefixed by `control-`. JVM home/temp use that control's
`tmp` directory, and the bundled worker imports the original binary into a new
project under that control's `state` directory. The exporter still targets
`<run>/reports/program_model.json` and its existing checkpoint inventory.

This chooses normal import/analysis before exporter reuse, avoiding reliance on
the historically different saved-project reload path. Whole-program exporter
semantic validation must still reject incompatible checkpoints before reuse.
The command definition binds the stopped manifest and derived fresh paths; it
does not authenticate the manifest or prove that repeated analysis is identical.

The default remains v3. Fresh operation intents reject v4 before acquiring a
lease, and the fresh execution path accepts only v2/v3. The same-owner resume
path described below selects v4 after stopped-state revalidation, protects the
original state, and journals the separate attachment and START. Full hosted
execution and cumulative resource accounting still need qualification; command
contract tests do not prove either.

## Resume journal lifecycle

After stopped-state capture, `recordResumePrepared` admits a v4 resumed definition
only for an interrupted v3 original. It checks the same engine, artifact identities,
runtime inventory, output lease, environment and original state path, and requires
the stopped manifest hash and counts. Resume budgets cannot exceed original
per-leg ceilings; this check alone does not establish cumulative resource use.

The journal preserves all eleven stopped-run records and adds six no-replace
files: `resume-definition.json`, `resume-prepared.json`, `resume-attachment.json`,
`resume-start-authorized.json`, `resume-execution.json`, and
`resume-export-assessment.json`. Preparation binds the exact new definition and
links to stopped-state capture. Subsequent records hash-link to their predecessor.
The intermediate definition-only stage is explicit, so partial publication remains
preserved residue. Every stage checks exact membership and retained file identities;
wrong order, replacement, changed bytes and repeated transitions poison the journal.

These APIs record host decisions and assessments. They do not independently prove
attachment, START delivery, process absence, valid export contents or completion.
All records keep complete/release eligibility false. The coordinator must supply
those live checks when integrating the second execution. Local journal fixtures
use synthetic payloads and establish persistence/ordering only.

## Retained original project mount

The contained command launcher accepts an optional `readOnlyStateDirectory`
identity for the original `<run>/state` directory. It requires a separate active
control directory, verifies the original state and prior controls against the
pinned lease-root descriptor before launch and after absence, and commits the
state identity separately in the runtime closure. After binding the writable
run root, it applies read-only binds for the retained state and controls. The
active control's new project and the shared reports remain writable.

The option accepts an identity for the fixed `state` child; it does not accept
an arbitrary mount path or change the allowed prior-control names. Directory
identity is not a content manifest, so the resume coordinator must still run
stopped-state revalidation. Existing runtime commitments remain unchanged when
the option is absent. Descriptor fixtures exercise replacement and permission
changes. A local bubblewrap fixture tests retained write rejection and successful
writes to the new project/reports, without claiming authenticated runtime,
systemd/cgroup, dedicated ext4 or live compiler qualification.

## Same-owner resume integration

A successful v3 interruption now retains the first control-directory identity
and a SHA-256 commitment to all stopped planning checkpoint/fragment bytes.
The commitment uses the UTF-8 domain `gcc-bundled-planning-prefix-bytes-v1\n`,
followed in batch order by each checkpoint, functions, globals, types and failures
file, each framed by its eight-byte big-endian byte length. The stopped-prefix
journal assessment commits this digest alongside its semantic assessment.

`resume()` accepts no caller-supplied evidence and is available once under the
same retained owner. It revalidates stopped evidence, constructs the v4 definition,
records resume preparation, and launches through the existing authenticated keeper
with the old project and control directory read-only. Before START it recaptures
the old project and prefix and writes separate attachment/authorization records.
Failed execution retains cleanup responsibility; any failed attempt poisons the
owner and cannot be retried by reusing its receipts.

After the launcher proves process/cgroup absence, the coordinator records the
second execution, verifies the unchanged original project, validates the complete
export and requires exactly the retained reuse count, exporter state and function
inventory. It hashes the reused prefix bytes again and rejects changed serialization
even when the completed model validates. The resumed export receipt binds that
prefix digest. This result still has complete and release eligibility false.

This is implementation, not qualification: the local suites exercise command,
journal, namespace and byte-validation components, but have not executed the full
same-owner compiler lifecycle under the required hosted provisioning. The normal
CLI, real cc1/lto1 fresh/resumed model and planner comparisons, cumulative resource
accounting and benchmark publication remain incomplete. Per-leg ceilings are not
a cumulative A10 budget proof. The bounded first-incomplete-batch write sequence is handled as described below;
other residue still fails closed and is retained.

## First incomplete planning batch

Interrupted capture permits only the exporter write sequence immediately after
the progress-bound committed prefix: zero to four published fragments in the order
functions, globals, types, failures, plus at most the next artifact's named
`.pending` file (which can be the checkpoint pending file). Empty pending files
are allowed. These bytes are not parsed as committed evidence and do not increase
completed/reused counts. Missing committed records, gaps, multiple pending files,
future-batch residue, links and excess bytes are rejected.

Capture records every permitted leftover file's name, size, SHA-256, inode/mount/
ownership identity and modification metadata under the existing capture bounds.
The stopped-prefix journal assessment binds this manifest and its hash. Same-owner
revalidation requires the unchanged leftover manifest before START. Host capture
never removes residue. After semantic-state validation, the existing exporter
can discard its named pending file and rewrite the first incomplete batch; resumed
capture still requires the exact original committed prefix and reuse count.

A complete next nonterminal checkpoint can be validated as described below.
Terminal batches and multiple advances remain rejected, preserved states.
Hosted interrupted/resumed compiler qualification and whole-run resource evidence
remain required; local fixtures establish only bounded capture/validation behavior.

## Checkpoint published before progress

If exactly the next checkpoint exists beyond observed progress, stopped capture
reads its complete fragment set and the validator first validates the observed
prefix against the original progress bytes. It then validates the next full batch
and derives effective counters from its authenticated partial/failed counts. The
full extended prefix is validated again for contiguous inventory, ownership and
semantic commitments. Only one additional nonterminal full batch is admitted.
This is a diagnostic derivation, not a claim that the exporter wrote new progress.

The stopped journal payload retains `capturedProgressUtf8` (including its newline)
and its SHA-256 separately from `effectiveProgressUtf8`, and explicitly records
`effectiveProgressDerived`. The effective bytes must hash to the stopped assessment's
progress commitment. Same-owner revalidation requires unchanged captured progress,
checkpoint bytes and in-flight bindings. Host capture does not rewrite any file.
The resumed leg must reuse the extended committed count.

A bounded `.program_model.json.progress.json.pending` file may accompany the
advanced checkpoint; its bytes and identity are recorded as in-flight evidence.
Later batch fragments cannot accompany this state because the exporter writes
progress before starting another batch. Pending progress without an advanced
checkpoint, multiple advances, missing fragments and terminal checkpoints fail
closed. Local tests cover both sides of this race and the derived/observed evidence
separation; real hosted interruption and compiler/plan equivalence remain unproven.

## One retained-owner wall deadline

After initial preflight, entry into the first execution creates a same-process
monotonic deadline using the operation's wall ceiling. The same object covers
runtime preparation, interruption, stopped capture, time between legs, resume
preparation/execution and export capture. It cannot be reconstructed from a receipt
or reset by `resume()`. Expiry or clock regression permanently revokes it.

Each launch receives at most the remaining whole service seconds. The launcher
binds the deadline policy in its runtime closure, checks immediately before START,
limits the outcome wait to remaining milliseconds and checks on every outcome
poll. Expiry uses the existing failure cleanup and process-absence path. It never
extends cleanup deadlines or bypasses cleanup to meet a timing target. Execution
receipts and export assessments include the same monotonic start, maximum wall
budget, elapsed time and remaining time; the owner rechecks after journal/lease
post-validation before returning a successful result.

This covers the retained-owner execution interval. Initial preflight/lease
preparation, other benchmark legs, cumulative CPU/disk accounting and full A10
publication policy still need separate integration and evidence. Local clock tests
cover inter-leg gaps, floor rounding, expiry, monotonic wrap and regression; the
hosted authored-ELF fixture also checks receipt timing consistency when provisioned.
No full hosted compiler-resume qualification is inferred from clock tests.

## Required hosted authored resume fixture

CI provisions two additional independent 1 GiB ext4 images: one for the authored
interruption/resume owner and one for its uninterrupted fresh control. Their
prepare/release selectors are `--bundled-ghidra-resume` and
`--bundled-ghidra-resume-control`; each has a fixed mount parent and environment
prefix. The existing required-provisioning flag makes missing hosted prerequisites
fail the fixture rather than silently skip. Local unprovisioned runs skip the two
contained Ghidra fixtures, while a separate local test compiles the generated ELF
and checks its 4,096 defined functions.

The hosted resume test observes a checkpoint, resumes under the same owner,
checks preserved journal records and expected reuse, then compares complete model
bytes against fresh normal import/analysis on the other filesystem. Both module
plans are derived by the deterministic planner from the respective captured
models. Retained artifacts include the two plans, model/checkpoint evidence,
receipts and a comparison record linking both evidence directories and receipt
hashes. Control logs are read from the execution's actual control directory.
Failures preserve bounded compiler, journal and control-log diagnostics.

This is an authored integration gate, not cc1/lto1 benchmark acceptance. It has
been compiled but requires the hosted runtime, user-systemd and dedicated-ext4
setup to qualify. Real compiler equivalence, the normal CLI and complete A10
resource/publication evidence remain separate requirements. Trusted CI fixture
teardown does not imply production scratch-release authority.

# LLVM behavior native sandbox policy v2 operation journal

This checkpoint adds a daemon-free, descriptor-bound journal for one verified native sandbox
policy v2 draft. It makes the static ACP boundary part of the durable operation identity without
claiming that candidate lineage, runtime inputs, a reference, or a live execution have been bound.

The journal deliberately stops before any preparation or START boundary. It has exactly two
phases:

- `POLICY_DRAFT_BOUND`: the five build-local policy inputs passed the sealed v2 verifier and their
  validation facts, paths, and static ACP requirements are durably bound.
- `CLOSED_WITHOUT_START`: the caller closed this journal path without asking it to cross START.

No other phase is parsed or accepted. In particular, this journal is not candidate admission,
runtime preflight, a runner, a containment authority, an observation author, a scorer, a
certifier, or release admission. `CLOSED_WITHOUT_START` describes only this journal's transition
history; it is not evidence that no unrelated process executed bytes.

## Public boundary

`LlvmBehaviorNativeSandboxPolicyV2OperationJournal.open(...)` accepts exactly six raw `Path`
arguments, in this order:

1. the pre-provisioned journal root;
2. `llvm-behavior-native-sandbox-policy-v2.json`;
3. `decomp-llvm-behavior-helper`;
4. `decomp-llvm-behavior-helper.sha256`;
5. `decomp_llvm_behavior_helper.c`;
6. `decomp-llvm-behavior-helper-build-v2.json`.

Every argument must already be absolute and normalized. The five policy inputs are passed to
`LlvmBehaviorNativeSandboxPolicyV2Verifier`; callers cannot inject validation results, parsed JSON,
digests, an operation identifier, callbacks, runner objects, admission/preflight objects, or ACP
receipt bytes. Policy inputs beneath the journal root are rejected so journal publication cannot
mutate its own inputs.

`open` returns a sealed `AutoCloseable` owner. The owner exposes only immutable validation and
commitment facts, the current phase, and `closeWithoutStart()`:

- `closeWithoutStart()` re-runs the sealed verifier, requires every fact to match the binding,
  appends the terminal transition idempotently, and verifies the inputs once more.
- ordinary `close()` only releases the child and root locks. It does not append a transition. This
  permits a later typed v2 composer to reopen an operation left at `POLICY_DRAFT_BOUND`.

An owner is poisoned after any failed state operation. Closing a poisoned owner remains allowed so
its descriptors and locks can be released.

## Durable records

The operation identifier is the SHA-256 of a canonical request preimage. The operation directory
is derived solely from that identifier:

```text
.llvm-behavior-native-sandbox-policy-v2-operation-<operationId>
```

The request preimage commits to the request provider and journal authority, all sealed-verifier facts, all
six path-string SHA-256 commitments, the static ACP requirements, and the journal's false claims.
The directory contains at most these immutable mode-0400, single-link files:

```text
binding.json
transition-0000.json
transition-0001.json
```

These are the completed target records. During bounded cold recovery, at most one additional
deterministic mode-0400 temporary may be present.

`binding.json` is strict canonical JSON with a `bindingSha256` self-hash. It persists every field
returned by the sealed v2 verifier:

- policy validation authority and schema version;
- policy and bundled-schema hashes;
- helper validation flag, byte length, and helper/checksum/source/build-record hashes;
- helper protocol and container path;
- the verifier's false reference, START, scoring, and release flags.

It also persists SHA-256 commitments to the exact normalized string form of the journal root and
all five inputs. Paths themselves are not treated as content authority.

The ACP section binds these exact static requirements from policy v2:

- role `first-class-candidate-producer-operator`;
- contribution `authenticated-session-change-build-artifact-provenance`;
- read-only oracle provenance access;
- Kotlin-host ownership for candidate admission, separately reviewed Kotlin-host ownership for
  candidate live execution, and Kotlin-host-only reference admission;
- required candidate session, change, hosted-clean-build, and admitted-artifact provenance;
- false ACP oracle, reference-authoring, policy-authoring, validation, observation-authoring,
  START, containment, terminal-absence, scoring, certification, and release authority.

No ACP receipt or artifact bytes are accepted or persisted by this checkpoint.

Both transition records contain the operation ID, binding hash, schema/provider/authority,
sequence, phase, previous-transition hash, all false journal claims, and a self-hash. Sequence zero
uses the all-zero previous hash; sequence one names sequence zero's self-hash. The persisted false
journal claims are:

- `runtimeInputsBound`;
- `candidateLineageBound`;
- `prepared`;
- `liveRuntimeIdentityVerified`;
- `liveContainmentVerified`;
- `executionClaimed`;
- `referencePinned`;
- `candidateStarted`;
- `startAuthorized`;
- containment, terminal-absence, observation-authoring, scoring, and certification authority;
- `releaseEligible`.

## Descriptor and locking boundary

The journal root must already exist as a canonical, non-root, current-user mode-0700 directory. Its
canonical parent must be owned by root or the current user and must not be group/world writable.
The implementation pins parent and root descriptors, verifies pathname-to-descriptor identity,
and acquires a nonblocking exclusive `flock` on the root.

The operation directory is created and opened relative to the root descriptor. It must be a
current-user mode-0700 nonsymlink directory on the root filesystem. The operation child lock is
acquired after the root lock and released before it. Parent/root and root/child bindings are checked
before and after every journal operation; drift poisons the handle.

The root lock serializes cooperating JVMs and is the initial daemon-free ownership constraint. It
does not turn persisted records into live authority and it does not defend against arbitrary
same-UID processes that ignore the protocol; repeated descriptor/name checks make such mutation a
detected failure rather than silently accepting a different inode.

## Atomic publication and cold recovery

Every record uses `DescriptorBoundAtomicStateFile.publishNoReplace`. Publication creates and
synchronizes an unnamed inode, materializes the deterministic temporary, synchronizes the
directory, performs a no-replace rename, and synchronizes the directory again. Existing target
bytes are accepted only when exact.

On every open, cold recovery classifies the bounded directory membership before initialization.
It completes at most one deterministic temporary, and only when all of these hold:

- no target with the same name exists;
- the retained temporary descriptor still names the inspected inode and exact canonical bytes;
- the record parses with the closed schema, valid self-hash, expected request binding, and exact
  prefix position;
- the binding and descriptor/name relationships remain valid.

A pending binding is accepted only as the sole entry. A pending initial transition requires the
exact binding and no transition. A pending close transition requires exactly the binding and
`POLICY_DRAFT_BOUND`. Unknown entries, multiple temporaries, target-plus-temporary collisions,
gaps, unsupported phases, malformed/noncanonical JSON, cross-request bytes, and inode replacement
are retained and rejected. Recovery never overwrites, deletes, quarantines, or regenerates unknown
residue.

The only crash-stable prefixes are therefore an empty created operation directory, binding only,
`POLICY_DRAFT_BOUND`, and `CLOSED_WITHOUT_START`. A successful `open` always returns one of the two
phased states; unphased prefixes are completed before ownership is returned.

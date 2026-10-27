# Independent machine-call producer v1

This component derives positive direct-call observations from committed ELF bytes
and an independently supplied canonical oracle. It does not consume a recovered
program model, recovered function boundaries, a Ghidra Program, an analyzed
listing, persisted references, or decompiled output. Its result is not a release
certificate: `complete`, `negativeCompleteness`, and `releaseEligible` remain
`false`.

The existing [native call collector](../native-call-observations-v1.md) reads an
analyzed Program and therefore has a different evidence boundary. A successful
run of either component does not establish that every machine call was found.

## Owned inputs and runtime

`IndependentMachineCallWorkerV1` reads a closed, canonical request by its expected
SHA-256. The request commits the rich ELF and canonical oracle by path, byte
length, and digest, along with the manifest digest, output path, runtime identity,
and explicit limits. There is no recovered-model input field. Unknown request
fields, overlapping input/output paths, missing bytes, or changed commitments
are rejected.

The runtime request pins the bundled Ghidra 12.1.3 archive, bridge JAR, bundle
manifest, and `x86:LE:64:default` language version 4.8. The worker reuses the
existing complete archive/installation verification and bundle verification,
then opens an isolated class loader whose parent is the JDK platform loader.
That loader reads only the explicitly authenticated JARs. It does not follow
manifest `Class-Path` or `INDEX.LIST` expansion, and bounds JAR entry inventories,
manifest bytes, and class bytes before loading. Multi-release selection and
package sealing retain their JVM meanings.
The loaded bridge's code-source path and complete digest must match the request
before its initializer runs. Runtime and input commitments are checked again
before publication.

The worker is a child computation, not a containment launcher. Its result records
`containmentStatus: external-owner-required`. No production coordinator or scoring
consumer is registered by this component. An external execution owner must still
provide authenticated request authority, process/resource/filesystem isolation,
termination, and cleanup evidence. A request's own hashes cannot supply those
authorities.

## Byte decoder

`ByteInstructionDecoderV1` exposes JDK-only arguments and a JDK-only immutable
record for reflective use. `initialize(releasePath)` initializes the bundled
application without importing an input or creating a Program. Extension and
patch discovery are disabled in that initialization path. An existing
application must have the pinned version and installation path; module roots
outside the installation are refused. The constructor accepts only the declared
x86-64 language/version and rejects a custom disassembler class.

Initialization uses the public `ApplicationConfiguration` base API and the typed
`SleighLanguageProvider`. The full headless tool configuration would install
remote deserialization support, discover plugins and extension points on the
boot JVM classpath, and run module initializers. Byte decoding needs none of
those steps and does not change the boot classpath.

Each `decode(addressBits, bytes)` call clones between 1 and 32 input bytes and
constructs a fresh language-only disassembler. The factory applies the language's
default context. A little-endian `ByteMemBufferImpl` supplies only the owned bytes;
`pseudoDisassembleBlock(buffer, null, 1)` requests exactly one instruction.
Reported errors, zero/multiple instructions, a different address, incomplete
bytes, delay slots, next-instruction dependencies, or inconsistent fallthrough
are failures. Bytes spanning the end of the address space are rejected. Addresses
preserve unsigned 64-bit values in canonical hexadecimal.

A positive `direct-call` record requires all of the following:

- The typed `FlowType` is a call and is not computed.
- Exactly one raw `PcodeOp.CALL` supplies a target in the input address space.
- No `CALLIND` is present, and the raw target exactly equals the single typed flow
  target.
- No unimplemented p-code, user operation, exported processor-context commit, or
  identified mode-register write makes the interpretation unsupported.

Direct jumps retain their typed targets only after agreement with raw
`BRANCH`/`CBRANCH` targets. Returns require a terminal typed flow, exactly one raw
`RETURN`, no direct target, and no fallthrough. Ordinary instructions require a
consistent fallthrough; a missing fallthrough is never silently treated as a
completed ordinary instruction.

`indirect-call` and `indirect-jump` remain explicit classifications. Traps and
user operations, unimplemented p-code, context-changing operations, and other
unsupported flows remain explicit unsupported classifications. Such a record is
not evidence that a path contains no call. A direct-call target is null on these
records. The decoder checks interruption before, during, and after decoding.

The record contains the exact decoded bytes, length, flow flags, fallthrough,
direct targets, optional verified direct-call target, and `contextStatus`.
Byte arrays are cloned on construction and access; target lists are immutable.
The context status distinguishes ordinary default context, explicit context
changes, and unassessed user-operation or p-code effects.

## Extent ownership and bounded traversal

`IndependentMachineCallsV1` validates the canonical function oracle's production
scope, exact digest and manifest binding, rich-artifact digest, image base, ELF
type, and executable ranges. The ELF parser separately inventories every raw
`STT_FUNC` and GNU IFUNC symbol with its original name, locator, type, binding,
visibility, section identity, value, and size. Names and suffixes do not decide
ownership or exclusion.

Exact aliases collapse only when their value, size, section index, and section
kind agree. A traversable extent must have a nonzero, nonoverflowing size and an
unambiguous mapping inside one executable, allocated, file-backed section and
one executable load segment. Section and segment file mappings must agree.
Undefined symbols, IFUNC identity, zero sizes, conflicting or overlapping
extents, and canonical starts inside another extent remain ownership problems.
Overlap checks include every nonempty, nonoverflowing absolute symbol interval,
even an otherwise invalid symbol starting below the image base with no RVA.
The producer never guesses an end from the next symbol.

Traversal starts at each independently owned extent entry. It reads at most 15
file-backed bytes at a requested instruction address, validates the decoder's
address/length/bytes, and maintains an ordered queue and decoded-interval map.
Ordinary instructions and calls schedule their fallthrough. Direct jumps
schedule their target and any fallthrough. Returns stop a path. Computed jumps,
unsupported instructions, decoding refusals, overlapping instruction paths, and
successors outside the owned extent remain explicit stops. There is no scan for
call-like byte values, guessed instruction resynchronization, or tail-jump-to-call
conversion.

A site receives `positive-internal-exact-start` only when its direct caller and
target both bind exact, nonexcluded canonical starts, the target has one
unambiguous symbol extent, and the caller traversal has no overlapping
instruction paths. Indirect calls remain `unresolved-indirect-target`. Missing or
excluded caller/target identities, invalid target extents, and instruction
overlaps retain their own unresolved dispositions. A positive site does not
imply that the caller's remaining paths, the target's implementation, or the
whole call population are complete.

Three inventories preserve the evidence boundary:

- `canonicalPopulation` includes every supplied canonical function, including
  null-address/inline-only exclusions and starts without usable symbol extents.
- `roots` retains every grouped raw-symbol origin, ownership problems,
  instruction count, and traversal stops. The sorted `traversalStops` reason
  summary is accompanied by sorted, deduplicated `traversalStopEvents` with the
  exact address/RVA, reason, and target address when known. Event bytes distinguish
  an undecoded `available-window` from a `decoded-instruction`; unavailable bytes
  stay null. Each event is charged to the output budget before retention.
- `calls` retains positive and unresolved visited call sites with exact
  instruction bytes, length, caller root, canonical identities when available,
  flow targets, context status, and disposition.

`canonicalPopulationComplete` and `rawSymbolPopulationComplete` mean those input
inventories were fully enumerated. They do not mean complete discovery of all
functions, instructions, or calls in the ELF. Per-root and per-site
`negativeCompleteness` remain false, including a traversed root with zero observed
calls. No target-normalization, PLT/GOT resolution, inline-parent attribution,
DWARF call-site relation, or source-level call denominator is supplied here.

## Publication and limits

The request bounds roots, instructions per root, aggregate instructions, calls,
work units, canonical output bytes, and wall time. Its maximum accepted ceilings
are 131,072 roots; 1,000,000 instructions per root; 10,000,000 aggregate
instructions; 1,000,000 calls; 100,000,000 work units; 64 MiB output; and 30 minutes.
These are computation bounds, not an achieved compiler-scale performance result
or host-enforced CPU/RSS/disk limits.

The canonical function-oracle loader currently retains its existing 20,000-record
limit. The larger traversal ceilings do not remove that input limit or establish
cc1/full-tree scale support. Inputs exceeding any supported bound fail without
silently shrinking the population.

`IndependentMachineCallReportV1` validates the closed component report before it
is returned. Its bounded canonical parser also accepts retained component bytes.
Validation checks field sets, authority flags, inventory order and uniqueness,
origin and root references, extent/site coordinates, instruction-byte lengths,
typed/raw target agreement, recomputed dispositions, stop inventories, and counts.
Worker validation additionally binds the full request digest, runtime, input
digests and byte count, and limits. This checks report consistency; authentic
instruction semantics still come from the authenticated byte decoder and inputs.
It does not turn caller-authored JSON into authenticated positive evidence.

After successful validation, the worker stages and syncs the complete canonical
result, rechecks its output parent, and publishes with an atomic hard-link create.
An existing output is never replaced. Failure is not permission to publish a
partial result as complete or erase earlier evidence.

## Verification scope

`tests/oracle/test_byte_instruction_decoder.py` compiles the actual bridge against
the bundled APIs and runs `ByteInstructionDecoderControls.java` on authored byte
strings. The controls cover direct and indirect calls, signed relative
displacements and unsigned addresses, conditional/direct/computed jumps,
returns, ordinary instructions followed by call bytes, traps, context changes,
truncation, bounds, cancellation, immutable output, and runtime/language refusal.
They import or execute no target ELF.
The Python control launches them through a separate loader with Ghidra absent
from the boot JVM classpath and checks that initialization leaves that classpath
unchanged. The worker integration tests separately exercise the authenticated
explicit-JAR loader in a fresh process.

`IndependentMachineCallReportV1Test` mutates an authored generated component
report to reject forged positives, stale counts, reordered or duplicate
inventories, unknown fields, changed byte/extent coordinates, authority flags,
and mismatched worker commitments.

From a checkout with a staged bundle, run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.oracle.test_byte_instruction_decoder -v
```

`DECOMP_BYTE_DECODER_GHIDRA_RELEASE` can select an existing bundled release for
the authored API controls. These tests verify decoder behavior; they do not
authenticate a retained compiler run or establish production oracle authority.

The [retained GCC driver component evidence](../../oracle/gcc/16.2.0/machine-call-component-v1/README.md)
contains the exact compressed report, original request, source/input commitments,
and a bounded offline verifier with create-new extraction. Its producer JAR hash
remains a recorded build observation; the retained material grants no production
or source-to-binary attestation authority.

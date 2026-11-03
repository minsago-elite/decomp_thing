# Native call observations v1

Status: implementation contract; production qualification is incomplete. These are native observations and byte assessments, not oracle identities, scored recovery, or release authority.

The production route requires the retained pinned selected cc1 or driver profile. Authored ELF controls cannot create the production operation capability. Existing model exporter bytes and invocation encodings remain unchanged. New versions are runtime 8, operation intent 5, and containment definition 5. The fresh command is `gcc-engine-native-calls <cc1|driver>`; it does not support resume or an arbitrary collector.

## Output and traversal

The compiled collector runs after the unchanged full-model export against the same bundled Ghidra Program. It inventories every non-external recovered function, including thunks and zero-call functions; scans `Listing.getInstructions(true)` globally; and emits per-function summaries. Ownership is `getFunctionContaining(address)` or null. Ordinary non-call instructions are counted, not emitted as site records.

Site selection, in precedence order:

1. `prototype-call`: the raw prototype reports a call.
2. `analysis-call-candidate`: effective flow or a persisted reference reports a call but the prototype does not.
3. `direct-tail-candidate`: an unconditional noncomputed prototype jump to an exact different recovered function outside the owning body. This remains a candidate, not an asserted call.

Ordinary conditional/internal branches and switch jumps are not calls. Unresolved computed jumps remain separate coverage counters. Use `prototype.getFlowType(context)` and `prototype.getFlows(context)` before overrides; do not substitute `getDefaultFlows()`.

The new operation owns `reports/native-calls-v1/manifest.json` and `reports/native-calls-v1/native-calls.json`. The native directory must be absent before collection and is created after START. Publish the manifest last, after closing the stream and rechecking the paired model. The combined inventory is at most 1 GiB; the manifest is at most 64 KiB. No shards are used.

## Closed JSON grammar

All objects have exactly the following fields. Arrays and records have deterministic native address ordering. Strings preserve bounded native metadata and do not normalize names into identities.

```text
NativeCallsRootV1 {
  addressSpaces: [AddressSpace],
  bindings: NativeCallBindingsV1,
  policy: "ghidra-native-call-observations-v1",
  records: [FunctionRecord | SiteRecord | FunctionSummaryRecord],
  schemaVersion: 1,
  summary: ScanSummary
}

NativeCallBindingsV1 {
  collectorSha256: sha256,
  compilerSpecId: string,
  ghidraArchiveSha256: sha256,
  imageBase: Address,
  inputSha256: sha256,
  languageId: string,
  programModelBytes: positive integer,
  programModelExporterSha256: sha256,
  programModelSha256: sha256
}

ManifestV1 {
  bytes: positive integer,
  collectorSha256: sha256,
  file: "native-calls.json",
  inputSha256: sha256,
  kind: "ghidra-native-call-observation-manifest-v1",
  programModelSha256: sha256,
  schemaVersion: 1,
  sha256: sha256
}

AddressSpace {
  index: integer,
  name: string,
  type: integer,
  sizeBits: integer,
  addressableUnitSize: positive integer,
  overlay: boolean,
  signedOffsets: boolean
}

Address = { kind: "no-address" }
        | { kind: "address", spaceIndex: integer, offsetBits: hex64 }

FunctionRecord {
  recordKind: "function",
  entry: Address,
  bodyAddressCount: nonnegative integer,
  bodyRangeCount: nonnegative integer,
  isThunk: boolean,
  immediateThunkTarget: TargetObservation | null
}

SiteRecord {
  recordKind: "site",
  address: Address,
  owner: Address | null,
  observationKind: "prototype-call" | "analysis-call-candidate" | "direct-tail-candidate",
  listedLength: integer,
  delaySlotDepth: nonnegative integer,
  lengthOverridden: boolean,
  byteStatus: "available" | "unsupported-boundary",
  instructionBytes: lowercase hex | null,
  prototypeFlow: ReferenceType,
  effectiveFlow: ReferenceType,
  flowOverride: native enum string,
  prototypeFallThrough: Address | null,
  effectiveFallThrough: Address | null,
  prototypeTargets: [TargetObservation],
  references: [ReferenceObservation],
  referenceNeighborhoods: [ReferenceNeighborhood]
}

FunctionSummaryRecord {
  recordKind: "function-summary",
  entry: Address,
  instructionsVisited: nonnegative integer,
  prototypeCalls: nonnegative integer,
  analysisCallCandidates: nonnegative integer,
  directTailCandidates: nonnegative integer,
  ordinaryJumpInstructions: nonnegative integer,
  unresolvedComputedJumps: nonnegative integer
}

ReferenceType { code: integer, name: string }

TargetObservation {
  address: Address,
  functionEntry: Address | null,
  external: ExternalObservation | null,
  memoryBlock: MemoryBlockObservation | null
}

ReferenceObservation {
  from: Address,
  target: TargetObservation,
  operandIndex: integer,
  primary: boolean,
  source: native SourceType string,
  referenceType: ReferenceType
}

ExternalObservation {
  externalSpaceAddress: Address,
  externalProgramAddress: Address | null,
  libraryName: string,
  label: string,
  originalImportedName: string | null,
  source: native SourceType string
}

MemoryBlockObservation {
  name: string,
  start: Address,
  end: Address,
  initialized: boolean,
  executable: boolean
}

ReferenceNeighborhood {
  viaReferenceIndex: nonnegative integer,
  source: Address,
  references: [ReferenceObservation]
}
```

`hex64` is exactly 16 lowercase hexadecimal characters preserving the native 64-bit offset representation, not an RVA. Sort the bounded address-space table by native `AddressSpace.compareTo()` before assigning indices; `getAllAddressSpaces()` insertion order can differ from global listing order. Order function/site addresses by table index and signed or unsigned offset comparison declared by that space. Preserve EXTERNAL and other reference spaces. Reject an unrepresented space rather than dropping it.

The collector is target neutral. There is no x86 language restriction or 15-byte assumption. Delayed, length-overridden or oversized boundaries remain explicit unsupported records with null bytes; instruction-byte safety bound is 4 KiB. Actual API/read failures abort. Fall-through fields are observations, not derived return-PC claims.

Resolve function entries only with `getFunctionAt`. Retain immediate thunk targets with `getThunkedFunction(false)` without recursive semantic resolution; a thunk with unavailable immediate Function evidence aborts. Local target function entries must agree with the exhaustive native function inventory, including forward thunk targets. A nonnull external-program address must use native loaded-memory RAM/CODE space; it need not lie in the current binary's memory blocks or executable ranges. For a direct instruction reference to memory classified as data or INDIRECTION, retain references from that exact destination as one hop, including an empty neighborhood. They never fill missing prototype targets.

Validate native reference type code/name pairs against bundled Ghidra 12.1.3. SourceType values are `DEFAULT`, `ANALYSIS`, `AI`, `IMPORTED`, `USER_DEFINED`; verify these against the bundled API before implementation. Native nullable metadata stays nullable.

## Coverage and resource bounds

`ScanSummary.coverage` is `all-currently-listed-instructions-and-recovered-functions`. It means traversal of the current Ghidra listing, not complete binary decoding. Its exact fields are `coverage`, `functions`, `thunks`, `instructionsVisited`, `ownedInstructions`, `unownedInstructions`, `sites`, `prototypeCalls`, `analysisCallCandidates`, `directTailCandidates`, `ordinaryJumpInstructions`, `unresolvedComputedJumps`, `directReferences`, `neighborhoodReferences`, `unownedPrototypeCalls`, `unownedAnalysisCallCandidates`, and `unownedDirectTailCandidates`. Ordinary jumps are prototype jumps not selected as any site category. Unresolved computed jumps are prototype computed jumps with no persisted non-INDIRECTION call/jump flow reference to a memory or EXTERNAL address; this is coverage, not call credit.

The stream phases are all function inventories, then all sites, then all function summaries. Validation checks phase order, unique addresses, ownership membership, every summary, canonical bytes, exact length and digest. It retains only a bounded function-counter inventory and one record. Callbacks are speculative until successful return.

Maxima: 131,072 functions; 100,000,000 visited instructions; 10,000,000 sites; 256 address spaces; 64 prototype targets per site; 64 references per source address; 256 retained references per site including neighborhoods; 1 MiB per record; 4 KiB UTF-8 per metadata string; only `instructionBytes` allows 8 KiB of encoded hexadecimal for its 4 KiB native-byte cap; depth 16. Check native reference count before allocation and returned array length afterward. Overflow fails without truncation. Existing operation wall, CPU, memory and filesystem ceilings remain enforced throughout.

## Internal parser and capture interfaces

```kotlin
data class NativeCallObservationLimitsV1(/* declared maxima; tests may lower */)
data class NativeCallBindingsV1(/* closed binding fields above */)
data class NativeCallManifestV1(/* closed manifest fields above */)
sealed interface NativeCallRecordV1
data class NativeCallObservationSummaryV1(/* validated counts and hashes */)

object NativeCallObservationsV1 {
    fun validate(
        manifestBytes: ByteArray,
        expectedBindings: NativeCallBindingsV1,
        limits: NativeCallObservationLimitsV1,
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (NativeCallRecordV1) -> Unit = {},
    ): NativeCallObservationSummaryV1
}
```

The collector takes exactly six arguments: input SHA-256, unchanged model-exporter SHA-256, pinned Ghidra-archive SHA-256, collector-source SHA-256, paired model path, and absent output directory. Only the compiled `ExportNativeCallsV1.class` post-script is allowed; the source is staged as a resource for independent digest binding, not executed or recompiled by the worker.

Capture uses `validateBoundToSpaces` internally when its independent image-base binding must resolve a validated space-table index. Its expected-binding factory is invoked once after the closed table is read, before records. The concrete-bindings `validate` method delegates to this same implementation.

Add an internal owned-stream overload to `FullTreeCanonicalStreaming`, retaining its path API/checks. Capture supplies a stream from its retained readable descriptor, never a reopened caller-selected path.

The coordinator adds `executeNativeCallObservations(): GccBundledNativeCallOperation` and `publishNativeCallCliResult(): Path`. The operation uses the existing private coordinator construction permit and retains admitted intent, execution receipt, model snapshot, native capture and assessment. It has no constructor accepting caller-provided verified evidence.

Capture follows existing descriptor types: retained run descriptor, control name and expected identity, captured `GccBundledFullExportSnapshot`, expected native bindings, limits and checkpoint. The resulting `GccBundledNativeCallSnapshot` is byte-assessment evidence. Only the retained coordinator can create the production operation handle.

After proved worker/cgroup absence, capture the unchanged full model, then the exact native directory through pinned descriptors. Require exact membership, private ownership/mount identity, regular single-link files, stable metadata and matching model/input/collector/target bindings. The capture applies the existing stronger aggregate limit: the retained full-model tree (model, sidecars, state and progress) plus native observations and manifest must fit within 1 GiB. Qualification must prove that the actual pinned cc1 artifacts fit this limit. Preserve native-only thunks even when their targets have no current binary backing; exact non-thunk entries still match the admitted model's default-memory census. Recheck model/progress/checkpoint identities before publication. Reuse the linked execution/assessment journal envelope with a new native payload. Publish small immutable binding/result documents pointing to retained scratch evidence. Complete expensive validation and cancellation checks before the durable result marker; once that marker succeeds, return its success without a post-marker cancellation check. They remain unscored, release-ineligible and unqualified for cold recovery. Runtime 8 is rejected by ordinary full-export publication/planning/resume methods. The selected driver post-freeze path below extends model provenance and boundary replay; it does not grant call-domain scoring authority.

## Verification boundary

Real compiled native controls cover repeated/recursive direct calls, zero-call functions and an unowned disassembled call; resolved/unresolved register/memory indirect calls; branch/switch discrimination and separately tagged tails; PLT and `-fno-plt` EXTERNAL/pointer-slot provenance; immediate thunks; RETURN/CALL_RETURN overrides and unsupported boundaries; repeated deterministic collection and unchanged model/progress/checkpoint bytes. Owned capture controls reject substitutions, extra files, malformed coverage, stale destinations, overflow and cancellation without successful publication.

Small authored ELF controls are not production qualification. Production acceptance requires an actual pinned cc1 collection through the normal CLI and independently verified deterministic regeneration. Structural admission, selected independent identities, production replay, scoring and full milestone requirements remain incomplete.

### Selected driver capture

The driver uses the same compiled collector, closed raw observation format,
serial runtime v8 and fresh intent v5 as cc1. Its retained profile selects the
independently pinned driver input and target; cross-target input, profile,
manifest, runtime and CLI substitutions are rejected before execution. Native
capture remains a separate operation from ordinary full export and cannot resume.
The contained recovery worker receives no independent call oracle.

Use the `qualify:driver-native-calls` PR label to select normal installed-CLI
capture. It coexists with `qualify:driver-full-export`. Qualification retains the
whole raw native stream and manifest, paired model, exporter/runtime/collector
bindings and execution/assessment lineage. It replays every raw record twice
against the independently pinned target and model commitments and retains a
population summary. This checks deterministic byte interpretation, not a second
execution of the native producer.

The frozen population includes prototype calls, analysis-call candidates and
direct-tail candidates as distinct categories. Repeated, external, indirect,
unowned and synthetic-address-space observations keep their original coordinates
and metadata; none is removed by matching against oracle positives. Consumers
must retain these distinctions and visible unknowns when mapping to the shared
call-site contract. Ghidra observations are recovered claims, never oracle truth.
This driver extension does not close the original cc1 production qualification,
complete call identity mapping or call-scoring outcomes.

### Post-freeze selected driver replay

For the driver, normal native CLI publication continues after raw capture through
two additional contained JVMs. The existing selected-boundary worker first
replays the exact model paired with the native stream. A native operation cannot
borrow the model or admission capability from another full export. The native
receipt chain, profile, exporter, loaded target, image base, model bytes and
output tree are checked by the same structural model-binding policy used by
ordinary full export. The independent host boundary observation must agree with
the contained replay before its opaque selected input capability is retained.

Only after this freeze does the independent machine-call worker receive the
pinned rich ELF and canonical oracle. Its explicit bundled decoder runtime is
bound to the retained application's bridge, inventory and release archive. It
receives no recovered model, native observations or recovered function names.
The launcher protects the original state, model/native reports and completed
control directories as read-only, retains stable rich/oracle inputs, and proves
worker/cgroup absence before a bounded descriptor capture. Before START and
after absence, the host rechecks both raw native files and their paired model.
Each additional worker has at most five minutes and 4 GiB within the remaining
original operation deadline; these limits do not establish measured terminal
CPU, memory or PID counters.

Driver native `result.json` is version 2 and points to the selected boundary
score, the independent positive report and `native-structural-replay-binding.json`.
The request, attachment, START authorization, execution and capture documents
remain separate evidence. The original component report keeps its own false
completion, negative-completeness and release flags; its authenticated producer
execution is established by the coordinator-owned operation, not by replacing
those flags. cc1 retains native result version 1; selected replay is not enabled for that
target.

The only scored domains remain model provenance, selected function boundaries
and surviving symbol identities. `CALLS` is unavailable pending the shared
complete-population projection and independent external composition. Unmatched
recovered records do not become fabricated facts merely because the positive
producer lacks a matching observation. The hosted driver native lane retains
and validates both additional executions and independently replays the selected
boundary observation. A successful component or local test is not evidence that
this hosted lane has completed.

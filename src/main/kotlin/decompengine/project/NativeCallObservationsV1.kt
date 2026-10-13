package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeCanonicalStreaming
import decompengine.oracle.fulltree.FullTreeCanonicalStreamingLimits
import java.io.InputStream
import java.math.BigInteger
import kotlinx.serialization.json.*

/** Native coordinates; offsetBits preserves the exact native long representation, never an RVA. */
data class NativeCallAddressV1(val spaceIndex: Int?, val offsetBits: String?) {
    init { require((spaceIndex == null) == (offsetBits == null)); require(spaceIndex == null || spaceIndex >= 0); require(offsetBits == null || offsetBits.matches(Regex("[0-9a-f]{16}"))) }
    val isNoAddress: Boolean get() = spaceIndex == null
}
data class NativeCallAddressSpaceV1(val index: Int, val name: String, val type: Int, val sizeBits: Int, val addressableUnitSize: Int, val overlay: Boolean, val signedOffsets: Boolean)
data class NativeCallBindingsV1(
    val collectorSha256: String, val compilerSpecId: String, val ghidraArchiveSha256: String,
    val imageBase: NativeCallAddressV1, val inputSha256: String, val languageId: String,
    val programModelBytes: Long, val programModelExporterSha256: String, val programModelSha256: String,
)
data class NativeCallManifestV1(val bytes: Long, val collectorSha256: String, val file: String, val inputSha256: String, val kind: String, val programModelSha256: String, val schemaVersion: Int, val sha256: String)
data class NativeCallReferenceTypeV1(val code: Int, val name: String)
data class NativeCallExternalV1(val externalSpaceAddress: NativeCallAddressV1, val externalProgramAddress: NativeCallAddressV1?, val libraryName: String, val label: String, val originalImportedName: String?, val source: String)
data class NativeCallMemoryBlockV1(val name: String, val start: NativeCallAddressV1, val end: NativeCallAddressV1, val initialized: Boolean, val executable: Boolean)
data class NativeCallTargetV1(val address: NativeCallAddressV1, val functionEntry: NativeCallAddressV1?, val external: NativeCallExternalV1?, val memoryBlock: NativeCallMemoryBlockV1?)
data class NativeCallReferenceV1(val from: NativeCallAddressV1, val target: NativeCallTargetV1, val operandIndex: Int, val primary: Boolean, val source: String, val referenceType: NativeCallReferenceTypeV1)
data class NativeCallReferenceNeighborhoodV1(val viaReferenceIndex: Int, val source: NativeCallAddressV1, val references: List<NativeCallReferenceV1>)
sealed interface NativeCallRecordV1
/** Function and site metadata are native observations. None of these records grants production authority. */
data class NativeCallFunctionRecordV1(val entry: NativeCallAddressV1, val bodyAddressCount: Long, val bodyRangeCount: Long, val isThunk: Boolean, val immediateThunkTarget: NativeCallTargetV1?) : NativeCallRecordV1
data class NativeCallSiteRecordV1(
    val address: NativeCallAddressV1, val owner: NativeCallAddressV1?, val observationKind: String,
    val listedLength: Int, val delaySlotDepth: Int, val lengthOverridden: Boolean, val byteStatus: String,
    val instructionBytes: String?, val prototypeFlow: NativeCallReferenceTypeV1, val effectiveFlow: NativeCallReferenceTypeV1,
    val flowOverride: String, val prototypeFallThrough: NativeCallAddressV1?, val effectiveFallThrough: NativeCallAddressV1?,
    val prototypeTargets: List<NativeCallTargetV1>, val references: List<NativeCallReferenceV1>,
    val referenceNeighborhoods: List<NativeCallReferenceNeighborhoodV1>,
) : NativeCallRecordV1
data class NativeCallFunctionSummaryRecordV1(
    val entry: NativeCallAddressV1, val instructionsVisited: Long, val prototypeCalls: Long,
    val analysisCallCandidates: Long, val directTailCandidates: Long, val ordinaryJumpInstructions: Long,
    val unresolvedComputedJumps: Long,
) : NativeCallRecordV1
data class NativeCallScanSummaryV1(
    val coverage: String, val functions: Long, val thunks: Long, val instructionsVisited: Long,
    val ownedInstructions: Long, val unownedInstructions: Long, val sites: Long, val prototypeCalls: Long,
    val analysisCallCandidates: Long, val directTailCandidates: Long, val ordinaryJumpInstructions: Long,
    val unresolvedComputedJumps: Long, val directReferences: Long, val neighborhoodReferences: Long,
    val unownedPrototypeCalls: Long, val unownedAnalysisCallCandidates: Long, val unownedDirectTailCandidates: Long,
)
data class NativeCallObservationSummaryV1(
    val manifest: NativeCallManifestV1, val bindings: NativeCallBindingsV1,
    val addressSpaces: List<NativeCallAddressSpaceV1>, val scanSummary: NativeCallScanSummaryV1,
    val records: Long, val observationsSha256: String, val observationsBytes: Long,
) {
    val authoritativeOracleEvidence: Boolean = false
    val recoveredModelScored: Boolean = false
    val releaseEligible: Boolean = false
}
data class NativeCallObservationLimitsV1(
    val maximumCombinedBytes: Long = 1024L * 1024 * 1024,
    val maximumManifestBytes: Int = 64 * 1024,
    val maximumFunctions: Int = 131_072,
    val maximumInstructions: Long = 100_000_000L,
    val maximumSites: Long = 10_000_000L,
    val maximumAddressSpaces: Int = 256,
    val maximumPrototypeTargets: Int = 64,
    val maximumReferencesPerSource: Int = 64,
    val maximumReferencesPerSite: Int = 256,
    val maximumRecordBytes: Int = 1024 * 1024,
    val maximumStringBytes: Int = 4096,
    val maximumDepth: Int = 16,
) {
    init {
        require(maximumCombinedBytes in 1..1024L * 1024 * 1024); require(maximumManifestBytes in 1..64 * 1024)
        require(maximumFunctions in 1..131_072); require(maximumInstructions in 1..100_000_000L); require(maximumSites in 1..10_000_000L)
        require(maximumAddressSpaces in 1..256); require(maximumPrototypeTargets in 1..64); require(maximumReferencesPerSource in 1..64)
        require(maximumReferencesPerSite in 1..256); require(maximumRecordBytes in 1..1024 * 1024)
        require(maximumStringBytes in 1..4096 && maximumStringBytes <= maximumRecordBytes); require(maximumDepth in 1..16)
    }
}

/** Strict byte assessment. All consume callbacks are speculative until successful return. */
object NativeCallObservationsV1 {
    fun validate(
        manifestBytes: ByteArray,
        expectedBindings: NativeCallBindingsV1,
        limits: NativeCallObservationLimitsV1 = NativeCallObservationLimitsV1(),
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (NativeCallRecordV1) -> Unit = {},
    ): NativeCallObservationSummaryV1 {
        validateExpected(expectedBindings)
        return validateBoundToSpaces(manifestBytes, { expectedBindings }, limits, checkpoint, openObservations, consume)
    }

    internal fun validateBoundToSpaces(
        manifestBytes: ByteArray,
        expectedBindings: (List<NativeCallAddressSpaceV1>) -> NativeCallBindingsV1,
        limits: NativeCallObservationLimitsV1 = NativeCallObservationLimitsV1(),
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (NativeCallRecordV1) -> Unit = {},
    ): NativeCallObservationSummaryV1 {
        checkpoint()
        require(manifestBytes.size in 1..limits.maximumManifestBytes) { "native-call manifest exceeds its bound" }
        val manifestObject = OracleJson.parse(manifestBytes, strictLimits(limits, limits.maximumManifestBytes)) as? JsonObject
            ?: error("native-call manifest must be an object")
        require(OracleJson.canonicalBytes(manifestObject).contentEquals(manifestBytes)) { "native-call manifest must be canonical" }
        fields(manifestObject, "bytes", "collectorSha256", "file", "inputSha256", "kind", "programModelSha256", "schemaVersion", "sha256")
        val manifest = NativeCallManifestV1(count(manifestObject, "bytes"), digest(manifestObject, "collectorSha256"), text(manifestObject, "file"), digest(manifestObject, "inputSha256"), text(manifestObject, "kind"), digest(manifestObject, "programModelSha256"), integer(manifestObject, "schemaVersion"), digest(manifestObject, "sha256"))
        require(manifest.schemaVersion == 1 && manifest.file == "native-calls.json" && manifest.kind == "ghidra-native-call-observation-manifest-v1") { "unsupported native-call manifest" }
        require(manifest.bytes > 0 && manifest.bytes <= limits.maximumCombinedBytes - manifestBytes.size) { "native-call inventory exceeds combined byte bound" }
        var resolvedExpected: NativeCallBindingsV1? = null
        var spaces: List<NativeCallAddressSpaceV1>? = null
        var binding: NativeCallBindingsV1? = null
        var scan: NativeCallScanSummaryV1? = null
        val functionCounters = linkedMapOf<NativeCallAddressV1, Counters>()
        var phase = 0
        var previousFunction: NativeCallAddressV1? = null
        var previousSite: NativeCallAddressV1? = null
        var previousSummary: NativeCallAddressV1? = null
        val totals = Counters()
        val unowned = Counters()
        var thunks = 0L
        var siteCount = 0L
        var directReferences = 0L
        var neighborhoodReferences = 0L
        var recordCount = 0L
        var inventoryComplete = false
        fun checkTargetFunction(target: NativeCallTargetV1) {
            val address = target.address
            if (!address.isNoAddress && checkNotNull(spaces)[address.spaceIndex!!].type != 10) {
                require((target.functionEntry != null) == functionCounters.containsKey(address)) {
                    "native target function entry disagrees with exhaustive inventory"
                }
            }
        }
        fun finishInventory() {
            if (!inventoryComplete) {
                functionCounters.values.forEach { counter ->
                    checkpoint()
                    counter.thunkEntry?.let { require(functionCounters.containsKey(it)) { "immediate native thunk target is outside exhaustive inventory" } }
                    counter.thunkEntry = null
                }
                inventoryComplete = true
            }
        }
        fun context() = Context(checkNotNull(spaces), limits)
        val streamed = openObservations().use { input -> FullTreeCanonicalStreaming.readObject(
            input, "native-call observations", manifest.sha256, manifest.bytes,
            listOf("addressSpaces", "bindings", "policy", "records", "schemaVersion", "summary"), setOf("records"), null,
            FullTreeCanonicalStreamingLimits(
                maximumInputBytes = manifest.bytes, maximumTokens = 1_000_000_000,
                maximumEntities = limits.maximumSites + 2L * limits.maximumFunctions,
                maximumEntityBytes = limits.maximumRecordBytes, maximumEntityNodes = 100_000,
                maximumDepth = limits.maximumDepth,
                maximumStringBytes = minOf(limits.maximumRecordBytes, maxOf(limits.maximumStringBytes, 8192)),
                maximumTotalStringBytes = manifest.bytes, maximumNumberCharacters = 20,
            ),
            consumeEnvelope = { field, value ->
                checkpoint()
                validateMetadataStrings(value, limits.maximumStringBytes)
                when (field) {
                    "addressSpaces" -> {
                        spaces = parseSpaces(value, limits)
                        resolvedExpected = expectedBindings(checkNotNull(spaces).toList()).also {
                            validateExpected(it)
                            require(manifest.collectorSha256 == it.collectorSha256 && manifest.inputSha256 == it.inputSha256 && manifest.programModelSha256 == it.programModelSha256) { "native-call manifest binding mismatch" }
                        }
                    }
                    "bindings" -> {
                        binding = context().bindings(obj(value))
                        require(binding == resolvedExpected) { "native-call observations input/model/collector/target binding mismatch" }
                    }
                    "policy" -> require(string(value) == "ghidra-native-call-observations-v1") { "unsupported native-call policy" }
                    "schemaVersion" -> require(number(value) == 1L) { "unsupported native-call schema" }
                    "summary" -> scan = parseScan(obj(value))
                }
            },
        ) { _, _, value, _ ->
            checkpoint()
            recordCount = Math.addExact(recordCount, 1)
            val ctx = context()
            validateMetadataStrings(value, limits.maximumStringBytes)
            when (text(value, "recordKind")) {
                "function" -> {
                    require(phase == 0) { "native function inventory must precede sites/summaries" }
                    fields(value, "recordKind", "entry", "bodyAddressCount", "bodyRangeCount", "isThunk", "immediateThunkTarget")
                    val entry = ctx.address(value.getValue("entry")); require(!entry.isNoAddress && ctx.spaces[entry.spaceIndex!!].type != 10) { "native function inventory cannot include EXTERNAL entries" }
                    require(previousFunction == null || ctx.compare(previousFunction!!, entry) < 0) { "native functions must be unique and ordered" }
                    previousFunction = entry
                    require(functionCounters.size < limits.maximumFunctions) { "native function inventory bound exceeded" }
                    val thunk = bool(value, "isThunk"); val target = ctx.nullableTarget(value.getValue("immediateThunkTarget"))
                    require(thunk == (target != null) && (target == null || target.functionEntry != null)) {
                        "native thunk target evidence is incomplete or misplaced"
                    }
                    val body = count(value, "bodyAddressCount"); val ranges = count(value, "bodyRangeCount")
                    require((body == 0L) == (ranges == 0L) && ranges <= body) { "invalid native function body counts" }
                    functionCounters[entry] = Counters().also { it.thunkEntry = target?.functionEntry?.takeIf { ctx.spaces[it.spaceIndex!!].type != 10 } }
                    if (thunk) thunks++
                    consume(NativeCallFunctionRecordV1(entry, body, ranges, thunk, target))
                }
                "site" -> {
                    require(phase <= 1) { "native sites must precede summaries" }; phase = 1
                    finishInventory()
                    val site = ctx.site(value)
                    require(previousSite == null || ctx.compare(previousSite!!, site.address) < 0) { "native sites must be unique and ordered" }; previousSite = site.address
                    site.prototypeTargets.forEach(::checkTargetFunction)
                    site.references.forEach { checkTargetFunction(it.target) }
                    site.referenceNeighborhoods.forEach { neighborhood -> neighborhood.references.forEach { checkTargetFunction(it.target) } }
                    val owner = site.owner?.let { functionCounters[it] ?: error("site owner is outside function inventory") } ?: unowned
                    owner.site(site.observationKind); totals.site(site.observationKind)
                    siteCount = Math.addExact(siteCount, 1); require(siteCount <= limits.maximumSites)
                    directReferences = Math.addExact(directReferences, site.references.size.toLong())
                    neighborhoodReferences = Math.addExact(neighborhoodReferences, site.referenceNeighborhoods.sumOf { it.references.size.toLong() })
                    consume(site)
                }
                "function-summary" -> {
                    phase = 2
                    finishInventory()
                    fields(value, "recordKind", "entry", "instructionsVisited", "prototypeCalls", "analysisCallCandidates", "directTailCandidates", "ordinaryJumpInstructions", "unresolvedComputedJumps")
                    val entry = ctx.address(value.getValue("entry"))
                    require(previousSummary == null || ctx.compare(previousSummary!!, entry) < 0) { "native summaries must be unique and ordered" }; previousSummary = entry
                    val counters = functionCounters[entry] ?: error("summary is outside function inventory")
                    require(!counters.summarized); counters.summarized = true
                    val summary = NativeCallFunctionSummaryRecordV1(entry, count(value, "instructionsVisited"), count(value, "prototypeCalls"), count(value, "analysisCallCandidates"), count(value, "directTailCandidates"), count(value, "ordinaryJumpInstructions"), count(value, "unresolvedComputedJumps"))
                    require(summary.prototypeCalls == counters.prototype && summary.analysisCallCandidates == counters.analysis && summary.directTailCandidates == counters.tail) { "function site coverage mismatch" }
                    require(summary.instructionsVisited <= limits.maximumInstructions && summary.ordinaryJumpInstructions <= summary.instructionsVisited && summary.unresolvedComputedJumps <= summary.instructionsVisited && summary.instructionsVisited >= Math.addExact(counters.sites(), summary.ordinaryJumpInstructions) && summary.unresolvedComputedJumps <= Math.addExact(summary.ordinaryJumpInstructions, summary.analysisCallCandidates)) { "contradictory native function instruction coverage" }
                    counters.instructions = summary.instructionsVisited; counters.ordinary = summary.ordinaryJumpInstructions; counters.unresolved = summary.unresolvedComputedJumps
                    require(counters.instructions <= limits.maximumInstructions)
                    consume(summary)
                }
                else -> error("unsupported native-call record kind")
            }
        } }
        finishInventory()
        val summary = checkNotNull(scan)
        require(functionCounters.values.all { it.summarized }) { "native function summaries are incomplete" }
        val ownedInstructions = functionCounters.values.fold(0L) { count, item -> Math.addExact(count, item.instructions) }
        val ownedOrdinary = functionCounters.values.fold(0L) { count, item -> Math.addExact(count, item.ordinary) }
        val ownedUnresolved = functionCounters.values.fold(0L) { count, item -> Math.addExact(count, item.unresolved) }
        require(summary.coverage == "all-currently-listed-instructions-and-recovered-functions")
        require(summary.functions == functionCounters.size.toLong() && summary.thunks == thunks)
        require(summary.sites == siteCount && summary.prototypeCalls == totals.prototype && summary.analysisCallCandidates == totals.analysis && summary.directTailCandidates == totals.tail)
        require(summary.unownedPrototypeCalls == unowned.prototype && summary.unownedAnalysisCallCandidates == unowned.analysis && summary.unownedDirectTailCandidates == unowned.tail)
        require(summary.directReferences == directReferences && summary.neighborhoodReferences == neighborhoodReferences)
        require(summary.ownedInstructions == ownedInstructions && summary.instructionsVisited == Math.addExact(ownedInstructions, summary.unownedInstructions) && summary.instructionsVisited <= limits.maximumInstructions)
        require(summary.unownedInstructions >= unowned.sites() && summary.ordinaryJumpInstructions >= ownedOrdinary && summary.unresolvedComputedJumps >= ownedUnresolved)
        require(summary.ordinaryJumpInstructions - ownedOrdinary <= summary.unownedInstructions - unowned.sites())
        require(summary.unresolvedComputedJumps - ownedUnresolved <= summary.ordinaryJumpInstructions - ownedOrdinary + unowned.analysis)
        require(summary.ordinaryJumpInstructions <= summary.instructionsVisited && summary.unresolvedComputedJumps <= summary.instructionsVisited && summary.instructionsVisited >= Math.addExact(siteCount, summary.ordinaryJumpInstructions))
        require(recordCount == siteCount + 2L * functionCounters.size)
        checkpoint()
        return NativeCallObservationSummaryV1(manifest, checkNotNull(binding), checkNotNull(spaces).toList(), summary, recordCount, streamed.sourceSha256, streamed.sourceBytes)
    }

    private class Counters {
        var prototype = 0L; var analysis = 0L; var tail = 0L; var instructions = 0L; var ordinary = 0L; var unresolved = 0L; var summarized = false
        var thunkEntry: NativeCallAddressV1? = null
        fun site(kind: String) { when(kind) { "prototype-call" -> prototype++; "analysis-call-candidate" -> analysis++; "direct-tail-candidate" -> tail++; else -> error("invalid site kind") } }
        fun sites() = Math.addExact(Math.addExact(prototype, analysis), tail)
    }
    private class Context(val spaces: List<NativeCallAddressSpaceV1>, val limits: NativeCallObservationLimitsV1) {
        fun address(value: JsonElement): NativeCallAddressV1 {
            val node = obj(value)
            return when(text(node, "kind")) {
                "no-address" -> { fields(node, "kind"); NativeCallAddressV1(null, null) }
                "address" -> {
                    fields(node, "kind", "spaceIndex", "offsetBits")
                    val index = integer(node, "spaceIndex"); require(index in spaces.indices)
                    val bits = text(node, "offsetBits"); require(bits.matches(HEX64))
                    val space = spaces[index]
                    val span = nativeSpan(space.sizeBits, space.addressableUnitSize)
                    val offset = if (space.signedOffsets) BigInteger.valueOf(bits.toULong(16).toLong()) else BigInteger(bits,16)
                    require(if(space.signedOffsets) offset >= span.shiftRight(1).negate() && offset < span.shiftRight(1) else offset.signum() >= 0 && offset < span) { "native offset is outside declared address space" }
                    NativeCallAddressV1(index, bits)
                }
                else -> error("invalid native address kind")
            }
        }
        fun nullableAddress(value: JsonElement) = if (value == JsonNull) null else address(value)
        fun compare(left: NativeCallAddressV1, right: NativeCallAddressV1): Int {
            if (left.isNoAddress || right.isNoAddress) return when { left == right -> 0; left.isNoAddress -> -1; else -> 1 }
            val space = left.spaceIndex!!.compareTo(right.spaceIndex!!)
            if (space != 0) return space
            val l = left.offsetBits!!.toULong(16); val r = right.offsetBits!!.toULong(16)
            return if (spaces[left.spaceIndex].signedOffsets) l.toLong().compareTo(r.toLong()) else l.compareTo(r)
        }
        fun bindings(node: JsonObject): NativeCallBindingsV1 {
            fields(node, "collectorSha256", "compilerSpecId", "ghidraArchiveSha256", "imageBase", "inputSha256", "languageId", "programModelBytes", "programModelExporterSha256", "programModelSha256")
            return NativeCallBindingsV1(digest(node, "collectorSha256"), text(node, "compilerSpecId"), digest(node, "ghidraArchiveSha256"), address(node.getValue("imageBase")), digest(node, "inputSha256"), text(node, "languageId"), count(node, "programModelBytes"), digest(node, "programModelExporterSha256"), digest(node, "programModelSha256"))
        }
        fun target(value: JsonElement): NativeCallTargetV1 {
            val node = obj(value); fields(node, "address", "functionEntry", "external", "memoryBlock")
            val address = address(node.getValue("address")); val entry = nullableAddress(node.getValue("functionEntry"))
            require(entry == null || !entry.isNoAddress && spaces[entry.spaceIndex!!].type in (MEMORY_TYPES + 10)) { "function target must name native memory or EXTERNAL space" }
            require(entry == null || entry == address) { "function entry must be exact target address" }
            val external = node.getValue("external").takeUnless { it == JsonNull }?.let { raw ->
                val x = obj(raw); fields(x, "externalSpaceAddress", "externalProgramAddress", "libraryName", "label", "originalImportedName", "source")
                val ext = address(x.getValue("externalSpaceAddress")); require(ext == address && !ext.isNoAddress && spaces[ext.spaceIndex!!].type == 10) { "external metadata must name target EXTERNAL space" }
                val externalAddress = nullableAddress(x.getValue("externalProgramAddress"))
                require(externalAddress == null || !externalAddress.isNoAddress && spaces[externalAddress.spaceIndex!!].type in setOf(1,2)) { "external program address must be native loaded memory" }
                NativeCallExternalV1(ext, externalAddress, text(x, "libraryName"), text(x, "label"), nullableText(x.getValue("originalImportedName")), source(x, "source"))
            }
            val block = node.getValue("memoryBlock").takeUnless { it == JsonNull }?.let { raw ->
                val b = obj(raw); fields(b, "name", "start", "end", "initialized", "executable")
                val start = address(b.getValue("start")); val end = address(b.getValue("end"))
                require(!address.isNoAddress && start.spaceIndex == address.spaceIndex && end.spaceIndex == address.spaceIndex && compare(start, address) <= 0 && compare(address, end) <= 0) { "target memory-block range mismatch" }
                NativeCallMemoryBlockV1(text(b, "name"), start, end, bool(b, "initialized"), bool(b, "executable"))
            }
            require((!address.isNoAddress && spaces[address.spaceIndex!!].type == 10) == (external != null)) { "EXTERNAL target metadata is incomplete or misplaced" }
            require(block == null || !address.isNoAddress && spaces[address.spaceIndex!!].type in MEMORY_TYPES) { "memory-block metadata must name native memory" }
            require(external == null || block == null)
            return NativeCallTargetV1(address, entry, external, block)
        }
        fun nullableTarget(value: JsonElement) = if(value == JsonNull) null else target(value)
        fun reference(value: JsonElement): NativeCallReferenceV1 {
            val node = obj(value); fields(node, "from", "target", "operandIndex", "primary", "source", "referenceType")
            return NativeCallReferenceV1(address(node.getValue("from")), target(node.getValue("target")), integer(node, "operandIndex"), bool(node, "primary"), source(node, "source"), refType(node.getValue("referenceType")))
        }
        fun references(value: JsonElement, from: NativeCallAddressV1): List<NativeCallReferenceV1> {
            val array = array(value); require(array.size <= limits.maximumReferencesPerSource)
            val refs = array.map(::reference); require(refs.all { it.from == from }) { "reference source mismatch" }
            require(refs.zipWithNext().all { (a,b) -> compareRefs(a,b) < 0 }) { "references must be unique and ordered" }
            return refs
        }
        fun compareRefs(a: NativeCallReferenceV1, b: NativeCallReferenceV1): Int {
            var c = compare(a.target.address, b.target.address); if(c != 0) return c
            c = a.operandIndex.compareTo(b.operandIndex); if(c != 0) return c
            c = a.referenceType.code.compareTo(b.referenceType.code); if(c != 0) return c
            c = a.source.compareTo(b.source); if(c != 0) return c
            return a.primary.compareTo(b.primary)
        }
        fun site(node: JsonObject): NativeCallSiteRecordV1 {
            fields(node, "recordKind", "address", "owner", "observationKind", "listedLength", "delaySlotDepth", "lengthOverridden", "byteStatus", "instructionBytes", "prototypeFlow", "effectiveFlow", "flowOverride", "prototypeFallThrough", "effectiveFallThrough", "prototypeTargets", "references", "referenceNeighborhoods")
            val addr = address(node.getValue("address")); require(!addr.isNoAddress)
            val owner = nullableAddress(node.getValue("owner")); require(owner == null || !owner.isNoAddress)
            val kind = text(node, "observationKind"); require(kind in SITE_KINDS)
            val length = integer(node, "listedLength"); require(length > 0)
            val delay = integer(node, "delaySlotDepth"); require(delay >= 0)
            val overridden = bool(node, "lengthOverridden"); val status = text(node, "byteStatus"); val bytes = if (node.getValue("instructionBytes") == JsonNull) null else string(node.getValue("instructionBytes")).also { require(it.length <= 8192) }
            val supported = !overridden && delay == 0 && length <= 4096
            require(if(supported) status == "available" && bytes != null && bytes.matches(Regex("[0-9a-f]{${length * 2}}")) else status == "unsupported-boundary" && bytes == null) { "native instruction byte/boundary status mismatch" }
            val proto = refType(node.getValue("prototypeFlow")); val effective = refType(node.getValue("effectiveFlow"))
            val override = text(node, "flowOverride"); require(override in setOf("NONE", "BRANCH", "CALL", "CALL_RETURN", "RETURN"))
            val rawTargets = array(node.getValue("prototypeTargets")); require(rawTargets.size <= limits.maximumPrototypeTargets)
            val targets = rawTargets.map(::target); require(targets.zipWithNext().all { (a,b) -> compare(a.address,b.address) < 0 }) { "prototype targets must be unique and ordered" }
            val refs = references(node.getValue("references"), addr)
            val neighborhoodsRaw = array(node.getValue("referenceNeighborhoods")); require(neighborhoodsRaw.size <= refs.size)
            var previous = -1
            val neighborhoods = neighborhoodsRaw.map { raw ->
                val n = obj(raw); fields(n, "viaReferenceIndex", "source", "references")
                val index = integer(n, "viaReferenceIndex"); require(index > previous && index in refs.indices); previous = index
                val from = address(n.getValue("source")); val via = refs[index]
                require(from == via.target.address && !from.isNoAddress && spaces[from.spaceIndex!!].type in MEMORY_TYPES && (via.referenceType.code in DATA_TYPES || via.referenceType.code == 9)) { "invalid one-hop reference provenance" }
                NativeCallReferenceNeighborhoodV1(index, from, references(n.getValue("references"), from))
            }
            val eligible = refs.indices.filter { i -> val r=refs[i]; !r.target.address.isNoAddress && spaces[r.target.address.spaceIndex!!].type in MEMORY_TYPES && (r.referenceType.code in DATA_TYPES || r.referenceType.code == 9) }
            require(neighborhoods.map { it.viaReferenceIndex } == eligible) { "one-hop reference neighborhoods are incomplete" }
            require(refs.size + neighborhoods.sumOf { it.references.size } <= limits.maximumReferencesPerSite)
            val protoCall = proto.code in CALL_TYPES
            val analysisCall = effective.code in CALL_TYPES || refs.any { it.referenceType.code in CALL_TYPES }
            when(kind) {
                "prototype-call" -> require(protoCall)
                "analysis-call-candidate" -> require(!protoCall && analysisCall)
                "direct-tail-candidate" -> require(!protoCall && !analysisCall && proto.code in UNCONDITIONAL_DIRECT_JUMPS && targets.size == 1 && targets.single().functionEntry != null && targets.single().functionEntry != owner && !targets.single().address.isNoAddress && spaces[targets.single().address.spaceIndex!!].type in MEMORY_TYPES)
            }
            return NativeCallSiteRecordV1(addr, owner, kind, length, delay, overridden, status, bytes, proto, effective, override, nullableAddress(node.getValue("prototypeFallThrough")), nullableAddress(node.getValue("effectiveFallThrough")), targets, refs, neighborhoods)
        }
    }
    private fun validateMetadataStrings(value: JsonElement, maximum: Int, key: String? = null) {
        when(value) {
            is JsonObject -> value.forEach { (name,child) -> require(name.toByteArray(Charsets.UTF_8).size <= maximum); validateMetadataStrings(child,maximum,name) }
            is JsonArray -> value.forEach { validateMetadataStrings(it,maximum) }
            is JsonPrimitive -> if(value.isString) require(value.content.toByteArray(Charsets.UTF_8).size <= if(key == "instructionBytes") 8192 else maximum) { "native metadata string exceeds its bound" }
        }
    }
    private fun parseSpaces(value: JsonElement, limits: NativeCallObservationLimitsV1): List<NativeCallAddressSpaceV1> {
        val array = array(value); require(array.isNotEmpty() && array.size <= limits.maximumAddressSpaces)
        val names = hashSetOf<String>()
        return array.mapIndexed { index, raw ->
            val node = obj(raw); fields(node, "index", "name", "type", "sizeBits", "addressableUnitSize", "overlay", "signedOffsets")
            require(integer(node, "index") == index)
            val name = text(node, "name"); require(name.isNotEmpty() && names.add(name))
            val size = integer(node, "sizeBits"); val unit = integer(node, "addressableUnitSize"); require(size in 1..64 && unit > 0); require(nativeSpan(size, unit) <= BigInteger.ONE.shiftLeft(64)) { "native address-space byte span exceeds 64 bits" }
            NativeCallAddressSpaceV1(index, name, integer(node, "type"), size, unit, bool(node, "overlay"), bool(node, "signedOffsets"))
        }
    }
    private fun nativeSpan(sizeBits: Int, addressableUnitSize: Int): BigInteger = BigInteger.valueOf(addressableUnitSize.toLong()).shiftLeft(sizeBits)
    private fun parseScan(node: JsonObject): NativeCallScanSummaryV1 {
        fields(node, "coverage", "functions", "thunks", "instructionsVisited", "ownedInstructions", "unownedInstructions", "sites", "prototypeCalls", "analysisCallCandidates", "directTailCandidates", "ordinaryJumpInstructions", "unresolvedComputedJumps", "directReferences", "neighborhoodReferences", "unownedPrototypeCalls", "unownedAnalysisCallCandidates", "unownedDirectTailCandidates")
        return NativeCallScanSummaryV1(text(node, "coverage"), count(node, "functions"), count(node, "thunks"), count(node, "instructionsVisited"), count(node, "ownedInstructions"), count(node, "unownedInstructions"), count(node, "sites"), count(node, "prototypeCalls"), count(node, "analysisCallCandidates"), count(node, "directTailCandidates"), count(node, "ordinaryJumpInstructions"), count(node, "unresolvedComputedJumps"), count(node, "directReferences"), count(node, "neighborhoodReferences"), count(node, "unownedPrototypeCalls"), count(node, "unownedAnalysisCallCandidates"), count(node, "unownedDirectTailCandidates"))
    }
    private fun validateExpected(binding: NativeCallBindingsV1) {
        listOf(binding.collectorSha256,binding.ghidraArchiveSha256,binding.inputSha256,binding.programModelExporterSha256,binding.programModelSha256).forEach { require(it.matches(SHA256)) }
        require(binding.programModelBytes in 1..512L * 1024 * 1024 && !binding.imageBase.isNoAddress && binding.compilerSpecId.isNotEmpty() && binding.languageId.isNotEmpty())
    }
    private fun refType(value: JsonElement): NativeCallReferenceTypeV1 {
        val node = obj(value); fields(node,"code","name"); val code=integer(node,"code"); val name=text(node,"name"); require(REFERENCE_TYPES[code] == name) { "unknown native reference type code/name" }; return NativeCallReferenceTypeV1(code,name)
    }
    private fun strictLimits(limits: NativeCallObservationLimitsV1, bytes: Int) = StrictJsonLimits(maximumInputBytes=bytes,maximumCanonicalBytes=bytes,maximumDepth=limits.maximumDepth,maximumNodes=100_000,maximumStringBytes=limits.maximumStringBytes,maximumTotalStringBytes=bytes,maximumNumberCharacters=20)
    private fun obj(value: JsonElement) = value as? JsonObject ?: error("native-call value must be an object")
    private fun array(value: JsonElement) = value as? JsonArray ?: error("native-call value must be an array")
    private fun fields(node: JsonObject,vararg names:String) { require(node.keys == names.toSet()) { "native-call object has missing or extra fields" } }
    private fun string(value: JsonElement): String { val p=value as? JsonPrimitive ?: error("native-call value must be a string"); require(p.isString); return p.content }
    private fun text(node:JsonObject,key:String)=string(node.getValue(key)).also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) { "native metadata string exceeds its bound" } }
    private fun nullableText(value:JsonElement)=if(value==JsonNull)null else string(value).also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) { "native metadata string exceeds its bound" } }
    private fun number(value:JsonElement):Long { val p=value as? JsonPrimitive ?: error("native-call value must be an integer"); require(!p.isString && p.content.matches(Regex("-?(?:0|[1-9][0-9]*)"))); return p.content.toLong() }
    private fun count(node:JsonObject,key:String)=number(node.getValue(key)).also { require(it>=0) }
    private fun integer(node:JsonObject,key:String)=number(node.getValue(key)).also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }.toInt()
    private fun bool(node:JsonObject,key:String):Boolean { val p=node.getValue(key) as? JsonPrimitive ?: error("native-call value must be boolean"); require(!p.isString); return p.booleanOrNull ?: error("native-call value must be boolean") }
    private fun digest(node:JsonObject,key:String)=text(node,key).also { require(it.matches(SHA256)) }
    private fun source(node:JsonObject,key:String)=text(node,key).also { require(it in SOURCES) }
    private val SHA256=Regex("[0-9a-f]{64}"); private val HEX64=Regex("[0-9a-f]{16}")
    private val SOURCES=setOf("DEFAULT","ANALYSIS","AI","IMPORTED","USER_DEFINED")
    private val SITE_KINDS=setOf("prototype-call","analysis-call-candidate","direct-tail-candidate")
    private val CALL_TYPES=setOf(3,4,8,10,13,14,15,16,18)
    private val UNCONDITIONAL_DIRECT_JUMPS=setOf(1,11,17,19)
    private val DATA_TYPES=setOf(100,101,102,103,104,105,106,107,113,114,127)
    private val MEMORY_TYPES=setOf(1,2,7,13)
    private val REFERENCE_TYPES=mapOf(-2 to "INVALID",-1 to "FLOW",0 to "FALL_THROUGH",1 to "UNCONDITIONAL_JUMP",2 to "CONDITIONAL_JUMP",3 to "UNCONDITIONAL_CALL",4 to "CONDITIONAL_CALL",5 to "TERMINATOR",6 to "COMPUTED_JUMP",7 to "CONDITIONAL_TERMINATOR",8 to "COMPUTED_CALL",9 to "INDIRECTION",10 to "CALL_TERMINATOR",11 to "JUMP_TERMINATOR",12 to "CONDITIONAL_COMPUTED_JUMP",13 to "CONDITIONAL_COMPUTED_CALL",14 to "CONDITIONAL_CALL_TERMINATOR",15 to "COMPUTED_CALL_TERMINATOR",16 to "CALL_OVERRIDE_UNCONDITIONAL",17 to "JUMP_OVERRIDE_UNCONDITIONAL",18 to "CALLOTHER_OVERRIDE_CALL",19 to "CALLOTHER_OVERRIDE_JUMP",100 to "DATA",101 to "READ",102 to "WRITE",103 to "READ_WRITE",104 to "READ_IND",105 to "WRITE_IND",106 to "READ_WRITE_IND",107 to "PARAM",113 to "EXTERNAL",114 to "DATA_IND",127 to "THUNK")
}

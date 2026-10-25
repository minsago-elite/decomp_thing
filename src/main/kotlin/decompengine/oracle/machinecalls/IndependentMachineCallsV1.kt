package decompengine.oracle.machinecalls

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeElfFunctionExtent
import decompengine.oracle.fulltree.FullTreeElfFunctionExtentLayout
import decompengine.oracle.fulltree.FullTreeElfLayout
import decompengine.oracle.fulltree.FullTreeElfLayoutLimits
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.structural.StructuralRecoveryV1Inputs
import java.nio.file.Path
import java.util.TreeMap
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A decoder receives only the requested address and an owned, bounded byte window. */
fun interface MachineInstructionDecoderV1 {
    fun decode(address: ULong, bytes: ByteArray): MachineInstructionV1
}

/** An explicitly refused byte decode, distinct from a malformed decoder receipt or runtime failure. */
class MachineInstructionRefusalV1(reason: String) : IllegalArgumentException(reason) {
    init { require(reason.matches(Regex("[a-z0-9-]{1,128}"))) }
}

data class MachineInstructionV1(
    val address: ULong,
    val length: Int,
    val bytes: ByteArray,
    val classification: String,
    val fallthrough: ULong?,
    val directTargets: List<ULong>,
    val directCallTarget: ULong?,
    val contextStatus: String,
)

data class MachineCallLimitsV1(
    val maximumRoots: Int = 131_072,
    val maximumInstructionsPerRoot: Int = 1_000_000,
    val maximumInstructions: Long = 10_000_000,
    val maximumCalls: Int = 1_000_000,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
    val maximumWallMillis: Long = 1_800_000,
) {
    init {
        require(maximumRoots in 1..131_072)
        require(maximumInstructionsPerRoot in 1..1_000_000)
        require(maximumInstructions in 1..10_000_000)
        require(maximumCalls in 1..1_000_000)
        require(maximumWorkUnits in 1..100_000_000)
        require(maximumOutputBytes in 1..64 * 1024 * 1024)
        require(maximumWallMillis in 1..1_800_000)
    }

    fun toJson(): JsonObject = obj(
        "maximumRoots" to num(maximumRoots), "maximumInstructionsPerRoot" to num(maximumInstructionsPerRoot),
        "maximumInstructions" to num(maximumInstructions), "maximumCalls" to num(maximumCalls),
        "maximumWorkUnits" to num(maximumWorkUnits), "maximumOutputBytes" to num(maximumOutputBytes),
        "maximumWallMillis" to num(maximumWallMillis),
    )
}

/**
 * Positive-only component. The supplied decoder is a dependency, not authenticated authority;
 * only the separate worker authenticates its bundled implementation. No recovered model is an input.
 * A completed traversal NEVER establishes a negative call fact or a complete call population.
 */
object IndependentMachineCallsV1 {
    fun produce(
        richArtifact: Path,
        canonicalOracle: Path,
        expectedInputSha256: String,
        expectedOracleSha256: String,
        expectedManifestSha256: String,
        decoder: MachineInstructionDecoderV1,
        limits: MachineCallLimitsV1 = MachineCallLimitsV1(),
    ): JsonObject {
        listOf(expectedInputSha256, expectedOracleSha256, expectedManifestSha256).forEach {
            require(it.matches(Regex("[0-9a-f]{64}"))) { "expected identity must be lowercase SHA-256" }
        }
        val budget = Budget(limits)
        val oracle = StructuralRecoveryV1Inputs.loadFunctionOracle(canonicalOracle)
        budget.check("canonical oracle validation")
        require(oracle.scope == "production" && oracle.artifactManifestSha256 == expectedManifestSha256 &&
            oracle.snapshot.sha256 == expectedOracleSha256) { "canonical oracle identity mismatch" }
        val artifact = oracle.artifacts.getValue("rich")
        require(artifact.inputSha256 == expectedInputSha256) { "canonical oracle rich identity mismatch" }
        val canonical = (oracle.document.getValue("functions") as JsonArray).map { raw ->
            val item = raw as JsonObject
            Canonical(text(item, "id"), address(item["rva"]), item.getValue("exclusion"))
        }.sortedWith(compareBy<Canonical> { it.rva == null }.thenBy { it.rva }.thenBy { it.id })
        require(canonical.size <= limits.maximumRoots) { "canonical population exceeds root limit" }
        val canonicalByRva = canonical.filter { it.rva != null }.associateBy { it.rva!! }
        return StableControlFile.openWithCheckpoint(richArtifact, 512L * 1024 * 1024, "rich machine-call ELF", budget::check).use { file ->
            require(file.authenticatedSha256 == expectedInputSha256) { "rich ELF identity mismatch" }
            val symbols = arrayListOf<FullTreeElfFunctionExtent>()
            val layout = FullTreeElfLayout.scanFunctionExtents(file, "rich machine-call ELF",
                FullTreeElfLayoutLimits(maximumParseSteps = limits.maximumWorkUnits), budget::check) { symbol ->
                require(symbols.size < limits.maximumRoots) { "raw function symbol population exceeds root limit" }
                budget.output(768L + symbol.name.length.toLong() * 4 + symbol.locator.length.toLong() * 4)
                symbols += symbol
            }
            require(layout.elfClass == 2 && layout.byteOrder == 1 && layout.machine == 62) {
                "byte decoder v1 supports only ELF64 little-endian x86-64"
            }
            require(layout.elfType == artifact.elfType && layout.imageBase == artifact.elfImageBase &&
                layout.executableRanges.map { it.start to it.endExclusive } == artifact.executableRvaRanges) {
                "rich ELF layout disagrees with canonical oracle"
            }
            val roots = classifyRoots(symbols, layout, file.size, budget)
            val rootsByRva = roots.filter { it.rva != null }.groupBy { it.rva!! }
            // Canonical starts inside an extent are an independent ownership conflict, even without a symbol.
            val canonicalStarts = canonicalByRva.keys.sorted()
            roots.filter { it.end != null && it.rva != null }.forEach { root ->
                val start = root.rva!!
                val end = root.end!! - layout.imageBase
                val index = canonicalStarts.binarySearch(start).let { if (it < 0) -it - 1 else it + 1 }
                if (index < canonicalStarts.size && canonicalStarts[index] < end) root.reasons += "interior-canonical-start"
            }
            val calls = arrayListOf<JsonObject>()
            var accepted = 0
            roots.forEach { root ->
                budget.check("root traversal")
                if (root.reasons.isEmpty()) traverse(root, file, layout.imageBase, decoder, budget)
                root.calls.sortedBy { it.instruction.address }.forEach { call ->
                    val caller = root.rva?.let(canonicalByRva::get)
                    val targetRva = call.instruction.directCallTarget?.let { if (it >= layout.imageBase) it - layout.imageBase else null }
                    val target = targetRva?.let(canonicalByRva::get)
                    val targetRoots = targetRva?.let(rootsByRva::get).orEmpty()
                    val disposition = when {
                        root.decodeOverlap -> "unresolved-instruction-overlap"
                        call.instruction.classification == "indirect-call" -> "unresolved-indirect-target"
                        caller == null -> "unresolved-caller-outside-canonical-population"
                        caller.exclusion != JsonNull -> "unresolved-caller-canonical-exclusion"
                        target == null -> "unresolved-target-outside-canonical-population"
                        target.exclusion != JsonNull -> "unresolved-target-canonical-exclusion"
                        targetRoots.size != 1 || targetRoots.single().reasons.isNotEmpty() -> "unresolved-target-extent"
                        else -> "positive-internal-exact-start"
                    }
                    if (disposition == "positive-internal-exact-start") accepted++
                    calls += obj(
                        "callerRoot" to str(root.id), "callerRva" to hex(root.rva),
                        "callerCanonicalId" to nullable(caller?.id), "instructionRva" to hex(call.instruction.address - layout.imageBase),
                        "instructionBytes" to str(call.instruction.bytes.joinToString("") { "%02x".format(it.toInt() and 255) }),
                        "instructionLength" to num(call.instruction.length), "classification" to str(call.instruction.classification),
                        "directTargetRva" to hex(targetRva), "directTargetAddress" to hex(call.instruction.directCallTarget),
                        "rawPcodeCallTargetAddress" to hex(call.instruction.directCallTarget),
                        "targetAgreement" to str(if (call.instruction.classification == "direct-call") "typed-flow-and-raw-call" else "computed-target-unresolved"),
                        "targetCanonicalId" to nullable(target?.id),
                        "directTargetAddresses" to JsonArray(call.instruction.directTargets.map(::hex)),
                        "fallthroughAddress" to hex(call.instruction.fallthrough), "contextStatus" to str(call.instruction.contextStatus),
                        "disposition" to str(disposition), "negativeCompleteness" to JsonPrimitive(false),
                    )
                }
            }
            val population = canonical.map { item ->
                budget.output(512L + item.id.length.toLong() * 4)
                val selected = item.rva?.let(rootsByRva::get).orEmpty()
                obj("id" to str(item.id), "rva" to hex(item.rva), "exclusion" to item.exclusion,
                    "rootIds" to JsonArray(selected.map { str(it.id) }),
                    "disposition" to str(when {
                        item.rva == null -> "unresolved-no-emitted-address"
                        selected.isEmpty() -> "unresolved-missing-symbol-extent"
                        selected.size != 1 -> "unresolved-multiple-symbol-extents"
                        selected.single().reasons.isNotEmpty() -> "unresolved-symbol-extent"
                        item.exclusion != JsonNull -> "unresolved-canonical-exclusion-no-parent-inference"
                        else -> "owned-symbol-extent"
                    }))
            }
            val report = obj(
                "schemaVersion" to num(1), "kind" to str("independent-machine-call-positive-observations"),
                "scope" to str("component"), "complete" to JsonPrimitive(false),
                "releaseEligible" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false),
                "canonicalPopulationComplete" to JsonPrimitive(true), "rawSymbolPopulationComplete" to JsonPrimitive(true),
                "inputSha256" to str(expectedInputSha256), "inputBytes" to num(file.size),
                "canonicalOracleSha256" to str(expectedOracleSha256), "artifactManifestSha256" to str(expectedManifestSha256),
                "imageBase" to hex(layout.imageBase), "languageId" to str("x86:LE:64:default"), "languageVersion" to str("4.8"),
                "decoderAuthentication" to str("external-worker-required"),
                "limits" to limits.toJson(), "canonicalOracleRecordLimit" to num(20_000),
                "canonicalPopulation" to JsonArray(population), "roots" to JsonArray(roots.map { it.toJson(layout.imageBase) }),
                "calls" to JsonArray(calls),
                "counts" to obj("rawFunctionSymbols" to num(symbols.size), "roots" to num(roots.size),
                    "canonicalFunctions" to num(canonical.size), "instructionAttempts" to num(budget.instructions),
                    "physicalCallSites" to num(calls.size), "positiveInternalCallSites" to num(accepted),
                    "unresolvedCallSites" to num(calls.size - accepted),
                    "rootsWithUnresolvedOwnership" to num(roots.count { it.reasons.isNotEmpty() }),
                    "rootsWithTraversalStops" to num(roots.count { it.stops.isNotEmpty() })),
            )
            IndependentMachineCallReportV1.validateComponent(report)
            OracleJson.canonicalBytes(report, outputLimits(limits), budget::check)
            file.verifyUnchanged("rich machine-call ELF")
            report
        }
    }

    internal fun outputLimits(limits: MachineCallLimitsV1): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumOutputBytes, maximumCanonicalBytes = limits.maximumOutputBytes,
        maximumNodes = 1_000_000, maximumStringBytes = limits.maximumOutputBytes,
        maximumTotalStringBytes = limits.maximumOutputBytes,
    )
}

private data class Canonical(val id: String, val rva: ULong?, val exclusion: JsonElement)
private data class Call(val instruction: MachineInstructionV1)
private data class StopKey(val address: ULong, val reason: String, val target: ULong?, val bytesKind: String?, val bytesHex: String?)
private class Root(val symbols: List<FullTreeElfFunctionExtent>, val rva: ULong?, val end: ULong?, val fileOffset: Long?) {
    val id = "symbol-root:${symbols.first().locator}"
    val reasons = sortedSetOf<String>()
    val stops = sortedSetOf<String>()
    private val stopEvents = TreeSet(compareBy<StopKey> { it.address }.thenBy { it.reason }
        .thenBy { it.target }.thenBy { it.bytesKind }.thenBy { it.bytesHex })
    val calls = arrayListOf<Call>()
    var instructionCount = 0
    var decodeOverlap = false
    fun stop(address: ULong, reason: String, budget: Budget, bytes: ByteArray? = null,
        bytesKind: String? = null, target: ULong? = null) {
        require(bytes == null && bytesKind == null || bytes != null && bytes.size in 1..32 &&
            bytesKind in setOf("available-window", "decoded-instruction")) { "invalid traversal stop byte evidence" }
        val event = StopKey(address, reason, target, bytesKind, bytes?.joinToString("") { "%02x".format(it.toInt() and 255) })
        if (!stopEvents.contains(event)) {
            budget.output(1024L + reason.length.toLong() * 4 + (event.bytesHex?.length ?: 0))
            stopEvents += event
        }
        stops += reason
    }
    fun toJson(base: ULong): JsonObject = obj(
        "id" to str(id), "rva" to hex(rva), "endExclusiveRva" to hex(end?.takeIf { it >= base }?.let { it - base }),
        "fileOffset" to (fileOffset?.let(::num) ?: JsonNull),
        "ownershipProblems" to JsonArray(reasons.map(::str)), "traversalStops" to JsonArray(stops.map(::str)),
        "traversalStopEvents" to JsonArray(stopEvents.map { event -> obj(
            "address" to hex(event.address), "rva" to hex(event.address.takeIf { it >= base }?.let { it - base }),
            "reason" to str(event.reason), "targetAddress" to hex(event.target),
            "bytesKind" to nullable(event.bytesKind), "bytes" to nullable(event.bytesHex),
        ) }),
        "instructionAttempts" to num(instructionCount), "negativeCompleteness" to JsonPrimitive(false),
        "origins" to JsonArray(symbols.map { symbol -> obj(
            "name" to str(symbol.name), "locator" to str(symbol.locator), "type" to num(symbol.type),
            "binding" to num(symbol.binding), "visibility" to num(symbol.visibility), "other" to num(symbol.other),
            "sectionKind" to str(symbol.sectionKind.name.lowercase()), "sectionIndex" to num(symbol.resolvedSectionIndex),
            "sectionName" to nullable(symbol.sectionName), "value" to hex(symbol.value), "size" to hex(symbol.size),
        ) }),
    )
}

private fun classifyRoots(
    symbols: List<FullTreeElfFunctionExtent>, layout: FullTreeElfFunctionExtentLayout, inputBytes: Long, budget: Budget,
): List<Root> {
    // Exact aliases collapse only when all ownership coordinates agree, not by spelling or suffix.
    val grouped = symbols.groupBy { listOf(it.value, it.size, it.resolvedSectionIndex, it.sectionKind) }
    val roots = grouped.values.map { group ->
        budget.check("extent classification")
        val symbol = group.first()
        val end = if (symbol.size > 0UL && symbol.value <= ULong.MAX_VALUE - symbol.size) symbol.value + symbol.size else null
        val reasons = sortedSetOf<String>()
        if (group.any { it.type == 10 }) reasons += "ifunc-resolver-identity-unresolved"
        if (symbol.sectionKind != FullTreeElfSymbolSectionKind.DEFINED) reasons += "non-defined-function-symbol"
        if (symbol.rva == null) reasons += "below-image-base"
        if (symbol.size == 0UL) reasons += "zero-size-no-end-inference"
        if (symbol.size > 0UL && end == null) reasons += "extent-address-overflow"
        val sectionStart = symbol.sectionAddress
        val sectionSize = symbol.sectionSize
        val sectionOffset = symbol.sectionFileOffset
        if (symbol.sectionType != 1L || symbol.sectionFlags?.and(6UL) != 6UL || sectionStart == null ||
            sectionSize == null || sectionOffset == null || end == null || symbol.value < sectionStart ||
            sectionStart > ULong.MAX_VALUE - sectionSize || end > sectionStart + sectionSize) reasons += "extent-not-in-executable-section"
        val segments = if (end == null) emptyList() else layout.loadedMemory.filter {
            budget.check("executable segment ownership")
            it.flags and 1L != 0L && symbol.value >= it.virtualAddress && end <= it.fileEndExclusive
        }
        if (segments.size != 1) reasons += "extent-not-in-one-file-backed-executable-load"
        // A second load can replace part of these bytes even when it does not contain the whole extent.
        if (end != null && layout.loadedMemory.count {
            budget.check("load overlap ownership")
            symbol.value < it.endExclusive && end > it.virtualAddress
        } != 1) reasons += "overlapping-load-ownership"
        val offset = if (segments.size == 1) segments.single().let { it.fileOffset + symbol.value - it.virtualAddress } else null
        if (offset != null && (offset > Long.MAX_VALUE.toULong() || offset > inputBytes.toULong() ||
                symbol.size > inputBytes.toULong() - offset)) reasons += "extent-file-range-invalid"
        if (offset != null && sectionStart != null && sectionOffset != null && symbol.value >= sectionStart &&
            offset != sectionOffset.toULong() + symbol.value - sectionStart) reasons += "section-load-file-mapping-disagreement"
        Root(group.sortedBy { it.locator }, symbol.rva, end, offset?.takeIf { it <= Long.MAX_VALUE.toULong() }?.toLong()).also {
            it.reasons += reasons
        }
    }.sortedWith(compareBy<Root> { it.rva == null }.thenBy { it.rva }.thenBy { it.id })
    // Even an otherwise invalid symbol can make another physical extent ambiguous.
    val ranges = roots.filter { it.end != null && it.rva != null }.sortedBy { it.symbols.first().value }
    var previous: Root? = null
    ranges.forEach { root ->
        budget.check("extent overlap classification")
        val prior = previous
        if (prior != null && root.symbols.first().value < prior.end!!) {
            prior.reasons += "overlapping-symbol-extents"
            root.reasons += "overlapping-symbol-extents"
        }
        if (prior == null || root.end!! > prior.end!!) previous = root
    }
    roots.groupBy { it.symbols.first().value }.values.filter { it.size > 1 }.forEach { sameStart ->
        sameStart.forEach { it.reasons += "conflicting-symbols-at-start" }
    }
    return roots
}

private fun traverse(root: Root, file: StableControlFile, base: ULong, decoder: MachineInstructionDecoderV1, budget: Budget) {
    val start = root.symbols.first().value
    val end = checkNotNull(root.end)
    val offset = checkNotNull(root.fileOffset)
    val pending = TreeSet<ULong>().apply { add(start) }
    val decoded = TreeMap<ULong, ULong>()
    fun schedule(instruction: MachineInstructionV1, target: ULong) {
        budget.check("CFG successor")
        if (target < start || target >= end) {
            root.stop(instruction.address, "control-flow-outside-owned-extent", budget,
                instruction.bytes, "decoded-instruction", target)
        } else pending += target
    }
    while (pending.isNotEmpty()) {
        budget.check("CFG traversal")
        val address = pending.pollFirst()
        if (decoded.containsKey(address)) continue
        if (address < start || address >= end) {
            root.stop(address, "control-flow-outside-owned-extent", budget)
            continue
        }
        val previous = decoded.floorEntry(address)
        if (previous != null && previous.value > address) {
            root.decodeOverlap = true
            root.stop(address, "overlapping-instruction-paths", budget)
            continue
        }
        budget.instruction(++root.instructionCount)
        val available = file.readExactly(Math.addExact(offset, (address - start).toLong()), minOf(15UL, end - address).toInt(),
            "owned instruction bytes", budget::check)
        val instruction = try { decoder.decode(address, available.copyOf()) } catch (failure: MachineInstructionRefusalV1) {
            budget.check("decoder refusal")
            root.stop(address, "decoder-refused-instruction", budget, available, "available-window")
            continue
        }
        require(instruction.address == address && instruction.length in 1..available.size &&
            instruction.bytes.contentEquals(available.copyOf(instruction.length))) { "decoder changed requested address or owned bytes" }
        require(instruction.classification in CLASSIFICATIONS) { "decoder returned unknown classification" }
        val next = address + instruction.length.toULong()
        require(instruction.fallthrough == null || instruction.fallthrough == next) { "decoder returned nonsequential fallthrough" }
        require(instruction.directTargets.distinct().size == instruction.directTargets.size && instruction.directTargets.size <= 1) {
            "decoder returned ambiguous direct targets"
        }
        if (instruction.classification == "direct-call") require(instruction.directCallTarget != null &&
            instruction.directTargets == listOf(instruction.directCallTarget)) { "direct CALL target disagreement" }
        else require(instruction.directCallTarget == null) { "non-direct call has a direct CALL target" }
        if (instruction.classification in setOf("ordinary", "return", "indirect-call", "indirect-jump")) {
            require(instruction.directTargets.isEmpty()) { "non-direct instruction has direct targets" }
        }
        if (instruction.classification == "direct-jump") require(instruction.directTargets.size == 1) { "direct jump lacks exact target" }
        if (instruction.classification in setOf("ordinary", "direct-call", "indirect-call")) require(instruction.fallthrough == next) {
            "continuing instruction lacks fallthrough"
        }
        if (!instruction.classification.startsWith("unsupported-")) require(instruction.contextStatus == "language-default-no-commits-v1") {
            "supported instruction has unassessed context"
        }
        val following = decoded.ceilingEntry(address)
        if (following != null && following.key < next) {
            root.decodeOverlap = true
            root.stop(address, "overlapping-instruction-paths", budget, instruction.bytes, "decoded-instruction")
            continue
        }
        decoded[address] = next
        when (instruction.classification) {
            "direct-call", "indirect-call" -> {
                budget.call()
                root.calls += Call(instruction.copy(bytes = instruction.bytes.copyOf(), directTargets = instruction.directTargets.toList()))
                schedule(instruction, checkNotNull(instruction.fallthrough))
            }
            "ordinary" -> schedule(instruction, checkNotNull(instruction.fallthrough))
            "direct-jump" -> {
                schedule(instruction, instruction.directTargets.single())
                instruction.fallthrough?.let { schedule(instruction, it) }
            }
            "return" -> Unit
            "indirect-jump" -> root.stop(address, "unresolved-indirect-jump", budget, instruction.bytes, "decoded-instruction")
            else -> root.stop(address, instruction.classification, budget, instruction.bytes,
                "decoded-instruction", instruction.directTargets.singleOrNull())
        }
    }
}

private class Budget(val limits: MachineCallLimitsV1) {
    private val started = System.nanoTime()
    private var work = 0L
    private var output = 0L
    private var calls = 0
    var instructions = 0L
        private set
    fun check(stage: String) {
        check(!Thread.currentThread().isInterrupted) { "machine-call producer interrupted during $stage" }
        check(++work <= limits.maximumWorkUnits) { "machine-call producer work limit exceeded" }
        check((System.nanoTime() - started) / 1_000_000 <= limits.maximumWallMillis) { "machine-call producer wall limit exceeded" }
    }
    fun output(bytes: Long) {
        output = Math.addExact(output, bytes)
        require(output <= limits.maximumOutputBytes) { "machine-call producer modeled output limit exceeded" }
    }
    fun instruction(rootCount: Int) {
        require(rootCount <= limits.maximumInstructionsPerRoot && ++instructions <= limits.maximumInstructions) {
            "machine-call producer instruction limit exceeded"
        }
    }
    fun call() {
        require(++calls <= limits.maximumCalls) { "machine-call producer call limit exceeded" }
        output(2048)
    }
}

private val CLASSIFICATIONS = setOf("direct-call", "indirect-call", "direct-jump", "indirect-jump", "return", "ordinary",
    "unsupported-pcode", "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
private fun obj(vararg pairs: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*pairs))
private fun str(value: String): JsonPrimitive = JsonPrimitive(value)
private fun nullable(value: String?): JsonElement = value?.let(::str) ?: JsonNull
private fun num(value: Number): JsonPrimitive = JsonPrimitive(value)
private fun hex(value: ULong?): JsonElement = value?.let { str("0x${it.toString(16)}") } ?: JsonNull
private fun text(item: JsonObject, key: String): String = (item.getValue(key) as JsonPrimitive).content
private fun address(value: JsonElement?): ULong? = if (value == null || value == JsonNull) null else
    (value as JsonPrimitive).content.removePrefix("0x").toULong(16)

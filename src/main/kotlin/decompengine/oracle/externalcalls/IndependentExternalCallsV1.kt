package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.machinecalls.IndependentMachineCallReportV1
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV1
import decompengine.oracle.machinecalls.MachineInstructionDecoderV1
import decompengine.oracle.machinecalls.MachineInstructionV1
import decompengine.oracle.machinecalls.MachineInstructionRefusalV1
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Known memory location read by a transfer; never the runtime pointer stored at that location. */
internal data class StaticMemoryTransferV1(
    val address: ULong, val length: Int, val bytes: ByteArray, val classification: String,
    val pointerSlotAddress: ULong?, val pointerWidthBytes: Int?, val relationship: String,
    val rawReadOpcode: String?, val rawReadOpIndex: Int?, val rawTransferOpcode: String?,
    val rawTransferOpIndex: Int?, val rawCopyOpIndices: List<Int>, val contextStatus: String,
    val unresolvedReason: String?,
)
internal fun interface StaticMemoryTransferDecoderV1 {
    fun decode(address: ULong, bytes: ByteArray): StaticMemoryTransferV1
}
internal data class ExternalCallLimitsV1(
    val maximumCalls: Int = 100_000,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
    val maximumWallMillis: Long = 1_800_000,
    val metadata: ElfDynamicBindingLimitsV1 = ElfDynamicBindingLimitsV1(),
) {
    init {
        require(maximumCalls in 1..100_000 && maximumWorkUnits in 1..100_000_000)
        require(maximumOutputBytes in 1..64 * 1024 * 1024 && maximumWallMillis in 1..1_800_000)
    }
}

/**
 * Composes independent byte witnesses with independent ELF metadata. Every original physical
 * site remains; one supported forwarding instruction adds evidence to that site, not another call.
 * Runtime pointer values, actual providers, and negative call coverage are never inferred.
 */
internal object IndependentExternalCallsV1 {
    fun produce(
        richArtifact: Path, sourceReport: Path, sourceRequest: Path,
        expectedInputSha256: String, expectedReportSha256: String, expectedRequestSha256: String,
        instructionDecoder: MachineInstructionDecoderV1, memoryDecoder: StaticMemoryTransferDecoderV1,
        limits: ExternalCallLimitsV1 = ExternalCallLimitsV1(),
    ): JsonObject {
        listOf(expectedInputSha256, expectedReportSha256, expectedRequestSha256).forEach(::requireDigest)
        require(limits.metadata == ElfDynamicBindingLimitsV1()) { "external-call metadata policy must use its closed default limits" }
        val budget = ExternalBudget(limits)
        return StableControlFile.openWithCheckpoint(sourceRequest, 65_536, "source machine-call request", budget::check).use { requestFile ->
            require(requestFile.authenticatedSha256 == expectedRequestSha256) { "source request commitment differs" }
            val request = IndependentMachineCallRequestV1.parse(requestFile.readExactly(0, requestFile.size.toInt(), "source request", budget::check))
            StableControlFile.openWithCheckpoint(sourceReport, HARD_BYTES.toLong(), "source machine-call report", budget::check).use { reportFile ->
                require(reportFile.authenticatedSha256 == expectedReportSha256) { "source report commitment differs" }
                val report = OracleJson.parseCanonical(reportFile.readExactly(0, reportFile.size.toInt(), "source report", budget::check),
                    jsonLimits(HARD_BYTES), budget::check) as? JsonObject ?: error("source report must be an object")
                IndependentMachineCallReportV1.validateWorker(report, expectedRequestSha256, request)
                require(request.richFile.sha256 == expectedInputSha256) { "source request rich input differs" }
                StableControlFile.openWithCheckpoint(richArtifact, 512L * 1024 * 1024, "external-call rich ELF", budget::check).use { rich ->
                    require(rich.authenticatedSha256 == expectedInputSha256 && rich.size == request.richFile.bytes) { "rich input commitment differs" }
                    val inventory = BoundedElfDynamicBindingsV1.scan(rich, expectedInputSha256, limits.metadata, budget::check)
                    val base = inventory.imageBase
                    require(address(report.getValue("imageBase")) == base) { "source report image base differs" }
                    val sourceCalls = report.getValue("calls") as JsonArray
                    val eligibleCallerIds = (report.getValue("canonicalPopulation") as JsonArray).map { it as JsonObject }
                        .filter { it.getValue("exclusion") == JsonNull }.mapTo(hashSetOf()) { text(it, "id") }
                    require(sourceCalls.size <= limits.maximumCalls) { "source call population exceeds bound" }
                    val imports = inventory.dynamicSymbols.filter { symbol ->
                        budget.check("import namespace")
                        symbol.symbolIndex != 0L && symbol.raw.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED &&
                            symbol.name.isNotEmpty() && symbol.binding in setOf(1, 2) && symbol.visibility == 0 && symbol.type in setOf(0, 2, 10)
                    }.associate { symbol ->
                        val identity = importIdentity(expectedInputSha256, symbol)
                        val token = "ext-${OracleArtifacts.sha256(OracleJson.canonicalBytes(identity))}"
                        (symbol.tableSectionIndex to symbol.symbolIndex) to ImportReference(token, identity)
                    }
                    val namespace = obj("schemaVersion" to number(1), "kind" to string("elf-static-import-request-namespace-v1"),
                        "inputSha256" to string(expectedInputSha256), "populationBasis" to string("eligible-section-declared-undefined-dynamic-symbols"),
                        "runtimeImplementationAvailable" to bool(false), "negativeCompleteness" to bool(false),
                        "entries" to JsonArray(imports.values.map { obj("id" to string(it.id), "identity" to it.identity) }))
                    val namespaceSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(namespace, jsonLimits(limits.maximumOutputBytes), budget::check))
                    val symbols = inventory.dynamicSymbols.associateBy { it.tableSectionIndex to it.symbolIndex }
                    val relocations = inventory.relocations.groupBy { it.offset }
                    val writeCoverage = ElfRelocationWriteCoverageV1.build(inventory, charge = budget::check)
                    val mechanismUnresolved = inventory.unsupportedReasons.any { it in UNSUPPORTED_WRITE_MECHANISMS }
                    val records = sourceCalls.mapIndexed { ordinal, raw ->
                        budget.check("physical call composition")
                        budget.retain(1536)
                        val call = raw as JsonObject
                        val siteRva = address(call.getValue("instructionRva"))!!
                        val site = add(base, siteRva)
                        val expectedBytes = unhex(text(call, "instructionBytes"))
                        val siteWindow = codeWindow(rich, inventory, site, budget)
                            ?: error("source call is not in unambiguous executable file bytes")
                        require(expectedBytes.size <= siteWindow.size && expectedBytes.contentEquals(siteWindow.copyOf(expectedBytes.size))) {
                            "source call bytes differ from rich input"
                        }
                        val decoded = instructionDecoder.decode(site, siteWindow.copyOf())
                        requireSourceCall(call, decoded, expectedBytes, base)
                        var transfer: StaticMemoryTransferV1? = null
                        var probe: JsonObject? = null
                        var viaForwarder = false
                        var status: String
                        var binding: JsonObject? = null
                        var importId: String? = null
                        if (text(call, "disposition") == "unresolved-instruction-overlap") {
                            status = "unresolved-source-instruction-boundary"
                        } else if (decoded.classification == "direct-call" && call.getValue("targetCanonicalId") != JsonNull) {
                            status = "retained-canonical-target"
                        } else {
                            val location = if (decoded.classification == "indirect-call") site else checkNotNull(decoded.directCallTarget)
                            val bytes = if (location == site) siteWindow else codeWindow(rich, inventory, location, budget)
                            viaForwarder = location != site
                            if (bytes == null) {
                                status = if (location == 0UL) "unresolved-null-physical-target" else "unresolved-forwarder-byte-ownership"
                            } else {
                                probe = obj("address" to hex(location), "availableBytes" to string(bytes.joinToString("") { "%02x".format(it.toInt() and 255) }),
                                    "refusal" to JsonNull)
                                val observed = try { memoryDecoder.decode(location, bytes.copyOf()) } catch (failure: MachineInstructionRefusalV1) {
                                    probe = JsonObject(checkNotNull(probe) + ("refusal" to string(checkNotNull(failure.message))))
                                    null
                                }
                                observed?.let {
                                    validateTransfer(it, location, bytes)
                                    val physical = if (location == site) decoded else instructionDecoder.decode(location, bytes.copyOf())
                                    require(physical.address == it.address && physical.length == it.length && physical.bytes.contentEquals(it.bytes) &&
                                        physical.classification == it.classification && physical.contextStatus == it.contextStatus) {
                                        "memory-transfer receipt differs from physical instruction decode"
                                    }
                                }
                                transfer = observed
                                val desired = if (viaForwarder) "indirect-jump" else "indirect-call"
                                when {
                                    observed == null -> status = "unresolved-memory-decoder-refusal"
                                    observed.classification != desired -> status = "unresolved-forwarder-sequence"
                                    observed.pointerSlotAddress == null -> status = "unresolved-memory-transfer"
                                    mechanismUnresolved -> status = "unresolved-unexpanded-relocation-writes"
                                    else -> {
                                        val slot = observed.pointerSlotAddress
                                        val candidates = relocations[slot].orEmpty()
                                        if (candidates.size != 1) {
                                            status = if (candidates.isEmpty()) "unresolved-slot-without-relocation" else "unresolved-competing-relocations"
                                        } else {
                                            val relocation = candidates.single()
                                            val symbol = symbols[relocation.symbolTableSectionIndex to relocation.symbolIndex]
                                            val reference = imports[relocation.symbolTableSectionIndex to relocation.symbolIndex]
                                            val writes = writeCoverage.assess(slot, relocation)
                                            importId = reference?.id
                                            status = when {
                                                relocation.dynamicTables.size != 1 -> "unresolved-relocation-runtime-membership"
                                                relocation.slotLoadIndices.size != 1 -> "unresolved-slot-memory-ownership"
                                                relocation.slotFileOffset == null -> "unresolved-slot-file-storage"
                                                relocation.symbolTableSectionIndex != inventory.activeSymbolTableSectionIndex -> "unresolved-inactive-symbol-table"
                                                relocation.type == 37L -> "unresolved-irelative-resolver"
                                                relocation.type !in setOf(6L, 7L) -> "unresolved-relocation-type"
                                                relocation.symbolIndex == 0L -> "unresolved-null-symbol-index"
                                                !writes.safeForStaticSlotAssociation -> "unresolved-relocation-write-coverage"
                                                symbol == null -> error("relocation symbol is missing from closed inventory")
                                                symbol.type == 10 -> "unresolved-ifunc-runtime-implementation"
                                                symbol.raw.sectionKind != FullTreeElfSymbolSectionKind.UNDEFINED -> "unresolved-defined-symbol-reference"
                                                reference == null -> "unresolved-symbol-import-identity"
                                                symbol.version != null && symbol.version.index >= 2 &&
                                                    (symbol.version.name == null || symbol.version.providerRequest == null) -> "unresolved-symbol-version"
                                                symbol.binding == 2 -> "unresolved-weak-runtime-target"
                                                symbol.type == 0 -> "unresolved-untyped-import-request"
                                                else -> "static-import-request-reference"
                                            }
                                            binding = obj("slotAddress" to hex(slot), "relocationLocator" to string(relocation.locator),
                                                "relocationType" to number(relocation.type), "relocationAddend" to (relocation.addend?.let(::number) ?: JsonNull),
                                                "dynamicTables" to strings(relocation.dynamicTables), "slotLoadIndices" to JsonArray(relocation.slotLoadIndices.map(::number)),
                                                "slotFileOffset" to (relocation.slotFileOffset?.let(::number) ?: JsonNull),
                                                "relocationDispositions" to strings(relocation.dispositions), "writeCoverage" to writes.toJson(),
                                                "symbolTableSectionIndex" to number(relocation.symbolTableSectionIndex), "symbolIndex" to number(relocation.symbolIndex),
                                                "symbolLocator" to (symbol?.raw?.locator?.let(::string) ?: JsonNull),
                                                "runtimeImplementationAvailable" to bool(false), "runtimeProviderAvailable" to bool(false))
                                        }
                                    }
                                }
                            }
                        }
                        val callerEligible = call.getValue("callerCanonicalId") != JsonNull &&
                            text(call, "callerCanonicalId") in eligibleCallerIds
                        val compositionStatus = when {
                            text(call, "disposition") == "unresolved-instruction-overlap" -> "unresolved-source-instruction-boundary"
                            !callerEligible -> "unresolved-source-caller"
                            text(call, "disposition") == "unresolved-target-canonical-exclusion" -> "unresolved-source-target-exclusion"
                            text(call, "disposition") == "unresolved-target-extent" -> "unresolved-source-target-extent"
                            else -> status
                        }
                        obj("sourceOrdinal" to number(ordinal), "callerRoot" to call.getValue("callerRoot"),
                            "callerCanonicalId" to call.getValue("callerCanonicalId"), "callerRva" to call.getValue("callerRva"),
                            "instructionRva" to hex(siteRva), "instructionBytes" to call.getValue("instructionBytes"),
                            "instructionLength" to number(decoded.length), "returnAddress" to hex(decoded.fallthrough),
                            "physicalClassification" to string(decoded.classification), "physicalTargetAddress" to hex(decoded.directCallTarget),
                            "sourceDisposition" to call.getValue("disposition"), "compositionDisposition" to string(compositionStatus), "targetBindingDisposition" to string(status),
                            "externalTargetId" to (importId?.let(::string) ?: JsonNull), "viaForwarder" to bool(viaForwarder),
                            "memoryProbe" to (probe ?: JsonNull), "memoryTransfer" to (transfer?.let(::transferJson) ?: JsonNull), "relocationBinding" to (binding ?: JsonNull),
                            "negativeCompleteness" to bool(false))
                    }
                    val statuses = records.groupingBy { text(it, "compositionDisposition") }.eachCount().toSortedMap()
                    val result = obj("schemaVersion" to number(1), "kind" to string("independent-external-call-component-v1"),
                        "scope" to string("component"), "decoderAuthentication" to string("external-worker-required"), "complete" to bool(false), "releaseEligible" to bool(false), "negativeCompleteness" to bool(false),
                        "sourceCallRecordsEnumerated" to bool(true), "sourceCallPopulationComplete" to bool(false),
                        "limits" to obj("maximumCalls" to number(limits.maximumCalls), "maximumWorkUnits" to number(limits.maximumWorkUnits),
                            "maximumOutputBytes" to number(limits.maximumOutputBytes), "maximumWallMillis" to number(limits.maximumWallMillis)),
                        "metadataPolicy" to string("elf-dynamic-binding-default-limits-v1"),
                        "inputSha256" to string(expectedInputSha256), "inputBytes" to number(rich.size), "imageBase" to hex(base),
                        "sourceReportSha256" to string(expectedReportSha256), "sourceRequestSha256" to string(expectedRequestSha256),
                        "externalNamespaceSha256" to string(namespaceSha), "externalNamespace" to namespace,
                        "sourceCanonicalPopulation" to JsonArray((report.getValue("canonicalPopulation") as JsonArray).map { raw ->
                            val canonical = raw as JsonObject
                            obj("id" to canonical.getValue("id"), "rva" to canonical.getValue("rva"), "exclusion" to canonical.getValue("exclusion"))
                        }), "dynamicInventory" to inventory.toJson(), "sites" to JsonArray(records),
                        "counts" to obj("sourcePhysicalSites" to number(sourceCalls.size), "composedSiteRecords" to number(records.size),
                            "namespaceEntries" to number(imports.size), "dispositions" to JsonObject(statuses.mapValues { number(it.value) })))
                    IndependentExternalCallReportV1.validateComponent(result)
                    OracleJson.canonicalBytes(result, jsonLimits(limits.maximumOutputBytes), budget::check)
                    rich.verifyUnchanged("external-call rich ELF after composition")
                    reportFile.verifyUnchanged("source call report after composition")
                    requestFile.verifyUnchanged("source call request after composition")
                    result
                }
            }
        }
    }
}

private data class ImportReference(val id: String, val identity: JsonObject)
private fun importIdentity(input: String, symbol: ElfDynamicSymbolV1): JsonObject = obj(
    "schemaVersion" to number(1), "namespace" to string("elf-static-import-request-v1"), "inputSha256" to string(input),
    "symbolTableSectionIndex" to number(symbol.tableSectionIndex), "symbolIndex" to number(symbol.symbolIndex),
    "name" to string(symbol.name), "type" to number(symbol.type), "binding" to number(symbol.binding), "visibility" to number(symbol.visibility),
    "version" to (symbol.version?.let { obj("raw" to number(it.raw), "index" to number(it.index), "hidden" to bool(it.hidden),
        "kind" to string(it.kind), "name" to (it.name?.let(::string) ?: JsonNull), "providerRequest" to (it.providerRequest?.let(::string) ?: JsonNull)) } ?: JsonNull),
    "weakMayRemainNull" to bool(symbol.binding == 2), "ifuncImplementationUnresolved" to bool(symbol.type == 10),
    "runtimeProviderAvailable" to bool(false), "runtimeImplementationAvailable" to bool(false), "interpositionUnresolved" to bool(true),
)

private fun codeWindow(file: StableControlFile, inventory: ElfDynamicBindingInventoryV1, address: ULong, budget: ExternalBudget): ByteArray? {
    val sections = inventory.sections.filter { section ->
        budget.check("code section ownership")
        section.flags and 2UL != 0UL && section.address <= address && section.size > address - section.address
    }
    if (sections.size != 1) return null
    val section = sections.single()
    if (section.type != 1L || section.flags and 6UL != 6UL || section.address > ULong.MAX_VALUE - section.size) return null
    val loads = inventory.loadedMemory.filter { budget.check("code load ownership"); address >= it.virtualAddress && address < it.endExclusive }
    if (loads.size != 1) return null
    val load = loads.single()
    if (load.flags and 1L == 0L || address >= load.fileEndExclusive) return null
    val length = minOf(15UL, section.address + section.size - address, load.fileEndExclusive - address).toInt()
    val end = address + length.toULong()
    if (inventory.loadedMemory.any { budget.check("overlapping code load"); it.index != load.index && address < it.endExclusive && end > it.virtualAddress }) return null
    if (inventory.sections.any { budget.check("overlapping code section"); it.index != section.index && it.flags and 2UL != 0UL &&
            it.address < end && it.address <= ULong.MAX_VALUE - it.size && address < it.address + it.size }) return null
    val loadOffset = load.fileOffset + address - load.virtualAddress
    val sectionOffset = section.offset.toULong() + address - section.address
    if (loadOffset != sectionOffset || loadOffset > Long.MAX_VALUE.toULong()) return null
    return file.readExactly(loadOffset.toLong(), length, "external-call owned code", budget::check)
}

private fun requireSourceCall(call: JsonObject, decoded: MachineInstructionV1, bytes: ByteArray, base: ULong) {
    require(decoded.address == add(base, address(call.getValue("instructionRva"))!!) && decoded.length == bytes.size && decoded.bytes.contentEquals(bytes)) {
        "source call decoder receipt differs"
    }
    require(decoded.classification == text(call, "classification") && decoded.contextStatus == "language-default-no-commits-v1" &&
        decoded.fallthrough == address(call.getValue("fallthroughAddress")) &&
        decoded.directCallTarget == address(call.getValue("directTargetAddress")) &&
        decoded.directTargets == (call.getValue("directTargetAddresses") as JsonArray).map { address(it)!! }) { "source call semantics differ" }
}

private fun validateTransfer(value: StaticMemoryTransferV1, address: ULong, bytes: ByteArray) {
    require(value.address == address && value.length in 1..minOf(15, bytes.size) && value.bytes.contentEquals(bytes.copyOf(value.length))) {
        "memory-transfer decoder changed owned bytes or address"
    }
    if (value.pointerSlotAddress == null) {
        require(value.relationship == "unresolved" && value.unresolvedReason != null && value.pointerWidthBytes == null &&
            value.rawReadOpcode == null && value.rawReadOpIndex == null && value.rawCopyOpIndices.isEmpty())
        return
    }
    require(value.pointerSlotAddress <= ULong.MAX_VALUE - 7UL && value.pointerWidthBytes == 8 && value.unresolvedReason == null &&
        value.contextStatus == "language-default-no-commits-v1" && value.classification in setOf("indirect-call", "indirect-jump"))
    require(value.relationship in setOf("static-ram-varnode-exact-transfer-v1", "single-static-load-exact-transfer-v1"))
    require(value.rawTransferOpcode == if (value.classification == "indirect-call") "CALLIND" else "BRANCHIND")
    require(value.rawReadOpcode in setOf("COPY", "LOAD", "CALLIND", "BRANCHIND"))
    val read = requireNotNull(value.rawReadOpIndex); val transfer = requireNotNull(value.rawTransferOpIndex)
    require(read in 0..4095 && transfer in read..4095 && value.rawCopyOpIndices.size <= 4096 &&
        value.rawCopyOpIndices == value.rawCopyOpIndices.distinct().sorted() && value.rawCopyOpIndices.all { it in read until transfer })
    when (value.relationship) {
        "single-static-load-exact-transfer-v1" -> require(value.rawReadOpcode == "LOAD" && read < transfer && value.rawCopyOpIndices.all { it > read })
        "static-ram-varnode-exact-transfer-v1" -> when (value.rawReadOpcode) {
            "COPY" -> require(read < transfer && value.rawCopyOpIndices.firstOrNull() == read)
            value.rawTransferOpcode -> require(read == transfer && value.rawCopyOpIndices.isEmpty())
            else -> error("invalid implicit RAM read proof")
        }
    }
}

private fun transferJson(value: StaticMemoryTransferV1): JsonObject = obj(
    "address" to hex(value.address), "length" to number(value.length), "bytes" to string(value.bytes.joinToString("") { "%02x".format(it.toInt() and 255) }),
    "classification" to string(value.classification), "pointerSlotAddress" to hex(value.pointerSlotAddress),
    "pointerWidthBytes" to (value.pointerWidthBytes?.let(::number) ?: JsonNull), "relationship" to string(value.relationship),
    "rawReadOpcode" to (value.rawReadOpcode?.let(::string) ?: JsonNull), "rawReadOpIndex" to (value.rawReadOpIndex?.let(::number) ?: JsonNull),
    "rawTransferOpcode" to (value.rawTransferOpcode?.let(::string) ?: JsonNull), "rawTransferOpIndex" to (value.rawTransferOpIndex?.let(::number) ?: JsonNull),
    "rawCopyOpIndices" to JsonArray(value.rawCopyOpIndices.map(::number)), "contextStatus" to string(value.contextStatus),
    "unresolvedReason" to (value.unresolvedReason?.let(::string) ?: JsonNull),
)

private class ExternalBudget(val limits: ExternalCallLimitsV1) {
    private val started = System.nanoTime()
    private var work = 0L
    private var retained = 0L
    fun check(stage: String) {
        check(!Thread.currentThread().isInterrupted) { "external-call composition cancelled during $stage" }
        require(++work <= limits.maximumWorkUnits) { "external-call work limit exceeded" }
        require((System.nanoTime() - started) / 1_000_000 <= limits.maximumWallMillis) { "external-call wall limit exceeded" }
    }
    fun retain(bytes: Long) { retained = Math.addExact(retained, bytes); require(retained <= limits.maximumOutputBytes) { "external-call output model exceeded" } }
}
private val UNSUPPORTED_WRITE_MECHANISMS = setOf("packed-relr-relocations-not-expanded", "android-packed-relocations-not-expanded", "unclassified-dynamic-tag")
private const val HARD_BYTES = 64 * 1024 * 1024
private fun jsonLimits(bytes: Int) = StrictJsonLimits(maximumInputBytes = bytes, maximumCanonicalBytes = bytes,
    maximumNodes = 1_000_000, maximumStringBytes = bytes, maximumTotalStringBytes = bytes)
private fun requireDigest(value: String) = require(value.matches(Regex("[0-9a-f]{64}")))
private fun add(left: ULong, right: ULong): ULong { require(left <= ULong.MAX_VALUE - right); return left + right }
private fun obj(vararg entries: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*entries))
private fun number(value: Number) = JsonPrimitive(value)
private fun string(value: String) = JsonPrimitive(value)
private fun bool(value: Boolean) = JsonPrimitive(value)
private fun strings(values: List<String>) = JsonArray(values.map(::string))
private fun hex(value: ULong?): JsonElement = value?.let { string("0x${it.toString(16)}") } ?: JsonNull
private fun address(value: JsonElement): ULong? = if (value == JsonNull) null else (value as JsonPrimitive).content.removePrefix("0x").toULong(16)
private fun text(value: JsonObject, key: String) = (value.getValue(key) as JsonPrimitive).content
private fun unhex(value: String): ByteArray { require(value.matches(Regex("(?:[0-9a-f]{2}){1,15}"))); return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }

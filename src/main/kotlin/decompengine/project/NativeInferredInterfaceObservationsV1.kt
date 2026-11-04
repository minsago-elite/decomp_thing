package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeCanonicalStreaming
import decompengine.oracle.fulltree.FullTreeCanonicalStreamingLimits
import java.io.InputStream
import java.math.BigInteger
import java.security.MessageDigest
import kotlinx.serialization.json.*
import decompengine.project.InferredWireV1.array
import decompengine.project.InferredWireV1.boolean
import decompengine.project.InferredWireV1.count
import decompengine.project.InferredWireV1.digest
import decompengine.project.InferredWireV1.fields
import decompengine.project.InferredWireV1.immutable
import decompengine.project.InferredWireV1.integer
import decompengine.project.InferredWireV1.nullableBoolean
import decompengine.project.InferredWireV1.nullableInteger
import decompengine.project.InferredWireV1.nullableText
import decompengine.project.InferredWireV1.number
import decompengine.project.InferredWireV1.objectValue
import decompengine.project.InferredWireV1.text

sealed interface NativeInferredInterfaceRecordV1

data class NativeInferredInterfaceBindingsV1(
    val listingBindings: NativeInterfaceBindingsV1, val collectorSha256: String, val wrapperSha256: String,
    val nativeDecompilerSha256: String, val listingBytes: Long, val listingSha256: String,
    val listingManifestSha256: String, val configurationSha256: String, val typeGraphSha256: String,
)
data class NativeInferredInterfaceManifestV1(
    val bytes: Long, val collectorSha256: String, val configurationSha256: String, val inputSha256: String,
    val listingSha256: String, val programModelSha256: String, val sha256: String, val typeGraphSha256: String,
)
data class NativeInferredInterfaceResultV1(
    val completed: Boolean, val valid: Boolean, val timedOut: Boolean, val cancelled: Boolean,
    val failedToStart: Boolean, val diagnostic: String,
)
data class NativeInferredInterfacePrototypeV1(
    val parameterCount: Int, val localSymbolParameterCount: Int, val parameterCountsMatch: Boolean,
    val backedByLocalSymbols: Boolean, val modelName: String?, val varArgs: Boolean, val extraPop: Int,
    val hasThis: Boolean, val noReturn: Boolean, val inline: Boolean, val constructor: Boolean,
    val destructor: Boolean, val returnType: Int?, val returnStorage: NativeInterfaceStorageV1,
) {
    val formalEffectiveRelation: String = "unavailable-native-api"
    val allMappings: String = "first-mapping-only"
    val privateFlags: String = "unavailable-native-api"
}
data class NativeInferredInterfaceParameterV1(
    val index: Int, val categoryIndex: Int, val highParamSlot: Int?, val highVariableState: String,
    val nativeIdBits: String, val name: String?, val type: Int?, val typeLocked: Boolean,
    val nameLocked: Boolean, val isThisPointer: Boolean, val isHiddenReturn: Boolean,
    val storage: NativeInterfaceStorageV1, val firstUse: NativeInterfaceAddressV1?,
) {
    val formalEffectiveRelation: String = "unavailable-native-api"
    val forcedIndirectMeaning: String = "unavailable-for-plain-decoded-storage"
    val allMappings: String = "first-mapping-only"
}
data class NativeInferredInterfaceFunctionV1(
    val functionOrdinal: Int, val entry: NativeInterfaceAddressV1, val isExternal: Boolean, val isThunk: Boolean,
    val disposition: String, val attempt: Int, val result: NativeInferredInterfaceResultV1?,
    val prototype: NativeInferredInterfacePrototypeV1?, val parameters: List<NativeInferredInterfaceParameterV1>,
) : NativeInferredInterfaceRecordV1

data class NativeInferredInterfaceScanV1(
    val functions: Long, val internalFunctions: Long, val externalFunctions: Long, val thunks: Long,
    val attempted: Long, val observed: Long, val parameters: Long, val storageVarnodes: Long,
    val roots: Long, val graphNodes: Long, val graphEdges: Long, val graphWork: Long,
    val dispositions: Map<String, Long>,
)
data class NativeInferredInterfaceSummaryV1(
    val manifest: NativeInferredInterfaceManifestV1, val bindings: NativeInferredInterfaceBindingsV1,
    val listing: NativeInterfaceObservationSummaryV1, val dataOrganization: JsonObject,
    val scan: NativeInferredInterfaceScanV1,
) {
    val authoritativeOracleEvidence: Boolean = false
    val recoveredModelScored: Boolean = false
    val productionInterfacesAdmitted: Boolean = false
    val releaseEligible: Boolean = false
    val abiClassification: String = "not-captured"
    val sourceTypeIdentity: String = "not-captured"
}

data class NativeInferredInterfaceObservationLimitsV1(
    val maximumCombinedBytes: Long = 1024L * 1024 * 1024,
    val maximumManifestBytes: Int = 64 * 1024,
    val maximumModelBytes: Int = 512 * 1024 * 1024,
    val maximumFunctions: Int = 131_072,
    val maximumParametersPerFunction: Int = 1024,
    val maximumParameters: Int = 1_000_000,
    val maximumListingTypes: Int = 524_288,
    val maximumStorageVarnodes: Int = 1_000_000,
    val maximumVarnodesPerStorage: Int = 64,
    val maximumAddressSpaces: Int = 256,
    val maximumRecordBytes: Int = 1024 * 1024,
    val maximumStringBytes: Int = 4096,
    val maximumRoots: Int = 3_393_216,
    val maximumGraphNodes: Int = 200_000,
    val maximumGraphEdges: Int = 1_000_000,
    val maximumGraphDepth: Int = 64,
    val maximumGraphChildren: Int = 4096,
    val maximumGraphWork: Long = 5_000_000,
) {
    init {
        require(maximumCombinedBytes in 1..1024L * 1024 * 1024)
        require(maximumManifestBytes in 1..64 * 1024 && maximumModelBytes in 1..512 * 1024 * 1024)
        require(maximumFunctions in 1..131_072 && maximumParametersPerFunction in 1..1024)
        require(maximumParameters in 1..1_000_000 && maximumListingTypes in 1..524_288)
        require(maximumStorageVarnodes in 1..1_000_000 && maximumVarnodesPerStorage in 1..64)
        require(maximumAddressSpaces in 1..256 && maximumRecordBytes in 1..1024 * 1024)
        require(maximumStringBytes in 1..4096 && maximumStringBytes <= maximumRecordBytes)
        require(maximumRoots in 0..3_393_216 && maximumGraphNodes in 0..200_000 && maximumGraphEdges in 0..1_000_000)
        require(maximumGraphDepth in 0..64 && maximumGraphChildren in 0..4096 && maximumGraphWork in 0..5_000_000)
    }
    internal fun listingLimits() = NativeInterfaceObservationLimitsV1(maximumCombinedBytes, maximumManifestBytes,
        maximumModelBytes, maximumFunctions, maximumParametersPerFunction, maximumParameters, maximumListingTypes,
        maximumStorageVarnodes, maximumVarnodesPerStorage, maximumAddressSpaces, maximumRecordBytes, maximumStringBytes)
}

/** Bounded recovered-byte validation. Callbacks remain speculative until the entire return succeeds. */
object NativeInferredInterfaceObservationsV1 {
    val configurationJson: JsonObject = jsonObject(
        "simplificationStyle" to JsonPrimitive("decompile"), "syntaxTree" to JsonPrimitive(true), "cCode" to JsonPrimitive(false),
        "maximumInstructions" to JsonPrimitive(500000), "maximumPayloadMBytes" to JsonPrimitive(50),
        "maximumJumpTableEntries" to JsonPrimitive(1024), "maximumSecondsPerFunction" to JsonPrimitive(60),
        "maximumOperationMillis" to JsonPrimitive(120000), "attemptsPerFunction" to JsonPrimitive(1),
    )
    val configurationSha256: String = sha256(OracleJson.canonicalBytes(configurationJson))
    val dispositions: Set<String> = java.util.Collections.unmodifiableSet(setOf("high-function-observed", "not-attempted-external", "not-attempted-unsupported-body",
        "decompile-timeout", "decompile-cancelled", "decompiler-start-failed", "decompiler-error",
        "completed-without-high-function", "unsupported-high-representation"))

    fun validate(
        manifestBytes: ByteArray,
        expectedBindings: NativeInferredInterfaceBindingsV1,
        programModelBytes: ByteArray,
        listingManifestBytes: ByteArray,
        limits: NativeInferredInterfaceObservationLimitsV1 = NativeInferredInterfaceObservationLimitsV1(),
        checkpoint: () -> Unit,
        openListing: () -> InputStream,
        openObservations: () -> InputStream,
        consume: (NativeInferredInterfaceRecordV1) -> Unit = {},
    ): NativeInferredInterfaceSummaryV1 {
        checkpoint()
        require(manifestBytes.size in 1..limits.maximumManifestBytes)
        val manifest = parseManifest(objectValue(OracleJson.parseCanonical(manifestBytes, jsonLimits(manifestBytes.size, limits))))
        val expected = expectedBindings
        for (value in listOf(expected.collectorSha256, expected.wrapperSha256, expected.nativeDecompilerSha256, expected.listingSha256,
            expected.listingManifestSha256, expected.configurationSha256, expected.typeGraphSha256)) require(SHA.matches(value))
        require(expected.configurationSha256 == configurationSha256 && manifest.configurationSha256 == configurationSha256)
        require(manifest.typeGraphSha256 == expected.typeGraphSha256 && manifest.collectorSha256 == expected.collectorSha256 && manifest.listingSha256 == expected.listingSha256 &&
            manifest.inputSha256 == expected.listingBindings.inputSha256 && manifest.programModelSha256 == expected.listingBindings.programModelSha256)
        require(sha256(listingManifestBytes) == expected.listingManifestSha256) { "inferred observation does not bind the exact listing manifest" }
        val totalBytes = Math.addExact(programModelBytes.size.toLong(), Math.addExact(listingManifestBytes.size.toLong(),
            Math.addExact(expected.listingBytes, Math.addExact(manifestBytes.size.toLong(), manifest.bytes))))
        require(manifest.bytes > 0 && expected.listingBytes > 0 && totalBytes <= limits.maximumCombinedBytes) { "combined model/listing/inferred inventory exceeds its byte bound" }
        val listingFunctions = arrayListOf<ListingFunction>()
        val listingTypes = arrayListOf<NativeInterfaceTypeV1>()
        var listingRootObligations = 0L
        val listing = NativeInterfaceObservationsV1.validate(listingManifestBytes, expected.listingBindings, programModelBytes,
            limits.listingLimits(), checkpoint, openListing) { row -> when (row) {
                is NativeInterfaceFunctionV1 -> {
                    listingRootObligations += 2L * (row.parameters.size + if (row.returned == null) 0 else 1)
                    require(listingRootObligations <= limits.maximumRoots) { "listing root obligations exceed the shared root bound" }
                    val roots = arrayListOf<ListingRoot>()
                    row.returned?.let { roots += ListingRoot("return-formal", -1, it.formalType); roots += ListingRoot("return-effective", -1, it.effectiveType) }
                    row.parameters.forEach { roots += ListingRoot("parameter-formal", it.ordinal, it.formalType); roots += ListingRoot("parameter-effective", it.ordinal, it.effectiveType) }
                    listingFunctions += ListingFunction(row.entry, row.isExternal, row.isThunk, immutable(roots))
                }
                is NativeInterfaceTypeV1 -> listingTypes += row
            }
        }
        require(listing.manifest.bytes == expected.listingBytes && listing.manifest.sha256 == expected.listingSha256) { "inferred observation differs from the validated listing bytes" }
        val graph = NativeInterfaceTypeGraphValidatorV1(limits, checkpoint)
        var listingRootFunction = 0
        var listingRootIndex = 0
        var inferredPhase = false
        var functionOrdinal = 0
        var rootScope: Int? = null
        val inferredRoots = arrayListOf<NativeInterfaceTypeRootV1>()
        var dataOrganization: JsonObject? = null
        var alignments = 0
        var summary: NativeInferredInterfaceScanV1? = null
        val observedDispositions = dispositions.associateWith { 0L }.toMutableMap()
        var attempted = 0L; var observed = 0L; var parameters = 0L; var storageVarnodes = 0L
        fun finishListingRoots() {
            while (listingRootFunction < listingFunctions.size && listingRootIndex == listingFunctions[listingRootFunction].roots.size) {
                listingRootFunction++; listingRootIndex = 0
            }
            require(listingRootFunction == listingFunctions.size) { "inferred capture omits listing type-root obligations" }
        }
        fun inferredScope(scope: NativeInterfaceGraphScopeV1) {
            if (scope.channel == "inferred") {
                if (!inferredPhase) { finishListingRoots(); inferredPhase = true }
                require(scope.functionOrdinal == functionOrdinal) { "inferred graph scope differs from the next frozen native function" }
                rootScope = scope.functionOrdinal
            } else {
                require(!inferredPhase && scope.functionOrdinal in listingFunctions.indices) { "listing graph scope is absent or follows inference" }
                while (listingRootFunction < listingFunctions.size && listingRootIndex == listingFunctions[listingRootFunction].roots.size) {
                    listingRootFunction++; listingRootIndex = 0
                }
                require(scope.functionOrdinal == listingRootFunction) { "listing graph scope differs from its next root obligation" }
            }
        }
        openObservations().use { input -> FullTreeCanonicalStreaming.readObject(input, "native inferred interface observations",
            manifest.sha256, manifest.bytes,
            listOf("addressSpaces", "bindings", "configuration", "dataOrganization", "policy", "records", "schemaVersion", "summary"), setOf("records"), null,
            FullTreeCanonicalStreamingLimits(manifest.bytes, 100_000_000, maxOf(1, limits.maximumFunctions.toLong() + limits.maximumRoots + limits.maximumGraphNodes + limits.maximumGraphEdges),
                limits.maximumRecordBytes, 100_000, 20, limits.maximumStringBytes, manifest.bytes, 20),
            consumeEnvelope = { field, value ->
                checkpoint()
                when (field) {
                    "addressSpaces" -> require(value == spacesJson(listing.addressSpaces)) { "inferred address spaces differ from the frozen listing" }
                    "bindings" -> require(value == bindingJson(expected)) { "inferred collector/runtime/options/listing binding mismatch" }
                    "configuration" -> require(value == configurationJson) { "inferred configuration differs from fixed bounded policy" }
                    "dataOrganization" -> { dataOrganization = InferredWireV1.freeze(value).jsonObject; alignments = validateDataOrganization(checkNotNull(dataOrganization), limits) }
                    "policy" -> require(InferredWireV1.string(value) == "ghidra-native-inferred-interface-observations-v1")
                    "schemaVersion" -> require(number(value) == 1L)
                    "summary" -> summary = parseSummary(objectValue(value))
                }
            },
        ) { _, _, raw, _ ->
            checkpoint()
            when (text(raw, "recordKind")) {
                "type-node" -> {
                    inferredScope(graph.scopeOf(raw))
                    val node = graph.node(raw)
                    if (node.kind == "bitfield") require(node.details.getValue("bigEndian") == checkNotNull(dataOrganization).getValue("bigEndian")) { "native bitfield context differs from captured data organization" }
                    consume(node)
                }
                "type-edge" -> { inferredScope(graph.scopeOf(raw)); consume(graph.edge(raw)) }
                "type-root" -> {
                    inferredScope(graph.scopeOf(raw))
                    val (root, node) = graph.root(raw)
                    if (root.scope.channel == "listing") {
                        val obligation = listingFunctions[listingRootFunction].roots[listingRootIndex++]
                        require(root.role == obligation.role && root.slot == obligation.slot && root.listingTypeOrdinal == obligation.type) { "listing type root differs from its exact signature occurrence" }
                        require((root.node == null) == (obligation.type == null)) { "listing root omitted or fabricated a native datatype" }
                        obligation.type?.let { ordinal ->
                            val type = listingTypes[ordinal]; val actual = checkNotNull(node)
                            val expectedKind = if (type.kind == "other") setOf("bitfield", "unsupported") else setOf(type.kind)
                            require(actual.kind in expectedKind && actual.nativeClass == type.nativeClass && actual.length == type.length &&
                                actual.alignedLength == type.alignedLength && actual.alignment == type.alignment && actual.notYetDefined == type.notYetDefined && actual.undefined == type.undefined) {
                                "listing graph root primitive metadata differs from exact listing occurrence"
                            }
                            if (type.kind == "integer") require(boolean(actual.details.getValue("signed")) == (type.signedness == "signed"))
                        }
                    } else {
                        require(root.listingTypeOrdinal == null && root.role == if (inferredRoots.isEmpty()) "inferred-return" else "inferred-parameter")
                        require(root.slot == inferredRoots.size - 1 && inferredRoots.size <= limits.maximumParametersPerFunction)
                        inferredRoots += root
                    }
                    consume(root)
                }
                "function" -> {
                    if (!inferredPhase) { finishListingRoots(); inferredPhase = true }
                    graph.finish()
                    require(functionOrdinal < listingFunctions.size) { "inferred function census exceeds frozen listing" }
                    val function = function(raw, listing.addressSpaces, limits)
                    val frozen = listingFunctions[functionOrdinal]
                    require(function.functionOrdinal == functionOrdinal && function.entry == frozen.entry && function.isExternal == frozen.external && function.isThunk == frozen.thunk) {
                        "inferred function must retain the exact complete listing census"
                    }
                    if (function.disposition == "high-function-observed") {
                        val prototype = checkNotNull(function.prototype)
                        require(rootScope == functionOrdinal && inferredRoots.size == 1 + function.parameters.size)
                        require(inferredRoots.first().node == prototype.returnType)
                        function.parameters.forEachIndexed { index, parameter -> require(inferredRoots[index + 1].node == parameter.type) }
                        observed++
                        parameters += function.parameters.size
                        require(parameters <= limits.maximumParameters)
                        storageVarnodes += prototype.returnStorage.varnodes.size + function.parameters.sumOf { it.storage.varnodes.size.toLong() }
                        require(storageVarnodes <= limits.maximumStorageVarnodes)
                    } else require(inferredRoots.isEmpty() && rootScope == null) { "unsuccessful inference cannot publish inferred roots" }
                    attempted += function.attempt
                    observedDispositions[function.disposition] = observedDispositions.getValue(function.disposition) + 1
                    inferredRoots.clear(); rootScope = null; functionOrdinal++
                    consume(function)
                }
                else -> error("unsupported inferred record kind")
            }
            val work = Math.addExact(graph.rootCount, Math.addExact(3 * graph.nodeCount, Math.addExact(3 * graph.edgeCount, 1L + alignments)))
            require(work <= limits.maximumGraphWork) { "aggregate native graph work bound exceeded" }
        } }
        finishListingRoots(); graph.finish()
        require(functionOrdinal == listingFunctions.size && inferredRoots.isEmpty() && rootScope == null) { "inferred capture omits native function outcomes" }
        val work = graph.rootCount + 3 * graph.nodeCount + 3 * graph.edgeCount + 1 + alignments
        require(work <= limits.maximumGraphWork)
        val actual = NativeInferredInterfaceScanV1(listing.scan.functions, listing.scan.internalFunctions, listing.scan.externalFunctions,
            listing.scan.thunks, attempted, observed, parameters, storageVarnodes, graph.rootCount, graph.nodeCount, graph.edgeCount, work,
            java.util.Collections.unmodifiableMap(observedDispositions.toMap()))
        require(summary == actual) { "inferred summary does not conserve the complete function/root/graph population" }
        return NativeInferredInterfaceSummaryV1(manifest, expected, listing, checkNotNull(dataOrganization), actual)
    }

    private data class ListingRoot(val role: String, val slot: Int, val type: Int?)
    private data class ListingFunction(val entry: NativeInterfaceAddressV1, val external: Boolean, val thunk: Boolean, val roots: List<ListingRoot>)

    private fun function(raw: JsonObject, spaces: List<NativeInterfaceAddressSpaceV1>, limits: NativeInferredInterfaceObservationLimitsV1): NativeInferredInterfaceFunctionV1 {
        fields(raw, "recordKind", "functionOrdinal", "entry", "isExternal", "isThunk", "disposition", "attempt", "result", "prototype", "parameters")
        val state = text(raw, "disposition").also { require(it in dispositions) }
        val attempt = integer(raw.getValue("attempt")); val external = boolean(raw.getValue("isExternal"))
        val result = raw.getValue("result").takeUnless { it == JsonNull }?.let { value ->
            val node = objectValue(value); fields(node, "completed", "valid", "timedOut", "cancelled", "failedToStart", "diagnostic")
            NativeInferredInterfaceResultV1(boolean(node.getValue("completed")), boolean(node.getValue("valid")), boolean(node.getValue("timedOut")),
                boolean(node.getValue("cancelled")), boolean(node.getValue("failedToStart")), text(node, "diagnostic"))
        }
        val parameterNodes = array(raw.getValue("parameters")); require(parameterNodes.size <= limits.maximumParametersPerFunction)
        val parameters = parameterNodes.mapIndexed { index, value -> parameter(objectValue(value), index, spaces, limits) }
        val prototype = raw.getValue("prototype").takeUnless { it == JsonNull }?.let { value ->
            val node = objectValue(value)
            fields(node, "parameterCount", "localSymbolParameterCount", "parameterCountsMatch", "backedByLocalSymbols", "modelName", "varArgs", "extraPop", "hasThis", "noReturn", "inline", "constructor", "destructor", "returnType", "returnStorage", "formalEffectiveRelation", "allMappings", "privateFlags")
            require(text(node, "formalEffectiveRelation") == "unavailable-native-api" && text(node, "allMappings") == "first-mapping-only" && text(node, "privateFlags") == "unavailable-native-api")
            val count = integer(node.getValue("parameterCount")); val local = integer(node.getValue("localSymbolParameterCount"))
            require(count in 0..limits.maximumParametersPerFunction && local == parameters.size)
            val countsMatch = boolean(node.getValue("parameterCountsMatch")); require(countsMatch == (count == local))
            require(boolean(node.getValue("backedByLocalSymbols")))
            NativeInferredInterfacePrototypeV1(count, local, countsMatch, true, nullableText(node.getValue("modelName")), boolean(node.getValue("varArgs")),
                integer(node.getValue("extraPop")), boolean(node.getValue("hasThis")), boolean(node.getValue("noReturn")), boolean(node.getValue("inline")),
                boolean(node.getValue("constructor")), boolean(node.getValue("destructor")), nullableInteger(node.getValue("returnType")), storage(node.getValue("returnStorage"), spaces, limits))
        }
        val nonAttempt = state.startsWith("not-attempted-")
        require(attempt == if (nonAttempt) 0 else 1)
        require((result == null) == nonAttempt)
        require(external == (state == "not-attempted-external")) { "external native functions must retain explicit non-attempt outcomes" }
        require((prototype != null) == (state == "high-function-observed"))
        if (prototype == null) require(parameters.isEmpty())
        result?.let {
            val flagState = when {
                it.timedOut -> "decompile-timeout"
                it.cancelled -> "decompile-cancelled"
                it.failedToStart -> "decompiler-start-failed"
                else -> null
            }
            if (flagState != null) require(state == flagState)
            else require(state !in setOf("decompile-timeout", "decompile-cancelled", "decompiler-start-failed"))
            if (state in setOf("high-function-observed", "unsupported-high-representation", "completed-without-high-function")) require(it.completed)
            if (state == "decompiler-error") require(!it.completed)
        }
        return NativeInferredInterfaceFunctionV1(integer(raw.getValue("functionOrdinal")), address(raw.getValue("entry"), spaces), external,
            boolean(raw.getValue("isThunk")), state, attempt, result, prototype, immutable(parameters))
    }

    private fun parameter(node: JsonObject, index: Int, spaces: List<NativeInterfaceAddressSpaceV1>, limits: NativeInferredInterfaceObservationLimitsV1): NativeInferredInterfaceParameterV1 {
        fields(node, "index", "categoryIndex", "highParamSlot", "highVariableState", "nativeIdBits", "name", "type", "typeLocked", "nameLocked", "isThisPointer", "isHiddenReturn", "storage", "firstUse", "formalEffectiveRelation", "forcedIndirectMeaning", "allMappings")
        require(integer(node.getValue("index")) == index)
        val state = text(node, "highVariableState").also { require(it in setOf("absent", "parameter", "other")) }
        val highSlot = nullableInteger(node.getValue("highParamSlot")); require((highSlot != null) == (state == "parameter"))
        val id = text(node, "nativeIdBits"); require(HEX.matches(id))
        require(text(node, "formalEffectiveRelation") == "unavailable-native-api" && text(node, "forcedIndirectMeaning") == "unavailable-for-plain-decoded-storage" && text(node, "allMappings") == "first-mapping-only")
        return NativeInferredInterfaceParameterV1(index, integer(node.getValue("categoryIndex")), highSlot, state, id, nullableText(node.getValue("name")),
            nullableInteger(node.getValue("type")), boolean(node.getValue("typeLocked")), boolean(node.getValue("nameLocked")),
            boolean(node.getValue("isThisPointer")), boolean(node.getValue("isHiddenReturn")), storage(node.getValue("storage"), spaces, limits),
            node.getValue("firstUse").takeUnless { it == JsonNull }?.let { address(it, spaces) })
    }

    private fun storage(value: JsonElement, spaces: List<NativeInterfaceAddressSpaceV1>, limits: NativeInferredInterfaceObservationLimitsV1): NativeInterfaceStorageV1 {
        val node = objectValue(value); fields(node, "state", "size", "autoStorage", "autoParameterType", "forcedIndirect", "varnodes")
        val state = text(node, "state").also { require(it in setOf("assigned", "bad", "unassigned", "void", "absent")) }
        val size = nullableInteger(node.getValue("size")); val auto = nullableBoolean(node.getValue("autoStorage"))
        val indirect = nullableBoolean(node.getValue("forcedIndirect")); val autoType = nullableText(node.getValue("autoParameterType"))
        require(autoType == null || autoType in setOf("THIS", "RETURN_STORAGE_PTR")) { "unsupported native automatic storage role" }
        val pieces = array(node.getValue("varnodes")); require(pieces.size <= limits.maximumVarnodesPerStorage)
        val parsed = pieces.map { raw ->
            val piece = objectValue(raw); fields(piece, "address", "size")
            val location = address(piece.getValue("address"), spaces); val bytes = integer(piece.getValue("size"))
            require(!location.isNoAddress && bytes > 0)
            val space = spaces[checkNotNull(location.spaceIndex)]
            val span = BigInteger.valueOf(space.addressableUnitSize.toLong()).shiftLeft(space.sizeBits)
            val start = if (space.signedOffsets) BigInteger.valueOf(checkNotNull(location.offsetBits).toULong(16).toLong())
                else BigInteger(checkNotNull(location.offsetBits), 16)
            val upper = if (space.signedOffsets) span.shiftRight(1) else span
            require(start.add(BigInteger.valueOf(bytes.toLong())) <= upper) { "native storage piece crosses its typed address space" }
            NativeInterfaceVarnodeV1(location, bytes)
        }
        if (state == "absent") require(size == null && auto == null && indirect == null && autoType == null && parsed.isEmpty())
        else {
            require(size != null && size >= 0 && auto != null && indirect != null && auto == (autoType != null))
            require(size.toLong() == parsed.sumOf { it.size.toLong() } && (state == "assigned") == parsed.isNotEmpty())
        }
        return NativeInterfaceStorageV1(state, size, auto, autoType, indirect, immutable(parsed))
    }

    private fun address(value: JsonElement, spaces: List<NativeInterfaceAddressSpaceV1>): NativeInterfaceAddressV1 {
        val node = objectValue(value)
        if (text(node, "kind") == "no-address") { fields(node, "kind"); return NativeInterfaceAddressV1(null, null) }
        fields(node, "kind", "spaceIndex", "offsetBits"); require(text(node, "kind") == "address")
        val index = integer(node.getValue("spaceIndex")); require(index in spaces.indices)
        val bits = text(node, "offsetBits"); require(HEX.matches(bits))
        val space = spaces[index]; val span = BigInteger.valueOf(space.addressableUnitSize.toLong()).shiftLeft(space.sizeBits)
        val offset = if (space.signedOffsets) BigInteger.valueOf(bits.toULong(16).toLong()) else BigInteger(bits, 16)
        require(if (space.signedOffsets) offset >= span.shiftRight(1).negate() && offset < span.shiftRight(1) else offset.signum() >= 0 && offset < span)
        return NativeInterfaceAddressV1(index, bits)
    }

    private fun validateDataOrganization(node: JsonObject, limits: NativeInferredInterfaceObservationLimitsV1): Int {
        fields(node, "bigEndian", "pointerSize", "pointerShift", "signedChar", "charSize", "wideCharSize", "shortSize", "integerSize", "longSize", "longLongSize", "floatSize", "doubleSize", "longDoubleSize", "absoluteMaxAlignment", "machineAlignment", "defaultAlignment", "defaultPointerAlignment", "sizeAlignments", "bitFieldPacking")
        boolean(node.getValue("bigEndian")); boolean(node.getValue("signedChar"))
        for (name in listOf("pointerSize", "pointerShift", "charSize", "wideCharSize", "shortSize", "integerSize", "longSize", "longLongSize", "floatSize", "doubleSize", "longDoubleSize", "absoluteMaxAlignment", "machineAlignment", "defaultAlignment", "defaultPointerAlignment")) require(integer(node.getValue(name)) >= 0)
        val rows = array(node.getValue("sizeAlignments")); require(rows.size <= minOf(256, limits.maximumGraphChildren))
        var previous = -1
        for (row in rows) {
            val item = objectValue(row); fields(item, "size", "alignment")
            val size = integer(item.getValue("size")); require(size > previous && integer(item.getValue("alignment")) >= 0); previous = size
        }
        val packing = objectValue(node.getValue("bitFieldPacking")); fields(packing, "msConvention", "typeAlignmentEnabled", "zeroLengthBoundary")
        boolean(packing.getValue("msConvention")); boolean(packing.getValue("typeAlignmentEnabled")); require(integer(packing.getValue("zeroLengthBoundary")) >= 0)
        return rows.size
    }

    private fun parseManifest(node: JsonObject): NativeInferredInterfaceManifestV1 {
        fields(node, "bytes", "collectorSha256", "configurationSha256", "file", "inputSha256", "kind", "listingSha256", "programModelSha256", "schemaVersion", "sha256", "typeGraphSha256")
        require(text(node, "file") == "native-inferred-interfaces.json" && text(node, "kind") == "ghidra-native-inferred-interface-observation-manifest-v1" && number(node.getValue("schemaVersion")) == 1L)
        return NativeInferredInterfaceManifestV1(count(node, "bytes"), digest(node, "collectorSha256"), digest(node, "configurationSha256"),
            digest(node, "inputSha256"), digest(node, "listingSha256"), digest(node, "programModelSha256"), digest(node, "sha256"), digest(node, "typeGraphSha256"))
    }
    private fun parseSummary(node: JsonObject): NativeInferredInterfaceScanV1 {
        fields(node, "functions", "internalFunctions", "externalFunctions", "thunks", "attempted", "observed", "parameters", "storageVarnodes", "roots", "graphNodes", "graphEdges", "graphWork", "dispositions", "coverage", "authoritativeOracleEvidence", "recoveredModelScored", "productionInterfacesAdmitted", "releaseEligible", "abiClassification", "sourceTypeIdentity")
        require(text(node, "coverage") == "all-currently-listed-internal-and-external-functions" && text(node, "abiClassification") == "not-captured" && text(node, "sourceTypeIdentity") == "not-captured")
        for (name in listOf("authoritativeOracleEvidence", "recoveredModelScored", "productionInterfacesAdmitted", "releaseEligible")) require(!boolean(node.getValue(name)))
        val counts = objectValue(node.getValue("dispositions")); fields(counts, *dispositions.toTypedArray())
        return NativeInferredInterfaceScanV1(count(node, "functions"), count(node, "internalFunctions"), count(node, "externalFunctions"), count(node, "thunks"),
            count(node, "attempted"), count(node, "observed"), count(node, "parameters"), count(node, "storageVarnodes"), count(node, "roots"),
            count(node, "graphNodes"), count(node, "graphEdges"), count(node, "graphWork"), dispositions.associateWith { count(counts, it) })
    }
    private fun listingBindingJson(b: NativeInterfaceBindingsV1) = jsonObject("collectorSha256" to JsonPrimitive(b.collectorSha256), "compilerSpecId" to JsonPrimitive(b.compilerSpecId),
        "ghidraArchiveSha256" to JsonPrimitive(b.ghidraArchiveSha256), "imageBase" to addressJson(b.imageBase), "inputSha256" to JsonPrimitive(b.inputSha256),
        "languageId" to JsonPrimitive(b.languageId), "programModelBytes" to JsonPrimitive(b.programModelBytes), "programModelExporterSha256" to JsonPrimitive(b.programModelExporterSha256), "programModelSha256" to JsonPrimitive(b.programModelSha256))
    private fun bindingJson(b: NativeInferredInterfaceBindingsV1) = jsonObject("listingBindings" to listingBindingJson(b.listingBindings), "collectorSha256" to JsonPrimitive(b.collectorSha256),
        "wrapperSha256" to JsonPrimitive(b.wrapperSha256), "nativeDecompilerSha256" to JsonPrimitive(b.nativeDecompilerSha256), "listingBytes" to JsonPrimitive(b.listingBytes),
        "listingSha256" to JsonPrimitive(b.listingSha256), "listingManifestSha256" to JsonPrimitive(b.listingManifestSha256), "configurationSha256" to JsonPrimitive(b.configurationSha256), "typeGraphSha256" to JsonPrimitive(b.typeGraphSha256))
    private fun spacesJson(spaces: List<NativeInterfaceAddressSpaceV1>) = JsonArray(spaces.map { jsonObject("index" to JsonPrimitive(it.index), "name" to JsonPrimitive(it.name), "type" to JsonPrimitive(it.type),
        "sizeBits" to JsonPrimitive(it.sizeBits), "addressableUnitSize" to JsonPrimitive(it.addressableUnitSize), "overlay" to JsonPrimitive(it.overlay), "signedOffsets" to JsonPrimitive(it.signedOffsets)) })
    private fun addressJson(a: NativeInterfaceAddressV1): JsonObject = if (a.isNoAddress) jsonObject("kind" to JsonPrimitive("no-address")) else jsonObject("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(a.spaceIndex!!), "offsetBits" to JsonPrimitive(a.offsetBits!!))
    private fun jsonObject(vararg pairs: Pair<String, JsonElement>) = InferredWireV1.freeze(JsonObject(pairs.toMap())).jsonObject
    private fun jsonLimits(bytes: Int, limits: NativeInferredInterfaceObservationLimitsV1) = StrictJsonLimits(bytes, bytes, 20, 100_000, limits.maximumStringBytes, bytes, 20)
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private val SHA = Regex("[0-9a-f]{64}")
    private val HEX = Regex("[0-9a-f]{16}")
}

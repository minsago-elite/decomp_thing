package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeCanonicalStreaming
import decompengine.oracle.fulltree.FullTreeCanonicalStreamingLimits
import decompengine.oracle.structural.CanonicalProgramModelStreaming
import decompengine.oracle.structural.CanonicalProgramModelStreamingLimits
import java.io.InputStream
import java.math.BigInteger
import java.util.Collections
import kotlinx.serialization.json.*

/** Native coordinates are reused verbatim: these offsets are not RVAs or oracle identities. */
typealias NativeInterfaceAddressV1 = NativeCallAddressV1
typealias NativeInterfaceAddressSpaceV1 = NativeCallAddressSpaceV1
typealias NativeInterfaceBindingsV1 = NativeCallBindingsV1

data class NativeInterfaceManifestV1(
    val bytes: Long, val collectorSha256: String, val inputSha256: String,
    val programModelSha256: String, val sha256: String,
)
data class NativeInterfaceVarnodeV1(val address: NativeInterfaceAddressV1, val size: Int)
data class NativeInterfaceStorageV1(
    val state: String, val size: Int?, val autoStorage: Boolean?, val autoParameterType: String?,
    val forcedIndirect: Boolean?, val varnodes: List<NativeInterfaceVarnodeV1>,
)
data class NativeInterfaceParameterV1(
    val ordinal: Int, val name: String?, val source: String?, val autoParameter: Boolean,
    val autoParameterType: String?, val forcedIndirect: Boolean, val formalType: Int?,
    val effectiveType: Int?, val storage: NativeInterfaceStorageV1,
)
data class NativeInterfaceConventionV1(val name: String?, val resolvedModel: String?, val state: String)
sealed interface NativeInterfaceRecordV1
data class NativeInterfaceFunctionV1(
    val entry: NativeInterfaceAddressV1, val name: String, val isExternal: Boolean, val isThunk: Boolean,
    val immediateThunkTarget: NativeInterfaceAddressV1?, val signatureSource: String,
    val convention: NativeInterfaceConventionV1, val varArgs: Boolean, val customStorage: Boolean,
    val parameterCount: Int, val autoParameterCount: Int, val returned: NativeInterfaceParameterV1?,
    val parameters: List<NativeInterfaceParameterV1>,
) : NativeInterfaceRecordV1 {
    /** Native thunk getters may disagree; neither raw field is replaced by a derived value. */
    val autoParameterCountMatchesObserved: Boolean get() = autoParameterCount == parameters.count { it.autoParameter }
}

/** A type ordinal identifies one signature-root occurrence, never type equality or type closure. */
data class NativeInterfaceTypeV1(
    val ordinal: Int, val kind: String, val nativeClass: String, val name: String, val path: String,
    val length: Int, val alignedLength: Int, val alignment: Int, val undefined: Boolean,
    val notYetDefined: Boolean, val signedness: String?,
) : NativeInterfaceRecordV1
data class NativeInterfaceModelFunctionV1(
    val id: String, val modelAddressBits: String, val candidateEntries: List<NativeInterfaceAddressV1>, val state: String,
)
data class NativeInterfaceObservedFunctionV1(
    val entry: NativeInterfaceAddressV1, val state: String, val modelIds: List<String>,
)
data class NativeInterfaceScanV1(
    val functions: Long, val internalFunctions: Long, val externalFunctions: Long, val thunks: Long,
    val parameters: Long, val autoParameters: Long, val types: Long, val storageVarnodes: Long,
)
data class NativeInterfaceObservationSummaryV1(
    val manifest: NativeInterfaceManifestV1, val bindings: NativeInterfaceBindingsV1,
    val addressSpaces: List<NativeInterfaceAddressSpaceV1>, val scan: NativeInterfaceScanV1,
    val modelFunctions: List<NativeInterfaceModelFunctionV1>,
    val observedFunctions: List<NativeInterfaceObservedFunctionV1>,
) {
    val authoritativeOracleEvidence: Boolean = false
    val recoveredModelScored: Boolean = false
    val productionInterfacesAdmitted: Boolean = false
    val releaseEligible: Boolean = false
    val highFunctionState: String = "not-captured"
    val typeClosureState: String = "not-captured"
    val abiClassificationState: String = "not-captured"
}
data class NativeInterfaceObservationLimitsV1(
    val maximumCombinedBytes: Long = 1024L * 1024 * 1024,
    val maximumManifestBytes: Int = 64 * 1024,
    val maximumModelBytes: Int = 512 * 1024 * 1024,
    val maximumFunctions: Int = 131_072,
    val maximumParametersPerFunction: Int = 1024,
    val maximumParameters: Int = 1_000_000,
    val maximumTypes: Int = 524_288,
    val maximumStorageVarnodes: Int = 1_000_000,
    val maximumVarnodesPerStorage: Int = 64,
    val maximumAddressSpaces: Int = 256,
    val maximumRecordBytes: Int = 1024 * 1024,
    val maximumStringBytes: Int = 4096,
) {
    init {
        require(maximumCombinedBytes in 1..1024L * 1024 * 1024)
        require(maximumManifestBytes in 1..64 * 1024 && maximumModelBytes in 1..512 * 1024 * 1024)
        require(maximumFunctions in 1..131_072 && maximumParametersPerFunction in 1..1024)
        require(maximumParameters in 1..1_000_000 && maximumTypes in 1..524_288)
        require(maximumStorageVarnodes in 1..1_000_000 && maximumVarnodesPerStorage in 1..64)
        require(maximumAddressSpaces in 1..256 && maximumRecordBytes in 1..1024 * 1024)
        require(maximumStringBytes in 1..4096 && maximumStringBytes <= maximumRecordBytes)
    }
}

/**
 * Strict recovered-byte assessment and exhaustive model-coordinate projection. All callbacks are
 * speculative until successful return. A successful assessment is not a live operation capability.
 */
object NativeInterfaceObservationsV1 {
    fun validate(
        manifestBytes: ByteArray,
        expectedBindings: NativeInterfaceBindingsV1,
        programModelBytes: ByteArray,
        limits: NativeInterfaceObservationLimitsV1 = NativeInterfaceObservationLimitsV1(),
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (NativeInterfaceRecordV1) -> Unit = {},
    ): NativeInterfaceObservationSummaryV1 = validateBoundToSpaces(
        manifestBytes, { expectedBindings }, programModelBytes, limits, checkpoint, openObservations, consume,
    )

    internal fun validateBoundToSpaces(
        manifestBytes: ByteArray,
        expectedBindings: (List<NativeInterfaceAddressSpaceV1>) -> NativeInterfaceBindingsV1,
        programModelBytes: ByteArray,
        limits: NativeInterfaceObservationLimitsV1 = NativeInterfaceObservationLimitsV1(),
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (NativeInterfaceRecordV1) -> Unit = {},
    ): NativeInterfaceObservationSummaryV1 {
        checkpoint()
        require(manifestBytes.size in 1..limits.maximumManifestBytes) { "interface manifest exceeds its byte bound" }
        val manifestNode = objectValue(OracleJson.parseCanonical(manifestBytes, jsonLimits(limits.maximumManifestBytes, limits)))
        fields(manifestNode, "bytes", "collectorSha256", "file", "inputSha256", "kind", "programModelSha256", "schemaVersion", "sha256")
        require(text(manifestNode, "file") == "native-interfaces.json" &&
            text(manifestNode, "kind") == "ghidra-native-interface-observation-manifest-v1" &&
            number(manifestNode.getValue("schemaVersion")) == 1L) { "unsupported native interface manifest" }
        val manifest = NativeInterfaceManifestV1(count(manifestNode, "bytes"), digest(manifestNode, "collectorSha256"),
            digest(manifestNode, "inputSha256"), digest(manifestNode, "programModelSha256"), digest(manifestNode, "sha256"))
        require(manifest.bytes in 1..(limits.maximumCombinedBytes - manifestBytes.size)) { "interface output exceeds its combined byte bound" }
        val model = CanonicalProgramModelStreaming.readCanonical(programModelBytes, CanonicalProgramModelStreamingLimits(
            maximumInputBytes = limits.maximumModelBytes, maximumFunctions = limits.maximumFunctions,
        ))
        require(model.sha256 == manifest.programModelSha256 && model.model.inputSha256 == manifest.inputSha256) {
            "interface manifest does not bind the exact model and input"
        }
        checkpoint()
        var spaces: List<NativeInterfaceAddressSpaceV1>? = null
        var binding: NativeInterfaceBindingsV1? = null
        var expected: NativeInterfaceBindingsV1? = null
        var scan: NativeInterfaceScanV1? = null
        val functions = linkedMapOf<NativeInterfaceAddressV1, Boolean>()
        val thunkTargets = linkedSetOf<NativeInterfaceAddressV1>()
        var previousEntry: NativeInterfaceAddressV1? = null
        var typePhase = false
        var typeReferences = 0
        var types = 0
        var parameters = 0L
        var autoParameters = 0L
        var external = 0L
        var thunks = 0L
        var storageVarnodes = 0L
        fun reference(value: JsonElement): Int? {
            if (value == JsonNull) return null
            val ordinal = integer(value)
            require(typeReferences < limits.maximumTypes && ordinal == typeReferences) { "interface type occurrences must be dense and in signature order" }
            typeReferences++
            return ordinal
        }
        fun parameter(value: JsonElement): NativeInterfaceParameterV1 {
            val node = objectValue(value)
            fields(node, "ordinal", "name", "source", "autoParameter", "autoParameterType", "forcedIndirect", "formalType", "effectiveType", "storage")
            val formal = reference(node.getValue("formalType"))
            val effective = reference(node.getValue("effectiveType"))
            val source = nullableText(node.getValue("source"))?.also { require(it in SOURCES) { "unsupported parameter source" } }
            val auto = boolean(node.getValue("autoParameter"))
            val autoType = nullableText(node.getValue("autoParameterType"))
            require(auto == (autoType != null)) { "automatic parameter metadata is inconsistent" }
            val storage = storage(node.getValue("storage"), checkNotNull(spaces), limits)
            storageVarnodes = Math.addExact(storageVarnodes, storage.varnodes.size.toLong())
            require(storageVarnodes <= limits.maximumStorageVarnodes) { "interface storage population exceeds its bound" }
            return NativeInterfaceParameterV1(integer(node.getValue("ordinal")), nullableText(node.getValue("name")),
                source, auto, autoType, boolean(node.getValue("forcedIndirect")), formal, effective, storage)
        }
        openObservations().use { stream -> FullTreeCanonicalStreaming.readObject(
            stream, "native interface observations", manifest.sha256, manifest.bytes,
            listOf("addressSpaces", "bindings", "policy", "records", "schemaVersion", "summary"), setOf("records"), null,
            FullTreeCanonicalStreamingLimits(
                maximumInputBytes = manifest.bytes, maximumTokens = 100_000_000,
                maximumEntities = limits.maximumFunctions.toLong() + limits.maximumTypes,
                maximumEntityBytes = limits.maximumRecordBytes, maximumEntityNodes = 100_000,
                maximumDepth = 16, maximumStringBytes = limits.maximumStringBytes,
                maximumTotalStringBytes = manifest.bytes, maximumNumberCharacters = 20,
            ),
            consumeEnvelope = { field, value ->
                checkpoint()
                when (field) {
                    "addressSpaces" -> {
                        spaces = parseSpaces(value, limits)
                        expected = expectedBindings(immutable(checkNotNull(spaces))).also { selected ->
                            listOf(selected.collectorSha256, selected.ghidraArchiveSha256, selected.inputSha256,
                                selected.programModelExporterSha256, selected.programModelSha256).forEach { require(SHA.matches(it)) }
                            require(selected.programModelBytes == model.sizeBytes.toLong() && selected.programModelSha256 == model.sha256 &&
                                selected.inputSha256 == model.model.inputSha256 && selected.collectorSha256 == manifest.collectorSha256) {
                                "interface expected binding differs from the frozen model or manifest"
                            }
                            require(!selected.imageBase.isNoAddress && selected.imageBase.spaceIndex in checkNotNull(spaces).indices)
                            val imageSpace = checkNotNull(spaces)[selected.imageBase.spaceIndex!!]
                            require(imageSpace.type in MEMORY_SPACE_TYPES && !imageSpace.overlay) { "model image base must identify the native base memory space" }
                            require(selected.languageId.isNotEmpty() && selected.compilerSpecId.isNotEmpty())
                        }
                    }
                    "bindings" -> {
                        binding = parseBindings(objectValue(value), checkNotNull(spaces))
                        require(binding == expected) { "interface input/model/exporter/collector/target binding mismatch" }
                    }
                    "policy" -> require(string(value) == "ghidra-native-interface-observations-v1") { "unsupported interface policy" }
                    "schemaVersion" -> require(number(value) == 1L) { "unsupported interface schema" }
                    "summary" -> scan = parseScan(objectValue(value))
                }
            },
        ) { _, _, node, _ ->
            checkpoint()
            when (text(node, "recordKind")) {
                "function" -> {
                    require(!typePhase && functions.size < limits.maximumFunctions) { "interface function order or count is invalid" }
                    fields(node, "recordKind", "entry", "name", "isExternal", "isThunk", "immediateThunkTarget", "signatureSource",
                        "convention", "varArgs", "customStorage", "parameterCount", "autoParameterCount", "return", "parameters", "highFunction")
                    require(text(node, "highFunction") == "not-captured") { "listing observations cannot claim HighFunction capture" }
                    val entry = address(node.getValue("entry"), checkNotNull(spaces))
                    require(!entry.isNoAddress && (previousEntry == null || compare(previousEntry!!, entry, checkNotNull(spaces)) < 0)) { "interface functions must have unique ordered typed entries" }
                    previousEntry = entry
                    val isExternal = boolean(node.getValue("isExternal"))
                    require(isExternal == (checkNotNull(spaces)[entry.spaceIndex!!].type == 10)) { "external function must retain its native external address space" }
                    val isThunk = boolean(node.getValue("isThunk"))
                    val target = nullableAddress(node.getValue("immediateThunkTarget"), checkNotNull(spaces))
                    require(isThunk == (target != null) && target?.isNoAddress != true) { "thunk target is missing or misplaced" }
                    target?.let(thunkTargets::add)
                    val signatureSource = text(node, "signatureSource").also { require(it in SOURCES) }
                    val convention = objectValue(node.getValue("convention"))
                    fields(convention, "name", "resolvedModel", "state")
                    val conventionValue = NativeInterfaceConventionV1(nullableText(convention.getValue("name")),
                        nullableText(convention.getValue("resolvedModel")), text(convention, "state"))
                    val expectedConventionState = when (conventionValue.name) {
                        null, "unknown" -> "unknown"
                        "default" -> "default"
                        else -> if (conventionValue.resolvedModel == null) "named-unresolved" else "named-resolved"
                    }
                    require(conventionValue.state == expectedConventionState) { "convention state differs from native name and model metadata" }
                    val returned = node.getValue("return").takeUnless { it == JsonNull }?.let(::parameter)
                    require(returned == null || returned.ordinal == -1) { "return parameter must retain its native return ordinal" }
                    val parameterNodes = array(node.getValue("parameters"))
                    require(parameterNodes.size <= limits.maximumParametersPerFunction) { "interface parameter list exceeds its bound" }
                    parameters = Math.addExact(parameters, parameterNodes.size.toLong())
                    require(parameters <= limits.maximumParameters) { "interface aggregate parameter count exceeds its bound" }
                    val parsedParameters = parameterNodes.mapIndexed { index, value -> parameter(value).also {
                        require(it.ordinal == index) { "native parameter ordinal differs from its ordered listing slot" }
                    } }
                    val parameterCount = integer(node.getValue("parameterCount"))
                    val automaticCount = integer(node.getValue("autoParameterCount"))
                    require(parameterCount == parsedParameters.size && automaticCount in 0..parameterCount) {
                        "native parameter counts disagree with the complete parameter list"
                    }
                    autoParameters += parsedParameters.count { it.autoParameter }
                    if (isExternal) external++
                    if (isThunk) thunks++
                    functions[entry] = isExternal
                    consume(NativeInterfaceFunctionV1(entry, text(node, "name"), isExternal, isThunk, target, signatureSource,
                        conventionValue, boolean(node.getValue("varArgs")), boolean(node.getValue("customStorage")), parameterCount,
                        automaticCount, returned, immutable(parsedParameters)))
                }
                "type" -> {
                    typePhase = true
                    fields(node, "recordKind", "ordinal", "kind", "nativeClass", "name", "path", "length", "alignedLength", "alignment",
                        "undefined", "notYetDefined", "signedness", "layout", "typeClosure")
                    require(types < typeReferences && integer(node.getValue("ordinal")) == types) { "missing, duplicate or unexpected signature type occurrence" }
                    require(text(node, "layout") == "not-captured" && text(node, "typeClosure") == "not-captured") { "root type metadata cannot claim layout or type closure" }
                    val kind = text(node, "kind").also { require(it in TYPE_KINDS) }
                    val signedness = nullableText(node.getValue("signedness"))
                    require(signedness == null || signedness in setOf("signed", "unsigned"))
                    require((signedness != null) == (kind == "integer")) { "signedness requires a typed native integer observation" }
                    consume(NativeInterfaceTypeV1(types++, kind, text(node, "nativeClass"), text(node, "name"), text(node, "path"),
                        integer(node.getValue("length")), integer(node.getValue("alignedLength")), integer(node.getValue("alignment")),
                        boolean(node.getValue("undefined")), boolean(node.getValue("notYetDefined")), signedness))
                }
                else -> error("unsupported interface record kind")
            }
        } }
        require(thunkTargets.all { it in functions }) { "complete interface census omits an immediate thunk target" }
        require(types == typeReferences) { "interface observations omit referenced signature type occurrences" }
        val actual = NativeInterfaceScanV1(functions.size.toLong(), functions.size - external, external, thunks,
            parameters, autoParameters, types.toLong(), storageVarnodes)
        require(scan == actual) { "interface summary does not conserve the complete observed population" }
        val fixedBinding = checkNotNull(binding)
        val modelByAddress = model.model.functions.groupBy { it.address }
        val modelIdsByAddress = modelByAddress.mapValues { (_, rows) -> immutable(rows.map { it.id }.sorted()) }
        // ExportProgramModel stores only getOffset(), so its scalar alone cannot identify a
        // native address space. Retain all non-external candidates before permitting any join.
        val nativeByOffset = functions.filterValues { !it }.keys.groupBy { checkNotNull(it.offsetBits).toULong(16) }
            .mapValues { (_, entries) -> immutable(entries) }
        val modelRows = model.model.functions.sortedBy { it.id }.map { function ->
            checkpoint()
            val candidates = nativeByOffset[function.address].orEmpty()
            val state = when {
                modelByAddress.getValue(function.address).size != 1 -> "ambiguous-model-address"
                candidates.size > 1 -> "ambiguous-native-address"
                candidates.isEmpty() -> "missing-listing-function"
                candidates.single().spaceIndex != fixedBinding.imageBase.spaceIndex -> "different-address-space"
                else -> "matched"
            }
            NativeInterfaceModelFunctionV1(function.id, function.address.toString(16).padStart(16, '0'), candidates, state)
        }
        val observedRows = functions.map { (entry, isExternal) ->
            checkpoint()
            val offset = checkNotNull(entry.offsetBits).toULong(16)
            val ids = if (!isExternal) modelIdsByAddress[offset].orEmpty() else emptyList()
            val state = when {
                isExternal -> "external-unmapped"
                ids.size > 1 -> "ambiguous-model-address"
                ids.isNotEmpty() && nativeByOffset.getValue(offset).size > 1 -> "ambiguous-native-address"
                entry.spaceIndex != fixedBinding.imageBase.spaceIndex -> "different-address-space"
                ids.isEmpty() -> "unmatched-observed-function"
                else -> "matched"
            }
            NativeInterfaceObservedFunctionV1(entry, state, ids)
        }
        return NativeInterfaceObservationSummaryV1(manifest, fixedBinding, immutable(checkNotNull(spaces)), actual,
            immutable(modelRows), immutable(observedRows))
    }

    private fun storage(value: JsonElement, spaces: List<NativeInterfaceAddressSpaceV1>, limits: NativeInterfaceObservationLimitsV1): NativeInterfaceStorageV1 {
        val node = objectValue(value)
        fields(node, "state", "size", "autoStorage", "autoParameterType", "forcedIndirect", "varnodes")
        val state = text(node, "state").also { require(it in setOf("assigned", "bad", "unassigned", "void", "absent")) }
        val size = node.getValue("size").takeUnless { it == JsonNull }?.let(::integer)
        val auto = nullableBoolean(node.getValue("autoStorage"))
        val indirect = nullableBoolean(node.getValue("forcedIndirect"))
        val autoType = nullableText(node.getValue("autoParameterType"))
        val pieces = array(node.getValue("varnodes"))
        require(pieces.size <= limits.maximumVarnodesPerStorage) { "native storage piece count exceeds its bound" }
        val parsed = pieces.map { item ->
            val piece = objectValue(item); fields(piece, "address", "size")
            val location = address(piece.getValue("address"), spaces)
            val bytes = integer(piece.getValue("size"))
            require(!location.isNoAddress && bytes > 0) { "storage pieces require a native address and positive size" }
            NativeInterfaceVarnodeV1(location, bytes)
        }
        if (state == "absent") require(size == null && auto == null && indirect == null && autoType == null && parsed.isEmpty())
        else {
            require(size != null && size >= 0 && auto != null && indirect != null && auto == (autoType != null)) { "storage metadata is incomplete" }
            require(size.toLong() == parsed.sumOf { it.size.toLong() }) { "storage size differs from its ordered pieces" }
            require((state == "assigned") == parsed.isNotEmpty()) { "storage state differs from its pieces" }
        }
        return NativeInterfaceStorageV1(state, size, auto, autoType, indirect, immutable(parsed))
    }

    private fun parseScan(node: JsonObject): NativeInterfaceScanV1 {
        fields(node, "coverage", "functions", "internalFunctions", "externalFunctions", "thunks", "parameters", "autoParameters",
            "types", "storageVarnodes", "highFunction", "typeClosure", "abiClassification")
        require(text(node, "coverage") == "all-currently-listed-internal-and-external-functions" &&
            listOf("highFunction", "typeClosure", "abiClassification").all { text(node, it) == "not-captured" }) {
            "native interface coverage or unavailable domains changed"
        }
        return NativeInterfaceScanV1(count(node, "functions"), count(node, "internalFunctions"), count(node, "externalFunctions"),
            count(node, "thunks"), count(node, "parameters"), count(node, "autoParameters"), count(node, "types"), count(node, "storageVarnodes"))
    }

    private fun parseBindings(node: JsonObject, spaces: List<NativeInterfaceAddressSpaceV1>): NativeInterfaceBindingsV1 {
        fields(node, "collectorSha256", "compilerSpecId", "ghidraArchiveSha256", "imageBase", "inputSha256", "languageId",
            "programModelBytes", "programModelExporterSha256", "programModelSha256")
        return NativeInterfaceBindingsV1(digest(node, "collectorSha256"), text(node, "compilerSpecId"), digest(node, "ghidraArchiveSha256"),
            address(node.getValue("imageBase"), spaces), digest(node, "inputSha256"), text(node, "languageId"), count(node, "programModelBytes"),
            digest(node, "programModelExporterSha256"), digest(node, "programModelSha256"))
    }

    private fun parseSpaces(value: JsonElement, limits: NativeInterfaceObservationLimitsV1): List<NativeInterfaceAddressSpaceV1> {
        val nodes = array(value)
        require(nodes.size in 1..limits.maximumAddressSpaces) { "native address space inventory exceeds its bound" }
        val spaces = nodes.mapIndexed { index, raw ->
            val node = objectValue(raw)
            fields(node, "index", "name", "type", "sizeBits", "addressableUnitSize", "overlay", "signedOffsets")
            val result = NativeInterfaceAddressSpaceV1(integer(node.getValue("index")), text(node, "name"), integer(node.getValue("type")),
                integer(node.getValue("sizeBits")), integer(node.getValue("addressableUnitSize")), boolean(node.getValue("overlay")), boolean(node.getValue("signedOffsets")))
            require(result.index == index && result.name.isNotEmpty() && result.type in 0..15 && result.sizeBits in 1..64 && result.addressableUnitSize > 0) {
                "invalid native address-space descriptor"
            }
            require(nativeSpan(result) <= BigInteger.ONE.shiftLeft(64)) { "native address-space byte span exceeds 64 bits" }
            result
        }
        require(spaces.map { it.name }.distinct().size == spaces.size) { "duplicate native address-space name" }
        return spaces
    }

    private fun address(value: JsonElement, spaces: List<NativeInterfaceAddressSpaceV1>): NativeInterfaceAddressV1 {
        val node = objectValue(value)
        if (text(node, "kind") == "no-address") {
            fields(node, "kind")
            return NativeInterfaceAddressV1(null, null)
        }
        fields(node, "kind", "spaceIndex", "offsetBits")
        require(text(node, "kind") == "address")
        val index = integer(node.getValue("spaceIndex")); require(index in spaces.indices)
        val bits = text(node, "offsetBits"); require(HEX.matches(bits))
        val space = spaces[index]
        val span = nativeSpan(space)
        val offset = if (space.signedOffsets) BigInteger.valueOf(bits.toULong(16).toLong()) else BigInteger(bits, 16)
        require(if (space.signedOffsets) offset >= span.shiftRight(1).negate() && offset < span.shiftRight(1)
            else offset.signum() >= 0 && offset < span) { "native offset bits exceed their typed address space" }
        return NativeInterfaceAddressV1(index, bits)
    }

    private fun nativeSpan(space: NativeInterfaceAddressSpaceV1) = BigInteger.valueOf(space.addressableUnitSize.toLong()).shiftLeft(space.sizeBits)
    private fun nullableAddress(value: JsonElement, spaces: List<NativeInterfaceAddressSpaceV1>) = if (value == JsonNull) null else address(value, spaces)
    private fun compare(a: NativeInterfaceAddressV1, b: NativeInterfaceAddressV1, spaces: List<NativeInterfaceAddressSpaceV1>): Int {
        val order = checkNotNull(a.spaceIndex).compareTo(checkNotNull(b.spaceIndex))
        if (order != 0) return order
        return if (spaces[checkNotNull(a.spaceIndex)].signedOffsets)
            checkNotNull(a.offsetBits).toULong(16).toLong().compareTo(checkNotNull(b.offsetBits).toULong(16).toLong())
        else checkNotNull(a.offsetBits).compareTo(checkNotNull(b.offsetBits))
    }
    private fun jsonLimits(bytes: Int, limits: NativeInterfaceObservationLimitsV1) = StrictJsonLimits(
        maximumInputBytes = bytes, maximumCanonicalBytes = bytes, maximumDepth = 16, maximumNodes = 100_000,
        maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = bytes, maximumNumberCharacters = 20,
    )
    private fun objectValue(value: JsonElement) = value as? JsonObject ?: error("native interface value must be an object")
    private fun array(value: JsonElement) = value as? JsonArray ?: error("native interface value must be an array")
    private fun fields(node: JsonObject, vararg names: String) { require(node.keys == names.toSet()) { "native interface object has missing or extra fields" } }
    private fun string(value: JsonElement): String {
        val primitive = value as? JsonPrimitive ?: error("native interface value must be a string")
        require(primitive.isString && primitive.content.toByteArray(Charsets.UTF_8).size <= 4096)
        return primitive.content
    }
    private fun text(node: JsonObject, name: String) = string(node.getValue(name))
    private fun nullableText(value: JsonElement) = if (value == JsonNull) null else string(value)
    private fun number(value: JsonElement): Long {
        val primitive = value as? JsonPrimitive ?: error("native interface value must be an integer")
        require(!primitive.isString && primitive.content.matches(Regex("-?(?:0|[1-9][0-9]*)")))
        return primitive.content.toLong()
    }
    private fun integer(value: JsonElement) = number(value).also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }.toInt()
    private fun count(node: JsonObject, name: String) = number(node.getValue(name)).also { require(it >= 0) }
    private fun boolean(value: JsonElement): Boolean {
        val primitive = value as? JsonPrimitive ?: error("native interface value must be boolean")
        require(!primitive.isString)
        return primitive.booleanOrNull ?: error("native interface value must be boolean")
    }
    private fun nullableBoolean(value: JsonElement) = if (value == JsonNull) null else boolean(value)
    private fun digest(node: JsonObject, name: String) = text(node, name).also { require(SHA.matches(it)) }
    private fun <T> immutable(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
    private val SHA = Regex("[0-9a-f]{64}")
    private val HEX = Regex("[0-9a-f]{16}")
    private val SOURCES = setOf("DEFAULT", "ANALYSIS", "AI", "IMPORTED", "USER_DEFINED")
    private val TYPE_KINDS = setOf("void", "undefined", "integer", "float", "pointer", "array", "structure", "union", "enum", "typedef", "function-definition", "other")
    private val MEMORY_SPACE_TYPES = setOf(1, 2, 7, 13)
}

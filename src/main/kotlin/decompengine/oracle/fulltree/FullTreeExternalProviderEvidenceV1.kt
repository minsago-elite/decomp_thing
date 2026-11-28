package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.externalcalls.ElfDynamicBindingInventoryV1
import kotlinx.serialization.json.*
import java.util.Collections

internal data class ExternalLinkStageIdentityV1(
    val buildRunId: String, val graphActionId: String, val ordinal: Int,
    val sourceRevisionSha256: String, val planSha256: String, val policySha256: String,
    val outputRole: String, val outputBytes: Long, val outputSha256: String,
)

internal class RecordedElfEvidenceV1(
    val schemaKind: String, val sourceSha256: String, val stage: ExternalLinkStageIdentityV1,
    val inventorySha256: String, val symbolCount: Int, val relocationCount: Int,
    symbols: List<JsonObject>, references: List<JsonObject>,
    neededLibraries: List<String>, unsupportedReasons: List<String>, canonicalBytes: ByteArray, inventoryRecord: JsonObject, budget: ExternalBoundaryBudgetV1? = null,
) {
    init { require(symbols.size.toLong()+references.size+neededLibraries.size+unsupportedReasons.size <= (budget?.limits?.maximumReferencesAndEvents ?: 65536)); boundedConstructorStrings(listOf(schemaKind,sourceSha256,inventorySha256,stage.buildRunId,stage.graphActionId,stage.outputRole)+neededLibraries+unsupportedReasons,budget) }
    private val owned = BoundaryOwnedSnapshotV1(canonicalBytes, listOf(JsonArray(symbols), JsonArray(references), inventoryRecord, JsonArray(neededLibraries.map(::JsonPrimitive)), JsonArray(unsupportedReasons.map(::JsonPrimitive))), budget)
    private val canonicalBytes = owned.bytes
    private val inventoryRecord = owned.json[2].jsonObject
    val symbols: List<JsonObject> = Collections.unmodifiableList(owned.json[0].jsonArray.map { it.jsonObject })
    val references: List<JsonObject> = Collections.unmodifiableList(owned.json[1].jsonArray.map { it.jsonObject })
    val neededLibraries: List<String> = Collections.unmodifiableList(neededLibraries.toList())
    val unsupportedReasons: List<String> = Collections.unmodifiableList(unsupportedReasons.toList())
    fun snapshot(): ByteArray = canonicalBytes.copyOf()
    fun toJson(): JsonObject = buildJsonObject {
        put("schemaKind", schemaKind); put("sourceSha256", sourceSha256)
        put("stage", buildJsonObject {
            put("buildRunId", stage.buildRunId); put("graphActionId", stage.graphActionId); put("ordinal", stage.ordinal)
            put("sourceRevisionSha256", stage.sourceRevisionSha256); put("planSha256", stage.planSha256); put("policySha256", stage.policySha256)
            put("outputRole", stage.outputRole); put("outputBytes", stage.outputBytes); put("outputSha256", stage.outputSha256)
        })
        put("inventorySha256", inventorySha256); put("symbolCount", symbolCount); put("relocationCount", relocationCount)
        put("symbols", JsonArray(symbols)); put("references", JsonArray(references))
        put("neededLibraries", JsonArray(neededLibraries.map(::JsonPrimitive)))
        put("unsupportedReasons", JsonArray(unsupportedReasons.map(::JsonPrimitive)))
        put("inventory", inventoryRecord)
        put("limitations", JsonArray(listOf("section-declared DYNSYM is not a complete full-tree symbol universe", "ELF inventory does not authenticate a link stage or runtime provider").map(::JsonPrimitive)))
    }
}

internal class RecordedRuntimeCandidatesV1(
    val schemaKind: String, val sourceSha256: String, val schemaVersion: Int,
    canonicalBytes: ByteArray, nodes: List<JsonObject>, edges: List<JsonObject>,
    rawLayers: List<JsonObject>, readOnlyRuntime: JsonObject, staticGraph: JsonObject,
    val mergedNamespaceSha256: String,
    val candidateCount: Int, val ambiguousCandidateCount: Int, limitations: List<String>, budget: ExternalBoundaryBudgetV1? = null,
) {
    init { require(nodes.size.toLong()+edges.size+rawLayers.size+limitations.size <= (budget?.limits?.maximumReferencesAndEvents ?: 65536)); boundedConstructorStrings(listOf(schemaKind,sourceSha256,mergedNamespaceSha256)+limitations,budget) }
    private val owned = BoundaryOwnedSnapshotV1(canonicalBytes, listOf(JsonArray(nodes), JsonArray(edges), JsonArray(rawLayers), readOnlyRuntime, staticGraph), budget)
    private val canonicalBytes = owned.bytes
    val nodes: List<JsonObject> = Collections.unmodifiableList(owned.json[0].jsonArray.map { it.jsonObject })
    val edges: List<JsonObject> = Collections.unmodifiableList(owned.json[1].jsonArray.map { it.jsonObject })
    val rawLayers: List<JsonObject> = Collections.unmodifiableList(owned.json[2].jsonArray.map { it.jsonObject })
    val readOnlyRuntime: JsonObject = owned.json[3].jsonObject
    val staticGraph: JsonObject = owned.json[4].jsonObject
    val limitations: List<String> = Collections.unmodifiableList(limitations.toList())
    fun snapshot(): ByteArray = canonicalBytes.copyOf()
    fun toJson(budget: ExternalBoundaryBudgetV1): JsonObject = buildJsonObject {
        put("schemaKind", schemaKind); put("sourceSha256", sourceSha256); put("schemaVersion", schemaVersion)
        put("raw", OracleJson.parseCanonical(canonicalBytes, budget.jsonLimits(), budget::checkpoint) as JsonObject)
        put("mergedNamespaceSha256", mergedNamespaceSha256); put("nodes", JsonArray(nodes)); put("edges", JsonArray(edges))
        put("orderedRawLayers", JsonArray(rawLayers)); put("readOnlyRuntime", readOnlyRuntime); put("staticGraph", staticGraph)
        put("candidateCount", candidateCount); put("ambiguousCandidateCount", ambiguousCandidateCount)
        put("limitations", JsonArray(limitations.map(::JsonPrimitive)))
    }
}

internal class RecordedRuntimeClosureV1(
    val schemaKind: String, val sourceSha256: String, canonicalBytes: ByteArray,
    val executableBindingPresent: Boolean, val interpreterCount: Int, val libraryCount: Int,
    val resolverPresent: Boolean, val cachePresent: Boolean, limitations: List<String>,
    interpreters: List<JsonObject>, libraries: List<JsonObject>, resolver: JsonObject?, loaderCache: JsonObject?, budget: ExternalBoundaryBudgetV1? = null,
) {
    init { require(interpreters.size.toLong()+libraries.size+limitations.size <= (budget?.limits?.maximumReferencesAndEvents ?: 65536)); boundedConstructorStrings(listOf(schemaKind,sourceSha256)+limitations,budget) }
    private val owned = BoundaryOwnedSnapshotV1(canonicalBytes, listOf(JsonArray(interpreters), JsonArray(libraries), resolver ?: JsonNull, loaderCache ?: JsonNull), budget)
    private val canonicalBytes = owned.bytes
    val interpreters: List<JsonObject> = Collections.unmodifiableList(owned.json[0].jsonArray.map { it.jsonObject })
    val libraries: List<JsonObject> = Collections.unmodifiableList(owned.json[1].jsonArray.map { it.jsonObject })
    val resolver: JsonObject? = owned.json[2].takeUnless { it == JsonNull }?.jsonObject
    val loaderCache: JsonObject? = owned.json[3].takeUnless { it == JsonNull }?.jsonObject
    val limitations: List<String> = Collections.unmodifiableList(limitations.toList())
    fun snapshot(): ByteArray = canonicalBytes.copyOf()
    fun toJson(budget: ExternalBoundaryBudgetV1): JsonObject = buildJsonObject {
        put("schemaKind", schemaKind); put("sourceSha256", sourceSha256)
        put("raw", OracleJson.parseCanonical(canonicalBytes, budget.jsonLimits(), budget::checkpoint) as JsonObject)
        put("executableBindingPresent", executableBindingPresent); put("interpreterCount", interpreterCount); put("libraryCount", libraryCount)
        put("resolverPresent", resolverPresent); put("cachePresent", cachePresent)
        put("interpreters", JsonArray(interpreters)); put("libraries", JsonArray(libraries))
        put("resolver", resolver ?: JsonNull); put("loaderCache", loaderCache ?: JsonNull)
        put("limitations", JsonArray(limitations.map(::JsonPrimitive)))
    }
}

internal object FullTreeExternalProviderEvidenceV1 {
    fun fromElf(stage: ExternalLinkStageIdentityV1, inventory: ElfDynamicBindingInventoryV1, budget: ExternalBoundaryBudgetV1): RecordedElfEvidenceV1 {
        budget.checkpoint("ELF evidence adaptation")
        require(stage.outputSha256 == inventory.inputSha256) { "link stage output digest differs from ELF inventory input" }
        require(stage.outputBytes > 0 && stage.ordinal >= 0)
        boundedConstructorStrings(listOf(stage.buildRunId,stage.graphActionId,stage.outputRole),budget)
        require(stage.outputRole in setOf("executable","shared-library","relocatable"))
        require(listOf(stage.outputSha256,stage.sourceRevisionSha256,stage.planSha256,stage.policySha256).all { it.matches(Regex("[0-9a-f]{64}")) })
        require(inventory.dynamicSymbols.size + inventory.relocations.size <= budget.limits.maximumReferencesAndEvents)
        budget.retain(0, inventory.dynamicSymbols.size.toLong() + inventory.relocations.size, "ELF inventory row population")
        budget.checkpoint("before existing ELF inventory snapshot", inventory.dynamicSymbols.size.toLong() + inventory.relocations.size)
        preflightElfProjection(stage, inventory, budget)
        val json = boundedInventoryJson(inventory, budget)
        val bytes = OracleJson.canonicalBytes(json, budget.jsonLimits(), budget::checkpoint)
        require(bytes.size <= budget.limits.maximumDocumentBytes) { "ELF projection exceeds output ceiling" }
        budget.retain(bytes.size.toLong(), stage = "ELF evidence snapshot")
        val symbolsJson = (json["dynamicSymbols"] as JsonArray).mapIndexed { index, item -> budget.checkpoint("ELF raw symbol snapshot $index"); item as JsonObject }
        val symbols = symbolsJson.mapIndexed { index, symbol -> budget.checkpoint("ELF symbol evidence projection $index"); buildJsonObject {
            put("artifactRole", stage.outputRole); put("artifactSha256", stage.outputSha256)
            put("tableSectionIndex", symbol["tableSectionIndex"]!!); put("symbolIndex", symbol["symbolIndex"]!!)
            put("rawLocator", symbol["locator"]!!); put("name", symbol["name"]!!); put("type", symbol["type"]!!)
            put("binding", symbol["binding"]!!); put("visibility", symbol["visibility"]!!)
            put("version", symbol["version"]!!); put("sectionKind", symbol["sectionKind"]!!)
        } }
        val symbolIndex = HashMap<Pair<JsonElement?, JsonElement?>, JsonObject>()
        symbolsJson.forEach { symbol ->
            budget.checkpoint("ELF symbol index construction")
            require(symbolIndex.put(symbol["tableSectionIndex"] to symbol["symbolIndex"], symbol) == null) { "duplicate physical ELF symbol" }
        }
        val references = (json["relocations"] as JsonArray).mapIndexed { index, relocation ->
            budget.checkpoint("ELF relocation evidence projection $index")
            relocation as JsonObject
            val symbol = symbolIndex[relocation["symbolTableSectionIndex"] to relocation["symbolIndex"]] ?: error("ELF relocation has no exact symbol-table locator")
            buildJsonObject {
                put("artifactRole", stage.outputRole); put("artifactSha256", stage.outputSha256)
                put("member", JsonNull); put("tableSectionIndex", symbol["tableSectionIndex"]!!)
                put("symbolIndex", symbol["symbolIndex"]!!); put("rawLocator", symbol["locator"]!!)
                put("relocationSectionIndex", relocation["sectionIndex"]!!); put("relocationIndex", relocation["relocationIndex"]!!)
                put("offset", relocation["offset"]!!); put("type", relocation["type"]!!); put("addend", relocation["addend"]!!)
                put("ownerModuleId", JsonNull); put("ownerEntityId", JsonNull); put("abiSourceId", JsonNull)
            }
        }
        budget.checkpoint("before ELF inventory digest", bytes.size.toLong())
        val sourceDigest = boundarySha256(bytes, budget)
        budget.checkpoint("after ELF inventory digest")
        val result = RecordedElfEvidenceV1("independent-elf-dynamic-bindings-v1", sourceDigest, stage,
            sourceDigest, inventory.dynamicSymbols.size, inventory.relocations.size,
            symbols, references,
            Collections.unmodifiableList(inventory.neededLibraries.toList()),
            Collections.unmodifiableList(inventory.unsupportedReasons.toList()), bytes, json, budget)
        budget.checkpoint("terminal ELF evidence publication")
        return result
    }

    fun fromRawMeasurement(bytes: ByteArray, budget: ExternalBoundaryBudgetV1): RecordedRuntimeCandidatesV1 {
        budget.checkpoint("raw runtime measurement decode")
        require(bytes.size <= budget.limits.maximumDocumentBytes)
        val obj = OracleJson.parseCanonical(bytes, budget.jsonLimits(), budget::checkpoint) as? JsonObject ?: error("measurement must be an object")
        validateMeasurement(obj, budget)
        require(obj["artifactKind"] == JsonPrimitive("native-runtime-measurement-candidate"))
        require(obj["authority"] == JsonPrimitive("unapproved-raw-measurement-only"))
        listOf("oracleAuthority", "runtimeProfileApproved", "startAuthorized", "containmentProved", "scoringAuthority", "releaseEligible")
            .forEach { require(obj[it] == JsonPrimitive(false)) { "raw measurement claims authority" } }
        val version = (obj["schemaVersion"] as? JsonPrimitive)?.intOrNull ?: error("missing schema version")
        require(version == 2 || version == 3) { "unsupported raw measurement schema" }
        val canonical = OracleJson.canonicalBytes(obj, budget.jsonLimits(), budget::checkpoint)
        val graph = obj["subjectStaticElfClosure"] as JsonObject
        val nodes = (graph["nodes"] as JsonArray).mapIndexed { i, item -> budget.checkpoint("runtime node retained projection $i"); JsonObject(item.jsonObject) }
        val edges = (graph["edges"] as JsonArray).mapIndexed { i, item -> budget.checkpoint("runtime edge retained projection $i"); JsonObject(item.jsonObject) }
        val layers = (obj["orderedRawLayers"] as JsonArray).mapIndexed { i, item -> budget.checkpoint("raw layer retained projection $i"); JsonObject(item.jsonObject) }
        val candidates = edges.sumOf { (it["candidates"] as JsonArray).size.toLong() }
        require(candidates <= budget.limits.maximumReferencesAndEvents)
        val ambiguous = edges.count { it["selectionUniqueUnderStatedModel"] == JsonPrimitive(false) }
        budget.retain(canonical.size.toLong(), stage = "raw measurement retained snapshot")
        budget.checkpoint("before raw runtime measurement digest", canonical.size.toLong())
        val sourceDigest = boundarySha256(canonical, budget)
        budget.checkpoint("after raw runtime measurement digest")
        budget.checkpoint("before raw runtime snapshot copy", canonical.size.toLong())
        val result = RecordedRuntimeCandidatesV1("native-runtime-measurement-candidate-v$version", sourceDigest, version,
            canonical.copyOf(), nodes, edges, layers, obj["readOnlyRuntime"]!!.jsonObject, graph,
            obj["mergedNamespaceSha256"]!!.jsonPrimitive.content, candidates.toInt(), ambiguous,
            Collections.unmodifiableList(listOf("static provider candidates are not runtime binding evidence", "measurement has no authority", "loader search, binding and namespace resolution remain unqualified")), budget)
        budget.checkpoint("terminal runtime candidates publication")
        return result
    }

    fun fromRecordedClosure(bytes: ByteArray, budget: ExternalBoundaryBudgetV1): RecordedRuntimeClosureV1 {
        budget.checkpoint("runtime closure receipt decode")
        require(bytes.size <= budget.limits.maximumDocumentBytes)
        val obj = OracleJson.parseCanonical(bytes, budget.jsonLimits(), budget::checkpoint) as? JsonObject ?: error("closure must be object")
        validateClosure(obj, budget)
        val kind = (obj["provider"] as JsonPrimitive).content
        val canonical = OracleJson.canonicalBytes(obj, budget.jsonLimits(), budget::checkpoint)
        val interpreters = obj["interpreters"] as JsonArray; val libraries = obj["libraries"] as JsonArray
        budget.retain(0, interpreters.size.toLong() + libraries.size, "runtime closure mount projections")
        budget.retain(canonical.size.toLong(), stage = "runtime closure retained snapshot")
        val resolver = obj["resolver"] != JsonNull; val cache = obj["loaderCache"] != JsonNull
        budget.checkpoint("before recorded closure digest", canonical.size.toLong())
        val sourceDigest = boundarySha256(canonical, budget)
        budget.checkpoint("after recorded closure digest")
        budget.checkpoint("before closure snapshot copy", canonical.size.toLong())
        val result = RecordedRuntimeClosureV1(kind, sourceDigest, canonical.copyOf(), false,
            interpreters.size, libraries.size, resolver, cache,
            Collections.unmodifiableList(listOf("closure receipt is recorded diagnostic input", "executable-to-closure binding is absent", "host resolver/cache facts do not authenticate an A14 provider policy")),
            interpreters.map { it.jsonObject }, libraries.map { it.jsonObject }, obj["resolver"]?.takeIf { it != JsonNull }?.jsonObject,
            obj["loaderCache"]?.takeIf { it != JsonNull }?.jsonObject, budget)
        budget.checkpoint("terminal runtime closure publication")
        return result
    }

    private fun validateMeasurement(o: JsonObject, budget: ExternalBoundaryBudgetV1) {
        val version = (o["schemaVersion"] as? JsonPrimitive)?.intOrNull ?: error("measurement schema version missing")
        val top = setOf("schemaVersion", "artifactKind", "authority", "oracleAuthority", "runtimeProfileApproved", "startAuthorized", "containmentProved", "scoringAuthority", "releaseEligible", "deploymentJarSha256", "deploymentJarBytes", "codecDeploymentInputs", "measurementRecipeBinding", "rawOciIndexSha256", "rawOciIndexBytes", "rawOciManifestSha256", "rawOciManifestBytes", "rawConfigSha256", "rawConfigBytes", "mergedNamespaceSha256", "mergedNamespaceEntries", "orderedRawLayers", "readOnlyRuntime", "subjectStaticElfClosure")
        require(o.keys == top) {
            "runtime measurement fields differ from raw V$version producer schema"
        }
        require(version == 2 || version == 3)
        require(o["schemaVersion"] == JsonPrimitive(version)) { "runtime schema version must be an integer token" }
        for (field in listOf("deploymentJarSha256", "rawOciIndexSha256", "rawOciManifestSha256", "rawConfigSha256", "mergedNamespaceSha256")) requireSha(o, field)
        for (field in listOf("deploymentJarBytes", "rawOciIndexBytes", "rawOciManifestBytes", "rawConfigBytes", "mergedNamespaceEntries")) requireNonNegative(o, field)
        val codecs = o["codecDeploymentInputs"] as? JsonArray ?: error("codecDeploymentInputs missing")
        require(codecs.size <= budget.limits.maximumTools)
        budget.retain(0,codecs.size.toLong(),"runtime codec population")
        require(codecs.map { it.jsonObject["filename"] }.toSet().size == codecs.size)
        codecs.forEachIndexed { index, item ->
            budget.checkpoint("runtime codec input validation $index")
            val r = item.jsonObject
            require(r.keys == setOf("filename", "bytes", "sha256", "nativeFallbackAllowed", "selectedCodecClassesOriginVerified"))
            requireString(r, "filename"); requireNonNegative(r, "bytes"); requireSha(r, "sha256")
            require(r["nativeFallbackAllowed"] == JsonPrimitive(false) && r["selectedCodecClassesOriginVerified"] == JsonPrimitive(true))
        }
        val recipe = o["measurementRecipeBinding"]!!.jsonObject
        require(recipe.keys == setOf("ownJarResource", "containerPath", "bytes", "sha256", "rawImageBytesMatchDeployment", "buildExecutionAuthenticated", "runtimeProfileApproved"))
        requireString(recipe, "ownJarResource"); requireAbsolutePath(recipe, "containerPath"); requireNonNegative(recipe, "bytes"); requireSha(recipe, "sha256")
        require(recipe["rawImageBytesMatchDeployment"] == JsonPrimitive(true) && recipe["buildExecutionAuthenticated"] == JsonPrimitive(false) && recipe["runtimeProfileApproved"] == JsonPrimitive(false))
        val layers = o["orderedRawLayers"]!!.jsonArray
        require(layers.size <= budget.limits.maximumStages)
        budget.retain(0,layers.size.toLong(),"runtime layer population")
        val layerDiffIds = layers.mapIndexed { index, item -> budget.checkpoint("ordered OCI layer validation $index"); val layer = item.jsonObject
            require(layer.keys == setOf("blobSha256", "blobBytes", "mediaType", "uncompressedDiffId", "uncompressedBytes"))
            requireSha(layer, "blobSha256"); require(requireString(layer, "uncompressedDiffId").matches(Regex("sha256:[0-9a-f]{64}"))); requireNonNegative(layer, "blobBytes"); requireNonNegative(layer, "uncompressedBytes"); requireString(layer,"mediaType")
            layer["uncompressedDiffId"]!!.jsonPrimitive.content
        }
        val runtime = o["readOnlyRuntime"]!!.jsonObject
        val runtimeKeys = setOf("apiVersion", "serverVersion", "fixedReadOnlyRequests", "version", "versionCanonicalSha256", "info", "infoCanonicalSha256", "inspect", "inspectCanonicalSha256", "exportConfigSha256", "exportLayerDiffIds", "exportSha256", "exportBytes", "exportMergedNamespaceSha256")
        require(runtime.keys == if (version == 3) runtimeKeys + "observedListenerContinuity" else runtimeKeys)
        require(runtime["apiVersion"] == JsonPrimitive("1.55") && runtime["serverVersion"] == JsonPrimitive("29.7.2"))
        for (field in listOf("versionCanonicalSha256", "infoCanonicalSha256", "inspectCanonicalSha256", "exportConfigSha256", "exportSha256", "exportMergedNamespaceSha256")) requireSha(runtime, field)
        for ((recordKey, hashKey) in listOf("version" to "versionCanonicalSha256", "info" to "infoCanonicalSha256", "inspect" to "inspectCanonicalSha256")) {
            val record=runtime[recordKey] as? JsonObject ?: error("read-only Docker $recordKey response must be an object")
            val rendered=OracleJson.canonicalBytes(record, budget.jsonLimits(), budget::checkpoint)
            require(boundarySha256(rendered, budget) == runtime[hashKey]!!.jsonPrimitive.content) { "Docker $recordKey response hash mismatch" }
        }
        val versionFacts=runtime["version"]!!.jsonObject
        require(versionFacts["Version"] == JsonPrimitive("29.7.2") && versionFacts["ApiVersion"] == JsonPrimitive("1.55") && versionFacts["Os"] == JsonPrimitive("linux") && versionFacts["Arch"] == JsonPrimitive("amd64") && versionFacts["GitCommit"] == JsonPrimitive("6a43e3d"))
        val info=runtime["info"]!!.jsonObject
        require(info["ServerVersion"] == JsonPrimitive("29.7.2") && info["OSType"] == JsonPrimitive("linux") && info["Driver"] == JsonPrimitive("overlay2") && info["CgroupVersion"] == JsonPrimitive("2"))
        require((info["SecurityOptions"] as? JsonArray)?.contains(JsonPrimitive("name=rootless")) == true)
        val inspect=runtime["inspect"]!!.jsonObject
        require(inspect["Os"] == JsonPrimitive("linux") && inspect["Architecture"] == JsonPrimitive("amd64"))
        val rootFs=inspect["RootFS"] as? JsonObject ?: error("Docker inspect RootFS missing")
        require(rootFs["Type"] == JsonPrimitive("layers"))
        requireNonNegative(runtime,"exportBytes")
        val fixed = runtime["fixedReadOnlyRequests"]!!.jsonArray
        require(fixed.size == 5 && fixed.all { it is JsonPrimitive && it.isString })
        val diffs = runtime["exportLayerDiffIds"]!!.jsonArray
        require(diffs.isNotEmpty() && diffs.all { it is JsonPrimitive && it.isString && Regex("sha256:[0-9a-f]{64}").matches(it.content) })
        require(layerDiffIds == diffs.map { it.jsonPrimitive.content }) { "OCI raw layer order differs from Docker export layer identities" }
        require(rootFs["Layers"] == diffs) { "Docker inspect and retained export layer order differ" }
        val configSha = o["rawConfigSha256"]!!.jsonPrimitive.content
        require(fixed.map { it.jsonPrimitive.content } == listOf(
            "HEAD /_ping", "GET /version", "GET /info",
            "GET /v1.55/images/sha256:$configSha/json", "GET /v1.55/images/sha256:$configSha/get",
        )) { "read-only Docker request sequence differs from the pinned producer" }
        require(runtime["exportConfigSha256"] == o["rawConfigSha256"])
        require(runtime["exportMergedNamespaceSha256"] == o["mergedNamespaceSha256"])
        validateStaticGraph(o["subjectStaticElfClosure"]!!.jsonObject, budget)
        if (version == 3) validateContinuity(runtime["observedListenerContinuity"]!!.jsonObject)
    }

    private fun validateStaticGraph(g: JsonObject, budget: ExternalBoundaryBudgetV1) {
        val keys = setOf("scope", "subjectRequestedPath", "interpreter", "glibcSearchModelVersion", "loaderSearchImplementationQualified", "loaderBuiltInDirectoriesQualified", "processEnvironmentAndAuxvQualified", "dynamicDlopenAndSymbolResolutionQualified", "libraryClosureQualified", "staticGraphCompleteUnderStatedModel", "loaderCache", "nodes", "edges", "incompleteReasons")
        require(g.keys == keys)
        require(g["scope"] == JsonPrimitive("read-only-ELF64-x86-64-static-dependency-candidates")); requireAbsolutePath(g,"subjectRequestedPath"); require(g["glibcSearchModelVersion"] == JsonPrimitive("2.39-static-source-model"))
        for (k in listOf("loaderSearchImplementationQualified", "loaderBuiltInDirectoriesQualified", "processEnvironmentAndAuxvQualified", "dynamicDlopenAndSymbolResolutionQualified", "libraryClosureQualified")) require(g[k] == JsonPrimitive(false)) { "$k cannot claim qualification" }
        require(g["staticGraphCompleteUnderStatedModel"] is JsonPrimitive && g["staticGraphCompleteUnderStatedModel"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull != null)
        val interpreter=g["interpreter"]!!.jsonObject
        val present=interpreter["present"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull ?: error("interpreter presence flag invalid")
        if (present) {
            require(interpreter.keys == setOf("requestedPath", "present", "resolvedPath", "inode", "bytes", "sha256"))
            requireAbsolutePath(interpreter,"requestedPath"); requireAbsolutePath(interpreter,"resolvedPath"); requireNonNegative(interpreter,"inode"); require(requireNonNegative(interpreter,"bytes") > 0); requireSha(interpreter,"sha256")
        } else {
            require(interpreter.keys == setOf("present") || interpreter.keys == setOf("requestedPath", "present"))
            interpreter["requestedPath"]?.let { requireAbsolutePath(interpreter,"requestedPath") }
        }
        val nodes = g["nodes"]!!.jsonArray; val edges = g["edges"]!!.jsonArray
        require(nodes.size <= minOf(256, budget.limits.maximumReferencesAndEvents) && edges.size <= minOf(2048, budget.limits.maximumReferencesAndEvents))
        val cache=g["loaderCache"]!!.jsonObject
        val cachePresent=(cache["present"] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: error("loader-cache present flag missing")
        if (!cachePresent) require(cache.keys == setOf("present")) else {
            require(cache.keys == setOf("present", "path", "inode", "bytes", "sha256", "format", "legacyCompatibilityPrefix", "entries", "extensions"))
            requireAbsolutePath(cache,"path"); requireNonNegative(cache,"inode"); requireNonNegative(cache,"bytes"); requireSha(cache,"sha256")
            require(cache["format"] == JsonPrimitive("glibc-ld.so.cache-1.1")); require(cache["legacyCompatibilityPrefix"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull != null)
            requireNonNegative(cache,"entries"); val exts=cache["extensions"]!!.jsonArray; require(exts.size <= 64)
            budget.retain(0,exts.size.toLong(),"runtime cache extension population")
            exts.forEachIndexed { index, ext -> budget.checkpoint("loader cache hwcap validation $index"); val e=ext.jsonObject; require(e.keys == setOf("tag","flags","bytes","hwcapNames")); requireNonNegative(e,"tag"); requireNonNegative(e,"flags"); requireNonNegative(e,"bytes"); require(e["hwcapNames"]!!.jsonArray.all { it is JsonPrimitive && it.jsonPrimitive.isString }); budget.retain(0,e["hwcapNames"]!!.jsonArray.size.toLong(),"runtime cache hwcap population") }
        }
        nodes.forEachIndexed { index, n -> budget.checkpoint("static ELF node validation $index"); val x=n.jsonObject
            require(x.keys == setOf("resolvedPath", "inode", "bytes", "sha256", "elfType", "needed", "soname", "interpreter", "rpath", "runpath", "flags1", "unsupportedDynamicTags"))
            requireAbsolutePath(x,"resolvedPath"); requireNonNegative(x,"inode"); require(requireNonNegative(x,"bytes") > 0); requireSha(x,"sha256"); require(requireString(x,"elfType") in setOf("ET_DYN", "ET_EXEC")); requireNonNegative(x,"flags1")
            if (x["interpreter"] != JsonNull) requireAbsolutePath(x,"interpreter")
            for (field in listOf("soname", "interpreter", "rpath", "runpath")) require(x[field] == JsonNull || x[field] is JsonPrimitive && x[field]!!.jsonPrimitive.isString)
            for (field in listOf("needed", "unsupportedDynamicTags")) require(x[field] is JsonArray && x[field]!!.jsonArray.all { it is JsonPrimitive && it.jsonPrimitive.isString })
        }
        require(nodes.map { it.jsonObject["resolvedPath"] }.toSet().size == nodes.size) { "duplicate runtime node path" }
        val inodeRecords = mutableMapOf<JsonElement, Pair<JsonElement?, JsonElement?>>()
        nodes.forEach { n -> val x=n.jsonObject; val value=x["sha256"] to x["bytes"]
            val previous=inodeRecords.put(x["inode"]!!,value); require(previous == null || previous == value) { "conflicting runtime inode" }
        }
        var nestedObservations = nodes.sumOf { it.jsonObject["needed"]!!.jsonArray.size.toLong() + it.jsonObject["unsupportedDynamicTags"]!!.jsonArray.size }
        edges.forEachIndexed { index, e -> budget.checkpoint("static ELF edge validation $index"); val x=e.jsonObject
            require(x.keys == setOf("requester", "needed", "searches", "candidates", "selectionUniqueUnderStatedModel")); requireAbsolutePath(x,"requester"); requireString(x,"needed")
            val searches=x["searches"]!!.jsonArray; require(searches.size <= 512)
            nestedObservations = Math.addExact(nestedObservations, searches.size.toLong())
            searches.forEach { search -> val s=search.jsonObject; require(s.keys == setOf("path","provenance","present","conditional")); requireAbsolutePath(s,"path"); requireString(s,"provenance"); require(s["present"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull != null && s["conditional"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull != null) }
            val candidates=x["candidates"]!!.jsonArray
            nestedObservations = Math.addExact(nestedObservations, candidates.size.toLong())
            require(nestedObservations <= budget.limits.maximumReferencesAndEvents)
            candidates.forEach { c -> val candidate=c.jsonObject; require(candidate.keys == setOf("requestedPath","resolvedPath","inode","sha256")); requireAbsolutePath(candidate,"requestedPath"); requireAbsolutePath(candidate,"resolvedPath"); requireNonNegative(candidate,"inode"); requireSha(candidate,"sha256") }
            require(candidates.map { it.jsonObject["requestedPath"] to it.jsonObject["resolvedPath"] }.toSet().size == candidates.size) { "duplicate runtime candidate" }
            require(x["selectionUniqueUnderStatedModel"]!!.jsonPrimitive.takeUnless { it.isString }?.booleanOrNull != null)
            require(x["selectionUniqueUnderStatedModel"] != JsonPrimitive(true) || candidates.size == 1) { "unique runtime selection must have exactly one candidate" }
            require(nodes.any { it.jsonObject["resolvedPath"] == x["requester"] }) { "runtime requester lacks a static node" }
            candidates.forEach { c ->
                budget.checkpoint("runtime candidate-search join", searches.size.toLong())
                require(searches.any { search -> val row=search.jsonObject; row["path"] == c.jsonObject["requestedPath"] && row["present"] == JsonPrimitive(true) }) { "candidate lacks a successful recorded search" }
            }
        }
        require(g["incompleteReasons"] is JsonArray && g["incompleteReasons"]!!.jsonArray.all { it is JsonPrimitive && it.jsonPrimitive.isString })
        budget.retain(0, Math.addExact(nodes.size.toLong() + edges.size, nestedObservations), "runtime candidate graph projection")
    }

    private fun validateContinuity(c: JsonObject) {
        val fields = mapOf("schemaVersion" to JsonPrimitive(1), "identityKind" to JsonPrimitive("linux-af-unix-listener-credential-snapshot"), "identifierNamespace" to JsonPrimitive("observer"), "peerHandleMechanism" to JsonPrimitive("SO_PEERPIDFD"), "fixedExchangeCount" to JsonPrimitive(5), "sameListenerSnapshot" to JsonPrimitive(true), "retentionBoundary" to JsonPrimitive("final-factory-guard"), "daemonExecutableApproved" to JsonPrimitive(false), "httpResponderIdentityProved" to JsonPrimitive(false))
        require(c.keys == fields.keys + setOf("pid", "uid", "gid") && fields.all { c[it.key] == it.value })
        for (k in listOf("pid", "uid", "gid")) requireNonNegative(c,k)
    }

    private fun validateClosure(o: JsonObject, budget: ExternalBoundaryBudgetV1) {
        val keys = setOf("schemaVersion", "provider", "elfMachine", "elfClass", "elfOsAbi", "elfAbiFlags", "byteOrder", "resolver", "loaderCache", "resolverListingBytes", "resolverListingSha256", "interpreters", "libraries", "visibleSearchPath", "hostRuntimeRootsVisible", "closureSha256")
        require(o.keys == keys && o["schemaVersion"] == JsonPrimitive(1) && o["provider"] == JsonPrimitive("bounded-elf-needed-runtime-v1"))
        require(requireNonNegative(o,"elfMachine") in setOf(62L,183L))
        require(requireNonNegative(o,"elfOsAbi") <= 255)
        require(requireNonNegative(o,"elfAbiFlags") <= 0xffffffffL)
        require(o["elfClass"] == JsonPrimitive(32) || o["elfClass"] == JsonPrimitive(64)); require(o["byteOrder"] == JsonPrimitive("little") || o["byteOrder"] == JsonPrimitive("big"))
        requireString(o,"visibleSearchPath").split(':').forEach { val p=java.nio.file.Path.of(it); require(p.isAbsolute && p.normalize().toString() == it) }; require(o["hostRuntimeRootsVisible"] == JsonPrimitive(false))
        val resolvers = listOf("resolver" to setOf("bytes","sha256","path"), "loaderCache" to setOf("bytes","sha256","path"))
        resolvers.forEach { (field, shape) -> o[field]?.let { if (it != JsonNull) { val x=it.jsonObject; require(x.keys == shape); requireNonNegative(x,"bytes"); requireSha(x,"sha256"); requireAbsolutePath(x,"path") } } }
        if (o["resolverListingBytes"] == JsonNull) require(o["resolverListingSha256"] == JsonNull) else { requireNonNegative(o,"resolverListingBytes"); requireSha(o,"resolverListingSha256") }
        val resolverPresent=o["resolver"] != JsonNull; val cachePresent=o["loaderCache"] != JsonNull
        require(resolverPresent == cachePresent && resolverPresent == (o["resolverListingBytes"] != JsonNull)) { "resolver/cache/listing evidence must be complete as one recorded group" }
        val interpreters=o["interpreters"]!!.jsonArray; val libraries=o["libraries"]!!.jsonArray
        require(interpreters.size <= 256 && libraries.size <= 4096)
        require(interpreters.size.toLong() + libraries.size <= budget.limits.maximumReferencesAndEvents)
        interpreters.forEachIndexed { index, item -> budget.checkpoint("closure interpreter mount validation $index"); val x=item.jsonObject; require(x.keys == setOf("guestPath","sourcePath","snapshotPath","bytes","sha256")); requireAbsolutePath(x,"guestPath"); requireAbsolutePath(x,"sourcePath"); requireAbsolutePath(x,"snapshotPath"); require(requireNonNegative(x,"bytes") > 0); requireSha(x,"sha256") }
        libraries.forEachIndexed { index, item -> budget.checkpoint("closure library mount validation $index"); val x=item.jsonObject; require(x.keys == setOf("name","sourcePath","snapshotPath","bytes","sha256")); requireString(x,"name"); requireAbsolutePath(x,"sourcePath"); requireAbsolutePath(x,"snapshotPath"); require(requireNonNegative(x,"bytes") > 0); requireSha(x,"sha256") }
        val mountDestinations = mutableSetOf<String>()
        val snapshots = mutableSetOf<String>()
        val sources = mutableMapOf<String, Pair<JsonElement?,JsonElement?>>()
        for (mount in interpreters + libraries) {
            budget.checkpoint("closure mount collision join")
            val row = mount.jsonObject
            val destination = if ("guestPath" in row) requireString(row,"guestPath") else "/runtime/lib/" + requireString(row,"name").also { require('/' !in it && it != "." && it != "..") }
            require(mountDestinations.add(destination) && snapshots.add(requireString(row,"snapshotPath"))) { "duplicate or conflicting closure mount" }
            val value = row["bytes"] to row["sha256"]
            val previous = sources.put(requireString(row,"sourcePath"),value)
            require(previous == null || previous == value) { "conflicting closure source bytes" }
        }
        val payload = JsonObject(o - "closureSha256")
        val closureBytes = OracleJson.canonicalBytes(payload, budget.jsonLimits(), budget::checkpoint)
        budget.checkpoint("before closure self-digest", closureBytes.size.toLong())
        val digest = boundarySha256(closureBytes, budget)
        budget.checkpoint("after closure self-digest")
        require(o["closureSha256"] == JsonPrimitive(digest)) { "closure receipt digest mismatch" }
    }

    private fun requireString(o: JsonObject, key: String): String = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content?.also { require(it.isNotBlank() && it.length <= 16*1024 && it.none(Char::isISOControl)) } ?: error("$key must be string")
    private fun requireNonNegative(o: JsonObject, key: String): Long = (o[key] as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull?.also { require(it >= 0) } ?: error("$key must be nonnegative integer")
    private fun requireSha(o: JsonObject, key: String) { require(Regex("[0-9a-f]{64}").matches(requireString(o,key))) }
    private fun requireAbsolutePath(o: JsonObject, key: String) { val s=requireString(o,key); val p=java.nio.file.Path.of(s); require(p.isAbsolute && p.normalize().toString()==s) }
}

/** Two-pass visitor: the first pass counts the exact canonical shape without retaining a JSON tree. */
internal class BoundaryTreeV1(private val budget: ExternalBoundaryBudgetV1?, private val build: Boolean) {
    private val limits = budget?.limits ?: ExternalProviderLimitsV1()
    var nodes = 0L; private set
    var strings = 0L; private set
    var bytes = 1L; private set
    var maximumDepth = 0; private set
    var largestString = 0L; private set
    private var depth = 0
    private val frames = ArrayList<Any>()
    var result: JsonElement = JsonNull; private set
    private fun charge(n: Long) {
        require(n >= 0 && bytes <= limits.maximumDocumentBytes.toLong() - n) { "typed output preflight ceiling exceeded" }; bytes += n
    }
    private fun work(phase: String, units: Long = 1) {
        if (budget != null) budget.checkpoint(phase, units)
        else if (Thread.currentThread().isInterrupted) throw InterruptedException("cancelled $phase")
    }
    private fun stringCost(s: String): Long {
        var utf8 = 0L; var encoded = 2L; var i = 0
        while (i < s.length) {
            if (i % 256 == 0) work("typed nested string preflight", minOf(256,s.length-i).toLong())
            val c=s[i]; val n = when {
                c.isHighSurrogate() -> { require(i+1 < s.length && s[i+1].isLowSurrogate()); i++; 4 }
                c.isLowSurrogate() -> error("unpaired UTF-16 surrogate")
                c.code < 128 -> 1
                c.code < 2048 -> 2
                else -> 3
            }
            utf8 += n
            encoded += when(c) { '"','\\','\b','\u000c','\n','\r','\t' -> 2; else -> if(c.code < 32) 6 else n }
            require(utf8 <= limits.maximumStringBytes)
            i++
        }
        require(strings <= limits.maximumTotalStringBytes.toLong()-utf8)
        strings += utf8; largestString=maxOf(largestString,utf8)
        return encoded
    }
    private fun entry(key: String?) {
        work(if(build) "typed JSON projection" else "typed JSON preflight")
        require(++nodes <= limits.maximumNodes)
        if(key != null) charge(stringCost(key)+2)
    }
    @Suppress("UNCHECKED_CAST")
    private fun attach(key: String?, value: JsonElement) {
        if(!build) return
        if(frames.isEmpty()) result=value
        else when(val frame=frames.last()) {
            is MutableMap<*,*> -> (frame as MutableMap<String,JsonElement>)[requireNotNull(key)]=value
            else -> (frame as MutableList<JsonElement>).add(value)
        }
    }
    private fun container(key: String?, count: Int, objectKind: Boolean, block: BoundaryTreeV1.()->Unit) {
        entry(key); require(count >= 0 && count.toLong() <= limits.maximumNodes-nodes)
        depth++; maximumDepth=maxOf(maximumDepth,depth); require(depth <= limits.maximumDepth)
        // OracleJson pretty canonical framing: two spaces per indentation level.
        charge(if(count==0) 2 else 2L + count.toLong()*(1+depth*2L) + count-1 + 1+(depth-1)*2L)
        if(build) frames.add(if(objectKind) linkedMapOf<String,JsonElement>() else arrayListOf<JsonElement>())
        block()
        if(build) {
            val frame=frames.removeAt(frames.lastIndex)
            @Suppress("UNCHECKED_CAST")
            val value=if(objectKind) JsonObject(Collections.unmodifiableMap(frame as Map<String,JsonElement>)) else JsonArray(Collections.unmodifiableList(frame as List<JsonElement>))
            attach(key,value)
        }
        depth--
    }
    fun obj(key: String? = null, count: Int, block: BoundaryTreeV1.()->Unit) = container(key,count,true,block)
    fun <T> array(key: String?, values: Collection<T>, block: BoundaryTreeV1.(T)->Unit) = container(key,values.size,false) { values.forEach { block(it) } }
    fun str(key: String?, value: String?) { entry(key); charge(if(value==null) 4 else stringCost(value)); if(build) attach(key,value?.let(::JsonPrimitive) ?: JsonNull) }
    fun num(key: String?, value: Number?) { entry(key); val text=value?.toString(); charge(text?.length?.toLong() ?: 4); if(build) attach(key,value?.let(::JsonPrimitive) ?: JsonNull) }
    fun bool(key: String?, value: Boolean) { entry(key); charge(if(value) 4 else 5); if(build) attach(key,JsonPrimitive(value)) }
    fun hex(key: String?, value: ULong) = str(key,"0x"+value.toString(16))
    fun json(key: String?, value: JsonElement) {
        when(value) {
            is JsonObject -> obj(key,value.size) { value.forEach { (k,v) -> json(k,v) } }
            is JsonArray -> array(key,value) { json(null,it) }
            JsonNull -> str(key,null)
            is JsonPrimitive -> if(value.isString) str(key,value.content) else {
                entry(key); charge(value.content.length.toLong()); if(build) attach(key,value)
            }
        }
    }
}

/** Direct constructors also own their inputs; factories supply the original invocation budget. */
internal class BoundaryOwnedSnapshotV1(bytes: ByteArray, values: List<JsonElement>, budget: ExternalBoundaryBudgetV1? = null) {
    val bytes: ByteArray
    val json: List<JsonElement>
    init {
        val cap=budget?.limits ?: ExternalProviderLimitsV1()
        require(bytes.size <= cap.maximumDocumentBytes)
        val preflight=BoundaryTreeV1(budget,false)
        preflight.array(null,values) { json(null,it) }
        budget?.checkpoint("constructor bytes ownership",bytes.size.toLong())
        this.bytes=bytes.copyOf()
        val copy=BoundaryTreeV1(budget,true)
        copy.array(null,values) { json(null,it) }
        json=Collections.unmodifiableList(copy.result.jsonArray.toList())
        budget?.checkpoint("terminal constructor ownership")
    }
}

private fun boundedInventoryJson(i: ElfDynamicBindingInventoryV1, budget: ExternalBoundaryBudgetV1): JsonObject {
    // Checked aggregate populations, including nested version and relocation arrays, before any projection.
    var population=0L
    fun population(n: Int) { require(n >= 0); population=Math.addExact(population,n.toLong()); require(population <= budget.limits.maximumReferencesAndEvents) }
    listOf(i.sections.size,i.programHeaders.size,i.dynamicEntries.size,i.versionRequirements.size,i.versionDefinitions.size,i.neededLibraries.size,i.unsupportedReasons.size).forEach(::population)
    i.versionDefinitions.forEach { budget.checkpoint("version population preflight"); population(it.parentNames.size); population(it.auxiliaryOffsets.size); population(it.auxiliaryNameOffsets.size) }
    i.relocations.forEach { budget.checkpoint("relocation population preflight"); population(it.dynamicTables.size); population(it.slotLoadIndices.size); population(it.dispositions.size) }
    budget.retain(0,population,"typed ELF nested populations")
    val count=BoundaryTreeV1(budget,false); visitInventory(i,count)
    budget.checkpoint("typed ELF admitted before materialization",count.bytes)
    val build=BoundaryTreeV1(budget,true); visitInventory(i,build)
    budget.checkpoint("typed ELF materialization complete")
    return build.result.jsonObject
}

private fun visitInventory(i: ElfDynamicBindingInventoryV1, w: BoundaryTreeV1, key: String? = null) = with(w) {
    obj(key,count=23) {
        num("schemaVersion",1); str("kind","independent-elf-dynamic-bindings-v1"); str("authority","diagnostic-authenticated-elf-metadata"); str("inputSha256",i.inputSha256)
        num("elfClass",i.structure.core.elfClass); num("byteOrder",i.structure.core.byteOrder); str("elfType",i.structure.core.elfType); num("machine",i.structure.core.machine)
        hex("imageBase",i.imageBase); num("activeSymbolTableSectionIndex",i.activeSymbolTableSectionIndex); str("symbolPopulationBasis","section-declared-dynsym")
        bool("complete",false); bool("releaseEligible",false); bool("negativeCompleteness",false)
        array("sections",i.sections) { x -> obj(count=11) {
            num("index",x.index); str("name",x.name); num("type",x.type); hex("flags",x.flags); hex("address",x.address); num("offset",x.offset); hex("size",x.size)
            num("link",x.link); num("info",x.info); hex("alignment",x.alignment); hex("entrySize",x.entrySize)
        } }
        array("programHeaders",i.programHeaders) { x -> obj(count=9) {
            num("index",x.index); num("type",x.type); num("flags",x.flags); hex("offset",x.offset); hex("virtualAddress",x.virtualAddress); hex("physicalAddress",x.physicalAddress)
            hex("fileSize",x.fileSize); hex("memorySize",x.memorySize); hex("alignment",x.alignment)
        } }
        array("dynamicEntries",i.dynamicEntries) { x -> obj(count=4) { num("index",x.index); num("fileOffset",x.fileOffset); hex("tag",x.tag); hex("value",x.value) } }
        array("dynamicSymbols",i.dynamicSymbols) { x -> val r=x.raw; obj(count=16) {
            num("tableSectionIndex",r.tableSectionIndex); num("symbolIndex",r.symbolIndex); str("locator",r.locator); num("nameOffset",r.nameOffset); str("name",r.name)
            num("info",r.info); num("other",r.other); num("type",x.type); num("binding",x.binding); num("visibility",x.visibility)
            num("rawSectionIndex",r.rawSectionIndex); num("resolvedSectionIndex",r.resolvedSectionIndex); str("sectionKind",r.sectionKind.name.lowercase()); hex("value",r.value); hex("size",r.size)
            val v=x.version
            if(v==null) str("version",null) else obj("version",8) {
                num("sectionIndex",v.sectionIndex); num("fileOffset",v.fileOffset); num("raw",v.raw); num("index",v.index); bool("hidden",v.hidden); str("kind",v.kind); str("name",v.name); str("providerRequest",v.providerRequest)
            }
        } }
        array("relocations",i.relocations) { x -> obj(count=13) {
            num("sectionIndex",x.sectionIndex); num("relocationIndex",x.relocationIndex); num("fileOffset",x.fileOffset); str("locator",x.locator)
            num("symbolTableSectionIndex",x.symbolTableSectionIndex); num("symbolIndex",x.symbolIndex); hex("offset",x.offset); num("type",x.type); num("addend",x.addend)
            array("dynamicTables",x.dynamicTables) { str(null,it) }; num("slotFileOffset",x.slotFileOffset); array("slotLoadIndices",x.slotLoadIndices) { num(null,it) }; array("dispositions",x.dispositions) { str(null,it) }
        } }
        array("versionRequirements",i.versionRequirements) { x -> obj(count=12) {
            num("sectionIndex",x.sectionIndex); num("stringSectionIndex",x.stringSectionIndex); num("recordOffset",x.recordOffset); num("auxiliaryOffset",x.auxiliaryOffset)
            str("providerRequest",x.providerRequest); num("providerRequestOffset",x.providerRequestOffset); str("name",x.name); num("nameOffset",x.nameOffset)
            num("rawIndex",x.rawIndex); num("index",x.index); num("flags",x.flags); num("hash",x.hash)
        } }
        array("versionDefinitions",i.versionDefinitions) { x -> obj(count=11) {
            num("sectionIndex",x.sectionIndex); num("stringSectionIndex",x.stringSectionIndex); num("recordOffset",x.recordOffset); num("rawIndex",x.rawIndex); num("index",x.index); num("flags",x.flags); num("hash",x.hash); str("name",x.name)
            array("parentNames",x.parentNames) { str(null,it) }; array("auxiliaryOffsets",x.auxiliaryOffsets) { num(null,it) }; array("auxiliaryNameOffsets",x.auxiliaryNameOffsets) { num(null,it) }
        } }
        array("neededLibraries",i.neededLibraries) { str(null,it) }; array("unsupportedReasons",i.unsupportedReasons) { str(null,it) }
    }
}

private fun preflightElfProjection(stage: ExternalLinkStageIdentityV1, i: ElfDynamicBindingInventoryV1, budget: ExternalBoundaryBudgetV1) {
    // Reject even a one-node/one-byte cap at the root before constructing the physical index.
    val inventoryMeasure=BoundaryTreeV1(budget,false); visitInventory(i,inventoryMeasure)
    val index=HashMap<Pair<Int,Long>,decompengine.oracle.externalcalls.ElfDynamicSymbolV1>()
    i.dynamicSymbols.forEach { symbol ->
        budget.checkpoint("typed ELF symbol lookup index")
        require(index.put(symbol.tableSectionIndex to symbol.symbolIndex,symbol)==null)
    }
    val w=BoundaryTreeV1(budget,false)
    with(w) { obj(count=12) {
        str("schemaKind","independent-elf-dynamic-bindings-v1"); str("sourceSha256",stage.outputSha256); str("inventorySha256",stage.outputSha256)
        obj("stage",9) {
            str("buildRunId",stage.buildRunId); str("graphActionId",stage.graphActionId); num("ordinal",stage.ordinal)
            str("sourceRevisionSha256",stage.sourceRevisionSha256); str("planSha256",stage.planSha256); str("policySha256",stage.policySha256)
            str("outputRole",stage.outputRole); num("outputBytes",stage.outputBytes); str("outputSha256",stage.outputSha256)
        }
        num("symbolCount",i.dynamicSymbols.size); num("relocationCount",i.relocations.size)
        array("symbols",i.dynamicSymbols) { x -> obj(count=11) {
            str("artifactRole",stage.outputRole); str("artifactSha256",stage.outputSha256); num("tableSectionIndex",x.tableSectionIndex); num("symbolIndex",x.symbolIndex)
            str("rawLocator",x.raw.locator); str("name",x.name); num("type",x.type); num("binding",x.binding); num("visibility",x.visibility)
            str("sectionKind",x.raw.sectionKind.name.lowercase())
            val v=x.version
            if(v==null) str("version",null) else obj("version",8) {
                num("sectionIndex",v.sectionIndex); num("fileOffset",v.fileOffset); num("raw",v.raw); num("index",v.index); bool("hidden",v.hidden); str("kind",v.kind); str("name",v.name); str("providerRequest",v.providerRequest)
            }
        } }
        array("references",i.relocations) { x ->
            budget.checkpoint("typed ELF relocation indexed join")
            val symbol=index[x.symbolTableSectionIndex to x.symbolIndex] ?: error("ELF relocation has no physical symbol")
            obj(count=14) {
                str("artifactRole",stage.outputRole); str("artifactSha256",stage.outputSha256); str("member",null)
                num("tableSectionIndex",symbol.tableSectionIndex); num("symbolIndex",symbol.symbolIndex); str("rawLocator",symbol.raw.locator)
                num("relocationSectionIndex",x.sectionIndex); num("relocationIndex",x.relocationIndex); hex("offset",x.offset); num("type",x.type); num("addend",x.addend)
                str("ownerModuleId",null); str("ownerEntityId",null); str("abiSourceId",null)
            }
        }
        array("neededLibraries",i.neededLibraries) { str(null,it) }; array("unsupportedReasons",i.unsupportedReasons) { str(null,it) }
        visitInventory(i,this,"inventory")
        array("limitations",listOf("section-declared DYNSYM is not a complete full-tree symbol universe", "ELF inventory does not authenticate a link stage or runtime provider")) { str(null,it) }
    } }
    budget.checkpoint("full ELF projection admitted before materialization",w.bytes)
}

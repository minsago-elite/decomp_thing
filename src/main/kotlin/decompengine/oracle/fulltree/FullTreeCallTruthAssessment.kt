package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

class FullTreeCallTruthAssessmentException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable ceilings for the in-memory, non-authoritative semantic checkpoint. */
data class FullTreeCallTruthAssessmentLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val maximumIndexBytes: Int = CALL_ASSESSMENT_MAXIMUM_INDEX_BYTES,
    val maximumShardBytes: Int = CALL_ASSESSMENT_MAXIMUM_SHARD_BYTES,
    val maximumShards: Int = CALL_ASSESSMENT_MAXIMUM_SHARDS,
    val maximumFunctions: Long = CALL_ASSESSMENT_MAXIMUM_FUNCTIONS,
    val maximumObservations: Long = CALL_ASSESSMENT_MAXIMUM_OBSERVATIONS,
    val maximumAliases: Long = CALL_ASSESSMENT_MAXIMUM_ALIASES,
    val maximumDiagnosticBytes: Int = CALL_ASSESSMENT_MAXIMUM_DIAGNOSTIC_BYTES,
) {
    init {
        require(maximumIndexBytes in 1..CALL_ASSESSMENT_MAXIMUM_INDEX_BYTES)
        require(maximumShardBytes in 1..CALL_ASSESSMENT_MAXIMUM_SHARD_BYTES)
        require(maximumShards in 1..CALL_ASSESSMENT_MAXIMUM_SHARDS)
        require(maximumFunctions in 1L..CALL_ASSESSMENT_MAXIMUM_FUNCTIONS)
        require(maximumObservations in 1L..CALL_ASSESSMENT_MAXIMUM_OBSERVATIONS)
        require(maximumAliases in 1L..CALL_ASSESSMENT_MAXIMUM_ALIASES)
        require(maximumDiagnosticBytes in 1..CALL_ASSESSMENT_MAXIMUM_DIAGNOSTIC_BYTES)
    }
}

/**
 * Immutable fixture-scale diagnostic derived from raw artifacts. It is not full-tree validation,
 * call truth, oracle evidence, a complete population assertion, a score, or a release decision.
 */
sealed interface FullTreeCallTruthAssessment {
    val authority: String
    val complete: Boolean
    val releaseEligible: Boolean
    val missingAuthorities: List<String>
    val scopeSha256: String
    val inventorySha256: String
    val functionTruthIndexSha256: String
    val elfFunctionIndexSha256: String
    val callObservationIndexSha256: String
    val historicalCallTruthConfigurationSha256: String
    val shards: List<FullTreeCallTruthShardAssessment>
    val assessmentSha256: String
}

sealed interface FullTreeCallTruthShardAssessment {
    val id: String
    val calls: List<FullTreeCallTruthEdgeAssessment>
    val canonicalBytes: ByteArray
}

sealed interface FullTreeCallTruthEdgeAssessment {
    val id: String
    val observationIds: List<String>
    val callerId: String?
    val callerLocalReturnOffset: String?
    val returnPcRva: String?
    val targetKind: String
    val dispatchKind: String
    val physicalTargetId: String?
    val semanticTargetId: String?
    val externalTargetIds: List<String>
    val provenTargetIds: List<String>
    val population: String
    val reasonCode: String?
    val tailCall: Boolean
    val targetEvidence: String
}

/**
 * Raw-path-only, bounded fixture-scale semantic parity checkpoint for the historical full-tree
 * call composer. Its in-memory 64 MiB diagnostic ceiling is deliberately far below the known
 * historical 899 MiB call-truth tree; a scalable SQLite/sharded Kotlin producer remains missing.
 *
 * No parsed document, namespace, analyzer, edge, verdict, output path, ACP material, or claimed
 * digest is accepted. The result is permanently non-authoritative because this historical input
 * tree predates the Kotlin-owned raw producers and lacks a Kotlin-owned whole-process-tree
 * containment/runtime receipt.
 */
object FullTreeCallTruthAssessmentVerifier {
    /** Configuration identity of the historical per-shard call-truth v1 format, not this wrapper. */
    val historicalCallTruthConfigurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-call-truth", CALL_TRUTH_POLICY)
    }

    fun assess(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        inventoryPath: Path,
        functionTruthRoot: Path,
        elfFunctionIndexPath: Path,
        callObservationRoot: Path,
        limits: FullTreeCallTruthAssessmentLimits = FullTreeCallTruthAssessmentLimits(),
    ): FullTreeCallTruthAssessment = try {
        DerivedAssessment.create(
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            inventoryPath,
            functionTruthRoot,
            elfFunctionIndexPath,
            callObservationRoot,
            limits,
        )
    } catch (failure: FullTreeCallTruthAssessmentException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeCallTruthAssessmentException(
            "non-authoritative full-tree call assessment failed: ${failure.message}",
            failure,
        )
    }

    private class DerivedAssessment private constructor(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        inventoryPath: Path,
        functionTruthRoot: Path,
        elfFunctionIndexPath: Path,
        callObservationRoot: Path,
        limits: FullTreeCallTruthAssessmentLimits,
    ) : FullTreeCallTruthAssessment {
        override val authority: String = NON_AUTHORITY
        override val complete: Boolean = false
        override val releaseEligible: Boolean = false
        override val missingAuthorities: List<String> = MISSING_AUTHORITIES
        override val scopeSha256: String
        override val inventorySha256: String
        override val functionTruthIndexSha256: String
        override val elfFunctionIndexSha256: String
        override val callObservationIndexSha256: String
        override val historicalCallTruthConfigurationSha256: String =
            FullTreeCallTruthAssessmentVerifier.historicalCallTruthConfigurationSha256
        override val shards: List<FullTreeCallTruthShardAssessment>
        override val assessmentSha256: String

        init {
            val derived = derive(
                RawInputs(
                    scopePath,
                    sourceLockPath,
                    artifactManifestPath,
                    inventoryPath,
                    functionTruthRoot,
                    elfFunctionIndexPath,
                    callObservationRoot,
                ),
                limits,
            )
            scopeSha256 = derived.scopeSha256
            inventorySha256 = derived.inventorySha256
            functionTruthIndexSha256 = derived.functionTruthIndexSha256
            elfFunctionIndexSha256 = derived.elfFunctionIndexSha256
            callObservationIndexSha256 = derived.callObservationIndexSha256
            shards = Collections.unmodifiableList(derived.shards.map(::ImmutableShard))
            assessmentSha256 = derived.assessmentSha256
        }

        companion object {
            fun create(
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                inventoryPath: Path,
                functionTruthRoot: Path,
                elfFunctionIndexPath: Path,
                callObservationRoot: Path,
                limits: FullTreeCallTruthAssessmentLimits,
            ): FullTreeCallTruthAssessment = DerivedAssessment(
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                inventoryPath,
                functionTruthRoot,
                elfFunctionIndexPath,
                callObservationRoot,
                limits,
            )
        }
    }

    private class ImmutableShard(source: DiagnosticShard) : FullTreeCallTruthShardAssessment {
        private val storedBytes = source.canonicalBytes.copyOf()
        override val id: String = source.id
        override val calls: List<FullTreeCallTruthEdgeAssessment> =
            Collections.unmodifiableList(source.calls.map(::ImmutableEdge))
        override val canonicalBytes: ByteArray
            get() = storedBytes.copyOf()
    }

    private class ImmutableEdge(source: Edge) : FullTreeCallTruthEdgeAssessment {
        override val id: String = source.id
        override val observationIds: List<String> = Collections.unmodifiableList(source.observationIds.toList())
        override val callerId: String? = source.callerId
        override val callerLocalReturnOffset: String? = source.callerLocalReturnOffset
        override val returnPcRva: String? = source.returnPcRva
        override val targetKind: String = source.targetKind
        override val dispatchKind: String = source.dispatchKind
        override val physicalTargetId: String? = source.physicalTargetId
        override val semanticTargetId: String? = source.semanticTargetId
        override val externalTargetIds: List<String> = Collections.unmodifiableList(source.externalTargetIds.toList())
        override val provenTargetIds: List<String> = Collections.unmodifiableList(source.provenTargetIds.toList())
        override val population: String = source.population
        override val reasonCode: String? = source.reasonCode
        override val tailCall: Boolean = source.tailCall
        override val targetEvidence: String = source.targetEvidence
    }
}

private fun derive(
    paths: RawInputs,
    limits: FullTreeCallTruthAssessmentLimits,
): DerivedState {
    requireDistinctInputs(paths)
    val scope = FullTreeScopeControl.load(
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        limits.control,
    )
    val (inventory, inventoryBytes) = readCanonicalControlObject(
        paths.inventory,
        limits.control.maximumInventoryBytes,
        "full-tree inventory",
        "full-tree-inventory",
    )
    FullTreeInventoryControl.validate(inventory, scope, limits.control)
    val inventorySha256 = OracleArtifacts.sha256(inventoryBytes)
    val inventoryShards = inventory.callArray("shards", "full-tree inventory")
        .mapIndexed { index, value -> value.callObject("inventory shard $index") }
    if (inventoryShards.size !in 1..limits.maximumShards) fail("inventory shard count exceeds the assessment bound")
    val shardIds = inventoryShards.map { it.callString("id", "inventory shard") }
    if (shardIds != shardIds.sortedWith(FULL_TREE_CODE_POINT_ORDER) || shardIds.toSet().size != shardIds.size) {
        fail("inventory shard identities are not unique and canonically ordered")
    }
    val shardsById = inventoryShards.associateBy { it.callString("id", "inventory shard") }
    val units = inventory.callArray("units", "full-tree inventory")
        .mapIndexed { index, value -> value.callObject("inventory unit $index") }
    val unitsById = units.associateBy { it.callString("id", "inventory unit") }
    if (unitsById.size != units.size) fail("inventory unit identities are not unique")

    val (elf, elfBytes) = readCanonicalControlObject(
        paths.elfFunctionIndex,
        limits.maximumIndexBytes,
        "full-tree ELF function index",
        "full-tree-elf-functions",
    )
    val elfSha256 = OracleArtifacts.sha256(elfBytes)
    val externalNames = validateElfIndex(elf, scope, inventory, limits)

    val functionState = loadFunctionTruth(
        paths.functionTruthRoot,
        scope,
        inventory,
        shardsById,
        elf,
        elfSha256,
        limits,
    )
    val observationState = loadCallObservations(
        paths.callObservationRoot,
        scope,
        inventory,
        inventoryBytes,
        shardsById,
        unitsById,
        limits,
    )
    val composedShards = composeEdges(
        shardIds,
        functionState.functions,
        functionState.aliases,
        externalNames,
        observationState.observations,
        limits,
    )
    val diagnosticShards = validateAndEncodeComposedShards(
        composedShards,
        scope.sha256,
        inventorySha256,
        functionState.indexSha256,
        elfSha256,
        observationState.indexSha256,
    )
    val totalDiagnosticBytes = diagnosticShards.fold(0L) { total, shard ->
        addBounded(total, shard.canonicalBytes.size.toLong(), limits.maximumDiagnosticBytes.toLong(), "call diagnostic byte")
    }
    check(totalDiagnosticBytes >= 0L)
    return DerivedState(
        scope.sha256,
        inventorySha256,
        functionState.indexSha256,
        elfSha256,
        observationState.indexSha256,
        diagnosticShards,
        assessmentDigest(
            scope.sha256,
            inventorySha256,
            functionState.indexSha256,
            elfSha256,
            observationState.indexSha256,
            diagnosticShards,
        ),
    )
}

private fun validateElfIndex(
    document: JsonObject,
    scope: AuthenticatedFullTreeScope,
    inventory: JsonObject,
    limits: FullTreeCallTruthAssessmentLimits,
): Set<String> {
    val oracle = document.callObject("oracle", "ELF function index")
    oracle.callRequireKeys(ELF_ORACLE_FIELDS, "ELF function oracle")
    if (
        oracle.callString("configurationSha256", "ELF function oracle") !=
        FullTreeElfFunctionsSqlite.configurationSha256 ||
        oracle.callString("inventoryIndexSha256", "ELF function oracle") !=
        inventory.callString("indexSha256", "inventory") ||
        oracle.callString("scopeSha256", "ELF function oracle") != scope.sha256
    ) {
        fail("ELF function index bindings do not match the authenticated controls")
    }
    val scopeOracle = scope.document.controlObject("oracle")
    val artifacts = document.callObject("artifacts", "ELF function index")
    if (
        artifacts.callObject("rich", "ELF artifacts").callString("inputSha256", "rich ELF") !=
        scopeOracle.controlString("richArtifactSha256") ||
        artifacts.callObject("stripped", "ELF artifacts").callString("inputSha256", "stripped ELF") !=
        scopeOracle.controlString("strippedArtifactSha256")
    ) {
        fail("ELF function index artifact bindings do not match the authenticated scope")
    }
    val functions = document.callArray("functions", "ELF function index")
        .mapIndexed { index, value -> value.callObject("ELF function $index") }
    if (functions.size.toLong() > limits.maximumFunctions) fail("ELF function count exceeds the assessment bound")
    val rvas = ArrayList<ULong>(functions.size)
    var aliasCount = 0L
    val ids = HashSet<String>()
    functions.forEach { function ->
        val rvaText = function.callString("rva", "ELF function")
        val rva = parseAddress(rvaText, "ELF function RVA")
        rvas += rva
        val id = function.callString("id", "ELF function")
        if (id != "function-rva-$rvaText" || !ids.add(id)) fail("ELF function identity is duplicate or differs from its RVA")
        val aliases = function.callArray("aliases", "ELF function").map { value ->
            value.callObject("ELF function alias").callString("name", "ELF function alias")
        }
        if (aliases != aliases.sortedWith(FULL_TREE_CODE_POINT_ORDER) || aliases.toSet().size != aliases.size) {
            fail("ELF function aliases are not unique and canonically ordered")
        }
        aliasCount = addBounded(aliasCount, aliases.size.toLong(), limits.maximumAliases, "ELF alias")
    }
    if (rvas != rvas.sorted() || rvas.toSet().size != rvas.size) fail("ELF functions are not uniquely RVA ordered")
    val external = document.callArray("externalFunctions", "ELF function index")
        .mapIndexed { index, value -> value.callObject("ELF external function $index") }
        .map { it.callString("name", "ELF external function") }
    if (external != external.sortedWith(FULL_TREE_CODE_POINT_ORDER) || external.toSet().size != external.size) {
        fail("ELF external functions are not unique and canonically ordered")
    }
    addBounded(
        aliasCount,
        external.size.toLong(),
        limits.maximumAliases,
        "retained ELF function or external name",
    )
    val counts = document.callObject("counts", "ELF function index")
    if (
        counts.callLong("aliases", "ELF counts") != aliasCount ||
        counts.callLong("externalFunctions", "ELF counts") != external.size.toLong() ||
        counts.callLong("functionRvas", "ELF counts") != functions.size.toLong() ||
        counts.callLong("strippedFunctionRvas", "ELF counts") !in 0L..functions.size.toLong()
    ) {
        fail("ELF function counts do not reconcile")
    }
    return external.toSet()
}

private fun loadFunctionTruth(
    root: Path,
    scope: AuthenticatedFullTreeScope,
    inventory: JsonObject,
    inventoryShards: Map<String, JsonObject>,
    elf: JsonObject,
    elfSha256: String,
    limits: FullTreeCallTruthAssessmentLimits,
): FunctionState {
    val indexPath = root.toAbsolutePath().normalize().resolve("index.json")
    val (index, indexBytes) = readCanonicalControlObject(
        indexPath,
        limits.maximumIndexBytes,
        "full-tree function truth index",
        "full-tree-function-truth-index",
    )
    val indexSha256 = OracleArtifacts.sha256(indexBytes)
    validateSelfHash(index, "indexSha256", "function truth index")
    val oracle = index.callObject("oracle", "function truth index")
    oracle.callRequireKeys(FUNCTION_ORACLE_FIELDS, "function truth oracle")
    val expectedFunctionConfiguration = historicalFunctionTruthConfigurationSha256()
    if (
        oracle.callString("configurationSha256", "function truth oracle") != expectedFunctionConfiguration ||
        oracle.callString("elfIndexSha256", "function truth oracle") != elfSha256 ||
        oracle.callString("inventoryIndexSha256", "function truth oracle") !=
        inventory.callString("indexSha256", "inventory") ||
        oracle.callString("scopeSha256", "function truth oracle") != scope.sha256
    ) {
        fail("function truth index bindings do not match the authenticated inputs")
    }
    requireDigest(oracle.callString("observationIndexSha256", "function truth oracle"), "function observation index")
    val records = index.callArray("shards", "function truth index")
        .mapIndexed { position, value -> value.callObject("function truth index shard $position") }
    val expectedIds = inventoryShards.keys.sortedWith(FULL_TREE_CODE_POINT_ORDER)
    if (records.map { it.callString("id", "function truth index shard") } != expectedIds) {
        fail("function truth index does not cover every inventory shard in canonical order")
    }
    val namespace = LinkedHashMap<String, FunctionRecord>()
    val aliases = HashMap<String, MutableSet<String>>()
    val seenRvas = HashSet<String>()
    val seenNonEmitted = HashSet<String>()
    val emittedAliasNames = HashSet<String>()
    val nonEmittedRecords = ArrayList<JsonObject>()
    var functionCount = 0L
    var retainedFunctionEntities = 0L
    var retainedFunctionAliases = 0L
    var scored = 0L
    var dwarfOnly = 0L
    var coalesced = 0L
    var nonEmittedObservationCount = 0L
    val nonEmittedReasons = HashMap<String, Long>()
    records.forEach { record ->
        val shardId = record.callString("id", "function truth index shard")
        val relative = record.callString("path", "function truth index shard")
        if (relative != "shards/$shardId.json") fail("function truth shard path is not the fixed shard path")
        val (document, bytes) = readCanonicalControlObject(
            root.toAbsolutePath().normalize().resolve("shards").resolve("$shardId.json"),
            limits.maximumShardBytes,
            "function truth shard $shardId",
            "full-tree-function-truth",
        )
        if (
            record.callLong("bytes", "function truth index shard") != bytes.size.toLong() ||
            record.callString("sha256", "function truth index shard") != OracleArtifacts.sha256(bytes)
        ) {
            fail("function truth shard $shardId differs from its index binding")
        }
        if (document.callObject("oracle", "function truth shard") != oracle ||
            document.callObject("shard", "function truth shard") != inventoryShards.getValue(shardId)
        ) {
            fail("function truth shard $shardId bindings do not match")
        }
        val functions = document.callArray("functions", "function truth shard")
            .mapIndexed { position, value -> value.callObject("function truth function $position") }
        val nonEmitted = document.callArray("nonEmitted", "function truth shard")
            .mapIndexed { position, value -> value.callObject("non-emitted function $position") }
        if (
            document.callObject("counts", "function truth shard").callLong("functions", "function counts") !=
            functions.size.toLong() ||
            document.callObject("counts", "function truth shard").callLong("nonEmitted", "function counts") !=
            nonEmitted.size.toLong() ||
            record.callLong("functions", "function truth index shard") != functions.size.toLong() ||
            record.callLong("nonEmitted", "function truth index shard") != nonEmitted.size.toLong()
        ) {
            fail("function truth shard $shardId counts do not reconcile")
        }
        val rvas = functions.map { parseAddress(it.callString("rva", "function truth function"), "function RVA") }
        if (rvas != rvas.sorted() || rvas.toSet().size != rvas.size) fail("function truth shard $shardId RVAs are not unique and ordered")
        val nonEmittedIds = nonEmitted.map { it.callString("id", "non-emitted function") }
        if (nonEmittedIds != nonEmittedIds.sortedWith(FULL_TREE_CODE_POINT_ORDER)) {
            fail("function truth shard $shardId non-emitted identities are not ordered")
        }
        val unitIds = inventoryShards.getValue(shardId).callArray("unitIds", "inventory shard")
            .map { it.callString("inventory shard unit") }.toSet()
        functions.forEach { function ->
            functionCount = addBounded(functionCount, 1L, limits.maximumFunctions, "function truth")
            retainedFunctionEntities = addBounded(
                retainedFunctionEntities,
                1L,
                limits.maximumFunctions,
                "retained function-truth entity",
            )
            val rva = function.callString("rva", "function truth function")
            val id = function.callString("id", "function truth function")
            if (id != "function-rva-$rva" || !seenRvas.add(rva) || namespace.containsKey(id)) {
                fail("function truth contains a duplicate or non-canonical function identity")
            }
            val owner = function.callString("ownerUnitId", "function truth function")
            if (owner !in unitIds) fail("function truth owner is outside its shard")
            val names = function.callArray("aliases", "function truth function").map { value ->
                value.callObject("function truth alias").callString("name", "function truth alias")
            }
            if (names != names.sortedWith(FULL_TREE_CODE_POINT_ORDER) || names.toSet().size != names.size) {
                fail("function truth aliases are not unique and canonically ordered")
            }
            retainedFunctionAliases = addBounded(
                retainedFunctionAliases,
                names.size.toLong(),
                limits.maximumAliases,
                "retained function-truth alias",
            )
            val expectedKind = if (names.any { it.startsWith("_ZTh") || it.startsWith("_ZTv") || it.startsWith("_ZTc") }) "thunk" else "function"
            val kind = function.callString("entityKind", "function truth function")
            if (kind != expectedKind) fail("function truth function/thunk classification contradicts its aliases")
            val ownershipCandidates = function.callArray("ownershipCandidates", "function truth function")
                .map { it.callString("function ownership candidate") }
            val expectedEmission = if (ownershipCandidates.size > 1) "coalesced-odr-or-comdat" else "single-definition"
            if (function.callString("emissionKind", "function truth function") != expectedEmission) {
                fail("function truth emission classification contradicts ownership evidence")
            }
            if (expectedEmission == "coalesced-odr-or-comdat") coalesced++
            when (function.callString("population", "function truth function")) {
                "scored" -> scored++
                "excluded" -> dwarfOnly++
                else -> fail("function truth population is unsupported")
            }
            namespace[id] = FunctionRecord(shardId, kind)
            names.forEach { name ->
                emittedAliasNames += name
                aliases.getOrPut(name) { linkedSetOf() }.add(id)
            }
        }
        nonEmitted.forEach { item ->
            retainedFunctionEntities = addBounded(
                retainedFunctionEntities,
                1L,
                limits.maximumFunctions,
                "retained function-truth entity",
            )
            val id = item.callString("id", "non-emitted function")
            if (!seenNonEmitted.add(id)) fail("function truth duplicates a non-emitted identity")
            if (item.callString("ownerUnitId", "non-emitted function") !in unitIds) {
                fail("non-emitted function owner is outside its shard")
            }
            nonEmittedObservationCount = addBounded(
                nonEmittedObservationCount,
                item.callArray("observationDieOffsets", "non-emitted function").size.toLong(),
                limits.maximumObservations,
                "non-emitted observation",
            )
            val reason = item.callString("reasonCode", "non-emitted function")
            nonEmittedReasons[reason] = addExact(nonEmittedReasons[reason] ?: 0L, 1L, "non-emitted reason")
            val nonEmittedAliases = item.callArray("aliases", "non-emitted function").map { value ->
                value.callObject("non-emitted alias").callString("name", "non-emitted alias")
            }
            if (
                nonEmittedAliases != nonEmittedAliases.sortedWith(FULL_TREE_CODE_POINT_ORDER) ||
                nonEmittedAliases.toSet().size != nonEmittedAliases.size
            ) {
                fail("non-emitted function aliases are not unique and canonically ordered")
            }
            retainedFunctionAliases = addBounded(
                retainedFunctionAliases,
                nonEmittedAliases.size.toLong(),
                limits.maximumAliases,
                "retained function-truth alias",
            )
            nonEmittedRecords += item
        }
    }
    nonEmittedRecords.forEach { item ->
        if (item.callString("reasonCode", "non-emitted function") == "comdat-or-odr-selected-elsewhere") {
            val overlaps = item.callArray("aliases", "non-emitted function").any { value ->
                value.callObject("non-emitted alias").callString("name", "non-emitted alias") in emittedAliasNames
            }
            if (!overlaps) fail("selected-elsewhere function lacks emitted alias evidence")
        }
    }
    val exclusion = index.callObject("exclusions", "function truth index")
    if (exclusion.callString("path", "function truth exclusions") != "exclusions.json") {
        fail("function truth exclusion path is not fixed")
    }
    val (exclusionDocument, exclusionBytes) = readCanonicalControlObject(
        root.toAbsolutePath().normalize().resolve("exclusions.json"),
        limits.maximumShardBytes,
        "function truth exclusions",
        "full-tree-function-exclusions",
    )
    if (
        exclusion.callLong("bytes", "function truth exclusions") != exclusionBytes.size.toLong() ||
        exclusion.callString("sha256", "function truth exclusions") != OracleArtifacts.sha256(exclusionBytes) ||
        exclusionDocument.callObject("oracle", "function truth exclusions") != oracle
    ) {
        fail("function truth exclusions differ from their index binding")
    }
    val exclusions = exclusionDocument.callArray("functions", "function truth exclusions")
        .mapIndexed { position, value -> value.callObject("function truth exclusion $position") }
    retainedFunctionEntities = addBounded(
        retainedFunctionEntities,
        exclusions.size.toLong(),
        limits.maximumFunctions,
        "retained function-truth entity",
    )
    exclusions.forEach { item ->
        val exclusionAliases = item.callArray("aliases", "function truth exclusion").map { value ->
            value.callObject("function truth exclusion alias").callString("name", "function truth exclusion alias")
        }
        if (
            exclusionAliases != exclusionAliases.sortedWith(FULL_TREE_CODE_POINT_ORDER) ||
            exclusionAliases.toSet().size != exclusionAliases.size
        ) {
            fail("function truth exclusion aliases are not unique and canonically ordered")
        }
        retainedFunctionAliases = addBounded(
            retainedFunctionAliases,
            exclusionAliases.size.toLong(),
            limits.maximumAliases,
            "retained function-truth alias",
        )
    }
    val exclusionRvas = exclusions.map { it.callString("rva", "function truth exclusion") }
    if (
        exclusionRvas.map { parseAddress(it, "function truth exclusion RVA") } !=
        exclusionRvas.map { parseAddress(it, "function truth exclusion RVA") }.sorted() ||
        exclusionRvas.toSet().size != exclusionRvas.size ||
        exclusionRvas.any { it in seenRvas }
    ) {
        fail("function truth exclusions are duplicate, overlapping, or unordered")
    }
    if (
        exclusion.callLong("functions", "function truth exclusions") != exclusions.size.toLong() ||
        exclusion.callLong("nonEmitted", "function truth exclusions") != 0L
    ) {
        fail("function truth exclusion counts do not reconcile")
    }
    val expectedCounts = mapOf(
        "coalescedEmittedRvas" to coalesced,
        "definitionNoRangeUnique" to (nonEmittedReasons["definition-no-emitted-range"] ?: 0L),
        "dwarfOnlyRvas" to dwarfOnly,
        "dwarfRvas" to functionCount,
        "elfOnlyRvas" to exclusions.size.toLong(),
        "elfRvas" to addExact(scored, exclusions.size.toLong(), "ELF truth count"),
        "inlineOnlyUnique" to (nonEmittedReasons["inline-no-emitted-range"] ?: 0L),
        "nonEmittedObservations" to nonEmittedObservationCount,
        "nonEmittedUnique" to seenNonEmitted.size.toLong(),
        "scoredRvas" to scored,
        "selectedElsewhereUnique" to (nonEmittedReasons["comdat-or-odr-selected-elsewhere"] ?: 0L),
    )
    val indexCounts = index.callObject("counts", "function truth index")
    if (indexCounts.keys != expectedCounts.keys || expectedCounts.any { (name, value) -> indexCounts.callLong(name, "function truth counts") != value }) {
        fail("function truth aggregate counts do not reconcile")
    }
    if (expectedCounts.getValue("elfRvas") != elf.callArray("functions", "ELF function index").size.toLong()) {
        fail("function truth ELF population differs from the bound ELF function index")
    }
    return FunctionState(indexSha256, namespace, aliases.mapValues { it.value.toSet() })
}

private fun loadCallObservations(
    root: Path,
    scope: AuthenticatedFullTreeScope,
    inventory: JsonObject,
    inventoryBytes: ByteArray,
    inventoryShards: Map<String, JsonObject>,
    unitsById: Map<String, JsonObject>,
    limits: FullTreeCallTruthAssessmentLimits,
): ObservationState {
    val normalizedRoot = root.toAbsolutePath().normalize()
    val (_, indexBytes) = readCanonicalControlObject(
        normalizedRoot.resolve("index.json"),
        limits.maximumIndexBytes,
        "call observation bounded-shard index",
        "bounded-shard-index",
    )
    val indexSha256 = OracleArtifacts.sha256(indexBytes)
    val binding = try {
        BoundedShardRunVerifier.verifyEmbedded(
            normalizedRoot,
            indexSha256,
            CALL_OBSERVATION_ROOT_MEMBERS,
            BoundedShardRunLimits(
                maximumControlArtifactBytes = limits.maximumIndexBytes,
                maximumShards = limits.maximumShards,
                maximumPerShardEntities = limits.maximumObservations,
                maximumWholeRunEntities = limits.maximumObservations,
                maximumPerShardOutputBytes = limits.maximumShardBytes.toLong(),
                maximumWholeRunOutputBytes = minOf(
                    64L * 1024L * 1024L * 1024L,
                    Math.multiplyExact(limits.maximumShardBytes.toLong(), limits.maximumShards.toLong()),
                ),
                maximumTotalStringBytesPerOutput = limits.maximumShardBytes.toLong(),
            ),
        )
    } catch (failure: Exception) {
        throw FullTreeCallTruthAssessmentException("call observation bounded-shard tree is not authenticated", failure)
    }
    validateCallObservationRunContract(binding, scope, inventoryShards.size)
    requireExactDirectoryMembership(
        normalizedRoot.resolve("control"),
        setOf("inventory.json", "scope.json"),
        "call observation control directory",
    )
    val (copiedScope, copiedScopeBytes) = readCanonicalControlObject(
        normalizedRoot.resolve("control").resolve("scope.json"),
        limits.control.maximumScopeBytes,
        "call observation copied scope",
        "full-tree-scope",
    )
    val (copiedInventory, copiedInventoryBytes) = readCanonicalControlObject(
        normalizedRoot.resolve("control").resolve("inventory.json"),
        limits.control.maximumInventoryBytes,
        "call observation copied inventory",
        "full-tree-inventory",
    )
    if (
        copiedScope != scope.document ||
        !MessageDigest.isEqual(copiedScopeBytes, OracleJson.canonicalBytes(scope.document)) ||
        copiedInventory != inventory ||
        !MessageDigest.isEqual(copiedInventoryBytes, inventoryBytes)
    ) {
        fail("call observation copied controls differ from the authenticated inputs")
    }
    val expectedShardIds = inventoryShards.keys.sortedWith(FULL_TREE_CODE_POINT_ORDER)
    if (binding.outputs.map { it.shardId } != expectedShardIds) {
        fail("call observation run does not cover every inventory shard in canonical order")
    }
    val configuration = callObservationConfigurationSha256()
    val expectedOracle = JsonObject(
        mapOf(
            "configurationSha256" to JsonPrimitive(configuration),
            "inventoryIndexSha256" to inventory.callElement("indexSha256", "inventory"),
            "richArtifactSha256" to scope.document.controlObject("oracle")["richArtifactSha256"]!!,
            "scopeSha256" to JsonPrimitive(scope.sha256),
        ),
    )
    val observations = ArrayList<Observation>()
    val identities = HashSet<String>()
    var total = 0L
    var targetAliasCount = 0L
    binding.outputs.forEach { output ->
        val shardId = output.shardId
        val path = normalizedRoot.resolve("outputs").resolve("$shardId.json")
        val (document, bytes) = readCanonicalControlObject(
            path,
            limits.maximumShardBytes,
            "call observation shard $shardId",
            "full-tree-call-observations",
        )
        if (bytes.size.toLong() != output.outputBytes || OracleArtifacts.sha256(bytes) != output.outputSha256) {
            fail("call observation shard $shardId differs from its bounded-run binding")
        }
        val expectedUnits = inventoryShards.getValue(shardId).callArray("unitIds", "inventory shard")
            .map { id -> unitsById.getValue(id.callString("inventory shard unit")) }
        val expectedInput = callObservationInputSha256(
            inventory.callString("indexSha256", "inventory"),
            configuration,
            scope.document.controlObject("oracle").controlString("richArtifactSha256"),
            scope.sha256,
            shardId,
            expectedUnits,
        )
        if (output.inputSha256 != expectedInput ||
            document.callObject("oracle", "call observation shard") != expectedOracle ||
            document.callObject("shard", "call observation shard") != JsonObject(
                mapOf("id" to JsonPrimitive(shardId), "inputSha256" to JsonPrimitive(expectedInput)),
            )
        ) {
            fail("call observation shard $shardId bindings do not match")
        }
        val calls = document.callArray("calls", "call observation shard")
            .mapIndexed { position, value -> value.callObject("call observation $position") }
        val ids = calls.map { it.callString("id", "call observation") }
        if (ids != ids.sortedWith(FULL_TREE_CODE_POINT_ORDER) || ids.toSet().size != ids.size) {
            fail("call observations in shard $shardId are not unique and canonically ordered")
        }
        val unitIds = expectedUnits.map { it.callString("id", "inventory unit") }.toSet()
        calls.forEach { call ->
            total = addBounded(total, 1L, limits.maximumObservations, "call observation")
            val observation = parseObservation(call, shardId, unitIds)
            targetAliasCount = addBounded(
                targetAliasCount,
                observation.target.aliases.size.toLong(),
                limits.maximumAliases,
                "retained call-target alias",
            )
            if (!identities.add(observation.id)) fail("call observation identity ${observation.id} is duplicated across shards")
            observations += observation
        }
        val counts = document.callObject("counts", "call observation shard")
        if (
            counts.callLong("units", "call observation counts") != expectedUnits.size.toLong() ||
            counts.callLong("observedCallSites", "call observation counts") != calls.size.toLong() ||
            counts.callLong("scored", "call observation counts") != observations.takeLast(calls.size).count { it.population == "scored" }.toLong() ||
            counts.callLong("unobservable", "call observation counts") != observations.takeLast(calls.size).count { it.population == "unobservable" }.toLong() ||
            counts.callLong("scannedDies", "call observation counts") < calls.size.toLong() ||
            output.entities != calls.size.toLong()
        ) {
            fail("call observation shard $shardId counts do not reconcile")
        }
    }
    validateObservationExecutionEvidence(
        normalizedRoot,
        binding,
        scope,
        inventory,
        inventoryBytes,
        limits,
    )
    binding.outputs.forEach { output ->
        val snapshot = try {
            OracleArtifacts.read(
                normalizedRoot.resolve("outputs").resolve("${output.shardId}.json"),
                OracleArtifactLimits(limits.maximumShardBytes),
            )
        } catch (failure: Exception) {
            throw FullTreeCallTruthAssessmentException(
                "cannot repeat-authenticate call observation shard ${output.shardId}",
                failure,
            )
        }
        if (snapshot.size.toLong() != output.outputBytes || snapshot.sha256 != output.outputSha256) {
            fail("call observation shard ${output.shardId} changed before assessment return")
        }
    }
    return ObservationState(indexSha256, observations)
}

private fun validateCallObservationRunContract(
    binding: BoundedShardRunBinding,
    scope: AuthenticatedFullTreeScope,
    expectedShards: Int,
) {
    val run = binding.run
    if (run.callString("id", "call observation run") != "full-tree-calls-${scope.sha256.take(16)}") {
        fail("call observation run identity differs from the authenticated scope")
    }
    val actual = run.callObject("bounds", "call observation run")
    val perShard = scope.document.controlObject("bounds").controlObject("perShard")
    val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
    val expected = mapOf(
        "maximumResidentBytes" to wholeRun.controlLong("maximumResidentBytes"),
        "maximumShards" to expectedShards.toLong(),
        "perShardBytes" to perShard.controlLong("serializedBytes"),
        "perShardCpuSeconds" to perShard.controlLong("cpuSeconds"),
        "perShardEntities" to perShard.controlLong("entities"),
        "perShardSeconds" to perShard.controlLong("wallClockSeconds"),
        "wholeRunBytes" to wholeRun.controlLong("serializedBytes"),
        "wholeRunCpuSeconds" to wholeRun.controlLong("cpuSeconds"),
        "wholeRunEntities" to wholeRun.controlLong("entities"),
        "wholeRunSeconds" to wholeRun.controlLong("wallClockSeconds"),
    )
    if (expected.any { (name, value) -> actual.callLong(name, "call observation run bounds") != value }) {
        fail("call observation run bounds differ from the authenticated scope")
    }
    val workers = actual.callLong("maximumWorkers", "call observation run bounds")
    if (workers !in 1L..minOf(32L, expectedShards.toLong())) {
        fail("call observation worker count is outside the authenticated shard population")
    }
}

private fun validateObservationExecutionEvidence(
    root: Path,
    binding: BoundedShardRunBinding,
    scope: AuthenticatedFullTreeScope,
    inventory: JsonObject,
    inventoryBytes: ByteArray,
    limits: FullTreeCallTruthAssessmentLimits,
) {
    val expectedUsageNames = binding.outputs.mapTo(linkedSetOf()) { "${it.shardId}.json" }
    requireExactDirectoryMembership(root.resolve("usage"), expectedUsageNames, "call observation usage directory")
    val perShardBounds = scope.document.controlObject("bounds").controlObject("perShard")
    val wholeRunBounds = scope.document.controlObject("bounds").controlObject("wholeRun")
    val usages = binding.outputs.map { output ->
        val (document, bytes) = readCanonicalControlObject(
            root.resolve("usage").resolve("${output.shardId}.json"),
            limits.maximumIndexBytes,
            "call observation usage ${output.shardId}",
        )
        document.callRequireKeys(USAGE_FIELDS, "call observation usage ${output.shardId}")
        if (
            document.callString("id", "call observation usage") != output.shardId ||
            document.callString("inputSha256", "call observation usage") != output.inputSha256 ||
            document.callString("outputSha256", "call observation usage") != output.outputSha256 ||
            document.callLong("serializedBytes", "call observation usage") != output.outputBytes ||
            document.callLong("entities", "call observation usage") != output.entities
        ) {
            fail("call observation usage ${output.shardId} differs from its bounded-run binding")
        }
        val resident = document.callLong("maximumResidentBytes", "call observation usage")
        val user = document.callNonNegativeDouble("userCpuSeconds", "call observation usage")
        val system = document.callNonNegativeDouble("systemCpuSeconds", "call observation usage")
        val wall = document.callNonNegativeDouble("wallClockSeconds", "call observation usage")
        if (
            resident !in 0L..perShardBounds.controlLong("maximumResidentBytes") ||
            user + system > perShardBounds.controlLong("cpuSeconds").toDouble() ||
            wall > perShardBounds.controlLong("wallClockSeconds").toDouble()
        ) {
            fail("call observation usage ${output.shardId} exceeds the authenticated per-shard bounds")
        }
        UsageRecord(document, bytes, resident, user, system, wall, output.entities, output.outputBytes)
    }
    val (evidence, evidenceBytes) = readCanonicalControlObject(
        root.resolve("execution-evidence.json"),
        limits.maximumIndexBytes,
        "call observation execution evidence",
        "full-tree-execution-evidence",
    )
    validateSelfHash(evidence, "evidenceSha256", "call observation execution evidence")
    if (
        evidence.callString("runSha256", "call observation execution evidence") != binding.runSha256 ||
        evidence.callString("indexSha256", "call observation execution evidence") !=
        binding.index.callString("indexSha256", "bounded-shard index") ||
        evidence.callObject("bounds", "call observation execution evidence") !=
        scope.document.controlObject("bounds") ||
        evidence.callArray("shards", "call observation execution evidence") !=
        JsonArray(usages.map { it.document })
    ) {
        fail("call observation execution evidence bindings do not reconcile")
    }
    val environment = evidence.callObject("environment", "call observation execution evidence")
    environment.callRequireKeys(setOf("platform", "python"), "call observation execution environment")
    if (
        environment.callString("platform", "call observation execution environment").isEmpty() ||
        environment.callString("python", "call observation execution environment").isEmpty()
    ) {
        fail("call observation execution environment is empty")
    }
    val observed = evidence.callObject("observed", "call observation execution evidence")
    observed.callRequireKeys(EXECUTION_OBSERVED_FIELDS, "call observation execution totals")
    val entities = usages.fold(0L) { total, usage -> addExact(total, usage.entities, "execution entity") }
    val serialized = usages.fold(0L) { total, usage -> addExact(total, usage.serializedBytes, "execution byte") }
    val resident = usages.maxOf { it.maximumResidentBytes }
    val user = usages.sumOf { it.userCpuSeconds }
    val system = usages.sumOf { it.systemCpuSeconds }
    val wall = observed.callNonNegativeDouble("wallClockSeconds", "call observation execution totals")
    if (
        observed.callLong("entities", "call observation execution totals") != entities ||
        observed.callLong("serializedBytes", "call observation execution totals") != serialized ||
        observed.callLong("maximumResidentBytes", "call observation execution totals") != resident ||
        observed.callNonNegativeDouble("userCpuSeconds", "call observation execution totals") != user ||
        observed.callNonNegativeDouble("systemCpuSeconds", "call observation execution totals") != system ||
        resident > perShardBounds.controlLong("maximumResidentBytes") ||
        user + system > wholeRunBounds.controlLong("cpuSeconds").toDouble() ||
        wall < usages.maxOf { it.wallClockSeconds } ||
        wall > wholeRunBounds.controlLong("wallClockSeconds").toDouble()
    ) {
        fail("call observation execution totals differ or exceed authenticated bounds")
    }
    requireExactDirectoryMembership(
        root,
        setOf(
            "checkpoints",
            "control",
            "execution-evidence.json",
            "index.json",
            "outputs",
            "run.json",
            "usage",
        ),
        "embedded call observation root",
    )
    requireExactDirectoryMembership(
        root.resolve("control"),
        setOf("inventory.json", "scope.json"),
        "call observation control directory",
    )
    requireExactDirectoryMembership(root.resolve("usage"), expectedUsageNames, "call observation usage directory")
    usages.forEach { usage ->
        val (_, repeatedBytes) = readCanonicalControlObject(
            root.resolve("usage").resolve("${usage.document.callString("id", "call observation usage")}.json"),
            limits.maximumIndexBytes,
            "call observation terminal usage",
        )
        if (!MessageDigest.isEqual(usage.bytes, repeatedBytes)) fail("call observation usage changed before assessment return")
    }
    val (_, repeatedEvidenceBytes) = readCanonicalControlObject(
        root.resolve("execution-evidence.json"),
        limits.maximumIndexBytes,
        "call observation terminal execution evidence",
        "full-tree-execution-evidence",
    )
    if (!MessageDigest.isEqual(evidenceBytes, repeatedEvidenceBytes)) {
        fail("call observation execution evidence changed before assessment return")
    }
    val (terminalScope, terminalScopeBytes) = readCanonicalControlObject(
        root.resolve("control/scope.json"),
        limits.control.maximumScopeBytes,
        "call observation terminal copied scope",
        "full-tree-scope",
    )
    val (terminalInventory, terminalInventoryBytes) = readCanonicalControlObject(
        root.resolve("control/inventory.json"),
        limits.control.maximumInventoryBytes,
        "call observation terminal copied inventory",
        "full-tree-inventory",
    )
    if (
        terminalScope != scope.document ||
        !MessageDigest.isEqual(terminalScopeBytes, OracleJson.canonicalBytes(scope.document)) ||
        terminalInventory != inventory ||
        !MessageDigest.isEqual(terminalInventoryBytes, inventoryBytes)
    ) {
        fail("call observation copied controls changed before assessment return")
    }
}

private fun parseObservation(document: JsonObject, sourceShard: String, unitIds: Set<String>): Observation {
    val id = document.callString("id", "call observation")
    val unitId = document.callString("unitId", "call observation")
    if (unitId !in unitIds) fail("call observation owner is outside its shard")
    val dieOffset = document.callString("dieOffset", "call observation")
    parseAddress(dieOffset, "call observation DIE offset")
    val population = document.callString("population", "call observation")
    val reason = document.callNullableString("reasonCode", "call observation")
    val callerId = document.callNullableString("callerId", "call observation")
    val local = document.callNullableString("callerLocalReturnOffset", "call observation")
    val returnPc = document.callNullableString("returnPcRva", "call observation")
    local?.let { parseAddress(it, "caller-local return offset") }
    returnPc?.let { parseAddress(it, "return-PC RVA") }
    when (population) {
        "scored" -> if (reason != null || callerId == null || local == null || returnPc == null) {
            fail("scored call observation has incomplete caller identity")
        }
        "unobservable" -> if (reason == null || callerId != null || local != null) {
            fail("unobservable call observation has contradictory caller identity")
        }
        else -> fail("call observation population is unsupported")
    }
    if (reason == "call-site-no-address" && returnPc != null) fail("addressless call observation has a return-PC RVA")
    if (reason == "caller-no-emitted-range" && returnPc == null) fail("callerless call observation lacks a return-PC RVA")
    if (callerId != null) {
        val callerRvaText = callerId.removePrefix("function-rva-")
        val callerRva = parseAddress(callerRvaText, "call observation caller RVA")
        val localRva = parseAddress(checkNotNull(local), "caller-local return offset")
        val observedReturn = parseAddress(checkNotNull(returnPc), "return-PC RVA")
        if (localRva > ULong.MAX_VALUE - callerRva || callerRva + localRva != observedReturn) {
            fail("call observation caller-local return offset does not reconcile without overflow")
        }
    }
    val identityPayload = JsonObject(
        mapOf(
            "caller" to callerId?.removePrefix("function-rva-").jsonNullable(),
            "die" to JsonPrimitive(dieOffset),
            "return" to returnPc.jsonNullable(),
            "unit" to JsonPrimitive(unitId),
        ),
    )
    val expectedId = "call-${OracleArtifacts.sha256(OracleJson.canonicalBytes(identityPayload)).take(32)}"
    if (id != expectedId) fail("call observation identity differs from its authenticated locators")
    val targetObject = document.callObject("target", "call observation")
    val kind = targetObject.callString("kind", "call target")
    val dispatch = targetObject.callString("dispatchKind", "call target")
    val functionId = targetObject.callNullableString("functionId", "call target")
    val aliases = targetObject.callArray("aliases", "call target").map { it.callString("call target alias") }
    if (aliases != aliases.sortedWith(FULL_TREE_CODE_POINT_ORDER) || aliases.toSet().size != aliases.size) {
        fail("call target aliases are not unique and canonically ordered")
    }
    targetObject.callNullableString("originDieOffset", "call target")?.let {
        parseAddress(it, "call target origin DIE offset")
    }
    val proven = targetObject.callArray("provenFunctionIds", "call target")
        .map { it.callString("proven call target") }
    if (proven != proven.sortedWith(FULL_TREE_CODE_POINT_ORDER) || proven.toSet().size != proven.size || proven.size > 16) {
        fail("proven call targets are not bounded, unique, and canonically ordered")
    }
    when (kind) {
        "direct-internal" -> if (dispatch != "direct" || functionId == null || proven.isNotEmpty()) fail("direct call target classification is contradictory")
        "external-unresolved" -> if (dispatch != "direct" || functionId != null || proven.isNotEmpty()) fail("external call target classification is contradictory")
        "indirect-proven" -> if (dispatch != "indirect-proven" || functionId != null || proven.isEmpty() || aliases.isNotEmpty()) fail("proven indirect call classification is contradictory")
        "indirect-unresolved" -> if (dispatch != "indirect-unresolved" || functionId != null || proven.isNotEmpty() || aliases.isNotEmpty()) fail("unresolved indirect call classification is contradictory")
        "virtual-unresolved" -> if (dispatch != "virtual-unresolved" || functionId != null || proven.isNotEmpty()) fail("virtual call classification is contradictory")
        else -> fail("call target kind is unsupported")
    }
    return Observation(
        id,
        sourceShard,
        population,
        reason,
        callerId,
        local,
        returnPc,
        document.callBoolean("tailCall", "call observation"),
        Target(
            kind,
            dispatch,
            functionId,
            aliases,
            proven,
            targetObject.callString("targetEvidence", "call target"),
        ),
    )
}

private fun composeEdges(
    shardIds: List<String>,
    functions: Map<String, FunctionRecord>,
    aliases: Map<String, Set<String>>,
    externalNames: Set<String>,
    observations: List<Observation>,
    limits: FullTreeCallTruthAssessmentLimits,
): List<DiagnosticShard> {
    val grouped = TreeMap<String, MutableList<Observation>>(FULL_TREE_CODE_POINT_ORDER)
    observations.forEach { observation ->
        val identity = if (observation.population == "scored") {
            JsonObject(
                mapOf(
                    "callerId" to JsonPrimitive(checkNotNull(observation.callerId)),
                    "returnPcRva" to JsonPrimitive(checkNotNull(observation.returnPcRva)),
                ),
            )
        } else {
            JsonObject(mapOf("observationId" to JsonPrimitive(observation.id)))
        }
        val key = OracleArtifacts.sha256(OracleJson.canonicalBytes(identity))
        grouped.getOrPut(key) { arrayListOf() }.add(observation)
    }
    if (grouped.size.toLong() > limits.maximumObservations) fail("call edge count exceeds the assessment bound")
    val byOwner = shardIds.associateWith { arrayListOf<Edge>() }.toMutableMap()
    grouped.forEach { (key, rawGroup) ->
        val group = rawGroup.sortedBy { it.id }
        val first = group.first()
        val signature = first.signature()
        if (group.any { it.signature() != signature }) fail("incompatible duplicate call observations for $key")
        val caller = first.callerId?.let(functions::get)
        if (first.population == "scored" && caller == null) fail("call ${first.id} has a dangling caller identity")
        val owner = caller?.ownerShard ?: group.minOf { it.sourceShard }
        var targetKind = first.target.kind
        var population = first.population
        var reason = first.reasonCode
        var physical: String? = null
        var semantic: String? = null
        var externalIds = emptyList<String>()
        var provenIds = emptyList<String>()
        when (first.target.kind) {
            "direct-internal" -> {
                val targetId = checkNotNull(first.target.functionId)
                val target = functions[targetId] ?: fail("call ${first.id} has a dangling direct target")
                physical = targetId
                if (target.kind == "thunk") reason = "thunk-semantic-target-unresolved" else semantic = targetId
            }
            "external-unresolved" -> {
                val internal = first.target.aliases.flatMap { aliases[it].orEmpty() }
                    .toSortedSet(FULL_TREE_CODE_POINT_ORDER).toList()
                when {
                    internal.size == 1 -> {
                        targetKind = "direct-internal"
                        physical = internal.single()
                        if (functions.getValue(physical).kind == "thunk") {
                            reason = "thunk-semantic-target-unresolved"
                        } else {
                            semantic = physical
                        }
                    }
                    internal.size > 1 -> {
                        targetKind = "indirect-unresolved"
                        population = "unobservable"
                        reason = "ambiguous-authenticated-internal-aliases"
                    }
                    else -> {
                        targetKind = "external"
                        externalIds = first.target.aliases.filter { it in externalNames }
                            .map(::externalFunctionId).distinct().sortedWith(FULL_TREE_CODE_POINT_ORDER)
                        if (externalIds.isEmpty()) {
                            population = "unobservable"
                            reason = "external-without-elf-evidence"
                        }
                    }
                }
            }
            "indirect-proven" -> {
                first.target.provenFunctionIds.forEach { id ->
                    if (id !in functions) fail("call ${first.id} has a dangling proven target")
                }
                provenIds = first.target.provenFunctionIds.sortedWith(FULL_TREE_CODE_POINT_ORDER)
            }
            "virtual-unresolved" -> {
                population = "unobservable"
                reason = "virtual-target-set-unproven"
            }
            "indirect-unresolved" -> Unit
            else -> fail("unsupported call target kind")
        }
        val edge = Edge(
            id = "call-edge-${key.take(32)}",
            observationIds = group.map { it.id },
            callerId = first.callerId,
            callerLocalReturnOffset = first.callerLocalReturnOffset,
            returnPcRva = first.returnPcRva,
            targetKind = targetKind,
            dispatchKind = first.target.dispatchKind,
            physicalTargetId = physical,
            semanticTargetId = semantic,
            externalTargetIds = externalIds,
            provenTargetIds = provenIds,
            population = population,
            reasonCode = reason,
            tailCall = first.tailCall,
            targetEvidence = first.target.targetEvidence,
        )
        byOwner.getValue(owner) += edge
    }
    return shardIds.map { id ->
        DiagnosticShard(id, byOwner.getValue(id).sortedBy { it.id })
    }
}

private fun aggregateCounts(shards: List<DiagnosticShard>): Counts {
    var result = Counts()
    shards.forEach { shard ->
        shard.calls.forEach { edge ->
            result = result.accept(edge)
        }
    }
    return result
}

private fun validateAndEncodeComposedShards(
    shards: List<DiagnosticShard>,
    scopeSha256: String,
    inventorySha256: String,
    functionTruthIndexSha256: String,
    elfFunctionIndexSha256: String,
    callObservationIndexSha256: String,
): List<DiagnosticShard> {
    val oracle = JsonObject(
        mapOf(
            "assessmentAuthority" to JsonPrimitive(NON_AUTHORITY),
            "callObservationIndexSha256" to JsonPrimitive(callObservationIndexSha256),
            "elfFunctionIndexSha256" to JsonPrimitive(elfFunctionIndexSha256),
            "functionTruthIndexSha256" to JsonPrimitive(functionTruthIndexSha256),
            "historicalCallTruthConfigurationSha256" to JsonPrimitive(
                FullTreeCallTruthAssessmentVerifier.historicalCallTruthConfigurationSha256,
            ),
            "inventorySha256" to JsonPrimitive(inventorySha256),
            "scopeSha256" to JsonPrimitive(scopeSha256),
        ),
    )
    return shards.map { shard ->
        validateComposedSemantics(shard)
        val document = JsonObject(
            mapOf(
                "calls" to JsonArray(shard.calls.map(::edgeJson)),
                "counts" to countsJson(aggregateCounts(listOf(shard))),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to JsonObject(mapOf("id" to JsonPrimitive(shard.id))),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-call-truth", document)
        } catch (failure: Exception) {
            throw FullTreeCallTruthAssessmentException(
                "composed diagnostic shard ${shard.id} fails the historical call-truth schema",
                failure,
            )
        }
        val bytes = try {
            OracleJson.canonicalBytes(document, controlJsonLimits(CALL_ASSESSMENT_MAXIMUM_SHARD_BYTES))
        } catch (failure: Exception) {
            throw FullTreeCallTruthAssessmentException(
                "composed diagnostic shard ${shard.id} exceeds strict JSON limits",
                failure,
            )
        }
        shard.copy(canonicalBytes = bytes)
    }
}

private fun validateComposedSemantics(shard: DiagnosticShard) {
    val ids = shard.calls.map { it.id }
    if (ids != ids.sortedWith(FULL_TREE_CODE_POINT_ORDER) || ids.toSet().size != ids.size) {
        fail("composed call edges in ${shard.id} are not unique and canonically ordered")
    }
    shard.calls.forEach { edge ->
        if (
            edge.observationIds.isEmpty() ||
            edge.observationIds != edge.observationIds.sortedWith(FULL_TREE_CODE_POINT_ORDER) ||
            edge.observationIds.toSet().size != edge.observationIds.size
        ) {
            fail("composed call edge ${edge.id} has invalid observation membership")
        }
        if (edge.population == "scored" && (
                edge.callerId == null || edge.returnPcRva == null ||
                    edge.reasonCode !in setOf(null, "thunk-semantic-target-unresolved")
                )
        ) {
            fail("composed scored call edge ${edge.id} has contradictory caller or reason state")
        }
        if (edge.population == "unobservable" && edge.reasonCode == null) {
            fail("composed unobservable call edge ${edge.id} lacks a closed reason")
        }
        when (edge.targetKind) {
            "direct-internal" -> {
                if (edge.dispatchKind != "direct" || edge.physicalTargetId == null ||
                    edge.externalTargetIds.isNotEmpty() || edge.provenTargetIds.isNotEmpty()
                ) {
                    fail("composed direct edge ${edge.id} has contradictory target fields")
                }
                if (edge.semanticTargetId != null && edge.semanticTargetId != edge.physicalTargetId) {
                    fail("composed direct edge ${edge.id} has a divergent semantic target")
                }
                if ((edge.semanticTargetId == null) != (edge.reasonCode == "thunk-semantic-target-unresolved")) {
                    fail("composed direct edge ${edge.id} has contradictory thunk semantics")
                }
            }
            "external" -> {
                if (edge.dispatchKind != "direct" || edge.physicalTargetId != null || edge.semanticTargetId != null ||
                    edge.provenTargetIds.isNotEmpty()
                ) {
                    fail("composed external edge ${edge.id} has contradictory target fields")
                }
                if (edge.externalTargetIds.isEmpty() != (edge.reasonCode == "external-without-elf-evidence")) {
                    fail("composed external edge ${edge.id} contradicts exact ELF evidence")
                }
            }
            "indirect-proven" -> if (
                edge.dispatchKind != "indirect-proven" || edge.physicalTargetId != null ||
                edge.semanticTargetId != null || edge.externalTargetIds.isNotEmpty() || edge.provenTargetIds.isEmpty()
            ) {
                fail("composed proven-indirect edge ${edge.id} has contradictory target fields")
            }
            "indirect-unresolved" -> {
                if (edge.physicalTargetId != null || edge.semanticTargetId != null ||
                    edge.externalTargetIds.isNotEmpty() || edge.provenTargetIds.isNotEmpty()
                ) {
                    fail("composed unresolved-indirect edge ${edge.id} has contradictory target fields")
                }
                if (edge.dispatchKind == "direct") {
                    if (edge.reasonCode != "ambiguous-authenticated-internal-aliases" || edge.population != "unobservable") {
                        fail("composed alias-ambiguous edge ${edge.id} has contradictory dispatch state")
                    }
                } else if (edge.dispatchKind != "indirect-unresolved") {
                    fail("composed unresolved-indirect edge ${edge.id} has unsupported dispatch state")
                }
            }
            "virtual-unresolved" -> if (
                edge.dispatchKind != "virtual-unresolved" || edge.population != "unobservable" ||
                edge.reasonCode != "virtual-target-set-unproven" || edge.physicalTargetId != null ||
                edge.semanticTargetId != null || edge.externalTargetIds.isNotEmpty() || edge.provenTargetIds.isNotEmpty()
            ) {
                fail("composed virtual edge ${edge.id} has contradictory target fields")
            }
            else -> fail("composed call edge ${edge.id} has an unsupported target kind")
        }
    }
}

private fun assessmentDigest(
    scopeSha256: String,
    inventorySha256: String,
    functionTruthIndexSha256: String,
    elfFunctionIndexSha256: String,
    callObservationIndexSha256: String,
    shards: List<DiagnosticShard>,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(ASSESSMENT_DIGEST_DOMAIN)
    listOf(
        scopeSha256,
        inventorySha256,
        functionTruthIndexSha256,
        elfFunctionIndexSha256,
        callObservationIndexSha256,
    ).forEach { digest.update(it.toByteArray(StandardCharsets.US_ASCII)) }
    shards.forEach { shard ->
        val id = shard.id.toByteArray(StandardCharsets.UTF_8)
        digest.update(java.nio.ByteBuffer.allocate(Int.SIZE_BYTES).putInt(id.size).array())
        digest.update(id)
        digest.update(MessageDigest.getInstance("SHA-256").digest(shard.canonicalBytes))
    }
    return digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun Counts.accept(edge: Edge): Counts = copy(
    edges = addExact(edges, 1L, "diagnostic edge"),
    observations = addExact(observations, edge.observationIds.size.toLong(), "diagnostic observation"),
    directInternal = directInternal + if (edge.targetKind == "direct-internal") 1L else 0L,
    external = external + if (edge.targetKind == "external") 1L else 0L,
    indirectProven = indirectProven + if (edge.targetKind == "indirect-proven") 1L else 0L,
    indirectUnresolved = indirectUnresolved + if (edge.targetKind == "indirect-unresolved") 1L else 0L,
    virtualUnresolved = virtualUnresolved + if (edge.targetKind == "virtual-unresolved") 1L else 0L,
    tailCalls = tailCalls + if (edge.tailCall) 1L else 0L,
    unobservable = unobservable + if (edge.population == "unobservable") 1L else 0L,
)

private fun countsJson(counts: Counts): JsonObject = JsonObject(
    mapOf(
        "directInternal" to JsonPrimitive(counts.directInternal),
        "edges" to JsonPrimitive(counts.edges),
        "external" to JsonPrimitive(counts.external),
        "indirectProven" to JsonPrimitive(counts.indirectProven),
        "indirectUnresolved" to JsonPrimitive(counts.indirectUnresolved),
        "observations" to JsonPrimitive(counts.observations),
        "tailCalls" to JsonPrimitive(counts.tailCalls),
        "unobservable" to JsonPrimitive(counts.unobservable),
        "virtualUnresolved" to JsonPrimitive(counts.virtualUnresolved),
    ),
)

private fun edgeJson(edge: Edge): JsonObject = JsonObject(
    mapOf(
        "callerId" to edge.callerId.jsonNullable(),
        "callerLocalReturnOffset" to edge.callerLocalReturnOffset.jsonNullable(),
        "dispatchKind" to JsonPrimitive(edge.dispatchKind),
        "externalTargetIds" to JsonArray(edge.externalTargetIds.map(::JsonPrimitive)),
        "id" to JsonPrimitive(edge.id),
        "observationIds" to JsonArray(edge.observationIds.map(::JsonPrimitive)),
        "physicalTargetId" to edge.physicalTargetId.jsonNullable(),
        "population" to JsonPrimitive(edge.population),
        "provenTargetIds" to JsonArray(edge.provenTargetIds.map(::JsonPrimitive)),
        "reasonCode" to edge.reasonCode.jsonNullable(),
        "returnPcRva" to edge.returnPcRva.jsonNullable(),
        "semanticTargetId" to edge.semanticTargetId.jsonNullable(),
        "tailCall" to JsonPrimitive(edge.tailCall),
        "targetEvidence" to JsonPrimitive(edge.targetEvidence),
        "targetKind" to JsonPrimitive(edge.targetKind),
    ),
)

private fun String?.jsonNullable(): JsonElement = this?.let(::JsonPrimitive) ?: JsonNull

private fun validateSelfHash(document: JsonObject, field: String, label: String) {
    val expected = document.callString(field, label)
    requireDigest(expected, "$label self")
    val without = JsonObject(document.filterKeys { it != field })
    if (OracleArtifacts.sha256(OracleJson.canonicalBytes(without)) != expected) fail("$label self-hash does not reconcile")
}

private fun callObservationInputSha256(
    inventoryIndexSha256: String,
    configurationSha256: String,
    richArtifactSha256: String,
    scopeSha256: String,
    shardId: String,
    units: List<JsonObject>,
): String = FullTreeCallObservations.historicalV2InputSha256(
    inventoryIndexSha256,
    configurationSha256,
    richArtifactSha256,
    scopeSha256,
    shardId,
    units,
)

private fun callObservationConfigurationSha256(): String =
    FullTreeCallObservations.historicalV2ConfigurationSha256

private fun historicalFunctionTruthConfigurationSha256(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(OracleJson.canonicalBytes(FUNCTION_TRUTH_POLICY))
    listOf(
        "full-tree-function-exclusions",
        "full-tree-function-truth",
        "full-tree-function-truth-index",
    ).forEach { name ->
        val resource = "oracle/$name.schema.json"
        val bytes = FullTreeCallTruthAssessmentVerifier::class.java.classLoader
            .getResourceAsStream(resource)?.use { input -> input.readNBytes(MAXIMUM_SCHEMA_BYTES + 1) }
            ?: fail("bundled $name schema is unavailable")
        if (bytes.size > MAXIMUM_SCHEMA_BYTES) fail("bundled $name schema exceeds its byte bound")
        digest.update(bytes)
    }
    return digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun externalFunctionId(name: String): String =
    "external-function-${OracleArtifacts.sha256(name.toByteArray(StandardCharsets.UTF_8)).take(32)}"

private fun requireDistinctInputs(paths: RawInputs) {
    val named = listOf(
        "scope" to paths.scope,
        "source lock" to paths.sourceLock,
        "artifact manifest" to paths.artifactManifest,
        "inventory" to paths.inventory,
        "function truth index" to paths.functionTruthRoot.toAbsolutePath().normalize().resolve("index.json"),
        "ELF function index" to paths.elfFunctionIndex,
        "call observation index" to paths.callObservationRoot.toAbsolutePath().normalize().resolve("index.json"),
    ).map { (label, path) -> label to path.toAbsolutePath().normalize() }
    named.forEachIndexed { index, (label, path) ->
        named.drop(index + 1).forEach { (otherLabel, otherPath) ->
            if (path == otherPath) fail("$label and $otherLabel must be distinct raw inputs")
        }
    }
}

private fun requireExactDirectoryMembership(path: Path, expectedNames: Set<String>, label: String) {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = try {
        Files.readAttributes(normalized, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw FullTreeCallTruthAssessmentException("$label is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || normalized.toRealPath() != normalized) {
        fail("$label must be a real non-symlink directory")
    }
    val actual = linkedSetOf<String>()
    try {
        Files.newDirectoryStream(normalized).use { entries ->
            entries.forEach { entry ->
                val name = entry.fileName?.toString() ?: fail("$label contains an unnamed member")
                if (!actual.add(name)) fail("$label contains duplicate membership")
                val member = Files.readAttributes(
                    entry,
                    java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (member.isSymbolicLink) fail("$label contains a symbolic link")
            }
        }
    } catch (failure: FullTreeCallTruthAssessmentException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeCallTruthAssessmentException("cannot enumerate $label", failure)
    }
    if (actual != expectedNames) fail("$label membership is missing or extra")
}

private fun parseAddress(value: String, label: String): ULong {
    if (!value.matches(ADDRESS)) fail("$label is not canonical unsigned 64-bit hexadecimal")
    return value.substring(2).toULongOrNull(16)
        ?: fail("$label exceeds unsigned 64-bit range")
}

private fun requireDigest(value: String, label: String) {
    if (!value.matches(SHA256)) fail("$label digest is invalid")
}

private fun addBounded(current: Long, addition: Long, maximum: Long, label: String): Long {
    val result = addExact(current, addition, label)
    if (result > maximum) fail("$label count exceeds the assessment bound")
    return result
}

private fun addExact(current: Long, addition: Long, label: String): Long = try {
    Math.addExact(current, addition)
} catch (failure: ArithmeticException) {
    throw FullTreeCallTruthAssessmentException("$label count overflows signed 64-bit arithmetic", failure)
}

private fun fail(message: String): Nothing = throw FullTreeCallTruthAssessmentException(message)

private fun JsonObject.callRequireKeys(expected: Set<String>, label: String) {
    if (keys != expected) fail("$label has unknown or missing fields")
}

private fun JsonObject.callElement(name: String, label: String): JsonElement =
    this[name] ?: fail("$label field $name is absent")

private fun JsonObject.callObject(name: String, label: String): JsonObject =
    callElement(name, label).callObject("$label.$name")

private fun JsonElement.callObject(label: String): JsonObject = this as? JsonObject
    ?: fail("$label is not an object")

private fun JsonObject.callArray(name: String, label: String): JsonArray =
    callElement(name, label) as? JsonArray ?: fail("$label.$name is not an array")

private fun JsonObject.callString(name: String, label: String): String =
    callElement(name, label).callString("$label.$name")

private fun JsonElement.callString(label: String): String {
    val primitive = this as? JsonPrimitive ?: fail("$label is not a string")
    if (!primitive.isString) fail("$label is not a string")
    return primitive.content
}

private fun JsonObject.callNullableString(name: String, label: String): String? {
    val value = callElement(name, label)
    if (value == JsonNull) return null
    return value.callString("$label.$name")
}

private fun JsonObject.callLong(name: String, label: String): Long {
    val primitive = callElement(name, label) as? JsonPrimitive ?: fail("$label.$name is not an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) fail("$label.$name is not an integer")
    return primitive.longOrNull ?: fail("$label.$name exceeds signed 64-bit integer range")
}

private fun JsonObject.callBoolean(name: String, label: String): Boolean {
    val primitive = callElement(name, label) as? JsonPrimitive ?: fail("$label.$name is not a Boolean")
    return primitive.booleanOrNull ?: fail("$label.$name is not a Boolean")
}

private fun JsonObject.callNonNegativeDouble(name: String, label: String): Double {
    val primitive = callElement(name, label) as? JsonPrimitive ?: fail("$label.$name is not a number")
    if (primitive.isString) fail("$label.$name is not a number")
    val value = primitive.doubleOrNull ?: fail("$label.$name is not a finite number")
    if (!value.isFinite() || value < 0.0) fail("$label.$name is not a finite non-negative number")
    return value
}

private fun Observation.signature(): String = OracleJson.canonicalBytes(
    JsonObject(
        mapOf(
            "callerId" to callerId.jsonNullable(),
            "callerLocalReturnOffset" to callerLocalReturnOffset.jsonNullable(),
            "dispatchKind" to JsonPrimitive(target.dispatchKind),
            "functionId" to target.functionId.jsonNullable(),
            "aliases" to JsonArray(target.aliases.map(::JsonPrimitive)),
            "population" to JsonPrimitive(population),
            "provenFunctionIds" to JsonArray(target.provenFunctionIds.map(::JsonPrimitive)),
            "reasonCode" to reasonCode.jsonNullable(),
            "returnPcRva" to returnPcRva.jsonNullable(),
            "tailCall" to JsonPrimitive(tailCall),
            "targetEvidence" to JsonPrimitive(target.targetEvidence),
            "targetKind" to JsonPrimitive(target.kind),
        ),
    ),
).decodeToString()

private data class RawInputs(
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
    val inventory: Path,
    val functionTruthRoot: Path,
    val elfFunctionIndex: Path,
    val callObservationRoot: Path,
)

private data class DerivedState(
    val scopeSha256: String,
    val inventorySha256: String,
    val functionTruthIndexSha256: String,
    val elfFunctionIndexSha256: String,
    val callObservationIndexSha256: String,
    val shards: List<DiagnosticShard>,
    val assessmentSha256: String,
)

private data class FunctionState(
    val indexSha256: String,
    val functions: Map<String, FunctionRecord>,
    val aliases: Map<String, Set<String>>,
)

private data class FunctionRecord(val ownerShard: String, val kind: String)
private data class ObservationState(val indexSha256: String, val observations: List<Observation>)

private data class UsageRecord(
    val document: JsonObject,
    val bytes: ByteArray,
    val maximumResidentBytes: Long,
    val userCpuSeconds: Double,
    val systemCpuSeconds: Double,
    val wallClockSeconds: Double,
    val entities: Long,
    val serializedBytes: Long,
)

private data class Observation(
    val id: String,
    val sourceShard: String,
    val population: String,
    val reasonCode: String?,
    val callerId: String?,
    val callerLocalReturnOffset: String?,
    val returnPcRva: String?,
    val tailCall: Boolean,
    val target: Target,
)

private data class Target(
    val kind: String,
    val dispatchKind: String,
    val functionId: String?,
    val aliases: List<String>,
    val provenFunctionIds: List<String>,
    val targetEvidence: String,
)

private data class Edge(
    val id: String,
    val observationIds: List<String>,
    val callerId: String?,
    val callerLocalReturnOffset: String?,
    val returnPcRva: String?,
    val targetKind: String,
    val dispatchKind: String,
    val physicalTargetId: String?,
    val semanticTargetId: String?,
    val externalTargetIds: List<String>,
    val provenTargetIds: List<String>,
    val population: String,
    val reasonCode: String?,
    val tailCall: Boolean,
    val targetEvidence: String,
)

private data class DiagnosticShard(
    val id: String,
    val calls: List<Edge>,
    val canonicalBytes: ByteArray = byteArrayOf(),
)

private data class Counts(
    val edges: Long = 0,
    val observations: Long = 0,
    val directInternal: Long = 0,
    val external: Long = 0,
    val indirectProven: Long = 0,
    val indirectUnresolved: Long = 0,
    val virtualUnresolved: Long = 0,
    val tailCalls: Long = 0,
    val unobservable: Long = 0,
)

private const val NON_AUTHORITY = "non-authoritative-bounded-kotlin-call-semantics-fixture-assessment"
private const val MAXIMUM_SCHEMA_BYTES = 1024 * 1024
private const val CALL_ASSESSMENT_MAXIMUM_INDEX_BYTES = 16 * 1024 * 1024
private const val CALL_ASSESSMENT_MAXIMUM_SHARD_BYTES = 64 * 1024 * 1024
private const val CALL_ASSESSMENT_MAXIMUM_SHARDS = 16_384
private const val CALL_ASSESSMENT_MAXIMUM_FUNCTIONS = 2_500_000L
private const val CALL_ASSESSMENT_MAXIMUM_OBSERVATIONS = 2_500_000L
private const val CALL_ASSESSMENT_MAXIMUM_ALIASES = 10_000_000L
private const val CALL_ASSESSMENT_MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024 * 1024
private val MISSING_AUTHORITIES: List<String> = Collections.unmodifiableList(
    listOf(
        "kotlin-full-tree-function-truth-producer",
        "kotlin-dwarf-call-observation-producer",
        "kotlin-contained-whole-process-tree-call-observation-runtime-receipt",
        "kotlin-scalable-sqlite-sharded-call-truth-producer",
    ),
)
private val CALL_OBSERVATION_ROOT_MEMBERS = setOf("control", "execution-evidence.json", "usage")
private val ELF_ORACLE_FIELDS = setOf("configurationSha256", "inventoryIndexSha256", "scopeSha256")
private val FUNCTION_ORACLE_FIELDS = setOf(
    "configurationSha256",
    "elfIndexSha256",
    "inventoryIndexSha256",
    "observationIndexSha256",
    "scopeSha256",
)
private val USAGE_FIELDS = setOf(
    "entities",
    "id",
    "inputSha256",
    "maximumResidentBytes",
    "outputSha256",
    "serializedBytes",
    "systemCpuSeconds",
    "userCpuSeconds",
    "wallClockSeconds",
)
private val EXECUTION_OBSERVED_FIELDS = setOf(
    "entities",
    "maximumResidentBytes",
    "serializedBytes",
    "systemCpuSeconds",
    "userCpuSeconds",
    "wallClockSeconds",
)
private val SHA256 = Regex("[0-9a-f]{64}")
private val ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val ASSESSMENT_DIGEST_DOMAIN =
    "bounded-call-semantics-fixture-assessment-v1\u0000".toByteArray(StandardCharsets.UTF_8)

private val FUNCTION_TRUTH_POLICY = JsonObject(
    mapOf(
        "elfOnlyPopulation" to JsonPrimitive("excluded-elf-no-source-aligned-dwarf"),
        "emittedIdentity" to JsonPrimitive("one-record-per-rva"),
        "id" to JsonPrimitive("full-tree-function-truth"),
        "nonEmissionPolicy" to JsonPrimitive("inline-or-definition-without-range-and-emitted-alias-reconciliation"),
        "nonEmittedIdentity" to JsonPrimitive("declaration-and-alias-name-sha256-prefix-128"),
        "ownerSelection" to JsonPrimitive("lowest-source-aligned-unit-id"),
        "version" to JsonPrimitive(2),
    ),
)

private val CALL_TRUTH_POLICY = JsonObject(
    mapOf(
        "dispatchPolicy" to JsonPrimitive("direct-virtual-indirect-preserved-without-name-inference"),
        "externalNamespace" to JsonPrimitive("exact-undefined-elf-function-name"),
        "id" to JsonPrimitive("full-tree-call-truth"),
        "identity" to JsonPrimitive("caller-id-and-return-pc-rva"),
        "thunkPolicy" to JsonPrimitive("physical-target-retained-semantic-target-explicitly-unresolved"),
        "version" to JsonPrimitive(2),
    ),
)

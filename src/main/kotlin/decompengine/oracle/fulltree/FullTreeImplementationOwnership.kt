package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Collections
import java.util.LinkedHashMap
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeImplementationOwnershipException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable ceilings beneath the immutable historical-projection v1 policy. */
data class FullTreeImplementationOwnershipLimits(
    val planning: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    val maximumTruthIndexBytes: Int = OWNERSHIP_MAXIMUM_TRUTH_INDEX_BYTES,
    val maximumBaselineBytes: Int = OWNERSHIP_MAXIMUM_BASELINE_BYTES,
    val maximumTruthShardBytes: Long = OWNERSHIP_MAXIMUM_TRUTH_SHARD_BYTES,
    val maximumTruthBytes: Long = OWNERSHIP_MAXIMUM_TRUTH_BYTES,
    val maximumTruthShards: Int = OWNERSHIP_MAXIMUM_TRUTH_SHARDS,
    val maximumImplementations: Long = OWNERSHIP_MAXIMUM_IMPLEMENTATIONS,
    val maximumInlineDeclarations: Long = OWNERSHIP_MAXIMUM_INLINE_DECLARATIONS,
    val maximumWorkUnits: Long = OWNERSHIP_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = OWNERSHIP_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumTruthIndexBytes in 1..OWNERSHIP_MAXIMUM_TRUTH_INDEX_BYTES)
        require(maximumBaselineBytes in 1..OWNERSHIP_MAXIMUM_BASELINE_BYTES)
        require(maximumTruthShardBytes in 1L..OWNERSHIP_MAXIMUM_TRUTH_SHARD_BYTES)
        require(maximumTruthBytes in 1L..OWNERSHIP_MAXIMUM_TRUTH_BYTES)
        require(maximumTruthShards in 1..OWNERSHIP_MAXIMUM_TRUTH_SHARDS)
        require(maximumImplementations in 1L..OWNERSHIP_MAXIMUM_IMPLEMENTATIONS)
        require(maximumInlineDeclarations in 1L..OWNERSHIP_MAXIMUM_INLINE_DECLARATIONS)
        require(maximumWorkUnits in 1L..OWNERSHIP_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..OWNERSHIP_MAXIMUM_SERIALIZED_BYTES)
    }
}

/** Immutable, explicitly non-authoritative planning result. */
sealed interface FullTreeImplementationOwnershipAssessment {
    val reportSha256: String
    val recoveredImplementations: Long
    val missingImplementations: Long
    val canonicalBytes: ByteArray
}

/**
 * Bounded Kotlin/JVM projection of the published historical A13-v2 function population onto the
 * authenticated A14 source-module inventory.
 *
 * This API is intentionally not an oracle. It does not regenerate function truth, authenticate
 * the historical release container, infer headers or dependencies, construct source, score a
 * candidate, publish an artifact, or authorize a release. Its result is a digest-bound planning
 * assessment of caller-supplied historical artifacts in the fixed inline-only-v1 format.
 */
object FullTreeImplementationOwnership {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-implementation-ownership", OWNERSHIP_POLICY)
    }

    fun assessHistoricalA13V2(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        functionTruthIndexPath: Path,
        functionBaselinePath: Path,
        limits: FullTreeImplementationOwnershipLimits = FullTreeImplementationOwnershipLimits(),
    ): FullTreeImplementationOwnershipAssessment = try {
        ValidatedAssessment.create(
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            functionTruthIndexPath,
            functionBaselinePath,
            limits,
        )
    } catch (failure: FullTreeImplementationOwnershipException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeImplementationOwnershipException(
            "historical full-tree implementation ownership assessment failed: ${failure.message}",
            failure,
        )
    }

    private class ValidatedAssessment private constructor(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        functionTruthIndexPath: Path,
        functionBaselinePath: Path,
        limits: FullTreeImplementationOwnershipLimits,
    ) : FullTreeImplementationOwnershipAssessment {
        private val state = assessOwnership(
            OwnershipPaths(
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                functionTruthIndexPath,
                functionBaselinePath,
            ),
            limits,
        )
        override val reportSha256: String = state.reportSha256
        override val recoveredImplementations: Long = state.recovered
        override val missingImplementations: Long = state.missing
        override val canonicalBytes: ByteArray
            get() = state.bytes.copyOf()

        companion object {
            fun create(
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                planningInventoryPath: Path,
                functionTruthIndexPath: Path,
                functionBaselinePath: Path,
                limits: FullTreeImplementationOwnershipLimits,
            ): FullTreeImplementationOwnershipAssessment = ValidatedAssessment(
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                functionTruthIndexPath,
                functionBaselinePath,
                limits,
            )
        }
    }
}

private fun assessOwnership(
    paths: OwnershipPaths,
    limits: FullTreeImplementationOwnershipLimits,
): OwnershipAssessmentState {
    requireDistinctOwnershipInputs(paths)
    val registry = loadPlanningRegistry(paths, limits)
    val (planningDocument, planningBytes) = readCanonicalControlObject(
        paths.planningInventory,
        limits.planning.maximumSerializedBytes,
        "full-tree planning inventory",
        "full-tree-planning-inventory",
    )
    val planningArtifactSha256 = OracleArtifacts.sha256(planningBytes)
    if (planningArtifactSha256 != registry.artifactSha256) {
        ownershipFailure("planning inventory changed after authenticated registry admission")
    }
    val planningOracle = planningDocument.controlObject("oracle")

    val sourceOnlyUnitIds = HashSet<String>()
    val sourceOnlyCommitment = IdCommitment("source-only", "source-path")
    var previousSourceOnlyPath: String? = null
    registry.sourceOnlyUnits.forEach { sourceOnly ->
        val precedingSourceOnlyPath = previousSourceOnlyPath
        if (precedingSourceOnlyPath != null &&
            FULL_TREE_CODE_POINT_ORDER.compare(precedingSourceOnlyPath, sourceOnly.sourcePath) >= 0
        ) {
            ownershipFailure("planning source-only paths are not strictly ordered")
        }
        previousSourceOnlyPath = sourceOnly.sourcePath
        sourceOnlyCommitment.add(sourceOnly.sourcePath)
        val unitId = FullTreeInventoryControl.compilationUnitId(sourceOnly.sourcePath)
        if (!sourceOnlyUnitIds.add(unitId)) ownershipFailure("source-only unit identities collide")
    }

    val modules = LinkedHashMap<String, ModuleAccumulator>()
    val modulesByShard = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
    registry.sourceModules.forEach { module ->
        if (module.moduleId != module.unitId || !module.unitId.matches(UNIT_ID)) {
            ownershipFailure("planning registry contains a non-source-bound module identity")
        }
        if (module.unitId in sourceOnlyUnitIds) {
            ownershipFailure("planning module identity collides with source-only evidence")
        }
        if (modules.put(module.unitId, ModuleAccumulator(module)) != null) {
            ownershipFailure("planning registry repeats a module owner")
        }
        modulesByShard.computeIfAbsent(module.shardId) { arrayListOf() }.add(module.unitId)
    }
    if (modules.isEmpty()) ownershipFailure("planning registry has no source modules")
    modulesByShard.values.forEach { it.sortWith(FULL_TREE_CODE_POINT_ORDER) }

    val truthIndex = readHistoricalTruthIndex(
        paths.functionTruthIndex,
        planningOracle,
        modulesByShard,
        limits,
    )
    val baseline = readHistoricalBaseline(paths.functionBaseline, truthIndex.sourceSha256, limits)

    val inputIdentities = HashSet<Any>()
    paths.fixedInputs().forEach { path -> registerUniqueInputIdentity(path, inputIdentities) }
    truthIndex.allPaths.forEach { path -> registerUniqueInputIdentity(path, inputIdentities) }

    var totalTruthBytes = addOwnershipCount(
        truthIndex.sourceBytes,
        baseline.sourceBytes,
        "historical input byte",
    )
    truthIndex.records.forEach { record ->
        totalTruthBytes = addOwnershipCount(totalTruthBytes, record.bytes, "historical input byte")
    }
    totalTruthBytes = addOwnershipCount(
        totalTruthBytes,
        truthIndex.exclusions.bytes,
        "historical input byte",
    )
    if (totalTruthBytes > limits.maximumTruthBytes || totalTruthBytes > OWNERSHIP_MAXIMUM_TRUTH_BYTES) {
        ownershipFailure("historical function inputs exceed the aggregate byte bound")
    }

    val indexedEmitted = truthIndex.records.fold(0L) { total, record ->
        addOwnershipCount(total, record.functions, "indexed emitted implementation")
    }
    val indexedInlineOnly = truthIndex.records.fold(0L) { total, record ->
        addOwnershipCount(total, record.inlineOnly, "indexed inline-only declaration")
    }
    if (indexedEmitted > limits.maximumImplementations ||
        indexedInlineOnly > limits.maximumInlineDeclarations
    ) {
        ownershipFailure("historical function truth descriptors exceed configured entity bounds")
    }

    val workUnits = ownershipWorkUnits(
        registry = registry,
        index = truthIndex,
        baseline = baseline,
        emitted = indexedEmitted,
        inlineOnly = indexedInlineOnly,
        ownerlessExcluded = truthIndex.exclusions.functions,
        outputModules = modules.size,
    )
    if (workUnits > limits.maximumWorkUnits || workUnits > OWNERSHIP_MAXIMUM_WORK_UNITS) {
        ownershipFailure("implementation ownership projection exceeds its work-unit bound")
    }

    val context = ProjectionContext(
        modules = modules,
        sourceOnlyUnitIds = sourceOnlyUnitIds,
        missingByTruthId = baseline.missingByTruthId.toMutableMap(),
        limits = limits,
    )
    truthIndex.records.forEach { record ->
        streamHistoricalTruthShard(record, truthIndex.oracle, modulesByShard.getValue(record.id), baseline, context)
    }
    streamHistoricalExclusions(truthIndex.exclusions, truthIndex.oracle, context)
    if (context.missingByTruthId.isNotEmpty()) {
        ownershipFailure("baseline missing records do not resolve to historical truth implementations")
    }

    validateTruthTotals(truthIndex, context)
    validateBaselineTotals(baseline, truthIndex, context)
    val reconciledWorkUnits = ownershipWorkUnits(
        registry = registry,
        index = truthIndex,
        baseline = baseline,
        emitted = context.emitted,
        inlineOnly = context.inlineOnly,
        ownerlessExcluded = context.ownerlessExcluded,
        outputModules = modules.size,
    )
    if (reconciledWorkUnits != workUnits) {
        ownershipFailure("implementation ownership work units do not reconcile with streamed truth")
    }

    val document = buildOwnershipDocument(
        registry,
        planningOracle,
        truthIndex,
        baseline,
        modules.values.toList(),
        sourceOnlyCommitment,
        context,
        workUnits,
    )
    val bytes = canonicalOwnershipBytes(document, limits.maximumSerializedBytes)
    validateOwnershipSchema(document)

    terminalReauthenticate(paths, limits, registry, truthIndex, baseline)
    return OwnershipAssessmentState(
        reportSha256 = document.controlString("reportSha256"),
        recovered = context.recovered,
        missing = context.missing,
        bytes = bytes.copyOf(),
    )
}

private fun loadPlanningRegistry(
    paths: OwnershipPaths,
    limits: FullTreeImplementationOwnershipLimits,
): AuthenticatedFullTreePlanningRegistry = FullTreePlanningInventoryControl.loadAndValidate(
    paths.planningInventory,
    paths.scope,
    paths.sourceLock,
    paths.artifactManifest,
    paths.buildRecord,
    paths.inventory,
    paths.sourceInventory,
    limits.planning,
)

private fun readHistoricalTruthIndex(
    path: Path,
    planningOracle: JsonObject,
    modulesByShard: Map<String, List<String>>,
    limits: FullTreeImplementationOwnershipLimits,
): HistoricalTruthIndex {
    val normalized = path.toAbsolutePath().normalize()
    if (normalized.fileName?.toString() != "index.json" || normalized.parent == null) {
        ownershipFailure("historical function truth index must be named index.json")
    }
    val rootIdentity = ownershipDirectoryIdentity(normalized.parent, "historical function truth root")
    val sourceSha256 = stableOwnershipSha256(
        normalized,
        limits.maximumTruthIndexBytes.toLong(),
        "historical function truth index",
    )
    val records = arrayListOf<HistoricalFileRecord>()
    val streamed = FullTreeCanonicalStreaming.readObject(
        normalized,
        "historical function truth index",
        sourceSha256,
        INDEX_FIELD_ORDER,
        setOf("shards"),
        "indexSha256",
        streamingLimits(
            limits.maximumTruthIndexBytes.toLong(),
            maximumEntities = limits.maximumTruthShards.toLong(),
            maximumEntityBytes = 64 * 1024,
        ),
    ) { field, _, value, _ ->
        if (field != "shards") ownershipFailure("truth index exposed an unexpected streamed field")
        records += parseHistoricalFileRecord(value, exclusion = false, limits)
    }
    val envelope = streamed.envelope
    requireExactKeys(envelope, INDEX_KEYS, "historical function truth index")
    requireInteger(envelope, "schemaVersion", 1L, "historical function truth index")
    requireBoolean(envelope, "complete", true, "historical function truth index")
    val oracle = validateHistoricalTruthOracle(envelope.controlObject("oracle"), planningOracle)
    val counts = validateHistoricalTruthCounts(envelope.controlObject("counts"), limits)
    val exclusions = parseHistoricalFileRecord(envelope.controlObject("exclusions"), exclusion = true, limits)
    val logicalSha256 = envelope.controlString("indexSha256")
    requireDigest(logicalSha256, "historical function truth index logical")
    if (logicalSha256 != streamed.canonicalWithoutOmittedFieldSha256) {
        ownershipFailure("historical function truth index hash does not reconcile")
    }
    if (records.isEmpty() || records.size > limits.maximumTruthShards) {
        ownershipFailure("historical function truth index exceeds its shard bound")
    }
    val expectedShardIds = modulesByShard.keys.toList()
    if (records.map { it.id } != expectedShardIds) {
        ownershipFailure("historical function truth shards differ from planning subsystem boundaries")
    }
    val seenPaths = HashSet<Path>()
    records.forEach { record ->
        val expectedRelative = "shards/${record.id}.json"
        if (record.pathText != expectedRelative) {
            ownershipFailure("historical function truth shard path is not fixed by its shard ID")
        }
        val resolved = normalized.parent.resolve(record.pathText).normalize()
        if (!resolved.startsWith(normalized.parent) || !seenPaths.add(resolved)) {
            ownershipFailure("historical function truth shard paths escape or alias their root")
        }
        record.path = resolved
    }
    if (exclusions.id != HISTORICAL_EXCLUSION_SHARD ||
        exclusions.pathText != "exclusions.json" || exclusions.inlineOnly != 0L
    ) {
        ownershipFailure("historical function exclusions descriptor is unsupported")
    }
    exclusions.path = normalized.parent.resolve("exclusions.json").normalize()
    if (!seenPaths.add(exclusions.path)) ownershipFailure("historical exclusions alias a truth shard")
    val shardsIdentity = ownershipDirectoryIdentity(
        normalized.parent.resolve("shards"),
        "historical function truth shards",
    )
    return HistoricalTruthIndex(
        path = normalized,
        rootIdentity = rootIdentity,
        shardsIdentity = shardsIdentity,
        sourceSha256 = streamed.sourceSha256,
        sourceBytes = streamed.sourceBytes,
        logicalSha256 = logicalSha256,
        oracle = oracle,
        counts = counts,
        records = Collections.unmodifiableList(records),
        exclusions = exclusions,
    )
}

private fun readHistoricalBaseline(
    path: Path,
    truthArtifactSha256: String,
    limits: FullTreeImplementationOwnershipLimits,
): HistoricalBaseline {
    val normalized = path.toAbsolutePath().normalize()
    val sourceSha256 = stableOwnershipSha256(
        normalized,
        limits.maximumBaselineBytes.toLong(),
        "historical function baseline",
    )
    val missingByTruthId = LinkedHashMap<String, String>()
    val metrics = TreeMap<String, FunctionMetric>(FULL_TREE_CODE_POINT_ORDER)
    var previousMismatchId: String? = null
    var previousMetricId: String? = null
    var mismatchCount = 0L
    val streamed = FullTreeCanonicalStreaming.readObject(
        normalized,
        "historical function baseline",
        sourceSha256,
        BASELINE_FIELD_ORDER,
        setOf("mismatches", "shards"),
        "reportSha256",
        streamingLimits(
            limits.maximumBaselineBytes.toLong(),
            maximumEntities = addOwnershipCount(
                limits.maximumImplementations,
                limits.maximumTruthShards.toLong() + 1L,
                "baseline entity bound",
            ),
            maximumEntityBytes = 64 * 1024,
        ),
    ) { field, _, value, _ ->
        when (field) {
            "mismatches" -> {
                requireExactKeys(value, BASELINE_MISMATCH_KEYS, "historical baseline mismatch")
                val kind = value.controlString("kind")
                if (kind != "missing") {
                    ownershipFailure("historical ownership planning rejects fabricated baseline records")
                }
                val truthId = value.controlString("truthId")
                requireFunctionId(truthId, "historical baseline truth")
                val shardId = requireNullableString(value, "shardId", "historical baseline mismatch")
                    ?: ownershipFailure("historical missing implementation has no shard owner")
                requireShardId(shardId, "historical baseline mismatch")
                val expectedMismatchId = baselineMismatchId(kind, truthId)
                val mismatchId = value.controlString("id")
                if (mismatchId != expectedMismatchId) {
                    ownershipFailure("historical baseline mismatch identity does not reconcile")
                }
                val precedingMismatchId = previousMismatchId
                if (precedingMismatchId != null &&
                    FULL_TREE_CODE_POINT_ORDER.compare(precedingMismatchId, mismatchId) >= 0
                ) {
                    ownershipFailure("historical baseline mismatches are not strictly ordered")
                }
                previousMismatchId = mismatchId
                if (missingByTruthId.put(truthId, shardId) != null) {
                    ownershipFailure("historical baseline duplicates a missing truth implementation")
                }
                mismatchCount = incrementOwnership(mismatchCount, "historical baseline mismatch")
                if (mismatchCount > limits.maximumImplementations) {
                    ownershipFailure("historical baseline exceeds the implementation bound")
                }
            }
            "shards" -> {
                requireExactKeys(value, BASELINE_SHARD_KEYS, "historical baseline shard metric")
                val id = value.controlString("id")
                requireShardId(id, "historical baseline shard metric", allowExclusions = true)
                val precedingMetricId = previousMetricId
                if (precedingMetricId != null &&
                    FULL_TREE_CODE_POINT_ORDER.compare(precedingMetricId, id) >= 0
                ) {
                    ownershipFailure("historical baseline shard metrics are not strictly ordered")
                }
                previousMetricId = id
                val metric = parseMetric(value.controlObject("metric"), "historical baseline shard metric")
                if (metrics.put(id, metric) != null) {
                    ownershipFailure("historical baseline repeats a shard metric")
                }
            }
            else -> ownershipFailure("historical baseline exposed an unexpected streamed field")
        }
    }
    val envelope = streamed.envelope
    requireExactKeys(envelope, BASELINE_KEYS, "historical function baseline")
    requireInteger(envelope, "schemaVersion", 1L, "historical function baseline")
    if (envelope.controlString("truthIndexSha256") != truthArtifactSha256) {
        ownershipFailure("historical function baseline is not bound to the supplied truth index artifact")
    }
    val configurationSha256 = envelope.controlString("configurationSha256")
    if (configurationSha256 != HISTORICAL_BASELINE_CONFIGURATION_SHA256) {
        ownershipFailure("historical function baseline configuration is not the checked v1 contract")
    }
    val reportSha256 = envelope.controlString("reportSha256")
    requireDigest(reportSha256, "historical function baseline report")
    if (reportSha256 != streamed.canonicalWithoutOmittedFieldSha256) {
        ownershipFailure("historical function baseline report hash does not reconcile")
    }
    val aggregate = parseMetric(envelope.controlObject("aggregate"), "historical baseline aggregate")
    val summed = metrics.values.fold(FunctionMetric.ZERO) { total, metric -> total + metric }
    if (aggregate != summed) ownershipFailure("historical baseline aggregate does not reconcile")
    if (aggregate.fabricated != 0L) {
        ownershipFailure("historical ownership planning does not accept fabricated implementations")
    }
    return HistoricalBaseline(
        path = normalized,
        sourceSha256 = streamed.sourceSha256,
        sourceBytes = streamed.sourceBytes,
        configurationSha256 = configurationSha256,
        reportSha256 = reportSha256,
        aggregate = aggregate,
        metrics = Collections.unmodifiableMap(metrics),
        missingByTruthId = Collections.unmodifiableMap(missingByTruthId),
        mismatchCount = mismatchCount,
    )
}

private fun streamHistoricalTruthShard(
    record: HistoricalFileRecord,
    expectedOracle: JsonObject,
    expectedUnitIds: List<String>,
    baseline: HistoricalBaseline,
    context: ProjectionContext,
) {
    val shardState = ShardProjectionState(record.id)
    val streamed = FullTreeCanonicalStreaming.readObject(
        record.path,
        "historical function truth shard ${record.id}",
        record.sha256,
        TRUTH_SHARD_FIELD_ORDER,
        setOf("functions", "inlineOnly"),
        omittedDigestField = null,
        limits = streamingLimits(
            minOf(record.bytes, context.limits.maximumTruthShardBytes),
            maximumEntities = addOwnershipCount(
                record.functions,
                record.inlineOnly,
                "truth shard entity bound",
            ),
            maximumEntityBytes = OWNERSHIP_MAXIMUM_ENTITY_BYTES,
        ),
    ) { field, _, value, canonical ->
        when (field) {
            "functions" -> consumeHistoricalFunction(value, canonical, record.id, shardState, context)
            "inlineOnly" -> consumeHistoricalInline(value, canonical, record.id, shardState, context)
            else -> ownershipFailure("truth shard exposed an unexpected streamed field")
        }
    }
    if (streamed.sourceBytes != record.bytes) {
        ownershipFailure("historical function truth shard byte count differs from its index")
    }
    val envelope = streamed.envelope
    requireExactKeys(envelope, TRUTH_SHARD_KEYS, "historical function truth shard")
    requireInteger(envelope, "schemaVersion", 1L, "historical function truth shard")
    if (envelope.controlObject("oracle") != expectedOracle) {
        ownershipFailure("historical function truth shard oracle binding differs from its index")
    }
    val shard = envelope.controlObject("shard")
    requireExactKeys(shard, TRUTH_SHARD_DESCRIPTOR_KEYS, "historical truth shard descriptor")
    if (shard.controlString("id") != record.id) {
        ownershipFailure("historical truth shard identity differs from its index")
    }
    val unitIds = requireStringArray(shard, "unitIds", "historical truth shard units")
    if (unitIds != expectedUnitIds) {
        ownershipFailure("historical truth shard unit boundary differs from the planning inventory")
    }
    val counts = envelope.controlObject("counts")
    requireExactKeys(counts, TRUTH_SHARD_COUNT_KEYS, "historical truth shard counts")
    if (counts.controlLong("functions") != shardState.functions ||
        counts.controlLong("inlineOnly") != shardState.inlineOnly ||
        record.functions != shardState.functions || record.inlineOnly != shardState.inlineOnly
    ) {
        ownershipFailure("historical truth shard counts do not reconcile")
    }
    val expectedMetric = baseline.metrics[record.id]
        ?: ownershipFailure("historical baseline omits truth shard ${record.id}")
    if (expectedMetric != shardState.metric()) {
        ownershipFailure("historical baseline metric differs from truth shard ${record.id}")
    }
}

private fun consumeHistoricalFunction(
    value: JsonObject,
    canonical: ByteArray,
    shardId: String,
    shardState: ShardProjectionState,
    context: ProjectionContext,
) {
    if (canonical.size > OWNERSHIP_MAXIMUM_ENTITY_BYTES) {
        ownershipFailure("historical function entity exceeds its byte bound")
    }
    requireExactKeys(value, HISTORICAL_FUNCTION_KEYS, "historical function truth record")
    val rvaText = value.controlString("rva")
    val rva = parseRva(rvaText, "historical function truth")
    val id = value.controlString("id")
    requireFunctionId(id, "historical function truth")
    if (id != "function-rva-$rvaText") {
        ownershipFailure("historical function identity differs from its RVA")
    }
    val previousRva = shardState.previousRva
    if (previousRva != null && rva <= previousRva) {
        ownershipFailure("historical truth functions are not strictly RVA ordered")
    }
    shardState.previousRva = rva
    if (!context.seenRvas.add(rva)) {
        ownershipFailure("historical function RVA has duplicate ownership")
    }
    val ownerUnitId = value.controlString("ownerUnitId")
    val owner = context.requireModule(ownerUnitId, "historical function owner")
    if (owner.module.shardId != shardId) {
        ownershipFailure("historical function owner crosses its A13 shard boundary")
    }
    val candidates = requireStringArray(value, "ownershipCandidates", "historical ownership candidates")
    if (candidates.isEmpty() || candidates.distinct().size != candidates.size ||
        candidates != candidates.sortedWith(FULL_TREE_CODE_POINT_ORDER)
    ) {
        ownershipFailure("historical ownership candidates are empty, repeated, or unordered")
    }
    candidates.forEach { context.requireModule(it, "historical ownership candidate") }
    if (ownerUnitId != candidates.first()) {
        ownershipFailure("historical function owner is not the lowest authenticated candidate")
    }
    val aliasFacts = validateAliases(value.controlArray("aliases"), context, "historical function aliases")
    validateDeclarations(value.controlArray("declarations"), "historical function declarations")
    val entityKind = value.controlString("entityKind")
    val expectedKind = if (aliasFacts.hasThunkName) "thunk" else "function"
    if (entityKind != expectedKind) ownershipFailure("historical function/thunk classification differs")

    val population = value.controlString("population")
    val reason = requireNullableString(value, "reasonCode", "historical function truth")
    val missingShard = context.missingByTruthId.remove(id)
    when (population) {
        "scored" -> {
            if (reason != null) ownershipFailure("scored historical function has an exclusion reason")
            val isMissing = !aliasFacts.survivesInStrippedArtifact
            if (isMissing != (missingShard != null) || missingShard?.let { it != shardId } == true) {
                ownershipFailure("historical baseline survival classification differs from truth evidence")
            }
            owner.addScored(id, isMissing)
            shardState.addScored(isMissing)
            if (isMissing) context.missing = incrementOwnership(context.missing, "missing implementation")
            else context.recovered = incrementOwnership(context.recovered, "recovered implementation")
            context.scored = incrementOwnership(context.scored, "scored implementation")
        }
        "excluded" -> {
            if (reason != "dwarf-rva-without-elf-function" || missingShard != null) {
                ownershipFailure("owned historical exclusion classification is inconsistent")
            }
            owner.addExcluded(id)
            shardState.addExcluded()
            context.ownedExcluded = incrementOwnership(context.ownedExcluded, "owned excluded implementation")
        }
        else -> ownershipFailure("historical function population is unsupported")
    }
    context.emitted = incrementOwnership(context.emitted, "emitted implementation")
    if (context.emitted > context.limits.maximumImplementations) {
        ownershipFailure("historical truth exceeds the implementation bound")
    }
    shardState.functions = incrementOwnership(shardState.functions, "truth shard function")
}

private fun consumeHistoricalInline(
    value: JsonObject,
    canonical: ByteArray,
    shardId: String,
    shardState: ShardProjectionState,
    context: ProjectionContext,
) {
    if (canonical.size > OWNERSHIP_MAXIMUM_ENTITY_BYTES) {
        ownershipFailure("historical inline entity exceeds its byte bound")
    }
    requireExactKeys(value, HISTORICAL_INLINE_KEYS, "historical inline-only record")
    val id = value.controlString("id")
    if (!id.matches(INLINE_ID)) ownershipFailure("historical inline-only identity is invalid")
    val previousInlineId = shardState.previousInlineId
    if (previousInlineId != null &&
        FULL_TREE_CODE_POINT_ORDER.compare(previousInlineId, id) >= 0
    ) {
        ownershipFailure("historical inline-only records are not strictly ordered")
    }
    shardState.previousInlineId = id
    if (!context.seenInlineIds.add(id)) {
        ownershipFailure("historical inline-only identity has duplicate ownership")
    }
    if (value.controlString("population") != "unobservable" ||
        value.controlString("reasonCode") != "inline-no-emitted-range"
    ) {
        ownershipFailure("historical inline-only population is inconsistent")
    }
    val owner = context.requireModule(value.controlString("ownerUnitId"), "historical inline-only owner")
    if (owner.module.shardId != shardId) {
        ownershipFailure("historical inline-only owner crosses its A13 shard boundary")
    }
    validateAliases(value.controlArray("aliases"), context, "historical inline-only aliases")
    validateDeclarations(value.controlArray("declarations"), "historical inline-only declarations")
    val observations = requireStringArray(value, "observationIds", "historical inline observation IDs")
    if (observations.isEmpty() || observations.distinct().size != observations.size) {
        ownershipFailure("historical inline-only record has empty or duplicate observations")
    }
    owner.addInline(id)
    shardState.inlineOnly = incrementOwnership(shardState.inlineOnly, "inline-only declaration")
    context.inlineOnly = incrementOwnership(context.inlineOnly, "inline-only declaration")
    context.inlineObservations = addOwnershipCount(
        context.inlineObservations,
        observations.size.toLong(),
        "inline observation",
    )
    if (context.inlineOnly > context.limits.maximumInlineDeclarations) {
        ownershipFailure("historical truth exceeds the inline-declaration bound")
    }
}

private fun streamHistoricalExclusions(
    record: HistoricalFileRecord,
    expectedOracle: JsonObject,
    context: ProjectionContext,
) {
    var previousRva: ULong? = null
    var count = 0L
    val streamed = FullTreeCanonicalStreaming.readObject(
        record.path,
        "historical function truth exclusions",
        record.sha256,
        EXCLUSION_FIELD_ORDER,
        setOf("functions"),
        omittedDigestField = null,
        limits = streamingLimits(
            minOf(record.bytes, context.limits.maximumTruthShardBytes),
            maximumEntities = record.functions,
            maximumEntityBytes = OWNERSHIP_MAXIMUM_ENTITY_BYTES,
        ),
    ) { field, _, value, canonical ->
        if (field != "functions") ownershipFailure("exclusions exposed an unexpected streamed field")
        if (canonical.size > OWNERSHIP_MAXIMUM_ENTITY_BYTES) {
            ownershipFailure("ownerless exclusion exceeds its entity byte bound")
        }
        requireExactKeys(value, HISTORICAL_EXCLUSION_KEYS, "historical ownerless exclusion")
        val rvaText = value.controlString("rva")
        val rva = parseRva(rvaText, "historical ownerless exclusion")
        val id = value.controlString("id")
        requireFunctionId(id, "historical ownerless exclusion")
        if (id != "function-rva-$rvaText") {
            ownershipFailure("ownerless exclusion identity differs from its RVA")
        }
        val precedingRva = previousRva
        if (precedingRva != null && rva <= precedingRva) {
            ownershipFailure("ownerless exclusions are not strictly RVA ordered")
        }
        previousRva = rva
        if (!context.seenRvas.add(rva)) {
            ownershipFailure("ownerless exclusion duplicates an owned function RVA")
        }
        if (value.controlString("reasonCode") != "elf-no-source-aligned-dwarf") {
            ownershipFailure("ownerless exclusion has an unsupported reason")
        }
        validateAliases(value.controlArray("aliases"), context, "historical exclusion aliases")
        context.ownerlessExclusionCommitment.add(id)
        context.ownerlessExcluded = incrementOwnership(
            context.ownerlessExcluded,
            "ownerless excluded implementation",
        )
        count = incrementOwnership(count, "ownerless exclusion")
    }
    if (streamed.sourceBytes != record.bytes || count != record.functions) {
        ownershipFailure("historical ownerless exclusion count differs from its index")
    }
    val envelope = streamed.envelope
    requireExactKeys(envelope, EXCLUSION_KEYS, "historical function truth exclusions")
    requireInteger(envelope, "schemaVersion", 1L, "historical function truth exclusions")
    if (envelope.controlObject("oracle") != expectedOracle ||
        envelope.controlString("reasonCode") != "elf-no-source-aligned-dwarf"
    ) {
        ownershipFailure("historical function truth exclusions are misbound")
    }
}

private fun validateHistoricalTruthOracle(value: JsonObject, planningOracle: JsonObject): JsonObject {
    requireExactKeys(value, HISTORICAL_TRUTH_ORACLE_KEYS, "historical function truth oracle")
    value.values.forEach { element ->
        val digest = element.controlString("historical function truth oracle digest")
        requireDigest(digest, "historical function truth oracle")
    }
    if (value.controlString("configurationSha256") != HISTORICAL_TRUTH_CONFIGURATION_SHA256) {
        ownershipFailure("historical function truth is not the checked inline-only-v1 format")
    }
    if (value.controlString("scopeSha256") != planningOracle.controlString("scopeSha256") ||
        value.controlString("inventoryIndexSha256") != planningOracle.controlString("inventoryIndexSha256")
    ) {
        ownershipFailure("historical function truth differs from the authenticated planning scope")
    }
    return value
}

private fun validateHistoricalTruthCounts(
    value: JsonObject,
    limits: FullTreeImplementationOwnershipLimits,
): HistoricalTruthCounts {
    requireExactKeys(value, HISTORICAL_TRUTH_COUNT_KEYS, "historical function truth counts")
    val result = HistoricalTruthCounts(
        elfRvas = requireNonNegative(value, "elfRvas", "historical truth count"),
        dwarfRvas = requireNonNegative(value, "dwarfRvas", "historical truth count"),
        scoredRvas = requireNonNegative(value, "scoredRvas", "historical truth count"),
        elfOnlyRvas = requireNonNegative(value, "elfOnlyRvas", "historical truth count"),
        dwarfOnlyRvas = requireNonNegative(value, "dwarfOnlyRvas", "historical truth count"),
        inlineObservations = requireNonNegative(value, "inlineObservations", "historical truth count"),
        inlineUnique = requireNonNegative(value, "inlineUnique", "historical truth count"),
    )
    if (result.scoredRvas > limits.maximumImplementations ||
        result.dwarfOnlyRvas > limits.maximumImplementations ||
        result.elfOnlyRvas > limits.maximumImplementations ||
        result.inlineUnique > limits.maximumInlineDeclarations
    ) {
        ownershipFailure("historical function truth counts exceed configured bounds")
    }
    return result
}

private fun parseHistoricalFileRecord(
    value: JsonObject,
    exclusion: Boolean,
    limits: FullTreeImplementationOwnershipLimits,
): HistoricalFileRecord {
    requireExactKeys(value, HISTORICAL_FILE_KEYS, "historical function truth file record")
    val id = value.controlString("id")
    requireShardId(id, "historical function truth file", allowExclusions = exclusion)
    val path = value.controlString("path")
    if (path.length > 4096 || path.isEmpty() || '\u0000' in path) {
        ownershipFailure("historical function truth file path is invalid")
    }
    val sha256 = value.controlString("sha256")
    requireDigest(sha256, "historical function truth file")
    val bytes = requireNonNegative(value, "bytes", "historical function truth file")
    if (bytes !in 1L..limits.maximumTruthShardBytes) {
        ownershipFailure("historical function truth file exceeds its byte bound")
    }
    val functions = requireNonNegative(value, "functions", "historical function truth file")
    val inlineOnly = requireNonNegative(value, "inlineOnly", "historical function truth file")
    if (functions > limits.maximumImplementations || inlineOnly > limits.maximumInlineDeclarations) {
        ownershipFailure("historical function truth file exceeds its entity bounds")
    }
    return HistoricalFileRecord(id, path, sha256, bytes, functions, inlineOnly)
}

private fun validateTruthTotals(index: HistoricalTruthIndex, context: ProjectionContext) {
    val counts = index.counts
    if (counts.dwarfOnlyRvas != context.ownedExcluded ||
        counts.dwarfRvas != context.emitted ||
        counts.scoredRvas != context.scored ||
        counts.elfOnlyRvas != context.ownerlessExcluded ||
        counts.elfRvas != addOwnershipCount(context.scored, context.ownerlessExcluded, "ELF RVA") ||
        counts.inlineObservations != context.inlineObservations ||
        counts.inlineUnique != context.inlineOnly
    ) {
        ownershipFailure("historical function truth aggregate counts do not reconcile")
    }
    if (context.emitted != addOwnershipCount(context.scored, context.ownedExcluded, "emitted implementation") ||
        context.scored != addOwnershipCount(context.recovered, context.missing, "scored implementation")
    ) {
        ownershipFailure("implementation ownership population equations do not reconcile")
    }
}

private fun validateBaselineTotals(
    baseline: HistoricalBaseline,
    index: HistoricalTruthIndex,
    context: ProjectionContext,
) {
    val expectedMetricIds = (index.records.map { it.id } + HISTORICAL_EXCLUSION_SHARD)
        .sortedWith(FULL_TREE_CODE_POINT_ORDER)
    if (baseline.metrics.keys.toList() != expectedMetricIds) {
        ownershipFailure("historical baseline shard coverage differs from truth")
    }
    val exclusionMetric = baseline.metrics.getValue(HISTORICAL_EXCLUSION_SHARD)
    val expectedExclusionMetric = FunctionMetric.metric(0L, 0L, 0L, context.ownerlessExcluded)
    if (exclusionMetric != expectedExclusionMetric) {
        ownershipFailure("historical baseline ownerless exclusion metric differs from truth")
    }
    val expected = FunctionMetric.metric(
        context.recovered,
        context.missing,
        fabricated = 0L,
        excluded = addOwnershipCount(
            context.ownedExcluded,
            context.ownerlessExcluded,
            "excluded implementation",
        ),
    )
    if (baseline.aggregate != expected || baseline.mismatchCount != context.missing) {
        ownershipFailure("historical baseline aggregate differs from checked truth evidence")
    }
}

private fun validateAliases(
    aliases: JsonArray,
    context: ProjectionContext,
    label: String,
): AliasFacts {
    if (aliases.isEmpty()) ownershipFailure("$label must not be empty")
    var previousName: String? = null
    var survives = false
    var thunk = false
    aliases.forEach { element ->
        val alias = element as? JsonObject ?: ownershipFailure("$label contains a non-object")
        requireExactKeys(alias, ALIAS_KEYS, label)
        val name = alias.controlString("name")
        requireBoundedText(name, 16_384, "$label name")
        val precedingName = previousName
        if (precedingName != null && FULL_TREE_CODE_POINT_ORDER.compare(precedingName, name) >= 0) {
            ownershipFailure("$label are not strictly name ordered")
        }
        previousName = name
        if (name.startsWith("_ZTh") || name.startsWith("_ZTv") || name.startsWith("_ZTc")) thunk = true
        val evidence = alias.controlArray("evidence")
        if (evidence.isEmpty()) ownershipFailure("$label entry has no evidence")
        var previousEvidence: ByteArray? = null
        val seenEvidence = HashSet<String>()
        evidence.forEach { raw ->
            val item = raw as? JsonObject ?: ownershipFailure("$label evidence contains a non-object")
            requireExactKeys(item, EVIDENCE_KEYS, "$label evidence")
            val kind = item.controlString("kind")
            if (kind !in setOf("dwarf-subprogram", "elf-symbol")) {
                ownershipFailure("$label evidence kind is unsupported")
            }
            val locator = item.controlString("locator")
            requireBoundedText(locator, 16_384, "$label locator")
            val unitId = requireNullableString(item, "unitId", "$label evidence")
            if (unitId != null) context.requireModule(unitId, "$label evidence unit")
            if (kind == "dwarf-subprogram" && unitId == null) {
                ownershipFailure("$label DWARF evidence has no authenticated unit")
            }
            if (kind == "elf-symbol" && locator.startsWith("stripped:")) survives = true
            val canonical = OracleJson.canonicalBytes(item, ownershipEntityJsonLimits())
            val precedingEvidence = previousEvidence
            if (precedingEvidence != null && compareUnsigned(precedingEvidence, canonical) >= 0) {
                ownershipFailure("$label evidence is not strictly canonical ordered")
            }
            previousEvidence = canonical
            if (!seenEvidence.add(OracleArtifacts.sha256(canonical))) {
                ownershipFailure("$label repeats evidence")
            }
        }
    }
    return AliasFacts(survives, thunk)
}

private fun validateDeclarations(declarations: JsonArray, label: String) {
    if (declarations.isEmpty()) ownershipFailure("$label must not be empty")
    var previous: ByteArray? = null
    val seen = HashSet<String>()
    declarations.forEach { element ->
        val declaration = element as? JsonObject ?: ownershipFailure("$label contains a non-object")
        if (!declaration.keys.containsAll(DECLARATION_REQUIRED_KEYS)) {
            ownershipFailure("$label omits required source-location fields")
        }
        val sourcePath = requireNullableString(declaration, "sourcePath", label)
        sourcePath?.let { requireBoundedText(it, 16_384, "$label source path") }
        requireBoundedText(declaration.controlString("unitSourcePath"), 16_384, "$label unit source path")
        val externalPathSha256 = requireNullableString(declaration, "externalPathSha256", label)
        externalPathSha256?.let { requireDigest(it, "$label external path") }
        if (sourcePath != null && externalPathSha256 != null) {
            ownershipFailure("$label cannot identify both a local and external source path")
        }
        requireNullableNonNegativeInteger(declaration, "line", label)
        requireNullableNonNegativeInteger(declaration, "column", label)
        requireNullableNonNegativeInteger(declaration, "fileIndex", label)
        val canonical = OracleJson.canonicalBytes(declaration, ownershipEntityJsonLimits())
        val preceding = previous
        if (preceding != null && compareUnsigned(preceding, canonical) >= 0) {
            ownershipFailure("$label are not strictly canonical ordered")
        }
        previous = canonical
        if (!seen.add(OracleArtifacts.sha256(canonical))) ownershipFailure("$label repeat a location")
    }
}

private fun buildOwnershipDocument(
    registry: AuthenticatedFullTreePlanningRegistry,
    planningOracle: JsonObject,
    truthIndex: HistoricalTruthIndex,
    baseline: HistoricalBaseline,
    modules: List<ModuleAccumulator>,
    sourceOnlyCommitment: IdCommitment,
    context: ProjectionContext,
    workUnits: Long,
): JsonObject {
    val moduleDocuments = modules.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.module.sourcePath })
        .map(ModuleAccumulator::document)
    val totalExcluded = addOwnershipCount(
        context.ownedExcluded,
        context.ownerlessExcluded,
        "excluded implementation",
    )
    val withoutHash = JsonObject(
        mapOf(
            "authority" to JsonObject(
                mapOf(
                    "historicalFunctionTruthFormat" to JsonPrimitive("inline-only-v1"),
                    "purpose" to JsonPrimitive("historical-a13-v2-implementation-ownership-planning"),
                    "releaseEligible" to JsonPrimitive(false),
                    "status" to JsonPrimitive("non-authoritative"),
                ),
            ),
            "bounds" to JsonObject(
                mapOf(
                    "maximumBaselineBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_BASELINE_BYTES),
                    "maximumImplementations" to JsonPrimitive(OWNERSHIP_MAXIMUM_IMPLEMENTATIONS),
                    "maximumInlineDeclarations" to JsonPrimitive(OWNERSHIP_MAXIMUM_INLINE_DECLARATIONS),
                    "maximumSerializedBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_SERIALIZED_BYTES),
                    "maximumSourceModules" to JsonPrimitive(OWNERSHIP_MAXIMUM_SOURCE_MODULES),
                    "maximumTruthBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_BYTES),
                    "maximumTruthIndexBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_INDEX_BYTES),
                    "maximumTruthShardBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_SHARD_BYTES),
                    "maximumTruthShards" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_SHARDS),
                    "maximumWorkUnits" to JsonPrimitive(OWNERSHIP_MAXIMUM_WORK_UNITS),
                ),
            ),
            "counts" to JsonObject(
                mapOf(
                    "dependencyEdges" to JsonPrimitive(0),
                    "emittedImplementations" to JsonPrimitive(context.emitted),
                    "fabricatedImplementations" to JsonPrimitive(0),
                    "inlineOnlyDeclarations" to JsonPrimitive(context.inlineOnly),
                    "missingImplementations" to JsonPrimitive(context.missing),
                    "modulesWithImplementations" to JsonPrimitive(
                        modules.count { it.emitted > 0L },
                    ),
                    "ownedExcludedImplementations" to JsonPrimitive(context.ownedExcluded),
                    "ownerlessExcludedImplementations" to JsonPrimitive(context.ownerlessExcluded),
                    "recoveredImplementations" to JsonPrimitive(context.recovered),
                    "scoredImplementations" to JsonPrimitive(context.scored),
                    "sourceModules" to JsonPrimitive(modules.size),
                    "sourceOnlyUnits" to JsonPrimitive(registry.sourceOnlyUnits.size),
                    "totalExcludedImplementations" to JsonPrimitive(totalExcluded),
                    "truthShards" to JsonPrimitive(truthIndex.records.size),
                    "workUnits" to JsonPrimitive(workUnits),
                ),
            ),
            "dependencies" to JsonObject(
                mapOf(
                    "edges" to JsonArray(emptyList()),
                    "status" to JsonPrimitive("not-inferred-from-historical-function-evidence"),
                ),
            ),
            "modules" to JsonArray(moduleDocuments),
            "oracle" to JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(FullTreeImplementationOwnership.configurationSha256),
                    "historicalFunctionBaselineArtifactSha256" to JsonPrimitive(baseline.sourceSha256),
                    "historicalFunctionBaselineConfigurationSha256" to JsonPrimitive(
                        baseline.configurationSha256,
                    ),
                    "historicalFunctionBaselineReportSha256" to JsonPrimitive(baseline.reportSha256),
                    "historicalFunctionTruthArtifactSha256" to JsonPrimitive(truthIndex.sourceSha256),
                    "historicalFunctionTruthConfigurationSha256" to truthIndex.oracle.getValue(
                        "configurationSha256",
                    ),
                    "historicalFunctionTruthIndexSha256" to JsonPrimitive(truthIndex.logicalSha256),
                    "id" to planningOracle.getValue("id"),
                    "inventoryIndexSha256" to planningOracle.getValue("inventoryIndexSha256"),
                    "planningInventoryArtifactSha256" to JsonPrimitive(registry.artifactSha256),
                    "planningInventoryConfigurationSha256" to JsonPrimitive(registry.configurationSha256),
                    "planningInventoryReportSha256" to JsonPrimitive(registry.reportSha256),
                    "scopeSha256" to planningOracle.getValue("scopeSha256"),
                ),
            ),
            "ownerlessExclusions" to JsonObject(
                mapOf(
                    "count" to JsonPrimitive(context.ownerlessExcluded),
                    "implementationIdsSha256" to JsonPrimitive(context.ownerlessExclusionCommitment.finish()),
                    "reasonCode" to JsonPrimitive("elf-no-source-aligned-dwarf"),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
            "sourceOnly" to JsonObject(
                mapOf(
                    "count" to JsonPrimitive(registry.sourceOnlyUnits.size),
                    "ownershipStatus" to JsonPrimitive("excluded-non-owning"),
                    "sourcePathsSha256" to JsonPrimitive(sourceOnlyCommitment.finish()),
                ),
            ),
        ),
    )
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, ownershipOutputJsonLimits()),
    )
    return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
}

private fun terminalReauthenticate(
    paths: OwnershipPaths,
    limits: FullTreeImplementationOwnershipLimits,
    initialRegistry: AuthenticatedFullTreePlanningRegistry,
    truthIndex: HistoricalTruthIndex,
    baseline: HistoricalBaseline,
) {
    val terminalRegistry = loadPlanningRegistry(paths, limits)
    if (terminalRegistry.artifactSha256 != initialRegistry.artifactSha256 ||
        terminalRegistry.reportSha256 != initialRegistry.reportSha256 ||
        terminalRegistry.configurationSha256 != initialRegistry.configurationSha256
    ) {
        ownershipFailure("planning inventory changed before terminal assessment acceptance")
    }
    val terminalModules = terminalRegistry.sourceModules.map {
        listOf(it.moduleId, it.unitId, it.shardId, it.sourceKind, it.sourcePath)
    }
    val initialModules = initialRegistry.sourceModules.map {
        listOf(it.moduleId, it.unitId, it.shardId, it.sourceKind, it.sourcePath)
    }
    if (terminalModules != initialModules || terminalRegistry.sourceOnlyUnits.map {
            listOf(it.sourcePath, it.shardId, it.reasonCode)
        } != initialRegistry.sourceOnlyUnits.map { listOf(it.sourcePath, it.shardId, it.reasonCode) }
    ) {
        ownershipFailure("planning registry changed before terminal assessment acceptance")
    }
    if (stableOwnershipSha256(
            truthIndex.path,
            limits.maximumTruthIndexBytes.toLong(),
            "terminal historical truth index",
        ) != truthIndex.sourceSha256 ||
        stableOwnershipSha256(
            baseline.path,
            limits.maximumBaselineBytes.toLong(),
            "terminal historical baseline",
        ) != baseline.sourceSha256
    ) {
        ownershipFailure("historical index or baseline changed before terminal acceptance")
    }
    (truthIndex.records + truthIndex.exclusions).forEach { record ->
        if (stableOwnershipSha256(
                record.path,
                minOf(record.bytes, limits.maximumTruthShardBytes),
                "terminal historical truth file ${record.id}",
            ) != record.sha256
        ) {
            ownershipFailure("historical truth file ${record.id} changed before terminal acceptance")
        }
    }
    if (ownershipDirectoryIdentity(truthIndex.rootIdentity.path, "terminal historical truth root") !=
        truthIndex.rootIdentity ||
        ownershipDirectoryIdentity(truthIndex.shardsIdentity.path, "terminal historical truth shards") !=
        truthIndex.shardsIdentity
    ) {
        ownershipFailure("historical function truth directories changed before terminal acceptance")
    }
}

private fun ownershipWorkUnits(
    registry: AuthenticatedFullTreePlanningRegistry,
    index: HistoricalTruthIndex,
    baseline: HistoricalBaseline,
    emitted: Long,
    inlineOnly: Long,
    ownerlessExcluded: Long,
    outputModules: Int,
): Long = listOf(
    registry.sourceModules.size.toLong(),
    registry.sourceOnlyUnits.size.toLong(),
    index.records.size.toLong() + 1L,
    baseline.mismatchCount,
    baseline.metrics.size.toLong(),
    emitted,
    inlineOnly,
    ownerlessExcluded,
    outputModules.toLong(),
).fold(0L) { total, count -> addOwnershipCount(total, count, "ownership work-unit") }

private fun requireDistinctOwnershipInputs(paths: OwnershipPaths) {
    val inputs = paths.fixedInputs().map(Path::toAbsolutePath).map(Path::normalize)
    if (inputs.toSet().size != inputs.size) ownershipFailure("ownership input paths must be distinct")
    inputs.forEachIndexed { leftIndex, left ->
        for (rightIndex in leftIndex + 1 until inputs.size) {
            val right = inputs[rightIndex]
            if (Files.exists(left, LinkOption.NOFOLLOW_LINKS) &&
                Files.exists(right, LinkOption.NOFOLLOW_LINKS) && Files.isSameFile(left, right)
            ) {
                ownershipFailure("ownership inputs must not be hard-link aliases")
            }
        }
    }
}

private fun registerUniqueInputIdentity(path: Path, seen: MutableSet<Any>) {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        ownershipFailure("ownership input is not an identified regular file")
    }
    if (!seen.add(attributes.fileKey())) ownershipFailure("ownership inputs contain a physical-file alias")
}

private fun ownershipDirectoryIdentity(path: Path, label: String): DirectoryIdentity {
    val (normalized, key) = requireStableDirectory(path, label)
    return DirectoryIdentity(normalized, key)
}

private fun stableOwnershipSha256(path: Path, maximumBytes: Long, label: String): String =
    StableControlFile.open(path, maximumBytes, label).use { input ->
        input.sha256(label = label).also { input.verifyUnchanged(label) }
    }

private fun canonicalOwnershipBytes(document: JsonObject, maximumBytes: Int): ByteArray = try {
    OracleJson.canonicalBytes(
        document,
        StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 32,
            maximumNodes = 1_000_000,
            maximumStringBytes = 16_384,
            maximumTotalStringBytes = maximumBytes,
        ),
    )
} catch (failure: Exception) {
    throw FullTreeImplementationOwnershipException("ownership output exceeds canonical bounds", failure)
}

private fun validateOwnershipSchema(document: JsonObject) {
    try {
        OracleSchemas.validate("full-tree-implementation-ownership", document)
    } catch (failure: Exception) {
        throw FullTreeImplementationOwnershipException("generated ownership output fails its schema", failure)
    }
}

private class ProjectionContext(
    val modules: Map<String, ModuleAccumulator>,
    private val sourceOnlyUnitIds: Set<String>,
    val missingByTruthId: MutableMap<String, String>,
    val limits: FullTreeImplementationOwnershipLimits,
) {
    val seenRvas = HashSet<ULong>()
    val seenInlineIds = HashSet<String>()
    val ownerlessExclusionCommitment = IdCommitment("ownerless-exclusions", "excluded")
    var emitted = 0L
    var scored = 0L
    var recovered = 0L
    var missing = 0L
    var ownedExcluded = 0L
    var ownerlessExcluded = 0L
    var inlineOnly = 0L
    var inlineObservations = 0L

    fun requireModule(ownerUnitId: String, label: String): ModuleAccumulator {
        if (!ownerUnitId.matches(UNIT_ID)) ownershipFailure("$label identity is invalid")
        if (ownerUnitId in sourceOnlyUnitIds) ownershipFailure("$label names a source-only non-owner")
        return modules[ownerUnitId] ?: ownershipFailure("$label is outside the authenticated planning inventory")
    }
}

private class ModuleAccumulator(val module: FullTreePlanningSourceModule) {
    private val emittedCommitment = IdCommitment(module.moduleId, "emitted")
    private val recoveredCommitment = IdCommitment(module.moduleId, "recovered")
    private val missingCommitment = IdCommitment(module.moduleId, "missing")
    private val excludedCommitment = IdCommitment(module.moduleId, "excluded")
    private val inlineCommitment = IdCommitment(module.moduleId, "inline-only")
    var emitted = 0L
        private set
    private var scored = 0L
    private var recovered = 0L
    private var missing = 0L
    private var excluded = 0L
    private var inlineOnly = 0L

    fun addScored(id: String, isMissing: Boolean) {
        emittedCommitment.add(id)
        emitted = incrementOwnership(emitted, "module emitted implementation")
        scored = incrementOwnership(scored, "module scored implementation")
        if (isMissing) {
            missingCommitment.add(id)
            missing = incrementOwnership(missing, "module missing implementation")
        } else {
            recoveredCommitment.add(id)
            recovered = incrementOwnership(recovered, "module recovered implementation")
        }
    }

    fun addExcluded(id: String) {
        emittedCommitment.add(id)
        excludedCommitment.add(id)
        emitted = incrementOwnership(emitted, "module emitted implementation")
        excluded = incrementOwnership(excluded, "module excluded implementation")
    }

    fun addInline(id: String) {
        inlineCommitment.add(id)
        inlineOnly = incrementOwnership(inlineOnly, "module inline-only declaration")
    }

    fun document(): JsonObject {
        if (emitted != addOwnershipCount(scored, excluded, "module emitted implementation") ||
            scored != addOwnershipCount(recovered, missing, "module scored implementation")
        ) {
            ownershipFailure("module ownership populations do not reconcile")
        }
        return JsonObject(
            mapOf(
                "commitments" to JsonObject(
                    mapOf(
                        "emittedImplementationIdsSha256" to JsonPrimitive(emittedCommitment.finish()),
                        "excludedImplementationIdsSha256" to JsonPrimitive(excludedCommitment.finish()),
                        "inlineOnlyDeclarationIdsSha256" to JsonPrimitive(inlineCommitment.finish()),
                        "missingImplementationIdsSha256" to JsonPrimitive(missingCommitment.finish()),
                        "recoveredImplementationIdsSha256" to JsonPrimitive(recoveredCommitment.finish()),
                    ),
                ),
                "counts" to JsonObject(
                    mapOf(
                        "emittedImplementations" to JsonPrimitive(emitted),
                        "excludedImplementations" to JsonPrimitive(excluded),
                        "inlineOnlyDeclarations" to JsonPrimitive(inlineOnly),
                        "missingImplementations" to JsonPrimitive(missing),
                        "recoveredImplementations" to JsonPrimitive(recovered),
                        "scoredImplementations" to JsonPrimitive(scored),
                    ),
                ),
                "moduleId" to JsonPrimitive(module.moduleId),
                "ownerUnitId" to JsonPrimitive(module.unitId),
                "shardId" to JsonPrimitive(module.shardId),
                "sourceKind" to JsonPrimitive(module.sourceKind),
                "sourcePath" to JsonPrimitive(module.sourcePath),
            ),
        )
    }
}

/** Fixed-width, domain-separated commitment over the validated source sequence. */
private class IdCommitment(owner: String, population: String) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var finished: String? = null

    init {
        addFramed(COMMITMENT_DOMAIN)
        addFramed(owner)
        addFramed(population)
    }

    fun add(value: String) {
        if (finished != null) ownershipFailure("ownership commitment is already finalized")
        addFramed(value)
    }

    fun finish(): String = finished ?: digest.digest().hexString().also { finished = it }

    private fun addFramed(value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > 1_048_576) ownershipFailure("ownership commitment component is oversized")
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        digest.update(bytes)
    }
}

private class ShardProjectionState(val id: String) {
    var previousRva: ULong? = null
    var previousInlineId: String? = null
    var functions = 0L
    var inlineOnly = 0L
    private var recovered = 0L
    private var missing = 0L
    private var excluded = 0L

    fun addScored(isMissing: Boolean) {
        if (isMissing) missing = incrementOwnership(missing, "shard missing implementation")
        else recovered = incrementOwnership(recovered, "shard recovered implementation")
    }

    fun addExcluded() {
        excluded = incrementOwnership(excluded, "shard excluded implementation")
    }

    fun metric(): FunctionMetric = FunctionMetric.metric(recovered, missing, 0L, excluded)
}

private data class FunctionMetric(
    val denominator: Long,
    val excluded: Long,
    val fabricated: Long,
    val missing: Long,
    val recallDenominator: Long,
    val recallNumerator: Long,
    val recovered: Long,
) {
    operator fun plus(other: FunctionMetric): FunctionMetric = metric(
        addOwnershipCount(recovered, other.recovered, "baseline recovered"),
        addOwnershipCount(missing, other.missing, "baseline missing"),
        addOwnershipCount(fabricated, other.fabricated, "baseline fabricated"),
        addOwnershipCount(excluded, other.excluded, "baseline excluded"),
    )

    companion object {
        val ZERO = metric(0L, 0L, 0L, 0L)

        fun metric(recovered: Long, missing: Long, fabricated: Long, excluded: Long): FunctionMetric {
            val denominator = addOwnershipCount(recovered, missing, "baseline denominator")
            return FunctionMetric(
                denominator,
                excluded,
                fabricated,
                missing,
                denominator,
                recovered,
                recovered,
            )
        }
    }
}

private fun parseMetric(value: JsonObject, label: String): FunctionMetric {
    requireExactKeys(value, METRIC_KEYS, label)
    val metric = FunctionMetric(
        denominator = requireNonNegative(value, "denominator", label),
        excluded = requireNonNegative(value, "excluded", label),
        fabricated = requireNonNegative(value, "fabricated", label),
        missing = requireNonNegative(value, "missing", label),
        recallDenominator = requireNonNegative(value, "recallDenominator", label),
        recallNumerator = requireNonNegative(value, "recallNumerator", label),
        recovered = requireNonNegative(value, "recovered", label),
    )
    if (metric != FunctionMetric.metric(metric.recovered, metric.missing, metric.fabricated, metric.excluded)) {
        ownershipFailure("$label population equations do not reconcile")
    }
    return metric
}

private data class OwnershipPaths(
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
    val buildRecord: Path,
    val inventory: Path,
    val sourceInventory: Path,
    val planningInventory: Path,
    val functionTruthIndex: Path,
    val functionBaseline: Path,
) {
    fun fixedInputs(): List<Path> = listOf(
        scope,
        sourceLock,
        artifactManifest,
        buildRecord,
        inventory,
        sourceInventory,
        planningInventory,
        functionTruthIndex,
        functionBaseline,
    )
}

private data class HistoricalTruthIndex(
    val path: Path,
    val rootIdentity: DirectoryIdentity,
    val shardsIdentity: DirectoryIdentity,
    val sourceSha256: String,
    val sourceBytes: Long,
    val logicalSha256: String,
    val oracle: JsonObject,
    val counts: HistoricalTruthCounts,
    val records: List<HistoricalFileRecord>,
    val exclusions: HistoricalFileRecord,
) {
    val allPaths: List<Path>
        get() = records.map { it.path } + listOf(exclusions.path)
}

private data class HistoricalTruthCounts(
    val elfRvas: Long,
    val dwarfRvas: Long,
    val scoredRvas: Long,
    val elfOnlyRvas: Long,
    val dwarfOnlyRvas: Long,
    val inlineObservations: Long,
    val inlineUnique: Long,
)

private data class HistoricalFileRecord(
    val id: String,
    val pathText: String,
    val sha256: String,
    val bytes: Long,
    val functions: Long,
    val inlineOnly: Long,
) {
    lateinit var path: Path
}

private data class HistoricalBaseline(
    val path: Path,
    val sourceSha256: String,
    val sourceBytes: Long,
    val configurationSha256: String,
    val reportSha256: String,
    val aggregate: FunctionMetric,
    val metrics: Map<String, FunctionMetric>,
    val missingByTruthId: Map<String, String>,
    val mismatchCount: Long,
)

private data class DirectoryIdentity(val path: Path, val fileKey: Any)
private data class AliasFacts(val survivesInStrippedArtifact: Boolean, val hasThunkName: Boolean)
private data class OwnershipAssessmentState(
    val reportSha256: String,
    val recovered: Long,
    val missing: Long,
    val bytes: ByteArray,
)

private fun streamingLimits(
    maximumBytes: Long,
    maximumEntities: Long,
    maximumEntityBytes: Int,
): FullTreeCanonicalStreamingLimits = FullTreeCanonicalStreamingLimits(
    maximumInputBytes = maximumBytes,
    maximumTokens = minOf(1_000_000_000L, maximumBytes.coerceAtLeast(1L) * 4L),
    maximumEntities = maximumEntities.coerceAtLeast(1L),
    maximumEntityBytes = maximumEntityBytes,
    maximumEntityNodes = 1_000_000,
    maximumDepth = 128,
    maximumStringBytes = minOf(maximumEntityBytes, 1024 * 1024),
    maximumTotalStringBytes = maximumBytes,
)

private fun ownershipEntityJsonLimits(): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = OWNERSHIP_MAXIMUM_ENTITY_BYTES,
    maximumCanonicalBytes = OWNERSHIP_MAXIMUM_ENTITY_BYTES,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = OWNERSHIP_MAXIMUM_ENTITY_BYTES,
)

private fun ownershipOutputJsonLimits(): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = OWNERSHIP_MAXIMUM_SERIALIZED_BYTES,
    maximumCanonicalBytes = OWNERSHIP_MAXIMUM_SERIALIZED_BYTES,
    maximumDepth = 32,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16_384,
    maximumTotalStringBytes = OWNERSHIP_MAXIMUM_SERIALIZED_BYTES,
)

private fun requireExactKeys(value: JsonObject, expected: Set<String>, label: String) {
    if (value.keys != expected) ownershipFailure("$label has missing or extra fields")
}

private fun requireBoolean(value: JsonObject, name: String, expected: Boolean, label: String) {
    val primitive = value[name] as? JsonPrimitive ?: ownershipFailure("$label field $name is not Boolean")
    if (primitive.isString || primitive.content != expected.toString()) {
        ownershipFailure("$label field $name differs")
    }
}

private fun requireInteger(value: JsonObject, name: String, expected: Long, label: String) {
    if (value.controlLong(name) != expected) ownershipFailure("$label field $name differs")
}

private fun requireNonNegative(value: JsonObject, name: String, label: String): Long =
    value.controlLong(name).also { if (it < 0L) ownershipFailure("$label field $name is negative") }

private fun requireNullableNonNegativeInteger(value: JsonObject, name: String, label: String): Long? {
    val element = value[name] ?: ownershipFailure("$label omits $name")
    if (element === JsonNull) return null
    val primitive = element as? JsonPrimitive ?: ownershipFailure("$label field $name is not nullable integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        ownershipFailure("$label field $name is not nullable integer")
    }
    return primitive.content.toLongOrNull()?.also {
        if (it < 0L) ownershipFailure("$label field $name is negative")
    } ?: ownershipFailure("$label field $name exceeds the integer range")
}

private fun requireNullableString(value: JsonObject, name: String, label: String): String? {
    val element = value[name] ?: ownershipFailure("$label omits $name")
    if (element === JsonNull) return null
    val primitive = element as? JsonPrimitive ?: ownershipFailure("$label field $name is not nullable text")
    if (!primitive.isString) ownershipFailure("$label field $name is not nullable text")
    return primitive.content
}

private fun requireStringArray(value: JsonObject, name: String, label: String): List<String> =
    value.controlArray(name).map { it.controlString(label) }

private fun requireDigest(value: String, label: String) {
    if (!value.matches(SHA256)) ownershipFailure("$label digest is invalid")
}

private fun requireFunctionId(value: String, label: String) {
    if (!value.matches(FUNCTION_ID)) ownershipFailure("$label function identity is invalid")
}

private fun requireShardId(value: String, label: String, allowExclusions: Boolean = false) {
    if (allowExclusions && value == HISTORICAL_EXCLUSION_SHARD) return
    if (!value.matches(SHARD_ID)) ownershipFailure("$label shard identity is invalid")
}

private fun requireBoundedText(value: String, maximumBytes: Int, label: String) {
    if (value.isEmpty() || value.toByteArray(StandardCharsets.UTF_8).size > maximumBytes || '\u0000' in value) {
        ownershipFailure("$label is empty, oversized, or contains NUL")
    }
}

private fun parseRva(value: String, label: String): ULong {
    if (!value.matches(RVA)) ownershipFailure("$label RVA is invalid")
    return value.substring(2).toULongOrNull(16) ?: ownershipFailure("$label RVA exceeds 64 bits")
}

private fun baselineMismatchId(kind: String, truthId: String): String {
    val payload = OracleJson.canonicalBytes(
        JsonObject(mapOf("kind" to JsonPrimitive(kind), "truthId" to JsonPrimitive(truthId))),
        ownershipEntityJsonLimits(),
    )
    return "$kind-function-${OracleArtifacts.sha256(payload).take(32)}"
}

private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
    val shared = minOf(left.size, right.size)
    for (index in 0 until shared) {
        val compared = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
        if (compared != 0) return compared
    }
    return left.size.compareTo(right.size)
}

private fun incrementOwnership(value: Long, label: String): Long = addOwnershipCount(value, 1L, label)

private fun addOwnershipCount(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeImplementationOwnershipException("$label count overflows", failure)
}

private fun ownershipFailure(message: String): Nothing = throw FullTreeImplementationOwnershipException(message)

private fun ByteArray.hexString(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private const val OWNERSHIP_MAXIMUM_TRUTH_INDEX_BYTES = 1024 * 1024
private const val OWNERSHIP_MAXIMUM_BASELINE_BYTES = 64 * 1024 * 1024
private const val OWNERSHIP_MAXIMUM_TRUTH_SHARD_BYTES = 512L * 1024L * 1024L
private const val OWNERSHIP_MAXIMUM_TRUTH_BYTES = 3L * 1024L * 1024L * 1024L
private const val OWNERSHIP_MAXIMUM_TRUTH_SHARDS = 10_000
private const val OWNERSHIP_MAXIMUM_SOURCE_MODULES = 1_000_000
private const val OWNERSHIP_MAXIMUM_IMPLEMENTATIONS = 3_000_000L
private const val OWNERSHIP_MAXIMUM_INLINE_DECLARATIONS = 3_000_000L
private const val OWNERSHIP_MAXIMUM_WORK_UNITS = 10_000_000L
private const val OWNERSHIP_MAXIMUM_SERIALIZED_BYTES = 64 * 1024 * 1024
private const val OWNERSHIP_MAXIMUM_ENTITY_BYTES = 64 * 1024 * 1024
private const val HISTORICAL_TRUTH_CONFIGURATION_SHA256 =
    "3c192005e782c255a9779769676a2cf3e7d33050830f220adc32e03d3e65b329"
private const val HISTORICAL_BASELINE_CONFIGURATION_SHA256 =
    "c29ef7047ba26e9165e78faffd5781711923f75c1fb265e5f615bfd1ffd21951"
private const val HISTORICAL_EXCLUSION_SHARD = "elf-only-exclusions"
private const val COMMITMENT_DOMAIN = "full-tree-implementation-ownership-v1"

private val SHA256 = Regex("[0-9a-f]{64}")
private val UNIT_ID = Regex("cu-[0-9a-f]{32}")
private val SHARD_ID = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val RVA = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val FUNCTION_ID = Regex("function-rva-0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val INLINE_ID = Regex("inline-declaration-[0-9a-f]{32}")

private val INDEX_FIELD_ORDER = listOf(
    "complete", "counts", "exclusions", "indexSha256", "oracle", "schemaVersion", "shards",
)
private val BASELINE_FIELD_ORDER = listOf(
    "aggregate", "configurationSha256", "mismatches", "reportSha256", "schemaVersion", "shards",
    "truthIndexSha256",
)
private val TRUTH_SHARD_FIELD_ORDER = listOf(
    "counts", "functions", "inlineOnly", "oracle", "schemaVersion", "shard",
)
private val EXCLUSION_FIELD_ORDER = listOf("functions", "oracle", "reasonCode", "schemaVersion")

private val INDEX_KEYS = INDEX_FIELD_ORDER.toSet()
private val BASELINE_KEYS = BASELINE_FIELD_ORDER.toSet()
private val TRUTH_SHARD_KEYS = TRUTH_SHARD_FIELD_ORDER.toSet()
private val EXCLUSION_KEYS = EXCLUSION_FIELD_ORDER.toSet()
private val HISTORICAL_TRUTH_ORACLE_KEYS = setOf(
    "configurationSha256", "elfIndexSha256", "inventoryIndexSha256", "observationIndexSha256", "scopeSha256",
)
private val HISTORICAL_TRUTH_COUNT_KEYS = setOf(
    "dwarfOnlyRvas", "dwarfRvas", "elfOnlyRvas", "elfRvas", "inlineObservations", "inlineUnique", "scoredRvas",
)
private val HISTORICAL_FILE_KEYS = setOf("bytes", "functions", "id", "inlineOnly", "path", "sha256")
private val BASELINE_MISMATCH_KEYS = setOf("id", "kind", "shardId", "truthId")
private val BASELINE_SHARD_KEYS = setOf("id", "metric")
private val METRIC_KEYS = setOf(
    "denominator", "excluded", "fabricated", "missing", "recallDenominator", "recallNumerator", "recovered",
)
private val TRUTH_SHARD_DESCRIPTOR_KEYS = setOf("id", "unitIds")
private val TRUTH_SHARD_COUNT_KEYS = setOf("functions", "inlineOnly")
private val HISTORICAL_FUNCTION_KEYS = setOf(
    "aliases", "declarations", "entityKind", "id", "ownerUnitId", "ownershipCandidates", "population",
    "reasonCode", "rva",
)
private val HISTORICAL_INLINE_KEYS = setOf(
    "aliases", "declarations", "id", "observationIds", "ownerUnitId", "population", "reasonCode",
)
private val HISTORICAL_EXCLUSION_KEYS = setOf("aliases", "id", "reasonCode", "rva")
private val ALIAS_KEYS = setOf("evidence", "name")
private val EVIDENCE_KEYS = setOf("kind", "locator", "unitId")
private val DECLARATION_REQUIRED_KEYS = setOf(
    "column", "externalPathSha256", "fileIndex", "line", "sourcePath", "unitSourcePath",
)

private val OWNERSHIP_POLICY = JsonObject(
    mapOf(
        "authority" to JsonPrimitive("non-authoritative-historical-planning-only"),
        "commitmentFraming" to JsonPrimitive("sha256-over-unsigned-big-endian-u32-length-prefixed-utf8-components"),
        "commitmentSequence" to JsonPrimitive("validated-historical-canonical-record-order"),
        "dependencyPolicy" to JsonPrimitive("not-inferred"),
        "historicalFunctionTruthConfigurationSha256" to JsonPrimitive(HISTORICAL_TRUTH_CONFIGURATION_SHA256),
        "historicalFunctionTruthFormat" to JsonPrimitive("inline-only-v1"),
        "id" to JsonPrimitive("full-tree-implementation-ownership"),
        "maximumBaselineBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_BASELINE_BYTES),
        "maximumImplementations" to JsonPrimitive(OWNERSHIP_MAXIMUM_IMPLEMENTATIONS),
        "maximumInlineDeclarations" to JsonPrimitive(OWNERSHIP_MAXIMUM_INLINE_DECLARATIONS),
        "maximumSerializedBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_SERIALIZED_BYTES),
        "maximumTruthBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_BYTES),
        "maximumTruthIndexBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_INDEX_BYTES),
        "maximumTruthShardBytes" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_SHARD_BYTES),
        "maximumTruthShards" to JsonPrimitive(OWNERSHIP_MAXIMUM_TRUTH_SHARDS),
        "maximumWorkUnits" to JsonPrimitive(OWNERSHIP_MAXIMUM_WORK_UNITS),
        "moduleIdentity" to JsonPrimitive("authenticated-planning-unit-id"),
        "ownerSelection" to JsonPrimitive("lowest-authenticated-historical-candidate"),
        "sourceOnlyOwnership" to JsonPrimitive("forbidden"),
        "version" to JsonPrimitive(1),
        "workUnitModel" to JsonPrimitive(
            "planning-records-plus-truth-index-records-plus-baseline-records-plus-truth-entities-plus-output-modules",
        ),
    ),
)

package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeHeaderPlanReadinessException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable aggregation ceilings beneath the immutable readiness-v1 policy. */
data class FullTreeHeaderPlanReadinessLimits(
    val dependencies: FullTreeSourceHeaderDependencyLimits = FullTreeSourceHeaderDependencyLimits(),
    val maximumSourceModules: Int = HEADER_READINESS_MAXIMUM_SOURCE_MODULES,
    val maximumSourceOnlyUnits: Int = HEADER_READINESS_MAXIMUM_SOURCE_ONLY_UNITS,
    val maximumAuthenticatedSourceHeaderCandidates: Int =
        HEADER_READINESS_MAXIMUM_AUTHENTICATED_SOURCE_HEADER_CANDIDATES,
    val maximumBlockers: Int = HEADER_READINESS_MAXIMUM_BLOCKERS,
    val maximumOutputRecords: Int = HEADER_READINESS_MAXIMUM_OUTPUT_RECORDS,
    val maximumWorkUnits: Long = HEADER_READINESS_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumSourceModules in 1..HEADER_READINESS_MAXIMUM_SOURCE_MODULES)
        require(maximumSourceOnlyUnits in 1..HEADER_READINESS_MAXIMUM_SOURCE_ONLY_UNITS)
        require(
            maximumAuthenticatedSourceHeaderCandidates in
                1..HEADER_READINESS_MAXIMUM_AUTHENTICATED_SOURCE_HEADER_CANDIDATES,
        )
        require(maximumBlockers in 1..HEADER_READINESS_MAXIMUM_BLOCKERS)
        require(maximumOutputRecords in 1..HEADER_READINESS_MAXIMUM_OUTPUT_RECORDS)
        require(maximumWorkUnits in 1L..HEADER_READINESS_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES)
    }
}

/**
 * Immutable authenticated prerequisites for A14 header planning.
 *
 * The source-header population is deliberately a known source-only subset, not a complete header
 * universe. Fixed blockers keep this result unready until generated/project inventory, compiler
 * capture, physical roots, and Ninja generator provenance have separate Kotlin-owned admission.
 */
sealed interface AuthenticatedFullTreeHeaderPlanReadiness {
    val artifactSha256: String
    val artifactBytes: Long
    val reportSha256: String
    val configurationSha256: String
    val planningInventoryArtifactSha256: String
    val planningInventoryReportSha256: String
    val planningInventoryConfigurationSha256: String
    val sourceArchiveSha256: String
    val sourceDependencyArtifactSha256: String
    val sourceDependencyReportSha256: String
    val sourceDependencyConfigurationSha256: String
    val sourceHeaderManifestSha256: String
    val sourceModules: List<FullTreePlanningSourceModule>
    val sourceOnlyUnits: List<FullTreePlanningSourceOnlyUnit>
    val authenticatedSourceHeaderCandidatePaths: List<String>
    val blockerCodes: List<String>
    val canonicalBytes: ByteArray
}

/**
 * Kotlin/JVM authority for the pre-capture A14 header-plan readiness envelope.
 *
 * Every module, shard, source-only exclusion, and authenticated source-header candidate is derived
 * internally from the eight raw control/archive paths. ACP is fixed in the artifact as the
 * first-class candidate producer/operator with read-only evidence access and no oracle authority.
 */
object FullTreeHeaderPlanReadinessControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(HEADER_READINESS_SCHEMA, HEADER_READINESS_POLICY)
    }

    fun generateAndPublish(
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        output: Path,
        limits: FullTreeHeaderPlanReadinessLimits = FullTreeHeaderPlanReadinessLimits(),
    ): AuthenticatedFullTreeHeaderPlanReadiness = createReadiness(
        sourceArchivePath,
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        planningInventoryPath,
        output,
        limits,
        publish = true,
    )

    fun loadAndValidate(
        path: Path,
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeHeaderPlanReadinessLimits = FullTreeHeaderPlanReadinessLimits(),
    ): AuthenticatedFullTreeHeaderPlanReadiness = createReadiness(
        sourceArchivePath,
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        planningInventoryPath,
        path,
        limits,
        publish = false,
    )

    private fun createReadiness(
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        artifactPath: Path,
        limits: FullTreeHeaderPlanReadinessLimits,
        publish: Boolean,
    ): AuthenticatedFullTreeHeaderPlanReadiness = try {
        ValidatedReadiness.create(
            sourceArchivePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            artifactPath,
            limits,
            publish,
        )
    } catch (failure: FullTreeHeaderPlanReadinessException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeHeaderPlanReadinessException(
            "full-tree header-plan readiness admission failed: ${failure.message}",
            failure,
        )
    }

    /** The only construction seam accepts raw paths, caller-lowering limits, and generate/load. */
    private class ValidatedReadiness private constructor(
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        artifactPath: Path,
        limits: FullTreeHeaderPlanReadinessLimits,
        publish: Boolean,
    ) : AuthenticatedFullTreeHeaderPlanReadiness {
        private val state = authenticateReadinessState(
            ReadinessPaths(
                sourceArchivePath,
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                artifactPath,
            ),
            limits,
            publish,
        )

        override val artifactSha256: String = state.artifactSha256
        override val artifactBytes: Long = state.artifactBytes
        override val reportSha256: String = state.reportSha256
        override val configurationSha256: String = state.configurationSha256
        override val planningInventoryArtifactSha256: String = state.planningArtifactSha256
        override val planningInventoryReportSha256: String = state.planningReportSha256
        override val planningInventoryConfigurationSha256: String = state.planningConfigurationSha256
        override val sourceArchiveSha256: String = state.sourceArchiveSha256
        override val sourceDependencyArtifactSha256: String = state.dependencyArtifactSha256
        override val sourceDependencyReportSha256: String = state.dependencyReportSha256
        override val sourceDependencyConfigurationSha256: String = state.dependencyConfigurationSha256
        override val sourceHeaderManifestSha256: String = state.sourceHeaderManifestSha256
        override val sourceModules: List<FullTreePlanningSourceModule> =
            Collections.unmodifiableList(ArrayList(state.sourceModules))
        override val sourceOnlyUnits: List<FullTreePlanningSourceOnlyUnit> =
            Collections.unmodifiableList(ArrayList(state.sourceOnlyUnits))
        override val authenticatedSourceHeaderCandidatePaths: List<String> =
            Collections.unmodifiableList(ArrayList(state.sourceHeaderCandidates))
        override val blockerCodes: List<String> =
            Collections.unmodifiableList(ArrayList(HEADER_READINESS_BLOCKER_CODES))
        override val canonicalBytes: ByteArray
            get() = state.bytes.copyOf()

        companion object {
            fun create(
                sourceArchivePath: Path,
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                planningInventoryPath: Path,
                artifactPath: Path,
                limits: FullTreeHeaderPlanReadinessLimits,
                publish: Boolean,
            ): AuthenticatedFullTreeHeaderPlanReadiness = ValidatedReadiness(
                sourceArchivePath,
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                artifactPath,
                limits,
                publish,
            )
        }
    }
}

private fun authenticateReadinessState(
    paths: ReadinessPaths,
    limits: FullTreeHeaderPlanReadinessLimits,
    publish: Boolean,
): ReadinessState {
    requireDistinctControlOutput(
        paths.artifact,
        "source archive" to paths.sourceArchive,
        "scope" to paths.scope,
        "source lock" to paths.sourceLock,
        "artifact manifest" to paths.artifactManifest,
        "build record" to paths.buildRecord,
        "full-tree inventory" to paths.inventory,
        "full-tree source inventory" to paths.sourceInventory,
        "full-tree planning inventory" to paths.planningInventory,
    )
    val snapshot = authenticateReadinessInputs(paths, limits)
    val expected = buildReadinessDocument(snapshot)
    val bytes = if (publish) {
        validateReadinessDocument(expected, limits)
        publishCanonicalControl(paths.artifact, expected, limits.maximumSerializedBytes)
    } else {
        val (loaded, loadedBytes) = readCanonicalControlObject(
            paths.artifact,
            limits.maximumSerializedBytes,
            "full-tree header-plan readiness",
            HEADER_READINESS_SCHEMA,
        )
        validateReadinessDocument(loaded, limits)
        if (loaded != expected) readinessFail("readiness artifact differs from authenticated prerequisites")
        loadedBytes
    }
    if (bytes.size > limits.maximumSerializedBytes) readinessFail("readiness artifact exceeds its byte bound")
    terminallyReauthenticateReadinessInputs(paths, limits, snapshot)
    return ReadinessState(
        artifactSha256 = OracleArtifacts.sha256(bytes),
        artifactBytes = bytes.size.toLong(),
        reportSha256 = expected.controlString("reportSha256"),
        configurationSha256 = FullTreeHeaderPlanReadinessControl.configurationSha256,
        planningArtifactSha256 = snapshot.planningArtifactSha256,
        planningReportSha256 = snapshot.planningReportSha256,
        planningConfigurationSha256 = snapshot.planningConfigurationSha256,
        dependencyArtifactSha256 = snapshot.dependencyArtifactSha256,
        dependencyReportSha256 = snapshot.dependencyReportSha256,
        dependencyConfigurationSha256 = snapshot.dependencyConfigurationSha256,
        sourceArchiveSha256 = snapshot.sourceArchiveSha256,
        sourceHeaderManifestSha256 = snapshot.sourceHeaderManifestSha256,
        sourceModules = snapshot.sourceModules,
        sourceOnlyUnits = snapshot.sourceOnlyUnits,
        sourceHeaderCandidates = snapshot.sourceHeaderCandidates,
        bytes = bytes.copyOf(),
    )
}

private fun terminallyReauthenticateReadinessInputs(
    paths: ReadinessPaths,
    limits: FullTreeHeaderPlanReadinessLimits,
    initial: ReadinessSnapshot,
) {
    val terminalRegistry = FullTreePlanningInventoryControl.loadAndValidate(
        paths.planningInventory,
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        paths.buildRecord,
        paths.inventory,
        paths.sourceInventory,
        limits.dependencies.planning,
    )
    val terminalModules = terminalRegistry.sourceModules.map { module ->
        listOf(module.moduleId, module.unitId, module.shardId, module.sourceKind, module.sourcePath)
    }
    val initialModules = initial.sourceModules.map { module ->
        listOf(module.moduleId, module.unitId, module.shardId, module.sourceKind, module.sourcePath)
    }
    val terminalSourceOnly = terminalRegistry.sourceOnlyUnits.map { unit ->
        listOf(unit.sourcePath, unit.shardId, unit.reasonCode)
    }
    val initialSourceOnly = initial.sourceOnlyUnits.map { unit ->
        listOf(unit.sourcePath, unit.shardId, unit.reasonCode)
    }
    if (terminalRegistry.artifactSha256 != initial.planningArtifactSha256 ||
        terminalRegistry.reportSha256 != initial.planningReportSha256 ||
        terminalRegistry.configurationSha256 != initial.planningConfigurationSha256 ||
        terminalModules != initialModules || terminalSourceOnly != initialSourceOnly
    ) {
        readinessFail("planning inputs changed before terminal readiness acceptance")
    }

    val archive = StableControlFile.open(
        paths.sourceArchive,
        limits.dependencies.planning.control.maximumSourceArchiveBytes,
        "terminal readiness source archive",
    )
    try {
        if (archive.sha256(label = "terminal readiness source archive") != initial.sourceArchiveSha256) {
            readinessFail("source archive changed before terminal readiness acceptance")
        }
    } finally {
        archive.close()
    }
}

private fun authenticateReadinessInputs(
    paths: ReadinessPaths,
    limits: FullTreeHeaderPlanReadinessLimits,
): ReadinessSnapshot {
    val registry = FullTreePlanningInventoryControl.loadAndValidate(
        paths.planningInventory,
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        paths.buildRecord,
        paths.inventory,
        paths.sourceInventory,
        limits.dependencies.planning,
    )
    if (registry.sourceModules.size > limits.maximumSourceModules) {
        readinessFail("readiness source-module population exceeds its configured bound")
    }
    if (registry.sourceOnlyUnits.size > limits.maximumSourceOnlyUnits) {
        readinessFail("readiness source-only population exceeds its configured bound")
    }
    val dependency = FullTreeSourceHeaderDependencies.assess(
        paths.sourceArchive,
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        paths.buildRecord,
        paths.inventory,
        paths.sourceInventory,
        paths.planningInventory,
        limits.dependencies,
    )
    if (dependency.planningInventoryArtifactSha256 != registry.artifactSha256) {
        readinessFail("source/header assessment differs from the authenticated planning registry")
    }
    if (dependency.canonicalSourceHeaderPaths.size > limits.maximumAuthenticatedSourceHeaderCandidates) {
        readinessFail("readiness source-header candidate population exceeds its configured bound")
    }
    if (HEADER_READINESS_BLOCKER_CODES.size > limits.maximumBlockers) {
        readinessFail("readiness blocker population exceeds its configured bound")
    }

    val sourceModules = registry.sourceModules.map { module ->
        ReadinessSourceModule(
            module.moduleId,
            module.unitId,
            module.shardId,
            module.sourceKind,
            module.sourcePath,
        )
    }
    val sourceOnlyUnits = registry.sourceOnlyUnits.map { unit ->
        ReadinessSourceOnlyUnit(unit.sourcePath, unit.shardId, unit.reasonCode)
    }
    val sourceHeaderCandidates = ArrayList(dependency.canonicalSourceHeaderPaths)
    validateReadinessPopulations(sourceModules, sourceOnlyUnits, sourceHeaderCandidates)
    if (readinessSourceHeaderManifestSha256(sourceHeaderCandidates) !=
        dependency.canonicalSourceHeaderManifestSha256
    ) {
        readinessFail("authenticated source-header candidate manifest commitment does not reconcile")
    }

    val populationRecords = addReadinessCount(
        addReadinessCount(sourceModules.size.toLong(), sourceOnlyUnits.size.toLong(), "population record"),
        sourceHeaderCandidates.size.toLong(),
        "population record",
    )
    val outputRecords = addReadinessCount(
        populationRecords,
        HEADER_READINESS_BLOCKER_CODES.size.toLong(),
        "output record",
    )
    if (outputRecords > limits.maximumOutputRecords) {
        readinessFail("readiness output record population exceeds its configured bound")
    }
    val workUnits = addReadinessCount(
        Math.multiplyExact(populationRecords, 3L),
        HEADER_READINESS_FIXED_WORK_UNITS,
        "work unit",
    )
    if (workUnits > limits.maximumWorkUnits) {
        readinessFail("readiness aggregation exceeds its configured work-unit bound")
    }
    val dependencyBytes = dependency.canonicalBytes
    return ReadinessSnapshot(
        planningArtifactSha256 = registry.artifactSha256,
        planningReportSha256 = registry.reportSha256,
        planningConfigurationSha256 = registry.configurationSha256,
        dependencyArtifactSha256 = OracleArtifacts.sha256(dependencyBytes),
        dependencyReportSha256 = dependency.reportSha256,
        dependencyConfigurationSha256 = FullTreeSourceHeaderDependencies.configurationSha256,
        sourceArchiveSha256 = dependency.sourceArchiveSha256,
        sourceHeaderManifestSha256 = dependency.canonicalSourceHeaderManifestSha256,
        sourceModules = immutableReadinessList(sourceModules),
        sourceOnlyUnits = immutableReadinessList(sourceOnlyUnits),
        sourceHeaderCandidates = immutableReadinessList(sourceHeaderCandidates),
        outputRecords = outputRecords,
        workUnits = workUnits,
    )
}

private fun validateReadinessPopulations(
    modules: List<ReadinessSourceModule>,
    sourceOnly: List<ReadinessSourceOnlyUnit>,
    headers: List<String>,
) {
    if (modules.isEmpty()) readinessFail("readiness requires at least one authenticated source module")
    val moduleIds = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    val modulePaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    var previousModule: ReadinessSourceModule? = null
    modules.forEach { module ->
        if (!HEADER_READINESS_MODULE_ID.matches(module.moduleId) || module.moduleId != module.unitId) {
            readinessFail("readiness module identity differs from its authenticated A13 unit")
        }
        requireReadinessShard(module.shardId, "source module")
        requireReadinessPath(module.sourcePath, "source module")
        if (module.sourceKind !in HEADER_READINESS_SOURCE_KINDS ||
            (module.sourceKind == "generated") != module.sourcePath.startsWith("generated/")
        ) {
            readinessFail("readiness source module kind differs from its canonical path")
        }
        if (!moduleIds.add(module.moduleId) || !modulePaths.add(module.sourcePath)) {
            readinessFail("readiness source modules repeat an identity or path")
        }
        previousModule?.let { preceding ->
            if (HEADER_READINESS_MODULE_ORDER.compare(preceding, module) >= 0) {
                readinessFail("readiness source modules are not strictly ordered")
            }
        }
        previousModule = module
    }

    val sourceOnlyPaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    var previousSourceOnly: String? = null
    sourceOnly.forEach { unit ->
        requireReadinessShard(unit.shardId, "source-only unit")
        requireReadinessSourcePath(unit.sourcePath, "source-only unit")
        if (unit.reasonCode !in HEADER_READINESS_SOURCE_ONLY_REASONS) {
            readinessFail("readiness source-only reason is unsupported")
        }
        if (!sourceOnlyPaths.add(unit.sourcePath)) readinessFail("readiness source-only path is repeated")
        previousSourceOnly?.let { preceding ->
            if (FULL_TREE_CODE_POINT_ORDER.compare(preceding, unit.sourcePath) >= 0) {
                readinessFail("readiness source-only paths are not strictly ordered")
            }
        }
        previousSourceOnly = unit.sourcePath
    }

    val headerPaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    var previousHeader: String? = null
    headers.forEach { path ->
        requireReadinessSourcePath(path, "authenticated source-header candidate")
        if (HEADER_READINESS_HEADER_SUFFIXES.none(path::endsWith)) {
            readinessFail("authenticated source-header candidate has an unsupported suffix")
        }
        if (!headerPaths.add(path)) readinessFail("authenticated source-header candidate is repeated")
        previousHeader?.let { preceding ->
            if (FULL_TREE_CODE_POINT_ORDER.compare(preceding, path) >= 0) {
                readinessFail("authenticated source-header candidates are not strictly ordered")
            }
        }
        previousHeader = path
    }
    if (modulePaths.any { it in sourceOnlyPaths || it in headerPaths } ||
        sourceOnlyPaths.any { it in headerPaths }
    ) {
        readinessFail("readiness module, source-only, and source-header populations overlap")
    }
}

private fun buildReadinessDocument(snapshot: ReadinessSnapshot): JsonObject {
    val generatedModules = snapshot.sourceModules.count { it.sourceKind == "generated" }
    val populations = JsonObject(
        mapOf(
            "authenticatedSourceHeaderCandidates" to JsonArray(
                snapshot.sourceHeaderCandidates.map(::JsonPrimitive),
            ),
            "sourceModules" to JsonArray(snapshot.sourceModules.map { module ->
                JsonObject(
                    mapOf(
                        "moduleId" to JsonPrimitive(module.moduleId),
                        "shardId" to JsonPrimitive(module.shardId),
                        "sourceKind" to JsonPrimitive(module.sourceKind),
                        "sourcePath" to JsonPrimitive(module.sourcePath),
                        "unitId" to JsonPrimitive(module.unitId),
                    ),
                )
            }),
            "sourceOnlyUnits" to JsonArray(snapshot.sourceOnlyUnits.map { unit ->
                JsonObject(
                    mapOf(
                        "reasonCode" to JsonPrimitive(unit.reasonCode),
                        "shardId" to JsonPrimitive(unit.shardId),
                        "sourcePath" to JsonPrimitive(unit.sourcePath),
                    ),
                )
            }),
        ),
    )
    val withoutHash = JsonObject(
        mapOf(
            "acpBoundary" to HEADER_READINESS_ACP_BOUNDARY,
            "authority" to HEADER_READINESS_AUTHORITY,
            "blockers" to HEADER_READINESS_BLOCKERS,
            "bounds" to HEADER_READINESS_BOUNDS,
            "counts" to JsonObject(
                mapOf(
                    "authenticatedSourceHeaderCandidates" to JsonPrimitive(
                        snapshot.sourceHeaderCandidates.size,
                    ),
                    "blockers" to JsonPrimitive(HEADER_READINESS_BLOCKER_CODES.size),
                    "generatedSourceModules" to JsonPrimitive(generatedModules),
                    "handwrittenSourceModules" to JsonPrimitive(
                        snapshot.sourceModules.size - generatedModules,
                    ),
                    "outputRecords" to JsonPrimitive(snapshot.outputRecords),
                    "sourceModules" to JsonPrimitive(snapshot.sourceModules.size),
                    "sourceOnlyUnits" to JsonPrimitive(snapshot.sourceOnlyUnits.size),
                    "workUnits" to JsonPrimitive(snapshot.workUnits),
                ),
            ),
            "kind" to JsonPrimitive(HEADER_READINESS_KIND),
            "oracle" to JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(
                        FullTreeHeaderPlanReadinessControl.configurationSha256,
                    ),
                    "planningInventoryArtifactSha256" to JsonPrimitive(
                        snapshot.planningArtifactSha256,
                    ),
                    "planningInventoryConfigurationSha256" to JsonPrimitive(
                        snapshot.planningConfigurationSha256,
                    ),
                    "planningInventoryReportSha256" to JsonPrimitive(snapshot.planningReportSha256),
                    "sourceArchiveSha256" to JsonPrimitive(snapshot.sourceArchiveSha256),
                    "sourceDependencyArtifactSha256" to JsonPrimitive(
                        snapshot.dependencyArtifactSha256,
                    ),
                    "sourceDependencyConfigurationSha256" to JsonPrimitive(
                        snapshot.dependencyConfigurationSha256,
                    ),
                    "sourceDependencyReportSha256" to JsonPrimitive(snapshot.dependencyReportSha256),
                    "sourceHeaderManifestSha256" to JsonPrimitive(snapshot.sourceHeaderManifestSha256),
                ),
            ),
            "populations" to populations,
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES)),
    )
    return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
}

private fun validateReadinessDocument(
    value: JsonObject,
    limits: FullTreeHeaderPlanReadinessLimits,
) {
    val (document, _) = snapshotControlObject(
        value,
        limits.maximumSerializedBytes,
        "full-tree header-plan readiness",
        HEADER_READINESS_SCHEMA,
    )
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val expected = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumSerializedBytes)),
    )
    if (document.controlString("reportSha256") != expected) {
        readinessFail("readiness report hash does not reconcile")
    }
}

private fun requireReadinessShard(value: String, label: String) {
    if (!HEADER_READINESS_SHARD_ID.matches(value) || value in HEADER_READINESS_CATCH_ALL_IDS) {
        readinessFail("readiness $label shard is malformed or a forbidden catch-all")
    }
}

private fun requireReadinessSourcePath(value: String, label: String) {
    if (!value.startsWith("source/")) readinessFail("readiness $label is not source-backed")
    requireReadinessPath(value, label)
}

private fun requireReadinessPath(value: String, label: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    if (value.isEmpty() || bytes.size > HEADER_READINESS_MAXIMUM_PATH_BYTES || value.startsWith('/') ||
        '\\' in value || value.any { it.code !in 0x20..0x7e } ||
        !(value.startsWith("source/") || value.startsWith("generated/")) ||
        value.split('/').any { it.isEmpty() || it == "." || it == ".." }
    ) {
        readinessFail("readiness $label path is not canonical and bounded")
    }
}

private fun addReadinessCount(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeHeaderPlanReadinessException("readiness $label count overflows", failure)
}

private fun readinessSourceHeaderManifestSha256(paths: List<String>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    listOf(
        "full-tree-source-header-dependencies-v1-length-framed-utf8",
        "full-tree-source-header-manifest-v1",
        "canonical-source-header-paths",
    ).forEach { digest.updateReadinessFrame(it) }
    paths.forEach { digest.updateReadinessFrame(it) }
    return digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun MessageDigest.updateReadinessFrame(value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
    update(bytes)
}

private fun <T> immutableReadinessList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun readinessFail(message: String): Nothing = throw FullTreeHeaderPlanReadinessException(message)

private data class ReadinessPaths(
    val sourceArchive: Path,
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
    val buildRecord: Path,
    val inventory: Path,
    val sourceInventory: Path,
    val planningInventory: Path,
    val artifact: Path,
)

private data class ReadinessSourceModule(
    override val moduleId: String,
    override val unitId: String,
    override val shardId: String,
    override val sourceKind: String,
    override val sourcePath: String,
) : FullTreePlanningSourceModule

private data class ReadinessSourceOnlyUnit(
    override val sourcePath: String,
    override val shardId: String,
    override val reasonCode: String,
) : FullTreePlanningSourceOnlyUnit

private data class ReadinessSnapshot(
    val planningArtifactSha256: String,
    val planningReportSha256: String,
    val planningConfigurationSha256: String,
    val dependencyArtifactSha256: String,
    val dependencyReportSha256: String,
    val dependencyConfigurationSha256: String,
    val sourceArchiveSha256: String,
    val sourceHeaderManifestSha256: String,
    val sourceModules: List<ReadinessSourceModule>,
    val sourceOnlyUnits: List<ReadinessSourceOnlyUnit>,
    val sourceHeaderCandidates: List<String>,
    val outputRecords: Long,
    val workUnits: Long,
)

private data class ReadinessState(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val planningArtifactSha256: String,
    val planningReportSha256: String,
    val planningConfigurationSha256: String,
    val dependencyArtifactSha256: String,
    val dependencyReportSha256: String,
    val dependencyConfigurationSha256: String,
    val sourceArchiveSha256: String,
    val sourceHeaderManifestSha256: String,
    val sourceModules: List<ReadinessSourceModule>,
    val sourceOnlyUnits: List<ReadinessSourceOnlyUnit>,
    val sourceHeaderCandidates: List<String>,
    val bytes: ByteArray,
)

private val HEADER_READINESS_MODULE_ORDER = Comparator<ReadinessSourceModule> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.sourcePath, right.sourcePath).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.unitId, right.unitId)
}
private val HEADER_READINESS_MODULE_ID = Regex("cu-[0-9a-f]{32}")
private val HEADER_READINESS_SHARD_ID = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val HEADER_READINESS_SOURCE_KINDS = setOf("generated", "handwritten")
private val HEADER_READINESS_SOURCE_ONLY_REASONS = setOf(
    "not-selected-by-authenticated-build-graph",
    "target-not-enabled-or-not-linked",
    "tool-not-linked-into-clang-driver",
)
private val HEADER_READINESS_HEADER_SUFFIXES = setOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc")
private val HEADER_READINESS_CATCH_ALL_IDS = setOf("catch-all", "catchall", "core", "default", "misc", "unowned")

private const val HEADER_READINESS_SCHEMA = "full-tree-header-plan-readiness"
private const val HEADER_READINESS_KIND = "full-tree-header-plan-readiness-v1"
private const val HEADER_READINESS_MAXIMUM_PATH_BYTES = 4096
internal const val HEADER_READINESS_MAXIMUM_SOURCE_MODULES = 10_000
internal const val HEADER_READINESS_MAXIMUM_SOURCE_ONLY_UNITS = 50_000
internal const val HEADER_READINESS_MAXIMUM_AUTHENTICATED_SOURCE_HEADER_CANDIDATES = 50_000
internal const val HEADER_READINESS_MAXIMUM_BLOCKERS = 5
internal const val HEADER_READINESS_MAXIMUM_OUTPUT_RECORDS = 110_005
internal const val HEADER_READINESS_MAXIMUM_WORK_UNITS = 1_000_000L
internal const val HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES = 16 * 1024 * 1024
private const val HEADER_READINESS_FIXED_WORK_UNITS = 19L

private val HEADER_READINESS_BLOCKER_CODES = listOf(
    "complete-project-header-inventory-missing",
    "compiler-capture-provenance-missing",
    "generated-file-provenance-missing",
    "ninja-generator-provenance-missing",
    "physical-project-roots-unverified",
)
private val HEADER_READINESS_BLOCKERS = JsonArray(HEADER_READINESS_BLOCKER_CODES.map { code ->
    JsonObject(
        mapOf(
            "code" to JsonPrimitive(code),
            "status" to JsonPrimitive("unresolved"),
        ),
    )
})
private val HEADER_READINESS_AUTHORITY = JsonObject(
    mapOf(
        "cleanCompilationProven" to JsonPrimitive(false),
        "compilerCaptureAuthenticated" to JsonPrimitive(false),
        "headerPlanReady" to JsonPrimitive(false),
        "headerPopulationComplete" to JsonPrimitive(false),
        "purpose" to JsonPrimitive("a14-header-plan-readiness"),
        "releaseEligible" to JsonPrimitive(false),
        "status" to JsonPrimitive("incomplete-authenticated-prerequisites"),
    ),
)
private val HEADER_READINESS_ACP_BOUNDARY = JsonObject(
    mapOf(
        "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
        "candidateContribution" to JsonPrimitive("authenticated-session-change-build-artifact-provenance"),
        "candidateEvidenceDisposition" to JsonPrimitive("non-authoritative-input-to-later-host-validation"),
        "candidateLineageAdmission" to JsonPrimitive("not-an-input-to-readiness-v1"),
        "candidateLiveExecutionOwner" to JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
        "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
        "certificationAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "observationAuthoringAuthority" to JsonPrimitive(false),
        "oracleAuthority" to JsonPrimitive(false),
        "policyAuthoringAuthority" to JsonPrimitive(false),
        "referenceAuthoringAuthority" to JsonPrimitive(false),
        "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
        "releaseAuthority" to JsonPrimitive(false),
        "role" to JsonPrimitive("first-class-candidate-producer-operator"),
        "scoringAuthority" to JsonPrimitive(false),
        "startAuthority" to JsonPrimitive(false),
        "terminalAbsenceAuthority" to JsonPrimitive(false),
        "validationAuthority" to JsonPrimitive(false),
    ),
)
private val HEADER_READINESS_BOUNDS = JsonObject(
    mapOf(
        "maximumAuthenticatedSourceHeaderCandidates" to JsonPrimitive(
            HEADER_READINESS_MAXIMUM_AUTHENTICATED_SOURCE_HEADER_CANDIDATES,
        ),
        "maximumBlockers" to JsonPrimitive(HEADER_READINESS_MAXIMUM_BLOCKERS),
        "maximumOutputRecords" to JsonPrimitive(HEADER_READINESS_MAXIMUM_OUTPUT_RECORDS),
        "maximumSerializedBytes" to JsonPrimitive(HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES),
        "maximumSourceModules" to JsonPrimitive(HEADER_READINESS_MAXIMUM_SOURCE_MODULES),
        "maximumSourceOnlyUnits" to JsonPrimitive(HEADER_READINESS_MAXIMUM_SOURCE_ONLY_UNITS),
        "maximumWorkUnits" to JsonPrimitive(HEADER_READINESS_MAXIMUM_WORK_UNITS),
    ),
)
private val HEADER_READINESS_POLICY = JsonObject(
    mapOf(
        "acpBoundary" to HEADER_READINESS_ACP_BOUNDARY,
        "authenticatedSourceHeaderCandidates" to JsonPrimitive(
            "eligible-regular-source-headers-under-a13-derived-enabled-roots",
        ),
        "blockers" to JsonArray(HEADER_READINESS_BLOCKER_CODES.map(::JsonPrimitive)),
        "bounds" to HEADER_READINESS_BOUNDS,
        "id" to JsonPrimitive(HEADER_READINESS_SCHEMA),
        "moduleIdentity" to JsonPrimitive("authenticated-a13-planning-unit-id"),
        "outputRecordModel" to JsonPrimitive(
            "source-modules-plus-source-only-plus-authenticated-source-header-candidates-plus-fixed-blockers",
        ),
        "sourceOnlyOwnership" to JsonPrimitive("excluded-non-owning"),
        "version" to JsonPrimitive(1),
        "workUnitModel" to JsonPrimitive(
            "three-per-population-record-plus-two-per-fixed-blocker-plus-nine-provenance-bindings",
        ),
    ),
)

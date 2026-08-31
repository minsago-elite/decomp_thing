package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Caller-selectable ceilings beneath the immutable planning-inventory v1 policy maxima. */
data class FullTreePlanningInventoryLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val maximumSourceModules: Int = PLANNING_MAXIMUM_SOURCE_MODULES,
    val maximumCandidateSourceUnits: Int = PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS,
    val maximumOutputRecords: Int = PLANNING_MAXIMUM_OUTPUT_RECORDS,
    val maximumWorkUnits: Long = PLANNING_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = PLANNING_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumSourceModules in 1..PLANNING_MAXIMUM_SOURCE_MODULES)
        require(maximumCandidateSourceUnits in 1..PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS)
        require(maximumOutputRecords in 1..PLANNING_MAXIMUM_OUTPUT_RECORDS)
        require(maximumWorkUnits in 1L..PLANNING_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..PLANNING_MAXIMUM_SERIALIZED_BYTES)
    }
}

/** A non-authoritative value view returned only from an authenticated planning registry. */
sealed interface FullTreePlanningSourceModule {
    val moduleId: String
    val unitId: String
    val shardId: String
    val sourceKind: String
    val sourcePath: String
}

/** Source evidence excluded from the authenticated linked/generated compilation-unit population. */
sealed interface FullTreePlanningSourceOnlyUnit {
    val sourcePath: String
    val shardId: String
    val reasonCode: String
}

/**
 * Opaque, immutable registry constructed only by [FullTreePlanningInventoryControl] after complete
 * schema, digest, provenance, semantic, and bounds validation.
 */
sealed interface AuthenticatedFullTreePlanningRegistry {
    val artifactSha256: String
    val reportSha256: String
    val configurationSha256: String
    val sourceModules: List<FullTreePlanningSourceModule>
    val sourceOnlyUnits: List<FullTreePlanningSourceOnlyUnit>

    /** Resolves an authenticated A13 owner unit exactly; there is no nullable or catch-all fallback. */
    fun requireOwnerModule(ownerUnitId: String): FullTreePlanningSourceModule
}

data class FullTreePlanningInventoryGeneration(
    val registry: AuthenticatedFullTreePlanningRegistry,
    val reportSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
)

/**
 * Kotlin/JVM authority for the source-boundary-only A14 planning inventory.
 *
 * This deliberately makes no recovered-entity, header, dependency, or build-graph claim. One
 * stable module is registered for each authenticated compilation unit, while source-only units
 * remain non-owning evidence.
 */
object FullTreePlanningInventoryControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(PLANNING_SCHEMA, PLANNING_POLICY)
    }

    fun generateAndPublish(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        output: Path,
        limits: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    ): FullTreePlanningInventoryGeneration = ValidatedFullTreePlanningRegistry.generate(
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        output,
        limits,
    )

    fun loadAndValidate(
        path: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        limits: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    ): AuthenticatedFullTreePlanningRegistry = ValidatedFullTreePlanningRegistry.load(
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        path,
        limits,
    )

    private fun authenticateRegistryState(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        path: Path,
        limits: FullTreePlanningInventoryLimits,
        publish: Boolean,
    ): ValidatedPlanningRegistryState {
        requireOutputDistinctFromInputs(
            path,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
        )
        val inputs = authenticateInputs(
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            limits,
        )
        val (document, bytes) = if (publish) {
            val generated = buildDocument(inputs, limits)
            validateShapeAndHash(generated, limits)
            generated to publishCanonicalControl(path, generated, limits.maximumSerializedBytes)
        } else {
            readCanonicalControlObject(
                path,
                limits.maximumSerializedBytes,
                "full-tree planning inventory",
                PLANNING_SCHEMA,
            ).also { (loaded, _) -> validateDocument(loaded, inputs, limits) }
        }
        return validatedRegistryState(document, OracleArtifacts.sha256(bytes), bytes.size.toLong())
    }

    private fun authenticateInputs(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        limits: FullTreePlanningInventoryLimits,
    ): AuthenticatedPlanningInputs {
        val control = limits.control
        val scope = FullTreeScopeControl.load(scopePath, sourceLockPath, artifactManifestPath, control)
        val (buildRecord, buildRecordBytes) = readCanonicalControlObject(
            buildRecordPath,
            control.maximumBuildRecordBytes,
            "build record",
            "build-record",
        )
        val (inventory, inventoryBytes) = readCanonicalControlObject(
            inventoryPath,
            control.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        FullTreeInventoryControl.validate(inventory, scope, control)
        val (sourceInventory, sourceInventoryBytes) = readCanonicalControlObject(
            sourceInventoryPath,
            control.maximumSourceInventoryBytes,
            "full-tree source inventory",
            "full-tree-source-inventory",
        )
        FullTreeSourceInventoryControl.validate(sourceInventory, scope, buildRecord, inventory, control)
        return AuthenticatedPlanningInputs(
            scope = scope,
            buildRecordSha256 = OracleArtifacts.sha256(buildRecordBytes),
            inventory = inventory,
            inventoryArtifactSha256 = OracleArtifacts.sha256(inventoryBytes),
            sourceInventory = sourceInventory,
            sourceInventoryArtifactSha256 = OracleArtifacts.sha256(sourceInventoryBytes),
        )
    }

    private fun buildDocument(
        inputs: AuthenticatedPlanningInputs,
        limits: FullTreePlanningInventoryLimits,
    ): JsonObject {
        enforceInputBounds(inputs, limits)
        val inventoryUnits = inputs.inventory.controlArray("units").controlObjects("inventory units")
        val sourceUnits = inputs.sourceInventory.controlArray("sourceUnits")
            .controlObjects("source inventory units")
        val generatedUnits = inputs.sourceInventory.controlArray("generatedCompilationUnits")
            .controlObjects("generated compilation units")

        val sourceModules = inventoryUnits.map { unit ->
            val unitId = unit.controlString("id")
            JsonObject(
                mapOf(
                    "moduleId" to JsonPrimitive(unitId),
                    "shardId" to unit.getValue("shardId"),
                    "sourceKind" to unit.getValue("sourceKind"),
                    "sourcePath" to unit.getValue("sourcePath"),
                    "unitId" to JsonPrimitive(unitId),
                ),
            )
        }.sortedWith(SOURCE_MODULE_ORDER)
        val sourceOnlyUnits = sourceUnits.asSequence()
            .filter { it.controlString("classification") == "source-only" }
            .map { unit ->
                JsonObject(
                    mapOf(
                        "reasonCode" to unit.getValue("reasonCode"),
                        "shardId" to unit.getValue("shardId"),
                        "sourcePath" to unit.getValue("path"),
                    ),
                )
            }
            .sortedWith(SOURCE_ONLY_ORDER)
            .toList()

        val outputRecords = addExact(
            sourceModules.size.toLong(),
            sourceOnlyUnits.size.toLong(),
            "planning output record",
        )
        if (outputRecords > limits.maximumOutputRecords || outputRecords > PLANNING_MAXIMUM_OUTPUT_RECORDS) {
            throw FullTreeControlException("planning inventory exceeds its output-record bound")
        }
        val workUnits = listOf(
            inventoryUnits.size,
            sourceUnits.size,
            generatedUnits.size,
            sourceModules.size,
            sourceOnlyUnits.size,
        ).fold(0L) { total, count -> addExact(total, count.toLong(), "planning work-unit") }
        if (workUnits > limits.maximumWorkUnits || workUnits > PLANNING_MAXIMUM_WORK_UNITS) {
            throw FullTreeControlException("planning inventory exceeds its work-unit bound")
        }

        val generated = sourceModules.count { it.controlString("sourceKind") == "generated" }
        val authenticatedModuleBound = minOf(
            inputs.scope.document.controlObject("bounds").controlObject("wholeRun")
                .controlLong("compilationUnits"),
            PLANNING_MAXIMUM_SOURCE_MODULES.toLong(),
        )
        val withoutHash = JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "maximumCandidateSourceUnits" to JsonPrimitive(PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS),
                        "maximumOutputRecords" to JsonPrimitive(PLANNING_MAXIMUM_OUTPUT_RECORDS),
                        "maximumSerializedBytes" to JsonPrimitive(PLANNING_MAXIMUM_SERIALIZED_BYTES),
                        "maximumSourceModules" to JsonPrimitive(authenticatedModuleBound),
                        "maximumWorkUnits" to JsonPrimitive(PLANNING_MAXIMUM_WORK_UNITS),
                    ),
                ),
                "counts" to JsonObject(
                    mapOf(
                        "generatedSourceModules" to JsonPrimitive(generated),
                        "handwrittenSourceModules" to JsonPrimitive(sourceModules.size - generated),
                        "sourceModuleShards" to JsonPrimitive(
                            sourceModules.map { it.controlString("shardId") }.toSet().size,
                        ),
                        "sourceModules" to JsonPrimitive(sourceModules.size),
                        "sourceOnlyShards" to JsonPrimitive(
                            sourceOnlyUnits.map { it.controlString("shardId") }.toSet().size,
                        ),
                        "sourceOnlyUnits" to JsonPrimitive(sourceOnlyUnits.size),
                        "workUnits" to JsonPrimitive(workUnits),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(inputs.scope.artifactManifestSha256),
                        "buildRecordSha256" to JsonPrimitive(inputs.buildRecordSha256),
                        "configurationSha256" to JsonPrimitive(configurationSha256),
                        "id" to inputs.scope.document.controlObject("oracle").getValue("id"),
                        "inventoryArtifactSha256" to JsonPrimitive(inputs.inventoryArtifactSha256),
                        "inventoryIndexSha256" to inputs.inventory.getValue("indexSha256"),
                        "scopeSha256" to JsonPrimitive(inputs.scope.sha256),
                        "sourceInventoryArtifactSha256" to JsonPrimitive(inputs.sourceInventoryArtifactSha256),
                        "sourceInventoryReportSha256" to inputs.sourceInventory.getValue("reportSha256"),
                        "sourceLockSha256" to JsonPrimitive(inputs.scope.sourceLockSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "sourceModules" to JsonArray(sourceModules),
                "sourceOnlyUnits" to JsonArray(sourceOnlyUnits),
            ),
        )
        val reportSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(withoutHash, controlJsonLimits(PLANNING_MAXIMUM_SERIALIZED_BYTES)),
        )
        return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
    }

    private fun enforceInputBounds(
        inputs: AuthenticatedPlanningInputs,
        limits: FullTreePlanningInventoryLimits,
    ) {
        val sourceModules = inputs.inventory.controlArray("units").size
        val sourceCandidates = inputs.sourceInventory.controlArray("sourceUnits").size
        val authenticatedModules = inputs.scope.document.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        val effectiveModuleLimit = minOf(
            authenticatedModules,
            limits.maximumSourceModules.toLong(),
            limits.control.maximumCompilationUnits.toLong(),
            PLANNING_MAXIMUM_SOURCE_MODULES.toLong(),
        )
        if (sourceModules.toLong() > effectiveModuleLimit) {
            throw FullTreeControlException("planning inventory exceeds its source-module bound")
        }
        if (sourceCandidates > limits.maximumCandidateSourceUnits ||
            sourceCandidates > limits.control.maximumArchiveMembers ||
            sourceCandidates > PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS
        ) {
            throw FullTreeControlException("planning inventory exceeds its candidate-source-unit bound")
        }
    }

    private fun validateDocument(
        value: JsonObject,
        inputs: AuthenticatedPlanningInputs,
        limits: FullTreePlanningInventoryLimits,
    ) {
        val document = validateShapeAndHash(value, limits)
        val expected = buildDocument(inputs, limits)
        if (document != expected) {
            throw FullTreeControlException("planning inventory differs from authenticated source-boundary inputs")
        }
    }

    private fun validateShapeAndHash(
        value: JsonObject,
        limits: FullTreePlanningInventoryLimits,
    ): JsonObject {
        val (document, _) = snapshotControlObject(
            value,
            limits.maximumSerializedBytes,
            "full-tree planning inventory",
            PLANNING_SCHEMA,
        )
        val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
        val expectedReportSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumSerializedBytes)),
        )
        if (document.controlString("reportSha256") != expectedReportSha256) {
            throw FullTreeControlException("planning inventory report hash does not reconcile")
        }
        return document
    }

    private fun requireOutputDistinctFromInputs(
        output: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
    ) = requireDistinctControlOutput(
        output,
        "scope" to scopePath,
        "source lock" to sourceLockPath,
        "artifact manifest" to artifactManifestPath,
        "build record" to buildRecordPath,
        "full-tree inventory" to inventoryPath,
        "full-tree source inventory" to sourceInventoryPath,
    )

    private fun validatedRegistryState(
        document: JsonObject,
        artifactSha256: String,
        artifactBytes: Long,
    ): ValidatedPlanningRegistryState {
        requireControlDigest(artifactSha256, "planning inventory artifact")
        val oracle = document.controlObject("oracle")
        val modules = document.controlArray("sourceModules").controlObjects("planning source modules")
            .map { module ->
                val moduleId = module.controlString("moduleId")
                val unitId = module.controlString("unitId")
                if (moduleId != unitId) {
                    throw FullTreeControlException("planning module ID differs from its authenticated unit ID")
                }
                ValidatedSourceModule(
                    moduleId = moduleId,
                    unitId = unitId,
                    shardId = module.controlString("shardId"),
                    sourceKind = module.controlString("sourceKind"),
                    sourcePath = module.controlString("sourcePath"),
                )
            }
        val sourceOnly = document.controlArray("sourceOnlyUnits").controlObjects("planning source-only units")
            .map { unit ->
                ValidatedSourceOnlyUnit(
                    sourcePath = unit.controlString("sourcePath"),
                    shardId = unit.controlString("shardId"),
                    reasonCode = unit.controlString("reasonCode"),
                )
            }
        return ValidatedPlanningRegistryState(
            artifactSha256 = artifactSha256,
            artifactBytes = artifactBytes,
            reportSha256 = document.controlString("reportSha256"),
            configurationSha256 = oracle.controlString("configurationSha256"),
            modules = modules,
            sourceOnly = sourceOnly,
        )
    }

    /**
     * The constructor itself is the production validation boundary. Kotlin emits a public
     * synthetic bridge for a private constructor used by its companion, so that bridge accepts
     * only untrusted production paths, caller-lowering bounds, and the generate/load selector.
     * It cannot accept a parsed document, digest, record collection, authenticated scope, or
     * validation seam; every construction executes the fixed authentication path above.
     */
    private class ValidatedFullTreePlanningRegistry private constructor(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreePlanningInventoryLimits,
        publish: Boolean,
    ) : AuthenticatedFullTreePlanningRegistry {
        private val state = authenticateRegistryState(
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            limits,
            publish,
        )

        override val artifactSha256: String = state.artifactSha256
        override val reportSha256: String = state.reportSha256
        override val configurationSha256: String = state.configurationSha256
        override val sourceModules: List<FullTreePlanningSourceModule> =
            Collections.unmodifiableList(ArrayList(state.modules))
        override val sourceOnlyUnits: List<FullTreePlanningSourceOnlyUnit> =
            Collections.unmodifiableList(ArrayList(state.sourceOnly))
        private val modulesByOwnerUnitId: Map<String, FullTreePlanningSourceModule> = Collections.unmodifiableMap(
            LinkedHashMap<String, FullTreePlanningSourceModule>().apply {
                sourceModules.forEach { module ->
                    if (put(module.unitId, module) != null) {
                        throw FullTreeControlException("planning registry contains duplicate owner unit IDs")
                    }
                }
            },
        )

        override fun requireOwnerModule(ownerUnitId: String): FullTreePlanningSourceModule {
            if (!ownerUnitId.matches(COMPILATION_UNIT_ID)) {
                throw FullTreeControlException("planning owner unit ID is invalid")
            }
            return modulesByOwnerUnitId[ownerUnitId]
                ?: throw FullTreeControlException("planning owner unit ID is outside the authenticated inventory")
        }

        companion object {
            fun generate(
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                output: Path,
                limits: FullTreePlanningInventoryLimits,
            ): FullTreePlanningInventoryGeneration {
                val registry = ValidatedFullTreePlanningRegistry(
                    scopePath,
                    sourceLockPath,
                    artifactManifestPath,
                    buildRecordPath,
                    inventoryPath,
                    sourceInventoryPath,
                    output,
                    limits,
                    true,
                )
                return FullTreePlanningInventoryGeneration(
                    registry = registry,
                    reportSha256 = registry.reportSha256,
                    outputSha256 = registry.artifactSha256,
                    outputBytes = registry.state.artifactBytes,
                )
            }

            fun load(
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                path: Path,
                limits: FullTreePlanningInventoryLimits,
            ): AuthenticatedFullTreePlanningRegistry = ValidatedFullTreePlanningRegistry(
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                path,
                limits,
                false,
            )
        }
    }
}

private data class AuthenticatedPlanningInputs(
    val scope: AuthenticatedFullTreeScope,
    val buildRecordSha256: String,
    val inventory: JsonObject,
    val inventoryArtifactSha256: String,
    val sourceInventory: JsonObject,
    val sourceInventoryArtifactSha256: String,
)

private data class ValidatedSourceModule(
    override val moduleId: String,
    override val unitId: String,
    override val shardId: String,
    override val sourceKind: String,
    override val sourcePath: String,
) : FullTreePlanningSourceModule

private data class ValidatedSourceOnlyUnit(
    override val sourcePath: String,
    override val shardId: String,
    override val reasonCode: String,
) : FullTreePlanningSourceOnlyUnit

private data class ValidatedPlanningRegistryState(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val modules: List<FullTreePlanningSourceModule>,
    val sourceOnly: List<FullTreePlanningSourceOnlyUnit>,
)

private fun addExact(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label count overflows the supported range", failure)
}

private val SOURCE_MODULE_ORDER = Comparator<JsonObject> { left, right ->
    val path = FULL_TREE_CODE_POINT_ORDER.compare(
        left.controlString("sourcePath"),
        right.controlString("sourcePath"),
    )
    if (path != 0) path else FULL_TREE_CODE_POINT_ORDER.compare(
        left.controlString("unitId"),
        right.controlString("unitId"),
    )
}
private val SOURCE_ONLY_ORDER = Comparator<JsonObject> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.controlString("sourcePath"), right.controlString("sourcePath"))
}
private val COMPILATION_UNIT_ID = Regex("cu-[0-9a-f]{32}")

private const val PLANNING_SCHEMA = "full-tree-planning-inventory"
private const val PLANNING_MAXIMUM_SOURCE_MODULES = 1_000_000
private const val PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS = 200_000
private const val PLANNING_MAXIMUM_OUTPUT_RECORDS = 203_000
private const val PLANNING_MAXIMUM_WORK_UNITS = 500_000L
private const val PLANNING_MAXIMUM_SERIALIZED_BYTES = 32 * 1024 * 1024
private val PLANNING_POLICY = JsonObject(
    mapOf(
        "id" to JsonPrimitive(PLANNING_SCHEMA),
        "maximumCandidateSourceUnits" to JsonPrimitive(PLANNING_MAXIMUM_CANDIDATE_SOURCE_UNITS),
        "maximumOutputRecords" to JsonPrimitive(PLANNING_MAXIMUM_OUTPUT_RECORDS),
        "maximumSerializedBytes" to JsonPrimitive(PLANNING_MAXIMUM_SERIALIZED_BYTES),
        "maximumSourceModules" to JsonPrimitive("authenticated-scope-whole-run-compilation-units"),
        "maximumWorkUnits" to JsonPrimitive(PLANNING_MAXIMUM_WORK_UNITS),
        "moduleIdentity" to JsonPrimitive("authenticated-inventory-unit-id"),
        "sourceOnlyOwnership" to JsonPrimitive("forbidden"),
        "version" to JsonPrimitive(1),
        "workUnitModel" to JsonPrimitive("one-per-consumed-input-record-plus-one-per-emitted-record"),
    ),
)

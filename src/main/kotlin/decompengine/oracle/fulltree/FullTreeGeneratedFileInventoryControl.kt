package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.provenance.BoundedTarEntry
import decompengine.oracle.provenance.BoundedTarEntryKind
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzException
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzRegularFileVisitor
import decompengine.oracle.provenance.BoundedTarXzSource
import decompengine.oracle.provenance.BoundedTarXzSummary
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Caller-lowerable ceilings beneath the immutable generated-snapshot v1 policy maxima. */
data class FullTreeGeneratedFileInventoryLimits(
    val planning: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    val maximumArchiveBytes: Long = GENERATED_MAXIMUM_ARCHIVE_BYTES,
    val maximumExpandedArchiveBytes: Long = GENERATED_MAXIMUM_EXPANDED_ARCHIVE_BYTES,
    val maximumXzDecoderMemoryKiB: Int = GENERATED_MAXIMUM_XZ_DECODER_MEMORY_KIB,
    val maximumArchiveMembers: Int = GENERATED_MAXIMUM_ARCHIVE_MEMBERS,
    val maximumArchiveIndexBytes: Long = GENERATED_MAXIMUM_ARCHIVE_INDEX_BYTES,
    val maximumPathBytes: Int = GENERATED_MAXIMUM_PATH_BYTES,
    val maximumPathComponentBytes: Int = GENERATED_MAXIMUM_PATH_COMPONENT_BYTES,
    val maximumProvenanceBytes: Int = GENERATED_MAXIMUM_PROVENANCE_BYTES,
    val maximumGeneratedHeaders: Int = GENERATED_MAXIMUM_HEADERS,
    val maximumGeneratedTranslationUnits: Int = GENERATED_MAXIMUM_TRANSLATION_UNITS,
    val maximumGeneratedFiles: Int = GENERATED_MAXIMUM_FILES,
    val maximumGeneratedFileBytes: Long = GENERATED_MAXIMUM_FILE_BYTES,
    val maximumTotalGeneratedFileBytes: Long = GENERATED_MAXIMUM_TOTAL_FILE_BYTES,
    val maximumGeneratorActions: Int = GENERATED_MAXIMUM_ACTIONS,
    val maximumActionOutputReferences: Int = GENERATED_MAXIMUM_ACTION_OUTPUT_REFERENCES,
    val maximumCmakeEvidenceBytes: Long = GENERATED_MAXIMUM_CMAKE_EVIDENCE_BYTES,
    val maximumNinjaEvidenceBytes: Long = GENERATED_MAXIMUM_NINJA_EVIDENCE_BYTES,
    val maximumOutputRecords: Int = GENERATED_MAXIMUM_OUTPUT_RECORDS,
    val maximumWorkUnits: Long = GENERATED_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = GENERATED_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumArchiveBytes in 1L..GENERATED_MAXIMUM_ARCHIVE_BYTES)
        require(maximumExpandedArchiveBytes in 1L..GENERATED_MAXIMUM_EXPANDED_ARCHIVE_BYTES)
        require(maximumXzDecoderMemoryKiB in 1..GENERATED_MAXIMUM_XZ_DECODER_MEMORY_KIB)
        require(maximumArchiveMembers in 1..GENERATED_MAXIMUM_ARCHIVE_MEMBERS)
        require(maximumArchiveIndexBytes in 1L..GENERATED_MAXIMUM_ARCHIVE_INDEX_BYTES)
        require(maximumPathBytes in 1..GENERATED_MAXIMUM_PATH_BYTES)
        require(maximumPathComponentBytes in 1..GENERATED_MAXIMUM_PATH_COMPONENT_BYTES)
        require(maximumProvenanceBytes in 1..GENERATED_MAXIMUM_PROVENANCE_BYTES)
        require(maximumGeneratedHeaders in 1..GENERATED_MAXIMUM_HEADERS)
        require(maximumGeneratedTranslationUnits in 1..GENERATED_MAXIMUM_TRANSLATION_UNITS)
        require(maximumGeneratedFiles in 1..GENERATED_MAXIMUM_FILES)
        require(maximumGeneratedFileBytes in 1L..GENERATED_MAXIMUM_FILE_BYTES)
        require(maximumTotalGeneratedFileBytes in 1L..GENERATED_MAXIMUM_TOTAL_FILE_BYTES)
        require(maximumGeneratorActions in 1..GENERATED_MAXIMUM_ACTIONS)
        require(maximumActionOutputReferences in 1..GENERATED_MAXIMUM_ACTION_OUTPUT_REFERENCES)
        require(maximumCmakeEvidenceBytes in 1L..GENERATED_MAXIMUM_CMAKE_EVIDENCE_BYTES)
        require(maximumNinjaEvidenceBytes in 1L..GENERATED_MAXIMUM_NINJA_EVIDENCE_BYTES)
        require(maximumOutputRecords in 1..GENERATED_MAXIMUM_OUTPUT_RECORDS)
        require(maximumWorkUnits in 1L..GENERATED_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..GENERATED_MAXIMUM_SERIALIZED_BYTES)
    }
}

/** Immutable byte identity for one file admitted from the selective generated snapshot. */
sealed interface FullTreeGeneratedFile {
    val sourcePath: String
    val bytes: Long
    val sha256: String
    val generatorActionSha256: String
}

sealed interface FullTreeGeneratedHeader : FullTreeGeneratedFile

sealed interface FullTreeGeneratedTranslationUnit : FullTreeGeneratedFile {
    val moduleId: String
    val unitId: String
    val shardId: String
}

/**
 * Opaque Kotlin/JVM-validated snapshot registry. It verifies stable byte integrity only;
 * [generationReceiptBound] is fixed false until a later isolated CMake/Ninja receipt exists.
 */
sealed interface FullTreeGeneratedFileRegistry {
    val artifactSha256: String
    val artifactBytes: Long
    val reportSha256: String
    val configurationSha256: String
    val archiveSha256: String
    val provenanceSha256: String
    val canonicalGeneratedFileManifestSha256: String
    val canonicalGeneratedHeaderManifestSha256: String
    val buildGraphProvenanceSha256: String
    val generationReceiptBound: Boolean
    val canonicalGeneratedFilePaths: List<String>
    val canonicalGeneratedHeaderPaths: List<String>
    val generatedFiles: List<FullTreeGeneratedFile>
    val generatedHeaders: List<FullTreeGeneratedHeader>
    val generatedTranslationUnits: List<FullTreeGeneratedTranslationUnit>

    fun requireGeneratedFile(sourcePath: String): FullTreeGeneratedFile

    fun requireGeneratedTranslationUnit(ownerUnitId: String): FullTreeGeneratedTranslationUnit
}

data class FullTreeGeneratedFileInventoryGeneration(
    val registry: FullTreeGeneratedFileRegistry,
    val reportSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
)

/** Kotlin/JVM-only validation and publication of the unreceipted generated header/TU snapshot. */
object FullTreeGeneratedFileInventoryControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(GENERATED_INVENTORY_SCHEMA, GENERATED_POLICY)
    }

    fun generateAndPublish(
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        output: Path,
        limits: FullTreeGeneratedFileInventoryLimits = FullTreeGeneratedFileInventoryLimits(),
    ): FullTreeGeneratedFileInventoryGeneration = ValidatedGeneratedFileRegistry.generate(
        generatedTreeArchivePath,
        generatedProvenancePath,
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        planningInventoryPath,
        output,
        limits,
    )

    fun loadAndValidate(
        path: Path,
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeGeneratedFileInventoryLimits = FullTreeGeneratedFileInventoryLimits(),
    ): FullTreeGeneratedFileRegistry = ValidatedGeneratedFileRegistry.load(
        generatedTreeArchivePath,
        generatedProvenancePath,
        scopePath,
        sourceLockPath,
        artifactManifestPath,
        buildRecordPath,
        inventoryPath,
        sourceInventoryPath,
        planningInventoryPath,
        path,
        limits,
    )

    private fun authenticateState(
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        output: Path,
        limits: FullTreeGeneratedFileInventoryLimits,
        publish: Boolean,
    ): ValidatedGeneratedRegistryState {
        requireDistinctControlOutput(
            output,
            "generated snapshot archive" to generatedTreeArchivePath,
            "generated provenance" to generatedProvenancePath,
            "scope" to scopePath,
            "source lock" to sourceLockPath,
            "artifact manifest" to artifactManifestPath,
            "build record" to buildRecordPath,
            "full-tree inventory" to inventoryPath,
            "full-tree source inventory" to sourceInventoryPath,
            "full-tree planning inventory" to planningInventoryPath,
        )
        val inputs = authenticatePlanningInputs(
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            limits,
        )
        StableControlFile.open(
            generatedTreeArchivePath,
            limits.maximumArchiveBytes,
            "generated snapshot archive",
        ).use { archive ->
            archive.requireSingleLink("generated snapshot archive")
            StableControlFile.open(
                generatedProvenancePath,
                limits.maximumProvenanceBytes.toLong(),
                "generated snapshot provenance",
            ).use { provenance ->
                provenance.requireSingleLink("generated snapshot provenance")
                val (provenanceDocument, provenanceBytes) = readStableCanonicalObject(
                    provenance,
                    limits.maximumProvenanceBytes,
                    "generated snapshot provenance",
                    GENERATED_PROVENANCE_SCHEMA,
                )
                validateReportHash(
                    provenanceDocument,
                    limits.maximumProvenanceBytes,
                    "generated snapshot provenance",
                )
                val archiveSha256 = archive.sha256(label = "generated snapshot archive")
                validateProvenanceArchiveBinding(provenanceDocument, archive, archiveSha256)
                val snapshot = scanGeneratedSnapshot(archive, inputs, limits)
                val actions = validateProvenanceSemantics(
                    provenanceDocument,
                    inputs,
                    snapshot,
                    limits,
                )
                val expected = buildInventoryDocument(
                    inputs,
                    provenanceDocument,
                    provenanceBytes,
                    archive,
                    archiveSha256,
                    snapshot,
                    actions,
                    limits,
                )
                val state = authenticateOutput(output, expected, limits, publish)

                archive.verifyUnchanged("generated snapshot archive")
                provenance.verifyUnchanged("generated snapshot provenance")
                requireTerminalPlanningState(
                    inputs,
                    scopePath,
                    sourceLockPath,
                    artifactManifestPath,
                    buildRecordPath,
                    inventoryPath,
                    sourceInventoryPath,
                    planningInventoryPath,
                    limits,
                )
                return state
            }
        }
    }

    private fun authenticatePlanningInputs(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeGeneratedFileInventoryLimits,
    ): AuthenticatedGeneratedInputs {
        val planning = FullTreePlanningInventoryControl.loadAndValidate(
            planningInventoryPath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            limits.planning,
        )
        val (planningDocument, planningBytes) = readCanonicalControlObject(
            planningInventoryPath,
            limits.planning.maximumSerializedBytes,
            "full-tree planning inventory",
            "full-tree-planning-inventory",
        )
        if (OracleArtifacts.sha256(planningBytes) != planning.artifactSha256) {
            generatedFail("planning registry artifact changed after authentication")
        }
        val (buildRecord, buildRecordBytes) = readCanonicalControlObject(
            buildRecordPath,
            limits.planning.control.maximumBuildRecordBytes,
            "build record",
            "build-record",
        )
        val buildRecordSha256 = OracleArtifacts.sha256(buildRecordBytes)
        if (planningDocument.controlObject("oracle").controlString("buildRecordSha256") != buildRecordSha256) {
            generatedFail("planning registry build-record commitment does not reconcile")
        }
        val expectedBuildGraph = expectedBuildGraph(buildRecord, buildRecordSha256)
        val generatedModules = planning.sourceModules.filter { it.sourceKind == "generated" }
        if (generatedModules.isEmpty()) generatedFail("planning registry contains no generated translation unit")
        if (generatedModules.size > limits.maximumGeneratedTranslationUnits) {
            generatedFail("generated translation-unit population exceeds its bound")
        }
        val modulesByPath = LinkedHashMap<String, FullTreePlanningSourceModule>()
        generatedModules.forEach { module ->
            requireGeneratedPath(module.sourcePath, "planning generated translation unit")
            if (modulesByPath.put(module.sourcePath, module) != null) {
                generatedFail("planning registry duplicates a generated translation-unit path")
            }
        }
        return AuthenticatedGeneratedInputs(
            planning = planning,
            planningDocument = planningDocument,
            buildRecord = buildRecord,
            buildRecordSha256 = buildRecordSha256,
            expectedBuildGraph = expectedBuildGraph,
            generatedModulesByPath = Collections.unmodifiableMap(modulesByPath),
        )
    }

    private fun expectedBuildGraph(buildRecord: JsonObject, buildRecordSha256: String): ExpectedBuildGraph {
        if (buildRecord.controlString("buildSystem") != "cmake-ninja") {
            generatedFail("generated snapshot requires the authenticated cmake-ninja build profile")
        }
        val commands = buildRecord.controlObject("commands")
        val configureCommand = commands.controlArray("configure")
        val compileCommand = commands.controlArray("compile")
        val configureCommandSha256 = generatedCanonicalCommitment(
            GENERATED_CONFIGURE_COMMAND_DOMAIN,
            configureCommand,
        )
        val compileCommandSha256 = generatedCanonicalCommitment(
            GENERATED_COMPILE_COMMAND_DOMAIN,
            compileCommand,
        )
        val tools = buildRecord.controlArray("tools").controlObjects("build-record tools")
        val cmake = tools.singleOrNull { it.controlString("role") == "buildSystem" }
            ?: generatedFail("build record must contain exactly one buildSystem tool")
        val ninja = tools.singleOrNull { it.controlString("role") == "buildGenerator" }
            ?: generatedFail("build record must contain exactly one buildGenerator tool")
        val cmakeBinding = expectedToolBinding(cmake, "buildSystem")
        val ninjaBinding = expectedToolBinding(ninja, "buildGenerator")
        val epoch = buildRecord.controlObject("environment").controlObject("variables")
            .controlString("SOURCE_DATE_EPOCH").toLongOrNull()
            ?: generatedFail("build-record SOURCE_DATE_EPOCH is not an integer")
        if (epoch !in 1L..GENERATED_MAXIMUM_TAR_MTIME) {
            generatedFail("build-record SOURCE_DATE_EPOCH exceeds canonical USTAR")
        }
        val buildDirectory = buildRecord.controlObject("directories").controlString("build")
        return ExpectedBuildGraph(
            buildRecordSha256 = buildRecordSha256,
            buildDirectory = buildDirectory,
            sourceDateEpoch = epoch,
            configureCommandSha256 = configureCommandSha256,
            compileCommandSha256 = compileCommandSha256,
            cmakeTool = cmakeBinding,
            ninjaTool = ninjaBinding,
            cmakeIdentitySha256 = generatedCanonicalCommitment(GENERATED_TOOL_IDENTITY_DOMAIN, cmakeBinding),
            ninjaIdentitySha256 = generatedCanonicalCommitment(GENERATED_TOOL_IDENTITY_DOMAIN, ninjaBinding),
        )
    }

    private fun expectedToolBinding(tool: JsonObject, expectedRole: String): JsonObject {
        val path = tool.controlString("path")
        val versionCommand = tool.controlArray("versionCommand")
        if ((versionCommand.firstOrNull() as? JsonPrimitive)?.content != path) {
            generatedFail("$expectedRole version command does not start with its executable path")
        }
        val executableBytes = tool.controlLong("executableBytes")
        if (executableBytes !in 1L..GENERATED_MAXIMUM_TOOL_BYTES) {
            generatedFail("$expectedRole executable exceeds the generated provenance bound")
        }
        return JsonObject(
            mapOf(
                "executableBytes" to JsonPrimitive(executableBytes),
                "executableSha256" to JsonPrimitive(tool.controlString("executableSha256")),
                "path" to JsonPrimitive(path),
                "role" to JsonPrimitive(expectedRole),
                "versionOutputSha256" to JsonPrimitive(
                    OracleArtifacts.sha256(tool.controlString("versionOutput").toByteArray(StandardCharsets.UTF_8)),
                ),
            ),
        )
    }

    private fun scanGeneratedSnapshot(
        archive: StableControlFile,
        inputs: AuthenticatedGeneratedInputs,
        limits: FullTreeGeneratedFileInventoryLimits,
    ): GeneratedSnapshot {
        val collectors = LinkedHashMap<String, StreamingGeneratedFile>()
        var totalBytes = 0L
        var headers = 0
        try {
            val summary = BoundedTarXzArchive.scanGeneratedSnapshot(
                source = object : BoundedTarXzSource {
                    override val size: Long = archive.size

                    override fun read(
                        position: Long,
                        destination: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int = archive.readAt(position, destination, offset, length)
                },
                expectedRoot = GENERATED_ARCHIVE_ROOT,
                expectedMtime = inputs.expectedBuildGraph.sourceDateEpoch,
                limits = BoundedTarXzLimits(
                    maximumCompressedBytes = limits.maximumArchiveBytes,
                    maximumExpandedBytes = limits.maximumExpandedArchiveBytes,
                    maximumDecoderMemoryKiB = limits.maximumXzDecoderMemoryKiB,
                    maximumMembers = limits.maximumArchiveMembers,
                    maximumMetadataBytes = 1,
                    maximumEntryBytes = limits.maximumGeneratedFileBytes,
                    maximumPathBytes = limits.maximumPathBytes,
                    maximumComponentBytes = limits.maximumPathComponentBytes,
                    maximumLinkBytes = 1,
                    maximumIndexBytes = limits.maximumArchiveIndexBytes,
                    maximumSelectedBytes = 0,
                ),
                regularFileVisitor = object : BoundedTarXzRegularFileVisitor {
                    override fun wants(entry: BoundedTarEntry): Boolean =
                        entry.kind == BoundedTarEntryKind.REGULAR

                    override fun onChunk(
                        entry: BoundedTarEntry,
                        bytes: ByteArray,
                        length: Int,
                        endOfEntry: Boolean,
                    ) {
                        collectors[entry.path]?.update(bytes, length, endOfEntry)
                            ?: generatedFail("generated snapshot streamed an unregistered regular file")
                    }
                },
                onEntry = { entry ->
                    if (entry.kind == BoundedTarEntryKind.REGULAR) {
                        val header = isGeneratedHeaderPath(entry.path)
                        val module = inputs.generatedModulesByPath[entry.path]
                        if (!header && module == null) {
                            generatedFail(
                                "selective generated snapshot contains a non-header, non-A13 regular file",
                            )
                        }
                        if (header && module != null) {
                            generatedFail("generated snapshot path is both a header and an A13 translation unit")
                        }
                        if (header) {
                            headers = Math.addExact(headers, 1)
                            if (headers > limits.maximumGeneratedHeaders) {
                                generatedFail("generated header population exceeds its bound")
                            }
                        }
                        if (collectors.size >= limits.maximumGeneratedFiles) {
                            generatedFail("generated file population exceeds its bound")
                        }
                        totalBytes = addGeneratedExact(totalBytes, entry.size, "generated file byte")
                        if (totalBytes > limits.maximumTotalGeneratedFileBytes) {
                            generatedFail("generated file population exceeds its aggregate byte bound")
                        }
                        if (collectors.put(
                                entry.path,
                                StreamingGeneratedFile(entry.path, entry.size, header, module),
                            ) != null
                        ) {
                            generatedFail("generated snapshot duplicates a selected file")
                        }
                    }
                },
            )
            val files = collectors.values.map(StreamingGeneratedFile::finish)
                .sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER, GeneratedFileSnapshot::sourcePath))
            val paths = files.map(GeneratedFileSnapshot::sourcePath).toSet()
            val missingUnits = inputs.generatedModulesByPath.keys - paths
            if (missingUnits.isNotEmpty()) {
                generatedFail("generated snapshot omits an authenticated A13 generated translation unit")
            }
            if (summary.regularFileCount != files.size || summary.symbolicLinkCount != 0) {
                generatedFail("generated snapshot archive counts do not reconcile")
            }
            return GeneratedSnapshot(summary, files, totalBytes)
        } catch (failure: BoundedTarXzException) {
            throw FullTreeControlException(
                failure.message ?: "generated snapshot violates its strict archive profile",
                failure,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("generated snapshot count overflows", failure)
        }
    }

    private fun validateProvenanceArchiveBinding(
        provenance: JsonObject,
        archive: StableControlFile,
        archiveSha256: String,
    ) {
        val snapshot = provenance.controlObject("snapshot")
        if (snapshot.controlString("archiveRoot") != GENERATED_ARCHIVE_ROOT ||
            snapshot.controlLong("archiveBytes") != archive.size ||
            snapshot.controlString("archiveSha256") != archiveSha256
        ) {
            generatedFail("generated provenance archive binding does not reconcile")
        }
    }

    private fun validateProvenanceSemantics(
        provenance: JsonObject,
        inputs: AuthenticatedGeneratedInputs,
        snapshot: GeneratedSnapshot,
        limits: FullTreeGeneratedFileInventoryLimits,
    ): List<ValidatedGeneratedAction> {
        val buildGraph = provenance.controlObject("buildGraph")
        validateBuildGraph(buildGraph, inputs.expectedBuildGraph, limits)
        val expectedFiles = JsonArray(snapshot.files.map(GeneratedFileSnapshot::provenanceRecord))
        if (provenance.controlArray("files") != expectedFiles) {
            generatedFail("generated provenance file population differs from streamed snapshot bytes")
        }
        val rawActions = provenance.controlArray("actions").controlObjects("generated provenance actions")
        if (rawActions.size > limits.maximumGeneratorActions) {
            generatedFail("generated provenance exceeds its action bound")
        }
        val firstOutputs = rawActions.map { action ->
            (action.controlArray("outputPaths").first() as JsonPrimitive).content
        }
        if (firstOutputs.toSet().size != firstOutputs.size) {
            generatedFail("generated provenance duplicates an action's first output path")
        }
        val canonicalActions = rawActions.sortedWith(GENERATED_ACTION_ORDER)
        if (rawActions != canonicalActions) {
            generatedFail("generated provenance actions are not in canonical order")
        }
        val filesByPath = snapshot.files.associateBy(GeneratedFileSnapshot::sourcePath)
        val actionByOutput = LinkedHashMap<String, String>()
        var outputReferences = 0L
        val validated = rawActions.map { action ->
            val outputPaths = action.controlArray("outputPaths").map { value ->
                (value as? JsonPrimitive)?.content
                    ?: generatedFail("generated action output path is not a string")
            }
            if (outputPaths.isEmpty() || outputPaths != outputPaths.sortedWith(FULL_TREE_CODE_POINT_ORDER) ||
                outputPaths.toSet().size != outputPaths.size
            ) {
                generatedFail("generated action output paths are not nonempty, unique, and canonical")
            }
            outputReferences = addGeneratedExact(
                outputReferences,
                outputPaths.size.toLong(),
                "generated action-output-reference",
            )
            if (outputReferences > limits.maximumActionOutputReferences.toLong()) {
                generatedFail("generated provenance exceeds its action-output-reference bound")
            }
            outputPaths.forEach { path ->
                requireGeneratedPath(path, "generated action output")
                if (path !in filesByPath) generatedFail("generated action names an output outside the snapshot")
            }
            val producer = action.controlObject("producer")
            when (producer.controlString("kind")) {
                "cmake-configure" -> {
                    if (producer.controlString("runnerIdentitySha256") !=
                        inputs.expectedBuildGraph.cmakeIdentitySha256 ||
                        producer.controlString("ninjaDisposition") != "not-a-ninja-edge"
                    ) {
                        generatedFail("CMake generated action does not reconcile with the build record")
                    }
                }
                "ninja-edge" -> {
                    if (producer.controlString("runnerIdentitySha256") !=
                        inputs.expectedBuildGraph.ninjaIdentitySha256) {
                        generatedFail("Ninja generated action does not reconcile with the build record")
                    }
                }
                else -> generatedFail("generated action producer kind is unsupported")
            }
            val actionSha256 = generatedCanonicalCommitment(GENERATED_ACTION_DOMAIN, action)
            outputPaths.forEach { path ->
                if (actionByOutput.put(path, actionSha256) != null) {
                    generatedFail("generated actions overlap an output path")
                }
            }
            ValidatedGeneratedAction(action, actionSha256, outputPaths)
        }
        if (actionByOutput.keys != filesByPath.keys) {
            generatedFail("generated actions do not cover the selective snapshot exactly")
        }
        val graphCommitmentInput = JsonObject(
            mapOf(
                "actions" to provenance.getValue("actions"),
                "buildGraph" to buildGraph,
            ),
        )
        val expectedGraphSha256 = generatedCanonicalCommitment(
            GENERATED_BUILD_GRAPH_DOMAIN,
            graphCommitmentInput,
        )
        if (provenance.controlString("buildGraphProvenanceSha256") != expectedGraphSha256) {
            generatedFail("generated build-graph provenance commitment does not reconcile")
        }
        return validated
    }

    private fun validateBuildGraph(
        value: JsonObject,
        expected: ExpectedBuildGraph,
        limits: FullTreeGeneratedFileInventoryLimits,
    ) {
        if (value.controlString("buildRecordSha256") != expected.buildRecordSha256 ||
            value.controlString("buildSystem") != "cmake-ninja" ||
            value.controlString("buildDirectory") != expected.buildDirectory ||
            value.controlLong("sourceDateEpoch") != expected.sourceDateEpoch ||
            value.controlString("configureCommandSha256") != expected.configureCommandSha256 ||
            value.controlString("compileCommandSha256") != expected.compileCommandSha256 ||
            value.controlObject("cmakeTool") != expected.cmakeTool ||
            value.controlObject("ninjaTool") != expected.ninjaTool
        ) {
            generatedFail("generated provenance build graph differs from the authenticated build record")
        }
        if (value.controlLong("cmakeCacheBytes") !in 1L..limits.maximumCmakeEvidenceBytes) {
            generatedFail("generated provenance CMake cache exceeds its byte bound")
        }
        if (value.controlLong("ninjaManifestBytes") !in 1L..limits.maximumNinjaEvidenceBytes) {
            generatedFail("generated provenance Ninja manifest exceeds its byte bound")
        }
    }

    private fun buildInventoryDocument(
        inputs: AuthenticatedGeneratedInputs,
        provenance: JsonObject,
        provenanceBytes: ByteArray,
        archive: StableControlFile,
        archiveSha256: String,
        snapshot: GeneratedSnapshot,
        actions: List<ValidatedGeneratedAction>,
        limits: FullTreeGeneratedFileInventoryLimits,
    ): JsonObject {
        val actionByOutput = actions.flatMap { action ->
            action.outputPaths.map { path -> path to action.actionSha256 }
        }.toMap()
        val generatedFiles = snapshot.files.map { file ->
            val actionSha256 = actionByOutput[file.sourcePath]
                ?: generatedFail("generated file has no validated producer action")
            file.inventoryRecord(actionSha256)
        }
        val generatedHeaders = snapshot.files.filter(GeneratedFileSnapshot::header)
        val outputActions = actions.map { action ->
            JsonObject(
                mapOf(
                    "actionSha256" to JsonPrimitive(action.actionSha256),
                    "outputPaths" to action.document.getValue("outputPaths"),
                    "producer" to action.document.getValue("producer"),
                ),
            )
        }
        val outputReferences = actions.sumOf { it.outputPaths.size.toLong() }
        val outputRecords = listOf(
            generatedFiles.size.toLong(),
            actions.size.toLong(),
            outputReferences,
            GENERATED_BLOCKERS.size.toLong(),
        ).fold(0L) { total, value -> addGeneratedExact(total, value, "generated output record") }
        if (outputRecords > limits.maximumOutputRecords || outputRecords > GENERATED_MAXIMUM_OUTPUT_RECORDS) {
            generatedFail("generated inventory exceeds its output-record bound")
        }
        val workUnits = listOf(
            snapshot.summary.memberCount.toLong(),
            generatedFiles.size.toLong() * 3L,
            actions.size.toLong() * 2L,
            outputReferences,
            GENERATED_FIXED_WORK_UNITS,
        ).fold(0L) { total, value -> addGeneratedExact(total, value, "generated work-unit") }
        if (workUnits > limits.maximumWorkUnits || workUnits > GENERATED_MAXIMUM_WORK_UNITS) {
            generatedFail("generated inventory exceeds its work-unit bound")
        }
        val canonicalFileManifestSha256 = generatedCanonicalCommitment(
            GENERATED_FILE_MANIFEST_DOMAIN,
            JsonArray(generatedFiles),
        )
        val canonicalHeaderManifestSha256 = generatedStringManifestCommitment(
            GENERATED_HEADER_MANIFEST_DOMAIN,
            generatedHeaders.map(GeneratedFileSnapshot::sourcePath),
        )
        val summary = snapshot.summary
        val withoutHash = JsonObject(
            mapOf(
                "acpBoundary" to GENERATED_ACP_BOUNDARY,
                "authority" to GENERATED_AUTHORITY,
                "blockers" to JsonArray(GENERATED_BLOCKERS),
                "bounds" to GENERATED_BOUNDS,
                "canonicalGeneratedFileManifestSha256" to JsonPrimitive(canonicalFileManifestSha256),
                "canonicalGeneratedHeaderManifestSha256" to JsonPrimitive(canonicalHeaderManifestSha256),
                "counts" to JsonObject(
                    mapOf(
                        "archiveDirectories" to JsonPrimitive(summary.directoryCount),
                        "archiveMembers" to JsonPrimitive(summary.memberCount),
                        "archiveRegularFiles" to JsonPrimitive(summary.regularFileCount),
                        "archiveSymbolicLinks" to JsonPrimitive(summary.symbolicLinkCount),
                        "blockers" to JsonPrimitive(GENERATED_BLOCKERS.size),
                        "generatedFileBytes" to JsonPrimitive(snapshot.totalBytes),
                        "generatedFiles" to JsonPrimitive(generatedFiles.size),
                        "generatedHeaders" to JsonPrimitive(generatedHeaders.size),
                        "generatedTranslationUnits" to JsonPrimitive(
                            generatedFiles.size - generatedHeaders.size,
                        ),
                        "generatorActionOutputReferences" to JsonPrimitive(outputReferences),
                        "generatorActions" to JsonPrimitive(actions.size),
                        "outputRecords" to JsonPrimitive(outputRecords),
                        "workUnits" to JsonPrimitive(workUnits),
                    ),
                ),
                "generatedFiles" to JsonArray(generatedFiles),
                "generatorActions" to JsonArray(outputActions),
                "kind" to JsonPrimitive("full-tree-generated-file-inventory-v1"),
                "oracle" to JsonObject(
                    mapOf(
                        "buildRecordSha256" to JsonPrimitive(inputs.buildRecordSha256),
                        "configurationSha256" to JsonPrimitive(configurationSha256),
                        "id" to inputs.buildRecord.controlObject("oracle").getValue("id"),
                        "planningInventoryArtifactSha256" to JsonPrimitive(inputs.planning.artifactSha256),
                        "planningInventoryConfigurationSha256" to JsonPrimitive(
                            inputs.planning.configurationSha256,
                        ),
                        "planningInventoryReportSha256" to JsonPrimitive(inputs.planning.reportSha256),
                    ),
                ),
                "provenance" to JsonObject(
                    mapOf(
                        "artifactBytes" to JsonPrimitive(provenanceBytes.size),
                        "artifactSha256" to JsonPrimitive(OracleArtifacts.sha256(provenanceBytes)),
                        "buildGraph" to provenance.getValue("buildGraph"),
                        "buildGraphProvenanceSha256" to provenance.getValue("buildGraphProvenanceSha256"),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "selectionPolicy" to GENERATED_SELECTION_POLICY,
                "snapshot" to JsonObject(
                    mapOf(
                        "archiveBytes" to JsonPrimitive(archive.size),
                        "archiveRoot" to JsonPrimitive(GENERATED_ARCHIVE_ROOT),
                        "archiveSha256" to JsonPrimitive(archiveSha256),
                        "directoryCount" to JsonPrimitive(summary.directoryCount),
                        "expandedBytes" to JsonPrimitive(summary.expandedBytes),
                        "memberCount" to JsonPrimitive(summary.memberCount),
                        "regularFileCount" to JsonPrimitive(summary.regularFileCount),
                        "sourceDateEpoch" to JsonPrimitive(inputs.expectedBuildGraph.sourceDateEpoch),
                        "symbolicLinkCount" to JsonPrimitive(summary.symbolicLinkCount),
                    ),
                ),
            ),
        )
        val reportSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(
                withoutHash,
                controlJsonLimits(GENERATED_MAXIMUM_SERIALIZED_BYTES),
            ),
        )
        return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
    }

    private fun authenticateOutput(
        output: Path,
        expected: JsonObject,
        limits: FullTreeGeneratedFileInventoryLimits,
        publish: Boolean,
    ): ValidatedGeneratedRegistryState {
        if (publish) {
            validateInventoryShapeAndHash(expected, limits)
            publishCanonicalControl(output, expected, limits.maximumSerializedBytes)
        }
        return StableControlFile.open(
            output,
            limits.maximumSerializedBytes.toLong(),
            "full-tree generated-file inventory",
        ).use { artifact ->
            artifact.requireSingleLink("full-tree generated-file inventory")
            val (document, bytes) = readStableCanonicalObject(
                artifact,
                limits.maximumSerializedBytes,
                "full-tree generated-file inventory",
                GENERATED_INVENTORY_SCHEMA,
            )
            validateInventoryShapeAndHash(document, limits)
            if (document != expected) {
                generatedFail("generated-file inventory differs from authenticated raw inputs")
            }
            artifact.verifyUnchanged("full-tree generated-file inventory")
            validatedRegistryState(document, OracleArtifacts.sha256(bytes), bytes.size.toLong())
        }
    }

    private fun validateInventoryShapeAndHash(
        value: JsonObject,
        limits: FullTreeGeneratedFileInventoryLimits,
    ) {
        val (document, _) = snapshotControlObject(
            value,
            limits.maximumSerializedBytes,
            "full-tree generated-file inventory",
            GENERATED_INVENTORY_SCHEMA,
        )
        validateReportHash(document, limits.maximumSerializedBytes, "full-tree generated-file inventory")
        val counts = document.controlObject("counts")
        if (counts.controlLong("generatedHeaders") > limits.maximumGeneratedHeaders ||
            counts.controlLong("generatedTranslationUnits") > limits.maximumGeneratedTranslationUnits ||
            counts.controlLong("generatedFiles") > limits.maximumGeneratedFiles ||
            counts.controlLong("generatorActions") > limits.maximumGeneratorActions ||
            counts.controlLong("generatorActionOutputReferences") > limits.maximumActionOutputReferences ||
            counts.controlLong("generatedFileBytes") > limits.maximumTotalGeneratedFileBytes ||
            counts.controlLong("outputRecords") > limits.maximumOutputRecords ||
            counts.controlLong("workUnits") > limits.maximumWorkUnits
        ) {
            generatedFail("generated-file inventory exceeds a caller-lowered output bound")
        }
    }

    private fun validatedRegistryState(
        document: JsonObject,
        artifactSha256: String,
        artifactBytes: Long,
    ): ValidatedGeneratedRegistryState {
        requireControlDigest(artifactSha256, "generated-file inventory artifact")
        val actions = document.controlArray("generatorActions").controlObjects("generated actions")
            .associate { action ->
                action.controlString("actionSha256") to action.controlArray("outputPaths").map { value ->
                    (value as JsonPrimitive).content
                }
            }
        val files = document.controlArray("generatedFiles").controlObjects("generated files").map { file ->
            val actionSha256 = file.controlString("generatorActionSha256")
            if (file.controlString("sourcePath") !in (actions[actionSha256] ?: emptyList())) {
                generatedFail("generated-file output references an absent producer action")
            }
            when (file.controlString("kind")) {
                "header" -> ValidatedGeneratedHeader(
                    sourcePath = file.controlString("sourcePath"),
                    bytes = file.controlLong("bytes"),
                    sha256 = file.controlString("sha256"),
                    generatorActionSha256 = actionSha256,
                )
                "a13-translation-unit" -> ValidatedGeneratedTranslationUnit(
                    sourcePath = file.controlString("sourcePath"),
                    bytes = file.controlLong("bytes"),
                    sha256 = file.controlString("sha256"),
                    generatorActionSha256 = actionSha256,
                    moduleId = file.controlString("moduleId"),
                    unitId = file.controlString("unitId"),
                    shardId = file.controlString("shardId"),
                )
                else -> generatedFail("generated-file output contains an unsupported file kind")
            }
        }
        val snapshot = document.controlObject("snapshot")
        val provenance = document.controlObject("provenance")
        return ValidatedGeneratedRegistryState(
            artifactSha256 = artifactSha256,
            artifactBytes = artifactBytes,
            reportSha256 = document.controlString("reportSha256"),
            configurationSha256 = document.controlObject("oracle").controlString("configurationSha256"),
            archiveSha256 = snapshot.controlString("archiveSha256"),
            provenanceSha256 = provenance.controlString("artifactSha256"),
            canonicalFileManifestSha256 = document.controlString("canonicalGeneratedFileManifestSha256"),
            canonicalHeaderManifestSha256 = document.controlString("canonicalGeneratedHeaderManifestSha256"),
            buildGraphProvenanceSha256 = provenance.controlString("buildGraphProvenanceSha256"),
            files = files,
        )
    }

    private fun requireTerminalPlanningState(
        expected: AuthenticatedGeneratedInputs,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeGeneratedFileInventoryLimits,
    ) {
        val terminal = FullTreePlanningInventoryControl.loadAndValidate(
            planningInventoryPath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            limits.planning,
        )
        if (terminal.artifactSha256 != expected.planning.artifactSha256 ||
            terminal.reportSha256 != expected.planning.reportSha256 ||
            terminal.configurationSha256 != expected.planning.configurationSha256 ||
            planningRegistrySnapshot(terminal) != planningRegistrySnapshot(expected.planning)
        ) {
            generatedFail("planning registry changed during generated snapshot authentication")
        }
    }

    /**
     * The constructor is the production validation boundary. Its synthetic bridge accepts only
     * raw paths, caller-lowering limits, and the generate/load selector—never parsed JSON,
     * claimed digests, record collections, callbacks, or caller-created registries.
     */
    private class ValidatedGeneratedFileRegistry private constructor(
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        output: Path,
        limits: FullTreeGeneratedFileInventoryLimits,
        publish: Boolean,
    ) : FullTreeGeneratedFileRegistry {
        private val state = authenticateState(
            generatedTreeArchivePath,
            generatedProvenancePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            output,
            limits,
            publish,
        )

        override val artifactSha256: String = state.artifactSha256
        override val artifactBytes: Long = state.artifactBytes
        override val reportSha256: String = state.reportSha256
        override val configurationSha256: String = state.configurationSha256
        override val archiveSha256: String = state.archiveSha256
        override val provenanceSha256: String = state.provenanceSha256
        override val canonicalGeneratedFileManifestSha256: String = state.canonicalFileManifestSha256
        override val canonicalGeneratedHeaderManifestSha256: String = state.canonicalHeaderManifestSha256
        override val buildGraphProvenanceSha256: String = state.buildGraphProvenanceSha256
        override val generationReceiptBound: Boolean = false
        override val generatedFiles: List<FullTreeGeneratedFile> =
            Collections.unmodifiableList(ArrayList(state.files))
        override val generatedHeaders: List<FullTreeGeneratedHeader> = Collections.unmodifiableList(
            generatedFiles.filterIsInstance<FullTreeGeneratedHeader>(),
        )
        override val generatedTranslationUnits: List<FullTreeGeneratedTranslationUnit> = Collections.unmodifiableList(
            generatedFiles.filterIsInstance<FullTreeGeneratedTranslationUnit>(),
        )
        override val canonicalGeneratedFilePaths: List<String> = Collections.unmodifiableList(
            generatedFiles.map(FullTreeGeneratedFile::sourcePath),
        )
        override val canonicalGeneratedHeaderPaths: List<String> = Collections.unmodifiableList(
            generatedHeaders.map(FullTreeGeneratedHeader::sourcePath),
        )
        private val filesByPath: Map<String, FullTreeGeneratedFile> = Collections.unmodifiableMap(
            LinkedHashMap<String, FullTreeGeneratedFile>().apply {
                generatedFiles.forEach { file ->
                    if (put(file.sourcePath, file) != null) {
                        generatedFail("generated registry contains a duplicate file path")
                    }
                }
            },
        )
        private val translationUnitsByOwner: Map<String, FullTreeGeneratedTranslationUnit> =
            Collections.unmodifiableMap(
                LinkedHashMap<String, FullTreeGeneratedTranslationUnit>().apply {
                    generatedTranslationUnits.forEach { unit ->
                        if (unit.moduleId != unit.unitId || put(unit.unitId, unit) != null) {
                            generatedFail("generated registry contains an invalid translation-unit identity")
                        }
                    }
                },
            )

        override fun requireGeneratedFile(sourcePath: String): FullTreeGeneratedFile {
            requireGeneratedPath(sourcePath, "generated registry lookup")
            return filesByPath[sourcePath]
                ?: generatedFail("generated file path is outside the authenticated snapshot")
        }

        override fun requireGeneratedTranslationUnit(ownerUnitId: String): FullTreeGeneratedTranslationUnit {
            if (!ownerUnitId.matches(GENERATED_COMPILATION_UNIT_ID)) {
                generatedFail("generated translation-unit owner ID is invalid")
            }
            return translationUnitsByOwner[ownerUnitId]
                ?: generatedFail("generated translation-unit owner is outside the authenticated snapshot")
        }

        companion object {
            fun generate(
                generatedTreeArchivePath: Path,
                generatedProvenancePath: Path,
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                planningInventoryPath: Path,
                output: Path,
                limits: FullTreeGeneratedFileInventoryLimits,
            ): FullTreeGeneratedFileInventoryGeneration {
                val registry = ValidatedGeneratedFileRegistry(
                    generatedTreeArchivePath,
                    generatedProvenancePath,
                    scopePath,
                    sourceLockPath,
                    artifactManifestPath,
                    buildRecordPath,
                    inventoryPath,
                    sourceInventoryPath,
                    planningInventoryPath,
                    output,
                    limits,
                    true,
                )
                return FullTreeGeneratedFileInventoryGeneration(
                    registry = registry,
                    reportSha256 = registry.reportSha256,
                    outputSha256 = registry.artifactSha256,
                    outputBytes = registry.artifactBytes,
                )
            }

            fun load(
                generatedTreeArchivePath: Path,
                generatedProvenancePath: Path,
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                planningInventoryPath: Path,
                path: Path,
                limits: FullTreeGeneratedFileInventoryLimits,
            ): FullTreeGeneratedFileRegistry = ValidatedGeneratedFileRegistry(
                generatedTreeArchivePath,
                generatedProvenancePath,
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                path,
                limits,
                false,
            )
        }
    }
}

private data class AuthenticatedGeneratedInputs(
    val planning: AuthenticatedFullTreePlanningRegistry,
    val planningDocument: JsonObject,
    val buildRecord: JsonObject,
    val buildRecordSha256: String,
    val expectedBuildGraph: ExpectedBuildGraph,
    val generatedModulesByPath: Map<String, FullTreePlanningSourceModule>,
)

private data class ExpectedBuildGraph(
    val buildRecordSha256: String,
    val buildDirectory: String,
    val sourceDateEpoch: Long,
    val configureCommandSha256: String,
    val compileCommandSha256: String,
    val cmakeTool: JsonObject,
    val ninjaTool: JsonObject,
    val cmakeIdentitySha256: String,
    val ninjaIdentitySha256: String,
)

private data class GeneratedSnapshot(
    val summary: BoundedTarXzSummary,
    val files: List<GeneratedFileSnapshot>,
    val totalBytes: Long,
)

private data class GeneratedFileSnapshot(
    val sourcePath: String,
    val bytes: Long,
    val sha256: String,
    val header: Boolean,
    val module: FullTreePlanningSourceModule?,
) {
    fun provenanceRecord(): JsonObject = JsonObject(
        mapOf(
            "bytes" to JsonPrimitive(bytes),
            "sha256" to JsonPrimitive(sha256),
            "sourcePath" to JsonPrimitive(sourcePath),
        ),
    )

    fun inventoryRecord(generatorActionSha256: String): JsonObject = if (header) {
        JsonObject(
            mapOf(
                "bytes" to JsonPrimitive(bytes),
                "generatorActionSha256" to JsonPrimitive(generatorActionSha256),
                "kind" to JsonPrimitive("header"),
                "sha256" to JsonPrimitive(sha256),
                "sourcePath" to JsonPrimitive(sourcePath),
            ),
        )
    } else {
        val authenticatedModule = module
            ?: generatedFail("generated translation-unit snapshot has no authenticated module")
        JsonObject(
            mapOf(
                "bytes" to JsonPrimitive(bytes),
                "generatorActionSha256" to JsonPrimitive(generatorActionSha256),
                "kind" to JsonPrimitive("a13-translation-unit"),
                "moduleId" to JsonPrimitive(authenticatedModule.moduleId),
                "sha256" to JsonPrimitive(sha256),
                "shardId" to JsonPrimitive(authenticatedModule.shardId),
                "sourcePath" to JsonPrimitive(sourcePath),
                "unitId" to JsonPrimitive(authenticatedModule.unitId),
            ),
        )
    }
}

private class StreamingGeneratedFile(
    private val sourcePath: String,
    private val expectedBytes: Long,
    private val header: Boolean,
    private val module: FullTreePlanningSourceModule?,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var observedBytes = 0L
    private var ended = false

    fun update(bytes: ByteArray, length: Int, endOfEntry: Boolean) {
        if (ended || length !in 0..bytes.size) {
            generatedFail("generated snapshot visitor returned an invalid payload sequence")
        }
        observedBytes = addGeneratedExact(observedBytes, length.toLong(), "generated payload")
        if (observedBytes > expectedBytes) generatedFail("generated snapshot payload exceeds its tar size")
        if (length != 0) digest.update(bytes, 0, length)
        if (endOfEntry) {
            if (observedBytes != expectedBytes) generatedFail("generated snapshot payload ended at the wrong size")
            ended = true
        }
    }

    fun finish(): GeneratedFileSnapshot {
        if (!ended || observedBytes != expectedBytes) {
            generatedFail("generated snapshot payload did not terminate")
        }
        return GeneratedFileSnapshot(
            sourcePath = sourcePath,
            bytes = observedBytes,
            sha256 = digest.digest().generatedHex(),
            header = header,
            module = module,
        )
    }
}

private data class ValidatedGeneratedAction(
    val document: JsonObject,
    val actionSha256: String,
    val outputPaths: List<String>,
)

private data class ValidatedGeneratedHeader(
    override val sourcePath: String,
    override val bytes: Long,
    override val sha256: String,
    override val generatorActionSha256: String,
) : FullTreeGeneratedHeader

private data class ValidatedGeneratedTranslationUnit(
    override val sourcePath: String,
    override val bytes: Long,
    override val sha256: String,
    override val generatorActionSha256: String,
    override val moduleId: String,
    override val unitId: String,
    override val shardId: String,
) : FullTreeGeneratedTranslationUnit

private data class ValidatedGeneratedRegistryState(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val archiveSha256: String,
    val provenanceSha256: String,
    val canonicalFileManifestSha256: String,
    val canonicalHeaderManifestSha256: String,
    val buildGraphProvenanceSha256: String,
    val files: List<FullTreeGeneratedFile>,
)

private data class PlanningModuleSnapshot(
    val moduleId: String,
    val unitId: String,
    val shardId: String,
    val sourceKind: String,
    val sourcePath: String,
)

private data class PlanningSourceOnlySnapshot(
    val sourcePath: String,
    val shardId: String,
    val reasonCode: String,
)

private data class PlanningRegistrySnapshot(
    val modules: List<PlanningModuleSnapshot>,
    val sourceOnly: List<PlanningSourceOnlySnapshot>,
)

private fun planningRegistrySnapshot(registry: AuthenticatedFullTreePlanningRegistry): PlanningRegistrySnapshot =
    PlanningRegistrySnapshot(
        modules = registry.sourceModules.map { module ->
            PlanningModuleSnapshot(
                module.moduleId,
                module.unitId,
                module.shardId,
                module.sourceKind,
                module.sourcePath,
            )
        },
        sourceOnly = registry.sourceOnlyUnits.map { unit ->
            PlanningSourceOnlySnapshot(unit.sourcePath, unit.shardId, unit.reasonCode)
        },
    )

private fun readStableCanonicalObject(
    file: StableControlFile,
    maximumBytes: Int,
    label: String,
    schemaName: String,
): Pair<JsonObject, ByteArray> {
    if (file.size !in 1L..maximumBytes.toLong()) generatedFail("$label exceeds its byte bound")
    val bytes = file.readExactly(0L, file.size.toInt(), label)
    val document = try {
        OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as? JsonObject
            ?: generatedFail("$label root must be an object")
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is not strict canonical JSON", failure)
    }
    try {
        OracleSchemas.validate(schemaName, document)
    } catch (failure: Exception) {
        throw FullTreeControlException("$label fails its bundled schema", failure)
    }
    return document to bytes
}

private fun validateReportHash(document: JsonObject, maximumBytes: Int, label: String) {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val expected = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(maximumBytes)),
    )
    if (document.controlString("reportSha256") != expected) {
        generatedFail("$label report hash does not reconcile")
    }
}

private fun requireGeneratedPath(value: String, label: String) {
    if (!value.matches(GENERATED_PATH) || value.length > GENERATED_MAXIMUM_PATH_BYTES ||
        value.contains("//") || value.split('/').any { component ->
            component == "." || component == ".." ||
                component.toByteArray(StandardCharsets.US_ASCII).size > GENERATED_MAXIMUM_PATH_COMPONENT_BYTES
        }
    ) {
        generatedFail("$label path is not canonical")
    }
}

private fun isGeneratedHeaderPath(path: String): Boolean {
    requireGeneratedPath(path, "generated snapshot")
    return GENERATED_HEADER_SUFFIXES.any(path::endsWith)
}

private fun addGeneratedExact(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label count overflows", failure)
}

private fun generatedFail(message: String): Nothing = throw FullTreeControlException(message)

private fun ByteArray.generatedHex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

internal fun fullTreeGeneratedConfigureCommandSha256(command: JsonArray): String =
    generatedCanonicalCommitment(GENERATED_CONFIGURE_COMMAND_DOMAIN, command)

internal fun fullTreeGeneratedCompileCommandSha256(command: JsonArray): String =
    generatedCanonicalCommitment(GENERATED_COMPILE_COMMAND_DOMAIN, command)

internal fun fullTreeGeneratedToolIdentitySha256(toolBinding: JsonObject): String =
    generatedCanonicalCommitment(GENERATED_TOOL_IDENTITY_DOMAIN, toolBinding)

internal fun fullTreeGeneratedActionSha256(action: JsonObject): String =
    generatedCanonicalCommitment(GENERATED_ACTION_DOMAIN, action)

internal fun fullTreeGeneratedBuildGraphSha256(buildGraph: JsonObject, actions: JsonArray): String =
    generatedCanonicalCommitment(
        GENERATED_BUILD_GRAPH_DOMAIN,
        JsonObject(mapOf("actions" to actions, "buildGraph" to buildGraph)),
    )

private fun generatedCanonicalCommitment(domain: String, value: JsonElement): String =
    GeneratedCommitment(domain).apply {
        token(
            OracleJson.canonicalBytes(
                value,
                controlJsonLimits(GENERATED_MAXIMUM_SERIALIZED_BYTES),
            ),
        )
    }.finish()

private fun generatedStringManifestCommitment(domain: String, values: List<String>): String =
    GeneratedCommitment(domain).apply {
        long(values.size.toLong())
        values.forEach { value -> token(value.toByteArray(StandardCharsets.UTF_8)) }
    }.finish()

private class GeneratedCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token(domain.toByteArray(StandardCharsets.UTF_8))
    }

    fun long(value: Long) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array())
    }

    fun token(bytes: ByteArray) {
        long(bytes.size.toLong())
        digest.update(bytes)
    }

    fun finish(): String = digest.digest().generatedHex()
}

private val GENERATED_ACTION_ORDER = Comparator<JsonObject> { left, right ->
    val leftPath = (left.controlArray("outputPaths").first() as JsonPrimitive).content
    val rightPath = (right.controlArray("outputPaths").first() as JsonPrimitive).content
    val path = FULL_TREE_CODE_POINT_ORDER.compare(leftPath, rightPath)
    if (path != 0) {
        path
    } else {
        val leftBytes = OracleJson.canonicalBytes(left, controlJsonLimits(GENERATED_MAXIMUM_PROVENANCE_BYTES))
        val rightBytes = OracleJson.canonicalBytes(right, controlJsonLimits(GENERATED_MAXIMUM_PROVENANCE_BYTES))
        compareUnsignedBytes(leftBytes, rightBytes)
    }
}

private fun compareUnsignedBytes(left: ByteArray, right: ByteArray): Int {
    val common = minOf(left.size, right.size)
    for (index in 0 until common) {
        val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
        if (difference != 0) return difference
    }
    return left.size.compareTo(right.size)
}

private val GENERATED_AUTHORITY = JsonObject(
    mapOf(
        "cleanCompilationProven" to JsonPrimitive(false),
        "generatedHeaderPopulationComplete" to JsonPrimitive(false),
        "generationReceiptBound" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
        "snapshotBytesAuthenticated" to JsonPrimitive(false),
        "snapshotBytesIntegrityVerified" to JsonPrimitive(true),
        "status" to JsonPrimitive("unreceipted-generated-snapshot"),
    ),
)

private val GENERATED_ACP_BOUNDARY = JsonObject(
    mapOf(
        "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
        "candidateContribution" to JsonPrimitive("authenticated-session-change-build-artifact-provenance"),
        "candidateEvidenceDisposition" to JsonPrimitive("non-authoritative-input-to-later-host-validation"),
        "candidateLineageAdmission" to JsonPrimitive("not-an-input-to-generated-snapshot-v1"),
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

private val GENERATED_BOUNDS = JsonObject(
    mapOf(
        "maximumActionOutputReferences" to JsonPrimitive(GENERATED_MAXIMUM_ACTION_OUTPUT_REFERENCES),
        "maximumArchiveBytes" to JsonPrimitive(GENERATED_MAXIMUM_ARCHIVE_BYTES),
        "maximumArchiveIndexBytes" to JsonPrimitive(GENERATED_MAXIMUM_ARCHIVE_INDEX_BYTES),
        "maximumArchiveMembers" to JsonPrimitive(GENERATED_MAXIMUM_ARCHIVE_MEMBERS),
        "maximumBlockers" to JsonPrimitive(4),
        "maximumCmakeEvidenceBytes" to JsonPrimitive(GENERATED_MAXIMUM_CMAKE_EVIDENCE_BYTES),
        "maximumExpandedArchiveBytes" to JsonPrimitive(GENERATED_MAXIMUM_EXPANDED_ARCHIVE_BYTES),
        "maximumGeneratedFileBytes" to JsonPrimitive(GENERATED_MAXIMUM_FILE_BYTES),
        "maximumGeneratedFiles" to JsonPrimitive(GENERATED_MAXIMUM_FILES),
        "maximumGeneratedHeaders" to JsonPrimitive(GENERATED_MAXIMUM_HEADERS),
        "maximumGeneratedTranslationUnits" to JsonPrimitive(GENERATED_MAXIMUM_TRANSLATION_UNITS),
        "maximumGeneratorActions" to JsonPrimitive(GENERATED_MAXIMUM_ACTIONS),
        "maximumNinjaEvidenceBytes" to JsonPrimitive(GENERATED_MAXIMUM_NINJA_EVIDENCE_BYTES),
        "maximumOutputRecords" to JsonPrimitive(GENERATED_MAXIMUM_OUTPUT_RECORDS),
        "maximumPathBytes" to JsonPrimitive(GENERATED_MAXIMUM_PATH_BYTES),
        "maximumPathComponentBytes" to JsonPrimitive(GENERATED_MAXIMUM_PATH_COMPONENT_BYTES),
        "maximumProvenanceBytes" to JsonPrimitive(GENERATED_MAXIMUM_PROVENANCE_BYTES),
        "maximumSerializedBytes" to JsonPrimitive(GENERATED_MAXIMUM_SERIALIZED_BYTES),
        "maximumToolBytes" to JsonPrimitive(GENERATED_MAXIMUM_TOOL_BYTES),
        "maximumTotalGeneratedFileBytes" to JsonPrimitive(GENERATED_MAXIMUM_TOTAL_FILE_BYTES),
        "maximumWorkUnits" to JsonPrimitive(GENERATED_MAXIMUM_WORK_UNITS),
        "maximumXzDecoderMemoryKiB" to JsonPrimitive(GENERATED_MAXIMUM_XZ_DECODER_MEMORY_KIB),
    ),
)

private val GENERATED_SELECTION_POLICY = JsonObject(
    mapOf(
        "eligibleHeaderSuffixMatching" to JsonPrimitive("case-sensitive"),
        "otherRegularFiles" to JsonPrimitive("forbidden"),
        "provenanceFileCoverage" to JsonPrimitive("exact-all-archive-regular-files"),
        "regularFilePopulation" to JsonPrimitive(
            "eligible-generated-headers-union-authenticated-a13-generated-tus",
        ),
        "snapshotKind" to JsonPrimitive("selective-generated-header-and-a13-tu-snapshot"),
    ),
)

private val GENERATED_BLOCKERS = listOf(
    JsonObject(mapOf("code" to JsonPrimitive("generated-generation-receipt-missing"), "status" to JsonPrimitive("unresolved"))),
    JsonObject(mapOf("code" to JsonPrimitive("generated-snapshot-completeness-unproven"), "status" to JsonPrimitive("unresolved"))),
    JsonObject(mapOf("code" to JsonPrimitive("ninja-live-edge-replay-missing"), "status" to JsonPrimitive("unresolved"))),
    JsonObject(mapOf("code" to JsonPrimitive("physical-build-root-unverified"), "status" to JsonPrimitive("unresolved"))),
)

private val GENERATED_POLICY = JsonObject(
    mapOf(
        "acpBoundary" to GENERATED_ACP_BOUNDARY,
        "archiveProfile" to JsonPrimitive("single-crc64-xz-canonical-ustar-no-pax-no-links-source-date-epoch"),
        "archiveRoot" to JsonPrimitive(GENERATED_ARCHIVE_ROOT),
        "bounds" to GENERATED_BOUNDS,
        "headerSuffixes" to JsonArray(
            listOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc").map(::JsonPrimitive),
        ),
        "id" to JsonPrimitive(GENERATED_INVENTORY_SCHEMA),
        "provenanceSchemaSha256" to JsonPrimitive(OracleSchemas.identity(GENERATED_PROVENANCE_SCHEMA).sha256),
        "regularFilePopulation" to JsonPrimitive("eligible-generated-headers-union-authenticated-a13-generated-tus"),
        "selectionPolicy" to GENERATED_SELECTION_POLICY,
        "status" to JsonPrimitive("unreceipted-byte-consistent-snapshot"),
        "version" to JsonPrimitive(1),
        "workUnitModel" to JsonPrimitive(
            "archive-members-plus-three-per-file-plus-two-per-action-plus-output-references-plus-12",
        ),
    ),
)

private val GENERATED_PATH = Regex(
    "^generated/(?:(?!\\.{1,2}(?:/|$))[A-Za-z0-9._+-]{1,255}/)*" +
        "(?!\\.{1,2}$)[A-Za-z0-9._+-]{1,255}$",
)
private val GENERATED_COMPILATION_UNIT_ID = Regex("cu-[0-9a-f]{32}")
private val GENERATED_HEADER_SUFFIXES = listOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc")

private const val GENERATED_PROVENANCE_SCHEMA = "full-tree-generated-file-provenance"
private const val GENERATED_INVENTORY_SCHEMA = "full-tree-generated-file-inventory"
private const val GENERATED_ARCHIVE_ROOT = "generated"
private const val GENERATED_CONFIGURE_COMMAND_DOMAIN = "full-tree-generated-configure-command-v1"
private const val GENERATED_COMPILE_COMMAND_DOMAIN = "full-tree-generated-compile-command-v1"
private const val GENERATED_TOOL_IDENTITY_DOMAIN = "full-tree-generated-tool-identity-v1"
private const val GENERATED_ACTION_DOMAIN = "full-tree-generated-action-v1"
private const val GENERATED_BUILD_GRAPH_DOMAIN = "full-tree-generated-build-graph-v1"
private const val GENERATED_FILE_MANIFEST_DOMAIN = "full-tree-generated-file-manifest-v1"
private const val GENERATED_HEADER_MANIFEST_DOMAIN = "full-tree-generated-header-manifest-v1"
private const val GENERATED_FIXED_WORK_UNITS = 12L
private const val GENERATED_MAXIMUM_ARCHIVE_BYTES = 512L * 1024L * 1024L
private const val GENERATED_MAXIMUM_EXPANDED_ARCHIVE_BYTES = 8L * 1024L * 1024L * 1024L
private const val GENERATED_MAXIMUM_XZ_DECODER_MEMORY_KIB = 256 * 1024
private const val GENERATED_MAXIMUM_ARCHIVE_MEMBERS = 200_000
private const val GENERATED_MAXIMUM_ARCHIVE_INDEX_BYTES = 64L * 1024L * 1024L
private const val GENERATED_MAXIMUM_PATH_BYTES = 4096
private const val GENERATED_MAXIMUM_PATH_COMPONENT_BYTES = 255
private const val GENERATED_MAXIMUM_PROVENANCE_BYTES = 64 * 1024 * 1024
private const val GENERATED_MAXIMUM_HEADERS = 50_000
private const val GENERATED_MAXIMUM_TRANSLATION_UNITS = 10_000
private const val GENERATED_MAXIMUM_FILES = 60_000
private const val GENERATED_MAXIMUM_FILE_BYTES = 512L * 1024L * 1024L
private const val GENERATED_MAXIMUM_TOTAL_FILE_BYTES = 2L * 1024L * 1024L * 1024L
private const val GENERATED_MAXIMUM_ACTIONS = 60_000
private const val GENERATED_MAXIMUM_ACTION_OUTPUT_REFERENCES = 60_000
private const val GENERATED_MAXIMUM_CMAKE_EVIDENCE_BYTES = 64L * 1024L * 1024L
private const val GENERATED_MAXIMUM_NINJA_EVIDENCE_BYTES = 512L * 1024L * 1024L
private const val GENERATED_MAXIMUM_OUTPUT_RECORDS = 180_004
private const val GENERATED_MAXIMUM_WORK_UNITS = 5_000_000L
private const val GENERATED_MAXIMUM_SERIALIZED_BYTES = 64 * 1024 * 1024
private const val GENERATED_MAXIMUM_TOOL_BYTES = 512L * 1024L * 1024L
private const val GENERATED_MAXIMUM_TAR_MTIME = 0x1ffffffffL

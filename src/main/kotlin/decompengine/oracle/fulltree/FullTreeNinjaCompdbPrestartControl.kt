package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Caller-lowerable ceilings beneath the immutable Ninja compdb-prestart v1 policy. */
data class FullTreeNinjaCompdbPrestartLimits(
    val reconciliation: FullTreeClangCompdbReconciliationLimits =
        FullTreeClangCompdbReconciliationLimits(),
    val manifestArchive: FullTreeNinjaManifestArchiveLimits = FullTreeNinjaManifestArchiveLimits(),
    val maximumCanonicalBytes: Int = NINJA_PRESTART_MAXIMUM_CANONICAL_BYTES,
    val maximumCompilerRules: Int = NINJA_PRESTART_MAXIMUM_COMPILER_RULES,
    val maximumEnvironmentBytes: Long = NINJA_PRESTART_MAXIMUM_ENVIRONMENT_BYTES,
    val maximumEnvironmentVariables: Int = NINJA_PRESTART_MAXIMUM_ENVIRONMENT_VARIABLES,
    val maximumPathBytes: Int = NINJA_PRESTART_MAXIMUM_PATH_BYTES,
    val maximumRuleNameBytes: Int = NINJA_PRESTART_MAXIMUM_RULE_NAME_BYTES,
    val maximumStdoutBytes: Int = NINJA_PRESTART_MAXIMUM_STDOUT_BYTES,
    val maximumToolBytes: Long = NINJA_PRESTART_MAXIMUM_TOOL_BYTES,
) {
    init {
        require(maximumCanonicalBytes in 1..NINJA_PRESTART_MAXIMUM_CANONICAL_BYTES)
        require(maximumCompilerRules in 1..NINJA_PRESTART_MAXIMUM_COMPILER_RULES)
        require(maximumEnvironmentBytes in 1L..NINJA_PRESTART_MAXIMUM_ENVIRONMENT_BYTES)
        require(maximumEnvironmentVariables in 3..NINJA_PRESTART_MAXIMUM_ENVIRONMENT_VARIABLES)
        require(maximumPathBytes in 1..NINJA_PRESTART_MAXIMUM_PATH_BYTES)
        require(maximumRuleNameBytes in 1..NINJA_PRESTART_MAXIMUM_RULE_NAME_BYTES)
        require(maximumStdoutBytes in 2..NINJA_PRESTART_MAXIMUM_STDOUT_BYTES)
        require(maximumToolBytes in 1L..NINJA_PRESTART_MAXIMUM_TOOL_BYTES)
    }
}

/**
 * Immutable, persisted, and deliberately unexecuted Ninja compilation-database prestart.
 *
 * No process, callback, command, environment, mount, or start seam is exposed by this registry.
 */
sealed interface FullTreeNinjaCompdbPrestartRegistry {
    val artifactSha256: String
    val artifactBytes: Long
    val reportSha256: String
    val configurationSha256: String
    val reconciliationArtifactSha256: String
    val prestartContextSha256: String
    val predecessorManifestSha256: String
    val manifestArchiveSha256: String
    val manifestClosureSha256: String
    val manifestConfigurationSha256: String
    val manifestReportSha256: String
    val manifestFileManifestSha256: String
    val manifestIncludeGraphSha256: String
    val manifestRuleManifestSha256: String
    val manifestArchiveRoot: String
    val manifestRootFile: String
    val manifestRootBytes: Long
    val manifestRootSha256: String
    val compilerRulesSha256: String
    val compilerRuleNames: List<String>
    val ninjaExecutablePath: String
    val ninjaExecutableBytes: Long
    val ninjaExecutableSha256: String
    val ninjaToolIdentitySha256: String
    val workingDirectory: String
    val argv: List<String>
    val argvSha256: String
    val environment: Map<String, String>
    val environmentSha256: String
    val expectedStdoutBytes: Long
    val expectedStdoutSha256: String
    val expectedStdoutCanonicalSha256: String
    val expectedStdoutCommitmentSha256: String
    val invocationSha256: String
    val containmentPolicySha256: String
    val blockerCodes: List<String>
    val canonicalBytes: ByteArray
    val startAuthorized: Boolean
    val processAuthority: Boolean
}

/** Kotlin/JVM-only derivation and validation. This control cannot start Ninja or any subprocess. */
object FullTreeNinjaCompdbPrestartControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(NINJA_PRESTART_SCHEMA, NINJA_PRESTART_CONFIGURATION_POLICY)
    }

    fun generateAndPublish(
        manifestArchivePath: Path,
        reconciliationPath: Path,
        compdbPath: Path,
        captureInputPath: Path,
        headerPlanReadinessPath: Path,
        generatedFileInventoryPath: Path,
        sourceArchivePath: Path,
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        outputPath: Path,
        limits: FullTreeNinjaCompdbPrestartLimits = FullTreeNinjaCompdbPrestartLimits(),
    ): FullTreeNinjaCompdbPrestartRegistry {
        val paths = NinjaPrestartPaths(
            outputPath,
            manifestArchivePath,
            reconciliationPath,
            compdbPath,
            captureInputPath,
            headerPlanReadinessPath,
            generatedFileInventoryPath,
            sourceArchivePath,
            generatedTreeArchivePath,
            generatedProvenancePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
        )
        requireDistinctControlOutput(
            paths.artifact,
            *paths.inputs().mapIndexed { index, input -> "Ninja compdb-prestart input $index" to input }
                .toTypedArray(),
        )
        requireDistinctNinjaPrestartInputs(paths.inputs())
        val expected = NinjaPrestartInputGuards.open(paths, limits).use { inputs ->
            val derived = deriveNinjaPrestartDocument(paths, limits)
            inputs.verifyUnchanged()
            derived
        }
        publishCanonicalControl(paths.artifact, expected, limits.maximumCanonicalBytes)
        return loadNinjaPrestart(paths, limits)
    }

    fun loadAndValidate(
        path: Path,
        manifestArchivePath: Path,
        reconciliationPath: Path,
        compdbPath: Path,
        captureInputPath: Path,
        headerPlanReadinessPath: Path,
        generatedFileInventoryPath: Path,
        sourceArchivePath: Path,
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeNinjaCompdbPrestartLimits = FullTreeNinjaCompdbPrestartLimits(),
    ): FullTreeNinjaCompdbPrestartRegistry = loadNinjaPrestart(
        NinjaPrestartPaths(
            path,
            manifestArchivePath,
            reconciliationPath,
            compdbPath,
            captureInputPath,
            headerPlanReadinessPath,
            generatedFileInventoryPath,
            sourceArchivePath,
            generatedTreeArchivePath,
            generatedProvenancePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
        ),
        limits,
    )
}

internal data class NinjaPrestartPaths(
    val artifact: Path,
    val manifestArchive: Path,
    val reconciliation: Path,
    val compdb: Path,
    val captureInput: Path,
    val readiness: Path,
    val generatedInventory: Path,
    val sourceArchive: Path,
    val generatedArchive: Path,
    val generatedProvenance: Path,
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
    val buildRecord: Path,
    val inventory: Path,
    val sourceInventory: Path,
    val planningInventory: Path,
) {
    fun inputs(): List<Path> = listOf(
        manifestArchive,
        reconciliation,
        compdb,
        captureInput,
        readiness,
        generatedInventory,
        sourceArchive,
        generatedArchive,
        generatedProvenance,
        scope,
        sourceLock,
        artifactManifest,
        buildRecord,
        inventory,
        sourceInventory,
        planningInventory,
    )

    fun all(): List<Path> = listOf(artifact) + inputs()
}

private fun loadNinjaPrestart(
    paths: NinjaPrestartPaths,
    limits: FullTreeNinjaCompdbPrestartLimits,
): FullTreeNinjaCompdbPrestartRegistry {
    requireDistinctNinjaPrestartInputs(paths.all())
    StableControlFile.open(
        paths.artifact,
        limits.maximumCanonicalBytes.toLong(),
        "full-tree Ninja compdb prestart",
    ).use { artifact ->
        artifact.requireSingleLink("full-tree Ninja compdb prestart")
        NinjaPrestartInputGuards.open(paths, limits).use { inputs ->
            val bytes = artifact.readExactly(0L, artifact.size.toInt(), "full-tree Ninja compdb prestart")
            val document = parseNinjaPrestart(bytes, limits)
            validateNinjaPrestartReportHash(document, limits)
            val expected = deriveNinjaPrestartDocument(paths, limits)
            if (document != expected) ninjaPrestartFail("Ninja compdb prestart differs from its raw inputs")
            val terminal = deriveNinjaPrestartDocument(paths, limits)
            if (terminal != expected) {
                ninjaPrestartFail("Ninja compdb-prestart inputs changed during terminal rederivation")
            }
            requireDistinctNinjaPrestartInputs(paths.all())
            inputs.verifyUnchanged()
            artifact.verifyUnchanged("full-tree Ninja compdb prestart")
            return ValidatedNinjaPrestartRegistry(validatedNinjaPrestartState(document, bytes))
        }
    }
}

internal class NinjaPrestartInputGuards private constructor(
    private val files: List<Pair<String, StableControlFile>>,
) : AutoCloseable {
    internal fun identities(): List<NinjaPrestartRetainedInputIdentity> =
        Collections.unmodifiableList(files.map { (label, file) ->
            NinjaPrestartRetainedInputIdentity(label, file.size, file.authenticatedSha256)
        })

    fun verifyUnchanged() {
        files.forEach { (label, file) ->
            file.requireSingleLink(label)
            file.verifyUnchanged(label)
        }
    }

    override fun close() {
        var firstFailure: Throwable? = null
        files.asReversed().forEach { (_, file) ->
            try {
                file.close()
            } catch (failure: Throwable) {
                val existing = firstFailure
                if (existing == null) firstFailure = failure else existing.addSuppressed(failure)
            }
        }
        firstFailure?.let { throw it }
    }

    companion object {
        fun open(
            paths: NinjaPrestartPaths,
            limits: FullTreeNinjaCompdbPrestartLimits,
        ): NinjaPrestartInputGuards {
            val capture = limits.reconciliation.captureInput
            val generated = capture.generated
            val generatedPlanning = generated.planning
            val readinessPlanning = capture.readiness.dependencies.planning
            val generatedControl = generatedPlanning.control
            val readinessControl = readinessPlanning.control
            val specs = listOf(
                Triple("Ninja manifest archive", paths.manifestArchive, limits.manifestArchive.maximumArchiveBytes),
                Triple(
                    "Clang compdb reconciliation",
                    paths.reconciliation,
                    limits.reconciliation.maximumCanonicalBytes.toLong(),
                ),
                Triple("external compilation database", paths.compdb, limits.reconciliation.maximumCompdbBytes.toLong()),
                Triple("Clang capture input", paths.captureInput, capture.maximumCanonicalBytes.toLong()),
                Triple(
                    "header-plan readiness",
                    paths.readiness,
                    capture.readiness.maximumSerializedBytes.toLong(),
                ),
                Triple(
                    "generated-file inventory",
                    paths.generatedInventory,
                    generated.maximumSerializedBytes.toLong(),
                ),
                Triple(
                    "source archive",
                    paths.sourceArchive,
                    maxOf(generatedControl.maximumSourceArchiveBytes, readinessControl.maximumSourceArchiveBytes),
                ),
                Triple("generated-tree archive", paths.generatedArchive, generated.maximumArchiveBytes),
                Triple(
                    "generated provenance",
                    paths.generatedProvenance,
                    generated.maximumProvenanceBytes.toLong(),
                ),
                Triple(
                    "scope",
                    paths.scope,
                    maxOf(generatedControl.maximumScopeBytes, readinessControl.maximumScopeBytes).toLong(),
                ),
                Triple(
                    "source lock",
                    paths.sourceLock,
                    maxOf(generatedControl.maximumSourceLockBytes, readinessControl.maximumSourceLockBytes).toLong(),
                ),
                Triple(
                    "oracle artifact manifest",
                    paths.artifactManifest,
                    maxOf(
                        generatedControl.maximumArtifactManifestBytes,
                        readinessControl.maximumArtifactManifestBytes,
                    ).toLong(),
                ),
                Triple(
                    "build record",
                    paths.buildRecord,
                    maxOf(generatedControl.maximumBuildRecordBytes, readinessControl.maximumBuildRecordBytes).toLong(),
                ),
                Triple(
                    "full-tree inventory",
                    paths.inventory,
                    maxOf(generatedControl.maximumInventoryBytes, readinessControl.maximumInventoryBytes).toLong(),
                ),
                Triple(
                    "full-tree source inventory",
                    paths.sourceInventory,
                    maxOf(
                        generatedControl.maximumSourceInventoryBytes,
                        readinessControl.maximumSourceInventoryBytes,
                    ).toLong(),
                ),
                Triple(
                    "full-tree planning inventory",
                    paths.planningInventory,
                    maxOf(generatedPlanning.maximumSerializedBytes, readinessPlanning.maximumSerializedBytes).toLong(),
                ),
            )
            val opened = ArrayList<Pair<String, StableControlFile>>(specs.size)
            try {
                specs.forEach { (label, path, maximumBytes) ->
                    val file = StableControlFile.open(path, maximumBytes, label)
                    opened += label to file
                    file.requireSingleLink(label)
                }
                return NinjaPrestartInputGuards(Collections.unmodifiableList(opened))
            } catch (failure: Throwable) {
                opened.asReversed().forEach { (_, file) ->
                    try {
                        file.close()
                    } catch (closeFailure: Throwable) {
                        failure.addSuppressed(closeFailure)
                    }
                }
                throw failure
            }
        }
    }
}

internal data class NinjaPrestartRetainedInputIdentity(
    val label: String,
    val bytes: Long,
    val sha256: String,
)

private fun deriveNinjaPrestartDocument(
    paths: NinjaPrestartPaths,
    limits: FullTreeNinjaCompdbPrestartLimits,
): JsonObject {
    val reconciliation = FullTreeClangCompdbReconciliationControl.loadAndValidate(
        paths.reconciliation,
        paths.compdb,
        paths.captureInput,
        paths.readiness,
        paths.generatedInventory,
        paths.sourceArchive,
        paths.generatedArchive,
        paths.generatedProvenance,
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        paths.buildRecord,
        paths.inventory,
        paths.sourceInventory,
        paths.planningInventory,
        limits.reconciliation,
    )
    val (reconciliationDocument, reconciliationBytes) = readCanonicalControlObject(
        paths.reconciliation,
        limits.reconciliation.maximumCanonicalBytes,
        "full-tree Clang compdb reconciliation",
        "full-tree-clang-compdb-reconciliation",
    )
    val reconciliationOracle = reconciliationDocument.controlObject("oracle")
    val reconciliationBuild = reconciliationDocument.controlObject("build")
    val reconciliationEvidence = reconciliationDocument.controlObject("evidence")
    val reconciliationCommitments = reconciliationDocument.controlObject("commitments")
    if (OracleArtifacts.sha256(reconciliationBytes) != reconciliation.artifactSha256 ||
        reconciliationBytes.size.toLong() != reconciliation.artifactBytes ||
        reconciliationDocument.controlString("reportSha256") != reconciliation.reportSha256 ||
        reconciliationOracle.controlString("configurationSha256") != reconciliation.configurationSha256 ||
        reconciliationOracle.controlString("captureInputArtifactSha256") !=
        reconciliation.captureInputArtifactSha256 ||
        reconciliationOracle.controlString("captureContextSha256") != reconciliation.captureContextSha256 ||
        reconciliationCommitments.controlString("matchManifestSha256") !=
        reconciliation.matchManifestSha256
    ) {
        ninjaPrestartFail("compdb reconciliation document differs from its validated registry")
    }

    val controlLimits = limits.reconciliation.captureInput.generated.planning.control
    val scope = FullTreeScopeControl.load(
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        controlLimits,
    )
    val (buildRecord, buildRecordBytes) = readCanonicalControlObject(
        paths.buildRecord,
        controlLimits.maximumBuildRecordBytes,
        "build record",
        "build-record",
    )
    val buildRecordSha256 = FullTreeScopeControl.requireBuildRecordBinding(
        scope,
        buildRecordBytes,
        controlLimits,
    )
    if (reconciliationOracle.controlString("buildRecordSha256") != buildRecordSha256) {
        ninjaPrestartFail("compdb reconciliation uses a different build record")
    }

    val buildDirectory = requireNinjaPrestartAbsolutePath(
        buildRecord.controlObject("directories").controlString("build"),
        "build-record build directory",
        limits,
    )
    if (reconciliationBuild.controlString("buildDirectory") != buildDirectory) {
        ninjaPrestartFail("compdb reconciliation build directory differs from the build record")
    }
    val environment = deriveNinjaPrestartEnvironment(buildRecord, reconciliationBuild, limits)
    val sourceDateEpoch = environment.values["SOURCE_DATE_EPOCH"]?.toLongOrNull()
        ?: ninjaPrestartFail("build-record SOURCE_DATE_EPOCH is not an integer")
    if (sourceDateEpoch !in 1L..NINJA_PRESTART_SOURCE_DATE_EPOCH_MAXIMUM) {
        ninjaPrestartFail("build-record SOURCE_DATE_EPOCH exceeds canonical USTAR")
    }
    val ninjaTool = deriveNinjaPrestartTool(buildRecord, reconciliationBuild, limits)

    val expectedRootBytes = reconciliationBuild.controlLong("ninjaManifestBytes")
    val expectedRootSha256 = reconciliationBuild.controlString("ninjaManifestSha256")
    val manifest = try {
        FullTreeNinjaManifestArchive.inspect(
            paths.manifestArchive,
            expectedRootBytes,
            expectedRootSha256,
            sourceDateEpoch,
            limits.manifestArchive,
        )
    } catch (failure: FullTreeNinjaManifestArchiveException) {
        throw FullTreeControlException("Ninja manifest closure is invalid: ${failure.message}", failure)
    }
    val compilerRules = selectNinjaCompilerRules(manifest, limits)
    val expectedStdout = authenticateExpectedNinjaStdout(
        paths.compdb,
        reconciliation,
        reconciliationEvidence,
        limits,
    )
    if (reconciliation.blockerCodes != NINJA_PRESTART_BLOCKER_CODES) {
        ninjaPrestartFail("compdb reconciliation blockers are not the exact carried population")
    }

    return expectedNinjaPrestartDocument(
        reconciliation,
        reconciliationDocument,
        reconciliationBytes,
        scope,
        buildRecordBytes,
        buildRecordSha256,
        buildDirectory,
        environment,
        ninjaTool,
        manifest,
        compilerRules,
        expectedStdout,
        limits,
    )
}

private data class NinjaPrestartEnvironment(
    val records: JsonArray,
    val values: Map<String, String>,
    val sha256: String,
)

private data class NinjaPrestartTool(
    val document: JsonObject,
    val identitySha256: String,
)

private data class NinjaPrestartCompilerRules(
    val names: List<String>,
    val namesSha256: String,
    val rulesSha256: String,
)

private data class NinjaPrestartExpectedStdout(
    val bytes: Long,
    val sha256: String,
    val canonicalSha256: String,
)

private fun deriveNinjaPrestartEnvironment(
    buildRecord: JsonObject,
    reconciliationBuild: JsonObject,
    limits: FullTreeNinjaCompdbPrestartLimits,
): NinjaPrestartEnvironment {
    val variables = buildRecord.controlObject("environment").controlObject("variables")
    if (variables.size !in 3..limits.maximumEnvironmentVariables ||
        variables.size > limits.reconciliation.captureInput.maximumBaseEnvironmentVariables
    ) {
        ninjaPrestartFail("build-record environment exceeds the prestart variable bound")
    }
    var totalBytes = 0L
    val records = variables.entries.map { (name, raw) ->
        if (!name.matches(NINJA_PRESTART_ENVIRONMENT_NAME)) {
            ninjaPrestartFail("build-record environment name is invalid")
        }
        val primitive = raw as? JsonPrimitive
            ?: ninjaPrestartFail("build-record environment value is not a string")
        if (!primitive.isString || '\u0000' in primitive.content) {
            ninjaPrestartFail("build-record environment value is invalid")
        }
        totalBytes = ninjaPrestartAddExact(
            totalBytes,
            name.toByteArray(StandardCharsets.UTF_8).size.toLong(),
            "environment byte",
        )
        totalBytes = ninjaPrestartAddExact(
            totalBytes,
            primitive.content.toByteArray(StandardCharsets.UTF_8).size.toLong(),
            "environment byte",
        )
        if (totalBytes > limits.maximumEnvironmentBytes) {
            ninjaPrestartFail("build-record environment exceeds its byte bound")
        }
        JsonObject(mapOf("name" to JsonPrimitive(name), "value" to JsonPrimitive(primitive.content)))
    }.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.controlString("name") })
    if (records.map { it.controlString("name") }.toSet().size != records.size) {
        ninjaPrestartFail("build-record environment contains duplicate names")
    }
    val array = JsonArray(records)
    val captureEnvironmentSha256 = ninjaPrestartCanonicalCommitment(
        NINJA_PRESTART_CAPTURE_ENVIRONMENT_DOMAIN,
        array,
    )
    if (reconciliationBuild.controlString("baseEnvironmentSha256") != captureEnvironmentSha256) {
        ninjaPrestartFail("compdb reconciliation environment differs from the build record")
    }
    val prestartSha256 = ninjaPrestartCanonicalCommitment(
        NINJA_PRESTART_ENVIRONMENT_DOMAIN,
        array,
    )
    return NinjaPrestartEnvironment(
        records = array,
        values = Collections.unmodifiableMap(
            LinkedHashMap<String, String>().apply {
                records.forEach { record ->
                    put(record.controlString("name"), record.controlString("value"))
                }
            },
        ),
        sha256 = prestartSha256,
    )
}

private fun deriveNinjaPrestartTool(
    buildRecord: JsonObject,
    reconciliationBuild: JsonObject,
    limits: FullTreeNinjaCompdbPrestartLimits,
): NinjaPrestartTool {
    val tool = buildRecord.controlArray("tools").controlObjects("build-record tools")
        .singleOrNull { it.controlString("role") == "buildGenerator" }
        ?: ninjaPrestartFail("build record must contain exactly one buildGenerator tool")
    val path = requireNinjaPrestartAbsolutePath(tool.controlString("path"), "recorded Ninja path", limits)
    val executableBytes = tool.controlLong("executableBytes")
    if (executableBytes !in 1L..limits.maximumToolBytes) {
        ninjaPrestartFail("recorded Ninja executable exceeds its byte bound")
    }
    val versionCommand = tool.controlArray("versionCommand")
    if (versionCommand.firstOrNull()?.controlString("Ninja version command") != path) {
        ninjaPrestartFail("recorded Ninja version command does not start with its executable path")
    }
    val document = JsonObject(
        mapOf(
            "executableBytes" to JsonPrimitive(executableBytes),
            "executableSha256" to JsonPrimitive(tool.controlString("executableSha256")),
            "path" to JsonPrimitive(path),
            "role" to JsonPrimitive("buildGenerator"),
            "versionOutputSha256" to JsonPrimitive(
                OracleArtifacts.sha256(tool.controlString("versionOutput").toByteArray(StandardCharsets.UTF_8)),
            ),
        ),
    )
    val identity = fullTreeGeneratedToolIdentitySha256(document)
    if (reconciliationBuild.controlObject("ninjaTool") != document ||
        reconciliationBuild.controlString("ninjaToolIdentitySha256") != identity
    ) {
        ninjaPrestartFail("compdb reconciliation Ninja identity differs from the build record")
    }
    return NinjaPrestartTool(document, identity)
}

private fun selectNinjaCompilerRules(
    manifest: FullTreeNinjaManifestSnapshot,
    limits: FullTreeNinjaCompdbPrestartLimits,
): NinjaPrestartCompilerRules {
    val names = manifest.rules.asSequence()
        .map(FullTreeNinjaManifestRule::name)
        .filter(NINJA_PRESTART_COMPILER_RULE::matches)
        .sortedWith(FULL_TREE_CODE_POINT_ORDER)
        .toList()
    if (names.isEmpty() || names.size > limits.maximumCompilerRules ||
        names.any { it.toByteArray(StandardCharsets.UTF_8).size > limits.maximumRuleNameBytes }
    ) {
        ninjaPrestartFail("Ninja compiler-rule population exceeds its admitted bounds")
    }
    val families = names.map { it.substringBefore("_COMPILER__") }.toSet()
    if (families != NINJA_PRESTART_COMPILER_RULE_FAMILIES) {
        ninjaPrestartFail("Ninja manifest must declare selected ASM, C, and CXX compiler rules")
    }
    val namesSha256 = ninjaPrestartStringListCommitment(NINJA_PRESTART_RULE_NAMES_DOMAIN, names)
    val rulesSha256 = NinjaPrestartCommitment(NINJA_PRESTART_RULES_DOMAIN).apply {
        token(manifest.ruleManifestSha256.asciiBytes())
        long(names.size.toLong())
        names.forEach { token(it.utf8Bytes()) }
        token(namesSha256.asciiBytes())
    }.finish()
    return NinjaPrestartCompilerRules(
        Collections.unmodifiableList(ArrayList(names)),
        namesSha256,
        rulesSha256,
    )
}

private fun authenticateExpectedNinjaStdout(
    path: Path,
    reconciliation: FullTreeClangCompdbReconciliationRegistry,
    evidence: JsonObject,
    limits: FullTreeNinjaCompdbPrestartLimits,
): NinjaPrestartExpectedStdout = StableControlFile.open(
    path,
    minOf(limits.maximumStdoutBytes, limits.reconciliation.maximumCompdbBytes).toLong(),
    "external reconciled compilation database",
).use { compdb ->
    compdb.requireSingleLink("external reconciled compilation database")
    val sha256 = compdb.sha256(label = "external reconciled compilation database")
    val expectedBytes = evidence.controlLong("compdbBytes")
    val expectedSha256 = evidence.controlString("compdbSha256")
    val canonicalSha256 = evidence.controlString("canonicalCompdbSha256")
    if (compdb.size != expectedBytes || sha256 != expectedSha256 ||
        expectedSha256 != reconciliation.compdbSha256
    ) {
        ninjaPrestartFail("expected Ninja stdout differs from the reconciled external compdb")
    }
    compdb.verifyUnchanged("external reconciled compilation database")
    NinjaPrestartExpectedStdout(compdb.size, sha256, canonicalSha256)
}

private fun expectedNinjaPrestartDocument(
    reconciliation: FullTreeClangCompdbReconciliationRegistry,
    reconciliationDocument: JsonObject,
    reconciliationBytes: ByteArray,
    scope: AuthenticatedFullTreeScope,
    buildRecordBytes: ByteArray,
    buildRecordSha256: String,
    buildDirectory: String,
    environment: NinjaPrestartEnvironment,
    ninjaTool: NinjaPrestartTool,
    manifest: FullTreeNinjaManifestSnapshot,
    compilerRules: NinjaPrestartCompilerRules,
    expectedStdout: NinjaPrestartExpectedStdout,
    limits: FullTreeNinjaCompdbPrestartLimits,
): JsonObject {
    val reconciliationOracle = reconciliationDocument.controlObject("oracle")
    val root = manifest.files.singleOrNull { it.path == manifest.rootManifest }
        ?: ninjaPrestartFail("Ninja manifest snapshot has no unique root manifest")
    val argv = buildList {
        add(ninjaTool.document.controlString("path"))
        add("-f")
        add("build.ninja")
        add("-t")
        add("compdb")
        addAll(compilerRules.names)
    }
    val argvSha256 = ninjaPrestartStringListCommitment(NINJA_PRESTART_ARGV_DOMAIN, argv)
    val expectedStdoutSha256 = NinjaPrestartCommitment(NINJA_PRESTART_EXPECTED_STDOUT_DOMAIN).apply {
        long(expectedStdout.bytes)
        token(expectedStdout.sha256.asciiBytes())
        token(expectedStdout.canonicalSha256.asciiBytes())
    }.finish()
    val manifestClosureSha256 = NinjaPrestartCommitment(NINJA_PRESTART_MANIFEST_CLOSURE_DOMAIN).apply {
        token(manifest.configurationSha256.asciiBytes())
        token(manifest.reportSha256.asciiBytes())
        long(manifest.archiveBytes)
        token(manifest.archiveSha256.asciiBytes())
        token(manifest.archiveRoot.utf8Bytes())
        token(manifest.rootManifest.utf8Bytes())
        long(root.bytes)
        token(root.sha256.asciiBytes())
        long(manifest.files.size.toLong())
        long(manifest.edges.size.toLong())
        long(manifest.rules.size.toLong())
        long(manifest.totalBytes)
        token(manifest.fileManifestSha256.asciiBytes())
        token(manifest.includeGraphSha256.asciiBytes())
        token(manifest.ruleManifestSha256.asciiBytes())
    }.finish()
    val predecessorManifestSha256 = NinjaPrestartCommitment(NINJA_PRESTART_PREDECESSORS_DOMAIN).apply {
        long(reconciliationBytes.size.toLong())
        token(reconciliation.artifactSha256.asciiBytes())
        token(reconciliation.reportSha256.asciiBytes())
        token(reconciliation.configurationSha256.asciiBytes())
        token(reconciliation.captureInputArtifactSha256.asciiBytes())
        token(reconciliation.captureContextSha256.asciiBytes())
        token(reconciliation.matchManifestSha256.asciiBytes())
        long(expectedStdout.bytes)
        token(expectedStdout.sha256.asciiBytes())
        long(buildRecordBytes.size.toLong())
        token(buildRecordSha256.asciiBytes())
        token(scope.sha256.asciiBytes())
        token(scope.sourceLockSha256.asciiBytes())
        token(scope.artifactManifestSha256.asciiBytes())
    }.finish()
    val invocationSha256 = NinjaPrestartCommitment(NINJA_PRESTART_INVOCATION_DOMAIN).apply {
        token(buildDirectory.utf8Bytes())
        token(argvSha256.asciiBytes())
        token(environment.sha256.asciiBytes())
        token(expectedStdoutSha256.asciiBytes())
        token("cleared".asciiBytes())
        token("closed".asciiBytes())
        token("direct-exec".asciiBytes())
    }.finish()
    val containmentPolicySha256 = ninjaPrestartCanonicalCommitment(
        NINJA_PRESTART_CONTAINMENT_DOMAIN,
        NINJA_PRESTART_REQUIRED_CONTAINMENT,
    )
    val prestartContextSha256 = NinjaPrestartCommitment(NINJA_PRESTART_CONTEXT_DOMAIN).apply {
        token(FullTreeNinjaCompdbPrestartControl.configurationSha256.asciiBytes())
        token(predecessorManifestSha256.asciiBytes())
        token(ninjaTool.identitySha256.asciiBytes())
        token(manifestClosureSha256.asciiBytes())
        token(compilerRules.rulesSha256.asciiBytes())
        token(invocationSha256.asciiBytes())
        token(expectedStdoutSha256.asciiBytes())
        token(containmentPolicySha256.asciiBytes())
    }.finish()

    val withoutHash = JsonObject(
        mapOf(
            "acpBoundary" to NINJA_PRESTART_ACP_BOUNDARY,
            "authority" to NINJA_PRESTART_AUTHORITY,
            "blockerDispositions" to JsonArray(NINJA_PRESTART_BLOCKER_DISPOSITIONS),
            "blockers" to JsonArray(NINJA_PRESTART_BLOCKERS),
            "bounds" to NINJA_PRESTART_BOUNDS,
            "commitments" to JsonObject(
                mapOf(
                    "compilerRulesSha256" to JsonPrimitive(compilerRules.rulesSha256),
                    "containmentPolicySha256" to JsonPrimitive(containmentPolicySha256),
                    "expectedStdoutSha256" to JsonPrimitive(expectedStdoutSha256),
                    "invocationSha256" to JsonPrimitive(invocationSha256),
                    "manifestClosureSha256" to JsonPrimitive(manifestClosureSha256),
                    "ninjaIdentitySha256" to JsonPrimitive(ninjaTool.identitySha256),
                    "predecessorManifestSha256" to JsonPrimitive(predecessorManifestSha256),
                    "prestartContextSha256" to JsonPrimitive(prestartContextSha256),
                ),
            ),
            "compilerRules" to JsonObject(
                mapOf(
                    "count" to JsonPrimitive(compilerRules.names.size),
                    "declaredRuleManifestSha256" to JsonPrimitive(manifest.ruleManifestSha256),
                    "names" to JsonArray(compilerRules.names.map(::JsonPrimitive)),
                    "namesSha256" to JsonPrimitive(compilerRules.namesSha256),
                    "selection" to JsonPrimitive(
                        "kotlin-host-prefix-filtered-declared-c-cxx-asm-compiler-rules",
                    ),
                ),
            ),
            "execution" to NINJA_PRESTART_EXECUTION,
            "invocation" to JsonObject(
                mapOf(
                    "argv" to JsonArray(argv.map(::JsonPrimitive)),
                    "argvSha256" to JsonPrimitive(argvSha256),
                    "environment" to environment.records,
                    "environmentSha256" to JsonPrimitive(environment.sha256),
                    "expectedStdout" to JsonObject(
                        mapOf(
                            "bytes" to JsonPrimitive(expectedStdout.bytes),
                            "canonicalSha256" to JsonPrimitive(expectedStdout.canonicalSha256),
                            "sha256" to JsonPrimitive(expectedStdout.sha256),
                            "source" to JsonPrimitive("external-reconciled-compdb"),
                        ),
                    ),
                    "inheritedEnvironment" to JsonPrimitive("cleared"),
                    "shell" to JsonPrimitive(false),
                    "stderr" to JsonObject(
                        mapOf(
                            "maximumBytes" to JsonPrimitive(NINJA_PRESTART_MAXIMUM_STDERR_BYTES),
                            "merge" to JsonPrimitive(false),
                        ),
                    ),
                    "stdin" to JsonPrimitive("closed"),
                    "workingDirectory" to JsonPrimitive(buildDirectory),
                ),
            ),
            "kind" to JsonPrimitive("full-tree-ninja-compdb-prestart-v1"),
            "manifestClosure" to JsonObject(
                mapOf(
                    "archiveBytes" to JsonPrimitive(manifest.archiveBytes),
                    "archiveRoot" to JsonPrimitive(manifest.archiveRoot),
                    "archiveSha256" to JsonPrimitive(manifest.archiveSha256),
                    "configurationSha256" to JsonPrimitive(manifest.configurationSha256),
                    "edges" to JsonPrimitive(manifest.edges.size),
                    "fileManifestSha256" to JsonPrimitive(manifest.fileManifestSha256),
                    "files" to JsonPrimitive(manifest.files.size),
                    "includeGraphSha256" to JsonPrimitive(manifest.includeGraphSha256),
                    "reportSha256" to JsonPrimitive(manifest.reportSha256),
                    "rootManifest" to JsonPrimitive(manifest.rootManifest),
                    "rootManifestBytes" to JsonPrimitive(root.bytes),
                    "rootManifestSha256" to JsonPrimitive(root.sha256),
                    "ruleManifestSha256" to JsonPrimitive(manifest.ruleManifestSha256),
                    "rules" to JsonPrimitive(manifest.rules.size),
                    "totalBytes" to JsonPrimitive(manifest.totalBytes),
                ),
            ),
            "ninja" to JsonObject(
                ninjaTool.document + mapOf(
                    "runtimeClosureManifestSha256" to JsonNull,
                    "toolIdentitySha256" to JsonPrimitive(ninjaTool.identitySha256),
                ),
            ),
            "oracle" to JsonObject(
                mapOf(
                    "buildRecordBytes" to JsonPrimitive(buildRecordBytes.size),
                    "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
                    "captureContextSha256" to JsonPrimitive(reconciliation.captureContextSha256),
                    "captureInputArtifactSha256" to JsonPrimitive(
                        reconciliation.captureInputArtifactSha256,
                    ),
                    "compdbReconciliationArtifactBytes" to JsonPrimitive(reconciliation.artifactBytes),
                    "compdbReconciliationArtifactSha256" to JsonPrimitive(
                        reconciliation.artifactSha256,
                    ),
                    "compdbReconciliationConfigurationSha256" to JsonPrimitive(
                        reconciliation.configurationSha256,
                    ),
                    "compdbReconciliationReportSha256" to JsonPrimitive(reconciliation.reportSha256),
                    "configurationSha256" to JsonPrimitive(
                        FullTreeNinjaCompdbPrestartControl.configurationSha256,
                    ),
                    "id" to reconciliationOracle.getValue("id"),
                    "matchManifestSha256" to JsonPrimitive(reconciliation.matchManifestSha256),
                    "oracleManifestSha256" to JsonPrimitive(scope.artifactManifestSha256),
                    "scopeSha256" to JsonPrimitive(scope.sha256),
                    "sourceLockSha256" to JsonPrimitive(scope.sourceLockSha256),
                ),
            ),
            "prestartPolicy" to NINJA_PRESTART_POLICY,
            "requiredContainment" to NINJA_PRESTART_REQUIRED_CONTAINMENT,
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(NINJA_PRESTART_MAXIMUM_CANONICAL_BYTES)),
    )
    val expected = JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
    val (_, bytes) = snapshotControlObject(
        expected,
        limits.maximumCanonicalBytes,
        "full-tree Ninja compdb prestart",
        NINJA_PRESTART_SCHEMA,
    )
    if (bytes.size > limits.maximumCanonicalBytes) {
        ninjaPrestartFail("Ninja compdb prestart exceeds its canonical byte bound")
    }
    return expected
}

private data class ValidatedNinjaPrestartState(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val reconciliationArtifactSha256: String,
    val prestartContextSha256: String,
    val predecessorManifestSha256: String,
    val manifestArchiveSha256: String,
    val manifestClosureSha256: String,
    val manifestConfigurationSha256: String,
    val manifestReportSha256: String,
    val manifestFileManifestSha256: String,
    val manifestIncludeGraphSha256: String,
    val manifestRuleManifestSha256: String,
    val manifestArchiveRoot: String,
    val manifestRootFile: String,
    val manifestRootBytes: Long,
    val manifestRootSha256: String,
    val compilerRulesSha256: String,
    val compilerRuleNames: List<String>,
    val ninjaExecutablePath: String,
    val ninjaExecutableBytes: Long,
    val ninjaExecutableSha256: String,
    val ninjaToolIdentitySha256: String,
    val workingDirectory: String,
    val argv: List<String>,
    val argvSha256: String,
    val environment: Map<String, String>,
    val environmentSha256: String,
    val expectedStdoutBytes: Long,
    val expectedStdoutSha256: String,
    val expectedStdoutCanonicalSha256: String,
    val expectedStdoutCommitmentSha256: String,
    val invocationSha256: String,
    val containmentPolicySha256: String,
    val blockerCodes: List<String>,
    val canonicalBytes: ByteArray,
)

private class ValidatedNinjaPrestartRegistry(
    state: ValidatedNinjaPrestartState,
) : FullTreeNinjaCompdbPrestartRegistry {
    override val artifactSha256: String = state.artifactSha256
    override val artifactBytes: Long = state.artifactBytes
    override val reportSha256: String = state.reportSha256
    override val configurationSha256: String = state.configurationSha256
    override val reconciliationArtifactSha256: String = state.reconciliationArtifactSha256
    override val prestartContextSha256: String = state.prestartContextSha256
    override val predecessorManifestSha256: String = state.predecessorManifestSha256
    override val manifestArchiveSha256: String = state.manifestArchiveSha256
    override val manifestClosureSha256: String = state.manifestClosureSha256
    override val manifestConfigurationSha256: String = state.manifestConfigurationSha256
    override val manifestReportSha256: String = state.manifestReportSha256
    override val manifestFileManifestSha256: String = state.manifestFileManifestSha256
    override val manifestIncludeGraphSha256: String = state.manifestIncludeGraphSha256
    override val manifestRuleManifestSha256: String = state.manifestRuleManifestSha256
    override val manifestArchiveRoot: String = state.manifestArchiveRoot
    override val manifestRootFile: String = state.manifestRootFile
    override val manifestRootBytes: Long = state.manifestRootBytes
    override val manifestRootSha256: String = state.manifestRootSha256
    override val compilerRulesSha256: String = state.compilerRulesSha256
    override val compilerRuleNames: List<String> =
        Collections.unmodifiableList(ArrayList(state.compilerRuleNames))
    override val ninjaExecutablePath: String = state.ninjaExecutablePath
    override val ninjaExecutableBytes: Long = state.ninjaExecutableBytes
    override val ninjaExecutableSha256: String = state.ninjaExecutableSha256
    override val ninjaToolIdentitySha256: String = state.ninjaToolIdentitySha256
    override val workingDirectory: String = state.workingDirectory
    override val argv: List<String> = Collections.unmodifiableList(ArrayList(state.argv))
    override val argvSha256: String = state.argvSha256
    override val environment: Map<String, String> =
        Collections.unmodifiableMap(LinkedHashMap(state.environment))
    override val environmentSha256: String = state.environmentSha256
    override val expectedStdoutBytes: Long = state.expectedStdoutBytes
    override val expectedStdoutSha256: String = state.expectedStdoutSha256
    override val expectedStdoutCanonicalSha256: String = state.expectedStdoutCanonicalSha256
    override val expectedStdoutCommitmentSha256: String = state.expectedStdoutCommitmentSha256
    override val invocationSha256: String = state.invocationSha256
    override val containmentPolicySha256: String = state.containmentPolicySha256
    override val blockerCodes: List<String> = Collections.unmodifiableList(ArrayList(state.blockerCodes))
    private val storedCanonicalBytes = state.canonicalBytes.copyOf()
    override val canonicalBytes: ByteArray
        get() = storedCanonicalBytes.copyOf()
    override val startAuthorized: Boolean = false
    override val processAuthority: Boolean = false
}

private fun validatedNinjaPrestartState(
    document: JsonObject,
    bytes: ByteArray,
): ValidatedNinjaPrestartState {
    val oracle = document.controlObject("oracle")
    val commitments = document.controlObject("commitments")
    val closure = document.controlObject("manifestClosure")
    val rules = document.controlObject("compilerRules")
    val ninja = document.controlObject("ninja")
    val invocation = document.controlObject("invocation")
    val expectedStdout = invocation.controlObject("expectedStdout")
    val environment = LinkedHashMap<String, String>()
    invocation.controlArray("environment").controlObjects("prestart environment").forEach { record ->
        if (environment.put(record.controlString("name"), record.controlString("value")) != null) {
            ninjaPrestartFail("validated prestart environment contains a duplicate name")
        }
    }
    return ValidatedNinjaPrestartState(
        artifactSha256 = OracleArtifacts.sha256(bytes),
        artifactBytes = bytes.size.toLong(),
        reportSha256 = document.controlString("reportSha256"),
        configurationSha256 = oracle.controlString("configurationSha256"),
        reconciliationArtifactSha256 = oracle.controlString("compdbReconciliationArtifactSha256"),
        prestartContextSha256 = commitments.controlString("prestartContextSha256"),
        predecessorManifestSha256 = commitments.controlString("predecessorManifestSha256"),
        manifestArchiveSha256 = closure.controlString("archiveSha256"),
        manifestClosureSha256 = commitments.controlString("manifestClosureSha256"),
        manifestConfigurationSha256 = closure.controlString("configurationSha256"),
        manifestReportSha256 = closure.controlString("reportSha256"),
        manifestFileManifestSha256 = closure.controlString("fileManifestSha256"),
        manifestIncludeGraphSha256 = closure.controlString("includeGraphSha256"),
        manifestRuleManifestSha256 = closure.controlString("ruleManifestSha256"),
        manifestArchiveRoot = closure.controlString("archiveRoot"),
        manifestRootFile = closure.controlString("rootManifest"),
        manifestRootBytes = closure.controlLong("rootManifestBytes"),
        manifestRootSha256 = closure.controlString("rootManifestSha256"),
        compilerRulesSha256 = commitments.controlString("compilerRulesSha256"),
        compilerRuleNames = rules.controlArray("names").map { it.controlString("compiler rule") },
        ninjaExecutablePath = ninja.controlString("path"),
        ninjaExecutableBytes = ninja.controlLong("executableBytes"),
        ninjaExecutableSha256 = ninja.controlString("executableSha256"),
        ninjaToolIdentitySha256 = ninja.controlString("toolIdentitySha256"),
        workingDirectory = invocation.controlString("workingDirectory"),
        argv = invocation.controlArray("argv").map { it.controlString("Ninja argv") },
        argvSha256 = invocation.controlString("argvSha256"),
        environment = environment,
        environmentSha256 = invocation.controlString("environmentSha256"),
        expectedStdoutBytes = expectedStdout.controlLong("bytes"),
        expectedStdoutSha256 = expectedStdout.controlString("sha256"),
        expectedStdoutCanonicalSha256 = expectedStdout.controlString("canonicalSha256"),
        expectedStdoutCommitmentSha256 = commitments.controlString("expectedStdoutSha256"),
        invocationSha256 = commitments.controlString("invocationSha256"),
        containmentPolicySha256 = commitments.controlString("containmentPolicySha256"),
        blockerCodes = document.controlArray("blockers").controlObjects("prestart blockers")
            .map { it.controlString("code") },
        canonicalBytes = bytes.copyOf(),
    )
}

private fun parseNinjaPrestart(
    bytes: ByteArray,
    limits: FullTreeNinjaCompdbPrestartLimits,
): JsonObject = try {
    val document = OracleJson.parseCanonical(bytes, controlJsonLimits(limits.maximumCanonicalBytes)) as? JsonObject
        ?: ninjaPrestartFail("Ninja compdb-prestart root must be an object")
    OracleSchemas.validate(NINJA_PRESTART_SCHEMA, document)
    document
} catch (failure: FullTreeControlException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeControlException(
        "Ninja compdb prestart is not strict canonical schema-valid JSON",
        failure,
    )
}

private fun validateNinjaPrestartReportHash(
    document: JsonObject,
    limits: FullTreeNinjaCompdbPrestartLimits,
) {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val expected = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumCanonicalBytes)),
    )
    if (document.controlString("reportSha256") != expected) {
        ninjaPrestartFail("Ninja compdb-prestart report hash does not reconcile")
    }
}

private fun requireNinjaPrestartAbsolutePath(
    value: String,
    label: String,
    limits: FullTreeNinjaCompdbPrestartLimits,
): String {
    if (!value.startsWith('/') || value == "/" ||
        value.toByteArray(StandardCharsets.UTF_8).size > limits.maximumPathBytes ||
        value.endsWith('/') || "//" in value || '\\' in value ||
        value.any { it == '\u0000' || it == '\r' || it == '\n' }
    ) {
        ninjaPrestartFail("$label is not a canonical absolute path")
    }
    value.removePrefix("/").split('/').forEach { component ->
        if (component.isEmpty() || component == "." || component == ".." ||
            component.toByteArray(StandardCharsets.UTF_8).size >
            limits.manifestArchive.maximumPathComponentBytes
        ) {
            ninjaPrestartFail("$label contains a noncanonical path component")
        }
    }
    return value
}

private fun ninjaPrestartCanonicalCommitment(domain: String, value: JsonElement): String =
    NinjaPrestartCommitment(domain).apply {
        token(
            OracleJson.canonicalBytes(
                value,
                controlJsonLimits(NINJA_PRESTART_MAXIMUM_CANONICAL_BYTES),
            ),
        )
    }.finish()

private fun ninjaPrestartStringListCommitment(domain: String, values: List<String>): String =
    NinjaPrestartCommitment(domain).apply {
        long(values.size.toLong())
        values.forEach { token(it.utf8Bytes()) }
    }.finish()

private class NinjaPrestartCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token(domain.utf8Bytes())
    }

    fun long(value: Long) {
        if (value < 0L) ninjaPrestartFail("negative value cannot enter a prestart commitment")
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array())
    }

    fun token(bytes: ByteArray) {
        long(bytes.size.toLong())
        digest.update(bytes)
    }

    fun finish(): String = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun ninjaPrestartAddExact(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("Ninja compdb-prestart $label count overflows", failure)
}

private fun String.utf8Bytes(): ByteArray = toByteArray(StandardCharsets.UTF_8)
private fun String.asciiBytes(): ByteArray = toByteArray(StandardCharsets.US_ASCII)

private fun requireDistinctNinjaPrestartInputs(paths: List<Path>) {
    val normalized = paths.map { it.toAbsolutePath().normalize() }
    if (normalized.toSet().size != normalized.size) ninjaPrestartFail("input paths must be distinct")
    val identities = HashSet<Any>()
    normalized.forEach { path ->
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeControlException("Ninja compdb-prestart input is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            ninjaPrestartFail("input is not an identified regular file")
        }
        if (!identities.add(attributes.fileKey())) ninjaPrestartFail("inputs contain a physical-file alias")
    }
}

private fun ninjaPrestartFail(message: String): Nothing = throw FullTreeControlException(message)

private const val NINJA_PRESTART_SCHEMA = "full-tree-ninja-compdb-prestart"
private const val NINJA_PRESTART_MAXIMUM_CANONICAL_BYTES = 16 * 1024 * 1024
private const val NINJA_PRESTART_MAXIMUM_COMPILER_RULES = 65_536
private const val NINJA_PRESTART_MAXIMUM_ENVIRONMENT_BYTES = 4L * 1024L * 1024L
private const val NINJA_PRESTART_MAXIMUM_ENVIRONMENT_VARIABLES = 64
private const val NINJA_PRESTART_MAXIMUM_PATH_BYTES = 4_096
private const val NINJA_PRESTART_MAXIMUM_RULE_NAME_BYTES = 256
private const val NINJA_PRESTART_MAXIMUM_STDOUT_BYTES = 64 * 1024 * 1024
private const val NINJA_PRESTART_MAXIMUM_STDERR_BYTES = 8 * 1024 * 1024
private const val NINJA_PRESTART_MAXIMUM_TOOL_BYTES = 512L * 1024L * 1024L
private const val NINJA_PRESTART_SOURCE_DATE_EPOCH_MAXIMUM = 0x1ffffffffL
private val NINJA_PRESTART_ENVIRONMENT_NAME = Regex("[A-Z_][A-Z0-9_]*")
private val NINJA_PRESTART_COMPILER_RULE =
    Regex("(?:C|CXX|ASM)_COMPILER__[A-Za-z0-9_.+\\-]+_RelWithDebInfo")
private val NINJA_PRESTART_COMPILER_RULE_FAMILIES = setOf("ASM", "C", "CXX")

private val NINJA_PRESTART_CONFIGURATION_POLICY: JsonObject by lazy {
    JsonObject(
        mapOf(
            "acpBoundary" to NINJA_PRESTART_ACP_BOUNDARY,
            "authority" to NINJA_PRESTART_AUTHORITY,
            "blockerDispositions" to JsonArray(NINJA_PRESTART_BLOCKER_DISPOSITIONS),
            "blockers" to JsonArray(NINJA_PRESTART_BLOCKERS),
            "bounds" to NINJA_PRESTART_BOUNDS,
            "compdbReconciliationSchemaSha256" to JsonPrimitive(
                OracleSchemas.identity("full-tree-clang-compdb-reconciliation").sha256,
            ),
            "execution" to NINJA_PRESTART_EXECUTION,
            "id" to JsonPrimitive(NINJA_PRESTART_SCHEMA),
            "manifestArchiveConfigurationSha256" to JsonPrimitive(
                FullTreeNinjaManifestArchive.configurationSha256,
            ),
            "prestartPolicy" to NINJA_PRESTART_POLICY,
            "requiredContainment" to NINJA_PRESTART_REQUIRED_CONTAINMENT,
            "version" to JsonPrimitive(1),
        ),
    )
}

private val NINJA_PRESTART_AUTHORITY = ninjaPrestartConstantObject(
    """
    {
      "status":"kotlin-bound-unexecuted-ninja-compdb-prestart",
      "predecessorBindingsReconciled":true,
      "rawInputIntegrityVerified":true,
      "buildRecordOracleManifestBindingVerified":true,
      "recordedNinjaExecutableIdentityBound":true,
      "liveNinjaExecutableAuthenticated":false,
      "manifestClosureIntegrityBound":true,
      "manifestClosureOriginAuthenticated":false,
      "manifestIncludeGraphValidated":true,
      "compilerRulesSelectedByKotlinHost":true,
      "compilerRuleDeclarationsOriginAuthenticated":false,
      "invocationFixedByKotlinHost":true,
      "expectedStdoutBound":true,
      "containmentRequirementsBound":true,
      "ninjaRuntimeClosureAuthenticated":false,
      "runtimeProvisioned":false,
      "retainedRuntimeHandlesPresent":false,
      "startAuthorized":false,
      "executionStarted":false,
      "ninjaExecuted":false,
      "stdoutObserved":false,
      "stderrObserved":false,
      "exitStatusObserved":false,
      "compdbExecutionAuthenticated":false,
      "buildGraphOriginAuthenticated":false,
      "compilerActionGraphOriginAuthenticated":false,
      "compilerExecuted":false,
      "captureStarted":false,
      "captureOutputsPresent":false,
      "exitStatusesPresent":false,
      "compilerCaptureAuthenticated":false,
      "compilerWriteSetContained":false,
      "generatedSnapshotAuthenticated":false,
      "headerPopulationComplete":false,
      "headerPlanReady":false,
      "cleanCompilationProven":false,
      "releaseEligible":false
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_ACP_BOUNDARY = ninjaPrestartConstantObject(
    """
    {
      "role":"first-class-candidate-producer-operator",
      "candidateContribution":"authenticated-session-change-build-artifact-provenance",
      "candidateProvenanceAccess":"read-only-oracle-input",
      "candidateAdmissionOwner":"kotlin-jvm-host",
      "candidateLiveExecutionOwner":"separately-reviewed-kotlin-jvm-host",
      "candidateEvidenceDisposition":"non-authoritative-input-to-later-host-validation",
      "candidateLineageAdmission":"not-an-input-to-ninja-compdb-prestart-v1",
      "referenceSubjectAdmission":"kotlin-jvm-host-only",
      "prestartAuthoringAuthority":false,
      "manifestClosureAuthoringAuthority":false,
      "compilerRuleSelectionAuthority":false,
      "invocationAuthority":false,
      "graphEvidenceAuthoringAuthority":false,
      "compdbEvidenceAuthoringAuthority":false,
      "compilerActionAuthoringAuthority":false,
      "captureAuthority":false,
      "executionAuthority":false,
      "oracleAuthority":false,
      "referenceAuthoringAuthority":false,
      "policyAuthoringAuthority":false,
      "validationAuthority":false,
      "observationAuthoringAuthority":false,
      "startAuthority":false,
      "containmentAuthority":false,
      "terminalAbsenceAuthority":false,
      "scoringAuthority":false,
      "certificationAuthority":false,
      "releaseAuthority":false
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_POLICY = ninjaPrestartConstantObject(
    """
    {
      "owner":"kotlin-jvm-host",
      "artifactState":"persisted-unexecuted-revalidated-prestart",
      "rawInputModel":"caller-supplied-paths-opened-as-bounded-stable-single-link-regular-files",
      "manifestArchive":"strict-canonical-ustar-xz-ninja-manifest-only-closure",
      "manifestGraph":"rooted-build-ninja-recursive-include-and-subninja-closure",
      "compilerRuleSelection":"kotlin-host-derived-c-cxx-asm-compiler-rule-names-no-caller-rule-list",
      "invocation":"direct-exec-ninja-f-build-ninja-t-compdb-exact-selected-rules-no-x",
      "environment":"authenticated-build-record-variables-canonical-name-order-inherited-environment-cleared",
      "stdoutExpectation":"byte-exact-external-reconciled-compdb-plus-canonical-digest",
      "stderrDisposition":"separate-bounded-nonmerged-capture-required-at-execution",
      "executionDisposition":"not-executed-no-process-no-shell-no-callback",
      "runtimeClosureDisposition":"absent-and-unauthenticated-start-forbidden",
      "persistence":"canonical-json-rederived-from-raw-predecessors-on-load",
      "startDisposition":"separate-reviewed-kotlin-host-revalidation-retained-descriptors-and-containment-required",
      "identity":"kotlin-jvm-domain-separated-length-framed-sha256",
      "blockerDisposition":"all-eight-clang-compdb-reconciliation-blockers-carried-unchanged"
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_BOUNDS = ninjaPrestartConstantObject(
    """
    {
      "maximumAddressSpaceBytes":1073741824,
      "maximumArchiveBytes":67108864,
      "maximumArchiveIndexBytes":16777216,
      "maximumArchiveMembers":10000,
      "maximumBlockers":8,
      "maximumCanonicalBytes":16777216,
      "maximumCompilerRules":65536,
      "maximumCpuSeconds":120,
      "maximumEnvironmentBytes":4194304,
      "maximumEnvironmentVariables":64,
      "maximumExecutionMillis":120000,
      "maximumExpandedArchiveBytes":268435456,
      "maximumGraphWorkUnits":10000000,
      "maximumIncludeEdges":32768,
      "maximumManifestFileBytes":33554432,
      "maximumManifestFiles":4096,
      "maximumManifestLines":2000000,
      "maximumManifestRules":65536,
      "maximumManifestTotalBytes":134217728,
      "maximumOpenFiles":128,
      "maximumPathBytes":4096,
      "maximumPathComponentBytes":255,
      "maximumProcesses":16,
      "maximumRuleNameBytes":256,
      "maximumSingleLineBytes":1048576,
      "maximumStderrBytes":8388608,
      "maximumStdoutBytes":67108864,
      "maximumToolBytes":536870912,
      "maximumXzDecoderBytes":268435456,
      "sourceDateEpochMaximum":8589934591
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_REQUIRED_CONTAINMENT = ninjaPrestartConstantObject(
    """
    {
      "boundary":"linux-bubblewrap-boundary",
      "launchPurpose":"ninja-compdb-query",
      "startGate":"positive-byte-after-complete-provisioning",
      "network":"unshared-no-network",
      "inheritedFilesystem":"none",
      "manifestClosureMount":"authenticated-read-only-at-recorded-build-directory",
      "ninjaExecutableMount":"authenticated-read-only",
      "runtimeClosureMounts":"authenticated-read-only-required-before-start",
      "callerMounts":"forbidden",
      "callerStagingRoots":"forbidden",
      "inheritedEnvironment":"cleared",
      "stdin":"closed",
      "shell":"forbidden",
      "cgroupV2":"pids-memory-cpu-required-no-fallback",
      "wholeCgroupCleanup":"required-on-every-terminal-path",
      "terminalAbsenceProof":"required-before-return",
      "concurrentOutputCapture":"bounded-nontruncating-separate-stdout-stderr-fail-closed",
      "resourceLimits":{
        "maximumProcesses":16,
        "maximumOpenFiles":128,
        "maximumFileBytes":67108864,
        "maximumAddressSpaceBytes":1073741824,
        "maximumCpuSeconds":120,
        "maximumWallMillis":120000,
        "maximumStdoutBytes":67108864,
        "maximumStderrBytes":8388608
      }
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_EXECUTION = ninjaPrestartConstantObject(
    """
    {
      "phase":"pre-start",
      "startAuthorized":false,
      "runtimeProvisioned":false,
      "processStarted":false,
      "stdoutBytes":null,
      "stdoutSha256":null,
      "stdoutCanonicalSha256":null,
      "stderrBytes":null,
      "stderrSha256":null,
      "exitStatus":null,
      "timedOut":null,
      "outputLimitExceeded":null,
      "cleanupComplete":null,
      "terminalAbsenceProven":null,
      "containmentReceiptSha256":null,
      "compdbReceiptSha256":null
    }
    """.trimIndent(),
)

private val NINJA_PRESTART_BLOCKER_CODES = listOf(
    "complete-project-header-inventory-missing",
    "compiler-capture-provenance-missing",
    "compiler-option-arity-unvalidated",
    "generated-generation-receipt-missing",
    "generated-snapshot-completeness-unproven",
    "ninja-live-edge-replay-missing",
    "physical-build-root-unverified",
    "physical-project-roots-unverified",
)
private val NINJA_PRESTART_BLOCKERS = NINJA_PRESTART_BLOCKER_CODES.map { code ->
    JsonObject(mapOf("code" to JsonPrimitive(code), "status" to JsonPrimitive("unresolved")))
}
private val NINJA_PRESTART_BLOCKER_DISPOSITIONS = NINJA_PRESTART_BLOCKER_CODES.map { code ->
    JsonObject(
        mapOf(
            "activeCodes" to JsonArray(listOf(JsonPrimitive(code))),
            "code" to JsonPrimitive(code),
            "disposition" to JsonPrimitive("carried"),
            "source" to JsonPrimitive("clang-compdb-reconciliation-v1"),
        ),
    )
}

private fun ninjaPrestartConstantObject(value: String): JsonObject = try {
    OracleJson.parse(value.toByteArray(StandardCharsets.UTF_8), controlJsonLimits(128 * 1024)) as? JsonObject
        ?: error("trusted Ninja prestart constant is not an object")
} catch (failure: Exception) {
    throw ExceptionInInitializerError(failure)
}

private const val NINJA_PRESTART_CAPTURE_ENVIRONMENT_DOMAIN =
    "full-tree-clang-capture-base-environment-v1"
private const val NINJA_PRESTART_ENVIRONMENT_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-environment/v1"
private const val NINJA_PRESTART_RULE_NAMES_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-rule-names/v1"
private const val NINJA_PRESTART_RULES_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-compiler-rules/v1"
private const val NINJA_PRESTART_ARGV_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-argv/v1"
private const val NINJA_PRESTART_EXPECTED_STDOUT_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-expected-stdout/v1"
private const val NINJA_PRESTART_MANIFEST_CLOSURE_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-manifest-closure/v1"
private const val NINJA_PRESTART_PREDECESSORS_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-predecessors/v1"
private const val NINJA_PRESTART_INVOCATION_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-invocation/v1"
private const val NINJA_PRESTART_CONTAINMENT_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-containment/v1"
private const val NINJA_PRESTART_CONTEXT_DOMAIN =
    "decomp-thing/full-tree-ninja-compdb-prestart-context/v1"

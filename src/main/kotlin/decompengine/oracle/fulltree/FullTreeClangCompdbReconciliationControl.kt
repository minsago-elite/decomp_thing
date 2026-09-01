package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Caller-lowerable ceilings beneath the immutable external compdb reconciliation profile. */
data class FullTreeClangCompdbReconciliationLimits(
    val captureInput: FullTreeClangCaptureInputLimits = FullTreeClangCaptureInputLimits(),
    val maximumActions: Int = COMPDB_MAXIMUM_ACTIONS,
    val maximumCanonicalBytes: Int = COMPDB_MAXIMUM_CANONICAL_BYTES,
    val maximumCommandBytes: Int = COMPDB_MAXIMUM_COMMAND_BYTES,
    val maximumCommandWordsPerAction: Int = COMPDB_MAXIMUM_COMMAND_WORDS_PER_ACTION,
    val maximumCompdbBytes: Int = COMPDB_MAXIMUM_BYTES,
    val maximumCompdbRecords: Int = COMPDB_MAXIMUM_RECORDS,
    val maximumOutputRecords: Long = COMPDB_MAXIMUM_OUTPUT_RECORDS,
    val maximumPathBytes: Int = COMPDB_MAXIMUM_PATH_BYTES,
    val maximumPathComponentBytes: Int = COMPDB_MAXIMUM_PATH_COMPONENT_BYTES,
    val maximumRawStringBytes: Int = COMPDB_MAXIMUM_RAW_STRING_BYTES,
    val maximumTotalCommandBytes: Long = COMPDB_MAXIMUM_TOTAL_COMMAND_BYTES,
    val maximumTotalCommandWords: Long = COMPDB_MAXIMUM_TOTAL_COMMAND_WORDS,
    val maximumWorkUnits: Long = COMPDB_MAXIMUM_WORK_UNITS,
) {
    init {
        require(maximumActions in 1..COMPDB_MAXIMUM_ACTIONS)
        require(maximumCanonicalBytes in 1..COMPDB_MAXIMUM_CANONICAL_BYTES)
        require(maximumCommandBytes in 1..COMPDB_MAXIMUM_COMMAND_BYTES)
        require(maximumCommandWordsPerAction in 10..COMPDB_MAXIMUM_COMMAND_WORDS_PER_ACTION)
        require(maximumCompdbBytes in 2..COMPDB_MAXIMUM_BYTES)
        require(maximumCompdbRecords in 1..COMPDB_MAXIMUM_RECORDS)
        require(maximumOutputRecords in 1L..COMPDB_MAXIMUM_OUTPUT_RECORDS)
        require(maximumPathBytes in 1..COMPDB_MAXIMUM_PATH_BYTES)
        require(maximumPathComponentBytes in 1..COMPDB_MAXIMUM_PATH_COMPONENT_BYTES)
        require(maximumRawStringBytes in 1..COMPDB_MAXIMUM_RAW_STRING_BYTES)
        require(maximumTotalCommandBytes in 1L..COMPDB_MAXIMUM_TOTAL_COMMAND_BYTES)
        require(maximumTotalCommandWords in 10L..COMPDB_MAXIMUM_TOTAL_COMMAND_WORDS)
        require(maximumWorkUnits in 1L..COMPDB_MAXIMUM_WORK_UNITS)
    }
}

/** One recomputed byte-exact relation between an external compdb record and a capture action. */
sealed interface FullTreeClangCompdbMatch {
    val captureActionSha256: String
    val compdbRecordIndex: Int
    val directory: String
    val file: String
    val output: String
    val resolvedOutput: String
    val commandBytes: Int
    val commandSha256: String
    val commandWords: Int
    val compdbRecordSha256: String
    val decodedArgumentsSha256: String
    val derivedCaptureArgumentsSha256: String
    val matchSha256: String
}

/**
 * Integrity-validated reconciliation of caller-supplied compdb bytes.
 *
 * The registry intentionally omits "authenticated", "Ninja", and "replay" from its name. A
 * separately reviewed isolated Kotlin producer must authenticate graph origin and execution.
 */
sealed interface FullTreeClangCompdbReconciliationRegistry {
    val artifactSha256: String
    val artifactBytes: Long
    val reportSha256: String
    val configurationSha256: String
    val captureInputArtifactSha256: String
    val captureContextSha256: String
    val compdbSha256: String
    val matchManifestSha256: String
    val matches: List<FullTreeClangCompdbMatch>
    val blockerCodes: List<String>
    val canonicalBytes: ByteArray

    fun requireMatchForCaptureAction(captureActionSha256: String): FullTreeClangCompdbMatch
}

/** Kotlin/JVM-only projection and validation. No operation executes Ninja, a compiler, or a shell. */
object FullTreeClangCompdbReconciliationControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(COMPDB_SCHEMA, COMPDB_CONFIGURATION_POLICY)
    }

    fun generateAndPublish(
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
        limits: FullTreeClangCompdbReconciliationLimits = FullTreeClangCompdbReconciliationLimits(),
    ): FullTreeClangCompdbReconciliationRegistry {
        val paths = CompdbPaths(
            artifact = outputPath,
            compdb = compdbPath,
            captureInput = captureInputPath,
            readiness = headerPlanReadinessPath,
            generatedInventory = generatedFileInventoryPath,
            sourceArchive = sourceArchivePath,
            generatedArchive = generatedTreeArchivePath,
            generatedProvenance = generatedProvenancePath,
            scope = scopePath,
            sourceLock = sourceLockPath,
            artifactManifest = artifactManifestPath,
            buildRecord = buildRecordPath,
            inventory = inventoryPath,
            sourceInventory = sourceInventoryPath,
            planningInventory = planningInventoryPath,
        )
        requireDistinctControlOutput(
            paths.artifact,
            *paths.inputs().mapIndexed { index, input -> "compdb reconciliation input $index" to input }
                .toTypedArray(),
        )
        requireDistinctCompdbInputs(paths.inputs())
        val expected = deriveCompdbDocument(paths, limits)
        publishCanonicalControl(paths.artifact, expected, limits.maximumCanonicalBytes)
        return load(paths, limits)
    }

    fun loadAndValidate(
        path: Path,
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
        limits: FullTreeClangCompdbReconciliationLimits = FullTreeClangCompdbReconciliationLimits(),
    ): FullTreeClangCompdbReconciliationRegistry = load(
        CompdbPaths(
            artifact = path,
            compdb = compdbPath,
            captureInput = captureInputPath,
            readiness = headerPlanReadinessPath,
            generatedInventory = generatedFileInventoryPath,
            sourceArchive = sourceArchivePath,
            generatedArchive = generatedTreeArchivePath,
            generatedProvenance = generatedProvenancePath,
            scope = scopePath,
            sourceLock = sourceLockPath,
            artifactManifest = artifactManifestPath,
            buildRecord = buildRecordPath,
            inventory = inventoryPath,
            sourceInventory = sourceInventoryPath,
            planningInventory = planningInventoryPath,
        ),
        limits,
    )

    private fun load(
        paths: CompdbPaths,
        limits: FullTreeClangCompdbReconciliationLimits,
    ): FullTreeClangCompdbReconciliationRegistry {
        requireDistinctCompdbInputs(paths.all())
        StableControlFile.open(
            paths.artifact,
            limits.maximumCanonicalBytes.toLong(),
            "full-tree Clang compdb reconciliation",
        ).use { artifact ->
            artifact.requireSingleLink("full-tree Clang compdb reconciliation")
            val bytes = artifact.readExactly(
                0L,
                artifact.size.toInt(),
                "full-tree Clang compdb reconciliation",
            )
            val document = parseCompdbArtifact(bytes, limits)
            validateCompdbReportHash(document, limits)
            val expected = deriveCompdbDocument(paths, limits)
            if (document != expected) {
                compdbFail("Clang compdb reconciliation differs from its raw inputs")
            }
            artifact.verifyUnchanged("full-tree Clang compdb reconciliation")
            return ValidatedCompdbRegistry(validatedCompdbState(document, bytes))
        }
    }

    private fun deriveCompdbDocument(
        paths: CompdbPaths,
        limits: FullTreeClangCompdbReconciliationLimits,
    ): JsonObject {
        StableControlFile.open(
            paths.compdb,
            limits.maximumCompdbBytes.toLong(),
            "external Clang compilation database",
        ).use { compdb ->
            compdb.requireSingleLink("external Clang compilation database")
            if (compdb.size > Int.MAX_VALUE) compdbFail("external compdb exceeds JVM byte addressing")
            val rawBytes = compdb.readExactly(0L, compdb.size.toInt(), "external Clang compilation database")
            val parsed = parseExternalCompdb(rawBytes, limits)
            val capture = loadCapture(paths, limits.captureInput)
            val captureDocument = readCaptureDocument(paths.captureInput, capture, limits)
            val reconciliation = reconcileCompdb(parsed, capture, limits)
            val expected = expectedCompdbDocument(
                capture,
                captureDocument,
                parsed,
                reconciliation,
                limits,
            )
            compdb.verifyUnchanged("external Clang compilation database")
            val terminal = loadCapture(paths, limits.captureInput)
            if (captureSnapshot(capture) != captureSnapshot(terminal)) {
                compdbFail("capture input or its raw predecessors changed during compdb reconciliation")
            }
            compdb.verifyUnchanged("external Clang compilation database")
            return expected
        }
    }

    private fun loadCapture(
        paths: CompdbPaths,
        limits: FullTreeClangCaptureInputLimits,
    ): FullTreeClangCaptureInputRegistry = FullTreeClangCaptureInputControl.loadAndValidate(
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
        limits,
    )

    private fun readCaptureDocument(
        path: Path,
        capture: FullTreeClangCaptureInputRegistry,
        limits: FullTreeClangCompdbReconciliationLimits,
    ): JsonObject {
        val (document, bytes) = readCanonicalControlObject(
            path,
            limits.captureInput.maximumCanonicalBytes,
            "full-tree Clang capture input",
            "full-tree-clang-capture-input",
        )
        if (OracleArtifacts.sha256(bytes) != capture.artifactSha256 ||
            bytes.size.toLong() != capture.artifactBytes ||
            document.controlString("reportSha256") != capture.reportSha256 ||
            document.controlObject("oracle").controlString("configurationSha256") !=
            capture.configurationSha256 ||
            document.controlObject("commitments").controlString("captureContextSha256") !=
            capture.captureContextSha256 ||
            document.controlObject("commitments").controlString("actionsSha256") !=
            capture.captureActionsSha256
        ) {
            compdbFail("capture-input document differs from its validated registry")
        }
        return document
    }

    private fun reconcileCompdb(
        parsed: ParsedCompdb,
        capture: FullTreeClangCaptureInputRegistry,
        limits: FullTreeClangCompdbReconciliationLimits,
    ): CompdbReconciliation {
        if (capture.actions.size !in 1..limits.maximumActions ||
            capture.actions.size > limits.captureInput.maximumActions
        ) {
            compdbFail("capture action population exceeds the compdb reconciliation bound")
        }
        if (parsed.records.size < capture.actions.size) {
            compdbFail("external compdb cannot cover the capture action population")
        }
        val actionsByInput = LinkedHashMap<String, FullTreeClangCaptureAction>()
        val expectedOutputs = HashSet<String>()
        capture.actions.forEach { action ->
            if (actionsByInput.put(action.mainInput, action) != null ||
                !expectedOutputs.add(action.objectOutput)
            ) {
                compdbFail("capture actions do not expose unique input and object identities")
            }
        }
        val matchesByAction = HashMap<String, ValidatedCompdbMatch>()
        val ignoredRecordSha256 = ArrayList<String>()
        var selectedCommandBytes = 0L
        var selectedCommandWords = 0L

        parsed.records.forEachIndexed { index, record ->
            val action = actionsByInput[record.file]
            val resolvedOutput = resolveCompdbOutput(record.directory, record.output, limits)
            if (action == null) {
                if (resolvedOutput in expectedOutputs) {
                    compdbFail("ignored compdb record collides with a capture object output")
                }
                ignoredRecordSha256 += record.recordSha256
                return@forEachIndexed
            }
            if (matchesByAction.containsKey(action.actionSha256)) {
                compdbFail("external compdb contains multiple records for a capture main input")
            }
            if (record.directory != action.workingDirectory ||
                record.output != action.arguments[8] ||
                resolvedOutput != action.objectOutput
            ) {
                compdbFail("external compdb action paths do not match the capture action byte-for-byte")
            }
            val words = record.decodedCommandWords
            selectedCommandBytes = compdbAddExact(
                selectedCommandBytes,
                record.commandBytes.toLong(),
                "selected compdb command byte",
            )
            if (selectedCommandBytes > limits.maximumTotalCommandBytes) {
                compdbFail("selected compdb commands exceed their aggregate byte bound")
            }
            selectedCommandWords = compdbAddExact(
                selectedCommandWords,
                words.size.toLong(),
                "selected compdb command word",
            )
            if (selectedCommandWords > limits.maximumTotalCommandWords) {
                compdbFail("selected compdb commands exceed their aggregate word bound")
            }
            val rawOutput = action.arguments[8]
            val rawDependency = action.arguments[6]
            val expectedSuffix = listOf(
                "-MD",
                "-MT",
                rawOutput,
                "-MF",
                rawDependency,
                "-o",
                rawOutput,
                "-c",
                action.mainInput,
            )
            if (rawDependency != "$rawOutput.d" ||
                words.first() != action.arguments.first() ||
                words.drop(words.size - COMPDB_RAW_FRAME_SIZE) != expectedSuffix ||
                "--no-default-config" in words
            ) {
                compdbFail("external compdb command does not use the exact raw compiler-frame suffix")
            }
            val rawOptionPrefix = words.subList(1, words.size - COMPDB_RAW_FRAME_SIZE)
            val derivedCaptureArguments = buildList {
                add(words.first())
                add("--no-default-config")
                addAll(expectedSuffix)
                addAll(rawOptionPrefix)
            }
            if (derivedCaptureArguments != action.arguments) {
                compdbFail("external compdb command does not derive the committed capture arguments exactly")
            }
            val decodedArgumentsSha256 = compdbStringListCommitment(
                COMPDB_DECODED_ARGUMENTS_DOMAIN,
                words,
            )
            val derivedCaptureArgumentsSha256 = compdbStringListCommitment(
                COMPDB_DERIVED_ARGUMENTS_DOMAIN,
                derivedCaptureArguments,
            )
            val matchSha256 = CompdbCommitment(COMPDB_MATCH_DOMAIN).apply {
                token(configurationSha256.asciiBytes())
                token(capture.artifactSha256.asciiBytes())
                token(capture.captureContextSha256.asciiBytes())
                token(action.actionSha256.asciiBytes())
                long(index.toLong())
                token(record.recordSha256.asciiBytes())
                token(decodedArgumentsSha256.asciiBytes())
                token(derivedCaptureArgumentsSha256.asciiBytes())
                token(record.directory.utf8Bytes())
                token(record.file.utf8Bytes())
                token(record.output.utf8Bytes())
                token(resolvedOutput.utf8Bytes())
            }.finish()
            matchesByAction[action.actionSha256] = ValidatedCompdbMatch(
                captureActionSha256 = action.actionSha256,
                compdbRecordIndex = index,
                directory = record.directory,
                file = record.file,
                output = record.output,
                resolvedOutput = resolvedOutput,
                commandBytes = record.commandBytes,
                commandSha256 = record.commandSha256,
                commandWords = words.size,
                compdbRecordSha256 = record.recordSha256,
                decodedArgumentsSha256 = decodedArgumentsSha256,
                derivedCaptureArgumentsSha256 = derivedCaptureArgumentsSha256,
                matchSha256 = matchSha256,
            )
        }
        val ordered = capture.actions.map { action ->
            matchesByAction[action.actionSha256]
                ?: compdbFail("external compdb omits a capture action main input")
        }
        if (ordered.size != capture.actions.size || matchesByAction.size != capture.actions.size) {
            compdbFail("external compdb match relation is not a capture-action bijection")
        }
        val matchedRecordManifestSha256 = CompdbCommitment(COMPDB_MATCHED_RECORD_MANIFEST_DOMAIN).apply {
            long(ordered.size.toLong())
            ordered.forEach { match -> token(match.compdbRecordSha256.asciiBytes()) }
        }.finish()
        val ignoredRecordManifestSha256 = CompdbCommitment(COMPDB_IGNORED_RECORD_MANIFEST_DOMAIN).apply {
            long(ignoredRecordSha256.size.toLong())
            ignoredRecordSha256.forEach { digest -> token(digest.asciiBytes()) }
        }.finish()
        val matchManifestSha256 = CompdbCommitment(COMPDB_MATCH_MANIFEST_DOMAIN).apply {
            long(ordered.size.toLong())
            ordered.forEach { match -> token(match.matchSha256.asciiBytes()) }
        }.finish()
        return CompdbReconciliation(
            matches = Collections.unmodifiableList(ordered),
            matchedRecordManifestSha256 = matchedRecordManifestSha256,
            ignoredRecordManifestSha256 = ignoredRecordManifestSha256,
            matchManifestSha256 = matchManifestSha256,
            selectedCommandBytes = selectedCommandBytes,
            selectedCommandWords = selectedCommandWords,
        )
    }

    private fun expectedCompdbDocument(
        capture: FullTreeClangCaptureInputRegistry,
        captureDocument: JsonObject,
        parsed: ParsedCompdb,
        reconciliation: CompdbReconciliation,
        limits: FullTreeClangCompdbReconciliationLimits,
    ): JsonObject {
        val outputRecords = compdbAddExact(
            reconciliation.matches.size.toLong(),
            COMPDB_BLOCKERS.size.toLong(),
            "compdb reconciliation output record",
        )
        if (outputRecords > limits.maximumOutputRecords) {
            compdbFail("compdb reconciliation exceeds its output-record bound")
        }
        val workUnits = listOf(
            64L,
            compdbMultiplyExact(4L, parsed.records.size.toLong(), "compdb record work-unit"),
            compdbMultiplyExact(6L, reconciliation.matches.size.toLong(), "compdb match work-unit"),
            compdbMultiplyExact(4L, parsed.commandWords, "compdb word work-unit"),
            compdbMultiplyExact(2L, COMPDB_BLOCKERS.size.toLong(), "compdb blocker work-unit"),
        ).fold(0L) { total, value -> compdbAddExact(total, value, "compdb work-unit") }
        if (workUnits > limits.maximumWorkUnits) {
            compdbFail("compdb reconciliation exceeds its work-unit bound")
        }
        val captureOracle = captureDocument.controlObject("oracle")
        val captureBuild = captureDocument.controlObject("build")
        val captureEnvironment = captureDocument.controlObject("environment")
        val ninjaTool = captureBuild.controlObject("ninjaTool")
        val withoutHash = JsonObject(
            mapOf(
                "acpBoundary" to COMPDB_ACP_BOUNDARY,
                "authority" to COMPDB_AUTHORITY,
                "blockerDispositions" to JsonArray(COMPDB_BLOCKER_DISPOSITIONS),
                "blockers" to JsonArray(COMPDB_BLOCKERS),
                "bounds" to COMPDB_BOUNDS,
                "build" to JsonObject(
                    mapOf(
                        "baseEnvironmentSha256" to captureEnvironment.getValue("baseEnvironmentSha256"),
                        "buildDirectory" to captureBuild.getValue("buildDirectory"),
                        "inheritedEnvironment" to JsonPrimitive("cleared"),
                        "manifestClosureBound" to JsonPrimitive(false),
                        "compdbExecutionReceiptBound" to JsonPrimitive(false),
                        "ninjaManifestBytes" to captureBuild.getValue("ninjaManifestBytes"),
                        "ninjaManifestSha256" to captureBuild.getValue("ninjaManifestSha256"),
                        "ninjaTool" to ninjaTool,
                        "ninjaToolIdentitySha256" to JsonPrimitive(
                            fullTreeGeneratedToolIdentitySha256(ninjaTool),
                        ),
                    ),
                ),
                "commitments" to JsonObject(
                    mapOf(
                        "captureContextSha256" to JsonPrimitive(capture.captureContextSha256),
                        "ignoredCompdbRecordManifestSha256" to JsonPrimitive(
                            reconciliation.ignoredRecordManifestSha256,
                        ),
                        "matchManifestSha256" to JsonPrimitive(reconciliation.matchManifestSha256),
                        "selectedCompdbRecordManifestSha256" to JsonPrimitive(
                            reconciliation.matchedRecordManifestSha256,
                        ),
                    ),
                ),
                "counts" to JsonObject(
                    mapOf(
                        "blockers" to JsonPrimitive(COMPDB_BLOCKERS.size),
                        "captureActions" to JsonPrimitive(capture.actions.size),
                        "compdbBytes" to JsonPrimitive(parsed.rawBytes.size),
                        "compdbCommandBytes" to JsonPrimitive(parsed.commandBytes),
                        "compdbCommandWords" to JsonPrimitive(parsed.commandWords),
                        "compdbRecords" to JsonPrimitive(parsed.records.size),
                        "ignoredCompdbRecords" to JsonPrimitive(
                            parsed.records.size - reconciliation.matches.size,
                        ),
                        "matches" to JsonPrimitive(reconciliation.matches.size),
                        "outputRecords" to JsonPrimitive(outputRecords),
                        "rawStringBytes" to JsonPrimitive(parsed.rawStringBytes),
                        "selectedCommandBytes" to JsonPrimitive(reconciliation.selectedCommandBytes),
                        "selectedCommandWords" to JsonPrimitive(reconciliation.selectedCommandWords),
                        "workUnits" to JsonPrimitive(workUnits),
                    ),
                ),
                "evidence" to JsonObject(
                    mapOf(
                        "canonicalCompdbSha256" to JsonPrimitive(parsed.canonicalSha256),
                        "compdbBytes" to JsonPrimitive(parsed.rawBytes.size),
                        "compdbExecutionReceiptBound" to JsonPrimitive(false),
                        "compdbSha256" to JsonPrimitive(parsed.rawSha256),
                        "duplicateKeysRejected" to JsonPrimitive(true),
                        "exitStatusBound" to JsonPrimitive(false),
                        "manifestClosureBound" to JsonPrimitive(false),
                        "stderrBound" to JsonPrimitive(false),
                        "strictUtf8" to JsonPrimitive(true),
                        "transport" to JsonPrimitive("external-raw-filtered-compdb-sidecar"),
                    ),
                ),
                "kind" to JsonPrimitive("full-tree-clang-compdb-reconciliation-v1"),
                "matches" to JsonArray(reconciliation.matches.map(ValidatedCompdbMatch::document)),
                "oracle" to JsonObject(
                    mapOf(
                        "buildRecordSha256" to captureOracle.getValue("buildRecordSha256"),
                        "captureActionsSha256" to JsonPrimitive(capture.captureActionsSha256),
                        "captureContextSha256" to JsonPrimitive(capture.captureContextSha256),
                        "captureInputArtifactBytes" to JsonPrimitive(capture.artifactBytes),
                        "captureInputArtifactSha256" to JsonPrimitive(capture.artifactSha256),
                        "captureInputConfigurationSha256" to JsonPrimitive(capture.configurationSha256),
                        "captureInputReportSha256" to JsonPrimitive(capture.reportSha256),
                        "configurationSha256" to JsonPrimitive(configurationSha256),
                        "generatedFileInventoryArtifactSha256" to
                            captureOracle.getValue("generatedFileInventoryArtifactSha256"),
                        "headerPlanReadinessArtifactSha256" to
                            captureOracle.getValue("headerPlanReadinessArtifactSha256"),
                        "id" to captureOracle.getValue("id"),
                        "planningInventoryArtifactSha256" to
                            captureOracle.getValue("planningInventoryArtifactSha256"),
                    ),
                ),
                "reconciliationPolicy" to COMPDB_RECONCILIATION_POLICY,
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        val reportSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(withoutHash, controlJsonLimits(COMPDB_MAXIMUM_CANONICAL_BYTES)),
        )
        val expected = JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
        val (_, bytes) = snapshotControlObject(
            expected,
            limits.maximumCanonicalBytes,
            "full-tree Clang compdb reconciliation",
            COMPDB_SCHEMA,
        )
        if (bytes.size > limits.maximumCanonicalBytes) {
            compdbFail("compdb reconciliation exceeds its canonical byte bound")
        }
        return expected
    }
}

private data class CompdbPaths(
    val artifact: Path,
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

private data class ParsedCompdb(
    val rawBytes: ByteArray,
    val rawSha256: String,
    val canonicalSha256: String,
    val rawStringBytes: Long,
    val commandBytes: Long,
    val commandWords: Long,
    val records: List<ParsedCompdbRecord>,
)

private data class ParsedCompdbRecord(
    val directory: String,
    val command: String,
    val file: String,
    val output: String,
    val commandBytes: Int,
    val commandSha256: String,
    val decodedCommandWords: List<String>,
    val recordSha256: String,
)

private data class CompdbReconciliation(
    val matches: List<ValidatedCompdbMatch>,
    val matchedRecordManifestSha256: String,
    val ignoredRecordManifestSha256: String,
    val matchManifestSha256: String,
    val selectedCommandBytes: Long,
    val selectedCommandWords: Long,
)

private data class ValidatedCompdbMatch(
    override val captureActionSha256: String,
    override val compdbRecordIndex: Int,
    override val directory: String,
    override val file: String,
    override val output: String,
    override val resolvedOutput: String,
    override val commandBytes: Int,
    override val commandSha256: String,
    override val commandWords: Int,
    override val compdbRecordSha256: String,
    override val decodedArgumentsSha256: String,
    override val derivedCaptureArgumentsSha256: String,
    override val matchSha256: String,
) : FullTreeClangCompdbMatch {
    fun document(): JsonObject = JsonObject(
        mapOf(
            "captureActionSha256" to JsonPrimitive(captureActionSha256),
            "commandBytes" to JsonPrimitive(commandBytes),
            "commandSha256" to JsonPrimitive(commandSha256),
            "commandWords" to JsonPrimitive(commandWords),
            "compdbRecordIndex" to JsonPrimitive(compdbRecordIndex),
            "compdbRecordSha256" to JsonPrimitive(compdbRecordSha256),
            "decodedArgumentsSha256" to JsonPrimitive(decodedArgumentsSha256),
            "derivedCaptureArgumentsSha256" to JsonPrimitive(derivedCaptureArgumentsSha256),
            "directory" to JsonPrimitive(directory),
            "file" to JsonPrimitive(file),
            "matchSha256" to JsonPrimitive(matchSha256),
            "output" to JsonPrimitive(output),
            "resolvedOutput" to JsonPrimitive(resolvedOutput),
        ),
    )
}

private data class CaptureActionSnapshot(
    val actionSha256: String,
    val moduleId: String,
    val unitId: String,
    val shardId: String,
    val sourceKind: String,
    val sourcePath: String,
    val workingDirectory: String,
    val mainInput: String,
    val arguments: List<String>,
    val objectOutput: String,
    val dependencyFile: String,
)

private data class CaptureRegistrySnapshot(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val captureContextSha256: String,
    val captureActionsSha256: String,
    val actions: List<CaptureActionSnapshot>,
    val blockers: List<String>,
)

private fun captureSnapshot(capture: FullTreeClangCaptureInputRegistry): CaptureRegistrySnapshot =
    CaptureRegistrySnapshot(
        artifactSha256 = capture.artifactSha256,
        artifactBytes = capture.artifactBytes,
        reportSha256 = capture.reportSha256,
        configurationSha256 = capture.configurationSha256,
        captureContextSha256 = capture.captureContextSha256,
        captureActionsSha256 = capture.captureActionsSha256,
        actions = capture.actions.map { action ->
            CaptureActionSnapshot(
                action.actionSha256,
                action.moduleId,
                action.unitId,
                action.shardId,
                action.sourceKind,
                action.sourcePath,
                action.workingDirectory,
                action.mainInput,
                action.arguments.toList(),
                action.objectOutput,
                action.dependencyFile,
            )
        },
        blockers = capture.blockerCodes.toList(),
    )

private data class ValidatedCompdbState(
    val artifactSha256: String,
    val artifactBytes: Long,
    val reportSha256: String,
    val configurationSha256: String,
    val captureInputArtifactSha256: String,
    val captureContextSha256: String,
    val compdbSha256: String,
    val matchManifestSha256: String,
    val matches: List<ValidatedCompdbMatch>,
    val blockerCodes: List<String>,
    val canonicalBytes: ByteArray,
)

private class ValidatedCompdbRegistry(
    state: ValidatedCompdbState,
) : FullTreeClangCompdbReconciliationRegistry {
    override val artifactSha256: String = state.artifactSha256
    override val artifactBytes: Long = state.artifactBytes
    override val reportSha256: String = state.reportSha256
    override val configurationSha256: String = state.configurationSha256
    override val captureInputArtifactSha256: String = state.captureInputArtifactSha256
    override val captureContextSha256: String = state.captureContextSha256
    override val compdbSha256: String = state.compdbSha256
    override val matchManifestSha256: String = state.matchManifestSha256
    override val matches: List<FullTreeClangCompdbMatch> = Collections.unmodifiableList(
        ArrayList(state.matches),
    )
    override val blockerCodes: List<String> = Collections.unmodifiableList(ArrayList(state.blockerCodes))
    private val storedCanonicalBytes = state.canonicalBytes.copyOf()
    override val canonicalBytes: ByteArray
        get() = storedCanonicalBytes.copyOf()
    private val byAction = Collections.unmodifiableMap(
        LinkedHashMap<String, FullTreeClangCompdbMatch>().apply {
            matches.forEach { match ->
                if (put(match.captureActionSha256, match) != null) {
                    compdbFail("compdb registry contains a duplicate capture-action match")
                }
            }
        },
    )

    override fun requireMatchForCaptureAction(captureActionSha256: String): FullTreeClangCompdbMatch {
        if (!captureActionSha256.matches(COMPDB_SHA256)) {
            compdbFail("capture action SHA-256 is invalid")
        }
        return byAction[captureActionSha256]
            ?: compdbFail("capture action is outside the reconciled compdb population")
    }
}

private fun validatedCompdbState(document: JsonObject, bytes: ByteArray): ValidatedCompdbState {
    val oracle = document.controlObject("oracle")
    val evidence = document.controlObject("evidence")
    val commitments = document.controlObject("commitments")
    val matches = document.controlArray("matches").controlObjects("compdb matches").map { match ->
        ValidatedCompdbMatch(
            captureActionSha256 = match.controlString("captureActionSha256"),
            compdbRecordIndex = match.controlLong("compdbRecordIndex").toInt(),
            directory = match.controlString("directory"),
            file = match.controlString("file"),
            output = match.controlString("output"),
            resolvedOutput = match.controlString("resolvedOutput"),
            commandBytes = match.controlLong("commandBytes").toInt(),
            commandSha256 = match.controlString("commandSha256"),
            commandWords = match.controlLong("commandWords").toInt(),
            compdbRecordSha256 = match.controlString("compdbRecordSha256"),
            decodedArgumentsSha256 = match.controlString("decodedArgumentsSha256"),
            derivedCaptureArgumentsSha256 = match.controlString("derivedCaptureArgumentsSha256"),
            matchSha256 = match.controlString("matchSha256"),
        )
    }
    return ValidatedCompdbState(
        artifactSha256 = OracleArtifacts.sha256(bytes),
        artifactBytes = bytes.size.toLong(),
        reportSha256 = document.controlString("reportSha256"),
        configurationSha256 = oracle.controlString("configurationSha256"),
        captureInputArtifactSha256 = oracle.controlString("captureInputArtifactSha256"),
        captureContextSha256 = oracle.controlString("captureContextSha256"),
        compdbSha256 = evidence.controlString("compdbSha256"),
        matchManifestSha256 = commitments.controlString("matchManifestSha256"),
        matches = Collections.unmodifiableList(matches),
        blockerCodes = COMPDB_BLOCKERS.map { it.controlString("code") },
        canonicalBytes = bytes.copyOf(),
    )
}

private fun parseExternalCompdb(
    bytes: ByteArray,
    limits: FullTreeClangCompdbReconciliationLimits,
): ParsedCompdb {
    if (bytes.size !in 2..limits.maximumCompdbBytes) {
        compdbFail("external compdb exceeds its byte bound")
    }
    val jsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumCompdbBytes,
        maximumCanonicalBytes = limits.maximumCompdbBytes,
        maximumDepth = 4,
        maximumNodes = compdbNodeLimit(limits.maximumCompdbRecords),
        maximumStringBytes = maxOf(limits.maximumCommandBytes, limits.maximumPathBytes),
        maximumTotalStringBytes = limits.maximumRawStringBytes,
        maximumNumberCharacters = 32,
    )
    val root = try {
        OracleJson.parse(bytes, jsonLimits) as? JsonArray
            ?: compdbFail("external compdb root must be an array")
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("external compdb is not strict bounded UTF-8 JSON", failure)
    }
    if (root.size !in 1..limits.maximumCompdbRecords) {
        compdbFail("external compdb record population exceeds its bound")
    }
    var rawStringBytes = 0L
    var commandBytesTotal = 0L
    var commandWordsTotal = 0L
    val records = root.mapIndexed { index, element ->
        val record = element as? JsonObject ?: compdbFail("external compdb record $index is not an object")
        if (record.keys != COMPDB_RECORD_KEYS) {
            compdbFail("external compdb record $index does not have the exact four-field profile")
        }
        val directory = record.strictCompdbString("directory", index)
        val command = record.strictCompdbString("command", index)
        val file = record.strictCompdbString("file", index)
        val output = record.strictCompdbString("output", index)
        listOf(directory, command, file, output).forEach { value ->
            rawStringBytes = compdbAddExact(
                rawStringBytes,
                value.utf8Bytes().size.toLong(),
                "external compdb string byte",
            )
            if (rawStringBytes > limits.maximumRawStringBytes) {
                compdbFail("external compdb strings exceed their aggregate byte bound")
            }
        }
        requireCompdbAbsolutePath(directory, "compdb directory", limits)
        requireCompdbAbsolutePath(file, "compdb file", limits)
        requireCompdbOutputPath(output, "compdb output", limits)
        val commandBytes = command.utf8Bytes()
        if (commandBytes.isEmpty() || commandBytes.size > limits.maximumCommandBytes ||
            command.any { it == '\u0000' || it == '\r' || it == '\n' || it == '\t' }
        ) {
            compdbFail("external compdb command $index violates its byte profile")
        }
        val words = decodeSafeCompdbCommand(command, limits)
        requireCompdbAbsolutePath(words.first(), "external compdb command driver", limits)
        val expectedFrame = listOf(
            "-MD",
            "-MT",
            output,
            "-MF",
            "$output.d",
            "-o",
            output,
            "-c",
            file,
        )
        val rawOptionPrefix = words.subList(1, words.size - COMPDB_RAW_FRAME_SIZE)
        if (rawOptionPrefix.any(::isForbiddenRawCompdbOption) ||
            words.takeLast(COMPDB_RAW_FRAME_SIZE) != expectedFrame ||
            "--no-default-config" in words
        ) {
            compdbFail("external compdb record $index command does not agree with its file and output fields")
        }
        commandBytesTotal = compdbAddExact(
            commandBytesTotal,
            commandBytes.size.toLong(),
            "external compdb command byte",
        )
        if (commandBytesTotal > limits.maximumTotalCommandBytes) {
            compdbFail("external compdb commands exceed their aggregate byte bound")
        }
        commandWordsTotal = compdbAddExact(
            commandWordsTotal,
            words.size.toLong(),
            "external compdb command word",
        )
        if (commandWordsTotal > limits.maximumTotalCommandWords) {
            compdbFail("external compdb commands exceed their aggregate word bound")
        }
        ParsedCompdbRecord(
            directory = directory,
            command = command,
            file = file,
            output = output,
            commandBytes = commandBytes.size,
            commandSha256 = OracleArtifacts.sha256(commandBytes),
            decodedCommandWords = Collections.unmodifiableList(words),
            recordSha256 = compdbCanonicalCommitment(COMPDB_RECORD_DOMAIN, record),
        )
    }
    val canonical = try {
        OracleJson.canonicalBytes(root, jsonLimits)
    } catch (failure: Exception) {
        throw FullTreeControlException("external compdb cannot be canonically committed", failure)
    }
    return ParsedCompdb(
        rawBytes = bytes.copyOf(),
        rawSha256 = OracleArtifacts.sha256(bytes),
        canonicalSha256 = OracleArtifacts.sha256(canonical),
        rawStringBytes = rawStringBytes,
        commandBytes = commandBytesTotal,
        commandWords = commandWordsTotal,
        records = Collections.unmodifiableList(records),
    )
}

private fun JsonObject.strictCompdbString(field: String, index: Int): String {
    val primitive = this[field] as? JsonPrimitive
        ?: compdbFail("external compdb record $index field $field is not a string")
    if (!primitive.isString) compdbFail("external compdb record $index field $field is not a string")
    return primitive.content
}

private fun decodeSafeCompdbCommand(
    command: String,
    limits: FullTreeClangCompdbReconciliationLimits,
): List<String> {
    if (command.startsWith(' ') || command.endsWith(' ') || "  " in command) {
        compdbFail("selected compdb command does not use single U+0020 separators")
    }
    val words = command.split(' ')
    if (words.size !in 10..limits.maximumCommandWordsPerAction ||
        words.size >= limits.captureInput.maximumArgumentsPerAction
    ) {
        compdbFail("selected compdb command word population exceeds its bound")
    }
    if (words.any { !it.matches(COMPDB_SAFE_WORD) }) {
        compdbFail("selected compdb command is outside the safe unquoted-word grammar")
    }
    return words
}

private fun isForbiddenRawCompdbOption(argument: String): Boolean {
    if (!argument.startsWith('-') ||
        argument.startsWith('@') ||
        argument.startsWith("--config") ||
        argument.startsWith("-x") ||
        COMPDB_RAW_OPAQUE_FORWARDING_PREFIXES.any(argument::startsWith) ||
        COMPDB_RAW_CAPTURE_OPTION_PREFIXES.any(argument::startsWith) ||
        argument in COMPDB_RAW_FORBIDDEN_ARGUMENTS
    ) {
        return true
    }
    return COMPDB_RAW_JOINED_FIXED_OPTION_PREFIXES.any { prefix ->
        argument.length > prefix.length && argument.startsWith(prefix)
    }
}

private fun resolveCompdbOutput(
    directory: String,
    output: String,
    limits: FullTreeClangCompdbReconciliationLimits,
): String {
    requireCompdbAbsolutePath(directory, "compdb directory", limits)
    return if (output.startsWith('/')) {
        requireCompdbAbsolutePath(output, "compdb output", limits)
    } else {
        requireCompdbRelativePath(output, "compdb output", limits)
        val resolved = "$directory/$output"
        requireCompdbAbsolutePath(resolved, "resolved compdb output", limits)
    }
}

private fun requireCompdbOutputPath(
    value: String,
    label: String,
    limits: FullTreeClangCompdbReconciliationLimits,
): String = if (value.startsWith('/')) {
    requireCompdbAbsolutePath(value, label, limits)
} else {
    requireCompdbRelativePath(value, label, limits)
}

private fun requireCompdbAbsolutePath(
    value: String,
    label: String,
    limits: FullTreeClangCompdbReconciliationLimits,
): String {
    if (!value.startsWith('/') || value == "/" || value.utf8Bytes().size > limits.maximumPathBytes) {
        compdbFail("$label is not a canonical absolute path")
    }
    requireCompdbPathComponents(value.removePrefix("/"), label, limits)
    return value
}

private fun requireCompdbRelativePath(
    value: String,
    label: String,
    limits: FullTreeClangCompdbReconciliationLimits,
): String {
    if (value.isEmpty() || value.startsWith('/') || value.utf8Bytes().size > limits.maximumPathBytes) {
        compdbFail("$label is not a canonical relative path")
    }
    requireCompdbPathComponents(value, label, limits)
    return value
}

private fun requireCompdbPathComponents(
    value: String,
    label: String,
    limits: FullTreeClangCompdbReconciliationLimits,
) {
    if (value.endsWith('/') || value.contains("//") ||
        value.any { it == '\u0000' || it == '\r' || it == '\n' || it == '\\' }
    ) {
        compdbFail("$label is not a canonical path spelling")
    }
    value.split('/').forEach { component ->
        if (component.isEmpty() || component == "." || component == ".." ||
            component.utf8Bytes().size > limits.maximumPathComponentBytes
        ) {
            compdbFail("$label contains a noncanonical path component")
        }
    }
}

private fun parseCompdbArtifact(
    bytes: ByteArray,
    limits: FullTreeClangCompdbReconciliationLimits,
): JsonObject = try {
    val document = OracleJson.parseCanonical(bytes, controlJsonLimits(limits.maximumCanonicalBytes)) as? JsonObject
        ?: compdbFail("Clang compdb reconciliation root must be an object")
    OracleSchemas.validate(COMPDB_SCHEMA, document)
    document
} catch (failure: FullTreeControlException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeControlException("Clang compdb reconciliation is not strict canonical schema-valid JSON", failure)
}

private fun validateCompdbReportHash(
    document: JsonObject,
    limits: FullTreeClangCompdbReconciliationLimits,
) {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val expected = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumCanonicalBytes)),
    )
    if (document.controlString("reportSha256") != expected) {
        compdbFail("Clang compdb reconciliation report hash does not reconcile")
    }
}

private fun requireDistinctCompdbInputs(paths: List<Path>) {
    val normalized = paths.map { it.toAbsolutePath().normalize() }
    if (normalized.toSet().size != normalized.size) {
        compdbFail("compdb reconciliation input paths must be distinct")
    }
    val identities = HashSet<Any>()
    normalized.forEach { path ->
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeControlException("compdb reconciliation input is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            compdbFail("compdb reconciliation input is not an identified regular file")
        }
        if (!identities.add(attributes.fileKey())) {
            compdbFail("compdb reconciliation inputs contain a physical-file alias")
        }
    }
}

private fun compdbNodeLimit(maximumRecords: Int): Int = try {
    Math.addExact(1, Math.multiplyExact(5, maximumRecords))
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("compdb JSON node bound overflows", failure)
}

private fun compdbStringListCommitment(domain: String, values: List<String>): String =
    CompdbCommitment(domain).apply {
        long(values.size.toLong())
        values.forEach { value -> token(value.utf8Bytes()) }
    }.finish()

private fun compdbCanonicalCommitment(domain: String, value: JsonObject): String =
    CompdbCommitment(domain).apply {
        token(OracleJson.canonicalBytes(value, controlJsonLimits(COMPDB_MAXIMUM_CANONICAL_BYTES)))
    }.finish()

private class CompdbCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token(domain.utf8Bytes())
    }

    fun long(value: Long) {
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

private fun compdbAddExact(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label count overflows", failure)
}

private fun compdbMultiplyExact(left: Long, right: Long, label: String): Long = try {
    Math.multiplyExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label count overflows", failure)
}

private fun compdbFail(message: String): Nothing = throw FullTreeControlException(message)

private fun String.utf8Bytes(): ByteArray = toByteArray(StandardCharsets.UTF_8)

private fun String.asciiBytes(): ByteArray = toByteArray(StandardCharsets.US_ASCII)

private val COMPDB_AUTHORITY = JsonObject(
    mapOf(
        "buildGraphOriginAuthenticated" to JsonPrimitive(false),
        "captureActionExternalCompdbMatchExact" to JsonPrimitive(true),
        "captureInputAuthenticated" to JsonPrimitive(false),
        "captureOutputsPresent" to JsonPrimitive(false),
        "captureStarted" to JsonPrimitive(false),
        "cleanCompilationProven" to JsonPrimitive(false),
        "compilerActionsAuthenticated" to JsonPrimitive(false),
        "compilerCaptureAuthenticated" to JsonPrimitive(false),
        "compilerExecuted" to JsonPrimitive(false),
        "compilerOptionArityValidated" to JsonPrimitive(false),
        "compilerWriteSetContained" to JsonPrimitive(false),
        "compdbExecutionAuthenticated" to JsonPrimitive(false),
        "exitStatusesPresent" to JsonPrimitive(false),
        "externalEvidenceAuthenticated" to JsonPrimitive(false),
        "generatedSnapshotAuthenticated" to JsonPrimitive(false),
        "headerPlanReady" to JsonPrimitive(false),
        "headerPopulationComplete" to JsonPrimitive(false),
        "predecessorBindingsReconciled" to JsonPrimitive(true),
        "rawEvidenceIntegrityVerified" to JsonPrimitive(true),
        "releaseEligible" to JsonPrimitive(false),
        "status" to JsonPrimitive("external-unreceipted-compdb-reconciliation"),
        "strictArgumentTransformationVerified" to JsonPrimitive(true),
    ),
)

private val COMPDB_ACP_BOUNDARY = JsonObject(
    mapOf(
        "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
        "candidateContribution" to JsonPrimitive("authenticated-session-change-build-artifact-provenance"),
        "candidateEvidenceDisposition" to JsonPrimitive("non-authoritative-input-to-later-host-validation"),
        "candidateLineageAdmission" to JsonPrimitive("not-an-input-to-clang-compdb-reconciliation-v1"),
        "candidateLiveExecutionOwner" to JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
        "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
        "captureAuthority" to JsonPrimitive(false),
        "captureInputAuthoringAuthority" to JsonPrimitive(false),
        "certificationAuthority" to JsonPrimitive(false),
        "compilerActionAuthoringAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "executionAuthority" to JsonPrimitive(false),
        "compdbEvidenceAuthoringAuthority" to JsonPrimitive(false),
        "graphEvidenceAuthoringAuthority" to JsonPrimitive(false),
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

private val COMPDB_RECONCILIATION_POLICY = JsonObject(
    mapOf(
        "capturePathJoin" to JsonPrimitive(
            "directory-byte-equals-capture-working-directory-record-file-resolves-to-capture-main-" +
                "record-output-byte-equals-capture-raw-output-and-resolved-output-equals-capture-object-output",
        ),
        "captureTransformation" to JsonPrimitive(
            "driver-plus-no-default-config-plus-exact-raw-frame-plus-original-option-prefix",
        ),
        "commandDecoding" to JsonPrimitive(
            "ascii-safe-unquoted-words-separated-by-single-u0020-no-shell",
        ),
        "commandGrammar" to JsonPrimitive("safe-word=[A-Za-z0-9_+./=,:@%-]+"),
        "commandMutation" to JsonPrimitive(
            "only-fixed-no-default-config-insertion-and-frame-relocation",
        ),
        "evidenceOrigin" to JsonPrimitive("external-caller-supplied-unreceipted-compdb-bytes"),
        "executionDisposition" to JsonPrimitive("not-executed-by-this-boundary"),
        "driverSpelling" to JsonPrimitive("canonical-absolute-path"),
        "identity" to JsonPrimitive("kotlin-jvm-domain-separated-length-framed-sha256"),
        "ignoredActionInputDisposition" to JsonPrimitive(
            "forbidden-no-ignored-record-file-or-terminal-c-operand-may-equal-a-capture-main-input",
        ),
        "ignoredRecordDisposition" to JsonPrimitive("digest-bound-ignored-non-authoritative"),
        "inputFormat" to JsonPrimitive(
            "strict-utf8-four-string-field-clang-compilation-database-json",
        ),
        "matchCoverage" to JsonPrimitive("exact-one-per-reconciled-capture-action"),
        "matchIdentity" to JsonPrimitive(
            "configuration-capture-input-artifact-capture-context-capture-action-raw-compdb-record-" +
                "index-record-decoded-arguments-and-derived-arguments",
        ),
        "matchOrdering" to JsonPrimitive("reconciled-capture-action-order"),
        "optionArityDisposition" to JsonPrimitive("unvalidated-carried-from-capture-input"),
        "outputRecordModel" to JsonPrimitive("one-match-per-capture-action-plus-eight-blockers"),
        "pathMapping" to JsonPrimitive("exact-recorded-roots-no-rewrite-no-realpath"),
        "rawCommandFrame" to JsonPrimitive(
            "driver-option-prefix-followed-by-exact-terminal-md-mt-object-mf-depfile-o-object-c-main-frame",
        ),
        "rawOptionPrefix" to JsonPrimitive("every-non-driver-pre-frame-word-dash-prefixed"),
        "rawOptionProfile" to JsonPrimitive(
            "dash-prefixed-no-indirection-opaque-forwarding-language-override-header-overlay-or-" +
                "fixed-and-noncompiling-modes",
        ),
        "recordPopulationDisposition" to JsonPrimitive(
            "caller-supplied-compiler-rule-filtered-population-filter-origin-unreceipted",
        ),
        "recordCommandFieldAgreement" to JsonPrimitive(
            "every-record-command-terminal-frame-byte-equals-record-file-and-output-fields",
        ),
        "rawRecordJoin" to JsonPrimitive(
            "record-file-byte-equals-frame-main-and-record-output-byte-equals-frame-mt-and-o-with-" +
                "frame-mf-equal-output-plus-dot-d",
        ),
        "recordSelection" to JsonPrimitive(
            "exactly-one-complete-compdb-record-per-reconciled-capture-main-input",
        ),
        "workUnitModel" to JsonPrimitive(
            "64-plus-4-per-compdb-record-plus-6-per-match-plus-4-per-command-word-plus-2-per-blocker",
        ),
    ),
)

private val COMPDB_BOUNDS = JsonObject(
    mapOf(
        "maximumActions" to JsonPrimitive(COMPDB_MAXIMUM_ACTIONS),
        "maximumBlockers" to JsonPrimitive(8),
        "maximumCanonicalBytes" to JsonPrimitive(COMPDB_MAXIMUM_CANONICAL_BYTES),
        "maximumCommandBytes" to JsonPrimitive(COMPDB_MAXIMUM_COMMAND_BYTES),
        "maximumCommandWordsPerAction" to JsonPrimitive(COMPDB_MAXIMUM_COMMAND_WORDS_PER_ACTION),
        "maximumCompdbBytes" to JsonPrimitive(COMPDB_MAXIMUM_BYTES),
        "maximumCompdbRecords" to JsonPrimitive(COMPDB_MAXIMUM_RECORDS),
        "maximumOutputRecords" to JsonPrimitive(COMPDB_MAXIMUM_OUTPUT_RECORDS),
        "maximumPathBytes" to JsonPrimitive(COMPDB_MAXIMUM_PATH_BYTES),
        "maximumPathComponentBytes" to JsonPrimitive(COMPDB_MAXIMUM_PATH_COMPONENT_BYTES),
        "maximumRawStringBytes" to JsonPrimitive(COMPDB_MAXIMUM_RAW_STRING_BYTES),
        "maximumTotalCommandBytes" to JsonPrimitive(COMPDB_MAXIMUM_TOTAL_COMMAND_BYTES),
        "maximumTotalCommandWords" to JsonPrimitive(COMPDB_MAXIMUM_TOTAL_COMMAND_WORDS),
        "maximumWorkUnits" to JsonPrimitive(COMPDB_MAXIMUM_WORK_UNITS),
    ),
)

private val COMPDB_BLOCKER_DISPOSITIONS = listOf(
    compdbBlockerDisposition("complete-project-header-inventory-missing", "carried"),
    compdbBlockerDisposition("compiler-capture-provenance-missing", "carried"),
    compdbBlockerDisposition("compiler-option-arity-unvalidated", "carried"),
    compdbBlockerDisposition("generated-generation-receipt-missing", "carried"),
    compdbBlockerDisposition("generated-snapshot-completeness-unproven", "carried"),
    compdbBlockerDisposition("ninja-live-edge-replay-missing", "carried"),
    compdbBlockerDisposition("physical-build-root-unverified", "carried"),
    compdbBlockerDisposition("physical-project-roots-unverified", "carried"),
)

private val COMPDB_BLOCKERS = listOf(
    compdbBlocker("complete-project-header-inventory-missing"),
    compdbBlocker("compiler-capture-provenance-missing"),
    compdbBlocker("compiler-option-arity-unvalidated"),
    compdbBlocker("generated-generation-receipt-missing"),
    compdbBlocker("generated-snapshot-completeness-unproven"),
    compdbBlocker("ninja-live-edge-replay-missing"),
    compdbBlocker("physical-build-root-unverified"),
    compdbBlocker("physical-project-roots-unverified"),
)

private fun compdbBlocker(code: String): JsonObject = JsonObject(
    mapOf("code" to JsonPrimitive(code), "status" to JsonPrimitive("unresolved")),
)

private fun compdbBlockerDisposition(code: String, disposition: String): JsonObject = JsonObject(
    mapOf(
        "activeCodes" to JsonArray(listOf(JsonPrimitive(code))),
        "code" to JsonPrimitive(code),
        "disposition" to JsonPrimitive(disposition),
        "source" to JsonPrimitive("clang-capture-input-v1"),
    ),
)

private val COMPDB_CONFIGURATION_POLICY = JsonObject(
    mapOf(
        "acpBoundary" to COMPDB_ACP_BOUNDARY,
        "authority" to COMPDB_AUTHORITY,
        "bounds" to COMPDB_BOUNDS,
        "captureInputSchemaSha256" to JsonPrimitive(
            OracleSchemas.identity("full-tree-clang-capture-input").sha256,
        ),
        "id" to JsonPrimitive(COMPDB_SCHEMA),
        "reconciliationPolicy" to COMPDB_RECONCILIATION_POLICY,
        "version" to JsonPrimitive(1),
    ),
)

private val COMPDB_RECORD_KEYS = setOf("command", "directory", "file", "output")
private val COMPDB_SAFE_WORD = Regex("[A-Za-z0-9_+./=,:@%\\-]+")
private val COMPDB_SHA256 = Regex("[0-9a-f]{64}")
private val COMPDB_RAW_OPAQUE_FORWARDING_PREFIXES = listOf("-Wa,", "-Wl,", "-Wp,", "-X", "-mllvm")
private val COMPDB_RAW_CAPTURE_OPTION_PREFIXES = listOf(
    "-header-include-file",
    "-header-include-filtering",
    "-header-include-format",
)
private val COMPDB_RAW_FORBIDDEN_ARGUMENTS = setOf(
    "-",
    "--",
    "--no-default-config",
    "-cc1",
    "-cc1as",
    "-E",
    "-S",
    "-fno-integrated-as",
    "-fsyntax-only",
    "-M",
    "-MM",
    "-MMD",
    "-MD",
    "-MT",
    "-MQ",
    "-MF",
    "-o",
    "-c",
)
private val COMPDB_RAW_JOINED_FIXED_OPTION_PREFIXES = listOf("-MD", "-MT", "-MQ", "-MF", "-o")

private const val COMPDB_SCHEMA = "full-tree-clang-compdb-reconciliation"
private const val COMPDB_RAW_FRAME_SIZE = 9
private const val COMPDB_RECORD_DOMAIN = "full-tree-clang-compdb-record-v1"
private const val COMPDB_DECODED_ARGUMENTS_DOMAIN = "full-tree-clang-compdb-decoded-arguments-v1"
private const val COMPDB_DERIVED_ARGUMENTS_DOMAIN = "full-tree-clang-compdb-derived-capture-arguments-v1"
private const val COMPDB_MATCH_DOMAIN = "full-tree-clang-compdb-match-v1"
private const val COMPDB_MATCHED_RECORD_MANIFEST_DOMAIN = "full-tree-clang-compdb-matched-record-manifest-v1"
private const val COMPDB_IGNORED_RECORD_MANIFEST_DOMAIN = "full-tree-clang-compdb-ignored-record-manifest-v1"
private const val COMPDB_MATCH_MANIFEST_DOMAIN = "full-tree-clang-compdb-match-manifest-v1"
private const val COMPDB_MAXIMUM_ACTIONS = 10_000
private const val COMPDB_MAXIMUM_CANONICAL_BYTES = 32 * 1024 * 1024
private const val COMPDB_MAXIMUM_COMMAND_BYTES = 256 * 1024
private const val COMPDB_MAXIMUM_COMMAND_WORDS_PER_ACTION = 4095
private const val COMPDB_MAXIMUM_BYTES = 64 * 1024 * 1024
private const val COMPDB_MAXIMUM_RECORDS = 100_000
private const val COMPDB_MAXIMUM_OUTPUT_RECORDS = 10_008L
private const val COMPDB_MAXIMUM_PATH_BYTES = 4096
private const val COMPDB_MAXIMUM_PATH_COMPONENT_BYTES = 255
private const val COMPDB_MAXIMUM_RAW_STRING_BYTES = 64 * 1024 * 1024
private const val COMPDB_MAXIMUM_TOTAL_COMMAND_BYTES = 32L * 1024L * 1024L
private const val COMPDB_MAXIMUM_TOTAL_COMMAND_WORDS = 499_999L
private const val COMPDB_MAXIMUM_WORK_UNITS = 5_000_000L

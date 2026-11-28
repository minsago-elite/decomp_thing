package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateInspection
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal class GccBundledOperationJournal private constructor(
    val path: Path,
    private val operationId: String,
    private val intentSha256: String,
    private val rootPath: Path,
    private val parent: LinuxDescriptor,
    private val root: LinuxDescriptor,
    private val directory: LinuxDescriptor,
    intentSnapshot: DescriptorBoundStateSnapshot,
) : AutoCloseable {
    private val snapshots = linkedMapOf(INTENT_FILE to intentSnapshot)
    private var stage = JournalStage.INTENT
    private var diskEvidenceSha256: String? = null
    private var plannerBaseFiles: Set<String>? = null
    private var recoveredStopped: GccBundledStoppedJournalEvidence? = null
    /** Complete atomic temporary of an adoption a crashed later owner linked but did not rename; held open. */
    private var pendingAdoption: DescriptorBoundStateInspection? = null
    private var poisoned = false
    private var closed = false

    /** Exact durable record of a later owner's adoption; null for every fresh or same-owner chain. */
    val recoveryRecordBytes: ByteArray?
        @Synchronized get() = snapshots[RECOVERY_FILE]?.bytes

    /** Stopped evidence parsed by [openStoppedForRecovery]; absent for every newly created journal. */
    val recoveredStoppedEvidence: GccBundledStoppedJournalEvidence
        @Synchronized get() {
            checkOpen()
            return checkNotNull(recoveredStopped) { "GCC journal was not reopened for later-invocation recovery" }
        }

    val preparedBytes: ByteArray
        @Synchronized get() {
            checkOpen()
            check(stage >= JournalStage.PREPARED) { "GCC bundled operation is not prepared" }
            return snapshots.getValue(PREPARED_FILE).bytes
        }

    @Synchronized
    fun recordLease(evidence: FullTreeDiskScratchEvidence) = boundOperation("recording GCC disk lease") {
        check(stage == JournalStage.INTENT) { "GCC bundled disk lease requires the intent-only stage" }
        if (evidence.operationId != operationId || evidence.requestSha256 != intentSha256) {
            journalFail("GCC bundled disk evidence belongs to a different operation intent")
        }
        val bytes = evidence.canonicalBytes()
        val parsed = FullTreeDiskScratchEvidence.parseCanonical(bytes)
        if (parsed.evidenceSha256 != evidence.evidenceSha256) {
            journalFail("GCC bundled disk evidence identity changed")
        }
        publish(LEASE_FILE, bytes)
        diskEvidenceSha256 = evidence.evidenceSha256
        stage = JournalStage.LEASED
    }

    @Synchronized
    fun recordPrepared(definitionBytes: ByteArray, deploymentClosureSha256: String) = boundOperation("recording prepared GCC operation") {
        check(stage == JournalStage.LEASED) { "GCC bundled preparation requires one recorded disk lease" }
        require(deploymentClosureSha256.matches(Regex("[a-f0-9]{64}"))) {
            "GCC bundled deployment closure digest is invalid"
        }
        val bytes = boundedCopy(definitionBytes, MAXIMUM_DEFINITION_BYTES, "GCC bundled containment definition")
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(bytes)
        if (definition.bundledRuntime == null) {
            journalFail("GCC bundled operation requires a v2 bundled containment definition")
        }
        if (path.startsWith(definition.outputLease.path) || definition.outputLease.path.startsWith(path)) {
            journalFail("GCC bundled journal must remain outside its writable output")
        }
        val prepared = preparedRecordBytes(operationId, intentSha256, checkNotNull(diskEvidenceSha256), bytes,
            definition.bindingSha256, deploymentClosureSha256)
        publish(DEFINITION_FILE, bytes)
        stage = JournalStage.DEFINITION_STAGED
        requireCurrent("after GCC definition publication")
        publish(PREPARED_FILE, prepared)
        stage = JournalStage.PREPARED
    }

    @Synchronized
    fun verify(label: String) = boundOperation(label) { }

    @Synchronized
    fun recordAttachment(attachmentBytes: ByteArray) = boundOperation("recording GCC command attachment") {
        check(stage == JournalStage.PREPARED) { "GCC command attachment requires a prepared operation" }
        publishLinkedRecord(ATTACHMENT_FILE, "gcc-bundled-command-attached-v1", PREPARED_FILE, "attachment", attachmentBytes)
        stage = JournalStage.ATTACHED
    }

    @Synchronized
    fun recordStartAuthorization() = boundOperation("authorizing GCC command START") {
        check(stage == JournalStage.ATTACHED) { "GCC command START requires a retained attachment" }
        publishLinkedRecord(START_FILE, "gcc-bundled-command-start-authorized-v1", ATTACHMENT_FILE, null, null)
        stage = JournalStage.START_AUTHORIZED
    }

    @Synchronized
    fun recordExecution(executionBytes: ByteArray): ByteArray = boundOperation("recording GCC command execution") {
        check(stage == JournalStage.START_AUTHORIZED) { "GCC command execution requires durable START authorization" }
        publishLinkedRecord(EXECUTION_FILE, "gcc-bundled-command-executed-v1", START_FILE, "execution", executionBytes)
        stage = JournalStage.EXECUTED
        snapshots.getValue(EXECUTION_FILE).bytes
    }

    @Synchronized
    fun recordExportAssessment(assessmentBytes: ByteArray): ByteArray = boundOperation("recording GCC export assessment") {
        check(stage == JournalStage.EXECUTED) { "GCC export assessment requires recorded contained execution" }
        publishLinkedRecord(EXPORT_FILE, "gcc-bundled-command-export-assessed-v1", EXECUTION_FILE, "assessment", assessmentBytes)
        stage = JournalStage.EXPORT_ASSESSED
        snapshots.getValue(EXPORT_FILE).bytes
    }

    @Synchronized
    fun recordInterruptionAuthorization(authorizationBytes: ByteArray) = boundOperation("authorizing GCC command interruption") {
        check(stage == JournalStage.START_AUTHORIZED) { "GCC interruption requires durable START authorization" }
        publishLinkedRecord(INTERRUPT_FILE, "gcc-bundled-command-interrupt-authorized-v1", START_FILE, "authorization", authorizationBytes)
        stage = JournalStage.INTERRUPT_AUTHORIZED
    }

    @Synchronized
    fun recordInterruptedExecution(executionBytes: ByteArray): ByteArray = boundOperation("recording interrupted GCC command") {
        check(stage == JournalStage.INTERRUPT_AUTHORIZED) { "GCC interrupted execution requires durable interruption authorization" }
        publishLinkedRecord(INTERRUPTED_FILE, "gcc-bundled-command-interrupted-v1", INTERRUPT_FILE, "execution", executionBytes)
        stage = JournalStage.INTERRUPTED
        snapshots.getValue(INTERRUPTED_FILE).bytes
    }

    @Synchronized
    fun recordInterruptedPrefixAssessment(assessmentBytes: ByteArray): ByteArray = boundOperation("recording interrupted GCC prefix") {
        check(stage == JournalStage.INTERRUPTED) { "GCC interrupted prefix requires recorded interrupted execution" }
        publishLinkedRecord(PREFIX_FILE, "gcc-bundled-command-prefix-assessed-v1", INTERRUPTED_FILE, "assessment", assessmentBytes)
        stage = JournalStage.PREFIX_ASSESSED
        snapshots.getValue(PREFIX_FILE).bytes
    }

    /**
     * Commits the stopped checkpoint. [operationWallTime] is sampled after the manifest and immediately before
     * the state record, so an operation whose deadline has expired never commits a recoverable stopped state,
     * and a later owner's resume allowance is charged for the prefix and state capture that preceded it.
     */
    @Synchronized
    fun recordInterruptedAnalysisState(
        snapshot: GccBundledAnalysisStateSnapshot,
        operationWallTime: () -> JsonObject,
    ): ByteArray = boundOperation("recording stopped GCC analysis state") {
        check(stage == JournalStage.PREFIX_ASSESSED) { "GCC stopped analysis state requires a validated interrupted prefix" }
        val manifest = snapshot.canonicalBytes
        publish(STATE_MANIFEST_FILE, manifest)
        stage = JournalStage.STATE_MANIFEST_STAGED
        requireCurrent("after GCC state manifest publication")
        val wallTime = operationWallTime()
        operationWallSnapshot(wallTime, "GCC stopped state commit")
        val summary = OracleJson.canonicalBytes(JsonObject(mapOf(
            "manifestSha256" to JsonPrimitive(snapshot.sha256),
            "manifestBytes" to JsonPrimitive(manifest.size),
            "entryCount" to JsonPrimitive(snapshot.entryCount),
            "totalBytes" to JsonPrimitive(snapshot.totalBytes),
            "operationWallTime" to wallTime,
        )))
        publishLinkedRecord(STATE_CAPTURED_FILE, "gcc-bundled-interrupted-state-captured-v1", PREFIX_FILE, "analysisState", summary)
        stage = JournalStage.STATE_CAPTURED
        snapshots.getValue(STATE_CAPTURED_FILE).bytes
    }

    /**
     * Durably names this later owner before any resume record. Only a journal reopened by
     * [openStoppedForRecovery] can reach this transition; a same-owner chain never contains it.
     */
    @Synchronized
    fun recordRecoveryAdopted(recoveryBytes: ByteArray): ByteArray = boundOperation("recording later-invocation GCC recovery") {
        val stopped = checkNotNull(recoveredStopped) { "GCC later-invocation recovery requires a reopened stopped journal" }
        check(stage == JournalStage.STATE_CAPTURED && pendingAdoption == null && stopped.retainedAdoptionPayloadBytes == null) {
            "GCC later-invocation recovery requires a reopened stopped journal without a retained adoption"
        }
        requireRecoveryPayload(recoveryBytes, snapshots.getValue(STATE_CAPTURED_FILE).bytes, stopped.recoveryWallCapMillis)
        publishLinkedRecord(RECOVERY_FILE, RECOVERY_RECORD_PROVIDER, STATE_CAPTURED_FILE, "recovery", recoveryBytes)
        stage = JournalStage.RECOVERY_ADOPTED
        snapshots.getValue(RECOVERY_FILE).bytes
    }

    /**
     * Reuses the single adoption a crashed later owner left before any resume record: an already published
     * record is confirmed unchanged, and its complete atomic temporary is renamed into place without new bytes.
     * Its recorded resume allowance stays authoritative, so a repeated crash never refreshes the budget.
     */
    @Synchronized
    fun completeRetainedRecoveryAdoption(): ByteArray = boundOperation("completing a retained later-invocation GCC recovery") {
        val stopped = checkNotNull(recoveredStopped) { "GCC later-invocation recovery requires a reopened stopped journal" }
        checkNotNull(stopped.retainedAdoptionPayloadBytes) { "GCC reopened journal has no retained adoption to complete" }
        when (stage) {
            JournalStage.RECOVERY_ADOPTED -> snapshots.getValue(RECOVERY_FILE).bytes
            JournalStage.STATE_CAPTURED -> {
                val pending = checkNotNull(pendingAdoption) { "GCC retained adoption temporary is not held" }
                requireDirectoryBindings()
                val published = DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
                    directory, RECOVERY_FILE, pending, maximumFileBytes(RECOVERY_FILE),
                )
                requireDirectoryBindings()
                snapshots[RECOVERY_FILE] = published
                pendingAdoption = null
                runCatching { pending.close() }
                stage = JournalStage.RECOVERY_ADOPTED
                published.bytes
            }
            else -> error("GCC retained adoption can only complete before any resume record")
        }
    }

    @Synchronized
    fun recordResumePrepared(definitionBytes: ByteArray): ByteArray = boundOperation("preparing GCC resume") {
        check(stage == JournalStage.STATE_CAPTURED || stage == JournalStage.RECOVERY_ADOPTED) { "GCC resume requires recorded stopped state" }
        check(stage == JournalStage.RECOVERY_ADOPTED || recoveredStopped == null) {
            "a reopened GCC journal must record its later-invocation owner before resume"
        }
        val resumePredecessor = if (stage == JournalStage.RECOVERY_ADOPTED) RECOVERY_FILE else STATE_CAPTURED_FILE
        val bytes = boundedCopy(definitionBytes, MAXIMUM_DEFINITION_BYTES, "GCC resume definition")
        val resumed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(bytes)
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(snapshots.getValue(DEFINITION_FILE).bytes)
        val oldRuntime = checkNotNull(original.bundledRuntime)
        val newRuntime = checkNotNull(resumed.bundledRuntime)
        require(original.runKind == GccCompilerEngineContainmentRunKind.INTERRUPTED && oldRuntime.invocationVersion == 3 &&
            resumed.runKind == GccCompilerEngineContainmentRunKind.RESUMED && newRuntime.invocationVersion == 4) {
            "GCC resume must follow an interrupted v3 invocation with explicit v4 reanalysis"
        }
        require(resumed.engineId == original.engineId && resumed.artifacts == original.artifacts &&
            resumed.outputLease == original.outputLease && resumed.environment == original.environment &&
            newRuntime.root == oldRuntime.root && newRuntime.classPath == oldRuntime.classPath &&
            resumed.analysisState.path == original.analysisState.path) { "GCC resume changed its retained operation inputs" }
        require(resumed.budgets.wallClockMillis <= original.budgets.wallClockMillis &&
            resumed.budgets.maximumResidentBytes <= original.budgets.maximumResidentBytes &&
            resumed.budgets.pidsMax <= original.budgets.pidsMax) { "GCC resume increased its operation budgets" }
        val manifest = snapshots.getValue(STATE_MANIFEST_FILE).bytes
        val captured = (OracleJson.parseCanonical(snapshots.getValue(STATE_CAPTURED_FILE).bytes) as JsonObject)
            .getValue("analysisState") as JsonObject
        require(resumed.analysisState.manifestSha256 == OracleArtifacts.sha256(manifest) &&
            captured["entryCount"] == JsonPrimitive(resumed.analysisState.entryCount) &&
            captured["totalBytes"] == JsonPrimitive(resumed.analysisState.totalBytes)) {
            "GCC resume state differs from the recorded stopped manifest"
        }
        publish(RESUME_DEFINITION_FILE, bytes)
        stage = JournalStage.RESUME_DEFINITION_STAGED
        requireCurrent("after GCC resume definition publication")
        val summary = OracleJson.canonicalBytes(JsonObject(mapOf(
            "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
            "definitionBindingSha256" to JsonPrimitive(resumed.bindingSha256),
        )))
        publishLinkedRecord(RESUME_PREPARED_FILE, "gcc-bundled-resume-prepared-v1", resumePredecessor, "resume", summary)
        stage = JournalStage.RESUME_PREPARED
        snapshots.getValue(RESUME_PREPARED_FILE).bytes
    }

    @Synchronized
    fun recordResumeAttachment(bytes: ByteArray) = boundOperation("recording GCC resume attachment") {
        check(stage == JournalStage.RESUME_PREPARED) { "GCC resume attachment requires resume preparation" }
        publishLinkedRecord(RESUME_ATTACHMENT_FILE, "gcc-bundled-resume-attached-v1", RESUME_PREPARED_FILE, "attachment", bytes)
        stage = JournalStage.RESUME_ATTACHED
    }

    @Synchronized
    fun recordResumeStartAuthorization() = boundOperation("authorizing GCC resume START") {
        check(stage == JournalStage.RESUME_ATTACHED) { "GCC resume START requires resume attachment" }
        publishLinkedRecord(RESUME_START_FILE, "gcc-bundled-resume-start-authorized-v1", RESUME_ATTACHMENT_FILE, null, null)
        stage = JournalStage.RESUME_START_AUTHORIZED
    }

    @Synchronized
    fun recordResumeExecution(bytes: ByteArray): ByteArray = boundOperation("recording GCC resume execution") {
        check(stage == JournalStage.RESUME_START_AUTHORIZED) { "GCC resume execution requires durable resume START" }
        publishLinkedRecord(RESUME_EXECUTION_FILE, "gcc-bundled-resume-executed-v1", RESUME_START_FILE, "execution", bytes)
        stage = JournalStage.RESUME_EXECUTED
        snapshots.getValue(RESUME_EXECUTION_FILE).bytes
    }

    @Synchronized
    fun recordResumeExportAssessment(bytes: ByteArray): ByteArray = boundOperation("recording GCC resume export") {
        check(stage == JournalStage.RESUME_EXECUTED) { "GCC resume export requires recorded resume execution" }
        publishLinkedRecord(RESUME_EXPORT_FILE, "gcc-bundled-resume-export-assessed-v1", RESUME_EXECUTION_FILE, "assessment", bytes)
        stage = JournalStage.RESUME_EXPORT_ASSESSED
        snapshots.getValue(RESUME_EXPORT_FILE).bytes
    }

    @Synchronized
    fun recordPlannerPrepared(requestBytes: ByteArray): ByteArray = boundOperation("preparing GCC planner") {
        val predecessor = when (stage) {
            JournalStage.EXPORT_ASSESSED -> EXPORT_FILE
            JournalStage.RESUME_EXPORT_ASSESSED -> RESUME_EXPORT_FILE
            else -> error("GCC planning requires an assessed fresh or resumed export")
        }
        val bytes = boundedCopy(requestBytes, MAXIMUM_INTENT_BYTES, "GCC planner request")
        val request = GccBundledPlannerRequest.parse(bytes)
        val intent = OracleJson.parseCanonical(snapshots.getValue(INTENT_FILE).bytes, JOURNAL_JSON_LIMITS).jsonObject
        require(intent["provider"] == JsonPrimitive("gcc-bundled-operation-intent-v2") && intent["schemaVersion"] == JsonPrimitive(2)) {
            "GCC planning requires an intent with bound planner policy"
        }
        val profile = intent.getValue("plannerProfile").jsonObject
        val reconstruction = profile.getValue("reconstructionProfile").jsonObject
        val limits = reconstruction.getValue("budgets").jsonObject
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(snapshots.getValue(DEFINITION_FILE).bytes)
        val exported = OracleJson.parseCanonical(snapshots.getValue(predecessor).bytes, JOURNAL_JSON_LIMITS)
            .jsonObject.getValue("assessment").jsonObject
        val exportSha = OracleArtifacts.sha256(snapshots.getValue(predecessor).bytes)
        require(request.operationRequestSha256 == intentSha256 &&
            request.profilePolicySha256 == OracleArtifacts.sha256(OracleJson.canonicalBytes(profile)) &&
            request.modelPath == definition.outputLease.path.resolve("reports/program_model.json") &&
            request.outputDirectory == definition.outputLease.path.resolve(gccBundledPlannerControlName(intentSha256, exportSha)).resolve("reports") &&
            request.inputSha256 == definition.artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY }.sha256 &&
            exported["programModelSha256"] == JsonPrimitive(request.modelSha256) &&
            exported["programModelBytes"] == JsonPrimitive(request.modelBytes) &&
            exported["functionCount"] == JsonPrimitive(request.functionCount)
        ) { "GCC planner request differs from its operation and captured model lineage" }
        require(OracleJson.parse(request.layout.canonicalJson().toByteArray()) == reconstruction.getValue("layout") &&
            limits["maximumFunctionsPerModule"] == JsonPrimitive(request.maximumFunctionsPerModule) &&
            limits["plannerMaximumEntities"] == JsonPrimitive(request.maximumEntities) &&
            limits["plannerMaximumDependencyEdges"] == JsonPrimitive(request.maximumDependencyEdges) &&
            limits["plannerMaximumWorkUnits"] == JsonPrimitive(request.maximumWorkUnits) &&
            request.maximumPlanBytes.toLong() <= definition.outputLease.maximumFilesystemBytes
        ) { "GCC planner request differs from its bound layout or resource policy" }
        plannerBaseFiles = snapshots.keys.toSet()
        publish(PLANNER_REQUEST_FILE, bytes)
        stage = JournalStage.PLANNER_REQUEST_STAGED
        requireCurrent("after GCC planner request publication")
        val summary = OracleJson.canonicalBytes(JsonObject(mapOf(
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
            "profilePolicySha256" to JsonPrimitive(request.profilePolicySha256),
        )))
        publishLinkedRecord(PLANNER_PREPARED_FILE, "gcc-bundled-planner-prepared-v1", predecessor, "planner", summary)
        stage = JournalStage.PLANNER_PREPARED
        snapshots.getValue(PLANNER_PREPARED_FILE).bytes
    }

    @Synchronized
    fun recordPlannerAttachment(bytes: ByteArray) = boundOperation("recording GCC planner attachment") {
        check(stage == JournalStage.PLANNER_PREPARED) { "GCC planner attachment requires planner preparation" }
        publishLinkedRecord(PLANNER_ATTACHMENT_FILE, "gcc-bundled-planner-attached-v1", PLANNER_PREPARED_FILE, "attachment", bytes)
        stage = JournalStage.PLANNER_ATTACHED
    }

    @Synchronized
    fun recordPlannerStartAuthorization() = boundOperation("authorizing GCC planner START") {
        check(stage == JournalStage.PLANNER_ATTACHED) { "GCC planner START requires planner attachment" }
        publishLinkedRecord(PLANNER_START_FILE, "gcc-bundled-planner-start-authorized-v1", PLANNER_ATTACHMENT_FILE, null, null)
        stage = JournalStage.PLANNER_START_AUTHORIZED
    }

    @Synchronized
    fun recordPlannerExecution(bytes: ByteArray): ByteArray = boundOperation("recording GCC planner execution") {
        check(stage == JournalStage.PLANNER_START_AUTHORIZED) { "GCC planner execution requires durable START" }
        publishLinkedRecord(PLANNER_EXECUTION_FILE, "gcc-bundled-planner-executed-v1", PLANNER_START_FILE, "execution", bytes)
        stage = JournalStage.PLANNER_EXECUTED
        snapshots.getValue(PLANNER_EXECUTION_FILE).bytes
    }

    @Synchronized
    fun recordPlannerAssessment(bytes: ByteArray): ByteArray = boundOperation("recording GCC planner assessment") {
        check(stage == JournalStage.PLANNER_EXECUTED) { "GCC planner assessment requires recorded execution" }
        val assessment = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS).jsonObject
        val rawRequest = snapshots.getValue(PLANNER_REQUEST_FILE).bytes
        val request = GccBundledPlannerRequest.parse(rawRequest)
        require(assessment["requestSha256"] == JsonPrimitive(OracleArtifacts.sha256(rawRequest)) &&
            assessment["modelSha256"] == JsonPrimitive(request.modelSha256) &&
            assessment["operationRequestSha256"] == JsonPrimitive(request.operationRequestSha256) &&
            assessment["profilePolicySha256"] == JsonPrimitive(request.profilePolicySha256) &&
            assessment["functionCount"] == JsonPrimitive(request.functionCount) &&
            assessment.getValue("planSha256").jsonPrimitive.let { it.isString && it.content.matches(Regex("[a-f0-9]{64}")) }) {
            "GCC planner assessment differs from its request/model lineage"
        }
        val planBytes = assessment.getValue("planBytes").jsonPrimitive
        require(!planBytes.isString && planBytes.content.toLong() in 1..request.maximumPlanBytes.toLong()) {
            "GCC planner assessment exceeds its output byte bound"
        }
        publishLinkedRecord(PLANNER_ASSESSMENT_FILE, "gcc-bundled-planner-assessed-v1", PLANNER_EXECUTION_FILE, "assessment", bytes)
        stage = JournalStage.PLANNER_ASSESSED
        snapshots.getValue(PLANNER_ASSESSMENT_FILE).bytes
    }

    private fun publishLinkedRecord(name: String, provider: String, previous: String, payloadName: String?, payloadBytes: ByteArray?) {
        publish(name, linkedRecordBytes(operationId, intentSha256, provider, snapshots.getValue(previous).bytes, payloadName, payloadBytes))
    }

    private fun publish(name: String, bytes: ByteArray) {
        requireDirectoryBindings()
        snapshots[name] = if (name == STATE_MANIFEST_FILE) {
            DescriptorBoundAtomicStateFile.publishManifestNoReplace(directory, name, bytes, maximumFileBytes(name))
        } else {
            DescriptorBoundAtomicStateFile.publishNoReplace(directory, name, bytes, maximumFileBytes(name))
        }
        requireDirectoryBindings()
    }

    private fun requireCurrent(label: String) {
        requireDirectoryBindings()
        val expectedNames = when (stage) {
            JournalStage.INTENT -> setOf(INTENT_FILE)
            JournalStage.LEASED -> setOf(INTENT_FILE, LEASE_FILE)
            JournalStage.DEFINITION_STAGED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE)
            JournalStage.PREPARED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE)
            JournalStage.ATTACHED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE)
            JournalStage.START_AUTHORIZED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE)
            JournalStage.EXECUTED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, EXECUTION_FILE)
            JournalStage.EXPORT_ASSESSED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, EXECUTION_FILE, EXPORT_FILE)
            JournalStage.INTERRUPT_AUTHORIZED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE)
            JournalStage.INTERRUPTED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE)
            JournalStage.PREFIX_ASSESSED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE)
            JournalStage.STATE_MANIFEST_STAGED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE, STATE_MANIFEST_FILE)
            JournalStage.RESUME_DEFINITION_STAGED, JournalStage.RESUME_PREPARED, JournalStage.RESUME_ATTACHED,
            JournalStage.RESUME_START_AUTHORIZED, JournalStage.RESUME_EXECUTED, JournalStage.RESUME_EXPORT_ASSESSED ->
                STOPPED_FILES + (if (recoveredStopped != null) setOf(RECOVERY_FILE) else emptySet()) +
                    RESUME_FILES.take(RESUME_STAGES.indexOf(stage) + 1)
            JournalStage.STATE_CAPTURED -> STOPPED_FILES
            JournalStage.RECOVERY_ADOPTED -> STOPPED_FILES + RECOVERY_FILE
            JournalStage.PLANNER_REQUEST_STAGED, JournalStage.PLANNER_PREPARED, JournalStage.PLANNER_ATTACHED,
            JournalStage.PLANNER_START_AUTHORIZED, JournalStage.PLANNER_EXECUTED, JournalStage.PLANNER_ASSESSED ->
                checkNotNull(plannerBaseFiles) + PLANNER_FILES.take(PLANNER_STAGES.indexOf(stage) + 1)
        }
        if (snapshots.keys != expectedNames) journalFail("GCC bundled journal has inconsistent retained state")
        val pending = pendingAdoption
        if (pending != null && stage != JournalStage.STATE_CAPTURED) journalFail("GCC retained adoption temporary outlived its stage")
        val residue = if (pending != null) setOf(RECOVERY_TEMPORARY_FILE) else emptySet()
        requireExactNames(expectedNames + residue, label)
        snapshots.forEach { (name, expected) ->
            val actual = (if (name == STATE_MANIFEST_FILE) {
                DescriptorBoundAtomicStateFile.readManifestOrNull(directory, name, maximumFileBytes(name))
            } else DescriptorBoundAtomicStateFile.readOrNull(directory, name, maximumFileBytes(name)))
                ?: journalFail("GCC bundled journal file disappeared $label: $name")
            if (actual.identity != expected.identity || !MessageDigest.isEqual(actual.bytes, expected.bytes)) {
                journalFail("GCC bundled journal file changed $label: $name")
            }
        }
        pending?.let { requirePendingAdoptionCurrent(it, label) }
        requireExactNames(expectedNames + residue, label)
        requireDirectoryBindings()
    }

    private fun requireExactNames(expected: Set<String>, label: String) {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_JOURNAL_ENTRIES + 1)
        if (names.size != expected.size || names.toSet() != expected) {
            journalFail("GCC bundled journal contains unexpected residue $label")
        }
    }

    private fun requireDirectoryBindings() {
        requireRootBinding(rootPath, parent, root)
        val current = LinuxFilesystemSyscalls.identity(directory.fd)
        requireManagedDirectory(current, root.identity, "GCC bundled operation journal")
        if (!sameDirectory(current, directory.identity)) journalFail("GCC bundled operation journal changed identity")
        LinuxFilesystemSyscalls.openDirectoryAt(root.fd, path.fileName.toString()).use { selected ->
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), current)) {
                journalFail("GCC bundled operation journal name changed identity")
            }
        }
        if (path.toRealPath() != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(directory))) {
            journalFail("GCC bundled operation journal pathname changed")
        }
    }

    private inline fun <T> boundOperation(label: String, action: () -> T): T {
        checkOpen()
        return try {
            requireCurrent("before $label")
            action().also { requireCurrent("after $label") }
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "GCC bundled operation journal is closed" }
        check(!poisoned) { "GCC bundled operation journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        val pendingFailure = pendingAdoption?.let { runCatching { it.close() }.exceptionOrNull() }
        pendingAdoption = null
        val failure = closeJournalDescriptors(directory, root, parent)
        if (failure != null && pendingFailure != null && pendingFailure !== failure) failure.addSuppressed(pendingFailure)
        (failure ?: pendingFailure)?.let { throw it }
    }

    companion object {
        fun create(root: Path, operationId: String, intentBytes: ByteArray): GccBundledOperationJournal {
            require(operationId.matches(Regex("[a-f0-9]{64}"))) { "GCC bundled operation ID is invalid" }
            val bytes = boundedCopy(intentBytes, MAXIMUM_INTENT_BYTES, "GCC bundled operation intent")
            require(OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) is JsonObject) {
                "GCC bundled operation intent must be a canonical JSON object"
            }
            if (
                !root.isAbsolute || root.normalize() != root || root.parent == null ||
                !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || root.toRealPath() != root
            ) journalFail("GCC bundled journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(root)
            val parent = LinuxFilesystemSyscalls.openRoot(root.parent)
            var rootDescriptor: LinuxDescriptor? = null
            var directory: LinuxDescriptor? = null
            var rootLocked = false
            var directoryLocked = false
            try {
                val openedRoot = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, root.fileName.toString())
                rootDescriptor = openedRoot
                requireRootBinding(root, parent, openedRoot)
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedRoot)) {
                    journalFail("GCC bundled journal root is already locked")
                }
                rootLocked = true
                LinuxFilesystemSyscalls.synchronize(openedRoot)
                LinuxFilesystemSyscalls.synchronize(parent)
                requireRootBinding(root, parent, openedRoot)
                val name = ".gcc-bundled-operation-$operationId"
                LinuxFilesystemSyscalls.openPathAtOrNull(openedRoot.fd, name)?.use {
                    journalFail("GCC bundled operation journal already exists")
                }
                LinuxFilesystemSyscalls.createDirectory(openedRoot.fd, name, OWNER_DIRECTORY_MODE)
                val openedDirectory = LinuxFilesystemSyscalls.openDirectoryAt(openedRoot.fd, name)
                directory = openedDirectory
                LinuxFilesystemSyscalls.chmod(openedDirectory, OWNER_DIRECTORY_MODE)
                requireManagedDirectory(
                    LinuxFilesystemSyscalls.identity(openedDirectory.fd),
                    openedRoot.identity,
                    "GCC bundled operation journal",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedDirectory)) {
                    journalFail("GCC bundled operation journal is already locked")
                }
                directoryLocked = true
                LinuxFilesystemSyscalls.synchronize(openedDirectory)
                LinuxFilesystemSyscalls.synchronize(openedRoot)
                requireRootBinding(root, parent, openedRoot)
                if (LinuxFilesystemSyscalls.directoryEntryNames(openedDirectory, 1).isNotEmpty()) {
                    journalFail("new GCC bundled operation journal contains residue")
                }
                val snapshot = DescriptorBoundAtomicStateFile.publishNoReplace(
                    openedDirectory,
                    INTENT_FILE,
                    bytes,
                    MAXIMUM_INTENT_BYTES,
                )
                return GccBundledOperationJournal(
                    root.resolve(name), operationId, OracleArtifacts.sha256(bytes), root,
                    parent, openedRoot, openedDirectory, snapshot,
                ).also { it.verify("after journal creation") }
            } catch (failure: Throwable) {
                closeJournalDescriptors(
                    directory, rootDescriptor, parent, directoryLocked, rootLocked,
                )?.let { if (it !== failure) failure.addSuppressed(it) }
                throw failure
            }
        }

        /**
         * Reopens one exactly stopped interrupted operation for a later owner. The journal-root and operation
         * locks are taken without blocking before any record is read; either lock still held means the earlier
         * owner is live, and recovery is refused. Every stopped record is rebuilt from its own payload and
         * predecessor and must match byte for byte. Nothing is appended, repaired or removed here.
         */
        fun openStoppedForRecovery(
            root: Path,
            operationId: String,
            intentBytes: ByteArray,
            deploymentClosureSha256: String,
        ): GccBundledOperationJournal {
            require(operationId.matches(Regex("[a-f0-9]{64}"))) { "GCC bundled operation ID is invalid" }
            require(deploymentClosureSha256.matches(Regex("[a-f0-9]{64}"))) { "GCC bundled deployment closure digest is invalid" }
            val expectedIntent = boundedCopy(intentBytes, MAXIMUM_INTENT_BYTES, "GCC bundled operation intent")
            if (
                !root.isAbsolute || root.normalize() != root || root.parent == null ||
                !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || root.toRealPath() != root
            ) journalFail("GCC bundled journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(root)
            val parent = LinuxFilesystemSyscalls.openRoot(root.parent)
            var rootDescriptor: LinuxDescriptor? = null
            var directory: LinuxDescriptor? = null
            var rootLocked = false
            var directoryLocked = false
            var journal: GccBundledOperationJournal? = null
            try {
                val openedRoot = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, root.fileName.toString())
                rootDescriptor = openedRoot
                requireRootBinding(root, parent, openedRoot)
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedRoot)) {
                    journalFail("GCC bundled journal root is held by a live owner; later-invocation recovery refused")
                }
                rootLocked = true
                requireRootBinding(root, parent, openedRoot)
                val name = ".gcc-bundled-operation-$operationId"
                LinuxFilesystemSyscalls.openPathAtOrNull(openedRoot.fd, name)?.close()
                    ?: journalFail("GCC bundled operation journal selected for recovery is absent")
                val openedDirectory = LinuxFilesystemSyscalls.openDirectoryAt(openedRoot.fd, name)
                directory = openedDirectory
                requireManagedDirectory(
                    LinuxFilesystemSyscalls.identity(openedDirectory.fd), openedRoot.identity, "GCC bundled operation journal",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedDirectory)) {
                    journalFail("GCC bundled operation journal is held by a live owner; later-invocation recovery refused")
                }
                directoryLocked = true
                requireRootBinding(root, parent, openedRoot)
                val intent = DescriptorBoundAtomicStateFile.readOrNull(openedDirectory, INTENT_FILE, MAXIMUM_INTENT_BYTES)
                    ?: journalFail("GCC stopped journal has no intent")
                val opened = GccBundledOperationJournal(
                    root.resolve(name), operationId, OracleArtifacts.sha256(expectedIntent), root,
                    parent, openedRoot, openedDirectory, intent,
                )
                journal = opened
                opened.restoreStopped(expectedIntent, deploymentClosureSha256)
                journal = null
                return opened
            } catch (failure: Throwable) {
                val opened = journal
                val cleanup = if (opened != null) runCatching { opened.close() }.exceptionOrNull()
                else closeJournalDescriptors(directory, rootDescriptor, parent, directoryLocked, rootLocked)
                cleanup?.let { if (it !== failure) failure.addSuppressed(it) }
                throw failure
            }
        }
    }

    private fun restoreStopped(expectedIntent: ByteArray, deploymentClosureSha256: String) {
        requireDirectoryBindings()
        // Only an exactly stopped history, or one whose single later-owner adoption was interrupted before any
        // resume record, is recoverable. A completed adoption or its complete atomic temporary is reused below.
        val adoptionName = when (LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_JOURNAL_ENTRIES + 1).toSet()) {
            STOPPED_FILES -> null
            STOPPED_FILES + RECOVERY_FILE -> RECOVERY_FILE
            STOPPED_FILES + RECOVERY_TEMPORARY_FILE -> RECOVERY_TEMPORARY_FILE
            else -> journalFail("GCC bundled journal contains unexpected residue before later-invocation recovery")
        }
        val read = STOPPED_FILES.associateWith { name ->
            (if (name == STATE_MANIFEST_FILE) {
                DescriptorBoundAtomicStateFile.readManifestOrNull(directory, name, maximumFileBytes(name))
            } else DescriptorBoundAtomicStateFile.readOrNull(directory, name, maximumFileBytes(name)))
                ?: journalFail("GCC stopped journal file disappeared: $name")
        }
        fun bytes(name: String) = read.getValue(name).bytes
        val intent = snapshots.getValue(INTENT_FILE)
        if (!MessageDigest.isEqual(bytes(INTENT_FILE), expectedIntent) || read.getValue(INTENT_FILE).identity != intent.identity ||
            !MessageDigest.isEqual(intent.bytes, expectedIntent)
        ) journalFail("GCC stopped journal intent differs from the later invocation's rebuilt intent")
        val leaseBytes = bytes(LEASE_FILE)
        val evidence = FullTreeDiskScratchEvidence.parseCanonical(leaseBytes)
        if (!MessageDigest.isEqual(evidence.canonicalBytes(), leaseBytes) ||
            evidence.operationId != operationId || evidence.requestSha256 != intentSha256
        ) journalFail("GCC stopped disk evidence belongs to a different operation intent")
        val definitionBytes = bytes(DEFINITION_FILE)
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definitionBytes)
        val runtime = definition.bundledRuntime ?: journalFail("GCC stopped operation lacks a bundled definition")
        if (definition.runKind != GccCompilerEngineContainmentRunKind.INTERRUPTED || runtime.invocationVersion != 3) {
            journalFail("GCC later-invocation recovery requires an interrupted v3 planning definition")
        }
        if (path.startsWith(definition.outputLease.path) || definition.outputLease.path.startsWith(path)) {
            journalFail("GCC bundled journal must remain outside its writable output")
        }
        if (!MessageDigest.isEqual(bytes(PREPARED_FILE), preparedRecordBytes(operationId, intentSha256,
                evidence.evidenceSha256, definitionBytes, definition.bindingSha256, deploymentClosureSha256))
        ) journalFail("GCC stopped prepared record differs from its definition, disk evidence or current deployment")
        fun linked(name: String, recordBytes: ByteArray, provider: String, previousBytes: ByteArray, payloadName: String?): ByteArray? {
            val record = OracleJson.parseCanonical(recordBytes, JOURNAL_JSON_LIMITS) as? JsonObject
                ?: journalFail("GCC stopped record is not an object: $name")
            val payload = payloadName?.let { field ->
                OracleJson.canonicalBytes(record[field] as? JsonObject ?: journalFail("GCC stopped record lacks $field: $name"),
                    JOURNAL_JSON_LIMITS)
            }
            if (!MessageDigest.isEqual(recordBytes,
                    linkedRecordBytes(operationId, intentSha256, provider, previousBytes, payloadName, payload))
            ) journalFail("GCC stopped record is not the exact linked successor of its predecessor: $name")
            return payload
        }
        fun linked(name: String, provider: String, previous: String, payloadName: String?) =
            linked(name, bytes(name), provider, bytes(previous), payloadName)
        val attachment = checkNotNull(linked(ATTACHMENT_FILE, "gcc-bundled-command-attached-v1", PREPARED_FILE, "attachment"))
        linked(START_FILE, "gcc-bundled-command-start-authorized-v1", ATTACHMENT_FILE, null)
        val authorization = checkNotNull(linked(INTERRUPT_FILE, "gcc-bundled-command-interrupt-authorized-v1", START_FILE, "authorization"))
        val execution = checkNotNull(linked(INTERRUPTED_FILE, "gcc-bundled-command-interrupted-v1", INTERRUPT_FILE, "execution"))
        val prefix = checkNotNull(linked(PREFIX_FILE, "gcc-bundled-command-prefix-assessed-v1", INTERRUPTED_FILE, "assessment"))
        val manifest = bytes(STATE_MANIFEST_FILE)
        val manifestDocument = OracleJson.parseCanonical(manifest, GccBundledAnalysisStateCapture.JSON_LIMITS) as? JsonObject
            ?: journalFail("GCC stopped state manifest is not an object")
        fun manifestCount(field: String) = (manifestDocument[field] as? JsonPrimitive)?.takeIf { !it.isString }
            ?.content?.toLongOrNull()?.takeIf { it > 0 } ?: journalFail("GCC stopped state manifest lacks a positive $field")
        val entryCount = manifestCount("entryCount")
        val totalBytes = manifestCount("totalBytes")
        val captured = OracleJson.parseCanonical(
            checkNotNull(linked(STATE_CAPTURED_FILE, "gcc-bundled-interrupted-state-captured-v1", PREFIX_FILE, "analysisState")),
            JOURNAL_JSON_LIMITS,
        ).jsonObject
        if (captured.keys != setOf("manifestSha256", "manifestBytes", "entryCount", "totalBytes", "operationWallTime") ||
            captured["manifestSha256"] != JsonPrimitive(OracleArtifacts.sha256(manifest)) ||
            captured["manifestBytes"] != JsonPrimitive(manifest.size) || captured["entryCount"] != JsonPrimitive(entryCount) ||
            captured["totalBytes"] != JsonPrimitive(totalBytes)
        ) journalFail("GCC stopped state record differs from its retained manifest or lacks its committed wall budget")
        val executed = OracleJson.parseCanonical(execution, JOURNAL_JSON_LIMITS).jsonObject
        if (executed["provider"]?.jsonPrimitive?.content?.matches(Regex("kotlin-lease-contained-command-interrupted-v[12]")) != true ||
            listOf("unitAbsent", "cgroupAbsent", "processesAbsent").any { executed[it] != JsonPrimitive(true) } ||
            executed["interruptionAuthorizationSha256"] != JsonPrimitive(OracleArtifacts.sha256(authorization))
        ) journalFail("GCC stopped execution does not durably prove worker absence after its authorized interruption")
        requireBoundInterruptedReceipts(definition, deploymentClosureSha256, attachment, authorization, execution)
        // The resume allowance comes only from the wall snapshot committed with the stopped state, never from the
        // earlier execution receipt: prefix and state capture after worker exit are charged to the operation.
        val executedWall = operationWallSnapshot(executed["operationWallTime"], "GCC stopped execution")
        val stoppedWall = operationWallSnapshot(captured["operationWallTime"], "GCC stopped state commit")
        if (executedWall.maximumWallMillis != definition.budgets.wallClockMillis ||
            stoppedWall.maximumWallMillis != definition.budgets.wallClockMillis ||
            stoppedWall.startedMonotonicNanos != executedWall.startedMonotonicNanos ||
            stoppedWall.elapsedNanos < executedWall.elapsedNanos
        ) journalFail("GCC stopped state wall budget is not the interrupted operation's own later snapshot")
        val wallCap = minOf(definition.budgets.wallClockMillis, stoppedWall.remainingNanos / 1_000_000_000L * 1_000L)
        val stateRecord = bytes(STATE_CAPTURED_FILE)
        val adoption = when (adoptionName) {
            null -> null
            RECOVERY_FILE -> DescriptorBoundAtomicStateFile.readOrNull(directory, RECOVERY_FILE, maximumFileBytes(RECOVERY_FILE))
                ?: journalFail("GCC retained later-invocation adoption disappeared")
            else -> DescriptorBoundAtomicStateFile.inspectOrNull(directory, RECOVERY_TEMPORARY_FILE, maximumFileBytes(RECOVERY_FILE))
                ?.also { pendingAdoption = it }?.snapshot()
                ?: journalFail("GCC retained later-invocation adoption temporary disappeared")
        }
        val adoptionPayload = adoption?.let { retained ->
            checkNotNull(linked(RECOVERY_FILE, retained.bytes, RECOVERY_RECORD_PROVIDER, stateRecord, "recovery")).also {
                requireRecoveryPayload(it, stateRecord, wallCap)
            }
        }
        snapshots.clear()
        read.forEach { (name, snapshot) -> snapshots[name] = snapshot }
        if (adoptionName == RECOVERY_FILE) snapshots[RECOVERY_FILE] = checkNotNull(adoption)
        diskEvidenceSha256 = evidence.evidenceSha256
        stage = if (adoptionName == RECOVERY_FILE) JournalStage.RECOVERY_ADOPTED else JournalStage.STATE_CAPTURED
        recoveredStopped = GccBundledStoppedJournalEvidence(evidence, definitionBytes, authorization,
            bytes(INTERRUPTED_FILE), execution, bytes(PREFIX_FILE), prefix, manifest, stateRecord,
            entryCount, totalBytes, stoppedWall.remainingNanos, wallCap, adoptionPayload)
        requireCurrent("after later-invocation recovery reopen")
    }

    private fun requirePendingAdoptionCurrent(pending: DescriptorBoundStateInspection, label: String) {
        val current = DescriptorBoundAtomicStateFile.readOrNull(directory, RECOVERY_TEMPORARY_FILE, maximumFileBytes(RECOVERY_FILE))
            ?: journalFail("GCC retained later-invocation adoption temporary disappeared $label")
        if (current.identity != pending.identity || !MessageDigest.isEqual(current.bytes, pending.bytes)) {
            journalFail("GCC retained later-invocation adoption temporary changed $label")
        }
    }

    private fun requireRecoveryPayload(payload: ByteArray, stateRecord: ByteArray, wallCapMillis: Long) {
        val recovery = OracleJson.parseCanonical(payload, JOURNAL_JSON_LIMITS) as? JsonObject
            ?: journalFail("GCC recovery record payload is not an object")
        val budget = (recovery["resumeWallBudgetMillis"] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
        if (recovery["provider"] != JsonPrimitive(RECOVERY_PAYLOAD_PROVIDER) || recovery["schemaVersion"] != JsonPrimitive(1) ||
            recovery["operationId"] != JsonPrimitive(operationId) || recovery["intentSha256"] != JsonPrimitive(intentSha256) ||
            recovery["stoppedStateRecordSha256"] != JsonPrimitive(OracleArtifacts.sha256(stateRecord)) ||
            recovery["complete"] != JsonPrimitive(false) || recovery["releaseEligible"] != JsonPrimitive(false) ||
            budget == null || budget % 1_000L != 0L || budget < 2_000L || budget > wallCapMillis
        ) journalFail("GCC recovery record differs from its reopened stopped operation or exceeds its committed wall budget")
    }
}

/** Exact stopped records parsed from a reopened journal. They grant no START until a live lease is held. */
internal class GccBundledStoppedJournalEvidence(
    val diskEvidence: FullTreeDiskScratchEvidence,
    definitionBytes: ByteArray,
    interruptAuthorizationBytes: ByteArray,
    interruptedRecordBytes: ByteArray,
    interruptedExecutionBytes: ByteArray,
    prefixRecordBytes: ByteArray,
    prefixAssessmentBytes: ByteArray,
    stateManifestBytes: ByteArray,
    stateRecordBytes: ByteArray,
    val stateEntryCount: Long,
    val stateTotalBytes: Long,
    /** Remaining whole-operation budget sampled immediately before the stopped state was committed. */
    val stoppedRemainingNanos: Long,
    /** Whole-second resume allowance derived from that commit snapshot and the operation's own budget. */
    val recoveryWallCapMillis: Long,
    retainedAdoptionPayloadBytes: ByteArray?,
) {
    private val definition = definitionBytes.copyOf()
    private val authorization = interruptAuthorizationBytes.copyOf()
    private val interruptedRecord = interruptedRecordBytes.copyOf()
    private val interruptedExecution = interruptedExecutionBytes.copyOf()
    private val prefixRecord = prefixRecordBytes.copyOf()
    private val prefixAssessment = prefixAssessmentBytes.copyOf()
    private val stateManifest = stateManifestBytes.copyOf()
    private val stateRecord = stateRecordBytes.copyOf()
    private val retainedAdoption = retainedAdoptionPayloadBytes?.copyOf()
    val definitionBytes: ByteArray get() = definition.copyOf()
    val interruptAuthorizationBytes: ByteArray get() = authorization.copyOf()
    val interruptedRecordBytes: ByteArray get() = interruptedRecord.copyOf()
    val interruptedExecutionBytes: ByteArray get() = interruptedExecution.copyOf()
    val prefixRecordBytes: ByteArray get() = prefixRecord.copyOf()
    val prefixAssessmentBytes: ByteArray get() = prefixAssessment.copyOf()
    val stateManifestBytes: ByteArray get() = stateManifest.copyOf()
    val stateRecordBytes: ByteArray get() = stateRecord.copyOf()
    /** The single adoption a crashed later owner already recorded (published or complete temporary), if any. */
    val retainedAdoptionPayloadBytes: ByteArray? get() = retainedAdoption?.copyOf()
}

private class GccOperationWallSnapshot(
    val maximumWallMillis: Long, val startedMonotonicNanos: Long, val elapsedNanos: Long, val remainingNanos: Long,
)

/** Shape of one ContainedCommandOperationDeadline snapshot; this restores no deadline or authority. */
private fun operationWallSnapshot(value: JsonElement?, label: String): GccOperationWallSnapshot {
    val wall = value as? JsonObject ?: journalFail("$label has no operation wall-budget snapshot")
    fun number(name: String) = (wall[name] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
        ?: journalFail("$label wall-budget snapshot lacks $name")
    if (wall.keys != setOf("provider", "maximumWallMillis", "startedMonotonicNanos", "elapsedNanos", "remainingNanos") ||
        wall["provider"] != JsonPrimitive("kotlin-contained-operation-wall-deadline-v1")
    ) journalFail("$label wall-budget snapshot is not an operation deadline snapshot")
    val snapshot = GccOperationWallSnapshot(number("maximumWallMillis"), number("startedMonotonicNanos"),
        number("elapsedNanos"), number("remainingNanos"))
    if (snapshot.maximumWallMillis !in 2_000L..86_400_000L || snapshot.maximumWallMillis % 1_000L != 0L ||
        snapshot.elapsedNanos < 0L || snapshot.remainingNanos <= 0L ||
        snapshot.elapsedNanos + snapshot.remainingNanos != snapshot.maximumWallMillis * 1_000_000L
    ) journalFail("$label wall-budget snapshot is inconsistent or expired")
    return snapshot
}

/**
 * Binds the stopped absence receipt to this operation's own interrupted command: the attachment must name the
 * definition's unit, cgroup, nonce and deployment, and the execution, authorization and HMAC-checked outcome
 * must all name that attachment's request and keeper.
 */
private fun requireBoundInterruptedReceipts(
    definition: GccCompilerEngineValidatedContainmentDefinition,
    deploymentClosureSha256: String,
    attachmentBytes: ByteArray,
    authorizationBytes: ByteArray,
    executionBytes: ByteArray,
) {
    fun document(bytes: ByteArray) = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) as? JsonObject
        ?: journalFail("GCC stopped receipt is not an object")
    fun selfHashed(record: JsonObject, field: String) =
        record[field] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - field), JOURNAL_JSON_LIMITS)))
    val attachment = document(attachmentBytes)
    val authorization = document(authorizationBytes)
    val execution = document(executionBytes)
    val outcome = execution["outcome"] as? JsonObject ?: journalFail("GCC stopped execution has no command outcome")
    val request = (attachment["requestSha256"] as? JsonPrimitive)?.takeIf { it.isString && it.content.matches(Regex("[a-f0-9]{64}")) }
        ?: journalFail("GCC stopped attachment has no command request")
    val keeper = (authorization["keeperPid"] as? JsonPrimitive)?.takeIf { !it.isString }
        ?: journalFail("GCC stopped interruption has no keeper identity")
    val keepers = (attachment["processes"] as? JsonArray)?.map { it as? JsonObject ?: journalFail("GCC stopped attachment process is invalid") }
        ?.filter { it["role"] == JsonPrimitive("supervisor-jvm") } ?: journalFail("GCC stopped attachment has no process population")
    if (attachment["provider"]?.jsonPrimitive?.content?.matches(Regex("kotlin-lease-contained-command-attachment-v[12]")) != true ||
        !selfHashed(attachment, "attachmentSha256") ||
        attachment["unitName"] != JsonPrimitive(definition.unitName) ||
        attachment["controlGroup"] != JsonPrimitive(definition.expectedControlGroup) ||
        attachment["nonce"] != JsonPrimitive(definition.bindingSha256) ||
        attachment["deploymentClosureSha256"] != JsonPrimitive(deploymentClosureSha256) ||
        keepers.size != 1 || (keepers.single()["namespacePids"] as? JsonArray)?.lastOrNull() != keeper ||
        authorization["provider"] != JsonPrimitive("kotlin-contained-command-interrupt-authorization-v1") ||
        !selfHashed(authorization, "authorizationSha256") || authorization["requestSha256"] != request ||
        !selfHashed(execution, "executionSha256") ||
        execution["attachmentSha256"] != JsonPrimitive(OracleArtifacts.sha256(attachmentBytes)) ||
        execution["requestSha256"] != request ||
        execution["deploymentClosureSha256"] != JsonPrimitive(deploymentClosureSha256) ||
        execution["interruptionAuthorization"] != authorization ||
        execution["outcomeSha256"] != JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome, JOURNAL_JSON_LIMITS))) ||
        outcome["event"] != JsonPrimitive("OUTCOME") || outcome["status"] != JsonPrimitive("INTERRUPTED") ||
        outcome["keeperPid"] != keeper || outcome["requestSha256"] != request ||
        outcome["nonce"] != JsonPrimitive(definition.bindingSha256)
    ) journalFail("GCC stopped absence receipt is not bound to this operation's interrupted command")
}

private fun preparedRecordBytes(operationId: String, intentSha256: String, diskEvidenceSha256: String,
    definitionBytes: ByteArray, definitionBindingSha256: String, deploymentClosureSha256: String): ByteArray {
    val unsigned = JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-prepared-operation-v1"),
        "schemaVersion" to JsonPrimitive(1),
        "operationId" to JsonPrimitive(operationId),
        "intentSha256" to JsonPrimitive(intentSha256),
        "diskEvidenceSha256" to JsonPrimitive(diskEvidenceSha256),
        "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(definitionBytes)),
        "definitionBindingSha256" to JsonPrimitive(definitionBindingSha256),
        "deploymentClosureSha256" to JsonPrimitive(deploymentClosureSha256),
    ))
    return OracleJson.canonicalBytes(
        JsonObject(unsigned + ("preparedSha256" to JsonPrimitive(
            OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, JOURNAL_JSON_LIMITS)),
        ))),
        JOURNAL_JSON_LIMITS,
    )
}

/** The single linked-record encoding shared by publication and later-invocation reconstruction. */
private fun linkedRecordBytes(operationId: String, intentSha256: String, provider: String, previousBytes: ByteArray,
    payloadName: String?, payloadBytes: ByteArray?): ByteArray {
    val fields = linkedMapOf<String, JsonElement>(
        "provider" to JsonPrimitive(provider),
        "schemaVersion" to JsonPrimitive(1),
        "operationId" to JsonPrimitive(operationId),
        "intentSha256" to JsonPrimitive(intentSha256),
        "previousSha256" to JsonPrimitive(OracleArtifacts.sha256(previousBytes)),
        "complete" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
    )
    if (payloadName != null) {
        val bytes = boundedCopy(requireNotNull(payloadBytes), MAXIMUM_INTENT_BYTES, "GCC command record")
        val payload = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS)
        require(payload is JsonObject) { "GCC command payload must be a canonical object" }
        fields[payloadName] = payload
        fields["${payloadName}Sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
    }
    fields["recordSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields), JOURNAL_JSON_LIMITS)))
    return OracleJson.canonicalBytes(JsonObject(fields), JOURNAL_JSON_LIMITS)
}

private fun requireRootBinding(path: Path, parent: LinuxDescriptor, root: LinuxDescriptor) {
    val currentParent = LinuxFilesystemSyscalls.identity(parent.fd)
    val uid = currentUid()
    if (
        !sameDirectory(currentParent, parent.identity) || currentParent.uid !in setOf(0, uid) ||
        currentParent.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0 ||
        path.parent.toRealPath() != path.parent ||
        !Files.isSameFile(path.parent, LinuxFilesystemSyscalls.descriptorPath(parent))
    ) journalFail("GCC bundled journal root has an untrusted or changed parent")
    val currentRoot = LinuxFilesystemSyscalls.identity(root.fd)
    requireManagedDirectory(currentRoot, root.identity, "GCC bundled journal root")
    if (!sameDirectory(currentRoot, root.identity)) journalFail("GCC bundled journal root changed identity")
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString()).use { selected ->
        if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
            journalFail("GCC bundled journal root name changed identity")
        }
    }
    if (path.toRealPath() != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(root))) {
        journalFail("GCC bundled journal root pathname changed")
    }
}

private fun requireManagedDirectory(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    val uid = currentUid()
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.mountId != parent.mountId || actual.uid != uid || parent.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not an owner-only directory on its authorized filesystem")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId && first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory && !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun boundedCopy(bytes: ByteArray, maximumBytes: Int, label: String): ByteArray {
    require(bytes.isNotEmpty() && bytes.size <= maximumBytes) { "$label exceeds its byte bound" }
    return bytes.copyOf()
}

private fun maximumFileBytes(name: String): Int =
    when (name) {
        DEFINITION_FILE, RESUME_DEFINITION_FILE -> MAXIMUM_DEFINITION_BYTES
        STATE_MANIFEST_FILE -> GccBundledAnalysisStateCapture.JSON_LIMITS.maximumCanonicalBytes
        else -> MAXIMUM_INTENT_BYTES
    }

private fun closeJournalDescriptors(
    directory: LinuxDescriptor?,
    root: LinuxDescriptor?,
    parent: LinuxDescriptor,
    directoryLocked: Boolean = true,
    rootLocked: Boolean = true,
): Throwable? {
    var failure: Throwable? = null
    fun attempt(action: () -> Unit) {
        runCatching(action).exceptionOrNull()?.let { next ->
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
    }
    if (directory != null) {
        if (directoryLocked) attempt { LinuxFilesystemSyscalls.unlock(directory) }
        attempt { directory.close() }
    }
    if (root != null) {
        if (rootLocked) attempt { LinuxFilesystemSyscalls.unlock(root) }
        attempt { root.close() }
    }
    attempt { parent.close() }
    return failure
}

private fun journalFail(message: String): Nothing = throw IllegalArgumentException(message)

private enum class JournalStage { INTENT, LEASED, DEFINITION_STAGED, PREPARED, ATTACHED, START_AUTHORIZED, EXECUTED, EXPORT_ASSESSED, INTERRUPT_AUTHORIZED, INTERRUPTED, PREFIX_ASSESSED, STATE_MANIFEST_STAGED, STATE_CAPTURED, RECOVERY_ADOPTED, RESUME_DEFINITION_STAGED, RESUME_PREPARED, RESUME_ATTACHED, RESUME_START_AUTHORIZED, RESUME_EXECUTED, RESUME_EXPORT_ASSESSED, PLANNER_REQUEST_STAGED, PLANNER_PREPARED, PLANNER_ATTACHED, PLANNER_START_AUTHORIZED, PLANNER_EXECUTED, PLANNER_ASSESSED }
private const val INTENT_FILE = "intent.json"
private const val LEASE_FILE = "lease-evidence.json"
private const val DEFINITION_FILE = "definition.json"
private const val PREPARED_FILE = "prepared.json"
private const val ATTACHMENT_FILE = "attachment.json"
private const val START_FILE = "start-authorized.json"
private const val EXECUTION_FILE = "execution.json"
private const val EXPORT_FILE = "export-assessment.json"
private const val INTERRUPT_FILE = "interrupt-authorized.json"
private const val INTERRUPTED_FILE = "interrupted-execution.json"
private const val PREFIX_FILE = "interrupted-prefix-assessment.json"
private const val STATE_MANIFEST_FILE = "analysis-state-manifest.json"
private const val STATE_CAPTURED_FILE = "analysis-state-captured.json"
private const val RECOVERY_FILE = "recovery-adopted.json"
private const val RECOVERY_TEMPORARY_FILE = ".recovery-adopted.json.atomic"
private const val RECOVERY_RECORD_PROVIDER = "gcc-bundled-later-invocation-recovery-adopted-v1"
internal const val RECOVERY_PAYLOAD_PROVIDER = "gcc-bundled-later-invocation-recovery-v1"
private const val RESUME_DEFINITION_FILE = "resume-definition.json"
private const val RESUME_PREPARED_FILE = "resume-prepared.json"
private const val RESUME_ATTACHMENT_FILE = "resume-attachment.json"
private const val RESUME_START_FILE = "resume-start-authorized.json"
private const val RESUME_EXECUTION_FILE = "resume-execution.json"
private const val RESUME_EXPORT_FILE = "resume-export-assessment.json"
private val STOPPED_FILES = setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE,
    START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE, STATE_MANIFEST_FILE, STATE_CAPTURED_FILE)
private val RESUME_FILES = listOf(RESUME_DEFINITION_FILE, RESUME_PREPARED_FILE, RESUME_ATTACHMENT_FILE,
    RESUME_START_FILE, RESUME_EXECUTION_FILE, RESUME_EXPORT_FILE)
private val RESUME_STAGES = listOf(JournalStage.RESUME_DEFINITION_STAGED, JournalStage.RESUME_PREPARED,
    JournalStage.RESUME_ATTACHED, JournalStage.RESUME_START_AUTHORIZED, JournalStage.RESUME_EXECUTED,
    JournalStage.RESUME_EXPORT_ASSESSED)
private const val PLANNER_REQUEST_FILE = "planner-request.json"
private const val PLANNER_PREPARED_FILE = "planner-prepared.json"
private const val PLANNER_ATTACHMENT_FILE = "planner-attachment.json"
private const val PLANNER_START_FILE = "planner-start-authorized.json"
private const val PLANNER_EXECUTION_FILE = "planner-execution.json"
private const val PLANNER_ASSESSMENT_FILE = "planner-assessment.json"
private val PLANNER_FILES = listOf(PLANNER_REQUEST_FILE, PLANNER_PREPARED_FILE, PLANNER_ATTACHMENT_FILE,
    PLANNER_START_FILE, PLANNER_EXECUTION_FILE, PLANNER_ASSESSMENT_FILE)
private val PLANNER_STAGES = listOf(JournalStage.PLANNER_REQUEST_STAGED, JournalStage.PLANNER_PREPARED,
    JournalStage.PLANNER_ATTACHED, JournalStage.PLANNER_START_AUTHORIZED, JournalStage.PLANNER_EXECUTED, JournalStage.PLANNER_ASSESSED)
private const val OWNER_DIRECTORY_MODE = 0x1c0
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12
private const val MAXIMUM_JOURNAL_ENTRIES = 24
private const val MAXIMUM_INTENT_BYTES = 256 * 1024
private const val MAXIMUM_DEFINITION_BYTES = 1024 * 1024
private val JOURNAL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_INTENT_BYTES,
    maximumCanonicalBytes = MAXIMUM_INTENT_BYTES,
    maximumDepth = 24,
    maximumNodes = 10_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = MAXIMUM_INTENT_BYTES,
)

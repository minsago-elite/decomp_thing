package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccCompilerEngineResumeEvidenceException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

private data class ParsedExporterState(
    val artifactBytes: Int,
    val artifactSha256: String,
    val exporterVersion: Int,
    val exporterSha256: String,
    val analysisToolSha256: String,
    val recoveryMode: String,
    val inputSha256: String,
    val language: String,
    val compilerSpec: String,
    val functionCount: Long,
    val planningBatchCount: Long,
    val canonicalBytes: Long,
    val semanticSha256: String,
    val batchCommitmentSha256: String,
)

private data class ParsedExportProgress(
    val artifactBytes: Int,
    val artifactSha256: String,
    val stateSha256: String,
    val phase: String,
    val completed: Long,
    val total: Long,
    val recovered: Long,
    val partial: Long,
    val failed: Long,
    val reused: Long,
)

internal data class GccResumeByteValidationLimits(
    val exporterStateBytes: Int = MAXIMUM_EXPORT_STATE_BYTES,
    val progressBytes: Int = MAXIMUM_PROGRESS_BYTES,
    val checkpointBytes: Int = MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES,
    val planningFragmentBytes: Int = MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES,
    val aggregateFragmentBytes: Long = MAXIMUM_RETAINED_FRAGMENT_BYTES,
    val assembledModelBytes: Int = MAXIMUM_PROGRAM_MODEL_BYTES,
    val modulePlanBytes: Int = MAXIMUM_MODULE_PLAN_BYTES,
    val transitionAggregateBytes: Long = MAXIMUM_TRANSITION_CAPTURE_BYTES,
) {
    init {
        require(exporterStateBytes in 1..MAXIMUM_EXPORT_STATE_BYTES)
        require(progressBytes in 1..MAXIMUM_PROGRESS_BYTES)
        require(checkpointBytes in 1..MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES)
        require(planningFragmentBytes in 1..MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES)
        require(aggregateFragmentBytes in 1..MAXIMUM_RETAINED_FRAGMENT_BYTES)
        require(assembledModelBytes in 1..MAXIMUM_PROGRAM_MODEL_BYTES)
        require(modulePlanBytes in 1..MAXIMUM_MODULE_PLAN_BYTES)
        require(transitionAggregateBytes in 1..MAXIMUM_TRANSITION_CAPTURE_BYTES)
    }
}

private class CapturedPlanningBatch(
    val checkpoint: ByteArray,
    val functions: ByteArray,
    val globals: ByteArray,
    val types: ByteArray,
    val failures: ByteArray,
)

private class CapturedRun(
    val state: ByteArray,
    val progress: ByteArray,
    val batches: List<CapturedPlanningBatch>,
    val programModel: ByteArray,
)

private class CapturedInterruptedPrefix(
    val state: ByteArray,
    val progress: ByteArray,
    val batches: List<CapturedPlanningBatch>,
)

private class CaptureBudget(private val maximumBytes: Long) {
    private var retainedBytes = 0L

    fun charge(bytes: Int, label: String) {
        retainedBytes = addExactBounded(retainedBytes, bytes.toLong(), maximumBytes, label)
    }
}

private data class BoundRecord(val id: String, val bytes: ByteArray)
private data class SemanticBinding(val canonicalBytes: Long, val sha256: String)

private fun snapshotBounded(
    raw: ByteArray,
    maximumBytes: Int,
    allowEmpty: Boolean,
    label: String,
): ByteArray {
    requireBoundedBytes(raw, maximumBytes, allowEmpty, label)
    return raw.copyOf()
}

private fun snapshotBounded(
    raw: ByteArray,
    maximumBytes: Int,
    allowEmpty: Boolean,
    label: String,
    captureBudget: CaptureBudget?,
): ByteArray {
    requireBoundedBytes(raw, maximumBytes, allowEmpty, label)
    captureBudget?.charge(raw.size, "transition capture bytes")
    return raw.copyOf()
}

private fun capturePlanningBatches(
    rawBatches: List<GccPlanningBatchBytes>,
    limits: GccResumeByteValidationLimits,
    leg: String,
    captureBudget: CaptureBudget?,
): List<CapturedPlanningBatch> {
    val declaredBatchCount = try {
        rawBatches.size
    } catch (failure: RuntimeException) {
        throw GccCompilerEngineResumeEvidenceException("$leg raw planning batch count cannot be read", failure)
    }
    if (declaredBatchCount !in 1..MAXIMUM_PLANNING_BATCHES.toInt()) {
        resumeValidationFailure("$leg has an invalid raw planning batch count")
    }
    val stableBatches = ArrayList<GccPlanningBatchBytes>(declaredBatchCount)
    try {
        val iterator = rawBatches.iterator()
        while (iterator.hasNext()) {
            if (stableBatches.size >= MAXIMUM_PLANNING_BATCHES) {
                resumeValidationFailure("$leg raw planning batch iterator exceeds its hard count bound")
            }
            val next: GccPlanningBatchBytes? = iterator.next()
            stableBatches += next ?: resumeValidationFailure("$leg raw planning batch iterator contains null")
        }
    } catch (failure: GccCompilerEngineResumeEvidenceException) {
        throw failure
    } catch (failure: RuntimeException) {
        throw GccCompilerEngineResumeEvidenceException("$leg raw planning batch list changed during capture", failure)
    }
    if (stableBatches.size != declaredBatchCount) {
        resumeValidationFailure("$leg raw planning batch declared and observed counts differ")
    }

    var retainedBytes = 0L
    val batches = ArrayList<CapturedPlanningBatch>(stableBatches.size)
    stableBatches.forEach { raw ->
        fun captureArtifact(bytes: ByteArray, maximum: Int, allowEmpty: Boolean, label: String): ByteArray {
            requireBoundedBytes(bytes, maximum, allowEmpty, label)
            retainedBytes = addExactBounded(
                retainedBytes,
                bytes.size.toLong(),
                limits.aggregateFragmentBytes,
                "$leg retained planning bytes",
            )
            captureBudget?.charge(bytes.size, "transition capture bytes")
            return bytes.copyOf()
        }
        batches += CapturedPlanningBatch(
            checkpoint = captureArtifact(raw.checkpoint, limits.checkpointBytes, false, "$leg planning checkpoint"),
            functions = captureArtifact(raw.functions, limits.planningFragmentBytes, false, "$leg function fragment"),
            globals = captureArtifact(raw.globals, limits.planningFragmentBytes, true, "$leg global fragment"),
            types = captureArtifact(raw.types, limits.planningFragmentBytes, true, "$leg type fragment"),
            failures = captureArtifact(raw.failures, limits.planningFragmentBytes, true, "$leg failure fragment"),
        )
    }
    return immutableList(batches)
}

private fun captureRun(
    rawState: ByteArray,
    rawProgress: ByteArray,
    rawBatches: List<GccPlanningBatchBytes>,
    rawProgramModel: ByteArray,
    limits: GccResumeByteValidationLimits,
    leg: String = "completed run",
    captureBudget: CaptureBudget? = null,
): CapturedRun {
    return CapturedRun(
        state = snapshotBounded(rawState, limits.exporterStateBytes, false, "$leg exporter state", captureBudget),
        progress = snapshotBounded(rawProgress, limits.progressBytes, false, "$leg export progress", captureBudget),
        batches = capturePlanningBatches(rawBatches, limits, leg, captureBudget),
        programModel = snapshotBounded(
            rawProgramModel,
            limits.assembledModelBytes,
            false,
            "$leg program model",
            captureBudget,
        ),
    )
}

private fun captureInterruptedPrefix(
    rawState: ByteArray,
    rawProgress: ByteArray,
    rawBatches: List<GccPlanningBatchBytes>,
    limits: GccResumeByteValidationLimits,
    captureBudget: CaptureBudget? = null,
): CapturedInterruptedPrefix = CapturedInterruptedPrefix(
    state = snapshotBounded(
        rawState,
        limits.exporterStateBytes,
        false,
        "interrupted exporter state",
        captureBudget,
    ),
    progress = snapshotBounded(
        rawProgress,
        limits.progressBytes,
        false,
        "interrupted export progress",
        captureBudget,
    ),
    batches = capturePlanningBatches(rawBatches, limits, "interrupted prefix", captureBudget),
)

private fun parseExporterState(bytes: ByteArray, limits: GccResumeByteValidationLimits): ParsedExporterState {
    requireBoundedBytes(bytes, limits.exporterStateBytes, allowEmpty = false, "exporter state")
    requireExactLine(bytes, "exporter state")
    val root = strictObject(bytes, limits.exporterStateBytes, "exporter state")
    root.requireExactKeys(
        setOf(
            "schemaVersion", "exporterVersion", "exporterSha256", "analysisToolSha256", "recoveryMode",
            "inputSha256", "language", "compilerSpec", "semanticStateBinding",
        ),
        "exporter state",
    )
    if (root.longValue("schemaVersion", "exporter state") != 2L) {
        resumeValidationFailure("exporter state does not use schema version 2")
    }
    val semantic = root.objectValue("semanticStateBinding", "exporter state")
    semantic.requireExactKeys(
        setOf(
            "schemaVersion", "scope", "functionCount", "planningBatchCount", "canonicalBytes", "sha256",
            "batchCommitmentSha256",
        ),
        "exporter semantic state",
    )
    if (semantic.longValue("schemaVersion", "exporter semantic state") != 1L ||
        semantic.stringValue("scope", "exporter semantic state") != "planning-exporter-visible-program"
    ) resumeValidationFailure("exporter semantic state uses an unsupported schema or scope")
    val functionCount = semantic.longValue("functionCount", "exporter semantic state")
    val planningBatchCount = semantic.longValue("planningBatchCount", "exporter semantic state")
    val canonicalBytes = semantic.longValue("canonicalBytes", "exporter semantic state")
    if (functionCount !in 1..MAXIMUM_FUNCTIONS || planningBatchCount != ceilingBatchCount(functionCount) ||
        planningBatchCount !in 1..MAXIMUM_PLANNING_BATCHES || canonicalBytes !in 1..MAXIMUM_SEMANTIC_BYTES
    ) resumeValidationFailure("exporter semantic state counts exceed or disagree with supported bounds")
    val recoveryMode = root.stringValue("recoveryMode", "exporter state")
    if (recoveryMode != "planning") resumeValidationFailure("exporter state recovery mode is not planning")
    val exporterVersion = root.intValue("exporterVersion", "exporter state")
    if (exporterVersion != SUPPORTED_EXPORTER_VERSION) {
        resumeValidationFailure("exporter state uses an unsupported exporter version")
    }
    val state = ParsedExporterState(
        artifactBytes = bytes.size,
        artifactSha256 = OracleArtifacts.sha256(bytes),
        exporterVersion = exporterVersion,
        exporterSha256 = requireSha256(root.stringValue("exporterSha256", "exporter state"), "exporter state"),
        analysisToolSha256 = requireSha256(
            root.stringValue("analysisToolSha256", "exporter state"),
            "analysis tool",
        ),
        recoveryMode = recoveryMode,
        inputSha256 = requireSha256(root.stringValue("inputSha256", "exporter state"), "exporter input"),
        language = requireIdentity(root.stringValue("language", "exporter state"), "exporter language"),
        compilerSpec = requireIdentity(root.stringValue("compilerSpec", "exporter state"), "compiler specification"),
        functionCount = functionCount,
        planningBatchCount = planningBatchCount,
        canonicalBytes = canonicalBytes,
        semanticSha256 = requireSha256(semantic.stringValue("sha256", "exporter semantic state"), "semantic state"),
        batchCommitmentSha256 = requireSha256(
            semantic.stringValue("batchCommitmentSha256", "exporter semantic state"),
            "semantic batch commitment",
        ),
    )
    requireExactBytes(bytes, renderExporterState(state), "exporter state")
    return state
}

private fun ParsedExporterState.assessment(): GccExporterStateAssessment = GccExporterStateAssessment(
    authority = NON_AUTHORITATIVE_ASSESSMENT,
    artifactBytes = artifactBytes,
    artifactSha256 = artifactSha256,
    functionCount = functionCount,
    planningBatchCount = planningBatchCount,
    semanticCanonicalBytes = canonicalBytes,
    semanticSha256 = semanticSha256,
    batchCommitmentSha256 = batchCommitmentSha256,
)

private fun parseExportProgress(
    state: ParsedExporterState,
    bytes: ByteArray,
    limits: GccResumeByteValidationLimits,
): ParsedExportProgress {
    requireBoundedBytes(bytes, limits.progressBytes, allowEmpty = false, "export progress")
    requireExactLine(bytes, "export progress")
    val root = strictObject(bytes, limits.progressBytes, "export progress")
    root.requireExactKeys(
        setOf(
            "schemaVersion", "phase", "completed", "total", "recovered", "partial", "failed", "reused",
            "currentFunction",
        ),
        "export progress",
    )
    if (root.longValue("schemaVersion", "export progress") != 1L || root["currentFunction"] !is JsonNull) {
        resumeValidationFailure("export progress schema or current-function boundary is invalid")
    }
    val completed = root.longValue("completed", "export progress")
    val total = root.longValue("total", "export progress")
    val recovered = root.longValue("recovered", "export progress")
    val partial = root.longValue("partial", "export progress")
    val failed = root.longValue("failed", "export progress")
    val reused = root.longValue("reused", "export progress")
    val phase = root.stringValue("phase", "export progress")
    if (phase !in setOf("planning", "complete")) resumeValidationFailure("export progress phase is unsupported")
    if (total != state.functionCount || recovered != 0L || completed !in 0..total || reused !in 0..completed ||
        exactAdd("export progress recovery counts", partial, failed) != completed ||
        !isContiguousPrefixPosition(completed, total) || !isContiguousPrefixPosition(reused, total) ||
        (phase == "complete" && completed != total)
    ) resumeValidationFailure("export progress is impossible for its raw exporter state")
    val progress = ParsedExportProgress(
        artifactBytes = bytes.size,
        artifactSha256 = OracleArtifacts.sha256(bytes),
        stateSha256 = state.artifactSha256,
        phase = phase,
        completed = completed,
        total = total,
        recovered = recovered,
        partial = partial,
        failed = failed,
        reused = reused,
    )
    requireExactBytes(bytes, renderExportProgress(progress), "export progress")
    return progress
}

private fun ParsedExportProgress.assessment(): GccExportProgressAssessment = GccExportProgressAssessment(
    authority = NON_AUTHORITATIVE_ASSESSMENT,
    artifactBytes = artifactBytes,
    artifactSha256 = artifactSha256,
    stateSha256 = stateSha256,
    phase = phase,
    completed = completed,
    total = total,
    partial = partial,
    failed = failed,
    reused = reused,
)

private fun isContiguousPrefixPosition(position: Long, total: Long): Boolean =
    position == total || position % PLANNING_BATCH_FUNCTIONS == 0L

private fun parsePlanningBatch(
    state: ParsedExporterState,
    captured: CapturedPlanningBatch,
    limits: GccResumeByteValidationLimits,
): ParsedPlanningBatch {
    val text = strictUtf8(captured.checkpoint, "planning checkpoint")
    if (!text.endsWith('\n') || '\r' in text || '\u0000' in text) {
        resumeValidationFailure("planning checkpoint is not canonical newline-terminated UTF-8")
    }
    val lines = text.dropLast(1).split('\n')
    if (lines.size != PLANNING_CHECKPOINT_KEYS.size) {
        resumeValidationFailure("planning checkpoint has an unexpected field count")
    }
    val values = LinkedHashMap<String, String>()
    lines.forEachIndexed { index, line ->
        val key = PLANNING_CHECKPOINT_KEYS[index]
        if (!line.startsWith("$key=")) resumeValidationFailure("planning checkpoint field order or name differs")
        val value = line.substring(key.length + 1)
        if ('=' in value || value.any { it.code < 0x20 || it.code == 0x7f }) {
            resumeValidationFailure("planning checkpoint contains a non-canonical field value")
        }
        values[key] = value
    }
    if (values.getValue("schemaVersion") != "1" || values.getValue("recoveryMode") != "planning") {
        resumeValidationFailure("planning checkpoint uses an unsupported schema or recovery mode")
    }
    val exporterVersion = canonicalNonnegativeLong(values.getValue("exporterVersion"), "exporter version")
    if (exporterVersion > Int.MAX_VALUE || exporterVersion.toInt() != state.exporterVersion) {
        resumeValidationFailure("planning checkpoint exporter version differs from exporter state")
    }
    val start = canonicalNonnegativeLong(values.getValue("startIndex"), "planning batch start")
    val end = canonicalNonnegativeLong(values.getValue("endExclusive"), "planning batch end")
    val span = exactSubtract("planning batch span", end, start)
    if (start !in 0 until MAXIMUM_FUNCTIONS || end !in 1..MAXIMUM_FUNCTIONS || end > state.functionCount ||
        start % PLANNING_BATCH_FUNCTIONS != 0L || span !in 1..PLANNING_BATCH_FUNCTIONS ||
        (span < PLANNING_BATCH_FUNCTIONS && end != state.functionCount)
    ) resumeValidationFailure("planning checkpoint has invalid inventory bounds")
    val functionIds = parseOrderedIds(values.getValue("functionIds"), FUNCTION_ID, false, "function")
    val failureIds = parseOrderedIds(values.getValue("failureIds"), FUNCTION_ID, true, "failure")
    val globalIds = parseOrderedIds(values.getValue("globalIds"), GLOBAL_ID, true, "global")
    val typeIds = parseOrderedIds(values.getValue("typeIds"), TYPE_ID, true, "type")
    if (functionIds.size.toLong() != span || failureIds.any { it !in functionIds }) {
        resumeValidationFailure("planning checkpoint identities differ from its inventory span")
    }
    val functionSummary = parseFunctionFragment(captured.functions, functionIds, limits.planningFragmentBytes)
    val globalSummary = parseGlobalFragment(captured.globals, globalIds)
    val typeSummary = parseTypeFragment(captured.types, typeIds)
    val failureSummary = parseFailureFragment(captured.failures, failureIds)
    if (failureSummary.ids != functionSummary.failedIds) {
        resumeValidationFailure("planning failure identities differ from failed functions")
    }
    val recovered = canonicalNonnegativeLong(values.getValue("recovered"), "recovered count")
    val partial = canonicalNonnegativeLong(values.getValue("partial"), "partial count")
    val failed = canonicalNonnegativeLong(values.getValue("failed"), "failed count")
    if (recovered != 0L || recovered != functionSummary.recovered || partial != functionSummary.partial ||
        failed != functionSummary.failed || exactAdd("planning checkpoint recovery counts", partial, failed) != span
    ) resumeValidationFailure("planning checkpoint recovery counts differ from canonical function records")
    requireFragmentBinding(captured.functions, values, "function")
    requireFragmentBinding(captured.globals, values, "global")
    requireFragmentBinding(captured.types, values, "type")
    requireFragmentBinding(captured.failures, values, "failure")
    val stateSha256 = requireSha256(values.getValue("stateSha256"), "planning checkpoint state")
    if (stateSha256 != state.artifactSha256) {
        resumeValidationFailure("planning checkpoint does not bind the exact exporter state bytes")
    }
    return ParsedPlanningBatch(
        checkpoint = ParsedArtifact(captured.checkpoint.size, OracleArtifacts.sha256(captured.checkpoint)),
        exporterVersion = exporterVersion.toInt(),
        stateSha256 = stateSha256,
        inventorySha256 = requireSha256(values.getValue("inventorySha256"), "planning inventory"),
        startIndex = start,
        endExclusive = end,
        recovered = recovered,
        partial = partial,
        failed = failed,
        functionIds = immutableList(functionIds),
        globalIds = immutableList(globalIds),
        typeIds = immutableList(typeIds),
        failureIds = immutableList(failureIds),
        functions = functionSummary.fragment,
        globals = globalSummary,
        types = typeSummary,
        failures = failureSummary,
    )
}

private fun retainFirstOwner(
    target: TreeMap<String, BoundRecord>,
    ids: List<String>,
    records: List<ByteArray>,
    label: String,
) {
    if (ids.size != records.size) resumeValidationFailure("$label record identities are incomplete")
    ids.zip(records).forEach { (id, record) ->
        if (target.putIfAbsent(id, BoundRecord(id, record)) != null) {
            resumeValidationFailure("$label evidence is owned by more than one planning batch")
        }
    }
}

private fun inventorySha256(functionIds: List<String>): String {
    if (functionIds.isEmpty() || functionIds.size > MAXIMUM_FUNCTIONS) {
        resumeValidationFailure("completed-run function inventory is empty or oversized")
    }
    val bytes = (functionIds.joinToString("\n") + "\n").toByteArray(StandardCharsets.UTF_8)
    return OracleArtifacts.sha256(bytes)
}

private fun batchCommitmentSha256(
    batches: List<ParsedPlanningBatch>,
    captured: List<CapturedPlanningBatch>,
): String {
    if (batches.size != captured.size || batches.size > MAXIMUM_PLANNING_BATCHES) {
        resumeValidationFailure("planning batch commitment has an invalid batch count")
    }
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(BATCH_COMMITMENT_DOMAIN)
    var nextStart = 0L
    batches.zip(captured).forEach { (batch, raw) ->
        if (batch.startIndex != nextStart) resumeValidationFailure("planning batch commitment is not contiguous")
        nextStart = batch.endExclusive
        updateDigestLong(digest, batch.startIndex)
        updateDigestLong(digest, batch.endExclusive)
        updateCommittedFragment(digest, raw.functions, batch.functions, "function")
        updateCommittedFragment(digest, raw.globals, batch.globals, "global")
        updateCommittedFragment(digest, raw.types, batch.types, "type")
        updateCommittedFragment(digest, raw.failures, batch.failures, "failure")
    }
    return digest.digest().toHex()
}

private fun updateCommittedFragment(
    digest: MessageDigest,
    bytes: ByteArray,
    parsed: ParsedFragment,
    label: String,
) {
    requireArtifact(bytes, ParsedArtifact(parsed.bytes, parsed.sha256), "$label fragment")
    updateDigestLong(digest, parsed.bytes.toLong())
    digest.update(parsed.sha256.toByteArray(StandardCharsets.US_ASCII))
}

private fun semanticFingerprint(
    functions: List<BoundRecord>,
    failures: Map<String, BoundRecord>,
    globals: Map<String, BoundRecord>,
    types: Map<String, BoundRecord>,
): SemanticBinding {
    val fingerprint = SemanticFingerprintV1()
    functions.forEach { fingerprint.append(FUNCTION_RECORD_TAG, it, MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES) }
    var uniqueEvidenceBytes = 0L
    fun appendEvidence(tag: Byte, records: Map<String, BoundRecord>) {
        records.values.forEach { record ->
            val retained = exactAdd(
                "semantic unique-evidence frame bytes",
                SEMANTIC_FRAME_OVERHEAD,
                record.id.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                record.bytes.size.toLong(),
            )
            uniqueEvidenceBytes = addExactBounded(
                uniqueEvidenceBytes,
                retained,
                MAXIMUM_UNIQUE_EVIDENCE_BYTES,
                "semantic unique-evidence bytes",
            )
            fingerprint.append(tag, record, MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES)
        }
    }
    appendEvidence(FAILURE_RECORD_TAG, failures)
    appendEvidence(GLOBAL_RECORD_TAG, globals)
    appendEvidence(TYPE_RECORD_TAG, types)
    fingerprint.append(
        TERMINAL_RECORD_TAG,
        BoundRecord("functions", functions.size.toString().toByteArray(StandardCharsets.UTF_8)),
        32,
    )
    return fingerprint.finish()
}

private class SemanticFingerprintV1 {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var canonicalBytes = 0L

    init {
        update(SEMANTIC_FINGERPRINT_DOMAIN)
    }

    fun append(tag: Byte, record: BoundRecord, maximumRecordBytes: Int) {
        if (record.bytes.size > maximumRecordBytes) resumeValidationFailure("semantic record exceeds its byte bound")
        val idBytes = record.id.toByteArray(StandardCharsets.UTF_8)
        val frameBytes = exactAdd(
            "semantic frame bytes",
            SEMANTIC_FRAME_OVERHEAD,
            idBytes.size.toLong(),
            record.bytes.size.toLong(),
        )
        if (exactAdd("semantic canonical bytes", canonicalBytes, frameBytes) > MAXIMUM_SEMANTIC_BYTES) {
            resumeValidationFailure("semantic fingerprint exceeds its canonical byte bound")
        }
        digest.update(tag)
        updateDigestLong(digest, idBytes.size.toLong())
        digest.update(idBytes)
        updateDigestLong(digest, record.bytes.size.toLong())
        digest.update(record.bytes)
        canonicalBytes += frameBytes
    }

    private fun update(bytes: ByteArray) {
        canonicalBytes = addExactBounded(
            canonicalBytes,
            bytes.size.toLong(),
            MAXIMUM_SEMANTIC_BYTES,
            "semantic canonical bytes",
        )
        digest.update(bytes)
    }

    fun finish(): SemanticBinding = SemanticBinding(canonicalBytes, digest.digest().toHex())
}

private fun updateDigestLong(digest: MessageDigest, value: Long) {
    for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
}

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

private fun reauthenticateRun(
    run: CapturedRun,
    state: ParsedExporterState,
    progress: ParsedExportProgress,
    batches: List<ParsedPlanningBatch>,
) {
    requireArtifact(run.state, ParsedArtifact(state.artifactBytes, state.artifactSha256), "exporter state")
    requireArtifact(run.progress, ParsedArtifact(progress.artifactBytes, progress.artifactSha256), "export progress")
    run.batches.zip(batches).forEach { (raw, parsed) ->
        requireArtifact(raw.checkpoint, parsed.checkpoint, "planning checkpoint")
        requireArtifact(raw.functions, ParsedArtifact(parsed.functions.bytes, parsed.functions.sha256), "function fragment")
        requireArtifact(raw.globals, ParsedArtifact(parsed.globals.bytes, parsed.globals.sha256), "global fragment")
        requireArtifact(raw.types, ParsedArtifact(parsed.types.bytes, parsed.types.sha256), "type fragment")
        requireArtifact(raw.failures, ParsedArtifact(parsed.failures.bytes, parsed.failures.sha256), "failure fragment")
    }
}

private fun requireArtifact(bytes: ByteArray, expected: ParsedArtifact, label: String) {
    if (bytes.size != expected.bytes || OracleArtifacts.sha256(bytes) != expected.sha256) {
        resumeValidationFailure("$label snapshot changed after validation")
    }
}

private fun verifyAssembledModel(
    actual: ByteArray,
    inputSha256: String,
    functions: List<BoundRecord>,
    globals: List<BoundRecord>,
    types: List<BoundRecord>,
    limits: GccResumeByteValidationLimits,
) {
    requireBoundedBytes(actual, limits.assembledModelBytes, false, "completed program model")
    requireSha256(inputSha256, "assembled program-model input")
    val verifier = ExactByteVerifier(actual, "completed program model", limits.assembledModelBytes)
    verifier.accept(
        "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"$inputSha256\",\n  \"functions\": [\n",
    )
    verifier.acceptRecordArray(functions.map { it.bytes })
    verifier.accept("  ],\n  \"globals\": [\n")
    verifier.acceptRecordArray(globals.map { it.bytes })
    verifier.accept("  ],\n  \"types\": [\n")
    verifier.acceptRecordArray(types.map { it.bytes })
    verifier.accept("  ]\n}\n")
    verifier.finish()
}

private data class ParsedFragment(
    val bytes: Int,
    val sha256: String,
    val ids: List<String>,
    val records: List<ByteArray>,
)

private data class ParsedPlanningBatch(
    val checkpoint: ParsedArtifact,
    val exporterVersion: Int,
    val stateSha256: String,
    val inventorySha256: String,
    val startIndex: Long,
    val endExclusive: Long,
    val recovered: Long,
    val partial: Long,
    val failed: Long,
    val functionIds: List<String>,
    val globalIds: List<String>,
    val typeIds: List<String>,
    val failureIds: List<String>,
    val functions: ParsedFragment,
    val globals: ParsedFragment,
    val types: ParsedFragment,
    val failures: ParsedFragment,
)

private data class ParsedArtifact(val bytes: Int, val sha256: String)

/** Raw, caller-owned bytes. The one-shot assessment snapshots every field before parsing it. */
internal class GccPlanningBatchBytes(
    val checkpoint: ByteArray,
    val functions: ByteArray,
    val globals: ByteArray,
    val types: ByteArray,
    val failures: ByteArray,
)

/** Diagnostic only. It is deliberately not accepted by any validator operation. */
internal class GccExporterStateAssessment internal constructor(
    val authority: String,
    val artifactBytes: Int,
    val artifactSha256: String,
    val functionCount: Long,
    val planningBatchCount: Long,
    val semanticCanonicalBytes: Long,
    val semanticSha256: String,
    val batchCommitmentSha256: String,
)

/** Diagnostic only. It is deliberately not accepted by any validator operation. */
internal class GccExportProgressAssessment internal constructor(
    val authority: String,
    val artifactBytes: Int,
    val artifactSha256: String,
    val stateSha256: String,
    val phase: String,
    val completed: Long,
    val total: Long,
    val partial: Long,
    val failed: Long,
    val reused: Long,
)

/** Diagnostic only; this is not interruption, resume, or publication evidence. */
internal class GccCompletedRunAssessment internal constructor(
    val authority: String,
    val stateSha256: String,
    val progressSha256: String,
    val programModelBytes: Int,
    val programModelSha256: String,
    val functionCount: Long,
    val planningBatchCount: Long,
    val inventorySha256: String,
    val semanticCanonicalBytes: Long,
    val semanticSha256: String,
    val batchCommitmentSha256: String,
    val partial: Long,
    val failed: Long,
    val reused: Long,
)

/** Diagnostic only; this does not prove that a process was stopped at this prefix. */
internal class GccInterruptedPrefixAssessment internal constructor(
    val authority: String,
    val stateSha256: String,
    val progressSha256: String,
    val functionCount: Long,
    val completed: Long,
    val observedBatchCount: Long,
    val declaredInventorySha256: String,
    val partial: Long,
    val failed: Long,
    val reused: Long,
)

/** Diagnostic only; byte equivalence is not process, interruption, or publication evidence. */
internal class GccResumeEquivalenceAssessment internal constructor(
    val authority: String,
    val stateSha256: String,
    val interruptedProgressSha256: String,
    val resumedProgressSha256: String,
    val freshProgressSha256: String,
    val interruptedCompleted: Long,
    val functionCount: Long,
    val planningBatchCount: Long,
    val programModelBytes: Int,
    val programModelSha256: String,
    val modulePlanBytes: Int,
    val modulePlanSha256: String,
)

/** Diagnostic derived progress; never a replacement for the captured exporter progress file. */
internal class GccStoppedCheckpointPrefix(val assessment: GccInterruptedPrefixAssessment, effectiveProgress: ByteArray) {
    private val progress = effectiveProgress.copyOf()
    val effectiveProgress: ByteArray get() = progress.copyOf()
}

private class ValidatedInterruptedPrefix(
    val state: ParsedExporterState,
    val progress: ParsedExportProgress,
    val assessment: GccInterruptedPrefixAssessment,
)

private class ValidatedCompletedRun(
    val state: ParsedExporterState,
    val progress: ParsedExportProgress,
    val assessment: GccCompletedRunAssessment,
)

private fun validateInterruptedPrefix(
    run: CapturedInterruptedPrefix,
    limits: GccResumeByteValidationLimits,
): ValidatedInterruptedPrefix {
    val state = parseExporterState(run.state, limits)
    val progress = parseExportProgress(state, run.progress, limits)
    if (progress.phase != "planning" || progress.completed < PLANNING_BATCH_FUNCTIONS ||
        progress.completed > progress.total || progress.reused != 0L
    ) {
        resumeValidationFailure(
            "interrupted prefix must be a planning leg with at least one full checkpoint and no reuse",
        )
    }
    val observedBatchCount = (progress.completed + PLANNING_BATCH_FUNCTIONS - 1) / PLANNING_BATCH_FUNCTIONS
    if (run.batches.size.toLong() != observedBatchCount || observedBatchCount > state.planningBatchCount) {
        resumeValidationFailure("interrupted prefix batch count differs from its completed position")
    }

    val globals = TreeMap<String, BoundRecord>()
    val types = TreeMap<String, BoundRecord>()
    val failures = TreeMap<String, BoundRecord>()
    var nextStart = 0L
    var partial = 0L
    var failed = 0L
    var inventorySha256: String? = null
    var previousFunctionId: String? = null
    val batches = ArrayList<ParsedPlanningBatch>(run.batches.size)
    run.batches.forEach { captured ->
        val batch = parsePlanningBatch(state, captured, limits)
        if (batch.startIndex != nextStart || batch.endExclusive != minOf(batch.startIndex + PLANNING_BATCH_FUNCTIONS, state.functionCount)) {
            resumeValidationFailure("interrupted planning batches are not an exact contiguous checkpoint prefix")
        }
        nextStart = batch.endExclusive
        if (inventorySha256 != null && inventorySha256 != batch.inventorySha256) {
            resumeValidationFailure("interrupted planning batches disagree on their inventory binding")
        }
        inventorySha256 = batch.inventorySha256
        batch.functionIds.forEach { id ->
            if (previousFunctionId != null && previousFunctionId!! >= id) {
                resumeValidationFailure("interrupted-prefix functions are not in strict inventory order")
            }
            previousFunctionId = id
        }
        retainFirstOwner(globals, batch.globalIds, batch.globals.records, "interrupted global")
        retainFirstOwner(types, batch.typeIds, batch.types.records, "interrupted type")
        retainFirstOwner(failures, batch.failureIds, batch.failures.records, "interrupted failure")
        partial = exactAdd("interrupted-prefix partial count", partial, batch.partial)
        failed = exactAdd("interrupted-prefix failed count", failed, batch.failed)
        batches += batch
    }
    if (nextStart != progress.completed ||
        progress.partial != partial || progress.failed != failed ||
        exactAdd("interrupted-prefix progress counts", partial, failed) != progress.completed
    ) {
        resumeValidationFailure("interrupted progress differs from the exact observed planning prefix")
    }
    if (progress.completed == state.functionCount) {
        val functions = batches.flatMap { batch ->
            batch.functionIds.zip(batch.functions.records).map { (id, record) -> BoundRecord(id, record) }
        }
        if (inventorySha256 != inventorySha256(functions.map { it.id }) ||
            batchCommitmentSha256(batches, run.batches) != state.batchCommitmentSha256
        ) resumeValidationFailure("terminal planning prefix commitments are not reproducible")
        val semantic = semanticFingerprint(functions, failures, globals, types)
        if (semantic.canonicalBytes != state.canonicalBytes || semantic.sha256 != state.semanticSha256) {
            resumeValidationFailure("terminal planning prefix semantic fingerprint is not reproducible")
        }
    }
    val declaredInventory = inventorySha256
        ?: resumeValidationFailure("interrupted prefix has no inventory binding")
    requireArtifact(run.state, ParsedArtifact(state.artifactBytes, state.artifactSha256), "interrupted exporter state")
    requireArtifact(
        run.progress,
        ParsedArtifact(progress.artifactBytes, progress.artifactSha256),
        "interrupted export progress",
    )
    run.batches.zip(batches).forEach { (raw, parsed) ->
        requireArtifact(raw.checkpoint, parsed.checkpoint, "interrupted planning checkpoint")
        requireArtifact(
            raw.functions,
            ParsedArtifact(parsed.functions.bytes, parsed.functions.sha256),
            "interrupted function fragment",
        )
        requireArtifact(
            raw.globals,
            ParsedArtifact(parsed.globals.bytes, parsed.globals.sha256),
            "interrupted global fragment",
        )
        requireArtifact(
            raw.types,
            ParsedArtifact(parsed.types.bytes, parsed.types.sha256),
            "interrupted type fragment",
        )
        requireArtifact(
            raw.failures,
            ParsedArtifact(parsed.failures.bytes, parsed.failures.sha256),
            "interrupted failure fragment",
        )
    }
    return ValidatedInterruptedPrefix(
        state,
        progress,
        GccInterruptedPrefixAssessment(
            authority = NON_AUTHORITATIVE_ASSESSMENT,
            stateSha256 = state.artifactSha256,
            progressSha256 = progress.artifactSha256,
            functionCount = state.functionCount,
            completed = progress.completed,
            observedBatchCount = observedBatchCount,
            declaredInventorySha256 = declaredInventory,
            partial = partial,
            failed = failed,
            reused = progress.reused,
        ),
    )
}

private fun validateCompletedRun(
    run: CapturedRun,
    limits: GccResumeByteValidationLimits,
): ValidatedCompletedRun {
    val state = parseExporterState(run.state, limits)
    val progress = parseExportProgress(state, run.progress, limits)
    if (progress.phase != "complete") resumeValidationFailure("completed run progress is not terminal")
    if (run.batches.size.toLong() != state.planningBatchCount) {
        resumeValidationFailure("completed run batch count differs from exporter state")
    }

    val batches = ArrayList<ParsedPlanningBatch>(run.batches.size)
    val functions = ArrayList<BoundRecord>()
    val globals = TreeMap<String, BoundRecord>()
    val types = TreeMap<String, BoundRecord>()
    val failures = TreeMap<String, BoundRecord>()
    var nextStart = 0L
    var partial = 0L
    var failed = 0L
    var inventorySha256: String? = null
    var previousFunctionId: String? = null
    run.batches.forEach { captured ->
        val batch = parsePlanningBatch(state, captured, limits)
        if (batch.startIndex != nextStart) resumeValidationFailure("planning batches are not a contiguous ordered run")
        nextStart = batch.endExclusive
        if (inventorySha256 != null && inventorySha256 != batch.inventorySha256) {
            resumeValidationFailure("planning batches disagree on their inventory binding")
        }
        inventorySha256 = batch.inventorySha256
        batch.functionIds.zip(batch.functions.records).forEach { (id, record) ->
            if (previousFunctionId != null && previousFunctionId!! >= id) {
                resumeValidationFailure("completed-run functions are not in strict inventory order")
            }
            functions += BoundRecord(id, record)
            previousFunctionId = id
        }
        retainFirstOwner(globals, batch.globalIds, batch.globals.records, "global")
        retainFirstOwner(types, batch.typeIds, batch.types.records, "type")
        retainFirstOwner(failures, batch.failureIds, batch.failures.records, "failure")
        partial = exactAdd("completed-run partial count", partial, batch.partial)
        failed = exactAdd("completed-run failed count", failed, batch.failed)
        batches += batch
    }
    if (nextStart != state.functionCount || functions.size.toLong() != state.functionCount) {
        resumeValidationFailure("planning batches do not cover the complete function inventory")
    }
    val recomputedInventory = inventorySha256(functions.map { it.id })
    if (inventorySha256 != recomputedInventory) resumeValidationFailure("planning inventory digest is not reproducible")
    val recomputedCommitment = batchCommitmentSha256(batches, run.batches)
    if (recomputedCommitment != state.batchCommitmentSha256) {
        resumeValidationFailure("planning batch commitment is not reproducible")
    }
    val semantic = semanticFingerprint(functions, failures, globals, types)
    if (semantic.canonicalBytes != state.canonicalBytes || semantic.sha256 != state.semanticSha256) {
        resumeValidationFailure("planning semantic fingerprint is not reproducible")
    }
    if (progress.completed != state.functionCount || progress.partial != partial || progress.failed != failed) {
        resumeValidationFailure("terminal progress differs from the validated planning batches")
    }

    reauthenticateRun(run, state, progress, batches)
    verifyAssembledModel(
        run.programModel,
        state.inputSha256,
        functions,
        globals.values.toList(),
        types.values.toList(),
        limits,
    )
    return ValidatedCompletedRun(
        state,
        progress,
        GccCompletedRunAssessment(
            authority = NON_AUTHORITATIVE_ASSESSMENT,
            stateSha256 = state.artifactSha256,
            progressSha256 = progress.artifactSha256,
            programModelBytes = run.programModel.size,
            programModelSha256 = OracleArtifacts.sha256(run.programModel),
            functionCount = state.functionCount,
            planningBatchCount = state.planningBatchCount,
            inventorySha256 = recomputedInventory,
            semanticCanonicalBytes = semantic.canonicalBytes,
            semanticSha256 = semantic.sha256,
            batchCommitmentSha256 = recomputedCommitment,
            partial = partial,
            failed = failed,
            reused = progress.reused,
        ),
    )
}

private fun requireExactArtifactBytes(left: ByteArray, right: ByteArray, label: String) {
    if (left.size != right.size || !MessageDigest.isEqual(left, right)) {
        resumeValidationFailure("$label bytes differ")
    }
}

private fun requireFrozenPrefix(
    interrupted: CapturedInterruptedPrefix,
    resumed: CapturedRun,
) {
    if (interrupted.batches.size >= resumed.batches.size) {
        resumeValidationFailure("interrupted batches are not a strict prefix of the resumed run")
    }
    interrupted.batches.forEachIndexed { index, frozen ->
        val resumedBatch = resumed.batches[index]
        requireExactArtifactBytes(frozen.checkpoint, resumedBatch.checkpoint, "frozen prefix checkpoint $index")
        requireExactArtifactBytes(frozen.functions, resumedBatch.functions, "frozen prefix function fragment $index")
        requireExactArtifactBytes(frozen.globals, resumedBatch.globals, "frozen prefix global fragment $index")
        requireExactArtifactBytes(frozen.types, resumedBatch.types, "frozen prefix type fragment $index")
        requireExactArtifactBytes(frozen.failures, resumedBatch.failures, "frozen prefix failure fragment $index")
    }
}

/**
 * Pure hostile-byte validation used by the future controller. Methods accept already captured
 * bytes; they do not read paths, mutate a workspace, launch a process, or publish evidence.
 */
internal object GccCompilerEngineResumeByteValidator {
    fun assessExporterState(
        rawState: ByteArray,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccExporterStateAssessment {
        val stateBytes = snapshotBounded(rawState, limits.exporterStateBytes, allowEmpty = false, "exporter state")
        return parseExporterState(stateBytes, limits).assessment()
    }

    fun assessExportProgress(
        rawState: ByteArray,
        rawProgress: ByteArray,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccExportProgressAssessment {
        val stateBytes = snapshotBounded(rawState, limits.exporterStateBytes, allowEmpty = false, "exporter state")
        val progressBytes = snapshotBounded(rawProgress, limits.progressBytes, allowEmpty = false, "export progress")
        val state = parseExporterState(stateBytes, limits)
        return parseExportProgress(state, progressBytes, limits).assessment()
    }

    fun assessCompletedRun(
        rawState: ByteArray,
        rawProgress: ByteArray,
        rawBatches: List<GccPlanningBatchBytes>,
        rawProgramModel: ByteArray,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccCompletedRunAssessment = validateCompletedRun(
        captureRun(rawState, rawProgress, rawBatches, rawProgramModel, limits),
        limits,
    ).assessment

    fun assessInterruptedPrefix(
        rawState: ByteArray,
        rawProgress: ByteArray,
        rawBatches: List<GccPlanningBatchBytes>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccInterruptedPrefixAssessment = validateInterruptedPrefix(
        captureInterruptedPrefix(rawState, rawProgress, rawBatches, limits),
        limits,
    ).assessment

    /** Validates a model published before worker absence, retaining planning progress only as a diagnostic. */
    fun assessStoppedPublishedModel(
        rawState: ByteArray,
        rawProgress: ByteArray,
        rawBatches: List<GccPlanningBatchBytes>,
        rawProgramModel: ByteArray,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccStoppedCheckpointPrefix {
        val run = captureRun(rawState, rawProgress, rawBatches, rawProgramModel, limits)
        val state = parseExporterState(run.state, limits)
        val observed = parseExportProgress(state, run.progress, limits)
        if (observed.completed != state.functionCount || observed.reused != 0L) {
            resumeValidationFailure("stopped published model requires all fresh checkpoints and published planning progress")
        }
        val complete = renderExportProgress(observed.copy(phase = "complete")).toByteArray(StandardCharsets.UTF_8)
        validateCompletedRun(CapturedRun(run.state, complete, run.batches, run.programModel), limits)
        val planning = renderExportProgress(observed.copy(phase = "planning")).toByteArray(StandardCharsets.UTF_8)
        val prefix = validateInterruptedPrefix(CapturedInterruptedPrefix(run.state, planning, run.batches), limits)
        return GccStoppedCheckpointPrefix(prefix.assessment, planning)
    }

    /** Derives at most one committed batch beyond the separately validated observed progress. */
    fun assessStoppedCheckpointPrefix(
        rawState: ByteArray,
        rawProgress: ByteArray,
        rawBatches: List<GccPlanningBatchBytes>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccStoppedCheckpointPrefix {
        val run = captureInterruptedPrefix(rawState, rawProgress, rawBatches, limits)
        val state = parseExporterState(run.state, limits)
        val observed = parseExportProgress(state, run.progress, limits)
        val count = (observed.completed + PLANNING_BATCH_FUNCTIONS - 1) / PLANNING_BATCH_FUNCTIONS
        if (run.batches.size.toLong() == count) {
            return GccStoppedCheckpointPrefix(validateInterruptedPrefix(run, limits).assessment, run.progress)
        }
        if (run.batches.size.toLong() != count + 1 || count < 1) {
            resumeValidationFailure("stopped checkpoint prefix may advance by at most one batch")
        }
        validateInterruptedPrefix(CapturedInterruptedPrefix(run.state, run.progress, run.batches.take(count.toInt())), limits)
        val next = parsePlanningBatch(state, run.batches.last(), limits)
        if (next.startIndex != observed.completed || next.endExclusive != minOf(observed.completed + PLANNING_BATCH_FUNCTIONS, observed.total) ||
            observed.completed >= observed.total) {
            resumeValidationFailure("advanced stopped checkpoint must be the next complete batch")
        }
        val effective = renderExportProgress(observed.copy(
            completed = next.endExclusive,
            partial = exactAdd("stopped partial count", observed.partial, next.partial),
            failed = exactAdd("stopped failed count", observed.failed, next.failed),
        )).toByteArray(StandardCharsets.UTF_8)
        val assessment = validateInterruptedPrefix(CapturedInterruptedPrefix(run.state, effective, run.batches), limits).assessment
        return GccStoppedCheckpointPrefix(assessment, effective)
    }

    @Suppress("LongParameterList")
    fun assessResumeEquivalence(
        rawInterruptedState: ByteArray,
        rawInterruptedProgress: ByteArray,
        rawInterruptedBatches: List<GccPlanningBatchBytes>,
        rawResumedState: ByteArray,
        rawResumedProgress: ByteArray,
        rawResumedBatches: List<GccPlanningBatchBytes>,
        rawResumedProgramModel: ByteArray,
        rawResumedModulePlan: ByteArray,
        rawFreshState: ByteArray,
        rawFreshProgress: ByteArray,
        rawFreshBatches: List<GccPlanningBatchBytes>,
        rawFreshProgramModel: ByteArray,
        rawFreshModulePlan: ByteArray,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccResumeEquivalenceAssessment {
        val captureBudget = CaptureBudget(limits.transitionAggregateBytes)
        val interrupted = captureInterruptedPrefix(
            rawInterruptedState,
            rawInterruptedProgress,
            rawInterruptedBatches,
            limits,
            captureBudget,
        )
        val resumed = captureRun(
            rawResumedState,
            rawResumedProgress,
            rawResumedBatches,
            rawResumedProgramModel,
            limits,
            "resumed run",
            captureBudget,
        )
        val resumedModulePlan = snapshotBounded(
            rawResumedModulePlan,
            limits.modulePlanBytes,
            false,
            "resumed module plan",
            captureBudget,
        )
        val fresh = captureRun(
            rawFreshState,
            rawFreshProgress,
            rawFreshBatches,
            rawFreshProgramModel,
            limits,
            "fresh run",
            captureBudget,
        )
        val freshModulePlan = snapshotBounded(
            rawFreshModulePlan,
            limits.modulePlanBytes,
            false,
            "fresh module plan",
            captureBudget,
        )

        val interruptedValidation = validateInterruptedPrefix(interrupted, limits)
        val resumedValidation = validateCompletedRun(resumed, limits)
        val freshValidation = validateCompletedRun(fresh, limits)
        requireExactArtifactBytes(interrupted.state, resumed.state, "interrupted and resumed exporter state")
        requireExactArtifactBytes(interrupted.state, fresh.state, "interrupted and fresh exporter state")
        requireFrozenPrefix(interrupted, resumed)
        if (resumedValidation.progress.reused != interruptedValidation.progress.completed) {
            resumeValidationFailure("resumed reuse count differs from the frozen interrupted prefix")
        }
        if (freshValidation.progress.reused != 0L) {
            resumeValidationFailure("fresh control unexpectedly reused planning records")
        }
        requireExactArtifactBytes(resumed.programModel, fresh.programModel, "resumed and fresh program model")
        requireExactArtifactBytes(resumedModulePlan, freshModulePlan, "resumed and fresh module plan")

        return GccResumeEquivalenceAssessment(
            authority = NON_AUTHORITATIVE_ASSESSMENT,
            stateSha256 = interruptedValidation.state.artifactSha256,
            interruptedProgressSha256 = interruptedValidation.progress.artifactSha256,
            resumedProgressSha256 = resumedValidation.progress.artifactSha256,
            freshProgressSha256 = freshValidation.progress.artifactSha256,
            interruptedCompleted = interruptedValidation.progress.completed,
            functionCount = resumedValidation.state.functionCount,
            planningBatchCount = resumedValidation.state.planningBatchCount,
            programModelBytes = resumed.programModel.size,
            programModelSha256 = OracleArtifacts.sha256(resumed.programModel),
            modulePlanBytes = resumedModulePlan.size,
            modulePlanSha256 = OracleArtifacts.sha256(resumedModulePlan),
        )
    }
}

private data class ParsedFunctionFragment(
    val fragment: ParsedFragment,
    val failedIds: List<String>,
    val recovered: Long,
    val partial: Long,
    val failed: Long,
)

private data class CanonicalRecord(val bytes: ByteArray, val document: JsonObject)

private fun parseFunctionFragment(
    bytes: ByteArray,
    expectedIds: List<String>,
    maximumFragmentBytes: Int,
): ParsedFunctionFragment {
    requireBoundedBytes(bytes, maximumFragmentBytes, allowEmpty = false, "function fragment")
    val records = splitCanonicalRecords(
        bytes,
        allowEmpty = false,
        maximumRecordBytes = MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES,
        maximumRecords = expectedIds.size,
        label = "function",
    )
    if (records.size != expectedIds.size) resumeValidationFailure("function fragment record count differs from checkpoint")
    val recovered = 0L
    var partial = 0L
    var failed = 0L
    val failedIds = ArrayList<String>()
    records.forEachIndexed { index, record ->
        val root = record.document
        if (root.stringValue("recoveryAssessment", "extracted record") != "unassessed") {
            resumeValidationFailure("extracted record cannot supply a scored recovery assessment")
        }
        root.requireExactKeys(
            setOf("id", "name", "address", "prototype", "extractionStatus", "recoveryAssessment", "calls", "referencedGlobals", "strings", "decompiledC"),
            "function record",
        )
        val id = root.stringValue("id", "function record")
        if (id != expectedIds[index]) resumeValidationFailure("function fragment embedded identity differs from checkpoint")
        val name = root.recordString("name", "function name", MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES)
        val address = root.stringValue("address", "function record")
        requireAddressIdentity(address, id, "fn_", "function")
        val prototype = root.recordString("prototype", "function prototype", MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES)
        val status = root.stringValue("extractionStatus", "function record")
        when (status) {
            "recovered" -> resumeValidationFailure("planning function fragment contains a recovered record")
            "partial" -> partial++
            "failed" -> {
                failed++
                failedIds += id
            }
            else -> resumeValidationFailure("function fragment has an unsupported recovery status")
        }
        val calls = root.orderedStringArray("calls", FUNCTION_ID, "function calls")
        val referencedGlobals = root.orderedStringArray("referencedGlobals", GLOBAL_ID, "referenced globals")
        val strings = root.orderedStringArray("strings", null, "function strings")
        if (root["decompiledC"] !is JsonNull) {
            resumeValidationFailure("planning function fragment contains a decompiled body")
        }
        val rendered = renderFunctionRecord(
            id,
            name,
            address,
            prototype,
            status,
            calls,
            referencedGlobals,
            strings,
        )
        requireExactBytes(record.bytes, rendered, "function record")
    }
    return ParsedFunctionFragment(
        fragment = fragmentSummary(bytes, expectedIds, records),
        failedIds = immutableList(failedIds),
        recovered = recovered,
        partial = partial,
        failed = failed,
    )
}

private fun parseGlobalFragment(bytes: ByteArray, expectedIds: List<String>): ParsedFragment {
    val records = splitCanonicalRecords(
        bytes,
        allowEmpty = true,
        maximumRecordBytes = MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES,
        maximumRecords = expectedIds.size,
        label = "global",
    )
    if (records.size != expectedIds.size) resumeValidationFailure("global fragment record count differs from checkpoint")
    val ids = ArrayList<String>()
    records.forEachIndexed { index, record ->
        val root = record.document
        if (root.stringValue("recoveryAssessment", "extracted record") != "unassessed") {
            resumeValidationFailure("extracted record cannot supply a scored recovery assessment")
        }
        root.requireExactKeys(setOf("id", "name", "address", "type", "initializer", "extractionStatus", "recoveryAssessment"), "global record")
        val id = root.stringValue("id", "global record")
        if (!id.matches(GLOBAL_ID)) resumeValidationFailure("global record has an invalid identity")
        if (id != expectedIds[index]) resumeValidationFailure("global fragment embedded identity differs from checkpoint")
        val name = root.recordString("name", "global name", MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES)
        val address = root.stringValue("address", "global record")
        requireAddressIdentity(address, id, "global_", "global")
        val type = root.recordString("type", "global type", MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES)
        val initializerElement = root["initializer"]
        val initializer = when (initializerElement) {
            is JsonNull -> null
            is JsonPrimitive -> if (initializerElement.isString) initializerElement.content else {
                resumeValidationFailure("global initializer is neither a string nor null")
            }
            else -> resumeValidationFailure("global initializer is neither a string nor null")
        }
        if (initializer != null && initializer.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES) {
            resumeValidationFailure("global initializer exceeds its record bound")
        }
        if (root.stringValue("extractionStatus", "global record") != "recovered") {
            resumeValidationFailure("global record status is not recovered")
        }
        requireExactBytes(record.bytes, renderGlobalRecord(id, name, address, type, initializer), "global record")
        ids += id
    }
    requireStrictlyOrderedIds(ids, "global fragment")
    return fragmentSummary(bytes, ids, records)
}

private fun parseTypeFragment(bytes: ByteArray, expectedIds: List<String>): ParsedFragment {
    val records = splitCanonicalRecords(
        bytes,
        allowEmpty = true,
        maximumRecordBytes = MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES,
        maximumRecords = expectedIds.size,
        label = "type",
    )
    if (records.size != expectedIds.size) resumeValidationFailure("type fragment record count differs from checkpoint")
    val ids = ArrayList<String>()
    records.forEachIndexed { index, record ->
        val root = record.document
        if (root.stringValue("recoveryAssessment", "extracted record") != "unassessed") {
            resumeValidationFailure("extracted record cannot supply a scored recovery assessment")
        }
        root.requireExactKeys(setOf("id", "declaration", "sourceAddress", "extractionStatus", "recoveryAssessment"), "type record")
        val id = root.stringValue("id", "type record")
        if (!id.matches(TYPE_ID)) resumeValidationFailure("type record has an invalid identity")
        if (id != expectedIds[index]) resumeValidationFailure("type fragment embedded identity differs from checkpoint")
        val declaration = root.recordString(
            "declaration",
            "type declaration",
            MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES,
        )
        val sourceAddress = root.stringValue("sourceAddress", "type record")
        requireHexAddress(sourceAddress, "type source address")
        if (root.stringValue("extractionStatus", "type record") != "partial") {
            resumeValidationFailure("type record status is not partial")
        }
        requireExactBytes(record.bytes, renderTypeRecord(id, declaration, sourceAddress), "type record")
        ids += id
    }
    requireStrictlyOrderedIds(ids, "type fragment")
    return fragmentSummary(bytes, ids, records)
}

private fun parseFailureFragment(bytes: ByteArray, expectedIds: List<String>): ParsedFragment {
    val records = splitCanonicalRecords(
        bytes,
        allowEmpty = true,
        maximumRecordBytes = MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES,
        maximumRecords = expectedIds.size,
        label = "failure",
    )
    if (records.size != expectedIds.size) resumeValidationFailure("failure fragment record count differs from checkpoint")
    val ids = ArrayList<String>()
    records.forEachIndexed { index, record ->
        val root = record.document
        root.requireExactKeys(setOf("id", "status", "message"), "failure record")
        val id = root.stringValue("id", "failure record")
        if (!id.matches(FUNCTION_ID)) resumeValidationFailure("failure record has an invalid identity")
        if (id != expectedIds[index]) resumeValidationFailure("failure fragment embedded identity differs from checkpoint")
        if (root.stringValue("status", "failure record") != "failed") {
            resumeValidationFailure("failure record status is not failed")
        }
        val message = root.recordString("message", "failure message", MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES)
        requireExactBytes(record.bytes, renderFailureRecord(id, message), "failure record")
        ids += id
    }
    requireStrictlyOrderedIds(ids, "failure fragment")
    return fragmentSummary(bytes, ids, records)
}

private fun splitCanonicalRecords(
    fragment: ByteArray,
    allowEmpty: Boolean,
    maximumRecordBytes: Int,
    maximumRecords: Int,
    label: String,
): List<CanonicalRecord> {
    val text = strictUtf8(fragment, "$label fragment")
    if (text.isEmpty()) {
        if (!allowEmpty) resumeValidationFailure("$label fragment is empty")
        return emptyList()
    }
    val records = ArrayList<CanonicalRecord>()
    var cursor = 0
    while (cursor < text.length) {
        if (records.size >= maximumRecords) {
            resumeValidationFailure("$label fragment has more records than its checkpoint")
        }
        if (!text.startsWith(RECORD_PREFIX, cursor)) {
            resumeValidationFailure("$label fragment has a malformed record prefix")
        }
        val next = text.indexOf(RECORD_SEPARATOR + RECORD_PREFIX, cursor + RECORD_PREFIX.length)
        val end = if (next < 0) text.length else next
        val recordText = text.substring(cursor, end)
        if (!recordText.endsWith(RECORD_SUFFIX)) {
            resumeValidationFailure("$label fragment has a truncated record")
        }
        val recordBytes = recordText.toByteArray(StandardCharsets.UTF_8)
        requireBoundedBytes(recordBytes, maximumRecordBytes, allowEmpty = false, "$label record")
        records += CanonicalRecord(recordBytes, strictRecordObject(recordBytes, maximumRecordBytes, "$label record"))
        if (next < 0) break
        cursor = next + RECORD_SEPARATOR.length
    }
    return Collections.unmodifiableList(records)
}

private fun strictRecordObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
    OracleJson.parse(
        bytes,
        StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 16,
            maximumNodes = MAXIMUM_RECORD_JSON_NODES,
            maximumStringBytes = maximumBytes,
            maximumTotalStringBytes = maximumBytes,
        ),
    ) as? JsonObject ?: resumeValidationFailure("$label root is not an object")
} catch (failure: GccCompilerEngineResumeEvidenceException) {
    throw failure
} catch (failure: Exception) {
    throw GccCompilerEngineResumeEvidenceException("$label is not strict bounded JSON", failure)
}

private fun JsonObject.recordString(name: String, label: String, maximumBytes: Int): String {
    val value = stringValue(name, label)
    if (value.toByteArray(StandardCharsets.UTF_8).size > maximumBytes) {
        resumeValidationFailure("$label exceeds its byte bound")
    }
    return value
}

private fun JsonObject.orderedStringArray(name: String, pattern: Regex?, label: String): List<String> {
    val array = this[name] as? JsonArray ?: resumeValidationFailure("$label is not an array")
    if (array.size > MAXIMUM_RECORD_ARRAY_ENTRIES) resumeValidationFailure("$label exceeds its entry bound")
    val values = array.map { element ->
        val primitive = element as? JsonPrimitive ?: resumeValidationFailure("$label contains a non-string")
        if (!primitive.isString || primitive.content.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_RECORD_STRING_BYTES) {
            resumeValidationFailure("$label contains an invalid or oversized string")
        }
        if (pattern != null && !primitive.content.matches(pattern)) {
            resumeValidationFailure("$label contains an invalid identity")
        }
        primitive.content
    }
    requireStrictlyOrderedIds(values, label)
    return immutableList(values)
}

private fun renderFunctionRecord(
    id: String,
    name: String,
    address: String,
    prototype: String,
    status: String,
    calls: List<String>,
    referencedGlobals: List<String>,
    strings: List<String>,
): String = buildString {
    append("    {\n")
    append("      \"id\": ").append(exporterJsonString(id)).append(",\n")
    append("      \"name\": ").append(exporterJsonString(name)).append(",\n")
    append("      \"address\": ").append(exporterJsonString(address)).append(",\n")
    append("      \"prototype\": ").append(exporterJsonString(prototype)).append(",\n")
    append("      \"extractionStatus\": ").append(exporterJsonString(status)).append(",\n")
    append("      \"recoveryAssessment\": \"unassessed\",\n")
    append("      \"calls\": [").append(renderStringArray(calls)).append("],\n")
    append("      \"referencedGlobals\": [").append(renderStringArray(referencedGlobals)).append("],\n")
    append("      \"strings\": [").append(renderStringArray(strings)).append("],\n")
    append("      \"decompiledC\": null\n")
    append("    }")
}

private fun renderGlobalRecord(id: String, name: String, address: String, type: String, initializer: String?): String =
    buildString {
        append("    {\n")
        append("      \"id\": ").append(exporterJsonString(id)).append(",\n")
        append("      \"name\": ").append(exporterJsonString(name)).append(",\n")
        append("      \"address\": ").append(exporterJsonString(address)).append(",\n")
        append("      \"type\": ").append(exporterJsonString(type)).append(",\n")
        append("      \"initializer\": ").append(initializer?.let(::exporterJsonString) ?: "null").append(",\n")
        append("      \"extractionStatus\": \"recovered\",\n")
        append("      \"recoveryAssessment\": \"unassessed\"\n")
        append("    }")
    }

private fun renderTypeRecord(id: String, declaration: String, sourceAddress: String): String = buildString {
    append("    {\n")
    append("      \"id\": ").append(exporterJsonString(id)).append(",\n")
    append("      \"declaration\": ").append(exporterJsonString(declaration)).append(",\n")
    append("      \"sourceAddress\": ").append(exporterJsonString(sourceAddress)).append(",\n")
    append("      \"extractionStatus\": \"partial\",\n")
    append("      \"recoveryAssessment\": \"unassessed\"\n")
    append("    }")
}

private fun renderFailureRecord(id: String, message: String): String = buildString {
    append("    {\n")
    append("      \"id\": ").append(exporterJsonString(id)).append(",\n")
    append("      \"status\": \"failed\",\n")
    append("      \"message\": ").append(exporterJsonString(message)).append('\n')
    append("    }")
}

private fun renderStringArray(values: List<String>): String = values.joinToString(", ", transform = ::exporterJsonString)

private fun fragmentSummary(
    bytes: ByteArray,
    ids: List<String>,
    records: List<CanonicalRecord>,
): ParsedFragment = ParsedFragment(
    bytes.size,
    OracleArtifacts.sha256(bytes),
    immutableList(ids),
    immutableList(records.map { it.bytes }),
)

private fun <T> immutableList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun requireStrictlyOrderedIds(values: List<String>, label: String) {
    if (values.zipWithNext().any { (left, right) -> left >= right }) {
        resumeValidationFailure("$label identities are duplicated or unordered")
    }
}

private fun requireAddressIdentity(value: String, id: String, prefix: String, label: String) {
    if (!value.matches(HEX_ADDRESS) || value.length !in 3..18) {
        resumeValidationFailure("$label address is not a canonical 64-bit hexadecimal address")
    }
    val expected = prefix + value.removePrefix("0x").padStart(16, '0')
    if (id != expected) resumeValidationFailure("$label identity does not match its address")
}

private fun requireHexAddress(value: String, label: String) {
    if (!value.matches(HEX_ADDRESS) || value.length !in 3..18) {
        resumeValidationFailure("$label is not a canonical 64-bit hexadecimal address")
    }
}

private class ExactByteVerifier(
    private val actual: ByteArray,
    private val label: String,
    private val maximumBytes: Int,
) {
    private var offset = 0

    fun accept(text: String) = accept(text.toByteArray(StandardCharsets.UTF_8))

    fun accept(bytes: ByteArray) {
        val next = try {
            Math.addExact(offset, bytes.size)
        } catch (failure: ArithmeticException) {
            throw GccCompilerEngineResumeEvidenceException("$label byte offset overflowed", failure)
        }
        if (next > maximumBytes) resumeValidationFailure("$label framing exceeds its supported byte bound")
        if (next > actual.size) resumeValidationFailure("$label is shorter than its assembled fragments")
        for (index in bytes.indices) {
            if (actual[offset + index] != bytes[index]) {
                resumeValidationFailure("$label differs from its assembled fragments")
            }
        }
        offset = next
    }

    fun acceptRecordArray(records: List<ByteArray>) {
        records.forEachIndexed { index, bytes ->
            if (bytes.isEmpty()) resumeValidationFailure("$label contains an empty record")
            accept(bytes)
            accept(if (index + 1 == records.size) "\n" else ",\n")
        }
    }

    fun finish() {
        if (offset != actual.size) resumeValidationFailure("$label has bytes beyond its assembled fragments")
    }
}

private fun requireFragmentBinding(bytes: ByteArray, values: Map<String, String>, prefix: String) {
    val expectedBytes = canonicalNonnegativeLong(values.getValue("${prefix}FragmentBytes"), "$prefix fragment bytes")
    val expectedSha256 = requireSha256(values.getValue("${prefix}FragmentSha256"), "$prefix fragment")
    if (expectedBytes != bytes.size.toLong() || expectedSha256 != OracleArtifacts.sha256(bytes)) {
        resumeValidationFailure("planning checkpoint does not authenticate its $prefix fragment")
    }
}

private fun strictObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
    OracleJson.parse(
        bytes,
        StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 16,
            maximumNodes = 256,
            maximumStringBytes = maximumBytes,
            maximumTotalStringBytes = maximumBytes,
        ),
    ) as? JsonObject ?: resumeValidationFailure("$label root is not an object")
} catch (failure: GccCompilerEngineResumeEvidenceException) {
    throw failure
} catch (failure: Exception) {
    throw GccCompilerEngineResumeEvidenceException("$label is not strict bounded JSON", failure)
}

private fun requireExactLine(bytes: ByteArray, label: String) {
    if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte() || bytes.any { it == '\r'.code.toByte() }) {
        resumeValidationFailure("$label is not exact newline-terminated JSON")
    }
    strictUtf8(bytes, label)
}

private fun requireBoundedBytes(bytes: ByteArray, maximumBytes: Int, allowEmpty: Boolean, label: String) {
    if ((!allowEmpty && bytes.isEmpty()) || bytes.size > maximumBytes) {
        resumeValidationFailure("$label is empty or exceeds its byte bound")
    }
}

private fun requireExactBytes(actual: ByteArray, rendered: String, label: String) {
    if (!MessageDigest.isEqual(actual, rendered.toByteArray(StandardCharsets.UTF_8))) {
        resumeValidationFailure("$label is not in the exact exporter-defined compact byte form")
    }
}

private fun renderExporterState(value: ParsedExporterState): String = buildString {
    append("{\"schemaVersion\":2,\"exporterVersion\":").append(value.exporterVersion)
    append(",\"exporterSha256\":").append(exporterJsonString(value.exporterSha256))
    append(",\"analysisToolSha256\":").append(exporterJsonString(value.analysisToolSha256))
    append(",\"recoveryMode\":").append(exporterJsonString(value.recoveryMode))
    append(",\"inputSha256\":").append(exporterJsonString(value.inputSha256))
    append(",\"language\":").append(exporterJsonString(value.language))
    append(",\"compilerSpec\":").append(exporterJsonString(value.compilerSpec))
    append(",\"semanticStateBinding\":{\"schemaVersion\":1")
    append(",\"scope\":\"planning-exporter-visible-program\"")
    append(",\"functionCount\":").append(value.functionCount)
    append(",\"planningBatchCount\":").append(value.planningBatchCount)
    append(",\"canonicalBytes\":").append(value.canonicalBytes)
    append(",\"sha256\":").append(exporterJsonString(value.semanticSha256))
    append(",\"batchCommitmentSha256\":").append(exporterJsonString(value.batchCommitmentSha256))
    append("}}\n")
}

private fun renderExportProgress(value: ParsedExportProgress): String = buildString {
    append("{\"schemaVersion\":1,\"phase\":").append(exporterJsonString(value.phase))
    append(",\"completed\":").append(value.completed)
    append(",\"total\":").append(value.total)
    append(",\"recovered\":").append(value.recovered)
    append(",\"partial\":").append(value.partial)
    append(",\"failed\":").append(value.failed)
    append(",\"reused\":").append(value.reused)
    append(",\"currentFunction\":null}\n")
}

private fun exporterJsonString(value: String): String = buildString {
    append('"')
    value.forEach { character ->
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u").append(character.code.toString(16).padStart(4, '0'))
            } else {
                append(character)
            }
        }
    }
    append('"')
}

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) resumeValidationFailure("$label fields are not exact")
}

private fun JsonObject.objectValue(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: resumeValidationFailure("$label field is not an object: $name")

private fun JsonObject.stringValue(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive ?: resumeValidationFailure("$label field is not a string: $name")
    if (!value.isString) resumeValidationFailure("$label field is not a string: $name")
    return value.content
}

private fun JsonObject.longValue(name: String, label: String): Long {
    val value = this[name] as? JsonPrimitive ?: resumeValidationFailure("$label field is not an integer: $name")
    if (value.isString || !value.content.matches(NONNEGATIVE_INTEGER)) {
        resumeValidationFailure("$label field is not a canonical nonnegative integer: $name")
    }
    return try {
        value.content.toLong()
    } catch (failure: NumberFormatException) {
        throw GccCompilerEngineResumeEvidenceException("$label integer is outside the Long range: $name", failure)
    }
}

private fun JsonObject.intValue(name: String, label: String): Int {
    val value = longValue(name, label)
    if (value > Int.MAX_VALUE) resumeValidationFailure("$label integer is outside the Int range: $name")
    return value.toInt()
}

private fun strictUtf8(bytes: ByteArray, label: String): String {
    val text = bytes.decodeToString()
    if (!MessageDigest.isEqual(bytes, text.encodeToByteArray())) {
        resumeValidationFailure("$label is not canonical UTF-8")
    }
    return text
}

private fun canonicalNonnegativeLong(value: String, label: String): Long {
    if (!value.matches(NONNEGATIVE_INTEGER)) resumeValidationFailure("$label is not a canonical nonnegative integer")
    return try {
        value.toLong()
    } catch (failure: NumberFormatException) {
        throw GccCompilerEngineResumeEvidenceException("$label is outside the Long range", failure)
    }
}

private fun parseOrderedIds(value: String, pattern: Regex, allowEmpty: Boolean, label: String): List<String> {
    if (value.isEmpty()) {
        if (!allowEmpty) resumeValidationFailure("planning checkpoint $label identities are empty")
        return emptyList()
    }
    val ids = value.split(',')
    if (ids.size > MAXIMUM_FUNCTIONS || ids.any { !it.matches(pattern) } ||
        ids.zipWithNext().any { (left, right) -> left >= right }
    ) {
        resumeValidationFailure("planning checkpoint $label identities are invalid or unordered")
    }
    return Collections.unmodifiableList(ids)
}

private fun requireSha256(value: String, label: String): String {
    if (!value.matches(SHA256)) resumeValidationFailure("$label has an invalid SHA-256 value")
    return value
}

private fun requireIdentity(value: String, label: String): String {
    if (value.isEmpty() || value.length > MAXIMUM_IDENTITY_CHARACTERS ||
        value.any { it.code < 0x20 || it.code == 0x7f }
    ) {
        resumeValidationFailure("$label is empty, oversized, or contains control characters")
    }
    return value
}

private fun exactAdd(label: String, vararg values: Long): Long = try {
    values.fold(0L, Math::addExact)
} catch (failure: ArithmeticException) {
    throw GccCompilerEngineResumeEvidenceException("$label overflows its supported range", failure)
}

private fun exactSubtract(label: String, left: Long, right: Long): Long = try {
    Math.subtractExact(left, right)
} catch (failure: ArithmeticException) {
    throw GccCompilerEngineResumeEvidenceException("$label overflows its supported range", failure)
}

private fun addExactBounded(current: Long, increment: Long, maximum: Long, label: String): Long {
    if (increment < 0L) resumeValidationFailure("$label has a negative increment")
    val value = try {
        Math.addExact(current, increment)
    } catch (failure: ArithmeticException) {
        throw GccCompilerEngineResumeEvidenceException("$label overflows its supported range", failure)
    }
    if (value > maximum) resumeValidationFailure("$label exceeds its supported bound")
    return value
}

private fun ceilingBatchCount(functionCount: Long): Long =
    exactAdd("planning batch ceiling", functionCount, PLANNING_BATCH_FUNCTIONS - 1L) / PLANNING_BATCH_FUNCTIONS

private fun resumeValidationFailure(message: String): Nothing =
    throw GccCompilerEngineResumeEvidenceException(message)

private const val MAXIMUM_EXPORT_STATE_BYTES = 64 * 1024
private const val MAXIMUM_PROGRESS_BYTES = 1024 * 1024
private const val MAXIMUM_PLANNING_BATCH_CHECKPOINT_BYTES = 256 * 1024
private const val MAXIMUM_PLANNING_BATCH_FRAGMENT_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_PLANNING_EVIDENCE_RECORD_BYTES = 1024 * 1024
private const val MAXIMUM_PROGRAM_MODEL_BYTES = 512 * 1024 * 1024
private const val MAXIMUM_MODULE_PLAN_BYTES = 512 * 1024 * 1024
private const val MAXIMUM_RETAINED_FRAGMENT_BYTES = 512L * 1024 * 1024
private const val MAXIMUM_TRANSITION_CAPTURE_BYTES = 2L * 1024 * 1024 * 1024
private const val MAXIMUM_SEMANTIC_BYTES = 1024L * 1024 * 1024
private const val MAXIMUM_UNIQUE_EVIDENCE_BYTES = 512L * 1024 * 1024
private const val SEMANTIC_FRAME_OVERHEAD = 17L
private const val MAXIMUM_RECORD_STRING_BYTES = 1024 * 1024
private const val MAXIMUM_RECORD_JSON_NODES = 1_000_000
private const val MAXIMUM_RECORD_ARRAY_ENTRIES = 1_000_000
private const val MAXIMUM_IDENTITY_CHARACTERS = 256
private const val SUPPORTED_EXPORTER_VERSION = 10
private const val FUNCTION_RECORD_TAG: Byte = 1
private const val GLOBAL_RECORD_TAG: Byte = 2
private const val TYPE_RECORD_TAG: Byte = 3
private const val FAILURE_RECORD_TAG: Byte = 4
private const val TERMINAL_RECORD_TAG: Byte = 5
private const val NON_AUTHORITATIVE_ASSESSMENT = "non-authoritative-byte-assessment"
private const val PLANNING_BATCH_FUNCTIONS = 512L
private const val MAXIMUM_PLANNING_BATCHES = 256L
private const val MAXIMUM_FUNCTIONS = PLANNING_BATCH_FUNCTIONS * MAXIMUM_PLANNING_BATCHES
private val SHA256 = Regex("[0-9a-f]{64}")
private val NONNEGATIVE_INTEGER = Regex("0|[1-9][0-9]*")
private val FUNCTION_ID = Regex("fn_[0-9a-f]{16}")
private val GLOBAL_ID = Regex("global_[0-9a-f]{16}")
private val TYPE_ID = Regex("type_[0-9a-f]{64}")
private val HEX_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]*)")
private const val RECORD_PREFIX = "    {\n      \"id\": "
private const val RECORD_SEPARATOR = ",\n"
private const val RECORD_SUFFIX = "\n    }"
private val SEMANTIC_FINGERPRINT_DOMAIN =
    "decomp-thing/program-semantic-fingerprint/v1\n".toByteArray(StandardCharsets.US_ASCII)
private val BATCH_COMMITMENT_DOMAIN =
    "decomp-thing/planning-batch-commitments/v1\n".toByteArray(StandardCharsets.US_ASCII)
private val PLANNING_CHECKPOINT_KEYS = listOf(
    "schemaVersion",
    "exporterVersion",
    "recoveryMode",
    "stateSha256",
    "inventorySha256",
    "startIndex",
    "endExclusive",
    "functionFragmentBytes",
    "functionFragmentSha256",
    "recovered",
    "partial",
    "failed",
    "functionIds",
    "globalFragmentBytes",
    "globalFragmentSha256",
    "globalIds",
    "typeFragmentBytes",
    "typeFragmentSha256",
    "typeIds",
    "failureFragmentBytes",
    "failureFragmentSha256",
    "failureIds",
)

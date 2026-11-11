package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import decompengine.agent.AgentStopReason
import decompengine.agent.isCanonicalAgentTurnId
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import kotlinx.serialization.json.Json

/**
 * Private, append-only workflow evidence outside the staged source tree. The workspace lease
 * binds every write to one live output root and input. The directory is a preserved workspace
 * entry, so an input switch archives it with the corresponding reconstruction outputs.
 */
internal enum class ReconstructionTurnEvidenceStorePoint {
    AFTER_TURN_DIRECTORY_OPEN,
    BEFORE_TEMPORARY_LINK,
    AFTER_PUBLICATION_RENAME,
    BEFORE_READBACK,
}

internal class ReconstructionTurnEvidenceStore(
    private val publicationLock: ReconstructionPublicationLock,
    private val inputSha256: String,
    private val faultInjector: ((ReconstructionTurnEvidenceStorePoint) -> Unit)? = null,
) {
    private val root: Path
        get() = publicationLock.canonicalRoot

    init {
        require(inputSha256.matches(HASH))
        require(publicationLock.admittedInputSha256 == inputSha256) {
            "turn evidence input differs from the admitted reconstruction input"
        }
    }

    fun persistIntent(intent: AgentTurnIntent): String {
        require(intent.profileSha256.matches(HASH))
        return openTurnDirectory(intent.taskId, intent.turnId, create = true).use { directory ->
            writeOnce(directory, INTENT_FILE, intent.canonicalBytes(), MAXIMUM_DOCUMENT_BYTES)
            directory.relative(INTENT_FILE)
        }
    }

    fun persistReceipt(intent: AgentTurnIntent, receiptBytes: ByteArray): Pair<String, String> {
        return openTurnDirectory(intent.taskId, intent.turnId, create = true).use { directory ->
            require(readFileAt(directory, INTENT_FILE, MAXIMUM_DOCUMENT_BYTES)
                .contentEquals(intent.canonicalBytes())) { "turn receipt has no matching durable intent" }
            val receipt = verifyAcpExecutionReceiptDocument(
                receiptBytes,
                RECONSTRUCTION_ACP_RECEIPT_KIND,
                RECONSTRUCTION_ACP_TASK_FIELD,
                intent.taskId,
            )
            require(receipt.schemaVersion >= 3 &&
                receipt.requestSha256 == intent.requestSha256 &&
                receipt.accessPolicySha256 == intent.policySha256 &&
                receipt.turnIdentity?.turnId == intent.turnId &&
                receipt.turnIdentity.taskId == intent.taskId &&
                receipt.turnIdentity.requestSha256 == intent.requestSha256) {
                "turn receipt identity or request differs from its durable intent"
            }
            writeOnce(directory, RECEIPT_FILE, receiptBytes, MAXIMUM_RECEIPT_BYTES)
            directory.relative(RECEIPT_FILE) to sha256(receiptBytes)
        }
    }

    fun persistAssessment(intent: AgentTurnIntent, assessment: AcpChangeAssessment): String {
        require(assessment.turnId == intent.turnId && assessment.intentSha256 == intent.sha256) {
            "turn assessment does not match its persisted intent"
        }
        return openTurnDirectory(intent.taskId, intent.turnId, create = true).use { directory ->
            // Intent is a mandatory pre-dispatch witness. Refuse to write a derived assessment if
            // that exact immutable source document is absent or was replaced.
            require(readFileAt(directory, INTENT_FILE, MAXIMUM_DOCUMENT_BYTES).contentEquals(intent.canonicalBytes())) {
                "turn assessment has no matching durable intent"
            }
            if (assessment.receiptSha256 == null) {
                require(!fileExistsAt(directory, RECEIPT_FILE)) {
                    "turn without a receipt cannot retain receipt bytes"
                }
            } else {
                val receipt = readFileAt(directory, RECEIPT_FILE, MAXIMUM_RECEIPT_BYTES)
                require(sha256(receipt) == assessment.receiptSha256) {
                    "turn assessment differs from its immutable receipt"
                }
            }
            writeOnce(directory, ASSESSMENT_FILE, assessment.canonicalBytes(), MAXIMUM_DOCUMENT_BYTES)
            directory.relative(ASSESSMENT_FILE)
        }
    }

    /**
     * Re-authenticates every schema-7 checkpoint reference before it can be reused or restored.
     * Embedded hashes alone are insufficient: an attacker or damaged checkpoint could replace an
     * assessment and recompute its self-declared digest without changing the invocation receipt.
     */
    fun verifyCheckpointProvenance(
        moduleId: String,
        profileSha256: String,
        sourcePath: String,
        sourceSha256: String,
        accepted: Boolean,
        intentPath: String?,
        intentSha256: String?,
        intent: AgentTurnIntent?,
        receiptPath: String?,
        receiptSha256: String?,
        executionEvidenceSha256: String?,
        assessmentPath: String?,
        assessmentSha256: String?,
        assessment: AcpChangeAssessment?,
        compilation: ModuleCompilationEvidence?,
        executionRequestSha256: String?,
        executionTerminalOutcome: String?,
        executionReleaseComplete: Boolean?,
    ): Boolean {
        try {
            val boundIntent = requireNotNull(intent)
            require(boundIntent.taskId == moduleId && boundIntent.attemptId == boundIntent.turnId &&
                boundIntent.profileSha256 == profileSha256 && boundIntent.requestSha256 == executionRequestSha256)
            val directory = "${DIRECTORY}/$inputSha256/$moduleId/${boundIntent.turnId}"
            val expectedIntentPath = "$directory/$INTENT_FILE"
            val expectedReceiptPath = "$directory/$RECEIPT_FILE"
            val expectedAssessmentPath = "$directory/$ASSESSMENT_FILE"
            require(intentPath == expectedIntentPath && assessmentPath == expectedAssessmentPath &&
                (receiptPath == null || receiptPath == expectedReceiptPath))
            val intentBytes = readExistingTurnFile(expectedIntentPath, MAXIMUM_DOCUMENT_BYTES)
            require(sha256(intentBytes) == intentSha256 && intentBytes.contentEquals(boundIntent.canonicalBytes()))
            val assessmentBytes = readExistingTurnFile(expectedAssessmentPath, MAXIMUM_DOCUMENT_BYTES)
            val parsedAssessment = requireNotNull(assessment)
            require(sha256(assessmentBytes) == assessmentSha256 &&
                assessmentBytes.contentEquals(parsedAssessment.canonicalBytes()) &&
                parsedAssessment.turnId == boundIntent.turnId &&
                parsedAssessment.intentSha256 == boundIntent.sha256 &&
                parsedAssessment.policySha256 == boundIntent.policySha256 &&
                parsedAssessment.beforeSha256 == boundIntent.beforeSha256)
            if (receiptPath == null || receiptSha256 == null || executionEvidenceSha256 == null) {
                require(receiptPath == null && receiptSha256 == null && executionEvidenceSha256 == null &&
                    parsedAssessment.receiptSha256 == null && parsedAssessment.sessionIdSha256 == null &&
                    parsedAssessment.changesSha256 == null && parsedAssessment.afterSha256 == null &&
                    parsedAssessment.beforeSha256 == boundIntent.beforeSha256 &&
                    parsedAssessment.observation == AcpChangeObservationStatus.UNKNOWN &&
                    parsedAssessment.eligibility == AcpChangePublicationEligibility.INTERRUPTED &&
                    !accepted)
                return true
            }
            val receipt = readExistingTurnFile(expectedReceiptPath, MAXIMUM_RECEIPT_BYTES)
            val expectedReceiptDigest = receiptSha256
            require(sha256(receipt) == expectedReceiptDigest && executionEvidenceSha256 == expectedReceiptDigest)
            val verified = verifyAcpExecutionReceiptDocument(
                receipt,
                RECONSTRUCTION_ACP_RECEIPT_KIND,
                RECONSTRUCTION_ACP_TASK_FIELD,
                moduleId,
            )
            require(verified.requestSha256 == boundIntent.requestSha256 &&
                verified.turnIdentity?.turnId == boundIntent.turnId &&
                verified.turnIdentity.taskId == boundIntent.taskId &&
                verified.turnIdentity.requestSha256 == boundIntent.requestSha256 &&
                verified.accessPolicySha256 == boundIntent.policySha256 &&
                verified.terminalOutcome == executionTerminalOutcome &&
                verified.releaseComplete == executionReleaseComplete)
            val facts = requireNotNull(verified.releaseFacts)
            val exactChange = facts.changes.single()
            require(exactChange.rootId == expectedAcpTextCommitment("project") &&
                exactChange.relativePath == expectedAcpTextCommitment(sourcePath) &&
                exactChange.afterSha256 != null &&
                (exactChange.beforeSha256 ?: sha256("absent-v1:$sourcePath".toByteArray(StandardCharsets.UTF_8))) ==
                    boundIntent.beforeSha256)
            val proofDigests = compilation?.let {
                listOf(sha256(OracleJson.canonicalBytes(
                    Json.parseToJsonElement(it.toJson()),
                    StrictJsonLimits(maximumInputBytes = 1024 * 1024, maximumCanonicalBytes = 1024 * 1024),
                )))
            }.orEmpty()
            val stopReason = verified.terminalOutcome.takeIf { it.startsWith("returned-") }
                ?.removePrefix("returned-")
                ?.let { AgentStopReason.valueOf(it.uppercase().replace('-', '_')) }
            require(parsedAssessment.turnId == boundIntent.turnId &&
                parsedAssessment.intentSha256 == boundIntent.sha256 &&
                parsedAssessment.receiptSha256 == expectedReceiptDigest &&
                parsedAssessment.sessionIdSha256 == verified.sessionIdCommitmentSha256?.let {
                    sha256("acp-session-commitment-v1:$it".toByteArray(StandardCharsets.UTF_8))
                } &&
                parsedAssessment.changesSha256 == verified.resultChangesSha256 &&
                parsedAssessment.beforeSha256 == boundIntent.beforeSha256 &&
                parsedAssessment.afterSha256 == exactChange.afterSha256 &&
                parsedAssessment.observation == AcpChangeObservationStatus.COMPLETE &&
                parsedAssessment.normalizedStopReason == stopReason &&
                parsedAssessment.protocolStopCode == null &&
                parsedAssessment.policySha256 == verified.accessPolicySha256 &&
                parsedAssessment.updatesSha256 == verified.updatesSha256 &&
                parsedAssessment.validationProofSha256 == proofDigests)
            if (accepted) {
                require(executionTerminalOutcome == "returned-completed" &&
                    executionReleaseComplete == true && compilation?.passed == true &&
                    exactChange.afterSha256 == sourceSha256 &&
                    parsedAssessment.policyVerdict == AcpChangePolicyVerdict.ALLOW &&
                    parsedAssessment.validationStatus == AcpChangeValidationStatus.PASSED &&
                    parsedAssessment.eligibility == AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION)
            } else {
                require(parsedAssessment.eligibility != AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION)
            }
            return true
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        } catch (_: Exception) {
            return false
        }
    }

    private fun openTurnDirectory(taskId: String, turnId: String, create: Boolean): TurnDirectory {
        publicationLock.borrow(root, inputSha256)
        require(taskId.matches(MODULE)) { "turn evidence task ID is invalid" }
        require(isCanonicalAgentTurnId(turnId)) { "turn evidence ID is invalid" }
        val rootDirectory = publicationLock.rootDirectoryDescriptor()
        val names = listOf(DIRECTORY, inputSha256, taskId, turnId)
        val opened = mutableListOf<LinuxDescriptor>()
        try {
            names.forEach { name ->
                publicationLock.borrow(root, inputSha256)
                val parent = opened.lastOrNull() ?: rootDirectory
                val next = openPrivateDirectoryAt(parent, name, rootDirectory.identity.uid, create)
                opened += next
            }
            return TurnDirectory(rootDirectory, names, opened.toList()).also {
                faultInjector?.invoke(ReconstructionTurnEvidenceStorePoint.AFTER_TURN_DIRECTORY_OPEN)
            }
        } catch (failure: Throwable) {
            opened.asReversed().forEach { it.close() }
            throw failure
        }
    }

    private fun openPrivateDirectoryAt(
        parent: LinuxDescriptor,
        name: String,
        ownerUid: Int,
        create: Boolean,
    ): LinuxDescriptor {
        val descriptor = try {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno != LinuxFilesystemSyscalls.ENOENT || !create) {
                throw IllegalArgumentException("turn evidence namespace is missing or unsafe", failure)
            }
            try {
                LinuxFilesystemSyscalls.createDirectory(parent.fd, name, PRIVATE_DIRECTORY_MODE)
                LinuxFilesystemSyscalls.synchronize(parent)
            } catch (race: LinuxSyscallException) {
                if (race.errno != LinuxFilesystemSyscalls.EEXIST) throw race
            }
            try {
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
            } catch (openFailure: LinuxSyscallException) {
                throw IllegalArgumentException("turn evidence namespace is missing or unsafe", openFailure)
            }
        }
        val identity = descriptor.identity
        if (!identity.isDirectory || identity.isSymbolicLink || identity.uid != ownerUid ||
            identity.mode.permissions != PRIVATE_DIRECTORY_MODE) {
            descriptor.close()
            throw IllegalArgumentException("turn evidence directory is not private to the workspace owner")
        }
        return descriptor
    }

    private fun writeOnce(directory: TurnDirectory, name: String, bytes: ByteArray, maximumBytes: Int) {
        require(bytes.size <= maximumBytes) { "turn evidence document exceeds its byte bound" }
        publicationLock.borrow(root, inputSha256)
        directory.verifyNamespace()
        require(!fileExistsAt(directory, name)) {
            "turn evidence is immutable and already exists"
        }
        val temporaryName = ".turn-evidence-${UUID.randomUUID()}.tmp"
        val temporary = LinuxFilesystemSyscalls.createTemporaryAt(directory.descriptor.fd)
        var linked = false
        try {
            LinuxFilesystemSyscalls.chmod(temporary, PRIVATE_FILE_MODE)
            LinuxFilesystemSyscalls.write(temporary, bytes) { }
            publicationLock.borrow(root, inputSha256)
            faultInjector?.invoke(ReconstructionTurnEvidenceStorePoint.BEFORE_TEMPORARY_LINK)
            directory.verifyNamespace()
            LinuxFilesystemSyscalls.linkTemporaryAt(temporary, directory.descriptor.fd, temporaryName)
            linked = true
            LinuxFilesystemSyscalls.synchronize(directory.descriptor)
            try {
                LinuxFilesystemSyscalls.renameNoReplace(directory.descriptor.fd, temporaryName, name)
                linked = false
                faultInjector?.invoke(ReconstructionTurnEvidenceStorePoint.AFTER_PUBLICATION_RENAME)
            } catch (failure: LinuxSyscallException) {
                if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                    throw IllegalStateException("turn evidence is immutable and already exists", failure)
                }
                throw failure
            }
            try {
                LinuxFilesystemSyscalls.synchronize(directory.descriptor)
                directory.verifyNamespace()
                val published = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.descriptor.fd, name))
                published.use { actual ->
                    require(actual.identity.key == temporary.identity.key && actual.identity.mountId == temporary.identity.mountId &&
                        actual.identity.uid == directory.descriptor.identity.uid && actual.identity.linkCount == 1 &&
                        actual.identity.mode.permissions == PRIVATE_FILE_MODE) {
                        "turn evidence publication identity or permissions changed"
                    }
                }
                faultInjector?.invoke(ReconstructionTurnEvidenceStorePoint.BEFORE_READBACK)
                require(readFileAt(directory, name, maximumBytes).contentEquals(bytes)) {
                    "turn evidence readback differs from the immutable document"
                }
                directory.verifyNamespace()
                LinuxFilesystemSyscalls.synchronize(publicationLock.rootDirectoryDescriptor())
            } catch (failure: Throwable) {
                // The name has been exchanged but this call has not returned a durable path to
                // its caller. If its pinned directory was detached between the preceding check
                // and readback, remove only the exact inode we published so an unacknowledged
                // sidecar cannot be stranded outside the admitted workspace namespace.
                discardUnacknowledgedPublication(directory.descriptor, name, temporary, failure)
                throw failure
            }
        } finally {
            if (linked) runCatching { LinuxFilesystemSyscalls.unlinkIfPresent(directory.descriptor.fd, temporaryName) }
            temporary.close()
        }
    }

    private fun discardUnacknowledgedPublication(
        directory: LinuxDescriptor,
        name: String,
        expected: LinuxDescriptor,
        original: Throwable,
    ) {
        try {
            val published = LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name) ?: return
            published.use { actual ->
                val identity = actual.identity
                if (identity.key == expected.identity.key && identity.mountId == expected.identity.mountId &&
                    identity.uid == directory.identity.uid && identity.linkCount == 1 &&
                    identity.mode.permissions == PRIVATE_FILE_MODE) {
                    LinuxFilesystemSyscalls.unlinkIfPresent(directory.fd, name)
                    LinuxFilesystemSyscalls.synchronize(directory)
                }
            }
        } catch (cleanupFailure: Throwable) {
            original.addSuppressed(cleanupFailure)
        }
    }

    private fun fileExistsAt(directory: TurnDirectory, name: String): Boolean =
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.descriptor.fd, name)?.use { true } ?: false

    private fun readFileAt(directory: TurnDirectory, name: String, maximumBytes: Int): ByteArray {
        publicationLock.borrow(root, inputSha256)
        directory.verifyNamespace()
        val pinned = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.descriptor.fd, name)) {
            "turn evidence is missing or is not an ordinary file"
        }
        pinned.use { entry ->
            val identity = entry.identity
            require(identity.uid == directory.descriptor.identity.uid && identity.linkCount == 1 &&
                identity.mode.permissions == PRIVATE_FILE_MODE) {
                "turn evidence file is not private to the workspace owner"
            }
            val readable = LinuxFilesystemSyscalls.openReadableFrom(entry)
            readable.use { file ->
                val before = LinuxFilesystemSyscalls.fileState(file)
                require(before.size in 0..maximumBytes.toLong()) { "turn evidence exceeds its byte bound" }
                val bytes = LinuxFilesystemSyscalls.read(file, maximumBytes) { }
                val after = LinuxFilesystemSyscalls.fileState(file)
                require(before.identity.key == after.identity.key && before.identity.mountId == after.identity.mountId &&
                    before.size == after.size && before.modificationTimeSeconds == after.modificationTimeSeconds &&
                    before.modificationTimeNanoseconds == after.modificationTimeNanoseconds &&
                    before.changeTimeSeconds == after.changeTimeSeconds &&
                    before.changeTimeNanoseconds == after.changeTimeNanoseconds && bytes.size.toLong() == before.size) {
                    "turn evidence changed while it was read"
                }
                directory.verifyNamespace()
                return bytes
            }
        }
    }

    private fun readExistingTurnFile(relativePath: String, maximumBytes: Int): ByteArray {
        require(relativePath.startsWith("$DIRECTORY/$inputSha256/") &&
            !relativePath.split('/').any { it == "." || it == ".." }) {
            "turn evidence path is outside its admitted namespace"
        }
        val components = relativePath.split('/')
        require(components.size == 5 && components[0] == DIRECTORY && components[1] == inputSha256 &&
            components[2].matches(MODULE) && isCanonicalAgentTurnId(components[3]) &&
            components[4] in setOf(INTENT_FILE, RECEIPT_FILE, ASSESSMENT_FILE)) {
            "turn evidence path has an invalid namespace shape"
        }
        return openTurnDirectory(components[2], components[3], create = false).use { directory ->
            readFileAt(directory, components[4], maximumBytes)
        }
    }

    private class TurnDirectory(
        private val root: LinuxDescriptor,
        private val names: List<String>,
        private val directories: List<LinuxDescriptor>,
    ) : AutoCloseable {
        val descriptor: LinuxDescriptor get() = directories.last()

        fun relative(fileName: String): String = "${names.joinToString("/")}/$fileName"

        fun verifyNamespace() {
            require(names.size == directories.size)
            var parent = root
            names.indices.forEach { index ->
                val named = try {
                    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, names[index])
                } catch (failure: LinuxSyscallException) {
                    throw IllegalArgumentException("turn evidence directory binding is missing or unsafe", failure)
                }
                named.use {
                    val expected = directories[index].identity
                    require(it.identity.key == expected.key && it.identity.mountId == expected.mountId) {
                        "turn evidence directory binding changed during the operation"
                    }
                }
                parent = directories[index]
            }
        }

        override fun close() = directories.asReversed().forEach { it.close() }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    companion object {
        const val DIRECTORY = ".agent-turn-evidence"
        const val INTENT_FILE = "intent.json"
        const val RECEIPT_FILE = "receipt.json"
        const val ASSESSMENT_FILE = "assessment.json"
        private const val RECONSTRUCTION_ACP_RECEIPT_KIND = "decomp-engine.reconstruction-acp-execution-receipt"
        private const val RECONSTRUCTION_ACP_TASK_FIELD = "moduleId"
        private const val MAXIMUM_DOCUMENT_BYTES = 1024 * 1024
        private const val MAXIMUM_RECEIPT_BYTES = 64 * 1024 * 1024
        private const val PRIVATE_DIRECTORY_MODE = 0x1c0 // 0700
        private const val PRIVATE_FILE_MODE = 0x180 // 0600
        private val HASH = Regex("[0-9a-f]{64}")
        private val MODULE = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    }
}

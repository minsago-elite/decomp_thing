package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.agent.isCanonicalAgentTurnId
import decompengine.agent.AgentStopReason
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.Json

/**
 * Private, append-only workflow evidence outside the staged source tree. The workspace lease
 * binds every write to one live output root and input. The directory is a preserved workspace
 * entry, so an input switch archives it with the corresponding reconstruction outputs.
 */
internal class ReconstructionTurnEvidenceStore(
    private val publicationLock: ReconstructionPublicationLock,
    private val inputSha256: String,
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
        val directory = turnDirectory(intent.taskId, intent.turnId)
        writeOnce(directory.resolve(INTENT_FILE), intent.canonicalBytes(), MAXIMUM_DOCUMENT_BYTES)
        return relative(directory.resolve(INTENT_FILE))
    }

    fun persistReceipt(intent: AgentTurnIntent, receiptBytes: ByteArray): Pair<String, String> {
        val directory = turnDirectory(intent.taskId, intent.turnId)
        require(readBoundedRegularFile(directory.resolve(INTENT_FILE), MAXIMUM_DOCUMENT_BYTES)
            .contentEquals(intent.canonicalBytes())) { "turn receipt has no matching durable intent" }
        val path = directory.resolve(RECEIPT_FILE)
        writeOnce(path, receiptBytes, MAXIMUM_RECEIPT_BYTES)
        return relative(path) to sha256(receiptBytes)
    }

    fun persistAssessment(intent: AgentTurnIntent, assessment: AcpChangeAssessment): String {
        require(assessment.turnId == intent.turnId && assessment.intentSha256 == intent.sha256) {
            "turn assessment does not match its persisted intent"
        }
        val directory = turnDirectory(intent.taskId, intent.turnId)
        // Intent is a mandatory pre-dispatch witness. Refuse to write a derived assessment if
        // that exact immutable source document is absent or was replaced.
        val intentPath = directory.resolve(INTENT_FILE)
        require(readBoundedRegularFile(intentPath, MAXIMUM_DOCUMENT_BYTES).contentEquals(intent.canonicalBytes())) {
            "turn assessment has no matching durable intent"
        }
        if (assessment.receiptSha256 == null) {
            require(!Files.exists(directory.resolve(RECEIPT_FILE), NOFOLLOW_LINKS)) {
                "turn without a receipt cannot retain receipt bytes"
            }
        } else {
            val receipt = readBoundedRegularFile(directory.resolve(RECEIPT_FILE), MAXIMUM_RECEIPT_BYTES)
            require(sha256(receipt) == assessment.receiptSha256) {
                "turn assessment differs from its immutable receipt"
            }
        }
        writeOnce(directory.resolve(ASSESSMENT_FILE), assessment.canonicalBytes(), MAXIMUM_DOCUMENT_BYTES)
        return relative(directory.resolve(ASSESSMENT_FILE))
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

    private fun turnDirectory(taskId: String, turnId: String): Path {
        publicationLock.borrow(root, inputSha256)
        require(taskId.matches(MODULE)) { "turn evidence task ID is invalid" }
        require(isCanonicalAgentTurnId(turnId)) { "turn evidence ID is invalid" }
        val base = root.resolve(DIRECTORY)
        ensurePrivateDirectory(root, base)
        val inputDirectory = base.resolve(inputSha256)
        ensurePrivateDirectory(base, inputDirectory)
        val taskDirectory = inputDirectory.resolve(taskId)
        ensurePrivateDirectory(inputDirectory, taskDirectory)
        val directory = taskDirectory.resolve(turnId)
        ensurePrivateDirectory(taskDirectory, directory)
        return directory
    }

    private fun writeOnce(path: Path, bytes: ByteArray, maximumBytes: Int) {
        require(bytes.size <= maximumBytes) { "turn evidence document exceeds its byte bound" }
        publicationLock.borrow(root, inputSha256)
        require(!Files.exists(path, NOFOLLOW_LINKS)) {
            "turn evidence is immutable and already exists"
        }
        val temporary = Files.createTempFile(
            path.parent,
            ".turn-evidence-",
            ".tmp",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        )
        try {
            FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            publicationLock.borrow(root, inputSha256)
            try {
                Files.move(temporary, path, ATOMIC_MOVE)
            } catch (failure: java.nio.file.FileAlreadyExistsException) {
                throw IllegalStateException("turn evidence is immutable and already exists", failure)
            }
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
                "turn evidence write did not publish an ordinary file"
            }
            val attributes = Files.readAttributes(path, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS)
            require(attributes.owner() == Files.readAttributes(root, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS).owner() &&
                attributes.permissions() == PosixFilePermissions.fromString("rw-------") &&
                attributes.size() == bytes.size.toLong() && bytes.size <= maximumBytes) {
                "turn evidence file identity or bounds changed during publication"
            }
            require(readBoundedRegularFile(path, maximumBytes).contentEquals(bytes)) {
                "turn evidence readback differs from the immutable document"
            }
            FileChannel.open(path.parent, READ, NOFOLLOW_LINKS).use { it.force(true) }
            LinuxFilesystemSyscalls.synchronize(publicationLock.rootDirectoryDescriptor())
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun ensurePrivateDirectory(parent: Path, directory: Path) {
        publicationLock.borrow(root, inputSha256)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) {
            try {
                Files.createDirectory(directory,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                FileChannel.open(parent, READ, NOFOLLOW_LINKS).use { it.force(true) }
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                // Validate the winner below; never accept a link or non-directory race.
            }
        }
        require(!Files.isSymbolicLink(directory) && Files.isDirectory(directory, NOFOLLOW_LINKS)) {
            "turn evidence path is not an ordinary directory"
        }
        val attrs = Files.readAttributes(directory, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS)
        require(attrs.permissions() == PosixFilePermissions.fromString("rwx------") &&
            attrs.owner() == Files.readAttributes(root, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS).owner()) {
            "turn evidence directory is not private to the workspace owner"
        }
    }

    private fun relative(path: Path): String = root.relativize(path).toString().replace('\\', '/')

    private fun readBoundedRegularFile(path: Path, maximumBytes: Int): ByteArray {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "turn evidence is missing or is not an ordinary file"
        }
        FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
            val size = channel.size()
            require(size in 0..maximumBytes.toLong()) { "turn evidence exceeds its byte bound" }
            val bytes = ByteArray(size.toInt())
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) {
                require(channel.read(buffer) >= 0) { "turn evidence became truncated during readback" }
            }
            require(channel.size() == size) { "turn evidence changed during readback" }
            return bytes
        }
    }

    private fun readExistingTurnFile(relativePath: String, maximumBytes: Int): ByteArray {
        require(relativePath.startsWith("$DIRECTORY/$inputSha256/") &&
            !relativePath.split('/').any { it == "." || it == ".." }) {
            "turn evidence path is outside its admitted namespace"
        }
        val path = root.resolve(relativePath).normalize()
        require(path.startsWith(root) && Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "turn evidence is missing or is not an ordinary file"
        }
        val components = root.relativize(path).toList()
        var parent = root
        val rootOwner = Files.readAttributes(root, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS).owner()
        components.dropLast(1).forEach { component ->
            parent = parent.resolve(component)
            require(Files.isDirectory(parent, NOFOLLOW_LINKS) && !Files.isSymbolicLink(parent)) {
                "turn evidence namespace contains a link or non-directory"
            }
            val directoryAttributes = Files.readAttributes(
                parent, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS,
            )
            require(directoryAttributes.owner() == rootOwner &&
                directoryAttributes.permissions() == PosixFilePermissions.fromString("rwx------")) {
                "turn evidence directory is not private to the workspace owner"
            }
        }
        val attributes = Files.readAttributes(path, java.nio.file.attribute.PosixFileAttributes::class.java, NOFOLLOW_LINKS)
        require(attributes.owner() == rootOwner && attributes.permissions() == PosixFilePermissions.fromString("rw-------")) {
            "turn evidence file is not private to the workspace owner"
        }
        return readBoundedRegularFile(path, maximumBytes)
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
        private val HASH = Regex("[0-9a-f]{64}")
        private val MODULE = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    }
}

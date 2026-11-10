package decompengine.project

import decompengine.agent.AgentStopReason
import decompengine.agent.AgentTurnIdentity
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReconstructionTurnEvidenceStoreTest {
    @Test
    fun `turn intent precedes assessment and both documents are immutable and owner private`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val base = Files.createTempDirectory(scratch, "turn-evidence-")
        val root = base.resolve("output")
        val input = base.resolve("input").also { Files.writeString(it, "input") }
        try {
            ReconstructionOutputWorkspace.open(root, input).use { workspace ->
                val store = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
                val turnId = UUID.randomUUID().toString()
                val intent = intent(turnId, "a".repeat(64), workspace.inputSha256)
                val intentPath = root.resolve(store.persistIntent(intent))
                assertTrue(Files.isRegularFile(intentPath))
                assertEquals(intent.sha256, AgentTurnIntent.parse(Files.readAllBytes(intentPath)).sha256)
                assertEquals("rwx------", PosixFilePermissions.toString(
                    Files.getPosixFilePermissions(intentPath.parent.parent.parent.parent)))
                assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(intentPath)))

                val assessment = AcpChangeAssessment.create(
                    intent = intent,
                    receiptSha256 = null,
                    sessionIdSha256 = null,
                    changesSha256 = null,
                    beforeSha256 = workspace.inputSha256,
                    afterSha256 = null,
                    observation = AcpChangeObservationStatus.UNKNOWN,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.CANCELLED,
                    policyVerdict = AcpChangePolicyVerdict.NOT_EVALUATED,
                    reasonCodes = listOf("workflow-interrupted"),
                    validationStatus = AcpChangeValidationStatus.NOT_RUN,
                    validationProofSha256 = emptyList(),
                    eligibility = AcpChangePublicationEligibility.INTERRUPTED,
                    updatesSha256 = null,
                )
                val assessmentPath = root.resolve(store.persistAssessment(intent, assessment))
                assertEquals(assessment.sha256, AcpChangeAssessment.parse(Files.readAllBytes(assessmentPath)).sha256)
                assertFailsWith<IllegalArgumentException> { store.persistIntent(intent) }

                val crossedIntent = intent(turnId, "b".repeat(64), workspace.inputSha256)
                assertFailsWith<IllegalArgumentException> { store.persistIntent(crossedIntent) }
                val crossedAssessment = AcpChangeAssessment.create(
                    intent = crossedIntent,
                    receiptSha256 = null,
                    sessionIdSha256 = null,
                    changesSha256 = null,
                    beforeSha256 = workspace.inputSha256,
                    afterSha256 = null,
                    observation = AcpChangeObservationStatus.UNKNOWN,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.CANCELLED,
                    policyVerdict = AcpChangePolicyVerdict.NOT_EVALUATED,
                    reasonCodes = listOf("workflow-interrupted"),
                    validationStatus = AcpChangeValidationStatus.NOT_RUN,
                    validationProofSha256 = emptyList(),
                    eligibility = AcpChangePublicationEligibility.INTERRUPTED,
                    updatesSha256 = null,
                )
                assertFailsWith<IllegalArgumentException> { store.persistAssessment(intent, crossedAssessment) }
            }
        } finally {
            Files.walk(base).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun `turn evidence refuses a symlinked namespace and a closed workspace capability`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val base = Files.createTempDirectory(scratch, "turn-evidence-link-")
        val root = base.resolve("output")
        val input = base.resolve("input").also { Files.writeString(it, "input") }
        val external = base.resolve("external")
        Files.createDirectory(external)
        try {
            val workspace = ReconstructionOutputWorkspace.open(root, input)
            val store = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
            Files.createSymbolicLink(root.resolve(ReconstructionTurnEvidenceStore.DIRECTORY), external)
            val intent = intent(UUID.randomUUID().toString(), "c".repeat(64), workspace.inputSha256)
            assertFailsWith<IllegalArgumentException> { store.persistIntent(intent) }
            assertFalse(Files.exists(external.resolve(workspace.inputSha256)))
            workspace.close()
            Files.delete(root.resolve(ReconstructionTurnEvidenceStore.DIRECTORY))
            assertFailsWith<IllegalStateException> { store.persistIntent(intent) }
        } finally {
            Files.walk(base).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun `completed receipt bytes are durable before an interrupted assessment references them`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val base = Files.createTempDirectory(scratch, "turn-receipt-evidence-")
        val root = base.resolve("output")
        val input = base.resolve("input").also { Files.writeString(it, "input") }
        try {
            ReconstructionOutputWorkspace.open(root, input).use { workspace ->
                val store = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
                val intent = intent(UUID.randomUUID().toString(), "f".repeat(64), workspace.inputSha256)
                store.persistIntent(intent)
                val receiptBytes = "{\"receipt\":\"captured-before-assessment\"}\n".toByteArray()
                val (receiptRelativePath, receiptSha256) = store.persistReceipt(intent, receiptBytes)
                val receiptPath = root.resolve(receiptRelativePath)
                assertTrue(Files.isRegularFile(receiptPath))
                assertEquals(receiptSha256, sha256(Files.readAllBytes(receiptPath)))

                val assessment = AcpChangeAssessment.create(
                    intent = intent,
                    receiptSha256 = receiptSha256,
                    sessionIdSha256 = null,
                    changesSha256 = null,
                    beforeSha256 = workspace.inputSha256,
                    afterSha256 = null,
                    observation = AcpChangeObservationStatus.UNKNOWN,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.CANCELLED,
                    policyVerdict = AcpChangePolicyVerdict.NOT_EVALUATED,
                    reasonCodes = listOf("workflow-interrupted"),
                    validationStatus = AcpChangeValidationStatus.NOT_RUN,
                    validationProofSha256 = emptyList(),
                    eligibility = AcpChangePublicationEligibility.INTERRUPTED,
                    updatesSha256 = null,
                )
                store.persistAssessment(intent, assessment)
                assertEquals(assessment.sha256, AcpChangeAssessment.parse(
                    Files.readAllBytes(root.resolve(".agent-turn-evidence/${workspace.inputSha256}/parse/${intent.turnId}/assessment.json")),
                ).sha256)
                assertFailsWith<IllegalArgumentException> { store.persistReceipt(intent, receiptBytes) }
            }
        } finally {
            Files.walk(base).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun intent(turnId: String, requestSha256: String, beforeSha256: String): AgentTurnIntent =
        AgentTurnIntent.create(
            AgentTurnIdentity(turnId, "parse", requestSha256, "workflow-test"),
            workflowId = "reconstruction",
            attemptId = turnId,
            profileSha256 = "d".repeat(64),
            policySha256 = "e".repeat(64),
            beforeSha256 = beforeSha256,
        )

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}

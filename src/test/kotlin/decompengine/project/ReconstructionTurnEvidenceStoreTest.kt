package decompengine.project

import decompengine.agent.AgentStopReason
import decompengine.agent.AgentTurnIdentity
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReconstructionTurnEvidenceStoreTest {
    @Test
    fun `hard process death during each turn evidence write leaves a restartable prefix`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (document in listOf("intent", "receipt", "assessment")) {
            for (point in ReconstructionTurnEvidenceStorePoint.entries) {
                val base = Files.createTempDirectory(scratch, "turn-evidence-hard-crash-")
                val root = base.resolve("output")
                val input = base.resolve("input").also { Files.writeString(it, "input") }
                val childTemp = Files.createDirectory(base.resolve("java-tmp"))
                val turnId = UUID.randomUUID().toString()
                val log = base.resolve("child.log")
                val process = ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Djava.io.tmpdir=$childTemp",
                    "-cp", System.getProperty("java.class.path"),
                    ReconstructionTurnEvidenceStoreCrashProbe::class.java.name,
                    root.toString(), input.toString(), document, point.name, turnId,
                ).redirectErrorStream(true).redirectOutput(log.toFile()).start()
                try {
                    assertTrue(process.waitFor(30, TimeUnit.SECONDS), "child did not halt at $document/$point")
                    assertEquals(86, process.exitValue(), "child did not halt at $document/$point: ${Files.readString(log)}")

                    ReconstructionOutputWorkspace.open(root, input).use { workspace ->
                        val intent = intent(turnId, "a".repeat(64), workspace.inputSha256)
                        val receiptBytes = "receipt-$turnId".toByteArray(Charsets.UTF_8)
                        val assessment = interruptedTurnAssessment(intent)
                        val store = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
                        val directory = root.resolve(
                            "${ReconstructionTurnEvidenceStore.DIRECTORY}/${workspace.inputSha256}/parse/$turnId",
                        )
                        val targetName = when (document) {
                            "intent" -> ReconstructionTurnEvidenceStore.INTENT_FILE
                            "receipt" -> ReconstructionTurnEvidenceStore.RECEIPT_FILE
                            "assessment" -> ReconstructionTurnEvidenceStore.ASSESSMENT_FILE
                            else -> error("unknown test document: $document")
                        }
                        val target = directory.resolve(targetName)
                        val expected = when (document) {
                            "intent" -> intent.canonicalBytes()
                            "receipt" -> receiptBytes
                            "assessment" -> assessment.canonicalBytes()
                            else -> error("unknown test document: $document")
                        }
                        val intentPath = directory.resolve(ReconstructionTurnEvidenceStore.INTENT_FILE)
                        if (document != "intent") {
                            assertTrue(Files.isRegularFile(intentPath), "the prerequisite intent must survive $document/$point")
                            assertContentEquals(intent.canonicalBytes(), Files.readAllBytes(intentPath))
                        }

                        val finalNameWasPublished = point == ReconstructionTurnEvidenceStorePoint.AFTER_PUBLICATION_RENAME ||
                            point == ReconstructionTurnEvidenceStorePoint.BEFORE_READBACK
                        if (finalNameWasPublished) {
                            assertTrue(Files.isRegularFile(target), "$document must be visible after $point")
                            assertContentEquals(expected, Files.readAllBytes(target))
                            when (document) {
                                "intent" -> assertFailsWith<IllegalArgumentException> { store.persistIntent(intent) }
                                "receipt" -> assertFailsWith<IllegalArgumentException> {
                                    store.persistReceipt(intent, receiptBytes)
                                }
                                "assessment" -> assertFailsWith<IllegalArgumentException> {
                                    store.persistAssessment(intent, assessment)
                                }
                            }
                        } else {
                            assertFalse(Files.exists(target), "$document must remain absent after $point")
                            when (document) {
                                "intent" -> store.persistIntent(intent)
                                "receipt" -> store.persistReceipt(intent, receiptBytes)
                                "assessment" -> store.persistAssessment(intent, assessment)
                            }
                            assertContentEquals(expected, Files.readAllBytes(target))
                        }
                    }
                } finally {
                    if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
                    Files.walk(base).use { paths ->
                        paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                    }
                }
            }
        }
    }

    @Test
    fun `turn intent precedes assessment and both documents are immutable and owner private`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val base = Files.createTempDirectory(scratch, "turn-evidence-")
        val root = base.resolve("output")
        val input = base.resolve("input").also { Files.writeString(it, "input") }
        val external = base.resolve("external").also(Files::createDirectory)
        try {
            ReconstructionOutputWorkspace.open(root, input).use { workspace ->
                val store = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
                val turnId = UUID.randomUUID().toString()
                val intent = intent(turnId, "a".repeat(64), workspace.inputSha256)
                val intentRelativePath = store.persistIntent(intent)
                val intentPath = root.resolve(intentRelativePath)
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
                val assessmentRelativePath = store.persistAssessment(intent, assessment)
                val assessmentPath = root.resolve(assessmentRelativePath)
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

                val turnDirectory = intentPath.parent
                var substituted = false
                val verifier = ReconstructionTurnEvidenceStore(
                    workspace.publicationLock,
                    workspace.inputSha256,
                ) { point ->
                    if (point == ReconstructionTurnEvidenceStorePoint.AFTER_TURN_DIRECTORY_OPEN && !substituted) {
                        Files.move(turnDirectory, turnDirectory.resolveSibling("detached-$turnId"), ATOMIC_MOVE)
                        Files.createSymbolicLink(turnDirectory, external)
                        substituted = true
                    }
                }
                assertFalse(verifier.verifyCheckpointProvenance(
                    moduleId = intent.taskId,
                    profileSha256 = intent.profileSha256,
                    sourcePath = "src/modules/parse.c",
                    sourceSha256 = workspace.inputSha256,
                    accepted = false,
                    intentPath = intentRelativePath,
                    intentSha256 = intent.sha256,
                    intent = intent,
                    receiptPath = null,
                    receiptSha256 = null,
                    executionEvidenceSha256 = null,
                    assessmentPath = assessmentRelativePath,
                    assessmentSha256 = assessment.sha256,
                    assessment = assessment,
                    compilation = null,
                    executionRequestSha256 = intent.requestSha256,
                    executionTerminalOutcome = null,
                    executionReleaseComplete = null,
                ))
                assertTrue(substituted)
                assertFalse(Files.exists(external.resolve(ReconstructionTurnEvidenceStore.INTENT_FILE)))
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
    fun `turn evidence directory substitution never writes through the replacement symlink`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (point in ReconstructionTurnEvidenceStorePoint.entries) {
            val base = Files.createTempDirectory(scratch, "turn-evidence-race-")
            val root = base.resolve("output")
            val input = base.resolve("input").also { Files.writeString(it, "input") }
            val external = base.resolve("external")
            Files.createDirectory(external)
            try {
                ReconstructionOutputWorkspace.open(root, input).use { workspace ->
                    val turnId = UUID.randomUUID().toString()
                    val intent = intent(turnId, "a".repeat(64), workspace.inputSha256)
                    val turnDirectory = root.resolve(
                        "${ReconstructionTurnEvidenceStore.DIRECTORY}/${workspace.inputSha256}/parse/$turnId",
                    )
                    var substituted = false
                    val store = ReconstructionTurnEvidenceStore(
                        workspace.publicationLock,
                        workspace.inputSha256,
                    ) { observed ->
                        if (observed == point && !substituted) {
                            val detached = turnDirectory.resolveSibling("detached-$turnId")
                            Files.move(turnDirectory, detached, ATOMIC_MOVE)
                            Files.createSymbolicLink(turnDirectory, external)
                            substituted = true
                        }
                    }

                    assertFailsWith<IllegalArgumentException>(point.name) { store.persistIntent(intent) }
                    assertTrue(substituted, "the race control must replace the directory at $point")
                    assertFalse(Files.exists(external.resolve(ReconstructionTurnEvidenceStore.INTENT_FILE)))
                }
            } finally {
                Files.walk(base).use { paths ->
                    paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                }
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
                val receiptBytes = ("{\"receipt\":\"" + "x".repeat(1024 * 1024) + "\"}\n").toByteArray()
                assertTrue(receiptBytes.size > 1024 * 1024)
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

private fun interruptedTurnAssessment(intent: AgentTurnIntent): AcpChangeAssessment = AcpChangeAssessment.create(
    intent = intent,
    receiptSha256 = null,
    sessionIdSha256 = null,
    changesSha256 = null,
    beforeSha256 = intent.beforeSha256,
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

/** Child process used to prove that evidence publication does not rely on orderly close/finally. */
internal object ReconstructionTurnEvidenceStoreCrashProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 5)
        val root = Path.of(args[0])
        val input = Path.of(args[1])
        val document = args[2]
        val crashPoint = ReconstructionTurnEvidenceStorePoint.valueOf(args[3])
        val turnId = args[4]
        ReconstructionOutputWorkspace.open(root, input).use { workspace ->
            val intent = AgentTurnIntent.create(
                AgentTurnIdentity(turnId, "parse", "a".repeat(64), "workflow-test"),
                workflowId = "reconstruction",
                attemptId = turnId,
                profileSha256 = "d".repeat(64),
                policySha256 = "e".repeat(64),
                beforeSha256 = workspace.inputSha256,
            )
            val ordinary = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256)
            if (document != "intent") ordinary.persistIntent(intent)
            val faulting = ReconstructionTurnEvidenceStore(workspace.publicationLock, workspace.inputSha256) { point ->
                if (point == crashPoint) Runtime.getRuntime().halt(86)
            }
            when (document) {
                "intent" -> faulting.persistIntent(intent)
                "receipt" -> faulting.persistReceipt(intent, "receipt-$turnId".toByteArray(Charsets.UTF_8))
                "assessment" -> faulting.persistAssessment(
                    intent,
                    interruptedTurnAssessment(intent),
                )
                else -> error("unknown test document: $document")
            }
        }
        Runtime.getRuntime().halt(87)
    }
}

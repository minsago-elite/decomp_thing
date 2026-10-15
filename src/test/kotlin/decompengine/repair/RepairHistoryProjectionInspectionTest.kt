package decompengine.repair

import decompengine.project.sha256
import decompengine.validation.ProcessInput
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.*
import kotlinx.serialization.json.*

/** Authored producer/captured-byte controls only; no recovery or receipt reads in the comparator. */
class RepairHistoryProjectionInspectionTest {
    private val budget = RepairResourceBudget()
    private val profile = DeclarativeRepairIndexProfile("PRIVATE-profile", RepairIndexLayout(listOf("code.c"), listOf("code.c")))
    private data class Capture(val root: Path, val graph: ByteArray, val history: ByteArray)

    @Test
    fun actualCurrentProducerMatchesFinalizedRunAndPreservesPrivateBytesOnlyInCapture() {
        val captured = produce(current = true, accepted = true)
        val result = compare(captured)
        assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, result.status)
        assertEquals(3, result.schemaVersion)
        assertEquals(RepairHistoryProjectionCoverage.FINALIZED_CORPUS_AND_RUNS, result.coverage)
        assertEquals(captured.history.size.toLong(), result.admittedBytes)
        assertEquals(sha256(captured.history), result.capturedSha256)
        for (bytes in listOf(byteArrayOf(), byteArrayOf(0, 0xff.toByte(), 0x80.toByte(), 10))) {
            val binary = produce(current = true, accepted = true, candidate = bytes)
            assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, compare(binary).status)
        }
        val surface = result.toString()
        for (private in listOf("PRIVATE-", "code.c", "repair-revisions", "bounded private prompt")) assertFalse(private in surface)
        assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY,
            readProjectRecordedRepairHistory(captured.root).snapshot?.qualification)
    }

    @Test
    fun genuinePreContractSucceededWireIsComparedWithoutAcceptedAuthorityUpgrade() {
        val captured = produce(current = false, accepted = true)
        assertTrue(captured.history.decodeToString().contains("\"succeeded\": true"))
        assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, compare(captured).status)
        assertEquals(2, compare(captured).schemaVersion)
        val snapshot = readProjectRecordedRepairHistory(captured.root).snapshot!!
        assertNull(snapshot.fullyAcceptedHead)
        assertEquals(ModuleRevisionStatus.LEGACY_UNVERIFIED, snapshot.attempts.single().status)
        // The existing versioned renderer emits schema1 too; this is authored old-wire data, not historical qualification.
        val canonicalRoot = Json.parseToJsonElement(captured.graph.decodeToString()).jsonObject
        val state = privateCall("parseGraph", JsonObject(canonicalRoot + ("schemaVersion" to JsonPrimitive(1))).toString())
        val graph = renderGraph(state)
        val legacyHistory = captured.history.decodeToString().replace("\"agentInvocation\": null,", "\"omitted\": null,")
        // Noncanonical field-stripping must never be silently treated as a matching complete producer wire.
        assertNotEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION,
            compareCapturedRepairHistoryProjection(graph, legacyHistory.toByteArray(), budget).status)
        val emptyRoot = root()
        ModuleRevisionGraph.open(emptyRoot, profile).close()
        val empty = emptyRoot.resolve("reports/repair-revisions/graph.json").readBytes()
        val emptyState = privateCall("parseGraph", JsonObject(Json.parseToJsonElement(empty.decodeToString()).jsonObject +
            ("schemaVersion" to JsonPrimitive(1))).toString())
        val emitted = renderRepairHistoryProjection(emptyList(), emptyList(), budget.maximumProjectionBytes, 1)
        val old = compareCapturedRepairHistoryProjection(renderGraph(emptyState), emitted.toByteArray(), budget)
        assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, old.status)
        assertEquals(1, old.schemaVersion)
        assertEquals(RepairHistoryProjectionCoverage.LEGACY_FINALIZED_AND_CORPUS, old.coverage)
    }

    @Test
    fun emittedMetadataCorpusPatchAndRunValueMutationsCannotMatch() {
        val captured = produce(current = true, accepted = true)
        val source = captured.history.decodeToString()
        val mutations = listOf(
            source.replace("bounded private prompt", "different private prompt"),
            source.replace("PRIVATE-summary", "PRIVATE-changed"),
            source.replace("PRIVATE-case", "PRIVATE-other"),
            source.replace("505249564154452d737464696e", "505249564154452d737464696f"),
            source.replace("63616e646964617465", "63616e646964617464"),
            source.replace("\"attemptedCount\":1", "\"attemptedCount\":0"),
            source.replace("\"originalBinarySha256\":\"" + sha256("reference".toByteArray()),
                "\"originalBinarySha256\":\"" + "a".repeat(64)),
        )
        mutations.forEach { changed ->
            assertNotEquals(source, changed, "mutation must reach an actual emitted value")
            val diagnostic = compareCapturedRepairHistoryProjection(captured.graph, changed.toByteArray(), budget)
            assertNotEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, diagnostic.status)
            assertFalse(diagnostic.toString().contains("PRIVATE-"))
        }
        assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, compare(captured).status)
    }

    @Test
    fun strictCompleteFieldsTypesDuplicateKeysAndEncodingNeverDefaultToSuccess() {
        val captured = produce(current = true, accepted = false)
        val source = captured.history.decodeToString()
        val malformed = listOf(
            source.replace("\"schemaVersion\": 3", "\"schemaVersion\": \"3\""),
            source.replace("\"succeeded\": false", "\"succeeded\": null"),
            source.replace("\"publicationMode\":", "\"unknownMode\":"),
            source.replaceFirst("{", "{\"regressionInputs\":[],"),
            source + "PRIVATE-trailer",
        )
        malformed.forEach { changed ->
            assertNotEquals(source, changed)
            assertNotEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION,
                compareCapturedRepairHistoryProjection(captured.graph, changed.toByteArray(), budget).status)
        }
        assertEquals(RepairHistoryProjectionStatus.INVALID,
            compareCapturedRepairHistoryProjection(captured.graph, byteArrayOf(0xc3.toByte(), 0x28), budget).status)
        val normalized = Json.parseToJsonElement(source).toString().toByteArray()
        assertEquals(RepairHistoryProjectionStatus.UNVERIFIABLE_ENCODING,
            compareCapturedRepairHistoryProjection(captured.graph, normalized, budget).status)
    }

    @Test
    fun pendingAndHistoricalRestorationFailureRemainCanonicalWhenHistoryIsCorrupt() {
        val root = root()
        var armed = false
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "rollback") throw RestoreFailure()
        }).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            armed = true
            assertFailsWith<RestoreFailure> { graph.reject(attempt) }
        }
        root.resolve("reports/repair_history.json").writeText("PRIVATE-corrupt")
        val pending = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, pending.status)
        assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, pending.snapshot?.pending?.rollback?.state)
        assertEquals(RepairHistoryProjectionStatus.INVALID, pending.projection.status)
        ModuleRevisionGraph.open(root, profile).close() // Producer recovery ONLY in test setup.
        root.resolve("reports/repair_history.json").writeText("PRIVATE-corrupt")
        val recovered = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, recovered.status)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, recovered.snapshot?.attempts?.last()?.rollback?.state)
        assertNotNull(recovered.snapshot?.attempts?.last()?.rollback?.failureCode)
        assertEquals(RepairHistoryProjectionStatus.INVALID, recovered.projection.status)
        assertEquals("base", Files.readString(root.resolve("code.c")))
    }

    @Test
    fun byteBoundsAndBadCanonicalInputCannotProducePartialMatchingCredit() {
        val captured = produce(current = true, accepted = false)
        val limited = budget.copy(maximumProjectionBytes = 1024)
        val boundedRoot = root()
        ModuleRevisionGraph.open(boundedRoot, profile, limited).close()
        val boundedGraph = boundedRoot.resolve("reports/repair-revisions/graph.json").readBytes()
        for (bytes in listOf(byteArrayOf(), ByteArray(1025))) {
            assertEquals(RepairHistoryProjectionStatus.UNAVAILABLE,
                compareCapturedRepairHistoryProjection(boundedGraph, bytes, limited).status)
        }
        val bad = compareCapturedRepairHistoryProjection("PRIVATE-invalid-graph".toByteArray(), captured.history, budget)
        assertEquals(RepairHistoryProjectionStatus.UNAVAILABLE, bad.status)
        assertEquals(RepairHistoryProjectionReason.CANONICAL, bad.reason)
        assertNull(bad.capturedSha256)
        assertNull(bad.schemaVersion)
    }


    @Test
    fun actualInProgressNotRequiredAndRestoredStatesSurviveMissingOrCorruptProjection() {
        val root = root()
        val progress = mutableListOf<RepairHistoryReadResult>()
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync && point.scope == "revision-state" && point.name == "graph.json") {
                val result = readProjectRecordedRepairHistory(root)
                if (result.snapshot?.pending?.rollback?.state == RepairRollbackState.RESTORE_IN_PROGRESS) progress += result
            }
        }).use { graph ->
            graph.enableRunContract()
            val first = graph.beginAttempt(listOf("code.c"))
            graph.reject(first)
            val notRequired = readProjectRecordedRepairHistory(root)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, notRequired.snapshot?.attempts?.last()?.rollback?.state)
            val second = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(second, mapOf("code.c" to "candidate".toByteArray()))
            root.resolve("reports/repair_history.json").writeText("PRIVATE-corrupt")
            graph.reject(second)
            val restored = readProjectRecordedRepairHistory(root)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, restored.snapshot?.attempts?.last()?.rollback?.state)
            assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, restored.snapshot?.qualification)
        }
        assertTrue(progress.isNotEmpty())
        progress.forEach { assertEquals(RepairHistoryReadStatus.RECORDED, it.status); assertNull(it.snapshot?.fullyAcceptedHead) }
        assertEquals("base", Files.readString(root.resolve("code.c")))
    }

    @Test
    fun actualProvisionalThenAcceptedProjectionPreservesDistinctCanonicalHeads() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("PRIVATE-case", emptyList(), byteArrayOf())))
            graph.beginRun(2, 60_000)
            graph.bindOriginalBinary(sha256("reference".toByteArray()))
            graph.bindExpectedObservations(sha256("expected".toByteArray()))
            fun metadata(index: Int) = RevisionRepairMetadata(index, "compile", "bounded private prompt", "PRIVATE-summary",
                corpus.inputs.map { it.id }, null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
            fun proof(attempt: ModuleRevisionAttempt) = RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)),
                graph.snapshot.profileSha256, graph.snapshot.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                sha256("rebuilt".toByteArray()), sha256("runtime".toByteArray()), sha256("evidence".toByteArray()),
                true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
            val first = graph.beginAttempt(listOf("code.c"), metadata(1))
            graph.installCandidate(first, mapOf("code.c" to "candidate".toByteArray()))
            graph.recordProvisional(first, RepairEvidence("behavior", "PRIVATE-peer"), proof(first))
            graph.synchronizeRepairHistory()
            val provisional = readProjectRecordedRepairHistory(root)
            assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, provisional.projection.status)
            assertEquals(first.id, provisional.snapshot?.provisionalHead?.value)
            assertNull(provisional.snapshot?.fullyAcceptedHead)
            val second = graph.beginAttempt(listOf("code.c"), metadata(2))
            graph.installCandidate(second, mapOf("code.c" to "accepted".toByteArray()))
            graph.accept(second, RepairEvidence("valid", "PRIVATE-peer"), proof(second))
            graph.synchronizeRepairHistory()
            val accepted = readProjectRecordedRepairHistory(root)
            assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, accepted.projection.status)
            assertEquals(second.id, accepted.snapshot?.fullyAcceptedHead?.value)
            assertNull(accepted.snapshot?.provisionalHead)
            assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, accepted.snapshot?.qualification)
        }
    }

    private class RestoreFailure : RuntimeException()
    private fun root(): Path {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "history-projection-").also { it.resolve("code.c").writeText("base") }
    }
    private fun produce(current: Boolean, accepted: Boolean, candidate: ByteArray = "candidate".toByteArray()): Capture {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            if (current) graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("PRIVATE-case", listOf("PRIVATE-arg"), "PRIVATE-stdin".toByteArray())))
            if (current) {
                graph.beginRun(2, 60_000)
                graph.bindOriginalBinary(sha256("reference".toByteArray()))
                graph.bindExpectedObservations(sha256("expected".toByteArray()))
            }
            val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "bounded private prompt",
                "PRIVATE-summary", corpus.inputs.map { it.id }, null, corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("code.c" to candidate))
            if (!accepted) graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-evidence"))
            else if (!current) graph.accept(attempt, RepairEvidence("valid", "PRIVATE-evidence"))
            else {
                val state = graph.snapshot
                val proof = RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)), state.profileSha256,
                    state.indexSha256, corpus.sha256, sha256("reference".toByteArray()), sha256("rebuilt".toByteArray()),
                    sha256("runtime".toByteArray()), sha256("evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
                graph.accept(attempt, RepairEvidence("valid", "PRIVATE-evidence"), proof)
            }
            graph.synchronizeRepairHistory()
        }
        return Capture(root, root.resolve("reports/repair-revisions/graph.json").readBytes(), root.resolve("reports/repair_history.json").readBytes())
    }
    private fun compare(captured: Capture) = compareCapturedRepairHistoryProjection(captured.graph, captured.history, budget)
    private fun privateCall(name: String, vararg arguments: Any): Any = Class.forName("decompengine.repair.ModuleRevisionGraphKt")
        .declaredMethods.single { it.name == name && it.parameterCount == arguments.size }.also { it.isAccessible = true }
        .invoke(null, *arguments)
    private fun renderGraph(state: Any): ByteArray {
        val method = Class.forName("decompengine.repair.ModuleRevisionGraphKt").declaredMethods.single { it.name == "renderGraph" && it.parameterCount == 2 }
        val wire = method.parameterTypes[1].enumConstants.single { (it as Enum<*>).name == "COMPACT" }
        return privateCall("renderGraph", state, wire).toString().toByteArray()
    }
}

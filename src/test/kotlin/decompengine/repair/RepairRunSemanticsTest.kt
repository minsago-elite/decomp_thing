package decompengine.repair

import decompengine.agent.*
import decompengine.project.sha256
import decompengine.jobs.AgentProgressJournal
import decompengine.validation.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.time.Duration
import kotlin.io.path.*
import kotlin.test.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class RepairRunSemanticsTest {
    private val profile = repairRunFixtureProfile()
    private val inputs = (0..2).map { ProcessInput("case$it", listOf("arg$it"), byteArrayOf(it.toByte())) }

    @Test
    fun `compile then partial behavior then full success only publishes the last revision`() {
        val fixture = fixture("broken", "pass1", "pass3")
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 3)
        assertEquals(RepairRunStatus.FULLY_ACCEPTED, result.runState.status)
        assertEquals(listOf("broken", "pass1"), fixture.seenSources)
        assertEquals(listOf("broken", "broken"), fixture.canonicalDuringPrompts)
        assertEquals(listOf(RepairAttemptDisposition.PROVISIONAL, RepairAttemptDisposition.FULLY_ACCEPTED), result.iterations.map { it.disposition })
        assertEquals("pass3", fixture.root.resolve("code.c").readText())
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            val state = graph.snapshot
            assertEquals(4, state.schemaVersion)
            assertEquals(state.headId, state.fullyAcceptedHeadId)
            assertNull(state.provisionalHeadId)
            assertEquals(state.nodes[1].id, state.nodes[2].parentId)
            assertEquals(result.runState, state.runs.single())
            assertEquals(inputs, graph.retainedRegressionCorpus().inputs)
        }
        assertEquals(result.runState, RepairHistory(fixture.root.resolve("reports/repair_history.json")).runStates().single())
        val events = AgentProgressJournal.read(fixture.root.resolve("reports"))!!.getValue("events").jsonArray.map { it.jsonObject }
        val states = events.filter { it["kind"]?.jsonPrimitive?.content == "workflow_run_state" }
        assertTrue(states.all { it.getValue("workflowRunIdSha256").jsonPrimitive.content == sha256(result.runState.id.toByteArray()) })
        val provisional = states.single { it.getValue("phase").jsonPrimitive.content == "provisional" }
        assertEquals(sha256(requireNotNull(result.iterations.first().revisionId).toByteArray()),
            provisional.getValue("revisionIdSha256").jsonPrimitive.content)
        assertFalse(provisional.containsKey("acceptedRevisionSha256"))
        assertEquals("accepted", states.last().getValue("phase").jsonPrimitive.content)
        assertTrue(states.last().containsKey("acceptedRevisionSha256"))
        assertEquals(2, events.count { it["kind"]?.jsonPrimitive?.content == "agent_finished" })
        assertTrue(events.indexOfFirst { it["kind"]?.jsonPrimitive?.content == "agent_finished" } < events.indexOf(provisional))
        assertTrue(events.filter { it["kind"]?.jsonPrimitive?.content == "task_started" }.all {
            it.getValue("workflowRunIdSha256").jsonPrimitive.content == sha256(result.runState.id.toByteArray())
        })
    }

    @Test
    fun `busy progress journal cannot change accepted source or cause a repair retry`() {
        val fixture = fixture("broken", "pass3")
        AgentProgressJournal(fixture.root.resolve("reports"), "repair").use {
            val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 2)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, result.runState.status)
            assertEquals(1, result.runState.attemptedCount)
            assertEquals(listOf("broken"), fixture.seenSources)
            assertEquals("pass3", fixture.root.resolve("code.c").readText())
            ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
                assertEquals(result.runState, graph.snapshot.runs.single())
            }
        }
    }

    @Test
    fun `interrupted projection close preserves cancellation and releases its writer lock`() {
        val reports = createTempDirectory("repair-progress-close-")
        val projection = RepairProgressProjection(reports)
        try {
            Thread.currentThread().interrupt()
            projection.close()
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
        AgentProgressJournal(reports, "repair").use { it.phase(AgentWorkflowPhase.UNRESOLVED) }
        assertNotNull(AgentProgressJournal.read(reports))
    }

    @Test
    fun `an imported baseline obtains acceptance only after complete validation without an invented agent turn`() {
        val fixture = fixture("pass3")
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.FULLY_ACCEPTED, result.runState.status)
        assertEquals(0, result.runState.attemptedCount)
        assertTrue(result.iterations.isEmpty())
        assertTrue(fixture.seenSources.isEmpty())
        assertNotNull(result.runState.expectedObservationsSha256)
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
            assertEquals(graph.snapshot.headId, graph.snapshot.fullyAcceptedHeadId)
            assertEquals(result.runState, graph.snapshot.runs.single())
        }
    }

    @Test
    fun `a failed history projection cannot turn committed acceptance into an unsuccessful API result`() {
        lateinit var fixture: Fixture
        fixture = fixture("broken", "pass3", afterValidation = { source ->
            if (source == "pass3") {
                val historyPath = fixture.root.resolve("reports/repair_history.json")
                Files.delete(historyPath)
                Files.createDirectory(historyPath)
            }
        })
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.FULLY_ACCEPTED, result.runState.status)
        assertEquals("pass3", fixture.root.resolve("code.c").readText())
        assertEquals(result.runState, fixture.history.runStates().single())
        Files.delete(fixture.root.resolve("reports/repair_history.json"))
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(result.runState, graph.snapshot.runs.single())
            assertEquals(graph.snapshot.headId, graph.snapshot.fullyAcceptedHeadId)
        }
    }

    @Test
    fun `several provisional improvements exhaust with original source and no invented accepted head`() {
        val fixture = fixture("pass0", "pass1", "pass2")
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 2)
        assertEquals(RepairRunStatus.ITERATION_EXHAUSTED, result.runState.status)
        assertEquals(2, result.runState.attemptedCount)
        assertEquals(0, result.runState.remainingAttempts)
        assertNull(result.runState.acceptedHeadId)
        assertNotNull(result.runState.provisionalHeadId)
        assertEquals("pass0", fixture.root.resolve("code.c").readText())
        val display = AgentProgressJournal.read(fixture.root.resolve("reports"))!!
        assertFalse(display.toString().contains("acceptedRevisionSha256"))
        assertEquals("exhausted", display.getValue("events").jsonArray.last().jsonObject.getValue("phase").jsonPrimitive.content)
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single { it.id == graph.snapshot.headId }.status)
            assertEquals(listOf(ModuleRevisionStatus.ROOT, ModuleRevisionStatus.PROVISIONAL, ModuleRevisionStatus.PROVISIONAL), graph.snapshot.nodes.map { it.status })
            assertEquals(result.runState.provisionalHeadId, graph.snapshot.provisionalHeadId)
            assertEquals(inputs, graph.retainedRegressionCorpus().inputs)
        }
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"), RepairRunReopenProbe::class.java.name, fixture.root.toString())
            .redirectErrorStream(true).start()
        val output = process.inputStream.readAllBytes().toString(Charsets.UTF_8)
        assertTrue(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS), output)
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.contains("iteration_exhausted"), output)
        assertTrue(output.contains("pass0"), output)
    }

    @Test
    fun `retained regression rejects candidate and preserves prior provisional lineage`() {
        val fixture = fixture("pass0", "pass1", "pass0")
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 2)
        assertEquals(RepairRunStatus.ITERATION_EXHAUSTED, result.runState.status)
        assertEquals(listOf(RepairAttemptDisposition.PROVISIONAL, RepairAttemptDisposition.REJECTED), result.iterations.map { it.disposition })
        assertEquals(result.iterations.first().revisionId, result.runState.provisionalHeadId)
        assertEquals("retained-regression", result.iterations.last().after?.kind)
        assertEquals("pass0", fixture.root.resolve("code.c").readText())
    }

    @Test
    fun `cancellation after validation rejects pending candidate before promotion`() {
        val cancellation = AgentCancellationSource()
        val fixture = fixture("broken", "pass3", cancellation = cancellation, afterValidation = { candidate ->
            if (candidate == "pass3") cancellation.cancel()
        })
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.CANCELLED, result.runState.status)
        assertNull(result.runState.acceptedHeadId)
        assertEquals("broken", fixture.root.resolve("code.c").readText())
        assertEquals(RepairAttemptDisposition.REJECTED, result.iterations.single().disposition)
        assertEquals(result.runState, RepairHistory(fixture.root.resolve("reports/repair_history.json")).runStates().single())
    }

    @Test
    fun `validation resource exhaustion retains a terminal run and the exact canonical source`() {
        val fixture = fixture("broken", "pass3", afterValidation = { source ->
            if (source == "pass3") throw RepairBudgetExceededException("fixture validation evidence budget exhausted")
        })
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 3)
        assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, result.runState.status)
        assertEquals(1, result.runState.attemptedCount)
        assertEquals(2, result.runState.remainingAttempts)
        assertEquals(RepairAttemptDisposition.REJECTED, result.iterations.single().disposition)
        assertEquals("broken", fixture.root.resolve("code.c").readText())
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            assertEquals(result.runState, graph.snapshot.runs.single())
        }
    }

    @Test
    fun `compile only returns provisional and persists compile valid terminal without replacing source`() {
        val fixture = fixture("broken", "pass3")
        val result = fixture.loop.repairCompileError(fixture.root, CompileFailure(listOf("fixture"), 1, "", "code.c:1: syntax error"), inputs)
        assertEquals(RepairAttemptDisposition.PROVISIONAL, result.disposition)
        assertFalse(result.succeeded)
        assertFalse(result.releaseComplete)
        assertEquals("broken", fixture.root.resolve("code.c").readText())
        assertEquals(RepairRunStatus.COMPILE_VALID, fixture.history.runStates().single().status)
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            assertNotNull(graph.snapshot.provisionalHeadId)
        }
    }

    @Test
    fun `missing retained cases fail validation rather than making success easier`() {
        val fixture = fixture("broken", "pass3", omitCase = true)
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.VALIDATION_FAILED, result.runState.status)
        assertEquals("broken", fixture.root.resolve("code.c").readText())
        assertNull(result.runState.acceptedHeadId)
        ModuleRevisionGraph.open(fixture.root, profile).use { assertEquals(inputs, it.retainedRegressionCorpus().inputs) }
    }

    @Test
    fun `original binary identity cannot change after the initial compile assessment`() {
        lateinit var fixture: Fixture
        fixture = fixture("broken", "pass3", afterValidation = { source ->
            if (source == "broken") fixture.original.writeText("changed reference")
        })
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.VALIDATION_FAILED, result.runState.status)
        assertEquals(sha256("reference".toByteArray()), result.runState.originalBinarySha256)
        assertEquals("broken", fixture.root.resolve("code.c").readText())
        assertNull(result.runState.acceptedHeadId)
    }

    @Test
    fun `pending detached attempt recovers as interrupted without publishing candidate bytes`() {
        val fixture = fixture("broken")
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(3, 60_000)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
            graph.installCandidate(attempt, mapOf("code.c" to "pass1".toByteArray()))
            assertEquals("broken", fixture.root.resolve("code.c").readText())
        }
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.single().status)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertTrue(graph.snapshot.nodes.last().recoveredAfterCrash)
            assertNull(graph.snapshot.fullyAcceptedHeadId)
        }
    }

    @Test
    fun `detached rollback record targets published head separately from provisional parent`() {
        val fixture = fixture("broken")
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(3, 60_000)
            graph.bindOriginalBinary(sha256("reference".toByteArray()))
            val publishedHead = graph.snapshot.headId
            val publishedSourceRevision = graph.snapshot.nodes.single { it.id == publishedHead }.sourceRevisionSha256

            val first = graph.beginAttempt(listOf("code.c"), metadata(corpus))
            graph.installCandidate(first, mapOf("code.c" to "pass1".toByteArray()))
            val firstState = graph.snapshot
            val firstProof = RepairValidationProof(
                repairCandidateSourceSha256(graph.candidateSources(first)), firstState.profileSha256,
                firstState.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                sha256("pass1".toByteArray()), sha256("fixture-runtime".toByteArray()),
                sha256("fixture-evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS,
            )
            val provisional = graph.recordProvisional(
                first,
                RepairEvidence("behavior", "provisional fixture"),
                firstProof,
            )
            assertEquals(publishedHead, graph.snapshot.headId)

            val second = graph.beginAttempt(
                listOf("code.c"),
                metadata(corpus).copy(iterationIndex = 2, failureKind = "behavior"),
            )
            graph.installCandidate(second, mapOf("code.c" to "pass2".toByteArray()))
            val rejected = graph.reject(second, RepairEvidence("rejected", "restore published head"))
            val rollback = requireNotNull(rejected.rollbackRecord)
            assertEquals(provisional.id, rejected.parentId)
            assertEquals(publishedHead, rollback.targetRevisionId)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, rollback.state)
            assertEquals(false, rollback.candidateSourceInstallStarted)
            assertEquals(publishedSourceRevision, rollback.expectedSourceRevisionSha256)
            assertEquals("broken", fixture.root.resolve("code.c").readText())
        }
    }

    @Test
    fun `finalized rollback targeting a provisional parent cannot reopen or mutate canonical state`() {
        val fixture = fixture("pass0", "pass1", "pass0")
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 2)
        assertEquals(RepairRunStatus.ITERATION_EXHAUSTED, result.runState.status)
        val state = ModuleRevisionGraph.open(fixture.root, profile).use { it.snapshot }
        val provisional = state.nodes.single { it.status == ModuleRevisionStatus.PROVISIONAL }
        val rejected = state.nodes.last()
        val rollback = requireNotNull(rejected.rollbackRecord)
        assertEquals(provisional.id, rejected.parentId)
        assertEquals(state.headId, rollback.targetRevisionId)
        assertTrue(rollback.expectedSourceRevisionSha256 != provisional.sourceRevisionSha256)

        val graphPath = fixture.root.resolve("reports/repair-revisions/graph.json")
        val cleanGraph = graphPath.readBytes()
        val tamperedGraph = cleanGraph.toString(Charsets.UTF_8)
            .replaceFirst("\"targetRevisionId\":\"${rollback.targetRevisionId}\"",
                "\"targetRevisionId\":\"${provisional.id}\"")
            .replaceFirst("\"expectedSourceRevisionSha256\":\"${rollback.expectedSourceRevisionSha256}\"",
                "\"expectedSourceRevisionSha256\":\"${provisional.sourceRevisionSha256}\"")
            .replaceFirst("\"observedSourceRevisionSha256\":\"${rollback.observedSourceRevisionSha256}\"",
                "\"observedSourceRevisionSha256\":\"${provisional.sourceRevisionSha256}\"")
            .toByteArray(Charsets.UTF_8)
        assertFalse(cleanGraph.contentEquals(tamperedGraph))
        graphPath.writeBytes(tamperedGraph)
        val sourcePath = fixture.root.resolve("code.c")
        val sourceBefore = sourcePath.readBytes()
        val sourceAttributes = Files.readAttributes(sourcePath, BasicFileAttributes::class.java)
        val graphAttributes = Files.readAttributes(graphPath, BasicFileAttributes::class.java)

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(fixture.root, profile).use { }
        }
        assertTrue(failure.message.orEmpty().contains("rollback target differs from the published head"))
        assertContentEquals(sourceBefore, sourcePath.readBytes())
        assertContentEquals(tamperedGraph, graphPath.readBytes())
        val sourceAfter = Files.readAttributes(sourcePath, BasicFileAttributes::class.java)
        val graphAfter = Files.readAttributes(graphPath, BasicFileAttributes::class.java)
        assertEquals(sourceAttributes.fileKey(), sourceAfter.fileKey())
        assertEquals(sourceAttributes.lastModifiedTime(), sourceAfter.lastModifiedTime())
        assertEquals(graphAttributes.fileKey(), graphAfter.fileKey())
        assertEquals(graphAttributes.lastModifiedTime(), graphAfter.lastModifiedTime())

        graphPath.writeBytes(cleanGraph)
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(state, graph.snapshot)
            assertEquals("pass0", sourcePath.readText())
        }
    }

    @Test
    fun `standalone attempts retain a provisional parent after completed and interrupted runs`() {
        listOf(false, true).forEach { interrupted ->
            val fixture = fixture("broken")
            var provisionalId: String? = null
            ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
                graph.enableRunContract()
                val corpus = graph.retainRegressionInputs(inputs)
                graph.beginRun(2, 60_000)
                graph.bindOriginalBinary(sha256("reference".toByteArray()))
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
                graph.installCandidate(attempt, mapOf("code.c" to "pass1".toByteArray()))
                val state = graph.snapshot
                val proof = RepairValidationProof(
                    repairCandidateSourceSha256(graph.candidateSources(attempt)), state.profileSha256,
                    state.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                    sha256("pass1".toByteArray()), sha256("fixture-runtime".toByteArray()),
                    sha256("fixture-evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS,
                )
                provisionalId = graph.recordProvisional(attempt, RepairEvidence("behavior", "partial"), proof).id
                if (!interrupted) graph.finishRun(RepairRunStatus.ITERATION_EXHAUSTED, RepairEvidence("exhausted", "fixture"))
            }
            var pendingId: String? = null
            ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
                assertTrue(graph.snapshot.runs.single().terminal)
                val publishedHead = graph.snapshot.headId
                val attempt = graph.beginAttempt(listOf("code.c"))
                val rejection = graph.reject(attempt, RepairEvidence("rejected", "no candidate installed"))
                assertEquals(provisionalId, rejection.parentId)
                assertEquals(publishedHead, rejection.rollbackRecord?.targetRevisionId)
                assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, rejection.rollbackRecord?.state)
                assertEquals("broken", fixture.root.resolve("code.c").readText())

                val candidate = graph.beginAttempt(listOf("code.c"))
                pendingId = candidate.id
                graph.installCandidate(candidate, mapOf("code.c" to "pass2".toByteArray()))
                assertEquals("pass2", graph.candidateSources(candidate).getValue("code.c").toString(Charsets.UTF_8))
                assertEquals("broken", fixture.root.resolve("code.c").readText())
                assertEquals(publishedHead, graph.snapshot.headId)
                assertEquals(provisionalId, graph.snapshot.provisionalHeadId)
            }
            ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
                val recovered = graph.snapshot.nodes.last()
                assertEquals(pendingId, recovered.id)
                assertEquals(provisionalId, recovered.parentId)
                assertTrue(recovered.recoveredAfterCrash)
                assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, recovered.rollbackRecord?.state)
                assertEquals(false, recovered.rollbackRecord?.legacyPendingStateUnknown)
                assertEquals(provisionalId, graph.snapshot.provisionalHeadId)
                assertNull(graph.snapshot.fullyAcceptedHeadId)
                assertEquals("broken", fixture.root.resolve("code.c").readText())
            }
        }
    }

    @Test
    fun `detached staged candidate has verified no rollback only before source promotion`() {
        val fixture = fixture("broken")
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(1, 60_000)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
            graph.installCandidate(attempt, mapOf("code.c" to "pass1".toByteArray()))

            assertEquals("broken", fixture.root.resolve("code.c").readText())
            val rejected = graph.reject(attempt, RepairEvidence("rejected", "staged candidate was never promoted"))

            val rollback = requireNotNull(rejected.rollbackRecord)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, rollback.state)
            assertEquals(false, rollback.candidateSourceInstallStarted)
            assertEquals(rollback.expectedSourceRevisionSha256, rollback.observedSourceRevisionSha256)
            assertEquals("broken", fixture.root.resolve("code.c").readText())
        }
    }

    @Test
    fun `interrupted canonical publication restores exact baseline before recording terminal recovery`() {
        val fixture = fixture("broken")
        class InterruptedPublication : Error()
        assertFailsWith<InterruptedPublication> {
            ModuleRevisionGraph.openForTesting(fixture.root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw InterruptedPublication()
            }).use { graph ->
                graph.enableRunContract()
                val corpus = graph.retainRegressionInputs(inputs)
                graph.beginRun(2, 60_000)
                graph.bindOriginalBinary(sha256("reference".toByteArray()))
                graph.bindExpectedObservations(sha256("fixture-expected".toByteArray()))
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
                graph.installCandidate(attempt, mapOf("code.c" to "pass3".toByteArray()))
                val state = graph.snapshot
                val proof = RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)),
                    state.profileSha256, state.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                    sha256("pass3".toByteArray()), sha256("fixture-runtime".toByteArray()), sha256("fixture-evidence".toByteArray()),
                    true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
                graph.accept(attempt, RepairEvidence("valid", "all retained fixture cases matched"), proof)
            }
        }
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals("broken", fixture.root.resolve("code.c").readText())
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.single().status)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            val rollback = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, rollback.state)
            assertEquals(false, rollback.legacyPendingStateUnknown)
            assertEquals(true, rollback.candidateSourceInstallStarted)
        }
    }

    @Test
    fun `restart retains a verified provisional snapshot as nonaccepted interrupted evidence`() {
        val fixture = fixture("broken")
        var provisional: String? = null
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(2, 60_000)
            graph.bindOriginalBinary(sha256("reference".toByteArray()))
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
            graph.installCandidate(attempt, mapOf("code.c" to "pass1".toByteArray()))
            val state = graph.snapshot
            val proof = RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)),
                state.profileSha256, state.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                sha256("pass1".toByteArray()), sha256("fixture-runtime".toByteArray()), sha256("fixture-evidence".toByteArray()),
                true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
            provisional = graph.recordProvisional(attempt, RepairEvidence("behavior", "two retained cases remain"), proof).id
        }
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            assertEquals(provisional, graph.snapshot.provisionalHeadId)
            assertEquals("pass1", graph.candidateSources().getValue("code.c").toString(Charsets.UTF_8))
            assertEquals("broken", fixture.root.resolve("code.c").readText())
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.single().status)
        }
    }

    @Test
    fun `legacy accepted records and history bytes migrate as unverified`() {
        val fixture = fixture("pass0")
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "pass1".toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "historical unchecked label"))
        }
        val graphPath = fixture.root.resolve("reports/repair-revisions/graph.json")
        val legacyBytes = graphPath.readBytes()
        val historyPath = fixture.root.resolve("reports/repair_history.json")
        val legacyHistory = "{\"schemaVersion\":2,\"regressionInputs\":[],\"iterations\":[]}\n".toByteArray()
        historyPath.writeBytes(legacyHistory)
        ModuleRevisionGraph.open(fixture.root, profile).use { graph ->
            graph.enableRunContract()
            assertEquals(ModuleRevisionStatus.LEGACY_UNVERIFIED, graph.snapshot.nodes.last().status)
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            assertEquals("pass1", fixture.root.resolve("code.c").readText())
        }
        assertContentEquals(legacyBytes, graphPath.parent.resolve("legacy-graph-${sha256(legacyBytes)}.json").readBytes())
        assertContentEquals(legacyHistory, graphPath.parent.resolve("legacy-history-${sha256(legacyHistory)}.json").readBytes())
    }

    @Test
    fun `manifest attributes every composed provisional edit to the final acceptance revision`() {
        val root = Files.createTempDirectory("repair-promoted-manifest-")
        val paths = listOf("code.c", "helper.c")
        paths.forEach { root.resolve(it).writeText("int value(void) { return 0; }\n") }
        val manifest = root.resolve("source_tree_manifest.json")
        manifest.writeText(paths.joinToString(prefix = "{\"files\":[", postfix = "]}") { path ->
            "{\"path\":\"$path\",\"sha256\":\"${sha256(root.resolve(path).readBytes())}\",\"generator\":\"fixture\"}"
        })
        val originalManifest = manifest.readBytes()
        val profile = DeclarativeRepairIndexProfile("composed-manifest-fixture", RepairIndexLayout(paths, paths,
            modules = listOf(RepairModuleEvidence("unit", paths)), behaviorRootModuleIds = listOf("unit")))
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(2, 60_000)
            graph.bindOriginalBinary(sha256("reference".toByteArray()))
            graph.bindExpectedObservations(sha256("fixture-expected".toByteArray()))
            fun proof(attempt: ModuleRevisionAttempt) = RepairValidationProof(
                repairCandidateSourceSha256(graph.candidateSources(attempt)), graph.snapshot.profileSha256,
                graph.snapshot.indexSha256, corpus.sha256, sha256("reference".toByteArray()),
                sha256("fixture-rebuilt".toByteArray()), sha256("fixture-runtime".toByteArray()),
                sha256("fixture-evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
            val first = graph.beginAttempt(listOf(paths[0]), metadata(corpus))
            graph.installCandidate(first, mapOf(paths[0] to "int value(void) { return 1; }\n".toByteArray()))
            graph.recordProvisional(first, RepairEvidence("behavior", "one retained case remains"), proof(first))
            assertContentEquals(originalManifest, manifest.readBytes())
            val second = graph.beginAttempt(listOf(paths[1]), metadata(corpus).copy(iterationIndex = 2, failureKind = "behavior"))
            graph.installCandidate(second, mapOf(paths[1] to "int value(void) { return 2; }\n".toByteArray()))
            val accepted = graph.accept(second, RepairEvidence("valid", "all fixture cases matched"), proof(second))
            assertEquals(listOf(paths[1]), accepted.changes.map { it.path })
            val files = Json.parseToJsonElement(manifest.readText()).jsonObject.getValue("files").jsonArray
            files.forEach { element ->
                val entry = element.jsonObject
                assertEquals(sha256(root.resolve(entry.getValue("path").jsonPrimitive.content).readBytes()),
                    entry.getValue("sha256").jsonPrimitive.content)
                assertEquals(sha256("revision:${accepted.id}".toByteArray()), entry.getValue("promptSha256").jsonPrimitive.content)
                assertEquals("repair-revision", entry.getValue("generator").jsonPrimitive.content)
            }
        }
        ModuleRevisionGraph.open(root, profile).use { graph ->
            assertEquals(graph.snapshot.headId, graph.snapshot.fullyAcceptedHeadId)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, graph.snapshot.runs.single().status)
        }
    }

    @Test
    fun `schema one run stays schema one and schema two failure requires typed link and resolution`() {
        val legacy = RepairRunState("run_00000001", RepairRunStatus.VALIDATION_FAILED,
            "baseline", null, null, "a".repeat(64), 2, 1, 1, 2, schemaVersion = 1)
        val bytes = legacy.toJson()
        assertFalse(bytes.contains("rollbackFailureAttemptId"))
        assertEquals(bytes, parseRepairRunState(bytes).toJson())
        assertNull(parseRepairRunState(bytes).rollbackFailureAttemptId)
        val failed = legacy.copy(schemaVersion = 2, status = RepairRunStatus.ROLLBACK_FAILED,
            rollbackFailureAttemptId = "revision_00000001_aaaaaaaaaaaaaaaa",
            rollbackResolution = RepairRollbackState.RESTORE_FAILED_UNRESOLVED)
        assertEquals(failed, parseRepairRunState(failed.toJson()))
        assertFailsWith<IllegalArgumentException> { failed.copy(rollbackFailureAttemptId = null) }
        assertFailsWith<IllegalArgumentException> { failed.copy(rollbackResolution = RepairRollbackState.RESTORED_VERIFIED) }
        assertFailsWith<IllegalArgumentException> { failed.copy(status = RepairRunStatus.VALIDATION_FAILED) }
        assertFailsWith<IllegalArgumentException> { parseRepairRunState(failed.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":3")) }
        assertFailsWith<IllegalArgumentException> { parseRepairRunState(failed.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":1")) }
    }

    @Test
    fun `live rollback failure atomically links pending run and survives independent process recovery`() {
        val root = rollbackRoot()
        var armed = false
        var attemptId = ""
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionFailure()
            if (point is ModuleRevisionFaultPoint.BeforeRollbackExchange && point.phase == "promotion") throw PromotionRollbackRefusal()
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "promotion-rollback") {
                throw RestorationRefusal()
            }
        }).use { graph ->
            val promoted = leavePromotedPending(graph, crash = false)
            val attempt = promoted.attempt
            attemptId = attempt.id
            val before = graph.snapshot
            armed = true
            val failure = assertFailsWith<RestorationRefusal> { graph.reject(attempt, RepairEvidence("rejected", "authored failure")) }
            assertEquals("authored restoration refusal", failure.message)
            val failed = graph.snapshot.runs.single()
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, failed.status)
            assertEquals(attempt.id, failed.rollbackFailureAttemptId)
            assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, failed.rollbackResolution)
            assertEquals(before.runs.single().attemptedCount, failed.attemptedCount)
            assertEquals(before.fullyAcceptedHeadId, graph.snapshot.fullyAcceptedHeadId)
            assertEquals(before.provisionalHeadId, graph.snapshot.provisionalHeadId)
            assertEquals(before.headId, graph.snapshot.headId)
            assertTrue(graph.derivedRepairIterations().isEmpty()) // Failure is run-level, not a fabricated finalized node.
            val durable = Json.parseToJsonElement(root.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
            val record = durable.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
            assertEquals("restore_failed_unresolved", record.getValue("state").jsonPrimitive.content)
            assertEquals(attempt.id, record.getValue("attemptId").jsonPrimitive.content)
            val durableBeforeAcceptance = root.resolve("reports/repair-revisions/graph.json").readBytes()
            val sourceBeforeAcceptance = root.resolve("code.c").readBytes()
            val acceptanceRefusal = assertFailsWith<IllegalArgumentException> {
                graph.accept(attempt, RepairEvidence("valid", "fixture matched"), promoted.proof)
            }
            assertEquals("a failed rollback attempt must be restored and finalized before further acceptance", acceptanceRefusal.message)
            assertContentEquals(durableBeforeAcceptance, root.resolve("reports/repair-revisions/graph.json").readBytes())
            assertContentEquals(sourceBeforeAcceptance, root.resolve("code.c").readBytes())
            assertEquals(failed, graph.finishRun(RepairRunStatus.CANCELLED, null))
            graph.synchronizeRepairHistory()
            assertEquals(failed, RepairHistory(root.resolve("reports/repair_history.json")).runStates().single())
            RepairProgressProjection(root.resolve("reports")).use { it.state(graph, AgentWorkflowPhase.REJECTED) }
            val events = AgentProgressJournal.read(root.resolve("reports"))!!.getValue("events").jsonArray
            assertEquals("failed", events.last().jsonObject.getValue("phase").jsonPrimitive.content)
        }
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${root}", "-cp", System.getProperty("java.class.path"),
            RepairRunReopenProbe::class.java.name, root.toString()).redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS))
            val output = process.inputStream.readNBytes(64 * 1024).decodeToString()
            assertEquals(0, process.exitValue(), output)
            assertTrue(output.contains("rollback_failed"), output)
            assertTrue(output.contains("restored_after_failure"), output)
            assertTrue(output.contains(attemptId), output)
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        }
        ModuleRevisionGraph.open(root, profile).use { graph ->
            val run = graph.snapshot.runs.single()
            val record = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, run.status)
            assertEquals(attemptId, run.rollbackFailureAttemptId)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, run.rollbackResolution)
            assertEquals(run.rollbackResolution, record.state)
            assertEquals(attemptId, record.attemptId)
            assertEquals(run.id, record.runId)
        }
    }

    @Test
    fun `startup failure commits same coupled outcome and rejects forged pending links before restoration`() {
        val root = rollbackRoot()
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionCrash()
        }).use { leavePromotedPending(it) }
        assertFailsWith<StartupRestoreRefusal> {
            ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") {
                    throw StartupRestoreRefusal()
                }
            }).use { }
        }
        val path = root.resolve("reports/repair-revisions/graph.json")
        val committed = path.readText()
        val document = Json.parseToJsonElement(committed).jsonObject
        val failed = parseRepairRunState(document.getValue("runs").jsonArray.single().toString())
        assertEquals(RepairRunStatus.ROLLBACK_FAILED, failed.status)
        assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, failed.rollbackResolution)
        val source = root.resolve("code.c").readBytes()
        val forgeries = listOf(
            committed.replace("\"rollbackFailureAttemptId\":\"${failed.rollbackFailureAttemptId}\"", "\"rollbackFailureAttemptId\":null"),
            committed.replace("\"rollbackFailureAttemptId\":\"${failed.rollbackFailureAttemptId}\"", "\"rollbackFailureAttemptId\":\"revision_missing\""),
            committed.replace("\"rollbackResolution\":\"restore_failed_unresolved\"", "\"rollbackResolution\":\"restored_after_failure\""),
            committed.replace("\"state\":\"restore_failed_unresolved\"", "\"state\":\"restore_in_progress\""),
            committed.replace("\"runId\":\"run_00000001\"", "\"runId\":\"run_00000002\""),
        )
        forgeries.forEach { forged ->
            assertNotEquals(committed, forged)
            path.writeText(forged)
            assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, profile).use { } }
            assertEquals(forged, path.readText())
            assertContentEquals(source, root.resolve("code.c").readBytes())
        }
        path.writeText(committed)
        ModuleRevisionGraph.open(root, profile).use { graph ->
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, graph.snapshot.runs.single().status)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, graph.snapshot.runs.single().rollbackResolution)
        }
    }

    @Test
    fun `uncommitted failure and generic pending validation cannot mint rollback terminal history`() {
        val root = rollbackRoot()
        var armed = false
        var writes = 0
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionFailure()
            if (point is ModuleRevisionFaultPoint.BeforeRollbackExchange && point.phase == "promotion") throw PromotionRollbackRefusal()
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "promotion-rollback") {
                throw RestorationRefusal()
            }
            if (armed && point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                point.scope == "revision-state" && point.name == "graph.json" && ++writes == 2) {
                throw FailurePublicationRefusal()
            }
        }).use { graph ->
            val promoted = leavePromotedPending(graph, crash = false)
            val attempt = promoted.attempt
            assertFailsWith<IllegalArgumentException> { graph.finishRun(RepairRunStatus.ROLLBACK_FAILED, null) }
            armed = true
            val failure = assertFailsWith<RestorationRefusal> { graph.reject(attempt, null) }
            assertTrue(failure.suppressed.any { it is FailurePublicationRefusal })
            assertEquals(2, writes)
            val durable = root.resolve("reports/repair-revisions/graph.json").readText()
            assertFalse(durable.contains("restore_failed_unresolved"))
            assertFalse(durable.contains("rollback_failed"))
            val document = Json.parseToJsonElement(durable).jsonObject
            assertEquals(RepairRunStatus.RUNNING, parseRepairRunState(document.getValue("runs").jsonArray.single().toString()).status)
            assertEquals("restore_in_progress", document.getValue("pending").jsonObject
                .getValue("rollbackRecord").jsonObject.getValue("state").jsonPrimitive.content)
            assertNull(graph.snapshot.runs.single().rollbackFailureAttemptId)
            armed = false
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.finishRun(RepairRunStatus.VALIDATION_FAILED, null).status)
        }
        ModuleRevisionGraph.open(root, profile).use { graph ->
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.single().status)
            assertNull(graph.snapshot.runs.single().rollbackFailureAttemptId)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, graph.snapshot.nodes.last().rollbackRecord?.state)
        }
    }

    @Test
    fun `generic workflow exception preserves canonical rollback failure instead of validation failure`() {
        lateinit var fixture: Fixture
        fixture = fixture("broken", "pass3", temporaryParent = Path.of("build/test-tmp").toAbsolutePath().normalize()
            .also { Files.createDirectories(it) }, afterValidation = { source ->
            if (source == "pass3") fixture.root.resolve("code.c").writeText("foreign replacement")
        })
        val result = fixture.loop.runRepair(fixture.root, fixture.original, inputs, maxIterations = 1)
        assertEquals(RepairRunStatus.ROLLBACK_FAILED, result.runState.status)
        assertNotNull(result.runState.rollbackFailureAttemptId)
        assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, result.runState.rollbackResolution)
        assertNull(result.runState.acceptedHeadId)
        assertTrue(result.iterations.isEmpty())
        assertEquals("foreign replacement", fixture.root.resolve("code.c").readText())
    }

    @Test
    fun `startup legacy run reserves real dependency lists and derived run fields before source exchange`() {
        val modules = listOf(RepairModuleEvidence("a_owner_" + "x".repeat(120), listOf("code.c"))) +
            (0 until 30).map { number -> RepairModuleEvidence("z_dep_${number.toString().padStart(2, '0')}_" + "y".repeat(120),
                emptyList(), dependencyModuleIds = listOf("a_owner_" + "x".repeat(120))) }
        val wideProfile = DeclarativeRepairIndexProfile("recovery-reservation-wide",
            RepairIndexLayout(listOf("code.c"), listOf("code.c"), modules = modules))
        for (graphLimit in listOf(true, false)) {
            val limit = 16L * 1024
            val budget = if (graphLimit) RepairResourceBudget(maximumGraphBytes = limit)
                else RepairResourceBudget(maximumProjectionBytes = limit)
            fun legacyPending(root: Path): String {
                ModuleRevisionGraph.openForTesting(root, wideProfile, budget, ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionCrash()
                }).use { graph ->
                    leavePromotedPending(graph, "RESERVATION_PADDING")
                }
                val path = root.resolve("reports/repair-revisions/graph.json")
                val run = parseRepairRunState(Json.parseToJsonElement(path.readText()).jsonObject
                    .getValue("runs").jsonArray.single().toString())
                assertEquals(RepairRunStatus.RUNNING, run.status)
                val legacy = path.readText().replace(run.toJson(), run.copy(schemaVersion = 1).toJson())
                assertNotEquals(path.readText(), legacy)
                path.writeText(legacy)
                return legacy
            }
            val reference = rollbackRoot()
            legacyPending(reference)
            assertFailsWith<StartupRestoreRefusal> {
                ModuleRevisionGraph.openForTesting(reference, wideProfile, budget, ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") {
                        throw StartupRestoreRefusal()
                    }
                }).use { }
            }
            val failureGraphBytes = reference.resolve("reports/repair-revisions/graph.json").readBytes().size
            ModuleRevisionGraph.open(reference, wideProfile, budget).use { graph ->
                val node = graph.snapshot.nodes.last()
                assertEquals(listOf(modules.first().id), node.changedModules)
                assertEquals(modules.drop(1).map { it.id }, node.invalidatedModules)
                assertEquals(RepairRunStatus.ROLLBACK_FAILED, graph.snapshot.runs.single().status)
                assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, graph.snapshot.runs.single().rollbackResolution)
                graph.synchronizeRepairHistory()
            }
            val terminalGraphBytes = reference.resolve("reports/repair-revisions/graph.json").readBytes().size
            val terminalHistoryBytes = reference.resolve("reports/repair_history.json").readBytes().size
            val padding = (limit - (if (graphLimit) terminalGraphBytes else terminalHistoryBytes) + 1).toInt()
            assertTrue(padding > 0)
            if (graphLimit) {
                assertTrue(failureGraphBytes + padding <= limit) // Pending failure fits; actual terminal graph cannot.
                assertTrue(terminalGraphBytes + padding > limit)
            } else assertTrue(terminalHistoryBytes + padding > limit)

            val root = rollbackRoot()
            val legacy = legacyPending(root)
            val padded = legacy.replace("RESERVATION_PADDING", "RESERVATION_PADDING" + "p".repeat(padding))
            val graphPath = root.resolve("reports/repair-revisions/graph.json")
            graphPath.writeText(padded)
            assertTrue(padded.toByteArray().size <= budget.maximumGraphBytes)
            val sourcePath = root.resolve("code.c")
            val sourceBytes = sourcePath.readBytes()
            val graphBytes = graphPath.readBytes()
            val sourceKey = Files.readAttributes(sourcePath, BasicFileAttributes::class.java).fileKey()
            val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            var exchanges = 0
            val failure = assertFailsWith<RepairBudgetExceededException> {
                ModuleRevisionGraph.openForTesting(root, wideProfile, budget, ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") exchanges++
                }).use { }
            }
            assertTrue(failure.message.orEmpty().contains(if (graphLimit) "revision graph" else "projection"), failure.message)
            assertEquals(0, exchanges)
            assertContentEquals(sourceBytes, sourcePath.readBytes())
            assertContentEquals(graphBytes, graphPath.readBytes())
            assertEquals(sourceKey, Files.readAttributes(sourcePath, BasicFileAttributes::class.java).fileKey())
            assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
        }
    }

    @Test
    fun `successful interrupted recovery history is reserved at its real projector boundary before candidate publication`() {
        // Resource-only iterator controls: no filesystem race or graph authority is inferred.
        fun inventory(entries: Iterable<Path>, maximum: Int) =
            decompengine.project.RepairAcpEvidenceArchiveVerifier.boundedDeclaredSourceEntryNames(entries, maximum)
        val first = Path.of("first")
        val second = Path.of("second")
        assertEquals(setOf("first", "second"), inventory(listOf(first, second), 2))
        val duplicate = assertFailsWith<IllegalArgumentException> { inventory(listOf(first, first), 2) }
        assertTrue(duplicate.message.orEmpty().contains("duplicate entry"))
        var observed = 0
        val beyondBound = Iterable {
            object : Iterator<Path> {
                override fun hasNext() = true
                override fun next(): Path {
                    observed++
                    check(observed <= 3) { "inventory advanced after refusing M+1" }
                    return Path.of("entry-$observed")
                }
            }
        }
        val overflow = assertFailsWith<IllegalArgumentException> { inventory(beyondBound, 2) }
        assertTrue(overflow.message.orEmpty().contains("entry bound"))
        assertEquals(3, observed)
        val reference = rollbackRoot()
        ModuleRevisionGraph.open(reference, profile).use { graph ->
            val corpus = graph.retainRegressionInputs(inputs)
            graph.beginRun(2, 60_000)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
            graph.installCandidate(attempt, mapOf("code.c" to "pass3".toByteArray()))
        }
        lateinit var iterations: List<RepairIteration>
        lateinit var runs: List<RepairRunState>
        ModuleRevisionGraph.open(reference, profile).use { graph ->
            assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.single().status)
            val rollback = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, rollback.state)
            assertEquals(true, rollback.candidateSourceInstallStarted)
            assertEquals("broken", reference.resolve("code.c").readText())
            assertNull(graph.snapshot.runs.single().rollbackFailureAttemptId)
            iterations = graph.derivedRepairIterations()
            runs = graph.snapshot.runs
        }
        // Ask the actual existing projector, not a duplicated size formula, for its exact admission edge.
        fun fits(limit: Long): Boolean = try {
            renderRepairHistoryProjection(iterations, inputs, limit, 3, runs)
            true
        } catch (_: RepairBudgetExceededException) { false }
        var low = 1L
        var high = 16L * 1024
        assertTrue(fits(high))
        while (low < high) {
            val middle = (low + high) / 2
            if (fits(middle)) high = middle else low = middle + 1
        }
        val admitted = low
        assertTrue(fits(admitted))
        assertFalse(fits(admitted - 1))
        for (limit in listOf(admitted, admitted - 1)) {
            val root = rollbackRoot()
            val source = root.resolve("code.c")
            val budget = RepairResourceBudget(maximumProjectionBytes = limit)
            var publications = 0
            ModuleRevisionGraph.openForTesting(root, profile, budget, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") publications++
            }).use { graph ->
                val corpus = graph.retainRegressionInputs(inputs)
                graph.beginRun(2, 60_000)
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus))
                val path = root.resolve("reports/repair-revisions/graph.json")
                val before = path.readBytes()
                val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
                val snapshot = graph.snapshot
                publications = 0
                if (limit == admitted) {
                    graph.installCandidate(attempt, mapOf("code.c" to "pass3".toByteArray()))
                } else {
                    assertFailsWith<RepairBudgetExceededException> {
                        graph.installCandidate(attempt, mapOf("code.c" to "pass3".toByteArray()))
                    }
                    assertEquals(0, publications)
                    assertEquals(snapshot, graph.snapshot)
                    assertContentEquals(before, path.readBytes())
                    assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
                    assertEquals("broken", source.readText())
                }
            }
            if (limit == admitted) {
                ModuleRevisionGraph.open(root, profile, budget).use { graph ->
                    assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.single().status)
                    assertNull(graph.snapshot.runs.single().rollbackFailureAttemptId)
                    graph.synchronizeRepairHistory()
                }
                assertTrue(root.resolve("reports/repair_history.json").readBytes().isNotEmpty())
            }
        }
    }

    @Test
    fun `startup snapshots authenticated target bytes when installed candidate exceeds aggregate source cap`() {
        val paths = listOf("a.c", "b.c")
        val original = "a".repeat(8).toByteArray()
        val unchanged = "b".repeat(8).toByteArray()
        val candidate = "c".repeat(16).toByteArray()
        val foreign = "x".repeat(16).toByteArray()
        val boundedProfile = DeclarativeRepairIndexProfile("oversized-recovery-target",
            RepairIndexLayout(paths, paths, modules = listOf(
                RepairModuleEvidence("a", listOf("a.c")), RepairModuleEvidence("b", listOf("b.c")))))
        val budget = RepairResourceBudget(maximumSourceFiles = 2, maximumSourceFileBytes = 16,
            maximumSourceBytes = 16, maximumContextFiles = 2, maximumContextBytes = 16,
            maximumStagingDirectories = 2, maximumStagingBytes = 16, maximumPatchFiles = 1,
            maximumPatchBytes = 16)
        for (foreignReplacement in listOf(false, true)) {
            val parent = Path.of("build/test-tmp").toAbsolutePath().normalize()
            Files.createDirectories(parent)
            val root = Files.createTempDirectory(parent, "oversized-recovery-")
            val source = root.resolve("a.c")
            source.writeBytes(original)
            root.resolve("b.c").writeBytes(unchanged)
            var exchanges = 0
            ModuleRevisionGraph.openForTesting(root, boundedProfile, budget, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "candidate") {
                    exchanges++
                    throw CandidateInstallCrash()
                }
            }).use { graph ->
                graph.enableRunContract()
                val attempt = graph.beginAttempt(listOf("a.c")) // Standalone: no owning run is fabricated.
                assertFailsWith<CandidateInstallCrash> { graph.installCandidate(attempt, mapOf("a.c" to candidate)) }
                // Error poisons the graph. Only close it, then reopen from durable state.
            }
            assertEquals(1, exchanges)
            assertContentEquals(candidate, source.readBytes())
            assertTrue(source.fileSize() + root.resolve("b.c").fileSize() > budget.maximumSourceBytes)
            assertTrue(paths.all { root.resolve(it).fileSize() <= budget.maximumSourceFileBytes })
            if (foreignReplacement) {
                source.writeBytes(foreign)
                val key = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
                val failure = assertFailsWith<IllegalStateException> {
                    ModuleRevisionGraph.open(root, boundedProfile, budget).use { }
                }
                assertEquals("pending repair recovery found an unrecognized source replacement", failure.message)
                assertContentEquals(foreign, source.readBytes())
                assertContentEquals(unchanged, root.resolve("b.c").readBytes())
                assertEquals(key, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
                val durable = Json.parseToJsonElement(root.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
                assertTrue(durable.getValue("runs").jsonArray.isEmpty())
                val record = durable.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
                assertEquals("unrecognized_source_state", record.getValue("failureCode").jsonPrimitive.content)
            } else {
                ModuleRevisionGraph.open(root, boundedProfile, budget).use { graph ->
                    assertContentEquals(original, source.readBytes())
                    assertContentEquals(unchanged, root.resolve("b.c").readBytes())
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertTrue(graph.snapshot.runs.isEmpty())
                    val recovered = graph.snapshot.nodes.last()
                    assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
                    assertTrue(recovered.recoveredAfterCrash)
                    assertEquals(RepairRollbackState.RESTORED_VERIFIED, recovered.rollbackRecord?.state)
                    assertNull(recovered.rollbackRecord?.runId)
                    assertEquals(listOf("a"), recovered.changedModules)
                }
            }
        }
    }

    @Test
    fun `schema one owning run cannot hide pending or finalized committed rollback failure`() {
        val root = rollbackRoot()
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionCrash()
        }).use { leavePromotedPending(it) }
        assertFailsWith<StartupRestoreRefusal> {
            ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") {
                    throw StartupRestoreRefusal()
                }
            }).use { }
        }
        val graphPath = root.resolve("reports/repair-revisions/graph.json")
        val sourcePath = root.resolve("code.c")
        fun refuseDowngrade(expectedResolution: RepairRollbackState) {
            val canonical = graphPath.readText()
            val run = parseRepairRunState(Json.parseToJsonElement(canonical).jsonObject
                .getValue("runs").jsonArray.single().toString())
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, run.status)
            assertEquals(expectedResolution, run.rollbackResolution)
            val downgraded = run.copy(schemaVersion = 1, status = RepairRunStatus.VALIDATION_FAILED,
                rollbackFailureAttemptId = null, rollbackResolution = null)
            val forged = canonical.replace(run.toJson(), downgraded.toJson())
            assertNotEquals(canonical, forged)
            graphPath.writeText(forged)
            val sourceBytes = sourcePath.readBytes()
            val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            val sourceKey = Files.readAttributes(sourcePath, BasicFileAttributes::class.java).fileKey()
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, profile).use { } }
            assertEquals("rollback record lacks its run failure link", failure.message)
            assertEquals(forged, graphPath.readText())
            assertContentEquals(sourceBytes, sourcePath.readBytes())
            assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
            assertEquals(sourceKey, Files.readAttributes(sourcePath, BasicFileAttributes::class.java).fileKey())
            graphPath.writeText(canonical)
        }
        refuseDowngrade(RepairRollbackState.RESTORE_FAILED_UNRESOLVED)
        ModuleRevisionGraph.open(root, profile).use { graph ->
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, graph.snapshot.runs.single().status)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, graph.snapshot.runs.single().rollbackResolution)
            assertEquals("broken", sourcePath.readText())
        }
        refuseDowngrade(RepairRollbackState.RESTORED_AFTER_FAILURE)
        ModuleRevisionGraph.open(root, profile).use { graph ->
            val run = graph.snapshot.runs.single()
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, run.status)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, run.rollbackResolution)
            assertEquals(run.rollbackFailureAttemptId, graph.snapshot.nodes.last().rollbackRecord?.attemptId)
        }
    }

    private class CandidateInstallCrash : Error()
    private class PromotionCrash : Error()
    private class PromotionFailure : IllegalStateException("authored promotion failure")
    private class PromotionRollbackRefusal : IllegalStateException("authored promotion CAS rollback refusal")
    private class RestorationRefusal : IllegalStateException("authored restoration refusal")
    private class FailurePublicationRefusal : IllegalStateException("authored failure-publication refusal")
    private class StartupRestoreRefusal : IllegalStateException("authored startup restoration refusal")
    private data class PromotedPending(val attempt: ModuleRevisionAttempt, val proof: RepairValidationProof)

    private fun rollbackRoot(): Path {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "rollback-run-").also { it.resolve("code.c").writeText("broken") }
    }

    private fun leavePromotedPending(graph: ModuleRevisionGraph, summary: String? = null, crash: Boolean = true): PromotedPending {
        graph.enableRunContract()
        val corpus = graph.retainRegressionInputs(inputs)
        graph.beginRun(2, 60_000)
        val reference = sha256("reference".toByteArray())
        graph.bindOriginalBinary(reference)
        graph.bindExpectedObservations(sha256("fixture-expected".toByteArray()))
        val attempt = graph.beginAttempt(listOf("code.c"), metadata(corpus).copy(summary = summary))
        graph.installCandidate(attempt, mapOf("code.c" to "pass3".toByteArray()))
        val proof = rollbackProof(graph, attempt)
        if (crash) {
            assertFailsWith<PromotionCrash> { graph.accept(attempt, RepairEvidence("valid", "fixture matched"), proof) }
            // Poisoned after Error: callers may close and inspect disk, never reuse this graph.
        } else {
            val failure = assertFailsWith<PromotionFailure> {
                graph.accept(attempt, RepairEvidence("valid", "fixture matched"), proof)
            }
            assertTrue(failure.suppressed.any { it is PromotionRollbackRefusal })
            assertEquals(RepairRunStatus.RUNNING, graph.snapshot.runs.single().status)
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        }
        return PromotedPending(attempt, proof)
    }

    private fun rollbackProof(graph: ModuleRevisionGraph, attempt: ModuleRevisionAttempt): RepairValidationProof {
        val state = graph.snapshot
        return RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)),
            state.profileSha256, state.indexSha256, graph.retainedRegressionCorpus().sha256,
            sha256("reference".toByteArray()), sha256("pass3".toByteArray()),
            sha256("fixture-runtime".toByteArray()), sha256("fixture-evidence".toByteArray()),
            true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
    }

    private fun metadata(corpus: RetainedRegressionCorpus) = RevisionRepairMetadata(1, "compile", "bounded repair", null,
        corpus.inputs.map { it.id }, RepairEvidence("compile", "code.c:1: syntax error"), corpus.sha256,
        publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)

    private data class Fixture(val root: Path, val original: Path, val loop: TraceGuidedRepairLoop,
        val history: RepairHistory, val seenSources: MutableList<String>, val canonicalDuringPrompts: MutableList<String>)

    private fun fixture(initial: String, vararg replacements: String, cancellation: AgentCancellationSource = AgentCancellationSource(),
        afterValidation: (String) -> Unit = {}, omitCase: Boolean = false, temporaryParent: Path? = null): Fixture {
        val root = if (temporaryParent == null) Files.createTempDirectory("repair-run-semantics-")
            else Files.createTempDirectory(temporaryParent, "repair-run-semantics-")
        root.resolve("code.c").writeText(initial)
        val original = root.resolve("reference.fixture").also { it.writeText("reference") }
        val seen = mutableListOf<String>()
        val canonical = mutableListOf<String>()
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult = error("captured only")
            override fun executeCaptured(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult {
                val before = initialFiles.getValue("code.c")
                seen += before.toString(Charsets.UTF_8)
                canonical += root.resolve("code.c").readText()
                val bytes = replacements[seen.lastIndex].toByteArray()
                output.replace("code.c", bytes)
                return AgentExecutionResult(AgentStopReason.COMPLETED, "bounded fixture edit", listOf(AgentFileChange(
                    AgentWorkspacePath("project", "code.c"), AgentFileChangeKind.MODIFIED, sha256(before), sha256(bytes), bytes.size.toLong())))
            }
        }
        val validator = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? = error("immutable candidate API required")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = error("immutable candidate API required")
            override fun evaluateBehavior(id: String, projectDir: Path, originalBinary: Path, rebuiltBinary: Path,
                inputs: List<ProcessInput>, reportsDir: Path, budget: RepairResourceBudget): BehaviorComparisonReport = error("immutable candidate API required")
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                val source = request.candidateSources.getValue("code.c").toString(Charsets.UTF_8)
                assertEquals(initial, root.resolve("code.c").readText())
                val proof = RepairValidationProof(request.sourceRevisionSha256, request.profileSha256, request.indexSha256,
                    request.regressionCorpusSha256, request.originalBinary?.let { sha256(original.readBytes()) },
                    if (source == "broken") null else sha256(source.toByteArray()), sha256("fixture-runtime".toByteArray()),
                    sha256("fixture-evidence:$source".toByteArray()), true, assurance)
                afterValidation(source)
                if (source == "broken") return RepairCandidateValidationOutcome.CompileFailed(CompileFailure(listOf("fixture"), 1, "", "code.c:1: syntax error"), proof)
                if (request.originalBinary == null) return RepairCandidateValidationOutcome.CompileValid(proof)
                val count = source.removePrefix("pass").toInt()
                val cases = request.inputs.mapIndexed { index, input -> BehaviorCaseResult(input,
                    ProcessOutput(0, "expected".toByteArray(), byteArrayOf(), listOf("fixture")),
                    ProcessOutput(0, (if (index < count) "expected" else "different").toByteArray(), byteArrayOf(), listOf("fixture"))) }
                val report = BehaviorComparisonReport(request.label, original, root.resolve("rebuilt.fixture"),
                    if (omitCase) cases.dropLast(1) else cases, request.reportsDir.resolve("${request.label}.validation.json"))
                return RepairCandidateValidationOutcome.BehaviorChecked(report, proof)
            }
        }
        val history = RepairHistory(root.resolve("reports/repair_history.json"))
        return Fixture(root, original, TraceGuidedRepairLoop.forTesting(harness, history, profile, validator,
            CapturedRepairStagingAuthority, limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(20)),
            cancellation = cancellation.cancellation), history, seen, canonical)
    }
}

object RepairRunReopenProbe {
    @JvmStatic fun main(args: Array<String>) {
        val root = Path.of(args.single())
        val profile = repairRunFixtureProfile()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            check(graph.snapshot.fullyAcceptedHeadId == null)
            check(graph.retainedRegressionCorpus().inputs.map { it.id } == listOf("case0", "case1", "case2"))
            println(graph.snapshot.runs.single().toJson())
            println(root.resolve("code.c").readText())
        }
    }
}

private fun repairRunFixtureProfile() = DeclarativeRepairIndexProfile("run-fixture",
    RepairIndexLayout(listOf("code.c"), listOf("code.c"),
        modules = listOf(RepairModuleEvidence("unit", listOf("code.c"))), behaviorRootModuleIds = listOf("unit")))

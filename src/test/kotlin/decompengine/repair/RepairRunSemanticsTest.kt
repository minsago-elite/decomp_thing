package decompengine.repair

import decompengine.agent.*
import decompengine.project.sha256
import decompengine.jobs.AgentProgressJournal
import decompengine.validation.*
import java.nio.file.Files
import java.nio.file.Path
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
            assertEquals(3, state.schemaVersion)
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

    private fun metadata(corpus: RetainedRegressionCorpus) = RevisionRepairMetadata(1, "compile", "bounded repair", null,
        corpus.inputs.map { it.id }, RepairEvidence("compile", "code.c:1: syntax error"), corpus.sha256,
        publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)

    private data class Fixture(val root: Path, val original: Path, val loop: TraceGuidedRepairLoop,
        val history: RepairHistory, val seenSources: MutableList<String>, val canonicalDuringPrompts: MutableList<String>)

    private fun fixture(initial: String, vararg replacements: String, cancellation: AgentCancellationSource = AgentCancellationSource(),
        afterValidation: (String) -> Unit = {}, omitCase: Boolean = false): Fixture {
        val root = Files.createTempDirectory("repair-run-semantics-")
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

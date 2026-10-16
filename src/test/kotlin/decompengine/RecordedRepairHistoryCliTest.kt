package decompengine

import decompengine.repair.*
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.*

class RecordedRepairHistoryCliTest {
    @Test
    fun `actual CLI reaches an older trace producer attempt and its corpus case pages without another execution`() {
        val project = root()
        val fixture = producePagedRecordedTraceHistory(project)
        val recorded = readProjectRecordedRepairHistory(project)
        val snapshot = requireNotNull(recorded.snapshot)
        val before = contents(project)
        val latest = captureCli(project)
        assertFalse(Regex("repair iteration 1:").containsMatchIn(latest), latest)
        assertTrue("Older history: --page 2 --case-page 1 --graph ${snapshot.graphSha256}" in latest, latest)
        val older = captureCli(project, "--page", "6", "--graph", snapshot.graphSha256)
        assertTrue("repair iteration 1: rejected" in older, older)
        assertTrue("summary: Compile repair — rejected" in older, older)
        assertTrue("evidence assurance: Test-only evidence; release completeness is not established." in older, older)
        assertTrue("after: Build validation evidence; recorded reference artifact_" in older, older)
        val first = snapshot.attempts.first()
        assertTrue("recorded run: ${first.run?.value}" in older, older)
        assertTrue("retained case corpus: ${first.corpusSha256}" in older, older)
        assertTrue(first.retainedCases.first().value in older, older)
        assertFalse(first.retainedCases.last().value in older, older)
        val laterCases = captureCli(project, "--page", "6", "--case-page", "2", "--graph", snapshot.graphSha256)
        assertTrue(first.retainedCases.last().value in laterCases, laterCases)
        assertFalse(first.retainedCases.first().value in laterCases, laterCases)
        assertTrue("Previous case references:" in laterCases, laterCases)
        assertFalse("PRIVATE" in older || "code.c" in older || "reports/" in older, older)
        fixture.assertSingleInvocation()
        val after = contents(project)
        assertEquals(before.keys, after.keys)
        before.forEach { (name, bytes) -> assertContentEquals(bytes, after.getValue(name), name) }
        assertEquals(2, presentRecordedRepairHistory(recorded,
            RepairRecordedHistorySelection(1, 1, "0".repeat(64))).exitCode)
        assertEquals(2, presentRecordedRepairHistory(recorded,
            RepairRecordedHistorySelection(99, 1, snapshot.graphSha256)).exitCode)
    }

    @Test
    fun `history arguments reject duplicate unknown unbound malformed and oversized page selections`() {
        val valid = parseRecordedRepairHistoryArguments(listOf("project", "--page", "2", "--case-page", "2", "--graph", "a".repeat(64)))
        assertEquals(RepairRecordedHistorySelection(2, 2, "a".repeat(64)), valid.selection)
        val invalid = listOf(emptyList(), listOf("project", "--page"), listOf("project", "--unknown", "1"),
            listOf("project", "--page", "1", "--page", "1"), listOf("project", "--page", "2"),
            listOf("project", "--case-page", "2"), listOf("project", "--graph", "PRIVATE")) +
            listOf("0", "-1", "01", "+1", "1e2", "2147483648", "1".repeat(100)).map { listOf("project", "--page", it) }
        invalid.forEach { args -> assertFailsWith<IllegalArgumentException> { parseRecordedRepairHistoryArguments(args) } }
    }

    @Test
    fun `actual trace guided rejection reconnects through CLI without repeating the agent or validator`() {
        val project = root()
        val fixture = produceRejectedRecordedTraceHistory(project)
        val before = contents(project)
        val first = captureCli(project)
        val second = captureCli(project)
        assertEquals(first, second)
        assertTrue("repair iteration 1: rejected" in first, first)
        assertTrue("repair run run_00000001: rejected" in first, first)
        assertTrue("Recorded restoration was not required; candidate source installation did not begin." in first, first)
        assertTrue("fully accepted revision: none" in first, first)
        assertTrue("retained regression cases: 1" in first, first)
        assertFalse("Recorded restoration completed and was verified." in first, first)
        assertFalse("PRIVATE" in first || "code.c" in first || "reports/" in first, first)
        fixture.assertSingleInvocation()
        val after = contents(project)
        assertEquals(before.keys, after.keys)
        before.forEach { (name, bytes) -> assertContentEquals(bytes, after.getValue(name), name) }
    }

    @Test
    fun `actual read only CLI reconnects to canonical history without another repair or private text`() {
        for (detached in listOf(false, true)) {
            val root = root()
            val profile = DeclarativeRepairIndexProfile("PRIVATE-profile", RepairIndexLayout(listOf("code.c"),
                listOf("code.c"), modules = listOf(RepairModuleEvidence("PRIVATE-module", listOf("code.c")))))
            root.resolve("code.c").writeText("PRIVATE-original-source")
            ModuleRevisionGraph.open(root, profile).use { graph ->
                graph.enableRunContract()
                graph.retainRegressionInputs(listOf(ProcessInput("PRIVATE-case", listOf("PRIVATE-argv"), "PRIVATE-stdin".toByteArray())))
                if (detached) {
                    graph.beginRun(2, 60_000)
                    graph.bindOriginalBinary(sha256("reference".toByteArray()))
                    graph.bindExpectedObservations(sha256("expected".toByteArray()))
                }
                val corpus = graph.retainedRegressionCorpus()
                val metadata = RevisionRepairMetadata(1, "compile", "PRIVATE-prompt", "PRIVATE-summary", corpus.inputs.map { it.id },
                    RepairEvidence("compile", "PRIVATE-diagnostic", "reports/PRIVATE-before.json"), corpus.sha256,
                    publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
                val attempt = graph.beginAttempt(listOf("code.c"), metadata)
                graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-candidate-source".toByteArray()))
                assertContentEquals((if (detached) "PRIVATE-original-source" else "PRIVATE-candidate-source").toByteArray(),
                    root.resolve("code.c").readBytes())
                val rejected = graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-peer"))
                val rollback = assertNotNull(rejected.rollbackRecord)
                assertEquals(if (detached) RepairRollbackState.NOT_REQUIRED_VERIFIED else RepairRollbackState.RESTORED_VERIFIED,
                    rollback.state)
                assertEquals(!detached, rollback.candidateSourceInstallStarted)
                assertEquals(rollback.expectedSourceRevisionSha256, rollback.observedSourceRevisionSha256)
                assertContentEquals("PRIVATE-original-source".toByteArray(), root.resolve("code.c").readBytes())
            }
            val before = contents(root)
            val first = captureCli(root)
            val second = captureCli(root)
            assertEquals(first, second)
            assertTrue("Recorded repair metadata" in first)
            assertTrue("repair iteration 1: rejected" in first)
            val expectedRollback = if (detached)
                "Recorded restoration was not required; candidate source installation did not begin."
            else "Recorded restoration completed and was verified."
            assertTrue(expectedRollback in first, first)
            assertFalse((if (detached) "Recorded restoration completed and was verified."
                else "Recorded restoration was not required;") in first, first)
            assertTrue("fully accepted revision: none" in first)
            assertTrue("retained regression cases: 1" in first)
            for (private in listOf("PRIVATE-", "code.c", "reports/")) assertFalse(private in first, first)
            val after = contents(root)
            assertEquals(before.keys, after.keys)
            for (name in before.keys) assertContentEquals(before.getValue(name), after.getValue(name), name)
        }
    }

    @Test
    fun `absent and invalid canonical histories have different closed CLI results`() {
        val absent = presentRecordedRepairHistory(readProjectRecordedRepairHistory(root()))
        assertEquals(0, absent.exitCode)
        assertEquals(listOf("No canonical repair history is recorded."), absent.lines)
        val invalidRoot = root()
        Files.createDirectories(invalidRoot.resolve("reports/repair-revisions"))
        invalidRoot.resolve("reports/repair-revisions/graph.json").writeText("PRIVATE-invalid")
        val invalid = presentRecordedRepairHistory(readProjectRecordedRepairHistory(invalidRoot))
        assertEquals(1, invalid.exitCode)
        assertEquals(listOf("Recorded repair history is unavailable or invalid."), invalid.lines)
    }

    private fun root(): Path {
        val parent = Path.of("build/test-tmp/recorded-history-cli").toAbsolutePath()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "case-")
    }

    private fun captureCli(root: Path, vararg options: String): String {
        val bytes = ByteArrayOutputStream()
        val original = System.out
        try {
            PrintStream(bytes, true, Charsets.UTF_8).use { output ->
                System.setOut(output)
                main(arrayOf("repair-history", root.toString(), *options))
            }
        } finally { System.setOut(original) }
        return bytes.toString(Charsets.UTF_8)
    }

    private fun contents(root: Path): Map<String, ByteArray> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) }.toList().associate { root.relativize(it).toString() to it.readBytes() }
    }
}

/** Actual repair producer with authored in-memory agent/validation; no compiler or model is run. */
internal class RecordedTraceHistoryFixture {
    val agentInvocations = java.util.concurrent.atomic.AtomicInteger()
    val validations = java.util.concurrent.atomic.AtomicInteger()

    fun assertSingleInvocation() {
        assertEquals(1, agentInvocations.get())
        assertEquals(1, validations.get())
    }
}

internal fun produceRejectedRecordedTraceHistory(project: Path, caseCount: Int = 1): RecordedTraceHistoryFixture {
    require(caseCount in 1..100)
    val fixture = RecordedTraceHistoryFixture()
    val original = "PRIVATE-original-source".toByteArray()
    val candidate = "PRIVATE-candidate-source".toByteArray()
    Files.createDirectories(project)
    Files.write(project.resolve("code.c"), original)
    val profile = DeclarativeRepairIndexProfile("PRIVATE-trace-profile", RepairIndexLayout(
        listOf("code.c"), listOf("code.c"),
        modules = listOf(RepairModuleEvidence("PRIVATE-module", listOf("code.c")))))
    val harness = object : CapturedRepairAgentHarness {
        override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult =
            error("recorded trace fixture requires captured staging")

        override fun executeCaptured(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
            output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult {
            fixture.agentInvocations.incrementAndGet()
            assertContentEquals(original, initialFiles.getValue("code.c"))
            val path = AgentWorkspacePath(request.workspaceRoots.single().id, "code.c")
            output.replace(path.relativePath, candidate)
            return AgentExecutionResult(AgentStopReason.COMPLETED, "<script>PRIVATE-peer</script>",
                listOf(AgentFileChange(path, AgentFileChangeKind.MODIFIED, sha256(original), sha256(candidate), candidate.size.toLong())))
        }
    }
    val validation = object : RepairValidationStrategy {
        override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
        override fun requireAvailable() = Unit
        override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure {
            fixture.validations.incrementAndGet()
            assertContentEquals(candidate, Files.readAllBytes(projectDir.resolve("code.c")))
            assertContentEquals(original, Files.readAllBytes(project.resolve("code.c")))
            return CompileFailure(listOf("authored-validator"), 1, "", "code.c: PRIVATE diagnostic")
        }
        override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = error("compile rejection fixture")
        override fun evaluateBehavior(id: String, projectDir: Path, originalBinary: Path, rebuiltBinary: Path,
            inputs: List<ProcessInput>, reportsDir: Path, budget: RepairResourceBudget) = error("compile rejection fixture")
    }
    val history = RepairHistory(project.resolve("reports/repair_history.json"))
    TraceGuidedRepairLoop.forTesting(harness, history, profile, validation, CapturedRepairStagingAuthority).use { loop ->
        val iteration = loop.repairCompileError(project, CompileFailure(listOf("authored-validator"), 1, "",
            "code.c: <script>PRIVATE initial diagnostic</script>"),
            List(caseCount) { index -> ProcessInput(if (caseCount == 1) "PRIVATE-case" else "PRIVATE-case-${index.toString().padStart(3, '0')}",
                listOf("PRIVATE-argument"), "PRIVATE-stdin".toByteArray()) })
        assertEquals(RepairAttemptDisposition.REJECTED, iteration.disposition)
    }
    fixture.assertSingleInvocation()
    assertContentEquals(original, Files.readAllBytes(project.resolve("code.c")))
    ModuleRevisionGraph.open(project, profile).use { graph ->
        assertEquals(null, graph.snapshot.pendingAttemptId)
        val node = graph.snapshot.nodes.last()
        assertEquals(ModuleRevisionStatus.REJECTED, node.status)
        assertEquals(RepairPublicationMode.TEST_ONLY_NON_RELEASE, node.repairMetadata?.publicationMode)
        assertEquals(RepairRunStatus.REJECTED, graph.snapshot.runs.single().status)
        assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, node.rollbackRecord?.state)
        assertEquals(false, node.rollbackRecord?.candidateSourceInstallStarted)
        assertEquals(node.rollbackRecord?.expectedSourceRevisionSha256, node.rollbackRecord?.observedSourceRevisionSha256)
        assertEquals(caseCount, graph.retainedRegressionCorpus().inputs.size)
    }
    return fixture
}

/** Put the real trace-guided attempt beyond both bounded tails using explicit test-host graph writes. */
internal fun producePagedRecordedTraceHistory(project: Path): RecordedTraceHistoryFixture {
    val fixture = produceRejectedRecordedTraceHistory(project, 25)
    project.resolve("reports/iteration_1.validation.json").writeText("{\"retained\":true}")
    val profile = DeclarativeRepairIndexProfile("PRIVATE-trace-profile", RepairIndexLayout(
        listOf("code.c"), listOf("code.c"),
        modules = listOf(RepairModuleEvidence("PRIVATE-module", listOf("code.c")))))
    ModuleRevisionGraph.open(project, profile).use { graph ->
        for (index in 2..101) {
            val corpus = graph.retainedRegressionCorpus()
            val metadata = RevisionRepairMetadata(index, "behavior", "PRIVATE-padding", "PRIVATE-padding",
                corpus.inputs.map { it.id }, RepairEvidence("behavior", "PRIVATE-before", "reports/PRIVATE-unavailable-$index.json"),
                corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata)
            graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-padding-$index".toByteArray()))
            graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-padding"))
        }
        graph.synchronizeRepairHistory()
    }
    fixture.assertSingleInvocation()
    return fixture
}

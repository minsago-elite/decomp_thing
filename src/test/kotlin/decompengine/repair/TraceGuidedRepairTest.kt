package decompengine.repair

import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.GeneratedCRepairValidationStrategy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpLifecycleTimeouts
import decompengine.acp.AcpAgentHarnessTest
import decompengine.acp.AcpFilesystemLimits
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.SourceTreeGenerator
import decompengine.project.sha256
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.BehaviorExecutionOutcomeException
import decompengine.validation.BehaviorExecutionTimeoutException
import decompengine.validation.BehaviorOutputLimitException
import decompengine.validation.ProcessInput
import decompengine.validation.ProcessOutput
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.net.InetSocketAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TraceGuidedRepairTest {
    private fun createRepairTempDirectory(prefix: String): Path {
        val testRoot = Path.of("build/test-tmp").createDirectories()
        return Files.createTempDirectory(testRoot, prefix)
    }

    @Test
    fun `repair caller never terminalizes an unresolved acceptance decision`() {
        val unexpectedAfterDecision = IllegalStateException("decision write outcome was ambiguous")
        assertFalse(repairFailureCanBeFinalized(unexpectedAfterDecision, "attempt_123"))
        assertFalse(repairFailureCanBeFinalized(RepairAcceptancePendingException("roll-forward required"), null))
        assertTrue(repairFailureCanBeFinalized(unexpectedAfterDecision, null))
    }

    @Test
    fun `repair abort preserves pending state after an immutable assessment is persisted`() {
        val cancellation = IllegalStateException("cancelled after assessment publication")
        assertFalse(repairAttemptCanBeRejected(finalized = false, assessmentPersisted = true, failure = cancellation))
        assertFalse(repairAttemptCanBeRejected(
            finalized = false,
            assessmentPersisted = false,
            RepairAgentEvidencePersistenceException("assessment write failed"),
        ))
        assertFalse(repairAttemptCanBeRejected(
            finalized = false,
            assessmentPersisted = false,
            RepairAcceptancePendingException("decision outcome is ambiguous"),
        ))
        assertFalse(repairAttemptCanBeRejected(finalized = true, assessmentPersisted = false, failure = cancellation))
        assertFalse(repairAttemptCanBeRejected(
            finalized = false,
            assessmentPersisted = false,
            failure = cancellation,
            assessmentPersistenceFailed = true,
        ))
        assertTrue(repairAttemptCanBeRejected(
            finalized = false,
            assessmentPersisted = false,
            cancellation,
        ))
    }

    @Test
    fun `rejection assessment binding failure leaves receipt pending for startup recovery`() {
        val project = createProject(
            createTempDirectory("trace-rejection-assessment-recovery-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val sourcePath = project.resolve("src/modules/reconstructed.c")
        val before = sourcePath.readBytes()
        var harnessReturned = false
        val injector = ModuleRevisionFaultInjector { point ->
            if (harnessReturned && point == ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync(
                    "revision-state",
                    "graph.json",
                ) && Files.newDirectoryStream(
                    project.resolve("reports/repair-revisions"),
                    "*.acp-assessment.json",
                ).use { entries -> entries.iterator().hasNext() }
            ) {
                throw IllegalStateException("injected rejection-assessment graph-binding failure")
            }
        }
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware repair must not discard invocation evidence")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware repair must not discard invocation evidence")

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                harnessReturned = true
                return partialAcpOutcomeHarness(
                    AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.PROTOCOL, "peer failure")),
                ).executeCapturedReceipt(request, initialFiles, output, onEvent)
            }
        }
        val loop = TraceGuidedRepairLoop.forTesting(
            harness,
            RepairHistory(project.resolve("reports/repair_history.json")),
            GeneratedCRepairIndexProfile,
            GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
            CapturedRepairStagingAuthority,
            faultInjector = injector,
        )

        val persistenceFailure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            loop.repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        assertTrue(persistenceFailure.message.orEmpty().contains("assessment"))
        assertTrue(persistenceFailure.suppressed.any { it is AgentExecutionException })
        val assessmentPath = Files.newDirectoryStream(
            project.resolve("reports/repair-revisions"),
            "*.acp-assessment.json",
        ).use { entries -> entries.iterator().asSequence().single() }
        assertTrue(Files.isRegularFile(assessmentPath))
        val pendingGraph = project.resolve("reports/repair-revisions/graph.json").readText()
        val attemptId = assessmentPath.fileName.toString().removeSuffix(".acp-assessment.json")
        val pendingState = Json.parseToJsonElement(pendingGraph).jsonObject
        assertEquals(attemptId, pendingState.getValue("pending").jsonObject.getValue("id").jsonPrimitive.content)
        assertEquals("running", pendingState.getValue("runs").jsonArray.single()
            .jsonObject.getValue("status").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertNull(recovered.snapshot.pendingAttemptId)
            val rejected = recovered.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertTrue(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            val assessment = decompengine.project.AcpChangeAssessment.parse(Files.readAllBytes(assessmentPath))
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(binding.assessmentSha256, assessment.sha256)
            assertContentEquals(before, sourcePath.readBytes())
        }
    }

    @Test
    fun `ordinary ACP terminal outcomes persist immutable receipts before rejected repair history`() {
        val cases = listOf(
            "returned-no-changes" to AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.NO_CHANGES, "peer secret no change"),
            ),
            "returned-refused" to AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.REFUSED, "peer secret refusal"),
            ),
            "returned-cancelled" to AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.CANCELLED, "peer secret cancellation"),
            ),
            "returned-limit-exhausted" to AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.LIMIT_EXHAUSTED, "peer secret limit"),
            ),
            "failed-protocol" to AgentExecutionOutcome.Failed(
                AgentFailure(AgentFailureKind.PROTOCOL, "peer secret protocol failure"),
            ),
            "failed-resource-exhausted" to AgentExecutionOutcome.Failed(
                AgentFailure(
                    AgentFailureKind.RESOURCE_EXHAUSTED,
                    "ACP aggregate stdout and stderr exceeded the configured execution limit",
                    details = mapOf("phase" to "process-output"),
                ),
            ),
        )
        cases.forEach { (expectedTerminal, outcome) ->
            val project = createProject(
                createRepairTempDirectory("trace-acp-${expectedTerminal.replace('-', '_')}-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) {\n",
            )
            val history = RepairHistory(project.resolve("reports/repair_history.json"))

            assertFailsWith<Exception>(expectedTerminal) {
                generatedCRepairLoop(partialAcpOutcomeHarness(outcome), history).repairCompileError(
                    project,
                    collectCompileFailure(project),
                    emptyList(),
                )
            }

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val node = graph.snapshot.nodes.last()
                val binding = requireNotNull(node.repairMetadata?.agentInvocation)
                assertEquals(ModuleRevisionStatus.REJECTED, node.status, expectedTerminal)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus, expectedTerminal)
                assertEquals(expectedTerminal, binding.terminalOutcome, expectedTerminal)
                assertFalse(binding.receiptReleaseComplete, expectedTerminal)
                val raw = project.resolve(binding.receiptPath)
                assertTrue(raw.exists(), expectedTerminal)
                assertEquals(binding.receiptSha256, sha256(raw.readBytes()), expectedTerminal)
                assertFalse(raw.readText().contains("peer secret"), expectedTerminal)
                if (expectedTerminal == "failed-resource-exhausted") {
                    val receipt = Json.parseToJsonElement(raw.readText()).jsonObject
                    val outcome = receipt.getValue("outcome").jsonObject
                    assertEquals("failed", outcome.getValue("type").jsonPrimitive.content)
                    assertEquals(
                        "resource-exhausted",
                        outcome.getValue("failure").jsonObject.getValue("kind").jsonPrimitive.content,
                    )
                }
            }
            assertFalse(
                project.resolve("reports/repair-revisions/graph.json").readText().contains("peer secret"),
                expectedTerminal,
            )
            assertEquals(expectedTerminal, history.all().single().agentInvocation?.terminalOutcome)
            assertEquals(expectedTerminal,
                RepairHistory(project.resolve("reports/repair_history.json")).all().single().agentInvocation?.terminalOutcome)
        }
    }

    @Test
    fun `completed empty repair is distinct from an invalid edit and leaves accepted head unchanged`() {
        val project = createProject(
            createTempDirectory("trace-completed-no-change-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val source = project.resolve("src/modules/reconstructed.c").readBytes()
        val rootHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                error("captured repair execution required")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ) = AgentExecutionResult(AgentStopReason.COMPLETED)
        }

        assertFailsWith<IllegalArgumentException> {
            generatedCRepairLoop(harness, RepairHistory(project.resolve("reports/repair_history.json")))
                .repairCompileError(project, collectCompileFailure(project), emptyList())
        }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(rootHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals("agent-no-change", graph.derivedRepairIterations().single().after?.kind)
        }
        assertContentEquals(source, project.resolve("src/modules/reconstructed.c").readBytes())
    }

    @Test
    fun `legacy repair history is exact non-release compatibility until explicit reconciliation`() {
        val historyPath = createTempDirectory("legacy-repair-history-").resolve("repair_history.json")
        val legacy = """
            {
              "regressionInputs": [

              ],
              "iterations": [

              ]
            }
        """.trimIndent() + "\n"
        historyPath.writeText(legacy)
        val history = RepairHistory(historyPath)

        assertEquals(legacy, history.toJson())
        assertFailsWith<IllegalArgumentException> {
            history.append(
                RepairIteration(1, "compile", "prompt", "summary", emptyList(), emptyList()),
            )
        }

        history.reconcile(emptyList())
        assertTrue(historyPath.readText().startsWith("{\n  \"schemaVersion\": 3,"))
    }

    @Test
    fun `failed validation cases produce structured diffs`() {
        val result = BehaviorCaseResult(
            input = ProcessInput(id = "default"),
            original = ProcessOutput(
                exitCode = 0,
                stdout = "hello\n".toByteArray(),
                stderr = ByteArray(0),
                sandboxCommand = listOf("bwrap"),
            ),
            rebuilt = ProcessOutput(
                exitCode = 1,
                stdout = "hullo\n".toByteArray(),
                stderr = "err\n".toByteArray(),
                sandboxCommand = listOf("bwrap"),
            ),
        )

        val diff = StructuredDiffBuilder.from("hello_world", listOf(result))

        assertEquals(false, diff.matches)
        assertEquals(false, diff.cases.single().exitCodeMatches)
        assertEquals(1, diff.cases.single().stdout.firstDifferenceOffset)
        assertEquals("68656c6c6f0a", diff.cases.single().stdout.expectedHex)
        assertEquals("68756c6c6f0a", diff.cases.single().stdout.actualHex)
    }

    @Test
    fun `repair loop can patch compile errors`() {
        val tempDir = createTempDirectory("repair-compile-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        var captured: AgentExecutionRequest? = null
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured test must not use a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                captured = request
                val path = AgentWorkspacePath("project", "src/modules/reconstructed.c")
                assertTrue(request.accessPolicy.allows(path, AgentOperation.WRITE_FILE))
                assertTrue(!request.workspaceRoots.single().path.exists())
                val before = initialFiles.getValue(path.relativePath)
                val replacement = goodHelloSource()
                output.replace(path.relativePath, replacement.toByteArray())
                return AgentExecutionResult(
                    AgentStopReason.COMPLETED,
                    "close missing brace",
                    listOf(
                        AgentFileChange(
                            path,
                            AgentFileChangeKind.MODIFIED,
                            sha256(before),
                            sha256(replacement.toByteArray()),
                            replacement.toByteArray().size.toLong(),
                        ),
                    ),
                )
            }
        }
        val failure = collectCompileFailure(projectDir)

        val iteration = generatedCRepairLoop(harness, history).repairCompileError(
            projectDir = projectDir,
            failure = failure,
            regressionInputs = listOf(ProcessInput(id = "hello_default")),
        )
        assertEquals("compile", iteration.failureKind)
        assertEquals(listOf("hello_default"), iteration.retainedRegressionIds)
        assertEquals("compile-valid", iteration.after?.kind)
        assertEquals(RepairAttemptDisposition.PROVISIONAL, iteration.disposition)
        assertEquals("int decomp_engine_main(void) {\n", projectDir.resolve("src/modules/reconstructed.c").readText())
        assertEquals(goodHelloSource(), iteration.patches.single().replacementBytes.toString(Charsets.UTF_8))
        assertFalse(history.all().single().summary.contains("close missing brace"))
        assertEquals(RepairPublicationMode.TEST_ONLY_NON_RELEASE, history.all().single().publicationMode)
        assertFalse(history.all().single().releaseComplete)
        assertTrue(projectDir.resolve("reports/repair_history.json").readText().contains("hello_default"))
        val request = assertNotNull(captured)
        assertTrue(request.objective.contains("stderr:"))
        assertTrue(request.workspaceRoots.single().path.isAbsolute)
        assertTrue(request.contextInputs.single { it.id == "retained-regression-inputs" }.content.contains("hello_default"))
    }

    @Test
    fun `captured legacy transport receives the mandatory bounded invocation`() {
        val project = createProject(
            createTempDirectory("repair-client-invocation-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val budget = RepairResourceBudget(maximumResponseBytes = 4_096)
        val limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(7), maxOutputBytes = 2_048)
        val cancellation = AgentCancellationSource()
        var observed: RepairClientInvocation? = null
        val client = object : RepairClient {
            override fun requestRepair(
                request: RepairRequest,
                invocation: RepairClientInvocation,
            ): RepairResponse {
                observed = invocation
                return RepairResponse("bounded repair", listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource())))
            }
        }

        generatedCRepairLoop(
            RepairClientAgentHarness(client),
            RepairHistory(project.resolve("reports/repair_history.json")),
            budget,
            limits,
            cancellation.cancellation,
        ).repairCompileError(project, collectCompileFailure(project), emptyList())

        val invocation = assertNotNull(observed)
        assertEquals(budget, invocation.budget)
        assertTrue(invocation.limits.wallClockTimeout <= limits.wallClockTimeout)
        assertTrue(invocation.limits.wallClockTimeout > Duration.ZERO)
        assertEquals(limits.copy(wallClockTimeout = invocation.limits.wallClockTimeout), invocation.limits)
        assertTrue(invocation.cancellation === cancellation.cancellation)
    }

    @Test
    fun `OpenAI-compatible HTTP client uses configured base URL and parses patch responses`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val requests = mutableListOf<String>()
        server.createContext("/api/v1/chat/completions") { exchange ->
            requests += exchange.requestBody.bufferedReader().readText()
            assertEquals("Bearer test-key", exchange.requestHeaders.getFirst("Authorization"))
            val response = """
                {
                  "choices": [
                    {
                      "message": {
                        "content": "{\"summary\":\"fix \\\"quoted\\\" compile error\",\"patches\":[{\"relativePath\":\"src/modules/reconstructed.c\",\"replacement\":\"int decomp_engine_main(void) {\\n    return 0;\\n}\\n\"}]}"
                      }
                    }
                  ]
                }
            """.trimIndent()
            exchange.sendResponseHeaders(200, response.toByteArray().size.toLong())
            exchange.responseBody.use { it.write(response.toByteArray()) }
        }
        server.start()
        try {
            val client = HttpOpenAiCompatibleRepairClient.fromEnvironment(
                mapOf(
                    "API_KEY" to "test-key",
                    "MODEL" to "compatible/test",
                    "BASE_URL" to "http://127.0.0.1:${server.address.port}/api/v1",
                    "REASONING_EFFORT" to "high",
                ),
            )

            val response = client.requestRepair(
                RepairRequest(
                    failureKind = "compile",
                    prompt = "compiler stderr",
                    projectFiles = mapOf("src/modules/reconstructed.c" to "broken"),
                    regressionInputs = listOf(ProcessInput(id = "default")),
                ),
            )

            assertEquals("fix \"quoted\" compile error", response.summary)
            assertEquals("src/modules/reconstructed.c", response.patches.single().relativePath)
            assertTrue(response.patches.single().replacement.contains("return 0;"))
            val requestJson = Json.parseToJsonElement(requests.single()).jsonObject
            assertEquals("compatible/test", requestJson.getValue("model").jsonPrimitive.content)
            assertEquals("high", requestJson.getValue("reasoning_effort").jsonPrimitive.content)
            val userContent = requestJson.getValue("messages").jsonArray[1].jsonObject
                .getValue("content").jsonPrimitive.content
            assertTrue("compiler stderr" in userContent)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `OpenAI-compatible client rejects unsupported reasoning effort`() {
        val error = assertFailsWith<IllegalArgumentException> {
            HttpOpenAiCompatibleRepairClient.fromEnvironment(
                mapOf(
                    "API_KEY" to "test-key",
                    "MODEL" to "compatible/test",
                    "BASE_URL" to "https://api.example.com/v1",
                    "REASONING_EFFORT" to "maximum",
                ),
            )
        }

        assertTrue(error.message.orEmpty().contains("REASONING_EFFORT"))
    }

    @Test
    fun `OpenAI-compatible client bounds chunked output and releases a pending graph attempt`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/v1/chat/completions") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            exchange.sendResponseHeaders(200, 0)
            runCatching {
                exchange.responseBody.use { output ->
                    repeat(16) {
                        output.write(ByteArray(128) { 'x'.code.toByte() })
                        output.flush()
                    }
                }
            }
        }
        server.start()
        val project = createProject(
            createTempDirectory("repair-http-overflow-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(3), maxOutputBytes = 256)
        try {
            val client = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
            )
            val failure = assertFailsWith<AgentExecutionException> {
                generatedCRepairLoop(
                    RepairClientAgentHarness(client),
                    RepairHistory(project.resolve("reports/repair_history.json")),
                    limits = limits,
                ).repairCompileError(project, collectCompileFailure(project), emptyList())
            }

            assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertEquals(null, graph.snapshot.pendingAttemptId)
                assertTrue(graph.snapshot.nodes.last().status == ModuleRevisionStatus.REJECTED)
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `OpenAI-compatible client aborts stalled bodies at the wall deadline`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val bodyStarted = CountDownLatch(1)
        server.createContext("/v1/chat/completions") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            exchange.sendResponseHeaders(200, 0)
            runCatching {
                exchange.responseBody.use { output ->
                    output.write('{'.code)
                    output.flush()
                    bodyStarted.countDown()
                    Thread.sleep(3_000)
                }
            }
        }
        server.start()
        try {
            val client = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
                defaultLimits = AgentExecutionLimits(
                    wallClockTimeout = Duration.ofMillis(150),
                    maxOutputBytes = 1024,
                ),
            )
            val failure = assertFailsWith<AgentExecutionException> {
                client.requestRepair(RepairRequest("compile", "failure", mapOf("source" to "broken"), emptyList()))
            }

            assertTrue(bodyStarted.await(1, TimeUnit.SECONDS))
            assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `OpenAI-compatible client cancellation aborts an in-flight body`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val bodyStarted = CountDownLatch(1)
        val cancellation = AgentCancellationSource()
        server.createContext("/v1/chat/completions") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            exchange.sendResponseHeaders(200, 0)
            runCatching {
                exchange.responseBody.use { output ->
                    output.write('{'.code)
                    output.flush()
                    bodyStarted.countDown()
                    Thread.sleep(3_000)
                }
            }
        }
        server.start()
        val cancelling = thread(start = true, name = "repair-http-canceller") {
            bodyStarted.await(1, TimeUnit.SECONDS)
            cancellation.cancel()
        }
        try {
            val client = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
                defaultLimits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(5), maxOutputBytes = 1024),
                defaultCancellation = cancellation.cancellation,
            )
            val staged = CapturedRepairStagingAuthority.execute(
                harness = RepairClientAgentHarness(client),
                initialFiles = mapOf("source" to "broken".toByteArray()),
                writablePaths = setOf("source"),
                budget = RepairResourceBudget(),
                requestFactory = { root ->
                    val path = AgentWorkspacePath(root.id, "source")
                    AgentExecutionRequest(
                        objective = "repair the captured source",
                        workspaceRoots = listOf(root),
                        accessPolicy = decompengine.agent.AgentAccessPolicy(
                            listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
                        ),
                        limits = AgentExecutionLimits(
                            wallClockTimeout = Duration.ofSeconds(5),
                            maxOutputBytes = 1024,
                        ),
                        cancellation = cancellation.cancellation,
                    )
                },
                onEvent = {},
            )

            assertEquals(AgentStopReason.CANCELLED, staged.result.stopReason)
            assertTrue(staged.result.summary.orEmpty().contains("cancelled"))
        } finally {
            cancelling.join(1_000)
            server.stop(0)
        }
    }

    @Test
    fun `HTTP body readers recover capacity after more stalled requests than worker threads`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val serverExecutor = Executors.newCachedThreadPool()
        val bodyExecutor = Executors.newFixedThreadPool(4)
        val releaseStalls = CountDownLatch(1)
        val requestNumber = AtomicInteger()
        server.executor = serverExecutor
        server.createContext("/v1/chat/completions") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            if (requestNumber.incrementAndGet() <= 5) {
                exchange.sendResponseHeaders(200, 0)
                runCatching {
                    exchange.responseBody.use { output ->
                        output.write('{'.code)
                        output.flush()
                        releaseStalls.await(5, TimeUnit.SECONDS)
                    }
                }
            } else {
                val content = "{\"summary\":\"recovered\",\"patches\":[{\"relativePath\":\"source\",\"replacement\":\"fixed\"}]}"
                val response = "{\"choices\":[{\"message\":{\"content\":${JsonPrimitive(content)}}}]}"
                exchange.sendResponseHeaders(200, response.toByteArray().size.toLong())
                exchange.responseBody.use { it.write(response.toByteArray()) }
            }
        }
        server.start()
        try {
            val client = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
                defaultLimits = AgentExecutionLimits(
                    wallClockTimeout = Duration.ofMillis(200),
                    maxOutputBytes = 4_096,
                ),
                bodyExecutor = bodyExecutor,
            )
            repeat(5) {
                val failure = assertFailsWith<AgentExecutionException> {
                    client.requestRepair(RepairRequest("compile", "stalled-$it", mapOf("source" to "broken"), emptyList()))
                }
                assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
            }

            val started = System.nanoTime()
            val response = client.requestRepair(
                RepairRequest("compile", "normal", mapOf("source" to "broken"), emptyList()),
                RepairClientInvocation(
                    RepairResourceBudget(),
                    AgentExecutionLimits(Duration.ofSeconds(2), maxOutputBytes = 4_096),
                    AgentCancellation.NONE,
                ),
            )
            val elapsedMillis = Duration.ofNanos(System.nanoTime() - started).toMillis()
            assertEquals("recovered", response.summary)
            assertTrue(elapsedMillis < 2_000, "normal response took $elapsedMillis ms after stalled requests")
        } finally {
            releaseStalls.countDown()
            server.stop(0)
            bodyExecutor.shutdownNow()
            serverExecutor.shutdownNow()
        }
    }

    @Test
    fun `OpenAI-compatible client caps the actual escaped request body and decoded patches`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var requests = 0
        var lastRequestBody: String? = null
        server.createContext("/v1/chat/completions") { exchange ->
            requests++
            lastRequestBody = exchange.requestBody.use { it.readBytes().toString(Charsets.UTF_8) }
            val content = "{\"summary\":\"large\",\"patches\":[{\"relativePath\":\"source\",\"replacement\":\"${"x".repeat(65)}\"}]}"
            val response = "{\"choices\":[{\"message\":{\"content\":${JsonPrimitive(content)}}}]}"
            exchange.sendResponseHeaders(200, response.toByteArray().size.toLong())
            exchange.responseBody.use { it.write(response.toByteArray()) }
        }
        server.start()
        try {
            val requestBudget = RepairResourceBudget(
                maximumRegressionInputBytes = 64,
                maximumRequestBytes = 1024,
            )
            val requestClient = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
                defaultBudget = requestBudget,
            )
            assertFailsWith<RepairBudgetExceededException> {
                requestClient.requestRepair(
                    RepairRequest("compile", "\u0001".repeat(200), mapOf("source" to "x"), emptyList()),
                )
            }
            assertEquals(0, requests)

            val patchClient = HttpOpenAiCompatibleRepairClient(
                "test-key",
                "test-model",
                URI.create("http://127.0.0.1:${server.address.port}/v1"),
                defaultBudget = RepairResourceBudget(maximumPatchBytes = 64),
            )
            assertFailsWith<RepairBudgetExceededException> {
                patchClient.requestRepair(
                    RepairRequest("compile", "failure \u2603 \u0001", mapOf("source" to "x"), emptyList()),
                )
            }
            assertEquals(1, requests)
            val requestJson = Json.parseToJsonElement(assertNotNull(lastRequestBody)).jsonObject
            val userContent = requestJson.getValue("messages").jsonArray[1].jsonObject
                .getValue("content").jsonPrimitive.content
            assertTrue("failure \u2603 \u0001" in userContent)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `repair loop can patch behavior mismatches`() {
        val tempDir = createTempDirectory("repair-behavior-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        val initialBuild = MakeProjectBuilder.build(projectDir)
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val client = FakeRepairClient(
            RepairResponse(
                summary = "match observed stdout",
                patches = listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource())),
            ),
        )
        val inputs = listOf(ProcessInput(id = "hello_default"))

        val iteration = generatedCRepairLoop(RepairClientAgentHarness(client), history).repairBehaviorMismatch(
            projectDir = projectDir,
            originalBinary = original,
            rebuiltBinary = initialBuild.projectDir.resolve("build/reconstructed"),
            inputs = inputs,
            reportsDir = projectDir.resolve("reports"),
        )
        val repairedBuild = MakeProjectBuilder.build(projectDir)
        val repairedReport = BehaviorComparator().compare(
            id = "hello_world_after_repair",
            originalBinary = original,
            rebuiltBinary = repairedBuild.projectDir.resolve("build/reconstructed"),
            cases = inputs,
            reportsDir = projectDir.resolve("reports"),
        )

        assertEquals("behavior", iteration.failureKind)
        assertTrue(client.lastRequest!!.prompt.contains("Structured behavior diff"))
        assertTrue(repairedReport.matches)
        assertEquals(listOf("hello_default"), history.all().single().retainedRegressionIds)
    }

    @Test
    fun `candidate output flooding is bounded and leaves the graph reopenable`() {
        val tempDir = createTempDirectory("repair-behavior-flood-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val project = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        val initial = MakeProjectBuilder.build(project).projectDir.resolve("build/reconstructed")
        val parent = project.resolve("src/modules/reconstructed.c").readBytes()
        val flooding = """
            #include <stdio.h>
            int decomp_engine_main(void) {
                for (;;) puts("unbounded candidate output");
            }
        """.trimIndent() + "\n"
        val budget = RepairResourceBudget(
            maximumBehaviorStdoutBytes = 1_024,
            maximumBehaviorStderrBytes = 1_024,
            maximumBehaviorOutputBytes = 2_048,
            maximumBehaviorExecutionMillis = 2_000,
        )

        assertFailsWith<BehaviorOutputLimitException> {
            generatedCRepairLoop(
                RepairClientAgentHarness(
                    FakeRepairClient(
                        RepairResponse(
                            "flood candidate",
                            listOf(SourcePatch("src/modules/reconstructed.c", flooding)),
                        ),
                    ),
                ),
                RepairHistory(project.resolve("reports/repair_history.json")),
                budget,
            ).repairBehaviorMismatch(
                project,
                original,
                initial,
                listOf(ProcessInput("default")),
                project.resolve("reports"),
            )
        }

        assertContentEquals(parent, project.resolve("src/modules/reconstructed.c").readBytes())
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertEquals(null, graph.snapshot.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `candidate exceeding selected behavior deadline is rejected and leaves graph reopenable`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val tempDir = Files.createTempDirectory(scratch, "repair-behavior-deadline-")
        try {
            val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
            val project = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
            val initial = MakeProjectBuilder.build(project).projectDir.resolve("build/reconstructed")
            val parent = project.resolve("src/modules/reconstructed.c").readBytes()
            val slowCandidate = """
                #define _POSIX_C_SOURCE 200809L
                #include <stdio.h>
                #include <time.h>
                int decomp_engine_main(void) {
                    struct timespec delay = { .tv_sec = 3, .tv_nsec = 0 };
                    nanosleep(&delay, 0);
                    puts("hello, world");
                    return 0;
                }
            """.trimIndent() + "\n"
            val budget = RepairResourceBudget(
                maximumBehaviorStdoutBytes = 1_024,
                maximumBehaviorStderrBytes = 1_024,
                maximumBehaviorOutputBytes = 2_048,
                maximumBehaviorExecutionMillis = 2_000,
            )

            val failure = assertFails {
                generatedCRepairLoop(
                    RepairClientAgentHarness(
                        FakeRepairClient(
                            RepairResponse(
                                "slow candidate",
                                listOf(SourcePatch("src/modules/reconstructed.c", slowCandidate)),
                            ),
                        ),
                    ),
                    RepairHistory(project.resolve("reports/repair_history.json")),
                    budget,
                ).repairBehaviorMismatch(
                    project,
                    original,
                    initial,
                    listOf(ProcessInput("default")),
                    project.resolve("reports"),
                )
            }
            assertTrue(
                failure is BehaviorExecutionTimeoutException || failure is BehaviorExecutionOutcomeException,
                "selected behavior deadline should terminate the candidate, got ${failure::class.simpleName}",
            )
            assertContentEquals(parent, project.resolve("src/modules/reconstructed.c").readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertEquals(null, graph.snapshot.pendingAttemptId)
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            }
        } finally {
            Files.walk(tempDir).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 240, unit = TimeUnit.SECONDS)
    fun `active behavior repair enforces exact stdout stderr and aggregate output byte boundaries`() {
        data class OutputBoundaryCase(
            val id: String,
            val referenceStdout: String,
            val referenceStderr: String,
            val exactStdout: String,
            val exactStderr: String,
            val overStdout: String,
            val overStderr: String,
            val maximumStdoutBytes: Long,
            val maximumStderrBytes: Long,
            val maximumOutputBytes: Long,
            val overDiagnostic: String,
            val exactCandidateMatchesReference: Boolean,
        )

        val cases = listOf(
            OutputBoundaryCase(
                id = "stdout",
                referenceStdout = "s".repeat(64),
                referenceStderr = "",
                exactStdout = "s".repeat(64),
                exactStderr = "",
                overStdout = "s".repeat(65),
                overStderr = "",
                maximumStdoutBytes = 64,
                maximumStderrBytes = 64,
                maximumOutputBytes = 128,
                overDiagnostic = "sandboxed behavior stdout exceeds 64 bytes",
                exactCandidateMatchesReference = true,
            ),
            OutputBoundaryCase(
                id = "stderr",
                referenceStdout = "",
                referenceStderr = "e".repeat(64),
                exactStdout = "",
                exactStderr = "e".repeat(64),
                overStdout = "",
                overStderr = "e".repeat(65),
                maximumStdoutBytes = 64,
                maximumStderrBytes = 64,
                maximumOutputBytes = 128,
                overDiagnostic = "sandboxed behavior stderr exceeds 64 bytes",
                exactCandidateMatchesReference = true,
            ),
            OutputBoundaryCase(
                id = "process-aggregate",
                referenceStdout = "",
                referenceStderr = "",
                exactStdout = "o".repeat(50),
                exactStderr = "p".repeat(50),
                overStdout = "o".repeat(50),
                overStderr = "p".repeat(51),
                maximumStdoutBytes = 64,
                maximumStderrBytes = 64,
                maximumOutputBytes = 100,
                overDiagnostic = "sandboxed behavior output exceeds 100 aggregate bytes",
                exactCandidateMatchesReference = false,
            ),
            OutputBoundaryCase(
                id = "comparison-aggregate",
                referenceStdout = "r".repeat(64),
                referenceStderr = "",
                exactStdout = "r".repeat(64),
                exactStderr = "",
                overStdout = "r".repeat(64),
                overStderr = "x",
                maximumStdoutBytes = 64,
                maximumStderrBytes = 64,
                maximumOutputBytes = 128,
                overDiagnostic = "behavior comparison output exceeds 128 aggregate bytes",
                exactCandidateMatchesReference = true,
            ),
        )

        fun cFunction(symbol: String, stdout: String, stderr: String): String = buildString {
            append("#include <stdio.h>\nint ").append(symbol).append("(void) {\n")
            if (stdout.isNotEmpty()) {
                append("    if (fwrite(\"").append(stdout).append("\", 1, ").append(stdout.length)
                    .append(", stdout) != ").append(stdout.length).append(") return 91;\n")
            }
            if (stderr.isNotEmpty()) {
                append("    if (fwrite(\"").append(stderr).append("\", 1, ").append(stderr.length)
                    .append(", stderr) != ").append(stderr.length).append(") return 92;\n")
            }
            append("    return 0;\n}\n")
        }

        for (case in cases) {
            val tempDir = createRepairTempDirectory("repair-behavior-output-${case.id}-")
            val original = compileC(
                tempDir,
                "reference",
                cFunction("main", case.referenceStdout, case.referenceStderr),
            )
            val budget = RepairResourceBudget(
                maximumBehaviorStdoutBytes = case.maximumStdoutBytes,
                maximumBehaviorStderrBytes = case.maximumStderrBytes,
                maximumBehaviorOutputBytes = case.maximumOutputBytes,
                maximumBehaviorExecutionMillis = 10_000,
            )

            fun runCandidate(
                attemptId: String,
                stdout: String,
                stderr: String,
            ): Triple<Path, String, RepairIteration?> {
                val project = createProject(
                    tempDir.resolve(attemptId).resolve("project"),
                    reconstructedSource = cFunction("decomp_engine_main", "wrong", ""),
                )
                val target = project.resolve("src/modules/reconstructed.c")
                val acceptedSource = target.readBytes()
                val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use {
                    it.snapshot.headId
                }
                val initialBuild = MakeProjectBuilder.build(project)
                val candidate = cFunction("decomp_engine_main", stdout, stderr)
                val loop = generatedCRepairLoop(
                    RepairClientAgentHarness(
                        FakeRepairClient(
                            RepairResponse(
                                "exercise ${case.id} output boundary",
                                listOf(SourcePatch("src/modules/reconstructed.c", candidate)),
                            ),
                        ),
                    ),
                    RepairHistory(project.resolve("reports/repair_history.json")),
                    budget,
                )
                return try {
                    val iteration = loop.repairBehaviorMismatch(
                        project,
                        original,
                        initialBuild.projectDir.resolve("build/reconstructed"),
                        listOf(ProcessInput("boundary")),
                        project.resolve("reports"),
                    )
                    Triple(project, baselineHead, iteration)
                } catch (failure: Exception) {
                    assertTrue(
                        failure is BehaviorOutputLimitException,
                        "${case.id}/$attemptId should fail only through the selected output boundary: $failure",
                    )
                    assertTrue(failure.message.orEmpty().contains(case.overDiagnostic), failure.message.orEmpty())
                    assertContentEquals(acceptedSource, target.readBytes(), "${case.id}/$attemptId rollback")
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId, "${case.id}/$attemptId")
                        assertEquals(baselineHead, graph.snapshot.headId, "${case.id}/$attemptId")
                        assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    }
                    Triple(project, baselineHead, null)
                } finally {
                    loop.close()
                }
            }

            val exact = runCandidate("exact", case.exactStdout, case.exactStderr)
            if (case.exactCandidateMatchesReference) {
                val iteration = assertNotNull(exact.third, "${case.id} equality must complete validation")
                assertTrue(iteration.succeeded, "${case.id} equality candidate must match the reference")
                assertContentEquals(
                    cFunction("decomp_engine_main", case.exactStdout, case.exactStderr).toByteArray(Charsets.UTF_8),
                    exact.first.resolve("src/modules/reconstructed.c").readBytes(),
                )
                ModuleRevisionGraph.open(exact.first, GeneratedCRepairIndexProfile, budget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId, case.id)
                    assertEquals(ModuleRevisionStatus.ACCEPTED, graph.snapshot.nodes.last().status, case.id)
                }
            } else {
                val iteration = assertNotNull(exact.third, "exact aggregate equality must reach comparison")
                assertFalse(iteration.succeeded, "the fixture intentionally differs from the empty reference")
                assertEquals("no-validated-improvement", assertNotNull(iteration.after).kind)
                assertContentEquals(
                    cFunction("decomp_engine_main", "wrong", "").toByteArray(Charsets.UTF_8),
                    exact.first.resolve("src/modules/reconstructed.c").readBytes(),
                    "mismatching but exact-limit candidate must be rejected",
                )
                ModuleRevisionGraph.open(exact.first, GeneratedCRepairIndexProfile, budget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId, case.id)
                    assertEquals(exact.second, graph.snapshot.headId, case.id)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status, case.id)
                }
            }

            val over = runCandidate("one-over", case.overStdout, case.overStderr)
            assertNull(over.third, "${case.id} one-over output must be refused")
        }
    }

    @Test
    fun `ordinary callers cannot forge the repair loop construction authority`() {
        val project = createProject(
            createTempDirectory("repair-validation-assurance-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val failure = assertFailsWith<SecurityException> {
            TraceGuidedRepairLoop.openAuthorized(
                Any(),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                false,
                null,
            )
        }

        assertTrue(failure.message.orEmpty().contains("authority"))
        assertTrue(!project.resolve("reports/repair-revisions/graph.json").exists())
    }

    @Test
    fun `regression tests are retained across repair attempts`() {
        val tempDir = createTempDirectory("repair-regression-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val inputs = listOf(
            ProcessInput(id = "no_args"),
            ProcessInput(id = "two_args", args = listOf("alpha", "beta")),
        )

        generatedCRepairLoop(
            RepairClientAgentHarness(FakeRepairClient(RepairResponse("fix", listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource()))))),
            history,
        )
            .repairCompileError(projectDir, collectCompileFailure(projectDir), inputs)

        assertEquals(listOf("no_args", "two_args"), history.all().single().retainedRegressionIds)
        val historyJson = projectDir.resolve("reports/repair_history.json").readText()
        assertTrue(historyJson.contains("no_args"))
        assertTrue(historyJson.contains("two_args"))
    }

    @Test
    fun `repair loop iterates from compile failure through behavior mismatch and persists regressions`() {
        val tempDir = createTempDirectory("repair-converge-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val historyPath = projectDir.resolve("reports/repair_history.json")
        val inputs = listOf(
            ProcessInput(id = "default"),
            ProcessInput(id = "argument", args = listOf("kept")),
        )
        val client = QueueRepairClient(
            RepairResponse("make it compile", listOf(SourcePatch("src/modules/reconstructed.c", helloMainSource("wrong")))),
            RepairResponse("match observed output", listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource()))),
        )

        val result = generatedCRepairLoop(RepairClientAgentHarness(client), RepairHistory(historyPath)).repairUntilValid(
            projectDir = projectDir,
            originalBinary = original,
            inputs = inputs,
            maxIterations = 3,
        )

        assertTrue(result.validation.matches)
        assertEquals(listOf("compile", "behavior"), result.iterations.map { it.failureKind })
        assertEquals(false, result.iterations.first().succeeded)
        assertEquals(true, result.iterations.last().succeeded)
        assertEquals("compile", result.iterations.first().before?.kind)
        assertEquals("behavior", result.iterations.first().after?.kind)
        assertEquals("valid", result.iterations.last().after?.kind)
        assertTrue(inputs.all { client.requests.last().prompt.contains(it.id) })
        assertTrue(projectDir.resolve("reports/iteration_1_behavior.diff.json").exists())
        ModuleRevisionGraph.open(projectDir, GeneratedCRepairIndexProfile).use { graph ->
            val accepted = graph.snapshot.nodes.single { it.id == graph.snapshot.fullyAcceptedHeadId }
            assertEquals(accepted.sourceRevisionSha256, accepted.validationProof?.sourceRevisionSha256)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, graph.snapshot.runs.last().status)
            assertTrue(accepted.validationProof?.cleanupVerified == true)
        }

        val reloaded = RepairHistory(historyPath)
        assertEquals(inputs.sortedBy { it.id }, reloaded.retainedInputs())
        assertEquals(2, reloaded.all().size)
        assertTrue(historyPath.readText().contains("\"before\""))
        assertTrue(historyPath.readText().contains("\"after\""))
    }

    @Test
    fun `reloaded repair history retains earlier regressions in later requests`() {
        val tempDir = createTempDirectory("repair-reload-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val historyPath = projectDir.resolve("reports/repair_history.json")
        RepairHistory(historyPath).retain(listOf(ProcessInput("earlier", stdin = "old\n".toByteArray())))
        val client = QueueRepairClient(RepairResponse("fix", listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource()))))

        generatedCRepairLoop(RepairClientAgentHarness(client), RepairHistory(historyPath)).repairCompileError(
            projectDir,
            collectCompileFailure(projectDir),
            listOf(ProcessInput("new", args = listOf("value"))),
        )

        assertTrue(listOf("earlier", "new").all { client.requests.single().prompt.contains(it) })
    }

    @Test
    fun `repair discovers manifest-owned modules and sends compile-relevant context`() {
        val tempDir = createTempDirectory("repair-tree-")
        val projectDir = tempDir.resolve("project")
        SourceTreeGenerator.generate(multiModuleModel(), projectDir)
        val parsePath = projectDir.resolve("src/modules/parse.c")
        val validParse = parsePath.readText()
        parsePath.writeText(validParse + "\nint unfinished_repair(\n")
        val client = FakeRepairClient(RepairResponse("repair parse module", listOf(SourcePatch("src/modules/parse.c", validParse))))

        generatedCRepairLoop(
            RepairClientAgentHarness(client),
            RepairHistory(projectDir.resolve("reports/repair_history.json")),
        ).repairCompileError(
            projectDir,
            collectCompileFailure(projectDir),
            listOf(ProcessInput("default")),
        )

        assertTrue(parsePath.readText().contains("unfinished_repair"))
        val repaired = RepairHistory(projectDir.resolve("reports/repair_history.json")).all().single()
        assertEquals(RepairAttemptDisposition.PROVISIONAL, repaired.disposition)
        assertEquals(validParse, repaired.patches.single().replacementBytes.toString(Charsets.UTF_8))
        assertTrue("src/modules/parse.c" in client.lastRequest!!.projectFiles)
        assertTrue("include/modules/parse.h" in client.lastRequest!!.projectFiles)
        assertTrue("src/modules/render.c" !in client.lastRequest!!.projectFiles)
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("src/modules/parse.c"))
    }

    @Test
    fun `manifest restriction rejects an invalid multi-file response before any write`() {
        val tempDir = createTempDirectory("repair-tree-atomic-")
        val projectDir = tempDir.resolve("project")
        SourceTreeGenerator.generate(multiModuleModel(), projectDir)
        val parsePath = projectDir.resolve("src/modules/parse.c")
        parsePath.writeText("broken\n")
        val before = parsePath.readText()
        val client = FakeRepairClient(
            RepairResponse(
                "unsafe response",
                listOf(SourcePatch("src/modules/parse.c", "replacement\n"), SourcePatch("src/rogue.c", "rogue\n")),
            ),
        )

        val failure = assertFailsWith<AgentExecutionException> {
            generatedCRepairLoop(
                RepairClientAgentHarness(client),
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
            ).repairCompileError(
                projectDir,
                CompileFailure(listOf("make"), 2, "", "src/modules/parse.c: error"),
                emptyList(),
            )
        }

        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, failure.failure.kind)
        assertEquals(before, parsePath.readText())
        assertTrue(!projectDir.resolve("src/rogue.c").exists())
    }

    @Test
    fun `compile-breaking behavior repair rolls back to the last buildable tree`() {
        val tempDir = createTempDirectory("repair-rollback-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        MakeProjectBuilder.build(projectDir)
        val before = projectDir.resolve("src/modules/reconstructed.c").readText()
        val client = QueueRepairClient(RepairResponse("bad repair", listOf(SourcePatch("src/modules/reconstructed.c", "int broken(\n"))))

        assertFailsWith<RepairExhaustedException> {
            generatedCRepairLoop(
                RepairClientAgentHarness(client),
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
            ).repairUntilValid(
                projectDir,
                original,
                listOf(ProcessInput("default")),
                maxIterations = 1,
            )
        }

        assertEquals(before, projectDir.resolve("src/modules/reconstructed.c").readText())
        assertEquals(0, MakeProjectBuilder.build(projectDir).returnCode)
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("\"accepted\":false"))
    }

    @Test
    fun `public repair loop recovers a pending valid candidate before its initial assessment`() {
        val tempDir = createTempDirectory("repair-pending-public-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val parentBytes = readStableRepairFile(projectDir, "src/modules/reconstructed.c", 1_048_576)
        val interrupted = ModuleRevisionGraph.open(projectDir, GeneratedCRepairIndexProfile)
        val pending = interrupted.beginAttempt(listOf("src/modules/reconstructed.c"))
        interrupted.installCandidate(pending, mapOf("src/modules/reconstructed.c" to goodHelloSource().toByteArray()))
        interrupted.close()
        assertContentEquals(parentBytes, readStableRepairFile(projectDir, "src/modules/reconstructed.c", 1_048_576),
            "schema-6 candidate installation must remain detached before acceptance")
        val client = QueueRepairClient(
            RepairResponse("repair recovered parent", listOf(SourcePatch("src/modules/reconstructed.c", goodHelloSource()))),
        )

        val result = generatedCRepairLoop(
            RepairClientAgentHarness(client),
            RepairHistory(projectDir.resolve("reports/repair_history.json")),
        ).repairUntilValid(projectDir, original, listOf(ProcessInput("default")), maxIterations = 1)

        assertTrue(result.validation.matches)
        assertEquals(1, client.requests.size)
        ModuleRevisionGraph.open(projectDir, GeneratedCRepairIndexProfile).use { graph ->
            assertTrue(graph.snapshot.nodes.any { it.recoveredAfterCrash })
        }
    }

    @Test
    fun `one-shot behavior repair rejects a candidate that remains invalid`() {
        val tempDir = createTempDirectory("repair-behavior-reject-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        val initialBuild = MakeProjectBuilder.build(projectDir)
        val before = readStableRepairFile(projectDir, "src/modules/reconstructed.c", 1_048_576)
        val client = FakeRepairClient(
            RepairResponse("still wrong", listOf(SourcePatch("src/modules/reconstructed.c", helloMainSource("also wrong")))),
        )

        val iteration = generatedCRepairLoop(
            RepairClientAgentHarness(client),
            RepairHistory(projectDir.resolve("reports/repair_history.json")),
        ).repairBehaviorMismatch(
            projectDir,
            original,
            initialBuild.projectDir.resolve("build/reconstructed"),
            listOf(ProcessInput("default")),
            projectDir.resolve("reports"),
        )

        assertEquals(false, iteration.succeeded)
        assertEquals("no-validated-improvement", iteration.after?.kind)
        assertContentEquals(before, readStableRepairFile(projectDir, "src/modules/reconstructed.c", 1_048_576))
    }

    @Test
    fun `integrated loop rejects a buildable candidate that regresses a retained matching case`() {
        val tempDir = createTempDirectory("repair-retained-regression-")
        val original = compileC(
            tempDir,
            "original",
            "#include <stdio.h>\nint main(int argc, char **argv) { (void)argv; puts(argc > 1 ? \"arg\" : \"zero\"); return 0; }\n",
        )
        val beforeSource = "#include <stdio.h>\nint decomp_engine_main(int argc) { (void)argc; puts(\"zero\"); return 0; }\n"
        val projectDir = createSingleSourceProject(tempDir.resolve("project"), beforeSource)
        val candidate = "#include <stdio.h>\nint decomp_engine_main(int argc) { (void)argc; puts(\"arg\"); return 0; }\n"
        val target = projectDir.resolve("src/modules/reconstructed.c")

        assertFailsWith<RepairExhaustedException> {
            generatedCRepairLoop(
                RepairClientAgentHarness(
                    FakeRepairClient(RepairResponse("swap the mismatch", listOf(SourcePatch("src/modules/reconstructed.c", candidate)))),
                ),
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
            ).repairUntilValid(
                projectDir,
                original,
                listOf(ProcessInput("default"), ProcessInput("argument", args = listOf("x"))),
                maxIterations = 1,
            )
        }

        assertEquals(beforeSource, target.readText())
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("\"accepted\":false"))
        assertTrue(projectDir.resolve("reports/repair_history.json").readText().contains("retained-regression"))
    }

    @Test
    fun `strict staging refuses an ordinary writable-directory harness before execution`() {
        val tempDir = createTempDirectory("repair-staging-host-refused-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val target = projectDir.resolve("src/modules/reconstructed.c")
        val before = target.readBytes()
        var executed = false
        val hostHarness = AgentHarness { _, _ ->
            executed = true
            error("ordinary host staging must not execute")
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            generatedCRepairLoop(
                hostHarness,
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
            ).repairCompileError(projectDir, collectCompileFailure(projectDir), emptyList())
        }

        assertTrue(failure.message.orEmpty().contains("CapturedRepairAgentHarness"))
        assertTrue(!executed)
        assertContentEquals(before, target.readBytes())
    }

    @Test
    fun `active repair path rejects create and delete mutations outside its replacement contract`() {
        val cases = listOf(
            "create-outside" to "captured repair output is unauthorized",
            "delete-target" to "violates declared mutation authority",
            "claim-created" to "repair may only modify existing project files",
            "claim-deleted" to "repair may only modify existing project files",
        )
        for ((mutation, expectedReason) in cases) {
            val project = createProject(
                createRepairTempDirectory("repair-mutation-contract-${mutation}-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) {\n",
            )
            val target = project.resolve("src/modules/reconstructed.c")
            val before = target.readBytes()
            val targetPath = AgentWorkspacePath("project", "src/modules/reconstructed.c")
            val candidate = goodHelloSource().toByteArray()
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    when (mutation) {
                        "create-outside" -> output.replace("src/modules/created.c", candidate)
                        "delete-target" -> output.delete(targetPath.relativePath)
                        else -> {
                            output.replace(targetPath.relativePath, candidate)
                            val kind = when (mutation) {
                                "claim-created" -> AgentFileChangeKind.CREATED
                                "claim-deleted" -> AgentFileChangeKind.DELETED
                                else -> error("unknown mutation fixture")
                            }
                            return AgentExecutionResult(
                                AgentStopReason.COMPLETED,
                                "fixture mutation claim",
                                listOf(AgentFileChange(
                                    targetPath,
                                    kind,
                                    if (kind == AgentFileChangeKind.CREATED) null
                                        else sha256(initialFiles.getValue(targetPath.relativePath)),
                                    if (kind == AgentFileChangeKind.DELETED) null else sha256(candidate),
                                    if (kind == AgentFileChangeKind.DELETED) null else candidate.size.toLong(),
                                )),
                            )
                        }
                    }
                    error("unauthorized mutation unexpectedly returned")
                }
            }

            val refusal = assertFailsWith<Exception>(mutation) {
                generatedCRepairLoop(
                    harness,
                    RepairHistory(project.resolve("reports/repair_history.json")),
                ).repairCompileError(project, collectCompileFailure(project), emptyList())
            }
            val failureReasons = mutableListOf<String>()
            var currentFailure: Throwable? = refusal
            while (currentFailure != null) {
                currentFailure.message?.let(failureReasons::add)
                currentFailure = currentFailure.cause
            }
            assertTrue(failureReasons.any { it.contains(expectedReason) },
                "$mutation refusal must retain its validator reason: $failureReasons")

            assertContentEquals(before, target.readBytes(), "$mutation must not alter the accepted source")
            assertFalse(project.resolve("src/modules/created.c").exists(), "$mutation must not create a source")
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId, "$mutation must close or recover its pending attempt")
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status, mutation)
            }
        }
    }

    @Test
    fun `active repair path rejects change claims that disagree with captured bytes`() {
        val cases = listOf(
            "duplicate-relative-path" to "reported a source path more than once",
            "non-canonical-order" to "changes must use canonical path order",
            "foreign-root" to "unauthorized file change: other:src/modules/reconstructed.c",
            "read-only-path" to "unauthorized file change: project:src/main.c",
            "omitted-claim" to "change report does not match workspace changes",
            "phantom-claim" to "change report does not match workspace changes",
            "reverted-write" to "change report does not match workspace changes",
            "wrong-before" to "digests do not match workspace file",
            "wrong-after" to "digests do not match workspace file",
            "wrong-size" to "size does not match workspace file",
            "null-size" to "size does not match workspace file",
        )
        for ((variant, expectedReason) in cases) {
            val project = createProject(
                createRepairTempDirectory("repair-change-claim-${variant}-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) {\n",
            )
            val target = project.resolve("src/modules/reconstructed.c")
            val before = target.readBytes()
            val beforeDigest = sha256(before)
            val candidate = goodHelloSource().toByteArray()
            val afterDigest = sha256(candidate)
            val targetPath = AgentWorkspacePath("project", "src/modules/reconstructed.c")
            val targetChange = AgentFileChange(
                targetPath,
                AgentFileChangeKind.MODIFIED,
                beforeDigest,
                afterDigest,
                candidate.size.toLong(),
            )
            val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    val changes = when (variant) {
                        "duplicate-relative-path" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange, targetChange.copy(
                                path = AgentWorkspacePath("other", targetPath.relativePath),
                            ))
                        }
                        "non-canonical-order" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(
                                targetChange,
                                targetChange.copy(path = AgentWorkspacePath("project", "a.c")),
                            )
                        }
                        "foreign-root" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange.copy(path = AgentWorkspacePath("other", targetPath.relativePath)))
                        }
                        "read-only-path" -> listOf(AgentFileChange(
                            AgentWorkspacePath("project", "src/main.c"),
                            AgentFileChangeKind.MODIFIED,
                            sha256("before".toByteArray()),
                            sha256("after".toByteArray()),
                            5,
                        ))
                        "omitted-claim" -> {
                            output.replace(targetPath.relativePath, candidate)
                            emptyList()
                        }
                        "phantom-claim" -> listOf(targetChange)
                        "reverted-write" -> {
                            output.replace(targetPath.relativePath, candidate)
                            output.replace(targetPath.relativePath, before)
                            listOf(targetChange)
                        }
                        "wrong-before" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange.copy(beforeSha256 = sha256("wrong-before".toByteArray())))
                        }
                        "wrong-after" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange.copy(afterSha256 = sha256("wrong-after".toByteArray())))
                        }
                        "wrong-size" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange.copy(sizeBytes = candidate.size + 1L))
                        }
                        "null-size" -> {
                            output.replace(targetPath.relativePath, candidate)
                            listOf(targetChange.copy(sizeBytes = null))
                        }
                        else -> error("unknown change-claim fixture: $variant")
                    }
                    return AgentExecutionResult(AgentStopReason.COMPLETED, "untrusted fixture claim", changes)
                }
            }

            val failure = assertFailsWith<Exception>(variant) {
                generatedCRepairLoop(
                    harness,
                    RepairHistory(project.resolve("reports/repair_history.json")),
                ).repairCompileError(project, collectCompileFailure(project), emptyList())
            }
            val messages = generateSequence<Throwable>(failure) { it.cause }
                .mapNotNull { it.message }
                .toList()
            assertTrue(messages.any { it.contains(expectedReason) }, "$variant: $messages")
            assertContentEquals(before, target.readBytes(), "$variant must leave the accepted source unchanged")
            assertFalse(project.resolve("src/modules/created.c").exists(), "$variant must not create a source")

            val persistedState = Json.parseToJsonElement(
                project.resolve("reports/repair-revisions/graph.json").readText(),
            ).jsonObject
            assertEquals(JsonNull, persistedState.getValue("pending"), "$variant must be rejected in-process")
            assertEquals(baselineHead, persistedState.getValue("headId").jsonPrimitive.content, variant)
            val terminalNode = persistedState.getValue("nodes").jsonArray.last().jsonObject
            assertEquals("rejected", terminalNode.getValue("status").jsonPrimitive.content, variant)
            assertEquals("candidate-error", terminalNode.getValue("evidenceKind").jsonPrimitive.content, variant)
            assertEquals(false, terminalNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean, variant)

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId, variant)
                assertEquals(baselineHead, graph.snapshot.headId, variant)
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status, variant)
            }
        }
    }

    @Test
    fun `active ACP repair retains resource-limited write refusal without changing accepted source`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-resource-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val budget = RepairResourceBudget(maximumPatchBytes = 4)
        val harness = AcpAgentHarnessTest().harness("repair-active-oversized-only")

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                resourceBudget = budget,
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
            it.message.orEmpty().contains("repair agent stopped with no_changes")
        }, generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList().toString())

        assertContentEquals(acceptedSource, target.readBytes())
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            val node = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            val binding = requireNotNull(node.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals("returned-no-changes", binding.terminalOutcome)
            assertFalse(binding.receiptReleaseComplete)
            val receipt = Json.parseToJsonElement(project.resolve(binding.receiptPath).readText()).jsonObject
            assertEquals("returned", receipt.getValue("outcome").jsonObject.getValue("type").jsonPrimitive.content)
            val filesystemAudit = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            assertEquals(1, filesystemAudit.getValue("recordCount").jsonPrimitive.int)
            val refusedWrite = filesystemAudit.getValue("records").jsonArray.single().jsonObject
            assertEquals("denied", refusedWrite.getValue("outcome").jsonPrimitive.content)
            assertEquals("resource-limit", refusedWrite.getValue("reason").jsonPrimitive.content)
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertEquals(true, process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            assertFalse(receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)
            assertFalse(project.resolve("src/modules/created.c").exists())
        }
    }

    @Test
    fun `active ACP repair retains real stream output exhaustion and rejects the candidate`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-output-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val harness = AcpAgentHarnessTest().harness("repair-active-output-limit")
        val limits = AgentExecutionLimits(maxOutputBytes = 64L * 1024)

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                limits = limits,
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
            it.message.orEmpty().contains("ACP aggregate stdout and stderr exceeded")
        }, generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList().toString())
        assertContentEquals(acceptedSource, target.readBytes())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            val node = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            val binding = requireNotNull(node.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals("failed-resource-exhausted", binding.terminalOutcome)
            assertFalse(binding.receiptReleaseComplete)
            val receipt = Json.parseToJsonElement(project.resolve(binding.receiptPath).readText()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("failed", outcome.getValue("type").jsonPrimitive.content)
            assertEquals(
                "resource-exhausted",
                outcome.getValue("failure").jsonObject.getValue("kind").jsonPrimitive.content,
            )
            val process = receipt.getValue("process").jsonObject
            assertTrue(process.getValue("outputLimitExceeded").jsonPrimitive.boolean)
            assertEquals(64 * 1024, process.getValue("producedOutputLimitBytes").jsonPrimitive.int)
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            assertFalse(receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)
        }
    }

    @Test
    fun `active ACP repair frame-count exhaustion retains completed write receipt and rejects the candidate`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-frame-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = AcpAgentHarnessTest().harness(
            "repair-active-declared-role-frame-limit-after-write",
            maximumProtocolFrames = 16,
        )

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        val failureChain = generateSequence<Throwable>(failure) { it.cause }.toList()
        val executionFailure = failureChain.filterIsInstance<AgentExecutionException>().single()
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, executionFailure.failure.kind)
        assertTrue(executionFailure.failure.message.contains("16-frame protocol limit"), executionFailure.failure.message)
        assertTrue(failure.suppressed.isEmpty(), failure.suppressed.joinToString())
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        val persistedGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, persistedGraph.getValue("pending"))
        assertEquals(baselineHead, persistedGraph.getValue("headId").jsonPrimitive.content)
        assertEquals("resource_exhausted", persistedGraph.getValue("runs").jsonArray.last()
            .jsonObject.getValue("status").jsonPrimitive.content)
        val rawNode = persistedGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content)
        assertFalse(rawNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertFalse(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("failed-resource-exhausted", binding.terminalOutcome)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertFalse(binding.receiptReleaseComplete)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("failed", outcome.getValue("type").jsonPrimitive.content)
            assertEquals("resource-exhausted", outcome.getValue("failure").jsonObject
                .getValue("kind").jsonPrimitive.content)
            assertEquals(0, receipt.getValue("process").jsonObject
                .getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(receipt.getValue("process").jsonObject
                .getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            assertFalse(receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)

            val filesystem = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content)
            assertEquals("completed", records.single().getValue("reason").jsonPrimitive.content)
            assertEquals(sha256("src/modules/reconstructed.c".toByteArray(Charsets.UTF_8)), records.single()
                .getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                .getValue("sha256").jsonPrimitive.content)
        }
    }

    @Test
    fun `active ACP repair frame-size exhaustion retains completed write receipt and rejects the candidate`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-frame-size-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = AcpAgentHarnessTest().harness(
            "repair-active-declared-role-frame-size-after-write",
            maximumFrameBytes = 16 * 1024,
        )

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        val failureChain = generateSequence<Throwable>(failure) { it.cause }.toList()
        val executionFailure = failureChain.filterIsInstance<AgentExecutionException>().single()
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, executionFailure.failure.kind)
        assertTrue(executionFailure.failure.message.contains("16384-byte frame limit"), executionFailure.failure.message)
        assertTrue(failure.suppressed.isEmpty(), failure.suppressed.joinToString())
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        val persistedGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, persistedGraph.getValue("pending"))
        assertEquals(baselineHead, persistedGraph.getValue("headId").jsonPrimitive.content)
        assertEquals("resource_exhausted", persistedGraph.getValue("runs").jsonArray.last()
            .jsonObject.getValue("status").jsonPrimitive.content)
        val rawNode = persistedGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content)
        assertFalse(rawNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertFalse(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("failed-resource-exhausted", binding.terminalOutcome)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertFalse(binding.receiptReleaseComplete)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("failed", outcome.getValue("type").jsonPrimitive.content)
            assertEquals("resource-exhausted", outcome.getValue("failure").jsonObject
                .getValue("kind").jsonPrimitive.content)
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            assertFalse(receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)

            val filesystem = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content)
            assertEquals("completed", records.single().getValue("reason").jsonPrimitive.content)
            assertEquals(sha256("src/modules/reconstructed.c".toByteArray(Charsets.UTF_8)), records.single()
                .getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                .getValue("sha256").jsonPrimitive.content)
        }
    }

    @Test
    fun `active ACP repair preserves tool-call exhaustion when final usage arrives during cancellation`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-tool-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val limits = AgentExecutionLimits(
            maxToolCalls = 1,
            // These exact token ceilings require the completed response to survive the
            // adjacent tool-limit update; otherwise the active repair records PROTOCOL.
            maxInputTokens = 11,
            maxOutputTokens = 7,
        )
        val harness = AcpAgentHarnessTest().harness(
            "repair-active-declared-role-tool-limit-delayed-response-after-write",
        )

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                limits = limits,
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
            it.message.orEmpty().contains("repair agent stopped with limit_exhausted")
        }, "${generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList()}\n" +
            "ACP stderr=${harness.latestDiagnostics()?.stderr}")
        assertTrue(failure.suppressed.isEmpty(), failure.suppressed.joinToString())
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        val rawGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        assertEquals("resource_exhausted", rawGraph.getValue("runs").jsonArray.last()
            .jsonObject.getValue("status").jsonPrimitive.content)
        val rawNode = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content)
        assertFalse(rawNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertFalse(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("returned-limit-exhausted", binding.terminalOutcome)
            assertFalse(binding.receiptReleaseComplete)
            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
            val result = outcome.getValue("result").jsonObject
            assertEquals("limit-exhausted", result.getValue("stopReason").jsonPrimitive.content)
            val usage = result.getValue("usage").jsonObject
            assertEquals(2, usage.getValue("toolCalls").jsonPrimitive.int)
            assertEquals(11L, usage.getValue("inputTokens").jsonPrimitive.long)
            assertEquals(7L, usage.getValue("outputTokens").jsonPrimitive.long)
            val filesystem = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content)
            assertEquals("completed", records.single().getValue("reason").jsonPrimitive.content)
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val assessment = decompengine.project.AcpChangeAssessment.parse(
                project.resolve(requireNotNull(binding.assessmentPath)).readBytes(),
            )
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.INTERRUPTED,
                assessment.eligibility)
        }
    }

    @Test
    fun `active ACP repair preserves tool exhaustion when cancellation yields no final usage`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-tool-limit-no-final-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = AcpAgentHarnessTest().harness(
            "repair-active-declared-role-tool-limit-no-final-response-after-write",
        )
        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                limits = AgentExecutionLimits(maxToolCalls = 1, maxInputTokens = 11, maxOutputTokens = 7),
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        val chain = generateSequence<Throwable>(failure) { it.cause }.toList()
        assertTrue(chain.any { it.message.orEmpty().contains("repair agent stopped with limit_exhausted") },
            "${chain.mapNotNull { it.message }}\nACP stderr=${harness.latestDiagnostics()?.stderr}")
        assertFalse(chain.any { it is AgentExecutionException && it.failure.kind == AgentFailureKind.PROTOCOL })
        assertContentEquals(acceptedSource, target.readBytes())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
            val binding = requireNotNull(graph.snapshot.nodes.last().repairMetadata?.agentInvocation)
            assertEquals("returned-limit-exhausted", binding.terminalOutcome)
            val receipt = Json.parseToJsonElement(project.resolve(binding.receiptPath).readText()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
            val result = outcome.getValue("result").jsonObject
            assertEquals("limit-exhausted", result.getValue("stopReason").jsonPrimitive.content)
            val usage = result.getValue("usage").jsonObject
            assertEquals(2, usage.getValue("toolCalls").jsonPrimitive.int)
            assertEquals(JsonNull, usage.getValue("inputTokens"))
            assertEquals(JsonNull, usage.getValue("outputTokens"))
        }
    }

    @Test
    fun `active ACP repair permits exact tool-call limit through candidate validation`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-tool-limit-boundary-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = AcpAgentHarnessTest().harness("repair-active-declared-role-tool-limit-after-write")
        val validationFailure = IllegalStateException("exact tool-call boundary reached candidate validation")
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(
                    listOf("Makefile", "include/modules/reconstructed.h", "src/main.c", "src/modules/reconstructed.c"),
                    request.candidateSourcePaths,
                )
                throw validationFailure
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate compilation is outside this tool-limit control")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate rebuild is outside this tool-limit control")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("behavior evaluation is outside this tool-limit control")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(maxToolCalls = 2),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = RepairResourceBudget(),
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(
                project,
                collectCompileFailure(project),
                emptyList(),
            )
        }
        assertSame(validationFailure, failure)
        assertEquals(1, validationCalls)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        val rawGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        assertEquals("validation_failed", rawGraph.getValue("runs").jsonArray.last()
            .jsonObject.getValue("status").jsonPrimitive.content)
        val rawNode = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content)
        assertFalse(rawNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertFalse(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)
            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val outcome = receipt.getValue("outcome").jsonObject
            assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
            val result = outcome.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            assertEquals(2, result.getValue("usage").jsonObject.getValue("toolCalls").jsonPrimitive.int)
            assertEquals(1, receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                .getValue("recordCount").jsonPrimitive.int)
        }
    }

    @Test
    fun `active ACP repair cancellation after acknowledged write preserves accepted state`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-acp-cancel-after-write-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val harness = AcpAgentHarnessTest().harness("repair-active-declared-role-cancel-after-write")
        val cancellation = AgentCancellationSource()
        val ready = java.util.concurrent.CountDownLatch(1)
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                error("cancelled candidate must not reach validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("cancelled candidate must not compile")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("cancelled candidate must not rebuild")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("cancelled candidate must not run behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = cancellation.cancellation,
            onAgentEvent = { event ->
                if (event is AgentMessageEvent && event.textDelta == "repair-cancel-after-ack-ready") {
                    ready.countDown()
                    cancellation.cancel()
                }
            },
            resourceBudget = RepairResourceBudget(),
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<Exception> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "src/modules/reconstructed.c: compiler error"),
                emptyList(),
            )
        }
        assertTrue(ready.await(1, TimeUnit.SECONDS), "agent must acknowledge the target write before cancellation")
        val messages = generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList()
        assertTrue(messages.any { it.contains("cancelled") }, messages.toString())
        assertEquals(0, validationCalls)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        val rawGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawNode = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content)
        val rawBinding = rawNode.getValue("repairMetadata").jsonObject
            .getValue("agentInvocation").jsonObject
        val receipt = Json.parseToJsonElement(project.resolve(
            rawBinding.getValue("receiptPath").jsonPrimitive.content,
        ).readText()).jsonObject
        val process = receipt.getValue("process").jsonObject
        assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
        assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.CANCELLED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("returned-cancelled", binding.terminalOutcome)
            val receipt = Json.parseToJsonElement(project.resolve(binding.receiptPath).readText()).jsonObject
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("cancelled", result.getValue("stopReason").jsonPrimitive.content)
            val records = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(1, records.size)
            assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content)
            val assessment = decompengine.project.AcpChangeAssessment.parse(
                project.resolve(requireNotNull(binding.assessmentPath)).readBytes(),
            )
            assertEquals(decompengine.project.AcpChangePublicationEligibility.INTERRUPTED, assessment.eligibility)
            assertEquals(AgentStopReason.CANCELLED, assessment.normalizedStopReason)
        }
    }

    @Test
    fun `active ACP repair enforces returned token ceilings after a write and permits exact usage`() {
        data class TokenCase(
            val label: String,
            val mode: String,
            val limits: AgentExecutionLimits,
            val exhausted: Boolean,
            val invalidUsageMessage: String? = null,
            val refused: Boolean = false,
        )

        val cases = listOf(
            TokenCase(
                "input", "repair-active-declared-role-token-limit-after-write",
                AgentExecutionLimits(maxInputTokens = 10), exhausted = true,
            ),
            TokenCase(
                "output", "repair-active-declared-role-token-limit-after-write",
                AgentExecutionLimits(maxOutputTokens = 6), exhausted = true,
            ),
            TokenCase(
                "max-turn-requests", "repair-active-declared-role-max-turn-requests-after-write",
                AgentExecutionLimits(), exhausted = true,
            ),
            TokenCase(
                "exact", "repair-active-declared-role-token-limit-after-write",
                AgentExecutionLimits(maxInputTokens = 11, maxOutputTokens = 7),
                exhausted = false,
            ),
            TokenCase(
                "missing-usage", "repair-active-declared-role-missing-usage-after-write",
                AgentExecutionLimits(maxInputTokens = 10, maxOutputTokens = 6), exhausted = false,
                invalidUsageMessage = "inputTokens,outputTokens",
            ),
            TokenCase(
                "negative-usage", "repair-active-declared-role-negative-usage-after-write",
                AgentExecutionLimits(maxInputTokens = 10), exhausted = false,
                invalidUsageMessage = "invalid prompt usage",
            ),
            TokenCase(
                "refusal", "repair-active-declared-role-refusal-after-write",
                AgentExecutionLimits(), exhausted = false, refused = true,
            ),
        )
        cases.forEach { case ->
            val project = createProject(
                createRepairTempDirectory("repair-active-acp-token-limit-${case.label}-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) {\n",
            )
            val target = project.resolve("src/modules/reconstructed.c")
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use {
                it.snapshot.headId
            }
            val harness = AcpAgentHarnessTest().harness(case.mode)
            val validationFailure = IllegalStateException("token usage reached candidate validation")
            var validationCalls = 0
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(
                        listOf("Makefile", "include/modules/reconstructed.h", "src/main.c", "src/modules/reconstructed.c"),
                        request.candidateSourcePaths,
                    )
                    throw validationFailure
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("compilation is outside this token-ceiling control")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("rebuild is outside this token-ceiling control")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("behavior evaluation is outside this token-ceiling control")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = case.limits,
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = RepairResourceBudget(),
                allowTestOnlyValidation = false,
                faultInjector = null,
            )

            val failure = assertFailsWith<Exception> {
                loop.repairCompileError(project, collectCompileFailure(project), emptyList())
            }
            if (case.invalidUsageMessage != null) {
                val messages = generateSequence<Throwable>(failure) { it.cause }
                    .mapNotNull { it.message }.toList()
                assertTrue(messages.any { it.contains(case.invalidUsageMessage) }, messages.toString())
                assertEquals(0, validationCalls)
            } else if (case.exhausted) {
                assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
                    it.message.orEmpty().contains("repair agent stopped with limit_exhausted")
                }, "${case.label} ceiling failure: ${generateSequence<Throwable>(failure) { it.cause }
                    .mapNotNull { it.message }.toList()}")
                assertEquals(0, validationCalls)
            } else if (case.refused) {
                assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
                    it.message.orEmpty().contains("repair agent stopped with refused")
                }, "${case.label} refusal: ${generateSequence<Throwable>(failure) { it.cause }
                    .mapNotNull { it.message }.toList()}")
                assertEquals(0, validationCalls)
            } else {
                assertSame(validationFailure, failure)
                assertEquals(1, validationCalls)
            }
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

            val rawGraph = Json.parseToJsonElement(
                project.resolve("reports/repair-revisions/graph.json").readText(),
            ).jsonObject
            assertEquals(JsonNull, rawGraph.getValue("pending"), case.label)
            assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content, case.label)
            val expectedRun = when {
                case.exhausted -> "resource_exhausted"
                case.refused -> "rejected"
                else -> "validation_failed"
            }
            assertEquals(expectedRun, rawGraph.getValue("runs").jsonArray.last()
                .jsonObject.getValue("status").jsonPrimitive.content, case.label)

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId, case.label)
                assertEquals(baselineHead, graph.snapshot.headId, case.label)
                assertEquals(
                    when {
                        case.exhausted -> RepairRunStatus.RESOURCE_EXHAUSTED
                        case.refused -> RepairRunStatus.REJECTED
                        else -> RepairRunStatus.VALIDATION_FAILED
                    },
                    graph.snapshot.runs.last().status,
                    case.label,
                )
                val rejected = graph.snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status, case.label)
                assertFalse(rejected.recoveredAfterCrash, case.label)
                val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
                val expectedTerminal = when {
                    case.exhausted -> "returned-limit-exhausted"
                    case.refused -> "returned-refused"
                    case.invalidUsageMessage != null -> "failed-protocol"
                    else -> "returned-completed"
                }
                assertEquals(expectedTerminal, binding.terminalOutcome, case.label)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes), case.label)
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val outcome = receipt.getValue("outcome").jsonObject
                if (case.invalidUsageMessage != null) {
                    assertEquals("failed", outcome.getValue("type").jsonPrimitive.content, case.label)
                    val failed = outcome.getValue("failure").jsonObject
                    assertEquals("protocol", failed.getValue("kind").jsonPrimitive.content, case.label)
                    val messageCommitment = failed.getValue("message").jsonObject
                    val observedFailure = generateSequence<Throwable>(failure) { it.cause }
                        .filterIsInstance<AgentExecutionException>()
                        .single()
                    val observedMessageBytes = observedFailure.failure.message.toByteArray(Charsets.UTF_8)
                    assertTrue(observedFailure.failure.message.contains(case.invalidUsageMessage), case.label)
                    assertEquals(observedMessageBytes.size.toLong(),
                        messageCommitment.getValue("encodedBytes").jsonPrimitive.content.toLong(), case.label)
                    assertEquals(sha256(observedMessageBytes),
                        messageCommitment.getValue("sha256").jsonPrimitive.content, case.label)
                    assertEquals("utf-8", messageCommitment.getValue("encoding").jsonPrimitive.content, case.label)
                    assertFalse(binding.receiptReleaseComplete, case.label)
                } else {
                    assertEquals("returned", outcome.getValue("type").jsonPrimitive.content, case.label)
                    val result = outcome.getValue("result").jsonObject
                    assertEquals(
                        when {
                            case.exhausted -> "limit-exhausted"
                            case.refused -> "refused"
                            else -> "completed"
                        },
                        result.getValue("stopReason").jsonPrimitive.content,
                        case.label,
                    )
                    val changes = result.getValue("changes").jsonObject
                    assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int, case.label)
                    val change = changes.getValue("records").jsonArray.single().jsonObject
                    assertEquals("modified", change.getValue("kind").jsonPrimitive.content, case.label)
                    val relativePath = change.getValue("relativePath").jsonObject
                    assertEquals(sha256("src/modules/reconstructed.c".toByteArray(Charsets.UTF_8)),
                        relativePath.getValue("sha256").jsonPrimitive.content, case.label)
                    assertEquals(sha256(acceptedSource),
                        change.getValue("beforeSha256").jsonPrimitive.content, case.label)
                    val candidateText = when {
                        case.refused -> "/* active refusal candidate */\nint decomp_engine_main(void) { return 1; }\n"
                        case.label == "max-turn-requests" ->
                            "/* active max-turn candidate */\nint decomp_engine_main(void) { return 1; }\n"
                        else -> "/* token-limit candidate */\nint decomp_engine_main(void) { return 1; }\n"
                    }
                    val candidate = candidateText.toByteArray(Charsets.UTF_8)
                    assertEquals(sha256(candidate), change.getValue("afterSha256").jsonPrimitive.content, case.label)
                    assertEquals(candidate.size.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong(), case.label)
                    if (!case.refused) {
                        val usage = result.getValue("usage").jsonObject
                        assertEquals(11, usage.getValue("inputTokens").jsonPrimitive.int, case.label)
                        assertEquals(7, usage.getValue("outputTokens").jsonPrimitive.int, case.label)
                        assertEquals(3, usage.getValue("cachedInputTokens").jsonPrimitive.int, case.label)
                        assertEquals(!case.exhausted, binding.receiptReleaseComplete, case.label)
                    }
                }
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                val record = filesystem.getValue("records").jsonArray.single().jsonObject
                assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int, case.label)
                assertEquals("allowed", record.getValue("outcome").jsonPrimitive.content, case.label)
                assertEquals("completed", record.getValue("reason").jsonPrimitive.content, case.label)
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int, case.label)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean, case.label)
                if (case.exhausted || case.invalidUsageMessage != null || case.refused) {
                    val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                    assertEquals(binding.assessmentSha256, sha256(assessmentBytes), case.label)
                    val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                    assertEquals(binding.receiptSha256, assessment.receiptSha256, case.label)
                    assertEquals(
                        if (case.exhausted) decompengine.project.AcpChangePublicationEligibility.INTERRUPTED
                        else decompengine.project.AcpChangePublicationEligibility.REJECTED,
                        assessment.eligibility,
                        case.label,
                    )
                    if (case.refused) {
                        assertEquals(AgentStopReason.REFUSED, assessment.normalizedStopReason, case.label)
                        assertEquals(listOf("candidate-rejected"), assessment.reasonCodes, case.label)
                        assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus, case.label)
                    }
                }
            }
        }
    }

    @Test
    fun `active repair path rejects candidate growth beyond the staging byte budget`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-staging-byte-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        // The original indexed source fits in the admission limit; the candidate does not.
        val budget = RepairResourceBudget(maximumStagingBytes = 4096)
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { it.snapshot.headId }
        val candidate = ("/*" + "x".repeat(8192) + "*/\n").toByteArray()
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                assertTrue(initialFiles.getValue(targetPath).size < budget.maximumStagingBytes)
                output.replace(targetPath, candidate)
                error("oversized candidate unexpectedly passed the staging byte budget")
            }
        }

        val failure = assertFailsWith<Exception> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                resourceBudget = budget,
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        val messages = generateSequence<Throwable>(failure) { it.cause }
            .mapNotNull { it.message }
            .toList()
        assertTrue(messages.any { it.contains("repair workspace contains") && it.contains("limit=4096") }, messages.toString())
        assertContentEquals(acceptedSource, target.readBytes())

        val persistedState = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, persistedState.getValue("pending"))
        assertEquals(baselineHead, persistedState.getValue("headId").jsonPrimitive.content)
        val terminalNode = persistedState.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", terminalNode.getValue("status").jsonPrimitive.content)
        assertEquals("agent-failure-resource-exhausted", terminalNode.getValue("evidenceKind").jsonPrimitive.content)
        assertEquals(false, terminalNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)
        assertEquals(JsonNull, terminalNode.getValue("repairMetadata").jsonObject.getValue("agentInvocation"))
        assertEquals(
            "resource_exhausted",
            persistedState.getValue("runs").jsonArray.last().jsonObject
                .getValue("status").jsonPrimitive.content,
        )

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
        }
    }

    @Test
    fun `active repair path classifies per-file output limit as resource exhaustion`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-source-file-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val target = project.resolve("src/modules/reconstructed.c")
        val acceptedSource = target.readBytes()
        val budget = RepairResourceBudget(maximumSourceFileBytes = 4096)
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { it.snapshot.headId }
        val harness = capturedReplacingHarness(ByteArray(4097) { 'x'.code.toByte() })

        val failure = assertFailsWith<AgentExecutionException> {
            generatedCRepairLoop(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                resourceBudget = budget,
            ).repairCompileError(project, collectCompileFailure(project), emptyList())
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
        assertIs<RepairBudgetExceededException>(failure.cause)
        assertTrue(failure.cause?.message.orEmpty().contains("exceeds the source-file byte budget"))
        assertContentEquals(acceptedSource, target.readBytes())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
        }
    }

    @Test
    fun `active repair path rejects a candidate over the patch file count`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-patch-file-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        project.resolve(secondPath).writeText("int secondary(void) { return 1; }\n")
        val paths = listOf(firstPath, secondPath).sorted()
        val before = paths.associateWith { project.resolve(it).readBytes() }
        val profile = DeclarativeRepairIndexProfile(
            "two-file-active-repair-v1",
            RepairIndexLayout(sourcePaths = paths, editablePaths = paths),
        )
        val budget = RepairResourceBudget(maximumPatchFiles = 1)
        val baselineHead = ModuleRevisionGraph.open(project, profile, budget).use { it.snapshot.headId }
        val failureText = paths.joinToString("\n") { "$it: compiler error" }
        val replacements = paths.associateWith { path ->
            ("/* candidate $path */\n" + before.getValue(path).decodeToString()).toByteArray()
        }
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                assertEquals(paths.toSet(), initialFiles.keys)
                output.replace(firstPath, replacements.getValue(firstPath))
                output.replace(secondPath, replacements.getValue(secondPath))
                error("two-file candidate unexpectedly passed the one-file patch budget")
            }
        }
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("patch-file refusal must happen before validation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("patch-file refusal must happen before rebuild")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("patch-file refusal must happen before behavior validation")
        }

        val failure = assertFailsWith<Exception> {
            TraceGuidedRepairLoop.forTesting(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                profile,
                validation,
                CapturedRepairStagingAuthority,
                resourceBudget = budget,
            ).repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", failureText),
                emptyList(),
            )
        }
        val messages = generateSequence<Throwable>(failure) { it.cause }
            .mapNotNull { it.message }
            .toList()
        assertTrue(messages.any { it.contains("captured repair output exceeds the patch-file budget") }, messages.toString())
        before.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }

        val persistedState = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, persistedState.getValue("pending"))
        assertEquals(baselineHead, persistedState.getValue("headId").jsonPrimitive.content)
        val terminalNode = persistedState.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", terminalNode.getValue("status").jsonPrimitive.content)
        assertEquals("agent-failure-resource-exhausted", terminalNode.getValue("evidenceKind").jsonPrimitive.content)
        assertEquals(false, terminalNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
        }
    }

    @Test
    fun `active repair path enforces aggregate patch bytes and permits the exact boundary`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-patch-byte-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) {\n",
        )
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        project.resolve(secondPath).writeText("int secondary(void) { return 1; }\n")
        val paths = listOf(firstPath, secondPath).sorted()
        val before = paths.associateWith { project.resolve(it).readBytes() }
        val profile = DeclarativeRepairIndexProfile(
            "two-file-patch-bytes-v1",
            RepairIndexLayout(sourcePaths = paths, editablePaths = paths),
        )
        val budget = RepairResourceBudget(maximumPatchFiles = 2, maximumPatchBytes = 4096)
        val baselineHead = ModuleRevisionGraph.open(project, profile, budget).use { it.snapshot.headId }
        val failureText = paths.joinToString("\n") { "$it: compiler error" }
        val tooLarge = mapOf(
            paths[0] to ByteArray(2048) { 'a'.code.toByte() },
            paths[1] to ByteArray(2049) { 'b'.code.toByte() },
        )
        val exactBoundary = paths.associateWith { path ->
            ByteArray(2048) { if (path == paths[0]) 'c'.code.toByte() else 'd'.code.toByte() }
        }
        fun harness(replacements: Map<String, ByteArray>, exceedBudget: Boolean): CapturedRepairAgentHarness =
            object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    paths.forEach { path -> output.replace(path, replacements.getValue(path)) }
                    if (exceedBudget) error("aggregate patch byte refusal should precede result construction")
                    return AgentExecutionResult(
                        AgentStopReason.COMPLETED,
                        "exact aggregate patch boundary",
                        paths.map { path ->
                            AgentFileChange(
                                AgentWorkspacePath("project", path),
                                AgentFileChangeKind.MODIFIED,
                                sha256(before.getValue(path)),
                                sha256(replacements.getValue(path)),
                                replacements.getValue(path).size.toLong(),
                            )
                        },
                    )
                }
            }
        val exactBoundaryValidationFailure = IllegalStateException("exact patch-byte boundary reached validation")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? {
                paths.forEach { path ->
                    assertContentEquals(exactBoundary.getValue(path), projectDir.resolve(path).readBytes(), path)
                }
                throw exactBoundaryValidationFailure
            }
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("compile exception prevents rebuild")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("compile exception prevents behavior validation")
        }
        fun loop(adapter: CapturedRepairAgentHarness) = TraceGuidedRepairLoop.forTesting(
            adapter,
            RepairHistory(project.resolve("reports/repair_history.json")),
            profile,
            validation,
            CapturedRepairStagingAuthority,
            resourceBudget = budget,
        )

        val refusal = assertFailsWith<AgentExecutionException> {
            loop(harness(tooLarge, exceedBudget = true)).repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", failureText),
                emptyList(),
            )
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, refusal.failure.kind)
        assertIs<RepairBudgetExceededException>(refusal.cause)
        assertTrue(refusal.cause?.message.orEmpty().contains("contains 4097 bytes"))
        before.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
            assertNull(graph.snapshot.pendingAttemptId)
        }

        assertFailsWith<IllegalStateException> {
            loop(harness(exactBoundary, exceedBudget = false)).repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", failureText),
                emptyList(),
            )
        }.also { assertTrue(it === exactBoundaryValidationFailure) }
        before.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            assertNull(graph.snapshot.pendingAttemptId)
        }
    }

    @Test
    fun `active repair production policy rejects malformed UTF-8 before candidate installation`() {
        val testRoot = java.nio.file.Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-declared-utf8-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val profile = requireNotNull(GeneratedCRepairIndexProfile.reconstructionProfile())
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        var dispatches = 0
        var validReplacementReachedSink = false
        var malformedReplacementFailure: IllegalArgumentException? = null
        var validationInvoked = false
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                assertTrue(initialFiles.getValue(targetPath).size < RepairResourceBudget().maximumSourceFileBytes)
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                val attemptId = Json.parseToJsonElement(
                    request.contextInputs.single { it.id == "repair-attempt-authority" }.content,
                ).jsonObject.getValue("attemptId").jsonPrimitive.content
                assertEquals("repair:$attemptId", authority.ownerId)
                assertEquals(profile.sha256, authority.profileSha256)
                assertEquals(profile.sha256, authority.grants.single().profileSha256)
                val grant = authority.grants.single()
                assertEquals(request.workspaceRoots.single().id, grant.path.rootId)
                assertEquals(targetPath, grant.path.relativePath)
                assertEquals(AgentOperation.WRITE_FILE, grant.operations.single())
                assertEquals(decompengine.agent.AgentMutationContentKind.UTF8_TEXT, grant.contentKind)
                assertEquals(profile.layout.declarationForPath(targetPath).id, grant.declarationId)
                assertEquals(
                    profile.layout.declarationForPath(targetPath).roles
                        .map(decompengine.project.ProjectFileRole::wireName).toSet(),
                    grant.roles,
                )
                assertEquals(
                    minOf(RepairResourceBudget().maximumSourceFileBytes, profile.budgets.archiveMaximumFileBytes),
                    grant.maximumBytes,
                )

                val validText = "/* café */\nint decomp_engine_main(void) { return 1; }\n"
                val validBytes = validText.toByteArray(Charsets.UTF_8)
                assertTrue(validBytes.size < RepairResourceBudget().maximumSourceFileBytes)
                output.replace(targetPath, validBytes)
                validReplacementReachedSink = true
                val malformed = byteArrayOf(0xc3.toByte(), 0x28)
                val malformedFailure = assertFailsWith<IllegalArgumentException> {
                    output.replace(targetPath, malformed)
                }
                malformedReplacementFailure = malformedFailure
                assertEquals(
                    "captured repair output violates declared mutation authority",
                    malformedFailure.message,
                )
                throw malformedFailure
            }
        }
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationInvoked = true
                error("candidate validation must not run after mutation-policy refusal")
            }
            override fun compile(projectDir: java.nio.file.Path, logPath: java.nio.file.Path,
                                 budget: RepairResourceBudget): CompileFailure? {
                validationInvoked = true
                error("candidate compilation must not run after mutation-policy refusal")
            }
            override fun rebuiltProgram(projectDir: java.nio.file.Path, budget: RepairResourceBudget): java.nio.file.Path =
                error("candidate validation must not run after mutation-policy refusal")
            override fun evaluateBehavior(
                id: String,
                projectDir: java.nio.file.Path,
                originalBinary: java.nio.file.Path,
                rebuiltBinary: java.nio.file.Path,
                inputs: List<ProcessInput>,
                reportsDir: java.nio.file.Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must not run after mutation-policy refusal")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = RepairResourceBudget(),
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                emptyList(),
            )
        }
        assertTrue(failure.message.orEmpty().contains("lacks schema-v2 ACP provider evidence"))
        assertEquals(1, dispatches)
        assertTrue(validReplacementReachedSink)
        assertEquals(
            "captured repair output violates declared mutation authority",
            malformedReplacementFailure?.message,
        )
        assertFalse(validationInvoked)
        assertContentEquals(acceptedSource, target.readBytes())

        val persisted = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, persisted.getValue("pending"))
        assertEquals(baselineHead, persisted.getValue("headId").jsonPrimitive.content)
        assertEquals("rejected", persisted.getValue("nodes").jsonArray.last().jsonObject
            .getValue("status").jsonPrimitive.content)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `active ACP repair persists declared-role denials and a no-change receipt`() {
        val testRoot = java.nio.file.Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-acp-declared-role-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val siblingPath = "src/modules/reconstructed_extra.c"
        val target = project.resolve(targetPath)
        val makefile = project.resolve("Makefile")
        val moduleHeader = project.resolve("include/modules/reconstructed.h")
        val mainSource = project.resolve("src/main.c")
        val acceptedSource = target.readBytes()
        val acceptedMakefile = makefile.readBytes()
        val acceptedModuleHeader = moduleHeader.readBytes()
        val acceptedMainSource = mainSource.readBytes()
        val profile = requireNotNull(GeneratedCRepairIndexProfile.reconstructionProfile())
        val resourceBudget = RepairResourceBudget(maximumSourceFileBytes = 4096)
        assertTrue(profile.budgets.archiveMaximumFileBytes >= resourceBudget.maximumSourceFileBytes)
        assertTrue(acceptedSource.size < resourceBudget.maximumSourceFileBytes)
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, resourceBudget).use {
            it.snapshot.headId
        }
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-no-change")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                val attemptId = Json.parseToJsonElement(
                    request.contextInputs.single { it.id == "repair-attempt-authority" }.content,
                ).jsonObject.getValue("attemptId").jsonPrimitive.content
                assertEquals("repair:$attemptId", authority.ownerId)
                assertEquals(profile.sha256, authority.profileSha256)
                val grant = authority.grants.single()
                assertEquals(profile.sha256, grant.profileSha256)
                assertEquals(request.workspaceRoots.single().id, grant.path.rootId)
                assertEquals(targetPath, grant.path.relativePath)
                assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                assertEquals(decompengine.agent.AgentMutationContentKind.UTF8_TEXT, grant.contentKind)
                assertEquals(profile.layout.declarationForPath(targetPath).id, grant.declarationId)
                assertEquals(
                    profile.layout.declarationForPath(targetPath).roles
                        .map(decompengine.project.ProjectFileRole::wireName).toSet(),
                    grant.roles,
                )
                assertEquals(
                    minOf(resourceBudget.maximumSourceFileBytes, profile.budgets.archiveMaximumFileBytes),
                    grant.maximumBytes,
                )
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationInvoked = false
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationInvoked = true
                error("no-change refusal must not enter candidate validation")
            }
            override fun compile(projectDir: java.nio.file.Path, logPath: java.nio.file.Path,
                                 budget: RepairResourceBudget): CompileFailure? {
                validationInvoked = true
                error("no-change refusal must not compile a candidate")
            }
            override fun rebuiltProgram(projectDir: java.nio.file.Path, budget: RepairResourceBudget): java.nio.file.Path =
                error("no-change refusal must not rebuild a candidate")
            override fun evaluateBehavior(
                id: String,
                projectDir: java.nio.file.Path,
                originalBinary: java.nio.file.Path,
                rebuiltBinary: java.nio.file.Path,
                inputs: List<ProcessInput>,
                reportsDir: java.nio.file.Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("no-change refusal must not run behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = resourceBudget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<Exception> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                emptyList(),
            )
        }
        val failureMessages = generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList()
        assertTrue(failureMessages.any { it.contains("no_changes") }, failureMessages.toString())
        assertFalse(failureMessages.any { it.contains("lacks schema-v2 ACP provider evidence") }, failureMessages.toString())
        assertEquals(1, dispatches)
        assertFalse(validationInvoked)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, makefile.readBytes())
        assertContentEquals(acceptedModuleHeader, moduleHeader.readBytes())
        assertContentEquals(acceptedMainSource, mainSource.readBytes())
        assertFalse(project.resolve(siblingPath).exists())

        val stateBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()
        val persisted = Json.parseToJsonElement(stateBytes.decodeToString()).jsonObject
        assertEquals(JsonNull, persisted.getValue("pending"))
        assertEquals(baselineHead, persisted.getValue("headId").jsonPrimitive.content)
        val rejectedNode = persisted.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rejectedNode.getValue("status").jsonPrimitive.content)
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, resourceBudget)
        graph.use {
            assertNull(it.snapshot.pendingAttemptId)
            assertEquals(baselineHead, it.snapshot.headId)
            assertEquals(ModuleRevisionStatus.REJECTED, it.snapshot.nodes.last().status)
            val binding = requireNotNull(it.snapshot.nodes.last().repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals("returned-no-changes", binding.terminalOutcome)
            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            assertEquals(3, receipt.getValue("schemaVersion").jsonPrimitive.int)
            assertEquals("returned", receipt.getValue("outcome").jsonObject
                .getValue("type").jsonPrimitive.content)
            val filesystem = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(9, filesystem.getValue("recordCount").jsonPrimitive.int)
            val policyDecisions = records.map { record ->
                val path = record.getValue("policyPath").jsonObject
                Triple(
                    path.getValue("relativePath").jsonObject.getValue("sha256").jsonPrimitive.content,
                    record.getValue("outcome").jsonPrimitive.content,
                    record.getValue("reason").jsonPrimitive.content,
                )
            }
            val siblingHash = sha256(siblingPath.toByteArray(Charsets.UTF_8))
            val makefileHash = sha256("Makefile".toByteArray(Charsets.UTF_8))
            val moduleHeaderHash = sha256("include/modules/reconstructed.h".toByteArray(Charsets.UTF_8))
            val mainSourceHash = sha256("src/main.c".toByteArray(Charsets.UTF_8))
            val repairGraphHash = sha256("reports/repair-revisions/graph.json".toByteArray(Charsets.UTF_8))
            val targetHash = sha256(targetPath.toByteArray(Charsets.UTF_8))
            assertEquals(
                listOf(
                    Triple(siblingHash, "denied", "policy-denied"),
                    Triple(makefileHash, "denied", "policy-denied"),
                    Triple(moduleHeaderHash, "denied", "policy-denied"),
                    Triple(mainSourceHash, "denied", "policy-denied"),
                    Triple(repairGraphHash, "denied", "policy-denied"),
                    Triple(targetHash, "denied", "policy-denied"),
                    Triple(targetHash, "allowed", "completed"),
                    Triple(targetHash, "allowed", "completed"),
                    Triple(targetHash, "allowed", "completed"),
                ),
                policyDecisions,
            )
            assertEquals(binding.receiptSchemaVersion, receipt.getValue("schemaVersion").jsonPrimitive.int)
            assertFalse(binding.receiptReleaseComplete)
            assertEquals(binding.receiptReleaseComplete, receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)
            val assessmentPath = requireNotNull(binding.assessmentPath)
            val assessmentBytes = project.resolve(assessmentPath).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(AgentStopReason.NO_CHANGES, assessment.normalizedStopReason)
            assertEquals("candidate-rejected", assessment.reasonCodes.single())
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair admits an exact initial captured source read and refuses one byte over before launch`() {
        val targetPath = "src/modules/reconstructed.c"
        val limit = 4096
        val suffix = "*/\nint decomp_engine_main(void) { return 0; }\n"
        val paddingBytes = limit - "/*".toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
        val initialSource = "/*" + "é".repeat(paddingBytes / 2) +
            (if (paddingBytes % 2 == 1) "x" else "") + suffix
        val initialBytes = initialSource.toByteArray(Charsets.UTF_8)
        assertEquals(limit, initialBytes.size)
        assertTrue(initialSource.length < initialBytes.size)

        fun runCase(exact: Boolean) {
            val maximumReadBytes = if (exact) limit else limit - 1
            val budget = RepairResourceBudget()
            val project = createProject(
                createRepairTempDirectory(
                    if (exact) "repair-active-initial-read-exact-" else "repair-active-initial-read-over-",
                ).resolve("project"),
                reconstructedSource = initialSource,
            )
            val target = project.resolve(targetPath)
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
            }
            val profile = requireNotNull(GeneratedCRepairIndexProfile.reconstructionProfile())
            val acp = AcpAgentHarnessTest().harness(
                "repair-active-declared-role-candidate",
                filesystemLimits = AcpFilesystemLimits(maximumReadBytes = maximumReadBytes),
            )
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("active repair must use captured receipt execution")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("active repair must retain the invocation receipt")

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = error("active repair must bind the turn identity")

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    assertEquals(
                        setOf("Makefile", targetPath),
                        initialFiles.keys,
                    )
                    assertContentEquals(initialBytes, initialFiles.getValue(targetPath))
                    assertTrue(initialFiles.filterKeys { it != targetPath }.values.all {
                        it.size < limit - 1
                    }, "the seeded target must be the sole initial source over the under-limit ceiling")
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                    val grant = authority.grants.single()
                    assertEquals(targetPath, grant.path.relativePath)
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    assertEquals(profile.sha256, grant.profileSha256)
                    val receipt = acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                    capturedReceipt = receipt
                    return receipt
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("exact initial source read reached candidate validation")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertContentEquals(
                        "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n"
                            .toByteArray(Charsets.UTF_8),
                        request.candidateSources.getValue(targetPath),
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("active repair must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("active repair must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("active repair must use immutable candidate validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )

            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                    assertEquals(1, dispatches)
                    assertEquals(1, validationCalls)
                    val receipt = requireNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                    assertNotNull(evidence.completeExecutionEvidence)
                    val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                    assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                    assertEquals(1, result.changes.size)
                } else {
                    val failure = assertFailsWith<AgentExecutionException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
                    assertTrue(failure.failure.message.contains("captured ACP source exceeds the configured read limit: $targetPath"))
                    assertEquals(1, dispatches, "the captured harness is dispatched before its preflight refusal")
                    assertEquals(0, validationCalls)
                    val receipt = requireNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.REQUEST_BOUND, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, evidence.cleanupDisposition)
                    assertNull(evidence.completeExecutionEvidence)
                    assertNull(evidence.diagnostics)
                    assertTrue(evidence.filesystemAudit.isEmpty())
                }

                assertContentEquals(acceptedSource, target.readBytes())
                assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(baseline.first, graph.snapshot.headId)
                    assertEquals(baseline.second + 1, graph.snapshot.nodes.size)
                    assertEquals(baseline.third + 1, graph.snapshot.runs.size)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    assertEquals(
                        if (exact) RepairRunStatus.VALIDATION_FAILED else RepairRunStatus.RESOURCE_EXHAUSTED,
                        graph.snapshot.runs.last().status,
                    )
                    val binding = requireNotNull(graph.snapshot.nodes.last().repairMetadata?.agentInvocation)
                    assertEquals(
                        if (exact) "returned-completed" else "failed-resource-exhausted",
                        binding.terminalOutcome,
                    )
                    assertFalse(graph.snapshot.nodes.last().recoveredAfterCrash)
                    assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                    val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                    assertEquals(binding.receiptSha256, sha256(receiptBytes))
                    val archived = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                    if (!exact) {
                        assertEquals(JsonNull, archived.getValue("process"))
                        assertEquals(JsonNull, archived.getValue("sandbox"))
                        assertEquals("resource-exhausted", archived.getValue("outcome").jsonObject
                            .getValue("failure").jsonObject.getValue("kind").jsonPrimitive.content)
                    }
                    val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                    assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                    val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                    assertEquals(binding.receiptSha256, assessment.receiptSha256)
                    assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                    assertEquals(
                        if (exact) decompengine.project.AcpChangeValidationStatus.FAILED
                        else decompengine.project.AcpChangeValidationStatus.NOT_RUN,
                        assessment.validationStatus,
                    )
                }
            } finally {
                loop.close()
            }
        }

        runCase(exact = true)
        runCase(exact = false)
    }

    @Test
    fun `active ACP repair passes a receipt-backed candidate to the validation strategy`() {
        val testRoot = java.nio.file.Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-acp-validator-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val candidateSource = "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val makefile = project.resolve("Makefile")
        val acceptedMakefile = makefile.readBytes()
        val profile = requireNotNull(GeneratedCRepairIndexProfile.reconstructionProfile())
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-candidate")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                val grant = authority.grants.single()
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals("project", grant.path.rootId)
                assertEquals(targetPath, grant.path.relativePath)
                assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                assertEquals(decompengine.agent.AgentMutationContentKind.UTF8_TEXT, grant.contentKind)
                assertEquals(profile.layout.declarationForPath(targetPath).id, grant.declarationId)
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        val validationReached = java.util.concurrent.atomic.AtomicInteger()
        var observedCandidateDigest: String? = null
        var observedInvocation: RepairValidationInvocation? = null
        val validationStop = IllegalStateException("candidate reached the injected validation boundary")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationReached.incrementAndGet()
                val candidateSources = request.candidateSources
                assertEquals(
                    setOf("Makefile", "include/modules/reconstructed.h", "src/main.c", targetPath),
                    request.candidateSourcePaths.toSet(),
                )
                assertContentEquals(candidateSource, candidateSources.getValue(targetPath))
                assertEquals(request.profileSha256, assertNotNull(request.invocation).profileSha256)
                assertEquals(
                    decompengine.repair.repairCandidateSourceSha256(candidateSources),
                    request.sourceRevisionSha256,
                )
                observedCandidateDigest = request.sourceRevisionSha256
                observedInvocation = request.invocation
                throw validationStop
            }
            override fun compile(projectDir: java.nio.file.Path, logPath: java.nio.file.Path,
                                 budget: RepairResourceBudget): CompileFailure? =
                error("active repair must use immutable candidate validation")
            override fun rebuiltProgram(projectDir: java.nio.file.Path, budget: RepairResourceBudget): java.nio.file.Path =
                error("active repair must use immutable candidate validation")
            override fun evaluateBehavior(
                id: String,
                projectDir: java.nio.file.Path,
                originalBinary: java.nio.file.Path,
                rebuiltBinary: java.nio.file.Path,
                inputs: List<ProcessInput>,
                reportsDir: java.nio.file.Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("active repair must use immutable candidate validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = RepairResourceBudget(),
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                emptyList(),
            )
        }
        assertTrue(failure === validationStop)
        assertEquals(1, dispatches)
        assertEquals(1, validationReached.get())
        val candidateDigest = assertNotNull(observedCandidateDigest)
        val validationInvocation = assertNotNull(
            observedInvocation,
            "the validator must receive the attempt-bound validation invocation",
        )
        assertEquals(candidateDigest, validationInvocation.sourceRevisionSha256)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, makefile.readBytes())
        assertTrue(validationStop.suppressed.isEmpty(), validationStop.suppressed.joinToString())

        val rawGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals(validationInvocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertFalse(rawRejected.getValue("recoveredAfterCrash").jsonPrimitive.boolean)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(validationInvocation.candidateRevisionId, rejected.id)
            assertEquals(validationInvocation.runId, rejected.repairMetadata?.runId)
            assertFalse(rejected.recoveredAfterCrash)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)
            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            assertTrue(receipt.getValue("lifecycle").jsonObject
                .getValue("releaseComplete").jsonPrimitive.boolean)
            assertEquals(binding.resultChangesSha256,
                receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
                    .getValue("changes").jsonObject.getValue("aggregateSha256").jsonPrimitive.content)
            val filesystem = receipt.getValue("policyAudits").jsonObject
                .getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals(1, records.size)
            assertEquals(sha256(targetPath.toByteArray(Charsets.UTF_8)), records.single()
                .getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                .getValue("sha256").jsonPrimitive.content)
            assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content)
            assertEquals("completed", records.single().getValue("reason").jsonPrimitive.content)
            val assessment = decompengine.project.AcpChangeAssessment.parse(
                project.resolve(requireNotNull(binding.assessmentPath)).readBytes(),
            )
            assertEquals(candidateDigest, assessment.afterSha256)
            assertEquals(binding.resultChangesSha256, assessment.changesSha256)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals("validation-failed", assessment.reasonCodes.single())
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair consumes a receipt-bound compile failure and rejects the candidate`() {
        activeAcpRepairConsumesReceiptBoundValidationResult(compileValid = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair records compile-only validation as provisional without accepting the head`() {
        activeAcpRepairConsumesReceiptBoundValidationResult(compileValid = true)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact aggregate retained regression bytes and refuses one byte over before dispatch`() {
        val exactInputs = listOf(
            ProcessInput("a", args = listOf("x"), stdin = byteArrayOf(1)),
            ProcessInput("β", args = listOf("é"), stdin = byteArrayOf(2)),
        )
        val exactBytes = exactInputs.sumOf { input ->
            input.id.toByteArray(Charsets.UTF_8).size.toLong() + input.stdin.size +
                input.args.sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
        }
        assertEquals(8L, exactBytes)
        val budget = RepairResourceBudget(
            maximumRegressionInputBytes = exactBytes,
            maximumRequestBytes = 64 * 1024,
        )
        activeAcpRepairConsumesReceiptBoundValidationResult(
            compileValid = true,
            regressionInputs = exactInputs,
            resourceBudget = budget,
        )

        val project = createProject(
            createRepairTempDirectory("repair-active-regression-input-over-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val source = project.resolve(sourcePath).readBytes()
        val overInputs = listOf(exactInputs[0], exactInputs[1].copy(stdin = byteArrayOf(2, 3)))
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("over-limit regression corpus must be refused before dispatch")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                validationCalls++
                error("over-limit regression corpus must be refused before validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("over-limit regression corpus must not reach compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("over-limit regression corpus must not reach rebuilding")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("over-limit regression corpus must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                overInputs,
            )
        }
        assertTrue(failure.message.orEmpty().contains("retained regression inputs contain 9 bytes"), failure.message)
        assertTrue(failure.message.orEmpty().contains("limit=8"), failure.message)
        assertEquals(0, dispatches)
        assertEquals(0, validationCalls)
        assertContentEquals(source, project.resolve(sourcePath).readBytes())
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baseline.first, graph.snapshot.headId)
            assertEquals(baseline.second, graph.snapshot.nodes.size)
            assertEquals(baseline.third, graph.snapshot.runs.size, "admission fails before a repair run starts")
            assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair enforces cumulative retained regression input count across calls`() {
        assertActiveRepairCumulativeRegressionAdmission(
            acceptedInputs = listOf(
                ProcessInput("first", args = listOf("alpha"), stdin = byteArrayOf(1)),
                ProcessInput("second", args = listOf("beta"), stdin = byteArrayOf(2)),
            ),
            rejectedInput = ProcessInput("third", args = listOf("gamma"), stdin = byteArrayOf(3)),
            budget = RepairResourceBudget(
                maximumRegressionInputs = 2,
                maximumRegressionInputBytes = 64,
                maximumRequestBytes = 64 * 1024,
            ),
            expectedFailure = "retained regression corpus contains 3 inputs; limit=2",
        )
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair enforces cumulative retained regression byte limit across calls`() {
        assertActiveRepairCumulativeRegressionAdmission(
            acceptedInputs = listOf(
                ProcessInput("a", args = listOf("x"), stdin = byteArrayOf(1)),
                ProcessInput("b", args = listOf("1234567890"), stdin = byteArrayOf(2)),
            ),
            rejectedInput = ProcessInput("c", args = emptyList(), stdin = byteArrayOf()),
            budget = RepairResourceBudget(
                maximumRegressionInputs = 10,
                maximumRegressionInputBytes = 15,
                maximumRequestBytes = 64 * 1024,
            ),
            expectedFailure = "retained regression inputs contain 16 bytes; limit=15",
        )
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair enforces cumulative UTF-8 regression argument bytes across calls`() {
        val acceptedInputs = listOf(
            ProcessInput("a", args = listOf("é"), stdin = byteArrayOf()),
            ProcessInput("b", args = listOf("界"), stdin = byteArrayOf()),
        )
        val acceptedBytes = acceptedInputs.sumOf { input ->
            input.id.toByteArray(Charsets.UTF_8).size.toLong() + input.stdin.size +
                input.args.sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
        }
        assertEquals(7L, acceptedBytes, "UTF-8 bytes from arguments contribute to the retained corpus limit")
        val budget = RepairResourceBudget(
            maximumRegressionInputs = 10,
            maximumRegressionInputBytes = acceptedBytes,
            maximumRegressionArguments = 10,
            maximumRequestBytes = 64 * 1024,
        )
        assertActiveRepairCumulativeRegressionAdmission(
            acceptedInputs = acceptedInputs,
            rejectedInput = ProcessInput("c", args = listOf("x"), stdin = byteArrayOf()),
            budget = budget,
            expectedFailure = "retained regression inputs contain 9 bytes; limit=7",
        )
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair enforces cumulative retained regression argument limit across calls`() {
        assertActiveRepairCumulativeRegressionAdmission(
            acceptedInputs = listOf(
                ProcessInput("a", args = listOf(""), stdin = byteArrayOf()),
                ProcessInput("b", args = listOf("", ""), stdin = byteArrayOf()),
            ),
            rejectedInput = ProcessInput("c", args = listOf(""), stdin = byteArrayOf()),
            budget = RepairResourceBudget(
                maximumRegressionInputs = 10,
                maximumRegressionArguments = 3,
                maximumRegressionInputBytes = 64,
                maximumRequestBytes = 64 * 1024,
            ),
            expectedFailure = "retained regression corpus contains 4 arguments; limit=3",
        )
    }

    private fun assertActiveRepairCumulativeRegressionAdmission(
        acceptedInputs: List<ProcessInput>,
        rejectedInput: ProcessInput,
        budget: RepairResourceBudget,
        expectedFailure: String,
    ) {
        val project = createProject(
            createRepairTempDirectory("repair-active-regression-cumulative-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val candidateSource = "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-candidate")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                val expectedInputs = acceptedInputs.take(validationCalls)
                assertEquals(expectedInputs.map { it.id }, request.inputs.map { it.id })
                assertEquals(
                    decompengine.repair.repairRegressionCorpusSha256(expectedInputs),
                    request.regressionCorpusSha256,
                )
                assertContentEquals(acceptedSource, request.projectDir.resolve(targetPath).readBytes())
                assertContentEquals(candidateSource, request.candidateSources.getValue(targetPath))
                assertEquals(
                    decompengine.repair.repairCandidateSourceSha256(request.candidateSources),
                    request.sourceRevisionSha256,
                )
                val invocation = assertNotNull(request.invocation)
                assertEquals(request.regressionCorpusSha256, invocation.regressionCorpusSha256)
                val evidenceBytes = (
                    "{\"schemaVersion\":1,\"outcome\":\"compile-failed\",\"sourceRevisionSha256\":" +
                        "\"${request.sourceRevisionSha256}\"}\n"
                    ).toByteArray(Charsets.UTF_8)
                request.reportsDir.createDirectories()
                val evidencePath = request.reportsDir.resolve("${request.label}.validation.json")
                evidencePath.writeBytes(evidenceBytes)
                val proof = RepairValidationProof(
                    sourceRevisionSha256 = request.sourceRevisionSha256,
                    profileSha256 = request.profileSha256,
                    indexSha256 = request.indexSha256,
                    regressionCorpusSha256 = request.regressionCorpusSha256,
                    originalBinarySha256 = null,
                    rebuiltBinarySha256 = null,
                    runtimeSha256 = sha256("cumulative-regression-fixture".toByteArray(Charsets.UTF_8)),
                    evidenceSha256 = sha256(evidenceBytes),
                    cleanupVerified = true,
                    assurance = RepairValidationAssurance.STRICT_CONTAINED,
                )
                return RepairCandidateValidationOutcome.CompileFailed(
                    CompileFailure(listOf("fixture-compiler"), 1, "", "$targetPath: fixture failure"),
                    proof,
                )
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("active repair must use immutable candidate validation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("active repair must use immutable candidate validation")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("compile-failed candidates must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        try {
            acceptedInputs.forEachIndexed { index, input ->
                val iteration = loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", "$targetPath: fixture compile error $index"),
                    listOf(input),
                )
                assertFalse(iteration.succeeded)
                assertEquals(RepairAttemptDisposition.REJECTED, iteration.disposition)
                assertContentEquals(acceptedSource, target.readBytes())
            }
            assertEquals(acceptedInputs.size, dispatches)
            assertEquals(acceptedInputs.size, validationCalls)

            val failure = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", "$targetPath: over-limit input"),
                    listOf(rejectedInput),
                )
            }
            assertEquals(expectedFailure, failure.message)
            assertEquals(acceptedInputs.size, dispatches, "cumulative overflow must be refused before ACP dispatch")
            assertEquals(acceptedInputs.size, validationCalls, "cumulative overflow must be refused before validation")
            assertContentEquals(acceptedSource, target.readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second + acceptedInputs.size, graph.snapshot.nodes.size)
                assertEquals(baseline.third + acceptedInputs.size, graph.snapshot.runs.size)
                assertEquals(acceptedInputs.map { it.id }, graph.retainedRegressionCorpus().inputs.map { it.id })
                assertEquals(
                    decompengine.repair.repairRegressionCorpusSha256(acceptedInputs),
                    graph.retainedRegressionCorpus().sha256,
                )
            }
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact retained regression input count and refuses one input over before dispatch`() {
        val exactInputs = listOf(
            ProcessInput("a", args = listOf("x"), stdin = byteArrayOf(1)),
            ProcessInput("b", args = listOf("y"), stdin = byteArrayOf(2)),
        )
        val budget = RepairResourceBudget(
            maximumRegressionInputs = exactInputs.size,
            maximumRegressionInputBytes = 64,
            maximumRequestBytes = 64 * 1024,
        )
        activeAcpRepairConsumesReceiptBoundValidationResult(
            compileValid = true,
            regressionInputs = exactInputs,
            resourceBudget = budget,
        )

        val project = createProject(
            createRepairTempDirectory("repair-active-regression-count-over-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val source = project.resolve(sourcePath).readBytes()
        val overInputs = exactInputs + ProcessInput("c", args = listOf("z"), stdin = byteArrayOf(3))
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("over-limit regression corpus must be refused before dispatch")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression corpus must be refused before dispatch")
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                validationCalls++
                error("over-limit regression corpus must be refused before validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("over-limit regression corpus must not reach compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("over-limit regression corpus must not reach rebuilding")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("over-limit regression corpus must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        try {
            val failure = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                    overInputs,
                )
            }
            assertEquals("retained regression corpus contains 3 inputs; limit=2", failure.message)
            assertEquals(0, dispatches)
            assertEquals(0, validationCalls)
            assertContentEquals(source, project.resolve(sourcePath).readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second, graph.snapshot.nodes.size)
                assertEquals(baseline.third, graph.snapshot.runs.size, "admission fails before a repair run starts")
                assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
            }
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact retained regression argument count and refuses one argument over before dispatch`() {
        val exactInputs = listOf(
            ProcessInput("a", args = listOf("x"), stdin = byteArrayOf(1)),
            ProcessInput("b", args = listOf("y", "z"), stdin = byteArrayOf(2)),
        )
        val budget = RepairResourceBudget(
            maximumRegressionInputs = exactInputs.size,
            maximumRegressionArguments = 3,
            maximumRegressionInputBytes = 64,
            maximumRequestBytes = 64 * 1024,
        )
        activeAcpRepairConsumesReceiptBoundValidationResult(
            compileValid = true,
            regressionInputs = exactInputs,
            resourceBudget = budget,
        )

        val project = createProject(
            createRepairTempDirectory("repair-active-regression-argument-over-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val source = project.resolve(sourcePath).readBytes()
        val overInputs = listOf(exactInputs[0], exactInputs[1].copy(args = exactInputs[1].args + "w"))
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("over-limit regression arguments must be refused before dispatch")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                error("over-limit regression arguments must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression arguments must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit regression arguments must be refused before dispatch")
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                validationCalls++
                error("over-limit regression arguments must be refused before validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("over-limit regression arguments must not reach compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("over-limit regression arguments must not reach rebuilding")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("over-limit regression arguments must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        try {
            val failure = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                    overInputs,
                )
            }
            assertEquals("retained regression corpus contains 4 arguments; limit=3", failure.message)
            assertEquals(0, dispatches)
            assertEquals(0, validationCalls)
            assertContentEquals(source, project.resolve(sourcePath).readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second, graph.snapshot.nodes.size)
                assertEquals(baseline.third, graph.snapshot.runs.size, "admission fails before a repair run starts")
                assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
            }
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact diagnostic character limit and records one over as resource exhaustion`() {
        val sourcePath = "src/modules/reconstructed.c"
        val diagnostic = "\n$sourcePath: original compile error"
        val budget = RepairResourceBudget(
            maximumDiagnosticCharacters = diagnostic.length,
            maximumRegressionInputBytes = 64,
            maximumRequestBytes = 64 * 1024,
        )
        activeAcpRepairConsumesReceiptBoundValidationResult(
            compileValid = true,
            resourceBudget = budget,
        )

        val project = createProject(
            createRepairTempDirectory("repair-active-diagnostic-over-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val source = project.resolve(sourcePath).readBytes()
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("over-limit diagnostic must be refused before dispatch")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                error("over-limit diagnostic must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit diagnostic must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit diagnostic must be refused before dispatch")
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                validationCalls++
                error("over-limit diagnostic must be refused before validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("over-limit diagnostic must not reach compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("over-limit diagnostic must not reach rebuilding")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("over-limit diagnostic must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        try {
            val overFailure = CompileFailure(listOf("make"), 2, "", "$sourcePath: original compile error!")
            assertEquals(diagnostic.length + 1, (overFailure.stdout + "\n" + overFailure.stderr).length)
            val failure = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(project, overFailure, emptyList())
            }
            assertEquals(
                "repair diagnostic contains ${diagnostic.length + 1} characters; limit=${diagnostic.length}",
                failure.message,
            )
            assertEquals(0, dispatches)
            assertEquals(0, validationCalls)
            assertContentEquals(source, project.resolve(sourcePath).readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second, graph.snapshot.nodes.size)
                assertEquals(baseline.third + 1, graph.snapshot.runs.size)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
                assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
            }
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact request byte limit and records one byte under as resource exhaustion`() {
        val exactRequestBytes = measuredActiveCompileRequestBytes()
        assertTrue(exactRequestBytes > 1)
        val exactBudget = RepairResourceBudget(
            maximumRegressionInputBytes = 1,
            maximumRequestBytes = exactRequestBytes,
        )
        activeAcpRepairConsumesReceiptBoundValidationResult(
            compileValid = true,
            resourceBudget = exactBudget,
        )

        val project = createProject(
            createRepairTempDirectory("repair-active-request-byte-over-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val source = project.resolve(sourcePath).readBytes()
        val overBudget = RepairResourceBudget(
            maximumRegressionInputBytes = 1,
            maximumRequestBytes = exactRequestBytes - 1,
        )
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, overBudget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("over-limit repair request must be refused before dispatch")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                error("over-limit repair request must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit repair request must be refused before dispatch")
            }

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                error("over-limit repair request must be refused before dispatch")
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
                validationCalls++
                error("over-limit repair request must be refused before validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("over-limit repair request must not reach compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("over-limit repair request must not reach rebuilding")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("over-limit repair request must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = overBudget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        try {
            val failure = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", "$sourcePath: original compile error"),
                    emptyList(),
                )
            }
            assertEquals(
                "repair request requires $exactRequestBytes bytes; limit=${exactRequestBytes - 1}",
                failure.message,
            )
            assertEquals(0, dispatches)
            assertEquals(0, validationCalls)
            assertContentEquals(source, project.resolve(sourcePath).readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, overBudget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second, graph.snapshot.nodes.size)
                assertEquals(baseline.third + 1, graph.snapshot.runs.size)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
                assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
            }
        } finally {
            loop.close()
        }
    }

    private fun measuredActiveCompileRequestBytes(): Long {
        val project = createProject(
            createRepairTempDirectory("repair-active-request-byte-measurement-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val failure = CompileFailure(listOf("make"), 2, "", "$sourcePath: original compile error")
        return ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val context = graph.selectContext("compile", failure.stdout + "\n" + failure.stderr)
            context.totalBytes + failure.toPrompt().toByteArray(Charsets.UTF_8).size +
                "<none>".toByteArray(Charsets.UTF_8).size +
                context.toContextJson().toByteArray(Charsets.UTF_8).size + 512L
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair admits exact stored blob bytes and removes one byte over candidate blob`() {
        val targetPath = "src/modules/reconstructed.c"
        val exactCandidateBytes = 4096L
        val maximumCandidateBytes = exactCandidateBytes + 1
        val initialSource = "int decomp_engine_main(void) { return 0; }\n"
        val sizingProject = createProject(
            createRepairTempDirectory("repair-active-stored-blob-sizing-").resolve("project"),
            reconstructedSource = initialSource,
        )
        val baselineBlobBytes = ModuleRevisionGraph.open(
            sizingProject,
            GeneratedCRepairIndexProfile,
        ).use { it.snapshot.storedBlobBytes }
        val storedBlobLimit = Math.addExact(baselineBlobBytes, exactCandidateBytes)
        val budget = RepairResourceBudget(
            maximumSourceFileBytes = maximumCandidateBytes,
            maximumSourceBytes = storedBlobLimit,
            maximumContextBytes = storedBlobLimit,
            maximumStagingBytes = storedBlobLimit,
            maximumPatchBytes = maximumCandidateBytes,
            maximumStoredBlobBytes = storedBlobLimit,
        )
        assertTrue(storedBlobLimit > maximumCandidateBytes)

        fun candidateOf(size: Int): ByteArray {
            val prefix = "/* active repair stored-blob byte boundary: "
            val suffix = " */\nint decomp_engine_main(void) { return 1; }\n"
            val paddingBytes = size - prefix.toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
            assertTrue(paddingBytes > 0)
            return (prefix + "s".repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8).also {
                assertEquals(size.toLong(), it.size.toLong())
            }
        }

        fun runCase(exact: Boolean) {
            val candidateBytes = if (exact) exactCandidateBytes else maximumCandidateBytes
            val candidate = candidateOf(candidateBytes.toInt())
            val project = createProject(
                createRepairTempDirectory(
                    if (exact) "repair-active-stored-blob-exact-" else "repair-active-stored-blob-over-",
                ).resolve("project"),
                reconstructedSource = initialSource,
            )
            val target = project.resolve(targetPath)
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val blobsPath = project.resolve("reports/repair-revisions/blobs")
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertEquals(baselineBlobBytes, graph.snapshot.storedBlobBytes)
                Triple(
                    graph.snapshot.headId,
                    graph.snapshot.nodes.size,
                    Files.newDirectoryStream(blobsPath).use { entries -> entries.map { it.fileName.toString() }.toSet() },
                )
            }
            val candidateDigest = sha256(candidate)
            assertTrue(sha256(acceptedSource) != candidateDigest)
            assertFalse(candidateDigest in baseline.third)
            val harnessMode = if (exact) {
                "repair-active-declared-role-stored-blob-exact"
            } else {
                "repair-active-declared-role-stored-blob-over"
            }
            val acp = AcpAgentHarnessTest().harness(harnessMode)
            var dispatches = 0
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    assertEquals(targetPath, request.accessPolicy.mutationAuthority?.grants?.single()?.path?.relativePath)
                    assertEquals(maximumCandidateBytes, request.accessPolicy.mutationAuthority?.grants?.single()?.maximumBytes)
                    assertEquals(setOf(AgentOperation.WRITE_FILE),
                        request.accessPolicy.mutationAuthority?.grants?.single()?.operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validationCalls = 0
            var validatedSourceRevisionSha256: String? = null
            val validationStop = IllegalStateException("exact stored-blob boundary reached validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertContentEquals(candidate, request.candidateSources.getValue(targetPath))
                    assertEquals(candidateDigest, sha256(request.candidateSources.getValue(targetPath)))
                    assertEquals(candidateBytes, request.candidateSources.getValue(targetPath).size.toLong())
                    validatedSourceRevisionSha256 = request.sourceRevisionSha256
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("stored-blob boundary must stop at immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("stored-blob boundary must stop at immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("stored-blob boundary must not run behavior validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "repair revision blobs require ${storedBlobLimit + 1} bytes; limit=$storedBlobLimit",
                        failure.message,
                    )
                }
            } finally {
                loop.close()
            }

            assertEquals(1, dispatches, "both limits are evaluated after the ACP candidate is dispatched")
            assertEquals(if (exact) 1 else 0, validationCalls)
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(baseline.first, snapshot.headId)
                assertEquals(baseline.second + 1, snapshot.nodes.size)
                assertEquals(
                    if (exact) storedBlobLimit else baselineBlobBytes,
                    snapshot.storedBlobBytes,
                )
                assertEquals(
                    if (exact) RepairRunStatus.VALIDATION_FAILED else RepairRunStatus.RESOURCE_EXHAUSTED,
                    snapshot.runs.last().status,
                )
                val rejected = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertTrue(binding.receiptReleaseComplete)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val outcome = receipt.getValue("outcome").jsonObject
                assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
                val result = outcome.getValue("result").jsonObject
                assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
                val changes = result.getValue("changes").jsonObject
                assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
                val change = changes.getValue("records").jsonArray.single().jsonObject
                assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                assertEquals(sha256(acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
                assertEquals(candidateDigest, change.getValue("afterSha256").jsonPrimitive.content)
                assertEquals(candidateBytes, change.getValue("sizeBytes").jsonPrimitive.content.toLong())
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                assertEquals(2, filesystem.getValue("recordCount").jsonPrimitive.int)
                val filesystemRecords = filesystem.getValue("records").jsonArray
                assertEquals(
                    listOf("fs/write_text_file", "fs/read_text_file").map {
                        sha256(it.toByteArray(Charsets.UTF_8))
                    },
                    filesystemRecords.map {
                        it.jsonObject.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content
                    },
                )
                assertTrue(filesystemRecords.all {
                    it.jsonObject.getValue("outcome").jsonPrimitive.content == "allowed" &&
                        it.jsonObject.getValue("reason").jsonPrimitive.content == "completed"
                })
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(
                    if (exact) decompengine.project.AcpChangeValidationStatus.FAILED
                    else decompengine.project.AcpChangeValidationStatus.NOT_RUN,
                    assessment.validationStatus,
                )
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                assertEquals(if (exact) validatedSourceRevisionSha256 else null, assessment.afterSha256)
            }
            val remainingBlobs = Files.newDirectoryStream(blobsPath).use { entries ->
                entries.map { it.fileName.toString() }.toSet()
            }
            if (exact) assertEquals(baseline.third + candidateDigest, remainingBlobs)
            else assertEquals(baseline.third, remainingBlobs, "over-limit candidate blob must be removed")
        }

        runCase(exact = true)
        runCase(exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair deduplicates shared candidate blobs before stored byte admission`() {
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        val failureText = "$firstPath: compiler error\n$secondPath: compiler error"
        val candidateSize = 4096
        val prefix = "/* shared content-addressed candidate: "
        val suffix = " */\nstatic int shared_candidate(void) { return 1; }\n"
        val paddingBytes = candidateSize - prefix.toByteArray(Charsets.UTF_8).size -
            suffix.toByteArray(Charsets.UTF_8).size
        assertTrue(paddingBytes > 0)
        val sharedCandidate = (prefix + "s".repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8)
        val distinctCandidate = sharedCandidate.copyOf().also { it[prefix.length] = 't'.code.toByte() }
        assertEquals(candidateSize, sharedCandidate.size)
        assertEquals(candidateSize, distinctCandidate.size)
        assertEquals(1, sharedCandidate.indices.count { sharedCandidate[it] != distinctCandidate[it] })
        val sharedDigest = sha256(sharedCandidate)
        val distinctDigest = sha256(distinctCandidate)
        assertTrue(sharedDigest != distinctDigest)

        fun paddedBaseline(prefixText: String, suffixText: String, size: Int): ByteArray {
            val padding = size - prefixText.toByteArray(Charsets.UTF_8).size - suffixText.toByteArray(Charsets.UTF_8).size
            assertTrue(padding > 0)
            return (prefixText + "b".repeat(padding) + suffixText).toByteArray(Charsets.UTF_8).also {
                assertEquals(size, it.size)
            }
        }
        val firstBefore = paddedBaseline(
            "/* reconstructed baseline */\n",
            "\nint decomp_engine_main(void) { return 0; }\n",
            8192,
        )
        val secondBefore = paddedBaseline(
            "/* secondary baseline */\n",
            "\nint secondary(void) { return 0; }\n",
            8192,
        )
        val acceptedPaths = listOf(
            "Makefile",
            "include/modules/reconstructed.h",
            "src/main.c",
            firstPath,
            secondPath,
        )

        fun seededProject(prefixName: String): Path = createProject(
            createRepairTempDirectory(prefixName).resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        ).also { project ->
            project.resolve(firstPath).writeBytes(firstBefore)
            project.resolve(secondPath).writeBytes(secondBefore)
        }

        val sizingProject = seededProject("repair-active-shared-blob-sizing-")
        val sizing = ModuleRevisionGraph.open(sizingProject, GeneratedCRepairIndexProfile).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
            val selected = graph.preflightStagingContext(context)
            Triple(
                graph.snapshot.storedBlobBytes,
                Files.newDirectoryStream(sizingProject.resolve("reports/repair-revisions/blobs")).use { entries ->
                    entries.map { it.fileName.toString() }.toSet()
                },
                selected,
            )
        }
        assertTrue(sharedDigest !in sizing.second)
        assertTrue(distinctDigest !in sizing.second)
        val exactStoredLimit = Math.addExact(sizing.first, candidateSize.toLong())

        fun runCase(shared: Boolean) {
            data class Baseline(
                val head: String,
                val nodes: Int,
                val runs: Int,
                val blobNames: Set<String>,
                val selectedFiles: Map<String, ByteArray>,
            )
            val project = seededProject(
                if (shared) "repair-active-shared-blob-equality-" else "repair-active-distinct-blob-over-",
            )
            val acceptedFiles = acceptedPaths.associateWith { project.resolve(it).readBytes() }
            assertContentEquals(firstBefore, acceptedFiles.getValue(firstPath))
            assertContentEquals(secondBefore, acceptedFiles.getValue(secondPath))
            val sourceBytes = acceptedFiles.values.fold(0L) { total, bytes ->
                Math.addExact(total, bytes.size.toLong())
            }
            val selectedBytes = sizing.third.values.fold(0L) { total, bytes ->
                Math.addExact(total, bytes.size.toLong())
            }
            val sourceBudget = maxOf(sourceBytes, selectedBytes)
            assertTrue(exactStoredLimit >= sourceBudget,
                "stored-blob budget must also leave source and selected-context budgets nonbinding")
            val budget = RepairResourceBudget(
                maximumSourceFileBytes = 16 * 1024,
                maximumSourceBytes = sourceBudget,
                maximumContextBytes = sourceBudget,
                maximumStagingBytes = sourceBudget,
                maximumPatchFiles = 2,
                maximumPatchBytes = 16 * 1024,
                maximumStoredBlobBytes = exactStoredLimit,
            )
            assertTrue(budget.maximumSourceFileBytes > maxOf(firstBefore.size, secondBefore.size, candidateSize))
            assertTrue(budget.maximumPatchBytes > candidateSize.toLong() * 2L)
            assertTrue(budget.maximumStagingBytes >= selectedBytes)

            val blobsPath = project.resolve("reports/repair-revisions/blobs")
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertEquals(sizing.first, graph.snapshot.storedBlobBytes)
                val context = graph.selectContext("compile", failureText)
                assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
                val selected = graph.preflightStagingContext(context)
                assertEquals(sizing.third.keys, selected.keys)
                sizing.third.forEach { (path, bytes) -> assertContentEquals(bytes, selected.getValue(path), path) }
                Baseline(
                    graph.snapshot.headId,
                    graph.snapshot.nodes.size,
                    graph.snapshot.runs.size,
                    Files.newDirectoryStream(blobsPath).use { entries -> entries.map { it.fileName.toString() }.toSet() },
                    selected,
                )
            }
            assertEquals(sizing.second, baseline.blobNames)
            val expectedSecond = if (shared) sharedCandidate else distinctCandidate
            val expectedSecondDigest = if (shared) sharedDigest else distinctDigest
            val mode = if (shared) {
                "repair-active-declared-role-stored-blob-shared"
            } else {
                "repair-active-declared-role-stored-blob-distinct"
            }
            val acp = AcpAgentHarnessTest().harness(mode)
            var dispatches = 0
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    assertEquals(baseline.selectedFiles.keys, initialFiles.keys)
                    baseline.selectedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, initialFiles.getValue(path), path) }
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                    assertEquals(setOf(firstPath, secondPath), authority.grants.map { it.path.relativePath }.toSet())
                    assertTrue(authority.grants.all {
                        it.operations == setOf(AgentOperation.WRITE_FILE) &&
                            it.maximumBytes == budget.maximumSourceFileBytes
                    })
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validationCalls = 0
            var validatedRevisionSha256: String? = null
            val validationStop = IllegalStateException("shared stored-blob equality reached validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    if (!shared) error("distinct stored blobs must be refused before validation")
                    assertEquals(acceptedFiles.keys, request.candidateSourcePaths.toSet())
                    acceptedFiles.filterKeys { it != firstPath && it != secondPath }.forEach { (path, bytes) ->
                        assertContentEquals(bytes, request.candidateSources.getValue(path), path)
                    }
                    assertContentEquals(sharedCandidate, request.candidateSources.getValue(firstPath))
                    assertContentEquals(sharedCandidate, request.candidateSources.getValue(secondPath))
                    val candidateRevision = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                    assertEquals(candidateRevision, request.sourceRevisionSha256)
                    validatedRevisionSha256 = candidateRevision
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("stored-blob deduplication must stop at the immutable candidate validator")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("stored-blob deduplication must stop at the immutable candidate validator")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("stored-blob deduplication must not run behavior validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (shared) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", failureText),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", failureText),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "repair revision blobs require ${sizing.first + candidateSize * 2L} bytes; limit=$exactStoredLimit",
                        failure.message,
                    )
                }
            } finally {
                loop.close()
            }

            assertEquals(1, dispatches)
            assertEquals(if (shared) 1 else 0, validationCalls)
            acceptedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(baseline.head, snapshot.headId)
                assertEquals(baseline.nodes + 1, snapshot.nodes.size)
                assertEquals(baseline.runs + 1, snapshot.runs.size)
                assertEquals(
                    if (shared) exactStoredLimit else sizing.first,
                    snapshot.storedBlobBytes,
                )
                assertEquals(
                    if (shared) RepairRunStatus.VALIDATION_FAILED else RepairRunStatus.RESOURCE_EXHAUSTED,
                    snapshot.runs.last().status,
                )
                val rejected = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertTrue(binding.receiptReleaseComplete)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)

                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
                assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
                val changes = result.getValue("changes").jsonObject
                assertEquals(2, changes.getValue("observedCount").jsonPrimitive.int)
                val changeRecords = changes.getValue("records").jsonArray.map { it.jsonObject }
                assertEquals(listOf(firstPath, secondPath).map { sha256(it.toByteArray(Charsets.UTF_8)) },
                    changeRecords.map {
                        it.getValue("relativePath").jsonObject.getValue("sha256").jsonPrimitive.content
                    })
                val expectedBefore = mapOf(firstPath to firstBefore, secondPath to secondBefore)
                val expectedAfter = mapOf(firstPath to sharedCandidate, secondPath to expectedSecond)
                changeRecords.zip(listOf(firstPath, secondPath)).forEach { (change, path) ->
                    assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                    assertEquals(sha256(expectedBefore.getValue(path)), change.getValue("beforeSha256").jsonPrimitive.content)
                    assertEquals(sha256(expectedAfter.getValue(path)), change.getValue("afterSha256").jsonPrimitive.content)
                    assertEquals(candidateSize.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())
                }
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
                assertEquals(4, filesystem.getValue("recordCount").jsonPrimitive.int)
                assertEquals(4, records.size)
                assertEquals(
                    listOf("fs/write_text_file", "fs/write_text_file", "fs/read_text_file", "fs/read_text_file")
                        .map { sha256(it.toByteArray(Charsets.UTF_8)) },
                    records.map { it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content },
                )
                assertEquals(listOf(firstPath, secondPath, firstPath, secondPath).map {
                    sha256(it.toByteArray(Charsets.UTF_8))
                }, records.map {
                    it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                        .getValue("sha256").jsonPrimitive.content
                })
                assertTrue(records.all {
                    it.getValue("outcome").jsonPrimitive.content == "allowed" &&
                        it.getValue("reason").jsonPrimitive.content == "completed"
                })
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(
                    if (shared) decompengine.project.AcpChangeValidationStatus.FAILED
                    else decompengine.project.AcpChangeValidationStatus.NOT_RUN,
                    assessment.validationStatus,
                )
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                assertEquals(if (shared) validatedRevisionSha256 else null, assessment.afterSha256)
            }
            val finalBlobNames = Files.newDirectoryStream(blobsPath).use { entries ->
                entries.map { it.fileName.toString() }.toSet()
            }
            if (shared) {
                assertEquals(baseline.blobNames + sharedDigest, finalBlobNames)
            } else {
                assertEquals(baseline.blobNames, finalBlobNames, "both unreferenced candidate blobs must be removed")
            }
        }

        runCase(shared = true)
        runCase(shared = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact generated C indexed entity count and refuses one below before dispatch`() {
        val model = RecoveredProgramModel(
            inputSha256 = "d".repeat(64),
            functions = listOf(
                RecoveredFunction(
                    id = "fn_reconstructed",
                    name = "reconstructed_main",
                    address = 0x1000UL,
                    prototype = "int reconstructed_main(void)",
                    decompiledC = "int reconstructed_main(void) { return global_counter; }",
                    referencedGlobals = setOf("global_counter"),
                ),
            ),
            globals = listOf(RecoveredGlobal("global_counter", "global_counter", 0x2000UL, "int", "0")),
            types = listOf(
                RecoveredType(
                    id = "type_counter",
                    declaration = "typedef struct Counter { int value; } Counter;",
                    sourceAddress = 0x3000UL,
                ),
            ),
        )
        val candidate = "/* indexed entity boundary candidate */\nint reconstructed_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val targetPath = "src/modules/reconstructed.c"

        fun budget(entityLimit: Int) = RepairResourceBudget(maximumIndexedEntities = entityLimit)

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            SourceTreeGenerator.generate(model, project)
            val wire = Json.parseToJsonElement(project.resolve("reports/program_model.json").readText()).jsonObject
            assertEquals(1, wire.getValue("functions").jsonArray.size)
            assertEquals(1, wire.getValue("globals").jsonArray.size)
            assertEquals(1, wire.getValue("types").jsonArray.size)
            val plan = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText()).jsonObject
            assertEquals(targetPath, plan.getValue("modules").jsonArray.single().jsonObject
                .getValue("sourcePath").jsonPrimitive.content)
            return project
        }

        fun runScenario(entityLimit: Int, exact: Boolean) {
            val project = project(
                if (exact) "repair-active-indexed-entities-exact-" else "repair-active-indexed-entities-over-",
            )
            val admittedLayout = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            assertEquals(3, admittedLayout.entities.size)
            assertTrue(targetPath in admittedLayout.editablePaths)
            val acceptedSources = admittedLayout.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val planBefore = project.resolve("reports/module_plan.json").readBytes()
            val modelBefore = project.resolve("reports/program_model.json").readBytes()
            val repairBudget = budget(entityLimit)
            val baseline = if (exact) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { it.snapshot }
            } else null

            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-entities")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val mutationAuthority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val implementationGrant = mutationAuthority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), implementationGrant.operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("indexed entity equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    acceptedSources.forEach { (path, beforeBytes) ->
                        assertContentEquals(
                            if (path == targetPath) candidate else beforeBytes,
                            request.candidateSources.getValue(path),
                            path,
                        )
                    }
                    assertEquals(baseline!!.indexSha256, request.indexSha256)
                    assertEquals(
                        GeneratedCRepairIndexProfile.configurationSha256(repairBudget),
                        request.profileSha256,
                    )
                    assertEquals(
                        repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("indexed entity admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("indexed entity admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("indexed entity admission test must use immutable candidate validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )

            if (exact) {
                val failure = assertFailsWith<IllegalStateException> {
                    loop.repairCompileError(
                        project,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                        emptyList(),
                    )
                }
                assertSame(validationStop, failure)
                assertEquals(1, dispatches)
                assertEquals(1, validationCalls)
                val receipt = assertNotNull(capturedReceipt)
                val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                assertNotNull(evidence.completeExecutionEvidence)
                val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                val change = result.changes.single()
                assertEquals(targetPath, change.path.relativePath)
                assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                assertEquals(sha256(candidate), change.afterSha256)
                assertEquals(candidate.size.toLong(), change.sizeBytes)
                acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(baseline!!.headId, graph.snapshot.headId)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    assertEquals(1, graph.snapshot.runs.size)
                }
            } else {
                val failure = assertFailsWith<RepairBudgetExceededException> {
                    loop.repairCompileError(
                        project,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                        emptyList(),
                    )
                }
                assertEquals("generated C model has 3 indexed entities; limit=2", failure.message)
                assertEquals(0, dispatches)
                assertEquals(0, validationCalls)
                acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                assertContentEquals(planBefore, project.resolve("reports/module_plan.json").readBytes())
                assertContentEquals(modelBefore, project.resolve("reports/program_model.json").readBytes())
                val graphPath = project.resolve("reports/repair-revisions/graph.json")
                if (graphPath.exists()) {
                    val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                    assertEquals(JsonNull, state.getValue("pending"))
                    assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                    assertTrue(state.getValue("runs").jsonArray.isEmpty())
                }
                assertFalse(project.resolve("reports/repair_history.json").exists())
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(3)).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(1, graph.snapshot.nodes.size)
                    assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                    assertTrue(graph.snapshot.runs.isEmpty())
                }
            }
        }

        runScenario(entityLimit = 3, exact = true)
        runScenario(entityLimit = 2, exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact aggregate generated C index evidence bytes and refuses one below before dispatch`() {
        val model = RecoveredProgramModel(
            inputSha256 = "d".repeat(64),
            functions = listOf(
                RecoveredFunction(
                    id = "fn_reconstructed",
                    name = "reconstructed_main",
                    address = 0x1000UL,
                    prototype = "int reconstructed_main(void)",
                    decompiledC = "int reconstructed_main(void) { return global_counter; }",
                    referencedGlobals = setOf("global_counter"),
                ),
            ),
            globals = listOf(RecoveredGlobal("global_counter", "global_counter", 0x2000UL, "int", "0")),
            types = listOf(
                RecoveredType(
                    id = "type_counter",
                    declaration = "typedef struct Counter { int value; } Counter;",
                    sourceAddress = 0x3000UL,
                ),
            ),
        )
        val targetPath = "src/modules/reconstructed.c"
        val candidate = "/* indexed entity boundary candidate */\nint reconstructed_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val trailingJsonWhitespace = ByteArray(32 * 1024) { ' '.code.toByte() }
        var exactEvidenceLimit = 0L
        var planBytesAtExactLimit = 0
        var modelBytesAtExactLimit = 0

        fun budget(evidenceBytes: Long) = RepairResourceBudget(maximumIndexEvidenceBytes = evidenceBytes)

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            SourceTreeGenerator.generate(model, project)
            val modelPath = project.resolve("reports/program_model.json")
            Files.write(modelPath, Files.readAllBytes(modelPath) + trailingJsonWhitespace)
            val wire = Json.parseToJsonElement(modelPath.readText()).jsonObject
            assertEquals(1, wire.getValue("functions").jsonArray.size)
            assertEquals(1, wire.getValue("globals").jsonArray.size)
            assertEquals(1, wire.getValue("types").jsonArray.size)
            val plan = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText()).jsonObject
            assertEquals(
                targetPath,
                plan.getValue("modules").jsonArray.single().jsonObject.getValue("sourcePath").jsonPrimitive.content,
            )
            return project
        }

        fun runExactLimit() {
            val project = project("repair-active-index-evidence-exact-")
            val planPath = project.resolve("reports/module_plan.json")
            val modelPath = project.resolve("reports/program_model.json")
            val planBefore = Files.readAllBytes(planPath)
            val modelBefore = Files.readAllBytes(modelPath)
            planBytesAtExactLimit = planBefore.size
            modelBytesAtExactLimit = modelBefore.size
            exactEvidenceLimit = planBefore.size.toLong() + modelBefore.size.toLong()
            assertTrue(planBefore.isNotEmpty())
            assertTrue(modelBefore.size > trailingJsonWhitespace.size)
            assertTrue(planBefore.size.toLong() <= exactEvidenceLimit - 1)
            assertTrue(modelBefore.size.toLong() > exactEvidenceLimit - 1 - planBefore.size)

            val repairBudget = budget(exactEvidenceLimit)
            val layout = GeneratedCRepairIndexProfile.resolve(project, repairBudget)
            assertTrue("Makefile" in layout.sourcePaths)
            assertTrue(targetPath in layout.sourcePaths)
            assertEquals(3, layout.entities.size)
            assertTrue(targetPath in layout.editablePaths)
            val acceptedSources = layout.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { it.snapshot }
            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-entities")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val grant = authority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("index evidence byte equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    assertContentEquals(candidate, request.candidateSources.getValue(targetPath))
                    assertEquals(baseline.indexSha256, request.indexSha256)
                    assertEquals(
                        GeneratedCRepairIndexProfile.configurationSha256(repairBudget),
                        request.profileSha256,
                    )
                    assertEquals(
                        repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("index evidence admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("index evidence admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("index evidence admission test must use immutable candidate validation")
            }
            val history = RepairHistory(project.resolve("reports/repair_history.json"))
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = history,
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                val failure = assertFailsWith<IllegalStateException> {
                    loop.repairCompileError(
                        project,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                        emptyList(),
                    )
                }
                assertSame(validationStop, failure)
                assertEquals(1, dispatches)
                assertEquals(1, validationCalls)
                val receipt = assertNotNull(capturedReceipt)
                val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                assertNotNull(evidence.completeExecutionEvidence)
                val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                val change = result.changes.single()
                assertEquals(targetPath, change.path.relativePath)
                assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                assertEquals(sha256(candidate), change.afterSha256)
                assertEquals(candidate.size.toLong(), change.sizeBytes)
                assertEquals(exactEvidenceLimit, planBefore.size.toLong() + modelBefore.size.toLong())
                assertContentEquals(planBefore, Files.readAllBytes(planPath))
                assertContentEquals(modelBefore, Files.readAllBytes(modelPath))
                acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(baseline.headId, graph.snapshot.headId)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    assertEquals(1, graph.snapshot.runs.size)
                }
            } finally {
                loop.close()
            }
        }

        fun runOneByteUnder() {
            val project = project("repair-active-index-evidence-under-")
            val planBefore = Files.readAllBytes(project.resolve("reports/module_plan.json"))
            val modelBefore = Files.readAllBytes(project.resolve("reports/program_model.json"))
            assertEquals(planBytesAtExactLimit, planBefore.size)
            assertEquals(modelBytesAtExactLimit, modelBefore.size)
            assertEquals(exactEvidenceLimit, planBefore.size.toLong() + modelBefore.size.toLong())
            assertTrue(planBefore.size.toLong() <= exactEvidenceLimit - 1)
            assertEquals(modelBefore.size.toLong(), exactEvidenceLimit - planBefore.size.toLong())
            assertTrue(modelBefore.size > 1)

            val repairBudget = budget(exactEvidenceLimit - 1)
            val layout = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            assertTrue("Makefile" in layout.sourcePaths)
            assertTrue(targetPath in layout.sourcePaths)
            assertEquals(3, layout.entities.size)
            val acceptedSources = layout.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-entities")
            var dispatches = 0
            var validationCalls = 0
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    error("one-under index evidence admission must refuse before candidate validation")
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("one-under index evidence admission must refuse before compilation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("one-under index evidence admission must refuse before compilation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("one-under index evidence admission must refuse before behavior validation")
            }
            val historyPath = project.resolve("reports/repair_history.json")
            val history = RepairHistory(historyPath)
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.execute(request, onEvent)
                }
                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.executeCaptured(request, initialFiles, output, onEvent)
                }
                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    return acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
                }
                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = history,
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                val failure = assertFailsWith<RepairBudgetExceededException> {
                    loop.repairCompileError(
                        project,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                        emptyList(),
                    )
                }
                assertEquals(
                    "stable file-read target reports/program_model.json has ${modelBefore.size} bytes; " +
                        "limit=${modelBefore.size - 1}",
                    failure.message,
                )
                assertEquals(0, dispatches)
                assertEquals(0, validationCalls)
                assertContentEquals(planBefore, Files.readAllBytes(project.resolve("reports/module_plan.json")))
                assertContentEquals(modelBefore, Files.readAllBytes(project.resolve("reports/program_model.json")))
                acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                assertFalse(historyPath.exists())
                val graphPath = project.resolve("reports/repair-revisions/graph.json")
                if (graphPath.exists()) {
                    val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                    assertEquals(JsonNull, state.getValue("pending"))
                    assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                    assertTrue(state.getValue("runs").jsonArray.isEmpty())
                }
            } finally {
                loop.close()
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(exactEvidenceLimit)).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(1, graph.snapshot.nodes.size)
                assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                assertTrue(graph.snapshot.runs.isEmpty())
            }
            assertFalse(historyPath.exists())
        }

        runExactLimit()
        runOneByteUnder()
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact generated C structural entries and refuses one below before dispatch`() {
        val targetPath = "src/modules/reconstructed.c"
        val structuralEntryLimit = 65L
        val candidate =
            "/* indexed entity boundary candidate */\nint reconstructed_main(void) { return 1; }\n"
                .toByteArray(Charsets.UTF_8)
        val model = RecoveredProgramModel(
            inputSha256 = "d".repeat(64),
            functions = listOf(
                RecoveredFunction(
                    id = "fn_reconstructed",
                    name = "reconstructed_main",
                    address = 0x1000UL,
                    prototype = "int reconstructed_main(void)",
                    decompiledC = "int reconstructed_main(void) { return 41; }",
                ),
            ),
        )

        fun budget(dependencyLimit: Long) = RepairResourceBudget(maximumDependencyEdges = dependencyLimit)

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            SourceTreeGenerator.generate(model, project)
            val planPath = project.resolve("reports/module_plan.json")
            val plan = Json.parseToJsonElement(planPath.readText()).jsonObject
            val module = plan.getValue("modules").jsonArray.single().jsonObject
            assertEquals(targetPath, module.getValue("sourcePath").jsonPrimitive.content)
            assertEquals(1, module.getValue("functionIds").jsonArray.size)
            assertTrue(module.getValue("globalIds").jsonArray.isEmpty())
            assertTrue(module.getValue("typeIds").jsonArray.isEmpty())
            val boundaryEvidence = JsonArray((0 until 64).map { JsonPrimitive("boundary-evidence-$it") })
            val rewrittenModule = JsonObject(module.toMutableMap().apply {
                put("boundaryEvidence", boundaryEvidence)
            })
            val rewrittenPlan = JsonObject(plan.toMutableMap().apply {
                put("modules", JsonArray(listOf(rewrittenModule)))
            })
            Files.writeString(planPath, rewrittenPlan.toString())
            val writtenPlan = Json.parseToJsonElement(planPath.readText()).jsonObject
            val writtenModule = writtenPlan.getValue("modules").jsonArray.single().jsonObject
            val modelWire = Json.parseToJsonElement(project.resolve("reports/program_model.json").readText()).jsonObject
            val function = modelWire.getValue("functions").jsonArray.single().jsonObject
            val measuredStructuralEntries =
                writtenModule.getValue("functionIds").jsonArray.size +
                    writtenModule.getValue("globalIds").jsonArray.size +
                    writtenModule.getValue("typeIds").jsonArray.size +
                    writtenModule.getValue("boundaryEvidence").jsonArray.size +
                    writtenPlan.getValue("dependencyCycles").jsonArray.sumOf { it.jsonArray.size } +
                    function.getValue("calls").jsonArray.size +
                    function.getValue("referencedGlobals").jsonArray.size +
                    function.getValue("strings").jsonArray.size
            assertEquals(65, measuredStructuralEntries)
            return project
        }

        fun runScenario(dependencyLimit: Long, exact: Boolean) {
            val project = project(
                if (exact) "repair-active-structural-entries-exact-" else "repair-active-structural-entries-under-",
            )
            val repairBudget = budget(dependencyLimit)
            val resolved = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            assertEquals(1, resolved.modules.size)
            assertEquals(1, resolved.modules.single().entityIds.size)
            assertTrue(resolved.sourcePaths.size < 64, "include-closure traversal must remain below the refused limit")
            val includeAndDeclaredDependencyEdges =
                resolved.pathDependencies.values.sumOf { it.size.toLong() } +
                    resolved.modules.sumOf { it.dependencyModuleIds.size.toLong() } +
                    resolved.entities.sumOf { it.dependencyEntityIds.size.toLong() }
            assertTrue(includeAndDeclaredDependencyEdges < 64, "other dependency-edge dimensions must have headroom")
            assertTrue(targetPath in resolved.editablePaths)
            val acceptedSources = resolved.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val planBefore = project.resolve("reports/module_plan.json").readBytes()
            val modelBefore = project.resolve("reports/program_model.json").readBytes()
            val baseline = if (exact) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { it.snapshot }
            } else null

            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-entities")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.execute(request, onEvent)
                }

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.executeCaptured(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    return acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val grant = authority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("structural entry equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    acceptedSources.forEach { (path, beforeBytes) ->
                        assertContentEquals(
                            if (path == targetPath) candidate else beforeBytes,
                            request.candidateSources.getValue(path),
                            path,
                        )
                    }
                    assertEquals(baseline!!.indexSha256, request.indexSha256)
                    assertEquals(
                        GeneratedCRepairIndexProfile.configurationSha256(repairBudget),
                        request.profileSha256,
                    )
                    assertEquals(
                        repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("structural-entry admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("structural-entry admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("structural-entry admission test must use immutable candidate validation")
            }
            val historyPath = project.resolve("reports/repair_history.json")
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(historyPath),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                    assertEquals(1, dispatches)
                    assertEquals(1, validationCalls)
                    val receipt = assertNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                    assertNotNull(evidence.completeExecutionEvidence)
                    val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                    assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                    val change = result.changes.single()
                    assertEquals(targetPath, change.path.relativePath)
                    assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                    assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                    assertEquals(sha256(candidate), change.afterSha256)
                    assertEquals(candidate.size.toLong(), change.sizeBytes)
                    assertEquals(2, evidence.filesystemAudit.size)
                    assertTrue(evidence.filesystemAudit.all {
                        it.outcome == decompengine.acp.AcpFilesystemAuditOutcome.ALLOWED &&
                            it.reason == decompengine.acp.AcpFilesystemAuditReason.COMPLETED
                    })
                    acceptedSources.forEach { (path, bytes) ->
                        assertContentEquals(bytes, project.resolve(path).readBytes(), path)
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(baseline!!.headId, graph.snapshot.headId)
                        assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                        assertEquals(1, graph.snapshot.runs.size)
                    }
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "generated C module boundary evidence structural entries exceed 64 entries",
                        failure.message,
                    )
                    assertEquals(0, dispatches)
                    assertEquals(0, validationCalls)
                    acceptedSources.forEach { (path, bytes) ->
                        assertContentEquals(bytes, project.resolve(path).readBytes(), path)
                    }
                    assertContentEquals(planBefore, project.resolve("reports/module_plan.json").readBytes())
                    assertContentEquals(modelBefore, project.resolve("reports/program_model.json").readBytes())
                    assertFalse(historyPath.exists())
                    val graphPath = project.resolve("reports/repair-revisions/graph.json")
                    if (graphPath.exists()) {
                        val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                        assertEquals(JsonNull, state.getValue("pending"))
                        assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                        assertTrue(state.getValue("runs").jsonArray.isEmpty())
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(structuralEntryLimit)).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(1, graph.snapshot.nodes.size)
                        assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                        assertTrue(graph.snapshot.runs.isEmpty())
                    }
                }
            } finally {
                loop.close()
            }
        }

        runScenario(dependencyLimit = structuralEntryLimit, exact = true)
        runScenario(dependencyLimit = structuralEntryLimit - 1, exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact generated C include closure traversal and refuses one below before dispatch`() {
        val targetPath = "src/modules/reconstructed.c"
        val sharedHeaderPath = "include/decomp_types.h"
        val original = "#include \"decomp_types.h\"\nint reconstructed_value(void) { return BOUNDARY_VALUE; }\n"
        val candidate = "#include \"decomp_types.h\"\nint reconstructed_value(void) { return BOUNDARY_VALUE + 1; }\n"

        fun budget(edgeLimit: Long) = RepairResourceBudget(maximumDependencyEdges = edgeLimit)

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            project.resolve("include").createDirectories()
            project.resolve("src/modules").createDirectories()
            project.resolve("reports").createDirectories()
            project.resolve("Makefile").writeText(
                "CC ?= cc\nCFLAGS ?= -Iinclude\nall:\n\t\$(CC) \$(CFLAGS) -c $targetPath -o build/reconstructed.o\n",
            )
            project.resolve(sharedHeaderPath).writeText(
                "#ifndef DECOMP_TYPES_H\n#define DECOMP_TYPES_H\n#define BOUNDARY_VALUE 41\n#endif\n",
            )
            project.resolve(targetPath).writeText(original)
            return project
        }

        fun runScenario(edgeLimit: Long, exact: Boolean) {
            val project = project(if (exact) "repair-active-include-closure-exact-" else "repair-active-include-closure-under-")
            val admissionLimit = budget(edgeLimit)
            val layout = GeneratedCRepairIndexProfile.resolve(project, admissionLimit)
            assertEquals(listOf("Makefile", sharedHeaderPath, targetPath), layout.sourcePaths)
            assertEquals(listOf(sharedHeaderPath), layout.pathDependencies.getValue(targetPath))
            assertTrue(targetPath in layout.editablePaths)
            assertTrue(project.resolve(sharedHeaderPath).readText().contains("#define BOUNDARY_VALUE 41"))
            val acceptedSources = layout.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val baseline = if (exact) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, admissionLimit).use { it.snapshot }
            } else null

            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-include-closure")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val grant = authority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("include closure equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    assertContentEquals(candidate.toByteArray(Charsets.UTF_8), request.candidateSources.getValue(targetPath))
                    assertContentEquals(acceptedSources.getValue(sharedHeaderPath), request.candidateSources.getValue(sharedHeaderPath))
                    assertEquals(baseline!!.indexSha256, request.indexSha256)
                    assertEquals(GeneratedCRepairIndexProfile.configurationSha256(admissionLimit), request.profileSha256)
                    assertEquals(repairCandidateSourceSha256(request.candidateSources), request.sourceRevisionSha256)
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("include-closure admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("include-closure admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("include-closure admission test must use immutable candidate validation")
            }
            val history = RepairHistory(project.resolve("reports/repair_history.json"))
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = history,
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = admissionLimit,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                    assertEquals(1, dispatches)
                    assertEquals(1, validationCalls)
                    val receipt = assertNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                    assertNotNull(evidence.completeExecutionEvidence)
                    val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                    assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                    val change = result.changes.single()
                    assertEquals(targetPath, change.path.relativePath)
                    assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                    assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                    assertEquals(sha256(candidate.toByteArray(Charsets.UTF_8)), change.afterSha256)
                    assertEquals(candidate.toByteArray(Charsets.UTF_8).size.toLong(), change.sizeBytes)
                    assertEquals(2, evidence.filesystemAudit.size)
                    assertTrue(evidence.filesystemAudit.all {
                        it.outcome == decompengine.acp.AcpFilesystemAuditOutcome.ALLOWED &&
                            it.reason == decompengine.acp.AcpFilesystemAuditReason.COMPLETED
                    })
                    acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, admissionLimit).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(baseline!!.headId, graph.snapshot.headId)
                        assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                        assertEquals(1, graph.snapshot.runs.size)
                    }
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals("repair include-closure traversal exceeds 1 entries", failure.message)
                    assertEquals(0, dispatches)
                    assertEquals(0, validationCalls)
                    acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                    assertFalse(project.resolve("reports/repair_history.json").exists())
                    val graphPath = project.resolve("reports/repair-revisions/graph.json")
                    if (graphPath.exists()) {
                        val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                        assertEquals(JsonNull, state.getValue("pending"))
                        assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                        assertTrue(state.getValue("runs").jsonArray.isEmpty())
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(2)).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(1, graph.snapshot.nodes.size)
                        assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                        assertTrue(graph.snapshot.runs.isEmpty())
                    }
                }
            } finally {
                loop.close()
            }
        }

        runScenario(edgeLimit = 2, exact = true)
        runScenario(edgeLimit = 1, exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact generated C indexed module count including fallback modules`() {
        val targetPath = "src/modules/reconstructed.c"
        val siblingPath = "src/modules/secondary.c"
        val originalTarget = "int reconstructed_value(void) { return 41; }\n"
        val candidateTarget = "int reconstructed_value(void) { return 42; }\n"
        val siblingSource = "int secondary_value(void) { return 7; }\n"

        fun budget(moduleLimit: Int) = RepairResourceBudget(
            maximumIndexedModules = moduleLimit,
            maximumContextModules = 1,
        )

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            project.resolve("src/modules").createDirectories()
            project.resolve("reports").createDirectories()
            project.resolve("Makefile").writeText(
                "CC ?= cc\nall:\n\t\$(CC) -c $targetPath -o build/reconstructed.o\n",
            )
            project.resolve(targetPath).writeText(originalTarget)
            project.resolve(siblingPath).writeText(siblingSource)
            assertFalse(project.resolve("reports/module_plan.json").exists())
            assertFalse(project.resolve("reports/program_model.json").exists())
            return project
        }

        fun runScenario(moduleLimit: Int, exact: Boolean) {
            val project = project(
                if (exact) "repair-active-indexed-modules-exact-" else "repair-active-indexed-modules-under-",
            )
            val resolved = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            assertTrue(resolved.modules.isEmpty(), "fixture must use fallback module mappings")
            assertEquals(setOf(targetPath, siblingPath), resolved.fallbackModuleIdsByPath.keys)
            assertEquals(2, resolved.fallbackModuleIdsByPath.values.toSet().size)
            assertTrue(targetPath in resolved.editablePaths)
            assertTrue(siblingPath in resolved.sourcePaths)
            assertEquals(listOf("Makefile", targetPath, siblingPath), resolved.sourcePaths)
            val acceptedSources = resolved.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val repairBudget = budget(moduleLimit)
            val baseline = if (exact) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { it.snapshot }
            } else null

            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-modules")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.execute(request, onEvent)
                }

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.executeCaptured(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    return acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val grant = authority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    assertFalse(authority.grants.any { it.path.relativePath == siblingPath })
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("indexed module equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    acceptedSources.forEach { (path, beforeBytes) ->
                        assertContentEquals(
                            if (path == targetPath) candidateTarget.toByteArray(Charsets.UTF_8) else beforeBytes,
                            request.candidateSources.getValue(path),
                            path,
                        )
                    }
                    assertEquals(baseline!!.indexSha256, request.indexSha256)
                    assertEquals(
                        GeneratedCRepairIndexProfile.configurationSha256(repairBudget),
                        request.profileSha256,
                    )
                    assertEquals(
                        repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("indexed module admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("indexed module admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("indexed module admission test must use immutable candidate validation")
            }
            val historyPath = project.resolve("reports/repair_history.json")
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(historyPath),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                    assertEquals(1, dispatches)
                    assertEquals(1, validationCalls)
                    val receipt = assertNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                    assertNotNull(evidence.completeExecutionEvidence)
                    val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                    assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                    val change = result.changes.single()
                    assertEquals(targetPath, change.path.relativePath)
                    assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                    assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                    assertEquals(sha256(candidateTarget.toByteArray(Charsets.UTF_8)), change.afterSha256)
                    assertEquals(candidateTarget.toByteArray(Charsets.UTF_8).size.toLong(), change.sizeBytes)
                    assertEquals(2, evidence.filesystemAudit.size)
                    assertTrue(evidence.filesystemAudit.all {
                        it.outcome == decompengine.acp.AcpFilesystemAuditOutcome.ALLOWED &&
                            it.reason == decompengine.acp.AcpFilesystemAuditReason.COMPLETED
                    })
                    acceptedSources.forEach { (path, bytes) ->
                        assertContentEquals(bytes, project.resolve(path).readBytes(), path)
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(baseline!!.headId, graph.snapshot.headId)
                        assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                        assertEquals(1, graph.snapshot.runs.size)
                    }
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals("repair index has 2 modules; limit=1", failure.message)
                    assertEquals(0, dispatches)
                    assertEquals(0, validationCalls)
                    acceptedSources.forEach { (path, bytes) ->
                        assertContentEquals(bytes, project.resolve(path).readBytes(), path)
                    }
                    assertFalse(historyPath.exists())
                    val graphPath = project.resolve("reports/repair-revisions/graph.json")
                    if (graphPath.exists()) {
                        val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                        assertEquals(JsonNull, state.getValue("pending"))
                        assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                        assertTrue(state.getValue("runs").jsonArray.isEmpty())
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(2)).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(1, graph.snapshot.nodes.size)
                        assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                        assertTrue(graph.snapshot.runs.isEmpty())
                    }
                }
            } finally {
                loop.close()
            }
        }

        runScenario(moduleLimit = 2, exact = true)
        runScenario(moduleLimit = 1, exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair charges discovery directories inside excluded repair trees`() {
        val targetPath = "src/modules/reconstructed.c"
        val excludedSourcePath = "src/modules/stale.repair/nested/ignored.c"
        val originalTarget = "int reconstructed_value(void) { return 41; }\n"
        val candidateTarget = "int reconstructed_value(void) { return 42; }\n"
        val excludedSource = "int ignored_value(void) { return 99; }\n"

        fun budget(directoryLimit: Int) = RepairResourceBudget(
            maximumDiscoveryDirectories = directoryLimit,
            maximumDiscoveryEntries = 64,
            maximumDiscoveryDepth = 16,
        )

        fun project(prefix: String): Path {
            val project = createRepairTempDirectory(prefix).resolve("project")
            project.resolve("src/modules/stale.repair/nested").createDirectories()
            project.resolve("reports").createDirectories()
            project.resolve("Makefile").writeText(
                "CC ?= cc\nall:\n\t\$(CC) -c $targetPath -o build/reconstructed.o\n",
            )
            project.resolve(targetPath).writeText(originalTarget)
            project.resolve(excludedSourcePath).writeText(excludedSource)
            assertFalse(project.resolve("reports/module_plan.json").exists())
            assertFalse(project.resolve("reports/program_model.json").exists())
            return project
        }

        fun runScenario(directoryLimit: Int, exact: Boolean) {
            val project = project(
                if (exact) "repair-active-discovery-directories-exact-" else "repair-active-discovery-directories-under-",
            )
            val repairBudget = budget(directoryLimit)
            val resolved = GeneratedCRepairIndexProfile.resolve(project, budget(4))
            assertEquals(listOf("Makefile", targetPath), resolved.sourcePaths)
            assertTrue(project.resolve(excludedSourcePath).exists())
            assertFalse(excludedSourcePath in resolved.sourcePaths)
            assertTrue(targetPath in resolved.editablePaths)
            assertTrue(resolved.fallbackModuleIdsByPath.containsKey(targetPath))
            assertFalse(project.resolve("reports/module_plan.json").exists())
            assertFalse(project.resolve("reports/program_model.json").exists())
            val acceptedSources = resolved.sourcePaths.associateWith { project.resolve(it).readBytes() }
            val excludedBytes = project.resolve(excludedSourcePath).readBytes()
            val baseline = if (exact) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { it.snapshot }
            } else null

            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-indexed-modules")
            var dispatches = 0
            var capturedReceipt: AgentExecutionReceipt? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.execute(request, onEvent)
                }

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches++
                    return acp.executeCaptured(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    return acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
                }

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                    val grant = authority.grants.single { it.path.relativePath == targetPath }
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                    assertFalse(authority.grants.any { it.path.relativePath == excludedSourcePath })
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                        .also { capturedReceipt = it }
                }
            }

            var validationCalls = 0
            val validationStop = IllegalStateException("discovery directory equality reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertEquals(acceptedSources.keys, request.candidateSources.keys)
                    acceptedSources.forEach { (path, beforeBytes) ->
                        assertContentEquals(
                            if (path == targetPath) candidateTarget.toByteArray(Charsets.UTF_8) else beforeBytes,
                            request.candidateSources.getValue(path),
                            path,
                        )
                    }
                    assertFalse(excludedSourcePath in request.candidateSources)
                    assertEquals(baseline!!.indexSha256, request.indexSha256)
                    assertEquals(
                        GeneratedCRepairIndexProfile.configurationSha256(repairBudget),
                        request.profileSha256,
                    )
                    assertEquals(
                        repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("discovery directory admission test must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("discovery directory admission test must use immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("discovery directory admission test must use immutable candidate validation")
            }

            val historyPath = project.resolve("reports/repair_history.json")
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(historyPath),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = repairBudget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                    assertEquals(1, dispatches)
                    assertEquals(1, validationCalls)
                    val receipt = assertNotNull(capturedReceipt)
                    val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
                    assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
                    assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
                    assertNotNull(evidence.completeExecutionEvidence)
                    val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
                    assertEquals(AgentStopReason.COMPLETED, result.stopReason)
                    val change = result.changes.single()
                    assertEquals(targetPath, change.path.relativePath)
                    assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                    assertEquals(sha256(acceptedSources.getValue(targetPath)), change.beforeSha256)
                    assertEquals(sha256(candidateTarget.toByteArray(Charsets.UTF_8)), change.afterSha256)
                    assertEquals(candidateTarget.toByteArray(Charsets.UTF_8).size.toLong(), change.sizeBytes)
                    assertEquals(2, evidence.filesystemAudit.size)
                    assertTrue(evidence.filesystemAudit.all {
                        it.outcome == decompengine.acp.AcpFilesystemAuditOutcome.ALLOWED &&
                            it.reason == decompengine.acp.AcpFilesystemAuditReason.COMPLETED
                    })
                    acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                    assertContentEquals(excludedBytes, project.resolve(excludedSourcePath).readBytes())
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, repairBudget).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(baseline!!.headId, graph.snapshot.headId)
                        assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                        assertEquals(1, graph.snapshot.runs.size)
                    }
                } else {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "generated C discovery exceeds 3 directories at src/modules/stale.repair/nested",
                        failure.message,
                    )
                    assertEquals(0, dispatches)
                    assertEquals(0, validationCalls)
                    acceptedSources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                    assertContentEquals(excludedBytes, project.resolve(excludedSourcePath).readBytes())
                    assertFalse(historyPath.exists())
                    val graphPath = project.resolve("reports/repair-revisions/graph.json")
                    if (graphPath.exists()) {
                        val state = Json.parseToJsonElement(graphPath.readText()).jsonObject
                        assertEquals(JsonNull, state.getValue("pending"))
                        assertTrue(state.getValue("nodes").jsonArray.isEmpty())
                        assertTrue(state.getValue("runs").jsonArray.isEmpty())
                    }
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget(4)).use { graph ->
                        assertNull(graph.snapshot.pendingAttemptId)
                        assertEquals(1, graph.snapshot.nodes.size)
                        assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
                        assertTrue(graph.snapshot.runs.isEmpty())
                    }
                }
            } finally {
                loop.close()
            }
        }

        runScenario(directoryLimit = 4, exact = true)
        runScenario(directoryLimit = 3, exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair bounds the complete candidate source tree including an unselected sibling`() {
        val targetPath = "src/modules/reconstructed.c"
        val siblingPath = "src/modules/secondary.c"
        val failureText = "$targetPath: compiler error"
        val candidateSize = 128

        fun paddedSource(prefix: String, suffix: String, size: Int, fill: Char): ByteArray {
            val padding = size - prefix.toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
            assertTrue(padding > 0)
            return (prefix + fill.toString().repeat(padding) + suffix).toByteArray(Charsets.UTF_8).also {
                assertEquals(size, it.size)
            }
        }

        val targetBefore = paddedSource(
            "/* small selected module ",
            "\n*/\nint decomp_engine_main(void) { return 0; }\n",
            96,
            'a',
        )
        val siblingBefore = paddedSource(
            "/* unselected sibling module ",
            "\n*/\nint secondary(void) { return 0; }\n",
            128,
            'b',
        )
        val candidatePrefix = "/* active aggregate source-byte boundary: "
        val candidateSuffix = " */\nint decomp_engine_main(void) { return 1; }\n"

        fun candidate(bytes: Int): ByteArray = paddedSource(candidatePrefix, candidateSuffix, bytes, 's')

        val exactCandidate = candidate(candidateSize)
        val oversizedCandidate = candidate(candidateSize + 1)

        fun seededProject(prefix: String): Path = createProject(
            createRepairTempDirectory(prefix).resolve("project"),
            reconstructedSource = targetBefore.decodeToString(),
        ).also { project -> project.resolve(siblingPath).writeBytes(siblingBefore) }

        val sizingProject = seededProject("repair-active-source-tree-sizing-")
        data class Sizing(
            val sources: Map<String, ByteArray>,
            val selected: Map<String, ByteArray>,
            val head: String,
            val nodes: Int,
            val runs: Int,
        )
        val sizing = ModuleRevisionGraph.open(sizingProject, GeneratedCRepairIndexProfile).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(targetPath), context.writablePaths.toSet())
            val selected = graph.preflightStagingContext(context)
            assertTrue(targetPath in selected)
            assertTrue(siblingPath !in selected, "the sibling must remain outside staged context")
            Sizing(
                graph.candidateSources(),
                selected,
                graph.snapshot.headId,
                graph.snapshot.nodes.size,
                graph.snapshot.runs.size,
            )
        }
        assertContentEquals(targetBefore, sizing.sources.getValue(targetPath))
        assertContentEquals(siblingBefore, sizing.sources.getValue(siblingPath))
        val baselineSourceBytes = sizing.sources.values.fold(0L) { total, bytes ->
            Math.addExact(total, bytes.size.toLong())
        }
        val sourceByteLimit = Math.addExact(
            baselineSourceBytes - targetBefore.size.toLong(),
            candidateSize.toLong(),
        )
        val exactCandidateBytes = sizing.sources.entries.fold(0L) { total, (path, bytes) ->
            Math.addExact(total, if (path == targetPath) exactCandidate.size.toLong() else bytes.size.toLong())
        }
        assertEquals(sourceByteLimit, exactCandidateBytes)
        assertTrue(oversizedCandidate.size.toLong() + baselineSourceBytes - targetBefore.size > sourceByteLimit)

        fun runCase(overLimit: Boolean) {
            data class Baseline(
                val sources: Map<String, ByteArray>,
                val selected: Map<String, ByteArray>,
                val head: String,
                val nodes: Int,
                val runs: Int,
            )
            val project = seededProject(
                if (overLimit) "repair-active-source-tree-over-" else "repair-active-source-tree-exact-",
            )
            val budget = RepairResourceBudget(
                maximumSourceFileBytes = 512,
                maximumSourceBytes = sourceByteLimit,
                maximumContextBytes = sourceByteLimit,
                maximumStagingBytes = sourceByteLimit,
                maximumPatchFiles = 1,
                maximumPatchBytes = 256,
            )
            val before = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val context = graph.selectContext("compile", failureText)
                assertEquals(setOf(targetPath), context.writablePaths.toSet())
                val selected = graph.preflightStagingContext(context)
                assertEquals(sizing.selected.keys, selected.keys)
                sizing.selected.forEach { (path, bytes) -> assertContentEquals(bytes, selected.getValue(path), path) }
                Baseline(
                    graph.candidateSources(),
                    selected,
                    graph.snapshot.headId,
                    graph.snapshot.nodes.size,
                    graph.snapshot.runs.size,
                )
            }
            assertEquals(sizing.sources.keys, before.sources.keys)
            before.sources.forEach { (path, bytes) -> assertContentEquals(bytes, sizing.sources.getValue(path), path) }
            assertTrue(budget.maximumSourceBytes >= budget.maximumSourceFileBytes)
            assertTrue(budget.maximumStagingBytes >= before.selected.values.sumOf { it.size.toLong() })
            assertTrue(budget.maximumPatchBytes > exactCandidate.size.toLong())
            val expectedCandidateSources = before.sources.toMutableMap().apply {
                put(targetPath, if (overLimit) oversizedCandidate else exactCandidate)
            }
            val expectedCandidateRevision = repairCandidateSourceSha256(expectedCandidateSources)

            val mode = if (overLimit) {
                "repair-active-declared-role-source-bytes-over"
            } else {
                "repair-active-declared-role-source-bytes-exact"
            }
            val acp = AcpAgentHarnessTest().harness(mode)
            var dispatches = 0
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    assertEquals(before.selected.keys, initialFiles.keys)
                    assertTrue(siblingPath !in initialFiles, "unselected sibling must not enter the staging snapshot")
                    before.selected.forEach { (path, bytes) -> assertContentEquals(bytes, initialFiles.getValue(path), path) }
                    val grants = assertNotNull(request.accessPolicy.mutationAuthority).grants
                    assertEquals(setOf(targetPath), grants.map { it.path.relativePath }.toSet())
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grants.single().operations)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validations = 0
            var validatedRevision: String? = null
            val validatorFailure = IllegalStateException("exact complete source-byte candidate reached validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validations++
                    if (overLimit) error("over-limit complete candidate must be refused before validation")
                    assertEquals(before.sources.keys.sorted(), request.candidateSourcePaths)
                    val sources = request.candidateSources
                    before.sources.filterKeys { it != targetPath }.forEach { (path, bytes) ->
                        assertContentEquals(bytes, sources.getValue(path), path)
                    }
                    assertContentEquals(exactCandidate, sources.getValue(targetPath))
                    assertContentEquals(siblingBefore, sources.getValue(siblingPath))
                    val total = sources.values.fold(0L) { sum, bytes -> Math.addExact(sum, bytes.size.toLong()) }
                    assertEquals(sourceByteLimit, total)
                    val revision = repairCandidateSourceSha256(sources)
                    assertEquals(expectedCandidateRevision, revision)
                    assertEquals(revision, request.sourceRevisionSha256)
                    validatedRevision = revision
                    throw validatorFailure
                }

                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("source-byte admission case must stop at the candidate validator")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("source-byte admission case must stop at the candidate validator")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("source-byte admission case must not run behavior validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (overLimit) {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", failureText),
                            emptyList(),
                        )
                    }
                    assertEquals("repair source inputs exceed $sourceByteLimit bytes", failure.message)
                } else {
                    val failure = assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", failureText),
                            emptyList(),
                        )
                    }
                    assertSame(validatorFailure, failure)
                }
            } finally {
                loop.close()
            }

            assertEquals(1, dispatches)
            assertEquals(if (overLimit) 0 else 1, validations)
            before.sources.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(before.head, snapshot.headId)
                assertEquals(before.nodes + 1, snapshot.nodes.size)
                assertEquals(before.runs + 1, snapshot.runs.size)
                assertEquals(
                    if (overLimit) RepairRunStatus.RESOURCE_EXHAUSTED else RepairRunStatus.VALIDATION_FAILED,
                    snapshot.runs.last().status,
                )
                val rejected = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertTrue(binding.receiptReleaseComplete)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val outcome = receipt.getValue("outcome").jsonObject
                assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
                val result = outcome.getValue("result").jsonObject
                assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
                val changeSet = result.getValue("changes").jsonObject
                assertEquals(1, changeSet.getValue("observedCount").jsonPrimitive.int)
                val change = changeSet.getValue("records").jsonArray.single().jsonObject
                assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                assertEquals(
                    sha256(targetPath.toByteArray(Charsets.UTF_8)),
                    change.getValue("relativePath").jsonObject.getValue("sha256").jsonPrimitive.content,
                )
                assertEquals(sha256(targetBefore), change.getValue("beforeSha256").jsonPrimitive.content)
                assertEquals(sha256(if (overLimit) oversizedCandidate else exactCandidate),
                    change.getValue("afterSha256").jsonPrimitive.content)
                assertEquals(
                    (if (overLimit) oversizedCandidate else exactCandidate).size.toLong(),
                    change.getValue("sizeBytes").jsonPrimitive.content.toLong(),
                )
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
                assertEquals(2, filesystem.getValue("recordCount").jsonPrimitive.int)
                assertEquals(2, records.size)
                assertEquals(
                    listOf("fs/write_text_file", "fs/read_text_file").map {
                        sha256(it.toByteArray(Charsets.UTF_8))
                    },
                    records.map { it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content },
                )
                assertTrue(records.all {
                    it.getValue("outcome").jsonPrimitive.content == "allowed" &&
                        it.getValue("reason").jsonPrimitive.content == "completed"
                })
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(
                    if (overLimit) decompengine.project.AcpChangeValidationStatus.NOT_RUN
                    else decompengine.project.AcpChangeValidationStatus.FAILED,
                    assessment.validationStatus,
                )
                assertEquals(
                    listOf(if (overLimit) "resource-exhausted" else "validation-failed"),
                    assessment.reasonCodes,
                )
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                assertEquals(if (overLimit) expectedCandidateRevision else validatedRevision, assessment.afterSha256)
            }
        }

        runCase(overLimit = false)
        runCase(overLimit = true)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair admits the exact candidate blob entry and refuses the next directory entry`() {
        val targetPath = "src/modules/reconstructed.c"
        val sourceText = "int decomp_engine_main(void) { return 0; }\n"
        val prefix = "/* active repair stored-blob byte boundary: "
        val suffix = " */\nint decomp_engine_main(void) { return 1; }\n"
        val candidateBytes = 4096
        val paddingBytes = candidateBytes - prefix.toByteArray(Charsets.UTF_8).size -
            suffix.toByteArray(Charsets.UTF_8).size
        val candidate = (prefix + "s".repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8)
        assertEquals(candidateBytes, candidate.size)
        val candidateDigest = sha256(candidate)
        val sizingProject = createProject(
            createRepairTempDirectory("repair-active-state-entry-sizing-").resolve("project"),
            reconstructedSource = sourceText,
        )
        val blobsRelative = "reports/repair-revisions/blobs"
        val sizingBlobs = sizingProject.resolve(blobsRelative)
        val baselineBlobNames = ModuleRevisionGraph.open(
            sizingProject,
            GeneratedCRepairIndexProfile,
        ).use {
            Files.newDirectoryStream(sizingBlobs).use { stream ->
                stream.map { it.fileName.toString() }.toSet()
            }
        }
        val exactEntryLimit = baselineBlobNames.size + 1
        assertTrue(baselineBlobNames.isNotEmpty())
        assertFalse(candidateDigest in baselineBlobNames)

        fun runCase(exact: Boolean) {
            val stateEntryLimit = if (exact) exactEntryLimit else exactEntryLimit - 1
            val budget = RepairResourceBudget(
                maximumStateDirectoryEntries = stateEntryLimit,
                maximumSourceFileBytes = 64 * 1024,
                maximumSourceBytes = 256 * 1024,
                maximumContextBytes = 256 * 1024,
                maximumStagingBytes = 256 * 1024,
                maximumPatchBytes = 64 * 1024,
            )
            val project = createProject(
                createRepairTempDirectory(
                    if (exact) "repair-active-state-entry-exact-" else "repair-active-state-entry-over-",
                ).resolve("project"),
                reconstructedSource = sourceText,
            )
            val target = project.resolve(targetPath)
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val blobsPath = project.resolve(blobsRelative)
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val names = Files.newDirectoryStream(blobsPath).use { stream ->
                    stream.map { it.fileName.toString() }.toSet()
                }
                assertEquals(baselineBlobNames, names)
                Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
            }
            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-stored-blob-exact")
            var dispatches = 0
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    assertEquals(
                        targetPath,
                        request.accessPolicy.mutationAuthority?.grants?.single()?.path?.relativePath,
                    )
                    assertEquals(
                        setOf(AgentOperation.WRITE_FILE),
                        request.accessPolicy.mutationAuthority?.grants?.single()?.operations,
                    )
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validationCalls = 0
            val validationStop = IllegalStateException("exact state directory entry reached candidate validator")
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertContentEquals(candidate, request.candidateSources.getValue(targetPath))
                    assertEquals(
                        decompengine.repair.repairCandidateSourceSha256(request.candidateSources),
                        request.sourceRevisionSha256,
                    )
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("blob entry admission must stop at immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("blob entry admission must stop at immutable candidate validation")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("blob entry admission must not run behavior validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (exact) {
                    assertSame(validationStop, assertFailsWith<IllegalStateException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    })
                } else {
                    val refusal = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "repair blob publication requires $exactEntryLimit directory entries; limit=${exactEntryLimit - 1}",
                        refusal.message,
                    )
                }
            } finally {
                loop.close()
            }

            assertEquals(1, dispatches, "both cases reach ACP before graph blob admission")
            assertEquals(if (exact) 1 else 0, validationCalls)
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(baseline.second + 1, graph.snapshot.nodes.size)
                assertEquals(baseline.third + 1, graph.snapshot.runs.size)
                assertEquals(
                    if (exact) RepairRunStatus.VALIDATION_FAILED else RepairRunStatus.RESOURCE_EXHAUSTED,
                    graph.snapshot.runs.last().status,
                )
                val rejected = graph.snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                assertFalse(rejected.recoveredAfterCrash)
                val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                assertTrue(binding.receiptReleaseComplete)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val outcome = receipt.getValue("outcome").jsonObject
                assertEquals("returned", outcome.getValue("type").jsonPrimitive.content)
                val result = outcome.getValue("result").jsonObject
                assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
                val change = result.getValue("changes").jsonObject.getValue("records").jsonArray.single().jsonObject
                assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                assertEquals(sha256(acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
                assertEquals(candidateDigest, change.getValue("afterSha256").jsonPrimitive.content)
                assertEquals(candidateBytes.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                assertEquals(2, filesystem.getValue("recordCount").jsonPrimitive.int)
                val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
                assertEquals(
                    listOf("fs/write_text_file", "fs/read_text_file").map {
                        sha256(it.toByteArray(Charsets.UTF_8))
                    },
                    records.map {
                        it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content
                    },
                )
                assertEquals(listOf("allowed", "allowed"), records.map {
                    it.getValue("outcome").jsonPrimitive.content
                })
                assertEquals(listOf("completed", "completed"), records.map {
                    it.getValue("reason").jsonPrimitive.content
                })
                assertTrue(records.all {
                    it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                        .getValue("sha256").jsonPrimitive.content ==
                        sha256(targetPath.toByteArray(Charsets.UTF_8))
                })
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                assertEquals(
                    if (exact) decompengine.project.AcpChangeValidationStatus.FAILED
                    else decompengine.project.AcpChangeValidationStatus.NOT_RUN,
                    assessment.validationStatus,
                )
            }
            val remainingBlobNames = Files.newDirectoryStream(blobsPath).use { stream ->
                stream.map { it.fileName.toString() }.toSet()
            }
            assertEquals(
                if (exact) baselineBlobNames + candidateDigest else baselineBlobNames,
                remainingBlobNames,
                "only the exact-entry candidate may create a new blob",
            )
        }

        runCase(exact = true)
        runCase(exact = false)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair admits the exact revision node count and refuses the next attempt before dispatch`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-revision-node-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val budget = RepairResourceBudget(maximumRevisionNodes = 2)
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
        }
        assertEquals(1, baseline.second, "fresh repair graph must begin with its root node")
        assertTrue(baseline.second < budget.maximumRevisionNodes)
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-candidate")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                assertEquals(targetPath, request.accessPolicy.mutationAuthority?.grants?.single()?.path?.relativePath)
                assertEquals(setOf(AgentOperation.WRITE_FILE),
                    request.accessPolicy.mutationAuthority?.grants?.single()?.operations)
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var validatedCandidateRevision: String? = null
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                val candidate = request.candidateSources.getValue(targetPath)
                assertEquals(
                    "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n",
                    candidate.decodeToString(),
                )
                validatedCandidateRevision = request.sourceRevisionSha256
                val evidenceBytes = (
                    "{\"schemaVersion\":1,\"outcome\":\"compile-failed\",\"sourceRevisionSha256\":" +
                        "\"${request.sourceRevisionSha256}\"}\n"
                    ).toByteArray(Charsets.UTF_8)
                request.reportsDir.createDirectories()
                val evidencePath = request.reportsDir.resolve("${request.label}.validation.json")
                evidencePath.writeBytes(evidenceBytes)
                val proof = RepairValidationProof(
                    sourceRevisionSha256 = request.sourceRevisionSha256,
                    profileSha256 = request.profileSha256,
                    indexSha256 = request.indexSha256,
                    regressionCorpusSha256 = request.regressionCorpusSha256,
                    originalBinarySha256 = null,
                    rebuiltBinarySha256 = null,
                    runtimeSha256 = sha256("revision-node-budget-fixture".toByteArray(Charsets.UTF_8)),
                    evidenceSha256 = sha256(evidenceBytes),
                    cleanupVerified = true,
                    assurance = RepairValidationAssurance.STRICT_CONTAINED,
                )
                return RepairCandidateValidationOutcome.CompileFailed(
                    CompileFailure(listOf("fixture-compiler"), 1, "", "$targetPath: fixture failure"),
                    proof,
                )
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("node-budget fixture must use immutable candidate validation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("node-budget fixture must use immutable candidate validation")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("compile-failed candidate must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )
        try {
            val admitted = loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "$targetPath: first compiler error"),
                emptyList(),
            )
            assertFalse(admitted.succeeded)
            assertEquals(RepairAttemptDisposition.REJECTED, admitted.disposition)
            assertEquals(1, dispatches)
            assertEquals(1, validationCalls)
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                assertEquals(budget.maximumRevisionNodes, graph.snapshot.nodes.size)
                assertEquals(baseline.second + 1, graph.snapshot.nodes.size)
                assertEquals(baseline.third + 1, graph.snapshot.runs.size)
                assertEquals(baseline.first, graph.snapshot.headId)
                assertEquals(RepairRunStatus.REJECTED, graph.snapshot.runs.last().status)
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
            }

            val nodeLimit = assertFailsWith<RepairBudgetExceededException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", "$targetPath: second compiler error"),
                    emptyList(),
                )
            }
            assertEquals("revision graph reached its node budget", nodeLimit.message)
            assertEquals(1, dispatches, "the exhausted node budget must refuse before another ACP launch")
            assertEquals(1, validationCalls, "the exhausted node budget must refuse before another validation")
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(budget.maximumRevisionNodes, snapshot.nodes.size)
                assertEquals(baseline.first, snapshot.headId)
                assertEquals(baseline.second + 1, snapshot.nodes.size)
                assertEquals(baseline.third + 2, snapshot.runs.size)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, snapshot.runs.last().status)
                val rejected = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                assertEquals(validatedCandidateRevision, rejected.sourceRevisionSha256)
                val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertTrue(binding.receiptReleaseComplete)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
                assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
                val change = result.getValue("changes").jsonObject.getValue("records").jsonArray.single().jsonObject
                assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                assertEquals(sha256(acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
                assertEquals(sha256("/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n"
                    .toByteArray(Charsets.UTF_8)), change.getValue("afterSha256").jsonPrimitive.content)
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            }
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair refuses candidate graph growth while persisting the rejected receipt`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-graph-byte-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val blobsPath = project.resolve("reports/repair-revisions/blobs")
        val budget = RepairResourceBudget(maximumGraphBytes = 8_920)
        data class Baseline(
            val head: String,
            val nodes: Int,
            val runs: Int,
            val storedBlobBytes: Long,
            val blobNames: Set<String>,
        )
        val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertTrue(Files.size(graphPath) < budget.maximumGraphBytes)
            Baseline(
                graph.snapshot.headId,
                graph.snapshot.nodes.size,
                graph.snapshot.runs.size,
                graph.snapshot.storedBlobBytes,
                Files.newDirectoryStream(blobsPath).use { entries ->
                    entries.map { it.fileName.toString() }.toSet()
                },
            )
        }
        val candidate = "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n".toByteArray(Charsets.UTF_8)
        val candidateDigest = sha256(candidate)
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-candidate")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                acp.execute(request, onEvent)
            override fun executeCaptured(
                request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit,
            ) = acp.executeCaptured(request, initialFiles, output, onEvent)
            override fun executeCapturedReceipt(
                request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit,
            ) = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
            override fun executeCapturedReceipt(
                request: AgentExecutionRequest, turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>, output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                val grant = request.accessPolicy.mutationAuthority?.grants?.single()
                assertEquals(targetPath, grant?.path?.relativePath)
                assertEquals(setOf(AgentOperation.WRITE_FILE), grant?.operations)
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                error("graph-byte refusal must occur before candidate validation")
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("graph-byte control must stop before compilation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("graph-byte control must stop before rebuild")
            override fun evaluateBehavior(
                id: String, projectDir: Path, originalBinary: Path, rebuiltBinary: Path,
                inputs: List<ProcessInput>, reportsDir: Path, budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("graph-byte control must stop before behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )
        try {
            val failure = assertFailsWith<Exception> {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", targetPath + ": compiler error"),
                    emptyList(),
                )
            }
            assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
                it is RepairBudgetExceededException && it.message ==
                    "repair revision graph exceeds " + budget.maximumGraphBytes + " content bytes"
            }, generateSequence<Throwable>(failure) { it.cause }.mapNotNull { it.message }.toList().toString())
            assertEquals(1, dispatches, "candidate graph admission occurs after the acknowledged ACP write")
            assertEquals(0, validationCalls)
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
            assertTrue(Files.size(graphPath) <= budget.maximumGraphBytes)

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(baseline.head, snapshot.headId)
                assertEquals(baseline.nodes + 1, snapshot.nodes.size)
                assertEquals(baseline.runs + 1, snapshot.runs.size)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, snapshot.runs.last().status)
                assertEquals(baseline.storedBlobBytes, snapshot.storedBlobBytes)
                val rejected = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                assertTrue(rejected.changes.isEmpty())
                val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals("returned-completed", binding.terminalOutcome)
                assertTrue(binding.receiptReleaseComplete)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes))
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
                val change = result.getValue("changes").jsonObject.getValue("records").jsonArray.single().jsonObject
                assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
                assertEquals(sha256(acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
                assertEquals(candidateDigest, change.getValue("afterSha256").jsonPrimitive.content)
                assertEquals(candidate.size.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())
                assertEquals(sha256(targetPath.toByteArray(Charsets.UTF_8)),
                    change.getValue("relativePath").jsonObject.getValue("sha256").jsonPrimitive.content)
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
                val lifecycle = receipt.getValue("lifecycle").jsonObject
                assertEquals("final-workspace-snapshot", lifecycle.getValue("phaseReached").jsonPrimitive.content)
                assertEquals("verified", lifecycle.getValue("cleanupDisposition").jsonPrimitive.content)
                val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int)
                val audit = filesystem.getValue("records").jsonArray.single().jsonObject
                assertEquals("allowed", audit.getValue("outcome").jsonPrimitive.content)
                assertEquals("completed", audit.getValue("reason").jsonPrimitive.content)
                assertEquals(sha256(targetPath.toByteArray(Charsets.UTF_8)),
                    audit.getValue("policyPath").jsonObject.getValue("relativePath")
                        .jsonObject.getValue("sha256").jsonPrimitive.content)
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256)
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
                assertEquals(decompengine.project.AcpChangeValidationStatus.NOT_RUN, assessment.validationStatus)
                assertEquals(listOf("candidate-rejected"), assessment.reasonCodes)
            }
            assertTrue(Files.size(graphPath) <= budget.maximumGraphBytes)
            val remainingBlobNames = Files.newDirectoryStream(blobsPath).use { entries ->
                entries.map { it.fileName.toString() }.toSet()
            }
            assertEquals(baseline.blobNames, remainingBlobNames)
        } finally {
            loop.close()
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 240, unit = TimeUnit.SECONDS)
    fun activeAcpRepairAdmitsExactProjectionBytesAndRefusesOneByteUnderAfterAcknowledgedWrite() {
        class ProjectionBoundaryCrash : Error()
        data class Baseline(
            val head: String,
            val nodes: Int,
            val runs: Int,
            val storedBlobBytes: Long,
            val blobNames: Set<String>,
        )
        data class Attempt(
            val project: Path,
            val baseline: Baseline,
            val acceptedSource: ByteArray,
            val acceptedMakefile: ByteArray,
            val dispatches: Int,
            val validationCalls: Int,
        )

        val targetPath = "src/modules/reconstructed.c"
        val initialSource = "int decomp_engine_main(void) { return 0; }\n"
        val prefix = "/* active repair stored-blob byte boundary: "
        val suffix = " */\nint decomp_engine_main(void) { return 1; }\n"
        val candidateBytes = 4_096
        val paddingBytes = candidateBytes - prefix.toByteArray(Charsets.UTF_8).size -
            suffix.toByteArray(Charsets.UTF_8).size
        val candidate = (prefix + "s".repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8)
        assertEquals(candidateBytes, candidate.size)
        val candidateDigest = sha256(candidate)

        fun runAttempt(label: String, projectionLimit: Long?, expectProjectionRefusal: Boolean): Attempt {
            val budget = if (projectionLimit == null) RepairResourceBudget()
                else RepairResourceBudget(maximumProjectionBytes = projectionLimit)
            val project = createProject(
                createRepairTempDirectory("repair-active-projection-$label-").resolve("project"),
                reconstructedSource = initialSource,
            )
            val target = project.resolve(targetPath)
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val blobsPath = project.resolve("reports/repair-revisions/blobs")
            val baseline = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                if (projectionLimit != null) graph.synchronizeRepairHistory()
                Baseline(
                    graph.snapshot.headId,
                    graph.snapshot.nodes.size,
                    graph.snapshot.runs.size,
                    graph.snapshot.storedBlobBytes,
                    Files.newDirectoryStream(blobsPath).use { entries ->
                        entries.map { it.fileName.toString() }.toSet()
                    },
                )
            }
            val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-stored-blob-exact")
            var dispatches = 0
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                    acp.execute(request, onEvent)
                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ) = acp.executeCaptured(request, initialFiles, output, onEvent)
                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ) = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)
                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatches++
                    val grant = request.accessPolicy.mutationAuthority?.grants?.single()
                    assertEquals(targetPath, grant?.path?.relativePath)
                    assertEquals(setOf(AgentOperation.WRITE_FILE), grant?.operations)
                    assertTrue((grant?.maximumBytes ?: 0L) >= candidate.size)
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validationCalls = 0
            val validationStop = ProjectionBoundaryCrash()
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    assertContentEquals(candidate, request.candidateSources.getValue(targetPath))
                    assertEquals(candidateDigest, sha256(request.candidateSources.getValue(targetPath)))
                    if (expectProjectionRefusal) error("one-byte-under projection case must not reach validation")
                    throw validationStop
                }
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("projection boundary must use immutable candidate validation")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("projection boundary must not rebuild")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("projection boundary must not evaluate behavior")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )
            try {
                if (expectProjectionRefusal) {
                    val failure = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", targetPath + ": compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals(
                        "repair history exceeds its " + projectionLimit + "-byte limit",
                        failure.message,
                    )
                } else {
                    val failure = assertFailsWith<ProjectionBoundaryCrash> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("make"), 2, "", targetPath + ": compiler error"),
                            emptyList(),
                        )
                    }
                    assertSame(validationStop, failure)
                }
            } finally {
                loop.close()
            }
            assertEquals(1, dispatches, "projection admission occurs after the acknowledged ACP write")
            assertEquals(if (expectProjectionRefusal) 0 else 1, validationCalls)
            assertContentEquals(acceptedSource, target.readBytes())
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
            return Attempt(project, baseline, acceptedSource, acceptedMakefile, dispatches, validationCalls)
        }

        fun measuredProjectionLimit(attempt: Attempt, budget: RepairResourceBudget): Long =
            ModuleRevisionGraph.open(attempt.project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val snapshot = graph.snapshot
                assertNull(snapshot.pendingAttemptId)
                assertEquals(RepairRunStatus.INTERRUPTED, snapshot.runs.last().status)
                assertEquals(attempt.baseline.head, snapshot.headId)
                assertEquals(attempt.baseline.nodes + 1, snapshot.nodes.size)
                val node = snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, node.status)
                assertTrue(node.recoveredAfterCrash)
                val change = node.changes.single()
                assertEquals(candidateDigest, change.afterSha256)
                assertEquals(candidateBytes.toLong(), change.afterBytes)
                val iterations = graph.derivedRepairIterations()
                val inputs = graph.retainedRegressionCorpus().inputs
                val runs = snapshot.runs
                fun fits(limit: Long): Boolean = try {
                    renderRepairHistoryProjection(iterations, inputs, limit, 4, runs)
                    true
                } catch (_: RepairBudgetExceededException) {
                    false
                }
                var low = 1L
                var high = 64L * 1024 * 1024
                assertTrue(fits(high))
                while (low < high) {
                    val middle = low + (high - low) / 2
                    if (fits(middle)) high = middle else low = middle + 1
                }
                assertTrue(fits(low))
                assertFalse(fits(low - 1))
                graph.synchronizeRepairHistory()
                low
            }

        val calibration = runAttempt("calibration", projectionLimit = null, expectProjectionRefusal = false)
        val calibrationBudget = RepairResourceBudget()
        val exactProjectionLimit = measuredProjectionLimit(calibration, calibrationBudget)
        println("measured maximumProjectionBytes admission edge=" + exactProjectionLimit)

        val exact = runAttempt("exact", exactProjectionLimit, expectProjectionRefusal = false)
        val exactBudget = RepairResourceBudget(maximumProjectionBytes = exactProjectionLimit)
        val exactMeasuredLimit = measuredProjectionLimit(exact, exactBudget)
        assertEquals(exactProjectionLimit, exactMeasuredLimit)
        ModuleRevisionGraph.open(exact.project, GeneratedCRepairIndexProfile, exactBudget).use { graph ->
            val node = graph.snapshot.nodes.last()
            assertEquals(RepairRunStatus.INTERRUPTED, graph.snapshot.runs.last().status)
            assertEquals(candidateDigest, node.changes.single().afterSha256)
            assertEquals(exact.baseline.head, graph.snapshot.headId)
            assertEquals(exact.baseline.storedBlobBytes + candidateBytes, graph.snapshot.storedBlobBytes)
            graph.synchronizeRepairHistory()
            assertTrue(Files.size(exact.project.resolve("reports/repair_history.json")) <= exactProjectionLimit)
        }

        val belowLimit = exactProjectionLimit - 1
        assertTrue(belowLimit > 0)
        val refused = runAttempt("one-byte-under", belowLimit, expectProjectionRefusal = true)
        val belowBudget = RepairResourceBudget(maximumProjectionBytes = belowLimit)
        ModuleRevisionGraph.open(refused.project, GeneratedCRepairIndexProfile, belowBudget).use { graph ->
            val snapshot = graph.snapshot
            assertNull(snapshot.pendingAttemptId)
            assertEquals(refused.baseline.head, snapshot.headId)
            assertEquals(refused.baseline.nodes + 1, snapshot.nodes.size)
            assertEquals(refused.baseline.runs + 1, snapshot.runs.size)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, snapshot.runs.last().status)
            assertEquals(refused.baseline.storedBlobBytes, snapshot.storedBlobBytes)
            val rejected = snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertTrue(rejected.changes.isEmpty())
            val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            val receiptBytes = refused.project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            val change = result.getValue("changes").jsonObject.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            assertEquals(sha256(refused.acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(candidateDigest, change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(candidateBytes.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val lifecycle = receipt.getValue("lifecycle").jsonObject
            assertEquals("final-workspace-snapshot", lifecycle.getValue("phaseReached").jsonPrimitive.content)
            assertEquals("verified", lifecycle.getValue("cleanupDisposition").jsonPrimitive.content)
            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            val records = filesystem.getValue("records").jsonArray
            assertEquals(2, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals(
                listOf("fs/write_text_file", "fs/read_text_file").map {
                    sha256(it.toByteArray(Charsets.UTF_8))
                },
                records.map {
                    it.jsonObject.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content
                },
            )
            assertTrue(records.all {
                it.jsonObject.getValue("outcome").jsonPrimitive.content == "allowed" &&
                    it.jsonObject.getValue("reason").jsonPrimitive.content == "completed"
            })
            val assessmentBytes = refused.project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(decompengine.project.AcpChangeValidationStatus.NOT_RUN, assessment.validationStatus)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(listOf("candidate-rejected"), assessment.reasonCodes)
            graph.synchronizeRepairHistory()
            assertTrue(Files.size(refused.project.resolve("reports/repair_history.json")) <= belowLimit)
        }
        val remainingBlobs = Files.newDirectoryStream(refused.project.resolve("reports/repair-revisions/blobs"))
            .use { entries -> entries.map { it.fileName.toString() }.toSet() }
        assertEquals(refused.baseline.blobNames, remainingBlobs)
        assertContentEquals(refused.acceptedSource, refused.project.resolve(targetPath).readBytes())
        assertContentEquals(refused.acceptedMakefile, refused.project.resolve("Makefile").readBytes())
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active legacy repair admits exact response byte limit and refuses one byte under before validation`() {
        val targetPath = "src/modules/reconstructed.c"
        val candidate = "/* bounded provider response */\nint decomp_engine_main(void) { return 1; }\n"
        val messageContent =
            "{\"summary\":\"bounded\",\"patches\":[{\"relativePath\":${JsonPrimitive(targetPath)}," +
                "\"replacement\":${JsonPrimitive(candidate)}}]}"
        val responseBody =
            "{\"choices\":[{\"message\":{\"content\":${JsonPrimitive(messageContent)}}}]}"
        val responseBytes = responseBody.toByteArray(Charsets.UTF_8)
        val requests = AtomicInteger()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/v1/chat/completions") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            requests.incrementAndGet()
            exchange.sendResponseHeaders(200, responseBytes.size.toLong())
            exchange.responseBody.use { it.write(responseBytes) }
        }
        server.start()
        val endpoint = URI.create("http://127.0.0.1:${server.address.port}/v1")
        val limits = AgentExecutionLimits(maxOutputBytes = 1024 * 1024)
        assertTrue(responseBytes.size.toLong() < limits.maxOutputBytes)

        fun strategy(validate: (RepairCandidateValidationRequest) -> RepairCandidateValidationOutcome) =
            object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome = validate(request)
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("legacy response boundary must use the injected candidate validator")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("legacy response boundary must use the injected candidate validator")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport =
                    error("legacy response boundary must use the injected candidate validator")
            }

        fun openLoop(project: Path, budget: RepairResourceBudget, validation: RepairValidationStrategy) =
            TestRepairRuntimeAccess.openLoop(
                harness = RepairClientAgentHarness(
                    HttpOpenAiCompatibleRepairClient(
                        apiKey = "test-key",
                        model = "test-model",
                        baseUrl = endpoint,
                        defaultBudget = budget,
                        defaultLimits = limits,
                    ),
                ),
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = limits,
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = true,
                faultInjector = null,
            )

        try {
            val exactBudget = RepairResourceBudget(
                maximumRegressionInputBytes = 64,
                maximumResponseBytes = responseBytes.size.toLong(),
            )
            val exactProject = createProject(
                createRepairTempDirectory("repair-active-response-exact-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
            )
            val exactSource = exactProject.resolve(targetPath).readBytes()
            val exactBaseline = ModuleRevisionGraph.open(
                exactProject, GeneratedCRepairIndexProfile, exactBudget,
            ).use { graph ->
                Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
            }
            val exactSentinel = IllegalStateException("exact response reached candidate validator")
            var exactValidationCalls = 0
            val exactLoop = openLoop(exactProject, exactBudget, strategy { request ->
                exactValidationCalls++
                assertContentEquals(candidate.toByteArray(Charsets.UTF_8), request.candidateSources.getValue(targetPath))
                throw exactSentinel
            })
            try {
                val failure = assertFailsWith<IllegalStateException> {
                    exactLoop.repairCompileError(
                        exactProject,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: original compile error"),
                        emptyList(),
                    )
                }
                assertTrue(failure === exactSentinel)
                assertEquals(1, requests.get(), "exact response must be served once")
                assertEquals(1, exactValidationCalls)
                assertContentEquals(exactSource, exactProject.resolve(targetPath).readBytes())
                ModuleRevisionGraph.open(exactProject, GeneratedCRepairIndexProfile, exactBudget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(exactBaseline.first, graph.snapshot.headId)
                    assertEquals(exactBaseline.second + 1, graph.snapshot.nodes.size)
                    assertEquals(exactBaseline.third + 1, graph.snapshot.runs.size)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
                }
            } finally {
                exactLoop.close()
            }

            val overBudget = RepairResourceBudget(
                maximumRegressionInputBytes = 64,
                maximumResponseBytes = responseBytes.size.toLong() - 1,
            )
            val overProject = createProject(
                createRepairTempDirectory("repair-active-response-under-limit-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
            )
            val overSource = overProject.resolve(targetPath).readBytes()
            val overBaseline = ModuleRevisionGraph.open(
                overProject, GeneratedCRepairIndexProfile, overBudget,
            ).use { graph ->
                Triple(graph.snapshot.headId, graph.snapshot.nodes.size, graph.snapshot.runs.size)
            }
            var overValidationCalls = 0
            val overLoop = openLoop(overProject, overBudget, strategy {
                overValidationCalls++
                error("undersized response budget must refuse before validation")
            })
            try {
                val failure = assertFailsWith<AgentExecutionException> {
                    overLoop.repairCompileError(
                        overProject,
                        CompileFailure(listOf("make"), 2, "", "$targetPath: original compile error"),
                        emptyList(),
                    )
                }
                assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
                assertEquals(
                    "OpenAI-compatible response exceeds its ${responseBytes.size - 1}-byte transport limit",
                    failure.failure.message,
                )
                assertEquals(2, requests.get())
                assertEquals(0, overValidationCalls)
                assertContentEquals(overSource, overProject.resolve(targetPath).readBytes())
                ModuleRevisionGraph.open(overProject, GeneratedCRepairIndexProfile, overBudget).use { graph ->
                    assertNull(graph.snapshot.pendingAttemptId)
                    assertEquals(overBaseline.first, graph.snapshot.headId)
                    assertEquals(overBaseline.second + 1, graph.snapshot.nodes.size)
                    assertEquals(overBaseline.third + 1, graph.snapshot.runs.size)
                    assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                    assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
                }
            } finally {
                overLoop.close()
            }
        } finally {
            server.stop(0)
        }
    }

    private fun activeAcpRepairConsumesReceiptBoundValidationResult(
        compileValid: Boolean,
        regressionInputs: List<ProcessInput> = emptyList(),
        resourceBudget: RepairResourceBudget = RepairResourceBudget(),
    ) {
        val testRoot = java.nio.file.Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-acp-compile-failed-result-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val candidateSource = "/* validated candidate */\nint decomp_engine_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val outcomeName = if (compileValid) "compile-valid" else "compile-failed"
        val (baselineHead, baselineFullyAcceptedHeadId) = ModuleRevisionGraph.open(
            project, GeneratedCRepairIndexProfile, resourceBudget,
        ).use { it.snapshot.headId to it.snapshot.fullyAcceptedHeadId }
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-candidate")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedCandidateDigest: String? = null
        var observedInvocation: RepairValidationInvocation? = null
        var observedProof: RepairValidationProof? = null
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(regressionInputs, request.inputs)
                val retainedInputBytes = request.inputs.sumOf { input ->
                    input.id.toByteArray(Charsets.UTF_8).size.toLong() + input.stdin.size +
                        input.args.sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
                }
                assertTrue(retainedInputBytes <= resourceBudget.maximumRegressionInputBytes)
                assertEquals(request.regressionCorpusSha256, assertNotNull(request.invocation).regressionCorpusSha256)
                assertEquals(
                    setOf("Makefile", "include/modules/reconstructed.h", "src/main.c", targetPath),
                    request.candidateSourcePaths.toSet(),
                )
                assertContentEquals(candidateSource, request.candidateSources.getValue(targetPath))
                val invocation = assertNotNull(request.invocation)
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                assertEquals(candidateDigest, invocation.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = invocation

                val rebuiltBinarySha256 = if (compileValid) {
                    sha256("fixture-rebuilt-binary".toByteArray(Charsets.UTF_8))
                } else null
                val evidenceBytes = (
                    "{\"schemaVersion\":1,\"outcome\":\"$outcomeName\",\"sourceRevisionSha256\":\"$candidateDigest\"," +
                        "\"rebuiltBinarySha256\":${rebuiltBinarySha256?.let { "\"$it\"" } ?: "null"}}\n"
                    ).toByteArray(Charsets.UTF_8)
                request.reportsDir.createDirectories()
                val evidencePath = request.reportsDir.resolve("${request.label}.validation.json")
                evidencePath.writeBytes(evidenceBytes)
                val proof = RepairValidationProof(
                    sourceRevisionSha256 = candidateDigest,
                    profileSha256 = request.profileSha256,
                    indexSha256 = request.indexSha256,
                    regressionCorpusSha256 = request.regressionCorpusSha256,
                    originalBinarySha256 = null,
                    rebuiltBinarySha256 = rebuiltBinarySha256,
                    runtimeSha256 = sha256(
                        "typed-${outcomeName}-fixture".toByteArray(Charsets.UTF_8),
                    ),
                    evidenceSha256 = sha256(evidenceBytes),
                    cleanupVerified = true,
                    assurance = RepairValidationAssurance.STRICT_CONTAINED,
                )
                observedProof = proof
                return if (compileValid) RepairCandidateValidationOutcome.CompileValid(proof)
                else RepairCandidateValidationOutcome.CompileFailed(
                    CompileFailure(listOf("fixture-compiler"), 1, "", "$targetPath: fixture compile error"),
                    proof,
                )
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("active repair must use immutable candidate validation")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("active repair must use immutable candidate validation")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("compile-only candidate must not reach behavior validation")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = resourceBudget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val iteration = loop.repairCompileError(
            project,
            CompileFailure(listOf("make"), 2, "", "$targetPath: original compile error"),
            regressionInputs,
        )

        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        assertEquals(if (compileValid) "compile-valid" else "compile", iteration.after?.kind)
        assertFalse(iteration.succeeded)
        assertEquals(
            if (compileValid) RepairAttemptDisposition.PROVISIONAL else RepairAttemptDisposition.REJECTED,
            iteration.disposition,
        )
        val candidateDigest = assertNotNull(observedCandidateDigest)
        val validationInvocation = assertNotNull(observedInvocation)
        val validationProof = assertNotNull(observedProof)
        assertEquals(candidateDigest, validationInvocation.sourceRevisionSha256)
        assertEquals(candidateDigest, validationProof.sourceRevisionSha256)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, resourceBudget).use { graph ->
            assertEquals(regressionInputs, graph.retainedRegressionCorpus().inputs)
            assertEquals(
                decompengine.repair.repairRegressionCorpusSha256(regressionInputs),
                graph.retainedRegressionCorpus().sha256,
            )
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(
                if (compileValid) RepairRunStatus.COMPILE_VALID else RepairRunStatus.REJECTED,
                graph.snapshot.runs.last().status,
            )
            assertEquals(baselineFullyAcceptedHeadId, graph.snapshot.fullyAcceptedHeadId)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(
                if (compileValid) ModuleRevisionStatus.PROVISIONAL else ModuleRevisionStatus.REJECTED,
                rejected.status,
            )
            if (compileValid) assertEquals(rejected.id, graph.snapshot.provisionalHeadId)
            else assertNull(graph.snapshot.provisionalHeadId)
            assertEquals(validationInvocation.candidateRevisionId, rejected.id)
            assertEquals(validationInvocation.runId, rejected.repairMetadata?.runId)
            val binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(iteration.agentInvocation?.receiptSha256, binding.receiptSha256)
            assertEquals(
                if (compileValid) RepairAgentAssessmentStatus.PROVISIONAL else RepairAgentAssessmentStatus.REJECTED,
                binding.assessmentStatus,
            )
            assertEquals("returned-completed", binding.terminalOutcome)
            val invocationReceiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(invocationReceiptBytes))
            val invocationReceipt = Json.parseToJsonElement(invocationReceiptBytes.decodeToString()).jsonObject
            val invocationResult = invocationReceipt.getValue("outcome").jsonObject
                .getValue("result").jsonObject
            assertEquals("completed", invocationResult.getValue("stopReason").jsonPrimitive.content)
            val resultChanges = invocationResult.getValue("changes").jsonObject
            assertEquals(binding.resultChangesSha256,
                resultChanges.getValue("aggregateSha256").jsonPrimitive.content)
            assertEquals("modified",
                resultChanges.getValue("records").jsonArray.single().jsonObject
                    .getValue("kind").jsonPrimitive.content)
            val assessment = decompengine.project.AcpChangeAssessment.parse(
                project.resolve(assertNotNull(binding.assessmentPath)).readBytes(),
            )
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(candidateDigest, assessment.afterSha256)
            assertEquals(
                if (compileValid) listOf(validationProof.evidenceSha256) else emptyList(),
                assessment.validationProofSha256,
            )
            assertEquals(
                if (compileValid) decompengine.project.AcpChangePublicationEligibility.PROVISIONAL
                else decompengine.project.AcpChangePublicationEligibility.REJECTED,
                assessment.eligibility,
            )
            assertEquals(
                if (compileValid) emptyList() else listOf("validation-failed"),
                assessment.reasonCodes,
            )
            assertEquals(
                if (compileValid) decompengine.project.AcpChangeValidationStatus.PASSED
                else decompengine.project.AcpChangeValidationStatus.FAILED,
                assessment.validationStatus,
            )
            val observation = graph.snapshot.runs.last().validationObservations.entries.single()
            assertEquals(validationInvocation, observation.invocation)
            assertEquals(
                if (compileValid) RepairValidationObservedOutcome.COMPILE_VALID
                else RepairValidationObservedOutcome.COMPILE_FAILED,
                observation.outcome,
            )
            assertEquals(validationProof, observation.proof)
            assertEquals(candidateDigest, observation.invocation.sourceRevisionSha256)
            assertEquals(validationProof.evidenceSha256, observation.primary.sha256)
            val retainedEvidence = project.resolve(observation.primary.path).readBytes()
            assertEquals(observation.primary.bytes, retainedEvidence.size.toLong())
            assertEquals(observation.primary.sha256, sha256(retainedEvidence))
            assertTrue(retainedEvidence.decodeToString().contains("\"outcome\":\"$outcomeName\""))
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair preserves an exact patch candidate after refusing an oversized retry`() {
        activeAcpRepairPreservesExactCandidateAfterRefusedRetry(ActiveAcpRepairQuota.PATCH_BYTES)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair enforces the filesystem write limit after retaining an exact candidate`() {
        activeAcpRepairPreservesExactCandidateAfterRefusedRetry(ActiveAcpRepairQuota.FILESYSTEM_WRITE_BYTES)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair enforces the filesystem read limit after an acknowledged candidate write`() {
        activeAcpRepairPreservesExactCandidateAfterRefusedRetry(ActiveAcpRepairQuota.FILESYSTEM_READ_BYTES)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair enforces the declared source-file byte grant after an acknowledged candidate`() {
        activeAcpRepairPreservesExactCandidateAfterRefusedRetry(ActiveAcpRepairQuota.SOURCE_FILE_BYTES)
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair rejects malformed Unicode after retaining the valid candidate`() {
        activeAcpRepairPreservesExactCandidateAfterRefusedRetry(ActiveAcpRepairQuota.INVALID_UNICODE)
    }

    private enum class ActiveAcpRepairQuota {
        PATCH_BYTES,
        FILESYSTEM_READ_BYTES,
        FILESYSTEM_WRITE_BYTES,
        SOURCE_FILE_BYTES,
        INVALID_UNICODE,
    }

    private fun activeAcpRepairPreservesExactCandidateAfterRefusedRetry(quota: ActiveAcpRepairQuota) {
        val readQuota = quota == ActiveAcpRepairQuota.FILESYSTEM_READ_BYTES
        val enforceAcpWriteLimit = quota == ActiveAcpRepairQuota.FILESYSTEM_WRITE_BYTES
        val sourceFileQuota = quota == ActiveAcpRepairQuota.SOURCE_FILE_BYTES
        val rejectInvalidUnicode = quota == ActiveAcpRepairQuota.INVALID_UNICODE
        val testRoot = Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(
                testRoot,
                if (readQuota) "repair-active-acp-read-quota-retry-" else if (enforceAcpWriteLimit) "repair-active-acp-write-quota-retry-" else
                    "repair-active-acp-patch-quota-retry-",
            ).resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val targetPath = "src/modules/reconstructed.c"
        val target = project.resolve(targetPath)
        val acceptedSource = target.readBytes()
        val acceptedMakefile = project.resolve("Makefile").readBytes()
        val patchLimit = 4096L
        val prefix = "/* exact repair quota-byte boundary: "
        val suffix = " */\nint decomp_engine_main(void) { return 1; }\n"
        val candidateLimit = patchLimit + if (readQuota) 1 else 0
        val paddingBytes =
            candidateLimit.toInt() - prefix.toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
        val padding = if (readQuota) {
            "q".repeat(paddingBytes)
        } else {
            "é".repeat(paddingBytes / 2) + if (paddingBytes % 2 == 1) "x" else ""
        }
        val candidateText = prefix + padding + suffix
        val candidateSource = candidateText.toByteArray(Charsets.UTF_8)
        assertEquals(candidateLimit, candidateSource.size.toLong())
        if (sourceFileQuota || rejectInvalidUnicode) {
            assertTrue(candidateText.length < candidateSource.size,
                "the active malformed-text case uses a bounded multibyte UTF-8 candidate")
            assertTrue('é' in candidateText)
        }
        val budget = RepairResourceBudget(
            maximumSourceFileBytes = if (sourceFileQuota) patchLimit else 64L * 1024,
            maximumPatchBytes = if (quota == ActiveAcpRepairQuota.PATCH_BYTES) patchLimit else 8L * 1024,
        )
        val filesystemLimits = AcpFilesystemLimits(
            maximumReadBytes = if (readQuota || sourceFileQuota) patchLimit.toInt() else 8 * 1024 * 1024,
            maximumWriteBytes = if (enforceAcpWriteLimit) patchLimit.toInt() else 8 * 1024 * 1024,
        )
        if (sourceFileQuota) assertEquals(candidateLimit, budget.maximumSourceFileBytes)
        else assertTrue(budget.maximumSourceFileBytes > candidateLimit)
        assertTrue(budget.maximumStagingBytes > candidateLimit)
        assertTrue(budget.maximumContextBytes > candidateLimit)
        assertTrue(budget.maximumPatchFiles > 1)
        if (quota == ActiveAcpRepairQuota.PATCH_BYTES) assertEquals(patchLimit, budget.maximumPatchBytes)
        else assertTrue(budget.maximumPatchBytes > candidateLimit)
        if (readQuota || sourceFileQuota) assertEquals(patchLimit.toInt(), filesystemLimits.maximumReadBytes)
        else assertTrue(filesystemLimits.maximumReadBytes > candidateLimit)
        val profile = requireNotNull(GeneratedCRepairIndexProfile.reconstructionProfile())
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use {
            it.snapshot.headId
        }
        val acp = AcpAgentHarnessTest().harness(
            if (readQuota) "repair-active-declared-role-read-limit-after-write"
            else if (rejectInvalidUnicode) "repair-active-declared-role-invalid-unicode-after-write"
            else "repair-active-declared-role-quota-retry",
            filesystemLimits = filesystemLimits,
        )
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                val grant = authority.grants.single()
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals(profile.sha256, grant.profileSha256)
                assertEquals(targetPath, grant.path.relativePath)
                assertEquals(setOf(AgentOperation.WRITE_FILE), grant.operations)
                assertEquals(budget.maximumSourceFileBytes, grant.maximumBytes)
                if (readQuota || sourceFileQuota) {
                    assertTrue(initialFiles.values.all { it.size <= filesystemLimits.maximumReadBytes })
                }
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedInvocation: RepairValidationInvocation? = null
        var observedCandidateDigest: String? = null
        val validationStop = IllegalStateException(
            when (quota) {
                ActiveAcpRepairQuota.PATCH_BYTES -> "patch-byte-limit-preserved candidate reached validator"
                ActiveAcpRepairQuota.FILESYSTEM_READ_BYTES -> "filesystem-read-limit-preserved candidate reached validator"
                ActiveAcpRepairQuota.FILESYSTEM_WRITE_BYTES -> "filesystem-write-limit-preserved candidate reached validator"
                ActiveAcpRepairQuota.SOURCE_FILE_BYTES -> "source-file-grant-preserved candidate reached validator"
                ActiveAcpRepairQuota.INVALID_UNICODE -> "invalid-Unicode refusal preserved candidate reached validator"
            },
        )
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertContentEquals(candidateSource, request.candidateSources.getValue(targetPath))
                assertEquals(candidateLimit, request.candidateSources.getValue(targetPath).size.toLong())
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = assertNotNull(request.invocation)
                throw validationStop
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate validation must use the immutable source snapshot")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate validation must use the immutable source snapshot")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must use the immutable source snapshot")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                emptyList(),
            )
        }
        assertSame(validationStop, failure)
        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        val invocation = assertNotNull(observedInvocation)
        assertContentEquals(acceptedSource, target.readBytes())
        assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes())
        assertTrue(validationStop.suppressed.isEmpty(), validationStop.suppressed.joinToString())

        val rawGraph = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertEquals(invocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(invocation.candidateRevisionId, rejected.id)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(invocation.runId, rejected.repairMetadata?.runId)
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            val changes = result.getValue("changes").jsonObject
            assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
            val change = changes.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            assertEquals(sha256(acceptedSource), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(sha256(candidateSource), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(candidateLimit, change.getValue("sizeBytes").jsonPrimitive.content.toLong())
            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            val expectedOutcomes = if (readQuota) listOf("allowed", "denied") else
                listOf("allowed", "denied", "allowed")
            val expectedReasons = when {
                readQuota -> listOf("completed", "resource-limit")
                sourceFileQuota -> listOf("completed", "policy-denied", "completed")
                rejectInvalidUnicode -> listOf("completed", "invalid-text", "completed")
                else -> listOf("completed", "resource-limit", "completed")
            }
            assertEquals(expectedOutcomes.size, filesystem.getValue("recordCount").jsonPrimitive.int)
            val auditRecords = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(expectedOutcomes, auditRecords.map {
                it.getValue("outcome").jsonPrimitive.content
            })
            assertEquals(expectedReasons, auditRecords.map {
                it.getValue("reason").jsonPrimitive.content
            })
            assertTrue(auditRecords.all {
                it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                    .getValue("sha256").jsonPrimitive.content == sha256(targetPath.toByteArray(Charsets.UTF_8))
            })

            val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(assertNotNull(observedCandidateDigest), assessment.afterSha256)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair preserves an exact staging candidate after refusing an oversized retry`() {
        val targetPath = "src/modules/reconstructed.c"
        val candidateBytes = 4096L
        val diagnostic = "$targetPath: compiler error"
        val sizingProject = createProject(
            createRepairTempDirectory("repair-active-acp-staging-quota-sizing-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sizingContext = ModuleRevisionGraph.open(sizingProject, GeneratedCRepairIndexProfile).use { graph ->
            graph.selectContext("compile", diagnostic).let { selection ->
                selection to graph.preflightStagingContext(selection)
            }
        }
        val contextWithoutTarget = sizingContext.second.filterKeys { it != targetPath }
        assertTrue(targetPath in sizingContext.second)
        val otherContextBytes = contextWithoutTarget.values.fold(0L) { total, bytes ->
            Math.addExact(total, bytes.size.toLong())
        }
        val stagingLimit = Math.addExact(otherContextBytes, candidateBytes)
        assertEquals(sizingContext.first.totalBytes, sizingContext.second.values.sumOf { it.size.toLong() })

        val project = createProject(
            createRepairTempDirectory("repair-active-acp-staging-quota-retry-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val acceptedPaths = listOf(
            "Makefile",
            "include/modules/reconstructed.h",
            "src/main.c",
            targetPath,
        )
        val acceptedFiles = acceptedPaths.associateWith { project.resolve(it).readBytes() }
        val candidatePrefix = "/* exact repair quota-byte boundary: "
        val candidateSuffix = " */\nint decomp_engine_main(void) { return 1; }\n"
        val candidatePaddingBytes = candidateBytes.toInt() -
            candidatePrefix.toByteArray(Charsets.UTF_8).size - candidateSuffix.toByteArray(Charsets.UTF_8).size
        val candidatePadding = "é".repeat(candidatePaddingBytes / 2) +
            if (candidatePaddingBytes % 2 == 1) "x" else ""
        val candidateText = candidatePrefix + candidatePadding + candidateSuffix
        val candidateSource = candidateText.toByteArray(Charsets.UTF_8)
        assertEquals(candidateBytes, candidateSource.size.toLong())
        assertTrue(candidateText.length < candidateSource.size,
            "the active staging fixture must compare encoded UTF-8 bytes, not character count")
        val budget = RepairResourceBudget(maximumStagingBytes = stagingLimit)
        assertEquals(otherContextBytes + candidateBytes, budget.maximumStagingBytes)
        assertTrue(budget.maximumSourceFileBytes > candidateBytes + 1)
        assertTrue(budget.maximumPatchBytes > candidateBytes + 1)
        assertTrue(budget.maximumPatchFiles > 1)
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use {
            it.snapshot.headId
        }
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-quota-retry")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                assertEquals(sizingContext.second.keys, initialFiles.keys)
                sizingContext.second.forEach { (path, bytes) -> assertContentEquals(bytes, initialFiles.getValue(path)) }
                val admittedBytes = initialFiles.values.fold(0L) { total, bytes ->
                    Math.addExact(total, bytes.size.toLong())
                }
                assertEquals(sizingContext.first.totalBytes, admittedBytes)
                assertEquals(stagingLimit, admittedBytes - initialFiles.getValue(targetPath).size + candidateBytes)
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                val grant = authority.grants.single()
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals(targetPath, grant.path.relativePath)
                assertEquals(budget.maximumSourceFileBytes, grant.maximumBytes)
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedInvocation: RepairValidationInvocation? = null
        var observedCandidateDigest: String? = null
        val validationStop = IllegalStateException("staging-preserved candidate reached validator")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(acceptedFiles.keys, request.candidateSourcePaths.toSet())
                acceptedFiles.filterKeys { it != targetPath }.forEach { (path, bytes) ->
                    assertContentEquals(bytes, request.candidateSources.getValue(path), path)
                }
                assertContentEquals(candidateSource, request.candidateSources.getValue(targetPath))
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = assertNotNull(request.invocation)
                throw validationStop
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate validation must use the immutable source snapshot")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate validation must use the immutable source snapshot")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must use the immutable source snapshot")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(project, CompileFailure(listOf("make"), 2, "", diagnostic), emptyList())
        }
        assertSame(validationStop, failure)
        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        val invocation = assertNotNull(observedInvocation)
        acceptedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
        assertTrue(validationStop.suppressed.isEmpty(), validationStop.suppressed.joinToString())

        val rawGraph = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertEquals(invocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(invocation.candidateRevisionId, rejected.id)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(invocation.runId, rejected.repairMetadata?.runId)
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            val changes = result.getValue("changes").jsonObject
            assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
            val change = changes.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            assertEquals(sha256(acceptedFiles.getValue(targetPath)), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(sha256(candidateSource), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(candidateBytes, change.getValue("sizeBytes").jsonPrimitive.content.toLong())
            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            assertEquals(3, filesystem.getValue("recordCount").jsonPrimitive.int)
            val auditRecords = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(listOf("allowed", "denied", "allowed"), auditRecords.map {
                it.getValue("outcome").jsonPrimitive.content
            })
            assertEquals(listOf("completed", "resource-limit", "completed"), auditRecords.map {
                it.getValue("reason").jsonPrimitive.content
            })
            assertTrue(auditRecords.all {
                it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                    .getValue("sha256").jsonPrimitive.content == sha256(targetPath.toByteArray(Charsets.UTF_8))
            })

            val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(assertNotNull(observedCandidateDigest), assessment.afterSha256)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair reuses a patch slot after restoring the first file`() {
        val testRoot = Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-acp-patch-count-retry-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        val secondBefore = "int secondary(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        project.resolve(secondPath).writeBytes(secondBefore)
        val failureText = "$firstPath: compiler error\n$secondPath: compiler error"
        val firstCandidate = "/* retained one-file patch */\nint decomp_engine_main(void) { return 1; }\n"
            .toByteArray(Charsets.UTF_8)
        val secondCandidate = "int secondary(void) { return 1; }\n".toByteArray(Charsets.UTF_8)
        val acceptedPaths = listOf(
            "Makefile",
            "include/modules/reconstructed.h",
            "src/main.c",
            firstPath,
            secondPath,
        )
        val acceptedFiles = acceptedPaths.associateWith { project.resolve(it).readBytes() }
        val budget = RepairResourceBudget(maximumPatchFiles = 1)
        assertTrue(budget.maximumSourceFileBytes > maxOf(firstCandidate.size, secondCandidate.size))
        assertTrue(budget.maximumPatchBytes > firstCandidate.size + secondCandidate.size)
        assertTrue(budget.maximumStagingBytes > firstCandidate.size + secondCandidate.size)
        val graphAdmission = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
            Triple(graph.snapshot.headId, context, graph.preflightStagingContext(context))
        }
        val baselineHead = graphAdmission.first
        val selectedContextFiles = graphAdmission.third
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-patch-count-retry")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                assertEquals(graphAdmission.second.readablePaths.toSet(), initialFiles.keys)
                selectedContextFiles.forEach { (path, bytes) ->
                    assertContentEquals(bytes, initialFiles.getValue(path), path)
                }
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals(setOf(firstPath, secondPath), authority.grants.map { it.path.relativePath }.toSet())
                assertTrue(authority.grants.all {
                    it.operations == setOf(AgentOperation.WRITE_FILE) &&
                        it.maximumBytes == budget.maximumSourceFileBytes
                })
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedInvocation: RepairValidationInvocation? = null
        var observedCandidateDigest: String? = null
        val validationStop = IllegalStateException("reused one-file patch candidate reached validator")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(acceptedFiles.keys, request.candidateSourcePaths.toSet())
                acceptedFiles.filterKeys { it != secondPath }.forEach { (path, bytes) ->
                    assertContentEquals(bytes, request.candidateSources.getValue(path), path)
                }
                assertContentEquals(secondCandidate, request.candidateSources.getValue(secondPath))
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = assertNotNull(request.invocation)
                throw validationStop
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate validation must use the immutable source snapshot")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate validation must use the immutable source snapshot")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must use the immutable source snapshot")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(project, CompileFailure(listOf("make"), 2, "", failureText), emptyList())
        }
        assertSame(validationStop, failure)
        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        val invocation = assertNotNull(observedInvocation)
        acceptedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }

        val rawGraph = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertEquals(invocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(invocation.candidateRevisionId, rejected.id)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(invocation.runId, rejected.repairMetadata?.runId)
            assertEquals("returned-completed", binding.terminalOutcome)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            val changes = result.getValue("changes").jsonObject
            assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
            val change = changes.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            val relativePath = secondPath.encodeToByteArray()
            val relativePathCommitment = change.getValue("relativePath").jsonObject
            assertEquals(sha256(relativePath), relativePathCommitment.getValue("sha256").jsonPrimitive.content)
            assertEquals(relativePath.size, relativePathCommitment.getValue("encodedBytes").jsonPrimitive.int)
            assertEquals("utf-8", relativePathCommitment.getValue("encoding").jsonPrimitive.content)
            assertEquals(sha256(secondBefore), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(sha256(secondCandidate), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(secondCandidate.size.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())
            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            assertEquals(8, filesystem.getValue("recordCount").jsonPrimitive.int)
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(
                listOf("write", "write", "read", "read", "write", "write", "read", "read").map {
                    sha256("fs/${it}_text_file".toByteArray(Charsets.UTF_8))
                },
                records.map {
                    it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content
                },
            )
            assertEquals(listOf("allowed", "denied", "allowed", "allowed", "allowed", "allowed", "allowed", "allowed"), records.map {
                it.getValue("outcome").jsonPrimitive.content
            })
            assertEquals(listOf("completed", "resource-limit", "completed", "completed", "completed", "completed", "completed", "completed"), records.map {
                it.getValue("reason").jsonPrimitive.content
            })
            assertEquals(listOf(firstPath, secondPath, firstPath, secondPath, firstPath, secondPath, firstPath, secondPath), records.map {
                it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                    .getValue("sha256").jsonPrimitive.content.let { pathDigest ->
                        mapOf(
                            sha256(firstPath.toByteArray(Charsets.UTF_8)) to firstPath,
                            sha256(secondPath.toByteArray(Charsets.UTF_8)) to secondPath,
                        ).getValue(pathDigest)
                    }
            })

            val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(assertNotNull(observedCandidateDigest), assessment.afterSha256)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active ACP repair reclaims aggregate patch bytes after shrink and baseline restoration`() {
        val testRoot = Path.of("build/test-tmp").createDirectories()
        val project = createProject(
            Files.createTempDirectory(testRoot, "repair-active-acp-patch-byte-reuse-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        val secondBefore = "int secondary(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        project.resolve(secondPath).writeBytes(secondBefore)
        val failureText = "$firstPath: compiler error\n$secondPath: compiler error"

        fun paddedSource(prefix: String, suffix: String, size: Int): ByteArray {
            val paddingBytes = size - prefix.toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
            assertTrue(paddingBytes >= 0)
            return (prefix + "x".repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8).also {
                assertEquals(size, it.size)
            }
        }

        val firstLarge = paddedSource("/* first-large ", " */\nint decomp_engine_main(void) { return 1; }\n", 2048)
        val firstSmall = paddedSource("/* first-small ", " */\nint decomp_engine_main(void) { return 1; }\n", 1024)
        val secondSmall = paddedSource("/* second-small ", " */\nint secondary(void) { return 1; }\n", 2048)
        val secondOver = paddedSource("/* second-over ", " */\nint secondary(void) { return 1; }\n", 2049)
        val secondLarge = paddedSource("/* second-large ", " */\nint secondary(void) { return 1; }\n", 3072)
        val secondLargeOver = paddedSource(
            "/* second-large-over ", " */\nint secondary(void) { return 1; }\n", 3073,
        )
        val secondExact = paddedSource("/* second-exact ", " */\nint secondary(void) { return 1; }\n", 4096)
        val acceptedPaths = listOf(
            "Makefile",
            "include/modules/reconstructed.h",
            "src/main.c",
            firstPath,
            secondPath,
        )
        val acceptedFiles = acceptedPaths.associateWith { project.resolve(it).readBytes() }
        val budget = RepairResourceBudget(maximumPatchFiles = 2, maximumPatchBytes = 4096)
        assertTrue(budget.maximumSourceFileBytes > secondExact.size)
        assertTrue(budget.maximumContextBytes > firstLarge.size + secondExact.size)
        assertTrue(budget.maximumStagingBytes > firstLarge.size + secondExact.size)
        val graphAdmission = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
            Triple(graph.snapshot.headId, context, graph.preflightStagingContext(context))
        }
        val baselineHead = graphAdmission.first
        val selectedContextFiles = graphAdmission.third
        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-patch-byte-reuse")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                assertEquals(graphAdmission.second.readablePaths.toSet(), initialFiles.keys)
                selectedContextFiles.forEach { (path, bytes) -> assertContentEquals(bytes, initialFiles.getValue(path), path) }
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals(setOf(firstPath, secondPath), authority.grants.map { it.path.relativePath }.toSet())
                assertTrue(authority.grants.all {
                    it.operations == setOf(AgentOperation.WRITE_FILE) &&
                        it.maximumBytes == budget.maximumSourceFileBytes
                })
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedInvocation: RepairValidationInvocation? = null
        var observedCandidateDigest: String? = null
        val validationStop = IllegalStateException("aggregate patch-byte candidate reached validator")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(acceptedFiles.keys, request.candidateSourcePaths.toSet())
                acceptedFiles.filterKeys { it != secondPath }.forEach { (path, bytes) ->
                    assertContentEquals(bytes, request.candidateSources.getValue(path), path)
                }
                assertContentEquals(secondExact, request.candidateSources.getValue(secondPath))
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = assertNotNull(request.invocation)
                throw validationStop
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate validation must use the immutable source snapshot")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate validation must use the immutable source snapshot")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must use the immutable source snapshot")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(project, CompileFailure(listOf("make"), 2, "", failureText), emptyList())
        }
        assertSame(validationStop, failure)
        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        val invocation = assertNotNull(observedInvocation)
        acceptedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }

        val rawGraph = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertEquals(invocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(invocation.candidateRevisionId, rejected.id)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(invocation.runId, rejected.repairMetadata?.runId)
            assertEquals("returned-completed", binding.terminalOutcome)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            val changes = result.getValue("changes").jsonObject
            assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
            val change = changes.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            val pathCommitment = change.getValue("relativePath").jsonObject
            assertEquals(sha256(secondPath.toByteArray(Charsets.UTF_8)), pathCommitment.getValue("sha256").jsonPrimitive.content)
            assertEquals(secondPath.toByteArray(Charsets.UTF_8).size, pathCommitment.getValue("encodedBytes").jsonPrimitive.int)
            assertEquals(sha256(secondBefore), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(sha256(secondExact), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(secondExact.size.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())

            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            assertEquals(13, filesystem.getValue("recordCount").jsonPrimitive.int)
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(13, records.size)
            assertEquals(
                listOf("write", "write", "write", "read", "read", "write", "write", "write", "read", "write", "write", "read", "read")
                    .map { sha256("fs/${it}_text_file".toByteArray(Charsets.UTF_8)) },
                records.map { it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content },
            )
            assertEquals(
                listOf("allowed", "allowed", "denied", "allowed", "allowed", "allowed", "allowed", "denied", "allowed", "allowed", "allowed", "allowed", "allowed"),
                records.map { it.getValue("outcome").jsonPrimitive.content },
            )
            assertEquals(
                listOf("completed", "completed", "resource-limit", "completed", "completed", "completed", "completed", "resource-limit", "completed", "completed", "completed", "completed", "completed"),
                records.map { it.getValue("reason").jsonPrimitive.content },
            )
            val auditPaths = listOf(
                firstPath, secondPath, secondPath, firstPath, secondPath, firstPath, secondPath,
                secondPath, secondPath, firstPath, secondPath, firstPath, secondPath,
            )
            assertEquals(
                auditPaths.map { sha256(it.toByteArray(Charsets.UTF_8)) },
                records.map {
                    it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                        .getValue("sha256").jsonPrimitive.content
                },
            )

            val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(assertNotNull(observedCandidateDigest), assessment.afterSha256)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 180, unit = TimeUnit.SECONDS)
    fun `active ACP repair enforces staging bytes across rewrites and baseline restoration`() {
        val firstPath = "src/modules/reconstructed.c"
        val secondPath = "src/modules/secondary.c"
        fun paddedSource(prefix: String, suffix: String, size: Int, padding: Char = 'x'): ByteArray {
            val paddingBytes = size - prefix.toByteArray(Charsets.UTF_8).size - suffix.toByteArray(Charsets.UTF_8).size
            assertTrue(paddingBytes >= 0)
            return (prefix + padding.toString().repeat(paddingBytes) + suffix).toByteArray(Charsets.UTF_8).also {
                assertEquals(size, it.size)
            }
        }

        val firstOriginal = paddedSource(
            "/* first-original ", " */\nint decomp_engine_main(void) { return 0; }\n", 1025, 'o',
        )
        val secondOriginal = paddedSource("/* second-original ", " */\nint secondary(void) { return 0; }\n", 2048)
        val failureText = "$firstPath: compiler error\n$secondPath: compiler error"
        val firstLarge = paddedSource("/* first-large ", " */\nint decomp_engine_main(void) { return 1; }\n", 2048)
        val firstSmall = paddedSource("/* first-small ", " */\nint decomp_engine_main(void) { return 1; }\n", 1024)
        val secondSmall = paddedSource("/* second-small ", " */\nint secondary(void) { return 1; }\n", 2048)
        val secondOver = paddedSource("/* second-over ", " */\nint secondary(void) { return 1; }\n", 2049)
        val secondLarge = paddedSource("/* second-large ", " */\nint secondary(void) { return 1; }\n", 3072)
        val secondLargeOver = paddedSource(
            "/* second-large-over ", " */\nint secondary(void) { return 1; }\n", 3073,
        )
        val secondShrunk = paddedSource("/* second-shrunk ", " */\nint secondary(void) { return 1; }\n", 3071)

        val sizingProject = createProject(
            createRepairTempDirectory("repair-active-acp-staging-byte-sizing-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        sizingProject.resolve(firstPath).writeBytes(firstOriginal)
        sizingProject.resolve(secondPath).writeBytes(secondOriginal)
        val sizingContext = ModuleRevisionGraph.open(sizingProject, GeneratedCRepairIndexProfile).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
            graph.preflightStagingContext(context)
        }
        val unchangedContextBytes = sizingContext.filterKeys { it != firstPath && it != secondPath }
            .values.fold(0L) { total, bytes -> Math.addExact(total, bytes.size.toLong()) }
        val stagingLimit = Math.addExact(unchangedContextBytes, 4096L)
        assertEquals(sizingContext.values.sumOf { it.size.toLong() }, unchangedContextBytes + 1025L + 2048L)

        val project = createProject(
            createRepairTempDirectory("repair-active-acp-staging-byte-reuse-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        project.resolve(firstPath).writeBytes(firstOriginal)
        project.resolve(secondPath).writeBytes(secondOriginal)

        val acceptedPaths = listOf(
            "Makefile",
            "include/modules/reconstructed.h",
            "src/main.c",
            firstPath,
            secondPath,
        )
        val acceptedFiles = acceptedPaths.associateWith { project.resolve(it).readBytes() }
        val activeBudget = RepairResourceBudget(
            maximumSourceFileBytes = 16 * 1024,
            maximumContextBytes = 64 * 1024,
            maximumStagingBytes = stagingLimit,
            maximumPatchFiles = 2,
            maximumPatchBytes = 16 * 1024,
        )
        val graphAdmission = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, activeBudget).use { graph ->
            val context = graph.selectContext("compile", failureText)
            assertEquals(setOf(firstPath, secondPath), context.writablePaths.toSet())
            Triple(graph.snapshot.headId, context, graph.preflightStagingContext(context))
        }
        val contextFiles = graphAdmission.third
        assertEquals(sizingContext.keys, contextFiles.keys)
        sizingContext.forEach { (path, bytes) -> assertContentEquals(bytes, contextFiles.getValue(path), path) }
        val actualUnchangedContextBytes = contextFiles.filterKeys { it != firstPath && it != secondPath }
            .values.fold(0L) { total, bytes -> Math.addExact(total, bytes.size.toLong()) }
        assertEquals(unchangedContextBytes, actualUnchangedContextBytes)
        assertEquals(unchangedContextBytes + 4096L, activeBudget.maximumStagingBytes)
        assertTrue(activeBudget.maximumContextBytes > contextFiles.values.sumOf { it.size.toLong() })
        assertTrue(activeBudget.maximumPatchBytes > 2048L + 2048L + 1L)
        assertTrue(activeBudget.maximumSourceFileBytes > secondLargeOver.size.toLong())

        val acp = AcpAgentHarnessTest().harness("repair-active-declared-role-staging-byte-reuse")
        var dispatches = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.execute(request, onEvent)

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                turnIdentity: decompengine.agent.AgentTurnIdentity,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                dispatches++
                assertEquals(contextFiles.keys, initialFiles.keys)
                contextFiles.forEach { (path, bytes) -> assertContentEquals(bytes, initialFiles.getValue(path), path) }
                val authority = assertNotNull(request.accessPolicy.mutationAuthority)
                assertEquals("declared-role-generated-c-repair-v1", authority.policyId)
                assertEquals(setOf(firstPath, secondPath), authority.grants.map { it.path.relativePath }.toSet())
                assertTrue(authority.grants.all {
                    it.operations == setOf(AgentOperation.WRITE_FILE) &&
                        it.maximumBytes == activeBudget.maximumSourceFileBytes
                })
                return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
            }
        }
        var validationCalls = 0
        var observedInvocation: RepairValidationInvocation? = null
        var observedCandidateDigest: String? = null
        val validationStop = IllegalStateException("staging-byte candidate reached validator")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.STRICT_CONTAINED
            override fun requireAvailable() = Unit
            override fun validateCandidate(
                request: RepairCandidateValidationRequest,
            ): RepairCandidateValidationOutcome {
                validationCalls++
                assertEquals(acceptedFiles.keys, request.candidateSourcePaths.toSet())
                acceptedFiles.filterKeys { it != secondPath }.forEach { (path, bytes) ->
                    assertContentEquals(bytes, request.candidateSources.getValue(path), path)
                }
                assertContentEquals(secondShrunk, request.candidateSources.getValue(secondPath))
                val candidateDigest = decompengine.repair.repairCandidateSourceSha256(request.candidateSources)
                assertEquals(candidateDigest, request.sourceRevisionSha256)
                observedCandidateDigest = candidateDigest
                observedInvocation = assertNotNull(request.invocation)
                throw validationStop
            }
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                error("candidate validation must use the immutable source snapshot")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("candidate validation must use the immutable source snapshot")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ): BehaviorComparisonReport = error("candidate validation must use the immutable source snapshot")
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = GeneratedCRepairIndexProfile,
            validationStrategy = validation,
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = activeBudget,
            allowTestOnlyValidation = false,
            faultInjector = null,
        )

        val failure = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(project, CompileFailure(listOf("make"), 2, "", failureText), emptyList())
        }
        assertSame(validationStop, failure)
        assertEquals(1, dispatches)
        assertEquals(1, validationCalls)
        val invocation = assertNotNull(observedInvocation)
        acceptedFiles.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }

        val rawGraph = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject
        assertEquals(JsonNull, rawGraph.getValue("pending"))
        assertEquals(graphAdmission.first, rawGraph.getValue("headId").jsonPrimitive.content)
        val rawRejected = rawGraph.getValue("nodes").jsonArray.last().jsonObject
        assertEquals("rejected", rawRejected.getValue("status").jsonPrimitive.content)
        assertEquals(invocation.candidateRevisionId, rawRejected.getValue("id").jsonPrimitive.content)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, activeBudget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(graphAdmission.first, graph.snapshot.headId)
            assertEquals(RepairRunStatus.VALIDATION_FAILED, graph.snapshot.runs.last().status)
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(invocation.candidateRevisionId, rejected.id)
            val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(invocation.runId, rejected.repairMetadata?.runId)
            assertEquals("returned-completed", binding.terminalOutcome)

            val receiptBytes = project.resolve(binding.receiptPath).readBytes()
            assertEquals(binding.receiptSha256, sha256(receiptBytes))
            val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
            val process = receipt.getValue("process").jsonObject
            assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int)
            assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean)
            val result = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
            assertEquals("completed", result.getValue("stopReason").jsonPrimitive.content)
            val changes = result.getValue("changes").jsonObject
            assertEquals(1, changes.getValue("observedCount").jsonPrimitive.int)
            val change = changes.getValue("records").jsonArray.single().jsonObject
            assertEquals("modified", change.getValue("kind").jsonPrimitive.content)
            val pathCommitment = change.getValue("relativePath").jsonObject
            assertEquals(sha256(secondPath.toByteArray(Charsets.UTF_8)), pathCommitment.getValue("sha256").jsonPrimitive.content)
            assertEquals(sha256(secondOriginal), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(sha256(secondShrunk), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(secondShrunk.size.toLong(), change.getValue("sizeBytes").jsonPrimitive.content.toLong())

            val filesystem = receipt.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
            val methods = listOf("write", "write", "write", "read", "read", "write", "write", "write", "read", "read", "write", "read", "read", "write", "write", "read", "read")
            val expectedOutcomes = listOf("allowed", "allowed", "denied", "allowed", "allowed", "allowed", "allowed", "denied", "allowed", "allowed", "denied", "allowed", "allowed", "allowed", "allowed", "allowed", "allowed")
            val expectedReasons = listOf("completed", "completed", "resource-limit", "completed", "completed", "completed", "completed", "resource-limit", "completed", "completed", "resource-limit", "completed", "completed", "completed", "completed", "completed", "completed")
            val expectedPaths = listOf(firstPath, secondPath, secondPath, firstPath, secondPath, firstPath, secondPath, secondPath, firstPath, secondPath, firstPath, firstPath, secondPath, secondPath, firstPath, firstPath, secondPath)
            val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
            assertEquals(methods.size, filesystem.getValue("recordCount").jsonPrimitive.int)
            assertEquals(methods.size, records.size)
            assertEquals(methods.map { sha256("fs/${it}_text_file".toByteArray(Charsets.UTF_8)) },
                records.map { it.getValue("method").jsonObject.getValue("sha256").jsonPrimitive.content })
            assertEquals(expectedOutcomes, records.map { it.getValue("outcome").jsonPrimitive.content })
            assertEquals(expectedReasons, records.map { it.getValue("reason").jsonPrimitive.content })
            assertEquals(expectedPaths.map { sha256(it.toByteArray(Charsets.UTF_8)) }, records.map {
                it.getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                    .getValue("sha256").jsonPrimitive.content
            })

            val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
            assertEquals(binding.assessmentSha256, sha256(assessmentBytes))
            val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
            assertEquals(binding.receiptSha256, assessment.receiptSha256)
            assertEquals(assertNotNull(observedCandidateDigest), assessment.afterSha256)
            assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED, assessment.eligibility)
            assertEquals(decompengine.project.AcpChangeValidationStatus.FAILED, assessment.validationStatus)
        }
    }

    @Test
    fun `active ACP repair deadlines retain timeout receipts after an acknowledged write`() {
        data class DeadlineCase(
            val id: String,
            val limits: AgentExecutionLimits,
            val expectedDiagnostic: String,
        )
        val cases = listOf(
            DeadlineCase(
                "wall",
                AgentExecutionLimits(
                    wallClockTimeout = Duration.ofSeconds(12),
                    idleTimeout = Duration.ofSeconds(30),
                ),
                "wall-clock",
            ),
            DeadlineCase(
                "idle",
                AgentExecutionLimits(
                    wallClockTimeout = Duration.ofSeconds(30),
                    idleTimeout = Duration.ofSeconds(12),
                ),
                "idle",
            ),
        )
        val testRoot = java.nio.file.Path.of("build/test-tmp").createDirectories()
        for (case in cases) {
            val project = createProject(
                Files.createTempDirectory(testRoot, "repair-active-acp-${case.id}-timeout-").resolve("project"),
                reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
            )
            val targetPath = "src/modules/reconstructed.c"
            val target = project.resolve(targetPath)
            val acceptedSource = target.readBytes()
            val acceptedMakefile = project.resolve("Makefile").readBytes()
            val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { it.snapshot.headId }
            val acp = AcpAgentHarnessTest().harness(
                "repair-active-declared-role-timeout-after-write",
                timeouts = AcpLifecycleTimeouts(request = Duration.ofSeconds(45)),
            )
            var dispatchedRequest: AgentExecutionRequest? = null
            var dispatchedIdentity: decompengine.agent.AgentTurnIdentity? = null
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.execute(request, onEvent)

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = acp.executeCaptured(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt = acp.executeCapturedReceipt(request, initialFiles, output, onEvent)

                override fun executeCapturedReceipt(
                    request: AgentExecutionRequest,
                    turnIdentity: decompengine.agent.AgentTurnIdentity,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionReceipt {
                    dispatchedRequest = request
                    dispatchedIdentity = turnIdentity
                    assertTrue(request.limits.wallClockTimeout <= case.limits.wallClockTimeout)
                    assertEquals(case.limits.idleTimeout, request.limits.idleTimeout)
                    assertEquals(
                        AgentExecutionRequestBinding.capture(request).requestSha256,
                        turnIdentity.requestSha256,
                    )
                    return acp.executeCapturedReceipt(request, turnIdentity, initialFiles, output, onEvent)
                }
            }
            var validationCalls = 0
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome {
                    validationCalls++
                    error("deadline refusal must occur before candidate validation")
                }
                override fun compile(projectDir: java.nio.file.Path, logPath: java.nio.file.Path,
                                     budget: RepairResourceBudget): CompileFailure? =
                    error("deadline refusal must not reach mutable-tree compilation")
                override fun rebuiltProgram(projectDir: java.nio.file.Path,
                                           budget: RepairResourceBudget): java.nio.file.Path =
                    error("deadline refusal must not rebuild a candidate")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: java.nio.file.Path,
                    originalBinary: java.nio.file.Path,
                    rebuiltBinary: java.nio.file.Path,
                    inputs: List<ProcessInput>,
                    reportsDir: java.nio.file.Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("deadline refusal must not run behavior validation")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = GeneratedCRepairIndexProfile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = case.limits,
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = RepairResourceBudget(),
                allowTestOnlyValidation = false,
                faultInjector = null,
            )

            val failure = assertFailsWith<Exception>(case.id) {
                loop.repairCompileError(
                    project,
                    CompileFailure(listOf("make"), 2, "", "$targetPath: compiler error"),
                    emptyList(),
                )
            }
            val failureChain = generateSequence<Throwable>(failure) { it.cause }.toList()
            val executionFailure = failureChain.filterIsInstance<AgentExecutionException>().single()
            assertEquals(AgentFailureKind.TIMEOUT, executionFailure.failure.kind, case.id)
            assertTrue(
                executionFailure.failure.message.contains(case.expectedDiagnostic, ignoreCase = true),
                executionFailure.failure.message,
            )
            assertTrue(failure.suppressed.isEmpty(), failure.suppressed.joinToString())
            assertEquals(0, validationCalls, case.id)

            val request = assertNotNull(dispatchedRequest, case.id)
            val identity = assertNotNull(dispatchedIdentity, case.id)
            val expectedRequestDigest = AgentExecutionRequestBinding.capture(request).requestSha256
            assertEquals(expectedRequestDigest, identity.requestSha256, case.id)
            assertContentEquals(acceptedSource, target.readBytes(), case.id)
            assertContentEquals(acceptedMakefile, project.resolve("Makefile").readBytes(), case.id)

            val graphBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()
            val rawGraph = Json.parseToJsonElement(graphBytes.decodeToString()).jsonObject
            assertEquals(JsonNull, rawGraph.getValue("pending"), case.id)
            assertEquals(baselineHead, rawGraph.getValue("headId").jsonPrimitive.content, case.id)
            val rawNode = rawGraph.getValue("nodes").jsonArray.last().jsonObject
            assertEquals("rejected", rawNode.getValue("status").jsonPrimitive.content, case.id)
            assertFalse(rawNode.getValue("recoveredAfterCrash").jsonPrimitive.boolean, case.id)
            assertEquals("resource_exhausted", rawGraph.getValue("runs").jsonArray.last()
                .jsonObject.getValue("status").jsonPrimitive.content, case.id)

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId, case.id)
                assertEquals(baselineHead, graph.snapshot.headId, case.id)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status, case.id)
                val rejected = graph.snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status, case.id)
                assertFalse(rejected.recoveredAfterCrash, case.id)
                assertEquals(identity.taskId, rejected.id, case.id)
                assertEquals(graph.snapshot.runs.last().id, identity.workflowRunId, case.id)
                val binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
                assertEquals(identity.turnId, binding.turnId, case.id)
                assertEquals(expectedRequestDigest, binding.requestSha256, case.id)
                assertEquals("failed-timeout", binding.terminalOutcome, case.id)
                assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus, case.id)
                assertFalse(binding.receiptReleaseComplete, case.id)

                val receiptBytes = project.resolve(binding.receiptPath).readBytes()
                assertEquals(binding.receiptSha256, sha256(receiptBytes), case.id)
                val receipt = Json.parseToJsonElement(receiptBytes.decodeToString()).jsonObject
                assertEquals("failed", receipt.getValue("outcome").jsonObject.getValue("type").jsonPrimitive.content, case.id)
                val failureJson = receipt.getValue("outcome").jsonObject.getValue("failure").jsonObject
                assertEquals("timeout", failureJson.getValue("kind").jsonPrimitive.content, case.id)
                val messageCommitment = failureJson.getValue("message").jsonObject
                assertTrue(messageCommitment.getValue("encodedBytes").jsonPrimitive.int > 0, case.id)
                assertTrue(messageCommitment.getValue("sha256").jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")), case.id)
                val receiptTurn = receipt.getValue("turnIdentity").jsonObject
                assertEquals(identity.turnId, receiptTurn.getValue("turnId").jsonPrimitive.content, case.id)
                assertEquals(identity.taskId, receiptTurn.getValue("taskId").jsonPrimitive.content, case.id)
                assertEquals(expectedRequestDigest, receiptTurn.getValue("requestSha256").jsonPrimitive.content, case.id)
                val lifecycle = receipt.getValue("lifecycle").jsonObject
                assertEquals("prompt-dispatched", lifecycle.getValue("phaseReached").jsonPrimitive.content, case.id)
                assertFalse(lifecycle.getValue("releaseComplete").jsonPrimitive.boolean, case.id)
                val process = receipt.getValue("process").jsonObject
                assertEquals(0, process.getValue("remainingProcessCount").jsonPrimitive.int, case.id)
                assertTrue(process.getValue("sandboxCleanupVerified").jsonPrimitive.boolean, case.id)

                val filesystem = receipt.getValue("policyAudits").jsonObject
                    .getValue("filesystem").jsonObject
                val records = filesystem.getValue("records").jsonArray.map { it.jsonObject }
                assertEquals(1, filesystem.getValue("recordCount").jsonPrimitive.int, case.id)
                assertEquals("allowed", records.single().getValue("outcome").jsonPrimitive.content, case.id)
                assertEquals("completed", records.single().getValue("reason").jsonPrimitive.content, case.id)
                assertEquals(sha256(targetPath.toByteArray(Charsets.UTF_8)), records.single()
                    .getValue("policyPath").jsonObject.getValue("relativePath").jsonObject
                    .getValue("sha256").jsonPrimitive.content, case.id)

                val intentPath = requireNotNull(binding.intentPath)
                val intentBytes = project.resolve(intentPath).readBytes()
                assertEquals(binding.intentSha256, sha256(intentBytes), case.id)
                val assessmentBytes = project.resolve(requireNotNull(binding.assessmentPath)).readBytes()
                assertEquals(binding.assessmentSha256, sha256(assessmentBytes), case.id)
                val assessment = decompengine.project.AcpChangeAssessment.parse(assessmentBytes)
                assertEquals(binding.receiptSha256, assessment.receiptSha256, case.id)
                assertEquals(identity.turnId, assessment.turnId, case.id)
                assertEquals(decompengine.project.AcpChangePublicationEligibility.REJECTED,
                    assessment.eligibility, case.id)
                assertEquals(decompengine.project.AcpChangeValidationStatus.NOT_RUN,
                    assessment.validationStatus, case.id)
            }
        }
    }

    @Test
    fun `agent termination closes the pending graph and releases its root lock`() {
        val tempDir = createRepairTempDirectory("repair-agent-termination-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val target = projectDir.resolve("src/modules/reconstructed.c")
        val before = target.readBytes()
        val budget = RepairResourceBudget(maximumGraphLockWaitMillis = 100)
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured test must not use a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = throw SimulatedAgentTermination()
        }
        val loop = generatedCRepairLoop(
            harness,
            RepairHistory(projectDir.resolve("reports/repair_history.json")),
            resourceBudget = budget,
        )

        assertFailsWith<SimulatedAgentTermination> {
            loop.repairCompileError(projectDir, collectCompileFailure(projectDir), emptyList())
        }
        loop.close()
        assertContentEquals(before, readStableRepairFile(projectDir, "src/modules/reconstructed.c", 1_048_576))

        ModuleRevisionGraph.open(projectDir, GeneratedCRepairIndexProfile, budget).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `staging rejects oversized agent output before allocation beyond its budget`() {
        val tempDir = createRepairTempDirectory("repair-staging-oversize-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val target = projectDir.resolve("src/modules/reconstructed.c")
        val before = target.readBytes()
        val budget = RepairResourceBudget(maximumPatchBytes = 1024)
        val harness = capturedReplacingHarness(ByteArray(1025) { 'x'.code.toByte() })

        val failure = assertFailsWith<AgentExecutionException> {
            generatedCRepairLoop(
                harness,
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
                resourceBudget = budget,
            ).repairCompileError(projectDir, collectCompileFailure(projectDir), emptyList())
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
        assertIs<RepairBudgetExceededException>(failure.cause)

        assertContentEquals(before, target.readBytes())
    }

    @Test
    fun `strict staging counts directories and files before agent execution`() {
        var executed = false
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                error("host execution is forbidden")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                executed = true
                return AgentExecutionResult(AgentStopReason.NO_CHANGES)
            }
        }
        val requestFactory: (decompengine.agent.AgentWorkspaceRoot) -> AgentExecutionRequest = { root ->
            AgentExecutionRequest(
                "bounded capture",
                listOf(root),
                accessPolicy = decompengine.agent.AgentAccessPolicy(emptyList()),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CapturedRepairStagingAuthority.execute(
                harness,
                mapOf("a/b/c.txt" to byteArrayOf(1)),
                emptySet(),
                RepairResourceBudget(maximumStagingDirectories = 2),
                requestFactory,
                {},
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CapturedRepairStagingAuthority.execute(
                harness,
                mapOf("a.txt" to byteArrayOf(1), "b.txt" to byteArrayOf(2)),
                emptySet(),
                RepairResourceBudget(maximumContextFiles = 1, maximumPatchFiles = 1),
                requestFactory,
                {},
            )
        }
        assertTrue(!executed)
    }

    @Test
    fun `active repair staging directory limit admits equality and refuses one fewer before dispatch`() {
        fun runCase(limit: Int, expectDispatch: Boolean) {
            val project = createRepairTempDirectory("repair-active-directory-entry-limit-").resolve("project")
            val sourcePath = "a/b/c/program.c"
            project.resolve(sourcePath).parent.createDirectories()
            val source = "int program(void) { return 1; }\n".toByteArray()
            project.resolve(sourcePath).writeBytes(source)
            val profile = DeclarativeRepairIndexProfile(
                "deep-staging-path-v1",
                RepairIndexLayout(sourcePaths = listOf(sourcePath), editablePaths = listOf(sourcePath)),
            )
            val budget = RepairResourceBudget(maximumStagingDirectories = limit)
            val baselineHead = ModuleRevisionGraph.open(project, profile, budget).use { it.snapshot.headId }
            val dispatches = AtomicInteger()
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches.incrementAndGet()
                    assertEquals(setOf(sourcePath), initialFiles.keys)
                    assertContentEquals(source, initialFiles.getValue(sourcePath))
                    return AgentExecutionResult(AgentStopReason.NO_CHANGES)
                }
            }
            val loop = TraceGuidedRepairLoop.forTesting(
                harness,
                RepairHistory(project.resolve("reports/repair_history.json")),
                profile,
                GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
                CapturedRepairStagingAuthority,
                resourceBudget = budget,
            )

            try {
                if (expectDispatch) {
                    val noChange = assertFailsWith<IllegalArgumentException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertTrue(noChange.message.orEmpty().contains("repair agent stopped with no_changes"))
                } else {
                    val refusal = assertFailsWith<RepairBudgetExceededException> {
                        loop.repairCompileError(
                            project,
                            CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                            emptyList(),
                        )
                    }
                    assertEquals("repair staging requires 4 directories; limit=3", refusal.message)
                }
            } finally {
                loop.close()
            }
            assertEquals(if (expectDispatch) 1 else 0, dispatches.get())
            assertContentEquals(source, project.resolve(sourcePath).readBytes())

            ModuleRevisionGraph.open(project, profile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId)
                assertEquals(baselineHead, graph.snapshot.headId)
                assertEquals(2, graph.snapshot.nodes.size)
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                assertEquals(
                    if (expectDispatch) RepairRunStatus.NO_CHANGES else RepairRunStatus.RESOURCE_EXHAUSTED,
                    graph.snapshot.runs.last().status,
                )
            }
        }

        runCase(limit = 4, expectDispatch = true)
        runCase(limit = 3, expectDispatch = false)
    }

    @Test
    fun `active repair request-byte budget refuses before dispatch and preserves the accepted head`() {
        val project = createProject(
            createRepairTempDirectory("repair-active-request-byte-limit-").resolve("project"),
            reconstructedSource = "int decomp_engine_main(void) { return 0; }\n",
        )
        val sourcePath = "src/modules/reconstructed.c"
        val source = project.resolve(sourcePath).readBytes()
        val budget = RepairResourceBudget(maximumRegressionInputBytes = 1024, maximumRequestBytes = 1024)
        val baselineHead = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use {
            it.snapshot.headId
        }
        val dispatches = AtomicInteger()
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches.incrementAndGet()
                error("agent must not run when the bounded repair request exceeds its budget")
            }
        }
        val loop = TraceGuidedRepairLoop.forTesting(
            harness,
            RepairHistory(project.resolve("reports/repair_history.json")),
            GeneratedCRepairIndexProfile,
            GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
            CapturedRepairStagingAuthority,
            resourceBudget = budget,
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", "$sourcePath: compiler error"),
                emptyList(),
            )
        }
        assertTrue(failure.message.orEmpty().contains("repair request requires"))
        assertTrue(failure.message.orEmpty().contains("limit=${budget.maximumRequestBytes}"))
        assertEquals(0, dispatches.get())
        assertContentEquals(source, project.resolve(sourcePath).readBytes())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(1, graph.snapshot.nodes.size, "request admission must not create a candidate node")
            assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status)
            assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status)
        }
    }

    @Test
    fun `active repair required context module file and byte budgets refuse before dispatch`() {
        data class ContextLimitCase(
            val id: String,
            val maximumModules: Int,
            val maximumFiles: Int,
            val maximumBytes: Long,
            val seedBothPaths: Boolean,
            val expectedDiagnostic: String,
        )

        val targetPath = "src/modules/reconstructed.c"
        val contextPath = "src/modules/secondary.c"
        val targetBytes = "int decomp_engine_main(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        val contextBytes = "int secondary(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        val requiredBytes = targetBytes.size.toLong() + contextBytes.size
        val cases = listOf(
            ContextLimitCase(
                "modules",
                maximumModules = 1,
                maximumFiles = 2,
                maximumBytes = requiredBytes,
                seedBothPaths = true,
                expectedDiagnostic = "repair identifies 2 required modules; context module limit=1",
            ),
            ContextLimitCase(
                "files",
                maximumModules = 64,
                maximumFiles = 1,
                maximumBytes = requiredBytes,
                seedBothPaths = false,
                expectedDiagnostic = "required repair context has 2 files; limit=1",
            ),
            ContextLimitCase(
                "bytes",
                maximumModules = 64,
                maximumFiles = 2,
                maximumBytes = requiredBytes - 1,
                seedBothPaths = false,
                expectedDiagnostic = "required repair context has $requiredBytes bytes; limit=${requiredBytes - 1}",
            ),
        )

        for (case in cases) {
            val project = createProject(
                createRepairTempDirectory("repair-active-context-${case.id}-limit-").resolve("project"),
                reconstructedSource = targetBytes.toString(Charsets.UTF_8),
            )
            project.resolve(contextPath).writeBytes(contextBytes)
            val profile = DeclarativeRepairIndexProfile(
                "active-context-${case.id}-limit-v1",
                RepairIndexLayout(
                    sourcePaths = listOf(targetPath, contextPath).sorted(),
                    editablePaths = listOf(targetPath),
                    modules = if (case.id == "modules") {
                        listOf(
                            RepairModuleEvidence("main", listOf(targetPath)),
                            RepairModuleEvidence("secondary", listOf(contextPath)),
                        )
                    } else {
                        listOf(RepairModuleEvidence("main", listOf(targetPath, contextPath).sorted()))
                    },
                ),
            )
            val acceptedFiles = mapOf(targetPath to targetBytes, contextPath to contextBytes)
            val budget = RepairResourceBudget(
                maximumContextModules = case.maximumModules,
                maximumContextFiles = case.maximumFiles,
                maximumContextBytes = case.maximumBytes,
                maximumPatchFiles = case.maximumFiles,
                maximumPatchBytes = case.maximumBytes,
            )
            assertEquals(requiredBytes, acceptedFiles.values.sumOf { it.size.toLong() }, case.id)
            val baselineHead = ModuleRevisionGraph.open(project, profile, budget).use { it.snapshot.headId }
            val dispatches = AtomicInteger()
            val harness = object : CapturedRepairAgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

                override fun executeCaptured(
                    request: AgentExecutionRequest,
                    initialFiles: Map<String, ByteArray>,
                    output: BoundedRepairOutput,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult {
                    dispatches.incrementAndGet()
                    error("agent must not run after required repair context exceeds its admission budget")
                }
            }
            val validation = object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.STRICT_CONTAINED
                override fun requireAvailable() = Unit
                override fun validateCandidate(
                    request: RepairCandidateValidationRequest,
                ): RepairCandidateValidationOutcome = error("validation must not run without an admitted context")
                override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
                    error("validation must not run without an admitted context")
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("validation must not run without an admitted context")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ): BehaviorComparisonReport = error("validation must not run without an admitted context")
            }
            val loop = TestRepairRuntimeAccess.openLoop(
                harness = harness,
                history = RepairHistory(project.resolve("reports/repair_history.json")),
                profile = profile,
                validationStrategy = validation,
                stagingAuthority = CapturedRepairStagingAuthority,
                limits = AgentExecutionLimits(),
                cancellation = AgentCancellation.NONE,
                onAgentEvent = {},
                resourceBudget = budget,
                allowTestOnlyValidation = false,
                faultInjector = null,
            )

            val failure = assertFailsWith<RepairBudgetExceededException>(case.id) {
                loop.repairCompileError(
                    project,
                    CompileFailure(
                        listOf("cc"),
                        2,
                        "",
                        buildString {
                            append("$targetPath: compiler error")
                            if (case.seedBothPaths) append("\n$contextPath: compiler error")
                        },
                    ),
                    emptyList(),
                )
            }
            assertTrue(failure.message.orEmpty().contains(case.expectedDiagnostic), case.id)
            assertEquals(0, dispatches.get(), case.id)
            acceptedFiles.forEach { (path, bytes) ->
                assertContentEquals(bytes, project.resolve(path).readBytes(), "${case.id}: $path")
            }

            ModuleRevisionGraph.open(project, profile, budget).use { graph ->
                assertNull(graph.snapshot.pendingAttemptId, case.id)
                assertEquals(baselineHead, graph.snapshot.headId, case.id)
                assertEquals(1, graph.snapshot.nodes.size, case.id)
                assertEquals(ModuleRevisionStatus.ROOT, graph.snapshot.nodes.single().status, case.id)
                assertEquals(RepairRunStatus.RESOURCE_EXHAUSTED, graph.snapshot.runs.last().status, case.id)
            }
        }
    }

    @Test
    @org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `active repair admits exact required context module file and byte limits`() {
        val targetPath = "src/modules/reconstructed.c"
        val contextPath = "src/modules/secondary.c"
        val targetBytes = "int decomp_engine_main(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        val contextBytes = "int secondary(void) { return 0; }\n".toByteArray(Charsets.UTF_8)
        val requiredBytes = targetBytes.size.toLong() + contextBytes.size
        assertEquals(requiredBytes, 77L, "the explicit source fixtures define the exact aggregate boundary")

        val project = createProject(
            createRepairTempDirectory("repair-active-context-exact-limit-").resolve("project"),
            reconstructedSource = targetBytes.toString(Charsets.UTF_8),
        )
        project.resolve(contextPath).writeBytes(contextBytes)
        val profile = DeclarativeRepairIndexProfile(
            "active-context-exact-limit-v1",
            RepairIndexLayout(
                sourcePaths = listOf(targetPath, contextPath).sorted(),
                editablePaths = listOf(targetPath),
                modules = listOf(
                    RepairModuleEvidence("main", listOf(targetPath)),
                    RepairModuleEvidence("secondary", listOf(contextPath)),
                ),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextModules = 2,
            maximumContextFiles = 2,
            maximumContextBytes = requiredBytes,
            maximumPatchFiles = 2,
            maximumPatchBytes = requiredBytes,
        )
        val baselineHead = ModuleRevisionGraph.open(project, profile, budget).use { it.snapshot.headId }
        var dispatches = 0
        var observedFiles: Map<String, ByteArray>? = null
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("strict captured repair must not expose a host workspace")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                dispatches++
                observedFiles = initialFiles.mapValues { (_, bytes) -> bytes.copyOf() }
                return AgentExecutionResult(AgentStopReason.NO_CHANGES)
            }
        }
        val loop = TestRepairRuntimeAccess.openLoop(
            harness = harness,
            history = RepairHistory(project.resolve("reports/repair_history.json")),
            profile = profile,
            validationStrategy = GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
            stagingAuthority = CapturedRepairStagingAuthority,
            limits = AgentExecutionLimits(),
            cancellation = AgentCancellation.NONE,
            onAgentEvent = {},
            resourceBudget = budget,
            allowTestOnlyValidation = true,
            faultInjector = null,
        )

        try {
            val failure = assertFailsWith<IllegalArgumentException> {
                loop.repairCompileError(
                    project,
                    CompileFailure(
                        listOf("cc"),
                        2,
                        "",
                        "$targetPath: compiler error\n$contextPath: compiler error",
                    ),
                    emptyList(),
                )
            }
            assertTrue(failure.message.orEmpty().contains("repair agent stopped with no_changes"))
        } finally {
            loop.close()
        }

        assertEquals(1, dispatches, "equality at all three required-context ceilings must reach the harness")
        val dispatched = assertNotNull(observedFiles)
        assertEquals(setOf(targetPath, contextPath), dispatched.keys)
        assertContentEquals(targetBytes, dispatched.getValue(targetPath))
        assertContentEquals(contextBytes, dispatched.getValue(contextPath))
        assertContentEquals(targetBytes, project.resolve(targetPath).readBytes())
        assertContentEquals(contextBytes, project.resolve(contextPath).readBytes())
        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertEquals(baselineHead, graph.snapshot.headId)
            assertEquals(RepairRunStatus.NO_CHANGES, graph.snapshot.runs.last().status)
            assertEquals(2, graph.snapshot.nodes.size)
        }
    }

    @Test
    fun `strict captured staging closes the mutation sink against background writers`() {
        lateinit var retainedOutput: BoundedRepairOutput
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                error("host execution is forbidden")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                retainedOutput = output
                return AgentExecutionResult(AgentStopReason.NO_CHANGES)
            }
        }
        CapturedRepairStagingAuthority.execute(
            harness,
            mapOf("source.txt" to "before".toByteArray()),
            setOf("source.txt"),
            RepairResourceBudget(),
            { root ->
                AgentExecutionRequest(
                    "bounded capture",
                    listOf(root),
                    accessPolicy = decompengine.agent.AgentAccessPolicy(
                        listOf(
                            decompengine.agent.AgentPathRule(
                                AgentWorkspacePath(root.id, "source.txt"),
                                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                            ),
                        ),
                    ),
                )
            },
            {},
        )
        assertFailsWith<IllegalStateException> {
            retainedOutput.replace("source.txt", "late".toByteArray())
        }
    }

    @Test
    fun `legacy captured adapter rejects malformed UTF-8 before sending a repair request`() {
        val client = FakeRepairClient(RepairResponse("must not run", emptyList()))
        val harness = RepairClientAgentHarness(client)
        val failure = assertFailsWith<AgentExecutionException> {
            CapturedRepairStagingAuthority.execute(
                harness,
                mapOf("source.bin" to byteArrayOf(0xc3.toByte(), 0x28)),
                setOf("source.bin"),
                RepairResourceBudget(),
                { root ->
                    AgentExecutionRequest(
                        "repair captured source",
                        listOf(root),
                        accessPolicy = decompengine.agent.AgentAccessPolicy(
                            listOf(
                                decompengine.agent.AgentPathRule(
                                    AgentWorkspacePath(root.id, "source.bin"),
                                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                                ),
                            ),
                        ),
                    )
                },
                {},
            )
        }

        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, failure.failure.kind)
        assertTrue(failure.message.orEmpty().contains("not valid UTF-8"))
        assertEquals(null, client.lastRequest)
    }

    @Test
    fun `generic repair graph and history accept byte-neutral non-UTF8 sources`() {
        val project = createTempDirectory("repair-binary-profile-").resolve("project")
        project.resolve("code").createDirectories()
        val target = project.resolve("code/program.bin")
        val parent = byteArrayOf(0xff.toByte(), 0x00)
        val candidate = byteArrayOf(0xfe.toByte(), 0x01)
        target.writeBytes(parent)
        val profile = DeclarativeRepairIndexProfile(
            "binary-layout-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/program.bin"),
                editablePaths = listOf("code/program.bin"),
            ),
        )
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                error("binary repair must use captured staging")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                val path = AgentWorkspacePath("project", "code/program.bin")
                output.replace(path.relativePath, candidate)
                return AgentExecutionResult(
                    AgentStopReason.COMPLETED,
                    "binary replacement",
                    listOf(
                        AgentFileChange(
                            path,
                            AgentFileChangeKind.MODIFIED,
                            sha256(parent),
                            sha256(candidate),
                            candidate.size.toLong(),
                        ),
                    ),
                )
            }
        }
        val historyPath = project.resolve("reports/repair_history.json")
        val loop = TraceGuidedRepairLoop.forTesting(
            harness,
            RepairHistory(historyPath),
            profile,
            object : RepairValidationStrategy {
                override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
                override fun requireAvailable() = Unit
                override fun compile(
                    projectDir: Path,
                    logPath: Path,
                    budget: RepairResourceBudget,
                ): CompileFailure? = null
                override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                    error("compile-only binary fixture")
                override fun evaluateBehavior(
                    id: String,
                    projectDir: Path,
                    originalBinary: Path,
                    rebuiltBinary: Path,
                    inputs: List<ProcessInput>,
                    reportsDir: Path,
                    budget: RepairResourceBudget,
                ) = error("compile-only binary fixture")
            },
            CapturedRepairStagingAuthority,
        )

        val iteration = loop.repairCompileError(
            project,
            CompileFailure(listOf("tool"), 1, "", "code/program.bin: failed"),
            emptyList(),
        )

        assertContentEquals(parent, target.readBytes())
        assertContentEquals(candidate, iteration.patches.single().replacementBytes)
        assertTrue(historyPath.readText().contains("\"replacementHex\": \"fe01\""))
        ModuleRevisionGraph.open(project, profile).use { graph ->
            assertContentEquals(candidate, graph.derivedRepairIterations().single().patches.single().replacementBytes)
        }
    }

    @Test
    fun `compile strategy exception immediately restores the observed candidate`() {
        val tempDir = createTempDirectory("repair-compile-throw-")
        val parent = "int decomp_engine_main(void) {\n"
        val project = createProject(tempDir.resolve("project"), parent)
        val candidate = goodHelloSource().toByteArray()
        val originalFailure = IllegalStateException("compile boundary failed after observing candidate")
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? {
                assertContentEquals(candidate, projectDir.resolve("src/modules/reconstructed.c").readBytes())
                assertEquals(parent,
                    readStableRepairFile(project, "src/modules/reconstructed.c", 1_048_576).decodeToString())
                throw originalFailure
            }
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
                error("compile-only fixture")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ) = error("compile-only fixture")
        }
        val loop = TraceGuidedRepairLoop.forTesting(
            capturedReplacingHarness(candidate),
            RepairHistory(project.resolve("reports/repair_history.json")),
            GeneratedCRepairIndexProfile,
            validation,
            CapturedRepairStagingAuthority,
        )

        val observed = assertFailsWith<IllegalStateException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("cc"), 1, "", "src/modules/reconstructed.c: error"),
                emptyList(),
            )
        }

        assertTrue(observed === originalFailure)
        assertEquals(parent, readStableRepairFile(project, "src/modules/reconstructed.c", 1_048_576).decodeToString())
        assertEquals("validation-error",
            RepairHistory(project.resolve("reports/repair_history.json")).all().single().after?.kind)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(null, graph.snapshot.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `complete staging context is budgeted before a durable attempt begins`() {
        val project = createTempDirectory("repair-context-preflight-").resolve("project")
        project.resolve("code").createDirectories()
        project.resolve("diagnostics").createDirectories()
        project.resolve("reports").createDirectories()
        val target = project.resolve("code/program.bin")
        target.writeBytes(byteArrayOf(1, 2))
        project.resolve("diagnostics/context.bin").writeBytes(ByteArray(8) { 7 })
        val profile = DeclarativeRepairIndexProfile(
            "context-preflight-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/program.bin", "diagnostics/context.bin"),
                editablePaths = listOf("code/program.bin"),
                modules = listOf(
                    RepairModuleEvidence(
                        id = "program",
                        ownedPaths = listOf("code/program.bin", "diagnostics/context.bin"),
                    ),
                ),
                sharedContextPaths = listOf("diagnostics/context.bin"),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextBytes = 64,
            maximumStagingBytes = 4,
            maximumPatchBytes = 4,
        )
        val harnessCalls = AtomicInteger()
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
                error("captured staging required")
            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                harnessCalls.incrementAndGet()
                error("agent must not run when the complete staging context exceeds budget")
            }
        }
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? = null
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = error("unused")
            override fun evaluateBehavior(
                id: String,
                projectDir: Path,
                originalBinary: Path,
                rebuiltBinary: Path,
                inputs: List<ProcessInput>,
                reportsDir: Path,
                budget: RepairResourceBudget,
            ) = error("unused")
        }
        val loop = TraceGuidedRepairLoop.forTesting(
            harness,
            RepairHistory(project.resolve("reports/repair_history.json")),
            profile,
            validation,
            CapturedRepairStagingAuthority,
            resourceBudget = budget,
        )

        assertFailsWith<RepairBudgetExceededException> {
            loop.repairCompileError(
                project,
                CompileFailure(listOf("tool"), 1, "", "diagnostics/context.bin: error"),
                emptyList(),
            )
        }

        assertEquals(0, harnessCalls.get())
        assertContentEquals(byteArrayOf(1, 2), target.readBytes())
        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }
    }

    @Test
    fun `history and compatibility log are derived after a crash following graph head commit`() {
        val tempDir = createTempDirectory("repair-evidence-reconcile-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = goodHelloSource())
        val target = projectDir.resolve("src/modules/reconstructed.c")
        val candidate = target.readText() + "\n/* behavior-preserving repair */\n"
        val graph = ModuleRevisionGraph.openForTesting(
            projectDir,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point == ModuleRevisionFaultPoint.AfterHeadPersist) throw SimulatedEvidenceCrash()
            },
        )
        val corpus = graph.retainRegressionInputs(listOf(ProcessInput("default")))
        graph.beginRun(maximumAttempts = 1, maximumWallMillis = 60_000)
        val attempt = graph.beginAttempt(
            listOf("src/modules/reconstructed.c"),
            RevisionRepairMetadata(
                1,
                "behavior",
                "preserve behavior",
                null,
                listOf("default"),
                RepairEvidence("behavior", "candidate requested"),
                corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
            ),
        )
        graph.annotateAttempt(attempt, "append a harmless comment")
        graph.installCandidate(attempt, mapOf("src/modules/reconstructed.c" to candidate.toByteArray()))
        val snapshot = graph.snapshot
        val proof = RepairValidationProof(
            sourceRevisionSha256 = repairCandidateSourceSha256(graph.candidateSources(attempt)),
            profileSha256 = snapshot.profileSha256,
            indexSha256 = snapshot.indexSha256,
            regressionCorpusSha256 = graph.retainedRegressionCorpus().sha256,
            originalBinarySha256 = sha256("synthetic original binary".toByteArray()),
            rebuiltBinarySha256 = sha256("synthetic rebuilt binary".toByteArray()),
            runtimeSha256 = sha256("synthetic runtime".toByteArray()),
            evidenceSha256 = sha256("synthetic validation evidence".toByteArray()),
            cleanupVerified = true,
            assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS,
        )
        graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
        graph.bindExpectedObservations(sha256(buildString {
            append(proof.originalBinarySha256).append('\n')
            corpus.inputs.forEach { input ->
                append(input.id.length).append(':').append(input.id).append(":0:")
                    .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
            }
        }.toByteArray()))
        assertFailsWith<SimulatedEvidenceCrash> {
            graph.accept(attempt, RepairEvidence("valid", "retained behavior matched", "reports/valid.json"), proof)
        }
        graph.close()
        assertTrue(!projectDir.resolve("reports/repair_history.json").exists())

        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val result = generatedCRepairLoop(
            object : AgentHarness {
                override fun execute(
                    request: AgentExecutionRequest,
                    onEvent: (AgentExecutionEvent) -> Unit,
                ): AgentExecutionResult = error("valid recovered head must not invoke the agent")
            },
            history,
        ).repairUntilValid(projectDir, original, listOf(ProcessInput("default")), maxIterations = 1)

        assertTrue(result.validation.matches)
        assertEquals("append a harmless comment", history.all().single().summary)
        assertEquals("valid", history.all().single().after?.kind)
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("\"accepted\":true"))
    }

    @Test
    fun `repair history freezes ingress and returns Java immutable detached projections`() {
        val historyPath = createTempDirectory("repair-history-freeze-").resolve("reports/repair_history.json")
        val history = RepairHistory(historyPath)
        val args = arrayListOf("before")
        val stdin = byteArrayOf(1, 2, 3)
        history.retain(listOf(ProcessInput("case", args, stdin)))
        args[0] = "after"
        stdin[0] = 99

        val patchBytes = byteArrayOf(4, 5, 6)
        val patches = arrayListOf(RepairPatch("code/program.bin", patchBytes))
        val retainedIds = arrayListOf("case")
        history.append(
            RepairIteration(
                index = 1,
                failureKind = "compile",
                prompt = "repair",
                summary = "detached",
                patches = patches,
                retainedRegressionIds = retainedIds,
            ),
        )
        patchBytes[0] = 88
        patches.clear()
        retainedIds.clear()

        val projectedInputs = history.retainedInputs()
        val projected = history.all()
        assertEquals(listOf("before"), projectedInputs.single().args)
        assertContentEquals(byteArrayOf(1, 2, 3), projectedInputs.single().stdin)
        assertContentEquals(byteArrayOf(4, 5, 6), projected.single().patches.single().replacementBytes)
        assertEquals(listOf("case"), projected.single().retainedRegressionIds)
        projectedInputs.single().stdin[1] = 77
        assertContentEquals(byteArrayOf(1, 2, 3), history.retainedInputs().single().stdin)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (projected as MutableList<RepairIteration>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (projected.single().patches as MutableList<RepairPatch>).clear()
        }

        val reopened = RepairHistory(historyPath)
        assertEquals(listOf("before"), reopened.retainedInputs().single().args)
        assertContentEquals(byteArrayOf(1, 2, 3), reopened.retainedInputs().single().stdin)
        assertContentEquals(byteArrayOf(4, 5, 6), reopened.all().single().patches.single().replacementBytes)
    }

    private fun generatedCRepairLoop(
        harness: AgentHarness,
        history: RepairHistory,
        resourceBudget: RepairResourceBudget = RepairResourceBudget(),
        limits: AgentExecutionLimits = AgentExecutionLimits(),
        cancellation: AgentCancellation = AgentCancellation.NONE,
    ): TraceGuidedRepairLoop = TraceGuidedRepairLoop.forTesting(
        harness,
        history,
        GeneratedCRepairIndexProfile,
        GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
        CapturedRepairStagingAuthority,
        limits = limits,
        cancellation = cancellation,
        resourceBudget = resourceBudget,
    )

    private class FakeRepairClient(private val response: RepairResponse) : RepairClient {
        var lastRequest: RepairRequest? = null

        override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
            lastRequest = request
            return response
        }
    }

    private fun partialAcpOutcomeHarness(outcome: AgentExecutionOutcome): CapturedRepairAgentHarness =
        object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware repair must not discard the invocation receipt")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware repair must not discard the invocation receipt")

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt = AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request),
                outcome,
                AcpInvocationEvidenceSnapshot(
                    factoryProvenance = null,
                    phaseReached = AcpExecutionLifecyclePhase.REQUEST_BOUND,
                    cleanupDisposition = AcpExecutionCleanupDisposition.NOT_REQUIRED,
                    negotiatedAgent = null,
                    wirePromptSha256 = null,
                    diagnostics = null,
                    filesystemAudit = emptyList(),
                    terminalAudit = emptyList(),
                    permissionAudit = emptyList(),
                    sandboxEvidence = null,
                    completeness = AcpExecutionEvidenceCompleteness(true, true, true),
                    completeExecutionEvidence = null,
                ),
            )
        }

    private fun capturedReplacingHarness(replacement: ByteArray): CapturedRepairAgentHarness = object : CapturedRepairAgentHarness {
        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult = error("strict captured test must not use a host workspace")

        override fun executeCaptured(
            request: AgentExecutionRequest,
            initialFiles: Map<String, ByteArray>,
            output: BoundedRepairOutput,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult {
            val path = AgentWorkspacePath("project", "src/modules/reconstructed.c")
            val before = initialFiles.getValue(path.relativePath)
            output.replace(path.relativePath, replacement)
            return AgentExecutionResult(
                AgentStopReason.COMPLETED,
                "malicious staging output",
                listOf(
                    AgentFileChange(
                        path,
                        AgentFileChangeKind.MODIFIED,
                        sha256(before),
                        sha256(replacement),
                        replacement.size.toLong(),
                    ),
                ),
            )
        }
    }

    private fun createSingleSourceProject(projectDir: Path, source: String): Path {
        projectDir.resolve("src/modules").createDirectories()
        projectDir.resolve("include/modules").createDirectories()
        projectDir.resolve("reports").createDirectories()
        projectDir.resolve("Makefile").writeText(
            "CC ?= cc\nCFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude\nTARGET ?= build/reconstructed\n" +
                "all: ${'$'}(TARGET)\n${'$'}(TARGET): src/main.c src/modules/reconstructed.c include/modules/reconstructed.h\n" +
                "\t@mkdir -p ${'$'}(dir ${'$'}@)\n" +
                "\t${'$'}(CC) ${'$'}(CFLAGS) src/main.c src/modules/reconstructed.c -o ${'$'}@\n",
        )
        projectDir.resolve("include/modules/reconstructed.h").writeText("int decomp_engine_main(int argc);\n")
        projectDir.resolve("src/main.c").writeText(
            "#include \"modules/reconstructed.h\"\nint main(int argc, char **argv) { (void)argv; return decomp_engine_main(argc); }\n",
        )
        projectDir.resolve("src/modules/reconstructed.c").writeText(source)
        return projectDir
    }

    private class SimulatedEvidenceCrash : Error("simulated crash after graph-head persistence")
    private class SimulatedAgentTermination : Error("simulated agent process termination")

    private class QueueRepairClient(vararg responses: RepairResponse) : RepairClient {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<RepairRequest>()

        override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
            requests += request
            return responses.removeFirstOrNull() ?: error("unexpected repair request")
        }
    }

    private fun createProject(projectDir: java.nio.file.Path, reconstructedSource: String): java.nio.file.Path {
        projectDir.resolve("src").createDirectories()
        projectDir.resolve("src/modules").createDirectories()
        projectDir.resolve("include/modules").createDirectories()
        projectDir.resolve("reports").createDirectories()
        projectDir.resolve("Makefile").writeText(
            """
            CC ?= gcc
            CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude
            TARGET ?= build/reconstructed
            SOURCES := src/main.c src/modules/reconstructed.c

            all: ${'$'}(TARGET)

            ${'$'}(TARGET): ${'$'}(SOURCES) include/modules/reconstructed.h
            	@mkdir -p ${'$'}(dir ${'$'}@)
            	${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(SOURCES) -o ${'$'}@
            """.trimIndent() + "\n",
        )
        projectDir.resolve("include/modules/reconstructed.h").writeText(
            """
            #ifndef DECOMP_ENGINE_H
            #define DECOMP_ENGINE_H

            int decomp_engine_main(void);

            #endif
            """.trimIndent() + "\n",
        )
        projectDir.resolve("src/main.c").writeText(
            """
            #include "modules/reconstructed.h"

            int main(void) {
                return decomp_engine_main();
            }
            """.trimIndent() + "\n",
        )
        projectDir.resolve("src/modules/reconstructed.c").writeText(reconstructedSource)
        return projectDir
    }

    private fun multiModuleModel() = RecoveredProgramModel(
        inputSha256 = "repair-fixture",
        functions = listOf(
            RecoveredFunction("fn_1000", "parse_input", 0x1000UL, "int parse_input(void)"),
            RecoveredFunction("fn_2000", "render_page", 0x2000UL, "int render_page(void)"),
        ),
    )

    private fun collectCompileFailure(projectDir: java.nio.file.Path): CompileFailure {
        val process = ProcessBuilder("make")
            .directory(projectDir.toFile())
            .redirectErrorStream(false)
            .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        assertTrue(exitCode != 0)
        return CompileFailure(listOf("make"), exitCode, stdout, stderr)
    }

    private fun compileC(tempDir: java.nio.file.Path, name: String, source: String): java.nio.file.Path {
        val buildDir = tempDir.resolve(name).createDirectories()
        val sourcePath = buildDir.resolve("$name.c")
        val binaryPath = buildDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed: $output" }
        return binaryPath
    }

    private fun helloProgramSource(message: String): String = """
        #include <stdio.h>

        int main(void) {
            puts("$message");
            return 0;
        }
    """.trimIndent() + "\n"

    private fun helloMainSource(message: String): String = """
        #include <stdio.h>

        int decomp_engine_main(void) {
            puts("$message");
            return 0;
        }
    """.trimIndent() + "\n"

    private fun goodHelloSource(): String = helloMainSource("hello, world")
}

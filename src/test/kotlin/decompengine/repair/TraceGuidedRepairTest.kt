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
import decompengine.acp.AcpAgentHarnessTest
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import decompengine.project.sha256
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorExecutionOutcomeException
import decompengine.validation.BehaviorExecutionTimeoutException
import decompengine.validation.BehaviorOutputLimitException
import decompengine.validation.ProcessInput
import decompengine.validation.ProcessOutput
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TraceGuidedRepairTest {
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
                createTempDirectory("trace-acp-${expectedTerminal.replace('-', '_')}-").resolve("project"),
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
                createTempDirectory("repair-mutation-contract-${mutation}-").resolve("project"),
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
                createTempDirectory("repair-change-claim-${variant}-").resolve("project"),
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
            createTempDirectory("repair-active-acp-resource-limit-").resolve("project"),
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
            createTempDirectory("repair-active-acp-output-limit-").resolve("project"),
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
    fun `agent termination closes the pending graph and releases its root lock`() {
        val tempDir = createTempDirectory("repair-agent-termination-")
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
        val tempDir = createTempDirectory("repair-staging-oversize-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val target = projectDir.resolve("src/modules/reconstructed.c")
        val before = target.readBytes()
        val budget = RepairResourceBudget(maximumPatchBytes = 1024)
        val harness = capturedReplacingHarness(ByteArray(1025) { 'x'.code.toByte() })

        assertFailsWith<RepairBudgetExceededException> {
            generatedCRepairLoop(
                harness,
                RepairHistory(projectDir.resolve("reports/repair_history.json")),
                resourceBudget = budget,
            ).repairCompileError(projectDir, collectCompileFailure(projectDir), emptyList())
        }

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

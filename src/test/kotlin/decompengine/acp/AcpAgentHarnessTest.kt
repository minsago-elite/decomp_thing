package decompengine.acp

import com.agentclientprotocol.model.LATEST_PROTOCOL_VERSION
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.execute
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AcpAgentHarnessTest {
    @Test
    fun `pinned SDK negotiates stable v1 and streams one subprocess turn without shell interpretation`() {
        assertEquals(1, LATEST_PROTOCOL_VERSION)
        assertEquals("0.30.1", ACP_KOTLIN_SDK_VERSION)
        val fixture = fixture()
        val shellMarker = fixture.workspace.resolve("shell-was-interpreted")
        val sentinel = "\$(touch $shellMarker)"
        val harness = harness("success", sentinel = sentinel)
        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()

        val result = harness.execute(fixture.request, events::add)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("fixture-session", result.session?.sessionId)
        assertEquals("scripted-acp-v1", result.session?.harnessId)
        assertEquals("editing fixture", result.summary)
        assertEquals(11, result.usage?.inputTokens)
        assertEquals(7, result.usage?.outputTokens)
        assertEquals(3, result.usage?.cachedInputTokens)
        assertEquals(1, result.usage?.toolCalls)
        assertEquals("new source\n", fixture.source.readText())
        assertFalse(shellMarker.exists(), "argv was interpreted by a shell")
        assertEquals(events.indices.map(Int::toLong), events.map { it.sequence })
        assertTrue(events.any { it is AgentMessageEvent && it.textDelta == "editing fixture" })
        assertTrue(events.any { it is AgentPlanEvent })
        assertTrue(events.any { it is AgentToolEvent && it.status == AgentToolStatus.SUCCEEDED })
        val change = events.filterIsInstance<AgentFileChangeEvent>().single().change
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
        assertEquals("src/module.c", change.path.relativePath)

        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertEquals(0, diagnostics.exitCode)
        assertTrue(diagnostics.stderr.contains("fixture-stderr:$sentinel"))
        assertFalse(diagnostics.stderrTruncated)
        assertFalse(diagnostics.forcedTermination)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `unsupported versions and missing configured capabilities fail actionably`() {
        val fixture = fixture()
        val versionFailure = assertFailsWith<AgentExecutionException> {
            harness("unsupported-version").execute(fixture.request)
        }
        assertEquals(
            AgentFailureKind.PROTOCOL,
            versionFailure.failure.kind,
            "${versionFailure.message}; ${versionFailure.failure.details}; cause=${versionFailure.cause}",
        )
        assertTrue(versionFailure.message.orEmpty().contains("stable v1"))
        assertEquals("2", versionFailure.failure.details["offeredVersion"])

        val capabilityFailure = assertFailsWith<AgentExecutionException> {
            harness(
                "success",
                requiredCapabilities = setOf(AcpRequiredAgentCapability.LOAD_SESSION),
            ).execute(fixture.request)
        }
        assertEquals(AgentFailureKind.CONFIGURATION, capabilityFailure.failure.kind)
        assertEquals("loadSession", capabilityFailure.failure.details["missingCapabilities"])

        val missingVersion = assertFailsWith<AgentExecutionException> {
            harness("missing-protocol-version").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, missingVersion.failure.kind)
    }

    @Test
    fun `unknown and duplicate JSON-RPC response ids are rejected before SDK dispatch`() {
        listOf("unknown-response-id", "duplicate-response-id").forEach { mode ->
            val harness = harness(mode)
            val failure = assertFailsWith<AgentExecutionException>(mode) {
                harness.execute(fixture().request)
            }

            assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind, mode)
            assertTrue(failure.message.orEmpty().contains("response id"), mode)
            assertProcessStopped(assertNotNull(harness.latestDiagnostics()).pid)
        }
    }

    @Test
    fun `malformed stdout clean EOF and nonzero crashes are distinct failures`() {
        val malformedInitialize = assertFailsWith<AgentExecutionException> {
            harness("malformed-initialize").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, malformedInitialize.failure.kind)

        val malformed = assertFailsWith<AgentExecutionException> {
            harness("malformed-prompt").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, malformed.failure.kind)
        assertTrue(malformed.message.orEmpty().contains("malformed JSON-RPC"))

        listOf(
            "contaminated-prompt",
            "missing-jsonrpc-prompt",
            "wrong-jsonrpc-prompt",
            "numeric-jsonrpc-prompt",
            "result-and-error-prompt",
        ).forEach { mode ->
            val strictFailure = assertFailsWith<AgentExecutionException>(mode) {
                harness(mode).execute(fixture().request)
            }
            assertEquals(AgentFailureKind.PROTOCOL, strictFailure.failure.kind, mode)
            assertTrue(strictFailure.message.orEmpty().contains("malformed JSON-RPC"), mode)
        }

        val invalidUtf8 = assertFailsWith<AgentExecutionException> {
            harness("invalid-utf8-prompt").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, invalidUtf8.failure.kind)
        assertTrue(invalidUtf8.message.orEmpty().contains("invalid UTF-8"))

        val invalidUpdate = assertFailsWith<AgentExecutionException> {
            harness("invalid-update").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, invalidUpdate.failure.kind)
        assertTrue(invalidUpdate.message.orEmpty().contains("empty tool call id"))

        val negativeUsage = assertFailsWith<AgentExecutionException> {
            harness("negative-usage").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROTOCOL, negativeUsage.failure.kind)
        assertTrue(negativeUsage.message.orEmpty().contains("invalid prompt usage"))

        val eof = assertFailsWith<AgentExecutionException> {
            harness("eof-prompt").execute(fixture().request)
        }
        assertEquals(AgentFailureKind.TRANSPORT, eof.failure.kind)

        val crashHarness = harness("crash-prompt")
        val crash = assertFailsWith<AgentExecutionException> {
            crashHarness.execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROCESS_CRASH, crash.failure.kind)
        assertEquals("23", crash.failure.details["exitCode"])
        assertProcessStopped(assertNotNull(crashHarness.latestDiagnostics()).pid)

        val initializeCrashHarness = harness("crash-after-initialize")
        val initializeCrash = assertFailsWith<AgentExecutionException> {
            initializeCrashHarness.execute(fixture().request)
        }
        assertEquals(AgentFailureKind.PROCESS_CRASH, initializeCrash.failure.kind)
        assertEquals("17", initializeCrash.failure.details["exitCode"])
        assertProcessStopped(assertNotNull(initializeCrashHarness.latestDiagnostics()).pid)
    }

    @Test
    fun `startup request and idle waits are independently bounded`() {
        val startupHarness = harness(
            "no-initialize",
            timeouts = timeouts(startup = 180, request = 1_000),
        )
        val startup = assertFailsWith<AgentExecutionException> {
            startupHarness.execute(fixture().request)
        }
        assertEquals(AgentFailureKind.TIMEOUT, startup.failure.kind)
        assertTrue(startup.message.orEmpty().contains("initialize"))
        assertProcessStopped(assertNotNull(startupHarness.latestDiagnostics()).pid)

        val requestHarness = harness(
            "no-session-response",
            timeouts = timeouts(startup = 1_000, request = 180),
        )
        val request = assertFailsWith<AgentExecutionException> {
            requestHarness.execute(fixture().request)
        }
        assertEquals(AgentFailureKind.TIMEOUT, request.failure.kind)
        assertTrue(request.message.orEmpty().contains("session/new"))
        assertProcessStopped(assertNotNull(requestHarness.latestDiagnostics()).pid)

        val idleFixture = fixture(idleMillis = 150)
        val idleHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 1_000, request = 2_000),
        )
        val idle = assertFailsWith<AgentExecutionException> {
            idleHarness.execute(idleFixture.request)
        }
        assertEquals(AgentFailureKind.TIMEOUT, idle.failure.kind)
        assertTrue(idle.message.orEmpty().contains("idle"))
        val idleDiagnostics = assertNotNull(idleHarness.latestDiagnostics())
        assertFalse(idleDiagnostics.forcedTermination)
        assertProcessStopped(idleDiagnostics.pid)

        val wallFixture = fixture(idleMillis = 2_000, wallMillis = 180)
        val wallHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 1_000, request = 2_000),
        )
        val wall = assertFailsWith<AgentExecutionException> {
            wallHarness.execute(wallFixture.request)
        }
        assertEquals(AgentFailureKind.TIMEOUT, wall.failure.kind)
        assertTrue(wall.message.orEmpty().contains("wall-clock"))
        assertProcessStopped(assertNotNull(wallHarness.latestDiagnostics()).pid)
    }

    @Test
    fun `a blocking event callback cannot prevent the wall deadline and process cleanup`() {
        val fixture = fixture(idleMillis = 2_000, wallMillis = 250)
        val harness = harness(
            "update-then-hang",
            timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 600),
        )
        val callbackEntered = CountDownLatch(1)
        val releaseCallback = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(fixture.request) {
                    callbackEntered.countDown()
                    releaseCallback.await()
                }
            }
            assertTrue(callbackEntered.await(2, TimeUnit.SECONDS), "fixture never delivered an event")

            val failure = try {
                execution.get(2, TimeUnit.SECONDS)
                error("execution unexpectedly succeeded")
            } catch (wrapped: ExecutionException) {
                wrapped.cause as? AgentExecutionException ?: throw wrapped
            }
            assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
            assertTrue(failure.message.orEmpty().contains("wall-clock"))
            assertProcessStopped(assertNotNull(harness.latestDiagnostics()).pid)
        } finally {
            releaseCallback.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun `caller cancellation sends session cancel and returns a cancelled result`() {
        val fixture = fixture(includeReadyPath = true)
        val cancellation = AgentCancellationSource()
        val request = fixture.request.withCancellation(cancellation)
        val ready = fixture.workspace.resolve("ready")
        val harness = harness(
            "wait-for-cancel",
            ready = ready,
            timeouts = timeouts(startup = 1_000, request = 3_000),
        )
        val executor = Executors.newSingleThreadExecutor()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> { harness.execute(request) }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (!ready.exists() && !execution.isDone && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(ready.exists(), "fixture never reached session/prompt")
            cancellation.cancel()

            val result = try {
                execution.get(3, TimeUnit.SECONDS)
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            }
            assertEquals(AgentStopReason.CANCELLED, result.stopReason)
            assertEquals("old source\n", fixture.source.readText())
            assertEquals(AgentFileChangeKind.CREATED, result.changes.single().kind)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination)
            assertProcessStopped(diagnostics.pid)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `caller cancellation remains bounded when the in-flight agent ignores cancel and term`() {
        val fixture = fixture(includeReadyPath = true)
        val cancellation = AgentCancellationSource()
        val ready = fixture.workspace.resolve("ready")
        val harness = harness(
            "ignore-cancel",
            ready = ready,
            timeouts = timeouts(startup = 1_000, request = 3_000, shutdown = 600),
        )
        val executor = Executors.newSingleThreadExecutor()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(fixture.request.withCancellation(cancellation))
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (!ready.exists() && !execution.isDone && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(ready.exists(), "fixture never reached session/prompt")
            cancellation.cancel()

            val result = try {
                execution.get(3, TimeUnit.SECONDS)
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            }
            assertEquals(AgentStopReason.CANCELLED, result.stopReason)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertTrue(diagnostics.forcedTermination)
            assertTrue(diagnostics.rootTerminationRequested)
            assertTrue(diagnostics.remainingProcessIds.isEmpty())
            assertProcessStopped(diagnostics.pid)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `shutdown deadline forcibly terminates an agent that ignores stdin EOF`() {
        val fixture = fixture()
        val harness = harness(
            "success-hang",
            timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 240),
        )

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.forcedTermination)
        assertTrue(diagnostics.rootTerminationRequested)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `a final prompt response followed by a natural nonzero exit remains a process crash`() {
        mapOf(
            "response-then-crash" to "31",
            "response-then-delayed-crash" to "32",
        ).forEach { (mode, expectedExit) ->
            val harness = harness(
                mode,
                timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 1_000),
            )

            val failure = assertFailsWith<AgentExecutionException>(mode) {
                harness.execute(fixture().request)
            }

            assertEquals(AgentFailureKind.PROCESS_CRASH, failure.failure.kind, mode)
            assertEquals(expectedExit, failure.failure.details["exitCode"], mode)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination, mode)
            assertFalse(diagnostics.rootTerminationRequested, mode)
            assertEquals(expectedExit.toInt(), diagnostics.exitCode, mode)
            assertProcessStopped(diagnostics.pid)
        }
    }

    @Test
    fun `forced shutdown repeatedly discovers and terminates subprocess descendants`() {
        val fixture = fixture(includeReadyPath = true)
        val childPidPath = fixture.workspace.resolve("ready")
        val harness = harness(
            "success-child-hang",
            ready = childPidPath,
            timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 600),
        )

        val result = harness.execute(fixture.request)

        val childPid = childPidPath.readText().trim().toLong()
        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.forcedTermination)
        assertTrue(diagnostics.rootTerminationRequested)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertProcessStopped(diagnostics.pid)
        assertProcessStopped(childPid)
    }

    @Test
    fun `stdout frame total and retained stderr sizes are bounded independently`() {
        val frameFailure = assertFailsWith<AgentExecutionException> {
            harness("oversized-frame-prompt", maximumFrameBytes = 1_024).execute(fixture().request)
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, frameFailure.failure.kind)
        assertTrue(frameFailure.message.orEmpty().contains("frame limit"))

        val totalFailure = assertFailsWith<AgentExecutionException> {
            harness("oversized-frame-prompt", maximumFrameBytes = 128 * 1024)
                .execute(fixture(maximumOutputBytes = 1_024).request)
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, totalFailure.failure.kind)
        assertTrue(totalFailure.message.orEmpty().contains("execution limit"))

        val stderrHarness = harness("stderr-overflow")
        stderrHarness.execute(fixture().request)
        val diagnostics = assertNotNull(stderrHarness.latestDiagnostics())
        assertTrue(diagnostics.stderrTruncated)
        assertTrue(diagnostics.stderr.toByteArray().size <= 64 * 1024)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `workspace snapshots stream large files and observe prelaunch cancellation and wall time`() {
        val largeFixture = fixture()
        largeFixture.source.writeText("x".repeat(2 * 1024 * 1024))

        val largeResult = harness("success").execute(largeFixture.request)

        assertEquals(AgentFileChangeKind.MODIFIED, largeResult.changes.single().kind)
        assertNotNull(largeResult.changes.single().beforeSha256)

        val cancellationPolls = AtomicInteger()
        val cancellation = AgentCancellation {
            cancellationPolls.incrementAndGet() >= 2
        }
        val cancelledFixture = fixture()
        val cancelledHarness = harness("success")

        val cancelled = cancelledHarness.execute(cancelledFixture.request.withCancellation(cancellation))

        assertEquals(AgentStopReason.CANCELLED, cancelled.stopReason)
        assertTrue(cancelled.summary.orEmpty().contains("initial workspace snapshot"))
        assertEquals(null, cancelledHarness.latestDiagnostics())

        val timeoutFixture = fixture()
        val timeoutHarness = harness("success")
        val timeout = assertFailsWith<AgentExecutionException> {
            timeoutHarness.execute(timeoutFixture.request.withWallClockTimeout(Duration.ofNanos(1)))
        }
        assertEquals(AgentFailureKind.TIMEOUT, timeout.failure.kind)
        assertTrue(timeout.message.orEmpty().contains("initial workspace snapshot"))
        assertEquals(null, timeoutHarness.latestDiagnostics())

        val finalCancellationFixture = fixture(includeReadyPath = true)
        val finalCancellationMarker = finalCancellationFixture.workspace.resolve("ready")
        val finalCancellationHarness = harness("cancel-after-response", ready = finalCancellationMarker)
        val finalCancellation = AgentCancellation { finalCancellationMarker.exists() }
        val finalFailure = assertFailsWith<AgentExecutionException> {
            finalCancellationHarness.execute(
                finalCancellationFixture.request.withCancellation(finalCancellation),
            )
        }
        assertEquals(AgentFailureKind.UNAVAILABLE, finalFailure.failure.kind)
        assertEquals("final-workspace-snapshot", finalFailure.failure.details["phase"])
        val finalDiagnostics = assertNotNull(finalCancellationHarness.latestDiagnostics())
        assertEquals(0, finalDiagnostics.exitCode)
        assertFalse(finalDiagnostics.forcedTermination)
        assertProcessStopped(finalDiagnostics.pid)
    }

    @Test
    fun `authentication-required JSON-RPC error is typed and does not leak the process`() {
        val harness = harness("auth-required")
        val failure = assertFailsWith<AgentExecutionException> {
            harness.execute(fixture().request)
        }

        assertEquals(AgentFailureKind.AUTHENTICATION, failure.failure.kind)
        assertEquals("-32000", failure.failure.details["rpcCode"])
        assertTrue(failure.message.orEmpty().contains("configure the external agent"))
        assertProcessStopped(assertNotNull(harness.latestDiagnostics()).pid)
    }

    private data class Fixture(
        val workspace: Path,
        val source: Path,
        val request: AgentExecutionRequest,
    )

    private fun fixture(
        idleMillis: Long = 1_000,
        includeReadyPath: Boolean = false,
        wallMillis: Long = 5_000,
        maximumOutputBytes: Long = 128 * 1024,
    ): Fixture {
        val workspace = createTempDirectory("acp-harness-").toAbsolutePath().normalize()
        val source = workspace.resolve("src/module.c")
        source.parent.createDirectories()
        source.writeText("old source\n")
        val rules = mutableListOf(
            AgentPathRule(
                AgentWorkspacePath("project", "src/module.c"),
                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
            ),
        )
        if (includeReadyPath) {
            rules += AgentPathRule(
                AgentWorkspacePath("project", "ready"),
                setOf(AgentOperation.CREATE_FILE, AgentOperation.WRITE_FILE),
            )
        }
        return Fixture(
            workspace,
            source,
            AgentExecutionRequest(
                objective = "edit the fixture",
                workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
                contextInputs = listOf(decompengine.agent.AgentContextInput("compiler", "compiler evidence")),
                accessPolicy = AgentAccessPolicy(rules),
                limits = AgentExecutionLimits(
                    wallClockTimeout = Duration.ofMillis(wallMillis),
                    idleTimeout = Duration.ofMillis(idleMillis),
                    maxTurns = 1,
                    maxToolCalls = 4,
                    maxOutputBytes = maximumOutputBytes,
                ),
            ),
        )
    }

    private fun AgentExecutionRequest.withCancellation(source: AgentCancellationSource): AgentExecutionRequest =
        withCancellation(source.cancellation)

    private fun AgentExecutionRequest.withCancellation(
        cancellation: AgentCancellation,
    ): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            limits,
            cancellation,
        )

    private fun AgentExecutionRequest.withWallClockTimeout(timeout: Duration): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            AgentExecutionLimits(
                wallClockTimeout = timeout,
                idleTimeout = limits.idleTimeout,
                maxTurns = limits.maxTurns,
                maxToolCalls = limits.maxToolCalls,
                maxOutputBytes = limits.maxOutputBytes,
                maxInputTokens = limits.maxInputTokens,
                maxOutputTokens = limits.maxOutputTokens,
            ),
            cancellation,
        )

    private fun harness(
        mode: String,
        sentinel: String = "literal-argv",
        ready: Path? = null,
        requiredCapabilities: Set<AcpRequiredAgentCapability> = emptySet(),
        timeouts: AcpLifecycleTimeouts = timeouts(),
        maximumFrameBytes: Int = 64 * 1024,
    ): AcpAgentHarness {
        val script = Path.of(requireNotNull(javaClass.getResource("/acp/fake_acp_v1_agent.py")).toURI())
        val arguments = mutableListOf(script.toString(), mode, sentinel)
        ready?.let { arguments += it.toString() }
        return AcpAgentHarness(
            AcpProcessConfiguration(
                executable = Path.of("/usr/bin/python3"),
                arguments = arguments,
                requiredAgentCapabilities = requiredCapabilities,
                timeouts = timeouts,
                maximumFrameBytes = maximumFrameBytes,
                maximumStderrBytes = 64 * 1024,
                implementationId = "scripted-acp-v1",
            ),
        )
    }

    private fun timeouts(
        startup: Long = 1_000,
        request: Long = 2_000,
        shutdown: Long = 600,
    ): AcpLifecycleTimeouts = AcpLifecycleTimeouts(
        startup = Duration.ofMillis(startup),
        request = Duration.ofMillis(request),
        cancellationGrace = Duration.ofMillis(300),
        transportDrainGrace = Duration.ofMillis(80),
        shutdown = Duration.ofMillis(shutdown),
    )

    private fun assertProcessStopped(pid: Long) {
        assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false), "process $pid is still alive")
    }
}

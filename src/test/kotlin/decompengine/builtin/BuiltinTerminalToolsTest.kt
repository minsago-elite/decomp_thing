package decompengine.builtin

import com.agentclientprotocol.model.*
import decompengine.acp.*
import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class BuiltinTerminalToolsTest {
    private fun call(operation: String = "check", extra: Boolean = false) = ModelToolCall("process_1", "run_process", buildJsonObject {
        put("operation", operation); if (extra) put("command", "/usr/bin/false")
    })

    @Test fun `operation metadata rejects invalid ids without creating a process`() {
        val placeholder = Path.of("/fixture/program")
        val rule = AcpTerminalCommandRule(AcpSandboxReadOnlyMount(placeholder, placeholder, "a".repeat(64)), emptyList(), Path.of("/fixture/stage"))
        assertFailsWith<IllegalArgumentException> { BuiltinProcessOperation("../command", BuiltinProcessPurpose.TEST, "fixture", rule) }
        assertFalse(BuiltinProcessOperation("check", BuiltinProcessPurpose.TEST, "fixture", rule).toString().contains(placeholder.toString()))
        assertEquals(2, terminalLimits(1024).resourceLimits.maximumCpuSeconds)
    }

    @Test fun `typed and direct ACP operations agree on output policy and complete terminal release`() = fixture { fixture ->
        val typed = fixture.open()
        val typedResult = typed.use {
            val result = it.execute(call(), fixture.control)
            assertFalse(result.failed)
            it.finish()
            assertTrue(it.audit().any { record -> record.reason == AcpTerminalAuditReason.RELEASED })
            assertTrue(it.audit().all { record -> record.networkIsolated })
            assertTrue(it.sandboxEvidence().networkIsolated)
            result
        }
        val data = Json.parseToJsonElement(typedResult.content).jsonObject
        val audit = AcpTerminalAuditRecorder(networkIsolated = true)
        LinuxBubblewrapBoundary.prepare(fixture.configuration).use { boundary ->
            boundary.openTerminalBroker(fixture.request, AgentCancellation.NONE, fixture.policy, emptyMap(), audit).use { broker -> runBlocking {
                broker.bindSession("direct")
                val rule = fixture.operation.rule
                val terminal = broker.create("direct", rule.command, rule.arguments, rule.workingDirectory.toString(), emptyList(), null).terminalId
                broker.observeToolCall("direct", SessionUpdate.ToolCallUpdate(ToolCallId("process_1"), title = "check",
                    kind = ToolKind.EXECUTE, status = ToolCallStatus.IN_PROGRESS, content = listOf(ToolCallContent.Terminal(terminal))))
                val exit = broker.waitForExit("direct", terminal)
                val output = broker.output("direct", terminal)
                broker.release("direct", terminal); broker.finishSession("direct")
                assertEquals(exit.exitCode?.toLong(), data.getValue("exitCode").jsonPrimitive.long)
                assertEquals(output.output, data.getValue("output").jsonPrimitive.content)
                assertEquals(output.truncated, data.getValue("truncated").jsonPrimitive.boolean)
            } }
        }
        assertEquals(audit.snapshot().map { it.reason }, typed.audit().map { it.reason })
        assertEquals(audit.snapshot().filter { it.reason == AcpTerminalAuditReason.LAUNCH_AUTHORIZED }.map { it.requestSha256 },
            typed.audit().filter { it.reason == AcpTerminalAuditReason.LAUNCH_AUTHORIZED }.map { it.requestSha256 })
        assertTrue(data.getValue("passed").jsonPrimitive.boolean)
    }

    @Test fun `unknown operation and argument injection cannot reach the launcher`() = fixture { fixture ->
        fixture.open().use { dispatcher ->
            assertTrue(dispatcher.execute(call("unknown"), fixture.control).failed)
            assertTrue(dispatcher.execute(call(extra = true), fixture.control).failed)
            assertTrue(dispatcher.audit().isEmpty())
            assertTrue(dispatcher.sandboxEvidence().launches.isEmpty())
            dispatcher.finish()
        }
    }

    @Test fun `workflow execution denial is the same broker decision`() = fixture(execute = false) { fixture ->
        fixture.open().use { dispatcher ->
            assertTrue(dispatcher.execute(call(), fixture.control).failed)
            assertEquals(AcpTerminalAuditReason.CAPABILITY_DISABLED, dispatcher.audit().single().reason)
            assertTrue(dispatcher.sandboxEvidence().launches.isEmpty())
            dispatcher.finish()
        }
    }

    @Test fun `nonzero command exits are feedback and truncated success cannot pass validation`() {
        fixture(mode = "unknown-mode") { fixture -> fixture.open().use { dispatcher ->
            val result = dispatcher.execute(call(), fixture.control)
            assertFalse(result.failed)
            val body = Json.parseToJsonElement(result.content).jsonObject
            assertEquals(2, body.getValue("exitCode").jsonPrimitive.int)
            assertFalse(body.getValue("passed").jsonPrimitive.boolean)
            dispatcher.finish()
        } }
        fixture(retainedBytes = 8) { fixture -> fixture.open().use { dispatcher ->
            val body = Json.parseToJsonElement(dispatcher.execute(call(), fixture.control).content).jsonObject
            assertTrue(body.getValue("truncated").jsonPrimitive.boolean)
            assertFalse(body.getValue("passed").jsonPrimitive.boolean)
            assertEquals("89abcdef", body.getValue("output").jsonPrimitive.content)
            dispatcher.finish()
        } }
    }

    @Test fun `original cancellation reaches running terminal and leaves no unreleased process`() = fixture(mode = "escape") { fixture ->
        val executor = Executors.newSingleThreadExecutor()
        val dispatcher = fixture.open()
        try {
            val work = executor.submit<BuiltinToolResult> { dispatcher.execute(call(), fixture.control) }
            val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
            while (dispatcher.audit().none { it.reason == AcpTerminalAuditReason.CREATED } && System.nanoTime() < deadline && !work.isDone) Thread.sleep(10)
            assertTrue(dispatcher.audit().any { it.reason == AcpTerminalAuditReason.CREATED })
            fixture.cancellation.cancel()
            assertFailsWith<java.util.concurrent.ExecutionException> { work.get(8, TimeUnit.SECONDS) }
            dispatcher.close()
            assertTrue(dispatcher.audit().any { it.reason == AcpTerminalAuditReason.RELEASED })
            assertTrue(dispatcher.audit().none { it.reason == AcpTerminalAuditReason.CLEANUP_FAILED })
        } finally { dispatcher.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
    }

    @Test fun `loop receives structured process feedback and still requires workflow validation`() = fixture { fixture ->
        var modelCalls = 0
        var tools: BuiltinProcessToolSession? = null
        val provider = ModelProvider { request, _ ->
            if (modelCalls++ == 0) ModelResponse("", listOf(call()), ModelFinishReason.TOOL_CALLS, ModelUsage(10, 10, false), 1)
            else {
                val feedback = Json.parseToJsonElement(request.messages.last().content).jsonObject
                assertTrue(feedback.getValue("passed").jsonPrimitive.boolean)
                ModelResponse("", emptyList(), ModelFinishReason.STOP, ModelUsage(10, 10, false), 1)
            }
        }
        val harness = BuiltinAgentHarness(provider, { _, control ->
            val workspace = object : BuiltinToolSession {
                override val definitions = emptyList<ModelToolDefinition>()
                override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl) = false
                override fun execute(call: ModelToolCall, control: BuiltinExecutionControl) = error("No workspace tool was registered")
                override fun changes(control: BuiltinExecutionControl) = emptyList<AgentFileChange>()
                override fun close() {}
            }
            BuiltinProcessToolSession(workspace, fixture.open(control)).also { tools = it }
        })
        val receipt = harness.executeReceipt(fixture.request) {}
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, assertIs<BuiltinLoopEvidence>(receipt.providerEvidence).stop)
        assertEquals(AgentStopReason.COMPLETED, receipt.requireResult().stopReason)
        assertTrue(requireNotNull(tools).terminalAudit().any { it.reason == AcpTerminalAuditReason.RELEASED })
    }

    private class Fixture(val request: AgentExecutionRequest, val control: BuiltinExecutionControl,
        val configuration: AcpLinuxSandboxConfiguration, val policy: AcpTerminalExecutionPolicy,
        val operation: BuiltinProcessOperation, val cancellation: AgentCancellationSource) {
        fun open(executionControl: BuiltinExecutionControl = control) =
            BuiltinTerminalDispatcher.open(request, executionControl, configuration, policy, listOf(operation), emptyMap(), 8192)
    }

    private fun fixture(mode: String = "terminal-output", retainedBytes: Int = 1024, execute: Boolean = true, test: (Fixture) -> Unit) {
        val bwrap = Path.of("/usr/bin/bwrap")
        val prlimit = Path.of("/usr/bin/prlimit")
        val systemd = Path.of("/usr/bin/systemd-run")
        val systemctl = Path.of("/usr/bin/systemctl")
        val bash = Path.of("/usr/bin/bash")
        val compiler = Path.of("/usr/bin/cc")
        val runtime = Path.of("/run/user/${Files.getAttribute(Path.of("/proc/self"), "unix:uid")}")
        AcpLiveContractHost.requireCapability(listOf(bwrap, prlimit, systemd, systemctl, bash, compiler).all(Files::isExecutable)
            && Files.exists(runtime.resolve("bus")), message = { "built-in terminal fixture requires the configured ACP sandbox host" })
        val parent = createTempDirectory("builtin-terminal-").toAbsolutePath().normalize()
        try {
            val probe = parent.resolve("probe")
            val source = Path.of(requireNotNull(javaClass.getResource("/acp/sandbox_probe.c")).toURI())
            val compilation = ProcessBuilder(compiler.toString(), "-O2", "-static", source.toString(), "-o", probe.toString())
                .redirectErrorStream(true).redirectOutput(parent.resolve("compiler.log").toFile()).start()
            try { assertTrue(compilation.waitFor(20, TimeUnit.SECONDS)); assertEquals(0, compilation.exitValue()) }
            finally { if (compilation.isAlive) { compilation.destroyForcibly(); compilation.waitFor(5, TimeUnit.SECONDS) } }
            val staging = AcpWorkflowStagingRoot.createReadOnly("project", parent)
            val cancellation = AgentCancellationSource()
            val request = AgentExecutionRequest("run fixture operation", listOf(staging.workspaceRoot), accessPolicy = AgentAccessPolicy(emptyList(),
                if (execute) setOf(AgentOperation.EXECUTE_COMMAND) else emptySet()), cancellation = cancellation.cancellation)
            val control = BuiltinExecutionControl(request, System.nanoTime() + Duration.ofSeconds(30).toNanos())
            val rule = AcpTerminalCommandRule(AcpSandboxReadOnlyMount(probe, Path.of("/builtin-process-probe"), calculateAcpRuntimeManifestSha256(probe)),
                listOf(mode), staging.path)
            val policy = AcpTerminalExecutionPolicy(listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)), listOf(rule),
                terminalLimits(retainedBytes))
            val helper = productionAcpGateHelper()
            val configuration = AcpLinuxSandboxConfiguration(bubblewrapExecutable = bwrap, resourceLimiterExecutable = prlimit,
                scopeSupervisorExecutable = systemd, scopeInspectorExecutable = systemctl, environmentFdOpenerExecutable = bash,
                sandboxGateHelperExecutable = helper, launcherRuntimeMounts = emptyList(), agentRuntimeMounts = emptyList(),
                systemdUserRuntimeDirectory = runtime, expectedBubblewrapSha256 = hash(bwrap), expectedResourceLimiterSha256 = hash(prlimit),
                expectedScopeSupervisorSha256 = hash(systemd), expectedScopeInspectorSha256 = hash(systemctl), expectedEnvironmentFdOpenerSha256 = hash(bash),
                expectedSandboxGateHelperSha256 = hash(helper), expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(helper))
            test(Fixture(request, control, configuration, policy, BuiltinProcessOperation("check", BuiltinProcessPurpose.TEST, "fixture check", rule), cancellation))
        } finally { Files.walk(parent).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private fun hash(path: Path): String = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }
    private fun terminalLimits(retainedBytes: Int) = AcpTerminalLimits(
        maximumConcurrentTerminals = 1, maximumTerminalCreates = 4, maximumRetainedOutputBytes = retainedBytes,
        maximumProducedOutputBytes = 64 * 1024, maximumDuration = Duration.ofSeconds(10), terminationGrace = Duration.ofMillis(100),
        resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 2),
    )
}

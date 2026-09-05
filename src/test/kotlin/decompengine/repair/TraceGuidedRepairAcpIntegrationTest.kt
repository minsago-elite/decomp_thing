package decompengine.repair

import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpLifecycleTimeouts
import decompengine.acp.AcpLinuxSandboxConfiguration
import decompengine.acp.AcpLiveContractHost
import decompengine.acp.AcpProcessConfiguration
import decompengine.acp.AcpSandboxReadOnlyMount
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.calculateAcpRuntimeManifestSha256
import decompengine.acp.productionAcpGateHelper
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentHarness
import decompengine.project.GeneratedCRepairValidationStrategy
import decompengine.project.MakeProjectBuilder
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Timeout
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The same benign repairs cross the fake adapter and the contained ACP JSON-RPC boundary. */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class TraceGuidedRepairAcpIntegrationTest {
    @Test
    fun `compile repair validates every retained input through fake and scripted ACP transports`() {
        forEachTransport { acp ->
            val fixture = fixture("#include \"fixture.h\"\nint main(void) {\n")
            val result = loop(fixture, acp, "repair").use {
                it.repairUntilValid(fixture.project, fixture.original, INPUTS, maxIterations = 1)
            }
            assertTrue(result.validation.matches)
            assertEquals(INPUTS.map { it.id }.sorted(), result.validation.cases.map { it.input.id }.sorted())
            val iteration = result.iterations.single()
            assertEquals("compile", iteration.failureKind)
            assertEquals("valid", iteration.after?.kind)
            assertTrue(iteration.succeeded)
            assertAccepted(fixture, iteration, acp)
        }
    }

    @Test
    fun `behavior repair validates every retained input through fake and scripted ACP transports`() {
        forEachTransport { acp ->
            val fixture = fixture(program("\"wrong\""))
            val rebuilt = MakeProjectBuilder.build(fixture.project).projectDir.resolve("build/reconstructed")
            val iteration = loop(fixture, acp, "repair").use {
                it.repairBehaviorMismatch(fixture.project, fixture.original, rebuilt, INPUTS, fixture.reports)
            }
            assertEquals("behavior", iteration.failureKind)
            assertEquals("valid", iteration.after?.kind)
            assertTrue(iteration.succeeded)
            assertAccepted(fixture, iteration, acp)
        }
    }

    @Test
    fun `compile breaking behavior edit restores the accepted tree with both transports`() {
        forEachTransport { acp ->
            val fixture = fixture(program("\"wrong\""))
            val rebuilt = MakeProjectBuilder.build(fixture.project).projectDir.resolve("build/reconstructed")
            val before = sourceSnapshot(fixture.project)
            val head = head(fixture.project)
            val iteration = loop(fixture, acp, "compile-invalid").use {
                it.repairBehaviorMismatch(fixture.project, fixture.original, rebuilt, INPUTS, fixture.reports)
            }
            assertFalse(iteration.succeeded)
            assertEquals("compile", iteration.after?.kind)
            assertRejected(fixture, head, before, acp)
        }
    }

    @Test
    fun `retained case regression restores the accepted tree with both transports`() {
        forEachTransport { acp ->
            val fixture = fixture(program("\"default\""))
            val before = sourceSnapshot(fixture.project)
            val head = head(fixture.project)
            assertFailsWith<RepairExhaustedException> {
                loop(fixture, acp, "retained-regression").use {
                    it.repairUntilValid(fixture.project, fixture.original, INPUTS, maxIterations = 1)
                }
            }
            assertEquals("retained-regression", RepairHistory(fixture.reports.resolve("repair_history.json"))
                .all().single().after?.kind)
            assertRejected(fixture, head, before, acp)
        }
    }

    @Test
    fun `scripted ACP terminal outcomes persist distinct evidence without advancing head`() {
        val cases = mapOf(
            "no-change" to "returned-no-changes",
            "refused" to "returned-refused",
            "limit" to "returned-limit-exhausted",
            "crash" to "failed-process-crash",
        )
        cases.forEach { (mode, terminal) ->
            val fixture = fixture("#include \"fixture.h\"\nint main(void) {\n")
            val before = sourceSnapshot(fixture.project)
            val head = head(fixture.project)
            val failure = assertFailsWith<Exception>(mode) {
                loop(fixture, true, mode).use {
                    it.repairUntilValid(fixture.project, fixture.original, INPUTS, maxIterations = 1)
                }
            }
            assertTrue(RepairHistory(fixture.reports.resolve("repair_history.json")).all().isNotEmpty(),
                failure.stackTraceToString())
            assertRejected(fixture, head, before, acp = true, completed = false)
            val iteration = RepairHistory(fixture.reports.resolve("repair_history.json")).all().single()
            assertEquals(terminal, iteration.agentInvocation?.terminalOutcome, mode)
        }
    }

    private fun assertAccepted(fixture: Fixture, iteration: RepairIteration, acp: Boolean) {
        ModuleRevisionGraph.open(fixture.project, PROFILE).use { graph ->
            val node = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.ACCEPTED, node.status)
            assertEquals(node.id, graph.snapshot.headId)
            assertEquals(INPUTS.sortedBy { it.id }, graph.retainedRegressionCorpus().inputs)
        }
        assertEquals(program("argc > 1 ? \"argument\" : \"default\""),
            fixture.project.resolve("src/program.c").readText())
        assertEquals(listOf("src/program.c"), iteration.patches.map { it.relativePath })
        assertFalse(iteration.releaseComplete, "host build fixture must remain non-release")
        if (acp) assertReceipt(fixture, iteration, accepted = true, completed = true)
    }

    private fun assertRejected(
        fixture: Fixture,
        head: String,
        before: Map<String, ByteArray>,
        acp: Boolean,
        completed: Boolean = true,
    ) {
        ModuleRevisionGraph.open(fixture.project, PROFILE).use { graph ->
            assertEquals(head, graph.snapshot.headId)
            val node = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            assertNotEquals(node.id, graph.snapshot.headId)
            assertEquals(INPUTS.sortedBy { it.id }, graph.retainedRegressionCorpus().inputs)
        }
        val after = sourceSnapshot(fixture.project)
        assertEquals(before.keys, after.keys)
        before.forEach { (path, bytes) -> assertContentEquals(bytes, after.getValue(path), path) }
        val iteration = RepairHistory(fixture.reports.resolve("repair_history.json")).all().single()
        assertFalse(iteration.succeeded)
        if (acp) assertReceipt(fixture, iteration, accepted = false, completed = completed)
    }

    private fun assertReceipt(fixture: Fixture, iteration: RepairIteration, accepted: Boolean, completed: Boolean) {
        val binding = assertNotNull(iteration.agentInvocation)
        assertEquals(if (accepted) RepairAgentAssessmentStatus.ACCEPTED else RepairAgentAssessmentStatus.REJECTED,
            binding.assessmentStatus)
        val bytes = fixture.project.resolve(binding.receiptPath).readBytes()
        assertEquals(binding.receiptSha256, sha256(bytes))
        val receipt = Json.parseToJsonElement(bytes.decodeToString()).jsonObject
        assertEquals(TRACE_REPAIR_ACP_RECEIPT_KIND, receipt.getValue("kind").jsonPrimitive.content)
        assertEquals("trace-scripted-acp-v1", receipt.getValue("factoryProvenance").jsonObject
            .getValue("implementationId").jsonPrimitive.content)
        assertEquals(sha256("1.0".toByteArray()), receipt.getValue("agent").jsonObject
            .getValue("negotiatedImplementation").jsonObject.getValue("version").commitment())
        assertEquals(sha256("trace-repair-fixture-session".toByteArray()), receipt.getValue("session")
            .jsonObject.getValue("sessionId").commitment())
        assertEquals(binding.requestSha256, receipt.getValue("request").jsonObject
            .getValue("requestSha256").jsonPrimitive.content)
        val request = receipt.getValue("request").jsonObject
        assertTrue(request.getValue("maximumTurns").jsonPrimitive.content.toInt() > 0)
        assertTrue(request.getValue("maximumOutputBytes").jsonPrimitive.content.toLong() > 0)
        assertTrue(receipt.getValue("events").jsonObject.getValue("records").jsonArray.isNotEmpty())
        assertTrue(receipt.getValue("sandbox").jsonObject.getValue("outerAgentContained").jsonPrimitive.content.toBoolean())
        if (completed) {
            assertEquals("returned-completed", binding.terminalOutcome)
            assertTrue(binding.receiptReleaseComplete)
            val changes = receipt.getValue("outcome").jsonObject.getValue("result").jsonObject
                .getValue("changes").jsonObject.getValue("records").jsonArray
            assertEquals(listOf(sha256("src/program.c".toByteArray())),
                changes.map { it.jsonObject.getValue("relativePath").commitment() })
            val audit = receipt.getValue("policyAudits").jsonObject.getValue("filesystem")
                .jsonObject.getValue("records").jsonArray
            assertEquals(3, audit.size)
            assertEquals(sha256("fs/write_text_file".toByteArray()), audit.last().jsonObject.getValue("method").commitment())
        }
    }

    private fun kotlinx.serialization.json.JsonElement.commitment() = jsonObject.getValue("sha256").jsonPrimitive.content

    private fun forEachTransport(block: (Boolean) -> Unit) {
        block(false)
        block(true)
    }

    private data class Fixture(val project: Path, val original: Path) {
        val reports: Path get() = project.resolve("reports")
    }

    private fun fixture(source: String): Fixture {
        val root = createTempDirectory("trace-repair-acp-")
        val project = root.resolve("project")
        project.resolve("src").createDirectories()
        project.resolve("include").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("include/fixture.h").writeText("#define FIXTURE 1\n")
        project.resolve("src/program.c").writeText(source)
        project.resolve("src/unrelated.c").writeText("int unrelated(void) { return 7; }\n")
        project.resolve("Makefile").writeText(
            "all: build/reconstructed\nbuild/reconstructed: src/program.c include/fixture.h\n" +
                "\t@mkdir -p build\n\tcc -std=c11 -Wall -Wextra -Werror -Iinclude src/program.c -o build/reconstructed\n",
        )
        val originalSource = root.resolve("original.c")
        originalSource.writeText(program("argc > 1 ? \"argument\" : \"default\""))
        val original = root.resolve("original")
        val diagnostics = root.resolve("original.log")
        val process = ProcessBuilder("/usr/bin/cc", "-I${project.resolve("include")}",
            originalSource.toString(), "-o", original.toString()).redirectErrorStream(true)
            .redirectOutput(diagnostics.toFile()).start()
        check(process.waitFor(20, TimeUnit.SECONDS)) { process.destroyForcibly(); "fixture compile timed out" }
        check(process.exitValue() == 0) { diagnostics.readText() }
        return Fixture(project, original)
    }

    private fun sourceSnapshot(project: Path): Map<String, ByteArray> = listOf(
        "src/program.c", "src/unrelated.c", "include/fixture.h", "Makefile",
    ).associateWith { project.resolve(it).readBytes() }

    private fun head(project: Path): String = ModuleRevisionGraph.open(project, PROFILE)
        .use { it.snapshot.headId }

    private fun loop(fixture: Fixture, acp: Boolean, mode: String): TraceGuidedRepairLoop {
        val harness: AgentHarness = if (acp) scriptedHarness(mode) else RepairClientAgentHarness(object : RepairClient {
            override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
                assertTrue(INPUTS.all { it.id in request.prompt })
                assertTrue("stdinHex=6b6570740a" in request.prompt)
                assertTrue("src/program.c" in request.projectFiles)
                assertTrue("include/fixture.h" in request.projectFiles)
                assertFalse("src/unrelated.c" in request.projectFiles)
                val replacement = when (mode) {
                    "compile-invalid" -> "#include \"fixture.h\"\nint main(void) {\n"
                    "retained-regression" -> program("\"argument\"")
                    else -> program("argc > 1 ? \"argument\" : \"default\"")
                }
                return RepairResponse("repair fixture", listOf(SourcePatch("src/program.c", replacement)))
            }
        })
        return TraceGuidedRepairLoop.forTesting(harness, RepairHistory(fixture.reports.resolve("repair_history.json")),
            PROFILE, GeneratedCRepairValidationStrategy(TestOnlyGeneratedCRepairValidationBoundary),
            CapturedRepairStagingAuthority, limits = AgentExecutionLimits(
                wallClockTimeout = Duration.ofSeconds(30), idleTimeout = Duration.ofSeconds(10),
                maxTurns = 1, maxToolCalls = 8, maxOutputBytes = 128 * 1024,
            ))
    }

    private fun scriptedHarness(mode: String): AcpAgentHarness {
        AcpLiveContractHost.requireCapability(PYTHON_RUNTIME.isSuccess,
            { "repair fixture Python discovery failed: ${PYTHON_RUNTIME.exceptionOrNull()?.message}" })
        val required = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, GATE_HELPER)
        AcpLiveContractHost.requireCapability(required.all(Files::isExecutable), { "repair ACP sandbox tools unavailable" })
        AcpLiveContractHost.requireCapability(Files.exists(USER_RUNTIME.resolve("bus")), { "systemd user bus unavailable" })
        val runtime = PYTHON_RUNTIME.getOrThrow()
        val script = Path.of(requireNotNull(javaClass.getResource("/repair/scripted_repair_agent.py")).toURI())
        val scriptDestination = Path.of("/decomp-acp-test/scripted_repair_agent.py")
        val configuration = AcpProcessConfiguration(
            executable = runtime.executable,
            arguments = listOf("-S", scriptDestination.toString(), mode),
            implementationId = "trace-scripted-acp-v1",
            timeouts = AcpLifecycleTimeouts(request = Duration.ofSeconds(20)),
            sandboxBoundary = AcpLinuxSandboxConfiguration(
                bubblewrapExecutable = BWRAP, resourceLimiterExecutable = PRLIMIT,
                scopeSupervisorExecutable = SYSTEMD_RUN, scopeInspectorExecutable = SYSTEMCTL,
                environmentFdOpenerExecutable = BASH, sandboxGateHelperExecutable = GATE_HELPER,
                systemdUserRuntimeDirectory = USER_RUNTIME,
                launcherRuntimeMounts = runtime.nativeRuntimeMounts + runtime.stdlibMounts(listOf(
                    "encodings", "json", "re", "collections", "_collections_abc.py", "abc.py", "codecs.py",
                    "copyreg.py", "enum.py", "functools.py", "keyword.py", "operator.py", "reprlib.py", "types.py", "zipimport.py",
                )),
                agentRuntimeMounts = listOf(AcpSandboxReadOnlyMount(script, scriptDestination,
                    calculateAcpRuntimeManifestSha256(script))),
                agentResourceLimits = AcpSandboxResourceLimits(maximumProcesses = 16, maximumOpenFiles = 128,
                    maximumFileBytes = 64L * 1024 * 1024, maximumAddressSpaceBytes = 512L * 1024 * 1024,
                    maximumCpuSeconds = 20),
                expectedBubblewrapSha256 = sha256(BWRAP.readBytes()),
                expectedResourceLimiterSha256 = sha256(PRLIMIT.readBytes()),
                expectedScopeSupervisorSha256 = sha256(SYSTEMD_RUN.readBytes()),
                expectedScopeInspectorSha256 = sha256(SYSTEMCTL.readBytes()),
                expectedEnvironmentFdOpenerSha256 = sha256(BASH.readBytes()),
                expectedSandboxGateHelperSha256 = sha256(GATE_HELPER.readBytes()),
                expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(GATE_HELPER),
            ),
        )
        return AcpAgentHarness(configuration).bindFactoryProvenance(AcpHarnessProvenance(
            harness = "acp", implementationId = configuration.implementationId,
            agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION, acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = sha256(script.readBytes() + mode.toByteArray()), deprecated = false,
        ))
    }

    private fun program(expression: String): String = "#include <stdio.h>\n#include \"fixture.h\"\n" +
        "int main(int argc, char **argv) { (void)argc; (void)argv; puts($expression); return 0; }\n"

    private companion object {
        val PROFILE = DeclarativeRepairIndexProfile("trace-acp-fixture-v1", RepairIndexLayout(
            sourcePaths = listOf("Makefile", "include/fixture.h", "src/program.c", "src/unrelated.c"),
            editablePaths = listOf("src/program.c", "src/unrelated.c"),
            modules = listOf(
                RepairModuleEvidence("program", listOf("src/program.c"), dependencyModuleIds = listOf("support")),
                RepairModuleEvidence("support", listOf("include/fixture.h"), dependencyContextPaths = listOf("include/fixture.h")),
                RepairModuleEvidence("unrelated", listOf("src/unrelated.c")),
            ),
            sharedContextPaths = listOf("Makefile"),
            behaviorRootModuleIds = listOf("program"),
        ))
        val INPUTS = listOf(ProcessInput("default", stdin = "kept\n".toByteArray()),
            ProcessInput("argument", args = listOf("kept"), stdin = "kept\n".toByteArray()))
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val PYTHON_RUNTIME by lazy { runCatching { AcpLiveContractHost.discoverPythonRuntime() } }
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
    }
}

package decompengine.acp

import decompengine.selectPatchStrategy
import decompengine.mvp.BinaryDecompiler
import decompengine.mvp.BinaryExecutionBoundary
import decompengine.mvp.BinaryExecutionResult
import decompengine.mvp.BinaryIsolation
import decompengine.mvp.MvpPatchOptions
import decompengine.mvp.MvpPatchWorkflow
import decompengine.mvp.PATCH_AGENT_EVIDENCE
import decompengine.mvp.RECONSTRUCTION_AGENT_EVIDENCE
import decompengine.project.sha256
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Timeout

@Timeout(value = 90, unit = TimeUnit.SECONDS)
class MvpPatchAcpIntegrationTest {
    @Test
    fun `default ACP patch turns use captured filesystem callbacks and archive both executions`() {
        requireLiveSandboxHost()
        val temporary = createTempDirectory("mvp-patch-acp-")
        val config = writeProvisioning(temporary.resolve("acp.json"))
        val environment = mapOf(
            "ACP_CONFIG_FILE" to config.toString(),
            // These values must neither select nor become a fallback transport.
            "BASE_URL" to "http://127.0.0.1:1/v1",
            "API_KEY" to "direct-http-fallback-must-not-run",
            "MODEL" to "legacy-model-must-not-run",
        )
        val strategy = selectPatchStrategy(null, environment)
        assertIs<AcpAgentHarness>(strategy.harness)

        val input = compileC(temporary, "original", originalSource())
        val output = temporary.resolve("output")
        MvpPatchWorkflow(
            harness = strategy.harness,
            environment = environment,
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw ->
                raw.writeText("int main(void) { /* authenticated Ghidra fixture */ }\n")
            },
            binaryExecution = testExecutionBoundary(),
            harnessProvenance = strategy.harnessProvenance,
        ).run(MvpPatchOptions(input, output))

        val reconstruction = executionEvidence(output, RECONSTRUCTION_AGENT_EVIDENCE)
        val patch = executionEvidence(output, PATCH_AGENT_EVIDENCE)
        assertCapturedTurn(reconstruction, "reconstruction-turn", "decompiled.c")
        assertCapturedTurn(patch, "patch-turn", "patched.c")
        assertFalse(
            reconstruction.getValue("validation").jsonObject.getValue("sourceSha256").jsonPrimitive.content ==
                patch.getValue("validation").jsonObject.getValue("sourceSha256").jsonPrimitive.content,
        )

        val summary = output.resolve("summary/SUMMARY.md").readText()
        listOf(RECONSTRUCTION_AGENT_EVIDENCE, PATCH_AGENT_EVIDENCE).forEach { name ->
            val artifact = output.resolve("evidence/$name")
            assertTrue(artifact.exists())
            assertTrue(summary.contains("evidence/$name"))
            assertTrue(summary.contains(sha256(artifact.readBytes())))
        }
        assertFalse(summary.contains("direct-http-fallback-must-not-run"))
    }

    @Test
    fun `failed behavior validation marks the captured patch execution rejected`() {
        requireLiveSandboxHost()
        val temporary = createTempDirectory("mvp-patch-acp-rejected-")
        val config = writeProvisioning(temporary.resolve("acp.json"), mode = "mvp-patch-bad-fix")
        val environment = mapOf("ACP_CONFIG_FILE" to config.toString())
        val strategy = selectPatchStrategy(null, environment)
        val input = compileC(temporary, "original", originalSource())
        val output = temporary.resolve("output")

        val failure = assertFailsWith<decompengine.mvp.MvpPatchException> {
            MvpPatchWorkflow(
                harness = strategy.harness,
                environment = environment,
                approve = { true },
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* Ghidra */ }\n") },
                binaryExecution = testExecutionBoundary(),
                harnessProvenance = strategy.harnessProvenance,
            ).run(MvpPatchOptions(input, output))
        }

        assertTrue(failure.message.orEmpty().contains("preserve observed behavior"))
        val patch = executionEvidence(output, PATCH_AGENT_EVIDENCE)
        val validation = patch.getValue("validation").jsonObject
        assertFalse(validation.getValue("accepted").jsonPrimitive.content.toBoolean())
        assertEquals(
            "workflow-validation-rejected",
            validation.getValue("issues").jsonArray.single().jsonObject.getValue("code").jsonPrimitive.content,
        )
        val artifact = output.resolve("evidence/$PATCH_AGENT_EVIDENCE")
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains(sha256(artifact.readBytes())))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
    }

    private fun assertCapturedTurn(evidence: JsonObject, taskId: String, target: String) {
        assertEquals("decomp-engine.mvp-patch-acp-execution", evidence.getValue("kind").jsonPrimitive.content)
        assertEquals(taskId, evidence.getValue("taskId").jsonPrimitive.content)
        assertEquals("acp", evidence.getValue("factoryProvenance").jsonObject.getValue("harness").jsonPrimitive.content)
        assertTrue(evidence.getValue("sandbox").jsonObject.getValue("outerAgentContained").jsonPrimitive.content.toBoolean())
        assertTrue(evidence.getValue("sandbox").jsonObject.getValue("networkIsolated").jsonPrimitive.content.toBoolean())
        val filesystem = evidence.getValue("policyAudits").jsonObject.getValue("filesystem").jsonArray
        assertTrue(filesystem.any { record ->
            val item = record.jsonObject
            item.getValue("method").jsonPrimitive.content == "fs/write_text_file" &&
                item.getValue("policyPath").jsonObject.getValue("relativePath").jsonPrimitive.content == target
        })
        assertTrue(evidence.getValue("policyAudits").jsonObject.getValue("terminal").jsonArray.isEmpty())
        val changes = evidence.getValue("result").jsonObject.getValue("changes").jsonArray
        assertEquals(listOf(target), changes.map { it.jsonObject.getValue("relativePath").jsonPrimitive.content })
        assertTrue(
            evidence.getValue("turn").jsonObject.getValue("accessPolicySha256").jsonPrimitive.content
                .matches(Regex("[0-9a-f]{64}")),
        )
    }

    private fun executionEvidence(output: Path, name: String): JsonObject =
        Json.parseToJsonElement(output.resolve("evidence/$name").readText()).jsonObject

    private fun writeProvisioning(path: Path, mode: String = "mvp-patch"): Path {
        val runtime = PYTHON_RUNTIME.getOrThrow()
        val script = Path.of(requireNotNull(javaClass.getResource("/acp/fake_acp_v1_agent.py")).toURI())
        val launcherMounts = runtime.nativeRuntimeMounts + runtime.stdlibMounts(
            listOf(
                "encodings", "json", "re", "collections",
                "_collections_abc.py", "abc.py", "codecs.py", "copyreg.py", "enum.py",
                "functools.py", "keyword.py", "operator.py", "reprlib.py", "types.py", "zipimport.py",
            ),
        )
        val agentMounts = listOf(
            AcpSandboxReadOnlyMount(script, AGENT_SCRIPT_DESTINATION),
        )
        val document = buildJsonObject {
            put("schemaVersion", 1)
            put("implementationId", "mvp-scripted-acp-v1")
            putJsonObject("agent") {
                put("executable", runtime.executable.toString())
                putJsonArray("arguments") {
                    add("-S")
                    add(AGENT_SCRIPT_DESTINATION.toString())
                    add(mode)
                    add("captured-mvp")
                }
                put("environment", buildJsonArray { })
                put("inheritParentEnvironment", false)
                put("requiredCapabilities", buildJsonArray { })
                putJsonObject("timeoutsMillis") {
                    put("startup", 20_000)
                    put("request", 20_000)
                    put("cancellationGrace", 2_000)
                    put("transportDrainGrace", 100)
                    put("shutdown", 5_000)
                }
                putJsonObject("protocolLimits") {
                    put("maximumFrameBytes", 1_048_576)
                    put("maximumProtocolFrames", 1_024)
                    put("maximumStderrBytes", 262_144)
                }
                putJsonObject("filesystemLimits") {
                    put("maximumReadBytes", 8_388_608)
                    put("maximumWriteBytes", 8_388_608)
                }
                put("permissionMode", "default-deny")
                put("expectedExecutableManifestSha256", calculateAcpRuntimeManifestSha256(runtime.executable))
            }
            putJsonObject("sandbox") {
                put("bubblewrapExecutable", BWRAP.toString())
                put("resourceLimiterExecutable", PRLIMIT.toString())
                put("scopeSupervisorExecutable", SYSTEMD_RUN.toString())
                put("scopeInspectorExecutable", SYSTEMCTL.toString())
                put("environmentFdOpenerExecutable", BASH.toString())
                put("sandboxGateHelperExecutable", GATE_HELPER.toString())
                put("systemdUserRuntimeDirectory", USER_RUNTIME.toString())
                put("agentWorkingDirectory", "/tmp")
                put("launcherRuntimeMounts", mountsJson(launcherMounts))
                put("agentRuntimeMounts", mountsJson(agentMounts))
                putJsonObject("agentResourceLimits") {
                    put("maximumProcesses", 16)
                    put("maximumOpenFiles", 128)
                    put("maximumFileBytes", 67_108_864)
                    put("maximumAddressSpaceBytes", 536_870_912)
                    put("maximumCpuSeconds", 20)
                }
                putJsonObject("runtimeClosureLimits") {
                    put("maximumEntries", 100_000)
                    put("maximumUserOwnedFileBytes", 2_147_483_648)
                    put("maximumDepth", 64)
                }
                put("expectedBubblewrapSha256", fileSha256(BWRAP))
                put("expectedResourceLimiterSha256", fileSha256(PRLIMIT))
                put("expectedScopeSupervisorSha256", fileSha256(SYSTEMD_RUN))
                put("expectedScopeInspectorSha256", fileSha256(SYSTEMCTL))
                put("expectedEnvironmentFdOpenerSha256", fileSha256(BASH))
                put("expectedSandboxGateHelperSha256", fileSha256(GATE_HELPER))
                put("expectedSandboxGateHelperManifestSha256", calculateAcpRuntimeManifestSha256(GATE_HELPER))
            }
        }
        path.writeText(document.toString() + "\n")
        Files.setPosixFilePermissions(path, setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        ))
        return path.toAbsolutePath().normalize()
    }

    private fun mountsJson(mounts: Collection<AcpSandboxReadOnlyMount>) = buildJsonArray {
        mounts.forEach { mount ->
            add(buildJsonObject {
                put("source", mount.source.toString())
                put("destination", mount.destination.toString())
                put("expectedManifestSha256", calculateAcpRuntimeManifestSha256(mount.source))
            })
        }
    }

    private fun requireLiveSandboxHost() {
        AcpLiveContractHost.requireCapability(
            PYTHON_RUNTIME.isSuccess,
            message = { "system Python runtime discovery failed: ${PYTHON_RUNTIME.exceptionOrNull()?.message}" },
        )
        val missing = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, PYTHON)
            .filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(
            missing.isEmpty(),
            message = { "live ACP harness sandbox tools are unavailable: $missing" },
        )
        AcpLiveContractHost.requireCapability(
            Files.exists(USER_RUNTIME.resolve("bus")),
            message = { "systemd user bus is unavailable" },
        )
        AcpLiveContractHost.requireCapability(
            Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")),
            message = { "cgroup v2 is unavailable" },
        )
        AcpLiveContractHost.requireCapability(
            Files.isExecutable(GATE_HELPER),
            message = { "static ACP gate helper could not be built" },
        )
    }

    private fun testExecutionBoundary() = BinaryExecutionBoundary { executable, directory, environment ->
        val process = ProcessBuilder(executable.toAbsolutePath().toString())
            .directory(directory.toFile())
            .apply { environment().putAll(environment) }
            .start()
        BinaryExecutionResult(
            process.waitFor(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
            BinaryIsolation("deterministic test boundary", networkIsolated = true, credentialsIsolated = true),
        )
    }

    private fun compileC(tempDir: Path, name: String, source: String): Path {
        val sourcePath = tempDir.resolve("$name.c")
        val binary = tempDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder(
            "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", sourcePath.pathString, "-o", binary.pathString,
        ).redirectErrorStream(true).start()
        val diagnostics = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { diagnostics }
        return binary
    }

    private fun originalSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent()

    private fun fileSha256(path: Path): String = sha256(Files.readAllBytes(path))

    private companion object {
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val PYTHON_RUNTIME: Result<AcpPythonRuntimeLayout> by lazy {
            runCatching { AcpLiveContractHost.discoverPythonRuntime() }
        }
        val PYTHON: Path get() = PYTHON_RUNTIME.getOrThrow().executable
        val AGENT_SCRIPT_DESTINATION: Path = Path.of("/decomp-acp-test/fake_acp_v1_agent.py")
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
    }
}

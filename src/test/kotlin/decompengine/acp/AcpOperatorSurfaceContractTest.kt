package decompengine.acp

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempFile
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AcpOperatorSurfaceContractTest {
    @Test
    fun `checked provisioning template is strict bounded ACP and preserves ordered argv and secret provenance`() {
        val template = Path.of("config/acp-v1.example.json").readText()
        val privateConfig = createTempFile("acp-operator-template-", ".json").toAbsolutePath().normalize()
        privateConfig.writeText(template)
        Files.setPosixFilePermissions(privateConfig, setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        ))

        val selection = AcpHarnessFactory.fromEnvironment(mapOf(
            "ACP_CONFIG_FILE" to privateConfig.toString(),
        ))
        val configuration = assertNotNull(selection.configuration)
        val sandbox = assertNotNull(configuration.sandboxBoundary)

        assertEquals(AcpHarnessKind.ACP, selection.kind)
        assertEquals(listOf("--stdio", "--non-interactive"), configuration.arguments)
        assertFalse(configuration.inheritParentEnvironment)
        assertTrue(configuration.environment.isEmpty())
        assertEquals(1_048_576, configuration.maximumFrameBytes)
        assertEquals(1_024, configuration.maximumProtocolFrames)
        assertEquals(8_388_608, configuration.filesystemLimits.maximumWriteBytes)
        assertEquals(16, sandbox.agentResourceLimits.maximumProcesses)
        assertEquals(536_870_912L, sandbox.agentResourceLimits.maximumAddressSpaceBytes)
        assertEquals(10_000, sandbox.runtimeClosureLimits.maximumEntries)
        assertEquals(536_870_912L, sandbox.runtimeClosureLimits.maximumUserOwnedFileBytes)
        assertEquals(32, sandbox.runtimeClosureLimits.maximumDepth)
        assertEquals(Path.of("/tmp"), sandbox.agentWorkingDirectory)
        assertTrue(sandbox.launcherRuntimeMounts.isEmpty())
        assertEquals(Path.of("/opt/decomp-acp-agent/runtime"), sandbox.agentRuntimeMounts.single().source)
        assertTrue(template.contains("\"environment\": []"))
        assertFalse(template.contains("BASE_URL"))
        assertFalse(template.contains("API_KEY"))
        assertFalse(template.contains("MODEL"))

        val secretTemplate = template.replace(
            "\"environment\": []",
            """"environment": [{"name":"ACP_AGENT_SECRET","provenance":"secret","valueFromEnvironment":"ACP_AGENT_SECRET"}]""",
        )
        val secretConfig = createTempFile("acp-operator-secret-", ".json").toAbsolutePath().normalize()
        secretConfig.writeText(secretTemplate)
        Files.setPosixFilePermissions(secretConfig, setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        ))
        val firstSecret = AcpHarnessFactory.fromEnvironment(mapOf(
            "ACP_CONFIG_FILE" to secretConfig.toString(),
            "ACP_AGENT_SECRET" to "operator-secret-one",
        ))
        val secondSecret = AcpHarnessFactory.fromEnvironment(mapOf(
            "ACP_CONFIG_FILE" to secretConfig.toString(),
            "ACP_AGENT_SECRET" to "operator-secret-two",
        ))
        assertEquals(
            AcpEnvironmentProvenance.SECRET,
            firstSecret.configuration?.environment?.getValue("ACP_AGENT_SECRET")?.provenance,
        )
        assertEquals(firstSecret.provenance.configurationSha256, secondSecret.provenance.configurationSha256)
        assertFalse(firstSecret.provenance.stableDescriptor.contains("operator-secret-one"))
        assertFalse(secondSecret.provenance.stableDescriptor.contains("operator-secret-two"))
    }

    @Test
    fun `standard environment and compose surface are ACP only and fail closed`() {
        val standardEnvironment = Path.of(".env.example").readText()
        val legacyEnvironment = Path.of(".env.legacy-openai.example").readText()
        val compose = Path.of("compose.yaml").readText()
        val acp = compose.substringAfter("  llm-bin-patch:")
            .substringBefore("\n  binary-runner-acp:")
        val acpRunner = compose.substringAfter("  binary-runner-acp:")
            .substringBefore("\n  llm-bin-patch-legacy:")
        val legacy = compose.substringAfter("  llm-bin-patch-legacy:")
            .substringBefore("\n  binary-runner:")

        assertTrue(standardEnvironment.contains("ACP_CONFIG_FILE="))
        assertTrue(standardEnvironment.contains("ACP_AGENT_RUNTIME_ROOT="))
        assertTrue(standardEnvironment.contains("ACP_SYSTEMD_USER_RUNTIME="))
        assertFalse(standardEnvironment.contains("BASE_URL="))
        assertFalse(standardEnvironment.contains("API_KEY="))
        assertFalse(standardEnvironment.contains("MODEL="))
        assertFalse(standardEnvironment.contains("REASONING_EFFORT="))
        assertFalse(standardEnvironment.contains("ACP_AGENT_SECRET="))

        assertTrue(acp.contains("- acp-host"))
        assertTrue(acp.contains("APP_UID: \${ACP_SERVICE_UID:-1000}"))
        assertTrue(acp.contains("APP_GID: \${ACP_SERVICE_GID:-1000}"))
        assertTrue(acp.contains("user: \"\${ACP_SERVICE_UID:-1000}:\${ACP_SERVICE_GID:-1000}\""))
        assertTrue(acp.contains("ACP_CONFIG_FILE: /run/decomp-engine/acp/config.json"))
        assertTrue(acp.contains("ACP_AGENT_RUNTIME_ROOT"))
        assertTrue(acp.contains("ACP_SYSTEMD_USER_RUNTIME"))
        assertTrue(acp.contains("network_mode: none"))
        assertTrue(acp.contains("pid: host"))
        assertTrue(acp.contains("cgroup: host"))
        assertTrue(acp.contains("userns_mode: host"))
        assertTrue(acp.contains("read_only: true"))
        assertTrue(acp.contains("- ALL"))
        assertTrue(acp.contains("no-new-privileges:true"))
        assertTrue(acp.contains("/sys/fs/cgroup:/sys/fs/cgroup:ro"))
        assertFalse(acp.contains("BASE_URL"))
        assertFalse(acp.contains("API_KEY"))
        assertFalse(acp.contains("MODEL"))
        assertFalse(acp.contains("ACP_HARNESS"))
        assertFalse(acp.contains("ACP_AGENT_SECRET"))
        assertFalse(acp.contains("env_file"))
        assertFalse(acp.contains("privileged:"))
        assertFalse(acp.contains("SYS_ADMIN"))
        assertFalse(acp.contains("seccomp"))
        assertTrue(acp.contains("- binary-runner-acp"))
        assertTrue(acp.contains("- runner-control-acp:/runner"))
        assertTrue(acpRunner.contains("APP_UID: \${ACP_SERVICE_UID:-1000}"))
        assertTrue(acpRunner.contains("APP_GID: \${ACP_SERVICE_GID:-1000}"))
        assertTrue(acpRunner.contains("user: \"\${ACP_SERVICE_UID:-1000}:\${ACP_SERVICE_GID:-1000}\""))
        assertTrue(acpRunner.contains("userns_mode: host"))
        assertTrue(acpRunner.contains("- runner-control-acp:/runner"))
        assertTrue(acpRunner.contains("network_mode: none"))
        assertTrue(acpRunner.contains("read_only: true"))
        assertTrue(acpRunner.contains("- ALL"))
        assertTrue(acpRunner.contains("no-new-privileges:true"))
        assertFalse(acpRunner.contains("ACP_AGENT_SECRET"))
        assertFalse(acpRunner.contains("privileged:"))
        assertFalse(acpRunner.contains("SYS_ADMIN"))
        assertFalse(acpRunner.contains("seccomp"))

        assertTrue(legacy.contains("- legacy-acceptance"))
        assertTrue(legacy.contains("ACP_HARNESS: legacy-openai"))
        assertTrue(legacy.contains("BASE_URL:"))
        assertTrue(legacy.contains("API_KEY:"))
        assertTrue(legacy.contains("MODEL:"))
        assertTrue(legacyEnvironment.contains("DEPRECATED"))
        assertTrue(legacyEnvironment.contains("ACP_HARNESS=legacy-openai"))
        assertTrue(legacyEnvironment.contains("BASE_URL="))
        assertTrue(legacyEnvironment.contains("API_KEY="))
        assertTrue(legacyEnvironment.contains("MODEL="))
    }

    @Test
    fun `operator guidance requires real initialize qualification without claiming remote agent support`() {
        val readme = Path.of("README.md").readText()
        val clientGuide = Path.of("docs/acp-v1-client.md").readText()
        val manifestScript = Path.of("scripts/calculate-acp-runtime-manifest.sh").readText()
        val manifestHelper = Path.of("scripts/support/AcpRuntimeManifest.java").readText()

        assertTrue(readme.contains("doctor --workflow all --output"))
        assertTrue(readme.contains("network-free native executable"))
        assertTrue(readme.contains("Remote or provider-backed agents do not work"))
        assertTrue(readme.contains("host is unqualified"))
        assertTrue(clientGuide.contains("never sends `session/new` or `session/prompt`"))
        assertTrue(clientGuide.contains("dedicated, uncompromised service account"))
        assertTrue(clientGuide.contains("calculate-acp-runtime-manifest.sh"))
        assertTrue(clientGuide.contains("-e ACP_AGENT_SECRET llm-bin-patch doctor"))
        assertTrue(clientGuide.contains("do not bypass the check"))
        assertTrue(manifestHelper.contains("LinuxBubblewrapBoundaryKt.calculateAcpRuntimeManifestSha256"))
        assertFalse(manifestScript.contains("python"))
        assertFalse(manifestHelper.contains("python"))
    }
}

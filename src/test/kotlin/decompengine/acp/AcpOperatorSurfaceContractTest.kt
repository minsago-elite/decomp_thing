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

    @Test
    fun `CI requires pinned credential-free independent ACP initialize and authentication receipts`() {
        val workflow = Path.of(".github/workflows/ci.yml").readText()
        val gooseScript = Path.of("scripts/ci-qualify-goose-acp.sh").readText()
        val codexScript = Path.of("scripts/ci-qualify-codex-acp.sh").readText()
        val provisioner = Path.of("scripts/support/AcpCompatibilityProvisioner.java").readText()
        val preflight = Path.of("scripts/support/AcpCompatibilityPreflight.java").readText()
        val authenticationProbe =
            Path.of("scripts/support/AcpCompatibilityAuthenticationProbe.java").readText()
        val guide = Path.of("docs/acp-v1-client.md").readText()

        assertTrue(workflow.contains("Qualify pinned credential-free third-party ACP initialize"))
        assertTrue(workflow.contains("scripts/ci-qualify-goose-acp.sh"))
        assertTrue(workflow.contains("acp-goose-compatibility-evidence"))
        assertTrue(workflow.contains("path: build/acp-compatibility/results"))
        assertTrue(workflow.contains("Qualify pinned credential-free codex-acp authentication boundary"))
        assertTrue(workflow.contains("scripts/ci-qualify-codex-acp.sh"))
        assertTrue(workflow.contains("acp-codex-authentication-evidence"))
        assertTrue(workflow.contains("path: build/acp-codex-compatibility/results"))

        assertTrue(gooseScript.contains("GOOSE_VERSION=\"1.46.0\""))
        assertTrue(gooseScript.contains("a1cf4856a765d07d6b95689a53c7bca21fcc6e6d65c0dfd064fc704052b85a7b"))
        assertTrue(gooseScript.contains("https://github.com/block/goose/releases/download/"))
        assertTrue(gooseScript.contains("AcpCompatibilityProvisioner"))
        assertTrue(gooseScript.contains("AcpCompatibilityPreflight"))
        assertTrue(gooseScript.contains("argv=goose acp"))
        assertTrue(gooseScript.contains("--proto '=https'"))
        assertFalse(gooseScript.contains("@latest"))
        assertFalse(gooseScript.contains("npx"))
        assertFalse(gooseScript.contains("API_KEY"))
        assertFalse(gooseScript.contains("TOKEN"))
        assertFalse(gooseScript.lowercase().contains("python"))

        assertTrue(codexScript.contains("CODEX_ACP_VERSION=\"0.16.0\""))
        assertTrue(codexScript.contains("0a9ad6c31ec9b2b87dccb7e9da3faf5d387e74470d24dbced75a160ed7b22d06"))
        assertTrue(codexScript.contains("23a9f2af247fc61aa9a895d5ee91a62a35d05a883bddc2c85d1dc6b2be697087"))
        assertTrue(codexScript.contains("5a5104807cfbe9b509d0b9fa1c46054ff48dbed5393f30d261b34263ebf0e3fe"))
        assertTrue(codexScript.contains("https://github.com/zed-industries/codex-acp/releases/download/"))
        assertTrue(codexScript.contains("archive_entries"))
        assertTrue(codexScript.contains("codex-acp\\ncodex-resources/bwrap"))
        assertTrue(codexScript.contains("AcpCompatibilityProvisioner"))
        assertTrue(codexScript.contains("AcpCompatibilityAuthenticationProbe"))
        assertTrue(codexScript.contains("--proto '=https'"))
        assertTrue(codexScript.contains("oracleAccessGranted=false"))
        assertFalse(codexScript.contains("oracle/"))
        assertFalse(codexScript.contains("@latest"))
        assertFalse(codexScript.contains("npx"))
        assertFalse(codexScript.contains("API_KEY"))
        assertFalse(codexScript.contains("TOKEN"))
        assertFalse(codexScript.lowercase().contains("python"))

        assertTrue(provisioner.contains("new ProcessBuilder(\"/usr/bin/ldd\""))
        assertTrue(provisioner.contains("processBuilder.environment().clear()"))
        assertTrue(provisioner.contains("requireBoundedArguments(arguments, 4)"))
        assertTrue(provisioner.contains("\"arguments\", agentArguments"))
        assertTrue(provisioner.contains("\"inheritParentEnvironment\", false"))
        assertTrue(provisioner.contains("\"maximumProcesses\", 32"))
        assertFalse(provisioner.contains("LD_LIBRARY_PATH"))
        assertTrue(preflight.contains("harness.preflight(AcpPreflightWorkflow.ALL)"))
        assertTrue(preflight.contains("\"sessionCreated\", false"))
        assertTrue(preflight.contains("\"modelPromptSent\", false"))
        assertTrue(preflight.contains("\"credentialsForwarded\", false"))
        assertTrue(preflight.contains("\"outerNetworkEnabled\", false"))
        assertTrue(preflight.contains("com.agentclientprotocol:acp:0.30.1"))

        assertTrue(authenticationProbe.contains("harness.executeReceipt"))
        assertTrue(authenticationProbe.contains("AgentFailureKind.AUTHENTICATION"))
        assertTrue(authenticationProbe.contains("AUTH_REQUIRED = -32_000"))
        assertTrue(authenticationProbe.contains("rpcFailure.getData() == null"))
        assertTrue(authenticationProbe.contains("AcpExecutionLifecyclePhase.INITIALIZED"))
        assertTrue(authenticationProbe.contains("getFilesystemAudit().isEmpty()"))
        assertTrue(authenticationProbe.contains("getTerminalAudit().isEmpty()"))
        assertTrue(authenticationProbe.contains("getPermissionAudit().isEmpty()"))
        assertTrue(authenticationProbe.contains("getAllPolicyAuditsComplete()"))
        assertTrue(authenticationProbe.contains("getNetworkIsolated()"))
        assertTrue(authenticationProbe.contains("getSandboxCleanupVerified()"))
        assertTrue(authenticationProbe.contains("initialWorkspace.equals(finalWorkspace)"))
        assertTrue(authenticationProbe.contains("\"oracleAccessGranted\", false"))
        assertFalse(authenticationProbe.contains("session/prompt"))

        assertTrue(guide.contains("| Block Goose | `1.46.0`"))
        assertTrue(guide.contains("| Zed `codex-acp` | `0.16.0`"))
        assertTrue(guide.contains("A skip is not accepted in either lane"))
        assertTrue(guide.contains("not the complete compatibility matrix from issue #67"))
        assertTrue(guide.contains("expose no oracle artifact"))
        assertTrue(guide.contains("authority to generate, validate, score, or certify oracle truth"))
    }
}

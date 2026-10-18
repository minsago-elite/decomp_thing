package decompengine.acp

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.doctor.CommandProbe
import decompengine.doctor.CommandProbeResult
import decompengine.doctor.ConnectivityProbe
import decompengine.doctor.Doctor
import decompengine.doctor.DoctorOptions
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Timeout

@Timeout(value = 90, unit = TimeUnit.SECONDS)
class AcpDoctorPreflightTest {
    @Test
    fun `doctor failure context withholds private text and retains only fixed mount witness fields`() {
        val phase = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val type = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = type.getDeclaredConstructor(phase, outcome, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java).apply { isAccessible = true }
        val witness = constructor.newInstance(phase.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
            outcome.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null) as Throwable
        val cause = java.io.IOException("PRIVATE-message /PRIVATE/path").apply {
            stackTrace = arrayOf(StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "PRIVATE-file", 123))
            addSuppressed(witness)
            addSuppressed(java.io.IOException("PRIVATE-suppressed"))
        }
        val failure = AgentExecutionException(AgentFailure(AgentFailureKind.CONFIGURATION, "PRIVATE-failure",
            details = mapOf("PRIVATE-key" to "PRIVATE-value")), cause)
        val context = doctorFailureContext(failure)
        assertTrue("failureKind=CONFIGURATION phase=missing cleanup=missing" in context, context)
        assertTrue("private-control-checkpoint" in context, context)
        assertTrue("mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA" in context, context)
        assertFalse("PRIVATE" in context || "/" in context, context)
        assertTrue(context.length <= 4096 && context.all { it.code in 32..126 })
    }

    @Test
    fun `doctor failure context bounds cause cycles stack prefixes and foreign witness messages`() {
        val first = java.io.IOException("PRIVATE-first")
        val second = IllegalStateException("PRIVATE-second")
        first.initCause(second); second.initCause(first)
        first.stackTrace = (List(32) { StackTraceElement("PRIVATE-class", "PRIVATE-method", "PRIVATE-file", 1) } +
            StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "PRIVATE-file", 123)).toTypedArray()
        first.addSuppressed(Throwable("mount-event-v1 phase=CHECKPOINT PRIVATE-forged"))
        val context = doctorFailureContext(AgentExecutionException(AgentFailure(AgentFailureKind.CONFIGURATION, "PRIVATE"), first))
        assertFalse("PRIVATE" in context || "mount-event-v1" in context || "private-control-checkpoint" in context, context)
        assertTrue(context.length <= 4096)
        assertTrue(context.split(" -> ").size <= 8)
    }

    @Test
    fun `cancelled preflight retains terminal receipt before launch and during initialize`() {
        requireLiveSandboxHost()
        for (duringInitialize in listOf(false, true)) {
            val temporary = createTempDirectory("doctor-cancel-")
            val harness = factoryHarness(writeProvisioning(temporary.resolve("acp.json"), mode = "no-initialize"))
            val cancellation = decompengine.agent.AgentCancellation {
                !duringInitialize || Thread.currentThread().stackTrace.any {
                    it.className.contains("AcpAgentHarness") && it.methodName.startsWith("awaitPhase")
                }
            }
            val cancelled = assertFailsWith<AcpPreflightCancelledException> {
                harness.preflight(AcpPreflightWorkflow.WEB, cancellation)
            }
            val result = assertIs<AgentExecutionOutcome.Returned>(cancelled.receipt.outcome).result
            assertEquals(decompengine.agent.AgentStopReason.CANCELLED, result.stopReason)
            val evidence = assertIs<AcpInvocationEvidenceSnapshot>(cancelled.receipt.providerEvidence)
            assertEquals(if (duringInitialize) AcpExecutionCleanupDisposition.VERIFIED else AcpExecutionCleanupDisposition.NOT_REQUIRED,
                evidence.cleanupDisposition)
            if (duringInitialize) assertTrue(assertNotNull(evidence.diagnostics).remainingProcessIds.isEmpty())
            assertEquals(null, evidence.completeExecutionEvidence)
        }
    }

    @Test
    fun `contained preflight inspects environment terminal and unknown methods without executing them`() {
        requireLiveSandboxHost()
        val temporary = createTempDirectory("doctor-auth-variants-")
        val harness = factoryHarness(writeProvisioning(temporary.resolve("acp.json"), mode = "doctor-auth-variants"))
        val result = harness.preflight()
        assertEquals(listOf("environment-login", "terminal-login", "future-login"), result.authentication.methods.map { it.id })
        assertEquals(listOf("environment", "terminal", "unknown"), result.authentication.methods.map { it.variant })
        assertTrue(result.authentication.methods.none { it.loginSupported })
        assertFalse(result.authentication.logoutAdvertised)
        assertFalse(result.authentication.logoutSupported)
        assertTrue(result.diagnostics.sandboxCleanupVerified)
        assertTrue(result.diagnostics.remainingProcessIds.isEmpty())
        assertFalse(result.stableDescriptor.contains("fixture-login"))
        assertFalse(result.stableDescriptor.contains("opaque-fixture-value"))
    }

    @Test
    fun `invalid authentication inventories fail preflight as protocol errors with cleanup`() {
        requireLiveSandboxHost()
        for (mode in listOf("doctor-auth-duplicate", "doctor-auth-count", "doctor-auth-blank", "doctor-auth-text", "doctor-auth-unicode", "doctor-auth-payload")) {
            val temporary = createTempDirectory("doctor-auth-invalid-")
            val harness = factoryHarness(writeProvisioning(temporary.resolve("acp.json"), mode = mode))
            val error = assertFailsWith<AgentExecutionException> { harness.preflight() }
            assertEquals(AgentFailureKind.PROTOCOL, error.failure.kind,
                if (error.failure.kind == AgentFailureKind.PROTOCOL) mode else
                    "$mode: " + runCatching { doctorFailureContext(error) }.getOrDefault("Doctor failure context unavailable"))
            assertEquals("invalidAuthenticationInventory", error.failure.details["reason"], mode)
            assertEquals("ACP agent advertised an invalid authentication inventory", error.failure.message)
            val receipt = assertNotNull(error.receipt)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, mode)
            assertTrue(assertNotNull(invocation.diagnostics).remainingProcessIds.isEmpty(), mode)
            assertEquals(null, invocation.completeExecutionEvidence)
        }
    }

    @Test
    fun `doctor reports the bounded invalid authentication inventory reason`() {
        requireLiveSandboxHost()
        val temporary = createTempDirectory("doctor-auth-reason-")
        val config = writeProvisioning(temporary.resolve("acp.json"), mode = "doctor-auth-duplicate")
        val doctor = Doctor(environment = mapOf("ACP_CONFIG_FILE" to config.toString()),
            commandProbe = CommandProbe { _, _ -> CommandProbeResult(0, "available") },
            connectivityProbe = ConnectivityProbe { _, _ -> error("inspection must not use direct HTTP") })
        val report = doctor.inspect(DoctorOptions(temporary.resolve("output"), showAuthMethods = true))
        val preflight = report.checks.single { it.name == "ACP preflight" }
        assertFalse(preflight.passed)
        assertTrue(preflight.detail.contains("kind=protocol"), preflight.detail)
        assertTrue(preflight.detail.contains("reason=invalidAuthenticationInventory"), preflight.detail)
    }

    @Test
    fun `doctor exposes authentication previews only through explicit prompt-free inspection`() {
        requireLiveSandboxHost()
        val temporary = createTempDirectory("doctor-acp-live-")
        val ghidra = temporary.resolve("ghidra/support").createDirectories().resolve("analyzeHeadless")
        ghidra.writeText("fixture")
        ghidra.toFile().setExecutable(true)
        val configuration = writeProvisioning(
            temporary.resolve("acp.json"),
            mode = "doctor-preflight",
            includeSecret = true,
        )
        val values = mapOf(
            "ACP_CONFIG_FILE" to configuration.toString(),
            "DOCTOR_TEST_TOKEN" to SECRET_CANARY,
            "GHIDRA_HOME" to ghidra.parent.parent.toString(),
            "BASE_URL" to "http://127.0.0.1:1/v1",
            "API_KEY" to "legacy-transport-must-not-run",
            "MODEL" to "legacy-model-must-not-run",
        )
        val environment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("doctor must not enumerate the ambient environment")

            override fun containsKey(key: String): Boolean = values.containsKey(key)
            override fun get(key: String): String? = values[key]
        }
        val doctor = Doctor(
            environment = environment,
            commandProbe = CommandProbe { _, _ -> CommandProbeResult(0, "available") },
            connectivityProbe = ConnectivityProbe { _, _ -> error("ACP doctor must not use direct HTTP") },
        )

        val defaults = doctor.inspect(DoctorOptions(temporary.resolve("default-output")))
        assertTrue(defaults.passed)
        assertFalse(defaults.checks.any { it.name.startsWith("ACP authentication method") })
        val report = doctor.inspect(DoctorOptions(temporary.resolve("output"), showAuthMethods = true))

        assertTrue(report.passed, report.checks.toString())
        val harness = report.checks.single { it.name == "ACP harness" }
        val preflight = report.checks.single { it.name == "ACP preflight" }
        assertTrue(harness.detail.startsWith("Selected agent-harness-v1:acp:"), harness.detail)
        assertTrue(preflight.passed)
        assertTrue(preflight.detail.startsWith("acp-preflight-v1:workflow-all:protocol-1:"), preflight.detail)
        assertTrue(preflight.detail.contains("client-fs-read-true:client-fs-write-true"))
        assertTrue(preflight.detail.contains("client-terminal-false"))
        assertTrue(preflight.detail.contains("auth-methods-1:auth-inventory-commitment-"))
        assertTrue(preflight.detail.contains("auth-inventory-format-sdk-auth-methods-hmac-sha256-v2"))
        assertTrue(preflight.detail.contains("auth-inventory-scope-"))
        assertFalse(preflight.detail.contains("auth-inventory-sha256-"))
        assertTrue(preflight.detail.contains("auth-logout-advertised-true:auth-logout-supported-false"))
        assertFalse(preflight.detail.contains("operator-login"))
        assertFalse(preflight.detail.contains("fixture-credential"))
        assertTrue(preflight.detail.contains("network-isolated-true:cleanup-verified-true"))
        val auth = report.checks.single { it.name == "ACP authentication method 1" }
        assertTrue(auth.detail.contains("operator-login"))
        assertTrue(auth.detail.contains("login unsupported; no login attempted"))
        assertFalse(auth.detail.contains("fixture-credential"))
        val rendered = report.checks.joinToString("\n") { "${it.name}: ${it.detail}" }
        assertFalse(rendered.contains(SECRET_CANARY))
        assertFalse(rendered.contains("legacy-transport-must-not-run"))
        assertFalse(rendered.contains("scripted-fixture"), "peer-controlled identity must be hashed")
        assertFalse(report.checks.any { it.name.startsWith("LLM") })
    }

    @Test
    fun `preflight rejects version capability and process failures after verified cleanup`() {
        requireLiveSandboxHost()
        val cases = listOf(
            FailureCase("unsupported-version", emptySet(), AgentFailureKind.PROTOCOL, "offeredVersion"),
            FailureCase(
                "doctor-preflight",
                setOf(AcpRequiredAgentCapability.LOAD_SESSION),
                AgentFailureKind.CONFIGURATION,
                "missingCapabilities",
            ),
            FailureCase("crash-after-initialize", emptySet(), AgentFailureKind.PROCESS_CRASH, "exitCode"),
        )
        cases.forEach { case ->
            val temporary = createTempDirectory("doctor-acp-${case.mode}-")
            val harness = factoryHarness(writeProvisioning(
                temporary.resolve("acp.json"),
                mode = case.mode,
                requiredCapabilities = case.requiredCapabilities,
            ))

            val failure = assertFailsWith<AgentExecutionException>(case.mode) {
                harness.preflight(AcpPreflightWorkflow.PATCH)
            }

            assertEquals(case.failureKind, failure.failure.kind, case.mode)
            assertTrue(case.expectedDetail in failure.failure.details, case.mode)
            val receipt = assertNotNull(failure.receipt, case.mode)
            assertIs<AgentExecutionOutcome.Failed>(receipt.outcome, case.mode)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence, case.mode)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, case.mode)
            assertEquals(null, invocation.completeExecutionEvidence, case.mode)
            val diagnostics = assertNotNull(invocation.diagnostics, case.mode)
            assertTrue(diagnostics.remainingProcessIds.isEmpty(), case.mode)
            assertTrue(diagnostics.sandboxCleanupVerified, case.mode)
        }
    }

    @Test
    fun `preflight proves descendant cleanup and fails closed on shutdown output overflow`() {
        requireLiveSandboxHost()
        val parent = Path.of("build/test-tmp/acp-doctor-preflight").toAbsolutePath().createDirectories()
        val temporary = Files.createTempDirectory(parent, "cleanup-")
        val childHarness = factoryHarness(writeProvisioning(
            temporary.resolve("child.json"),
            mode = "doctor-preflight-child-hang",
        ))

        val childResult = childHarness.preflight(AcpPreflightWorkflow.REPAIR)

        assertTrue(childResult.diagnostics.forcedTermination)
        assertTrue(childResult.diagnostics.remainingProcessIds.isEmpty())
        assertTrue(childResult.diagnostics.sandboxCleanupVerified)
        assertTrue(childResult.stableDescriptor.startsWith("acp-preflight-v1:workflow-repair:"))
        val burstHarness = factoryHarness(writeProvisioning(
            temporary.resolve("burst.json"),
            mode = "doctor-preflight-shutdown-burst",
        ))

        val overflow = assertFailsWith<AgentExecutionException> {
            burstHarness.preflight(AcpPreflightWorkflow.RECONSTRUCT)
        }

        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, overflow.failure.kind,
            if (overflow.failure.kind == AgentFailureKind.RESOURCE_EXHAUSTED) null else
                runCatching { doctorFailureContext(overflow) }.getOrDefault("Doctor failure context unavailable"))
        val receipt = assertNotNull(overflow.receipt)
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition)
        assertEquals(null, invocation.completeExecutionEvidence)
        val diagnostics = assertNotNull(invocation.diagnostics)
        assertTrue(diagnostics.outputLimitExceeded)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
    }

    /** Test diagnostics: typed facts and checked witness text; private messages and paths withheld. */
    private fun doctorFailureContext(failure: AgentExecutionException): String {
        val evidence = failure.receipt?.providerEvidence as? AcpInvocationEvidenceSnapshot
        val diagnostics = evidence?.diagnostics
        val types = mapOf("decompengine.agent.AgentExecutionException" to "agent-execution",
            "java.io.IOException" to "io", "java.lang.IllegalStateException" to "illegal-state",
            "decompengine.acp.LinuxSyscallException" to "syscall",
            "decompengine.acp.AcpCleanupProofFailure" to "cleanup-proof",
            "decompengine.acp.AcpPhaseTimeout" to "phase-timeout")
        val frames = mapOf(
            ("decompengine.acp.RuntimePrivateControlScope" to "checkpoint") to "private-control-checkpoint",
            ("decompengine.acp.RuntimePrivateControlScope" to "requireMountsUnchanged") to "mount-check",
            ("decompengine.acp.RuntimePrivateControlScope" to "requireDescriptor") to "descriptor-revalidation",
            ("decompengine.acp.RuntimePrivateControlScope" to "currentRoot") to "root-identity",
            ("decompengine.acp.RuntimePrivateControlScope" to "requireRootUnexposed") to "private-control-coverage",
            ("decompengine.acp.LinuxBubblewrapBoundaryKt" to "requirePrivateControlRegistryHealthy") to "registry-health",
            ("decompengine.acp.RuntimePrivateControlScope\$MountEventCheck" to "requireUnchanged") to "mount-check",
            ("decompengine.acp.RuntimePrivateControlScope\$MountEventCheck" to "eventFailure") to "mount-event",
            ("decompengine.acp.LinuxFilesystemSyscalls\$MountMetadataPollScratch" to "pollDescriptor") to "mount-poll",
            ("decompengine.acp.ProductionAcpSandboxExecution" to "<init>") to "sandbox-construction",
            ("decompengine.acp.AcpAgentHarness" to "executeInternalReceipt") to "harness-receipt")
        val witness = Regex("mount-event-v1 phase=(CHECKPOINT|CONTROL_ADMISSION|REFRESH) " +
            "generation=(NOT_EVALUATED|MISMATCH_ALREADY_OBSERVED) outcome=(EVENT|INVALID_DESCRIPTOR|SYSCALL_ERROR) " +
            "rc=(NA|-?[0-9]{1,10}) revents=(NA|[0-9]{1,5}) errno=(NA|-?[0-9]{1,10})")
        val pending = java.util.ArrayDeque<Throwable>()
        val seen = ArrayList<Throwable>(8)
        val causes = ArrayList<String>(8)
        pending.add(failure)
        failure.receipt?.failureCause?.let { pending.add(it) }
        while (pending.isNotEmpty() && seen.size < 8) {
            val current = pending.removeFirst()
            if (seen.any { it === current }) continue
            seen.add(current)
            val name = current.javaClass.name
            val record = if (name == "decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
                current.message?.takeIf { it.length <= 512 && witness.matches(it) } else null
            val sites = current.stackTrace.asSequence().take(32).mapNotNull { frames[it.className to it.methodName] }.take(2).joinToString(",")
            causes.add(record ?: "${types[name] ?: "other"}[$sites]")
            current.cause?.let { if (pending.size < 16) pending.add(it) }
            current.suppressed.take(2).forEach { if (pending.size < 16) pending.add(it) }
        }
        return ("failureKind=${failure.failure.kind.name} phase=${evidence?.phaseReached?.name ?: "missing"} " +
            "cleanup=${evidence?.cleanupDisposition?.name ?: "missing"} negotiated=${evidence?.negotiatedAgent != null} " +
            "diagnostics=${diagnostics != null} remainingProcesses=${diagnostics?.remainingProcessIds?.size ?: "missing"} " +
            "outputOverflow=${diagnostics?.outputLimitExceeded ?: "missing"} causes=" + causes.joinToString(" -> ")).take(4096)
    }

    private fun factoryHarness(configuration: Path): AcpAgentHarness {
        val selection = AcpHarnessFactory.fromEnvironment(mapOf("ACP_CONFIG_FILE" to configuration.toString()))
        return selection.createHarness() as AcpAgentHarness
    }

    private fun writeProvisioning(
        path: Path,
        mode: String,
        requiredCapabilities: Set<AcpRequiredAgentCapability> = emptySet(),
        includeSecret: Boolean = false,
    ): Path {
        val runtime = PYTHON_RUNTIME.getOrThrow()
        val script = Path.of(requireNotNull(javaClass.getResource("/acp/fake_acp_v1_agent.py")).toURI())
        val launcherMounts = runtime.nativeRuntimeMounts + runtime.stdlibMounts(
            listOf(
                "encodings", "json", "re", "collections",
                "_collections_abc.py", "abc.py", "codecs.py", "copyreg.py", "enum.py",
                "functools.py", "keyword.py", "operator.py", "reprlib.py", "types.py", "zipimport.py",
            ),
        )
        val document = buildJsonObject {
            put("schemaVersion", 2)
            put("implementationId", "doctor-scripted-acp-v1")
            putJsonObject("agent") {
                put("executable", runtime.executable.toString())
                putJsonArray("arguments") {
                    add("-S")
                    add(AGENT_SCRIPT_DESTINATION.toString())
                    add(mode)
                    add("doctor-preflight")
                }
                putJsonArray("environment") {
                    if (includeSecret) {
                        add(buildJsonObject {
                            put("name", "PROVIDER_TOKEN")
                            put("provenance", "secret")
                            put("valueFromEnvironment", "DOCTOR_TEST_TOKEN")
                        })
                    }
                }
                put("inheritParentEnvironment", false)
                putJsonArray("requiredCapabilities") {
                    requiredCapabilities.sortedBy(AcpRequiredAgentCapability::diagnosticName).forEach {
                        add(it.diagnosticName)
                    }
                }
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
            putJsonObject("session") {
                putJsonArray("configOptions") { }
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
                put("agentRuntimeMounts", mountsJson(listOf(
                    AcpSandboxReadOnlyMount(script, AGENT_SCRIPT_DESTINATION),
                )))
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
        val missing = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH)
            .filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(
            missing.isEmpty(),
            message = { "live ACP doctor sandbox tools are unavailable: $missing" },
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
            message = { "static ACP gate helper is unavailable" },
        )
    }

    private fun fileSha256(path: Path): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { byte -> "%02x".format(byte) }

    private data class FailureCase(
        val mode: String,
        val requiredCapabilities: Set<AcpRequiredAgentCapability>,
        val failureKind: AgentFailureKind,
        val expectedDetail: String,
    )

    private companion object {
        const val SECRET_CANARY = "doctor-secret-must-never-be-rendered"
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
        val AGENT_SCRIPT_DESTINATION: Path = Path.of("/decomp-acp-test/fake_acp_v1_agent.py")
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
    }
}

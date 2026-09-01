package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AcpSandboxPolicyTest {
    @Test
    fun `ordinary writable staging fails closed and invalid ids create no directory`() {
        val parent = createTempDirectory("acp-stage-policy-").toAbsolutePath().normalize()
        val before = Files.list(parent).use { it.count() }
        assertFailsWith<IllegalArgumentException> {
            AcpWorkflowStagingRoot.createReadOnly("bad/id", parent)
        }
        assertEquals(before, Files.list(parent).use { it.count() })

        val staging = AcpWorkflowStagingRoot.createReadOnly("stage", parent)
        val rule = rule(staging, Path.of("/usr/bin/true"), emptyList())
        assertFailsWith<IllegalArgumentException> {
            AcpTerminalExecutionPolicy(
                listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_WRITE)),
                listOf(rule),
            )
        }
        AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(rule),
        )
        assertFailsWith<IllegalArgumentException> {
            AcpTerminalExecutionPolicy(
                listOf(
                    AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY),
                    AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY),
                ),
                listOf(rule),
            )
        }
    }

    @Test
    fun `mount and environment authority rejects broad secret and nonportable inputs`() {
        assertFailsWith<IllegalArgumentException> { AcpSandboxReadOnlyMount(Path.of("/")) }
        assertFailsWith<IllegalArgumentException> { AcpSandboxReadOnlyMount(Path.of("/home/user/.ssh/tool")) }
        assertFailsWith<IllegalArgumentException> {
            AcpSandboxReadOnlyMount(Path.of("/usr/bin/true"), Path.of("/proc/tool"))
        }
        assertFailsWith<IllegalArgumentException> {
            AcpSandboxReadOnlyMount(Path.of("/usr/bin/true"), ACP_INTERNAL_SANDBOX_ROOT.resolve("gate-helper"))
        }
        assertFailsWith<IllegalArgumentException> {
            AcpSandboxReadOnlyMount(Path.of("/usr/bin/true"), ACP_INTERNAL_SANDBOX_ROOT)
        }

        val parent = createTempDirectory("acp-env-policy-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("stage", parent)
        assertFailsWith<IllegalArgumentException> {
            AcpTerminalCommandRule(
                AcpSandboxReadOnlyMount(Path.of("/usr/bin/true")),
                emptyList(),
                staging.path,
                mapOf("BAD-NAME" to "value"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpTerminalCommandRule(
                AcpSandboxReadOnlyMount(Path.of("/usr/bin/true")),
                emptyList(),
                staging.path,
                mapOf("API_TOKEN" to "value"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                environment = mapOf(
                    "BAD-NAME" to AcpEnvironmentValue("value", AcpEnvironmentProvenance.PUBLIC),
                ),
            )
        }
        val typed = AcpProcessConfiguration(
            Path.of("/usr/bin/true"),
            environment = mapOf(
                "PUBLIC_VALUE" to AcpEnvironmentValue("visible", AcpEnvironmentProvenance.PUBLIC),
                "SECRET_VALUE" to AcpEnvironmentValue("opaque", AcpEnvironmentProvenance.SECRET),
            ),
        )
        assertEquals(AcpEnvironmentProvenance.SECRET, typed.environment.getValue("SECRET_VALUE").provenance)
    }

    @Test
    fun `policy evidence digest binds all authority and canonicalizes unordered collections`() {
        val parent = createTempDirectory("acp-digest-policy-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("stage", parent)
        val sourceA = parent.resolve("tool-a").also { it.writeText("a") }
        val sourceB = parent.resolve("tool-b").also { it.writeText("b") }
        val runtimeA = parent.resolve("runtime-a").also { it.writeText("ra") }
        val runtimeB = parent.resolve("runtime-b").also { it.writeText("rb") }
        val digestA = "a".repeat(64)
        val digestB = "b".repeat(64)

        fun mount(source: Path, destination: String, digest: String = digestA) =
            AcpSandboxReadOnlyMount(source, Path.of(destination), digest)

        fun limits(
            concurrent: Int = 2,
            creates: Int = 4,
            retained: Int = 1024,
            produced: Long = 4096,
            duration: Duration = Duration.ofSeconds(10),
            grace: Duration = Duration.ofMillis(100),
            resources: AcpSandboxResourceLimits = AcpSandboxResourceLimits(
                maximumProcesses = 8,
                maximumOpenFiles = 64,
                maximumFileBytes = 1024 * 1024,
                maximumAddressSpaceBytes = 128L * 1024 * 1024,
                maximumCpuSeconds = 5,
            ),
        ) = AcpTerminalLimits(concurrent, creates, retained, produced, duration, grace, resources)

        fun policy(
            executable: AcpSandboxReadOnlyMount = mount(sourceA, "/tool", digestA),
            args: List<String> = listOf("one", "two"),
            environment: Map<String, String> = mapOf("MODE" to "safe"),
            runtime: List<AcpSandboxReadOnlyMount> = listOf(
                mount(runtimeA, "/runtime/a", digestA),
                mount(runtimeB, "/runtime/b", digestB),
            ),
            terminalLimits: AcpTerminalLimits = limits(),
            reverseRules: Boolean = false,
        ): AcpTerminalExecutionPolicy {
            val first = AcpTerminalCommandRule(executable, args, staging.path, environment, runtime)
            val second = AcpTerminalCommandRule(executable, listOf("other"), staging.path, environment, runtime)
            val rules = if (reverseRules) listOf(second, first) else listOf(first, second)
            return AcpTerminalExecutionPolicy(
                listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
                rules,
                terminalLimits,
            )
        }

        val baseline = policy()
        val baselineDigest = baseline.policyDigest()
        assertEquals(
            baselineDigest,
            policy(
                runtime = baseline.commandRules.first().runtimeMounts.reversed(),
                reverseRules = true,
            ).policyDigest(),
            "command-rule and runtime-mount order do not change authority",
        )
        val ambiguousArguments = AcpTerminalCommandRule(
            mount(sourceA, "/tool", digestA),
            listOf("X", "Y"),
            staging.path,
            emptyMap(),
            emptyList(),
        )
        val ambiguousEnvironment = AcpTerminalCommandRule(
            mount(sourceA, "/tool", digestA),
            emptyList(),
            staging.path,
            mapOf("X" to "Y"),
            emptyList(),
        )
        fun ambiguousPolicy(rules: List<AcpTerminalCommandRule>) = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            rules,
            limits(),
        )
        assertEquals(
            ambiguousPolicy(listOf(ambiguousArguments, ambiguousEnvironment)).policyDigest(),
            ambiguousPolicy(listOf(ambiguousEnvironment, ambiguousArguments)).policyDigest(),
            "tagged rule sorting must not depend on stable input order when untagged fields collide",
        )

        val variants = listOf(
            policy(executable = mount(sourceB, "/tool", digestA)),
            policy(executable = mount(sourceA, "/tool", digestB)),
            policy(args = listOf("one", "changed")),
            policy(environment = mapOf("MODE" to "changed")),
            policy(runtime = listOf(mount(runtimeA, "/runtime/changed", digestA))),
            policy(runtime = listOf(mount(runtimeA, "/runtime/a", digestB))),
            policy(terminalLimits = limits(concurrent = 3, creates = 4)),
            policy(terminalLimits = limits(creates = 5)),
            policy(terminalLimits = limits(retained = 2048)),
            policy(terminalLimits = limits(produced = 8192)),
            policy(terminalLimits = limits(duration = Duration.ofSeconds(11))),
            policy(terminalLimits = limits(grace = Duration.ofMillis(101))),
            policy(terminalLimits = limits(resources = limits().resourceLimits.copy(maximumProcesses = 9))),
            policy(terminalLimits = limits(resources = limits().resourceLimits.copy(maximumOpenFiles = 65))),
            policy(terminalLimits = limits(resources = limits().resourceLimits.copy(maximumFileBytes = 2L * 1024 * 1024))),
            policy(terminalLimits = limits(resources = limits().resourceLimits.copy(maximumAddressSpaceBytes = 192L * 1024 * 1024))),
            policy(terminalLimits = limits(resources = limits().resourceLimits.copy(maximumCpuSeconds = 6))),
        )
        variants.forEachIndexed { index, variant ->
            assertNotEquals(baselineDigest, variant.policyDigest(), "authority variant $index collided")
        }
        assertTrue(baselineDigest.matches(Regex("[0-9a-f]{64}")))

        val baseTool = AcpSecurityExecutableEvidence(
            "bubblewrap", "1".repeat(64), "2".repeat(64), 0x1ed, "4".repeat(64),
        )
        val secondTool = AcpSecurityExecutableEvidence(
            "gate-helper", "2".repeat(64), "3".repeat(64), 0x1ed, "5".repeat(64),
        )
        val baseMount = AcpSandboxMountEvidence(
            "3".repeat(64), "4".repeat(64), "5".repeat(64), 11L, 12L, 0x1ed, false,
        )
        val baseControllers = AcpCgroupControllerEvidence(
            8, 128L * 1024 * 1024, 0, 100_000, 100_000, true, 12_000_000, 3_000_000,
        )
        val baseResources = limits().resourceLimits
        val baseGate = AcpSandboxStartGateEvidence(
            descriptor = 0,
            waiterExecutableSha256 = "b".repeat(64),
            helperProtocolSha256 = "c".repeat(64),
            positiveByteRequired = true,
        )
        val baseEnvironment = AcpSandboxEnvironmentEvidence(
            sandboxPathSha256 = "d".repeat(64),
            bindingNamesSha256 = "e".repeat(64),
            contentSha256 = "f".repeat(64),
            bindingCount = 2,
            encodedBytes = 32,
            device = 31,
            inode = 32,
            mountId = 33,
            mode = 0x8180,
            linkCount = 0,
        )
        val baseRlimits = AcpSandboxRlimitEvidence(
            processesSoft = 1024,
            processesHard = 1024,
            openFilesSoft = baseResources.maximumOpenFiles.toLong(),
            openFilesHard = baseResources.maximumOpenFiles.toLong(),
            fileBytesSoft = baseResources.maximumFileBytes,
            fileBytesHard = baseResources.maximumFileBytes,
            coreBytesSoft = 0,
            coreBytesHard = 0,
            addressSpaceSoft = baseResources.maximumAddressSpaceBytes,
            addressSpaceHard = baseResources.maximumAddressSpaceBytes,
            cpuSecondsSoft = baseResources.maximumCpuSeconds.toLong(),
            cpuSecondsHard = baseResources.maximumCpuSeconds.toLong(),
        )
        val baseLaunch = AcpSandboxLaunchEvidence(
            AcpSandboxLaunchPurpose.OUTER_AGENT,
            baseResources,
            baseControllers,
            "6".repeat(64),
            baseGate,
            baseEnvironment,
            baseRlimits,
            baseMount,
            listOf(baseMount),
            "7".repeat(64),
            false,
            "8".repeat(64),
            0,
            "9".repeat(64),
            1,
        )
        val baseAudit = AcpTerminalAuditRecord(
            sequence = 0,
            sessionId = "session",
            method = "terminal/output",
            requestSha256 = "f".repeat(64),
            terminalIdSha256 = "0".repeat(64),
            toolCallIdSha256 = "1".repeat(64),
            outcome = AcpTerminalAuditOutcome.ALLOWED,
            reason = AcpTerminalAuditReason.OUTPUT_OBSERVED,
            networkIsolated = true,
            retainedOutputBytes = 8,
            producedOutputBytes = Long.MAX_VALUE,
            outputTruncated = true,
        )
        val baseAuthority = AcpSandboxAuthorityEvidence(
            rootId = "stage",
            rootPathSha256 = "2".repeat(64),
            mode = AcpSandboxRootMode.READ_WRITE,
            quota = AcpStagingQuotaEvidence(
                provider = "quota-provider",
                mountId = 21,
                maximumBytes = 4096,
                maximumEntries = 128,
                mountPathSha256 = "3".repeat(64),
            ),
        )
        val baseOuterOutput = AcpProducedOutputEvidence(8192, 4096, false)
        fun evidence(
            tools: List<AcpSecurityExecutableEvidence> = listOf(baseTool, secondTool),
            outer: AcpSandboxResourceLimits = baseResources,
            closure: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(10, 1024, 4),
            terminal: AcpTerminalLimits = limits(),
            openerDigest: String = "6".repeat(64),
            launches: List<AcpSandboxLaunchEvidence> = listOf(baseLaunch),
            authorities: List<AcpSandboxAuthorityEvidence> = listOf(baseAuthority),
            terminalAudit: List<AcpTerminalAuditRecord> = listOf(baseAudit),
            outerOutput: AcpProducedOutputEvidence? = baseOuterOutput,
            cancellationCheck: () -> Unit = {},
        ) = AcpSandboxEvidence(
            provider = "provider",
            providerVersion = "1",
            providerExecutableSha256 = baseTool.contentSha256,
            providerExecutableMode = baseTool.mode,
            resourceLimiterSha256 = "7".repeat(64),
            scopeSupervisorSha256 = "8".repeat(64),
            scopeInspectorSha256 = "9".repeat(64),
            environmentFdOpenerSha256 = openerDigest,
            securityExecutables = tools,
            outerAgentLimits = outer,
            runtimeClosureLimits = closure,
            cgroupV2PidsLimited = true,
            cgroupV2MemoryLimited = true,
            cgroupV2CpuLimited = true,
            networkIsolated = true,
            outerAgentContained = true,
            nestedUserNamespacesDisabled = true,
            newSession = true,
            dieWithParent = true,
            policySha256 = baselineDigest,
            terminalLimits = terminal,
            launches = launches,
            authorities = authorities,
            terminalAudit = terminalAudit,
            outerProcessOutput = outerOutput,
            cancellationCheck = cancellationCheck,
        )
        val baseEvidenceDigest = evidence().evidenceSha256
        assertEquals(
            baseEvidenceDigest,
            evidence(tools = listOf(secondTool, baseTool)).evidenceSha256,
            "security-tool collection order is not authority",
        )
        val evidenceVariants = listOf(
            evidence(tools = listOf(baseTool.copy(contentSha256 = "b".repeat(64)), secondTool)),
            evidence(tools = listOf(baseTool.copy(mode = 0x16d), secondTool)),
            evidence(tools = listOf(baseTool.copy(metadataSha256 = "d".repeat(64)), secondTool)),
            evidence(tools = listOf(baseTool.copy(canonicalPathSha256 = "c".repeat(64)), secondTool)),
            evidence(outer = baseResources.copy(maximumProcesses = baseResources.maximumProcesses + 1)),
            evidence(outer = baseResources.copy(maximumOpenFiles = baseResources.maximumOpenFiles + 1)),
            evidence(outer = baseResources.copy(maximumFileBytes = baseResources.maximumFileBytes + 1)),
            evidence(outer = baseResources.copy(maximumAddressSpaceBytes = baseResources.maximumAddressSpaceBytes + 1)),
            evidence(outer = baseResources.copy(maximumCpuSeconds = baseResources.maximumCpuSeconds + 1)),
            evidence(closure = AcpRuntimeClosureLimits(11, 1024, 4)),
            evidence(closure = AcpRuntimeClosureLimits(10, 2048, 4)),
            evidence(closure = AcpRuntimeClosureLimits(10, 1024, 5)),
            evidence(terminal = limits(produced = 8192)),
            evidence(outerOutput = baseOuterOutput.copy(maximumBytes = 8193)),
            evidence(outerOutput = baseOuterOutput.copy(observedBytes = 4097)),
            evidence(outerOutput = baseOuterOutput.copy(limitExceeded = true)),
            evidence(openerDigest = "b".repeat(64)),
            evidence(launches = listOf(baseLaunch.copy(purpose = AcpSandboxLaunchPurpose.TERMINAL))),
            evidence(launches = listOf(baseLaunch.copy(commandSha256 = "d".repeat(64)))),
            evidence(launches = listOf(baseLaunch.copy(workingDirectorySha256 = "d".repeat(64)))),
            evidence(launches = listOf(baseLaunch.copy(mergeError = true))),
            evidence(launches = listOf(baseLaunch.copy(stagingRootsSha256 = "d".repeat(64)))),
            evidence(launches = listOf(baseLaunch.copy(stagingRootCount = 1))),
            evidence(launches = listOf(baseLaunch.copy(emptyDirectoriesSha256 = "d".repeat(64)))),
            evidence(launches = listOf(baseLaunch.copy(emptyDirectoryCount = 2))),
            evidence(launches = listOf(baseLaunch.copy(startGate = baseGate.copy(descriptor = 1)))),
            evidence(launches = listOf(baseLaunch.copy(startGate = baseGate.copy(
                waiterExecutableSha256 = "d".repeat(64),
            )))),
            evidence(launches = listOf(baseLaunch.copy(startGate = baseGate.copy(
                helperProtocolSha256 = "d".repeat(64),
            )))),
            evidence(launches = listOf(baseLaunch.copy(startGate = baseGate.copy(positiveByteRequired = false)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(
                sandboxPathSha256 = "f".repeat(64),
            )))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(
                bindingNamesSha256 = "f".repeat(64),
            )))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(
                contentSha256 = "0".repeat(64),
            )))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(bindingCount = 3)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(encodedBytes = 33)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(device = 34)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(inode = 35)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(mountId = 36)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(mode = 0x8100)))),
            evidence(launches = listOf(baseLaunch.copy(environment = baseEnvironment.copy(linkCount = 1)))),
            evidence(launches = listOf(baseLaunch.copy(resourceLimits = baseResources.copy(maximumOpenFiles = 65)))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(sourcePathSha256 = "d".repeat(64))))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(destinationPathSha256 = "d".repeat(64))))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(manifestSha256 = "d".repeat(64))))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(device = 14)))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(inode = 14)))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(mode = 0x16d)))),
            evidence(launches = listOf(baseLaunch.copy(executableMount = baseMount.copy(directory = true)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(pidsMax = 9)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(memoryMaxBytes = 129L * 1024 * 1024)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(memorySwapMaxBytes = 1)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(cpuQuotaMicros = 90_000)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(cpuPeriodMicros = 90_000)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(memoryOomGroup = false)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(runtimeMaxMicros = 13_000_000)))),
            evidence(launches = listOf(baseLaunch.copy(controllers = baseControllers.copy(timeoutStopMicros = 4_000_000)))),
            evidence(launches = listOf(baseLaunch.copy(effectiveRlimits = baseRlimits.copy(openFilesSoft = 63)))),
            evidence(launches = listOf(baseLaunch.copy(effectiveRlimits = baseRlimits.copy(fileBytesHard = 2_000_000)))),
            evidence(launches = listOf(baseLaunch.copy(effectiveRlimits = baseRlimits.copy(coreBytesSoft = 1)))),
            evidence(launches = listOf(baseLaunch.copy(effectiveRlimits = baseRlimits.copy(addressSpaceHard = 1)))),
            evidence(launches = listOf(baseLaunch.copy(effectiveRlimits = baseRlimits.copy(cpuSecondsSoft = 1)))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(sourcePathSha256 = "e".repeat(64)))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(destinationPathSha256 = "e".repeat(64)))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(device = 13))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(inode = 13))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(mode = 0x16d))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(baseMount.copy(directory = true))))),
            evidence(launches = listOf(baseLaunch.copy(runtimeMounts = listOf(
                baseMount.copy(manifestSha256 = "e".repeat(64)),
            )))),
            evidence(authorities = listOf(baseAuthority.copy(rootId = "other"))),
            evidence(authorities = listOf(baseAuthority.copy(rootPathSha256 = "4".repeat(64)))),
            evidence(authorities = listOf(baseAuthority.copy(mode = AcpSandboxRootMode.READ_ONLY))),
            evidence(authorities = listOf(baseAuthority.copy(quota = baseAuthority.quota?.copy(provider = "other")))),
            evidence(authorities = listOf(baseAuthority.copy(quota = baseAuthority.quota?.copy(mountId = 22)))),
            evidence(authorities = listOf(baseAuthority.copy(quota = baseAuthority.quota?.copy(maximumBytes = 4097)))),
            evidence(authorities = listOf(baseAuthority.copy(quota = baseAuthority.quota?.copy(maximumEntries = 129)))),
            evidence(authorities = listOf(baseAuthority.copy(
                quota = baseAuthority.quota?.copy(mountPathSha256 = "5".repeat(64)),
            ))),
            evidence(terminalAudit = listOf(baseAudit.copy(producedOutputBytes = Long.MAX_VALUE - 1))),
        )
        evidenceVariants.forEachIndexed { index, variant ->
            assertNotEquals(baseEvidenceDigest, variant.evidenceSha256, "sandbox evidence variant $index collided")
        }

        val evidenceCheckpoints = AtomicInteger()
        assertFailsWith<IOException> {
            evidence(
                launches = List(128) { baseLaunch },
                cancellationCheck = {
                    if (Thread.currentThread().stackTrace.any {
                            it.methodName == "canonicalSandboxEvidenceDigest"
                        } && evidenceCheckpoints.incrementAndGet() >= 64
                    ) throw IOException("injected evidence deadline")
                },
            )
        }
        assertTrue(evidenceCheckpoints.get() >= 64, "evidence canonicalization must checkpoint")
    }

    private fun rule(
        staging: AcpWorkflowStagingRoot,
        executable: Path,
        arguments: List<String>,
    ): AcpTerminalCommandRule = AcpTerminalCommandRule(
        AcpSandboxReadOnlyMount(executable),
        arguments,
        staging.path,
    )
}

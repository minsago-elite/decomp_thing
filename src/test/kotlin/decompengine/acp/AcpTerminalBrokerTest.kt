package decompengine.acp

import com.agentclientprotocol.model.EnvVariable
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.ToolCallContent
import com.agentclientprotocol.model.ToolCallId
import com.agentclientprotocol.model.ToolCallStatus
import com.agentclientprotocol.model.ToolKind
import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentWorkspaceRoot
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class AcpTerminalBrokerTest {
    @Test
    fun `capability is the immutable intersection of workflow policy and verified boundary`() {
        val fixture = terminalFixture()
        val audit = AcpTerminalAuditRecorder()

        val disabledWithoutPolicy = fixture.boundary.openTerminalBroker(
            fixture.request,
            AgentCancellation.NONE,
            null,
            emptyMap(),
            audit,
        )
        assertFalse(disabledWithoutPolicy.capability)
        disabledWithoutPolicy.close()

        val deniedRequest = request(fixture.root, execute = false)
        val disabledByWorkflow = fixture.boundary.openTerminalBroker(
            deniedRequest,
            AgentCancellation.NONE,
            fixture.policy,
            emptyMap(),
            audit,
        )
        assertFalse(disabledByWorkflow.capability)
        disabledByWorkflow.close()

        val enabled = fixture.boundary.openTerminalBroker(
            fixture.request,
            AgentCancellation.NONE,
            fixture.policy,
            emptyMap(),
            audit,
        )
        assertTrue(enabled.capability)
        enabled.bindSession(SESSION)
        assertTrue(enabled.capability, "session binding may not drift the advertised capability")
        enabled.close()
        fixture.boundary.close()
    }

    @Test
    fun `exact argv cwd and environment mismatches fail before launch without secret disclosure`() {
        runBlocking {
        val fixture = terminalFixture(environment = mapOf("MODE" to "safe"))
        val audit = AcpTerminalAuditRecorder(networkIsolated = true)
        val broker = broker(fixture, audit)
        broker.bindSession(SESSION)

        val denied = listOf<suspend () -> Unit>(
            { broker.create(SESSION, "/usr/bin/false", fixture.args, fixture.root.path.toString(), fixture.env, null) },
            { broker.create(SESSION, fixture.command, fixture.args + "extra", fixture.root.path.toString(), fixture.env, null) },
            { broker.create(SESSION, fixture.command, fixture.args, fixture.root.path.resolve(".").toString() + "/../x", fixture.env, null) },
            { broker.create(SESSION, fixture.command, fixture.args, fixture.root.path.toString(), listOf(EnvVariable("MODE", "other")), null) },
            { broker.create(SESSION, fixture.command, fixture.args, fixture.root.path.toString(), listOf(EnvVariable("API_TOKEN", "do-not-log")), null) },
        )
        denied.forEach { attempt -> assertFailsWith<AcpExpectedError> { attempt() } }

        val collisionRecordStart = audit.snapshot().size
        assertFailsWith<AcpExpectedError> {
            broker.create(
                SESSION,
                "/audit-partition",
                listOf("tail"),
                fixture.root.path.toString(),
                emptyList(),
                null,
            )
        }
        assertFailsWith<AcpExpectedError> {
            broker.create(
                SESSION,
                "/audit-partition\u0000tail",
                emptyList(),
                fixture.root.path.toString(),
                emptyList(),
                null,
            )
        }
        val partitionedRequests = audit.snapshot().drop(collisionRecordStart)
        assertEquals(2, partitionedRequests.size)
        assertTrue(
            partitionedRequests.map { it.requestSha256 }.distinct().size == 2,
            "tagged length-delimited audit encoding must distinguish command/argv repartitioning",
        )

        assertTrue(fixture.boundary.evidence(fixture.policy).launches.isEmpty())
        assertTrue(audit.snapshot().all { it.outcome == AcpTerminalAuditOutcome.DENIED })
        assertFalse(audit.snapshot().toString().contains(fixture.root.path.toString()))
        assertFalse(audit.snapshot().toString().contains("do-not-log"))

        val copiedOuterValue = terminalFixture(environment = mapOf("MODE" to "opaque-agent-value"))
        assertFailsWith<IllegalArgumentException> {
            copiedOuterValue.boundary.openTerminalBroker(
                copiedOuterValue.request,
                AgentCancellation.NONE,
                copiedOuterValue.policy,
                mapOf(
                    "OUTER_VALUE" to AcpEnvironmentValue(
                        "opaque-agent-value",
                        AcpEnvironmentProvenance.SECRET,
                    ),
                ),
                AcpTerminalAuditRecorder(),
            )
        }
        val argvSecret = terminalFixture(mode = "prefix-opaque-agent-value-suffix")
        assertFailsWith<IllegalArgumentException> {
            argvSecret.boundary.openTerminalBroker(
                argvSecret.request,
                AgentCancellation.NONE,
                argvSecret.policy,
                mapOf(
                    "OUTER_VALUE" to AcpEnvironmentValue(
                        "opaque-agent-value",
                        AcpEnvironmentProvenance.SECRET,
                    ),
                ),
                AcpTerminalAuditRecorder(),
            )
        }
        val publicValueBroker = argvSecret.boundary.openTerminalBroker(
            argvSecret.request,
            AgentCancellation.NONE,
            argvSecret.policy,
            mapOf(
                "OUTER_VALUE" to AcpEnvironmentValue(
                    "opaque-agent-value",
                    AcpEnvironmentProvenance.PUBLIC,
                ),
            ),
            AcpTerminalAuditRecorder(),
        )
        assertTrue(publicValueBroker.capability)
        publicValueBroker.close()
        broker.close()
        fixture.boundary.close()
        copiedOuterValue.boundary.close()
        argvSecret.boundary.close()
        Unit
        }
    }

    @Test
    fun `terminal lifecycle requires tool binding truncates output and invalidates release`() {
        runBlocking {
        val fixture = terminalFixture(
            mode = "terminal-output",
            retainedBytes = 8,
        )
        val audit = AcpTerminalAuditRecorder(networkIsolated = true)
        val broker = broker(fixture, audit)
        broker.bindSession(SESSION)

        val terminalId = broker.create(
            SESSION,
            fixture.command,
            fixture.args,
            fixture.root.path.toString(),
            fixture.env,
            8u,
        ).terminalId
        assertFailsWith<AcpExpectedError> { broker.output(SESSION, terminalId) }
        broker.observeToolCall(SESSION, terminalUpdate("tool-1", terminalId))

        val exit = broker.waitForExit(SESSION, terminalId)
        assertEquals(0u, exit.exitCode)
        val output = broker.output(SESSION, terminalId)
        assertEquals("89abcdef", output.output)
        assertTrue(output.truncated)
        broker.release(SESSION, terminalId)
        assertFailsWith<AcpExpectedError> { broker.release(SESSION, terminalId) }
        broker.close()
        fixture.boundary.close()

        val records = audit.snapshot()
        assertTrue(records.any { it.reason == AcpTerminalAuditReason.CREATED })
        assertTrue(records.any { it.reason == AcpTerminalAuditReason.TOOL_BOUND })
        assertTrue(records.any { it.reason == AcpTerminalAuditReason.RELEASED })
        assertTrue(records.all { it.networkIsolated })
        assertTrue(records.filter { it.reason == AcpTerminalAuditReason.OUTPUT_OBSERVED }
            .all { it.producedOutputBytes == 16L })
        }
    }

    @Test
    fun `kill is idempotent while release and cross-session ids are strict`() {
        runBlocking {
        val fixture = terminalFixture(mode = "terminal-sleep")
        val broker = broker(fixture, AcpTerminalAuditRecorder())
        broker.bindSession(SESSION)
        val terminalId = broker.create(
            SESSION,
            fixture.command,
            fixture.args,
            fixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        broker.observeToolCall(SESSION, terminalUpdate("tool-1", terminalId))

        broker.kill(SESSION, terminalId)
        broker.kill(SESSION, terminalId)
        broker.release(SESSION, terminalId)
        assertFailsWith<AcpExpectedError> { broker.output(SESSION, terminalId) }
        broker.close()
        fixture.boundary.close()

        // A forged create must latch the broker failure before policy validation or launch. The
        // production raw-frame guard provides the corresponding pre-SDK-dispatch guarantee.
        val crossSessionCreateFixture = terminalFixture(mode = "terminal-sleep")
        val crossSessionCreateAudit = AcpTerminalAuditRecorder()
        val crossSessionCreateBroker = broker(crossSessionCreateFixture, crossSessionCreateAudit)
        crossSessionCreateBroker.bindSession(SESSION)
        assertFailsWith<AcpProtocolFailure> {
            crossSessionCreateBroker.create(
                "other-session",
                crossSessionCreateFixture.command,
                crossSessionCreateFixture.args,
                crossSessionCreateFixture.root.path.toString(),
                emptyList(),
                null,
            )
        }
        assertFailsWith<AcpProtocolFailure> {
            crossSessionCreateBroker.create(
                SESSION,
                crossSessionCreateFixture.command,
                crossSessionCreateFixture.args,
                crossSessionCreateFixture.root.path.toString(),
                emptyList(),
                null,
            )
        }
        assertTrue(crossSessionCreateAudit.snapshot().any {
            it.reason == AcpTerminalAuditReason.CROSS_SESSION
        })
        assertTrue(crossSessionCreateFixture.boundary.evidence(crossSessionCreateFixture.policy).launches.isEmpty())
        crossSessionCreateBroker.close()
        crossSessionCreateFixture.boundary.close()

        // A cross-session reference is a fatal protocol violation. Verify it on a separate
        // session instead of incorrectly expecting later callbacks to recover from that failure.
        val crossSessionFixture = terminalFixture(mode = "terminal-sleep")
        val crossSessionBroker = broker(crossSessionFixture, AcpTerminalAuditRecorder())
        crossSessionBroker.bindSession(SESSION)
        val crossSessionTerminal = crossSessionBroker.create(
            SESSION,
            crossSessionFixture.command,
            crossSessionFixture.args,
            crossSessionFixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        crossSessionBroker.observeToolCall(SESSION, terminalUpdate("tool-cross", crossSessionTerminal))
        assertFailsWith<AcpProtocolFailure> {
            crossSessionBroker.output("other-session", crossSessionTerminal)
        }
        assertFailsWith<AcpProtocolFailure> {
            crossSessionBroker.output(SESSION, crossSessionTerminal)
        }
        crossSessionBroker.close()
        crossSessionFixture.boundary.close()
        }
    }

    @Test
    fun `timeout output limit cancellation and close terminate process trees`() {
        runBlocking {
        val cases = listOf(
            terminalFixture(
                mode = "escape",
                // Launch attestation and the live probe share this wall budget.
                durationMillis = 2_000,
            ) to AcpTerminalAuditReason.TIMEOUT,
            terminalFixture(
                mode = "terminal-flood",
                maximumProducedBytes = 1024,
            ) to AcpTerminalAuditReason.OUTPUT_LIMIT,
            terminalFixture(
                mode = "terminal-burst-exit",
                maximumProducedBytes = 1024,
            ) to AcpTerminalAuditReason.OUTPUT_LIMIT,
        )
        cases.forEach { (fixture, expectedTerminationReason) ->
            val audit = AcpTerminalAuditRecorder()
            val broker = broker(fixture, audit)
            broker.bindSession(SESSION)
            val terminalId = broker.create(
                SESSION,
                fixture.command,
                fixture.args,
                fixture.root.path.toString(),
                emptyList(),
                null,
            ).terminalId
            broker.observeToolCall(SESSION, terminalUpdate("tool-1", terminalId))
            val completion = broker.waitForExit(SESSION, terminalId)
            broker.release(SESSION, terminalId)
            broker.close()
            fixture.boundary.close()
            val records = audit.snapshot()
            val authorized = records.single { it.reason == AcpTerminalAuditReason.LAUNCH_AUTHORIZED }
            val created = records.single { it.reason == AcpTerminalAuditReason.CREATED }
            assertTrue(authorized.sequence < created.sequence)
            assertTrue(records.any { it.reason == expectedTerminationReason })
            if (fixture.args.single() == "terminal-burst-exit") {
                assertEquals(null, completion.exitCode, "fast overflow must not be reported as a clean root exit")
                val limited = records.single { it.reason == AcpTerminalAuditReason.OUTPUT_LIMIT }
                assertTrue(created.sequence < limited.sequence, "CREATED must causally precede output-limit evidence")
            }
        }

        val cancellation = AgentCancellationSource()
        val fixture = terminalFixture(mode = "terminal-sleep")
        val broker = fixture.boundary.openTerminalBroker(
            fixture.request,
            cancellation.cancellation,
            fixture.policy,
            emptyMap(),
            AcpTerminalAuditRecorder(),
        )
        broker.bindSession(SESSION)
        val terminalId = broker.create(
            SESSION,
            fixture.command,
            fixture.args,
            fixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        broker.observeToolCall(SESSION, terminalUpdate("tool-cancel", terminalId))
        cancellation.cancel()
        broker.close()
        fixture.boundary.close()

        val postAuthorizationCancellation = AgentCancellationSource()
        val postAuthorizationFixture = terminalFixture(mode = "terminal-sleep")
        val postAuthorizationAudit = AcpTerminalAuditRecorder()
        val postAuthorizationBroker = postAuthorizationFixture.boundary.openTerminalBroker(
            postAuthorizationFixture.request,
            postAuthorizationCancellation.cancellation,
            postAuthorizationFixture.policy,
            emptyMap(),
            postAuthorizationAudit,
        )
        postAuthorizationBroker.bindSession(SESSION)
        val postAuthorizationExecutor = Executors.newSingleThreadExecutor()
        try {
            val postAuthorizationCreate = postAuthorizationExecutor.submit<String> {
                runBlocking {
                    postAuthorizationBroker.create(
                        SESSION,
                        postAuthorizationFixture.command,
                        postAuthorizationFixture.args,
                        postAuthorizationFixture.root.path.toString(),
                        emptyList(),
                        null,
                    ).terminalId
                }
            }
            val authorizationDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (postAuthorizationAudit.snapshot().none {
                    it.reason == AcpTerminalAuditReason.LAUNCH_AUTHORIZED
                } && System.nanoTime() < authorizationDeadline
            ) {
                TimeUnit.MILLISECONDS.sleep(1)
            }
            assertTrue(
                postAuthorizationAudit.snapshot().any { it.reason == AcpTerminalAuditReason.LAUNCH_AUTHORIZED },
                "terminal launch never published its write-ahead authorization",
            )
            postAuthorizationCancellation.cancel()
            val postAuthorizationTerminalId = postAuthorizationCreate.get(6, TimeUnit.SECONDS)
            postAuthorizationBroker.observeToolCall(
                SESSION,
                terminalUpdate("tool-post-authorization", postAuthorizationTerminalId),
            )
            assertFailsWith<AcpExpectedError> {
                postAuthorizationBroker.output(SESSION, postAuthorizationTerminalId)
            }
        } finally {
            postAuthorizationExecutor.shutdownNow()
            postAuthorizationBroker.close()
            postAuthorizationFixture.boundary.close()
        }
        val postAuthorizationRecords = postAuthorizationAudit.snapshot()
        val postAuthorizationReasons = postAuthorizationRecords.map { it.reason }
        assertTrue(
            postAuthorizationReasons.indexOf(AcpTerminalAuditReason.LAUNCH_AUTHORIZED) <
                postAuthorizationReasons.indexOf(AcpTerminalAuditReason.CREATED),
        )
        assertTrue(AcpTerminalAuditReason.CANCELLED in postAuthorizationReasons)
        assertFalse(
            postAuthorizationRecords.any {
                it.outcome == AcpTerminalAuditOutcome.DENIED &&
                    it.method == "terminal/create" &&
                    it.reason == AcpTerminalAuditReason.CANCELLED
            },
            "cancellation after write-ahead authorization must be an allowed launch followed by termination",
        )

        val launchEntered = CountDownLatch(1)
        val releaseLaunch = CountDownLatch(1)
        val firstLaunch = AtomicBoolean(true)
        val concurrentFixture = terminalFixture(
            mode = "terminal-sleep",
            launchHook = AcpSandboxLaunchHook {
                if (firstLaunch.compareAndSet(true, false)) {
                    launchEntered.countDown()
                    releaseLaunch.await(5, TimeUnit.SECONDS)
                }
            },
        )
        val concurrentCancellation = AgentCancellationSource()
        val concurrentBroker = concurrentFixture.boundary.openTerminalBroker(
            concurrentFixture.request,
            concurrentCancellation.cancellation,
            concurrentFixture.policy,
            emptyMap(),
            AcpTerminalAuditRecorder(),
        )
        concurrentBroker.bindSession(SESSION)
        val executor = Executors.newFixedThreadPool(2)
        try {
            fun submitCreate() = executor.submit<Throwable?> {
                try {
                    runBlocking {
                        concurrentBroker.create(
                            SESSION,
                            concurrentFixture.command,
                            concurrentFixture.args,
                            concurrentFixture.root.path.toString(),
                            emptyList(),
                            null,
                        )
                    }
                    null
                } catch (failure: Throwable) {
                    failure
                }
            }
            val firstCreate = submitCreate()
            assertTrue(launchEntered.await(3, TimeUnit.SECONDS), "first launch never reached its blocking hook")
            concurrentCancellation.cancel()
            val secondCreate = submitCreate()
            val secondFailure = secondCreate.get(750, TimeUnit.MILLISECONDS)
            assertTrue(secondFailure is AcpExpectedError, "concurrent cancellation was blocked behind another launch: $secondFailure")
            releaseLaunch.countDown()
            assertTrue(firstCreate.get(6, TimeUnit.SECONDS) is AcpExpectedError)
        } finally {
            releaseLaunch.countDown()
            executor.shutdownNow()
            concurrentBroker.close()
            concurrentFixture.boundary.close()
        }

        val releaseFaultInjected = AtomicBoolean(false)
        val releaseFault = terminalFixture(
            mode = "terminal-output",
            cleanupHook = AcpSandboxCleanupHook { stage ->
                if (stage == AcpSandboxCleanupStage.RUNTIME_SNAPSHOTS &&
                    releaseFaultInjected.compareAndSet(false, true)
                ) throw IOException("injected terminal cleanup proof failure")
            },
        )
        val releaseAudit = AcpTerminalAuditRecorder()
        val releaseBroker = broker(releaseFault, releaseAudit)
        releaseBroker.bindSession(SESSION)
        val failedReleaseId = releaseBroker.create(
            SESSION,
            releaseFault.command,
            releaseFault.args,
            releaseFault.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        releaseBroker.observeToolCall(SESSION, terminalUpdate("tool-cleanup-fault", failedReleaseId))
        assertFailsWith<AcpCleanupProofFailure> { releaseBroker.release(SESSION, failedReleaseId) }
        assertFailsWith<AcpCleanupProofFailure> { releaseBroker.close() }
        assertFailsWith<AcpCleanupProofFailure> { releaseBroker.close() }
        assertFailsWith<AcpCleanupProofFailure> { releaseFault.boundary.close() }
        assertFailsWith<AcpCleanupProofFailure> { releaseFault.boundary.close() }
        assertTrue(releaseAudit.snapshot().any { it.reason == AcpTerminalAuditReason.CLEANUP_FAILED })

        val launchFaultInjected = AtomicBoolean(false)
        val launchFault = terminalFixture(
            launchHook = AcpSandboxLaunchHook { stage ->
                if (stage == AcpSandboxLaunchStage.AFTER_SETUP_BIND_ATTESTATION_BEFORE_RELEASE) {
                    throw IOException("injected post-verification launch failure")
                }
            },
            cleanupHook = AcpSandboxCleanupHook { stage ->
                if (stage == AcpSandboxCleanupStage.SCOPE && launchFaultInjected.compareAndSet(false, true)) {
                    throw IOException("injected launch cleanup proof failure")
                }
            },
        )
        val launchBroker = broker(launchFault, AcpTerminalAuditRecorder())
        launchBroker.bindSession(SESSION)
        assertFailsWith<AcpCleanupProofFailure> {
            launchBroker.create(
                SESSION,
                launchFault.command,
                launchFault.args,
                launchFault.root.path.toString(),
                emptyList(),
                null,
            )
        }
        assertFailsWith<AcpCleanupProofFailure> { launchBroker.close() }
        assertFailsWith<AcpCleanupProofFailure> { launchBroker.close() }
        assertFailsWith<AcpCleanupProofFailure> { launchFault.boundary.close() }
        assertFailsWith<AcpCleanupProofFailure> { launchFault.boundary.close() }
        }
    }

    @Test
    fun `tool terminal ids cannot be orphaned or rebound`() {
        runBlocking {
        val fixture = terminalFixture(mode = "terminal-sleep")
        val broker = broker(fixture, AcpTerminalAuditRecorder())
        broker.bindSession(SESSION)
        val first = broker.create(
            SESSION,
            fixture.command,
            fixture.args,
            fixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        assertFailsWith<AcpProtocolFailure> { broker.finishSession(SESSION) }
        broker.close()
        fixture.boundary.close()

        val secondFixture = terminalFixture(mode = "terminal-sleep")
        val secondBroker = broker(secondFixture, AcpTerminalAuditRecorder())
        secondBroker.bindSession(SESSION)
        val second = secondBroker.create(
            SESSION,
            secondFixture.command,
            secondFixture.args,
            secondFixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        secondBroker.observeToolCall(SESSION, terminalUpdate("tool-a", second))
        assertFailsWith<AcpProtocolFailure> {
            secondBroker.observeToolCall(SESSION, terminalUpdate("tool-b", second))
        }
        secondBroker.close()
        secondFixture.boundary.close()

        val boundedAuditFixture = terminalFixture(mode = "terminal-sleep")
        val boundedAudit = AcpTerminalAuditRecorder(maximumRecords = 3)
        val boundedAuditBroker = broker(boundedAuditFixture, boundedAudit)
        boundedAuditBroker.bindSession(SESSION)
        val boundedTerminal = boundedAuditBroker.create(
            SESSION,
            boundedAuditFixture.command,
            boundedAuditFixture.args,
            boundedAuditFixture.root.path.toString(),
            emptyList(),
            null,
        ).terminalId
        boundedAuditBroker.observeToolCall(SESSION, terminalUpdate("tool-audit-cap", boundedTerminal))
        assertFailsWith<AcpProtocolFailure> {
            boundedAuditBroker.output(SESSION, boundedTerminal)
        }
        assertEquals(3, boundedAudit.snapshot().size, "terminal audit evidence must remain finitely bounded")
        boundedAuditBroker.close()
        boundedAuditFixture.boundary.close()
        assertNotNull(first)
        }
    }

    private fun broker(
        fixture: TerminalFixture,
        audit: AcpTerminalAuditRecorder,
    ): AcpTerminalBroker = fixture.boundary.openTerminalBroker(
        fixture.request,
        AgentCancellation.NONE,
        fixture.policy,
        emptyMap(),
        audit,
    )

    private fun terminalFixture(
        mode: String = "terminal-output",
        environment: Map<String, String> = emptyMap(),
        retainedBytes: Int = 1024,
        maximumProducedBytes: Long = 64 * 1024,
        durationMillis: Long = 2_000,
        launchHook: AcpSandboxLaunchHook? = null,
        cleanupHook: AcpSandboxCleanupHook? = null,
    ): TerminalFixture {
        val parent = createTempDirectory("acp-terminal-test-").toAbsolutePath().normalize()
        requireLiveHost()
        val staging = AcpWorkflowStagingRoot.createReadOnly("stage", parent)
        val root = staging.workspaceRoot
        val args = listOf(mode)
        val env = environment.map { (name, value) -> EnvVariable(name, value) }
        val policy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(
                        PROBE,
                        PROBE_DESTINATION,
                        calculateAcpRuntimeManifestSha256(PROBE),
                    ),
                    args,
                    root.path,
                    environment,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 2,
                maximumTerminalCreates = 4,
                maximumRetainedOutputBytes = retainedBytes,
                maximumProducedOutputBytes = maximumProducedBytes,
                maximumDuration = Duration.ofMillis(durationMillis),
                terminationGrace = Duration.ofMillis(80),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 2),
            ),
        )
        return TerminalFixture(
            root,
            request(root),
            policy,
            PROBE_DESTINATION.toString(),
            args,
            env,
            LinuxBubblewrapBoundary.prepare(
                liveConfiguration(),
                launchHook = launchHook,
                cleanupHook = cleanupHook,
            ),
        )
    }

    private fun request(
        root: AgentWorkspaceRoot,
        execute: Boolean = true,
    ): AgentExecutionRequest = AgentExecutionRequest(
        objective = "run an exact fixture command",
        workspaceRoots = listOf(root),
        accessPolicy = AgentAccessPolicy(
            emptyList(),
            if (execute) setOf(AgentOperation.EXECUTE_COMMAND) else emptySet(),
        ),
    )

    private fun terminalUpdate(toolCallId: String, terminalId: String): SessionUpdate.ToolCallUpdate =
        SessionUpdate.ToolCallUpdate(
            toolCallId = ToolCallId(toolCallId),
            title = "Run fixture",
            kind = ToolKind.EXECUTE,
            status = ToolCallStatus.IN_PROGRESS,
            content = listOf(ToolCallContent.Terminal(terminalId)),
        )

    private data class TerminalFixture(
        val root: AgentWorkspaceRoot,
        val request: AgentExecutionRequest,
        val policy: AcpTerminalExecutionPolicy,
        val command: String,
        val args: List<String>,
        val env: List<EnvVariable>,
        val boundary: LinuxBubblewrapBoundary,
    )

    private fun requireLiveHost() {
        val missing = SECURITY_TOOLS.filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(missing.isEmpty(), { "live ACP terminal sandbox tools unavailable: $missing" })
        AcpLiveContractHost.requireCapability(Files.exists(USER_RUNTIME.resolve("bus")), { "systemd user bus is unavailable" })
        AcpLiveContractHost.requireCapability(Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")), { "cgroup v2 is unavailable" })
        AcpLiveContractHost.requireCapability(Files.isExecutable(PROBE), { "static ACP terminal probe is unavailable" })
        AcpLiveContractHost.requireCapability(Files.isExecutable(GATE_HELPER), { "static ACP gate helper is unavailable" })
    }

    private fun liveConfiguration(): AcpLinuxSandboxConfiguration = AcpLinuxSandboxConfiguration(
        bubblewrapExecutable = BWRAP,
        resourceLimiterExecutable = PRLIMIT,
        scopeSupervisorExecutable = SYSTEMD_RUN,
        scopeInspectorExecutable = SYSTEMCTL,
        environmentFdOpenerExecutable = BASH,
        sandboxGateHelperExecutable = GATE_HELPER,
        launcherRuntimeMounts = emptyList(),
        agentRuntimeMounts = emptyList(),
        systemdUserRuntimeDirectory = USER_RUNTIME,
        agentResourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 8),
        expectedBubblewrapSha256 = sha256(BWRAP),
        expectedResourceLimiterSha256 = sha256(PRLIMIT),
        expectedScopeSupervisorSha256 = sha256(SYSTEMD_RUN),
        expectedScopeInspectorSha256 = sha256(SYSTEMCTL),
        expectedEnvironmentFdOpenerSha256 = sha256(BASH),
        expectedSandboxGateHelperSha256 = sha256(GATE_HELPER),
        expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(GATE_HELPER),
    )

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }

    private companion object {
        const val SESSION = "terminal-fixture-session"
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val CC: Path = Path.of("/usr/bin/cc")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val SECURITY_TOOLS = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, CC)
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
        val PROBE_DESTINATION: Path = Path.of("/decomp-acp-terminal-probe")
        val PROBE: Path by lazy {
            val compiler = Path.of("/usr/bin/cc")
            if (!Files.isExecutable(compiler)) return@lazy Path.of("/definitely-absent/decomp-acp-probe")
            val source = Path.of(
                requireNotNull(AcpTerminalBrokerTest::class.java.getResource("/acp/sandbox_probe.c")).toURI(),
            )
            val output = createTempDirectory("acp-terminal-static-probe-")
                .resolve("probe")
                .toAbsolutePath()
                .normalize()
            val process = ProcessBuilder(
                compiler.toString(), "-O2", "-static", source.toString(), "-o", output.toString(),
            ).redirectErrorStream(true).start()
            val diagnostics = process.inputStream.readNBytes(32 * 1024).toString(Charsets.UTF_8)
            if (!process.waitFor(20, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw IllegalStateException("static ACP terminal probe unavailable: $diagnostics")
            }
            output
        }
    }
}

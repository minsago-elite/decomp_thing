package decompengine.acp

import com.agentclientprotocol.model.LATEST_PROTOCOL_VERSION
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.execute
import decompengine.agent.executeReceipt
import decompengine.repair.CapturedRepairStagingAuthority
import decompengine.repair.RepairResourceBudget
import java.nio.file.Path
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Timeout

@Timeout(value = 60, unit = TimeUnit.SECONDS)
class AcpAgentHarnessTest {
    @Test
    fun `public harness fails closed before launch when the outer sandbox is absent`() {
        val fixture = fixture()
        val harness = AcpAgentHarness(
            AcpProcessConfiguration(executable = Path.of("/usr/bin/true")),
        )

        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request) }

        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertTrue(failure.failure.message.contains("sandbox"))
        val receipt = assertNotNull(failure.receipt)
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH, invocation.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.UNVERIFIED, invocation.cleanupDisposition)
        assertNull(invocation.completeExecutionEvidence)
        assertNull(harness.latestDiagnostics())
        assertNull(harness.latestSandboxEvidence(), "failed launch must not claim successful containment")
    }

    @Test
    fun `production bytecode exposes no launcher boundary or test mode bypass`() {
        val fixture = fixture()
        val harness = AcpAgentHarness(
            AcpProcessConfiguration(
                executable = Path.of("/usr/bin/true"),
                sandboxBoundary = missingSandboxConfiguration(),
            ),
        )

        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request) }

        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertNull(harness.latestSandboxEvidence())
        val bytecode = javap(AcpAgentHarness::class.java) + "\n" + javap(AcpTerminalBroker::class.java)
        listOf(
            "uncontainedForTesting",
            "withBoundaryForTesting",
            "openWithTestBoundary",
            "TEST_ONLY_UNCONTAINED",
            "AcpProcessSandboxBoundary",
            "AcpTerminalSandboxBoundary",
            "boundaryFactory",
            "launchMode",
        ).forEach { forbidden -> assertFalse(forbidden in bytecode, bytecode) }
        val harnessConstructors = AcpAgentHarness::class.java.declaredConstructors.toList()
        assertEquals(1, harnessConstructors.size)
        assertEquals(listOf(AcpProcessConfiguration::class.java), harnessConstructors.single().parameterTypes.toList())
        listOf(AcpAgentHarness::class.java, AcpTerminalBroker::class.java).forEach { type ->
            val callableParameterTypes = type.declaredConstructors.flatMap { it.parameterTypes.toList() } +
                type.declaredMethods.flatMap { it.parameterTypes.toList() }
            assertTrue(
                callableParameterTypes.none(::isForbiddenExecutionSeamType),
                "$type accepts ${callableParameterTypes.filter(::isForbiddenExecutionSeamType)}",
            )
        }
        assertTrue(AcpTerminalBroker::class.java.isSealed)
        assertTrue(AcpTerminalBroker::class.java.permittedSubclasses.all { permitted ->
            java.lang.reflect.Modifier.isPrivate(permitted.modifiers)
        })
        val acpTestMethods = listOf(
            AcpAgentHarnessTest::class.java,
            AcpPermissionPolicyTest::class.java,
            AcpSandboxPolicyTest::class.java,
            AcpTerminalBrokerTest::class.java,
            LinuxBubblewrapBoundaryTest::class.java,
        ).flatMap { type ->
            type.declaredMethods.filter { method ->
                method.annotations.any { annotation ->
                    annotation.annotationClass.java.name == "org.junit.jupiter.api.Test"
                }
            }
        }
        assertEquals(66, acpTestMethods.size, acpTestMethods.joinToString { it.name })
        assertTrue(
            acpTestMethods.all { it.returnType == Void.TYPE },
            acpTestMethods.filter { it.returnType != Void.TYPE }.joinToString {
                "${it.declaringClass.simpleName}.${it.name}:${it.returnType.name}"
            },
        )
    }

    @Test
    fun `pinned SDK negotiates stable v1 and streams one subprocess turn without shell interpretation`() {
        assertEquals(1, LATEST_PROTOCOL_VERSION)
        assertEquals("0.30.1", ACP_KOTLIN_SDK_VERSION)
        val fixture = fixture()
        val shellMarker = fixture.workspace.resolve("shell-was-interpreted")
        val sentinel = "\$(touch $shellMarker)"
        val harness = harness("success", sentinel = sentinel)
        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()

        val result = try {
            harness.execute(fixture.request, events::add)
        } catch (failure: Exception) {
            throw AssertionError(
                "canonical live ACP fixture failed; diagnostics=${harness.latestDiagnostics()}; " +
                    "sandbox=${harness.latestSandboxEvidence()}",
                failure,
            )
        }

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
    fun `fragmented stdout writes are assembled into complete protocol frames`() {
        val fixture = fixture(genericContract = true)
        val harness = harness("fragmented-stdout")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("updated artifact\n", fixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, fixture.forbiddenCanary.readText())
        assertCleanTermination(harness)
    }

    @Test
    fun `configured session preferences use advertised setters in deterministic order while defaults send none`() {
        val configuredFixture = fixture(genericContract = true)
        val configuredHarness = harness(
            mode = "session-preferences",
            sentinel = "preferences-success",
            sessionPreferences = AcpSessionPreferences(
                modelId = "model-safe",
                modeId = "mode-safe",
                configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                ),
            ),
        )

        val configuredResult = configuredHarness.execute(configuredFixture.request)

        assertEquals(AgentStopReason.COMPLETED, configuredResult.stopReason)
        assertEquals("updated artifact\n", configuredFixture.source.readText())
        assertCleanTermination(configuredHarness, "configured session preferences", configuredFixture)

        val defaultFixture = fixture(genericContract = true)
        val defaultHarness = harness(
            mode = "session-preferences",
            sentinel = "preferences-default",
        )

        val defaultResult = defaultHarness.execute(defaultFixture.request)

        assertEquals(AgentStopReason.COMPLETED, defaultResult.stopReason)
        assertEquals("updated artifact\n", defaultFixture.source.readText())
        assertCleanTermination(defaultHarness, "default session preferences", defaultFixture)
    }

    @Test
    fun `removed later config option stops the real setter flow before prompt and workspace changes`() {
        val fixture = fixture(genericContract = true)
        val harness = harness(
            mode = "session-preferences-config-removes-next",
            sessionPreferences = AcpSessionPreferences(configOptions = listOf(
                AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
            )),
        )
        val events = mutableListOf<AgentExecutionEvent>()
        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request, events::add) }
        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertEquals("currentInventoryMismatch", failure.failure.details["reason"])
        assertEquals("1", failure.failure.details["preferenceIndex"])
        assertEquals("original artifact\n", fixture.source.readText())
        assertTrue(events.isEmpty())
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached)
        assertNull(invocation.wirePromptSha256)
        assertCleanTermination(harness, "removed later option", fixture, failure = failure, events = events)
    }

    @Test
    fun `unknown absent and mistyped session preferences fail before every setter prompt and workspace operation`() {
        data class RejectedPreference(
            val label: String,
            val mode: String,
            val preferences: AcpSessionPreferences,
            val secretCanary: String,
        )

        val cases = listOf(
            RejectedPreference(
                "unknown model",
                "session-preferences",
                AcpSessionPreferences(modelId = "model-secret-canary"),
                "model-secret-canary",
            ),
            RejectedPreference(
                "unknown mode",
                "session-preferences",
                AcpSessionPreferences(modeId = "mode-secret-canary"),
                "mode-secret-canary",
            ),
            RejectedPreference(
                "unknown option",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference(
                        "option-secret-canary",
                        AcpSessionConfigValue.BooleanValue(false),
                    ),
                )),
                "option-secret-canary",
            ),
            RejectedPreference(
                "unknown select value",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference(
                        "reasoning",
                        AcpSessionConfigValue.Select("value-secret-canary"),
                    ),
                )),
                "value-secret-canary",
            ),
            RejectedPreference(
                "mismatched option type",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "not-present",
            ),
            RejectedPreference(
                "pipelined update cannot expand session new authority",
                "session-preferences-pipelined-update",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("late-option", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "late-option",
            ),
            RejectedPreference(
                "pipelined work cannot run while invalid preferences are rejected",
                "session-preferences-pipelined-work",
                AcpSessionPreferences(modelId = "model-secret-canary"),
                "model-secret-canary",
            ),
            RejectedPreference(
                "absent model capability",
                "session-preferences-no-models",
                AcpSessionPreferences(modelId = "model-safe"),
                "not-present",
            ),
            RejectedPreference(
                "absent mode capability",
                "session-preferences-no-modes",
                AcpSessionPreferences(modeId = "mode-safe"),
                "not-present",
            ),
            RejectedPreference(
                "absent config capability",
                "session-preferences-no-config-options",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "not-present",
            ),
        )

        cases.forEach { case ->
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode = case.mode,
                sentinel = "preferences-reject",
                sessionPreferences = case.preferences,
            )
            val events = mutableListOf<AgentExecutionEvent>()

            val failure = assertFailsWith<AgentExecutionException>(case.label) {
                harness.execute(fixture.request, events::add)
            }

            assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind, case.label)
            assertEquals("original artifact\n", fixture.source.readText(), case.label)
            assertTrue(events.isEmpty(), case.label)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
            assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached, case.label)
            assertNull(invocation.wirePromptSha256, case.label)
            assertFalse(failure.stackTraceToString().contains(case.secretCanary), case.label)
            assertFalse(invocation.toString().contains(case.secretCanary), case.label)
            assertCleanTermination(
                harness = harness,
                context = case.label,
                fixture = fixture,
                failure = failure,
                events = events,
            )
        }

        // Cancel from the setter wait itself instead of using a timing delay that could fire
        // during sandbox startup on a contended host. The hanging wire peer proves teardown does
        // not depend on a setter response.
        val cancellationFixture = fixture(genericContract = true)
        val setterWaitObserved = AtomicBoolean(false)
        val setterCancellation = AgentCancellation {
            val insideSetterWait = Thread.currentThread().stackTrace.any { frame ->
                frame.className == AcpAgentHarness::class.java.name &&
                    frame.methodName.startsWith("awaitSessionPreferenceSetter")
            }
            if (insideSetterWait) setterWaitObserved.set(true)
            insideSetterWait
        }
        val cancellationHarness = harness(
            mode = "session-preferences-setter-timeout",
            sentinel = "preference-setter-cancel",
            sessionPreferences = AcpSessionPreferences(modelId = "model-safe"),
            timeouts = timeouts(request = 3_000),
        )
        val cancellationEvents = mutableListOf<AgentExecutionEvent>()

        val cancellationReceipt = cancellationHarness.executeReceipt(
            cancellationFixture.request.withCancellation(setterCancellation),
            cancellationEvents::add,
        )
        val cancelled = assertIs<AgentExecutionOutcome.Returned>(cancellationReceipt.outcome).result

        assertTrue(setterWaitObserved.get())
        assertEquals(AgentStopReason.CANCELLED, cancelled.stopReason)
        assertEquals("fixture-session", cancelled.session?.sessionId)
        assertEquals("original artifact\n", cancellationFixture.source.readText())
        assertTrue(cancellationEvents.isEmpty())
        val cancellationEvidence = assertIs<AcpInvocationEvidenceSnapshot>(cancellationReceipt.providerEvidence)
        assertNull(cancellationEvidence.wirePromptSha256)
        assertCleanTermination(
            harness = cancellationHarness,
            context = "setter cancellation",
            fixture = cancellationFixture,
            events = cancellationEvents,
        )
    }

    @Test
    fun `session preference setter errors and timeouts are bounded redacted and cleaned before prompt`() {
        data class SetterFailureCase(
            val label: String,
            val mode: String,
            val expectedKind: AgentFailureKind,
            val timeouts: AcpLifecycleTimeouts,
            val preferences: AcpSessionPreferences,
        )
        val cases = listOf(
            SetterFailureCase(
                "setter error",
                "session-preferences-setter-error",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(modelId = "model-safe"),
            ),
            SetterFailureCase(
                "setter timeout",
                "session-preferences-setter-timeout",
                AgentFailureKind.TIMEOUT,
                timeouts(request = 200),
                AcpSessionPreferences(modelId = "model-safe"),
            ),
            SetterFailureCase(
                "config setter inconsistent postcondition",
                "session-preferences-config-inconsistent",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                )),
            ),
            SetterFailureCase(
                "later config setter cannot revert an earlier configured option",
                "session-preferences-config-reverts-earlier",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                )),
            ),
        )

        cases.forEach { case ->
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode = case.mode,
                sentinel = "preference-setter",
                sessionPreferences = case.preferences,
                timeouts = case.timeouts,
            )
            val events = mutableListOf<AgentExecutionEvent>()

            val failure = assertFailsWith<AgentExecutionException>(case.label) {
                harness.execute(fixture.request, events::add)
            }

            assertEquals(case.expectedKind, failure.failure.kind, case.label)
            assertEquals("original artifact\n", fixture.source.readText(), case.label)
            assertTrue(events.isEmpty(), case.label)
            assertFalse(failure.stackTraceToString().contains("setter-secret-canary"), case.label)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
            assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached, case.label)
            assertNull(invocation.wirePromptSha256, case.label)
            assertCleanTermination(
                harness = harness,
                context = case.label,
                fixture = fixture,
                failure = failure,
                events = events,
            )
        }
    }

    @Test
    fun `stable v1 stop reasons map to the program neutral execution contract`() {
        mapOf(
            "stop-max-tokens" to AgentStopReason.LIMIT_EXHAUSTED,
            "stop-max-turn-requests" to AgentStopReason.LIMIT_EXHAUSTED,
            "stop-refusal" to AgentStopReason.REFUSED,
        ).forEach { (mode, expected) ->
            val fixture = fixture(genericContract = true)
            val harness = harness(mode)

            val receipt = harness.executeReceipt(fixture.request)
            val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome).result
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)

            assertEquals(expected, result.stopReason, mode)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, mode)
            assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, invocation.phaseReached, mode)
            assertNotNull(invocation.completeExecutionEvidence, mode)
            assertEquals("original artifact\n", fixture.source.readText(), mode)
            assertEquals(FORBIDDEN_CANARY_CONTENT, fixture.forbiddenCanary.readText(), mode)
            assertCleanTermination(harness, mode)
        }
    }

    @Test
    fun `overlapping receipts retain their own request prompt and provider evidence`() {
        val firstFixture = fixture()
        val secondFixture = fixture()
        val firstRequest = firstFixture.request.withContextMarker("first-turn-marker")
        val secondRequest = secondFixture.request.withContextMarker("second-turn-marker")
        val harness = harness("success")
        val callbacksEntered = CountDownLatch(2)
        val executor = Executors.newFixedThreadPool(2)

        fun submit(request: AgentExecutionRequest) = executor.submit<AgentExecutionReceipt> {
            val firstCallback = AtomicBoolean(true)
            harness.executeReceipt(request) {
                if (firstCallback.compareAndSet(true, false)) {
                    callbacksEntered.countDown()
                    check(callbacksEntered.await(10, TimeUnit.SECONDS)) {
                        "overlapping ACP invocation did not reach its event callback"
                    }
                }
            }
        }

        try {
            val firstFuture = submit(firstRequest)
            val secondFuture = submit(secondRequest)
            val first = firstFuture.get(20, TimeUnit.SECONDS)
            val second = secondFuture.get(20, TimeUnit.SECONDS)
            val firstEvidence = assertIs<AcpInvocationEvidenceSnapshot>(first.providerEvidence)
            val secondEvidence = assertIs<AcpInvocationEvidenceSnapshot>(second.providerEvidence)

            assertEquals(AgentExecutionRequestBinding.capture(firstRequest), first.requestBinding)
            assertEquals(AgentExecutionRequestBinding.capture(secondRequest), second.requestBinding)
            assertEquals(expectedWirePromptSha256(firstRequest), firstEvidence.wirePromptSha256)
            assertEquals(expectedWirePromptSha256(secondRequest), secondEvidence.wirePromptSha256)
            assertFalse(firstEvidence.wirePromptSha256 == secondEvidence.wirePromptSha256)
            assertEquals(
                firstEvidence.wirePromptSha256,
                assertNotNull(firstEvidence.completeExecutionEvidence).wirePromptSha256,
            )
            assertEquals(
                secondEvidence.wirePromptSha256,
                assertNotNull(secondEvidence.completeExecutionEvidence).wirePromptSha256,
            )
            assertEquals(AgentStopReason.COMPLETED, assertIs<AgentExecutionOutcome.Returned>(first.outcome).result.stopReason)
            assertEquals(AgentStopReason.COMPLETED, assertIs<AgentExecutionOutcome.Returned>(second.outcome).result.stopReason)
            assertEquals("new source\n", firstFixture.source.readText())
            assertEquals("new source\n", secondFixture.source.readText())
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `fake agent permission request uses offered default denial and metadata-only evidence`() {
        val fixture = fixture()
        val request = fixture.request.withPolicy(
            AgentAccessPolicy(
                fixture.request.accessPolicy.pathRules,
                fixture.request.accessPolicy.allowedOperations + AgentOperation.REQUEST_PERMISSION,
            ),
        )
        val harness = harness("permission-default-deny")
        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()

        val result = harness.execute(request, events::add)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val permission = events.filterIsInstance<AgentPermissionEvent>().single()
        assertEquals(AgentPermissionDecision.DENY, permission.decision)
        assertEquals("reject", permission.selectedOptionId)
        assertEquals(2, result.usage?.toolCalls)
        assertEquals(
            1,
            events.filterIsInstance<AgentToolEvent>().count { it.toolCallId == "permission-tool" },
            "permission callback ToolCallUpdate must be translated and counted exactly once",
        )
        val evidence = harness.latestPermissionAudit().single()
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, evidence.reason)
        assertFalse(evidence.authorityExpanded)
        assertFalse(evidence.toString().contains("Run exact fixture command"))
    }

    @Test
    fun `fake agent exercises official terminal create wait output release and tool correlation`() {
        val parent = createTempDirectory("acp-terminal-wire-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("project", parent)
        val source = staging.path.resolve("contract/artifact.txt")
        source.parent.createDirectories()
        source.writeText("original artifact\n")
        val forbiddenCanary = staging.path.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val pathRule = AgentPathRule(
            AgentWorkspacePath("project", "contract/artifact.txt"),
            setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
        )
        val request = AgentExecutionRequest(
            objective = "exercise the protocol fixture",
            workspaceRoots = listOf(staging.workspaceRoot),
            contextInputs = listOf(decompengine.agent.AgentContextInput("contract", "protocol evidence")),
            accessPolicy = AgentAccessPolicy(
                listOf(pathRule),
                setOf(
                    AgentOperation.READ_FILE,
                    AgentOperation.WRITE_FILE,
                    AgentOperation.EXECUTE_COMMAND,
                    AgentOperation.REQUEST_PERMISSION,
                ),
            ),
        )
        val terminalArgument = "wire-terminal"
        val terminalPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(ECHO),
                    listOf(terminalArgument),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(3),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val harness = harness(
            "terminal-lifecycle",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )

        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()
        val result = try {
            harness.execute(request, events::add)
        } catch (failure: AgentExecutionException) {
            throw AssertionError(
                "terminal wire fixture failed; metadata-only audit=${harness.latestTerminalAudit()}",
                failure,
            )
        }

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        val reasons = harness.latestTerminalAudit().map { it.reason }.toSet()
        assertTrue(AcpTerminalAuditReason.CREATED in reasons)
        assertTrue(AcpTerminalAuditReason.TOOL_BOUND in reasons)
        assertTrue(AcpTerminalAuditReason.EXIT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.OUTPUT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.RELEASED in reasons)
        assertTrue(harness.latestTerminalAudit().all { it.networkIsolated })
        assertEquals(1, result.usage?.toolCalls)
        assertEquals(
            1,
            events.filterIsInstance<AgentToolEvent>().count { it.toolCallId == "terminal-tool" },
            "permission callback terminal binding must validate and count its tool call exactly once",
        )
        assertEquals(AgentPermissionDecision.DENY, events.filterIsInstance<AgentPermissionEvent>().single().decision)
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, harness.latestPermissionAudit().single().reason)
        val evidence = assertNotNull(harness.latestSandboxEvidence())
        assertTrue(evidence.outerAgentContained)
        assertEquals(
            listOf(AcpSandboxLaunchPurpose.OUTER_AGENT, AcpSandboxLaunchPurpose.TERMINAL),
            evidence.launches.map { it.purpose },
        )

        val orphanHarness = harness(
            "terminal-cancelled-orphan",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val orphanFailure = executeExpectingCleanFailure(
            orphanHarness,
            request,
            "orphan terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.PROTOCOL, orphanFailure.failure.kind)
        assertTrue(orphanFailure.message.orEmpty().contains("orphan terminal"))
        assertTrue(orphanHarness.latestTerminalAudit().any {
            it.reason == AcpTerminalAuditReason.UNBOUND_TERMINAL
        })

        val crossSessionHarness = harness(
            "terminal-cross-session-hang",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val crossSessionFailure = executeExpectingCleanFailure(
            crossSessionHarness,
            request,
            "cross-session terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(
            AgentFailureKind.PROTOCOL,
            crossSessionFailure.failure.kind,
            "fatal terminal callback violations must win even when the peer leaves session/prompt pending",
        )
        assertTrue(
            crossSessionFailure.message.orEmpty().contains("crossed session boundaries"),
            crossSessionFailure.message,
        )
        assertTrue(crossSessionHarness.latestTerminalAudit().none {
            it.reason == AcpTerminalAuditReason.CROSS_SESSION
        }, "raw session correlation must fail before SDK or terminal-broker dispatch")

        val missingSessionHarness = harness(
            "terminal-missing-session-hang",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val missingSessionFailure = executeExpectingCleanFailure(
            missingSessionHarness,
            request,
            "missing-session terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingSessionFailure.failure.kind)
        assertTrue(
            missingSessionFailure.message.orEmpty().contains("requires string params.sessionId"),
            missingSessionFailure.message,
        )
        assertTrue(missingSessionHarness.latestTerminalAudit().isEmpty())

        source.writeText("original artifact\n")
        val nearWallPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(SLEEP),
                    listOf("30"),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(10),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val nearWallHarness = harness(
            "terminal-near-wall",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000, shutdown = 1_000),
            terminalPolicy = nearWallPolicy,
        )
        val nearWallFailure = executeExpectingCleanFailure(
            nearWallHarness,
            request.withWallClockTimeout(Duration.ofSeconds(3)),
            "near-wall terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.TIMEOUT, nearWallFailure.failure.kind)
        assertEquals("near-wall terminal requested\n", source.readText(), "fixture never reached terminal/create")
        val nearWallAudit = nearWallHarness.latestTerminalAudit()
        val deadlineTermination = nearWallAudit.firstOrNull { it.reason == AcpTerminalAuditReason.TIMEOUT }
        assertNotNull(deadlineTermination, "near-wall terminal work did not observe the shared execution deadline")
        nearWallAudit.firstOrNull { it.reason == AcpTerminalAuditReason.CREATED }?.let { created ->
            assertTrue(
                created.sequence < deadlineTermination.sequence,
                "execution-wide timeout evidence must follow a successfully created terminal",
            )
        }
    }

    @Test
    fun `fake agent exercises terminal create kill wait output and release lifecycle`() {
        val parent = createTempDirectory("acp-terminal-kill-wire-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("project", parent)
        val artifact = staging.path.resolve("contract/artifact.txt")
        artifact.parent.createDirectories()
        artifact.writeText("original artifact\n")
        val forbiddenCanary = staging.path.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val request = AgentExecutionRequest(
            objective = "exercise the protocol fixture",
            workspaceRoots = listOf(staging.workspaceRoot),
            contextInputs = listOf(
                decompengine.agent.AgentContextInput("contract", "protocol evidence"),
            ),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "contract/artifact.txt"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
                setOf(
                    AgentOperation.READ_FILE,
                    AgentOperation.EXECUTE_COMMAND,
                    AgentOperation.REQUEST_PERMISSION,
                ),
            ),
        )
        val terminalPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(SLEEP),
                    listOf("30"),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(3),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val harness = harness(
            "terminal-kill-lifecycle",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )

        val result = harness.execute(request)

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        val reasons = harness.latestTerminalAudit().map { it.reason }.toSet()
        assertTrue(AcpTerminalAuditReason.CREATED in reasons)
        assertTrue(AcpTerminalAuditReason.TOOL_BOUND in reasons)
        assertTrue(AcpTerminalAuditReason.KILLED in reasons)
        assertTrue(AcpTerminalAuditReason.EXIT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.OUTPUT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.RELEASED in reasons)
        assertTrue(harness.latestTerminalAudit().all { it.networkIsolated })
        assertEquals(AcpPermissionAuditOutcome.DENIED, harness.latestPermissionAudit().single().outcome)
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, harness.latestPermissionAudit().single().reason)
        assertEquals(1, result.usage?.toolCalls)
        assertEquals("original artifact\n", artifact.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, forbiddenCanary.readText())
        assertCleanTermination(harness)
    }

    @Test
    fun `unsupported versions and missing configured capabilities fail actionably`() {
        val versionFixture = fixture(genericContract = true)
        val versionHarness = harness("unsupported-version")
        val versionFailure = executeExpectingCleanFailure(
            versionHarness,
            versionFixture.request,
            "unsupported version",
            versionFixture,
        )
        assertEquals(
            AgentFailureKind.PROTOCOL,
            versionFailure.failure.kind,
            "${versionFailure.message}; ${versionFailure.failure.details}; cause=${versionFailure.cause}",
        )
        assertTrue(versionFailure.message.orEmpty().contains("stable v1"))
        assertEquals("2", versionFailure.failure.details["offeredVersion"])

        val capabilityFixture = fixture(genericContract = true)
        val capabilityHarness = harness(
            "success",
            requiredCapabilities = setOf(AcpRequiredAgentCapability.LOAD_SESSION),
        )
        val capabilityFailure = executeExpectingCleanFailure(
            capabilityHarness,
            capabilityFixture.request,
            "missing required capability",
            capabilityFixture,
        )
        assertEquals(AgentFailureKind.CONFIGURATION, capabilityFailure.failure.kind)
        assertEquals("loadSession", capabilityFailure.failure.details["missingCapabilities"])

        val missingVersionFixture = fixture(genericContract = true)
        val missingVersionHarness = harness("missing-protocol-version")
        val missingVersion = executeExpectingCleanFailure(
            missingVersionHarness,
            missingVersionFixture.request,
            "missing protocol version",
            missingVersionFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingVersion.failure.kind)
    }

    @Test
    fun `unknown duplicate and late JSON-RPC response ids are rejected before SDK dispatch`() {
        listOf("unknown-response-id", "duplicate-response-id", "late-response-id").forEach { mode ->
            val fixture = fixture(genericContract = true)
            val harness = harness(mode)
            val failure = executeExpectingCleanFailure(harness, fixture.request, mode, fixture)

            assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind, mode)
            assertTrue(failure.message.orEmpty().contains("response id"), mode)
        }
    }

    @Test
    fun `pipelined callback ids unknown peer methods and denied writes follow JSON-RPC`() {
        val pipelinedFixture = fixture(genericContract = true)
        val pipelinedHarness = harness("pipelined-callbacks")

        val pipelined = pipelinedHarness.execute(pipelinedFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, pipelined.stopReason)
        assertEquals(listOf(0L, 1L), pipelinedHarness.latestFilesystemAudit().map { it.sequence })
        assertEquals(
            setOf("contract/artifact.txt"),
            pipelinedHarness.latestFilesystemAudit().map { assertNotNull(it.policyPath).relativePath }.toSet(),
        )
        assertEquals("original artifact\n", pipelinedFixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, pipelinedFixture.forbiddenCanary.readText())
        assertCleanTermination(pipelinedHarness, "pipelined callbacks")

        val unknownFixture = fixture(genericContract = true)
        val unknownHarness = harness("unknown-methods")

        val unknown = unknownHarness.execute(unknownFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, unknown.stopReason)
        assertTrue(unknownHarness.latestFilesystemAudit().isEmpty())
        assertEquals("original artifact\n", unknownFixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, unknownFixture.forbiddenCanary.readText())
        assertCleanTermination(unknownHarness, "unknown methods")

        val deniedFixture = fixture(genericContract = true)
        val canaryBefore = Files.readAllBytes(deniedFixture.forbiddenCanary)
        val deniedHarness = harness("forbidden-write")

        val denied = deniedHarness.execute(deniedFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, denied.stopReason)
        assertTrue(canaryBefore.contentEquals(Files.readAllBytes(deniedFixture.forbiddenCanary)))
        val denial = deniedHarness.latestFilesystemAudit().single()
        assertEquals("fs/write_text_file", denial.method)
        assertEquals("forbidden-canary.txt", assertNotNull(denial.policyPath).relativePath)
        assertEquals(AcpFilesystemAuditOutcome.DENIED, denial.outcome)
        assertEquals(AcpFilesystemAuditReason.POLICY_DENIED, denial.reason)
        assertFalse(denial.toString().contains(deniedFixture.workspace.toString()))
        assertFalse(denial.toString().contains("attempted overwrite payload"))
        assertCleanTermination(deniedHarness, "denied write")
    }

    @Test
    fun `malformed stdout clean EOF and nonzero crashes are distinct failures`() {
        val malformedInitializeFixture = fixture(genericContract = true)
        val malformedInitializeHarness = harness("malformed-initialize")
        val malformedInitialize = executeExpectingCleanFailure(
            malformedInitializeHarness,
            malformedInitializeFixture.request,
            "malformed initialize",
            malformedInitializeFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, malformedInitialize.failure.kind)

        val malformedFixture = fixture(genericContract = true)
        val malformedHarness = harness("malformed-prompt")
        val malformed = executeExpectingCleanFailure(
            malformedHarness,
            malformedFixture.request,
            "malformed prompt",
            malformedFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, malformed.failure.kind)
        assertTrue(malformed.message.orEmpty().contains("malformed JSON-RPC"))

        listOf(
            "contaminated-prompt",
            "missing-jsonrpc-prompt",
            "wrong-jsonrpc-prompt",
            "numeric-jsonrpc-prompt",
            "result-and-error-prompt",
        ).forEach { mode ->
            val strictFixture = fixture(genericContract = true)
            val strictHarness = harness(mode)
            val strictFailure = executeExpectingCleanFailure(
                strictHarness,
                strictFixture.request,
                mode,
                strictFixture,
            )
            assertEquals(AgentFailureKind.PROTOCOL, strictFailure.failure.kind, mode)
            assertTrue(strictFailure.message.orEmpty().contains("malformed JSON-RPC"), mode)
        }

        val invalidUtf8Fixture = fixture(genericContract = true)
        val invalidUtf8Harness = harness("invalid-utf8-prompt")
        val invalidUtf8 = executeExpectingCleanFailure(
            invalidUtf8Harness,
            invalidUtf8Fixture.request,
            "invalid UTF-8",
            invalidUtf8Fixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, invalidUtf8.failure.kind)
        assertTrue(invalidUtf8.message.orEmpty().contains("invalid UTF-8"))

        val invalidUpdateFixture = fixture(genericContract = true)
        val invalidUpdateHarness = harness("invalid-update")
        val invalidUpdate = executeExpectingCleanFailure(
            invalidUpdateHarness,
            invalidUpdateFixture.request,
            "invalid update",
            invalidUpdateFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, invalidUpdate.failure.kind)
        assertTrue(invalidUpdate.message.orEmpty().contains("empty tool call id"))

        val negativeUsageFixture = fixture(genericContract = true)
        val negativeUsageHarness = harness("negative-usage")
        val negativeUsage = executeExpectingCleanFailure(
            negativeUsageHarness,
            negativeUsageFixture.request,
            "negative usage",
            negativeUsageFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, negativeUsage.failure.kind)
        assertTrue(negativeUsage.message.orEmpty().contains("invalid prompt usage"))

        val missingUsageFixture = fixture(genericContract = true)
        val missingUsageHarness = harness("missing-usage")
        val missingUsage = executeExpectingCleanFailure(
            missingUsageHarness,
            missingUsageFixture.request.withTokenLimits(1_000, 1_000),
            "missing usage",
            missingUsageFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingUsage.failure.kind)
        assertTrue(missingUsage.message.orEmpty().contains("inputTokens,outputTokens"))

        val eofFixture = fixture(genericContract = true)
        val eofHarness = harness("eof-prompt")
        val eof = executeExpectingCleanFailure(eofHarness, eofFixture.request, "clean EOF", eofFixture)
        assertEquals(AgentFailureKind.TRANSPORT, eof.failure.kind)

        val crashFixture = fixture(genericContract = true)
        val crashHarness = harness("crash-prompt")
        val crash = executeExpectingCleanFailure(crashHarness, crashFixture.request, "prompt crash", crashFixture)
        assertEquals(AgentFailureKind.PROCESS_CRASH, crash.failure.kind)
        assertEquals("23", crash.failure.details["exitCode"])

        val initializeCrashFixture = fixture(genericContract = true)
        val initializeCrashHarness = harness("crash-after-initialize")
        val initializeCrash = executeExpectingCleanFailure(
            initializeCrashHarness,
            initializeCrashFixture.request,
            "initialize crash",
            initializeCrashFixture,
        )
        assertEquals(AgentFailureKind.PROCESS_CRASH, initializeCrash.failure.kind)
        assertEquals("17", initializeCrash.failure.details["exitCode"])
    }

    @Test
    fun `literal physical newline inside a JSON string fails closed and cleans containment`() {
        val fixture = fixture(genericContract = true, wallMillis = 2_000)
        val harness = harness(
            "physical-newline-in-string",
            timeouts = timeouts(request = 1_000, shutdown = 600),
        )

        val failure = assertBoundedCleanProtocolFailure(fixture, harness, maximumWallMillis = 5_000)

        assertTrue(failure.message.orEmpty().contains("malformed JSON-RPC"), failure.message)
    }

    @Test
    fun `startup request and idle waits are independently bounded`() {
        val startupFixture = fixture(genericContract = true)
        val startupHarness = harness(
            "no-initialize",
            timeouts = timeouts(startup = 180, request = 1_000),
        )
        val startup = executeExpectingCleanFailure(
            startupHarness,
            startupFixture.request,
            "initialize timeout",
            startupFixture,
        )
        assertEquals(AgentFailureKind.TIMEOUT, startup.failure.kind)
        assertTrue(startup.message.orEmpty().contains("initialize"))

        val requestFixture = fixture(genericContract = true)
        val requestHarness = harness(
            "no-session-response",
            timeouts = timeouts(startup = 1_000, request = 180),
        )
        val request = executeExpectingCleanFailure(
            requestHarness,
            requestFixture.request,
            "session request timeout",
            requestFixture,
        )
        assertEquals(AgentFailureKind.TIMEOUT, request.failure.kind)
        assertTrue(request.message.orEmpty().contains("session/new"))

        val idleFixture = fixture(idleMillis = 150, genericContract = true)
        val idleHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 1_000, request = 2_000),
        )
        val idle = executeExpectingCleanFailure(idleHarness, idleFixture.request, "idle timeout", idleFixture)
        assertEquals(AgentFailureKind.TIMEOUT, idle.failure.kind)
        assertTrue(idle.message.orEmpty().contains("idle"))
        val idleDiagnostics = assertNotNull(idleHarness.latestDiagnostics())
        assertFalse(idleDiagnostics.forcedTermination)

        // The wall budget includes the authenticated workspace snapshot and outer sandbox launch.
        // Leave enough headroom for a contended hosted runner while keeping idle out of contention.
        val wallFixture = fixture(idleMillis = 20_000, wallMillis = 5_000, genericContract = true)
        val wallHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 2_000, request = 10_000),
        )
        val wall = executeExpectingCleanFailure(wallHarness, wallFixture.request, "wall timeout", wallFixture)
        assertEquals(AgentFailureKind.TIMEOUT, wall.failure.kind)
        assertTrue(wall.message.orEmpty().contains("wall-clock"), wall.message)
    }

    @Test
    fun `a blocking event callback cannot prevent the wall deadline and process cleanup`() {
        // The callback must be reached before the wall clock expires; prelaunch containment can
        // legitimately take seconds under hosted contention and is part of the same wall budget.
        val fixture = fixture(idleMillis = 20_000, wallMillis = 5_000, genericContract = true)
        val harness = harness(
            "update-then-hang",
            timeouts = timeouts(startup = 2_000, request = 10_000, shutdown = 600),
        )
        val events = mutableListOf<AgentExecutionEvent>()
        val callbackEntered = CountDownLatch(1)
        val releaseCallback = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(fixture.request) { event ->
                    events += event
                    callbackEntered.countDown()
                    releaseCallback.await()
                }
            }
            assertTrue(callbackEntered.await(10, TimeUnit.SECONDS), "fixture never delivered an event")

            val failure = try {
                execution.get(10, TimeUnit.SECONDS)
                error("execution unexpectedly succeeded")
            } catch (wrapped: ExecutionException) {
                wrapped.cause as? AgentExecutionException ?: throw wrapped
            }
            assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
            assertTrue(failure.message.orEmpty().contains("wall-clock"))
            assertCleanTermination(
                harness = harness,
                context = "blocked callback timeout",
                fixture = fixture,
                failure = failure,
                events = events,
            )
        } finally {
            releaseCallback.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun `caller cancellation sends session cancel and returns a cancelled result`() {
        val fixture = fixture(includeReadyPath = true, genericContract = true)
        val cancellation = AgentCancellationSource()
        val request = fixture.request.withCancellation(cancellation)
        val ready = fixture.workspace.resolve("ready")
        val harness = harness(
            "wait-for-cancel",
            ready = ready,
            timeouts = timeouts(startup = 1_000, request = 3_000),
        )
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(request, events::add)
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
            assertEquals("original artifact\n", fixture.source.readText())
            assertEquals(AgentFileChangeKind.CREATED, result.changes.single().kind)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination)
            assertCleanTermination(
                harness = harness,
                context = "cooperative cancellation",
                fixture = fixture,
                events = events,
            )
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
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode,
                timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 1_000),
            )

            val failure = executeExpectingCleanFailure(harness, fixture.request, mode, fixture)

            assertEquals(AgentFailureKind.PROCESS_CRASH, failure.failure.kind, mode)
            assertEquals(expectedExit, failure.failure.details["exitCode"], mode)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination, mode)
            assertFalse(diagnostics.rootTerminationRequested, mode)
            assertEquals(expectedExit.toInt(), diagnostics.exitCode, mode)
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

        assertTrue(childPidPath.readText().trim().toLong() > 0L)
        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.forcedTermination)
        assertTrue(diagnostics.rootTerminationRequested)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `stdout frame total and retained stderr sizes are bounded independently`() {
        val frameFixture = fixture(genericContract = true)
        val frameHarness = harness("oversized-frame-prompt", maximumFrameBytes = 1_024)
        val frameFailure = executeExpectingCleanFailure(
            frameHarness,
            frameFixture.request,
            "individual frame limit",
            frameFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, frameFailure.failure.kind)
        assertTrue(frameFailure.message.orEmpty().contains("frame limit"))

        val totalFixture = fixture(maximumOutputBytes = 1_024, genericContract = true)
        val totalHarness = harness("oversized-frame-prompt", maximumFrameBytes = 128 * 1024)
        val totalFailure = executeExpectingCleanFailure(
            totalHarness,
            totalFixture.request,
            "aggregate stdout limit",
            totalFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, totalFailure.failure.kind)
        assertTrue(totalFailure.message.orEmpty().contains("execution limit"))

        val stderrFixture = fixture(genericContract = true)
        val stderrHarness = harness("stderr-overflow")
        val stderrEvents = mutableListOf<AgentExecutionEvent>()
        stderrHarness.execute(stderrFixture.request, stderrEvents::add)
        val diagnostics = assertNotNull(stderrHarness.latestDiagnostics())
        assertTrue(diagnostics.stderrTruncated)
        assertTrue(diagnostics.stderr.toByteArray().size <= 64 * 1024)
        assertCleanTermination(
            harness = stderrHarness,
            context = "retained stderr limit",
            fixture = stderrFixture,
            events = stderrEvents,
        )

        val aggregateLimit = 16L * 1024
        val floodFixture = fixture(maximumOutputBytes = aggregateLimit, genericContract = true)
        val floodHarness = harness(
            "stderr-flood",
            timeouts = timeouts(request = 2_000, shutdown = 1_000),
        )
        val floodFailure = executeExpectingCleanFailure(
            floodHarness,
            floodFixture.request,
            "stderr flood",
            floodFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, floodFailure.failure.kind)
        assertTrue(floodFailure.message.orEmpty().contains("stdout and stderr"))
        val floodDiagnostics = assertNotNull(floodHarness.latestDiagnostics())
        assertEquals(aggregateLimit, floodDiagnostics.producedOutputLimitBytes)
        assertTrue(floodDiagnostics.producedOutputBytes > aggregateLimit)
        assertTrue(floodDiagnostics.outputLimitExceeded)
        assertTrue(floodDiagnostics.rootTerminationRequested)
        val floodEvidence = assertNotNull(floodHarness.latestSandboxEvidence())
        assertEquals(floodDiagnostics.producedOutputBytes, floodEvidence.outerProcessOutput?.observedBytes)
        assertTrue(floodEvidence.outerProcessOutput?.limitExceeded == true)

        listOf("response-then-stderr-burst", "response-then-stdout-burst").forEach { mode ->
            val shutdownBurstFixture = fixture(
                maximumOutputBytes = aggregateLimit,
                genericContract = true,
            )
            val shutdownBurstHarness = harness(
                mode,
                timeouts = timeouts(request = 2_000, shutdown = 1_200),
            )
            val shutdownBurstFailure = executeExpectingCleanFailure(
                shutdownBurstHarness,
                shutdownBurstFixture.request,
                mode,
                shutdownBurstFixture,
            )
            assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, shutdownBurstFailure.failure.kind, mode)
            val shutdownBurstDiagnostics = assertNotNull(shutdownBurstHarness.latestDiagnostics(), mode)
            assertTrue(shutdownBurstDiagnostics.outputLimitExceeded, mode)
            assertTrue(shutdownBurstDiagnostics.producedOutputBytes > aggregateLimit, mode)
            assertTrue(
                shutdownBurstHarness.latestSandboxEvidence()?.outerProcessOutput?.limitExceeded == true,
                mode,
            )
        }
    }

    @Test
    fun `protocol frame flood is bounded before SDK dispatch and leaves no process or workspace residue`() {
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(Path.of("/usr/bin/true"), maximumProtocolFrames = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumProtocolFrames = MAXIMUM_ACP_PROTOCOL_FRAMES + 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumFrameBytes = MAXIMUM_ACP_FRAME_BYTES + 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumStderrBytes = MAXIMUM_ACP_STDERR_BYTES + 1,
            )
        }

        val fixture = fixture(
            wallMillis = 2_000,
            maximumOutputBytes = Long.MAX_VALUE,
            genericContract = true,
        )
        val harness = harness(
            "protocol-frame-flood",
            timeouts = timeouts(request = 1_000, shutdown = 600),
            maximumProtocolFrames = 8,
        )
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        try {
            val execution = executor.submit<AgentExecutionException> {
                assertFailsWith { harness.execute(fixture.request, events::add) }
            }
            val failure = try {
                execution.get(5, TimeUnit.SECONDS)
            } catch (wrapped: ExecutionException) {
                throw wrapped.cause ?: wrapped
            }

            assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
            assertTrue(failure.message.orEmpty().contains("8-frame protocol limit"), failure.message)
            assertEquals("original artifact\n", fixture.source.readText())
            assertCleanTermination(
                harness = harness,
                context = "protocol frame flood",
                fixture = fixture,
                failure = failure,
                events = events,
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `workspace snapshot limit rejects oversized input before launching an agent`() {
        val fixture = fixture()
        fixture.source.writeText("x".repeat(8 * 1024 * 1024 + 1))
        val receipt = harness("success").executeReceipt(fixture.request)
        val failure = assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.kind)
        assertEquals("initial-workspace-snapshot", failure.details["phase"])
        assertEquals("file-bytes", failure.details["limit"])
        val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.WORKSPACE_SNAPSHOT, evidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, evidence.cleanupDisposition)
        assertNull(evidence.diagnostics)
        assertNull(evidence.completeExecutionEvidence)
    }

    @Test
    fun `completed agent turn cannot return changes when final snapshot exceeds its limit`() {
        val fixture = fixture(genericContract = true, wallMillis = 15_000)
        val injected = java.util.concurrent.atomic.AtomicBoolean(false)
        val injection = AgentCancellation {
            val duringSnapshot = Thread.currentThread().stackTrace.any { frame ->
                frame.className == WorkspaceSnapshotBudget::class.java.name && frame.methodName == "checkpoint"
            }
            if (!injected.get() && duringSnapshot && fixture.source.readText() == "updated artifact\n" &&
                injected.compareAndSet(false, true)) {
                fixture.source.writeText("x".repeat(8 * 1024 * 1024 + 1))
            }
            false
        }
        val receipt = harness("missing-usage").executeReceipt(fixture.request.withCancellation(injection))
        assertTrue(injected.get(), "fixture did not reach the post-cleanup boundary")
        val failure = assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.kind)
        assertEquals("final-workspace-snapshot", failure.details["phase"])
        assertEquals("file-bytes", failure.details["limit"])
        assertNotNull(failure.session)
        assertEquals(8L * 1024 * 1024 + 1, java.nio.file.Files.size(fixture.source))
        val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
        assertNull(evidence.completeExecutionEvidence)
        val diagnostics = assertNotNull(evidence.diagnostics)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `final metadata rejection retains session and cleanup evidence`() {
        val fixture = fixture(genericContract = true, wallMillis = 15_000)
        val injected = java.util.concurrent.atomic.AtomicBoolean(false)
        val injection = AgentCancellation {
            val duringSnapshot = Thread.currentThread().stackTrace.any { frame ->
                frame.className == WorkspaceSnapshotBudget::class.java.name && frame.methodName == "checkpoint"
            }
            if (!injected.get() && duringSnapshot && fixture.source.readText() == "updated artifact\n" &&
                injected.compareAndSet(false, true)) {
                val permissions = java.nio.file.Files.getPosixFilePermissions(fixture.source).toMutableSet()
                val execute = java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE
                if (!permissions.add(execute)) permissions.remove(execute)
                java.nio.file.Files.setPosixFilePermissions(fixture.source, permissions)
            }
            false
        }
        val receipt = harness("missing-usage").executeReceipt(fixture.request.withCancellation(injection))
        assertTrue(injected.get(), "fixture did not reach the post-cleanup boundary")
        val failure = assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure
        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, failure.kind)
        assertEquals("final-workspace-snapshot", failure.details["phase"])
        assertEquals("file-metadata-changed", failure.details["reason"])
        assertNotNull(failure.session)
        assertEquals("updated artifact\n", fixture.source.readText())
        val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, evidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, evidence.cleanupDisposition)
        assertNull(evidence.completeExecutionEvidence)
        val diagnostics = assertNotNull(evidence.diagnostics)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `workspace snapshots stream large files and observe prelaunch cancellation and wall time`() {
        val largeFixture = fixture()
        largeFixture.source.writeText("x".repeat(2 * 1024 * 1024))

        val largeResult = harness("success").execute(largeFixture.request)

        assertEquals(AgentFileChangeKind.MODIFIED, largeResult.changes.single().kind)
        assertNotNull(largeResult.changes.single().beforeSha256)

        val cancellation = AgentCancellation {
            // Admission also polls cancellation. Target the actual snapshot boundary rather
            // than depending on how many cancellation checks precede workspace traversal.
            Thread.currentThread().stackTrace.any { frame ->
                frame.className == "decompengine.acp.WorkspaceSnapshotBudget" && frame.methodName == "checkpoint"
            }
        }
        val cancelledFixture = fixture()
        val cancelledHarness = harness("success")

        val cancelledReceipt = cancelledHarness.executeReceipt(
            cancelledFixture.request.withCancellation(cancellation),
        )
        val cancelled = assertIs<AgentExecutionOutcome.Returned>(cancelledReceipt.outcome).result
        val cancelledEvidence = assertIs<AcpInvocationEvidenceSnapshot>(cancelledReceipt.providerEvidence)

        assertEquals(AgentStopReason.CANCELLED, cancelled.stopReason)
        assertTrue(cancelled.summary.orEmpty().contains("initial workspace snapshot"))
        assertEquals(AcpExecutionLifecyclePhase.WORKSPACE_SNAPSHOT, cancelledEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, cancelledEvidence.cleanupDisposition)
        assertNull(cancelledEvidence.diagnostics)
        assertNull(cancelledEvidence.completeExecutionEvidence)
        assertEquals(null, cancelledHarness.latestDiagnostics())

        val launchCancellationObserved = java.util.concurrent.atomic.AtomicBoolean(false)
        val launchCancellation = AgentCancellation {
            val duringActualBoundaryLaunch = Thread.currentThread().stackTrace.any { frame ->
                frame.className == LinuxBubblewrapBoundary::class.java.name && frame.methodName == "launch"
            }
            if (duringActualBoundaryLaunch) launchCancellationObserved.set(true)
            duringActualBoundaryLaunch
        }
        val launchCancelledHarness = harness("success")
        val launchFixture = fixture()
        val launchReceipt = launchCancelledHarness.executeReceipt(
            launchFixture.request.withCancellation(launchCancellation),
        )
        val launchCancelled = assertIs<AgentExecutionOutcome.Returned>(launchReceipt.outcome).result
        val launchEvidence = assertIs<AcpInvocationEvidenceSnapshot>(launchReceipt.providerEvidence)
        assertTrue(launchCancellationObserved.get(), "fixture did not reach the real sandbox launch checkpoint")
        assertEquals(AgentStopReason.CANCELLED, launchCancelled.stopReason)
        assertTrue(launchCancelled.summary.orEmpty().contains("sandbox launch"))
        assertEquals(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH, launchEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.UNVERIFIED, launchEvidence.cleanupDisposition)
        assertNull(launchEvidence.completeExecutionEvidence)
        assertNull(launchCancelledHarness.latestDiagnostics())
        assertNull(launchCancelledHarness.latestSandboxEvidence())

        val evidenceCancellationObserved = java.util.concurrent.atomic.AtomicBoolean(false)
        val evidenceCancellation = AgentCancellation {
            val duringEvidenceConstruction = Thread.currentThread().stackTrace.any { frame ->
                frame.className == LinuxBubblewrapBoundary::class.java.name && frame.methodName == "evidence"
            }
            if (duringEvidenceConstruction) evidenceCancellationObserved.set(true)
            duringEvidenceConstruction
        }
        val evidenceCancelledHarness = harness("success")
        val evidenceFixture = fixture()
        val evidenceReceipt = evidenceCancelledHarness.executeReceipt(
            evidenceFixture.request.withCancellation(evidenceCancellation),
        )
        val evidenceCancelled = assertIs<AgentExecutionOutcome.Returned>(evidenceReceipt.outcome).result
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(evidenceReceipt.providerEvidence)
        assertTrue(
            evidenceCancellationObserved.get(),
            "fixture did not reach post-launch evidence construction",
        )
        assertEquals(AgentStopReason.CANCELLED, evidenceCancelled.stopReason)
        assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, invocation.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition)
        assertNull(invocation.completeExecutionEvidence)
        val evidenceCancellationDiagnostics = assertNotNull(invocation.diagnostics)
        assertTrue(evidenceCancellationDiagnostics.remainingProcessIds.isEmpty())
        assertTrue(evidenceCancellationDiagnostics.sandboxCleanupVerified)
        assertProcessStopped(evidenceCancellationDiagnostics.pid)

        val timeoutFixture = fixture()
        val timeoutHarness = harness("success")
        val timeout = assertFailsWith<AgentExecutionException> {
            timeoutHarness.execute(timeoutFixture.request.withWallClockTimeout(Duration.ofNanos(1)))
        }
        assertEquals(AgentFailureKind.TIMEOUT, timeout.failure.kind)
        assertEquals(mapOf("phase" to "scheduler", "reason" to "requestDeadline"), timeout.failure.details)
        val timeoutEvidence = assertIs<AcpInvocationEvidenceSnapshot>(assertNotNull(timeout.receipt).providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.REQUEST_BOUND, timeoutEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, timeoutEvidence.cleanupDisposition)
        assertNull(timeoutEvidence.completeExecutionEvidence)
        assertEquals(null, timeoutHarness.latestDiagnostics())

    }

    @Test
    fun `authentication-required JSON-RPC error is typed and does not leak the process`() {
        val fixture = fixture(genericContract = true)
        val harness = harness("auth-required")
        val failure = executeExpectingCleanFailure(harness, fixture.request, "authentication required", fixture)

        assertEquals(AgentFailureKind.AUTHENTICATION, failure.failure.kind)
        assertEquals("-32000", failure.failure.details["rpcCode"])
        assertTrue(failure.message.orEmpty().contains("configure the external agent"))
    }

    @Test
    fun `official ACP filesystem callbacks enforce policy and retain metadata-only audit`() {
        val fixture = fixture()
        val harness = harness("fs-read-write")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("new source through broker\n", fixture.source.readText())
        assertEquals(AgentFileChangeKind.MODIFIED, result.changes.single().kind)
        val audit = harness.latestFilesystemAudit()
        assertEquals(listOf(0L, 1L), audit.map { it.sequence })
        assertEquals(List(2) { "fixture-session" }, audit.map { it.sessionId })
        assertEquals(listOf("fs/read_text_file", "fs/write_text_file"), audit.map { it.method })
        assertEquals(List(2) { "src/module.c" }, audit.map { assertNotNull(it.policyPath).relativePath })
        assertTrue(audit.all { it.outcome == AcpFilesystemAuditOutcome.ALLOWED })
        assertFalse(audit.toString().contains(fixture.workspace.toString()))
        assertFalse(audit.toString().contains("new source through broker"))
        assertProcessStopped(assertNotNull(harness.latestDiagnostics()).pid)
    }

    @Test
    fun `captured repair writes traverse ACP without a writable host workspace`() {
        val harness = harness("repair-direct-write")
        val initial = mapOf("src/module.c" to "old source\n".toByteArray())
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))

        val execution = CapturedRepairStagingAuthority.execute(
            harness = harness,
            initialFiles = initial,
            writablePaths = initial.keys,
            budget = RepairResourceBudget(),
            requestFactory = ::capturedRepairRequest,
            onEvent = {},
        )

        assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
        assertContentEquals("new source\n".toByteArray(), execution.files.getValue("src/module.c"))
        val change = execution.result.changes.single()
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
        assertEquals("src/module.c", change.path.relativePath)
        val write = harness.latestFilesystemAudit().single()
        assertEquals("fs/write_text_file", write.method)
        assertEquals(AcpFilesystemAuditOutcome.ALLOWED, write.outcome)
        assertEquals(AcpFilesystemAuditReason.COMPLETED, write.reason)

        // The direct sandbox write in this fixture is intentionally different from the callback
        // body above. It dies with the namespace and cannot enter the host-owned captured result.
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
        val evidence = assertNotNull(harness.latestSandboxEvidence())
        assertTrue(evidence.outerAgentContained)
        assertTrue(evidence.networkIsolated)
        assertTrue(evidence.cgroupV2PidsLimited)
        assertTrue(evidence.cgroupV2MemoryLimited)
        assertTrue(evidence.cgroupV2CpuLimited)
        assertTrue(evidence.authorities.isEmpty(), "captured repair must not bind a host staging authority")
        assertEquals(AcpSandboxLaunchPurpose.OUTER_AGENT, evidence.launches.single().purpose)
        assertTrue(evidence.outerAgentLimits.maximumFileBytes > 0)
        assertTrue(evidence.outerAgentLimits.maximumAddressSpaceBytes > 0)
        assertTrue(evidence.outerAgentLimits.maximumCpuSeconds > 0)
    }

    @Test
    fun `captured repair rejects an oversized ACP write and permits a bounded retry`() {
        val harness = harness("repair-quota-retry")
        val initial = mapOf("src/module.c" to "old source\n".toByteArray())

        val execution = CapturedRepairStagingAuthority.execute(
            harness = harness,
            initialFiles = initial,
            writablePaths = initial.keys,
            budget = RepairResourceBudget(maximumPatchBytes = 4),
            requestFactory = ::capturedRepairRequest,
            onEvent = {},
        )

        assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
        assertContentEquals("fit\n".toByteArray(), execution.files.getValue("src/module.c"))
        assertContentEquals("old source\n".toByteArray(), initial.getValue("src/module.c"))
        assertEquals(4L, execution.result.changes.single().sizeBytes)
        assertEquals(
            listOf(AcpFilesystemAuditOutcome.DENIED, AcpFilesystemAuditOutcome.ALLOWED),
            harness.latestFilesystemAudit().map { it.outcome },
        )
        assertEquals(
            listOf(AcpFilesystemAuditReason.RESOURCE_LIMIT, AcpFilesystemAuditReason.COMPLETED),
            harness.latestFilesystemAudit().map { it.reason },
        )
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `filesystem capability advertisement is frozen to each workflow allowlist`() {
        val readFixture = fixture()
        val readRequest = readFixture.request.withPolicy(
            AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "src/module.c"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
            ),
        )
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-read-only").execute(readRequest).stopReason)

        val writeFixture = fixture()
        val writeRequest = writeFixture.request.withPolicy(
            AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "src/module.c"),
                        setOf(AgentOperation.WRITE_FILE),
                    ),
                ),
            ),
        )
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-write-only").execute(writeRequest).stopReason)

        val disabledFixture = fixture()
        val disabledRequest = disabledFixture.request.withPolicy(AgentAccessPolicy(emptyList()))
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-none").execute(disabledRequest).stopReason)
    }

    @Test
    fun `filesystem containment denial crosses the official JSON-RPC boundary without path disclosure`() {
        val fixture = fixture()
        val harness = harness("fs-denied-outside")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        assertEquals("old source\n", fixture.source.readText())
        val decision = harness.latestFilesystemAudit().single()
        assertEquals("fixture-session", decision.sessionId)
        assertEquals("fs/read_text_file", decision.method)
        assertEquals(AcpFilesystemAuditOutcome.DENIED, decision.outcome)
        assertEquals(AcpFilesystemAuditReason.OUTSIDE_WORKSPACE, decision.reason)
        assertNull(decision.policyPath)
        assertFalse(decision.toString().contains(fixture.workspace.parent.toString()))
    }

    @Test
    fun `durable session reload uses the advertised stable v1 method across fresh processes`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        harness("session-persistence", sentinel = "expect-new").executeReceipt(request).requireResult()
        val restored = harness("session-persistence", sentinel = "expect-load").executeReceipt(request).requireResult()
        assertTrue(restored.summary.orEmpty().contains("session/load"))
        assertEquals("fixture-session", restored.session?.resumeReference)
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals(2, journal.completedTurns)
            assertEquals("load-advertised-completed-session", journal.decision)
        }
        assertEquals("old source\n", fixture.source.readText())
    }

    @Test
    fun `agent without load records fresh session fallback instead of conversation restoration`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        repeat(2) { harness("session-persistence-no-load", sentinel = "expect-new").executeReceipt(request).requireResult() }
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals(2, journal.completedTurns)
            assertEquals("new-load-unsupported-project-evidence", journal.decision)
        }
    }

    @Test
    fun `failed load is retained and explicit new-session policy is required before retry`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        harness("session-persistence-load-fails", sentinel = "expect-new").executeReceipt(request).requireResult()
        val failure = harness("session-persistence-load-fails", sentinel = "expect-load").executeReceipt(request)
        assertIs<AgentExecutionOutcome.Failed>(failure.outcome)
        val exception = assertFailsWith<AgentExecutionException> { failure.requireResult() }
        assertTrue(generateSequence<Throwable>(exception) { it.cause }.any { it is decompengine.agent.AgentSessionRecoveryException })
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals("load-failed-no-implicit-fallback", journal.decision)
            assertEquals(1, journal.completedTurns)
        }
        val recreated = decompengine.agent.AgentSessionContinuation(
            continuation.directory, continuation.workflowSha256, continuation.taskId,
            continuation.workspaceFiles, policy = decompengine.agent.AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE,
        )
        harness("session-persistence-load-fails", sentinel = "expect-new")
            .executeReceipt(request.withContinuation(recreated)).requireResult()
        decompengine.agent.AgentSessionJournal.open(recreated).use { journal ->
            assertEquals("new-explicit-project-evidence", journal.decision)
            assertEquals(2, journal.completedTurns)
        }
    }

    private fun continuation(fixture: Fixture) = decompengine.agent.AgentSessionContinuation(
        createTempDirectory("acp-durable-session-"), "a".repeat(64), "module",
        mapOf(AgentWorkspacePath("project", "src/module.c") to sha256(Files.readAllBytes(fixture.source))),
    )

    private fun AgentExecutionRequest.withContinuation(continuation: decompengine.agent.AgentSessionContinuation) =
        AgentExecutionRequest(objective, workspaceRoots, contextInputs, accessPolicy, limits, cancellation, continuation)

    private data class Fixture(
        val workspace: Path,
        val source: Path,
        val forbiddenCanary: Path,
        val request: AgentExecutionRequest,
    )

    private fun capturedRepairRequest(root: AgentWorkspaceRoot): AgentExecutionRequest =
        AgentExecutionRequest(
            objective = "edit the fixture",
            workspaceRoots = listOf(root),
            contextInputs = listOf(AgentContextInput("compiler", "compiler evidence")),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath(root.id, "src/module.c"),
                        setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                    ),
                ),
            ),
            limits = AgentExecutionLimits(
                wallClockTimeout = Duration.ofSeconds(5),
                idleTimeout = Duration.ofSeconds(1),
                maxTurns = 1,
                maxToolCalls = 4,
                maxOutputBytes = 128L * 1024,
            ),
        )

    private fun fixture(
        idleMillis: Long = 1_000,
        includeReadyPath: Boolean = false,
        wallMillis: Long = 5_000,
        maximumOutputBytes: Long = 128 * 1024,
        genericContract: Boolean = false,
    ): Fixture {
        val workspace = createTempDirectory("acp-harness-").toAbsolutePath().normalize()
        val sourceRelativePath = if (genericContract) "contract/artifact.txt" else "src/module.c"
        val source = workspace.resolve(sourceRelativePath)
        source.parent.createDirectories()
        source.writeText(if (genericContract) "original artifact\n" else "old source\n")
        val forbiddenCanary = workspace.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val rules = mutableListOf(
            AgentPathRule(
                AgentWorkspacePath("project", sourceRelativePath),
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
            forbiddenCanary,
            AgentExecutionRequest(
                objective = if (genericContract) "exercise the protocol fixture" else "edit the fixture",
                workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
                contextInputs = listOf(
                    if (genericContract) {
                        decompengine.agent.AgentContextInput("contract", "protocol evidence")
                    } else {
                        decompengine.agent.AgentContextInput("compiler", "compiler evidence")
                    },
                ),
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

    private fun AgentExecutionRequest.withTokenLimits(input: Long?, output: Long?): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            AgentExecutionLimits(
                wallClockTimeout = limits.wallClockTimeout,
                idleTimeout = limits.idleTimeout,
                maxTurns = limits.maxTurns,
                maxToolCalls = limits.maxToolCalls,
                maxOutputBytes = limits.maxOutputBytes,
                maxInputTokens = input,
                maxOutputTokens = output,
            ),
            cancellation,
        )

    private fun AgentExecutionRequest.withPolicy(policy: AgentAccessPolicy): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            policy,
            limits,
            cancellation,
        )

    private fun AgentExecutionRequest.withContextMarker(marker: String): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs + AgentContextInput("turn-marker", marker),
            accessPolicy,
            limits,
            cancellation,
        )

    private fun expectedWirePromptSha256(request: AgentExecutionRequest): String = sha256(
        buildString {
            appendLine(request.objective)
            if (request.contextInputs.isNotEmpty()) {
                appendLine()
                appendLine("Context inputs (immutable):")
                request.contextInputs.forEach { context ->
                    append("--- ").append(context.id).append(" [").append(context.mediaType).append(']')
                    context.description?.let { append(" — ").append(it) }
                    appendLine()
                    appendLine(context.content)
                }
            }
        }.toByteArray(),
    )

    private fun harness(
        mode: String,
        sentinel: String = "literal-argv",
        ready: Path? = null,
        requiredCapabilities: Set<AcpRequiredAgentCapability> = emptySet(),
        timeouts: AcpLifecycleTimeouts = timeouts(),
        maximumFrameBytes: Int = 64 * 1024,
        maximumProtocolFrames: Int = DEFAULT_MAXIMUM_ACP_PROTOCOL_FRAMES,
        terminalPolicy: AcpTerminalExecutionPolicy? = null,
        sessionPreferences: AcpSessionPreferences = AcpSessionPreferences(),
    ): AcpAgentHarness {
        requireLiveSandboxHost()
        val script = Path.of(requireNotNull(javaClass.getResource("/acp/fake_acp_v1_agent.py")).toURI())
        val arguments = mutableListOf("-S", AGENT_SCRIPT_DESTINATION.toString(), mode, sentinel)
        ready?.let { arguments += it.toString() }
        return AcpAgentHarness(
            AcpProcessConfiguration(
                executable = PYTHON,
                arguments = arguments,
                requiredAgentCapabilities = requiredCapabilities,
                timeouts = timeouts,
                maximumFrameBytes = maximumFrameBytes,
                maximumProtocolFrames = maximumProtocolFrames,
                maximumStderrBytes = 64 * 1024,
                implementationId = "scripted-acp-v1",
                sandboxBoundary = liveSandboxConfiguration(
                    listOf(
                        AcpSandboxReadOnlyMount(
                            script,
                            AGENT_SCRIPT_DESTINATION,
                            calculateAcpRuntimeManifestSha256(script),
                        ),
                    ),
                ),
                terminalPolicy = terminalPolicy,
                sessionPreferences = sessionPreferences,
            ),
        ).bindFactoryProvenance(
            AcpHarnessProvenance(
                harness = "acp",
                implementationId = "scripted-acp-v1",
                agentExecutionContractVersion = decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION,
                acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
                configurationSha256 = "0".repeat(64),
                deprecated = false,
            ),
        )
    }

    private fun timeouts(
        startup: Long = 1_000,
        request: Long = 5_000,
        shutdown: Long = 600,
    ): AcpLifecycleTimeouts = AcpLifecycleTimeouts(
        startup = Duration.ofMillis(startup),
        request = Duration.ofMillis(request),
        cancellationGrace = Duration.ofMillis(300),
        transportDrainGrace = Duration.ofMillis(80),
        shutdown = Duration.ofMillis(shutdown),
    )

    private fun missingSandboxConfiguration(): AcpLinuxSandboxConfiguration =
        AcpLinuxSandboxConfiguration(
            bubblewrapExecutable = Path.of("/definitely-absent/decomp-bwrap"),
            resourceLimiterExecutable = Path.of("/definitely-absent/decomp-prlimit"),
            scopeSupervisorExecutable = Path.of("/definitely-absent/decomp-systemd-run"),
            scopeInspectorExecutable = Path.of("/definitely-absent/decomp-systemctl"),
            environmentFdOpenerExecutable = Path.of("/definitely-absent/decomp-bash"),
            sandboxGateHelperExecutable = Path.of("/definitely-absent/decomp-gate-helper"),
            launcherRuntimeMounts = emptyList(),
            agentRuntimeMounts = emptyList(),
            systemdUserRuntimeDirectory = Path.of("/definitely-absent/decomp-runtime"),
            expectedBubblewrapSha256 = "0".repeat(64),
            expectedResourceLimiterSha256 = "0".repeat(64),
            expectedScopeSupervisorSha256 = "0".repeat(64),
            expectedScopeInspectorSha256 = "0".repeat(64),
            expectedEnvironmentFdOpenerSha256 = "0".repeat(64),
            expectedSandboxGateHelperSha256 = "0".repeat(64),
            expectedSandboxGateHelperManifestSha256 = "0".repeat(64),
        )

    private fun liveSandboxConfiguration(
        agentRuntimeMounts: Collection<AcpSandboxReadOnlyMount>,
    ): AcpLinuxSandboxConfiguration = AcpLinuxSandboxConfiguration(
        bubblewrapExecutable = BWRAP,
        resourceLimiterExecutable = PRLIMIT,
        scopeSupervisorExecutable = SYSTEMD_RUN,
        scopeInspectorExecutable = SYSTEMCTL,
        environmentFdOpenerExecutable = BASH,
        sandboxGateHelperExecutable = GATE_HELPER,
        // Protected dynamic-loader/runtime destinations are immutable boundary closure, never
        // request-selected terminal mounts. They are pinned once and evidenced for every launch.
        launcherRuntimeMounts = PYTHON_RUNTIME_MOUNTS,
        agentRuntimeMounts = agentRuntimeMounts,
        systemdUserRuntimeDirectory = USER_RUNTIME,
        agentResourceLimits = AcpSandboxResourceLimits(
            maximumProcesses = 16,
            maximumOpenFiles = 128,
            maximumFileBytes = 64L * 1024 * 1024,
            maximumAddressSpaceBytes = 512L * 1024 * 1024,
            maximumCpuSeconds = 20,
        ),
        expectedBubblewrapSha256 = sha256(BWRAP),
        expectedResourceLimiterSha256 = sha256(PRLIMIT),
        expectedScopeSupervisorSha256 = sha256(SYSTEMD_RUN),
        expectedScopeInspectorSha256 = sha256(SYSTEMCTL),
        expectedEnvironmentFdOpenerSha256 = sha256(BASH),
        expectedSandboxGateHelperSha256 = sha256(GATE_HELPER),
        expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(GATE_HELPER),
    )

    private fun requireLiveSandboxHost() {
        AcpLiveContractHost.requireCapability(
            PYTHON_RUNTIME.isSuccess,
            message = {
                "system Python runtime discovery failed: " +
                    (PYTHON_RUNTIME.exceptionOrNull()?.message ?: "unknown failure")
            },
        )
        val missing = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, PYTHON, ECHO, SLEEP, CC)
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

    private fun javap(type: Class<*>): String {
        val executable = Path.of(System.getProperty("java.home"), "bin", "javap")
        val classPath = Path.of(requireNotNull(type.protectionDomain.codeSource).location.toURI()).toString()
        val process = ProcessBuilder(
            executable.toString(),
            "-p",
            "-classpath",
            classPath,
            type.name,
        ).redirectErrorStream(true).start()
        val exited = process.waitFor(10, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(3, TimeUnit.SECONDS)
        }
        val output = process.inputStream.readAllBytes().toString(Charsets.UTF_8)
        assertTrue(exited, "javap timed out")
        assertEquals(0, process.exitValue(), output)
        return output
    }

    private fun isForbiddenExecutionSeamType(type: Class<*>): Boolean =
        listOf("Boundary", "Launcher", "TestMode").any(type.name::contains)

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun assertBoundedCleanProtocolFailure(
        fixture: Fixture,
        harness: AcpAgentHarness,
        maximumWallMillis: Long,
    ): AgentExecutionException {
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        val startedAt = System.nanoTime()
        val execution = executor.submit<AgentExecutionException> {
            assertFailsWith { harness.execute(fixture.request, events::add) }
        }
        val failure = try {
            execution.get(maximumWallMillis, TimeUnit.MILLISECONDS)
        } catch (wrapped: ExecutionException) {
            throw wrapped.cause ?: wrapped
        } finally {
            execution.cancel(true)
            executor.shutdownNow()
        }
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
        assertTrue(
            elapsedMillis <= maximumWallMillis + 250,
            "protocol failure exceeded its bounded wall time: $elapsedMillis ms",
        )
        assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind)
        assertCleanTermination(
            harness = harness,
            context = "protocol failure",
            fixture = fixture,
            failure = failure,
            events = events,
        )
        return failure
    }

    private fun executeExpectingCleanFailure(
        harness: AcpAgentHarness,
        request: AgentExecutionRequest,
        context: String,
        fixture: Fixture? = null,
        forbiddenCanary: Path? = fixture?.forbiddenCanary,
    ): AgentExecutionException {
        val events = mutableListOf<AgentExecutionEvent>()
        val failure = assertFailsWith<AgentExecutionException>(context) {
            harness.execute(request, events::add)
        }
        val receipt = assertNotNull(failure.receipt, "$context receipt")
        assertEquals(AgentExecutionRequestBinding.capture(request), receipt.requestBinding, context)
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome, context)
        assertCleanTermination(
            harness = harness,
            context = context,
            fixture = fixture,
            forbiddenCanary = forbiddenCanary,
            failure = failure,
            events = events,
        )
        return failure
    }

    private fun assertCleanTermination(
        harness: AcpAgentHarness,
        context: String = "execution",
        fixture: Fixture? = null,
        forbiddenCanary: Path? = fixture?.forbiddenCanary,
        failure: AgentExecutionException? = null,
        events: Collection<AgentExecutionEvent> = emptyList(),
    ) {
        val invocation = failure?.receipt?.providerEvidence as? AcpInvocationEvidenceSnapshot
        if (failure != null) {
            assertNotNull(invocation, "$context invocation evidence")
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, context)
            assertNull(invocation.completeExecutionEvidence, "$context failed outcome archive evidence")
        }
        val diagnostics = assertNotNull(invocation?.diagnostics ?: harness.latestDiagnostics(), context)
        assertTrue(diagnostics.remainingProcessIds.isEmpty(), context)
        assertTrue(diagnostics.sandboxCleanupVerified, context)
        assertProcessStopped(diagnostics.pid)
        forbiddenCanary?.let { canary ->
            assertEquals(FORBIDDEN_CANARY_CONTENT, canary.readText(), context)
        }

        val evidence = assertNotNull(
            invocation?.sandboxEvidence ?: harness.latestSandboxEvidence(),
            "$context sandbox evidence",
        )
        val filesystemEvidence = invocation?.filesystemAudit ?: harness.latestFilesystemAudit()
        val permissionEvidence = invocation?.permissionAudit ?: harness.latestPermissionAudit()
        val terminalEvidence = invocation?.terminalAudit ?: harness.latestTerminalAudit()
        val secretSurfaces = linkedMapOf<String, Any?>(
            "failure message" to failure?.failure?.message,
            "failure details" to failure?.failure?.details,
            "diagnostics" to diagnostics,
            "events" to events,
            "filesystem audit" to filesystemEvidence,
            "permission audit" to permissionEvidence,
            "terminal audit" to terminalEvidence,
            "sandbox evidence" to listOf(
                evidence.provider,
                evidence.providerVersion,
                evidence.providerExecutableSha256,
                evidence.providerExecutableMode,
                evidence.resourceLimiterSha256,
                evidence.scopeSupervisorSha256,
                evidence.scopeInspectorSha256,
                evidence.environmentFdOpenerSha256,
                evidence.securityExecutables,
                evidence.outerAgentLimits,
                evidence.runtimeClosureLimits,
                evidence.cgroupV2PidsLimited,
                evidence.cgroupV2MemoryLimited,
                evidence.cgroupV2CpuLimited,
                evidence.networkIsolated,
                evidence.outerAgentContained,
                evidence.nestedUserNamespacesDisabled,
                evidence.newSession,
                evidence.dieWithParent,
                evidence.policySha256,
                evidence.terminalLimits,
                evidence.launches,
                evidence.authorities,
                evidence.terminalAudit,
                evidence.outerProcessOutput,
                evidence.evidenceSha256,
            ),
        )
        secretSurfaces.forEach { (label, surface) ->
            assertFalse(
                surface.toString().contains(PARENT_SECRET_CANARY),
                "$context retained parent-secret bytes in $label",
            )
        }
    }

    private fun assertProcessStopped(pid: Long) {
        assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false), "process $pid is still alive")
    }

    private companion object {
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val CC: Path = Path.of("/usr/bin/cc")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val PYTHON_RUNTIME: Result<AcpPythonRuntimeLayout> by lazy {
            runCatching { AcpLiveContractHost.discoverPythonRuntime() }
        }
        val PYTHON: Path get() = PYTHON_RUNTIME.getOrThrow().executable
        val ECHO: Path = Path.of("/usr/bin/echo")
        val SLEEP: Path = Path.of("/usr/bin/sleep")
        val AGENT_SCRIPT_DESTINATION: Path = Path.of("/decomp-acp-test/fake_acp_v1_agent.py")
        const val FORBIDDEN_CANARY_CONTENT: String = "forbidden canary must remain unchanged\n"
        val PARENT_SECRET_CANARY: String by lazy {
            requireNotNull(System.getenv("DECOMP_ACP_PARENT_SECRET_CANARY")) {
                "Gradle must inject the ACP parent-secret canary into the test process"
            }
        }
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
        val PYTHON_RUNTIME_MOUNTS: List<AcpSandboxReadOnlyMount> by lazy {
            val runtime = PYTHON_RUNTIME.getOrThrow()
            runtime.nativeRuntimeMounts + runtime.stdlibMounts(
                listOf(
                    "encodings", "json", "re", "collections",
                    "_collections_abc.py", "abc.py", "codecs.py", "copyreg.py", "enum.py",
                    "functools.py", "keyword.py", "operator.py", "reprlib.py", "types.py", "zipimport.py",
                ),
            )
        }
    }
}

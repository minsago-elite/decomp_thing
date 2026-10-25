package decompengine.web

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkspaceRoot
import decompengine.jobs.*
import decompengine.project.sha256
import decompengine.repair.DeclarativeRepairIndexProfile
import decompengine.repair.ModuleRevisionGraph
import decompengine.repair.open
import decompengine.repair.RepairEvidence
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.RepairIndexLayout
import decompengine.repair.RepairModuleEvidence
import decompengine.repair.RepairPublicationMode
import decompengine.repair.RepairRunStatus
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairValidationProof
import decompengine.repair.RevisionRepairMetadata
import decompengine.repair.readProjectRecordedRepairHistory
import decompengine.repair.repairCandidateSourceSha256
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.extension.ExtendWith
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.*

/** Inert engines only: no binary, Ghidra, sandbox or model agent runs in these controls. */
@ExtendWith(RecoveryMatrixEvidence::class)
class WebProductionWorkflowsTest {
    @Test
    fun `explore enforces wall-clock, idle and output limits and stops its child before returning`() = withRoot { root ->
        val engines = FakeEngines()
        val running = AtomicBoolean()
        fun outcome(limits: WorkflowExecutionLimits, body: (Path) -> Unit): DurableWebWorkflowOutcome {
            engines.exploreBody = { reports -> running.set(true); try { body(reports) } finally { running.set(false) } }
            val reports = Files.createTempDirectory(root, "reports-")
            val result = ExploreWorkflowAdapter(engines, FAST).execute(context(root, reports, limits))
            assertFalse(running.get(), "the explore child was still running after its adapter returned")
            return result
        }
        // Steady output keeps it active, so only the wall clock can stop it.
        val wall = outcome(WorkflowExecutionLimits(300uL, 300uL, 1_048_576uL, 0uL)) { reports ->
            var index = 0
            while (true) { reports.resolve("tick-${index++}").writeText("x"); Thread.sleep(20) }
        }
        assertLimitExhausted(wall)
        val idle = outcome(WorkflowExecutionLimits(60_000uL, 150uL, 1_048_576uL, 0uL)) { Thread.sleep(60_000) }
        assertLimitExhausted(idle)
        val output = outcome(WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL)) { reports ->
            reports.resolve("large.bin").toFile().writeBytes(ByteArray(4096)); Thread.sleep(60_000)
        }
        assertLimitExhausted(output)
        // Output written by a body that returns before the next sample is still bounded.
        assertLimitExhausted(outcome(WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL)) { reports ->
            reports.resolve("late.bin").toFile().writeBytes(ByteArray(4096))
        })
        val completed = assertIs<DurableWebWorkflowOutcome.Completed>(outcome(WebWorkflowDefaults.EXPLORE) { reports ->
            reports.resolve("exploration.json").writeText("{}")
        })
        assertNull(completed.candidate); assertNull(completed.usage?.toolCalls); assertNotNull(completed.usage?.wallClockMs)
        val failed = assertIs<DurableWebWorkflowOutcome.Failed>(outcome(WebWorkflowDefaults.EXPLORE) { error("inert failure") })
        assertEquals(WorkflowTerminalReason.FAILED, failed.reason)
    }

    @Test
    fun `completed exploration samples keep a long healthy exploration active`() = withRoot { root ->
        val engines = FakeEngines()
        // No report is written until the end; only per-sample progress shows activity.
        engines.exploreBody = { reports -> repeat(15) { Thread.sleep(20); engines.activity() }; reports.resolve("exploration.json").writeText("{}") }
        val limits = WorkflowExecutionLimits(60_000uL, 100uL, 1_048_576uL, 0uL)
        assertIs<DurableWebWorkflowOutcome.Completed>(ExploreWorkflowAdapter(engines, FAST).execute(context(root, root.resolve("active"), limits)))
        engines.exploreBody = { reports -> Thread.sleep(300); reports.resolve("exploration.json").writeText("{}") }
        assertLimitExhausted(ExploreWorkflowAdapter(engines, FAST).execute(context(root, root.resolve("idle"), limits)))
    }

    @Test
    fun `time limits are rechecked when a body finishes between samples`() = withRoot { root ->
        val engines = FakeEngines()
        engines.exploreBody = { Thread.sleep(100) }
        // The default 250 ms poll never samples while this body runs.
        val sparse = BoundedWorkflowExecutor()
        val wall = ExploreWorkflowAdapter(engines, sparse).execute(context(root, root.resolve("wall"),
            WorkflowExecutionLimits(10uL, 10uL, 1_048_576uL, 0uL)))
        assertLimitExhausted(wall)
        val idle = ExploreWorkflowAdapter(engines, sparse).execute(context(root, root.resolve("idle"),
            WorkflowExecutionLimits(60_000uL, 10uL, 1_048_576uL, 0uL)))
        assertLimitExhausted(idle)
        // Output written before returning is activity of unknown time, so it cannot prove idleness.
        engines.exploreBody = { reports -> Thread.sleep(100); reports.resolve("exploration.json").writeText("{}") }
        assertIs<DurableWebWorkflowOutcome.Completed>(ExploreWorkflowAdapter(engines, sparse).execute(context(root, root.resolve("active"),
            WorkflowExecutionLimits(60_000uL, 10uL, 1_048_576uL, 0uL))))
    }

    @Test
    fun `tool calls are distinct per agent invocation and reconciled with returned usage`() = withRoot { root ->
        val engines = FakeEngines()
        engines.reconstructBody = { reports, _, progress ->
            // Two module invocations reuse the same tool-call identity; each is a separate call.
            repeat(2) { module ->
                val task = progress.beginTask("module-$module", request(root))
                task.event(AgentToolEvent(0, "tool-1", "inert tool", AgentToolStatus.IN_PROGRESS))
                task.event(AgentToolEvent(1, "tool-1", "inert tool", AgentToolStatus.SUCCEEDED))
                // The second invocation reports more calls than it streamed.
                if (module == 1) task.complete(decompengine.agent.AgentExecutionReceipt(
                    decompengine.agent.AgentExecutionRequestBinding(decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)),
                    decompengine.agent.AgentExecutionOutcome.Returned(decompengine.agent.AgentExecutionResult(
                        decompengine.agent.AgentStopReason.COMPLETED, usage = decompengine.agent.AgentUsage(inputTokens = 7, toolCalls = 4)))))
            }
            writeSourceTree(reports.resolve("source-tree"), "base")
        }
        val agent = ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, "agent-acp", emptyList())
        val completed = assertIs<DurableWebWorkflowOutcome.Completed>(agent.execute(context(root, root.resolve("counted"), WebWorkflowDefaults.RECONSTRUCT_AGENT)))
        assertEquals(5uL, completed.usage?.toolCalls); assertEquals(7uL, completed.usage?.inputTokens)
        assertLimitExhausted(agent.execute(context(root, root.resolve("bounded"), WebWorkflowDefaults.RECONSTRUCT_AGENT.copy(maxToolCalls = 4uL))))
    }

    @Test
    fun `repair stays unavailable until the production repair validator is qualified`() = withRoot { root ->
        assertFalse(decompengine.project.LinuxGeneratedCRepairValidationBoundary.productionQualified())
        val ready = WebPrerequisite.AVAILABLE
        val prerequisites = WebWorkflowPrerequisites(ready, ready, ready, WebHarnessReadinessProjector.probeEnvironment(emptyMap(),
            root.resolve("bwrap"), root.resolve("timeout"), { true }, { true }).prerequisites!!.repairValidator)
        assertEquals("REPAIR_VALIDATOR_UNQUALIFIED", prerequisites.repairValidator.reasonCode)
        val reported = webWorkflowCapabilities(adapters(FakeEngines()), WebHarnessReadiness("supported", null, "ready", prerequisites = prerequisites))
            .associateBy { it.getValue("id").jsonPrimitive.content }
        assertEquals("unavailable", reported.getValue("workflow-repair-agent").getValue("state").jsonPrimitive.content)
        assertEquals("REPAIR_VALIDATOR_UNQUALIFIED", reported.getValue("workflow-repair-agent").getValue("reasonCode").jsonPrimitive.content)
        assertEquals("supported", reported.getValue("workflow-reconstruct-agent").getValue("state").jsonPrimitive.content)
        val store = JobStore(root.resolve("jobs")); val job = store.createFromUpload("validator.elf", elfFixture())
        val engines = FakeEngines()
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            assertCode("WORKFLOW_PREREQUISITE_UNAVAILABLE") {
                service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR,
                    "source_any", "agent-acp"), "repair_validator_closed", prerequisites)
            }
        }
        assertEquals(0, engines.calls.get())
    }

    @Test
    fun `passive bootstrap facts leave helper-dependent options unknown until an explicit inspection`() = withRoot { root ->
        val bwrap = root.resolve("bwrap").also { Files.createFile(it).toFile().setExecutable(true) }
        val timeout = root.resolve("timeout").also { Files.createFile(it).toFile().setExecutable(true) }
        // No agent configured: page load reads file metadata only and launches no helper.
        val passive = WebHarnessReadinessProjector.passiveReadiness(emptyMap(), bwrap, timeout, { true })
        val facts = assertNotNull(passive.prerequisites)
        assertTrue(facts.sandbox.unknown); assertEquals("SANDBOX_HELPER_UNCHECKED", facts.sandbox.reasonCode)
        assertTrue(facts.ghidra.available)
        val reported = webWorkflowCapabilities(adapters(FakeEngines()), passive).associateBy { it.getValue("id").jsonPrimitive.content }
        fun state(id: String) = reported.getValue(id).getValue("state").jsonPrimitive.content to
            reported.getValue(id)["reasonCode"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content
        assertEquals("unknown" to "SANDBOX_HELPER_UNCHECKED", state("workflow-explore-tools"))
        assertEquals("supported" to null, state("workflow-reconstruct-evidence-only"))
        assertEquals("unavailable" to "HARNESS_NOT_CONFIGURED", state("workflow-reconstruct-agent"))
        val store = JobStore(root.resolve("jobs")); val job = store.createFromUpload("passive.elf", elfFixture())
        val engines = FakeEngines()
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val explore = NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE)
            val refused = assertFailsWith<WebJobServiceException> {
                service.requestDurableStart(job.id, version(service, job.id), explore, "explore_unchecked_helpers", facts)
            }
            assertEquals("WORKFLOW_PREREQUISITE_UNAVAILABLE", refused.code)
            assertTrue(refused.message.orEmpty().contains("checked when this workflow starts"))
            assertEquals(0, engines.calls.get())
            // The HTTP start runs the bounded helper check itself; no agent or prior preflight is needed.
            val inspections = AtomicInteger()
            val admitted = webAdmissionPrerequisites(adapters(engines), explore, facts) { inspections.incrementAndGet(); WebPrerequisite.AVAILABLE }
            assertEquals(1, inspections.get())
            assertEquals(WorkflowRunState.COMPLETED, service.requestDurableStart(job.id, version(service, job.id), explore,
                "explore_inspected_helpers", admitted).attempt.state)
            // A failed check refuses with its own reason and starts nothing.
            val missing = WebPrerequisite(false, "SANDBOX_HELPER_MISSING", "The sandbox helpers required to run analyzed binaries are not available.")
            val failed = assertFailsWith<WebJobServiceException> {
                service.requestDurableStart(job.id, version(service, job.id), explore, "explore_helper_check_fail",
                    webAdmissionPrerequisites(adapters(engines), explore, facts) { missing })
            }
            assertEquals("WORKFLOW_PREREQUISITE_UNAVAILABLE", failed.code); assertTrue(failed.message.orEmpty().contains("not available"))
            assertEquals(1, engines.calls.get())
            // Options that do not need the sandbox, or that already miss another prerequisite, never run the check.
            val evidence = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE, harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY)
            val repair = NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, "source_any", "agent-acp")
            for (request in listOf(evidence, repair)) assertEquals(facts, webAdmissionPrerequisites(adapters(engines), request, facts) { error("checked") })
            assertNull(webAdmissionPrerequisites(adapters(engines), explore, null) { error("checked") })
        }
        // The projector's admission check is bounded and independent of any agent configuration.
        val projector = WebHarnessReadinessProjector(probe = { passive }, sandboxProbe = { WebPrerequisite.AVAILABLE })
        val hung = WebHarnessReadinessProjector(probe = { passive }, timeoutMillis = 100,
            sandboxProbe = { Thread.sleep(10_000); WebPrerequisite.AVAILABLE })
        try {
            assertTrue(projector.inspectSandbox().available)
            assertEquals("PROBE_TIMEOUT", hung.inspectSandbox().reasonCode)
        } finally { projector.close(); hung.close() }
        // The execution-capable check is the explicit path; its result makes helpers available.
        val checked = WebHarnessReadinessProjector.probeEnvironment(mapOf("ACP_HARNESS" to "legacy-openai",
            "BASE_URL" to "https://example.invalid/v1", "API_KEY" to "legacy-key", "MODEL" to "legacy-model"), bwrap, timeout, { true }, { true })
        assertTrue(assertNotNull(checked.prerequisites).sandbox.available)
    }

    @Test
    fun `caller interruption stops the child first and propagates for cancellation mapping`() = withRoot { root ->
        val engines = FakeEngines()
        val started = CountDownLatch(1); val childStopped = AtomicBoolean(); val observed = AtomicReference<Throwable>()
        engines.exploreBody = { started.countDown(); try { Thread.sleep(60_000) } finally {
            val until = System.nanoTime() + 50_000_000; while (System.nanoTime() < until) Thread.onSpinWait(); childStopped.set(true)
        } }
        val caller = Thread {
            try { ExploreWorkflowAdapter(engines, FAST).execute(context(root, root.resolve("reports"), WebWorkflowDefaults.EXPLORE)) }
            catch (failure: Throwable) { observed.set(failure); assertTrue(childStopped.get(), "returned before its child stopped") }
        }
        caller.start(); assertTrue(started.await(5, TimeUnit.SECONDS))
        caller.interrupt(); caller.join(10_000)
        assertFalse(caller.isAlive); assertIs<InterruptedException>(observed.get()); assertTrue(childStopped.get())
    }

    @Test
    fun `agent reconstruction meters distinct tool calls and records only a canonical candidate`() = withRoot { root ->
        val engines = FakeEngines()
        val modes = mutableListOf<WebReconstructionMode>()
        engines.reconstructBody = { reports, mode, progress ->
            modes += mode
            val task = progress.beginTask("module", request(root))
            listOf("call-a", "call-b", "call-a", "call-c").forEachIndexed { index, id ->
                task.event(AgentToolEvent(index.toLong(), id, "inert tool", AgentToolStatus.SUCCEEDED))
            }
            writeSourceTree(reports.resolve("source-tree"), "base")
        }
        val agent = ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, "agent-acp", emptyList())
        val exhausted = agent.execute(context(root, root.resolve("tools"), WebWorkflowDefaults.RECONSTRUCT_AGENT.copy(maxToolCalls = 2uL)))
        assertLimitExhausted(exhausted)
        assertEquals(baseCandidate(), (exhausted as DurableWebWorkflowOutcome.Failed).candidate, "candidate output is retained, not accepted")
        val completed = assertIs<DurableWebWorkflowOutcome.Completed>(agent.execute(context(root, root.resolve("agent"), WebWorkflowDefaults.RECONSTRUCT_AGENT)))
        assertEquals(baseCandidate(), completed.candidate); assertEquals(3uL, completed.usage?.toolCalls)
        val evidence = ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.EVIDENCE_ONLY, EVIDENCE_ONLY_CAPABILITY, emptyList())
        assertFalse(checkNotNull(evidence.launch).contactsAgent); assertTrue(checkNotNull(agent.launch).contactsAgent)
        engines.reconstructBody = { reports, mode, _ -> modes += mode; Files.createDirectories(reports) }
        val missing = assertIs<DurableWebWorkflowOutcome.Completed>(evidence.execute(context(root, root.resolve("evidence"), WebWorkflowDefaults.RECONSTRUCT_EVIDENCE)))
        assertNull(missing.candidate, "no build contract, no candidate identity")
        assertEquals(listOf(WebReconstructionMode.AGENT, WebReconstructionMode.AGENT, WebReconstructionMode.EVIDENCE_ONLY), modes)
    }

    @Test
    fun `admission requires an explicit ready option, server-approved bounds and the declared input`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("admission.elf", elfFixture())
        val engines = FakeEngines()
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val agentMissing = WebWorkflowPrerequisites(WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured."),
                WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE)
            fun start(request: NewWorkflowAttempt, key: String, prerequisites: WebWorkflowPrerequisites? = WebWorkflowPrerequisites.UNCHECKED) =
                service.requestDurableStart(job.id, version(service, job.id), request, key, prerequisites)
            val reconstruct = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp")
            assertCode("WORKFLOW_PREREQUISITE_UNAVAILABLE") { start(reconstruct, "agent_without_harness_01", agentMissing) }
            assertCode("WORKFLOW_PREREQUISITE_UNAVAILABLE") { start(reconstruct, "agent_unknown_readiness", null) }
            assertCode("HARNESS_UNAVAILABLE") { start(reconstruct.copy(harnessCapabilityId = null), "agent_unnamed_harness_01") }
            assertCode("WORKFLOW_LIMITS_UNAVAILABLE") {
                start(reconstruct.copy(limits = reconstruct.limits.copy(maxToolCalls = reconstruct.limits.maxToolCalls + 1uL)), "agent_raised_tool_limit")
            }
            val explore = NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE)
            assertCode("INPUT_REVISION_UNAVAILABLE") { start(explore.copy(inputRevisionId = "source_unrelated"), "explore_with_revision_1") }
            val repair = NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, harnessCapabilityId = "agent-acp")
            assertCode("INPUT_REVISION_REQUIRED") { start(repair, "repair_without_revision") }
            assertCode("WORKFLOW_LIMITS_UNAVAILABLE") {
                start(repair.copy(limits = repair.limits.copy(wallClockMs = 600_000uL, idleMs = 60_000uL)), "repair_fixed_limits_01")
            }
            assertEquals(0, engines.calls.get(), "refused admissions executed an engine")
            // The agent option alone is missing; evidence-only reconstruction stays an explicit, ready choice.
            val lowered = WebWorkflowDefaults.RECONSTRUCT_EVIDENCE.copy(wallClockMs = 600_000uL, idleMs = 300_000uL)
            val evidence = start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, lowered, harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY),
                "evidence_only_reconstruction", agentMissing)
            assertEquals(WorkflowRunState.COMPLETED, evidence.attempt.state); assertEquals(lowered, evidence.attempt.limits)
            assertEquals(EVIDENCE_ONLY_CAPABILITY, evidence.attempt.harnessCapabilityId)
            assertEquals(listOf(WebReconstructionMode.EVIDENCE_ONLY), engines.modes)
            assertEquals(baseCandidate(), evidence.attempt.candidate); assertNull(evidence.attempt.acceptedRevision)
        }
    }

    @Test
    fun `capabilities report each option, its prerequisites and unimplemented workflows without paths`() {
        val adapters = adapters(FakeEngines())
        val readiness = WebHarnessReadiness("unavailable", "HARNESS_NOT_CONFIGURED", "No agent harness is configured.",
            prerequisites = WebWorkflowPrerequisites(WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured."),
                WebPrerequisite.AVAILABLE, WebPrerequisite(false, "GHIDRA_MISSING", "The bundled Ghidra distribution is not present.")))
        val reported = webWorkflowCapabilities(adapters, readiness).associateBy { it.getValue("id").jsonPrimitive.content }
        assertEquals(setOf("workflow-explore-tools", "workflow-reconstruct-agent", "workflow-reconstruct-evidence-only",
            "workflow-repair-agent", "workflow-build", "workflow-validate"), reported.keys)
        fun state(id: String) = reported.getValue(id).getValue("state").jsonPrimitive.content to
            (reported.getValue(id)["reasonCode"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content)
        assertEquals("supported" to null, state("workflow-explore-tools"))
        assertEquals("unavailable" to "HARNESS_NOT_CONFIGURED", state("workflow-reconstruct-agent"))
        assertEquals("unavailable" to "GHIDRA_MISSING", state("workflow-reconstruct-evidence-only"))
        assertEquals("unavailable" to "HARNESS_NOT_CONFIGURED", state("workflow-repair-agent"))
        assertEquals("unsupported" to "WORKFLOW_NOT_IMPLEMENTED", state("workflow-build"))
        val repair = reported.getValue("workflow-repair-agent").getValue("launch").jsonObject
        assertEquals("recorded-required", repair.getValue("input").jsonPrimitive.content)
        assertEquals("false", repair.getValue("limitsAdjustable").jsonPrimitive.content)
        assertEquals("1", reported.getValue("workflow-repair-agent").getValue("agentContractVersion").jsonPrimitive.content)
        assertEquals(JsonNull, reported.getValue("workflow-reconstruct-evidence-only").getValue("agentContractVersion"))
        assertEquals("true", reported.getValue("workflow-explore-tools").getValue("launch").jsonObject.getValue("executesBinary").jsonPrimitive.content)
        assertEquals(JsonNull, reported.getValue("workflow-build").getValue("launch"))
        val unknown = webWorkflowCapabilities(adapters, WebHarnessReadiness("unavailable", "PROBE_TIMEOUT", "timed out"))
        assertTrue(unknown.filter { it["launch"] != JsonNull }.all { it.getValue("state").jsonPrimitive.content == "unknown" })
        val text = reported.values.joinToString()
        assertFalse(text.contains("/tmp") || text.contains(Path.of("").toAbsolutePath().toString()), "a capability exposed a host path")
        // Inert test registrations keep the general preview refusal rather than claiming production launch facts.
        val inert = webWorkflowCapabilities(listOf(object : DurableWebWorkflowAdapter {
            override val workflow = WorkflowKind.EXPLORE
            override val limits = WebWorkflowDefaults.EXPLORE
            override fun execute(context: DurableWebWorkflowContext) = DurableWebWorkflowOutcome.Completed()
        }), readiness)
        assertEquals(listOf("PREVIEW_UNAVAILABLE"), inert.map { it.getValue("reasonCode").jsonPrimitive.content })
    }

    @Test
    fun `explore, reconstruction and repair publish one validated acceptance and restart never repeats it`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("pipeline.elf", elfFixture())
        val engines = FakeEngines()
        lateinit var accepted: WorkflowAcceptanceReference
        service(store, adapters(engines, acceptTestOnly = true)).use { service ->
            service.initializeExistingStorage()
            fun start(request: NewWorkflowAttempt, key: String) = service.requestDurableStart(job.id, version(service, job.id), request, key)
            val explored = start(NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE), "pipeline_explore_start").attempt
            assertEquals(WorkflowRunState.COMPLETED, explored.state); assertNull(explored.candidate)
            val reconstructed = start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE,
                harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY), "pipeline_reconstruct_start").attempt
            assertEquals(baseCandidate(), reconstructed.candidate); assertNull(reconstructed.acceptedRevision)
            assertEquals(WorkflowRecoveryDisposition.COMPLETED_UNPUBLISHED, reconstructed.recoveryDisposition)
            val repaired = start(NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, reconstructed.candidate!!.revisionId,
                "agent-acp"), "pipeline_repair_start_01").attempt
            assertEquals(WorkflowRunState.COMPLETED, repaired.state)
            accepted = assertNotNull(repaired.acceptedRevision)
            assertEquals(repaired.candidate, WorkflowCandidate(accepted.revisionId, accepted.sourceSha256))
            assertNotEquals(baseCandidate(), repaired.candidate, "the repaired revision is a new source identity")
            assertEquals(accepted, service.presentation(job.id).snapshot!!.acceptedRevision)
            assertEquals("repair-graph", accepted.artifactId)
            // The selected input revision's retained evidence was copied, never modified in place.
            val input = store.runReportsDirectory(job.id, reconstructed.runId).resolve("source-tree")
            assertEquals("base", input.resolve("code.c").readText())
            assertFalse(Files.exists(input.resolve("reports/repair-revisions")))
            assertEquals(3, engines.calls.get())
        }
        val before = root.resolve(job.id).resolve("workflow-state.json").readBytes()
        service(store, adapters(engines, acceptTestOnly = true)).use { service ->
            service.initializeExistingStorage()
            val reconciliation = assertNotNull(service.startupReconciliation())
            assertEquals(0, reconciliation.publishedAcceptances)
            assertEquals(1, reconciliation.dispositions[WorkflowRecoveryDisposition.ACCEPTED])
            assertEquals(accepted, service.presentation(job.id).snapshot!!.acceptedRevision)
        }
        assertContentEquals(before, root.resolve(job.id).resolve("workflow-state.json").readBytes())
        assertEquals(3, engines.calls.get(), "restart executed an engine")
    }

    @Test
    fun `production policy never accepts a release-ineligible test-only repair graph`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("test-only.elf", elfFixture())
        service(store, adapters(FakeEngines())).use { service ->
            service.initializeExistingStorage()
            fun start(request: NewWorkflowAttempt, key: String) = service.requestDurableStart(job.id, version(service, job.id), request, key)
            val reconstructed = start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE,
                harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY), "test_only_reconstruct_01").attempt
            val repaired = start(NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, reconstructed.candidate!!.revisionId,
                "agent-acp"), "test_only_repair_start_1").attempt
            assertEquals(WorkflowRunState.COMPLETED, repaired.state); assertNotNull(repaired.candidate)
            assertNull(repaired.acceptedRevision); assertTrue(repaired.publicationPending)
            assertNull(service.presentation(job.id).snapshot!!.acceptedRevision)
        }
    }

    @Test
    fun `an input that already validates publishes its accepted root baseline`() = withRoot { root ->
        for (acceptTestOnly in listOf(true, false)) {
            val store = JobStore(root.resolve("jobs-$acceptTestOnly")); val job = store.createFromUpload("baseline.elf", elfFixture())
            val engines = FakeEngines().apply { repairBody = { project -> acceptRepairBaseline(project) } }
            service(store, adapters(engines, acceptTestOnly)).use { service ->
                service.initializeExistingStorage()
                fun start(request: NewWorkflowAttempt, key: String) = service.requestDurableStart(job.id, version(service, job.id), request, key)
                val reconstructed = start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE,
                    harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY), "baseline_reconstruct_01").attempt
                val repaired = start(NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, reconstructed.candidate!!.revisionId,
                    "agent-acp"), "baseline_repair_start_01").attempt
                assertEquals(WorkflowRunState.COMPLETED, repaired.state)
                val history = readProjectRecordedRepairHistory(store.runReportsDirectory(job.id, repaired.runId).resolve("source-tree"))
                val baseline = assertNotNull(history.snapshot?.acceptedBaseline, "the accepted root was not projected")
                assertEquals(WorkflowCandidate(webSourceRevisionId(baseline.sourceRevisionSha256), baseline.sourceRevisionSha256), repaired.candidate)
                if (acceptTestOnly) {
                    val accepted = assertNotNull(repaired.acceptedRevision)
                    assertEquals(baseline.identity.value, accepted.graphNodeId)
                } else assertNull(repaired.acceptedRevision, "a test-only baseline proof became release acceptance")
            }
        }
    }

    @Test
    fun `restart distinguishes queued, interrupted, unpublished and accepted attempts without executing work`() = withRoot { root ->
        val store = JobStore(root)
        val queued = store.createFromUpload("queued.elf", elfFixture())
        val running = store.createFromUpload("running.elf", elfFixture())
        val pending = store.createFromUpload("pending.elf", elfFixture())
        val accepted = store.createFromUpload("accepted.elf", elfFixture())
        val repair = NewWorkflowAttempt(WorkflowKind.REPAIR, WebWorkflowDefaults.REPAIR, "source_input", "agent-acp")
        lateinit var acceptedReference: WorkflowAcceptanceReference
        WorkflowAttemptStore.open(root).use { owner ->
            fun snapshot(jobId: String) = (owner.inspect(jobId) as WorkflowJobInspection.Available).snapshot
            owner.create(queued.id, snapshot(queued.id).version, NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE))
            val active = owner.create(running.id, snapshot(running.id).version, NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE)).attempt
            owner.transition(running.id, active.runId, active.version, WorkflowTransition.Start)
            // A completed repair whose canonical graph accepted its head, but whose acceptance was never recorded.
            fun completedRepair(jobId: String): WorkflowAttempt {
                val queuedRepair = owner.create(jobId, snapshot(jobId).version, repair).attempt
                val startedRepair = owner.transition(jobId, queuedRepair.runId, queuedRepair.version, WorkflowTransition.Start).attempt
                val project = store.runReportsDirectory(jobId, startedRepair.runId, create = true).resolve("source-tree")
                writeSourceTree(project, "base"); acceptRepairGraph(project)
                return owner.transition(jobId, startedRepair.runId, startedRepair.version, WorkflowTransition.Finish(
                    WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, acceptedHeadCandidate(project))).attempt
            }
            completedRepair(pending.id)
            val done = completedRepair(accepted.id)
            acceptedReference = assertNotNull(verifyRepairAcceptance(DurableWebWorkflowPublicationContext(store.get(accepted.id), done,
                store.runReportsDirectory(accepted.id, done.runId)), allowTestOnly = true))
            assertNull(verifyRepairAcceptance(DurableWebWorkflowPublicationContext(store.get(accepted.id), done,
                store.runReportsDirectory(accepted.id, done.runId))), "production policy accepted a test-only graph")
            owner.recordAcceptedRevision(accepted.id, done.runId, snapshot(accepted.id).version, done.version, acceptedReference)
        }
        val acceptedBefore = root.resolve(accepted.id).resolve("workflow-state.json").readBytes()
        val engines = FakeEngines()
        service(store, adapters(engines, acceptTestOnly = true)).use { service ->
            service.initializeExistingStorage()
            fun latest(jobId: String) = service.presentation(jobId).snapshot!!.latestRun!!
            assertEquals(WorkflowRunState.INTERRUPTED, latest(queued.id).state)
            assertEquals(WorkflowRecoveryDisposition.QUEUED_NOT_STARTED, latest(queued.id).recoveryDisposition)
            assertEquals(WorkflowRecoveryDisposition.INTERRUPTED_ACTIVE, latest(running.id).recoveryDisposition)
            assertEquals(WorkflowTerminalReason.PROCESS_INTERRUPTED, latest(running.id).terminalReason)
            val published = assertNotNull(latest(pending.id).acceptedRevision, "verified completed work was not reconciled")
            assertEquals(WorkflowCandidate(published.revisionId, published.sourceSha256), latest(pending.id).candidate)
            assertEquals(acceptedReference, latest(accepted.id).acceptedRevision)
            val reconciliation = assertNotNull(service.startupReconciliation())
            assertEquals(1, reconciliation.publishedAcceptances)
            assertEquals(mapOf(WorkflowRecoveryDisposition.QUEUED_NOT_STARTED to 1, WorkflowRecoveryDisposition.INTERRUPTED_ACTIVE to 1,
                WorkflowRecoveryDisposition.ACCEPTED to 2, WorkflowRecoveryDisposition.COMPLETED_UNPUBLISHED to 0),
                reconciliation.dispositions.filterKeys { it != WorkflowRecoveryDisposition.TERMINAL && it != WorkflowRecoveryDisposition.UNFINISHED })
        }
        assertContentEquals(acceptedBefore, root.resolve(accepted.id).resolve("workflow-state.json").readBytes(), "an accepted job changed on restart")
        val states = listOf(queued, running, pending, accepted).associate { it.id to root.resolve(it.id).resolve("workflow-state.json").readBytes() }
        service(store, adapters(engines, acceptTestOnly = true)).use { service ->
            service.initializeExistingStorage()
            assertEquals(0, assertNotNull(service.startupReconciliation()).publishedAcceptances)
        }
        states.forEach { (jobId, bytes) -> assertContentEquals(bytes, root.resolve(jobId).resolve("workflow-state.json").readBytes(), jobId) }
        assertEquals(0, engines.calls.get(), "restart executed an adapter engine")
    }

    @Test
    fun `source tree copies refuse links and never follow them`() = withRoot { root ->
        val source = root.resolve("source").createDirectories(); source.resolve("code.c").writeText("base")
        val outside = root.resolve("outside.txt").also { it.writeText("private") }
        Files.createSymbolicLink(source.resolve("link"), outside)
        assertFails { copyWebSourceTree(source, root.resolve("copy")) }
        assertFalse(Files.exists(root.resolve("copy/link")))
    }

    private class FakeEngines : WebWorkflowEngines {
        val calls = AtomicInteger()
        val modes = mutableListOf<WebReconstructionMode>()
        var exploreBody: (Path) -> Unit = { reports -> Files.createDirectories(reports); reports.resolve("exploration.json").writeText("{}") }
        var reconstructBody: (Path, WebReconstructionMode, AgentWorkflowProgress) -> Unit = { reports, mode, _ ->
            modes += mode; writeSourceTree(reports.resolve("source-tree"), "base")
        }
        var repairBody: (Path) -> Unit = { project -> acceptRepairGraph(project) }
        var activity: () -> Unit = {}
        override fun explore(binary: Path, reportsDirectory: Path, activity: () -> Unit) {
            calls.incrementAndGet(); this.activity = activity; exploreBody(reportsDirectory)
        }
        override fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress) {
            calls.incrementAndGet(); reconstructBody(reportsDirectory, mode, progress)
        }
        override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: String): RepairRunStatus {
            calls.incrementAndGet(); check(harness == "acp"); repairBody(project); return RepairRunStatus.FULLY_ACCEPTED
        }
    }

    private fun adapters(engines: WebWorkflowEngines, acceptTestOnly: Boolean = false): List<DurableWebWorkflowAdapter> = listOf(
        ExploreWorkflowAdapter(engines, FAST),
        ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, "agent-acp", emptyList()),
        ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.EVIDENCE_ONLY, EVIDENCE_ONLY_CAPABILITY, emptyList()),
        RepairWorkflowAdapter(engines, FAST, "agent-acp", acceptTestOnly),
    )
    private fun service(store: JobStore, adapters: List<DurableWebWorkflowAdapter>) = WebJobService(store,
        JobAnalyzer { _, _ -> throw AssertionError("legacy analyzer fallback") },
        JobReconstructor { _, _ -> throw AssertionError("legacy reconstructor fallback") }, Executor(Runnable::run),
        durableAdapters = adapters, attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC()) })
    private fun context(root: Path, reports: Path, limits: WorkflowExecutionLimits): DurableWebWorkflowContext {
        Files.createDirectories(reports)
        val job = Job("a".repeat(32), "fixture.elf", "uploaded", "2026-01-01T00:00:00Z", sizeBytes = 1,
            binaryPath = root.resolve("input.elf"), metadata = decompengine.binary.ElfMetadataReader.read(elfFixture()))
        val attempt = WorkflowAttempt("run_fixture", job.id, WorkflowKind.EXPLORE, WorkflowRunState.RUNNING, "version_fixture",
            java.time.Instant.now(), java.time.Instant.now(), null, null, null, null, limits, null, null, null, null)
        return DurableWebWorkflowContext(job, attempt, reports)
    }
    private fun request(root: Path) = AgentExecutionRequest("inert", listOf(AgentWorkspaceRoot("project", root)), accessPolicy = AgentAccessPolicy(emptyList()))
    private fun version(service: WebJobService, jobId: String) = webJob(service.presentation(jobId)).getValue("version").jsonPrimitive.content
    private fun assertCode(code: String, operation: () -> Unit) = assertEquals(code, assertFailsWith<WebJobServiceException> { operation() }.code)
    private fun assertLimitExhausted(outcome: DurableWebWorkflowOutcome) =
        assertEquals(WorkflowTerminalReason.LIMIT_EXHAUSTED, assertIs<DurableWebWorkflowOutcome.Failed>(outcome).reason)
    private fun withRoot(operation: (Path) -> Unit) {
        val root = createTempDirectory("production-workflows-")
        try { operation(root) } finally { root.toFile().deleteRecursively() }
    }

    private companion object {
        val FAST = BoundedWorkflowExecutor(pollMillis = 10, outputPollMillis = 10, reinterruptMillis = 10)
        val PROFILE = DeclarativeRepairIndexProfile("web-workflow-fixture", RepairIndexLayout(listOf("code.c"), listOf("code.c"),
            modules = listOf(RepairModuleEvidence("fixture-module", listOf("code.c")))))
        val INPUTS = listOf(ProcessInput("fixture-case"))

        fun baseSha(): String = sha256("base".toByteArray())
        fun baseCandidate() = WorkflowCandidate(webSourceRevisionId(baseSha()), baseSha())

        /** A minimal source tree and schema-3 build contract; the digest is an inert fixture value. */
        fun writeSourceTree(tree: Path, content: String) {
            tree.resolve("reports").createDirectories()
            tree.resolve("code.c").writeText(content)
            tree.resolve("reports/build_contract.json").writeText("""{"schemaVersion":3,"sourceRevisionSha256":"${sha256(content.toByteArray())}"}""")
        }

        /** Records a real fully accepted graph head through the test-only publication mode. */
        fun acceptRepairGraph(project: Path) {
            ModuleRevisionGraph.open(project, PROFILE).use { graph ->
                graph.enableRunContract(); graph.retainRegressionInputs(INPUTS); graph.beginRun(2, 60_000)
                graph.bindOriginalBinary(sha256("reference".toByteArray())); graph.bindExpectedObservations(sha256("expected".toByteArray()))
                val corpus = graph.retainedRegressionCorpus()
                val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "inert prompt", "inert summary",
                    corpus.inputs.map { it.id }, RepairEvidence("compile", "inert diagnostic"), corpus.sha256,
                    publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
                graph.installCandidate(attempt, mapOf("code.c" to "repaired".toByteArray()))
                val state = graph.snapshot
                graph.accept(attempt, RepairEvidence("valid", "inert summary"), RepairValidationProof(
                    repairCandidateSourceSha256(graph.candidateSources(attempt)), state.profileSha256, state.indexSha256, corpus.sha256,
                    sha256("reference".toByteArray()), sha256("rebuilt".toByteArray()), sha256("runtime".toByteArray()),
                    sha256("evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS))
            }
        }

        /** Records a FULLY_ACCEPTED run whose accepted head is the unchanged root, as a validated baseline does. */
        fun acceptRepairBaseline(project: Path) {
            ModuleRevisionGraph.open(project, PROFILE).use { graph ->
                graph.enableRunContract(); graph.retainRegressionInputs(INPUTS); graph.beginRun(2, 60_000)
                graph.bindOriginalBinary(sha256("reference".toByteArray())); graph.bindExpectedObservations(sha256("expected".toByteArray()))
                val state = graph.snapshot
                graph.acceptAssessedBaseline(RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources()), state.profileSha256,
                    state.indexSha256, graph.retainedRegressionCorpus().sha256, sha256("reference".toByteArray()), sha256("rebuilt".toByteArray()),
                    sha256("runtime".toByteArray()), sha256("evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS),
                    RepairEvidence("valid", "inert baseline"))
            }
        }

        fun acceptedHeadCandidate(project: Path): WorkflowCandidate {
            val history = readProjectRecordedRepairHistory(project)
            check(history.status == RepairHistoryReadStatus.RECORDED)
            val snapshot = checkNotNull(history.snapshot)
            val sha = checkNotNull(snapshot.attempts.single { it.identity == snapshot.fullyAcceptedHead }.sourceRevisionSha256)
            return WorkflowCandidate(webSourceRevisionId(sha), sha)
        }
    }
}

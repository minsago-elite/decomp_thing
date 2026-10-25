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
        val agent = ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, WebAgentHarness.ACP, emptyList())
        val exhausted = agent.execute(context(root, root.resolve("tools"), WebWorkflowDefaults.RECONSTRUCT_AGENT.copy(maxToolCalls = 2uL)))
        assertLimitExhausted(exhausted)
        assertEquals(baseCandidate(), (exhausted as DurableWebWorkflowOutcome.Failed).candidate, "candidate output is retained, not accepted")
        val completed = assertIs<DurableWebWorkflowOutcome.Completed>(agent.execute(context(root, root.resolve("agent"), WebWorkflowDefaults.RECONSTRUCT_AGENT)))
        assertEquals(baseCandidate(), completed.candidate); assertEquals(3uL, completed.usage?.toolCalls)
        val evidence = ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.EVIDENCE_ONLY, null, emptyList())
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
            WebWorkflowPrerequisites(WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured."),
                WebPrerequisite.AVAILABLE, WebPrerequisite(false, "GHIDRA_MISSING", "The bundled Ghidra distribution is not present.")))
        val reported = webWorkflowCapabilities(adapters, readiness).associateBy { it.getValue("id").jsonPrimitive.content }
        assertEquals(setOf("workflow-explore-tools", "workflow-reconstruct-agent-acp", "workflow-reconstruct-agent-builtin",
            "workflow-reconstruct-evidence-only", "workflow-repair-agent-acp", "workflow-repair-agent-builtin", "workflow-build",
            "workflow-validate"), reported.keys)
        fun state(id: String) = reported.getValue(id).getValue("state").jsonPrimitive.content to
            (reported.getValue(id)["reasonCode"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content)
        assertEquals("supported" to null, state("workflow-explore-tools"))
        assertEquals("unavailable" to "HARNESS_NOT_CONFIGURED", state("workflow-reconstruct-agent-acp"))
        assertEquals("unavailable" to "GHIDRA_MISSING", state("workflow-reconstruct-evidence-only"))
        assertEquals("unavailable" to "HARNESS_NOT_CONFIGURED", state("workflow-repair-agent-acp"))
        assertEquals("unsupported" to "BUILTIN_HARNESS_NOT_INTEGRATED", state("workflow-repair-agent-builtin"))
        assertEquals("unsupported" to "WORKFLOW_NOT_IMPLEMENTED", state("workflow-build"))
        val repair = reported.getValue("workflow-repair-agent-acp").getValue("launch").jsonObject
        assertEquals("recorded-required", repair.getValue("input").jsonPrimitive.content)
        assertEquals("false", repair.getValue("limitsAdjustable").jsonPrimitive.content)
        assertEquals("1", reported.getValue("workflow-repair-agent-acp").getValue("agentContractVersion").jsonPrimitive.content)
        assertEquals(JsonNull, reported.getValue("workflow-explore-tools").getValue("launch").jsonObject.getValue("harness"))
        assertEquals(JsonNull, reported.getValue("workflow-reconstruct-evidence-only").getValue("agentContractVersion"))
        assertEquals("true", reported.getValue("workflow-explore-tools").getValue("launch").jsonObject.getValue("executesBinary").jsonPrimitive.content)
        assertEquals(JsonNull, reported.getValue("workflow-build").getValue("launch"))
        val unknown = webWorkflowCapabilities(adapters, WebHarnessReadiness("unavailable", "PROBE_TIMEOUT", "timed out"))
        // Unknown readiness never hides that the built-in harness is unsupported regardless of any probe.
        assertEquals(mapOf("unknown" to 4, "unsupported" to 2), unknown.filter { it["launch"] != JsonNull }
            .groupingBy { it.getValue("state").jsonPrimitive.content }.eachCount())
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
    fun `each selectable harness is probed separately and the legacy adapter appears only when selected`() {
        val defaults = WebHarnessReadinessProjector.harnessFacts(emptyMap())
        assertEquals(setOf(WebAgentHarness.ACP), defaults.keys)
        assertEquals("HARNESS_NOT_CONFIGURED", defaults.getValue(WebAgentHarness.ACP).prerequisite.reasonCode)
        assertTrue(defaults.getValue(WebAgentHarness.ACP).selected); assertNull(defaults.getValue(WebAgentHarness.ACP).provenance)
        val legacyEnvironment = mapOf("ACP_HARNESS" to "legacy-openai", "BASE_URL" to "https://example.invalid/v1",
            "API_KEY" to "legacy-private-key", "MODEL" to "legacy-model")
        val legacy = WebHarnessReadinessProjector.harnessFacts(legacyEnvironment)
        assertEquals(setOf(WebAgentHarness.ACP, WebAgentHarness.LEGACY_OPENAI), legacy.keys)
        // Selecting the legacy adapter never makes ACP ready, and ACP is never substituted for it.
        assertEquals("HARNESS_NOT_CONFIGURED", legacy.getValue(WebAgentHarness.ACP).prerequisite.reasonCode)
        assertFalse(legacy.getValue(WebAgentHarness.ACP).selected)
        val legacyFacts = legacy.getValue(WebAgentHarness.LEGACY_OPENAI)
        assertTrue(legacyFacts.prerequisite.available); assertTrue(legacyFacts.selected)
        val provenance = assertNotNull(legacyFacts.provenance)
        assertEquals("legacy-openai-compatible", provenance.implementationId); assertTrue(provenance.deprecated)
        assertNull(provenance.configurationSha256)
        assertFalse(legacy.toString().contains("legacy-private-key") || legacy.toString().contains("example.invalid"))
        val unsupported = WebHarnessReadinessProjector.harnessFacts(mapOf("ACP_HARNESS" to "direct"))
        assertEquals("HARNESS_UNSUPPORTED", unsupported.getValue(WebAgentHarness.ACP).prerequisite.reasonCode)

        assertEquals(listOf("workflow-explore-tools", "workflow-reconstruct-agent-acp", "workflow-reconstruct-evidence-only",
            "workflow-repair-agent-acp"), productionDurableWebWorkflows(emptyMap(), engines = FakeEngines()).map(::webWorkflowCapabilityId))
        val retained = productionDurableWebWorkflows(legacyEnvironment, engines = FakeEngines())
        assertEquals(listOf("workflow-explore-tools", "workflow-reconstruct-agent-acp", "workflow-reconstruct-agent-legacy-openai",
            "workflow-reconstruct-evidence-only", "workflow-repair-agent-acp", "workflow-repair-agent-legacy-openai"),
            retained.map(::webWorkflowCapabilityId))
        assertEquals(listOf("agent-acp", "agent-legacy-openai", "evidence-only", "agent-acp", "agent-legacy-openai"),
            retained.drop(1).map { it.harnessCapabilityId })
        assertTrue(retained.none { it.launch?.harness == WebAgentHarness.BUILTIN }, "the built-in harness was registered")
    }

    @Test
    fun `harness options report identity, operations and deprecation and never select the built-in harness`() = withRoot { root ->
        val engines = FakeEngines()
        val adapters = adapters(engines) + listOf(
            ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, WebAgentHarness.LEGACY_OPENAI, emptyList()),
            RepairWorkflowAdapter(engines, FAST, WebAgentHarness.LEGACY_OPENAI))
        val prerequisites = harnessPrerequisites(acp = ACP_PROVENANCE, legacy = LEGACY_PROVENANCE)
        val reported = webWorkflowCapabilities(adapters, WebHarnessReadiness("supported", null, "ready", prerequisites))
            .associateBy { it.getValue("id").jsonPrimitive.content }
        fun harness(id: String) = reported.getValue(id).getValue("launch").jsonObject.getValue("harness").jsonObject
        assertEquals("acp", harness("workflow-reconstruct-agent-acp").getValue("kind").jsonPrimitive.content)
        assertEquals("fixture-agent", harness("workflow-reconstruct-agent-acp").getValue("implementationId").jsonPrimitive.content)
        assertEquals("1", harness("workflow-reconstruct-agent-acp").getValue("protocolVersion").jsonPrimitive.content)
        assertEquals("false", harness("workflow-repair-agent-acp").getValue("deprecated").jsonPrimitive.content)
        assertEquals(listOf("reconstruct", "repair"), harness("workflow-repair-agent-acp").getValue("operations").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("true", harness("workflow-repair-agent-legacy-openai").getValue("deprecated").jsonPrimitive.content)
        assertEquals("supported", reported.getValue("workflow-repair-agent-legacy-openai").getValue("state").jsonPrimitive.content)
        val builtin = reported.getValue("workflow-reconstruct-agent-builtin")
        assertEquals("unsupported", builtin.getValue("state").jsonPrimitive.content)
        assertEquals("agent-builtin", builtin.getValue("launch").jsonObject.getValue("harnessCapabilityId").jsonPrimitive.content)
        assertEquals(0, harness("workflow-reconstruct-agent-builtin").getValue("operations").jsonArray.size)
        assertEquals(JsonNull, harness("workflow-reconstruct-agent-builtin").getValue("implementationId"))
        assertFalse(reported.values.joinToString().contains(ACP_PROVENANCE.configurationSha256!!), "a configuration digest left the attempt record")

        val store = JobStore(root); val job = store.createFromUpload("builtin.elf", elfFixture())
        service(store, adapters).use { service ->
            service.initializeExistingStorage()
            // The built-in option has no registration: naming it is refused, never served by another harness.
            assertCode("HARNESS_UNAVAILABLE") {
                service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = WebAgentHarness.BUILTIN.capabilityId), "builtin_reconstruct_01", prerequisites)
            }
            // An unavailable ACP option never borrows the configured legacy adapter.
            assertCode("WORKFLOW_PREREQUISITE_UNAVAILABLE") {
                service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp"), "acp_without_configuration",
                    harnessPrerequisites(acp = null, legacy = LEGACY_PROVENANCE))
            }
            assertEquals(0, engines.calls.get())
        }
    }

    @Test
    fun `each attempt records its own validated configuration and a later change never rewrites it`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("configuration.elf", elfFixture())
        val engines = FakeEngines()
        val first = service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val attempt = service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp"), "configured_reconstruct_1",
                harnessPrerequisites(acp = ACP_PROVENANCE)).attempt
            val configuration = assertNotNull(attempt.configuration)
            assertEquals("workflow-reconstruct-agent-acp", configuration.optionId); assertEquals("agent", configuration.mode)
            assertEquals(WorkflowAttemptHarness("acp", "fixture-agent", 1, 1, ACP_PROVENANCE.sdkVersion,
                ACP_PROVENANCE.configurationSha256, false), configuration.harness)
            assertEquals(ACP_PROVENANCE.stableDescriptor, engines.harnesses.single()?.expectedDescriptor,
                "execution did not receive the admitted harness")
            // The run DTO projects the record, including the digest, without configuration content.
            val dto = webRun(attempt).getValue("configuration").jsonObject
            assertEquals(ACP_PROVENANCE.configurationSha256, dto.getValue("harness").jsonObject.getValue("configurationSha256").jsonPrimitive.content)
            val evidence = service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WebWorkflowDefaults.RECONSTRUCT_EVIDENCE, harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY), "configured_evidence_01",
                harnessPrerequisites(acp = ACP_PROVENANCE)).attempt
            assertNull(assertNotNull(evidence.configuration).harness); assertEquals("evidence-only", evidence.configuration?.mode)
            attempt
        }
        val changed = ACP_PROVENANCE.copy(configurationSha256 = "b".repeat(64),
            stableDescriptor = ACP_PROVENANCE.stableDescriptor.replace("a".repeat(64), "b".repeat(64)))
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val expected = version(service, job.id)
            val second = service.requestDurableStart(job.id, expected, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp"), "configured_reconstruct_2",
                harnessPrerequisites(acp = changed)).attempt
            assertEquals("b".repeat(64), second.configuration?.harness?.configurationSha256)
            val retained = service.presentation(job.id).snapshot!!.attempts.single { it.runId == first.runId }
            assertEquals(first.configuration, retained.configuration, "a later admission rewrote earlier provenance")
            // A keyed replay returns the original record, not one derived from the current configuration.
            val replay = service.requestDurableStart(job.id, expected, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp"), "configured_reconstruct_2",
                harnessPrerequisites(acp = ACP_PROVENANCE))
            assertTrue(replay.replayed); assertEquals(second.configuration, replay.attempt.configuration)
        }
    }

    @Test
    fun `a harness that resolves differently at execution refuses the attempt before any work`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("changed.elf", elfFixture())
        val engines = FakeEngines().apply { resolvedDescriptor = "agent-harness-v1:acp:changed" }
        var reconstructed = false
        engines.reconstructBody = { _, _, _ -> reconstructed = true }
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val attempt = service.requestDurableStart(job.id, version(service, job.id), NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp"), "changed_harness_start1",
                harnessPrerequisites(acp = ACP_PROVENANCE)).attempt
            assertEquals(WorkflowRunState.FAILED, attempt.state); assertEquals(WorkflowTerminalReason.REFUSED, attempt.terminalReason)
            assertFalse(reconstructed, "work ran under a harness other than the admitted one")
        }
        // A record the current factory cannot reproduce never matches any resolution.
        val unreproducible = WebAdmittedHarness.of(WebAgentHarness.ACP, WorkflowAttemptHarness("acp", "fixture-agent", 1, 1, null, null, false))
        assertFailsWith<WebHarnessConfigurationChanged> { unreproducible.requireResolved(ACP_PROVENANCE.stableDescriptor) }
        assertNull(WebAdmittedHarness.of(WebAgentHarness.ACP, null).expectedDescriptor, "an unchecked admission invented provenance")
    }

    @Test
    fun `reconstruction scope is server-bounded, never selects modules and is recorded exactly with the attempt`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("scope.elf", elfFixture())
        val engines = FakeEngines()
        val agent = adapters(engines)[1]
        val scope = assertNotNull(agent.reconstruction)
        assertEquals(120_000 to 4_096, scope.defaultContextCharacters to scope.minimumContextCharacters)
        val evidenceScope = assertNotNull(adapters(engines)[2].reconstruction)
        assertNull(evidenceScope.defaultContextCharacters); assertNotEquals(scope.profileSha256, evidenceScope.profileSha256)
        val facts = webWorkflowCapabilities(adapters(engines), WebHarnessReadiness("supported", null, "ready", harnessPrerequisites(ACP_PROVENANCE)))
            .associateBy { it.getValue("id").jsonPrimitive.content }
        val reported = facts.getValue("workflow-reconstruct-agent-acp").getValue("launch").jsonObject.getValue("reconstruction").jsonObject
        assertEquals("all-planned", reported.getValue("moduleSelection").jsonPrimitive.content)
        assertEquals("deterministic", reported.getValue("planner").jsonPrimitive.content)
        assertEquals("4096", reported.getValue("contextCharacters").jsonObject.getValue("minimum").jsonPrimitive.content)
        assertEquals(JsonNull, facts.getValue("workflow-explore-tools").getValue("launch").jsonObject.getValue("reconstruction"))
        assertEquals(JsonNull, facts.getValue("workflow-reconstruct-evidence-only").getValue("launch").jsonObject.getValue("reconstruction")
            .jsonObject.getValue("contextCharacters"))
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            fun start(request: NewWorkflowAttempt, key: String, expected: String = version(service, job.id)) =
                service.requestDurableStart(job.id, expected, request, key, harnessPrerequisites(ACP_PROVENANCE))
            val reconstruct = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_AGENT, harnessCapabilityId = "agent-acp")
            listOf(4_095uL, 120_001uL).forEachIndexed { index, value ->
                assertCode("RECONSTRUCTION_SCOPE_UNAVAILABLE") { start(reconstruct.copy(scope = WorkflowReconstructionScope(value)), "scope_out_of_range_$index") }
            }
            assertCode("RECONSTRUCTION_SCOPE_UNAVAILABLE") {
                start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE, harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY,
                    scope = WorkflowReconstructionScope(60_000uL)), "scope_for_evidence_only")
            }
            assertCode("RECONSTRUCTION_SCOPE_UNAVAILABLE") {
                start(NewWorkflowAttempt(WorkflowKind.EXPLORE, WebWorkflowDefaults.EXPLORE, scope = WorkflowReconstructionScope(60_000uL)), "scope_for_exploration")
            }
            assertEquals(0, engines.calls.get(), "a refused scope executed an engine")
            val expected = version(service, job.id)
            val narrowed = start(reconstruct.copy(scope = WorkflowReconstructionScope(60_000uL)), "scope_narrowed_start", expected).attempt
            assertEquals(WorkflowAttemptReconstruction(scope.profileId, scope.profileSha256, 60_000uL), narrowed.configuration?.reconstruction)
            assertEquals(WorkflowReconstructionScope(60_000uL), narrowed.scope)
            assertEquals("60000", webRun(narrowed).getValue("configuration").jsonObject.getValue("reconstruction").jsonObject
                .getValue("maxContextCharacters").jsonPrimitive.content)
            // The same key with a different scope is a different intent.
            assertCode("IDEMPOTENCY_CONFLICT") { start(reconstruct.copy(scope = WorkflowReconstructionScope(50_000uL)), "scope_narrowed_start", expected) }
            val defaulted = start(reconstruct, "scope_default_start1").attempt
            assertEquals(120_000uL, defaulted.configuration?.reconstruction?.maxContextCharacters); assertNull(defaulted.scope)
            val evidence = start(NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE,
                harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY), "scope_evidence_start").attempt
            assertEquals(WorkflowAttemptReconstruction(evidenceScope.profileId, evidenceScope.profileSha256, null), evidence.configuration?.reconstruction)
            assertEquals(listOf(60_000, 120_000, null), engines.contexts, "execution did not run with the recorded budget")
        }
        // The scoped receipt validates on reopen and still replays the original attempt.
        service(store, adapters(engines)).use { service ->
            service.initializeExistingStorage()
            val retained = service.presentation(job.id).snapshot!!.attempts.first()
            assertEquals(WorkflowReconstructionScope(60_000uL), retained.scope)
        }
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
        override fun explore(binary: Path, reportsDirectory: Path) { calls.incrementAndGet(); exploreBody(reportsDirectory) }
        val harnesses = mutableListOf<WebAdmittedHarness?>()
        val contexts = mutableListOf<Int?>()
        /** The descriptor the inert "factory" resolves at execution; null leaves the admitted one unchecked. */
        var resolvedDescriptor: String? = null
        override fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress,
            harness: WebAdmittedHarness?, maxContextCharacters: Int?) {
            calls.incrementAndGet(); harnesses += harness; contexts += maxContextCharacters
            resolvedDescriptor?.let { harness?.requireResolved(it) }
            reconstructBody(reportsDirectory, mode, progress)
        }
        override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: WebAdmittedHarness): RepairRunStatus {
            calls.incrementAndGet(); harnesses += harness; check(harness.selector == "acp")
            resolvedDescriptor?.let { harness.requireResolved(it) }
            acceptRepairGraph(project); return RepairRunStatus.FULLY_ACCEPTED
        }
    }

    private fun adapters(engines: WebWorkflowEngines, acceptTestOnly: Boolean = false): List<DurableWebWorkflowAdapter> = listOf(
        ExploreWorkflowAdapter(engines, FAST),
        ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.AGENT, WebAgentHarness.ACP, emptyList()),
        ReconstructWorkflowAdapter(engines, FAST, WebReconstructionMode.EVIDENCE_ONLY, null, emptyList()),
        RepairWorkflowAdapter(engines, FAST, WebAgentHarness.ACP, acceptTestOnly),
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
        val ACP_PROVENANCE = WebHarnessProvenance.of(decompengine.acp.AcpHarnessProvenance("acp", "fixture-agent",
            decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION, decompengine.acp.ACP_STABLE_PROTOCOL_VERSION,
            decompengine.acp.ACP_KOTLIN_SDK_VERSION, "a".repeat(64), false))
        val LEGACY_PROVENANCE = WebHarnessProvenance.of(decompengine.acp.AcpHarnessProvenance("legacy-openai", "legacy-openai-compatible",
            decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION, null, null, null, true))

        /** A complete probe snapshot with per-harness facts; a null provenance is an unconfigured harness. */
        fun harnessPrerequisites(acp: WebHarnessProvenance?, legacy: WebHarnessProvenance? = null): WebWorkflowPrerequisites {
            fun facts(provenance: WebHarnessProvenance?, selected: Boolean) = WebHarnessFacts(if (provenance != null) WebPrerequisite.AVAILABLE
                else WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured."), provenance, selected)
            val harnesses = buildMap {
                put(WebAgentHarness.ACP, facts(acp, legacy == null))
                if (legacy != null) put(WebAgentHarness.LEGACY_OPENAI, facts(legacy, true))
            }
            return WebWorkflowPrerequisites(harnesses.values.single { it.selected }.prerequisite, WebPrerequisite.AVAILABLE,
                WebPrerequisite.AVAILABLE, harnesses)
        }

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

        fun acceptedHeadCandidate(project: Path): WorkflowCandidate {
            val history = readProjectRecordedRepairHistory(project)
            check(history.status == RepairHistoryReadStatus.RECORDED)
            val snapshot = checkNotNull(history.snapshot)
            val sha = checkNotNull(snapshot.attempts.single { it.identity == snapshot.fullyAcceptedHead }.sourceRevisionSha256)
            return WorkflowCandidate(webSourceRevisionId(sha), sha)
        }
    }
}

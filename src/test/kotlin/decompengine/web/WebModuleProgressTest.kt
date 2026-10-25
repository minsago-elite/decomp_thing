package decompengine.web

import decompengine.jobs.*
import decompengine.project.ModulePlan
import decompengine.project.PlannedModule
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.util.concurrent.Executor
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.*

/** Retained-report fixtures only: nothing here plans, generates, builds or runs a model. */
@ExtendWith(RecoveryMatrixEvidence::class)
class WebModuleProgressTest {
    @Test
    fun `stages separate analysis, planning, generation, validation and publication as an attempt advances`() {
        val adapters = adapters()
        fun stages(attempt: WorkflowAttempt, progress: String? = null, summary: String? = null, plan: Boolean = false, generation: String? = null) =
            webModuleProgress(JOB, WebModuleProgressCapture(attempt, progress?.toByteArray(), summary?.toByteArray(),
                if (plan) PLAN.toByteArray() else null, generation?.toByteArray()), adapters, null)
        fun states(value: JsonObject) = value.getValue("stages").jsonArray.associate {
            it.jsonObject.getValue("stage").jsonPrimitive.content to it.jsonObject.getValue("state").jsonPrimitive.content
        }
        val queued = stages(attempt(WorkflowRunState.QUEUED))
        assertEquals("not-recorded", queued.getValue("state").jsonPrimitive.content)
        assertTrue(states(queued).values.all { it == "pending" })
        val analysing = stages(attempt(WorkflowRunState.RUNNING))
        assertEquals(mapOf("analysis" to "active", "planning" to "pending", "generation" to "pending", "validation" to "pending",
            "publication" to "pending"), states(analysing))
        val planning = stages(attempt(WorkflowRunState.RUNNING), progress = """{"phase":"planning","completed":0,"total":0}""")
        assertEquals("completed", states(planning)["analysis"]); assertEquals("active", states(planning)["planning"])
        val generating = stages(attempt(WorkflowRunState.RUNNING), progress = """{"phase":"modules","completed":1,"total":3,"module":"module_b"}""", plan = true)
        assertEquals("active", states(generating)["generation"]); assertEquals("module_b", generating.getValue("currentModuleId").jsonPrimitive.content)
        val generation = generating.getValue("stages").jsonArray[2].jsonObject
        assertEquals("1" to "3", generation.getValue("completedUnits").jsonPrimitive.content to generation.getValue("totalUnits").jsonPrimitive.content)
        assertEquals("3", generating.getValue("plan").jsonObject.getValue("moduleCount").jsonPrimitive.content)
        // Every module finished generating; the profile build is the active stage.
        val building = stages(attempt(WorkflowRunState.RUNNING), progress = """{"phase":"modules","completed":3,"total":3,"module":"module_c"}""", plan = true)
        assertEquals("completed", states(building)["generation"]); assertEquals("active", states(building)["validation"])
        val candidate = WorkflowCandidate("source_${"e".repeat(64)}", "e".repeat(64))
        val completed = stages(attempt(WorkflowRunState.COMPLETED, candidate = candidate),
            progress = """{"phase":"unresolved","completed":3,"total":3,"unresolvedEntityCount":2}""", summary = SUMMARY, plan = true,
            generation = GENERATION)
        assertEquals(listOf("completed"), states(completed).values.distinct())
        assertEquals(listOf(null, "plan-recorded", null, "build-passed", "candidate-recorded"),
            completed.getValue("stages").jsonArray.map { it.jsonObject.getValue("outcome").let { o -> if (o == JsonNull) null else o.jsonPrimitive.content } })
        val unresolved = completed.getValue("unresolved").jsonObject
        assertEquals("1", unresolved.getValue("moduleCount").jsonPrimitive.content)
        assertEquals(listOf("module_b"), unresolved.getValue("moduleIds").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("2", unresolved.getValue("entityCount").jsonPrimitive.content)
        assertEquals(JsonNull, completed.getValue("currentModuleId"))
        assertEquals("ATTEMPT_COMPLETED", completed.getValue("recovery").jsonObject.getValue("reasonCode").jsonPrimitive.content)
        // A partially rewritten progress record is unknown, never a stage outcome.
        val torn = stages(attempt(WorkflowRunState.RUNNING), progress = """{"phase":"modules","compl""")
        assertEquals("active", states(torn)["analysis"])
        // A generation record that omits a planned module reports no per-module outcomes.
        val partial = stages(attempt(WorkflowRunState.COMPLETED, candidate = candidate), progress = """{"phase":"complete","completed":3,"total":3}""",
            summary = SUMMARY, plan = true, generation = GENERATION.replace(""",{"moduleId":"module_c","outcome":"accepted"}""", ""))
        assertEquals(JsonNull, partial.getValue("unresolved").jsonObject.getValue("moduleCount"))
        // A failed build leaves a retained candidate recorded but its publication incomplete.
        val failedBuild = stages(attempt(WorkflowRunState.FAILED, candidate = candidate, reason = WorkflowTerminalReason.FAILED),
            progress = """{"phase":"modules","completed":3,"total":3}""", plan = true)
        assertEquals("stopped", states(failedBuild)["validation"]); assertEquals("stopped", states(failedBuild)["publication"])
        val explore = webModuleProgress(JOB, WebModuleProgressCapture(attempt(WorkflowRunState.COMPLETED, workflow = WorkflowKind.EXPLORE),
            null, null, null, null), adapters, null)
        assertEquals("not-applicable", explore.getValue("state").jsonPrimitive.content)
        assertEquals(0, explore.getValue("stages").jsonArray.size); assertEquals(JsonNull, explore.getValue("recovery"))
    }

    @Test
    fun `a retained plan explains which current options could reuse it and why the others cannot`() {
        val adapters = adapters()
        val acp = ACP.copy(configurationSha256 = "a".repeat(64))
        val agentProfile = checkNotNull(adapters[1].reconstruction)
        val recorded = WorkflowAttemptConfiguration("workflow-reconstruct-agent-acp", "agent", false, true,
            listOf("ghidra", "agent-harness", "c-toolchain"), "none", true,
            WorkflowAttemptHarness("acp", acp.implementationId, acp.agentContractVersion, acp.protocolVersion, acp.sdkVersion,
                acp.configurationSha256, false),
            WorkflowAttemptReconstruction(agentProfile.profileId, agentProfile.profileSha256, 120_000uL))
        fun recovery(attempt: WorkflowAttempt, harness: WebHarnessProvenance? = acp, plan: Boolean = true,
            progress: String = """{"phase":"modules","completed":2,"total":3}"""): JsonObject {
            val prerequisites = WebWorkflowPrerequisites(WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE,
                harnesses = if (harness == null) emptyMap() else mapOf(WebAgentHarness.ACP to WebHarnessFacts(WebPrerequisite.AVAILABLE, harness, true)))
            return webModuleProgress(JOB, WebModuleProgressCapture(attempt, progress.toByteArray(), null, if (plan) PLAN.toByteArray() else null,
                null), adapters, prerequisites).getValue("recovery").jsonObject
        }
        fun options(value: JsonObject) = value.getValue("options").jsonArray.associate { option ->
            option.jsonObject.getValue("optionId").jsonPrimitive.content to (option.jsonObject.getValue("compatibility").jsonPrimitive.content to
                option.jsonObject.getValue("reasonCode").let { if (it == JsonNull) null else it.jsonPrimitive.content })
        }
        val interrupted = attempt(WorkflowRunState.INTERRUPTED, reason = WorkflowTerminalReason.PROCESS_INTERRUPTED, configuration = recorded)
        val same = recovery(interrupted)
        assertTrue(same.getValue("eligible").jsonPrimitive.content.toBoolean())
        assertEquals("2", same.getValue("retainedModules").jsonPrimitive.content)
        assertEquals("120000", same.getValue("recordedContextCharacters").jsonPrimitive.content)
        assertEquals(mapOf("workflow-reconstruct-agent-acp" to ("compatible" to null),
            "workflow-reconstruct-evidence-only" to ("incompatible" to "PROFILE_CHANGED")), options(same))
        // The same harness kind under a changed configuration keeps the plan but regenerates its checkpoints.
        val changed = recovery(interrupted, harness = acp.copy(configurationSha256 = "b".repeat(64),
            stableDescriptor = acp.stableDescriptor.replace("a".repeat(64), "b".repeat(64))))
        assertEquals("stale" to "HARNESS_CONFIGURATION_CHANGED", options(changed)["workflow-reconstruct-agent-acp"])
        assertEquals("unknown" to "HARNESS_UNRESOLVED", options(recovery(interrupted, harness = null))["workflow-reconstruct-agent-acp"])
        val narrower = attempt(WorkflowRunState.FAILED, reason = WorkflowTerminalReason.LIMIT_EXHAUSTED,
            configuration = recorded.copy(reconstruction = recorded.reconstruction!!.copy(maxContextCharacters = 8_192uL)))
        assertEquals("stale" to "CONTEXT_DIFFERS", options(recovery(narrower))["workflow-reconstruct-agent-acp"])
        val upgraded = attempt(WorkflowRunState.CANCELLED, reason = WorkflowTerminalReason.CANCELLED,
            configuration = recorded.copy(reconstruction = recorded.reconstruction!!.copy(profileSha256 = "f".repeat(64))))
        assertEquals("incompatible" to "PROFILE_CHANGED", options(recovery(upgraded))["workflow-reconstruct-agent-acp"])
        // Nothing can be explained without a recorded plan or configuration, and no option is offered.
        val unplanned = recovery(interrupted, plan = false, progress = """{"phase":"planning","completed":0,"total":0}""")
        assertEquals("PLAN_NOT_RECORDED", unplanned.getValue("reasonCode").jsonPrimitive.content)
        assertEquals(0, unplanned.getValue("options").jsonArray.size)
        val legacy = recovery(attempt(WorkflowRunState.INTERRUPTED, reason = WorkflowTerminalReason.PROCESS_INTERRUPTED))
        assertEquals("CONFIGURATION_NOT_RECORDED", legacy.getValue("reasonCode").jsonPrimitive.content)
    }

    @Test
    fun `the service reads only the attempt's own reports and refuses a capture across an attempt change`() {
        val root = createTempDirectory("module-progress-")
        try {
            val store = JobStore(root); val job = store.createFromUpload("modules.elf", elfFixture())
            val run = WorkflowAttemptStore.open(root, Clock.systemUTC()).use { owner ->
                val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                val queued = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WebWorkflowDefaults.RECONSTRUCT_EVIDENCE,
                    harnessCapabilityId = EVIDENCE_ONLY_CAPABILITY)).attempt
                owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
            }
            val reports = store.runReportsDirectory(job.id, run.runId, create = true)
            reports.resolve("reconstruction_progress.json").writeText("""{"phase":"modules","completed":1,"total":3,"module":"module_a"}""")
            reports.resolve("source-tree/reports").createDirectories().resolve("module_plan.json").writeText(PLAN)
            // A sibling attempt's directory is never read for this attempt.
            store.runReportsDirectory(job.id, "run_other", create = true).resolve("reconstruction.json").writeText(SUMMARY)
            WebJobService(store, JobAnalyzer { _, _ -> error("legacy") }, JobReconstructor { _, _ -> error("legacy") }, Executor(Runnable::run),
                durableAdapters = adapters(), attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC()) }).use { service ->
                service.initializeExistingStorage()
                val capture = service.readModuleProgress(job.id, run.runId)
                // Startup recovery interrupted the running attempt; its reports remain readable as retained evidence.
                assertEquals(WorkflowRunState.INTERRUPTED, capture.attempt.state)
                assertNotNull(capture.progress); assertNotNull(capture.plan); assertNull(capture.summary); assertNull(capture.generation)
                val value = webModuleProgress(job.id, capture, service.durableRegistrations(), null)
                assertEquals("stopped", value.getValue("stages").jsonArray[2].jsonObject.getValue("state").jsonPrimitive.content)
                assertFailsWith<WebJobServiceException> { service.readModuleProgress(job.id, "run_missing") }
            }
            assertFalse(Files.readString(root.resolve(job.id).resolve("workflow-state.json")).contains("module_a"))
        } finally { root.toFile().deleteRecursively() }
    }

    private fun adapters(): List<DurableWebWorkflowAdapter> {
        val engines = object : WebWorkflowEngines {
            override fun explore(binary: Path, reportsDirectory: Path) = error("not executed")
            override fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode,
                progress: decompengine.agent.AgentWorkflowProgress, harness: WebAdmittedHarness?, maxContextCharacters: Int?) = error("not executed")
            override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: WebAdmittedHarness) = error("not executed")
        }
        return listOf(ExploreWorkflowAdapter(engines, BoundedWorkflowExecutor()),
            ReconstructWorkflowAdapter(engines, BoundedWorkflowExecutor(), WebReconstructionMode.AGENT, WebAgentHarness.ACP, emptyList()),
            ReconstructWorkflowAdapter(engines, BoundedWorkflowExecutor(), WebReconstructionMode.EVIDENCE_ONLY, null, emptyList()))
    }

    private fun attempt(state: WorkflowRunState, workflow: WorkflowKind = WorkflowKind.RECONSTRUCT, candidate: WorkflowCandidate? = null,
        reason: WorkflowTerminalReason? = if (state == WorkflowRunState.COMPLETED) WorkflowTerminalReason.COMPLETED else null,
        configuration: WorkflowAttemptConfiguration? = null): WorkflowAttempt {
        val now = Instant.parse("2026-10-01T00:00:00Z")
        return WorkflowAttempt("run_modules", JOB, workflow, state, "version_modules", now, if (state == WorkflowRunState.QUEUED) null else now,
            if (state.terminal) now else null, null, null, "agent-acp", WebWorkflowDefaults.RECONSTRUCT_AGENT, reason, null, candidate, null,
            configuration = configuration)
    }

    private companion object {
        val JOB = "a".repeat(32)
        val ACP = WebHarnessProvenance.of(decompengine.acp.AcpHarnessProvenance("acp", "fixture-agent",
            decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION, decompengine.acp.ACP_STABLE_PROTOCOL_VERSION,
            decompengine.acp.ACP_KOTLIN_SDK_VERSION, "a".repeat(64), false))
        val PLAN = ModulePlan(modules = listOf("module_a", "module_b", "module_c").map { id ->
            PlannedModule(id, "src/$id.c", "include/$id.h", listOf("fn_$id"), emptyList(), boundaryEvidence = emptyList())
        }).toJson()
        const val SUMMARY = """{"moduleCount":3,"buildExitCode":0,"implementationStatus":"unresolved","unresolvedEntityCount":2,""" +
            """"profileId":"generated-c-make-v1","profileSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"""
        const val GENERATION = """{"schemaVersion":2,"sourceGenerationBudgetEvidence":{"schemaVersion":1,"modules":[""" +
            """{"moduleId":"module_a","outcome":"accepted"},{"moduleId":"module_b","outcome":"unresolved"},{"moduleId":"module_c","outcome":"accepted"}]}}"""
    }
}

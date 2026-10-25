package decompengine.jobs

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import java.time.Clock
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

@ExtendWith(RecoveryMatrixEvidence::class)
class WorkflowAttemptConfigurationTest {
    @Test
    fun `a job recorded with the earlier configuration shape stays readable and keeps its record`() {
        val root = createTempDirectory("attempt-configuration-")
        try {
            val job = JobStore(root).createFromUpload("earlier.elf", elfFixture())
            val configuration = WorkflowAttemptConfiguration("workflow-explore-tools", "tools", true, false, listOf("sandbox", "angr"),
                "none", true, null)
            val created = WorkflowAttemptStore.open(root, Clock.systemUTC()).use { owner ->
                val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE,
                    WorkflowExecutionLimits(60_000uL, 30_000uL, 1024uL, 0uL), configuration = configuration)).attempt
            }
            // The earlier record named an always-null profileId instead of the reconstruction object.
            val state = root.resolve(job.id).resolve("workflow-state.json")
            val earlier = state.readText().replace(Regex("\"reconstruction\"\\s*:\\s*null"), "\"profileId\":null")
            check(earlier != state.readText()) { state.readText() }
            state.writeText(earlier)
            WorkflowAttemptStore.open(root, Clock.systemUTC()).use { owner ->
                val inspected = assertIs<WorkflowJobInspection.Available>(owner.inspect(job.id))
                val attempt = inspected.snapshot.attempts.single { it.runId == created.runId }
                assertEquals(configuration, attempt.configuration); assertNull(attempt.configuration?.reconstruction)
            }
            // An earlier record that claims a profile without its digest is not silently reinterpreted.
            state.writeText(earlier.replace("\"profileId\":null", "\"profileId\":\"generated-c-make-v1\""))
            WorkflowAttemptStore.open(root, Clock.systemUTC()).use { owner ->
                assertIs<WorkflowJobInspection.Unavailable>(owner.inspect(job.id))
            }
        } finally { root.toFile().deleteRecursively() }
        assertFailsWith<IllegalArgumentException> {
            WorkflowAttemptConfiguration("workflow-explore-tools", "agent", true, false, emptyList(), "none", true, null)
        }
    }
}

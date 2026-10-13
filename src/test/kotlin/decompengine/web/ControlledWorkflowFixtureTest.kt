package decompengine.web

import decompengine.jobs.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.ZoneId
import kotlin.test.*

/** Store/control tests only; real HTTP evidence lives in WebProgressCutoverTest. */
class ControlledWorkflowFixtureTest {
    @Test fun `zone views follow logical advancement and reject backwards time`() {
        val clock = WorkflowFixtureClock()
        val zone = ZoneId.of("America/New_York")
        val view = clock.withZone(zone)
        val initial = clock.instant()
        clock.advance(Duration.ofNanos(1))
        assertEquals(initial.plusNanos(1), view.instant())
        assertEquals(zone, view.zone)
        assertFailsWith<IllegalArgumentException> { clock.advance(Duration.ofNanos(-1)) }
        assertEquals(initial.plusNanos(1), clock.instant())
    }

    @Test fun `reopened fixture preserves run identity and never reuses consumed identities`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-fixtures")), "controlled-workflow-")
        try {
            val fixture = ControlledWorkflowFixture()
            val store = fixture.jobStore(root)
            val job = store.createFromUpload("synthetic.elf", elfFixture())
            val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))
            val first = fixture.attemptStore(root).use { owner ->
                val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                owner.create(job.id, snapshot.version, request).attempt
            }
            fixture.clock.advance(Duration.ofSeconds(3))
            fixture.attemptStore(root).use { owner ->
                val recovered = (owner.recoverAfterRestart(job.id) as WorkflowJobInspection.Available).snapshot
                val interrupted = recovered.attempts.single()
                assertEquals(first.runId, interrupted.runId)
                assertEquals(WorkflowRunState.INTERRUPTED, interrupted.state)
                assertEquals(fixture.clock.instant(), interrupted.endedAt)
                val next = owner.create(job.id, recovered.version, request.copy(previousRunId = first.runId)).attempt
                assertNotEquals(first.runId, next.runId)
                assertEquals(first.runId, next.previousRunId)
                assertEquals(3, setOf(first.version, interrupted.version, next.version).size)
                assertEquals(fixture.clock.instant(), next.createdAt)
            }
        } finally { root.toFile().deleteRecursively() }
    }
}

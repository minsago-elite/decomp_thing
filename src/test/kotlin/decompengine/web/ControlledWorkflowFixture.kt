package decompengine.web

import decompengine.jobs.*
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Test-only controls. Real transport/session/cursor randomness is deliberately not replaced. */
internal class ControlledWorkflowFixture {
    val clock = WorkflowFixtureClock()
    private val jobs = AtomicLong()
    private val identities = AtomicLong()

    fun jobStore(root: Path) = JobStore(root, AtomicUploadPublisher, clock = clock,
        newJobId = { jobs.incrementAndGet().toString(16).padStart(32, '0') })

    // Keep this factory alive across reopen: consumed identities must not be reused after restart.
    fun attemptStore(root: Path) = WorkflowAttemptStore.open(root, clock, WorkflowStoreFaultInjector {},
        newId = { prefix -> "${prefix}_fixture_${identities.incrementAndGet()}" })
}

/** Zone views share a thread-safe logical time; advancing it does not sleep or run scheduled work. */
internal class WorkflowFixtureClock private constructor(
    private val now: AtomicReference<Instant>, private val zone: ZoneId,
) : Clock() {
    constructor() : this(AtomicReference(Instant.parse("2026-09-08T00:00:00Z")), ZoneOffset.UTC)
    override fun instant(): Instant = now.get()
    override fun getZone(): ZoneId = zone
    override fun withZone(zone: ZoneId): Clock = WorkflowFixtureClock(now, zone)
    fun advance(duration: Duration) {
        require(!duration.isNegative) { "Fixture time cannot move backwards" }
        now.updateAndGet { it.plus(duration) }
    }
}

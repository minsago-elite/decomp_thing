package decompengine.web

import decompengine.project.SourceTreeManifestProbe
import decompengine.project.SourceTreeManifestStage
import decompengine.project.endSafely
import decompengine.project.rethrowManifestProbeCancellation
import java.util.concurrent.atomic.AtomicLong

/** Request-thread intervals. The terminal describes the caller's outcome, including early refusals. */
internal class WebStructureTiming(
    private val clock: () -> Long = System::nanoTime,
    private val output: (String) -> Unit = { System.err.println(it) },
) : SourceTreeManifestProbe {
    private companion object { val invocationIds = AtomicLong() }
    private val id = invocationIds.incrementAndGet()
    private val totals = LongArray(SourceTreeManifestStage.entries.size)
    private val segments = LongArray(SourceTreeManifestStage.entries.size)
    private var active: SourceTreeManifestStage? = null
    private var started = 0L

    val phase: (String, Long) -> Unit = { name, nanos ->
        emit("web-structure-timing phase=$name elapsedNanos=$nanos invocationId=$id")
    }

    override fun start(stage: SourceTreeManifestStage) {
        end()
        started = clock()
        active = stage
    }

    override fun end() {
        val stage = active ?: return
        active = null
        totals[stage.ordinal] += clock() - started
        segments[stage.ordinal]++
    }

    fun finish(status: String) {
        try {
            endSafely()
            for (stage in SourceTreeManifestStage.entries) {
                val count = segments[stage.ordinal]
                if (count > 0) emit("web-structure-manifest-timing stage=${stage.marker} elapsedNanos=${totals[stage.ordinal]} segments=$count invocationId=$id")
            }
        } finally {
            emit("web-structure-timing-terminal invocationId=$id status=$status")
        }
    }

    private fun emit(line: String) {
        try { output(line) } catch (failure: Throwable) { rethrowManifestProbeCancellation(failure) }
    }
}

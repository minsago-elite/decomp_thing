package decompengine.web

import java.time.Instant
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

sealed interface WebSchedulerSnapshot {
    val sampledAt: Instant
    data class Available(
        override val sampledAt: Instant,
        val stopping: Boolean,
        val activeWorkers: Int,
        val workerLimit: Int,
        val queuedTasks: Int,
        val queueCapacity: Int,
    ) : WebSchedulerSnapshot
    data class Unavailable(override val sampledAt: Instant) : WebSchedulerSnapshot
}

internal fun webSchedulerSnapshot(snapshot: WebSchedulerSnapshot): JsonObject = buildJsonObject {
    put("sampledAt", snapshot.sampledAt.toString())
    when (snapshot) {
        is WebSchedulerSnapshot.Unavailable -> {
            put("state", "unavailable")
            put("reasonCode", "EXTERNAL_EXECUTOR")
        }
        is WebSchedulerSnapshot.Available -> {
            put("state", "available")
            put("source", "web-workflow-executor")
            put("approximate", true)
            put("lifecycle", if (snapshot.stopping) "stopping" else "running")
            put("activeWorkers", snapshot.activeWorkers.toString())
            put("workerLimit", snapshot.workerLimit.toString())
            put("queuedTasks", snapshot.queuedTasks.toString())
            put("queueCapacity", snapshot.queueCapacity.toString())
        }
    }
}

/** One attempt's sampled place in this process's executor queue; never admission or scheduling authority. */
sealed interface WebQueuePosition {
    val sampledAt: Instant
    /** [position] is one-based; [ahead] counts queued tasks of any job without identifying them. */
    data class Queued(override val sampledAt: Instant, val position: Int, val queuedTasks: Int,
        val activeWorkers: Int, val workerLimit: Int) : WebQueuePosition {
        init { require(position in 1..32 && queuedTasks in position..32 && activeWorkers in 0..workerLimit && workerLimit in 1..2) }
    }
    data class NotQueued(override val sampledAt: Instant, val state: decompengine.jobs.WorkflowRunState) : WebQueuePosition {
        init { require(state != decompengine.jobs.WorkflowRunState.QUEUED) }
    }
    data class Unavailable(override val sampledAt: Instant, val reasonCode: String) : WebQueuePosition {
        init { require(reasonCode in setOf("EXTERNAL_EXECUTOR", "NOT_IN_LOCAL_QUEUE")) }
    }
}

internal fun webQueuePosition(jobId: String, runId: String, value: WebQueuePosition): JsonObject = buildJsonObject {
    put("jobId", jobId); put("runId", runId); put("sampledAt", value.sampledAt.toString())
    when (value) {
        is WebQueuePosition.Queued -> {
            put("state", "queued"); put("source", "web-workflow-executor"); put("approximate", true)
            put("position", value.position.toString()); put("ahead", (value.position - 1).toString())
            put("queuedTasks", value.queuedTasks.toString())
            put("activeWorkers", value.activeWorkers.toString()); put("workerLimit", value.workerLimit.toString())
        }
        is WebQueuePosition.NotQueued -> { put("state", "not-queued"); put("runState", value.state.wireName) }
        is WebQueuePosition.Unavailable -> { put("state", "unavailable"); put("reasonCode", value.reasonCode) }
    }
}

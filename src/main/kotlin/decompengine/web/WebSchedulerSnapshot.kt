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

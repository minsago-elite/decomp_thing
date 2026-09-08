package decompengine.jobs

import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.time.Instant
import java.util.Collections

/** Attribution and key scoping only; this value does not authorize a command. */
class WorkflowCancellationActor private constructor(val digest: String) {
    companion object {
        internal fun browserSession(sessionId: String): WorkflowCancellationActor {
            require(sessionId.matches(Regex("[0-9a-f]{64}")))
            return WorkflowCancellationActor(cancellationDigest("decomp-cancel-actor-v1:$sessionId"))
        }
    }
}

internal fun cancellationDigest(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(Charsets.US_ASCII)).joinToString("") { "%02x".format(it) }

data class WorkflowCancellationReceipt(val actorDigest: String, val requestKeyDigest: String,
    val runId: String, val expectedVersion: String, val appliedVersion: String,
    val acknowledgedState: WorkflowRunState, val at: Instant)

data class WorkflowCancellationRequestResult(val attempt: WorkflowAttempt, val receipt: WorkflowCancellationReceipt, val replayed: Boolean)

/** Receipts remain with the job. Refuse new keys at capacity rather than silently forgetting replay. */
class WorkflowCancellationReceipts private constructor(entries: List<WorkflowCancellationReceipt>) {
    val entries: List<WorkflowCancellationReceipt> = Collections.unmodifiableList(entries.toList())
    init {
        require(entries.size <= MAX_ENTRIES)
        require(entries.map { Triple(it.actorDigest, it.runId, it.requestKeyDigest) }.distinct().size == entries.size)
        entries.forEach { entry ->
            require(entry.actorDigest.matches(Regex("[0-9a-f]{64}")) && entry.requestKeyDigest.matches(Regex("[0-9a-f]{64}")))
            listOf(entry.runId, entry.expectedVersion, entry.appliedVersion).forEach { require(it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) }
            require(entry.acknowledgedState == WorkflowRunState.CANCELLING || entry.acknowledgedState.terminal)
            require(!entry.acknowledgedState.terminal || entry.expectedVersion == entry.appliedVersion)
            require(entry.at.toString().length <= 40)
        }
    }
    override fun equals(other: Any?) = other is WorkflowCancellationReceipts && entries == other.entries
    override fun hashCode() = entries.hashCode()
    internal fun append(entry: WorkflowCancellationReceipt): WorkflowCancellationReceipts {
        if (entries.size == MAX_ENTRIES) throw WorkflowStoreException("CANCELLATION_RECEIPT_CAPACITY", "Retained cancellation receipts are at capacity; no new command was applied.")
        return WorkflowCancellationReceipts(entries + entry)
    }
    internal fun validateTargets(attempts: List<WorkflowAttempt>) {
        val byId = attempts.associateBy { it.runId }
        entries.forEach { receipt ->
            val attempt = requireNotNull(byId[receipt.runId])
            require(attempt.state == WorkflowRunState.CANCELLING || attempt.state.terminal)
            require(!receipt.acknowledgedState.terminal || attempt.state == receipt.acknowledgedState)
        }
    }
    internal fun encode(): JsonObject = buildJsonObject {
        put("version", 1)
        put("entries", JsonArray(entries.map { e -> buildJsonObject {
            put("actorDigest", e.actorDigest); put("requestKeyDigest", e.requestKeyDigest); put("runId", e.runId)
            put("expectedVersion", e.expectedVersion); put("appliedVersion", e.appliedVersion)
            put("acknowledgedState", e.acknowledgedState.wireName); put("at", e.at.toString())
        } }))
    }
    companion object {
        const val MAX_ENTRIES = 256
        val EMPTY = WorkflowCancellationReceipts(emptyList())
        internal fun decode(value: JsonElement): WorkflowCancellationReceipts {
            val root = value.jsonObject
            require(root.keys == setOf("version", "entries") && root["version"] == JsonPrimitive(1))
            val entries = root.getValue("entries").jsonArray
            require(entries.size <= MAX_ENTRIES)
            return WorkflowCancellationReceipts(entries.map { value ->
                val e = value.jsonObject
                require(e.keys == setOf("actorDigest", "requestKeyDigest", "runId", "expectedVersion", "appliedVersion", "acknowledgedState", "at"))
                fun text(key: String) = e.getValue(key).jsonPrimitive.let { require(it.isString); it.content }
                val at = text("at"); require(at.length <= 40)
                val instant = Instant.parse(at); require(instant.toString() == at)
                WorkflowCancellationReceipt(text("actorDigest"), text("requestKeyDigest"), text("runId"), text("expectedVersion"), text("appliedVersion"),
                    WorkflowRunState.entries.single { it.wireName == text("acknowledgedState") }, instant)
            })
        }
    }
}

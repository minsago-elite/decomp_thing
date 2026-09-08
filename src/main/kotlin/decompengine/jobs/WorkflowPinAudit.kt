package decompengine.jobs

import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.time.Instant
import java.util.Collections

/** Attribution only: possession of an audit actor never authorizes a mutation. */
data class WorkflowPinActor private constructor(val kind: String, val sessionDigest: String?) {
    init {
        require(kind == "internal" && sessionDigest == null || kind == "browser_session" &&
            sessionDigest?.matches(Regex("[0-9a-f]{64}")) == true) { "invalid pin audit actor" }
    }
    companion object {
        val INTERNAL = WorkflowPinActor("internal", null)
        internal fun browserSession(sessionId: String): WorkflowPinActor {
            require(sessionId.matches(Regex("[0-9a-f]{64}"))) { "invalid session identity" }
            val digest = MessageDigest.getInstance("SHA-256").digest("decomp-pin-audit-v1:$sessionId".toByteArray(Charsets.US_ASCII))
                .joinToString("") { "%02x".format(it) }
            return WorkflowPinActor("browser_session", digest)
        }
        internal fun decode(kind: String, digest: String?) = WorkflowPinActor(kind, digest)
    }
}

data class WorkflowPinAuditEntry(
    val sequence: ULong, val at: Instant, val actor: WorkflowPinActor, val runId: String,
    val pinned: Boolean, val previousVersion: String, val appliedVersion: String,
)

/** Bounded receipts of applied changes, committed in the same file as the pin. Not a request log. */
class WorkflowPinAudit private constructor(val omitted: ULong, entries: List<WorkflowPinAuditEntry>) {
    val entries: List<WorkflowPinAuditEntry> = Collections.unmodifiableList(entries.toList())
    init {
        require(entries.size <= MAX_ENTRIES && (omitted == 0uL || entries.size == MAX_ENTRIES))
        require(omitted <= ULong.MAX_VALUE - entries.size.toULong())
        entries.forEachIndexed { index, entry ->
            require(entry.sequence == omitted + index.toULong())
            listOf(entry.runId, entry.previousVersion, entry.appliedVersion).forEach {
                require(it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
            }
            require(entry.previousVersion != entry.appliedVersion)
            require(entry.at.toString().length <= 40)
        }
    }
    override fun equals(other: Any?): Boolean = other is WorkflowPinAudit && omitted == other.omitted && entries == other.entries
    override fun hashCode(): Int = 31 * omitted.hashCode() + entries.hashCode()

    internal fun append(at: Instant, actor: WorkflowPinActor, before: WorkflowAttempt, after: WorkflowAttempt): WorkflowPinAudit {
        val next = omitted + entries.size.toULong()
        if (next == ULong.MAX_VALUE) throw WorkflowStoreException("STORE_LIMIT", "The retained pin audit sequence is exhausted.")
        val appended = entries + WorkflowPinAuditEntry(next, at, actor, after.runId, after.progressRetentionPinned, before.version, after.version)
        return WorkflowPinAudit(omitted + if (entries.size == MAX_ENTRIES) 1uL else 0uL, appended.takeLast(MAX_ENTRIES))
    }
    internal fun validateTargets(attempts: List<WorkflowAttempt>) {
        val byId = attempts.associateBy { it.runId }
        entries.groupBy { it.runId }.forEach { (runId, receipts) ->
            val attempt = requireNotNull(byId[runId])
            require(receipts.last().pinned == attempt.progressRetentionPinned)
            require(receipts.zipWithNext().all { (before, after) -> before.pinned != after.pinned })
        }
    }
    internal fun encode(): JsonObject = buildJsonObject {
        put("version", 1); put("omitted", omitted.toString())
        put("entries", JsonArray(entries.map { entry -> buildJsonObject {
            put("sequence", entry.sequence.toString()); put("at", entry.at.toString())
            put("actor", buildJsonObject {
                put("kind", entry.actor.kind); put("sessionDigest", entry.actor.sessionDigest?.let(::JsonPrimitive) ?: JsonNull)
            })
            put("runId", entry.runId); put("action", if (entry.pinned) "progress.pin" else "progress.unpin")
            put("outcome", "applied"); put("previousVersion", entry.previousVersion); put("appliedVersion", entry.appliedVersion)
        } }))
    }
    companion object {
        const val MAX_ENTRIES = 256
        val EMPTY = WorkflowPinAudit(0uL, emptyList())
        internal fun decode(value: JsonElement): WorkflowPinAudit {
            val root = value.jsonObject
            require(root.keys == setOf("version", "omitted", "entries"))
            require(root["version"] == JsonPrimitive(1))
            val entries = root.getValue("entries").jsonArray
            require(entries.size <= MAX_ENTRIES)
            return WorkflowPinAudit(root.uint("omitted"), entries.map { value ->
                val e = value.jsonObject
                require(e.keys == setOf("sequence", "at", "actor", "runId", "action", "outcome", "previousVersion", "appliedVersion"))
                require(e.text("outcome") == "applied")
                val actor = e.getValue("actor").jsonObject
                require(actor.keys == setOf("kind", "sessionDigest"))
                val at = e.text("at"); require(at.length <= 40)
                val instant = Instant.parse(at); require(instant.toString() == at)
                val action = e.text("action"); require(action in setOf("progress.pin", "progress.unpin"))
                WorkflowPinAuditEntry(e.uint("sequence"), instant,
                    WorkflowPinActor.decode(actor.text("kind"), if (actor.getValue("sessionDigest") == JsonNull) null else actor.text("sessionDigest")),
                    e.text("runId"), action == "progress.pin", e.text("previousVersion"), e.text("appliedVersion"))
            })
        }
        private fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.let { require(it.isString); it.content }
        private fun JsonObject.uint(key: String): ULong = text(key).let { require(it.matches(Regex("0|[1-9][0-9]{0,19}"))); it.toULong() }
    }
}

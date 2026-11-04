package decompengine.builtin.provider

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.Collections

/** Invocation-scoped synthetic-secret registry. Register dynamic additions before consuming output. */
internal class ChatGptPlanSecretsV1 {
    private val secrets = ArrayList<String>()
    private val guards = LinkedHashSet<Guard>()
    private var totalBytes = 0
    private var snapshot = Snapshot(0, emptyList())

    /**
     * Validation failures do not accept an addition. Once published, acceptance is permanent even
     * if a sink then fails with TRANSPORT; duplicates are no-ops, not publication retries. Every
     * surviving guard already has the accepted snapshot. This cannot protect previously emitted text.
     */
    @Synchronized
    fun registerSynthetic(secret: String) {
        val bytes = ChatGptPlanWireJsonV1.scalarUtf8Length(secret, MAX_SECRET_BYTES)
            ?: resourceExhausted()
        if (bytes == 0) malformed()
        if (secret in secrets) return
        if (secrets.size >= MAX_ENTRIES || bytes > MAX_TOTAL_BYTES - totalBytes) resourceExhausted()
        val next = Snapshot(snapshot.version + 1, snapshot.patterns + Pattern(secret))
        val live = guards.toList()
        secrets.add(secret)
        totalBytes += bytes
        snapshot = next
        // Phase one has no callbacks: reentrant sinks must never reach a stale live guard.
        live.forEach { it.installSnapshot(next) }
        // Use each guard's CURRENT snapshot: a callback may publish a newer version recursively.
        // A failed sink revokes that guard; unvisited survivors are current and rescan on next use.
        live.forEach { it.rescanHeldText() }
    }

    /** Reject private payloads containing registered secrets or credential-shaped fields/values. */
    @Synchronized
    fun rejectCredentialsInPrivateJson(value: JsonElement) {
        val budget = WalkBudget()
        try {
            scan(value, budget)
        } catch (_: PrivateWalkFailure) {
            throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
        }
    }

    @Synchronized
    fun displayGuard(emit: (String) -> Unit): ChatGptDisplayGuardV1 {
        val guard = Guard(this, emit, snapshot)
        guards.add(guard)
        return guard
    }

    @Synchronized
    private fun release(guard: Guard) { guards.remove(guard) }

    private fun scan(value: JsonElement, budget: WalkBudget) {
        val pending = ArrayDeque<Pair<JsonElement, Int>>()
        pending.addLast(value to 0)
        while (pending.isNotEmpty()) {
            val (element, depth) = pending.removeLast()
            budget.visit()
            if (depth > MAX_JSON_DEPTH) throw PrivateWalkFailure()
            when (element) {
                is JsonObject -> {
                    budget.ensureChildren(element.size, pending.size)
                    for ((key, child) in element) {
                        budget.scalar(key)
                        if (containsCredentialMarker(key) || containsSecret(key)) exposed()
                        pending.addLast(child to depth + 1)
                    }
                }
                is JsonArray -> {
                    budget.ensureChildren(element.size, pending.size)
                    for (child in element) pending.addLast(child to depth + 1)
                }
                is JsonPrimitive -> {
                    val scalar = element.content
                    budget.scalar(scalar)
                    if (containsCredentialMarker(scalar) || containsSecret(scalar)) exposed()
                }
            }
        }
    }

    private fun containsSecret(value: String): Boolean = secrets.any { value.contains(it) }

    private class WalkBudget {
        private var nodes = 0
        private var chars = 0L
        fun visit() {
            if (++nodes > MAX_JSON_NODES) throw PrivateWalkFailure()
        }
        fun ensureChildren(count: Int, queued: Int) {
            if (count > MAX_JSON_NODES - nodes - queued) throw PrivateWalkFailure()
        }
        fun scalar(value: String) {
            if (value.length > MAX_JSON_SCALAR_CHARS ||
                ChatGptPlanWireJsonV1.scalarUtf8Length(value, MAX_JSON_SCALAR_BYTES) == null) throw PrivateWalkFailure()
            chars += value.length.toLong()
            if (chars > MAX_JSON_TOTAL_CHARS) throw PrivateWalkFailure()
        }
    }

    private class PrivateWalkFailure : RuntimeException()

    /** Immutable shared matcher tables, built before acceptance and never exposed to callbacks. */
    private class Snapshot(val version: Int, entries: List<Pattern>) {
        val patterns: List<Pattern> = Collections.unmodifiableList(ArrayList(entries))
        val lookbehind = maxOf(1, (patterns.maxOfOrNull { it.text.length } ?: 0) - 1)
    }

    private class Pattern(val text: String) {
        private val prefix = IntArray(text.length).also { table ->
            var matched = 0
            for (i in 1 until text.length) {
                while (matched > 0 && text[i] != text[matched]) matched = table[matched - 1]
                if (text[i] == text[matched]) matched++
                table[i] = matched
            }
        }

        /** Mark ALL matches, including overlaps, and return the still-possible suffix length. */
        fun cover(input: String, ranges: IntArray): Int {
            var matched = 0
            for (i in input.indices) {
                while (matched > 0 && input[i] != text[matched]) matched = prefix[matched - 1]
                if (input[i] == text[matched]) matched++
                if (matched == text.length) {
                    ranges[i + 1 - text.length]++
                    ranges[i + 1]--
                    matched = prefix[matched - 1]
                }
            }
            return matched
        }
    }

    private class Guard(
        private val owner: ChatGptPlanSecretsV1,
        private val emit: (String) -> Unit,
        initial: Snapshot,
    ) : ChatGptDisplayGuardV1 {
        private var snapshot = initial
        private var tail = ""
        private var covered = BooleanArray(0)
        // Raw lookbehind includes already delivered positions, so a full match never erases
        // the state needed to cover a later overlapping match. delivered is relative to tail.
        private var delivered = 0
        private var redacting = false
        private var settled = false

        fun installSnapshot(next: Snapshot) {
            if (settled || next.version <= snapshot.version) return
            snapshot = next
        }

        fun rescanHeldText() {
            if (!settled) deliver(process("", flush = false))
        }

        override fun append(text: String) = synchronized(owner) {
            if (settled) fixedFailure()
            if (text.length > MAX_DISPLAY_CHUNK_CHARS) resourceExhausted()
            if (!validDisplayChunk(text, tail)) malformed()
            deliver(process(text, flush = false))
        }

        override fun finishValidatedCompletion() = synchronized(owner) {
            if (settled) fixedFailure()
            if (ChatGptPlanWireJsonV1.scalarUtf8Length(tail, MAX_LOOKBEHIND_BYTES) == null) {
                discardOnFailure()
                malformed()
            }
            val safe = process("", flush = true)
            discardOnFailure()
            deliver(safe)
        }

        override fun discardOnFailure() = synchronized(owner) {
            if (settled) return@synchronized
            tail = ""
            covered = BooleanArray(0)
            delivered = 0
            redacting = false
            settled = true
            owner.release(this)
        }

        /**
         * Union coverage survives both replacement and trimming. Emit uncovered text only when
         * no unfinished match can reach it; covered text may emit its marker immediately. Adjacent
         * or overlapping covered positions share a marker, independent of append partitions.
         * Retention is max-secret-length minus one UTF-16 units (at least one), plus at most one
         * scalar-boundary adjustment. Transient buffers add only the bounded append chunk.
         */
        private fun process(text: String, flush: Boolean): String {
            val input = tail + text
            if (input.isEmpty()) return ""
            val coverage = covered.copyOf(input.length)
            val ranges = IntArray(input.length + 1)
            var holdFrom = if (input.last().isHighSurrogate()) input.length - 1 else input.length
            for (pattern in snapshot.patterns) {
                holdFrom = minOf(holdFrom, input.length - pattern.cover(input, ranges))
            }
            var overlaps = 0
            for (i in input.indices) {
                overlaps += ranges[i]
                coverage[i] = coverage[i] || overlaps > 0
            }
            val out = StringBuilder()
            var cursor = delivered
            while (cursor < input.length) {
                if (coverage[cursor]) {
                    if (!redacting) out.append(REDACTED)
                    redacting = true
                } else {
                    if (!flush && cursor >= holdFrom) break
                    out.append(input[cursor])
                    redacting = false
                }
                cursor++
            }
            var drop = minOf(cursor, maxOf(0, input.length - snapshot.lookbehind))
            if (drop > 0 && input[drop].isLowSurrogate()) drop--
            tail = input.substring(drop)
            covered = coverage.copyOfRange(drop, input.length)
            delivered = cursor - drop
            return out.toString()
        }

        private fun validDisplayChunk(text: String, prefix: String): Boolean {
            val combined = prefix + text
            val scan = if (combined.lastOrNull()?.isHighSurrogate() == true) combined.dropLast(1) else combined
            return ChatGptPlanWireJsonV1.scalarUtf8Length(scan, MAX_DISPLAY_CHUNK_BYTES + MAX_LOOKBEHIND_BYTES) != null
        }

        private fun deliver(text: String) {
            if (text.isEmpty()) return
            try { emit(text) } catch (_: Throwable) {
                discardOnFailure()
                throw ModelProviderException(ModelFailureKind.TRANSPORT)
            }
        }

        override fun toString() = "ChatGptDisplayGuardV1(redacted)"
    }

    override fun toString() = "ChatGptPlanSecretsV1(redacted)"

    companion object {
        const val MAX_ENTRIES = 128
        const val MAX_SECRET_BYTES = 16 * 1024
        const val MAX_TOTAL_BYTES = 1024 * 1024
        const val MAX_JSON_NODES = 100_000
        const val MAX_JSON_DEPTH = 32
        const val MAX_JSON_SCALAR_BYTES = 1 shl 20
        const val MAX_JSON_SCALAR_CHARS = 1 shl 20
        const val MAX_JSON_TOTAL_CHARS = 4L shl 20
        const val MAX_DISPLAY_CHUNK_CHARS = 8192
        const val MAX_DISPLAY_CHUNK_BYTES = 32 * 1024
        // Raw context need not resemble a secret: a UTF-16 unit can occupy three UTF-8 bytes.
        private const val MAX_LOOKBEHIND_BYTES = 3 * MAX_SECRET_BYTES
        private const val REDACTED = "[REDACTED]"
        private val CREDENTIAL_FIELD = Regex("(?i)(?:access[_-]?token|refresh[_-]?token|bearer|authorization|credential|client[_-]?secret|password|id[_-]?token)")
        private val BEARER_VALUE = Regex("(?i)\\bbearer\\s+\\S+")

        private fun containsCredentialMarker(value: String) = CREDENTIAL_FIELD.containsMatchIn(value) || BEARER_VALUE.containsMatchIn(value)
        private fun exposed(): Nothing = throw ModelProviderException(ModelFailureKind.SECRET_EXPOSURE)
        private fun malformed(): Nothing = throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
        private fun resourceExhausted(): Nothing = throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
        private fun fixedFailure(): Nothing = throw ModelProviderException(ModelFailureKind.TRANSPORT)
    }
}

internal interface ChatGptDisplayGuardV1 {
    fun append(text: String)
    fun finishValidatedCompletion()
    fun discardOnFailure()
}

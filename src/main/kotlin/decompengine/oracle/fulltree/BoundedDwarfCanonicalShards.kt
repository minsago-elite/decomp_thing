package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.ByteArrayOutputStream
import java.util.ArrayDeque
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/** Aggregate limits belong to one writer session, including every record kind and envelope. */
internal data class BoundedDwarfShardLimits(
    val maximumShardBytes: Int = 8 * 1024 * 1024,
    val maximumShardNodes: Int = 100_000,
    val maximumTotalBytes: Long = 512L * 1024 * 1024,
    val maximumTotalNodes: Long = 16_000_000,
    val maximumShards: Int = 256,
) {
    init {
        require(maximumShardBytes in 1..8 * 1024 * 1024)
        require(maximumShardNodes in 1..100_000)
        require(maximumTotalBytes in 1..512L * 1024 * 1024)
        require(maximumTotalNodes in 1..16_000_000)
        require(maximumShards in 1..256)
    }

    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "maximumShardBytes" to JsonPrimitive(maximumShardBytes),
        "maximumShardNodes" to JsonPrimitive(maximumShardNodes),
        "maximumTotalBytes" to JsonPrimitive(maximumTotalBytes),
        "maximumTotalNodes" to JsonPrimitive(maximumTotalNodes),
        "maximumShards" to JsonPrimitive(maximumShards),
    ))

    internal fun jsonLimits(record: Boolean = false): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = maximumShardBytes,
        maximumCanonicalBytes = maximumShardBytes,
        maximumDepth = if (record) 62 else 64,
        maximumNodes = maximumShardNodes,
        maximumStringBytes = maximumShardBytes,
        maximumTotalStringBytes = maximumShardBytes,
    )
}

internal data class BoundedDwarfShardSummary(
    val totalBytes: Long,
    val totalNodes: Long,
    val totalShards: Int,
    val totalRecords: Long,
)

internal data class BoundedDwarfCanonicalShard(
    val kind: String,
    val ordinal: Int,
    val recordCount: Int,
    val records: List<JsonObject>,
    val nodeCount: Int,
)

/**
 * Validates one closed canonical envelope. This does not establish bundle order, completeness, or
 * provenance; its caller must bind those and charge [BoundedDwarfCanonicalShard.nodeCount] across
 * all raw and derived groups against the bundle's aggregate limits.
 */
internal fun parseCanonicalDwarfShard(
    bytes: ByteArray,
    limits: BoundedDwarfShardLimits = BoundedDwarfShardLimits(),
    expectedKind: String? = null,
    expectedOrdinal: Int? = null,
    expectedRecordCount: Int? = null,
): BoundedDwarfCanonicalShard {
    // OracleJson.parseCanonical snapshots its input before parsing, so reject before that copy.
    if (bytes.size > limits.maximumShardBytes) shardFail("canonical input exceeds the shard byte limit")
    val root = OracleJson.parseCanonical(bytes, limits.jsonLimits()) as? JsonObject
        ?: shardFail("envelope must be an object")
    if (root.keys != SHARD_KEYS) shardFail("envelope keys differ from the closed schema")
    fun string(key: String): String {
        val value = root[key] as? JsonPrimitive ?: shardFail("$key must be a string")
        if (!value.isString) shardFail("$key must be a string")
        return value.content
    }
    fun integer(key: String): Int {
        val value = root[key] as? JsonPrimitive ?: shardFail("$key must be an integer")
        if (value.isString) shardFail("$key must be an integer")
        return value.intOrNull?.takeIf { it >= 0 } ?: shardFail("$key must be a nonnegative integer")
    }
    if (string("schema") != SHARD_SCHEMA) shardFail("unsupported schema")
    val kind = string("kind")
    validateShardKind(kind)
    val ordinal = integer("ordinal")
    if (ordinal >= limits.maximumShards) shardFail("ordinal exceeds the shard count limit")
    val count = integer("recordCount")
    val records = root["records"] as? JsonArray ?: shardFail("records must be an array")
    if (count != records.size) shardFail("record count does not match the envelope")
    if (expectedKind != null && kind != expectedKind) shardFail("kind differs from the expected kind")
    if (expectedOrdinal != null && ordinal != expectedOrdinal) shardFail("ordinal differs from the expected ordinal")
    if (expectedRecordCount != null && count != expectedRecordCount) shardFail("record count differs from the expected count")
    val objects = records.map { it as? JsonObject ?: shardFail("every record must be an object") }
    return BoundedDwarfCanonicalShard(
        kind, ordinal, count, Collections.unmodifiableList(objects), countShardNodes(root, limits.maximumShardNodes),
    )
}

/**
 * Greedily emits deterministic shards in input order. An empty kind emits exactly one empty shard;
 * each kind can be written only once and starts at ordinal zero. No aggregate record list is built.
 *
 * Record canonical bytes are encoded once for sizing and retained until their shard is emitted.
 * Only indentation and array separators are added when assembling the envelope. The complete bytes
 * are checked again with OracleJson before the consumer receives them. Each record and each emitted
 * shard is visited a constant number of times; growing prefixes are never repeatedly serialized.
 *
 * A failure may follow already emitted shards. Callers must publish a complete bundle only after
 * [finish] succeeds. A failed or reentrant session cannot be used to publish further shards.
 */
internal class BoundedDwarfCanonicalShardWriter(
    private val limits: BoundedDwarfShardLimits = BoundedDwarfShardLimits(),
    private val consumer: (kind: String, ordinal: Int, bytes: ByteArray, recordCount: Int) -> Unit,
) {
    private enum class State { OPEN, WRITING, FAILED, FINISHED }
    private var state = State.OPEN
    private val kinds = HashSet<String>()
    private var totalBytes = 0L
    private var totalNodes = 0L
    private var totalShards = 0
    private var totalRecords = 0L

    fun write(kind: String, records: Sequence<JsonObject>) {
        if (state != State.OPEN) {
            if (state == State.WRITING) state = State.FAILED
            shardFail("writer is not open")
        }
        state = State.WRITING
        try {
            validateShardKind(kind)
            if (!kinds.add(kind)) shardFail("record kind was already written")
            var ordinal = 0
            var skeleton = emptyEnvelope(kind, ordinal, 0)
            val pending = ArrayList<ByteArray>()
            var indentedRecordBytes = 0L
            var nodes = SHARD_ENVELOPE_NODES

            fun emit() {
                if (state != State.WRITING) shardFail("record source reentered the writer")
                val expectedBytes = shardByteCount(skeleton.size, pending.size, indentedRecordBytes)
                if (expectedBytes > limits.maximumShardBytes || nodes > limits.maximumShardNodes) {
                    shardFail("envelope exceeds a shard limit")
                }
                // Charge the aggregate limits before allocating and validating the complete shard.
                if (totalShards >= limits.maximumShards ||
                    totalBytes > limits.maximumTotalBytes - expectedBytes ||
                    totalNodes > limits.maximumTotalNodes - nodes
                ) shardFail("aggregate shard budget exceeded")
                val bytes = assemble(kind, ordinal, pending, expectedBytes.toInt())
                val parsed = parseCanonicalDwarfShard(bytes, limits, kind, ordinal, pending.size)
                if (bytes.size.toLong() != expectedBytes || parsed.nodeCount != nodes) {
                    shardFail("canonical envelope differs from its measured budget")
                }
                totalBytes += bytes.size
                totalNodes += parsed.nodeCount
                totalShards++
                totalRecords += pending.size
                consumer(kind, ordinal, bytes, pending.size)
                if (state != State.WRITING) shardFail("consumer reentered the writer")
                pending.clear()
                indentedRecordBytes = 0L
                nodes = SHARD_ENVELOPE_NODES
            }

            for (record in records) {
                if (state != State.WRITING) shardFail("record source reentered the writer")
                val bytes = OracleJson.canonicalBytes(record, limits.jsonLimits(record = true))
                val recordNodes = countShardNodes(record, limits.maximumShardNodes)
                val indentedBytes = bytes.size.toLong() + 4L * bytes.count { it == NEWLINE }
                val singletonBytes = shardByteCount(skeleton.size, 1, indentedBytes)
                if (singletonBytes > limits.maximumShardBytes ||
                    recordNodes > limits.maximumShardNodes - SHARD_ENVELOPE_NODES
                ) shardFail("single record exceeds a shard limit")
                val candidateBytes = shardByteCount(skeleton.size, pending.size + 1, indentedRecordBytes + indentedBytes)
                if (pending.isNotEmpty() &&
                    (candidateBytes > limits.maximumShardBytes || recordNodes > limits.maximumShardNodes - nodes)
                ) {
                    emit()
                    ordinal++
                    skeleton = emptyEnvelope(kind, ordinal, 0)
                }
                if (shardByteCount(skeleton.size, 1, indentedBytes) > limits.maximumShardBytes) {
                    shardFail("single record and ordinal exceed a shard limit")
                }
                pending += bytes
                indentedRecordBytes += indentedBytes
                nodes += recordNodes
            }
            if (pending.isNotEmpty() || ordinal == 0) emit()
            state = State.OPEN
        } catch (failure: Throwable) {
            state = State.FAILED
            throw failure
        }
    }

    fun finish(): BoundedDwarfShardSummary {
        if (state != State.OPEN && state != State.FINISHED) {
            if (state == State.WRITING) state = State.FAILED
            shardFail("writer did not finish successfully")
        }
        state = State.FINISHED
        return BoundedDwarfShardSummary(totalBytes, totalNodes, totalShards, totalRecords)
    }

    private fun emptyEnvelope(kind: String, ordinal: Int, count: Int): ByteArray = OracleJson.canonicalBytes(
        JsonObject(linkedMapOf(
            "schema" to JsonPrimitive(SHARD_SCHEMA), "kind" to JsonPrimitive(kind),
            "ordinal" to JsonPrimitive(ordinal), "recordCount" to JsonPrimitive(count), "records" to JsonArray(emptyList()),
        )),
        limits.jsonLimits(),
    )

    private fun assemble(kind: String, ordinal: Int, records: List<ByteArray>, expectedSize: Int): ByteArray {
        val skeleton = emptyEnvelope(kind, ordinal, records.size)
        if (records.isEmpty()) return skeleton
        // The marker is a closed schema key. Record values and kind cannot influence its location.
        val marker = "  \"records\": []"
        val skeletonText = skeleton.toString(Charsets.UTF_8)
        val opening = skeletonText.indexOf(marker).takeIf { it >= 0 }?.plus(marker.length - 2)
            ?: shardFail("canonical envelope has no records slot")
        val output = ByteArrayOutputStream(expectedSize)
        output.write(skeleton, 0, opening + 1)
        output.write(NEWLINE.toInt())
        records.forEachIndexed { index, bytes ->
            var start = 0
            for (end in bytes.indices) {
                if (bytes[end] == NEWLINE) {
                    output.write(INDENT)
                    output.write(bytes, start, end - start)
                    if (end == bytes.lastIndex && index != records.lastIndex) output.write(','.code)
                    output.write(NEWLINE.toInt())
                    start = end + 1
                }
            }
        }
        output.write(' '.code)
        output.write(' '.code)
        output.write(skeleton, opening + 1, skeleton.size - opening - 1)
        return output.toByteArray()
    }
}

private fun shardByteCount(emptyEnvelopeBytes: Int, records: Int, indentedRecordBytes: Long): Long =
    emptyEnvelopeBytes.toLong() + (records.toString().length - 1) +
        if (records == 0) 0 else indentedRecordBytes + records + 2L

/** Objects, arrays and scalar values each consume one node; object keys do not. */
private fun countShardNodes(root: JsonElement, maximum: Int): Int {
    val stack = ArrayDeque<Iterator<JsonElement>>()
    stack.addLast(listOf(root).iterator())
    var nodes = 0
    while (stack.isNotEmpty()) {
        val current = stack.peekLast()
        if (!current.hasNext()) {
            stack.removeLast()
            continue
        }
        val value = current.next()
        if (++nodes > maximum) shardFail("JSON node budget exceeded")
        when (value) {
            is JsonObject -> stack.addLast(value.values.iterator())
            is JsonArray -> stack.addLast(value.iterator())
            else -> Unit
        }
    }
    return nodes
}

private fun validateShardKind(kind: String) {
    if (!SHARD_KIND.matches(kind)) shardFail("invalid record kind")
}

private fun shardFail(message: String): Nothing = throw FullTreeControlException("DWARF canonical shard: $message")

private const val SHARD_SCHEMA = "bounded-dwarf-record-shard-v1"
private const val SHARD_ENVELOPE_NODES = 6
private val SHARD_KEYS = setOf("schema", "kind", "ordinal", "recordCount", "records")
private val SHARD_KIND = Regex("[A-Za-z][A-Za-z0-9_-]{0,63}")
private val NEWLINE = '\n'.code.toByte()
private val INDENT = byteArrayOf(' '.code.toByte(), ' '.code.toByte(), ' '.code.toByte(), ' '.code.toByte())

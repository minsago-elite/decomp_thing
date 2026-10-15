package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** A wire record is one bounded, contiguous CU-local table; its rows remain individual physical DIEs. */
internal object DwarfPhysicalDieTableEncoding {
    const val NAME = "physical-die-contiguous-tables-v1"
    const val CENSUS_SCHEMA = "bounded-physical-die-census-v3"
    const val MAXIMUM_ROWS = 128
    const val MAXIMUM_RECORD_BYTES = 8 * 1024 * 1024
    const val MAXIMUM_RECORD_NODES = 100_000
    const val MAXIMUM_DECODED_DIES = 5_000_000
    private val KEYS = setOf("encoding", "compilationUnitOffset", "firstDieOrdinal", "rowCount", "rows")

    /** Fixed encoding limits determine partitioning; stricter caller limits may refuse the resulting records. */
    fun records(dies: List<DwarfPhysicalDieCensus>, maximumRecordBytes: Int = MAXIMUM_RECORD_BYTES,
                maximumRecordNodes: Int = MAXIMUM_RECORD_NODES): Sequence<JsonObject> = sequence {
        require(maximumRecordBytes in 1..MAXIMUM_RECORD_BYTES && maximumRecordNodes in 1..MAXIMUM_RECORD_NODES)
        var first = 0; var unit = -1L
        val pending = ArrayList<JsonPrimitive>(MAXIMUM_ROWS)
        var characters = 0L
        fun fits(count: Int, payloadCharacters: Long): Boolean {
            if (count !in 1..MAXIMUM_ROWS || count + 12 > maximumRecordNodes) return false
            // Fixed ASCII grammar cannot escape. This upper bound covers both the
            // record and its singleton shard (including the largest permitted ordinal).
            if (payloadCharacters + 512L + count * 12L <= maximumRecordBytes) return true
            return fitsExact(unit, first, count, payloadCharacters, maximumRecordBytes, maximumRecordNodes)
        }
        fun emit(): JsonObject {
            require(pending.isNotEmpty() && fits(pending.size, characters)) { "physical table exceeds record bounds" }
            val result = record(unit, first, pending.toList())
            // Defensive exact check against the unchanged actual canonical byte/node limits.
            OracleJson.canonicalBytes(result, jsonLimits(maximumRecordBytes, maximumRecordNodes))
            return result
        }
        for ((ordinal, die) in dies.withIndex()) {
            require(ordinal < MAXIMUM_DECODED_DIES)
            if (pending.isNotEmpty() && (die.compilationUnitOffset != unit || pending.size == MAXIMUM_ROWS)) {
                yield(emit()); pending.clear(); characters = 0
            }
            if (pending.isEmpty()) { first = ordinal; unit = die.compilationUnitOffset }
            val row = JsonPrimitive(DwarfPhysicalDieRowEncoding.encodeRow(die, maximumRecordBytes))
            if (!fits(pending.size + 1, characters + row.content.length)) {
                if (pending.isNotEmpty()) { yield(emit()); pending.clear(); characters = 0; first = ordinal; unit = die.compilationUnitOffset }
                if (!fits(1, row.content.length.toLong())) throw FullTreeControlException("single physical DIE row exceeds table record bounds")
            }
            pending += row; characters += row.content.length
        }
        if (pending.isNotEmpty()) yield(emit())
    }
    private fun record(unit: Long, first: Int, rows: List<JsonPrimitive>): JsonObject = JsonObject(linkedMapOf(
        "encoding" to JsonPrimitive(NAME), "compilationUnitOffset" to JsonPrimitive("0x${unit.toString(16)}"),
        "firstDieOrdinal" to JsonPrimitive(first), "rowCount" to JsonPrimitive(rows.size), "rows" to JsonArray(rows),
    ))
    fun logicalRowCount(record: JsonObject): Int {
        require(record.keys == KEYS && record["encoding"] == JsonPrimitive(NAME)) { "physical table keys or encoding differ from the closed schema" }
        val rows = record["rows"] as? JsonArray ?: throw IllegalArgumentException("physical table rows are not an array")
        require(rows.size in 1..MAXIMUM_ROWS) { "physical table row count exceeds bounds" }
        val count = record["rowCount"] as? JsonPrimitive
        require(count != null && !count.isString && count.content == rows.size.toString()) { "physical table rowCount differs from its rows" }
        return rows.size
    }
    fun firstOrdinal(record: JsonObject): Int {
        val value = record["firstDieOrdinal"] as? JsonPrimitive
        require(value != null && !value.isString && value.longOrNull != null && value.content == value.longOrNull!!.toString() &&
            value.longOrNull!! in 0 until MAXIMUM_DECODED_DIES.toLong()) {
            "physical table first DIE ordinal exceeds bounds"
        }
        return value.longOrNull!!.toInt()
    }
    fun compilationUnitOffset(record: JsonObject): Long {
        val value = record["compilationUnitOffset"] as? JsonPrimitive
        require(value != null && value.isString && Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})").matches(value.content)) {
            "physical table CU offset is not canonical"
        }
        return value.content.substring(2).toLongOrNull(16) ?: throw IllegalArgumentException("physical table CU offset exceeds its width")
    }
    /** Validates one row at a time; never constructs a second table of decoded DIE objects. */
    fun decode(record: JsonObject, expectedFirstOrdinal: Int? = null, maximumRecordBytes: Int = MAXIMUM_RECORD_BYTES,
               maximumRecordNodes: Int = MAXIMUM_RECORD_NODES, maximumShardBytes: Int = MAXIMUM_RECORD_BYTES,
               maximumShardNodes: Int = MAXIMUM_RECORD_NODES, rowWork: () -> Unit = {}, referenceWork: () -> Unit = {}): Sequence<DwarfPhysicalDieCensus> {
        require(maximumRecordBytes in 1..MAXIMUM_RECORD_BYTES && maximumRecordNodes in 1..MAXIMUM_RECORD_NODES)
        require(maximumShardBytes in 1..MAXIMUM_RECORD_BYTES && maximumShardNodes in 1..MAXIMUM_RECORD_NODES)
        val count = logicalRowCount(record)
        val first = firstOrdinal(record); val unit = compilationUnitOffset(record)
        require(count <= MAXIMUM_DECODED_DIES - first && (expectedFirstOrdinal == null || first == expectedFirstOrdinal)) {
            "physical table ordinals are clipped, missing, duplicated or reordered"
        }
        OracleJson.canonicalBytes(record, jsonLimits(maximumRecordBytes, maximumRecordNodes))
        val rows = record.getValue("rows") as JsonArray
        var payloadCharacters = 0L
        for (element in rows) {
            val row = element as? JsonPrimitive
            require(row != null && row.isString && row.content.length <= maximumRecordBytes &&
                row.content.all { it in 'a'..'z' || it in '0'..'9' || it == ',' || it == '-' || it == '|' || it == ';' }) {
                "physical table row is not a bounded ASCII grammar string"
            }
            payloadCharacters = Math.addExact(payloadCharacters, row.content.length.toLong())
        }
        require(fitsExact(unit, first, count, payloadCharacters, maximumRecordBytes, maximumRecordNodes,
            maximumShardBytes, maximumShardNodes)) {
            "physical table exceeds its record or singleton envelope bounds"
        }
        return sequence {
            for (element in rows) {
                rowWork()
                val row = element as? JsonPrimitive
                require(row != null && row.isString && row.content.length <= maximumRecordBytes) { "physical table row is not a bounded string" }
                val die = DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to row)), maximumRecordBytes, referenceWork)
                require(die.compilationUnitOffset == unit) { "physical table row belongs to another compilation unit" }
                yield(die)
            }
        }
    }
    private fun fitsExact(unit: Long, first: Int, count: Int, payloadCharacters: Long, bytes: Int, nodes: Int,
                          shardBytes: Int = bytes, shardNodes: Int = nodes): Boolean {
        if (count !in 1..MAXIMUM_ROWS || count + 6 > nodes || count + 12 > shardNodes) return false
        val skeleton = record(unit, first, List(count) { JsonPrimitive("") })
        val recordBytes = OracleJson.canonicalBytes(skeleton, jsonLimits()).size.toLong() + payloadCharacters
        val envelope = JsonObject(linkedMapOf("schema" to JsonPrimitive("bounded-dwarf-record-shard-v1"),
            "kind" to JsonPrimitive("physicalDies"), "ordinal" to JsonPrimitive(255), "recordCount" to JsonPrimitive(1),
            "records" to JsonArray(listOf(skeleton))))
        val envelopeBytes = OracleJson.canonicalBytes(envelope, jsonLimits()).size.toLong() + payloadCharacters
        return recordBytes <= bytes && envelopeBytes <= shardBytes
    }
    private fun jsonLimits(bytes: Int = MAXIMUM_RECORD_BYTES, nodes: Int = MAXIMUM_RECORD_NODES) = StrictJsonLimits(
        maximumInputBytes = bytes, maximumCanonicalBytes = bytes, maximumDepth = 4, maximumNodes = nodes,
        maximumStringBytes = bytes, maximumTotalStringBytes = bytes,
    )
}

package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedDwarfCanonicalShardsTest {
    @Test
    fun `writer matches OracleJson canonical bytes including nested and escaped records`() {
        val records = listOf(
            JsonObject(linkedMapOf(
                "z" to JsonArray(listOf(JsonPrimitive("line\n雪\"\\"), JsonNull, JsonObject(mapOf("a" to JsonPrimitive(true))))),
                "a" to JsonObject(emptyMap()),
            )),
            record(2),
            JsonObject(emptyMap()),
        )
        val emitted = mutableListOf<ByteArray>()
        val writer = BoundedDwarfCanonicalShardWriter { kind, ordinal, bytes, count ->
            assertEquals("functions", kind)
            assertEquals(0, ordinal)
            assertEquals(3, count)
            emitted += bytes
        }
        writer.write("functions", records.asSequence())
        assertContentEquals(envelope("functions", 0, records), emitted.single())
        val parsed = parseCanonicalDwarfShard(emitted.single(), expectedKind = "functions", expectedOrdinal = 0, expectedRecordCount = 3)
        assertEquals(records, parsed.records)
        assertEquals(16, parsed.nodeCount)
        assertEquals(BoundedDwarfShardSummary(emitted.single().size.toLong(), 16L, 1, 3L), writer.finish())
    }

    @Test
    fun `byte and node limits include the envelope and admit exact boundaries`() {
        val source = listOf(record(1))
        val bytes = envelope("types", 0, source)
        val limits = BoundedDwarfShardLimits(maximumShardBytes = bytes.size, maximumShardNodes = 8)
        val emitted = mutableListOf<ByteArray>()
        val writer = BoundedDwarfCanonicalShardWriter(limits) { _, _, output, _ -> emitted += output }
        writer.write("types", source.asSequence())
        assertContentEquals(bytes, emitted.single())
        assertEquals(8L, writer.finish().totalNodes)

        for (tooSmall in listOf(limits.copy(maximumShardBytes = bytes.size - 1), limits.copy(maximumShardNodes = 7))) {
            var calls = 0
            val rejected = BoundedDwarfCanonicalShardWriter(tooSmall) { _, _, _, _ -> calls++ }
            assertFailsWith<IllegalArgumentException> { rejected.write("types", source.asSequence()) }
            assertEquals(0, calls)
            assertFailsWith<IllegalArgumentException> { rejected.finish() }
        }
    }

    @Test
    fun `node bounded splits preserve all records and reset ordinals per kind`() {
        val observed = mutableListOf<BoundedDwarfCanonicalShard>()
        val limits = BoundedDwarfShardLimits(maximumShardNodes = 12)
        val writer = BoundedDwarfCanonicalShardWriter(limits) { kind, ordinal, bytes, count ->
            observed += parseCanonicalDwarfShard(bytes, limits, kind, ordinal, count)
        }
        val records = (0 until 24).map(::record)
        writer.write("globals", records.asSequence())
        writer.write("types", sequenceOf(record(100)))
        assertEquals(listOf(3, 3, 3, 3, 3, 3, 3, 3, 1), observed.map { it.recordCount })
        assertEquals((0..7).toList() + 0, observed.map { it.ordinal })
        assertEquals(records, observed.filter { it.kind == "globals" }.flatMap { it.records })
        assertEquals(25L, writer.finish().totalRecords)
    }

    @Test
    fun `byte bounded splits include count and ordinal digit growth`() {
        val kind = "objectSymbols"
        val records = (0 until 12).map { JsonObject(emptyMap()) }
        val tenRecordBytes = envelope(kind, 0, records.take(10)).size
        val limits = BoundedDwarfShardLimits(maximumShardBytes = tenRecordBytes)
        val parts = mutableListOf<BoundedDwarfCanonicalShard>()
        val writer = BoundedDwarfCanonicalShardWriter(limits) { _, _, bytes, _ ->
            assertTrue(bytes.size <= tenRecordBytes)
            parts += parseCanonicalDwarfShard(bytes, limits)
        }
        writer.write(kind, records.asSequence())
        assertEquals(listOf(10, 2), parts.map { it.recordCount })
        writer.finish()

        val oneRecordBytes = envelope(kind, 9, listOf(record(0))).size
        val ordinalLimits = limits.copy(maximumShardBytes = oneRecordBytes)
        var emitted = 0
        val ordinalWriter = BoundedDwarfCanonicalShardWriter(ordinalLimits) { _, _, bytes, _ ->
            assertTrue(bytes.size <= oneRecordBytes)
            emitted++
        }
        assertFailsWith<IllegalArgumentException> {
            ordinalWriter.write(kind, generateSequence { record(0) }.take(11))
        }
        assertEquals(10, emitted)
    }

    @Test
    fun `shared aggregate budgets reject the next kind before delivery`() {
        val first = envelope("functions", 0, listOf(record(0)))
        val second = envelope("types", 0, listOf(record(1)))
        val exact = BoundedDwarfShardLimits(
            maximumTotalBytes = (first.size + second.size).toLong(), maximumTotalNodes = 16, maximumShards = 2,
        )
        val admitted = mutableListOf<ByteArray>()
        val valid = BoundedDwarfCanonicalShardWriter(exact) { _, _, bytes, _ -> admitted += bytes }
        valid.write("functions", sequenceOf(record(0)))
        valid.write("types", sequenceOf(record(1)))
        assertEquals(BoundedDwarfShardSummary(exact.maximumTotalBytes, 16, 2, 2), valid.finish())
        for (tooSmall in listOf(
            exact.copy(maximumTotalBytes = exact.maximumTotalBytes - 1),
            exact.copy(maximumTotalNodes = 15),
            exact.copy(maximumShards = 1),
        )) {
            var calls = 0
            val rejected = BoundedDwarfCanonicalShardWriter(tooSmall) { _, _, _, _ -> calls++ }
            rejected.write("functions", sequenceOf(record(0)))
            assertFailsWith<IllegalArgumentException> { rejected.write("types", sequenceOf(record(1))) }
            assertEquals(1, calls)
            assertFailsWith<IllegalArgumentException> { rejected.write("other", emptySequence()) }
            assertFailsWith<IllegalArgumentException> { rejected.finish() }
        }
    }

    @Test
    fun `empty groups are explicit and duplicate or finished writes are rejected`() {
        val outputs = mutableListOf<ByteArray>()
        val writer = BoundedDwarfCanonicalShardWriter { _, _, bytes, _ -> outputs += bytes }
        writer.write("globals", emptySequence())
        assertContentEquals(envelope("globals", 0, emptyList()), outputs.single())
        assertEquals(6, parseCanonicalDwarfShard(outputs.single()).nodeCount)
        assertFailsWith<IllegalArgumentException> { writer.write("globals", sequenceOf(record(1))) }
        assertEquals(1, outputs.size)
        assertFailsWith<IllegalArgumentException> { writer.finish() }

        val finished = BoundedDwarfCanonicalShardWriter { _, _, _, _ -> error("no groups") }
        assertEquals(BoundedDwarfShardSummary(0, 0, 0, 0), finished.finish())
        assertEquals(finished.finish(), finished.finish())
        assertFailsWith<IllegalArgumentException> { finished.write("types", emptySequence()) }
    }

    @Test
    fun `writer consumes sequences incrementally and remains failed after consumer errors`() {
        var consumed = 0
        val records = sequence {
            repeat(100) {
                consumed++
                yield(record(it))
            }
        }
        val writer = BoundedDwarfCanonicalShardWriter(BoundedDwarfShardLimits(maximumShardNodes = 8)) { _, _, _, _ ->
            assertEquals(2, consumed)
            throw IllegalStateException("consumer declined")
        }
        assertFailsWith<IllegalStateException> { writer.write("types", records) }
        assertEquals(2, consumed)
        assertFailsWith<IllegalArgumentException> { writer.finish() }
        assertFailsWith<IllegalArgumentException> { writer.write("other", emptySequence()) }
    }

    @Test
    fun `all 24000 raw records survive bounded streaming without a monolithic array`() {
        var next = 0
        val limits = BoundedDwarfShardLimits(maximumShardNodes = 1000)
        val writer = BoundedDwarfCanonicalShardWriter(limits) { kind, ordinal, bytes, count ->
            val shard = parseCanonicalDwarfShard(bytes, limits, kind, ordinal, count)
            shard.records.forEach { assertEquals(next++, (it.getValue("value") as JsonPrimitive).content.toInt()) }
        }
        writer.write("globals", (0 until 24_000).asSequence().map(::record))
        assertEquals(24_000, next)
        val summary = writer.finish()
        assertEquals(24_000L, summary.totalRecords)
        assertEquals(49, summary.totalShards)
        assertEquals(48_000L + 49 * 6, summary.totalNodes)
    }

    @Test
    fun `caught reentrant calls still poison the publishing session`() {
        for (finish in listOf(false, true)) {
            var calls = 0
            lateinit var writer: BoundedDwarfCanonicalShardWriter
            writer = BoundedDwarfCanonicalShardWriter { _, _, _, _ ->
                calls++
                assertFailsWith<IllegalArgumentException> {
                    if (finish) writer.finish() else writer.write("nested", emptySequence())
                }
            }
            assertFailsWith<IllegalArgumentException> { writer.write("types", emptySequence()) }
            assertEquals(1, calls)
            assertFailsWith<IllegalArgumentException> { writer.finish() }
        }
    }

    @Test
    fun `record source reentry rejects buffered shards before consumer delivery`() {
        for (afterYield in listOf(false, true)) {
            var calls = 0
            val writer = BoundedDwarfCanonicalShardWriter { _, _, _, _ -> calls++ }
            val source = sequence {
                if (!afterYield) assertFailsWith<IllegalArgumentException> { writer.finish() }
                yield(record(1))
                if (afterYield) assertFailsWith<IllegalArgumentException> { writer.finish() }
            }
            assertFailsWith<IllegalArgumentException> { writer.write("types", source) }
            assertEquals(0, calls)
            assertFailsWith<IllegalArgumentException> { writer.finish() }
        }
    }

    @Test
    fun `record depth reserves both envelope container levels`() {
        fun nested(depth: Int): JsonObject {
            var value = JsonObject(emptyMap())
            repeat(depth - 1) { value = JsonObject(mapOf("child" to value)) }
            return value
        }
        var accepted = 0
        val valid = BoundedDwarfCanonicalShardWriter { _, _, bytes, _ ->
            parseCanonicalDwarfShard(bytes)
            accepted++
        }
        valid.write("types", sequenceOf(nested(62)))
        assertEquals(1, accepted)
        valid.finish()
        val rejected = BoundedDwarfCanonicalShardWriter { _, _, _, _ -> error("overdeep record delivered") }
        assertFailsWith<IllegalArgumentException> { rejected.write("types", sequenceOf(nested(63))) }
    }

    @Test
    fun `closed parser rejects noncanonical malformed and mismatched envelopes`() {
        val original = OracleJson.parse(envelope("types", 0, listOf(record(1)))) as JsonObject
        val variants = listOf(
            JsonObject(original + ("extra" to JsonPrimitive(true))),
            JsonObject(original - "schema"),
            JsonObject(original + ("schema" to JsonPrimitive("other"))),
            JsonObject(original + ("kind" to JsonPrimitive("../types"))),
            JsonObject(original + ("ordinal" to JsonPrimitive(-1))),
            JsonObject(original + ("ordinal" to JsonPrimitive(256))),
            JsonObject(original + ("ordinal" to JsonPrimitive("0"))),
            JsonObject(original + ("recordCount" to JsonPrimitive(2))),
            JsonObject(original + ("records" to JsonArray(listOf(JsonPrimitive(1))))),
        )
        for (invalid in variants) {
            assertFailsWith<IllegalArgumentException> { parseCanonicalDwarfShard(OracleJson.canonicalBytes(invalid)) }
        }
        val bytes = OracleJson.canonicalBytes(original)
        assertFailsWith<IllegalArgumentException> { parseCanonicalDwarfShard(bytes + '\n'.code.toByte()) }
        assertFailsWith<IllegalArgumentException> { parseCanonicalDwarfShard(bytes, expectedKind = "globals") }
        assertFailsWith<IllegalArgumentException> { parseCanonicalDwarfShard(bytes, expectedOrdinal = 1) }
        assertFailsWith<IllegalArgumentException> { parseCanonicalDwarfShard(bytes, expectedRecordCount = 2) }
        assertFailsWith<IllegalArgumentException> {
            parseCanonicalDwarfShard(bytes, BoundedDwarfShardLimits(maximumShardNodes = 7))
        }
        assertFailsWith<IllegalArgumentException> {
            parseCanonicalDwarfShard(bytes, BoundedDwarfShardLimits(maximumShardBytes = bytes.size - 1))
        }
    }

    @Test
    fun `limits cannot widen the supported per shard or aggregate ceilings`() {
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumShardBytes = 8 * 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumShardNodes = 100_001) }
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumTotalBytes = 512L * 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumTotalNodes = 16_000_001) }
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumShards = 257) }
        assertFailsWith<IllegalArgumentException> { BoundedDwarfShardLimits(maximumTotalNodes = 0) }
        assertEquals(5, BoundedDwarfShardLimits().toJson().size)
    }

    private fun record(index: Int): JsonObject = JsonObject(mapOf("value" to JsonPrimitive(index)))

    private fun envelope(kind: String, ordinal: Int, records: List<JsonObject>): ByteArray = OracleJson.canonicalBytes(
        JsonObject(linkedMapOf(
            "schema" to JsonPrimitive("bounded-dwarf-record-shard-v1"), "kind" to JsonPrimitive(kind),
            "ordinal" to JsonPrimitive(ordinal), "recordCount" to JsonPrimitive(records.size), "records" to JsonArray(records),
        )),
    )
}

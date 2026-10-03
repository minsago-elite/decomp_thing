package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedDwarfCanonicalShardsTest {
    @Test
    fun `type headers and ordered child rows reconstruct every original type fact`() {
        val nodes = detailedTypes()
        val facts = typeFacts(nodes.reversed().associateBy { it.id })
        val parts = collectTypeShards(facts)
        assertEquals(listOf("metadata", "functions", "types", "typeChildren", "globals", "objectSymbols"),
            parts.map { it.first.kind })
        val metadata = parts.single { it.first.kind == "metadata" }.first.records.single()
        assertEquals(JsonPrimitive("type-headers-with-ordered-child-locators-v2"), metadata["typeChildEncoding"])
        assertEquals(JsonObject(mapOf(
            "types" to JsonObject(typeFallbacks.mapValues { JsonPrimitive(it.value) }),
            "typeChildren" to JsonObject(childFallbacks.mapValues { JsonPrimitive(it.value) }),
        )), metadata["typePromotedFactFallbacks"])
        assertEquals(JsonPrimitive("only-exact-JSON-duplicates-omitted;absent-promoted-field-resolves-to-required-attribute;" +
            "explicit-field-takes-precedence"), metadata["typePromotedFactRule"])
        assertEquals(JsonPrimitive("functions-by-address-locator;types-by-locator;" +
            "typeChildren-by-parent-locator-physical-child;globals-by-physical-DIE;objects-by-table-entry"), metadata["ordering"])
        assertEquals(JsonPrimitive(nodes.sumOf { it.children.size }),
            (metadata.getValue("recordCounts") as JsonObject)["typeChildren"])
        val headers = parts.single { it.first.kind == "types" }.first.records
        val rows = parts.single { it.first.kind == "typeChildren" }.first.records
        assertEquals(nodes.sortedBy { it.id }.map { it.id }, headers.map { jsonString(it, "id") })
        assertEquals(nodes.sortedBy { it.id }.flatMap { parent -> parent.children.map { parent.id to it.id } },
            rows.map { jsonString(it, "parentTypeId") to jsonString(it.getValue("child") as JsonObject, "id") })
        rows.forEach { assertEquals(setOf("parentTypeId", "child"), it.keys) }
        var savedNodes = 0
        val omittedStates = mutableSetOf<String>()
        for (header in headers) {
            val original = nodes.single { it.id == jsonString(header, "id") }.toJson()
            val uncompressedHeader = JsonObject((original - "children") + ("childLocators" to header.getValue("childLocators")))
            savedNodes += assertExactPromotedCompression(uncompressedHeader, header, typeFallbacks)
            typeFallbacks.keys.filter { it !in header }.forEach {
                omittedStates += jsonString(original.getValue(it) as JsonObject, "state")
            }
            val children = rows.filter { jsonString(it, "parentTypeId") == jsonString(header, "id") }
                .map { row ->
                    val compact = row.getValue("child") as JsonObject
                    val full = (original.getValue("children") as JsonArray).map { it as JsonObject }
                        .single { jsonString(it, "id") == jsonString(compact, "id") }
                    savedNodes += assertExactPromotedCompression(full, compact, childFallbacks)
                    restorePromoted(compact, childFallbacks)
                }
            assertEquals(children.map { jsonString(it, "id") },
                (header.getValue("childLocators") as JsonArray).map { (it as JsonPrimitive).content })
            val reconstructed = JsonObject((restorePromoted(header, typeFallbacks) - "childLocators") +
                ("children" to JsonArray(children)))
            assertEquals(original, reconstructed)
            assertContentEquals(OracleJson.canonicalBytes(original), OracleJson.canonicalBytes(reconstructed))
        }
        assertTrue(savedNodes > 0)
        assertEquals(setOf("known", "absent", "unknown", "ambiguous"), omittedStates)
        // The convenient small-document representation still contains complete inline children.
        val inline = facts.toJson()
        assertEquals(JsonArray(facts.types.values.map { it.toJson() }), inline["types"])
        assertTrue("typeChildEncoding" !in inline)
        assertTrue("typePromotedFactFallbacks" !in inline)
        assertTrue("typePromotedFactRule" !in inline)
        assertTrue("typeChildren" !in inline)
        assertTrue("typeChildren" !in (inline.getValue("recordCounts") as JsonObject))
    }

    @Test
    fun `promoted facts remain explicit when any complete fact component differs or attribute is absent`() {
        val promoted = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf("left", "right"),
            listOf("source-a", "source-b"), listOf("reason-a", "reason-b"))
        val cases = linkedMapOf<String, DwarfInterfaceFact<String>?>(
            "missing" to null,
            "state" to DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, promoted.values, promoted.evidence, promoted.reasons),
            "values" to DwarfInterfaceFact(promoted.state, promoted.values.reversed(), promoted.evidence, promoted.reasons),
            "evidence" to DwarfInterfaceFact(promoted.state, promoted.values, promoted.evidence.reversed(), promoted.reasons),
            "reasons" to DwarfInterfaceFact(promoted.state, promoted.values, promoted.evidence, promoted.reasons.reversed()),
            "exact-copy" to DwarfInterfaceFact(promoted.state, promoted.values.toList(), promoted.evidence.toList(), promoted.reasons.toList()),
        )
        val nodes = cases.map { (label, attribute) ->
            val attributes = if (attribute == null) emptyMap() else
                listOf(0x3L, 0xbL, 0x3eL, 0x49L).associateWith { attribute }
            val child = DwarfInterfaceTypeChild("$label-child", 0x0d, promoted, promoted,
                attributes.filterKeys { it == 0x3L || it == 0x49L }, listOf("unmodified-child-reason"))
            DwarfInterfaceTypeNode(label, 0x13, promoted, promoted, promoted, promoted,
                attributes, listOf(child), listOf("unmodified-node-reason"))
        }
        val parts = collectTypeShards(typeFacts(nodes.associateBy { it.id }))
        val headers = parts.single { it.first.kind == "types" }.first.records
        val rows = parts.single { it.first.kind == "typeChildren" }.first.records
        for (node in nodes) {
            val header = headers.single { jsonString(it, "id") == node.id }
            val compactChild = rows.single { jsonString(it, "parentTypeId") == node.id }.getValue("child") as JsonObject
            for ((compact, fallbacks) in listOf(header to typeFallbacks, compactChild to childFallbacks)) {
                for (field in fallbacks.keys) {
                    if (node.id == "exact-copy") assertTrue(field !in compact)
                    else assertEquals(promoted.toJson(::JsonPrimitive), compact[field])
                    assertEquals(promoted.toJson(::JsonPrimitive), restorePromoted(compact, fallbacks)[field])
                }
            }
            val full = node.toJson()
            val uncompressedHeader = JsonObject((full - "children") + ("childLocators" to header.getValue("childLocators")))
            assertExactPromotedCompression(uncompressedHeader, header, typeFallbacks)
            assertExactPromotedCompression(node.children.single().toJson(), compactChild, childFallbacks)
            val reconstructed = JsonObject((restorePromoted(header, typeFallbacks) - "childLocators") +
                ("children" to JsonArray(listOf(restorePromoted(compactChild, childFallbacks)))))
            assertEquals(full, reconstructed)
        }
        val missing = headers.single { jsonString(it, "id") == "missing" }
        assertFailsWith<NoSuchElementException> { restorePromoted(JsonObject(missing - "name"), typeFallbacks) }
    }

    @Test
    fun `type shard bytes are independent of input map insertion order`() {
        val nodes = detailedTypes()
        val forward = collectTypeShards(typeFacts(nodes.associateBy { it.id }))
        val reversed = collectTypeShards(typeFacts(nodes.reversed().associateBy { it.id }))
        assertEquals(forward.map { it.first.kind to it.first.ordinal }, reversed.map { it.first.kind to it.first.ordinal })
        forward.zip(reversed).forEach { (left, right) -> assertContentEquals(left.second, right.second) }
    }

    @Test
    fun `empty type children remain an explicit shard with zero metadata count`() {
        val withoutChildren = detailedTypes().first().let { node -> DwarfInterfaceTypeNode(node.id, node.tag,
            node.name, node.byteSize, node.encoding, node.type, node.attributes, emptyList(), node.reasons) }
        for (types in listOf(emptyMap(), mapOf(withoutChildren.id to withoutChildren))) {
            val parts = collectTypeShards(typeFacts(types))
            val childParts = parts.filter { it.first.kind == "typeChildren" }
            assertEquals(1, childParts.size)
            val childPart = childParts.single().first
            assertEquals(0, childPart.ordinal)
            assertEquals(0, childPart.recordCount)
            assertEquals(emptyList(), childPart.records)
            assertContentEquals(envelope("typeChildren", 0, emptyList()), childParts.single().second)
            val metadata = parts.single { it.first.kind == "metadata" }.first.records.single()
            assertEquals(JsonPrimitive(0), (metadata.getValue("recordCounts") as JsonObject)["typeChildren"])
        }
    }

    @Test
    fun `4096 child enums and classes split below unchanged shard and aggregate ceilings`() {
        val defaults = BoundedDwarfShardLimits()
        assertEquals(8 * 1024 * 1024, defaults.maximumShardBytes)
        assertEquals(100_000, defaults.maximumShardNodes)
        assertEquals(512L * 1024 * 1024, defaults.maximumTotalBytes)
        assertEquals(16_000_000L, defaults.maximumTotalNodes)
        assertEquals(256, defaults.maximumShards)
        val nodes = listOf(largeType("enum", 0x04, 0x28), largeType("class", 0x02, 0x0d))
        val facts = typeFacts(nodes.associateBy { it.id })
        assertEquals(defaults, facts.limits.shardLimits)
        assertEquals(defaults.maximumTotalBytes, facts.limits.maximumOutputBytes)
        for (node in nodes) {
            assertEquals(4096, node.children.size)
            val inline = node.toJson()
            assertTrue(jsonNodeCount(inline) > defaults.maximumShardNodes)
            // The old single-record encoding exceeds the node ceiling even though it fits bytes.
            val inlineBytes = OracleJson.canonicalBytes(inline, StrictJsonLimits(
                maximumInputBytes = defaults.maximumShardBytes, maximumCanonicalBytes = defaults.maximumShardBytes,
                maximumNodes = 1_000_000, maximumTotalStringBytes = defaults.maximumShardBytes,
            ))
            assertTrue(inlineBytes.size < defaults.maximumShardBytes)
            var delivered = 0
            val oldWriter = BoundedDwarfCanonicalShardWriter { _, _, _, _ -> delivered++ }
            assertFailsWith<IllegalArgumentException> { oldWriter.write("types", sequenceOf(inline)) }
            assertEquals(0, delivered)
        }
        val expected = nodes.sortedBy { it.id }.flatMap { parent -> parent.children.map { parent.id to it } }
        var nextChild = 0
        var totalBytes = 0L
        var totalNodes = 0L
        var totalShards = 0
        val childOrdinals = mutableListOf<Int>()
        val headers = mutableListOf<JsonObject>()
        val summary = facts.visitCanonicalShards { kind, ordinal, bytes, count ->
            assertTrue(bytes.size <= defaults.maximumShardBytes)
            val part = parseCanonicalDwarfShard(bytes, defaults, kind, ordinal, count)
            assertTrue(part.nodeCount <= defaults.maximumShardNodes)
            totalBytes += bytes.size
            totalNodes += part.nodeCount
            totalShards++
            when (kind) {
                "metadata" -> assertEquals(JsonPrimitive(8192),
                    (part.records.single().getValue("recordCounts") as JsonObject)["typeChildren"])
                "types" -> headers += part.records
                "typeChildren" -> {
                    childOrdinals += ordinal
                    for (row in part.records) {
                        val (parentId, child) = expected[nextChild++]
                        assertEquals(setOf("parentTypeId", "child"), row.keys)
                        assertEquals(parentId, jsonString(row, "parentTypeId"))
                        val compact = row.getValue("child") as JsonObject
                        assertTrue("name" !in compact && "type" !in compact)
                        assertEquals(child.toJson(), restorePromoted(compact, childFallbacks))
                        assertTrue(jsonNodeCount(compact) < jsonNodeCount(child.toJson()))
                    }
                }
            }
        }
        assertEquals(8192, nextChild)
        assertTrue(childOrdinals.size > 1)
        assertEquals(childOrdinals.indices.toList(), childOrdinals)
        assertEquals(nodes.sortedBy { it.id }.map { it.id }, headers.map { jsonString(it, "id") })
        for (header in headers) {
            val node = nodes.single { it.id == jsonString(header, "id") }
            assertEquals(JsonArray(node.children.map { JsonPrimitive(it.id) }), header["childLocators"])
        }
        assertEquals(BoundedDwarfShardSummary(totalBytes, totalNodes, totalShards, 8195), summary)
        assertTrue(summary.totalBytes <= defaults.maximumTotalBytes)
        assertTrue(summary.totalNodes <= defaults.maximumTotalNodes)
        assertTrue(summary.totalShards <= defaults.maximumShards)
    }

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

    private val typeFallbacks = linkedMapOf("name" to "0x3", "byteSize" to "0xb", "encoding" to "0x3e", "type" to "0x49")
    private val childFallbacks = linkedMapOf("name" to "0x3", "type" to "0x49")

    private fun restorePromoted(compact: JsonObject, fallbacks: Map<String, String>): JsonObject {
        val attributes = compact.getValue("attributes") as JsonObject
        return JsonObject(compact + fallbacks.mapValues { (field, attribute) ->
            compact[field] ?: attributes.getValue(attribute)
        })
    }

    private fun assertExactPromotedCompression(full: JsonObject, compact: JsonObject,
        fallbacks: Map<String, String>): Int {
        val attributes = full.getValue("attributes") as JsonObject
        assertEquals(attributes, compact["attributes"])
        val omitted = fallbacks.filter { (field, attribute) -> full.getValue(field) == attributes[attribute] }.keys
        assertEquals(full.keys - omitted, compact.keys)
        for (field in fallbacks.keys) {
            if (field in omitted) assertTrue(field !in compact)
            else assertEquals(full.getValue(field), compact[field])
        }
        val saved = omitted.sumOf { jsonNodeCount(full.getValue(it)) }
        assertEquals(saved, jsonNodeCount(full) - jsonNodeCount(compact))
        assertEquals(full, restorePromoted(compact, fallbacks))
        return saved
    }

    private fun typeFacts(types: Map<String, DwarfInterfaceTypeNode>): BoundedDwarfInterfaceFacts =
        BoundedDwarfInterfaceFacts(inputSha256 = "0".repeat(64), inputBytes = 1L, elfType = "ET_EXEC",
            imageBase = 0x400000UL, executableRanges = emptyList(), functions = emptyList(), types = types,
            scannedDies = types.size.toLong() + types.values.sumOf { it.children.size.toLong() },
            compilationUnits = 1, dwarfPresent = true, limits = BoundedDwarfInterfaceFactLimits())

    private fun collectTypeShards(facts: BoundedDwarfInterfaceFacts): List<Pair<BoundedDwarfCanonicalShard, ByteArray>> {
        val parts = mutableListOf<Pair<BoundedDwarfCanonicalShard, ByteArray>>()
        facts.visitCanonicalShards { kind, ordinal, bytes, count ->
            parts += parseCanonicalDwarfShard(bytes, expectedKind = kind, expectedOrdinal = ordinal,
                expectedRecordCount = count) to bytes
        }
        return parts
    }

    private fun detailedTypes(): List<DwarfInterfaceTypeNode> {
        val firstId = ".debug_info:cu=0x0:die=0xb"
        val secondId = ".debug_info:cu=0x40:die=0x4b"
        fun known(value: String, evidence: String) = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN,
            listOf(value), listOf(evidence), listOf("retained-source-attribute"))
        val absent = DwarfInterfaceFact<String>(DwarfInterfaceFactState.ABSENT,
            evidence = listOf("$firstId:attribute=0x3e:absent"), reasons = listOf("no-encoding-attribute"))
        val ambiguous = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf("8", "16"),
            listOf("$firstId:attribute=0xb", "$secondId:attribute=0xb"), listOf("conflicting-declarations"))
        val unknown = DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, listOf(secondId),
            listOf("$firstId:attribute=0x49"), listOf("unsupported-reference", "type-reference-cycle:$firstId"))
        val name = known("Record\n雪\"\\", "$firstId:attribute=0x3")
        val firstChildren = listOf(
            DwarfInterfaceTypeChild(".debug_info:cu=0x0:die=0xf", 0x0d, name, unknown,
                linkedMapOf(0x49L to unknown, 0x3L to name, 0x38L to ambiguous),
                listOf("unsupported-type-child-layout", "type-reference-cycle:$firstId")),
            DwarfInterfaceTypeChild(".debug_info:cu=0x0:die=0x10", 0x0d, absent,
                known(secondId, "$firstId:second-child-type"),
                linkedMapOf(0x3L to absent, 0x38L to unknown), listOf("anonymous-child")),
        )
        val secondName = known("Choice", "$secondId:attribute=0x3")
        val secondChild = DwarfInterfaceTypeChild(".debug_info:cu=0x40:die=0x50", 0x28,
            known("signed_option", "$secondId:enumerator-name"), absent,
            linkedMapOf(0x1cL to known("-7", "$secondId:enumerator-value")), listOf("signed-enumerator"))
        return listOf(
            DwarfInterfaceTypeNode(firstId, 0x13, name, ambiguous, absent, unknown,
                linkedMapOf(0x49L to unknown, 0xbL to ambiguous, 0x3L to name, 0x3eL to absent, 0x2000L to unknown),
                firstChildren, listOf("inherited-type-children-unrepresented:$secondId", "raw-layout-unresolved")),
            DwarfInterfaceTypeNode(secondId, 0x04, secondName, known("4", "$secondId:attribute=0xb"), absent,
                known(firstId, "$secondId:attribute=0x49"), linkedMapOf(0x3L to secondName, 0x3eL to absent),
                listOf(secondChild), listOf("source-enumeration")),
        )
    }

    private fun largeType(label: String, tag: Long, childTag: Long): DwarfInterfaceTypeNode {
        val unit = if (label == "enum") 0 else 0x20000
        fun locator(offset: Int) = ".debug_info:cu=0x${unit.toString(16)}:die=0x${(unit + offset).toString(16)}"
        val id = locator(11)
        val absent = DwarfInterfaceFact<String>(DwarfInterfaceFactState.ABSENT)
        fun known(value: String, evidence: String) = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN,
            listOf(value), listOf(evidence))
        val children = (0 until 4096).map { index ->
            val childId = locator(0x20 + index * 16)
            val name = known("entry_$index", "$childId:attribute=0x3")
            val type = if (childTag == 0x28L) absent else known("base-int", "$childId:attribute=0x49")
            val value = known(index.toString(), "$childId:raw-value")
            DwarfInterfaceTypeChild(childId, childTag, name, type,
                linkedMapOf(0x3L to name, 0x49L to type, (if (childTag == 0x28L) 0x1cL else 0x38L) to value),
                listOf("physical-child-$index"))
        }
        val name = known(label, "$id:attribute=0x3")
        val size = known(if (tag == 0x04L) "4" else "16384", "$id:attribute=0xb")
        return DwarfInterfaceTypeNode(id, tag, name, size, absent, absent,
            linkedMapOf(0x3L to name, 0xbL to size), children, listOf("complete-raw-child-sequence"))
    }

    private fun jsonString(value: JsonObject, key: String): String = (value.getValue(key) as JsonPrimitive).content

    private fun jsonNodeCount(root: JsonElement): Int {
        val pending = java.util.ArrayDeque<JsonElement>()
        pending.addLast(root)
        var count = 0
        while (pending.isNotEmpty()) {
            when (val value = pending.removeLast()) {
                is JsonObject -> pending.addAll(value.values)
                is JsonArray -> pending.addAll(value)
                else -> Unit
            }
            count++
        }
        return count
    }

    private fun record(index: Int): JsonObject = JsonObject(mapOf("value" to JsonPrimitive(index)))

    private fun envelope(kind: String, ordinal: Int, records: List<JsonObject>): ByteArray = OracleJson.canonicalBytes(
        JsonObject(linkedMapOf(
            "schema" to JsonPrimitive("bounded-dwarf-record-shard-v1"), "kind" to JsonPrimitive(kind),
            "ordinal" to JsonPrimitive(ordinal), "recordCount" to JsonPrimitive(records.size), "records" to JsonArray(records),
        )),
    )
}

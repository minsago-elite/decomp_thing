package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedDwarfObservationInventoryTest {
    @Test
    fun `all physical interface roots survive including conflicting lists and automatic variables`() {
        val returnType = known("t-return", "return-type")
        val first = parameter("p-first", 0, known("t-first", "first-type"))
        val second = parameter("p-second", 1, known("t-second", "second-type"))
        val alternative = parameter("p-alternative", 0, known("t-alternative", "alternative-type"))
        val unmatched = parameter("p-unmatched", 2, known("t-unmatched", "unmatched-type"))
        val globalType = known("t-global", "global-type")
        val automaticType = known("t-automatic", "automatic-type", "type-graph-not-expanded-for-automatic-local")
        val input = facts(functions = listOf(function("f", returnType,
            parameters = listOf(first, unmatched), parameterLists = listOf(
                DwarfInterfaceParameterList("list-definition", listOf(first, second), absent()),
                DwarfInterfaceParameterList("list-declaration", listOf(alternative), absent()),
            ))), globals = listOf(variable("global", globalType), variable("automatic", automaticType, "automatic")))

        val inventory = collect(input)
        val roots = records(inventory, "inventoryRoots")
        assertEquals(7, roots.size)
        assertEquals(listOf(returnType, first.type, second.type, alternative.type, unmatched.type, globalType, automaticType)
            .map { it.toJson(::JsonPrimitive) }.toSet(), roots.map { it.getValue("typeFact") }.toSet())
        assertEquals(1, roots.count { string(it, "ownerKind") == "function-return" })
        assertEquals(3, roots.count { string(it, "ownerKind") == "function-parameter" })
        assertEquals(1, roots.count { string(it, "ownerKind") == "selected-parameter-unmatched" })
        assertEquals(2, roots.count { string(it, "ownerKind") == "variable" })
        val candidates = roots.filter { string(it, "ownerKind") == "function-parameter" }
        assertEquals(listOf("list-definition", "list-definition", "list-declaration"),
            candidates.map { string(it, "parameterListLocator") })
        assertEquals(listOf("0", "1", "0"), candidates.map { string(it, "parameterOrdinal") })
        roots.filter { string(it, "ownerKind") in setOf("function-return", "variable") }.forEach {
            assertEquals(JsonNull, it["parameterListLocator"])
            assertEquals(JsonNull, it["parameterOrdinal"])
        }
        val automatic = roots.single { it["typeFact"] == automaticType.toJson(::JsonPrimitive) }
        assertEquals("deferred", string(array(automatic, "candidates").single() as JsonObject, "availability"))
        assertFalse(boolean(inventory.manifest, "requiredTypePopulationComplete"))
    }

    @Test
    fun `ambiguous deferred missing and materialized references retain distinct evidence`() {
        val ambiguous = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS,
            listOf("present", "missing"), listOf("definition", "declaration"), listOf("conflicting-declarations"))
        val deferred = known("deferred", "automatic-local", "type-graph-not-expanded-for-automatic-local")
        val materializedDeferred = known("present", "deferred-edge", "type-reference-not-expanded:abi-layout")
        val input = facts(functions = listOf(function("f", ambiguous)), globals = listOf(
            variable("automatic", deferred, "automatic"), variable("materialized", materializedDeferred),
            variable("absent", absent()), variable("unknown", DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN,
                evidence = listOf("supplementary"), reasons = listOf("unsupported-reference-form"))),
        ), types = listOf(type("present")))
        val inventory = collect(input)
        val roots = records(inventory, "inventoryRoots")
        val ambiguousRoot = roots.single { it["typeFact"] == ambiguous.toJson(::JsonPrimitive) }
        assertEquals(listOf("present", "missing"), array(ambiguousRoot, "candidates").map {
            string(it as JsonObject, "targetId")
        })
        assertEquals(listOf("materialized", "missing"), array(ambiguousRoot, "candidates").map {
            string(it as JsonObject, "availability")
        })
        val materialized = roots.single { it["typeFact"] == materializedDeferred.toJson(::JsonPrimitive) }
        assertEquals("materialized", string(array(materialized, "candidates").single() as JsonObject, "availability"))
        val codes = records(inventory, "inventoryFindings").map { string(it, "code") }.toSet()
        assertTrue(codes.containsAll(setOf("reference-state-ambiguous", "reference-state-absent",
            "reference-state-unknown", "reference-target-missing:missing", "reference-target-deferred:deferred",
            "required-type-population-unresolved")))
    }

    @Test
    fun `cycles and containing type edges survive without claiming member completeness`() {
        val cycle = known("self", "member-type", "type-reference-cycle:self")
        val child = DwarfInterfaceTypeChild("member", 0x0dL, known("same", "member-name"), cycle,
            mapOf(0x49L to cycle, 0x1dL to known("container", "member-containing-type")), emptyList())
        val method = DwarfInterfaceTypeChild("method", 0x2eL, known("same", "method-name"), absent(),
            emptyMap(), listOf("unsupported-type-child-layout"))
        val input = facts(types = listOf(type("self", target = cycle,
            attributes = mapOf(0x49L to cycle, 0x1dL to known("container", "containing-type")),
            children = listOf(child, method)), type("container")))
        val inventory = collect(input)
        val edges = records(inventory, "inventoryReferences")
        assertTrue(edges.any { string(it, "ownerKind") == "type" && string(it, "relation") == "containing-type" &&
            string(it, "ownerLocator") == "self" })
        assertTrue(edges.any { string(it, "ownerKind") == "type-child" && string(it, "relation") == "containing-type" &&
            string(it, "ownerLocator") == "member" && string(it, "parentTypeId") == "self" })
        assertTrue(edges.any { it["typeFact"] == cycle.toJson(::JsonPrimitive) })
        assertTrue(records(inventory, "inventoryFindings").any { string(it, "code") == "reference-cycle" })
        val completeness = records(inventory, "inventoryTypeCompleteness")
        assertEquals(2, completeness.size)
        val self = completeness.single { string(it, "ownerTypeId") == "self" }
        assertEquals("2", string(self, "observedChildCount"))
        assertEquals("1", string(self, "observedDirectMemberCount"))
        completeness.forEach {
            assertEquals(JsonNull, it["requiredMemberCardinality"])
            assertFalse(boolean(it, "complete"))
        }
    }

    @Test
    fun `equal names and shapes never deduplicate physical types or roots`() {
        val input = facts(functions = listOf(function("f-one", known("type-one", "type-use-one")),
            function("f-two", known("type-two", "type-use-two"))),
            types = listOf(type("type-one"), type("type-two")))
        val inventory = collect(input)
        assertEquals(setOf("type-one", "type-two"), records(inventory, "inventoryTypeCompleteness")
            .map { string(it, "ownerTypeId") }.toSet())
        assertEquals(setOf("f-one", "f-two"), records(inventory, "inventoryRoots")
            .map { string(it, "ownerLocator") }.toSet())
        assertEquals("2", string(commitments(inventory, "rawCommitments").getValue("types"), "recordCount"))
        assertEquals("2", string(commitments(inventory, "rawCommitments").getValue("functions"), "recordCount"))
    }

    @Test
    fun `canonical commitments normalize type map and input role order`() {
        val one = facts(types = listOf(type("z"), type("a")))
        val two = facts(types = listOf(type("a"), type("z")))
        val inputs = listOf(richInput(), BoundedDwarfObservationInput("stripped", STRIPPED_SHA, 2L))
        val first = collect(one, inputs = inputs)
        val second = collect(two, inputs = inputs.reversed())
        assertEquals(first.manifest, second.manifest)
        val firstShards = shards(first)
        val secondShards = shards(second)
        assertEquals(firstShards.size, secondShards.size)
        firstShards.zip(secondShards).forEach { (a, b) -> assertContentEquals(a, b) }
    }

    @Test
    fun `raw and derived commitments use framed ordered canonical records`() {
        val input = facts(functions = listOf(function("f", known("t", "return"))), types = listOf(type("t")))
        val inventory = collect(input)
        val raw = linkedMapOf<String, MutableList<JsonObject>>()
        input.visitCanonicalShards { kind, ordinal, bytes, count ->
            raw.getOrPut(kind, ::mutableListOf) += parseCanonicalDwarfShard(bytes,
                expectedKind = kind, expectedOrdinal = ordinal, expectedRecordCount = count).records
        }
        val rawCommitments = commitments(inventory, "rawCommitments")
        raw.forEach { (kind, records) -> assertCommitment(kind,
            if (kind == "metadata") records.map(::semanticMetadata) else records, rawCommitments.getValue(kind)) }
        val derivedCommitments = commitments(inventory, "inventoryCommitments")
        derivedCommitments.forEach { (kind, commitment) -> assertCommitment(kind, records(inventory, kind), commitment) }
    }

    @Test
    fun `raw provenance and stripped layout mutations change the inventory identity`() {
        val original = facts(functions = listOf(function("f", known("t", "original-evidence"))), types = listOf(type("t")))
        val changed = facts(functions = listOf(function("f", known("t", "replacement-evidence"))), types = listOf(type("t")))
        val first = collect(original)
        val second = collect(changed)
        assertNotEquals(first.manifest["inventorySha256"], second.manifest["inventorySha256"])
        assertNotEquals(commitments(first, "rawCommitments").getValue("functions")["sha256"],
            commitments(second, "rawCommitments").getValue("functions")["sha256"])
        val inputs = listOf(richInput(), BoundedDwarfObservationInput("stripped", STRIPPED_SHA, 2L))
        val layoutOne = collect(original, inputs = inputs, strippedLayout = layout(0))
        val layoutTwo = collect(original, inputs = inputs, strippedLayout = layout(1))
        assertNotEquals(layoutOne.manifest["inventorySha256"], layoutTwo.manifest["inventorySha256"])
        val objectOne = collect(original, inputs = inputs, strippedObjects = listOf(symbol("table:1", "first")))
        val objectTwo = collect(original, inputs = inputs, strippedObjects = listOf(symbol("table:1", "second")))
        assertNotEquals(objectOne.manifest["inventorySha256"], objectTwo.manifest["inventorySha256"])
    }

    @Test
    fun `source identities reject mismatched rich facts and unbound stripped observations`() {
        val input = facts()
        val invalid = listOf(emptyList(), listOf(BoundedDwarfObservationInput("rich", STRIPPED_SHA, 1L)),
            listOf(BoundedDwarfObservationInput("rich", RICH_SHA, 2L)), listOf(richInput(), richInput()))
        invalid.forEach { inputs -> assertFailsWith<IllegalArgumentException> { collect(input, inputs = inputs) } }
        assertFailsWith<IllegalArgumentException> { collect(input, strippedLayout = layout(0)) }
        assertFailsWith<IllegalArgumentException> { collect(input, strippedObjects = listOf(symbol("table:1", "object"))) }
    }

    @Test
    fun `empty observations still emit explicit groups and unresolved population finding`() {
        val inventory = collect(facts())
        val observed = mutableListOf<Pair<String, Int>>()
        inventory.visitCanonicalShards { kind, ordinal, bytes, count ->
            val shard = parseCanonicalDwarfShard(bytes, expectedKind = kind, expectedOrdinal = ordinal,
                expectedRecordCount = count)
            observed += kind to shard.recordCount
        }
        assertEquals(setOf("inventoryRoots", "inventoryReferences", "inventoryTypeCompleteness",
            "inventoryFindings", "inventorySelections"), observed.map { it.first }.toSet())
        assertEquals(0, records(inventory, "inventoryRoots").size)
        assertEquals(0, records(inventory, "inventoryReferences").size)
        assertEquals(0, records(inventory, "inventoryTypeCompleteness").size)
        assertEquals(0, records(inventory, "inventorySelections").size)
        assertTrue(records(inventory, "inventoryFindings").any { string(it, "code") == "required-type-population-unresolved" })
        assertFalse(boolean(inventory.manifest, "requiredTypePopulationComplete"))
    }

    @Test
    fun `verifier binds raw and inventory streams and rejects missing reordered repeated or altered records`() {
        val input = facts(functions = listOf(function("f", known("t", "return"))), types = listOf(type("t")))
        val inventory = collect(input)
        val stream = stream(input, inventory)
        verify(inventory.manifest, stream)
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, stream.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, stream.reversed()) }
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, listOf(stream.first()) + stream) }
        val rootShard = stream.single { it.kind == "inventoryRoots" }
        val altered = replaceGroup(stream, "inventoryRoots", rootShard.records.map {
            JsonObject(it + ("ownerLocator" to JsonPrimitive("different-physical-function")))
        })
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, altered) }
        val extendedRoots = rootShard.records.map { JsonObject(it + ("accepted" to JsonPrimitive(true))) }
        val extendedManifest = replaceCommitment(inventory.manifest, "inventoryCommitments", "inventoryRoots", extendedRoots)
        val schemaFailure = assertFailsWith<IllegalArgumentException> {
            verify(extendedManifest, replaceGroup(stream, "inventoryRoots", extendedRoots))
        }
        assertTrue(schemaFailure.message.orEmpty().contains("closed schema"))
        val verifier = BoundedDwarfObservationInventoryV1.verifier(inventory.manifest)
        verifier.acceptStrippedLayout(null)
        stream.forEach { verifier.accept(it.kind, it.ordinal, it.bytes, it.records.size) }
        verifier.finish()
        assertFailsWith<IllegalArgumentException> { verifier.finish() }
    }

    @Test
    fun `rehashed empty and duplicate metadata cannot bypass the rich input identity`() {
        val input = facts()
        val inventory = collect(input)
        val stream = stream(input, inventory)
        val original = stream.single { it.kind == "metadata" }.records.single()
        for (records in listOf(emptyList(), listOf(original, original))) {
            val changed = replaceGroup(stream, "metadata", records)
            val manifest = replaceCommitment(inventory.manifest, "rawCommitments", "metadata", records.map(::semanticMetadata))
            val failure = assertFailsWith<IllegalArgumentException> { verify(manifest, changed) }
            assertTrue(failure.message.orEmpty().contains("exactly one raw metadata record"))
        }
        val wrongInput = JsonObject(original + ("inputSha256" to JsonPrimitive(STRIPPED_SHA)))
        val changed = replaceGroup(stream, "metadata", listOf(wrongInput))
        val manifest = replaceCommitment(inventory.manifest, "rawCommitments", "metadata", listOf(semanticMetadata(wrongInput)))
        assertFailsWith<IllegalArgumentException> { verify(manifest, changed) }
    }

    @Test
    fun `rehashed stripped objects without an input binding fail even with no layout`() {
        val input = facts()
        val objects = listOf(symbol("table:1", "object"))
        val inventory = collect(input, inputs = listOf(richInput(), BoundedDwarfObservationInput("stripped", STRIPPED_SHA, 2)),
            strippedObjects = objects)
        val stream = stream(input, inventory, objects)
        verify(inventory.manifest, stream)
        val manifest = rehash(JsonObject(inventory.manifest + ("inputs" to JsonArray(listOf(richInput().toJson())))))
        val failure = assertFailsWith<IllegalArgumentException> { verify(manifest, stream) }
        assertTrue(failure.message.orEmpty().contains("missing stripped input binding"))
    }

    @Test
    fun `closed manifest counts and stripped layout remain bound after digest recomputation`() {
        val input = facts()
        val inventory = collect(input, inputs = listOf(richInput(), BoundedDwarfObservationInput("stripped", STRIPPED_SHA, 2)),
            strippedLayout = layout(0))
        val stream = stream(input, inventory)
        verify(inventory.manifest, stream, layout(0).toJson())
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, stream, layout(1).toJson()) }
        val extra = rehash(JsonObject(inventory.manifest + ("extraAuthority" to JsonPrimitive(true))))
        assertFailsWith<IllegalArgumentException> { verify(extra, stream, layout(0).toJson()) }
        val counts = inventory.manifest.getValue("counts") as JsonObject
        val wrongCount = rehash(JsonObject(inventory.manifest + ("counts" to JsonObject(counts + ("variableRoots" to JsonPrimitive(1))))))
        assertFailsWith<IllegalArgumentException> { verify(wrongCount, stream, layout(0).toJson()) }
        val falseComplete = rehash(JsonObject(inventory.manifest + ("requiredTypePopulationComplete" to JsonPrimitive(true))))
        assertFailsWith<IllegalArgumentException> { verify(falseComplete, stream, layout(0).toJson()) }
    }

    @Test
    fun `collection and verification enforce aggregate record byte node work and shard bounds`() {
        val input = facts(functions = listOf(function("f", known("t", "return"))), types = listOf(type("t")))
        val inventory = collect(input)
        val stream = stream(input, inventory)
        val canonicalRecords = stream.flatMap { shard ->
            if (shard.kind == "metadata") shard.records.map(::semanticMetadata) else shard.records
        } + JsonObject(mapOf("objectLayout" to JsonNull))
        val recordCount = canonicalRecords.size.toLong()
        val byteCount = canonicalRecords.sumOf { OracleJson.canonicalBytes(it).size.toLong() }
        fun nodes(value: JsonElement): Long = 1L + when (value) {
            is JsonObject -> value.values.sumOf(::nodes)
            is JsonArray -> value.sumOf(::nodes)
            else -> 0L
        }
        val nodeCount = canonicalRecords.sumOf(::nodes)
        val exact = BoundedDwarfObservationInventoryLimits(maximumRecords = recordCount,
            maximumCanonicalBytes = byteCount, maximumCanonicalNodes = nodeCount)
        assertEquals(inventory.manifest, collect(input, limits = exact).manifest)
        verify(inventory.manifest, stream, limits = exact)
        for (limits in listOf(exact.copy(maximumRecords = recordCount - 1),
            exact.copy(maximumCanonicalBytes = byteCount - 1), exact.copy(maximumCanonicalNodes = nodeCount - 1),
            exact.copy(maximumWorkSteps = 1), exact.copy(maximumRecordBytes = 1), exact.copy(maximumRecordNodes = 1))) {
            assertFailsWith<IllegalArgumentException> { collect(input, limits = limits) }
            assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, stream, limits = limits) }
        }
        val bounded = collect(input, limits = exact.copy(shardLimits = BoundedDwarfShardLimits(maximumShards = 1)))
        assertFailsWith<IllegalArgumentException> { bounded.visitCanonicalShards { _, _, _, _ -> } }
        assertFailsWith<IllegalArgumentException> {
            verify(inventory.manifest, stream, limits = exact.copy(shardLimits = BoundedDwarfShardLimits(maximumShards = 1)))
        }
    }

    @Test
    fun `physical census retains unknown DIEs and references without changing semantic projections`() {
        val projected = facts(functions = listOf(function("f", known("t", "return"))), types = listOf(type("t")))
        val input = physicalFacts(functions = projected.functions, types = projected.types.values.toList())
        val inventory = collect(input)
        val census = inventory.manifest.getValue("physicalCensus") as JsonObject
        assertEquals("dwarf-pre-policy-inventory-v3", string(inventory.manifest, "schema"))
        assertTrue(boolean(census, "present"))
        assertTrue(boolean(census, "complete"))
        assertEquals("1", string(census, "compilationUnitCount"))
        assertEquals("4", string(census, "physicalRecordCount"))
        assertEquals("1", string(census, "nullRecordCount"))
        assertEquals("3", string(census, "nonNullRecordCount"))
        assertFalse(boolean(inventory.manifest, "requiredTypePopulationComplete"))
        val raw = stream(input, inventory)
        assertEquals(listOf("metadata", "functions", "types", "typeChildren", "globals", "objectSymbols",
            "physicalUnits", "physicalDies", "strippedObjects") + BoundedDwarfObservationInventoryV1.RECORD_KINDS,
            raw.map { it.kind })
        val dies = raw.single { it.kind == "physicalDies" }.records
        assertEquals(listOf("unit", "type", "unknown"), dies.map { string(it, "category") })
        assertEquals(listOf("retained-target", "missing-target", "unsupported-reference"), dies.flatMap { die ->
            array(die, "references").map { string(it as JsonObject, "state") }
        })
        BoundedDwarfObservationInventoryV1.RECORD_KINDS.forEach { kind ->
            fun semantic(records: List<JsonObject>) = if (kind == "inventoryFindings") records.filter {
                !string(it, "ownerKind").startsWith("physical-")
            } else records
            assertEquals(semantic(records(collect(projected), kind)), semantic(records(inventory, kind)), kind)
        }
        assertEquals(setOf("physical-DIE-tag-unresolved", "physical-reference-missing-target", "physical-reference-unsupported-reference"),
            records(inventory, "inventoryFindings").filter { string(it, "ownerKind").startsWith("physical-") }
                .map { string(it, "code") }.toSet())
        verify(inventory.manifest, raw)
        val authenticated = BoundedDwarfObservationInventoryV1.authenticatedVerifier(inventory.manifest, input)
        authenticated.acceptStrippedLayout(null)
        raw.forEach { authenticated.accept(it.kind, it.ordinal, it.bytes, it.records.size) }
        authenticated.finish()
    }

    @Test
    fun `rehashed physical drop duplicate orphan root count and reference state tampering fails structurally`() {
        val input = physicalFacts()
        val inventory = collect(input)
        val original = stream(input, inventory)
        val dies = original.single { it.kind == "physicalDies" }.records
        val units = original.single { it.kind == "physicalUnits" }.records
        val changes = listOf(
            "physicalDies" to dies.dropLast(1),
            "physicalDies" to (dies + dies.last()),
            "physicalDies" to dies.mapIndexed { index, record -> if (index == 1) JsonObject(record +
                ("parentLocator" to JsonPrimitive(".debug_info:cu=0x0:die=0xf"))) else record },
            "physicalUnits" to units.map { JsonObject(it + ("rootLocator" to JsonPrimitive(".debug_info:cu=0x0:die=0xc"))) },
            "physicalUnits" to units.map { JsonObject(it + ("nonNullRecordCount" to JsonPrimitive(2))) },
            "physicalDies" to dies.mapIndexed { index, record -> if (index != 0) record else JsonObject(record +
                ("references" to JsonArray(array(record, "references").map { element ->
                    JsonObject((element as JsonObject) + mapOf("state" to JsonPrimitive("missing-target"),
                        "reasons" to JsonArray(listOf(JsonPrimitive("missing-target")))))
                }))) },
            "physicalDies" to dies.mapIndexed { index, record -> if (index == 2) JsonObject(record +
                ("category" to JsonPrimitive("type"))) else record },
            "physicalDies" to dies.mapIndexed { index, record -> if (index != 0) record else JsonObject(record +
                ("references" to JsonArray(array(record, "references").map { element ->
                    JsonObject((element as JsonObject) + ("rawOperand" to JsonPrimitive("0xd")))
                }))) },
            "physicalDies" to dies.mapIndexed { index, record -> if (index != 0) record else JsonObject(record +
                ("references" to JsonArray(array(record, "references").map { element ->
                    JsonObject((element as JsonObject) + ("declaredForm" to JsonPrimitive("0x11")))
                }))) },
            "physicalDies" to dies.mapIndexed { index, record -> if (index != 0) record else JsonObject(record +
                ("references" to JsonArray(array(record, "references").map { element ->
                    JsonObject((element as JsonObject) + ("indirectDepth" to JsonPrimitive(5)))
                }))) },
            "physicalDies" to dies.mapIndexed { index, record -> if (index != 2) record else JsonObject(record +
                ("references" to JsonArray(array(record, "references").map { element ->
                    JsonObject((element as JsonObject) + mapOf("declaredForm" to JsonPrimitive("0x13"),
                        "resolvedForm" to JsonPrimitive("0x13")))
                }))) },
        )
        for ((kind, changedRecords) in changes) {
            val changedManifest = replaceCommitment(inventory.manifest, "rawCommitments", kind, changedRecords)
            assertFailsWith<IllegalArgumentException>(kind) {
                verify(changedManifest, replaceGroup(original, kind, changedRecords))
            }
        }
        val census = inventory.manifest.getValue("physicalCensus") as JsonObject
        val wrongCount = rehash(JsonObject(inventory.manifest + ("physicalCensus" to JsonObject(census + mapOf(
            "physicalRecordCount" to JsonPrimitive(5), "nullRecordCount" to JsonPrimitive(2))))))
        assertFailsWith<IllegalArgumentException> { verify(wrongCount, original) }
    }

    @Test
    fun `authenticated scan replay rejects a coherently rehashed omitted unknown DIE`() {
        val input = physicalFacts()
        val inventory = collect(input)
        var changed = stream(input, inventory)
        val changedDies = changed.single { it.kind == "physicalDies" }.records.take(2).mapIndexed { index, record ->
            if (index == 1) JsonObject(record + ("endOffset" to JsonPrimitive("0xe"))) else record
        }
        val changedUnits = changed.single { it.kind == "physicalUnits" }.records.map { JsonObject(it + mapOf(
            "physicalRecordCount" to JsonPrimitive(3), "nonNullRecordCount" to JsonPrimitive(2))) }
        val originalMetadata = changed.single { it.kind == "metadata" }.records.single()
        val recordCounts = originalMetadata.getValue("recordCounts") as JsonObject
        val census = inventory.manifest.getValue("physicalCensus") as JsonObject
        val changedCensus = JsonObject(census + mapOf("physicalRecordCount" to JsonPrimitive(3), "nonNullRecordCount" to JsonPrimitive(2)))
        val changedMetadata = JsonObject(originalMetadata + mapOf("recordCounts" to JsonObject(recordCounts +
            ("physicalDies" to JsonPrimitive(2))), "physicalCensus" to changedCensus))
        changed = replaceGroup(replaceGroup(replaceGroup(changed, "physicalDies", changedDies),
            "physicalUnits", changedUnits), "metadata", listOf(changedMetadata))
        var changedManifest = replaceCommitment(inventory.manifest, "rawCommitments", "physicalDies", changedDies)
        changedManifest = replaceCommitment(changedManifest, "rawCommitments", "physicalUnits", changedUnits)
        changedManifest = replaceCommitment(changedManifest, "rawCommitments", "metadata", listOf(semanticMetadata(changedMetadata)))
        changedManifest = rehash(JsonObject(changedManifest + ("physicalCensus" to changedCensus)))
        // Integrity verification cannot authenticate what these reinterpreted bytes originally contained.
        verify(changedManifest, changed)
        assertFailsWith<IllegalArgumentException> {
            BoundedDwarfObservationInventoryV1.authenticatedVerifier(changedManifest, input)
        }
        var backingSwitched = false
        val mutableBacking = object : LinkedHashMap<String, JsonElement>(changedManifest) {
            override fun get(key: String): JsonElement? {
                if (key == "inputs") {
                    backingSwitched = true
                    clear()
                    putAll(inventory.manifest)
                }
                return super.get(key)
            }
        }
        // The previous factory snapshotted the forged census, then authenticated fresh reads
        // from this mutable backing map after it had switched to the genuine scan manifest.
        assertFailsWith<IllegalArgumentException> {
            BoundedDwarfObservationInventoryV1.authenticatedVerifier(JsonObject(mutableBacking), input)
        }
        assertFalse(backingSwitched, "authentication must read its defensive snapshot exclusively")
        assertFailsWith<IllegalArgumentException> {
            BoundedDwarfObservationInventoryV1.authenticatedVerifier(collect(facts()).manifest, facts())
        }
    }

    @Test
    fun `absent census cannot claim physical completeness and census work stays bounded`() {
        val absent = collect(facts())
        val census = absent.manifest.getValue("physicalCensus") as JsonObject
        assertFalse(boolean(census, "present"))
        assertFalse(boolean(census, "complete"))
        val falselyComplete = rehash(JsonObject(absent.manifest + ("physicalCensus" to JsonObject(census +
            ("complete" to JsonPrimitive(true))))))
        assertFailsWith<IllegalArgumentException> { BoundedDwarfObservationInventoryV1.verifier(falselyComplete) }
        val physical = physicalFacts()
        val inventory = collect(physical)
        val tooLittleWork = BoundedDwarfObservationInventoryLimits(maximumWorkSteps = 3)
        assertFailsWith<IllegalArgumentException> { collect(physical, limits = tooLittleWork) }
        assertFailsWith<IllegalArgumentException> { verify(inventory.manifest, stream(physical, inventory), limits = tooLittleWork) }
    }

    @Test
    fun `GNU alternate direct and indirect rows reject rehashed local target and state forgeries`() {
        val root = ".debug_info:cu=0x0:die=0xb"
        fun alternate(ordinal: Int, declared: Long, depth: Int) =
            DwarfPhysicalReferenceCensus(ordinal, 0x49, declared, FULL_TREE_DW_FORM_GNU_REF_ALT, depth,
                11UL, null, "unsupported-reference").also { it.bindTargets(emptySet()); it.seal() }
        val input = facts(physicalCensusPresent = true,
            physicalUnits = listOf(DwarfPhysicalUnitCensus(0, 11, 12, root, 1, 0, 1)),
            physicalDies = listOf(DwarfPhysicalDieCensus(0, 11, 12, 0x11, 0, null, false, listOf(
                alternate(0, FULL_TREE_DW_FORM_GNU_REF_ALT, 0), alternate(1, FULL_TREE_DW_FORM_INDIRECT, 1)))))
        val inventory = collect(input)
        val raw = stream(input, inventory)
        verify(inventory.manifest, raw)
        for (state in listOf("retained-target", "missing-target", "unsupported-reference")) {
            val records = raw.single { it.kind == "physicalDies" }.records.map { die -> JsonObject(die +
                ("references" to JsonArray(array(die, "references").map { element ->
                    JsonObject((element as JsonObject) + mapOf("targetLocator" to JsonPrimitive(root), "state" to JsonPrimitive(state),
                        "reasons" to JsonArray(if (state == "retained-target") emptyList() else listOf(JsonPrimitive(state)))))
                }))) }
            val forged = replaceCommitment(inventory.manifest, "rawCommitments", "physicalDies", records)
            assertFailsWith<IllegalArgumentException>(state) { verify(forged, replaceGroup(raw, "physicalDies", records)) }
        }
    }

    @Test
    fun `expanded census version is rejected explicitly rather than reinterpreted as numeric rows`() {
        val inventory = collect(physicalFacts())
        val census = inventory.manifest.getValue("physicalCensus") as JsonObject
        val legacy = rehash(JsonObject(inventory.manifest + ("physicalCensus" to JsonObject(census +
            ("schema" to JsonPrimitive("bounded-physical-die-census-v1"))))))
        val failure = assertFailsWith<IllegalArgumentException> { BoundedDwarfObservationInventoryV1.verifier(legacy) }
        assertTrue(failure.message.orEmpty().contains("keys") || failure.message.orEmpty().contains("unsupported"), failure.message)
    }

    @Test
    fun `physical references rederive cross unit indirect unsupported and out of range operands`() {
        val firstRoot = ".debug_info:cu=0x0:die=0xb"
        val secondRoot = ".debug_info:cu=0x10:die=0x1b"
        val locators = setOf(firstRoot, secondRoot)
        fun bind(reference: DwarfPhysicalReferenceCensus) = reference.also { it.bindTargets(locators) }
        val input = facts(physicalCensusPresent = true, physicalUnits = listOf(
            // A trailing multibyte zero ULEB is a valid physical null record in the scanner.
            DwarfPhysicalUnitCensus(0, 0xb, 0x10, firstRoot, 2, 1, 1),
            DwarfPhysicalUnitCensus(0x10, 0x1b, 0x1c, secondRoot, 1, 0, 1),
        ), physicalDies = listOf(
            DwarfPhysicalDieCensus(0, 0xb, 0xc, 0x11, 0, null, false, listOf(bind(
                DwarfPhysicalReferenceCensus(0, 0x49, 0x16, 0x10, 1, 0x1bUL, secondRoot)))),
            DwarfPhysicalDieCensus(0x10, 0x1b, 0x1c, 0x11, 0, null, false, listOf(
                bind(DwarfPhysicalReferenceCensus(0, 0x49, 0x11, 0x11, 0, 0xfaUL, null, "out-of-range-reference")),
                bind(DwarfPhysicalReferenceCensus(1, 0x49, 0x24, 0x24, 0, ULong.MAX_VALUE, null, "unsupported-reference")),
            )),
        ))
        val inventory = collect(input)
        val raw = stream(input, inventory)
        verify(inventory.manifest, raw)
        val exactBytes = raw.sumOf { shard -> shard.records.sumOf { record ->
            OracleJson.canonicalBytes(if (shard.kind == "metadata") semanticMetadata(record) else wireForTest(shard.kind, record)).size.toLong()
        } } + OracleJson.canonicalBytes(JsonObject(mapOf("objectLayout" to JsonNull))).size
        val limits = BoundedDwarfObservationInventoryLimits(maximumCanonicalBytes = exactBytes)
        assertEquals(inventory.manifest, collect(input, limits = limits).manifest)
        val verifier = BoundedDwarfObservationInventoryV1.authenticatedVerifier(inventory.manifest, input, limits)
        verifier.acceptStrippedLayout(null)
        raw.forEach { verifier.accept(it.kind, it.ordinal, it.bytes, it.records.size) }
        verifier.finish()
        val census = inventory.manifest.getValue("physicalCensus") as JsonObject
        val hostileCount = rehash(JsonObject(inventory.manifest + ("physicalCensus" to JsonObject(census + mapOf(
            "physicalRecordCount" to JsonPrimitive(Long.MAX_VALUE), "nullRecordCount" to JsonPrimitive(Long.MAX_VALUE))))))
        assertFailsWith<IllegalArgumentException> { BoundedDwarfObservationInventoryV1.verifier(hostileCount) }
    }

    private data class Shard(val kind: String, val ordinal: Int, val bytes: ByteArray, val records: List<JsonObject>)

    private fun stream(input: BoundedDwarfInterfaceFacts, inventory: BoundedDwarfObservationInventory,
                       objects: List<FullTreeElfObjectSymbol> = emptyList()): List<Shard> = buildList {
        val retain: (String, Int, ByteArray, Int) -> Unit = { kind, ordinal, bytes, count ->
            add(Shard(kind, ordinal, bytes, parseCanonicalDwarfShard(bytes, expectedKind = kind,
                expectedOrdinal = ordinal, expectedRecordCount = count).records.map { expandedForTest(kind, it) }))
        }
        input.visitCanonicalShards(retain)
        BoundedDwarfCanonicalShardWriter(consumer = retain).apply {
            write("strippedObjects", objects.asSequence().map { it.toJson() }); finish()
        }
        inventory.visitCanonicalShards(retain)
    }

    private fun expandedForTest(kind: String, record: JsonObject): JsonObject =
        if (kind == "physicalDies" && record.keys == setOf("row")) DwarfPhysicalDieRowEncoding.decode(record).toJson() else record

    /** Tamper controls mutate full semantics, then independently rebuild the versioned wire row. */
    private fun wireForTest(kind: String, record: JsonObject): JsonObject {
        if (kind != "physicalDies" || "row" in record) return record
        fun hex(value: String) = value.removePrefix("0x").toLong(16)
        fun offset(key: String) = hex(string(record, key))
        val unit = string(record, "compilationUnitLocator").substringAfter("cu=0x").toLong(16)
        val references = array(record, "references").map { element ->
            val ref = element as JsonObject
            val target = ref.getValue("targetLocator").let { if (it == JsonNull) null else (it as JsonPrimitive).content }
            val state = string(ref, "state")
            DwarfPhysicalReferenceCensus(string(ref, "attributeOrdinal").toInt(), hex(string(ref, "attribute")),
                hex(string(ref, "declaredForm")), hex(string(ref, "resolvedForm")), string(ref, "indirectDepth").toInt(),
                string(ref, "rawOperand").removePrefix("0x").toULong(16), target, state.takeIf { it != "retained-target" }).also {
                it.bindTargets(if (state == "retained-target") setOf(target!!) else emptySet())
                if (array(ref, "reasons").contains(JsonPrimitive("reference-cycle"))) it.markCycle()
            }
        }
        val parent = record.getValue("parentLocator").let { if (it == JsonNull) null else (it as JsonPrimitive).content.substringAfterLast("die=0x").toLong(16) }
        val die = DwarfPhysicalDieCensus(unit, offset("offset"), offset("endOffset"), offset("tag"),
            string(record, "depth").toInt(), parent, string(record, "hasChildren").toBooleanStrict(), references)
        val encoded = DwarfPhysicalDieRowEncoding.encode(die)
        return if (record["category"] != JsonPrimitive(die.category)) JsonObject(encoded + ("unexpectedCategory" to record.getValue("category"))) else encoded
    }

    private fun replaceGroup(stream: List<Shard>, kind: String, records: List<JsonObject>): List<Shard> {
        val replacements = mutableListOf<Shard>()
        BoundedDwarfCanonicalShardWriter { observedKind, ordinal, bytes, count ->
            replacements += Shard(observedKind, ordinal, bytes, parseCanonicalDwarfShard(bytes,
                expectedKind = kind, expectedOrdinal = ordinal, expectedRecordCount = count).records.map { expandedForTest(kind, it) })
        }.apply { write(kind, records.asSequence().map { wireForTest(kind, it) }); finish() }
        val index = stream.indexOfFirst { it.kind == kind }
        return stream.take(index) + replacements + stream.drop(index).filter { it.kind != kind }
    }

    private fun verify(manifest: JsonObject, stream: List<Shard>, layout: JsonObject? = null,
                       limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits()) {
        val verifier = BoundedDwarfObservationInventoryV1.verifier(manifest, limits)
        verifier.acceptStrippedLayout(layout)
        stream.forEach { verifier.accept(it.kind, it.ordinal, it.bytes, it.records.size) }
        verifier.finish()
    }

    private fun replaceCommitment(manifest: JsonObject, field: String, kind: String, records: List<JsonObject>): JsonObject =
        rehash(JsonObject(manifest + (field to JsonArray(array(manifest, field).map { entry ->
            if (string(entry as JsonObject, "kind") == kind) commitment(kind, records) else entry
        }))))

    private fun rehash(manifest: JsonObject): JsonObject {
        val unsigned = JsonObject(manifest - "inventorySha256")
        val hash = MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unsigned))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return JsonObject(unsigned + ("inventorySha256" to JsonPrimitive(hash)))
    }

    // Independent expected semantic projection: operational scan counters and ceilings are not observations.
    private fun semanticMetadata(raw: JsonObject): JsonObject = JsonObject(linkedMapOf(
        *listOf("schema", "inputSha256", "inputBytes", "elfType", "imageBase", "executableRanges", "dwarfPresent",
            "recordCounts", "ordering", "typeChildEncoding", "typePromotedFactFallbacks", "typePromotedFactRule", "physicalCensus")
            .map { it to raw.getValue(it) }.toTypedArray(),
        "objectLayout" to raw.getValue("objectLayout").let { if (it == JsonNull) it else JsonObject((it as JsonObject) - "scannedSymbols") },
        "typeGraphScope" to (raw.getValue("limits") as JsonObject).getValue("typeGraphScope"),
    ))

    private fun collect(
        facts: BoundedDwarfInterfaceFacts,
        inputs: List<BoundedDwarfObservationInput> = listOf(richInput()),
        strippedObjects: List<FullTreeElfObjectSymbol> = emptyList(),
        strippedLayout: FullTreeElfObjectLayoutObservation? = null,
        selections: List<BoundedDwarfFunctionSelection> = emptyList(),
        limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits(),
    ): BoundedDwarfObservationInventory = BoundedDwarfObservationInventoryV1.collect(
        facts, strippedObjects, strippedLayout, inputs, selections, limits,
    )

    private fun records(inventory: BoundedDwarfObservationInventory, kind: String): List<JsonObject> {
        val result = mutableListOf<JsonObject>()
        inventory.visitCanonicalShards { observedKind, ordinal, bytes, count ->
            val shard = parseCanonicalDwarfShard(bytes, expectedKind = observedKind, expectedOrdinal = ordinal,
                expectedRecordCount = count)
            if (kind == observedKind) result += shard.records
        }
        return result
    }

    private fun shards(inventory: BoundedDwarfObservationInventory): List<ByteArray> = buildList {
        inventory.visitCanonicalShards { _, _, bytes, _ -> add(bytes) }
    }

    private fun commitments(inventory: BoundedDwarfObservationInventory, field: String): Map<String, JsonObject> =
        array(inventory.manifest, field).map { it as JsonObject }.associateBy { string(it, "kind") }

    private fun assertCommitment(kind: String, records: List<JsonObject>, commitment: JsonObject) {
        assertEquals(commitment(kind, records), commitment, kind)
    }

    private fun commitment(kind: String, records: List<JsonObject>): JsonObject {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("bounded-dwarf-observation-records-v1\n$kind\n".toByteArray(Charsets.UTF_8))
        var totalBytes = 0L
        records.forEach {
            val bytes = OracleJson.canonicalBytes(wireForTest(kind, it))
            digest.update(1.toByte())
            digest.update(ByteBuffer.allocate(8).putLong(bytes.size.toLong()).array())
            digest.update(bytes)
            totalBytes += bytes.size
        }
        digest.update(0.toByte())
        digest.update(ByteBuffer.allocate(8).putLong(records.size.toLong()).array())
        val hash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        return JsonObject(mapOf("kind" to JsonPrimitive(kind), "sha256" to JsonPrimitive(hash),
            "recordCount" to JsonPrimitive(records.size), "canonicalBytes" to JsonPrimitive(totalBytes)))
    }

    private fun facts(
        functions: List<DwarfInterfaceFunctionFacts> = emptyList(),
        types: List<DwarfInterfaceTypeNode> = emptyList(),
        globals: List<DwarfGlobalVariableFacts> = emptyList(),
        physicalUnits: List<DwarfPhysicalUnitCensus> = emptyList(),
        physicalDies: List<DwarfPhysicalDieCensus> = emptyList(),
        physicalCensusPresent: Boolean = false,
    ) = BoundedDwarfInterfaceFacts(inputSha256 = RICH_SHA, inputBytes = 1L, elfType = "ET_EXEC",
        imageBase = 0x400000UL, executableRanges = emptyList(), functions = functions,
        types = types.associateBy { it.id }, scannedDies = if (physicalCensusPresent) physicalUnits.sumOf { it.physicalRecordCount }
            else functions.size.toLong() + types.size + globals.size,
        compilationUnits = if (physicalCensusPresent) physicalUnits.size else 1, dwarfPresent = true,
        limits = BoundedDwarfInterfaceFactLimits(), globals = globals,
        physicalUnits = physicalUnits, physicalDies = physicalDies, physicalCensusPresent = physicalCensusPresent)

    private fun physicalFacts(functions: List<DwarfInterfaceFunctionFacts> = emptyList(),
                              types: List<DwarfInterfaceTypeNode> = emptyList()): BoundedDwarfInterfaceFacts {
        val root = ".debug_info:cu=0x0:die=0xb"
        val child = ".debug_info:cu=0x0:die=0xc"
        val locators = setOf(root, child, ".debug_info:cu=0x0:die=0xd")
        fun reference(ordinal: Int, target: String?, unresolved: String? = null): DwarfPhysicalReferenceCensus =
            DwarfPhysicalReferenceCensus(ordinal, 0x49, if (unresolved == "unsupported-reference") 0x1c else 0x13,
                if (unresolved == "unsupported-reference") 0x1c else 0x13, 0,
                target?.substringAfterLast("die=0x")?.toULong(16) ?: 0xcUL, target, unresolved).also {
                it.bindTargets(locators)
            }
        val dies = listOf(
            DwarfPhysicalDieCensus(0, 0xb, 0xc, 0x11, 0, null, true, listOf(reference(0, child))),
            DwarfPhysicalDieCensus(0, 0xc, 0xd, 0x24, 1, 0xb, false,
                listOf(reference(1, ".debug_info:cu=0x0:die=0xe"))),
            DwarfPhysicalDieCensus(0, 0xd, 0xe, 0xdead, 1, 0xb, false,
                listOf(reference(2, null, "unsupported-reference"))),
        )
        return facts(functions = functions, types = types, physicalUnits = listOf(
            DwarfPhysicalUnitCensus(0, 0xb, 0xf, root, 4, 1, 3)), physicalDies = dies, physicalCensusPresent = true)
    }

    private fun function(
        locator: String,
        returnType: DwarfInterfaceFact<String>,
        parameters: List<DwarfInterfaceParameterFacts> = emptyList(),
        parameterLists: List<DwarfInterfaceParameterList> = emptyList(),
    ) = DwarfInterfaceFunctionFacts(rva = 0x1000UL, absoluteAddress = 0x401000UL, executable = true,
        locator = locator, sourceName = known("same_function", "function-name"), linkageName = absent(),
        language = absent(), callingConvention = absent(), prototyped = absent(), artificial = absent(),
        declaration = absent(), returnType = returnType, parameters = parameters, parameterList = absent(),
        parameterLists = parameterLists, variadic = absent(), origins = emptyList(), reasons = emptyList())

    private fun parameter(locator: String, ordinal: Int, type: DwarfInterfaceFact<String>) =
        DwarfInterfaceParameterFacts(ordinal, locator, known("same_parameter", "parameter-name"), type,
            absent(), emptyList(), emptyList())

    private fun variable(locator: String, type: DwarfInterfaceFact<String>, storage: String = "static-storage") =
        DwarfGlobalVariableFacts(locator = locator, sourceName = known("same_variable", "variable-name"),
            linkageName = absent(), language = absent(), type = type, external = absent(), declaration = absent(),
            artificial = absent(), visibility = absent(), byteSize = absent(), alignment = absent(), constant = absent(),
            scope = absent(), location = absent(), address = absent(), rva = absent(), tlsOffset = absent(),
            storage = known(storage, "storage"), scopes = emptyList(), origins = emptyList(), reasons = emptyList())

    private fun type(
        id: String,
        target: DwarfInterfaceFact<String> = absent(),
        attributes: Map<Long, DwarfInterfaceFact<String>> = emptyMap(),
        children: List<DwarfInterfaceTypeChild> = emptyList(),
    ) = DwarfInterfaceTypeNode(id, 0x13L, known("SameType", "type-name"), known("4", "type-size"),
        absent(), target, attributes, children, emptyList())

    private fun layout(osAbi: Int) = FullTreeElfObjectLayoutObservation(2, 1, "ET_EXEC", 62, osAbi, 0,
        0x400000UL, emptyList(), 0L, emptyList(), emptyList())

    private fun symbol(locator: String, name: String) = FullTreeElfObjectSymbol(name, locator, 1, 1, 0, 0,
        1, 1L, FullTreeElfSymbolSectionKind.DEFINED, ".data", 0x402000UL, 4UL, 0x2000UL,
        FullTreeElfObjectStorage.MAPPED_LOAD, 3UL, 1L, 0x402000UL, 4UL, listOf(0), emptyList())

    private fun <T> absent(): DwarfInterfaceFact<T> = DwarfInterfaceFact(DwarfInterfaceFactState.ABSENT)
    private fun known(value: String, evidence: String, vararg reasons: String) =
        DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(evidence), reasons.toList())
    private fun string(objectValue: JsonObject, field: String): String = (objectValue.getValue(field) as JsonPrimitive).content
    private fun boolean(objectValue: JsonObject, field: String): Boolean = string(objectValue, field).toBooleanStrict()
    private fun array(objectValue: JsonObject, field: String): JsonArray = objectValue.getValue(field) as JsonArray
    private fun richInput() = BoundedDwarfObservationInput("rich", RICH_SHA, 1L)

    private companion object {
        const val RICH_SHA = "0000000000000000000000000000000000000000000000000000000000000000"
        const val STRIPPED_SHA = "1111111111111111111111111111111111111111111111111111111111111111"
    }
}

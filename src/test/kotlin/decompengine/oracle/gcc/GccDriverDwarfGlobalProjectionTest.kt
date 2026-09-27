package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactLimits
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.DwarfGlobalVariableFacts
import decompengine.oracle.fulltree.DwarfInterfaceFact
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.DwarfInterfaceTypeNode
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfMemorySegment
import decompengine.oracle.fulltree.FullTreeElfObjectLayoutObservation
import decompengine.oracle.fulltree.FullTreeElfObjectStorage
import decompengine.oracle.fulltree.FullTreeElfObjectSymbol
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccDriverDwarfGlobalProjectionTest {
    @Test
    fun `exact storage preserves aliases and repeated declarations without name joins or denominator inflation`() {
        val globals = listOf(global("definition", name = "source_name"), global("declaration", declaration = known("1")))
        val rich = listOf(symbol("table:1", name = "other_name"), symbol("table:2", name = "alias"))
        val result = project(globals, rich, listOf(symbol("table:1", name = "stripped_name")))
        assertEquals(6, result.records.size) // Five source records and one physical storage key.
        val binding = result.bindings().single()
        assertEquals(listOf("definition"), binding.strings("dwarfLocators"))
        assertEquals(listOf("table:1", "table:2"), binding.strings("richSymbolLocators"))
        assertEquals(listOf("table:1"), binding.strings("strippedSymbolLocators"))
        assertEquals("1", result.summary.text("storageBindings"))
        assertEquals("0", result.summary.text("excludedRecords"))
        assertEquals("false", result.summary.text("scored"))
        assertEquals(JsonNull, result.row("dwarf:declaration")["storageBindingId"])
        assertEquals("false", binding.text("namesJoined"))
        assertEquals("false", binding.text("typesJoined"))
        assertTrue(result.row("rich-object:table:1") != result.row("stripped-object:table:1"))
    }

    @Test
    fun `equal names never join different addresses and same coordinates keep conflicting sizes ambiguous`() {
        val names = project(listOf(global("first", 0x110UL), global("second", 0x120UL)), listOf(symbol("object", 0x110UL)))
        assertEquals(2, names.bindings().size)
        assertTrue(names.bindings().any { it.strings("dwarfLocators") == listOf("second") && it.strings("richSymbolLocators").isEmpty() })
        val conflict = project(listOf(global("first", size = known("4")), global("second", size = known("8"))))
        assertEquals(2, conflict.bindings().size)
        conflict.bindings().forEach {
            assertTrue("same-coordinate-with-conflicting-byte-sizes" in it.strings("ambiguities"))
            assertEquals("unresolved", it.text("sourceIdentity"))
        }
        val types = project(listOf(global("first", type = known("int")), global("second", type = known("float"))),
            types = mapOf("int" to type("int", 0x24, known("4")), "float" to type("float", 0x24, known("4"))))
        assertEquals(1, types.bindings().size)
        assertTrue("multiple-raw-type-identities" in types.bindings().single().strings("ambiguities"))
        assertEquals(listOf("first", "second"), types.bindings().single().strings("dwarfLocators"))
    }

    @Test
    fun `symbol-only unknown automatic and declaration records all remain visible`() {
        val globals = listOf(global("automatic", storage = known("automatic"), scope = "function"),
            global("unknown", storage = unknown("static-storage")),
            global("ambiguous", address = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf("0x110", "0x120"))),
            global("declaration", declaration = known("1")), global("uncertainDeclaration", declaration = unknown("0")))
        val symbols = listOf(symbol("only")) + listOf(FullTreeElfObjectStorage.UNDEFINED, FullTreeElfObjectStorage.COMMON,
            FullTreeElfObjectStorage.ABSOLUTE, FullTreeElfObjectStorage.NONALLOC, FullTreeElfObjectStorage.UNMAPPED)
            .map { symbol(it.name, storage = it) }
        val result = project(globals, symbols)
        assertEquals(globals.size + symbols.size + 1, result.records.size)
        globals.forEach { assertEquals("unresolved", result.row("dwarf:${it.locator}").text("state")) }
        symbols.drop(1).forEach { assertEquals("unresolved", result.row("rich-object:${it.locator}").text("state")) }
        assertTrue(result.bindings().single().strings("dwarfLocators").isEmpty())
        assertEquals("1", result.summary.getValue("counts").jsonObject.text("symbolOnlyBindings"))
    }

    @Test
    fun `static local storage can bind while absent and multiply valued facts never supply guessed coordinates`() {
        val result = project(listOf(global("staticLocal", scope = "block"), global("missing", address = absent()),
            global("multiple", address = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf("0x110", "0x120")))))
        assertEquals("storage-proved", result.row("dwarf:staticLocal").text("state"))
        assertEquals("unresolved", result.row("dwarf:missing").text("state"))
        assertEquals("unresolved", result.row("dwarf:multiple").text("state"))
    }

    @Test
    fun `explicit consistent typedef sizes bind but pointer array and atomic sizes are never inferred`() {
        val types = mapOf(
            "base" to type("base", 0x24, known("4")),
            "alias" to type("alias", 0x16, target = known("const")),
            "const" to type("const", 0x26, target = known("base")),
            "pointer" to type("pointer", 0x0f, target = known("base")),
            "sizedPointer" to type("sizedPointer", 0x0f, known("8"), known("base")),
            "array" to type("array", 0x01, target = known("base")),
            "atomic" to type("atomic", 0x47, target = known("base")),
            "sizedAtomic" to type("sizedAtomic", 0x47, known("8"), known("base")),
        )
        val globals = types.keys.map { global(it, size = absent(), type = known(it)) } +
            global("conflict", size = known("8"), type = known("alias"))
        val result = project(globals, types = types)
        for (id in listOf("base", "alias", "const", "sizedPointer", "sizedAtomic")) {
            assertEquals("storage-proved", result.row("dwarf:$id").text("state"), id)
        }
        for (id in listOf("pointer", "array", "atomic", "conflict")) {
            assertEquals("unresolved", result.row("dwarf:$id").text("state"), id)
        }
        assertTrue("conflicting-explicit-byte-sizes" in result.row("dwarf:conflict").strings("reasons"))
    }

    @Test
    fun `size cycles stay unknown and depth failures are bounded without rejecting recursive terminal types`() {
        val types = mapOf("a" to type("a", 0x16, target = known("b")), "b" to type("b", 0x26, target = known("a")),
            "struct" to type("struct", 0x13, known("8"), known("struct")))
        val result = project(listOf(global("cycle", size = absent(), type = known("a")),
            global("recursive", size = absent(), type = known("struct"))), types = types)
        assertTrue("cyclic-size-preserving-type-chain" in result.row("dwarf:cycle").strings("reasons"))
        assertEquals("storage-proved", result.row("dwarf:recursive").text("state"))
        assertFailsWith<FullTreeControlException> {
            project(listOf(global("deep", type = known("a"))), types = types,
                limits = GccDriverDwarfGlobalProjectionLimits(maximumTypeDepth = 1))
        }
        for (size in listOf(known("0"), known("-1"), known("18446744073709551616"), unknown("4"),
            DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf("4", "8")))) {
            assertEquals("unresolved", project(listOf(global("bad", size = size))).row("dwarf:bad").text("state"))
        }
    }

    @Test
    fun `address and TLS offset zero remain separate domains with full extent proof`() {
        val layout = layout(base = 0UL, loaded = listOf(segment(0, 0UL, 0x100UL)), tls = listOf(segment(1, 0x80UL, 16UL)))
        val result = project(listOf(global("static", coordinate = 0UL), global("tls", coordinate = 0UL, storage = known("thread-local"))),
            listOf(symbol("static", 0UL, base = 0UL), symbol("tls", 0UL, storage = FullTreeElfObjectStorage.TLS)),
            listOf(symbol("strippedTls", 0UL, storage = FullTreeElfObjectStorage.TLS)), richLayout = layout, strippedLayout = layout)
        assertEquals(2, result.bindings().size)
        assertEquals(setOf("process-address", "tls-offset"), result.bindings().map { it.getValue("storage").jsonObject.text("domain") }.toSet())
        val tls = result.bindings().single { it.getValue("storage").jsonObject.text("domain") == "tls-offset" }
        assertEquals(listOf("strippedTls"), tls.strings("strippedSymbolLocators"))
        assertEquals("true", tls.text("strippedStorageProved"))
    }

    @Test
    fun `point-only locations and overflowing extents cannot establish full object storage`() {
        val nearEnd = project(listOf(global("crossing", 0x1feUL), global("outside", 0x300UL)))
        assertTrue(nearEnd.bindings().isEmpty())
        val narrow = layout(elfClass = 1, base = 0UL,
            loaded = listOf(segment(0, 0UL, 0x100UL), segment(1, 0xffffff00UL, 0x100UL)))
        assertEquals(1, project(listOf(global("boundary32", 0xfffffffcUL)), richLayout = narrow, strippedLayout = narrow).bindings().size)
        assertEquals(1, project(listOf(global("lastByte32", 0xffffffffUL, size = known("1"))), richLayout = narrow, strippedLayout = narrow).bindings().size)
        assertTrue(project(listOf(global("overflow32", 0xfffffffdUL)), richLayout = narrow, strippedLayout = narrow).bindings().isEmpty())
        val wide = layout(base = 0UL, loaded = listOf(segment(0, 0UL, ULong.MAX_VALUE)))
        assertTrue(project(listOf(global("overflow64", ULong.MAX_VALUE - 1UL)), richLayout = wide, strippedLayout = wide).bindings().isEmpty())
        val tlsLayout = layout(tls = listOf(segment(1, 0x180UL, 8UL)))
        assertTrue(project(listOf(global("crossingTls", 6UL, storage = known("thread-local"))),
            richLayout = tlsLayout, strippedLayout = tlsLayout).bindings().isEmpty())
    }

    @Test
    fun `missing ambiguous or unknown-alignment TLS templates do not acquire cross-artifact bindings`() {
        for (segments in listOf(emptyList(), listOf(segment(1, 0x180UL, 16UL), segment(2, 0x190UL, 16UL)))) {
            val layout = layout(tls = segments)
            assertTrue(project(listOf(global("tls", 0UL, storage = known("thread-local"))),
                richLayout = layout, strippedLayout = layout).bindings().isEmpty())
        }
        val unknown = layout(tls = listOf(segment(1, 0x180UL, 16UL, alignment = null)))
        val disjoint = project(listOf(global("tls", 0UL, storage = known("thread-local"))),
            stripped = listOf(symbol("tls", 0UL, storage = FullTreeElfObjectStorage.TLS)), richLayout = unknown, strippedLayout = unknown)
        assertEquals(2, disjoint.bindings().size)
        assertEquals(setOf("rich", "stripped"), disjoint.bindings().map { it.text("layoutDomain") }.toSet())
        for (alignment in listOf(0UL, 1UL)) {
            val knownLayout = layout(tls = listOf(segment(1, 0x180UL, 16UL, alignment)))
            assertEquals(1, project(listOf(global("tls", 0UL, storage = known("thread-local"))),
                stripped = listOf(symbol("tls", 0UL, storage = FullTreeElfObjectStorage.TLS)), richLayout = knownLayout, strippedLayout = knownLayout).bindings().size)
        }
    }

    @Test
    fun `layout mismatches retain rich joins but separate stripped evidence and symbol counts do not affect geometry`() {
        for (strippedLayout in listOf(layout(machine = 3), layout(loaded = listOf(segment(0, 0x100UL, 0x110UL))),
            layout(tls = listOf(segment(1, 0x180UL, 16UL))))) {
            val result = project(listOf(global("global")), listOf(symbol("rich")), listOf(symbol("stripped")), strippedLayout = strippedLayout)
            assertEquals(2, result.bindings().size)
            val rich = result.bindings().single { it.text("layoutDomain") == "rich" }
            assertEquals(listOf("global"), rich.strings("dwarfLocators"))
            assertEquals(listOf("rich"), rich.strings("richSymbolLocators"))
            assertFalse(rich.text("strippedStorageProved").toBoolean())
        }
        val countsOnly = project(listOf(global("global")), stripped = listOf(symbol("stripped")), strippedLayout = layout(scanned = 1000))
        assertEquals(1, countsOnly.bindings().size)
    }

    @Test
    fun `aliases produce linear records and deterministic ordering under shuffled discovery`() {
        val rich = (0 until 500).map { symbol("symbol-$it") }
        val facts = facts(listOf(global("global")), rich)
        val first = GccDriverDwarfGlobalProjection.project(facts, emptyList(), layout(),
            GccDriverDwarfGlobalProjectionLimits(maximumWork = 3000))
        val second = project(listOf(global("global")), rich.reversed())
        assertEquals(502, first.records.size)
        assertEquals(500, first.bindings().single().strings("richSymbolLocators").size)
        assertContentEquals(OracleJson.canonicalBytes(JsonArray(first.records)), OracleJson.canonicalBytes(JsonArray(second.records)))
    }

    @Test
    fun `input work output record and duplicate locator bounds fail before publication`() {
        for (limits in listOf(GccDriverDwarfGlobalProjectionLimits(maximumInputsPerKind = 1),
            GccDriverDwarfGlobalProjectionLimits(maximumRecords = 1), GccDriverDwarfGlobalProjectionLimits(maximumWork = 1),
            GccDriverDwarfGlobalProjectionLimits(maximumRecordBytes = 32), GccDriverDwarfGlobalProjectionLimits(maximumRecordPayloadBytes = 32))) {
            assertFailsWith<IllegalArgumentException> { project(listOf(global("a"), global("b")), limits = limits) }
        }
        assertFailsWith<FullTreeControlException> { project(listOf(global("same"), global("same"))) }
        assertFailsWith<FullTreeControlException> { project(emptyList(), listOf(symbol("same"), symbol("same"))) }
    }

    @Test
    fun `payload byte cap measures each canonical record exactly and envelope accounting remains explicit`() {
        val globals = listOf(global("global"))
        val baseline = project(globals)
        val payloadBytes = baseline.records.sumOf { OracleJson.canonicalBytes(it).size.toLong() }
        assertEquals(payloadBytes.toString(), baseline.summary.text("canonicalRecordPayloadBytes"))
        assertEquals("sum-of-canonical-record-bytes-before-shard-envelopes", baseline.configuration.text("byteBudgetScope"))
        assertEquals(baseline.records, project(globals,
            limits = GccDriverDwarfGlobalProjectionLimits(maximumRecordPayloadBytes = payloadBytes)).records)
        assertFailsWith<FullTreeControlException> {
            project(globals, limits = GccDriverDwarfGlobalProjectionLimits(maximumRecordPayloadBytes = payloadBytes - 1))
        }
        assertEquals("0", project(emptyList(), limits = GccDriverDwarfGlobalProjectionLimits(maximumRecordPayloadBytes = 1))
            .summary.text("canonicalRecordPayloadBytes"))
    }

    private fun project(
        globals: List<DwarfGlobalVariableFacts>, rich: List<FullTreeElfObjectSymbol> = emptyList(),
        stripped: List<FullTreeElfObjectSymbol> = emptyList(), types: Map<String, DwarfInterfaceTypeNode> = emptyMap(),
        richLayout: FullTreeElfObjectLayoutObservation = layout(), strippedLayout: FullTreeElfObjectLayoutObservation = layout(),
        limits: GccDriverDwarfGlobalProjectionLimits = GccDriverDwarfGlobalProjectionLimits(),
    ) = GccDriverDwarfGlobalProjection.project(facts(globals, rich, types, richLayout), stripped, strippedLayout, limits)

    private fun facts(globals: List<DwarfGlobalVariableFacts>, objects: List<FullTreeElfObjectSymbol>,
        types: Map<String, DwarfInterfaceTypeNode> = emptyMap(), layout: FullTreeElfObjectLayoutObservation = layout()) =
        BoundedDwarfInterfaceFacts("a".repeat(64), 1024, layout.elfType, layout.imageBase, emptyList(), emptyList(), types,
            globals.size.toLong(), 1, true, BoundedDwarfInterfaceFactLimits(), globals = globals,
            objectSymbols = objects, objectLayout = layout)

    private fun global(id: String, coordinate: ULong = 0x110UL, name: String = "same-name",
        size: DwarfInterfaceFact<String> = known("4"), type: DwarfInterfaceFact<String> = absent(),
        storage: DwarfInterfaceFact<String> = known("static-storage"), address: DwarfInterfaceFact<String> = known("0x${coordinate.toString(16)}"),
        declaration: DwarfInterfaceFact<String> = absent(), scope: String = "file") = DwarfGlobalVariableFacts(
        locator = id, sourceName = known(name), linkageName = known(name), language = absent(), type = type,
        external = absent(), declaration = declaration, artificial = absent(), visibility = absent(), byteSize = size,
        alignment = absent(), constant = absent(), scope = known(scope), location = absent(), address = address,
        rva = absent(), tlsOffset = known("0x${coordinate.toString(16)}"), storage = storage,
        scopes = emptyList(), origins = listOf(id), reasons = emptyList(),
    )

    private fun symbol(id: String, coordinate: ULong = 0x110UL, size: ULong = 4UL, name: String = "same-name",
        storage: FullTreeElfObjectStorage = FullTreeElfObjectStorage.MAPPED_LOAD, base: ULong = 0x100UL) = FullTreeElfObjectSymbol(
        name, id, if (storage == FullTreeElfObjectStorage.TLS) 6 else 1, 1, 0, 0, 1, 1,
        FullTreeElfSymbolSectionKind.DEFINED, ".data", coordinate, size,
        if (storage == FullTreeElfObjectStorage.MAPPED_LOAD && coordinate >= base) coordinate - base else null,
        storage, 3UL, 1, 0x100UL, 0x100UL,
        listOf(if (storage == FullTreeElfObjectStorage.TLS) 1 else 0), emptyList(),
    )

    private fun type(id: String, tag: Long, size: DwarfInterfaceFact<String> = absent(),
        target: DwarfInterfaceFact<String> = absent()) =
        DwarfInterfaceTypeNode(id, tag, absent(), size, absent(), target, emptyMap(), emptyList(), emptyList())
    private fun layout(elfClass: Int = 2, base: ULong = 0x100UL, machine: Int = 62, scanned: Long = 0,
        loaded: List<FullTreeElfMemorySegment> = listOf(segment(0, 0x100UL, 0x100UL)), tls: List<FullTreeElfMemorySegment> = emptyList()) =
        FullTreeElfObjectLayoutObservation(elfClass, 1, "ET_EXEC", machine, 0, 0, base, emptyList(), scanned, loaded, tls)
    private fun segment(index: Int, address: ULong, size: ULong, alignment: ULong? = 8UL) =
        FullTreeElfMemorySegment(index, 6, 0UL, address, size, size, address + size, address + size, 0UL, alignment)
    private fun <T> absent() = DwarfInterfaceFact<T>(DwarfInterfaceFactState.ABSENT)
    private fun known(value: String) = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value))
    private fun unknown(value: String) = DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, listOf(value))
    private fun GccDriverDwarfGlobalProjectionResult.bindings() = records.filter { it.text("kind") == "storage-binding" }
    private fun GccDriverDwarfGlobalProjectionResult.row(id: String) = records.single { it.text("id") == id }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.strings(key: String) = getValue(key).jsonArray.map { it.jsonPrimitive.content }
}

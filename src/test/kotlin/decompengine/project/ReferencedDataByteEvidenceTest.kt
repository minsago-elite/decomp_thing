package decompengine.project

import decompengine.oracle.structural.CanonicalProgramModelStreaming
import kotlinx.serialization.json.Json
import kotlin.test.*

class ReferencedDataByteEvidenceTest {
    private fun known(address: ULong = 0x100uL, length: Int = 8) = ReferencedDataByteWindow(address, length,
        ReferencedDataByteOrigin(0x10uL, address, 0, "pcode_load"), "available",
        listOf(ReferencedDataByteSegment(0, length, "available", "00".repeat(length), null)))
    private fun unknown() = ReferencedDataByteWindow(0x200uL, null,
        ReferencedDataByteOrigin(0x20uL, 0x200uL, null, "unknown_width"), "unknown", emptyList())
    private fun model(e: ReferencedDataByteEvidence) = RecoveredProgramModel(3, "a".repeat(64), emptyList(),
        listOf(RecoveredGlobal("g", "g", 0x100uL, "undefined", "00h", byteEvidence = e)))

    @Test fun `schema three round trips known mixed and unknown windows through both readers`() {
        for (e in listOf(ReferencedDataByteEvidence(windows = listOf(known())),
            ReferencedDataByteEvidence(windows = listOf(unknown()), omissionReason = "unknown_access_width"),
            ReferencedDataByteEvidence(windows = listOf(known(), unknown()), omissionReason = "unknown_access_width"))) {
            val m = model(e)
            assertEquals(m, ProgramModelJson.readCanonical(m.toJson().toByteArray()))
            assertEquals(m, CanonicalProgramModelStreaming.readCanonical(m.toJson().toByteArray()).model)
        }
    }
    @Test fun `closed omission and availability relations reject contradictions`() {
        for (e in listOf(ReferencedDataByteEvidence(windows = emptyList()),
            ReferencedDataByteEvidence(windows = listOf(unknown())),
            ReferencedDataByteEvidence(windows = listOf(known()), omissionReason = "unknown_access_width"),
            ReferencedDataByteEvidence(windows = listOf(known().copy(segments = emptyList()))),
            ReferencedDataByteEvidence(windows = listOf(known().copy(availability = "partial"))),
            ReferencedDataByteEvidence(windows = listOf(known().copy(address = ULong.MAX_VALUE))))) {
            assertFailsWith<IllegalArgumentException> { model(e) }
        }
    }
    @Test fun `wire parsing rejects noncanonical hex unknown keys and bad coverage`() {
        val json = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known())))
        for (bad in listOf(json.replace("0000000000000000", "AA00000000000000"),
            json.replace("\"offset\":0", "\"offset\":1"), json.replace("\"schemaVersion\":1", "\"extra\":1,\"schemaVersion\":1"))) {
            assertFailsWith<IllegalArgumentException> { parseReferencedDataByteEvidence(Json.parseToJsonElement(bad)) }
        }
    }
    @Test fun `aggregate budgets admit exact boundary and reject one extra window byte work`() {
        val e = ReferencedDataByteEvidence(windows = (0 until 32).map { known((0x100 + it * 256).toULong(), 256) })
        val budget = ReferencedDataByteEvidenceBudget()
        repeat(8) { budget.accept(e) }
        assertEquals(65536L, budget.requestedBytes)
        assertFailsWith<IllegalArgumentException> { budget.accept(ReferencedDataByteEvidence(windows = listOf(known(length = 1)))) }
    }
    @Test fun `window count and per-window limits admit exact bounds`() {
        val windows = (0 until 32).map { unknown().copy(address = it.toULong(), origin = unknown().origin.copy(referenceAddress = it.toULong())) }
        val evidence = ReferencedDataByteEvidence(windows = windows, omissionReason = "unknown_access_width")
        val budget = ReferencedDataByteEvidenceBudget()
        repeat(128) { budget.accept(evidence) }
        assertEquals(4096L, budget.windows)
        assertFailsWith<IllegalArgumentException> { budget.accept(ReferencedDataByteEvidence(windows = listOf(unknown()), omissionReason = "unknown_access_width")) }
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(evidence.copy(windows = windows + unknown())) }
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(ReferencedDataByteEvidence(windows = listOf(known(length = 257)))) }
    }
    @Test fun `partial unavailable coverage preserves bytes and closed reasons`() {
        val segments = listOf(ReferencedDataByteSegment(0, 2, "available", "0000", null),
            ReferencedDataByteSegment(2, 6, "unavailable", null, "uninitialized"))
        val e = ReferencedDataByteEvidence(windows = listOf(known().copy(availability = "partial", segments = segments)))
        assertEquals(e, parseReferencedDataByteEvidence(Json.parseToJsonElement(renderReferencedDataByteEvidence(e))))
        val invalid = e.windows.single().copy(segments = segments + ReferencedDataByteSegment(8, 1, "unavailable", null, "read_failed"))
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(e.copy(windows = listOf(invalid))) }
    }
    private fun rejectWire(evidenceJson: String) {
        val good = ReferencedDataByteEvidence(windows = listOf(known()))
        val text = model(good).toJson().replace(renderReferencedDataByteEvidence(good), evidenceJson)
        assertFails { ProgramModelJson.read(text) }
        assertFails { ProgramModelJson.readCanonical(text.toByteArray()) }
        assertFails { CanonicalProgramModelStreaming.readCanonical(text.toByteArray()) }
    }

    @Test fun `both readers reject every omission and unknown-width contradiction`() {
        val knownJson = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known())))
        val unknownJson = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(unknown()), omissionReason = "unknown_access_width"))
        val mixedJson = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known(), unknown()), omissionReason = "unknown_access_width"))
        val segment = "{\"offset\":0,\"length\":1,\"availability\":\"available\",\"hex\":\"00\",\"reason\":null}"
        for (bad in listOf(
            "{\"schemaVersion\":1,\"windows\":[],\"omissionReason\":null}",
            "{\"schemaVersion\":1,\"windows\":[],\"omissionReason\":\"unknown_access_width\"}",
            unknownJson.replace("\"omissionReason\":\"unknown_access_width\"", "\"omissionReason\":null"),
            mixedJson.replace("\"omissionReason\":\"unknown_access_width\"", "\"omissionReason\":null"),
            knownJson.replace("\"omissionReason\":null", "\"omissionReason\":\"unknown_access_width\""),
            unknownJson.replace("unknown_access_width", "arbitrary"),
            unknownJson.replace("\"segments\":[]", "\"segments\":[$segment]")
        )) rejectWire(bad)
    }

    @Test fun `both readers reject malformed scalars duplicate and extra nested keys`() {
        val good = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known())))
        val mutations = listOf(
            good.replace("0000000000000000", "AA00000000000000"),
            good.replace("0000000000000000", "000000000000000"),
            good.replace("\"requestedLength\":8", "\"requestedLength\":0"),
            good.replace("\"requestedLength\":8", "\"requestedLength\":-1"),
            good.replace("\"requestedLength\":8", "\"requestedLength\":1.5"),
            good.replace("\"requestedLength\":8", "\"requestedLength\":\"8\""),
            good.replace("0x100", "0x10000000000000000"),
            good.replace("0x100", "0xA00"),
            good.replace("0x100", "0x0100"),
            good.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
            good.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"extra\":1"),
            good.replace("\"length\":8", "\"length\":8,\"length\":8"),
            good.replace("\"operandIndex\":0", "\"operandIndex\":0,\"extra\":1")
        )
        mutations.forEach { assertNotEquals(good, it); rejectWire(it) }
    }

    @Test fun `both readers reject gaps overlaps and uncoalesced unavailable ranges`() {
        val available = ReferencedDataByteSegment(0, 2, "available", "0000", null)
        val missing = ReferencedDataByteSegment(2, 6, "unavailable", null, "unmapped")
        val good = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known().copy(availability = "partial", segments = listOf(available, missing)))))
        for (bad in listOf(
            good.replace("\"offset\":2", "\"offset\":3"),
            good.replace("\"offset\":2", "\"offset\":1"),
            good.replace("\"length\":6", "\"length\":5"),
            good.replace("\"availability\":\"partial\"", "\"availability\":\"available\""),
            good.replace("\"reason\":\"unmapped\"", "\"reason\":\"arbitrary\""),
            good.replace("{\"offset\":2,\"length\":6,\"availability\":\"unavailable\",\"hex\":null,\"reason\":\"unmapped\"}",
                "{\"offset\":2,\"length\":3,\"availability\":\"unavailable\",\"hex\":null,\"reason\":\"unmapped\"},{\"offset\":5,\"length\":3,\"availability\":\"unavailable\",\"hex\":null,\"reason\":\"unmapped\"}")
        )) { assertNotEquals(good, bad); rejectWire(bad) }
    }

    @Test fun `both readers enforce cumulative window bound across distinct globals`() {
        val windows = (0 until 32).map { unknown().copy(address = it.toULong(), origin = unknown().origin.copy(referenceAddress = it.toULong())) }
        val evidence = ReferencedDataByteEvidence(windows = windows, omissionReason = "unknown_access_width")
        val globals = (0 until 128).map { RecoveredGlobal("g" + it.toString().padStart(3, '0'), "g", it.toULong(), "undefined", byteEvidence = evidence) }
        val exact = RecoveredProgramModel(3, "a".repeat(64), emptyList(), globals).toJson()
        assertEquals(4096, ProgramModelJson.readCanonical(exact.toByteArray()).globals.sumOf { it.byteEvidence!!.windows.size })
        assertEquals(128, CanonicalProgramModelStreaming.readCanonical(exact.toByteArray()).model.globals.size)
        val extra = model(ReferencedDataByteEvidence(windows = listOf(unknown()), omissionReason = "unknown_access_width"))
            .copy(globals = listOf(RecoveredGlobal("zzz", "g", 999uL, "undefined", byteEvidence = ReferencedDataByteEvidence(windows = listOf(unknown()), omissionReason = "unknown_access_width")))).toJson()
            .substringAfter("\"globals\": [\n").substringBefore("\n  ],\n  \"types\"")
        val over = exact.replace("\n  ],\n  \"types\"", ",\n$extra\n  ],\n  \"types\"")
        assertNotEquals(exact, over)
        assertFails { ProgramModelJson.read(over) }
        assertFails { CanonicalProgramModelStreaming.readCanonical(over.toByteArray()) }
    }

    @Test fun `stream rejects excess window before parsing its payload`() {
        val windows = (0 until 32).map { unknown().copy(address = it.toULong(), origin = unknown().origin.copy(referenceAddress = it.toULong())) }
        val evidence = ReferencedDataByteEvidence(windows = windows, omissionReason = "unknown_access_width")
        val original = renderReferencedDataByteEvidence(evidence)
        val oversized = original.replace("],\"omissionReason\"", ",\"unparsed payload\"],\"omissionReason\"")
        val wire = model(evidence).toJson().replace(original, oversized)
        val failure = assertFails { CanonicalProgramModelStreaming.readCanonical(wire.toByteArray()) }
        assertContains(failure.message.orEmpty(), "array bound exceeded")
    }

    @Test fun `historical schemas forbid evidence and retain historical bytes`() {
        for (schema in 1..2) {
            val m = RecoveredProgramModel(schema, "a", emptyList(), listOf(RecoveredGlobal("g", "g", 1u, "int")))
            assertEquals(m.toJson(), ProgramModelJson.readCanonical(m.toJson().toByteArray()).toJson())
            assertFailsWith<IllegalArgumentException> { m.copy(globals = listOf(m.globals.single().copy(byteEvidence = ReferencedDataByteEvidence(windows = listOf(known()))))) }
        }
    }
    @Test fun `model four nullable and v2 evidence roundtrip through strict readers`() {
        val variants = listOf(null, ReferencedDataByteEvidence(2, listOf(known())),
            ReferencedDataByteEvidence(2, emptyList(), collectionOmissions = listOf("reference_work_limit")),
            ReferencedDataByteEvidence(2, listOf(unknown()), "unknown_access_width", listOf("model_window_limit")))
        for (e in variants) {
            val m = RecoveredProgramModel(4, "a".repeat(64), emptyList(),
                listOf(RecoveredGlobal("g", "g", 0x100uL, "undefined", "00h", byteEvidence = e)))
            val wire = m.toJson()
            assertContains(wire, "\"byteEvidence\":")
            assertEquals(m, ProgramModelJson.read(wire))
            assertEquals(m, ProgramModelJson.readCanonical(wire.toByteArray()))
            assertEquals(m, CanonicalProgramModelStreaming.readCanonical(wire.toByteArray()).model)
            assertEquals(wire, CanonicalProgramModelStreaming.readCanonical(wire.toByteArray()).model.toJson())
        }
        val noGlobals = RecoveredProgramModel(4, "a".repeat(64), emptyList(), emptyList())
        assertEquals(noGlobals, ProgramModelJson.readCanonical(noGlobals.toJson().toByteArray()))
    }

    @Test fun `v2 omission relations are closed and origin metadata cannot split one identity`() {
        val complete = ReferencedDataByteEvidence(2, listOf(known()))
        for (reasons in listOf(listOf("other"), listOf("reference_work_limit", "reference_work_limit"),
            listOf("model_window_limit", "reference_work_limit"), listOf("reference_work_limit", "global_window_limit"),
            listOf("global_window_limit"), listOf("global_window_limit", "model_window_limit", "reference_work_limit"))) {
            assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(complete.copy(collectionOmissions = reasons)) }
        }
        val full = complete.copy(windows = (0 until 32).map { known((0x100 + it * 8).toULong()) },
            collectionOmissions = listOf("global_window_limit", "model_requested_byte_limit"))
        assertEquals(full, parseReferencedDataByteEvidence(Json.parseToJsonElement(renderReferencedDataByteEvidence(full))))
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(complete.copy(windows = emptyList())) }
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(complete.copy(windows = listOf(known(), known().copy(origin = known().origin.copy(widthBasis = "pcode_direct_read"))))) }
    }

    @Test fun `model generations cannot mix and model four requires a nullable key`() {
        val m = RecoveredProgramModel(4, "a".repeat(64), emptyList(), listOf(RecoveredGlobal("g", "g", 1uL, "int")))
        val nullWire = m.toJson()
        val v1 = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(windows = listOf(known())))
        val v2 = renderReferencedDataByteEvidence(ReferencedDataByteEvidence(2, listOf(known())))
        val malformed = listOf(nullWire.replace("\"byteEvidence\": null,", ""),
            nullWire.replace("\"byteEvidence\": null", "\"byteEvidence\": \"null\""),
            nullWire.replace("\"byteEvidence\": null", "\"byteEvidence\": $v1"),
            nullWire.replace("\"schemaVersion\": 4", "\"schemaVersion\": 3"),
            nullWire.replace("\"byteEvidence\": null", "\"byteEvidence\": $v2").replace("\"schemaVersion\": 4", "\"schemaVersion\": 3"))
        for (wire in malformed) {
            assertNotEquals(nullWire, wire)
            assertFails { ProgramModelJson.read(wire) }
            assertFails { ProgramModelJson.readCanonical(wire.toByteArray()) }
            assertFails { CanonicalProgramModelStreaming.readCanonical(wire.toByteArray()) }
        }
    }
    @Test fun `actual model four population stays unassessed under exact population schema`() {
        val model = RecoveredProgramModel(4, "a".repeat(64), emptyList(),
            listOf(RecoveredGlobal("g", "g", 1uL, "int")))
        val population = model.unassessedRecoveryAssessment()
        val definition = java.nio.file.Files.readString(java.nio.file.Path.of("oracle/unassessed-recovery-population.schema.json"))
        val schema = io.github.optimumcode.json.schema.JsonSchema.fromDefinition(definition)
        assertTrue(schema.validate(population) {})
        assertEquals(kotlinx.serialization.json.JsonPrimitive(4), population.getValue("modelSchemaVersion"))
        assertEquals(kotlinx.serialization.json.JsonArray(emptyList()), population.getValue("assessedEntityIds"))
        assertEquals(kotlinx.serialization.json.JsonPrimitive("unassessed"), population.getValue("state"))
    }
    @Test fun `typed oversized evidence refuses before accessing any lazy window`() {
        var accesses = 0
        val windows = object : AbstractList<ReferencedDataByteWindow>() {
            override val size: Int get() = 33
            override fun get(index: Int): ReferencedDataByteWindow {
                accesses++
                error("oversized list element must not be accessed")
            }
            override fun iterator(): Iterator<ReferencedDataByteWindow> {
                accesses++
                error("oversized list must not be iterated")
            }
        }
        for (version in listOf(1, 2)) {
            val value = ReferencedDataByteEvidence(version, windows)
            val failure = assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.validate(value) }
            assertContains(failure.message.orEmpty(), "global window bound")
            assertEquals(0, accesses)
        }
    }

}

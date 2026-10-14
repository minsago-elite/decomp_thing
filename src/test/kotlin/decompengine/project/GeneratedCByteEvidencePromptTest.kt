package decompengine.project

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class GeneratedCByteEvidencePromptTest {
    @Test
    fun `raw bytes and unavailable ranges remain distinct from listing initializer`() {
        val bytes = ReferencedDataByteEvidence(windows = listOf(
            ReferencedDataByteWindow(0x2008UL, 8,
                ReferencedDataByteOrigin(0x1000UL, 0x2008UL, 1, "pcode_load"), "partial", listOf(
                    ReferencedDataByteSegment(0, 6, "available", "000000000000", null),
                    ReferencedDataByteSegment(6, 2, "unavailable", null, "uninitialized"))),
            ReferencedDataByteWindow(0x2010UL, null,
                ReferencedDataByteOrigin(0x1010UL, 0x2010UL, null, "unknown_width"), "unknown", emptyList())),
            omissionReason = "unknown_access_width")
        val global = RecoveredGlobal("g", "value", 0x2008UL, "undefined", initializer = "00h", byteEvidence = bytes)
        val model = RecoveredProgramModel(schemaVersion = 3, inputSha256 = "fixture", functions = emptyList(), globals = listOf(global))
        val before = model.toJson()
        val prompt = GeneratedCModulePrompt.render(request(model)).evidence
        assertContains(prompt, "initializer=00h")
        assertContains(prompt, ReferencedDataByteEvidenceJson.render(bytes))
        assertContains(prompt, "non-authoritative; no object extent, type or initializer semantics")
        assertEquals(before, model.toJson())
    }

    @Test
    fun `historical models explicitly lack recovered windows`() {
        for (schema in listOf(1, 2)) {
            val model = RecoveredProgramModel(schemaVersion = schema, inputSha256 = "fixture", functions = emptyList(),
                globals = listOf(RecoveredGlobal("g", "value", 0x2008UL, "undefined", initializer = "00h")))
            assertContains(GeneratedCModulePrompt.render(request(model)).evidence,
                "recovered input windows: <unavailable in historical model>")
        }
    }

    @Test
    fun `exact decoded byte budget preserves every available byte`() {
        val globals = (0 until 8).map { g ->
            val windows = (0 until 32).map { w ->
                val address = (0x2000 + (g * 32 + w) * 256).toULong()
                ReferencedDataByteWindow(address, 256,
                    ReferencedDataByteOrigin(address, address, 0, "pcode_load"), "available",
                    listOf(ReferencedDataByteSegment(0, 256, "available", "00".repeat(256), null)))
            }
            RecoveredGlobal("g$g", "value$g", g.toULong(), "undefined",
                byteEvidence = ReferencedDataByteEvidence(windows = windows))
        }
        val model = RecoveredProgramModel(schemaVersion = 3, inputSha256 = "fixture", functions = emptyList(), globals = globals)
        val prompt = GeneratedCModulePrompt.render(request(model)).evidence
        globals.forEach { assertContains(prompt, ReferencedDataByteEvidenceJson.render(it.byteEvidence!!)) }
    }

    @Test
    fun `rendered evidence limit is checked before producing module prompt`() {
        // Individually valid globals, all unknown width, can exceed the text budget without byte allocation.
        val globals = (0 until 128).map { index ->
            val windows = (0 until 32).map { w ->
                val address = (0x2000 + index * 32 + w).toULong()
                ReferencedDataByteWindow(address, null,
                    ReferencedDataByteOrigin(address, address, null, "unknown_width"), "unknown", emptyList())
            }
            RecoveredGlobal("g$index", "value$index", index.toULong(), "undefined",
                byteEvidence = ReferencedDataByteEvidence(windows = windows, omissionReason = "unknown_access_width"))
        }
        val model = RecoveredProgramModel(schemaVersion = 3, inputSha256 = "fixture", functions = emptyList(), globals = globals)
        val error = assertFailsWith<IllegalArgumentException> { GeneratedCModulePrompt.render(request(model)) }
        assertContains(error.message.orEmpty(), "rendered-text prompt bound")
    }

    private fun request(model: RecoveredProgramModel) = ModuleReconstructionRequest(
        PlannedModule("m", "src/m.c", "include/m.h", emptyList(), model.globals.map { it.id }, boundaryEvidence = emptyList()),
        model, "", "", "", emptyMap(), Path.of("build"))
}

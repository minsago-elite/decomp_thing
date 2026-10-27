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

    @Test
    fun `exact rendered length admits boundary and rejects one byte less without global allocation`() {
        val segments = (0 until 256).map { index ->
            if (index % 2 == 0) ReferencedDataByteSegment(index, 1, "available", "00", null)
            else ReferencedDataByteSegment(index, 1, "unavailable", null, "uninitialized")
        }
        val value = ReferencedDataByteEvidence(windows = (0 until 32).map { index ->
            val address = (0x1000 + index * 256).toULong()
            ReferencedDataByteWindow(address, 256, ReferencedDataByteOrigin(address, address, 0, "pcode_direct_read"), "partial", segments)
        })
        val exact = ReferencedDataByteEvidenceJson.render(value).toByteArray(Charsets.UTF_8).size.toLong()
        assertEquals(exact, ReferencedDataByteEvidenceJson.renderedLength(value, exact))
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.renderedLength(value, exact - 1) }
        val model = RecoveredProgramModel(3, "fixture", emptyList(), listOf(RecoveredGlobal("g", "value", 0x1000UL, "undefined", byteEvidence = value)))
        assertContains(assertFailsWith<IllegalArgumentException> { GeneratedCModulePrompt.render(request(model)) }.message.orEmpty(), "rendered-text prompt bound")
    }

    private fun request(model: RecoveredProgramModel) = ModuleReconstructionRequest(
        PlannedModule("m", "src/modules/m.c", "include/modules/m.h", emptyList(), model.globals.map { it.id }, boundaryEvidence = emptyList()),
        model, "", "", "", emptyMap(), Path.of("build"))
    @Test fun `current null and cutoff have distinct completeness labels and commitments`() {
        val base = RecoveredProgramModel(4, "fixture", emptyList(),
            listOf(RecoveredGlobal("g", "value", 0x2008UL, "undefined", "00h")))
        val unsupplied = GeneratedCModulePrompt.render(request(base)).evidence
        assertContains(unsupplied, "not supplied; completeness unknown")
        val reasonA = ReferencedDataByteEvidence(2, emptyList(), collectionOmissions = listOf("model_window_limit"))
        val reasonB = reasonA.copy(collectionOmissions = listOf("reference_work_limit"))
        val models = listOf(reasonA, reasonB).map { base.copy(globals = listOf(base.globals.single().copy(byteEvidence = it))) }
        val prompts = models.map { GeneratedCModulePrompt.render(request(it)).evidence }
        models.zip(prompts).forEach { (m, prompt) ->
            assertContains(prompt, ReferencedDataByteEvidenceJson.render(m.globals.single().byteEvidence!!))
            assertContains(prompt, "further referenced data may be absent because collection stopped")
            assertContains(prompt, "initializer=00h")
        }
        kotlin.test.assertNotEquals(prompts[0], prompts[1])
        val fingerprints = models.map { SourceTreeGenerator.moduleFingerprint(request(it).module, it, "", "", "", emptyMap(), null, request(it).profile.sha256, "authored-policy") }
        kotlin.test.assertNotEquals(fingerprints[0], fingerprints[1])
        val exact = ReferencedDataByteEvidenceJson.render(reasonA).length.toLong()
        assertEquals(exact, ReferencedDataByteEvidenceJson.renderedLength(reasonA, exact))
        assertFailsWith<IllegalArgumentException> { ReferencedDataByteEvidenceJson.renderedLength(reasonA, exact - 1) }
    }

}

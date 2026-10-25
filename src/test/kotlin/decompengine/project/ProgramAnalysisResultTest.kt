package decompengine.project

import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertSame

class ProgramAnalysisResultTest {
    @Test
    fun `capture retains exact canonical bytes and historical schema identity`() {
        for (version in 1..4) {
            val model = model(version, "input-sha")
            val bytes = model.toJson().toByteArray()
            val analysis = ProgramAnalysisResult(bytes)

            assertContentEquals(bytes, analysis.canonicalModelBytes)
            assertEquals(model, analysis.model)
            assertEquals("input-sha", analysis.inputSha256)
            assertEquals(sha256(bytes), analysis.modelSha256)
            assertEquals(bytes.size.toLong(), analysis.modelBytes)
            assertEquals(version, analysis.modelSchemaVersion)
            assertEquals(RecoveryStatus.PARTIAL, analysis.model.functions.single().status)
        }
    }

    @Test
    fun `capture rejects alternate canonical encoding and malformed input`() {
        val bytes = model().toJson().toByteArray()
        for (invalid in listOf(bytes + byteArrayOf(32), bytes.dropLast(1).toByteArray(), byteArrayOf(),
            "{\"schemaVersion\":5}".toByteArray(), bytes + byteArrayOf(0xc0.toByte()))) {
            assertFails { ProgramAnalysisResult(invalid) }
        }
    }

    @Test
    fun `different valid canonical model bytes have different capture identities`() {
        val original = model()
        val changed = original.copy(functions = original.functions.map { it.copy(name = "changed_name") })
        val before = ProgramAnalysisResult.fromModel(original)
        val after = ProgramAnalysisResult.fromModel(changed)

        assertNotEquals(before.modelSha256, after.modelSha256)
        assertEquals(original, before.model)
        assertEquals(changed, after.model)
    }

    @Test
    fun `input bytes and returned bytes cannot mutate a retained capture`() {
        val bytes = model().toJson().toByteArray()
        val expected = bytes.copyOf()
        val analysis = ProgramAnalysisResult(bytes)
        bytes.fill(0)
        analysis.canonicalModelBytes.fill(1)

        assertContentEquals(expected, analysis.canonicalModelBytes)
        assertEquals(sha256(expected), analysis.modelSha256)
        assertEquals(model(), analysis.model)
    }

    @Test
    fun `model and nested collections cannot mutate a retained capture`() {
        val calls = mutableSetOf("callee")
        val strings = mutableSetOf("private-string")
        val segments = mutableListOf(ReferencedDataByteSegment(0, 1, "available", "ab", null))
        val windows = mutableListOf(ReferencedDataByteWindow(2u, 1,
            ReferencedDataByteOrigin(1u, 2u, 0, "pcode_load"), "available", segments))
        val functions = mutableListOf(model().functions.single().copy(calls = calls,
            referencedGlobals = mutableSetOf("global"), strings = strings))
        val globals = mutableListOf(RecoveredGlobal("global", "private_global", 2u, "char",
            byteEvidence = ReferencedDataByteEvidence(2, windows)))
        val types = mutableListOf(RecoveredType("type", "typedef char private_type;"))
        val original = RecoveredProgramModel(4, "a".repeat(64), functions, globals, types)
        val expected = original.toJson().toByteArray()
        val analysis = ProgramAnalysisResult.fromModel(original)

        calls.clear(); strings.clear(); segments.clear(); windows.clear()
        functions.clear(); globals.clear(); types.clear()
        attemptMutation { (analysis.model.functions as MutableList<*>).clear() }
        attemptMutation { (analysis.model.functions.single().calls as MutableSet<*>).clear() }
        attemptMutation { (analysis.model.functions.single().referencedGlobals as MutableSet<*>).clear() }
        attemptMutation { (analysis.model.functions.single().strings as MutableSet<*>).clear() }
        attemptMutation { (analysis.model.globals as MutableList<*>).clear() }
        attemptMutation { (analysis.model.types as MutableList<*>).clear() }
        attemptMutation { (analysis.model.globals.single().byteEvidence!!.windows as MutableList<*>).clear() }
        attemptMutation {
            (analysis.model.globals.single().byteEvidence!!.windows.single().segments as MutableList<*>).clear()
        }

        assertContentEquals(expected, analysis.canonicalModelBytes)
        assertEquals(expected.toString(Charsets.UTF_8), analysis.model.toJson())
        assertEquals(sha256(expected), analysis.modelSha256)
    }

    @Test
    fun `capture and from-model propagate cancellation without returning partial snapshots`() {
        val model = model()
        val bytes = model.toJson().toByteArray()
        val cancelled = CancellationException("controlled capture cancellation")
        assertSame(cancelled, assertFailsWith<CancellationException> {
            ProgramAnalysisResult(bytes, checkpoint = { throw cancelled })
        })
        assertSame(cancelled, assertFailsWith<CancellationException> {
            ProgramAnalysisResult.fromModel(model, checkpoint = { throw cancelled })
        })
        assertContentEquals(bytes, ProgramAnalysisResult.fromModel(model).canonicalModelBytes)
    }

    private fun model(version: Int = 4, inputSha256: String = "a".repeat(64)) = RecoveredProgramModel(
        schemaVersion = version,
        inputSha256 = inputSha256,
        functions = listOf(RecoveredFunction("function", "private_function", 1u, "int private_function(void)",
            status = RecoveryStatus.PARTIAL)),
    )

    private fun attemptMutation(change: () -> Unit) {
        try { change() } catch (_: UnsupportedOperationException) { } catch (_: ClassCastException) { }
    }
}

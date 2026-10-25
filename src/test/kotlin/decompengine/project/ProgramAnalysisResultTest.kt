package decompengine.project

import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

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

    @Test
    fun `bounded model encoding admits exact historical canonical sizes including byte evidence`() {
        for (version in 1..4) {
            val value = encodingModel(version)
            val expected = value.toJson().toByteArray(Charsets.UTF_8)
            assertContentEquals(expected, AnalysisCanonicalEncoding.encodeModel(value, expected.size))
            assertContentEquals(expected,
                ProgramAnalysisResult.fromModel(value, maximumBytes = expected.size).canonicalModelBytes)
            var serialized = false
            assertFailsWith<IllegalArgumentException> {
                AnalysisCanonicalEncoding.encodeModel(value, expected.size - 1) { stage ->
                    if (stage == "before bounded model serialization") serialized = true
                }
            }
            assertFalse(serialized, "schema $version exceeded its budget before legacy serialization")
            assertFailsWith<IllegalArgumentException> {
                ProgramAnalysisResult.fromModel(value, maximumBytes = expected.size - 1)
            }
        }
    }

    @Test
    fun `oversized model field fails before legacy serialization or further lazy reference traversal`() {
        val oversized = "\u0000".repeat(16 * 1024)
        var readReferences = 0
        val lazyStrings = object : AbstractSet<String>() {
            override val size = 2
            override fun iterator(): Iterator<String> = object : Iterator<String> {
                override fun hasNext(): Boolean = readReferences < 2
                override fun next(): String {
                    readReferences++
                    check(readReferences == 1) { "preflight walked beyond an already oversized reference" }
                    return oversized
                }
            }
        }
        val value = model().copy(functions = listOf(model().functions.single().copy(strings = lazyStrings)))
        var serialized = false
        assertFailsWith<IllegalArgumentException> {
            ProgramAnalysisResult.fromModel(value, maximumBytes = 1024, checkpoint = { stage ->
                if (stage == "before bounded model serialization") serialized = true
            })
        }
        assertEquals(1, readReferences)
        assertFalse(serialized)
    }

    @Test
    fun `bounded model encoding freezes caller collections before legacy serialization`() {
        val calls = mutableSetOf("callee")
        val strings = mutableSetOf("source")
        val references = mutableSetOf("global")
        val segments = mutableListOf(ReferencedDataByteSegment(0, 1, "available", "ab", null))
        val windows = mutableListOf(ReferencedDataByteWindow(2u, 1,
            ReferencedDataByteOrigin(1u, 2u, 0, "pcode_load"), "available", segments))
        val omissions = mutableListOf("reference_work_limit")
        val functions = mutableListOf(model().functions.single().copy(calls = calls,
            referencedGlobals = references, strings = strings))
        val globals = mutableListOf(RecoveredGlobal("global", "global", 2u, "char",
            byteEvidence = ReferencedDataByteEvidence(2, windows, collectionOmissions = omissions)))
        val types = mutableListOf(RecoveredType("type", "typedef char byte;"))
        val value = RecoveredProgramModel(4, "a".repeat(64), functions, globals, types)
        val expected = value.toJson().toByteArray(Charsets.UTF_8)
        var mutated = false
        val result = ProgramAnalysisResult.fromModel(value, maximumBytes = expected.size, checkpoint = { stage ->
            if (stage == "before bounded model serialization") {
                calls.clear(); strings.clear(); references.clear(); segments.clear(); windows.clear(); omissions.clear()
                functions.clear(); globals.clear(); types.clear()
                mutated = true
            }
        })
        assertTrue(mutated)
        assertContentEquals(expected, result.canonicalModelBytes)
    }

    @Test
    fun `bounded model preflight propagates cancellation before serialization`() {
        val cancelled = CancellationException("cancelled during bounded model preflight")
        var checkpoints = 0
        var serialized = false
        assertSame(cancelled, assertFailsWith<CancellationException> {
            AnalysisCanonicalEncoding.encodeModel(encodingModel(4)) { stage ->
                if (stage == "before bounded model serialization") serialized = true
                if (++checkpoints == 3) throw cancelled
            }
        })
        assertEquals(3, checkpoints)
        assertFalse(serialized)
    }

    @Test
    fun `bounded model capture rejects caller mutated historical byte evidence instead of normalizing it`() {
        val omissions = mutableListOf<String>()
        val window = ReferencedDataByteWindow(2u, 1,
            ReferencedDataByteOrigin(1u, 2u, 0, "pcode_load"), "available",
            listOf(ReferencedDataByteSegment(0, 1, "available", "ab", null)))
        val value = RecoveredProgramModel(3, "a".repeat(64), emptyList(),
            globals = listOf(RecoveredGlobal("global", "global", 2u, "char",
                byteEvidence = ReferencedDataByteEvidence(1, listOf(window), collectionOmissions = omissions))))
        omissions += "reference_work_limit"
        var serialized = false
        assertFailsWith<IllegalArgumentException> {
            ProgramAnalysisResult.fromModel(value, checkpoint = { stage ->
                if (stage == "before bounded model serialization") serialized = true
            })
        }
        assertFalse(serialized)
    }

    private fun encodingModel(version: Int): RecoveredProgramModel {
        val text = "quotes\" slash\\ newline\nreturn\rtab\tbackspace\bformfeed\u000c nul\u0000 한글 é 😀"
        fun evidence(generation: Int) = ReferencedDataByteEvidence(generation, listOf(
            ReferencedDataByteWindow(0x20u, null,
                ReferencedDataByteOrigin(0x12u, 0x20u, null, "unknown_width"), "unknown", emptyList()),
            ReferencedDataByteWindow(0x10u, 3,
                ReferencedDataByteOrigin(0x11u, 0x10u, 2, "pcode_load"), "partial", listOf(
                    ReferencedDataByteSegment(0, 1, "available", "ab", null),
                    ReferencedDataByteSegment(1, 2, "unavailable", null, "uninitialized"),
                )),
        ), omissionReason = "unknown_access_width",
            collectionOmissions = if (generation == 2) listOf("reference_work_limit") else emptyList())
        return RecoveredProgramModel(version, "historical-$text", functions = listOf(
            RecoveredFunction("last", text, ULong.MAX_VALUE, text, decompiledC = text,
                calls = linkedSetOf(text, "first"), referencedGlobals = linkedSetOf("second", text),
                strings = linkedSetOf("", text), status = RecoveryStatus.PARTIAL),
            RecoveredFunction("first", "", 0u, "", decompiledC = null, status = RecoveryStatus.SYNTHETIC),
        ), globals = listOf(
            RecoveredGlobal("second", text, ULong.MAX_VALUE, text, initializer = text,
                status = RecoveryStatus.FAILED, byteEvidence = if (version >= 3) evidence(version - 2) else null),
            RecoveredGlobal("first", "", 0u, "", status = RecoveryStatus.RECOVERED,
                byteEvidence = if (version == 3) evidence(1) else null),
        ), types = listOf(RecoveredType("second", text, ULong.MAX_VALUE, RecoveryStatus.PARTIAL),
            RecoveredType("first", "", status = RecoveryStatus.FAILED)))
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

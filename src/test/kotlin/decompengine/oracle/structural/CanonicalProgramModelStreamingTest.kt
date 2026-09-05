package decompengine.oracle.structural

import decompengine.project.ProgramModelJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveryStatus
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CanonicalProgramModelStreamingTest {
    @Test
    fun `schema two keeps completed extraction and unknown types unassessed with reader parity`() {
        val historical = ProgramModelJson.readCanonical(resourceBytes())
        val model = historical.copy(schemaVersion = 2,
            globals = historical.globals.map { it.copy(type = "undefined8", status = RecoveryStatus.RECOVERED) })
        val bytes = model.toJson().toByteArray(StandardCharsets.UTF_8)
        val snapshot = CanonicalProgramModelStreaming.readCanonical(bytes)
        assertEquals(model, snapshot.model)
        assertEquals(model, ProgramModelJson.readCanonical(bytes))
        assertContentEquals(bytes, snapshot.model.toJson().toByteArray(StandardCharsets.UTF_8))
        val text = bytes.toString(StandardCharsets.UTF_8)
        assertTrue("\"status\":" !in text)
        assertEquals(model.functions.size + model.globals.size + model.types.size,
            Regex("\"recoveryAssessment\": \"unassessed\"").findAll(text).count())
        for (claim in listOf("recovered", "exact", "abi-equivalent", "contradicted")) {
            val changed = text.replaceFirst("\"recoveryAssessment\": \"unassessed\"",
                "\"recoveryAssessment\": \"$claim\"").toByteArray(StandardCharsets.UTF_8)
            kotlin.test.assertFails { ProgramModelJson.readCanonical(changed) }
            kotlin.test.assertFails { CanonicalProgramModelStreaming.readCanonical(changed) }
        }
        assertContentEquals(resourceBytes(), model.copy(schemaVersion = 1, globals = historical.globals)
            .toJson().toByteArray(StandardCharsets.UTF_8))
    }

    @Test
    fun `frozen exporter wire parses with exact typed and byte parity`() {
        val bytes = resourceBytes()
        val snapshot = CanonicalProgramModelStreaming.readCanonical(bytes)
        val legacy = ProgramModelJson.readCanonical(bytes)

        assertEquals(legacy, snapshot.model)
        assertContentEquals(bytes, snapshot.model.toJson().toByteArray(StandardCharsets.UTF_8))
        assertEquals(FROZEN_MODEL_SHA256, snapshot.sha256)
        assertEquals(bytes.size, snapshot.sizeBytes)
        assertEquals(2, snapshot.model.functions.size)
        assertEquals(setOf("external_printf", "fn_0000000000002000"), snapshot.model.functions.first().calls)
        assertEquals("int alpha_λ(void) {\n\treturn 1;\n}", snapshot.model.functions.first().decompiledC)
        assertEquals(1, snapshot.model.globals.size)
        assertEquals(1, snapshot.model.types.size)
    }

    @Test
    fun `input depth node string and collection bounds reject`() {
        val bytes = resourceBytes()
        listOf(
            CanonicalProgramModelStreamingLimits(maximumInputBytes = bytes.size - 1),
            CanonicalProgramModelStreamingLimits(maximumDepth = 3),
            CanonicalProgramModelStreamingLimits(maximumNodes = 10),
            CanonicalProgramModelStreamingLimits(maximumTokens = 10),
            CanonicalProgramModelStreamingLimits(maximumFunctions = 1),
            CanonicalProgramModelStreamingLimits(maximumGlobals = 0),
            CanonicalProgramModelStreamingLimits(maximumTypes = 0),
            CanonicalProgramModelStreamingLimits(maximumReferencesPerFunction = 1),
            CanonicalProgramModelStreamingLimits(maximumIdentifierCodePoints = 8),
            CanonicalProgramModelStreamingLimits(maximumPrototypeCodePoints = 8),
            CanonicalProgramModelStreamingLimits(maximumTextCodePoints = 8),
            CanonicalProgramModelStreamingLimits(maximumTotalStringBytes = 64),
        ).forEach { limits ->
            assertFailsWith<StructuralRecoveryV1Exception> {
                CanonicalProgramModelStreaming.readCanonical(bytes, limits)
            }
        }
    }

    @Test
    fun `empty input and UTF-8 BOM reject before model parsing`() {
        assertFailsWith<StructuralRecoveryV1Exception> {
            CanonicalProgramModelStreaming.readCanonical(byteArrayOf())
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            CanonicalProgramModelStreaming.readCanonical(
                byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + resourceBytes(),
            )
        }
    }

    @Test
    fun `duplicate fields malformed UTF-8 numbers and surrogates reject`() {
        val text = resourceBytes().toString(StandardCharsets.UTF_8)
        val duplicate = text.replaceFirst(
            "  \"schemaVersion\": 1,",
            "  \"schemaVersion\": 1,\n  \"schemaVersion\": 1,",
        ).toByteArray(StandardCharsets.UTF_8)
        val unknownField = text.replaceFirst(
            "  \"functions\": [",
            "  \"unknown\": null,\n  \"functions\": [",
        ).toByteArray(StandardCharsets.UTF_8)
        val malformedNumber = text.replaceFirst("\"schemaVersion\": 1", "\"schemaVersion\": 01")
            .toByteArray(StandardCharsets.UTF_8)
        val unpairedSurrogate = text.replaceFirst("\"beta\"", "\"\\ud800\"")
            .toByteArray(StandardCharsets.UTF_8)
        val malformedUtf8 = resourceBytes().also { bytes ->
            val marker = byteArrayOf(0xce.toByte(), 0xbb.toByte())
            val index = bytes.indexOf(marker)
            check(index >= 0)
            bytes[index + 1] = 0x20
        }

        listOf(duplicate, unknownField, malformedNumber, unpairedSurrogate, malformedUtf8).forEach { bytes ->
            assertFailsWith<StructuralRecoveryV1Exception> {
                CanonicalProgramModelStreaming.readCanonical(bytes)
            }
        }
    }

    @Test
    fun `semantic equivalents in noncanonical wire forms reject`() {
        val bytes = resourceBytes()
        val text = bytes.toString(StandardCharsets.UTF_8)
        val alternatives = listOf(
            bytes + '\n'.code.toByte(),
            text.replaceFirst("λ", "\\u03bb").toByteArray(StandardCharsets.UTF_8),
            text.replaceFirst("  \"schemaVersion\": 1,\n  \"inputSha256\":", "  \"inputSha256\":")
                .replaceFirst(
                    "  \"functions\": [",
                    "  \"schemaVersion\": 1,\n  \"functions\": [",
                ).toByteArray(StandardCharsets.UTF_8),
            text.replaceFirst(
                "[\"external_printf\", \"fn_0000000000002000\"]",
                "[\"fn_0000000000002000\", \"external_printf\"]",
            ).toByteArray(StandardCharsets.UTF_8),
            text.replaceFirst("\"0x1000\"", "\"0x00001000\"").toByteArray(StandardCharsets.UTF_8),
            text.replaceFirst("\"status\": \"recovered\"", "\"status\" : \"recovered\"")
                .toByteArray(StandardCharsets.UTF_8),
        )
        alternatives.forEach { alternative ->
            val failure = assertFailsWith<StructuralRecoveryV1Exception> {
                CanonicalProgramModelStreaming.readCanonical(alternative)
            }
            assertTrue(failure.message.orEmpty().isNotBlank())
        }
    }

    @Test
    fun `canonical extremes escaping scalar ordering and immutable snapshot round trip`() {
        val model = RecoveredProgramModel(
            inputSha256 = "0".repeat(64),
            functions = listOf(
                RecoveredFunction(
                    id = "edge-zero",
                    name = "quote\" slash\\ nul\u0000 cr\r astral-\ud83d\ude00",
                    address = 0UL,
                    prototype = "void edge_zero(void)",
                    calls = linkedSetOf("\ud800\udc00", "\ue000"),
                    status = RecoveryStatus.SYNTHETIC,
                ),
                RecoveredFunction(
                    id = "edge-max",
                    name = "edge_max",
                    address = ULong.MAX_VALUE,
                    prototype = "void edge_max(void)",
                ),
            ),
        )
        val bytes = model.toJson().toByteArray(StandardCharsets.UTF_8)
        val snapshot = CanonicalProgramModelStreaming.readCanonical(bytes)

        assertEquals(model, snapshot.model)
        assertContentEquals(bytes, snapshot.model.toJson().toByteArray(StandardCharsets.UTF_8))
        assertEquals(listOf("\ud800\udc00", "\ue000"), snapshot.model.functions.first().calls.toList())
        assertFailsWith<UnsupportedOperationException> {
            (snapshot.model.functions as MutableList<RecoveredFunction>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (snapshot.model.functions.first().calls as MutableSet<String>).clear()
        }
    }

    @Test
    fun `fixed digest bound is independent of configurable entity string bounds`() {
        val model = RecoveredProgramModel(
            inputSha256 = "0".repeat(64),
            functions = listOf(
                RecoveredFunction(
                    id = "a",
                    name = "b",
                    address = 0UL,
                    prototype = "",
                ),
            ),
        )
        val snapshot = CanonicalProgramModelStreaming.readCanonical(
            model.toJson().toByteArray(StandardCharsets.UTF_8),
            CanonicalProgramModelStreamingLimits(
                maximumIdentifierCodePoints = 1,
                maximumPrototypeCodePoints = 1,
                maximumTextCodePoints = 1,
            ),
        )

        assertEquals(model, snapshot.model)
    }

    private fun resourceBytes(): ByteArray = checkNotNull(
        javaClass.getResourceAsStream("/oracle/canonical-program-model-v1/complete-model.json"),
    ) { "canonical program-model fixture is missing" }.use { it.readAllBytes() }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        if (needle.isEmpty()) return 0
        if (needle.size > size) return -1
        for (index in 0..size - needle.size) {
            if (needle.indices.all { this[index + it] == needle[it] }) return index
        }
        return -1
    }

    private companion object {
        const val FROZEN_MODEL_SHA256 = "bff3c74034c33b1be6b55d8bfd452a6c152b0a2ac1e9f29625c4bbc8c0134952"
    }
}

package decompengine.oracle.structural

import decompengine.project.ProgramModelJson
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CanonicalProgramModelStreamingTest {
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

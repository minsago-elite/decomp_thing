package decompengine.project

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class ReferencedByteEvidenceAdmissionTest {
    private fun evidence(windows: String) = "{\"byteEvidence\":{\"schemaVersion\":1,\"windows\":[$windows],\"omissionReason\":null}}"
    private fun root(globals: String) = "{\"schemaVersion\":3,\"globals\":[$globals]}"
    private fun window(address: Int, length: Int?) = "{\"address\":\"0x${address.toString(16)}\",\"requestedLength\":$length,\"origin\":{\"instructionAddress\":\"0x${address.toString(16)}\",\"referenceAddress\":\"0x${address.toString(16)}\",\"operandIndex\":0,\"widthBasis\":\"${if (length == null) "unknown_width" else "pcode_load"}\"},\"availability\":\"${if (length == null) "unknown" else "available"}\",\"segments\":[${if (length == null) "" else "{\"offset\":0,\"length\":$length,\"availability\":\"available\",\"hex\":\"${"00".repeat(length)}\",\"reason\":null}"}]}"
    private val forbiddenPayload get() = "{\"hex\":\"" + "x".repeat(1_000_000) // deliberately no closing syntax
    private fun rejectsBeforePayload(text: String, reason: String) {
        for (read in listOf<() -> Unit>({ ProgramModelJson.read(text) }, { ProgramModelJson.readCanonical(text.toByteArray()) })) {
            val failure = assertFailsWith<IllegalArgumentException> { read() }
            assertContains(failure.message.orEmpty(), reason)
        }
    }
    @Test fun `lexical nesting is bounded before a malformed huge suffix`() {
        val accepted = "{\"unused\":" + "[".repeat(31) + "0" + "]".repeat(31) + "}"
        val admission = ReferencedByteEvidenceAdmission(byteInput = false)
        accepted.forEach { admission.accept(it.code) }
        rejectsBeforePayload("{\"unused\":" + "[".repeat(32) + "\"" + "x".repeat(1_000_000), "nesting bound")
    }
    @Test fun `window thirty three is refused before malformed huge payload`() {
        rejectsBeforePayload(root(evidence(List(32) { "{}" }.joinToString(",") + "," + forbiddenPayload)), "global window bound")
    }
    @Test fun `segment two hundred fifty seven is refused before its payload`() {
        rejectsBeforePayload(root(evidence("{\"segments\":[" + List(256) { "{}" }.joinToString(",") + "," + forbiddenPayload)), "segment bound")
    }
    @Test fun `aggregate window four thousand ninety seven is refused before its payload`() {
        val full = evidence(List(32) { window(it + 1, null) }.joinToString(",")).replace("\"omissionReason\":null", "\"omissionReason\":\"unknown_access_width\"")
        rejectsBeforePayload(root(List(128) { full }.joinToString(",") + "," + evidence(forbiddenPayload)), "model window bound")
    }
    @Test fun `aggregate requested byte sixty five thousand five hundred thirty seven is refused before segments`() {
        val full = evidence(List(32) { window((it + 1) * 256, 256) }.joinToString(","))
        val extra = "{\"byteEvidence\":{\"windows\":[{\"requestedLength\":1,\"segments\":[" + forbiddenPayload
        rejectsBeforePayload(root(List(8) { full }.joinToString(",") + "," + extra), "model requested-byte bound")
    }
    @Test fun `first oversized scalar and unknown field refuse without materializing their payload`() {
        rejectsBeforePayload(root(evidence("{\"segments\":[{\"hex\":\"" + "0".repeat(1000000))), "string bound")
        rejectsBeforePayload(root(evidence("{\"unknown\":\"" + "0".repeat(1000000))), "unexpected byte evidence field")
        rejectsBeforePayload(root(evidence("{\"segments\":[{\"offset\":" + "1".repeat(1000000))), "number bound")
    }
    @Test fun `historical text BOM retains compatibility without full UTF8 conversion`() {
        val model = RecoveredProgramModel(1, "fixture", emptyList(), emptyList())
        assertEquals(model, ProgramModelJson.read("\uFEFF" + model.toJson()))
    }
    @Test fun `canonical byte input BOM cannot bypass early window admission`() {
        val text = root(evidence(List(32) { "{}" }.joinToString(",") + "," + forbiddenPayload))
        val input = byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + text.toByteArray()
        assertContains(assertFailsWith<IllegalArgumentException> { ProgramModelJson.readCanonical(input) }.message.orEmpty(), "global window bound")
    }
    @Test fun `both generic readers admit exact aggregate window and requested byte boundaries`() {
        for (known in listOf(false, true)) {
            val count = if (known) 8 else 128
            val globals = (0 until count).map { g ->
                val windows = (0 until 32).map { w ->
                    val address = ((g * 32 + w + 1) * 256).toULong()
                    ReferencedDataByteWindow(address, if (known) 256 else null,
                        ReferencedDataByteOrigin(address, address, 0, if (known) "pcode_direct_read" else "unknown_width"),
                        if (known) "available" else "unknown",
                        if (known) listOf(ReferencedDataByteSegment(0, 256, "available", "00".repeat(256), null)) else emptyList())
                }
                RecoveredGlobal("g$g", "value$g", g.toULong(), "undefined", byteEvidence = ReferencedDataByteEvidence(
                    windows = windows, omissionReason = if (known) null else "unknown_access_width"))
            }
            val model = RecoveredProgramModel(3, "fixture", emptyList(), globals)
            val json = model.toJson()
            assertEquals(json, ProgramModelJson.read(json).toJson())
            assertEquals(json, ProgramModelJson.readCanonical(json.toByteArray()).toJson())
        }
    }

    @Test fun `collection omission third entry refuses before malformed suffix`() {
        rejectsBeforePayload("{\"globals\":[{\"byteEvidence\":{\"collectionOmissions\":[\"global_window_limit\",\"model_window_limit\",\"" + "x".repeat(1_000_000), "collection omission bound")
    }
    @Test fun `nullable boundary refuses pseudo null and nonobject values early`() {
        for (payload in listOf("null" + "x".repeat(1_000_000), "\"" + "x".repeat(1_000_000), "[" + "x".repeat(1_000_000))) {
            val failure = assertFailsWith<IllegalArgumentException> {
                val a = ReferencedByteEvidenceAdmission(false)
                ("{\"globals\":[{\"byteEvidence\":" + payload).forEach { a.accept(it.code) }
            }
            assertContains(failure.message.orEmpty(), "byte evidence")
        }
    }
    @Test fun `decoded duplicates reject before their malformed large values`() {
        for (duplicate in listOf("hex", "he\\u0078")) {
            rejectsBeforePayload("{\"globals\":[{\"byteEvidence\":{\"windows\":[{\"segments\":[{\"hex\":\"00\",\"$duplicate\":\"" + "x".repeat(1_000_000), "duplicate byte evidence field")
        }
        for (duplicate in listOf("byteEvidence", "byteEvidenc\\u0065")) {
            rejectsBeforePayload("{\"globals\":[{\"byteEvidence\":null,\"$duplicate\":\"" + "x".repeat(1_000_000), "duplicate byte evidence field")
        }
    }

}

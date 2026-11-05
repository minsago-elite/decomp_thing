package decompengine.builtin.provider

import decompengine.builtin.*
import kotlin.test.*

class ChatGptPlanSseV1Test {
    private fun wire(newline: String = "\n", text: String = "é中😀", bom: String = ""): ByteArray {
        val raw = C2Fixture.message(text)
        val frames = listOf(
            """{"type":"response.created","sequence_number":0,"response":${C2Fixture.envelope("in_progress")}}""",
            """{"type":"response.output_item.added","sequence_number":2,"output_index":0,"item":${C2Fixture.message("", status = "in_progress")}}""",
            """{"type":"response.output_item.done","sequence_number":4,"output_index":0,"item":$raw}""",
            """{"type":"response.completed","sequence_number":7,"response":${C2Fixture.envelope("completed", listOf(raw))}}"""
        )
        return (bom + ": fixture heartbeat" + newline + newline + frames.joinToString("") { "data: $it$newline$newline" }).toByteArray()
    }
    @Test fun `every UTF8 and CRLF fragmentation boundary preserves exact response`() {
        for (ending in listOf("\n", "\r", "\r\n")) {
            val bytes = wire(ending, bom = "\uFEFF")
            for (split in 1 until bytes.size) {
                val f = C2Fixture(); f.session.feed(bytes, 0, split)
                if (f.session.readDemand() > 0) f.session.feed(bytes, split, bytes.size - split)
                val r = f.session.terminalResult() as? ChatGptAttemptResultV1.Completed
                assertNotNull(r, "split=$split ending=${ending.length}"); assertEquals("é中😀", r.response.text)
            }
            val f = C2Fixture(); f.sendBytes(bytes, 1); assertEquals("é中😀", (f.session.terminalResult() as ChatGptAttemptResultV1.Completed).response.text)
        }
    }
    @Test fun `invalid UTF8 never uses replacement and truncated sequences fail EOF`() {
        for (bad in listOf(byteArrayOf(0xc0.toByte(), 0x80.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()), byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()), byteArrayOf(0x80.toByte()))) {
            val f = C2Fixture(); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.sendBytes(": ".toByteArray() + bad + "\n\n".toByteArray()) }
        }
        val f = C2Fixture(); f.sendBytes(byteArrayOf(0xf0.toByte(), 0x9f.toByte())); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.session.endOfInput() }
    }
    @Test fun `strict fields comments multiline data event names and BOM`() {
        val f = C2Fixture(); val json = f.event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}")
        val comma = json.indexOf(',')
        f.sendBytes(("event: response.created\r\ndata: ${json.substring(0, comma + 1)}\r\ndata: ${json.substring(comma + 1)}\r\n: bounded comment\r\n\r\n").toByteArray(), 1)
        assertNull(f.session.terminalResult())
        for (prefix in listOf("id: x\n", "retry: 3\n", "unknown: x\n", "event: response.created\nevent: response.created\n", "event: wrong\n", "\uFEFF\uFEFF")) {
            C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().sendBytes((prefix + "data: $json\n\n").toByteArray()) }
        }
        for (raw in listOf("data:\n\n", "data: [DONE]\n\n", "data: {}\n\n", "event: response.created\n\n", ": a\u0000b\n\n", "data\n\n")) {
            C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().sendBytes(raw.toByteArray()) }
        }
    }
    @Test fun `EOF partial no separator and postterminal feeds cannot produce success`() {
        for (bytes in listOf(wire().dropLast(1).toByteArray(), "data: {}".toByteArray(), ": heartbeat\n\n".toByteArray(), byteArrayOf())) {
            val f = C2Fixture(); f.sendBytes(bytes); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.session.endOfInput() }; assertNull(f.session.terminalResult())
        }
        val f = C2Fixture(); val r = f.complete(); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.session.feed("\n".toByteArray()) }; assertNull(f.session.terminalResult()); assertEquals(AttemptOutcomeV2.COMPLETED, r.outcome)
        val g = C2Fixture(); g.sendBytes(wire() + "unread garbage".toByteArray()); assertNotNull(g.session.terminalResult()) // no claim about suffix validation
    }
    @Test fun `frame limit exact 4096 heartbeat blocks and one over`() {
        val f = C2Fixture(); repeat(4096) { f.sendBytes("\n".toByteArray()) }
        assertEquals(4096, f.session.observed().wireBytes)
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.sendBytes("\n".toByteArray()) }; assertEquals(4097, f.session.observed().wireBytes)
    }
    @Test fun `line and frame ceilings checked before buffering with exact boundary`() {
        val f = C2Fixture(V2Fixture(local = LocalBudgetV1(eventBytes = 128)))
        f.sendBytes((":" + "a".repeat(125) + "\n\n").toByteArray())
        assertEquals(128, f.session.observed().wireBytes)
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { C2Fixture(V2Fixture(local = LocalBudgetV1(eventBytes = 128))).sendBytes((":" + "a".repeat(126) + "\n\n").toByteArray()) }
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { C2Fixture(V2Fixture(local = LocalBudgetV1(eventBytes = 128))).sendBytes((":" + "a".repeat(128)).toByteArray()) }
    }
    @Test fun `response exact boundary capped demand and remaining plus one probe`() {
        val f = C2Fixture(V2Fixture(local = LocalBudgetV1(responseBytes = 1024, eventBytes = 128)))
        assertEquals(1025, f.session.readDemand())
        repeat(8) { f.sendBytes((":" + "x".repeat(125) + "\n\n").toByteArray()) }
        assertEquals(1024, f.session.observed().wireBytes); assertEquals(1, f.session.readDemand())
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.session.feed(byteArrayOf(10)) }
        assertEquals(1025, f.session.observed().wireBytes); assertEquals(1025, f.ledger.counters().wire)
        val g = C2Fixture(); assertEquals(8192, g.session.readDemand()); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { g.session.feed(ByteArray(8193)) }
    }
    @Test fun `strict duplicate decoded keys UTF16 canonical numbers and depth`() {
        val f = C2Fixture(); val base = f.event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}")
        for (bad in listOf(base.replace("\"sequence_number\":0", "\"sequence_number\":0,\"sequence_\\u006eumber\":1"),
            base.replace("\"sequence_number\":0", "\"sequence_number\":-0"), base.replace("\"sequence_number\":0", "\"sequence_number\":0e0"),
            base.replace("\"sequence_number\":0", "\"sequence_number\":01"), base.replace("fixture-model", "\\uD800"), base.replace("fixture-model", "\\uDC00"), base.replace("fixture-model", "\\u１２３４"))) {
            C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().send(bad) }
        }
        fun nested(n: Int) = base.replace("\"status\":\"in_progress\"", "\"status\":\"in_progress\",\"meta\":" + "[".repeat(n) + "0" + "]".repeat(n))
        C2Fixture().send(nested(30)); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().send(nested(31)) }
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().send(base + "{}") }
    }
    @Test fun `JSON token names numbers and retention controls before materialization`() {
        val f = C2Fixture(); val base = f.event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}")
        fun metadata(k: String, v: String) = base.replace("\"status\":\"in_progress\"", "\"status\":\"in_progress\",${C2Fixture.q(k)}:$v")
        C2Fixture().send(metadata("n".repeat(8192), "0")); C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { C2Fixture().send(metadata("n".repeat(8193), "0")) }
        C2Fixture().send(metadata("number", "1".repeat(32))); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().send(metadata("number", "1".repeat(33))) }
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { C2Fixture().send(metadata("many", "[" + List(100000) { "0" }.joinToString(",") + "]")) }
        val small = C2Fixture(V2Fixture(local = LocalBudgetV1(responseBytes = 1024, eventBytes = 1024)))
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { small.send(metadata("dense", "[" + List(100) { "0" }.joinToString(",") + "]")) }
    }
    @Test fun `CRLF separator last LF belongs to bounded frame`() {
        val f = C2Fixture(V2Fixture(local = LocalBudgetV1(eventBytes = 128)))
        f.sendBytes((":" + "a".repeat(123) + "\r\n\r\n").toByteArray(), 1)
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) {
            C2Fixture(V2Fixture(local = LocalBudgetV1(eventBytes = 128))).sendBytes((":" + "a".repeat(124) + "\r\n\r\n").toByteArray(), 1)
        }
    }

    @Test fun `JSON token count exact 100000 and one over independently of transport cap`() {
        fun parse(n: Int) {
            val b = LocalBudgetV1(responseBytes = 32L * 1024 * 1024, eventBytes = 2L * 1024 * 1024)
            val f = C2Fixture(V2Fixture(local = b, hostLocal = b, profileLocal = b))
            val bytes = ("[" + List(n) { "0" }.joinToString(",") + "]").toByteArray()
            ChatGptResponseWorkV1(f.call, f.secrets).parse(bytes)
        }
        parse(99999); C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { parse(100000) }
    }
    @Test fun `disconnect after visible delta never mints completed continuation`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
        f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"visible\""))
        assertEquals("visible", f.text()); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.session.endOfInput() }
        assertNull(f.session.terminalResult()); assertEquals(7, f.session.observed().decodedOutputBytes)
        val observation = f.ledger.markAmbiguous(f.lease); assertEquals(4096, observation.outputCharge); assertEquals(0, f.effects)
    }

    @Test fun `private scan overlap covers maximum C0 secret and scalar boundaries`() {
        val f = C2Fixture(reserve = 80000)
        val secret = "x".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES - 1) + "y"
        f.secrets.registerSynthetic(secret)
        val w = ChatGptResponseWorkV1(f.call, f.secrets)
        // Cross both the first 32768-unit window and an 8192-unit step.
        for (prefix in listOf("q".repeat(24575), "😀".repeat(12287) + "é")) {
            C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { w.scan(prefix + secret) }
        }
        w.scan("😀".repeat(20000))
    }

    @Test fun `revocation after external deadline callback aborts before buffering or publication`() {
        lateinit var f: C2Fixture
        var revoke = false
        val cancellation = decompengine.agent.AgentCancellation {
            if (revoke) { revoke = false; f.session.discard() }
            false
        }
        f = C2Fixture(V2Fixture(cancellation = cancellation), callback = { revoke = true })
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.complete("fixture-") }
        assertNull(f.session.terminalResult()); assertEquals(0, f.session.readDemand())
        assertEquals(8, f.session.observed().displayedBytes)
    }

    @Test fun `failure and explicit clear release owned buffers and unregister C0 guard`() {
        for (mode in 0..2) {
            val f = C2Fixture()
            f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(C2Fixture.message("fixture-"))
            when (mode) {
                0 -> f.session.discard()
                1 -> C2Fixture.failure { f.session.endOfInput() }
                else -> C2Fixture.failure { f.session.feed(byteArrayOf(0)) }
            }
            fun field(owner: Any, name: String): Any? = owner.javaClass.getDeclaredField(name).let { it.isAccessible = true; it.get(owner) }
            assertTrue(field(f.session, "dead") as Boolean)
            assertTrue((field(f.session, "items") as Collection<*>).isEmpty())
            assertTrue((field(f.session, "ids") as Collection<*>).isEmpty())
            assertTrue((field(f.session, "callIds") as Collection<*>).isEmpty())
            assertEquals("", field(f.session, "publicTail"))
            val framer = field(f.session, "framer")!!
            assertEquals(0, (field(framer, "line") as ByteArray).size)
            assertEquals(0, (field(framer, "data") as ByteArray).size)
            assertTrue((field(f.secrets, "guards") as Collection<*>).isEmpty())
            assertNull(f.session.terminalResult()); assertTrue(f.events.isEmpty())
        }
    }

}

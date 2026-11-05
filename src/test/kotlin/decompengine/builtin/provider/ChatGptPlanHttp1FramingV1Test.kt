package decompengine.builtin.provider

import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.time.Instant
import kotlin.test.*

internal class ChatGptPlanHttp1FramingV1Test {
    private class Fixture(text: String, cap: Long = 100000, endpoint: PlanHttpEndpointV1 = PlanHttpEndpointV1.RESPONSES,
        split: Int = 8192) {
        val arena = PlanHttpArenasV1()
        var observed = 0L; var framing = 0L; var reads = 0
        val raw = ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1))
        val parser = ChatGptPlanHttp1FramingV1(object : InputStream() {
            override fun read(): Int = error("unbounded scalar path")
            override fun read(b: ByteArray, off: Int, len: Int): Int { reads++; return raw.read(b, off, minOf(len, split)) }
        }, arena, endpoint, cap, {}, { observed += it }, { framing += it })
        fun all(): String {
            val b = StringBuilder()
            while (true) { val n = parser.read(8192); if (n == -1) break; b.append(String(arena.io, 0, n, Charsets.US_ASCII)) }
            return b.toString()
        }
    }
    private fun response(fields: String = "", body: String = "", status: String = "HTTP/1.1 200 OK") = "$status\r\n$fields\r\n$body"
    private fun bad(text: String, cap: Long = 100000) = assertFailsWith<PlanHttpBoundaryV1> { Fixture(text, cap).also { it.parser.headers(); it.all() } }

    @Test fun ordinaryLengthChunkedAndCloseDelimitedAllReadSplits() {
        for (split in 1..16) for ((headers, body) in listOf(
            "Content-Length: 5\r\n" to "helloEXTRA", "Transfer-Encoding: chunked\r\n" to "2; a=\"x\\\"y\"\r\nhe\r\n3\r\nllo\r\n0\r\nX-End: ok\r\n\r\n", "" to "hello")) {
            val f = Fixture(response(headers, body), split = split)
            val h = f.parser.headers()
            ChatGptHeaderMetadataV1.fromHeaders(h.fields, Instant.EPOCH)
            assertEquals(0, f.observed); assertEquals(body.length, f.raw.available())
            assertEquals("hello", f.all()); assertEquals(5, f.observed); assertTrue(f.parser.completeFraming())
            if (headers.startsWith("Content-Length")) assertEquals(5, f.raw.available())
            assertTrue(f.arena.maximumDemand <= 8192)
        }
    }
    @Test fun contentLengthZeroExactShortOverflowAndTerminalMismatch() {
        val zero = Fixture(response("Content-Length: 0\r\n", "left"))
        zero.parser.headers(); assertEquals(-1, zero.parser.read(1)); assertEquals(4, zero.raw.available())
        val f = Fixture(response("Content-Length: 2\r\n", "ab"))
        f.parser.headers(); f.parser.read(1); assertFalse(f.parser.terminalLengthMatches()); f.parser.read(1)
        assertTrue(f.parser.terminalLengthMatches()); assertEquals(-1, f.parser.read(1))
        bad(response("Content-Length: 2\r\n", "a"))
        bad(response("Content-Length: 11\r\n"), 10)
        for (v in listOf("-1", "+1", "1,1", "9223372036854775808", "", "1 0")) bad(response("Content-Length:$v\r\n"))
    }
    @Test fun metadataGrammarAndDuplicateSmugglingDenials() {
        for (h in listOf("A :v", " A:v", "A\t:v", "A:v\nB:x", "A:v\rB:x", "A:\u007f", "A:\u0080", "A:\u0000",
            "Content-Length:1\r\nContent-Length:1", "Content-Length:1\r\nTransfer-Encoding:chunked",
            "Transfer-Encoding:gzip", "Transfer-Encoding:chunked; x=y", "Transfer-Encoding:chunked,chunked",
            "Transfer-Encoding:chunked\r\nTransfer-Encoding:chunked", "Content-Encoding:gzip",
            "Content-Encoding:identity\r\nContent-Encoding:identity", "Upgrade:websocket", "Connection:keep-alive, upgrade",
            "Content-Type:text/event-stream\r\nContent-Type:text/event-stream", "Content-Type:application/json")) assertFailsWith<PlanHttpBoundaryV1> { Fixture(response("$h\r\n")).parser.headers() }
        for (s in listOf("HTTP/1.0 200 OK", "HTTP/1.1 100 Continue", "HTTP/1.1 101 Switching", "HTTP/1.1 600 No", "HTTP/1.1 20x OK", "HTTP/1.1 200", "HTTP/1.1 200\tOK")) bad(response(status = s))
        val f = Fixture(response("a:\t ok \t\r\nContent-Encoding:identity\r\nContent-Type:text/event-stream; charset=\"utf-8\"\r\n"))
        assertEquals("ok", f.parser.headers().fields[0].second)
    }
    @Test fun inclusiveStatusNameValueFieldCountAndSectionCaps() {
        Fixture(response(status = "HTTP/1.1 200 " + "a".repeat(1009))).parser.headers()
        bad(response(status = "HTTP/1.1 200 " + "a".repeat(1010)))
        Fixture(response("a".repeat(128) + ":v\r\n")).parser.headers()
        bad(response("a".repeat(129) + ":v\r\n"))
        Fixture(response("a:" + "v".repeat(4096) + "\r\n")).parser.headers()
        bad(response("a:" + "v".repeat(4097) + "\r\n"))
        Fixture(response("a:v\r\n".repeat(64))).parser.headers()
        bad(response("a:v\r\n".repeat(65)))
        // 4 fields x (name1 + colon1 + value4091 + CRLF2) + blank2 = 16382;
        // enlarge final by2 => 16384. B adds4 per field, so OWS makes its budget fit.
        val fields = ("a: " + "v".repeat(4090) + "\r\n").repeat(3) + "a: " + "v".repeat(4092) + "\r\n"
        val f = Fixture(response(fields)); f.parser.headers(); assertEquals(16384, f.arena.headerHighWater)
        bad(response(fields.replaceFirst("v\r\n", "vv\r\n")))
        assertTrue(f.arena.materializedAscii <= 16384); assertEquals(4, f.arena.fieldHighWater)
        println("C4A_ARENA fixed=${PlanHttpArenasV1.FIXED_BYTES} section=${f.arena.headerHighWater} fields=${f.arena.fieldHighWater} strings=${f.arena.materializedAscii}")
    }
    @Test fun maximalInitialAndTrailerSectionsFitCorrectedEnvelopeAtZeroEntity() {
        val full = ("a: " + "v".repeat(4090) + "\r\n").repeat(3) + "a: " + "v".repeat(4092) + "\r\n"
        // Include TE by shortening the final field by its exact wire length.
        val te = "Transfer-Encoding:chunked\r\n"
        val initial = te + full.dropLast(2 + te.length) + "\r\n"
        val f = Fixture(response(initial, "0\r\n$full\r\n"))
        f.parser.headers(); assertEquals("", f.all()); assertEquals(0, f.observed)
        assertTrue(f.framing > 17408); assertTrue(f.framing <= ChatGptPlanHttp1FramingV1.envelope(0))
        bad(response(initial, "0\r\n${full.replaceFirst("v\r\n", "vv\r\n")}\r\n"))
        assertFailsWith<ArithmeticException> { ChatGptPlanHttp1FramingV1.envelope(Long.MAX_VALUE) }
    }
    @Test fun chunkExtensionsNumericGuardsCrlfAndTrailerDenials() {
        val te = "Transfer-Encoding:chunked\r\n"
        val valid = listOf("0000000000000000000000000000001 ; a = b; q=\"x\\\\y\"", "1;" + "a".repeat(1020))
        for (line in valid) { val f = Fixture(response(te, "$line\r\nx\r\n0\r\n\r\n")); f.parser.headers(); assertEquals("x", f.all()) }
        for (body in listOf("1;" + "a".repeat(1021) + "\r\nx\r\n0\r\n\r\n", "8000000000000000\r\n", "-1\r\n", "\r\n", "1;=x\r\n", "1;a=\r\n", "1;a=\"unterminated\r\n", "1 \r\n", "1;a \r\n", "1\r\nx!!", "2\r\nx", "0\r\nContent-Length:0\r\n\r\n", "0\r\n A:v\r\n\r\n", "0\r\nA:v\r\n")) bad(response(te, body))
        val huge = Fixture(response(te, "7fffffffffffffff\r\nx"), 0)
        huge.parser.headers(); assertFailsWith<PlanHttpBoundaryV1> { huge.parser.read(8192) }
        assertEquals(1, huge.observed); assertEquals(1, huge.arena.maximumDemand)
    }
    @Test fun capPlusOneCountBeforeDenialNoDrainAndUnrequestedSuffixUncertified() {
        val f = Fixture(response(body = "abcdef"), 3)
        f.parser.headers(); assertFailsWith<PlanHttpBoundaryV1> { f.parser.read(8192) }
        assertEquals(4, f.observed); assertEquals(2, f.raw.available())
        val unknown = Fixture(response("Transfer-Encoding:chunked\r\n", "1\r\nxMALFORMED"))
        unknown.parser.headers(); assertEquals(1, unknown.parser.read(1))
        assertTrue(unknown.parser.terminalLengthMatches()); assertFalse(unknown.parser.completeFraming())
        assertFailsWith<PlanHttpBoundaryV1> { unknown.parser.read(1) }
    }
    @Test fun catalogRequiresMimeAndErrorRequiresCompleteFraming() {
        val good = Fixture(response("Content-Type:application/json\r\nContent-Length:2\r\n", "{}"), endpoint = PlanHttpEndpointV1.MODELS)
        good.parser.headers(); assertEquals("{}", good.all())
        assertFailsWith<PlanHttpBoundaryV1> { Fixture(response(), endpoint = PlanHttpEndpointV1.MODELS).parser.headers() }
        bad(response("Content-Length:4\r\n", "bad", "HTTP/1.1 503 Busy"))
        bad(response("Content-Length:32769\r\n", status = "HTTP/1.1 503 Busy"))
    }
    @Test fun maximumEntityDemandSizeOneChunkChainsAndPreMaterializationBounds() {
        val maximum = Fixture(response(body = "x".repeat(8192)), 8192)
        maximum.parser.headers(); assertEquals(8192, maximum.parser.read(8192)); assertEquals(-1, maximum.parser.read(8192))
        assertEquals(8192, maximum.arena.maximumDemand)
        val line = "1;" + "a".repeat(1020) + "\r\nx\r\n"
        val f = Fixture(response("Transfer-Encoding:chunked\r\n", line.repeat(100) + "0\r\n\r\n"))
        f.parser.headers(); assertEquals("x".repeat(100), f.all())
        assertEquals(100, f.observed); assertTrue(f.framing <= ChatGptPlanHttp1FramingV1.envelope(100))
        val rejected = Fixture(response("a:" + "x".repeat(4097) + "\r\n"))
        assertFailsWith<PlanHttpBoundaryV1> { rejected.parser.headers() }
        assertEquals(0, rejected.arena.materializedAscii); assertEquals(0, rejected.arena.fieldHighWater)
        for (trailer in listOf("a".repeat(129) + ":x\r\n", "a:" + "x".repeat(4097) + "\r\n", "a:x\r\n".repeat(65)))
            bad(response("Transfer-Encoding:chunked\r\n", "0\r\n$trailer\r\n"))
        println("C4A_DEMAND entity=${maximum.arena.maximumDemand} metadata=1 framing=${f.framing} entityBytes=${f.observed}")
    }
    @Test fun exactCatalogAndErrorCapsAndPlusOneAreDistinct() {
        for ((cap, status, endpoint, mime) in listOf(
            listOf(1048576, 200, PlanHttpEndpointV1.MODELS, "Content-Type:application/json\r\n"),
            listOf(32768, 503, PlanHttpEndpointV1.RESPONSES, ""))) {
            val n = cap as Int; val code = status as Int; val ep = endpoint as PlanHttpEndpointV1
            val raw = response(mime as String, "x".repeat(n), "HTTP/1.1 $code OK")
            val f = Fixture(raw, n.toLong(), ep); f.parser.headers(); assertEquals(n, f.all().length)
            val plus = Fixture(raw + "xSUFFIX", n.toLong(), ep); plus.parser.headers()
            assertFailsWith<PlanHttpBoundaryV1> { plus.all() }; assertEquals(n + 1L, plus.observed); assertEquals(6, plus.raw.available())
        }
    }

    @Test fun aggregateEnvelopeIsInclusiveAtEveryIndependentMaximum() {
        val full = ("a: " + "v".repeat(4090) + "\r\n").repeat(3) + "a: " + "v".repeat(4092) + "\r\n"
        val te = "Transfer-Encoding:chunked\r\n"
        val initial = te + full.dropLast(2 + te.length) + "\r\n"
        val positive = "1;" + "a".repeat(1020) + "\r\n"
        val zero = "0;" + "a".repeat(1020) + "\r\n"
        val status = "HTTP/1.1 200 " + "a".repeat(1009)
        val f = Fixture(response(initial, positive + "x\r\n" + zero + full + "\r\n", status))
        f.parser.headers(); assertEquals("x", f.all()); assertEquals(1, f.observed)
        assertEquals(ChatGptPlanHttp1FramingV1.envelope(1), f.framing)
        println("C4A_INCLUSIVE_ENVELOPE entity=1 framing=${f.framing}")
    }

}

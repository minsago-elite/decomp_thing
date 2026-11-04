package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException
import kotlin.test.*

class ChatGptAuthJsonTest {
    private fun parse(text: String) = ChatGptAuthJson.parse(text.toByteArray(), ChatGptStoreOperation.start())
    private fun fail(text: String) { assertFailsWith<ChatGptOidcFailure> { parse(text) } }

    @Test fun objectParserPreservesStrictStringsAndIntegersWithRedactedRendering() {
        val root = parse("""{"s":"synthetic-secret","n":42,"a":[{"k":"é😀"}]}""")
        assertEquals("synthetic-secret", root.required("s").string())
        assertEquals(42L, root.required("n").integer())
        assertEquals("é😀", root.required("a").elements().single().required("k").string())
        assertEquals("ChatGptAuthJson([redacted])", root.toString())
        assertEquals("ChatGptAuthJson([redacted])", root.required("s").toString())
    }
    @Test fun validBalancedDepth32AcceptsAndDepth33Rejects() {
        fun nested(count: Int) = "{\"a\":" + "[".repeat(count) + "0" + "]".repeat(count) + "}"
        parse(nested(31)); fail(nested(32))
        fun objects(count: Int) = "{\"a\":".repeat(count) + "0" + "}".repeat(count)
        parse(objects(32)); fail(objects(33))
    }
    @Test fun body256KiBAcceptsAndOneExtraByteRejects() {
        val base = "{\"s\":\"" + "x".repeat(ChatGptAuthJson.MAX_BYTES - 8) + "\"}"
        assertEquals(ChatGptAuthJson.MAX_BYTES, base.toByteArray().size)
        parse(base); fail(base + " ")
    }
    @Test fun strictUtf8RejectsAlternateEncodingBomMalformedSequencesAndSurrogateEscapes() {
        for (bytes in listOf(byteArrayOf(0xc0.toByte(), 0xaf.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            "{\"a\":1}".toByteArray(Charsets.UTF_16), byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + "{}".toByteArray())) {
            assertFailsWith<ChatGptOidcFailure> { ChatGptAuthJson.parse(bytes, ChatGptStoreOperation.start()) }
        }
        for (s in listOf("\\ud800", "\\udc00", "\\ud800x", "\\udc00\\ud800")) {
            fail("{\"v\":\"" + s + "\"}"); fail("{\"" + s + "\":0}")
        }
        assertEquals("😀", parse("{\"v\":\"\\ud83d\\ude00\"}").required("v").string())
    }
    @Test fun duplicateEscapedNamesAndNestedDuplicatesReject() {
        for (s in listOf("{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "{\"outer\":[{\"a\":null,\"a\":false}]}")) fail(s)
    }
    @Test fun nonObjectTrailingContentAndNonstandardJsonReject() {
        for (s in listOf("", "[]", "null", "42", "\"text\"", "{} {}", "{}x", "{\"x\":1,}", "{'x':1}", "{x:1}",
            "{/*x*/\"x\":1}", "{\"x\":NaN}", "{\"x\":01}", "{\"x\":+1}", "{\"x\":\"line\nbreak\"}")) fail(s)
    }
    @Test fun coercionNullAndNumericOverflowCannotImpersonateIntegerOrString() {
        for (value in listOf("null", "true", "false", "[]", "{}", "1.0", "1e0", "\"1\"", "9223372036854775808")) {
            val node = parse("{\"a\":" + value + "}").required("a")
            assertFailsWith<ChatGptOidcFailure> { node.integer() }
            if (value != "\"1\"") assertFailsWith<ChatGptOidcFailure> { node.string() }
        }
        assertEquals(Long.MAX_VALUE, parse("{\"a\":9223372036854775807}").required("a").integer())
        assertFailsWith<ChatGptOidcFailure> { parse("{}").required("absent") }
    }
    @Test fun parserUsesOriginalCancellationAndDeadlineThroughoutNestedWork() {
        val body = ("{\"a\":[" + (1..1000).joinToString(",") + "]}").toByteArray()
        var checks = 0
        assertFailsWith<CancellationException> {
            ChatGptAuthJson.parse(body, ChatGptStoreOperation.start(cancelled = { ++checks > 50 }))
        }
        assertTrue(checks > 50)
        var clock = 0L
        assertFailsWith<TimeoutException> { ChatGptAuthJson.parse(body,
            ChatGptStoreOperation.create(Duration.ofNanos(50), { false }, { clock++ })) }
        assertEquals(1000, ChatGptAuthJson.parse(body, ChatGptStoreOperation.start()).required("a").elements().size)
    }
}

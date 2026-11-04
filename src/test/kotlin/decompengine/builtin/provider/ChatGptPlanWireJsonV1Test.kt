package decompengine.builtin.provider

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ChatGptPlanWireJsonV1Test {
    @Test fun parsesStrictJsonUnicodeAndNestedUnknownMetadata() {
        val parsed = ChatGptPlanWireJsonV1.parse("""{"x":["😀",true,null,12.5e1,{"z":"\uD83D\uDE00"}]}""".toByteArray(), 4096)
        val root = parsed as ChatGptWireValueV1.Obj
        val values = (root.fields["x"] as ChatGptWireValueV1.Arr).values
        assertEquals(5, values.size)
        assertEquals("😀", (values[0] as ChatGptWireValueV1.Str).value)
        val nested = (values[4] as ChatGptWireValueV1.Obj).fields["z"] as ChatGptWireValueV1.Str
        assertEquals("😀", nested.value)
    }

    @Test fun rejectsDuplicateKeysAtEveryDepthAndMalformedUtf8() {
        listOf("""{"a":1,"a":2}""", """{"x":{"a":1,"a":2}}""", "[1,]").forEach { json ->
            assertThrows(ChatGptWireJsonException::class.java) { ChatGptPlanWireJsonV1.parse(json.toByteArray(), 100) }
        }
        assertThrows(ChatGptWireJsonException::class.java) {
            ChatGptPlanWireJsonV1.parse(byteArrayOf(0x22, 0xC3.toByte(), 0x28, 0x22), 10)
        }
    }

    @Test fun rejectsDepthOverLimitAndOneByteOverBound() {
        assertDoesNotThrow {
            ChatGptPlanWireJsonV1.parse(("[".repeat(32) + "0" + "]".repeat(32)).toByteArray(), 100)
        }
        assertThrows(ChatGptWireJsonException::class.java) {
            ChatGptPlanWireJsonV1.parse(("[".repeat(33) + "0" + "]".repeat(33)).toByteArray(), 100)
        }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptPlanWireJsonV1.parse("null ".toByteArray(), 4) }
    }

    @Test fun enforcesTokenNameAndNumberLexemeLimits() {
        val maximumName = "a".repeat(8192)
        assertDoesNotThrow { ChatGptPlanWireJsonV1.parse("{\"$maximumName\":0}".toByteArray(), 9000) }
        assertThrows(ChatGptWireJsonException::class.java) {
            ChatGptPlanWireJsonV1.parse("{\"${maximumName}a\":0}".toByteArray(), 9001)
        }
        assertDoesNotThrow { ChatGptPlanWireJsonV1.parse(("[" + "0,".repeat(99_998) + "0]").toByteArray(), 300_000) }
        assertThrows(ChatGptWireJsonException::class.java) {
            ChatGptPlanWireJsonV1.parse(("[" + "0,".repeat(99_999) + "0]").toByteArray(), 300_000)
        }
        assertDoesNotThrow { ChatGptPlanWireJsonV1.parse("1".repeat(32).toByteArray(), 100) }
        assertThrows(ChatGptWireJsonException::class.java) {
            ChatGptPlanWireJsonV1.parse("1".repeat(33).toByteArray(), 100)
        }
    }

    private fun parse(text: String) = ChatGptPlanWireJsonV1.parse(text.toByteArray(), 1 shl 20)

    @Test fun unicodeEscapesRequireAsciiHexInValuesKeysAndSurrogateComponents() {
        for (escape in listOf("\\u００３２", "\\u٠٠٣٢", "\\uD83D\\uＤＥ００")) {
            for (json in listOf("\"$escape\"", "{\"$escape\":0}", "{\"x\":[{\"y\":\"$escape\"}]}")) {
                assertThrows(ChatGptWireJsonException::class.java) { parse(json) }
            }
        }
        assertEquals("2aA😀", (parse("\"\\u0032\\u0061\\u0041\\ud83d\\uDE00\"") as ChatGptWireValueV1.Str).value)
    }

    @Test fun emptyAndNonemptyContainersHaveTheSameExactDepthLimit() {
        for (leaf in listOf("", "0", "{}", "[]")) {
            val containers = if (leaf in listOf("{}", "[]")) 31 else 32
            assertDoesNotThrow { parse("[".repeat(containers) + leaf + "]".repeat(containers)) }
            assertThrows(ChatGptWireJsonException::class.java) {
                parse("[".repeat(containers + 1) + leaf + "]".repeat(containers + 1))
            }
        }
        for (leaf in listOf("{}", "[]", "0")) {
            val wrappers = if (leaf == "0") 32 else 31
            assertDoesNotThrow { parse("{\"unknown\":".repeat(wrappers) + leaf + "}".repeat(wrappers)) }
            assertThrows(ChatGptWireJsonException::class.java) {
                parse("{\"unknown\":".repeat(wrappers + 1) + leaf + "}".repeat(wrappers + 1))
            }
        }
    }

    @Test fun decodedNameByteBoundHandlesLiteralAndEscapedUnicodeAtEveryEntryPoint() {
        for (name in listOf("a".repeat(8192), "é".repeat(4096), "😀".repeat(2048), "漢".repeat(2730) + "ab")) {
            val escaped = name.map { "\\u%04x".format(it.code) }.joinToString("")
            for (encoded in listOf(name, escaped)) {
                assertTrue((parse("{\"$encoded\":0}") as ChatGptWireValueV1.Obj).fields.containsKey(name))
                assertThrows(ChatGptWireJsonException::class.java) { parse("{\"${encoded}a\":0}") }
            }
            assertDoesNotThrow { ChatGptWireValueV1.Obj(mapOf(name to ChatGptWireValueV1.Null)) }
            assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Obj(mapOf(name + "a" to ChatGptWireValueV1.Null)) }
        }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Obj(mapOf("\uD800" to ChatGptWireValueV1.Null)) }
    }

    @Test fun wireCollectionsAreDeeplyImmutableAndDoNotAliasInputs() {
        val originalList = arrayListOf<ChatGptWireValueV1>(ChatGptWireValueV1.Str("😀"))
        val array = ChatGptWireValueV1.Arr(originalList)
        val originalMap = linkedMapOf<String, ChatGptWireValueV1>("a" to array)
        val obj = ChatGptWireValueV1.Obj(originalMap)
        originalList.clear(); originalMap.clear()
        assertEquals("😀", (((obj.fields["a"] as ChatGptWireValueV1.Arr).values.single()) as ChatGptWireValueV1.Str).value)
        for (root in listOf(obj, parse("{\"a\":[{\"b\":[]}]}") as ChatGptWireValueV1.Obj)) {
            assertThrows(UnsupportedOperationException::class.java) { (root.fields as MutableMap).clear() }
            assertThrows(UnsupportedOperationException::class.java) { (root.fields.entries.first() as MutableMap.MutableEntry).setValue(ChatGptWireValueV1.Null) }
            val nested = root.fields["a"] as ChatGptWireValueV1.Arr
            assertThrows(UnsupportedOperationException::class.java) { (nested.values as MutableList).clear() }
            assertThrows(UnsupportedOperationException::class.java) { (nested.values as MutableList)[0] = ChatGptWireValueV1.Null }
        }
        val nested = (((parse("{\"a\":[{\"b\":[]}]}") as ChatGptWireValueV1.Obj).fields["a"] as ChatGptWireValueV1.Arr).values[0] as ChatGptWireValueV1.Obj)
        assertThrows(UnsupportedOperationException::class.java) { (nested.fields as MutableMap).clear() }
        assertThrows(UnsupportedOperationException::class.java) { ((nested.fields["b"] as ChatGptWireValueV1.Arr).values as MutableList).add(ChatGptWireValueV1.Null) }
    }

    @Test fun directScalarsEnforceTheSameUnicodeAndNumberGrammarAsParsing() {
        for (text in listOf("not-json", "", "01", "+1", "1.", "1e", "１", "NaN", "1".repeat(33))) {
            assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Num(text) }
            assertThrows(ChatGptWireJsonException::class.java) { parse(text) }
        }
        for (text in listOf("0", "-0", "-12.3e+20", "1E-2", "1".repeat(32))) {
            assertEquals(text, ChatGptWireValueV1.Num(text).lexeme)
            assertEquals(text, (parse(text) as ChatGptWireValueV1.Num).lexeme)
        }
        for (text in listOf("\uD800", "\uDC00", "x\uD800z", "\uDC00\uD800")) {
            assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Str(text) }
        }
        for (text in listOf("", "😀é漢", "\u0000\n", "x".repeat((1 shl 20) - 2))) {
            assertEquals(text, ChatGptWireValueV1.Str(text).value)
        }
    }

    @Test fun directWireContainersEnforceCountBeforeReadingAndAggregateDepthAndTokens() {
        var reads = 0
        val tooMany = object : AbstractList<ChatGptWireValueV1>() {
            override val size = 100_000
            override fun get(index: Int): ChatGptWireValueV1 { reads++; return ChatGptWireValueV1.Null }
        }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Arr(tooMany) }
        assertEquals(0, reads)
        val tooManyFields = object : AbstractMap<String, ChatGptWireValueV1>() {
            override val size = 50_000
            override val entries: Set<Map.Entry<String, ChatGptWireValueV1>> get() { reads++; error("must not read entries") }
        }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Obj(tooManyFields) }
        assertEquals(0, reads)
        assertEquals(99_999, ChatGptWireValueV1.Arr(List(99_999) { ChatGptWireValueV1.Null }).values.size)
        val half = ChatGptWireValueV1.Arr(List(49_999) { ChatGptWireValueV1.Null })
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Arr(listOf(half, half)) }
        var value: ChatGptWireValueV1 = ChatGptWireValueV1.Null
        repeat(32) { value = if (it % 2 == 0) ChatGptWireValueV1.Arr(listOf(value)) else ChatGptWireValueV1.Obj(mapOf("x" to value)) }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Arr(listOf(value)) }
        assertThrows(ChatGptWireJsonException::class.java) { ChatGptWireValueV1.Obj(mapOf("x" to value)) }
    }
}

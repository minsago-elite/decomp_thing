package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class WebJsonUtf8Test {
    @Test
    fun `streamed JSON bytes match kotlinx serialization for nested values and UTF-8 edge cases`() {
        val value = buildJsonObject {
            put("quote\" slash\\", "quote\" slash\\ and controls\u0000\b\t\n\u000c\r")
            put("unicode", "한국어 café 😀")
            put("lone-surrogates", "high:\uD800 low:\uDC00")
            put("number", "1.250e+4".let { Json.parseToJsonElement(it) })
            put("values", buildJsonArray {
                add(Json.parseToJsonElement("true"))
                add(Json.parseToJsonElement("null"))
                add(buildJsonObject { put("nested", "value") })
            })
        }
        val expected = value.toString().toByteArray(Charsets.UTF_8)

        val actual = WebJsonUtf8.encode(value, 1_024)
        assertContentEquals(expected, actual)
        assertEquals(expected.size, WebJsonUtf8.encodedByteCount(value, expected.size))
    }

    @Test
    fun `encoding refuses the byte immediately beyond its exact ceiling`() {
        val value = buildJsonObject { put("text", "é😀") }
        val expectedBytes = value.toString().toByteArray(Charsets.UTF_8)

        assertFailsWith<WebJsonByteLimitException> { WebJsonUtf8.encode(value, expectedBytes.size - 1) }
        assertFailsWith<WebJsonByteLimitException> { WebJsonUtf8.encodedByteCount(value, expectedBytes.size - 1) }
    }

    @Test
    fun `empty containers and null fit a zero byte limit only when serialized size is zero`() {
        assertFailsWith<WebJsonByteLimitException> { WebJsonUtf8.encode(Json.parseToJsonElement("null"), 0) }
        assertEquals(2, WebJsonUtf8.encodedByteCount(Json.parseToJsonElement("[]"), 2))
        assertContentEquals("{}".toByteArray(), WebJsonUtf8.encode(Json.parseToJsonElement("{}"), 2))
    }
}

package decompengine.oracle.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class OracleJsonTest {
    @Test
    fun `canonical bytes match the Python oracle artifact format`() {
        val input = """{"𐀀":2,"":1,"z":"quote \" slash / backslash \\ tab \t lambda λ music 𝄞","a":[true,null,-0,1.0,0.0001,1e20,1e-5,1e2]}"""
        val expected = """
            {
              "a": [
                true,
                null,
                0,
                1.0,
                0.0001,
                1e+20,
                1e-05,
                100.0
              ],
              "z": "quote \" slash / backslash \\ tab \t lambda λ music 𝄞",
              "": 1,
              "𐀀": 2
            }
        """.trimIndent() + "\n"

        val canonical = OracleJson.parseAndCanonicalize(input.toByteArray())

        assertContentEquals(expected.toByteArray(), canonical)
        assertEquals('\n'.code.toByte(), canonical.last())
        assertEquals(OracleJson.parse(canonical), OracleJson.parseCanonical(canonical))
        assertFailsWith<StrictJsonException> { OracleJson.parseCanonical(input.toByteArray()) }
    }

    @Test
    fun `parser rejects duplicate decoded keys and malformed strings`() {
        assertRejected("""{"a":1,"a":2}""")
        assertRejected("""{"a":1,"\u0061":2}""")
        assertRejected("""["\uD800"]""")
        assertRejected("""["\uDC00"]""")
        assertRejected("""["\uD800\u0041"]""")
        assertRejected("""["\x00"]""")
        assertRejected("""["\u００６１"]""")
        assertRejected("""["\uＦＦＦＦ"]""")
        assertRejected("""["unterminated]""")
        assertFailsWith<StrictJsonException> {
            OracleJson.parse(byteArrayOf('"'.code.toByte(), 1, '"'.code.toByte()))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse(byteArrayOf(0xc3.toByte(), 0x28))
        }
    }

    @Test
    fun `parser accepts only strict finite JSON numbers`() {
        listOf(
            "+1",
            "01",
            "-01",
            "1.",
            ".1",
            "1e",
            "1e+",
            "NaN",
            "Infinity",
            "-Infinity",
            "1e9999",
        ).forEach(::assertRejected)

        assertEquals("0\n", OracleJson.parseAndCanonicalize("-0".toByteArray()).decodeToString())
        assertEquals("-0.0\n", OracleJson.parseAndCanonicalize("-0.0".toByteArray()).decodeToString())
        assertEquals("1e+20\n", OracleJson.parseAndCanonicalize("100000000000000000000.0".toByteArray()).decodeToString())
    }

    @Test
    fun `parser enforces every configured resource bound`() {
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("null".toByteArray(), StrictJsonLimits(maximumInputBytes = 3))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("[[]]".toByteArray(), StrictJsonLimits(maximumDepth = 1))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("[1,2]".toByteArray(), StrictJsonLimits(maximumNodes = 2))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("\"é\"".toByteArray(), StrictJsonLimits(maximumStringBytes = 1))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("[\"aa\",\"bb\"]".toByteArray(), StrictJsonLimits(maximumTotalStringBytes = 3))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parse("123".toByteArray(), StrictJsonLimits(maximumNumberCharacters = 2))
        }
        assertFailsWith<StrictJsonException> {
            OracleJson.parseAndCanonicalize("{}".toByteArray(), StrictJsonLimits(maximumCanonicalBytes = 2))
        }
    }

    @Test
    fun `encoder independently validates caller-created JSON trees`() {
        assertFailsWith<StrictJsonException> { OracleJson.canonicalBytes(JsonPrimitive(Double.NaN)) }
        assertFailsWith<StrictJsonException> { OracleJson.canonicalBytes(JsonPrimitive("\uD800")) }
        assertFailsWith<StrictJsonException> { OracleJson.canonicalBytes(JsonPrimitive(Double.MIN_VALUE)) }
        assertFailsWith<StrictJsonException> {
            OracleJson.canonicalBytes(
                JsonArray(listOf(JsonArray(emptyList()))),
                StrictJsonLimits(maximumDepth = 1),
            )
        }

        val sorted = OracleJson.canonicalBytes(
            JsonObject(linkedMapOf("𐀀" to JsonPrimitive(2), "" to JsonPrimitive(1))),
        ).decodeToString()
        assertTrue(sorted.indexOf("") < sorted.indexOf("𐀀"), sorted)
    }

    @Test
    fun `strict grammar rejects trailing data and non-JSON whitespace`() {
        assertRejected("true false")
        assertRejected("[1,]")
        assertRejected("{\"a\":1,}")
        assertRejected("null\u000b")
        assertRejected("")
    }

    private fun assertRejected(value: String) {
        assertFailsWith<StrictJsonException>(value) { OracleJson.parse(value.toByteArray()) }
    }
}

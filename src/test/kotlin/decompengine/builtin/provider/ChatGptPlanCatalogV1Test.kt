package decompengine.builtin.provider

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ChatGptPlanCatalogV1Test {
    private fun catalog(vararg rows: String) = """{"models":[${rows.joinToString(",")}] ,"ignored":{"anything":[true,3]}}""".toByteArray()
    private fun row(slug: String, visibility: String = "list", display: String = "Name", metadata: String = "") =
        """{"slug":"$slug","display_name":"$display","visibility":"$visibility"$metadata}"""

    @Test fun filtersInOriginalOrderAndRequiresExactSlugWithNoFallback() {
        val parsed = ChatGptCatalogV1.parse(catalog(row("second"), row("hidden", "private"), row("first")))
        assertEquals(listOf("second", "first"), parsed.models.map { it.slug })
        assertEquals("first", parsed.requireExactSlug("first").slug)
        val error = assertThrows(ModelProviderException::class.java) { parsed.requireExactSlug("First") }
        assertEquals(ModelFailureKind.MODEL_UNAVAILABLE, error.kind)
    }

    @Test fun rejectsDuplicateSlugEvenWhenOnlyOneRowIsVisibleAndRejectsBadHiddenRows() {
        assertMalformed(catalog(row("same", "private"), row("same")))
        assertMalformed(catalog(row("bad slug", "private")))
        assertMalformed(catalog("""{"slug":"hidden","display_name":"x","visibility":"private","extra":{"x":1,"x":2}}"""))
    }

    @Test fun validatesAllRequiredFieldsAndDisplayUnicodeControlAndByteBounds() {
        assertMalformed(catalog("""{"slug":"hidden","display_name":"x","visibility":false}"""))
        assertMalformed(catalog(row("visible", display = " ")))
        assertMalformed(catalog(row("visible", display = "ok\nno")))
        assertMalformed(catalog(row("visible", display = "😀".repeat(65))))
        assertEquals("😀".repeat(64), ChatGptCatalogV1.parse(catalog(row("valid", display = "😀".repeat(64)))).models.single().displayName)
    }

    @Test fun enforcesEntrySlugAndBodyBoundsAtAndOneOver() {
        assertEquals(1024, ChatGptCatalogV1.parse(catalog(*Array(1024) { row("m$it") })).models.size)
        val tooMany = catalog(*Array(1025) { row("m$it") })
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertThrows(ModelProviderException::class.java) { ChatGptCatalogV1.parse(tooMany) }.kind)
        assertEquals(200, ChatGptCatalogV1.parse(catalog(row("a".repeat(200)))).models.single().slug.length)
        assertMalformed(catalog(row("a".repeat(201))))
        val padding = "x".repeat(ChatGptCatalogV1.MAX_BODY_BYTES - "{\"models\":[],\"ignored\":\"\"}".toByteArray().size)
        val exact = "{\"models\":[],\"ignored\":\"$padding\"}".toByteArray()
        assertEquals(ChatGptCatalogV1.MAX_BODY_BYTES, exact.size)
        assertTrue(ChatGptCatalogV1.parse(exact).models.isEmpty())
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { ChatGptCatalogV1.parse(exact + byteArrayOf(' '.code.toByte())) }.kind)
    }

    @Test fun modelAndCatalogValuesAreImmutableAndRedacted() {
        val parsed = ChatGptCatalogV1.parse(catalog(row("private-sentinel", display = "display-sentinel")))
        assertThrows(UnsupportedOperationException::class.java) { (parsed.models as MutableList).clear() }
        assertFalse(parsed.toString().contains("private-sentinel"))
        assertFalse(parsed.models.single().toString().contains("display-sentinel"))
    }

    @Test fun rejectsMalformedRootAndInvalidUnicodeEscapes() {
        listOf("[]", "{}", """{"models":{}}""", """{"models":[null]}""", """{"models":[],"x":"\uD800"}""").forEach {
            assertMalformed(it.toByteArray())
        }
    }


    @Test fun constructorRejectsOversizedCountBeforeAnyElementReadAndCopiesValidInput() {
        var reads = 0
        val rows = object : AbstractList<CatalogModelV1>() {
            override val size = 1025
            override fun get(index: Int): CatalogModelV1 { reads++; return CatalogModelV1("m$index", "Name") }
        }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertThrows(ModelProviderException::class.java) { ChatGptCatalogV1(rows) }.kind)
        assertEquals(0, reads)
        val original = ArrayList(List(1024) { CatalogModelV1("m$it", "Name") })
        val catalog = ChatGptCatalogV1(original)
        original.clear()
        assertEquals(List(1024) { "m$it" }, catalog.models.map { it.slug })
        assertThrows(UnsupportedOperationException::class.java) { (catalog.models as MutableList).clear() }
        assertThrows(ModelProviderException::class.java) { ChatGptCatalogV1(listOf(CatalogModelV1("a", "A"), CatalogModelV1("a", "B"))) }
    }

    @Test fun constructorAndParserShareDisplayScalarAndUtf8BoundsIncludingHiddenRows() {
        for (display in listOf("a".repeat(256), "é".repeat(128), "😀".repeat(64), "漢".repeat(85) + "a")) {
            assertEquals(display, CatalogModelV1("valid", display).displayName)
            assertEquals(display, ChatGptCatalogV1.parse(catalog(row("valid", display = display))).models.single().displayName)
            assertThrows(ModelProviderException::class.java) { CatalogModelV1("valid", display + "a") }
            assertMalformed(catalog(row("valid", display = display + "a")))
            assertMalformed(catalog(row("hidden", "private", display + "a")))
        }
        for (bad in listOf("\uD800", "\uDC00", "x\uD800x")) {
            assertThrows(ModelProviderException::class.java) { CatalogModelV1("valid", bad) }
            val escaped = bad.map { "\\u%04x".format(it.code) }.joinToString("")
            assertMalformed(catalog(row("valid", display = escaped)))
        }
        assertThrows(ModelProviderException::class.java) { CatalogModelV1("valid", "x".repeat(1 shl 20)) }
        assertMalformed("""{"data":[]}""".toByteArray())
    }

    private fun assertMalformed(bytes: ByteArray) {
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE,
            assertThrows(ModelProviderException::class.java) { ChatGptCatalogV1.parse(bytes) }.kind)
    }
}

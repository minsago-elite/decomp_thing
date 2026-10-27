package decompengine.acp

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.lang.reflect.InvocationTargetException
import java.net.InetAddress
import org.apache.hc.core5.http.ClassicHttpResponse
import org.apache.hc.core5.http.ContentLengthStrategy
import org.apache.hc.core5.http.impl.io.DefaultBHttpClientConnection
import org.apache.hc.core5.http.impl.io.SessionInputBufferImpl
import org.apache.hc.core5.http.io.HttpMessageParser
import org.apache.hc.core5.http.io.SessionInputBuffer
import org.apache.hc.core5.util.CharArrayBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** These controls use the private production parser adapters without adding a network issuer. */
class AcpProviderHttpAttemptBoundaryTest {
    @Test
    fun `production parser accepts exact semantic header byte and field limits`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 32, maximumHeaderFields = 2)
        val response = parseResponse(bounds, "HTTP/1.1 200 OK\r\nX:  ${"a".repeat(16)} \r\nYY: ${"b".repeat(13)}\r\n\r\n")

        assertEquals(200, response.code)
        assertEquals(2, response.headers.size)
        assertEquals("a".repeat(16), response.getFirstHeader("X").value)
        assertEquals("b".repeat(13), response.getFirstHeader("YY").value)
    }

    @Test
    fun `production parser accepts the exact aggregate raw header character limit`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 32, maximumHeaderFields = 2)
        val first = "A:${" ".repeat(17)}"
        val second = "B:${" ".repeat(19)}"
        assertEquals(bounds.maximumHeaderBytes + 4 * bounds.maximumHeaderFields, first.length + second.length)
        val response = parseResponse(bounds, "HTTP/1.1 200 OK\r\n$first\r\n$second\r\n\r\n")

        assertEquals(2, response.headers.size)
        assertEquals("", response.getFirstHeader("A").value)
        assertEquals("", response.getFirstHeader("B").value)
    }

    @Test
    fun `excess raw header padding is refused before target copy across two or many fields`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 32, maximumHeaderFields = 2)
        val first = "A:${" ".repeat(17)}"
        val second = "B:${" ".repeat(20)}"
        assertEquals(bounds.maximumHeaderBytes + 4 * bounds.maximumHeaderFields + 1, first.length + second.length)
        val source = headerBuffer(bounds)
        val input = wire("HTTP/1.1 200 OK\r\n$first\r\n$second\r\n\r\n")
        readLine(source, input)
        assertEquals(first, readLine(source, input))
        assertEquals("provider raw header bound exceeded", refuseBeforeCopy(source, input).message)

        val manyBounds = AcpProviderTransportBounds(maximumHeaderBytes = 64, maximumHeaderFields = 4)
        val fields = listOf("A", "B", "C", "D").map { "$it:${" ".repeat(22)}a" }
        assertEquals(listOf(25, 25, 25, 25), fields.map(String::length))
        val manySource = headerBuffer(manyBounds)
        val manyInput = wire("HTTP/1.1 200 OK\r\n${fields.joinToString("\r\n")}\r\n\r\n")
        readLine(manySource, manyInput)
        fields.take(3).forEach { assertEquals(it, readLine(manySource, manyInput)) }
        assertEquals("provider raw header bound exceeded", refuseBeforeCopy(manySource, manyInput).message)
    }

    @Test
    fun `one excess semantic header byte is refused before parser target copy`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 32, maximumHeaderFields = 2)
        val source = headerBuffer(bounds)
        val input = wire("HTTP/1.1 200 OK\r\nX: ${"a".repeat(16)}\r\nYY: ${"b".repeat(14)}\r\n\r\n")
        readLine(source, input)
        readLine(source, input)

        val failure = refuseBeforeCopy(source, input)
        assertEquals("provider header bound exceeded", failure.message)
    }

    @Test
    fun `one excess header field is refused before parser target copy`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 64, maximumHeaderFields = 2)
        val source = headerBuffer(bounds)
        val input = wire("HTTP/1.1 200 OK\r\nA: a\r\nB: b\r\nC: c\r\n\r\n")
        readLine(source, input)
        assertEquals("A: a", readLine(source, input))
        assertEquals("B: b", readLine(source, input))

        val failure = refuseBeforeCopy(source, input)
        assertEquals("provider header bound exceeded", failure.message)
    }

    @Test
    fun `status limit accepts exactly 128 characters and refuses one more before copy`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 256)
        val exact = "HTTP/1.1 200 ${"a".repeat(115)}"
        assertEquals(128, exact.length)
        assertEquals(exact, readLine(headerBuffer(bounds), wire("$exact\r\n")))

        val input = wire("${exact}a\r\n${"unread".repeat(16)}")
        val failure = refuseBeforeCopy(headerBuffer(bounds), input)
        assertEquals("provider line framing refused", failure.message)
        assertTrue(input.available() >= 90, "the status bound must stop before consuming the following response")
    }

    @Test
    fun `folded malformed and control bearing lines are refused before parser target copy`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 256)
        listOf(" X: folded", "\tX: folded", "missing-colon", ": value", "X: a\tb", "X: a\u001fb", "X: a\u007fb").forEach { line ->
            val source = headerBuffer(bounds)
            val input = wire("HTTP/1.1 200 OK\r\n$line\r\n")
            readLine(source, input)
            refuseBeforeCopy(source, input)
        }
        listOf("HTTP/1.1 200 O\u001fK", "HTTP/1.1 200 O\u007fK").forEach { line ->
            val input = wire("$line\r\n${"unread".repeat(16)}")
            val failure = refuseBeforeCopy(headerBuffer(bounds), input)
            assertEquals("provider line framing refused", failure.message)
            assertTrue(input.available() >= 90, "a status control must stop before consuming the following response")
        }
        listOf("HTTP/1.1 2").forEach { line ->
            val failure = refuseBeforeCopy(headerBuffer(bounds), wire("$line\r\n"))
            assertEquals("provider status refused", failure.message)
        }
    }

    @Test
    fun `bounded line reader refuses an oversized header before target copy or full input consumption`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 32)
        val source = headerBuffer(bounds)
        val input = wire("HTTP/1.1 200 OK\r\nX: ${"a".repeat(4096)}\r\n")
        readLine(source, input)

        refuseBeforeCopy(source, input)
        assertTrue(input.available() > 4000, "the bounded reader must stop before consuming the oversized field")
    }

    @Test
    fun `production response parser refuses other versions informational and out of range status`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 64)
        listOf("HTTP/1.0 200 OK", "HTTP/1.1 100 Continue", "HTTP/1.1 199 Interim", "HTTP/1.1 600 Invalid").forEach { status ->
            val failure = assertFailsWith<IOException> { parseResponse(bounds, "$status\r\n\r\n") }
            assertEquals("provider response framing refused", failure.message)
        }
    }

    @Test
    fun `production response parser requires CRLF and a complete empty header terminator`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 128)
        listOf(
            "HTTP/1.1 200 OK\nX: a\n\n",
            "HTTP/1.1 200 OK\r\nX: a\n\r\n",
            "HTTP/1.1 200 OK\r\nX: a",
            "HTTP/1.1 200 OK\r\nX: a\r",
            "HTTP/1.1 200 OK\r\nX: a\r\n",
            "HTTP/1.1 200 OK\r\n",
            "HTTP/1.1 200 OK\rX: a\r\n\r\n",
        ).forEach { raw -> assertFailsWith<IOException> { parseResponse(bounds, raw) } }
    }

    @Test
    fun `production chunk decoder accepts exact aggregate metadata limit and refuses one more byte`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 15)
        // Size lines, the two body delimiters and the final empty trailer line total 15 bytes.
        assertEquals("ab", chunkStream(bounds, "1\r\na\r\n1\r\nb\r\n0\r\n\r\n").readBytes().toString(Charsets.US_ASCII))
        val failure = assertFailsWith<IOException> {
            chunkStream(bounds, "1;\r\na\r\n1\r\nb\r\n0\r\n\r\n").readBytes()
        }
        assertEquals("provider chunk metadata refused", failure.message)

        val source = chunkBuffer(bounds)
        val input = wire("1;\r\n\r\n1\r\n\r\n0\r\n\r\n")
        repeat(5) { readLine(source, input) }
        assertEquals("provider chunk metadata refused", refuseBeforeCopy(source, input).message)
    }

    @Test
    fun `production chunk decoder refuses trailers and oversized chunk lines`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 64)
        val trailer = assertFailsWith<IOException> { chunkStream(bounds, "0\r\nX: trailer\r\n\r\n").readBytes() }
        assertEquals("provider chunk metadata refused", trailer.message)

        val source = chunkBuffer(bounds)
        val input = wire("0\r\nX: trailer\r\n\r\n")
        assertEquals("0", readLine(source, input))
        assertEquals("provider chunk metadata refused", refuseBeforeCopy(source, input).message)
        assertFailsWith<IOException> { chunkStream(bounds, "1;${"a".repeat(4096)}\r\na\r\n0\r\n\r\n").readBytes() }
        listOf("z\r\n", "2\r\na", "1\r\na").forEach { raw ->
            assertFailsWith<IOException> { chunkStream(bounds, raw).readBytes() }
        }
    }

    @Test
    fun `production chunk decoder requires CRLF and the final empty trailer terminator`() {
        val bounds = AcpProviderTransportBounds(maximumHeaderBytes = 128)
        listOf(
            "1\na\n0\n\n",
            "1\r\na\n0\r\n\r\n",
            "1\r\na\r\n0\n\n",
            "1\r\na\r\n0\r\n",
            "1\r\na\r\n0\r\n\r",
            "0",
            "0\r\n",
        ).forEach { raw -> assertFailsWith<IOException> { chunkStream(bounds, raw).readBytes() } }
    }

    @Test
    fun `address selection preserves resolver first choice and refuses an empty result`() {
        val first = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1))
        val second = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
        assertSame(first, selectAddress(arrayOf(first, second)))
        assertSame(first, selectAddress(arrayOf(first, second)))
        assertSame(second, selectAddress(arrayOf(second, first)))
        assertSame(first, selectAddress(arrayOf(first)))
        assertEquals("provider address unavailable", assertFailsWith<IOException> { selectAddress(emptyArray()) }.message)
    }

    private fun wire(value: String): ByteArrayInputStream = ByteArrayInputStream(value.toByteArray(Charsets.ISO_8859_1))

    // A small real Core buffer makes every long input cross multiple physical reads.
    private fun coreBuffer(bounds: AcpProviderTransportBounds): SessionInputBuffer =
        SessionInputBufferImpl(7, bounds.maximumHeaderBytes + 5)

    private fun privateBuffer(name: String, bounds: AcpProviderTransportBounds): SessionInputBuffer =
        Class.forName("decompengine.acp.$name").getDeclaredConstructor(SessionInputBuffer::class.java, AcpProviderTransportBounds::class.java)
            .also { it.isAccessible = true }.newInstance(coreBuffer(bounds), bounds) as SessionInputBuffer

    private fun headerBuffer(bounds: AcpProviderTransportBounds): SessionInputBuffer = privateBuffer("ProviderHeaderBuffer", bounds)

    private fun chunkBuffer(bounds: AcpProviderTransportBounds): SessionInputBuffer = privateBuffer("ProviderChunkMetadataBuffer", bounds)

    private fun readLine(source: SessionInputBuffer, input: InputStream): String {
        val target = CharArrayBuffer(1)
        val count = source.readLine(target, input)
        assertEquals(target.length, count)
        return target.toString()
    }

    private fun refuseBeforeCopy(source: SessionInputBuffer, input: InputStream): IOException {
        val target = CharArrayBuffer(8).also { it.append("retained") }
        val capacity = target.capacity()
        val failure = assertFailsWith<IOException> { source.readLine(target, input) }
        assertNull(failure.cause)
        assertEquals("retained", target.toString())
        assertEquals(capacity, target.capacity())
        return failure
    }

    private fun connection(bounds: AcpProviderTransportBounds): DefaultBHttpClientConnection =
        Class.forName("decompengine.acp.ProviderHttpConnection").getDeclaredConstructor(AcpProviderTransportBounds::class.java)
            .also { it.isAccessible = true }.newInstance(bounds) as DefaultBHttpClientConnection

    private fun parseResponse(bounds: AcpProviderTransportBounds, value: String): ClassicHttpResponse {
        val connection = connection(bounds)
        @Suppress("UNCHECKED_CAST")
        val parser = DefaultBHttpClientConnection::class.java.getDeclaredField("responseParser")
            .also { it.isAccessible = true }.get(connection) as HttpMessageParser<ClassicHttpResponse>
        return parser.parse(coreBuffer(bounds), wire(value))
    }

    private fun chunkStream(bounds: AcpProviderTransportBounds, value: String): InputStream {
        val connection = connection(bounds)
        val method = connection.javaClass.getDeclaredMethod("createContentInputStream", Long::class.javaPrimitiveType,
            SessionInputBuffer::class.java, InputStream::class.java).also { it.isAccessible = true }
        return reflected { method.invoke(connection, ContentLengthStrategy.CHUNKED, coreBuffer(bounds), wire(value)) } as InputStream
    }

    private fun selectAddress(addresses: Array<InetAddress>): InetAddress {
        val method = Class.forName("decompengine.acp.AcpProviderBrokerKt").getDeclaredMethod("selectProviderAddress", Array<InetAddress>::class.java)
            .also { it.isAccessible = true }
        return reflected { method.invoke(null, addresses as Any) } as InetAddress
    }

    private inline fun reflected(action: () -> Any?): Any? = try {
        action()
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

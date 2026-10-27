package decompengine.acp

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.lang.reflect.InvocationTargetException
import org.apache.hc.core5.http.ContentLengthStrategy
import org.apache.hc.core5.http.impl.io.SessionInputBufferImpl
import org.apache.hc.core5.http.io.SessionInputBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Inert Core 5.4.4 framing through the production connection factory; no socket or worker. */
class AcpProviderNonDrainingBodyInputViewTest {
    @Test
    fun `partial length close neither reads nor closes transport`() {
        assertNonDrainingClose(8L, "a")
    }

    @Test
    fun `partial chunk and missing trailer close neither reads nor closes transport`() {
        assertNonDrainingClose(ContentLengthStrategy.CHUNKED, "8\r\na")
        assertNonDrainingClose(ContentLengthStrategy.CHUNKED, "1\r\na\r\n0\r\n")
    }

    @Test
    fun `normal length and chunk framing retain exact bytes and eof`() {
        listOf(3L to "abc", ContentLengthStrategy.CHUNKED to "3\r\nabc\r\n0\r\n\r\n").forEach { (length, wire) ->
            val input = ObservedInput(wire)
            val body = body(length, input)
            assertContentEquals("abc".toByteArray(), body.readBytes())
            assertEquals(-1, body.read())
            body.close()
            assertEquals(0, input.closes)
            assertClosed(body)
        }
    }

    @Test
    fun `open framing errors still propagate`() {
        assertFailsWith<IOException> { body(8L, ObservedInput("a")).readBytes() }
        assertFailsWith<IOException> { body(ContentLengthStrategy.CHUNKED, ObservedInput("1\r\na\n0\r\n\r\n")).readBytes() }
    }

    @Test
    fun `open bulk skip and available use framing`() {
        val body = body(4L, ObservedInput("abcd"))
        assertEquals(1L, body.skip(1))
        val bytes = ByteArray(2)
        assertEquals(2, body.read(bytes, 0, 2))
        assertContentEquals("bc".toByteArray(), bytes)
        assertEquals('d'.code, body.read())
        assertEquals(0, body.available())
        assertEquals(-1, body.read())
    }

    private fun assertNonDrainingClose(length: Long, wire: String) {
        val input = ObservedInput(wire)
        val body = body(length, input)
        assertEquals('a'.code, body.read())
        val reads = input.reads
        input.refuseReads = true
        body.close()
        body.close()
        assertClosed(body)
        assertEquals(reads, input.reads)
        assertEquals(0, input.closes)
    }

    private fun assertClosed(body: InputStream) {
        assertFailsWith<IOException> { body.read() }
        assertFailsWith<IOException> { body.read(ByteArray(1), 0, 1) }
        assertFailsWith<IOException> { body.skip(1) }
        assertFailsWith<IOException> { body.available() }
    }

    private fun body(length: Long, input: InputStream): InputStream {
        val bounds = AcpProviderTransportBounds()
        val type = Class.forName("decompengine.acp.ProviderHttpConnection")
        val connection = type.getDeclaredConstructor(AcpProviderTransportBounds::class.java)
            .also { it.isAccessible = true }.newInstance(bounds)
        val method = type.getDeclaredMethod("createContentInputStream", Long::class.javaPrimitiveType,
            SessionInputBuffer::class.java, InputStream::class.java).also { it.isAccessible = true }
        return try {
            method.invoke(connection, length, SessionInputBufferImpl(7, bounds.maximumHeaderBytes + 5), input) as InputStream
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private class ObservedInput(wire: String) : InputStream() {
        private val source = ByteArrayInputStream(wire.toByteArray(Charsets.ISO_8859_1))
        var reads = 0
        var closes = 0
        var refuseReads = false
        override fun read(): Int {
            reads++
            if (refuseReads) throw AssertionError("late input read")
            return source.read()
        }
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            reads++
            if (refuseReads) throw AssertionError("late input read")
            return source.read(bytes, offset, length)
        }
        override fun close() { closes++ }
    }
}

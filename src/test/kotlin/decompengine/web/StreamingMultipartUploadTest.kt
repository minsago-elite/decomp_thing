package decompengine.web

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.IOException
import java.security.MessageDigest
import kotlin.test.*

class StreamingMultipartUploadTest {
    private val boundary = "fixture_boundary_123"
    private val type = "multipart/form-data; boundary=$boundary"
    private fun body(payload: ByteArray, filename: String = "sample.elf", ending: String = "\r\n--$boundary--\r\n") =
        "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray() + payload + ending.toByteArray()
    private fun split(bytes: ByteArray, chunk: Int) = object : InputStream() {
        var offset = 0
        override fun read(): Int = if (offset == bytes.size) -1 else bytes[offset++].toInt() and 255
        override fun read(target: ByteArray, start: Int, length: Int): Int {
            if (offset == bytes.size) return -1
            val count = minOf(length, chunk, bytes.size - offset)
            bytes.copyInto(target, start, offset, offset + count); offset += count
            return count
        }
    }

    @Test fun `arbitrary binary bytes and boundary-shaped payload survive every stream split`() {
        val payload = ByteArray(256) { it.toByte() } +
            "\r\n--${boundary}X!\r\n--${boundary}--X\r\n--${boundary}--\rX\r\n--fixture_bound\r\n--\r\n".toByteArray()
        for (chunk in listOf(1, 2, 3, 7, 64, 65536)) {
            val output = ByteArrayOutputStream()
            val receipt = StreamingMultipartUpload.copy(split(body(payload), chunk), type, output)
            assertContentEquals(payload, output.toByteArray(), "chunk=$chunk")
            assertEquals(payload.size.toLong(), receipt.sizeBytes)
            assertContentEquals(payload.copyOf(64), receipt.elfHeader)
            assertEquals(MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }, receipt.sha256)
            assertEquals("sample.elf", receipt.filename)
        }
    }

    @Test fun `legacy compatibility parser no longer strips legitimate trailing delimiters or CRLF`() {
        listOf("ends--", "ends\r\n", "ends\r\n--", "", "ends\n").forEach { text ->
            assertContentEquals(text.toByteArray(), MultipartUpload.parse(body(text.toByteArray()), type).content)
        }
    }

    @Test fun `actual complete request ceiling is enforced without relying on a declared length`() {
        val bytes = body(ByteArray(8192) { 7 })
        val output = ByteArrayOutputStream()
        assertEquals(8192, StreamingMultipartUpload.copy(split(bytes, 17), type, output, bytes.size.toLong()).sizeBytes)
        for (chunk in listOf(1, 64, 65536)) {
            val failure = assertFailsWith<UploadBodyException> {
                StreamingMultipartUpload.copy(split(bytes, chunk), type, ByteArrayOutputStream(), bytes.size.toLong() - 1)
            }
            assertEquals("UPLOAD_TOO_LARGE", failure.reasonCode)
        }
    }

    @Test fun `missing closing boundary extra parts and ambiguous headers fail without a receipt`() {
        val payload = byteArrayOf(1, 2, 3)
        val invalid = listOf(body(payload, ending = ""), body(payload, ending = "\r\n--$boundary\r\n"),
            body(payload) + "epilogue".toByteArray(),
            body(payload).toString(Charsets.UTF_8).replace("name=\"binary\"", "name=\"other\"").toByteArray(),
            body(payload).toString(Charsets.UTF_8).replace("Content-Type:", "Content-Disposition: duplicate\r\nContent-Type:").toByteArray())
        invalid.forEach { bytes -> assertFailsWith<UploadBodyException> { StreamingMultipartUpload.copy(bytes.inputStream(), type, ByteArrayOutputStream()) } }
        assertFailsWith<UploadBodyException> { StreamingMultipartUpload.copy(body(payload).inputStream(), "$type; charset=UTF-8", ByteArrayOutputStream()) }
    }

    @Test fun `UTF8 filenames are display names and never carry directories`() {
        val output = ByteArrayOutputStream()
        assertEquals("프로그램.elf", StreamingMultipartUpload.copy(body(byteArrayOf(1), "../../folder\\프로그램.elf").inputStream(), type, output).filename)
        assertFailsWith<UploadBodyException> { StreamingMultipartUpload.copy(body(byteArrayOf(1), "x".repeat(256)).inputStream(), type, ByteArrayOutputStream()) }
        assertFailsWith<UploadBodyException> { StreamingMultipartUpload.copy(body(byteArrayOf(1), "..").inputStream(), type, ByteArrayOutputStream()) }
    }

    @Test fun `sink failures and cancellation propagate rather than reporting an accepted upload`() {
        val sink = object : java.io.OutputStream() { override fun write(value: Int) { throw IOException("inert sink failure") } }
        assertFailsWith<IOException> { StreamingMultipartUpload.copy(body(ByteArray(200000)).inputStream(), type, sink) }
        var checks = 0
        assertFailsWith<IOException> {
            StreamingMultipartUpload.copy(body(ByteArray(200000)).inputStream(), type, ByteArrayOutputStream(), checkActive = {
                if (++checks == 3) throw IOException("inert cancellation")
            })
        }
        assertEquals(3, checks)
    }

    @Test fun `large source streams write incrementally with bounded read requests`() {
        val prefix = body(byteArrayOf(), ending = "")
        val suffix = "\r\n--$boundary--".toByteArray()
        val payloadSize = 4 * 1024 * 1024
        var produced = 0
        var largestRead = 0
        val source = object : InputStream() {
            override fun read(): Int {
                val position = produced++
                return when {
                    position < prefix.size -> prefix[position].toInt() and 255
                    position < prefix.size + payloadSize -> 42
                    position < prefix.size + payloadSize + suffix.size -> suffix[position - prefix.size - payloadSize].toInt() and 255
                    else -> -1
                }
            }
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                largestRead = maxOf(largestRead, length)
                return super.read(bytes, offset, length)
            }
        }
        var written = 0L
        val sink = object : java.io.OutputStream() {
            override fun write(value: Int) { written++ }
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                assertTrue(produced.toLong() - prefix.size - written <= 2 * 65536 + suffix.size + 1)
                written += length
            }
        }
        val receipt = StreamingMultipartUpload.copy(source, type, sink)
        assertEquals(payloadSize.toLong(), written); assertEquals(written, receipt.sizeBytes)
        assertTrue(largestRead <= 65536)
    }
}

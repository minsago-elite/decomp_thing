package decompengine.web

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** The sink is caller-owned staging. Nothing is published by this parser. */
internal data class StreamedUpload(val filename: String, val sizeBytes: Long, val sha256: String, val elfHeader: ByteArray)

internal class UploadBodyException(val reasonCode: String, message: String) : IllegalArgumentException(message)

/** Exactly one binary part, with bounded headers and exact byte preservation across arbitrary read boundaries. */
internal object StreamingMultipartUpload {
    const val MAX_REQUEST_BYTES = 32L * 1024 * 1024
    private val mediaType = Regex("multipart/form-data[ \\t]*;[ \\t]*boundary=(?:([A-Za-z0-9'()+_,./:=?-]{1,70})|\"([A-Za-z0-9'()+_,./:=? -]{0,69}[A-Za-z0-9'()+_,./:=?-])\")", RegexOption.IGNORE_CASE)

    fun copy(input: InputStream, contentType: String, output: OutputStream,
             maxRequestBytes: Long = MAX_REQUEST_BYTES, checkActive: () -> Unit = {
                 if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Upload interrupted")
             }): StreamedUpload {
        require(maxRequestBytes in 1..MAX_REQUEST_BYTES)
        val match = mediaType.matchEntire(contentType) ?: invalid("UNSUPPORTED_MEDIA_TYPE", "Use multipart/form-data with one bounded boundary.")
        val boundary = match.groupValues[1].ifEmpty { match.groupValues[2] }
        // The counting wrapper is below buffering: even prefetch cannot exceed the request ceiling by more than the one rejection byte.
        var consumed = 0L
        val counted = object : InputStream() {
            override fun read(): Int {
                checkActive()
                val value = input.read()
                if (value >= 0 && ++consumed > maxRequestBytes) invalid("UPLOAD_TOO_LARGE", "The upload request exceeds its byte limit.")
                return value
            }
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                if (length == 0) return 0
                checkActive()
                val allowed = minOf(length.toLong(), maxRequestBytes - consumed + 1).toInt()
                val count = input.read(bytes, offset, allowed)
                if (count > 0) {
                    consumed += count
                    if (consumed > maxRequestBytes) invalid("UPLOAD_TOO_LARGE", "The upload request exceeds its byte limit.")
                }
                return count
            }
        }
        val source = BufferedInputStream(counted, 64 * 1024)
        fun byte(): Int = source.read().also { if (it < 0) invalid("MALFORMED_MULTIPART", "The upload body ended before its closing boundary.") }
        fun expect(text: String) { for (expected in text.toByteArray(StandardCharsets.US_ASCII)) if (byte() != expected.toInt()) invalid("MALFORMED_MULTIPART", "The upload boundary is malformed.") }
        expect("--$boundary\r\n")
        val headers = ByteArrayOutputStream()
        var tail = 0
        while (true) {
            val value = byte(); headers.write(value)
            if (headers.size() > 8192) invalid("MULTIPART_HEADERS_TOO_LARGE", "Upload headers exceed their byte limit.")
            tail = (tail shl 8) or value
            if (tail == 0x0d0a0d0a) break
        }
        val headerText = try { StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(headers.toByteArray(), 0, headers.size() - 4)).toString() }
            catch (_: java.nio.charset.CharacterCodingException) { invalid("MALFORMED_MULTIPART", "Upload headers must be valid UTF-8.") }
        val fields = linkedMapOf<String, String>()
        for (line in headerText.split("\r\n")) {
            val separator = line.indexOf(':')
            if (separator < 1) invalid("MALFORMED_MULTIPART", "Upload headers are malformed.")
            val name = line.substring(0, separator).lowercase(java.util.Locale.ROOT)
            val value = line.substring(separator + 1).trim(' ', '\t')
            if (name !in setOf("content-disposition", "content-type") || fields.put(name, value) != null ||
                value.any { it.code < 32 || it.code == 127 }) invalid("MALFORMED_MULTIPART", "Upload headers are unsupported or duplicated.")
        }
        val disposition = fields["content-disposition"] ?: invalid("MALFORMED_MULTIPART", "The binary part needs a content disposition.")
        val parameters = Regex("form-data;[ \\t]*name=\"binary\";[ \\t]*filename=\"([^\"]*)\"").matchEntire(disposition)
            ?: invalid("MALFORMED_MULTIPART", "Provide exactly one file part named binary.")
        val filename = parameters.groupValues[1].substringAfterLast('/').substringAfterLast('\\').ifBlank { "input.elf" }
        if (filename.length > 255 || filename in setOf(".", "..")) invalid("INVALID_FILENAME", "The display filename is invalid or exceeds 255 characters.")
        fields["content-type"]?.let {
            if (!it.matches(Regex("[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+"))) invalid("MALFORMED_MULTIPART", "The binary part content type is malformed.")
        }
        val delimiter = "\r\n--$boundary".toByteArray(StandardCharsets.US_ASCII)
        val prefix = IntArray(delimiter.size)
        for (index in 1 until delimiter.size) {
            var previous = prefix[index - 1]
            while (previous > 0 && delimiter[index] != delimiter[previous]) previous = prefix[previous - 1]
            if (delimiter[index] == delimiter[previous]) previous++
            prefix[index] = previous
        }
        val digest = MessageDigest.getInstance("SHA-256")
        val header = ByteArrayOutputStream(64)
        var size = 0L
        val sink = BufferedOutputStream(object : OutputStream() {
            override fun write(value: Int) { write(byteArrayOf(value.toByte()), 0, 1) }
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                checkActive()
                output.write(bytes, offset, length)
                digest.update(bytes, offset, length)
                if (header.size() < 64) header.write(bytes, offset, minOf(length, 64 - header.size()))
                size += length
            }
        }, 64 * 1024)
        var matched = 0
        fun payload(value: Int) {
            while (matched > 0 && value.toByte() != delimiter[matched]) {
                val fallback = prefix[matched - 1]
                sink.write(delimiter, 0, matched - fallback)
                matched = fallback
            }
            if (value.toByte() == delimiter[matched]) matched++ else sink.write(value)
        }
        while (true) {
            payload(byte())
            if (matched != delimiter.size) continue
            val first = byte(); val second = byte()
            if (first == '-'.code && second == '-'.code) {
                val suffix = source.read()
                if (suffix == -1) {
                    checkActive(); sink.flush()
                    return StreamedUpload(filename, size, digest.digest().joinToString("") { "%02x".format(it) }, header.toByteArray())
                }
                val afterCr = if (suffix == '\r'.code) byte() else -1
                if (suffix == '\r'.code && afterCr == '\n'.code) {
                    if (source.read() != -1) invalid("MALFORMED_MULTIPART", "Upload epilogues and extra parts are not supported.")
                    checkActive(); sink.flush()
                    return StreamedUpload(filename, size, digest.digest().joinToString("") { "%02x".format(it) }, header.toByteArray())
                }
                sink.write(delimiter); sink.write(first); sink.write(second); matched = 0
                payload(suffix)
                if (afterCr != -1) payload(afterCr)
                continue
            }
            if (first == '\r'.code && second == '\n'.code) invalid("MULTIPLE_UPLOAD_PARTS", "Provide exactly one binary part.")
            // A boundary-shaped sequence followed by ordinary bytes belongs to the binary.
            sink.write(delimiter); matched = 0
            payload(first); payload(second)
        }
    }

    private fun invalid(code: String, message: String): Nothing = throw UploadBodyException(code, message)
}

package decompengine.web

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.text.Normalizer

/**
 * The one normalizer for browser-supplied artifact identities. A public identity is a list of raw
 * (still percent-encoded) URL path segments; it is decoded exactly once, per segment, with RFC 3986
 * rules (`+` is a literal plus, not a space) and strict UTF-8, and then must already be the canonical
 * spelling of a contained relative name. There is exactly one accepted spelling for each name, so a
 * separator, traversal, absolute or reserved component cannot be smuggled through any encoding.
 *
 * Refused: empty segments, `.`/`..`, encoded or literal `/` and `\`, drive or stream separators
 * (`:`), NUL and other controls, Unicode format characters (bidirectional overrides, zero-width),
 * non-NFC spellings, a `%` that survives decoding (double encoding), Windows device names
 * (`CON`, `NUL`, `COM1`…), trailing dots or spaces, oversized segments and over-deep paths.
 *
 * Validation does not grant access: the caller still opens the result through the descriptor-pinned
 * containment readers, which re-check every component at the actual open and read.
 */
internal object WebPublicIdentity {
    const val MAXIMUM_SEGMENTS = 32
    const val MAXIMUM_SEGMENT_BYTES = 255
    const val MAXIMUM_PATH_CHARACTERS = 4096

    private val reservedDeviceNames = Regex("(?i)(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\\$|CONOUT\\$)")

    /** Decode raw URL segments into a canonical contained relative path, or refuse. */
    fun relativePath(rawSegments: List<String>): String {
        if (rawSegments.isEmpty() || rawSegments.size > MAXIMUM_SEGMENTS) refuse()
        val decoded = rawSegments.map(::decodeSegment)
        decoded.forEach(::requireCanonicalSegment)
        return decoded.joinToString("/").also { if (it.length > MAXIMUM_PATH_CHARACTERS) refuse() }
    }

    /** Validate an already-decoded relative path with exactly the same rules. */
    fun canonicalRelativePath(value: String): String {
        if (value.isEmpty() || value.length > MAXIMUM_PATH_CHARACTERS) refuse()
        val segments = value.split('/')
        if (segments.size > MAXIMUM_SEGMENTS) refuse()
        segments.forEach(::requireCanonicalSegment)
        return value
    }

    /** One decoded identity segment (for example a job ID taken from a legacy route). */
    fun segment(raw: String): String = decodeSegment(raw).also(::requireCanonicalSegment)

    private fun decodeSegment(raw: String): String {
        if (raw.isEmpty() || raw.length > MAXIMUM_SEGMENT_BYTES * 3) refuse()
        val bytes = ByteArrayOutputStream(raw.length)
        var index = 0
        while (index < raw.length) {
            val character = raw[index]
            if (character == '%') {
                if (index + 2 > raw.lastIndex) refuse()
                val high = Character.digit(raw[index + 1], 16)
                val low = Character.digit(raw[index + 2], 16)
                if (high < 0 || low < 0) refuse()
                bytes.write(high * 16 + low)
                index += 3
            } else {
                if (character.code > 0x7e || character.code < 0x21) refuse()
                bytes.write(character.code)
                index++
            }
        }
        val encoded = bytes.toByteArray()
        if (encoded.size > MAXIMUM_SEGMENT_BYTES) refuse()
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString()
        } catch (_: CharacterCodingException) { refuse() }
    }

    private fun requireCanonicalSegment(segment: String) {
        if (segment.isEmpty() || segment == "." || segment == ".." || segment.toByteArray().size > MAXIMUM_SEGMENT_BYTES) refuse()
        if (segment.any { it == '/' || it == '\\' || it == ':' || it == '%' || it.code < 0x20 || it.code == 0x7f }) refuse()
        if (segment.codePoints().anyMatch { Character.getType(it) == Character.FORMAT.toInt() || Character.isISOControl(it) }) refuse()
        if (!Normalizer.isNormalized(segment, Normalizer.Form.NFC)) refuse()
        if (segment.endsWith('.') || segment.endsWith(' ') || segment.startsWith(' ')) refuse()
        if (reservedDeviceNames.matches(segment.substringBefore('.').trimEnd())) refuse()
    }

    private fun refuse(): Nothing = throw WebAccessDenied(400, "INVALID_REQUEST", "The requested artifact identity is not a canonical contained name.")
}

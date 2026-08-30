package decompengine.oracle.fulltree

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.FilterInputStream
import java.io.InputStream
import java.io.PushbackInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.EnumSet
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Strict limits for canonical artifacts whose top-level entity arrays cannot be materialized. */
internal data class FullTreeCanonicalStreamingLimits(
    val maximumInputBytes: Long,
    val maximumTokens: Long,
    val maximumEntities: Long,
    val maximumEntityBytes: Int,
    val maximumEntityNodes: Int,
    val maximumDepth: Int = 128,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytes: Long,
    val maximumNumberCharacters: Int = 256,
) {
    init {
        require(maximumInputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumTokens in 1L..1_000_000_000L)
        require(maximumEntities in 1L..50_000_000L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumDepth in 1..256)
        require(maximumStringBytes in 1..maximumEntityBytes)
        require(maximumTotalStringBytes in 1L..maximumInputBytes)
        require(maximumNumberCharacters in 1..4096)
    }
}

internal data class FullTreeStreamedCanonicalObject(
    /** Non-array top-level values. Streamed arrays are represented by empty arrays. */
    val envelope: JsonObject,
    val sourceSha256: String,
    val sourceBytes: Long,
    val canonicalWithoutOmittedFieldSha256: String?,
)

/**
 * Reads a canonical top-level object while materializing at most one bounded array entity.
 *
 * Jackson performs strict UTF-8/token/duplicate/depth enforcement. A second canonical digest is
 * reconstructed from each bounded value, which makes non-canonical whitespace, escapes, numbers,
 * or field ordering fail even when the semantic JSON tree would be accepted. The caller supplies
 * the complete canonical field order and identifies the top-level arrays to stream. Array
 * callbacks are speculative until this method returns: their effects must remain in wholly
 * revocable scratch state and must not influence publication before final authentication.
 *
 * Java NIO cannot bind the open descriptor back to its pathname. As elsewhere in the oracle, the
 * owners of the regular file and its required non-group-writable parent directory are cooperating
 * trust principals and must not swap a pathname and restore it during the read.
 */
internal object FullTreeCanonicalStreaming {
    fun readObject(
        path: Path,
        label: String,
        expectedSourceSha256: String,
        fieldOrder: List<String>,
        arrayFields: Set<String>,
        omittedDigestField: String?,
        limits: FullTreeCanonicalStreamingLimits,
        consume: (field: String, index: Long, value: JsonObject, canonicalBytes: ByteArray) -> Unit,
    ): FullTreeStreamedCanonicalObject {
        requireDigest(expectedSourceSha256, "$label source")
        require(fieldOrder.isNotEmpty() && fieldOrder.distinct().size == fieldOrder.size)
        require(fieldOrder.all(CANONICAL_FIELD_NAME::matches)) {
            "streaming field names must be plain canonical schema keys"
        }
        require(arrayFields.all { it in fieldOrder })
        require(omittedDigestField == null || omittedDigestField in fieldOrder)

        val source = validateSource(path, label, limits.maximumInputBytes)
        val rawDigest = MessageDigest.getInstance("SHA-256")
        val completeDigest = CanonicalObjectDigest(limits.maximumInputBytes)
        val omittedDigest = omittedDigestField?.let { CanonicalObjectDigest(limits.maximumInputBytes) }
        val envelope = linkedMapOf<String, JsonElement>()
        val documentBudget = DocumentBudget(limits, label)
        val bounded = MaximumInputStream(
            Files.newInputStream(source.path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS),
            limits.maximumInputBytes,
            label,
        )
        val digested = DigestInputStream(bounded, rawDigest)
        var entityCount = 0L
        try {
            rejectBom(digested, label).use { input ->
                jsonFactory(limits).createParser(input).use { parser ->
                    requireToken(parser.nextToken(), JsonToken.START_OBJECT, "$label must be a JSON object")
                    completeDigest.startObject()
                    omittedDigest?.startObject()
                    fieldOrder.forEach { expectedField ->
                        requireToken(parser.nextToken(), JsonToken.FIELD_NAME, "$label fields are incomplete")
                        val actualField = parser.currentName()
                        documentBudget.chargeString(actualField, null)
                        if (actualField != expectedField) {
                            throw FullTreeDataTruthException(
                                "$label fields are absent, extra, duplicated, or not in canonical order",
                            )
                        }
                        completeDigest.field(actualField)
                        if (actualField != omittedDigestField) omittedDigest?.field(actualField)
                        val valueToken = parser.nextToken()
                            ?: throw FullTreeDataTruthException("$label field $actualField has no value")
                        if (actualField in arrayFields) {
                            requireToken(valueToken, JsonToken.START_ARRAY, "$label field $actualField must be an array")
                            completeDigest.startArray()
                            if (actualField != omittedDigestField) omittedDigest?.startArray()
                            var index = 0L
                            while (parser.nextToken() != JsonToken.END_ARRAY) {
                                entityCount = addExact(entityCount, 1L, "$label entity")
                                if (entityCount > limits.maximumEntities) {
                                    throw FullTreeDataTruthException("$label exceeds its entity limit")
                                }
                                val value = readBoundedElement(
                                    parser,
                                    parser.currentToken(),
                                    documentBudget,
                                    limits,
                                    label,
                                ) as? JsonObject
                                    ?: throw FullTreeDataTruthException("$label $actualField entity must be an object")
                                val canonical = canonicalBytes(value, limits, label)
                                completeDigest.arrayValue(canonical)
                                if (actualField != omittedDigestField) omittedDigest?.arrayValue(canonical)
                                consume(actualField, index, value, canonical)
                                index = addExact(index, 1L, "$label array index")
                            }
                            completeDigest.endArray()
                            if (actualField != omittedDigestField) omittedDigest?.endArray()
                            envelope[actualField] = JsonArray(emptyList())
                        } else {
                            val value = readBoundedElement(
                                parser,
                                valueToken,
                                documentBudget,
                                limits,
                                label,
                            )
                            val canonical = canonicalBytes(value, limits, label)
                            completeDigest.value(canonical)
                            if (actualField != omittedDigestField) omittedDigest?.value(canonical)
                            envelope[actualField] = value
                        }
                    }
                    requireToken(parser.nextToken(), JsonToken.END_OBJECT, "$label has extra top-level fields")
                    if (parser.nextToken() != null) {
                        throw FullTreeDataTruthException("$label has trailing JSON content")
                    }
                    completeDigest.endObject()
                    omittedDigest?.endObject()
                }
            }
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("cannot stream $label: ${failure.message}", failure)
        }
        ensureSourceIdentity(source, label)
        if (bounded.byteCount != source.attributes.size()) {
            throw FullTreeDataTruthException("$label changed size during streaming")
        }
        val raw = rawDigest.digest()
        val canonical = completeDigest.finish()
        if (!MessageDigest.isEqual(raw, canonical) || completeDigest.byteCount != bounded.byteCount) {
            throw FullTreeDataTruthException("$label is not in canonical byte form")
        }
        val rawSha256 = raw.hex()
        if (rawSha256 != expectedSourceSha256) {
            throw FullTreeDataTruthException("$label SHA-256 differs from its authenticated binding")
        }
        return FullTreeStreamedCanonicalObject(
            envelope = JsonObject(envelope),
            sourceSha256 = rawSha256,
            sourceBytes = bounded.byteCount,
            canonicalWithoutOmittedFieldSha256 = omittedDigest?.finish()?.hex(),
        )
    }

    private fun jsonFactory(limits: FullTreeCanonicalStreamingLimits): JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .disable(StreamReadFeature.AUTO_CLOSE_SOURCE)
        .streamReadConstraints(
            StreamReadConstraints.builder()
                .maxDocumentLength(limits.maximumInputBytes)
                .maxTokenCount(limits.maximumTokens)
                .maxNestingDepth(limits.maximumDepth + 2)
                .maxStringLength(limits.maximumStringBytes)
                .maxNameLength(limits.maximumStringBytes)
                .maxNumberLength(limits.maximumNumberCharacters)
                .build(),
        )
        .build()

    private fun readBoundedElement(
        parser: JsonParser,
        token: JsonToken,
        documentBudget: DocumentBudget,
        limits: FullTreeCanonicalStreamingLimits,
        label: String,
    ): JsonElement = readElement(
        parser,
        token,
        depth = 1,
        documentBudget,
        EntityBudget(limits, label),
        limits,
        label,
    )

    private fun readElement(
        parser: JsonParser,
        token: JsonToken,
        depth: Int,
        documentBudget: DocumentBudget,
        entityBudget: EntityBudget,
        limits: FullTreeCanonicalStreamingLimits,
        label: String,
    ): JsonElement {
        entityBudget.chargeNode()
        if (depth > limits.maximumDepth) {
            throw FullTreeDataTruthException("$label entity exceeds its nesting-depth limit")
        }
        return when (token) {
            JsonToken.START_OBJECT -> {
                val entries = linkedMapOf<String, JsonElement>()
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    requireToken(parser.currentToken(), JsonToken.FIELD_NAME, "$label object is malformed")
                    val field = parser.currentName()
                    documentBudget.chargeString(field, entityBudget)
                    if (entries.containsKey(field)) {
                        throw FullTreeDataTruthException("$label object repeats field $field")
                    }
                    val value = parser.nextToken()
                        ?: throw FullTreeDataTruthException("$label field $field has no value")
                    entries[field] = readElement(
                        parser,
                        value,
                        depth + 1,
                        documentBudget,
                        entityBudget,
                        limits,
                        label,
                    )
                }
                JsonObject(entries)
            }
            JsonToken.START_ARRAY -> {
                val entries = arrayListOf<JsonElement>()
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    entries += readElement(
                        parser,
                        parser.currentToken(),
                        depth + 1,
                        documentBudget,
                        entityBudget,
                        limits,
                        label,
                    )
                }
                JsonArray(entries)
            }
            JsonToken.VALUE_STRING -> parser.text.let { value ->
                documentBudget.chargeString(value, entityBudget)
                JsonPrimitive(value)
            }
            JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> strictNumber(parser, token, limits, label)
            JsonToken.VALUE_TRUE -> JsonPrimitive(true)
            JsonToken.VALUE_FALSE -> JsonPrimitive(false)
            JsonToken.VALUE_NULL -> JsonNull
            else -> throw FullTreeDataTruthException("$label contains an unsupported JSON token")
        }
    }

    private fun strictNumber(
        parser: JsonParser,
        token: JsonToken,
        limits: FullTreeCanonicalStreamingLimits,
        label: String,
    ): JsonPrimitive {
        val text = parser.text
        if (text.length > limits.maximumNumberCharacters) {
            throw FullTreeDataTruthException("$label number exceeds its character limit")
        }
        if (token == JsonToken.VALUE_NUMBER_FLOAT) {
            val value = text.toDoubleOrNull()
                ?: throw FullTreeDataTruthException("$label contains an invalid JSON number")
            if (!value.isFinite()) throw FullTreeDataTruthException("$label JSON number is not finite")
        } else {
            try {
                BigInteger(text)
            } catch (failure: NumberFormatException) {
                throw FullTreeDataTruthException("$label contains an invalid JSON integer", failure)
            }
        }
        return try {
            Json.parseToJsonElement(text) as JsonPrimitive
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label contains an invalid JSON number", failure)
        }
    }

    private fun canonicalBytes(
        value: JsonElement,
        limits: FullTreeCanonicalStreamingLimits,
        label: String,
    ): ByteArray = try {
        OracleJson.canonicalBytes(
            value,
            StrictJsonLimits(
                maximumInputBytes = limits.maximumEntityBytes,
                maximumCanonicalBytes = limits.maximumEntityBytes,
                maximumDepth = limits.maximumDepth,
                maximumNodes = limits.maximumEntityNodes,
                maximumStringBytes = limits.maximumStringBytes,
                maximumTotalStringBytes = limits.maximumEntityBytes,
                maximumNumberCharacters = limits.maximumNumberCharacters,
            ),
        )
    } catch (failure: Exception) {
        throw FullTreeDataTruthException("$label entity exceeds strict JSON limits", failure)
    }

    private fun rejectBom(input: InputStream, label: String): PushbackInputStream {
        val pushback = PushbackInputStream(input, UTF8_BOM.size)
        val prefix = pushback.readNBytes(UTF8_BOM.size)
        if (prefix.contentEquals(UTF8_BOM)) {
            throw FullTreeDataTruthException("$label must not contain a UTF-8 BOM")
        }
        pushback.unread(prefix)
        return pushback
    }

    private fun validateSource(path: Path, label: String, maximumBytes: Long): SourceFile {
        val source = path.toAbsolutePath().normalize()
        if (source.fileName == null || source.parent == null) {
            throw FullTreeDataTruthException("$label path must name a file")
        }
        val real = try {
            source.toRealPath()
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label is unavailable", failure)
        }
        if (real != source) throw FullTreeDataTruthException("$label path contains a symbolic link")
        requireTrustedDirectory(source.parent, "$label parent")
        val attributes = regularFileAttributes(source, label)
        if (attributes.size() !in 1L..maximumBytes) {
            throw FullTreeDataTruthException("$label exceeds its byte limit")
        }
        val permissions = filePermissions(source, label)
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeDataTruthException("$label is writable by an untrusted principal")
        }
        return SourceFile(source, attributes, EnumSet.copyOf(permissions))
    }

    private fun ensureSourceIdentity(source: SourceFile, label: String) {
        val after = regularFileAttributes(source.path, label)
        val permissions = filePermissions(source.path, label)
        if (
            after.fileKey() != source.attributes.fileKey() ||
            after.size() != source.attributes.size() ||
            after.lastModifiedTime() != source.attributes.lastModifiedTime() ||
            permissions != source.permissions ||
            permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }
        ) {
            throw FullTreeDataTruthException("$label changed identity, metadata, or permissions during streaming")
        }
    }

    private fun filePermissions(path: Path, label: String): Set<PosixFilePermission> =
        Files.getFileAttributeView(
            path,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataTruthException("$label requires POSIX permissions")

    private fun regularFileAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label attributes are unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified regular file")
        }
        return attributes
    }

    private fun requireTrustedDirectory(path: Path, label: String) {
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified real directory")
        }
        if (path.toRealPath() != path) throw FullTreeDataTruthException("$label path contains a symbolic link")
        val permissions = Files.getFileAttributeView(
            path,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataTruthException("$label requires POSIX permissions")
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeDataTruthException("$label is writable by an untrusted principal")
        }
    }

    private fun requireToken(actual: JsonToken?, expected: JsonToken, message: String) {
        if (actual != expected) throw FullTreeDataTruthException(message)
    }

    private fun requireDigest(value: String, label: String) {
        if (!value.matches(SHA256)) throw FullTreeDataTruthException("$label digest is invalid")
    }

    private data class SourceFile(
        val path: Path,
        val attributes: BasicFileAttributes,
        val permissions: Set<PosixFilePermission>,
    )

    private class DocumentBudget(
        private val limits: FullTreeCanonicalStreamingLimits,
        private val label: String,
    ) {
        private var totalStringBytes = 0L

        fun chargeString(value: String, entity: EntityBudget?) {
            requireScalarUnicode(value)
            val bytes = value.toByteArray(StandardCharsets.UTF_8).size
            if (bytes > limits.maximumStringBytes) {
                throw FullTreeDataTruthException("$label string exceeds its byte limit")
            }
            totalStringBytes = addExact(totalStringBytes, bytes.toLong(), "$label aggregate string-byte")
            if (totalStringBytes > limits.maximumTotalStringBytes) {
                throw FullTreeDataTruthException("$label strings exceed their aggregate byte limit")
            }
            entity?.chargeString(bytes)
        }

        private fun requireScalarUnicode(value: String) {
            var offset = 0
            while (offset < value.length) {
                val current = value[offset]
                when {
                    Character.isHighSurrogate(current) -> {
                        if (offset + 1 >= value.length || !Character.isLowSurrogate(value[offset + 1])) {
                            throw FullTreeDataTruthException("$label string contains an unpaired surrogate")
                        }
                        offset += 2
                    }
                    Character.isLowSurrogate(current) ->
                        throw FullTreeDataTruthException("$label string contains an unpaired surrogate")
                    else -> offset++
                }
            }
        }
    }

    private class EntityBudget(
        private val limits: FullTreeCanonicalStreamingLimits,
        private val label: String,
    ) {
        private var nodes = 0
        private var stringBytes = 0L

        fun chargeNode() {
            nodes++
            if (nodes > limits.maximumEntityNodes) {
                throw FullTreeDataTruthException("$label entity exceeds its node limit")
            }
        }

        fun chargeString(bytes: Int) {
            stringBytes = addExact(stringBytes, bytes.toLong(), "$label entity string-byte")
            if (stringBytes > limits.maximumEntityBytes.toLong()) {
                throw FullTreeDataTruthException("$label entity strings exceed its byte limit")
            }
        }
    }

    private class MaximumInputStream(
        input: InputStream,
        private val maximumBytes: Long,
        private val label: String,
    ) : FilterInputStream(input) {
        var byteCount: Long = 0L
            private set

        override fun read(): Int {
            if (byteCount == maximumBytes) {
                if (super.read() >= 0) throw FullTreeDataTruthException("$label exceeds its byte limit")
                return -1
            }
            val value = super.read()
            if (value >= 0) byteCount++
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            val remaining = maximumBytes - byteCount
            if (remaining == 0L) return read().let { if (it < 0) -1 else 1 }
            val read = super.read(buffer, offset, minOf(length.toLong(), remaining).toInt())
            if (read > 0) byteCount += read.toLong()
            return read
        }
    }

    private class CanonicalObjectDigest(private val maximumBytes: Long) {
        private val digest = MessageDigest.getInstance("SHA-256")
        private var fields = 0
        private var arrayValues = 0
        private var finished = false
        var byteCount: Long = 0L
            private set

        fun startObject() = writeAscii("{\n")

        fun field(name: String) {
            if (fields++ > 0) writeAscii(",\n")
            writeSpaces(2)
            writeAscii("\"$name\": ")
        }

        fun value(canonicalBytes: ByteArray) = writeCanonicalValue(canonicalBytes, 2, false)

        fun startArray() {
            arrayValues = 0
        }

        fun arrayValue(canonicalBytes: ByteArray) {
            if (arrayValues++ == 0) writeAscii("[\n") else writeAscii(",\n")
            writeCanonicalValue(canonicalBytes, 4, true)
        }

        fun endArray() {
            if (arrayValues == 0) writeAscii("[]") else writeAscii("\n  ]")
        }

        fun endObject() {
            writeAscii("\n}\n")
            finished = true
        }

        fun finish(): ByteArray {
            if (!finished) throw FullTreeDataTruthException("canonical streaming digest is incomplete")
            return digest.digest()
        }

        private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
            if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
                throw FullTreeDataTruthException("canonical streaming value is malformed")
            }
            if (indentFirst) writeSpaces(indentation)
            var start = 0
            for (index in 0 until bytes.lastIndex) {
                if (bytes[index] == '\n'.code.toByte()) {
                    write(bytes, start, index - start)
                    writeAscii("\n")
                    writeSpaces(indentation)
                    start = index + 1
                }
            }
            write(bytes, start, bytes.lastIndex - start)
        }

        private fun writeAscii(value: String) {
            val bytes = value.toByteArray(StandardCharsets.US_ASCII)
            write(bytes, 0, bytes.size)
        }

        private fun writeSpaces(count: Int) = repeat(count) { writeAscii(" ") }

        private fun write(bytes: ByteArray, offset: Int, length: Int) {
            byteCount = addExact(byteCount, length.toLong(), "canonical streaming byte")
            if (byteCount > maximumBytes) {
                throw FullTreeDataTruthException("canonical streaming JSON exceeds its byte limit")
            }
            digest.update(bytes, offset, length)
        }
    }

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("$label count exceeds the supported range", failure)
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private val SHA256 = Regex("[0-9a-f]{64}")
    private val CANONICAL_FIELD_NAME = Regex("[A-Za-z][A-Za-z0-9]*")
    private val UTF8_BOM = byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte())
    private val UNTRUSTED_WRITE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )
}

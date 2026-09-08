package decompengine.builtin.provider

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.io.OutputStream

/** Reject ambiguous objects and excessive depth before the in-memory JSON representation is built. */
internal fun parseProviderObject(text: String, maximumBytes: Int): JsonObject {
    require(text.length <= maximumBytes && text.toByteArray().size <= maximumBytes)
    val factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64)
            .maxDocumentLength(maximumBytes.toLong()).maxStringLength(maximumBytes)
            .maxNameLength(minOf(maximumBytes, 8192)).maxNumberLength(128).maxTokenCount(100_000).build()).build()
    factory.createParser(text).use { parser -> while (parser.nextToken() != null) { /* Validate the complete document. */ } }
    return Json.parseToJsonElement(text).jsonObject
}

/** Limit serialization as it happens, including JSON escaping, rather than after a large allocation. */
internal fun boundedProviderJson(maximumBytes: Int, write: (JsonGenerator) -> Unit): ByteArray {
    val buffer = ByteArrayOutputStream(minOf(maximumBytes, 8192))
    val output = object : OutputStream() {
        override fun write(value: Int) {
            if (buffer.size() >= maximumBytes) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            buffer.write(value)
        }
        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (length > maximumBytes - buffer.size()) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            buffer.write(bytes, offset, length)
        }
    }
    JsonFactory().createGenerator(output).use(write)
    return buffer.toByteArray()
}

internal fun JsonGenerator.writeProviderValue(value: JsonElement, depth: Int = 0) {
    if (depth > 64) throw ModelProviderException(ModelFailureKind.INVALID_REQUEST)
    when (value) {
        is JsonObject -> {
            writeStartObject()
            value.forEach { (key, child) -> writeFieldName(key); writeProviderValue(child, depth + 1) }
            writeEndObject()
        }
        is JsonArray -> { writeStartArray(); value.forEach { writeProviderValue(it, depth + 1) }; writeEndArray() }
        JsonNull -> writeNull()
        is JsonPrimitive -> when {
            value.isString -> writeString(value.content)
            value.booleanOrNull != null -> writeBoolean(value.boolean)
            else -> writeNumber(value.content)
        }
    }
}

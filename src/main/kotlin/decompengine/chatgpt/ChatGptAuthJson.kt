package decompengine.chatgpt

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** Private authentication JSON: no permissive coercions, duplicate members or printable payloads. */
internal class ChatGptAuthJson private constructor(private val value: Any?) {
    fun member(name: String): ChatGptAuthJson? = members()[name]
    fun required(name: String): ChatGptAuthJson = member(name) ?: invalid()
    private fun members(): Map<String, ChatGptAuthJson> {
        @Suppress("UNCHECKED_CAST")
        return value as? Map<String, ChatGptAuthJson> ?: invalid()
    }
    fun elements(): List<ChatGptAuthJson> {
        @Suppress("UNCHECKED_CAST")
        return value as? List<ChatGptAuthJson> ?: invalid()
    }
    fun string(): String = value as? String ?: invalid()
    fun integer(): Long = (value as? IntegerValue)?.text?.toLongOrNull() ?: invalid()
    fun isString(): Boolean = value is String
    override fun toString() = "ChatGptAuthJson([redacted])"

    private class IntegerValue(val text: String) {
        override fun toString() = "ChatGptAuthJson.Integer([redacted])"
    }

    companion object {
        const val MAX_BYTES = 256 * 1024
        private val factory = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(32).maxStringLength(MAX_BYTES).maxNumberLength(128).build())
            .build()

        fun parse(bytes: ByteArray, operation: ChatGptStoreOperation): ChatGptAuthJson = oidcBoundary {
            operation.check()
            if (bytes.isEmpty() || bytes.size > MAX_BYTES) invalid()
            // Decode explicitly: Jackson's byte parser can otherwise accept other Unicode encodings.
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            operation.check()
            factory.createParser(text).use { parser ->
                if (parser.nextToken() != JsonToken.START_OBJECT) invalid()
                val root = read(parser, operation, 1)
                operation.check()
                if (parser.nextToken() != null) invalid()
                root
            }
        }

        private fun read(p: JsonParser, operation: ChatGptStoreOperation, depth: Int): ChatGptAuthJson {
            operation.check()
            val result: Any? = when (p.currentToken()) {
                JsonToken.START_OBJECT -> {
                    if (depth > 32) invalid()
                    val members = linkedMapOf<String, ChatGptAuthJson>()
                    while (p.nextToken() != JsonToken.END_OBJECT) {
                        operation.check()
                        if (p.currentToken() != JsonToken.FIELD_NAME) invalid()
                        val name = p.currentName() ?: invalid()
                        unicode(name)
                        if (members.containsKey(name) || p.nextToken() == null) invalid()
                        members[name] = read(p, operation, depth + 1)
                    }
                    java.util.Collections.unmodifiableMap(members)
                }
                JsonToken.START_ARRAY -> {
                    if (depth > 32) invalid()
                    val values = mutableListOf<ChatGptAuthJson>()
                    while (p.nextToken() != JsonToken.END_ARRAY) {
                        if (p.currentToken() == null) invalid()
                        values.add(read(p, operation, depth + 1))
                    }
                    java.util.Collections.unmodifiableList(values)
                }
                JsonToken.VALUE_STRING -> p.text.also(::unicode)
                JsonToken.VALUE_NUMBER_INT -> IntegerValue(p.text)
                // Floats, booleans and null are legal JSON, but never coerced to strings/integers.
                JsonToken.VALUE_NUMBER_FLOAT, JsonToken.VALUE_TRUE, JsonToken.VALUE_FALSE, JsonToken.VALUE_NULL -> null
                else -> invalid()
            }
            operation.check()
            return ChatGptAuthJson(result)
        }

        private fun unicode(value: String) {
            Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        }
        private fun invalid(): Nothing = throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_JSON)
    }
}

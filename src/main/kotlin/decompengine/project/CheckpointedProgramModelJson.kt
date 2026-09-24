package decompengine.project

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import java.io.FilterInputStream
import java.io.InputStream
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Token and input-chunk checkpoints keep canonical model parsing inside its admitted deadline. */
internal fun parseCheckpointedProgramModelJson(input: InputStream, checkpoint: (String) -> Unit): JsonObject {
    checkpoint("before opening program model JSON parser")
    try {
        val parserInput = CheckpointedModelInput(input, checkpoint)
        MODEL_JSON_FACTORY.createParser(parserInput).use { parser ->
            val reader = CheckpointedModelReader(parser, checkpoint)
            val root = reader.readValue() as? JsonObject
                ?: throw IllegalArgumentException("program model root must be an object")
            require(reader.nextToken() == null) { "program model has trailing JSON content" }
            checkpoint("after parsing program model JSON tokens")
            return root
        }
    } catch (failure: JsonProcessingException) {
        throw IllegalArgumentException("program model is not strict UTF-8 JSON", failure)
    }
}

private class CheckpointedModelInput(input: InputStream, private val checkpoint: (String) -> Unit) : FilterInputStream(input) {
    override fun read(): Int {
        checkpoint("before reading program model JSON chunk")
        val value = super.read()
        checkpoint("after reading program model JSON chunk")
        return value
    }

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        checkpoint("before reading program model JSON chunk")
        val count = super.read(bytes, offset, minOf(length, 64 * 1024))
        checkpoint("after reading program model JSON chunk")
        return count
    }
}

private class CheckpointedModelReader(
    private val parser: JsonParser,
    private val checkpoint: (String) -> Unit,
) {
    fun nextToken(): JsonToken? {
        checkpoint("before parsing program model JSON token")
        val token = parser.nextToken()
        checkpoint("after parsing program model JSON token")
        return token
    }

    fun readValue(): JsonElement = readValue(nextToken())

    private fun readValue(token: JsonToken?): JsonElement = when (token) {
        JsonToken.START_OBJECT -> {
            val fields = linkedMapOf<String, JsonElement>()
            while (true) {
                when (nextToken()) {
                    JsonToken.END_OBJECT -> break
                    JsonToken.FIELD_NAME -> {
                        val name = readText()
                        require(name !in fields) { "program model has a duplicate JSON field" }
                        fields[name] = readValue()
                    }
                    else -> throw IllegalArgumentException("program model object has an invalid field")
                }
            }
            checkpoint("before completing program model JSON object")
            JsonObject(fields)
        }
        JsonToken.START_ARRAY -> {
            val values = arrayListOf<JsonElement>()
            while (true) {
                checkpoint("before reading program model JSON array entry")
                val item = nextToken()
                if (item == JsonToken.END_ARRAY) break
                values += readValue(item)
            }
            checkpoint("before completing program model JSON array")
            JsonArray(values)
        }
        JsonToken.VALUE_STRING -> JsonPrimitive(readText())
        JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> Json.parseToJsonElement(readText())
        JsonToken.VALUE_TRUE -> JsonPrimitive(true)
        JsonToken.VALUE_FALSE -> JsonPrimitive(false)
        JsonToken.VALUE_NULL -> JsonNull
        else -> throw IllegalArgumentException("program model JSON has an invalid value")
    }

    private fun readText(): String {
        checkpoint("before decoding program model JSON token")
        val text = parser.text
        checkpoint("after decoding program model JSON token")
        return text
    }
}

private val MODEL_JSON_FACTORY: JsonFactory = JsonFactory.builder()
    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
    .streamReadConstraints(StreamReadConstraints.builder()
        .maxDocumentLength(512L * 1024 * 1024)
        .maxTokenCount(64_000_000)
        .maxNestingDepth(32)
        .maxStringLength(512 * 1024 * 1024)
        .maxNameLength(4096)
        .maxNumberLength(64)
        .build())
    .build()

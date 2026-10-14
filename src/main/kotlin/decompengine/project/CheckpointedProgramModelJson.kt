package decompengine.project

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import java.io.FilterInputStream
import java.io.InputStream
import java.io.Reader
import java.io.FilterReader
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Token and input-chunk checkpoints keep canonical model parsing inside its admitted deadline. */
internal fun parseCheckpointedProgramModelJson(input: InputStream, checkpoint: (String) -> Unit): JsonObject {
    checkpoint("before opening program model JSON parser")
    return parseCheckpointedModelParser(MODEL_JSON_FACTORY.createParser(CheckpointedModelInput(input, checkpoint)), checkpoint)
}

internal fun parseCheckpointedProgramModelJson(input: Reader, checkpoint: (String) -> Unit): JsonObject {
    checkpoint("before opening program model JSON parser")
    return parseCheckpointedModelParser(MODEL_JSON_FACTORY.createParser(CheckpointedModelCharacters(input, checkpoint)), checkpoint)
}

private fun parseCheckpointedModelParser(parser: JsonParser, checkpoint: (String) -> Unit): JsonObject {
    try {
        parser.use {
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
    private val admission = ReferencedByteEvidenceAdmission(byteInput = true)
    override fun read(): Int {
        checkpoint("before reading program model JSON chunk")
        val value = super.read()
        if (value >= 0) admission.accept(value) else admission.finish()
        checkpoint("after reading program model JSON chunk")
        return value
    }

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        checkpoint("before reading program model JSON chunk")
        val count = super.read(bytes, offset, minOf(length, 64 * 1024))
        if (count < 0) admission.finish() else for (index in offset until offset + count) admission.accept(bytes[index].toInt() and 255)
        checkpoint("after reading program model JSON chunk")
        return count
    }
}

private class CheckpointedModelCharacters(input: Reader, private val checkpoint: (String) -> Unit) : FilterReader(input) {
    private val admission = ReferencedByteEvidenceAdmission(byteInput = false)
    override fun read(chars: CharArray, offset: Int, length: Int): Int {
        checkpoint("before reading program model JSON chunk")
        val count = super.read(chars, offset, minOf(length, 64 * 1024))
        if (count < 0) admission.finish() else for (index in offset until offset + count) admission.accept(chars[index].code)
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

    private val evidenceBudget = ReferencedDataByteEvidenceJson.Budget()

    fun readValue(): JsonElement = readValue(nextToken(), "root")

    private fun readValue(token: JsonToken?, role: String): JsonElement = when (token) {
        JsonToken.START_OBJECT -> {
            val fields = linkedMapOf<String, JsonElement>()
            while (true) {
                when (nextToken()) {
                    JsonToken.END_OBJECT -> break
                    JsonToken.FIELD_NAME -> {
                        val name = readText()
                        require(name !in fields) { "program model has a duplicate JSON field" }
                        val childRole = when {
                            role == "root" && name == "globals" -> "globals"
                            role == "global" && name == "byteEvidence" -> "evidence"
                            else -> "other"
                        }
                        fields[name] = readValue(nextToken(), childRole)
                    }
                    else -> throw IllegalArgumentException("program model object has an invalid field")
                }
            }
            checkpoint("before completing program model JSON object")
            JsonObject(fields).also { value ->
                // Reject invalid evidence at the first completed global, before retaining later globals.
                if (role == "evidence") evidenceBudget.charge(ReferencedDataByteEvidenceJson.parse(value))
            }
        }
        JsonToken.START_ARRAY -> {
            val values = arrayListOf<JsonElement>()
            while (true) {
                checkpoint("before reading program model JSON array entry")
                val item = nextToken()
                if (item == JsonToken.END_ARRAY) break
                values += readValue(item, if (role == "globals") "global" else "other")
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

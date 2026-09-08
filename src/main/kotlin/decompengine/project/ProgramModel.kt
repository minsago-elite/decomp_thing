package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.util.Locale

// Historical extraction/completion labels; these are not scored recovery assessments.
enum class RecoveryStatus { RECOVERED, PARTIAL, FAILED, SYNTHETIC }

data class RecoveredFunction(
    val id: String,
    val name: String,
    val address: ULong,
    val prototype: String,
    val decompiledC: String? = null,
    val calls: Set<String> = emptySet(),
    val referencedGlobals: Set<String> = emptySet(),
    val strings: Set<String> = emptySet(),
    val status: RecoveryStatus = RecoveryStatus.RECOVERED,
)

data class RecoveredGlobal(
    val id: String,
    val name: String,
    val address: ULong,
    val type: String,
    val initializer: String? = null,
    val status: RecoveryStatus = RecoveryStatus.RECOVERED,
)

data class RecoveredType(
    val id: String,
    val declaration: String,
    val sourceAddress: ULong? = null,
    val status: RecoveryStatus = RecoveryStatus.RECOVERED,
)

data class RecoveredProgramModel(
    val schemaVersion: Int = 1,
    val inputSha256: String,
    val functions: List<RecoveredFunction>,
    val globals: List<RecoveredGlobal> = emptyList(),
    val types: List<RecoveredType> = emptyList(),
) {
    init {
        require(schemaVersion in 1..2) { "unsupported program model schemaVersion: $schemaVersion" }
        require(functions.map { it.id }.distinct().size == functions.size) { "function IDs must be unique" }
        require(globals.map { it.id }.distinct().size == globals.size) { "global IDs must be unique" }
        require(types.map { it.id }.distinct().size == types.size) { "type IDs must be unique" }
    }

    private fun statusFields(status: RecoveryStatus): String {
        val value = status.name.lowercase(Locale.ROOT)
        return if (schemaVersion == 1) "\"status\": \"$value\""
        else "\"extractionStatus\": \"$value\",\n              \"recoveryAssessment\": \"unassessed\""
    }

    /** Schema 2 extraction labels never establish a scored recovery assessment. */
    fun isRecoveryUnresolved(status: RecoveryStatus): Boolean =
        schemaVersion == 2 || status != RecoveryStatus.RECOVERED

    fun toJson(): String = toJson {}

    /** Cooperative checkpoints do not preempt an individual sort, join, or library operation. */
    internal fun toJson(checkpoint: (String) -> Unit): String = checkedModelStage("rendering program model", checkpoint) {
        buildString {
            append("{\n  \"schemaVersion\": ").append(schemaVersion)
            append(",\n  \"inputSha256\": \"").append(inputSha256.json(checkpoint)).append("\",")
            append("\n  \"functions\": [")
            if (functions.isNotEmpty()) append('\n')
            val sortedFunctions = checkedModelStage("sorting program model functions", checkpoint) {
                functions.sortedWith(compareBy<RecoveredFunction> { it.address }.thenBy { it.id })
            }
            append(checkedModelStage("joining program model functions", checkpoint) {
                sortedFunctions.joinToString(",\n") { function ->
                    checkedModelStage("rendering program model function", checkpoint) {
                        """
            {
              "id": "${function.id.json(checkpoint)}",
              "name": "${function.name.json(checkpoint)}",
              "address": "0x${function.address.toString(16)}",
              "prototype": "${function.prototype.json(checkpoint)}",
              ${statusFields(function.status)},
              "calls": [${function.calls.json(checkpoint)}],
              "referencedGlobals": [${function.referencedGlobals.json(checkpoint)}],
              "strings": [${function.strings.json(checkpoint)}],
              "decompiledC": ${function.decompiledC?.let { "\"${it.json(checkpoint)}\"" } ?: "null"}
            }""".trimIndent().prependIndent("    ")
                    }
                }
            })
            append("\n  ],\n  \"globals\": [")
            if (globals.isNotEmpty()) append('\n')
            val sortedGlobals = checkedModelStage("sorting program model globals", checkpoint) {
                globals.sortedWith(compareBy<RecoveredGlobal> { it.address }.thenBy { it.id })
            }
            append(checkedModelStage("joining program model globals", checkpoint) {
                sortedGlobals.joinToString(",\n") { global ->
                    checkedModelStage("rendering program model global", checkpoint) {
                        """
            {
              "id": "${global.id.json(checkpoint)}",
              "name": "${global.name.json(checkpoint)}",
              "address": "0x${global.address.toString(16)}",
              "type": "${global.type.json(checkpoint)}",
              "initializer": ${global.initializer?.let { "\"${it.json(checkpoint)}\"" } ?: "null"},
              ${statusFields(global.status)}
            }""".trimIndent().prependIndent("    ")
                    }
                }
            })
            append("\n  ],\n  \"types\": [")
            if (types.isNotEmpty()) append('\n')
            val sortedTypes = checkedModelStage("sorting program model types", checkpoint) { types.sortedBy { it.id } }
            append(checkedModelStage("joining program model types", checkpoint) {
                sortedTypes.joinToString(",\n") { type ->
                    checkedModelStage("rendering program model type", checkpoint) {
                        """
            {
              "id": "${type.id.json(checkpoint)}",
              "declaration": "${type.declaration.json(checkpoint)}",
              "sourceAddress": ${type.sourceAddress?.let { "\"0x${it.toString(16)}\"" } ?: "null"},
              ${statusFields(type.status)}
            }""".trimIndent().prependIndent("    ")
                    }
                }
            })
            append("\n  ]\n}\n")
        }
    }
}

object ProgramModelJson {
    fun readCanonical(bytes: ByteArray): RecoveredProgramModel = readCanonical(bytes) {}

    /** Charset conversion and JSON parsing remain monolithic, with checks on either side. */
    internal fun readCanonical(bytes: ByteArray, checkpoint: (String) -> Unit): RecoveredProgramModel {
        checkpoint("before reading canonical program model")
        require(bytes.isNotEmpty()) { "program model must not be empty" }
        val text = checkedModelStage("decoding program model UTF-8", checkpoint) { bytes.toString(Charsets.UTF_8) }
        val encoded = checkedModelStage("encoding program model UTF-8", checkpoint) { text.toByteArray(Charsets.UTF_8) }
        require(checkedModelStage("comparing program model UTF-8", checkpoint) { bytes.contentEquals(encoded) }) {
            "program model must be canonical UTF-8"
        }
        val model = read(text, checkpoint)
        val canonicalText = model.toJson(checkpoint)
        val canonical = checkedModelStage("encoding canonical program model", checkpoint) { canonicalText.toByteArray(Charsets.UTF_8) }
        require(checkedModelStage("comparing canonical program model", checkpoint) { MessageDigest.isEqual(bytes, canonical) }) {
            "program model must use exact canonical fields, entity order, sets, and bytes"
        }
        checkpoint("before returning canonical program model")
        return model
    }

    fun read(text: String): RecoveredProgramModel = read(text) {}

    /** Library parsing and constructor validation remain nonpreemptible between checkpoints. */
    internal fun read(text: String, checkpoint: (String) -> Unit): RecoveredProgramModel {
        val root = checkedModelStage("parsing program model JSON", checkpoint) { Json.parseToJsonElement(text).jsonObject }
        val schemaVersion = root.int("schemaVersion", 1)
        require(schemaVersion in 1..2) { "unsupported program model schemaVersion: $schemaVersion" }
        val inputSha256 = root.string("inputSha256")
        val functions = checkedModelStage("reading program model functions", checkpoint) {
            root.array("functions").map { element ->
                checkedModelStage("reading program model function", checkpoint) {
                    val item = element.jsonObject
                    RecoveredFunction(
                        id = item.string("id"),
                        name = item.string("name"),
                        address = item.string("address").removePrefix("0x").toULong(16),
                        prototype = item.string("prototype"),
                        decompiledC = item["decompiledC"]?.jsonPrimitive?.contentOrNull,
                        calls = item.stringSet("calls", checkpoint),
                        referencedGlobals = item.stringSet("referencedGlobals", checkpoint),
                        strings = item.stringSet("strings", checkpoint),
                        status = readExtractionStatus(item, schemaVersion),
                    )
                }
            }
        }
        val globals = checkedModelStage("reading program model globals", checkpoint) {
            root.array("globals").map { element ->
                checkedModelStage("reading program model global", checkpoint) {
                    val item = element.jsonObject
                    RecoveredGlobal(
                        id = item.string("id"),
                        name = item.string("name"),
                        address = item.string("address").removePrefix("0x").toULong(16),
                        type = item.string("type"),
                        initializer = item["initializer"]?.jsonPrimitive?.contentOrNull,
                        status = readExtractionStatus(item, schemaVersion),
                    )
                }
            }
        }
        val types = checkedModelStage("reading program model types", checkpoint) {
            root.array("types").map { element ->
                checkedModelStage("reading program model type", checkpoint) {
                    val item = element.jsonObject
                    RecoveredType(
                        id = item.string("id"),
                        declaration = item.string("declaration"),
                        sourceAddress = item["sourceAddress"]?.jsonPrimitive?.contentOrNull?.removePrefix("0x")?.toULong(16),
                        status = readExtractionStatus(item, schemaVersion),
                    )
                }
            }
        }
        return checkedModelStage("constructing program model", checkpoint) {
            RecoveredProgramModel(schemaVersion, inputSha256, functions, globals, types)
        }
    }

    private fun readExtractionStatus(item: JsonObject, schemaVersion: Int): RecoveryStatus {
        if (schemaVersion == 2) {
            require("status" !in item) { "schema 2 uses extractionStatus, not historical status" }
            val assessment = item.getValue("recoveryAssessment").jsonPrimitive
            require(assessment.isString && assessment.content == "unassessed") {
                "an extracted model cannot supply a scored recovery assessment"
            }
        }
        val field = if (schemaVersion == 1) "status" else "extractionStatus"
        return RecoveryStatus.valueOf(item.string(field).uppercase(Locale.ROOT))
    }

    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
    private fun JsonObject.int(name: String, default: Int): Int = get(name)?.jsonPrimitive?.content?.toInt() ?: default
    private fun JsonObject.array(name: String) = getValue(name).jsonArray
    private fun JsonObject.stringSet(name: String, checkpoint: (String) -> Unit): Set<String> {
        val strings = checkedModelStage("reading program model set", checkpoint) {
            array(name).map {
                checkedModelStage("reading program model set entry", checkpoint) { it.jsonPrimitive.content }
            }
        }
        return checkedModelStage("constructing program model set", checkpoint) { strings.toSet() }
    }
}

data class PlannedModule(
    val id: String,
    val sourcePath: String,
    val headerPath: String,
    val functionIds: List<String>,
    val globalIds: List<String>,
    val typeIds: List<String> = emptyList(),
    val boundaryEvidence: List<String>,
)

data class ModulePlan(
    val schemaVersion: Int = 2,
    val modules: List<PlannedModule>,
    val dependencyCycles: List<List<String>> = emptyList(),
) {
    fun toJson(): String = buildString {
        append("{\n  \"schemaVersion\": ").append(schemaVersion).append(",\n  \"modules\": [")
        append(modules.sortedBy { it.id }.joinToString(",") { module ->
            """
            {
              "id": "${module.id.json()}",
              "sourcePath": "${module.sourcePath.json()}",
              "headerPath": "${module.headerPath.json()}",
              "functionIds": [${module.functionIds.joinToString(", ") { "\"${it.json()}\"" }}],
              "globalIds": [${module.globalIds.joinToString(", ") { "\"${it.json()}\"" }}],
              "typeIds": [${module.typeIds.joinToString(", ") { "\"${it.json()}\"" }}],
              "boundaryEvidence": [${module.boundaryEvidence.joinToString(", ") { "\"${it.json()}\"" }}]
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"dependencyCycles\": [")
        append(dependencyCycles.joinToString(",") { cycle -> "[${cycle.joinToString(",") { "\"${it.json()}\"" }}]" })
        append("]\n}\n")
    }
}

fun stableFunctionId(address: ULong): String = "fn_${address.toString(16).padStart(16, '0')}"
fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

internal fun safeIdentifier(value: String): String = value.lowercase(Locale.ROOT)
    .replace(Regex("[^a-z0-9_]+"), "_")
    .trim('_')
    .take(48)
    .ifBlank { "core" }

private fun String.json(): String = json {}

private fun String.json(checkpoint: (String) -> Unit): String = checkedModelStage("escaping program model string", checkpoint) {
    buildString {
        for ((index, char) in this@json.withIndex()) {
            if (index > 0 && index % 1024 == 0) checkpoint("escaping program model string after $index characters")
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (char.code < 0x20) append("\\u%04x".format(char.code)) else append(char)
            }
        }
    }
}

private fun Set<String>.json(checkpoint: (String) -> Unit): String {
    val strings = checkedModelStage("sorting program model set", checkpoint) { sorted() }
    return checkedModelStage("joining program model set", checkpoint) {
        strings.joinToString(", ") {
            checkedModelStage("rendering program model set entry", checkpoint) { "\"${it.json(checkpoint)}\"" }
        }
    }
}

private inline fun <T> checkedModelStage(stage: String, checkpoint: (String) -> Unit, operation: () -> T): T {
    checkpoint("before $stage")
    val result = operation()
    checkpoint("after $stage")
    return result
}

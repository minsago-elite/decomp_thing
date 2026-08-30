package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.util.Locale

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
        require(functions.map { it.id }.distinct().size == functions.size) { "function IDs must be unique" }
        require(globals.map { it.id }.distinct().size == globals.size) { "global IDs must be unique" }
        require(types.map { it.id }.distinct().size == types.size) { "type IDs must be unique" }
    }

    fun toJson(): String = buildString {
        append("{\n  \"schemaVersion\": ").append(schemaVersion)
        append(",\n  \"inputSha256\": \"").append(inputSha256.json()).append("\",")
        append("\n  \"functions\": [")
        if (functions.isNotEmpty()) append('\n')
        append(functions.sortedWith(compareBy<RecoveredFunction> { it.address }.thenBy { it.id }).joinToString(",\n") { function ->
            """
            {
              "id": "${function.id.json()}",
              "name": "${function.name.json()}",
              "address": "0x${function.address.toString(16)}",
              "prototype": "${function.prototype.json()}",
              "status": "${function.status.name.lowercase()}",
              "calls": [${function.calls.sorted().joinToString(", ") { "\"${it.json()}\"" }}],
              "referencedGlobals": [${function.referencedGlobals.sorted().joinToString(", ") { "\"${it.json()}\"" }}],
              "strings": [${function.strings.sorted().joinToString(", ") { "\"${it.json()}\"" }}],
              "decompiledC": ${function.decompiledC?.let { "\"${it.json()}\"" } ?: "null"}
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"globals\": [")
        if (globals.isNotEmpty()) append('\n')
        append(globals.sortedWith(compareBy<RecoveredGlobal> { it.address }.thenBy { it.id }).joinToString(",\n") { global ->
            """
            {
              "id": "${global.id.json()}",
              "name": "${global.name.json()}",
              "address": "0x${global.address.toString(16)}",
              "type": "${global.type.json()}",
              "initializer": ${global.initializer?.let { "\"${it.json()}\"" } ?: "null"},
              "status": "${global.status.name.lowercase()}"
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"types\": [")
        if (types.isNotEmpty()) append('\n')
        append(types.sortedBy { it.id }.joinToString(",\n") { type ->
            """
            {
              "id": "${type.id.json()}",
              "declaration": "${type.declaration.json()}",
              "sourceAddress": ${type.sourceAddress?.let { "\"0x${it.toString(16)}\"" } ?: "null"},
              "status": "${type.status.name.lowercase()}"
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ]\n}\n")
    }
}

object ProgramModelJson {
    fun readCanonical(bytes: ByteArray): RecoveredProgramModel {
        require(bytes.isNotEmpty()) { "program model must not be empty" }
        val text = bytes.toString(Charsets.UTF_8)
        require(bytes.contentEquals(text.toByteArray(Charsets.UTF_8))) {
            "program model must be canonical UTF-8"
        }
        val model = read(text)
        val canonical = model.toJson().toByteArray(Charsets.UTF_8)
        require(MessageDigest.isEqual(bytes, canonical)) {
            "program model must use exact canonical fields, entity order, sets, and bytes"
        }
        return model
    }

    fun read(text: String): RecoveredProgramModel {
        val root = Json.parseToJsonElement(text).jsonObject
        val schemaVersion = root.int("schemaVersion", 1)
        require(schemaVersion == 1) { "unsupported program model schemaVersion: $schemaVersion" }
        return RecoveredProgramModel(
            schemaVersion = schemaVersion,
            inputSha256 = root.string("inputSha256"),
            functions = root.array("functions").map { element ->
                val item = element.jsonObject
                RecoveredFunction(
                    id = item.string("id"),
                    name = item.string("name"),
                    address = item.string("address").removePrefix("0x").toULong(16),
                    prototype = item.string("prototype"),
                    decompiledC = item["decompiledC"]?.jsonPrimitive?.contentOrNull,
                    calls = item.stringSet("calls"),
                    referencedGlobals = item.stringSet("referencedGlobals"),
                    strings = item.stringSet("strings"),
                    status = RecoveryStatus.valueOf(item.string("status").uppercase(Locale.ROOT)),
                )
            },
            globals = root.array("globals").map { element ->
                val item = element.jsonObject
                RecoveredGlobal(
                    id = item.string("id"),
                    name = item.string("name"),
                    address = item.string("address").removePrefix("0x").toULong(16),
                    type = item.string("type"),
                    initializer = item["initializer"]?.jsonPrimitive?.contentOrNull,
                    status = RecoveryStatus.valueOf(item.string("status").uppercase(Locale.ROOT)),
                )
            },
            types = root.array("types").map { element ->
                val item = element.jsonObject
                RecoveredType(
                    id = item.string("id"),
                    declaration = item.string("declaration"),
                    sourceAddress = item["sourceAddress"]?.jsonPrimitive?.contentOrNull?.removePrefix("0x")?.toULong(16),
                    status = RecoveryStatus.valueOf(item.string("status").uppercase(Locale.ROOT)),
                )
            },
        )
    }

    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
    private fun JsonObject.int(name: String, default: Int): Int = get(name)?.jsonPrimitive?.content?.toInt() ?: default
    private fun JsonObject.array(name: String) = getValue(name).jsonArray
    private fun JsonObject.stringSet(name: String) = array(name).map { it.jsonPrimitive.content }.toSet()
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

private fun String.json(): String = buildString {
    for (char in this@json) when (char) {
        '\\' -> append("\\\\")
        '"' -> append("\\\"")
        '\n' -> append("\\n")
        '\r' -> append("\\r")
        '\t' -> append("\\t")
        else -> if (char.code < 0x20) append("\\u%04x".format(char.code)) else append(char)
    }
}

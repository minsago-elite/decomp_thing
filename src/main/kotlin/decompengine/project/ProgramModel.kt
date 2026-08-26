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
        append(functions.sortedWith(compareBy<RecoveredFunction> { it.address }.thenBy { it.id }).joinToString(",") { function ->
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
        append(globals.sortedWith(compareBy<RecoveredGlobal> { it.address }.thenBy { it.id }).joinToString(",") { global ->
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
        append(types.sortedBy { it.id }.joinToString(",") { type ->
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
    val boundaryEvidence: List<String>,
)

data class ModulePlan(
    val schemaVersion: Int = 1,
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
              "boundaryEvidence": [${module.boundaryEvidence.joinToString(", ") { "\"${it.json()}\"" }}]
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"dependencyCycles\": [")
        append(dependencyCycles.joinToString(",") { cycle -> "[${cycle.joinToString(",") { "\"${it.json()}\"" }}]" })
        append("]\n}\n")
    }
}

/** Deterministic ownership planning; LLM output is deliberately not allowed to choose paths. */
class DeterministicModulePlanner(private val maximumFunctionsPerModule: Int = 24) {
    init { require(maximumFunctionsPerModule > 0) }

    fun plan(model: RecoveredProgramModel, overrides: Map<String, String> = emptyMap()): ModulePlan {
        val functions = model.functions.sortedWith(compareBy<RecoveredFunction> { it.address }.thenBy { it.id })
        require(overrides.keys.all { id -> functions.any { it.id == id } || model.globals.any { it.id == id } }) {
            "module override references an unknown entity"
        }
        val grouped = linkedMapOf<String, MutableList<RecoveredFunction>>()
        functions.forEach { function ->
            val base = overrides[function.id]?.let(::safeIdentifier) ?: inferredModule(function)
            val groupsWithBase = grouped.keys.count { it == base || it.startsWith("${base}_") }
            val target = grouped.entries.lastOrNull { (name, members) ->
                (name == base || name.startsWith("${base}_")) && members.size < maximumFunctionsPerModule
            }?.key ?: if (groupsWithBase == 0) base else "${base}_${groupsWithBase + 1}"
            grouped.getOrPut(target) { mutableListOf() } += function
        }
        if (grouped.isEmpty()) grouped["core"] = mutableListOf()

        val functionOwner = grouped.flatMap { (module, members) -> members.map { it.id to module } }.toMap()
        val globalsByModule = model.globals.sortedWith(compareBy<RecoveredGlobal> { it.address }.thenBy { it.id })
            .groupBy { global ->
                overrides[global.id]?.let(::safeIdentifier)
                    ?: functions.firstOrNull { global.id in it.referencedGlobals }?.let { functionOwner[it.id] }
                    ?: grouped.keys.first()
            }
        val modules = grouped.map { (id, members) ->
            val referencedModules = members.flatMap { it.calls }.mapNotNull(functionOwner::get).filter { it != id }.distinct().sorted()
            PlannedModule(
                id = id,
                sourcePath = "src/modules/$id.c",
                headerPath = "include/modules/$id.h",
                functionIds = members.map { it.id },
                globalIds = globalsByModule[id].orEmpty().map { it.id },
                boundaryEvidence = buildList {
                    add(if (members.any { overrides.containsKey(it.id) }) "user override" else "stable symbol/address grouping")
                    if (referencedModules.isNotEmpty()) add("calls modules: ${referencedModules.joinToString(", ")}")
                },
            )
        }.sortedBy { it.id }
        val owner = modules.flatMap { module -> module.functionIds.map { it to module.id } }.toMap()
        val graph = modules.associate { module -> module.id to module.functionIds.flatMap { id ->
            model.functions.single { it.id == id }.calls.mapNotNull(owner::get)
        }.filter { it != module.id }.toSet() }
        return ModulePlan(modules = modules, dependencyCycles = dependencyCycles(graph))
    }

    private fun inferredModule(function: RecoveredFunction): String {
        val meaningfulName = function.name.takeUnless { it.startsWith("FUN_") || it.startsWith("sub_") || it.startsWith("fn_") }
        val prefix = meaningfulName?.substringBefore('_')?.takeIf { it.length >= 3 }
        return safeIdentifier(prefix ?: "core")
    }

    private fun dependencyCycles(graph: Map<String, Set<String>>): List<List<String>> {
        val cycles = linkedSetOf<List<String>>()
        fun visit(node: String, path: List<String>) {
            val existing = path.indexOf(node)
            if (existing >= 0) {
                val cycle = path.drop(existing)
                val canonical = cycle.indices.map { offset -> cycle.drop(offset) + cycle.take(offset) }.minBy { it.joinToString("\u0000") }
                cycles += canonical
                return
            }
            if (path.size >= graph.size) return
            graph[node].orEmpty().sorted().forEach { visit(it, path + node) }
        }
        graph.keys.sorted().forEach { visit(it, emptyList()) }
        return cycles.sortedBy { it.joinToString("\u0000") }
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

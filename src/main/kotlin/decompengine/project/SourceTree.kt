package decompengine.project

import decompengine.repair.RepairClient
import decompengine.repair.RepairRequest
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

data class ModuleReconstructionRequest(
    val module: PlannedModule,
    val model: RecoveredProgramModel,
    val sharedHeader: String,
    val moduleHeader: String,
    val privateHeader: String,
    val dependencyHeaders: Map<String, String>,
    val observedBehavior: String? = null,
)

data class ReconstructedModule(
    val source: String,
    val generator: String,
    val promptSha256: String,
)

fun interface ModuleReconstructor {
    fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule
}

/** Uses recovered C when available and explicit stubs otherwise; useful without API access and as an LLM baseline. */
class EvidenceModuleReconstructor : ModuleReconstructor {
    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val functions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val globals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val source = buildString {
            append("#include <stddef.h>\n#include \"modules/${request.module.id}.h\"\n#include \"${request.module.id}_internal.h\"\n")
            request.dependencyHeaders.keys.sorted().forEach { header -> append("#include \"").append(header.removePrefix("include/")).append("\"\n") }
            append('\n')
            globals.forEach { global ->
                append("/* recovered global @ 0x${global.address.toString(16)} */\n")
                append(globalDeclaration(global, external = false)).append("\n\n")
            }
            functions.forEach { function ->
                append("/* ${function.id} @ 0x${function.address.toString(16)}; status=${function.status.name.lowercase()} */\n")
                val recovered = function.decompiledC?.trim()?.takeIf(String::isNotEmpty)
                if (recovered != null) append(recovered).append("\n\n")
                else append(stub(function)).append("\n\n")
            }
        }
        return ReconstructedModule(source, "evidence", sha256(source.toByteArray()))
    }

    private fun stub(function: RecoveredFunction): String {
        val prototype = normalizedPrototype(function)
        val body = if (prototype.trimStart().startsWith("void ")) "    return;" else "    return 0;"
        return "$prototype {\n$body\n}"
    }
}

class BoundedLlmModuleReconstructor(
    private val client: RepairClient,
    private val maximumContextCharacters: Int = 120_000,
) : ModuleReconstructor {
    init { require(maximumContextCharacters >= 4_096) }

    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val target = request.module.sourcePath
        val localFunctions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val evidence = localFunctions.joinToString("\n\n") { function ->
            "${function.id} @ 0x${function.address.toString(16)}\nprototype: ${function.prototype}\n" +
                "calls: ${function.calls.sorted()}\nglobals: ${function.referencedGlobals.sorted()}\n" +
                "strings: ${function.strings.sorted()}\ndecompilation:\n${function.decompiledC ?: "<unavailable>"}"
        }
        val prompt = """
            Reconstruct exactly one C implementation unit at $target.
            Preserve recovered behavior and suspicious operations. Do not invent file paths or edit headers.
            Return one complete replacement for $target. Keep provenance comments containing every function ID.

            $evidence

            Observed behavior evidence:
            ${request.observedBehavior ?: "<not yet available; report this limitation>"}
        """.trimIndent()
        val files = linkedMapOf(
            "include/decomp_types.h" to request.sharedHeader,
            request.module.headerPath to request.moduleHeader,
            "src/modules/${request.module.id}_internal.h" to request.privateHeader,
        )
            .apply { putAll(request.dependencyHeaders) }
        val contextSize = prompt.length + files.entries.sumOf { it.key.length + it.value.length }
        require(contextSize <= maximumContextCharacters) {
            "module ${request.module.id} exceeds context budget: $contextSize > $maximumContextCharacters characters"
        }
        val response = client.requestRepair(RepairRequest("module-reconstruction", prompt, files, emptyList()))
        require(response.patches.size == 1 && response.patches.single().relativePath == target) {
            "module reconstruction must replace only $target"
        }
        return ReconstructedModule(response.patches.single().replacement, "llm:${client.modelIdentifier() ?: "unspecified"}", sha256(prompt.toByteArray()))
    }
}

data class GeneratedFileEvidence(
    val path: String,
    val sha256: String,
    val generator: String,
    val promptSha256: String? = null,
    val entityIds: List<String> = emptyList(),
)

data class SourceTreeManifest(
    val schemaVersion: Int = 1,
    val inputSha256: String,
    val files: List<GeneratedFileEvidence>,
    val unresolvedEntityIds: List<String>,
) {
    val editablePaths: Set<String> get() = files.map { it.path }.filter { it == "Makefile" || it.endsWith(".c") || it.endsWith(".h") }.toSet()

    fun toJson(): String = buildString {
        append("{\n  \"schemaVersion\": ").append(schemaVersion)
        append(",\n  \"inputSha256\": \"").append(inputSha256).append("\",")
        append("\n  \"files\": [")
        append(files.sortedBy { it.path }.joinToString(",") { file ->
            """
            {
              "path": "${file.path}",
              "sha256": "${file.sha256}",
              "generator": "${file.generator}",
              "promptSha256": ${file.promptSha256?.let { "\"$it\"" } ?: "null"},
              "entityIds": [${file.entityIds.sorted().joinToString(", ") { "\"$it\"" }}]
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"unresolvedEntityIds\": [")
        append(unresolvedEntityIds.sorted().joinToString(", ") { "\"$it\"" })
        append("]\n}\n")
    }
}

object SourceTreeGenerator {
    fun generate(
        model: RecoveredProgramModel,
        projectDir: Path,
        planner: DeterministicModulePlanner = DeterministicModulePlanner(),
        reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
        overrides: Map<String, String> = emptyMap(),
        observedBehavior: String? = null,
        onModuleProgress: (completed: Int, total: Int, moduleId: String) -> Unit = { _, _, _ -> },
    ): SourceTreeManifest {
        val plan = planner.plan(model, overrides)
        val includeDir = projectDir.resolve("include").createDirectories()
        val modulesIncludeDir = includeDir.resolve("modules").createDirectories()
        val modulesSourceDir = projectDir.resolve("src/modules").createDirectories()
        val moduleReportsDir = projectDir.resolve("reports/modules").createDirectories()

        val typesHeader = renderTypesHeader(model)
        includeDir.resolve("decomp_types.h").writeText(typesHeader)
        val headers = plan.modules.associate { module -> module.id to renderModuleHeader(module, model, plan) }
        val privateHeaders = plan.modules.associate { module -> module.id to renderPrivateHeader(module, model, plan) }
        headers.forEach { (id, content) -> modulesIncludeDir.resolve("$id.h").writeText(content) }
        privateHeaders.forEach { (id, content) -> modulesSourceDir.resolve("${id}_internal.h").writeText(content) }

        val generated = mutableListOf<GeneratedFileEvidence>()
        generated += evidence("include/decomp_types.h", typesHeader, "planner", model.types.map { it.id })
        headers.forEach { (id, content) ->
            val module = plan.modules.single { it.id == id }
            generated += evidence(module.headerPath, content, "planner", module.functionIds + module.globalIds)
        }
        privateHeaders.forEach { (id, content) ->
            val module = plan.modules.single { it.id == id }
            generated += evidence("src/modules/${id}_internal.h", content, "planner", module.functionIds)
        }

        generationOrder(plan, model).forEachIndexed { index, module ->
            val dependencies = dependencyModules(module, model, plan)
            val dependencyHeaders = dependencies.associate { dependency -> plan.modules.single { it.id == dependency }.headerPath to headers.getValue(dependency) }
            val fingerprint = moduleFingerprint(module, model, typesHeader, headers.getValue(module.id), privateHeaders.getValue(module.id), dependencyHeaders)
            val sourcePath = modulesSourceDir.resolve("${module.id}.c")
            val checkpointPath = moduleReportsDir.resolve("${module.id}.json")
            val cached = readCheckpoint(checkpointPath)?.takeIf { it.fingerprint == fingerprint && sourcePath.exists() }
            val result = cached?.let { ReconstructedModule(sourcePath.readText(), it.generator, it.promptSha256) }
                ?: reconstructor.reconstruct(
                    ModuleReconstructionRequest(module, model, typesHeader, headers.getValue(module.id), privateHeaders.getValue(module.id), dependencyHeaders, observedBehavior),
                ).also { reconstructed ->
                    sourcePath.writeText(reconstructed.source.trimEnd() + "\n")
                    checkpointPath.writeText(ModuleCheckpoint(fingerprint, reconstructed.generator, reconstructed.promptSha256).toJson())
                }
            val normalizedSource = result.source.trimEnd() + "\n"
            if (!sourcePath.exists() || sourcePath.readText() != normalizedSource) sourcePath.writeText(normalizedSource)
            generated += evidence(module.sourcePath, normalizedSource, result.generator, module.functionIds + module.globalIds, result.promptSha256)
            val checkpoint = checkpointPath.readText()
            generated += evidence("reports/modules/${module.id}.json", checkpoint, "planner", module.functionIds + module.globalIds)
            onModuleProgress(index + 1, plan.modules.size, module.id)
        }

        val hasRecoveredMain = model.functions.any { safeCName(it.name) == "main" }
        if (!hasRecoveredMain) {
            val entry = model.functions.firstOrNull { safeCName(it.name) == "decomp_engine_main" } ?: model.functions.minByOrNull { it.address }
            val mainSource = """
                #include "decomp_types.h"
                ${entry?.let { "extern ${normalizedPrototype(it)};" } ?: ""}

                int main(int argc, char **argv) {
                    (void)argc;
                    (void)argv;
                    return ${entry?.let { "${safeCName(it.name)}()" } ?: "0"};
                }
            """.trimIndent() + "\n"
            projectDir.resolve("src/main.c").writeText(mainSource)
            generated += evidence("src/main.c", mainSource, "planner", listOfNotNull(entry?.id))
        }
        val sourcePaths = generated.map { it.path }.filter { it.endsWith(".c") }.sorted()
        val makefile = renderMakefile(sourcePaths)
        projectDir.resolve("Makefile").writeText(makefile)
        generated += evidence("Makefile", makefile, "planner", emptyList())

        projectDir.resolve("reports/program_model.json").writeText(model.toJson())
        projectDir.resolve("reports/module_plan.json").writeText(plan.toJson())
        generated += evidence("reports/program_model.json", model.toJson(), "analysis", model.functions.map { it.id } + model.globals.map { it.id })
        generated += evidence("reports/module_plan.json", plan.toJson(), "planner", model.functions.map { it.id } + model.globals.map { it.id })
        val confidence = renderConfidence(model, plan)
        projectDir.resolve("reports/confidence.json").writeText(confidence)
        generated += evidence("reports/confidence.json", confidence, "evidence", model.functions.map { it.id } + model.globals.map { it.id })
        val toolchain = renderToolchain()
        projectDir.resolve("reports/toolchain.json").writeText(toolchain)
        generated += evidence("reports/toolchain.json", toolchain, "environment", emptyList())
        val manifest = SourceTreeManifest(
            inputSha256 = model.inputSha256,
            files = generated,
            unresolvedEntityIds = model.functions.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.globals.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.types.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id },
        )
        projectDir.resolve("source_tree_manifest.json").writeText(manifest.toJson())
        return manifest
    }

    private fun renderTypesHeader(model: RecoveredProgramModel): String = buildString {
        append("#ifndef DECOMP_TYPES_H\n#define DECOMP_TYPES_H\n\n#include <stddef.h>\n#include <stdint.h>\n\n")
        model.types.sortedBy { it.id }.forEach { type ->
            append("/* ${type.id}; status=${type.status.name.lowercase()}")
            type.sourceAddress?.let { append("; @ 0x${it.toString(16)}") }
            append(" */\n").append(type.declaration.trim()).append("\n\n")
        }
        append("#endif\n")
    }

    private fun renderModuleHeader(module: PlannedModule, model: RecoveredProgramModel, plan: ModulePlan): String = buildString {
        val guard = "DECOMP_MODULE_${module.id.uppercase()}_H"
        append("#ifndef $guard\n#define $guard\n\n#include \"decomp_types.h\"\n\n")
        module.globalIds.map { id -> model.globals.single { it.id == id } }.forEach { global ->
            append(globalDeclaration(global, external = true)).append(" /* ${global.id} @ 0x${global.address.toString(16)} */\n")
        }
        if (module.globalIds.isNotEmpty()) append('\n')
        val owner = plan.modules.flatMap { candidate -> candidate.functionIds.map { it to candidate.id } }.toMap()
        val externallyCalled = model.functions.flatMap { caller -> caller.calls.filter { called -> owner[called] != owner[caller.id] } }.toSet()
        module.functionIds.map { id -> model.functions.single { it.id == id } }
            .filter { it.id in externallyCalled || safeCName(it.name) in setOf("main", "decomp_engine_main") }
            .forEach { function ->
            append(normalizedPrototype(function)).append("; /* ${function.id} @ 0x${function.address.toString(16)} */\n")
        }
        append("\n#endif\n")
    }

    private fun renderPrivateHeader(module: PlannedModule, model: RecoveredProgramModel, plan: ModulePlan): String = buildString {
        val guard = "DECOMP_MODULE_${module.id.uppercase()}_INTERNAL_H"
        val owner = plan.modules.flatMap { candidate -> candidate.functionIds.map { it to candidate.id } }.toMap()
        val externallyCalled = model.functions.flatMap { caller -> caller.calls.filter { called -> owner[called] != owner[caller.id] } }.toSet()
        append("#ifndef $guard\n#define $guard\n\n#include \"modules/${module.id}.h\"\n\n")
        module.functionIds.map { id -> model.functions.single { it.id == id } }
            .filterNot { it.id in externallyCalled || safeCName(it.name) in setOf("main", "decomp_engine_main") }
            .forEach { function -> append(normalizedPrototype(function)).append("; /* private ${function.id} @ 0x${function.address.toString(16)} */\n") }
        append("\n#endif\n")
    }

    private fun dependencyModules(module: PlannedModule, model: RecoveredProgramModel, plan: ModulePlan): List<String> {
        val owner = plan.modules.flatMap { candidate -> candidate.functionIds.map { it to candidate.id } }.toMap()
        return module.functionIds.flatMap { id -> model.functions.single { it.id == id }.calls }
            .mapNotNull(owner::get).filter { it != module.id }.distinct().sorted()
    }

    private fun renderMakefile(sources: List<String>): String = listOf(
        "CC ?= gcc",
        "CFLAGS ?= -std=c11 -g -Wall -Wextra -Iinclude",
        "TARGET ?= build/reconstructed",
        "SOURCES := ${sources.joinToString(" ")}",
        "ACTUAL_SOURCES := ${'$'}(sort ${'$'}(shell find src -type f -name '*.c'))",
        "EXPECTED_SOURCES := ${'$'}(sort ${'$'}(SOURCES))",
        "ifneq (${'$'}(ACTUAL_SOURCES),${'$'}(EXPECTED_SOURCES))",
        "${'$'}(error source tree contains missing or unowned C files; expected '${'$'}(EXPECTED_SOURCES)', found '${'$'}(ACTUAL_SOURCES)')",
        "endif",
        "OBJECTS := ${'$'}(SOURCES:src/%.c=build/%.o)",
        "",
        "all: ${'$'}(TARGET)",
        "",
        "${'$'}(TARGET): ${'$'}(OBJECTS)",
        "\t${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(OBJECTS) -o ${'$'}@",
        "",
        "build/%.o: src/%.c",
        "\t@mkdir -p ${'$'}(dir ${'$'}@)",
        "\t${'$'}(CC) ${'$'}(CFLAGS) -MMD -MP -c ${'$'}< -o ${'$'}@",
        "",
        "clean:",
        "\trm -rf build",
        "",
        "-include ${'$'}(OBJECTS:.o=.d)",
        ".PHONY: all clean",
    ).joinToString("\n", postfix = "\n")

    private fun evidence(path: String, content: String, generator: String, ids: List<String>, prompt: String? = null) =
        GeneratedFileEvidence(path, sha256(content.toByteArray()), generator, prompt, ids.sorted())

    private data class ModuleCheckpoint(val fingerprint: String, val generator: String, val promptSha256: String) {
        fun toJson() = "{\"fingerprint\":\"$fingerprint\",\"generator\":\"$generator\",\"promptSha256\":\"$promptSha256\"}\n"
    }

    private fun readCheckpoint(path: Path): ModuleCheckpoint? {
        if (!path.exists()) return null
        val text = path.readText()
        fun field(name: String) = Regex("\\\"$name\\\":\\\"([^\\\"]*)\\\"").find(text)?.groupValues?.get(1)
        return ModuleCheckpoint(field("fingerprint") ?: return null, field("generator") ?: return null, field("promptSha256") ?: return null)
    }

    private fun moduleFingerprint(
        module: PlannedModule,
        model: RecoveredProgramModel,
        sharedHeader: String,
        moduleHeader: String,
        privateHeader: String,
        dependencyHeaders: Map<String, String>,
    ): String {
        val functions = module.functionIds.sorted().joinToString("\n") { id ->
            val item = model.functions.single { it.id == id }
            listOf(item.id, item.name, item.address.toString(), item.prototype, item.status.name, item.decompiledC.orEmpty(),
                item.calls.sorted().joinToString(","), item.referencedGlobals.sorted().joinToString(","), item.strings.sorted().joinToString(",")).joinToString("|")
        }
        val globals = module.globalIds.sorted().joinToString("\n") { id -> model.globals.single { it.id == id }.toString() }
        val dependencies = dependencyHeaders.toSortedMap().entries.joinToString("\n") { it.key + "\n" + it.value }
        return sha256((functions + "\n" + globals + "\n" + sharedHeader + moduleHeader + privateHeader + dependencies).toByteArray())
    }

    private fun generationOrder(plan: ModulePlan, model: RecoveredProgramModel): List<PlannedModule> {
        val owner = plan.modules.flatMap { module -> module.functionIds.map { it to module.id } }.toMap()
        val dependencies = plan.modules.associate { module -> module.id to module.functionIds.flatMap { id ->
            model.functions.single { it.id == id }.calls.mapNotNull(owner::get)
        }.filter { it != module.id }.toSet() }
        val ordered = mutableListOf<String>()
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        fun visit(id: String) {
            if (id in visited || !visiting.add(id)) return
            dependencies[id].orEmpty().sorted().forEach(::visit)
            visiting.remove(id)
            visited += id
            ordered += id
        }
        plan.modules.map { it.id }.sorted().forEach(::visit)
        return ordered.map { id -> plan.modules.single { it.id == id } }
    }

    private fun renderConfidence(model: RecoveredProgramModel, plan: ModulePlan): String {
        fun score(status: RecoveryStatus) = when (status) {
            RecoveryStatus.RECOVERED -> 1.0
            RecoveryStatus.PARTIAL -> 0.6
            RecoveryStatus.SYNTHETIC -> 0.25
            RecoveryStatus.FAILED -> 0.0
        }
        val moduleScores = plan.modules.map { module ->
            val statuses = module.functionIds.map { id -> model.functions.single { it.id == id }.status } +
                module.globalIds.map { id -> model.globals.single { it.id == id }.status }
            module.id to if (statuses.isEmpty()) 0.0 else statuses.map(::score).average()
        }
        val allStatuses = model.functions.map { it.status } + model.globals.map { it.status } + model.types.map { it.status }
        val projectScore = if (allStatuses.isEmpty()) 0.0 else allStatuses.map(::score).average()
        return buildString {
            append("{\n  \"basis\": \"recovery evidence only; behavioral equivalence is not implied\",")
            append("\n  \"projectScore\": ").append("%.4f".format(java.util.Locale.ROOT, projectScore)).append(',')
            append("\n  \"modules\": [")
            append(moduleScores.sortedBy { it.first }.joinToString(",") { (id, value) ->
                "\n    {\"id\":\"$id\",\"score\":${"%.4f".format(java.util.Locale.ROOT, value)}}"
            })
            append("\n  ],\n  \"unresolvedEntityIds\": [")
            val unresolved = model.functions.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.globals.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.types.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id }
            append(unresolved.sorted().joinToString(",") { "\"$it\"" })
            append("]\n}\n")
        }
    }

    private fun renderToolchain(): String {
        fun version(command: String): String = runCatching {
            ProcessBuilder(command, "--version").redirectErrorStream(true).start().let { process ->
                val line = process.inputStream.bufferedReader().readLine().orEmpty()
                process.waitFor()
                line
            }
        }.getOrDefault("unavailable").replace("\\", "\\\\").replace("\"", "\\\"")
        return """
            {
              "decompEngineVersion": "0.1.0",
              "javaVersion": "${System.getProperty("java.version")}",
              "gcc": "${version("gcc")}",
              "make": "${version("make")}",
              "note": "LLM model and prompt hashes are recorded per generated module when applicable."
            }
        """.trimIndent() + "\n"
    }
}

internal fun normalizedPrototype(function: RecoveredFunction): String {
    val raw = normalizeGhidraTypes(function.prototype.trim().removeSuffix(";"))
    if (Regex("\\b${Regex.escape(function.name)}\\s*\\(").containsMatchIn(raw)) return raw.replaceFirst(function.name, safeCName(function.name))
    return "int ${safeCName(function.name)}(void)"
}

private fun globalDeclaration(global: RecoveredGlobal, external: Boolean): String {
    val type = normalizeGhidraTypes(global.type.trim())
    val name = safeCName(global.name)
    val array = Regex("^(.+)\\[(\\d+)]$").matchEntire(type)
    val declaration = if (array == null) "$type $name" else "${array.groupValues[1]} $name[${array.groupValues[2]}]"
    if (external) return "extern $declaration;"
    val initializer = global.initializer?.trim()?.takeIf {
        it.matches(Regex("[-+]?((0x)?[0-9a-fA-F]+|[0-9]+([uUlLfF]|[uU][lL])*)")) ||
            (it.startsWith('"') && it.endsWith('"')) || (it.startsWith('{') && it.endsWith('}'))
    } ?: "0"
    return "$declaration = $initializer;"
}

private fun normalizeGhidraTypes(value: String): String = value
    .replace(Regex("\\bundefined8\\b"), "uint64_t")
    .replace(Regex("\\bundefined4\\b"), "uint32_t")
    .replace(Regex("\\bundefined2\\b"), "uint16_t")
    .replace(Regex("\\bundefined1\\b|\\bundefined\\b|\\bbyte\\b"), "uint8_t")
    .replace(Regex("\\blonglong\\b"), "long long")

internal fun safeCName(name: String): String {
    val sanitized = name.replace(Regex("[^A-Za-z0-9_]+"), "_").ifBlank { "recovered" }
    return if (sanitized.first().isDigit()) "fn_$sanitized" else sanitized
}

object SourceTreeManifestReader {
    private val pathPattern = Regex("\\\"path\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
    fun editablePaths(projectDir: Path): Set<String> {
        val path = projectDir.resolve("source_tree_manifest.json")
        if (!path.exists()) return emptySet()
        return pathPattern.findAll(path.readText()).map { it.groupValues[1] }
            .filter { it == "Makefile" || it.endsWith(".c") || it.endsWith(".h") }.toSet()
    }
}

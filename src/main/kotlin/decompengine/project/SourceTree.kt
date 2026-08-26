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
    val dependencyHeaders: Map<String, String>,
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
            append("#include <stddef.h>\n#include \"modules/${request.module.id}.h\"\n\n")
            globals.forEach { global ->
                append("/* recovered global @ 0x${global.address.toString(16)} */\n")
                append(global.type).append(' ').append(safeCName(global.name))
                    .append(" = ").append(global.initializer ?: "0").append(";\n\n")
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
        """.trimIndent()
        val files = linkedMapOf("include/decomp_types.h" to request.sharedHeader, request.module.headerPath to request.moduleHeader)
            .apply { putAll(request.dependencyHeaders) }
        val contextSize = prompt.length + files.entries.sumOf { it.key.length + it.value.length }
        require(contextSize <= maximumContextCharacters) {
            "module ${request.module.id} exceeds context budget: $contextSize > $maximumContextCharacters characters"
        }
        val response = client.requestRepair(RepairRequest("module-reconstruction", prompt, files, emptyList()))
        require(response.patches.size == 1 && response.patches.single().relativePath == target) {
            "module reconstruction must replace only $target"
        }
        return ReconstructedModule(response.patches.single().replacement, "llm", sha256(prompt.toByteArray()))
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
    ): SourceTreeManifest {
        val plan = planner.plan(model, overrides)
        val includeDir = projectDir.resolve("include").createDirectories()
        val modulesIncludeDir = includeDir.resolve("modules").createDirectories()
        val modulesSourceDir = projectDir.resolve("src/modules").createDirectories()
        projectDir.resolve("reports").createDirectories()

        val typesHeader = renderTypesHeader(model)
        includeDir.resolve("decomp_types.h").writeText(typesHeader)
        val headers = plan.modules.associate { module -> module.id to renderModuleHeader(module, model) }
        headers.forEach { (id, content) -> modulesIncludeDir.resolve("$id.h").writeText(content) }

        val generated = mutableListOf<GeneratedFileEvidence>()
        generated += evidence("include/decomp_types.h", typesHeader, "planner", model.types.map { it.id })
        headers.forEach { (id, content) ->
            val module = plan.modules.single { it.id == id }
            generated += evidence(module.headerPath, content, "planner", module.functionIds + module.globalIds)
        }

        plan.modules.forEach { module ->
            val dependencies = dependencyModules(module, model, plan)
            val result = reconstructor.reconstruct(
                ModuleReconstructionRequest(
                    module,
                    model,
                    typesHeader,
                    headers.getValue(module.id),
                    dependencies.associate { dependency -> plan.modules.single { it.id == dependency }.headerPath to headers.getValue(dependency) },
                ),
            )
            modulesSourceDir.resolve("${module.id}.c").writeText(result.source.trimEnd() + "\n")
            generated += evidence(module.sourcePath, result.source.trimEnd() + "\n", result.generator, module.functionIds + module.globalIds, result.promptSha256)
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

    private fun renderModuleHeader(module: PlannedModule, model: RecoveredProgramModel): String = buildString {
        val guard = "DECOMP_MODULE_${module.id.uppercase()}_H"
        append("#ifndef $guard\n#define $guard\n\n#include \"decomp_types.h\"\n\n")
        module.globalIds.map { id -> model.globals.single { it.id == id } }.forEach { global ->
            append("extern ${global.type} ${safeCName(global.name)}; /* ${global.id} @ 0x${global.address.toString(16)} */\n")
        }
        if (module.globalIds.isNotEmpty()) append('\n')
        module.functionIds.map { id -> model.functions.single { it.id == id } }.forEach { function ->
            append(normalizedPrototype(function)).append("; /* ${function.id} @ 0x${function.address.toString(16)} */\n")
        }
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
}

internal fun normalizedPrototype(function: RecoveredFunction): String {
    val raw = function.prototype.trim().removeSuffix(";")
    if (Regex("\\b${Regex.escape(function.name)}\\s*\\(").containsMatchIn(raw)) return raw.replaceFirst(function.name, safeCName(function.name))
    return "int ${safeCName(function.name)}(void)"
}

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

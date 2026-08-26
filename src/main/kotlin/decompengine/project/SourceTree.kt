package decompengine.project

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.execute
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

data class ModuleReconstructionRequest(
    val module: PlannedModule,
    val model: RecoveredProgramModel,
    val sharedHeader: String,
    val moduleHeader: String,
    val privateHeader: String,
    val dependencyHeaders: Map<String, String>,
    val workspaceRoot: Path,
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

/** Emits buildable evidence stubs by default; raw recovered C remains in the program model for later refinement. */
class EvidenceModuleReconstructor(private val includeRecoveredC: Boolean = false) : ModuleReconstructor {
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
                val recovered = function.decompiledC?.trim()?.takeIf(String::isNotEmpty)?.takeIf { includeRecoveredC }
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

/** Uses already-normalized recovered C, primarily for trusted fixtures and post-normalization pipelines. */
class RecoveredCModuleReconstructor : ModuleReconstructor by EvidenceModuleReconstructor(includeRecoveredC = true)

class BoundedLlmModuleReconstructor(
    private val harness: AgentHarness,
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
        val objective = """
            Reconstruct exactly one C implementation unit at $target.
            Preserve recovered behavior and suspicious operations. Do not invent file paths or edit headers.
            Edit $target in the authorized workspace and keep provenance comments containing every function ID.
        """.trimIndent()
        val files = linkedMapOf(
            "include/decomp_types.h" to request.sharedHeader,
            request.module.headerPath to request.moduleHeader,
            "src/modules/${request.module.id}_internal.h" to request.privateHeader,
        )
            .apply { putAll(request.dependencyHeaders) }
        val observed = request.observedBehavior ?: "<not yet available; report this limitation>"
        val contextSize = objective.length + evidence.length + observed.length + files.entries.sumOf { it.key.length + it.value.length }
        require(contextSize <= maximumContextCharacters) {
            "module ${request.module.id} exceeds context budget: $contextSize > $maximumContextCharacters characters"
        }
        val workspaceRoot = request.workspaceRoot.toAbsolutePath().normalize()
        val root = AgentWorkspaceRoot("project", workspaceRoot)
        val readRules = files.keys.map { path ->
            AgentPathRule(AgentWorkspacePath(root.id, path), setOf(AgentOperation.READ_FILE))
        }
        val targetPath = AgentWorkspacePath(root.id, target)
        val sourcePath = targetPath.resolve(listOf(root))
        val before = sourcePath.takeIf { it.exists() }?.readBytes()
        try {
            val execution = harness.execute(
                AgentExecutionRequest(
                    objective = objective,
                    workspaceRoots = listOf(root),
                    contextInputs = listOf(
                        AgentContextInput("recovered-module-evidence", evidence),
                        AgentContextInput("observed-behavior", observed),
                    ),
                    accessPolicy = AgentAccessPolicy(
                        readRules + AgentPathRule(
                            targetPath,
                            setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                        ),
                    ),
                ),
            )
            require(execution.stopReason == AgentStopReason.COMPLETED) {
                "module reconstruction stopped with ${execution.stopReason.name.lowercase()}: ${execution.summary.orEmpty()}"
            }
            require(execution.changes.size == 1 && execution.changes.single().path == targetPath) {
                "module reconstruction must change only $target"
            }
            val change = execution.changes.single()
            require(change.kind != AgentFileChangeKind.DELETED) { "module reconstruction deleted $target" }
            require(sourcePath.exists()) { "module reconstruction reported $target without creating it" }
            val source = sourcePath.readText()
            val sourceBytes = source.toByteArray()
            val expectedKind = if (before == null) AgentFileChangeKind.CREATED else AgentFileChangeKind.MODIFIED
            require(change.kind == expectedKind && change.beforeSha256 == before?.let(::sha256)) {
                "module reconstruction before-state does not match $target"
            }
            require(change.afterSha256 == sha256(sourceBytes) && (change.sizeBytes == null || change.sizeBytes == sourceBytes.size.toLong())) {
                "module reconstruction result does not match $target"
            }
            val promptEvidence = listOf(objective, evidence, observed).joinToString("\n\n")
            return ReconstructedModule(
                source,
                "agent:${harness.implementationIdentifier() ?: "unspecified"}",
                sha256(promptEvidence.toByteArray()),
            )
        } catch (failure: Exception) {
            if (before == null) sourcePath.deleteIfExists() else sourcePath.writeBytes(before)
            throw failure
        }
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
                    ModuleReconstructionRequest(
                        module,
                        model,
                        typesHeader,
                        headers.getValue(module.id),
                        privateHeaders.getValue(module.id),
                        dependencyHeaders,
                        projectDir,
                        observedBehavior,
                    ),
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
            val entry = model.functions.firstOrNull { safeCName(it.name) == "decomp_engine_main" }
                ?: model.functions.firstOrNull { safeCName(it.name) in setOf("entry", "recovered__start") }
                ?: model.functions.minByOrNull { it.address }
            val entryBody = entry?.let {
                if (normalizedPrototype(it).startsWith("void ")) "${safeCName(it.name)}();\n    return 0;"
                else "return ${safeCName(it.name)}();"
            } ?: "return 0;"
            val mainSource = """
                #include "decomp_types.h"
                ${entry?.let { "extern ${normalizedPrototype(it)};" } ?: ""}

                int main(int argc, char **argv) {
                    (void)argc;
                    (void)argv;
                    $entryBody
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
        val unresolvedMarkdown = renderUnresolvedMarkdown(model)
        projectDir.resolve("UNRESOLVED.md").writeText(unresolvedMarkdown)
        generated += evidence("UNRESOLVED.md", unresolvedMarkdown, "evidence", emptyList())
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

    private fun renderUnresolvedMarkdown(model: RecoveredProgramModel): String {
        val rows = buildList {
            model.functions.filter { it.status != RecoveryStatus.RECOVERED }.forEach { add("function" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.globals.filter { it.status != RecoveryStatus.RECOVERED }.forEach { add("global" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.types.filter { it.status != RecoveryStatus.RECOVERED }.forEach { add("type" to Triple(it.id, it.status, it.sourceAddress?.let { address -> "0x${address.toString(16)}" } ?: "no address")) }
        }
        return buildString {
            append("# Unresolved reconstruction evidence\n\n")
            append("This list is evidence-bounded. The generated project does not claim universal behavioral equivalence.\n\n")
            if (rows.isEmpty()) append("No structurally unresolved entities were identified. Untested behavior remains unresolved.\n")
            else {
                append("| Kind | Stable ID | Status | Provenance |\n|---|---|---|---|\n")
                rows.sortedBy { it.second.first }.forEach { (kind, details) ->
                    append("| $kind | `${details.first}` | ${details.second.name.lowercase()} | ${details.third} |\n")
                }
            }
        }
    }
}

internal fun normalizedPrototype(function: RecoveredFunction): String {
    val raw = normalizeGhidraTypes(function.prototype.trim().removeSuffix(";"))
    val name = safeCName(function.name)
    if (name == "main") return "int main(int argc, char **argv)"
    val rawReturn = raw.substringBefore(function.name).trim()
    val decompiledReturn = function.decompiledC?.trimStart()?.substringBefore(function.name)?.trim()?.substringAfterLast('\n')?.trim()
    val returnType = decompiledReturn?.takeIf(::portableReturnType) ?: rawReturn.takeIf(::portableReturnType) ?: "int"
    return "$returnType $name(void)"
}

private fun portableReturnType(value: String): Boolean = value.matches(
    Regex("(void|char|short|int|long|float|double|size_t|u?int(8|16|32|64)_t)(\\s+long|\\s*\\*)*"),
)

private fun globalDeclaration(global: RecoveredGlobal, external: Boolean): String {
    val type = normalizeGhidraTypes(global.type.trim())
    val name = safeCName(global.name)
    val array = Regex("^(.+)\\[(\\d+)]$").matchEntire(type)
    val declaration = if (array == null) "$type $name" else "${array.groupValues[1]} $name[${array.groupValues[2]}]"
    if (external) return "extern $declaration;"
    val rawInitializer = global.initializer?.trim()?.split(Regex("\\s+"), limit = 2)?.first()
    val aggregate = array != null || !portableReturnType(type.removeSuffix(" *").trim())
    val initializer = when {
        '*' in type -> "0"
        aggregate -> rawInitializer?.takeIf { (it.startsWith('"') && it.endsWith('"')) || (it.startsWith('{') && it.endsWith('}')) } ?: "{0}"
        rawInitializer?.matches(Regex("[0-9a-fA-F]+h")) == true -> "0x${rawInitializer.dropLast(1)}"
        else -> rawInitializer?.takeIf {
        it.matches(Regex("[-+]?(0x[0-9a-fA-F]+|0|[1-9][0-9]*)([uUlLfF]|[uU][lL])?")) ||
            (it.startsWith('"') && it.endsWith('"')) || (it.startsWith('{') && it.endsWith('}'))
        } ?: if (aggregate) "{0}" else "0"
    }
    return "$declaration = $initializer;"
}

private fun normalizeGhidraTypes(value: String): String = value
    .replace(Regex("\\bundefined8\\b"), "uint64_t")
    .replace(Regex("\\bundefined4\\b"), "uint32_t")
    .replace(Regex("\\bundefined2\\b"), "uint16_t")
    .replace(Regex("\\bundefined1\\b|\\bundefined\\b|\\bbyte\\b"), "uint8_t")
    .replace(Regex("\\blonglong\\b"), "long long")
    .replace(Regex("\\bpointer\\b"), "void *")

internal fun safeCName(name: String): String {
    val sanitized = name.replace(Regex("[^A-Za-z0-9_]+"), "_").ifBlank { "recovered" }
    val collision = sanitized in setOf("_init", "_fini", "_start", "stdin", "stdout", "stderr") || sanitized.startsWith("__")
    return when {
        sanitized.first().isDigit() -> "fn_$sanitized"
        collision -> "recovered_$sanitized"
        else -> sanitized
    }
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

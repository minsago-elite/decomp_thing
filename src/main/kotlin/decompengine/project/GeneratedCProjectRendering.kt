package decompengine.project

/** Generated-C declarations and GNU Make policy; no benchmark-specific assumptions. */
internal class GeneratedCProjectRendering(private val model: RecoveredProgramModel, plan: ModulePlan) {
    private val functions = model.functions.associateBy { it.id }
    private val globals = model.globals.associateBy { it.id }
    private val externallyCalled: Set<String>

    init {
        val owners = plan.modules.flatMap { module -> module.functionIds.map { it to module.id } }.toMap()
        externallyCalled = model.functions.flatMap { caller ->
            caller.calls.filter { called -> owners[called] != owners[caller.id] }
        }.toSet()
    }

    fun renderEntrypoint(): GeneratedCEntrypoint? {
        if (model.functions.any { safeCName(it.name) == "main" }) return null
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
        return GeneratedCEntrypoint(mainSource, listOfNotNull(entry?.id))
    }

    fun renderTypesHeader(): String = buildString {
        append("#ifndef DECOMP_TYPES_H\n#define DECOMP_TYPES_H\n\n#include <stddef.h>\n#include <stdint.h>\n\n")
        model.types.sortedBy { it.id }.forEach { type ->
            append("/* ${type.id}; status=${type.status.name.lowercase()}")
            type.sourceAddress?.let { append("; @ 0x${it.toString(16)}") }
            append(" */\n").append(type.declaration.trim()).append("\n\n")
        }
        append("#endif\n")
    }

    fun renderModuleHeader(module: PlannedModule): String = buildString {
        val guard = "DECOMP_MODULE_${module.id.uppercase()}_H"
        append("#ifndef $guard\n#define $guard\n\n#include \"decomp_types.h\"\n\n")
        module.globalIds.map { id -> globals.getValue(id) }.forEach { global ->
            append(globalDeclaration(global, external = true)).append(" /* ${global.id} @ 0x${global.address.toString(16)} */\n")
        }
        if (module.globalIds.isNotEmpty()) append('\n')
        module.functionIds.map { id -> functions.getValue(id) }
            .filter { it.id in externallyCalled || safeCName(it.name) in setOf("main", "decomp_engine_main") }
            .forEach { function ->
            append(normalizedPrototype(function)).append("; /* ${function.id} @ 0x${function.address.toString(16)} */\n")
        }
        append("\n#endif\n")
    }

    fun renderPrivateHeader(module: PlannedModule): String = buildString {
        val guard = "DECOMP_MODULE_${module.id.uppercase()}_INTERNAL_H"
        append("#ifndef $guard\n#define $guard\n\n#include \"modules/${module.id}.h\"\n\n")
        module.functionIds.map { id -> functions.getValue(id) }
            .filterNot { it.id in externallyCalled || safeCName(it.name) in setOf("main", "decomp_engine_main") }
            .forEach { function -> append(normalizedPrototype(function)).append("; /* private ${function.id} @ 0x${function.address.toString(16)} */\n") }
        append("\n#endif\n")
    }

    fun renderMakefile(sources: List<String>, profile: ReconstructionProfile): String {
        val cflags = profile.adapterConfiguration["compiler-flags"]?.joinToString(" ")
            ?: "-std=c11 -g -Wall -Wextra -Werror -Iinclude"
        val cc = profile.adapterConfiguration["compiler-driver"]?.firstOrNull() ?: "gcc"
        return listOf(
            "CC ?= $cc",
            "CFLAGS ?= $cflags",
        "REPRODUCIBLE_CFLAGS := \"-ffile-prefix-map=${'$'}${'$'}PWD=.\" \"-fdebug-prefix-map=${'$'}${'$'}PWD=.\" \"-fmacro-prefix-map=${'$'}${'$'}PWD=.\"",
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
        "\t@echo \"[link] ${'$'}@\"",
        "\t@${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(REPRODUCIBLE_CFLAGS) ${'$'}(OBJECTS) -o ${'$'}@",
        "",
        "build/%.o: src/%.c",
        "\t@mkdir -p ${'$'}(dir ${'$'}@)",
        "\t@echo \"[compile] ${'$'}< -> ${'$'}@\"",
        "\t@${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(REPRODUCIBLE_CFLAGS) -MMD -MP -c ${'$'}< -o ${'$'}@",
        "",
        "clean:",
        "\trm -rf build",
        "",
        "-include ${'$'}(OBJECTS:.o=.d)",
        ".PHONY: all clean",
    ).joinToString("\n", postfix = "\n")
    }

}

internal data class GeneratedCEntrypoint(val source: String, val entityIds: List<String>)

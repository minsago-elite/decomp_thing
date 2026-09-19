package decompengine.project

/** Emits buildable evidence stubs by default; raw recovered C remains in the program model for later refinement. */
class EvidenceModuleReconstructor(private val includeRecoveredC: Boolean = false) : ModuleReconstructor {
    override fun cacheIdentity(): String = if (includeRecoveredC) "recovered-c:v2" else "evidence-only:v1"

    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val functions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val globals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val source = buildString {
            append("#include <stddef.h>\n#include \"modules/${request.module.id}.h\"\n#include \"${request.module.id}_internal.h\"\n")
            request.dependencyHeaders.keys.sorted().forEach { header -> append("#include \"").append(header.removePrefix("include/")).append("\"\n") }
            append('\n')
            globals.forEach { global ->
                append("/* ${global.id}; recovered global @ 0x${global.address.toString(16)} */\n")
                append(globalDeclaration(global, external = false)).append("\n\n")
            }
            functions.forEach { function ->
                append("/* ${function.id} @ 0x${function.address.toString(16)}; status=${function.status.name.lowercase()} */\n")
                val recovered = function.decompiledC?.trim()?.takeIf(String::isNotEmpty)?.takeIf { includeRecoveredC }
                    ?.let(::markNamedParametersUsed)
                if (recovered != null) append(recovered).append("\n\n")
                else append(stub(function)).append("\n\n")
            }
        }
        val unresolved = if (includeRecoveredC) {
            functions.filter { it.decompiledC.isNullOrBlank() }.map { function ->
                ModuleReconstructionIssue(
                    "recovered-c-unavailable",
                    "normalized recovered C is unavailable for ${function.id}",
                    listOf(function.id),
                )
            }
        } else {
            listOf(
                ModuleReconstructionIssue(
                    "evidence-only-placeholder",
                    "evidence-only mode emits placeholders and does not accept implementations",
                    request.module.functionIds + request.module.globalIds,
                ),
            ).filter { it.entityIds.isNotEmpty() }
        }
        return ReconstructedModule(
            source = source,
            generator = if (includeRecoveredC) "recovered-c" else "evidence-only",
            promptSha256 = sha256(source.toByteArray()),
            issues = unresolved,
            retryable = false,
        )
    }

    private fun stub(function: RecoveredFunction): String {
        val prototype = normalizedPrototype(function)
        val body = if (prototype.trimStart().startsWith("void ")) "    return;" else "    return 0;"
        return markNamedParametersUsed("$prototype {\n$body\n}")
    }

    /** Keep strict warning builds honest without changing recovered behavior. */
    private fun markNamedParametersUsed(source: String): String {
        val bodyStart = source.indexOf('{')
        if (bodyStart < 0) return source
        val signature = source.substring(0, bodyStart)
        val parametersStart = signature.indexOf('(')
        val parametersEnd = signature.lastIndexOf(')')
        if (parametersStart < 0 || parametersEnd <= parametersStart) return source
        val cKeywords = setOf(
            "auto", "char", "const", "double", "enum", "extern", "float", "inline", "int", "long",
            "register", "restrict", "short", "signed", "static", "struct", "typedef", "union", "unsigned",
            "void", "volatile", "_Atomic", "_Bool", "_Complex",
        )
        val names = signature.substring(parametersStart + 1, parametersEnd)
            .split(',')
            .mapNotNull { parameter ->
                Regex("([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\[[^]]*])?\\s*$")
                    .find(parameter.trim())?.groupValues?.get(1)
            }
            .filterNot(cKeywords::contains)
            .distinct()
        if (names.isEmpty()) return source
        val body = source.substring(bodyStart + 1)
        val missingUses = names.filterNot { name ->
            Regex("\\(\\s*void\\s*\\)\\s*${Regex.escape(name)}\\s*;").containsMatchIn(body)
        }
        if (missingUses.isEmpty()) return source
        return buildString(source.length + missingUses.sumOf { it.length + 14 }) {
            append(source, 0, bodyStart + 1)
            missingUses.forEach { name -> append("\n    (void)").append(name).append(';') }
            append(source, bodyStart + 1, source.length)
        }
    }
}

/** Uses already-normalized recovered C, primarily for trusted fixtures and post-normalization pipelines. */
class RecoveredCModuleReconstructor : ModuleReconstructor by EvidenceModuleReconstructor(includeRecoveredC = true)


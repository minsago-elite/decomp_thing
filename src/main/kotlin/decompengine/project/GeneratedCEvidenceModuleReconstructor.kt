package decompengine.project

/** Emits buildable evidence stubs by default; raw recovered C remains in the program model for later refinement. */
class EvidenceModuleReconstructor(private val includeRecoveredC: Boolean = false) : ModuleReconstructor {
    private val declarationContexts = GeneratedCDeclarationContextCache()
    override fun cacheIdentity(): String = if (includeRecoveredC) "recovered-c:v5" else "evidence-only:v4"

    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val declarationContext = declarationContexts.forTypes(request.model.types)
        val functions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val globals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val source = buildString {
            append("#include <stddef.h>\n#include \"modules/${request.module.id}.h\"\n#include \"${request.module.id}_internal.h\"\n")
            request.dependencyHeaders.keys.sorted().forEach { header -> append("#include \"").append(header.removePrefix("include/")).append("\"\n") }
            append('\n')
            globals.forEach { global ->
                append("/* ${global.id}; recovered global @ 0x${global.address.toString(16)} */\n")
                append(globalDeclaration(global, external = false, context = declarationContext)).append("\n\n")
            }
            functions.forEach { function ->
                append("/* ${function.id} @ 0x${function.address.toString(16)}; status=${function.status.name.lowercase()} */\n")
                val recovered = function.decompiledC?.trim()?.takeIf(String::isNotEmpty)?.takeIf { includeRecoveredC }
                    ?.let { markRecoveredParametersUsed(it, function) }
                if (recovered != null) append(recovered).append("\n\n")
                else append(stub(function, declarationContext)).append("\n\n")
            }
        }
        val unresolved = if (includeRecoveredC) {
            functions.filter { it.decompiledC.isNullOrBlank() }.map { function ->
                ModuleReconstructionIssue(
                    "recovered-c-unavailable",
                    "normalized recovered C is unavailable for ${function.id}",
                    listOf(function.id),
                )
            } + globals.filter { it.initializer != null && it.initializer.isBlank() }.map { global ->
                ModuleReconstructionIssue(
                    "global-initializer-unavailable",
                    "blank recovered initializer supplies no value evidence for ${global.id}",
                    listOf(global.id),
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

    private fun stub(function: RecoveredFunction, context: GeneratedCDeclarationContext): String {
        val declaration = recoveredDeclaration(function, context)
        require(!declaration.hasUnnamedParameters) {
            "unsupported generated-C placeholder for ${function.id}: parameter names are unavailable"
        }
        return "${declaration.prototype} {\n${declaration.placeholderBody()}\n}"
    }
}

/** Uses already-normalized recovered C, primarily for trusted fixtures and post-normalization pipelines. */
class RecoveredCModuleReconstructor : ModuleReconstructor by EvidenceModuleReconstructor(includeRecoveredC = true)

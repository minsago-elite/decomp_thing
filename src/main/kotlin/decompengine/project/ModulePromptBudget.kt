package decompengine.project

internal fun moduleClaimsAgentExecution(generator: String, reconstructorIdentity: String): Boolean =
    generator.startsWith("agent:") || generator.startsWith("unresolved:agent:") ||
        reconstructorIdentity.startsWith("agent:")

/** Accepted agent evidence must attribute a prompt bounded by the selected profile. */
internal fun modulePromptBudgetIsValid(
    promptCharacters: Long?,
    promptBudgetCharacters: Long?,
    profile: ReconstructionProfile,
): Boolean = promptCharacters != null && promptBudgetCharacters != null &&
    promptBudgetCharacters in 1..profile.budgets.reconstructionMaximumContextCharacters.toLong() &&
    promptCharacters in 0..promptBudgetCharacters

/**
 * Prompt attribution follows the fresh-result rules whenever it is recorded: results that
 * claim agent execution must attribute a prompt, and any recorded prompt metadata must
 * attribute both size and budget within the selected profile. Reusing accepted checkpoints
 * applies the same rule so legacy over-budget metadata is revalidated, not silently accepted.
 */
internal fun modulePromptAttributionIsValid(
    claimsAgentExecution: Boolean,
    promptCharacters: Long?,
    promptBudgetCharacters: Long?,
    profile: ReconstructionProfile,
): Boolean = !(claimsAgentExecution || promptCharacters != null || promptBudgetCharacters != null) ||
    modulePromptBudgetIsValid(promptCharacters, promptBudgetCharacters, profile)

internal data class ModulePromptEvidence(
    val objective: String, val evidence: String, val files: Map<String, String>,
    val observed: String, val text: String,
)

internal fun modulePromptEvidence(request: ModuleReconstructionRequest): ModulePromptEvidence {
    val target = request.module.sourcePath
    val layout = request.profile.layout
    val implementation = layout.declaration("module-implementation")
    require(target == implementation.materialize(mapOf("module" to request.module.id)) &&
        ProjectFileRole.MODULE_IMPLEMENTATION in implementation.roles &&
        ProjectFileRole.EDITABLE in implementation.roles
    ) { "planned module target must match the profile-owned editable implementation" }
    val sharedInterface = layout.declaration("shared-interface")
    val sharedInterfacePath = sharedInterface.materialize()
    requireViewableTextInterface(sharedInterface, ProjectFileRole.PUBLIC_INTERFACE)
    val moduleInterface = layout.declaration("module-interface")
    val moduleInterfacePath = moduleInterface.materialize(mapOf("module" to request.module.id))
    require(request.module.headerPath == moduleInterfacePath) {
        "planned module header must match the profile-declared module interface"
    }
    requireViewableTextInterface(moduleInterface, ProjectFileRole.PUBLIC_INTERFACE)
    val privateInterface = layout.declaration("module-private-interface")
    val privateInterfacePath = privateInterface.materialize(mapOf("module" to request.module.id))
    requireViewableTextInterface(privateInterface, ProjectFileRole.PRIVATE_INTERFACE)
    request.dependencyHeaders.keys.forEach { path ->
        val declaration = layout.declarationForPath(path)
        require(declaration.id == "module-interface") {
            "module reconstruction dependency is not a declared module interface: $path"
        }
        requireViewableTextInterface(declaration, ProjectFileRole.PUBLIC_INTERFACE)
    }
    val contextPaths = listOf(sharedInterfacePath, moduleInterfacePath, privateInterfacePath) +
        request.dependencyHeaders.keys
    require(contextPaths.distinct().size == contextPaths.size && target !in contextPaths) {
        "module reconstruction context paths must be distinct from each other and the editable target"
    }
    val prompt = ReconstructionAdapters.resolve(request.profile).modulePrompt(request)
    val objective = prompt.objective
    val evidence = prompt.evidence
    val files = linkedMapOf(
        sharedInterfacePath to request.sharedHeader,
        moduleInterfacePath to request.moduleHeader,
        privateInterfacePath to request.privateHeader,
    )
        .apply { putAll(request.dependencyHeaders) }
    val observed = request.observedBehavior ?: "<not yet available; report this limitation>"
    val promptEvidence = buildString {
        append(objective).append("\n\n").append(evidence).append("\n\n").append(observed)
        files.toSortedMap().forEach { (path, content) ->
            append("\n\n--- ").append(path).append(" ---\n").append(content)
        }
    }
    return ModulePromptEvidence(objective, evidence, files, observed, promptEvidence)
}

private fun requireViewableTextInterface(declaration: ProjectFileDeclaration, expectedRole: ProjectFileRole) {
    require(expectedRole in declaration.roles) {
        "module reconstruction context ${declaration.id} lacks its declared $expectedRole role"
    }
    require(ProjectFileRole.VIEWABLE in declaration.roles) {
        "module reconstruction context ${declaration.id} is not declared viewable"
    }
    require(declaration.contentKind == ProjectContentKind.UTF8_TEXT) {
        "module reconstruction context ${declaration.id} is not declared UTF-8 text"
    }
}

internal fun moduleDependencies(model: RecoveredProgramModel, plan: ModulePlan): Map<String, List<String>> {
    val functionById = model.functions.associateBy { it.id }
    val functionOwners = plan.modules.flatMap { module -> module.functionIds.map { it to module.id } }.toMap()
    val globalOwners = plan.modules.flatMap { module -> module.globalIds.map { it to module.id } }.toMap()
    return plan.modules.associate { module -> module.id to
        module.functionIds.flatMap { id ->
            val function = functionById.getValue(id)
            function.calls.mapNotNull(functionOwners::get) + function.referencedGlobals.mapNotNull(globalOwners::get)
        }.filter { it != module.id }.distinct().sorted()
    }
}

// Fits the bounded checkpoint document even when JSON escapes every input byte.
internal const val MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES = 512 * 1024

internal fun requireRetainableModuleObservation(observed: String?) {
    require(observed == null || observed.toByteArray(Charsets.UTF_8).size <= MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES) {
        "pre-dispatch observation exceeds the retained prompt input bound"
    }
}

/** Original renderer inputs; repaired headers are deliberately not consulted. */
internal class ProfileModulePromptInputs(
    private val model: RecoveredProgramModel,
    plan: ModulePlan,
    private val profile: ReconstructionProfile,
) {
    private val adapter = ReconstructionAdapters.resolve(profile)
    private val rendering = adapter.rendering(model, plan)
    private val modules = plan.modules.associateBy { it.id }
    private val sharedHeader = rendering.sharedInterface()
    private val headers = plan.modules.associate { it.id to rendering.moduleInterface(it) }
    private val privateHeaders = plan.modules.associate { it.id to rendering.privateInterface(it) }
    private val dependencies = moduleDependencies(model, plan)
    private val interfaceFingerprints = moduleInterfaceFingerprints(
        dependencies, headers.mapValues { sha256(it.value.toByteArray(Charsets.UTF_8)) },
    )

    fun request(moduleId: String, projectDir: java.nio.file.Path, observedBehavior: String?): ModuleReconstructionRequest {
        requireRetainableModuleObservation(observedBehavior)
        return ModuleReconstructionRequest(
            modules.getValue(moduleId), model, sharedHeader, headers.getValue(moduleId),
            privateHeaders.getValue(moduleId), dependencies.getValue(moduleId).associate { dependency ->
                modules.getValue(dependency).headerPath to headers.getValue(dependency)
            }, projectDir, observedBehavior = observedBehavior, profile = profile,
        )
    }

    fun fingerprint(request: ModuleReconstructionRequest): String {
        val localFingerprint = SourceTreeGenerator.moduleFingerprint(
            request.module, model, request.sharedHeader, request.moduleHeader, request.privateHeader,
            request.dependencyHeaders, request.observedBehavior, profile.sha256, adapter.compilation.id,
        )
        return sha256(("transitive-interfaces-v2\n" + localFingerprint + "\n" +
            interfaceFingerprints.getValue(request.module.id)).toByteArray(Charsets.UTF_8))
    }
}

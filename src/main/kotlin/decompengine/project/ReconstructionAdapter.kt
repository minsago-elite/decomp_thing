package decompengine.project

/** Local generation policy; production execution authority is a separate contract. */
internal interface ReconstructionAdapter {
    val compilation: ModuleCompilationPolicy
    fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering
    fun defaultReconstructor(): ModuleReconstructor
    fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue>
    fun toolchainEvidence(profile: ReconstructionProfile): String
}

internal interface ProjectRendering {
    fun sharedInterface(): String
    fun moduleInterface(module: PlannedModule): String
    fun privateInterface(module: PlannedModule): String
    fun entrypoint(): RenderedEntrypoint?
    fun buildDefinition(sources: List<String>, profile: ReconstructionProfile): String
}

internal data class RenderedEntrypoint(val source: String, val entityIds: List<String>)

/** Application-owned dispatch; profile data cannot register executable implementations. */
internal object ReconstructionAdapters {
    fun resolve(profile: ReconstructionProfile): ReconstructionAdapter = when (profile.id) {
        GeneratedCMakeReconstructionProfile.PROFILE_ID -> GeneratedCReconstructionAdapter
        else -> throw IllegalArgumentException("no reconstruction adapter registered for profile: ${profile.id}")
    }
}

package decompengine.project

/** Generated-C/Make implementations selected together for the registered profile. */
internal object GeneratedCReconstructionAdapter : ReconstructionAdapter {
    override val compilation: ModuleCompilationPolicy = GeneratedCModuleValidation
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering =
        GeneratedCProjectRendering(model, plan)
    override fun defaultReconstructor(): ModuleReconstructor = EvidenceModuleReconstructor()
    override fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue> =
        GeneratedCCandidateValidation.assess(module, model, generator, source)
    override fun toolchainEvidence(profile: ReconstructionProfile): String = GeneratedCToolchainEvidence.render(profile)
}

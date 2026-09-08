package decompengine.project

import java.nio.file.Path

/** Generated-C/Make implementations selected together for the registered profile. */
internal object GeneratedCReconstructionAdapter : ReconstructionAdapter {
    override val compilation: ModuleCompilationPolicy = GeneratedCModuleValidation
    override val archiveBuild: ArchiveBuildPolicy = GeneratedCArchiveBuildPolicy
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering =
        GeneratedCProjectRendering(model, plan)
    override fun build(projectDir: Path, profile: ReconstructionProfile): BuildReport = MakeProjectBuilder.build(
        projectDir,
        ProjectBuildConfiguration(
            makeExecutable = profile.adapterConfiguration["build-executable"]?.singleOrNull() ?: "make",
            compilerExecutable = profile.adapterConfiguration["compiler-driver"]?.singleOrNull() ?: "gcc",
            cFlags = profile.adapterConfiguration["compiler-flags"] ?: ProjectBuildConfiguration().cFlags,
            wallClockTimeoutMillis = profile.budgets.buildWallClockMillis,
            maximumOutputBytes = profile.budgets.buildMaximumOutputBytes,
            buildDefinition = profile.layout.declaration("build-definition").materialize(),
        ),
        profile,
    )
    override fun defaultReconstructor(): ModuleReconstructor = EvidenceModuleReconstructor()
    override fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue> =
        GeneratedCCandidateValidation.assess(module, model, generator, source)
    override fun toolchainEvidence(profile: ReconstructionProfile): String = GeneratedCToolchainEvidence.render(profile)
}

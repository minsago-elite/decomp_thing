package decompengine.project

import java.nio.file.Path

internal object GeneratedCNinjaReconstructionAdapter : ReconstructionAdapter by GeneratedCReconstructionAdapter {
    override val diagnostics: ToolchainDiagnosticPolicy = GeneratedCToolchainDiagnostics("ninja", "Ninja")
    override val archiveBuild: ArchiveBuildPolicy = GeneratedCNinjaArchiveBuildPolicy
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering =
        GeneratedCNinjaProjectRendering(model, plan)
    private fun configuration(profile: ReconstructionProfile, parallelism: Int) = ProjectBuildConfiguration(
        parallelism = parallelism,
        compilerExecutable = profile.adapterConfiguration.getValue("compiler-driver").single(),
        cFlags = profile.adapterConfiguration.getValue("compiler-flags"),
        wallClockTimeoutMillis = profile.budgets.buildWallClockMillis,
        maximumOutputBytes = profile.budgets.buildMaximumOutputBytes,
        buildDefinition = profile.layout.declaration("build-definition").materialize(),
    )

    internal fun invocation(profile: ReconstructionProfile, parallelism: Int): GeneratedCBuildInvocation {
        val configuration = configuration(profile, parallelism)
        val command = listOf(profile.adapterConfiguration.getValue("build-executable").single(),
            "-f", configuration.buildDefinition, "-j", configuration.parallelism.toString())
        return GeneratedCBuildInvocation(command,
            listOf("Ninja", "C compiler (${configuration.compilerExecutable})", "POSIX shell", "POSIX find", "POSIX sort", "POSIX tr"),
            "The build requires Ninja, the configured C compiler `${configuration.compilerExecutable}`, a POSIX shell, find, sort and tr. Warnings are errors and file/macro/debug paths are mapped to the project root. No Make invocation, API credentials, network access or analysis caches are required. Per-module diagnostics and the source-bound build contract are under `reports/`.")
    }

    override fun build(
        projectDir: Path,
        profile: ReconstructionProfile,
        hostSafetyLimits: ReconstructionHostSafetyLimits,
    ): BuildReport {
        val configuration = configuration(profile, 4)
        return GeneratedCProjectBuilder.build(
            projectDir, configuration, profile, invocation(profile, configuration.parallelism), hostSafetyLimits,
        )
    }
}

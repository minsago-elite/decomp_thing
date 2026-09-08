package decompengine.project

import java.nio.file.Path

internal object GeneratedCNinjaReconstructionAdapter : ReconstructionAdapter by GeneratedCReconstructionAdapter {
    override val archiveBuild: ArchiveBuildPolicy = object : ArchiveBuildPolicy by GeneratedCArchiveBuildPolicy {
        override val rebuildInstructions = "Build with the exact Ninja command in `BUILDING.md`. Source, build and module evidence are retained under `reports/`."
    }
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering =
        GeneratedCNinjaProjectRendering(model, plan)
    override fun build(projectDir: Path, profile: ReconstructionProfile): BuildReport {
        val configuration = ProjectBuildConfiguration(
            compilerExecutable = profile.adapterConfiguration.getValue("compiler-driver").single(),
            cFlags = profile.adapterConfiguration.getValue("compiler-flags"),
            wallClockTimeoutMillis = profile.budgets.buildWallClockMillis,
            maximumOutputBytes = profile.budgets.buildMaximumOutputBytes,
            buildDefinition = profile.layout.declaration("build-definition").materialize(),
        )
        val command = listOf(profile.adapterConfiguration.getValue("build-executable").single(),
            "-f", configuration.buildDefinition, "-j", configuration.parallelism.toString())
        val invocation = GeneratedCBuildInvocation(command,
            listOf("Ninja", "C compiler (${configuration.compilerExecutable})", "POSIX shell", "POSIX find", "POSIX sort", "POSIX tr"),
            "The build requires Ninja, the configured C compiler `${configuration.compilerExecutable}`, a POSIX shell, find, sort and tr. Warnings are errors and file/macro/debug paths are mapped to the project root. No Make invocation, API credentials, network access or analysis caches are required. Per-module diagnostics and the source-bound build contract are under `reports/`.")
        return GeneratedCProjectBuilder.build(projectDir, configuration, profile, invocation)
    }
}

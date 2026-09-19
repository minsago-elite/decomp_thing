package decompengine.project

import decompengine.repair.readStableRegularFile
import java.nio.file.Path

internal object GeneratedCNinjaReconstructionAdapter : ReconstructionAdapter by GeneratedCReconstructionAdapter {
    override val diagnostics: ToolchainDiagnosticPolicy = GeneratedCToolchainDiagnostics("ninja", "Ninja")
    override val archiveBuild: ArchiveBuildPolicy = GeneratedCNinjaArchiveBuildPolicy
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering =
        GeneratedCNinjaProjectRendering(model, plan)
    private fun configuration(profile: ReconstructionProfile, parallelism: Int) = ProjectBuildConfiguration(
        makeExecutable = profile.adapterConfiguration.getValue("build-executable").single(),
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
        requireBuildDefinitionBindsConfiguration(projectDir, profile, configuration)
        return GeneratedCProjectBuilder.build(
            projectDir, configuration, profile, invocation(profile, configuration.parallelism), hostSafetyLimits,
        )
    }

    internal fun requireBuildDefinitionBindsConfiguration(
        projectDir: Path,
        profile: ReconstructionProfile,
        configuration: ProjectBuildConfiguration = configuration(profile, 4),
    ) {
        val expectedCompiler = profile.adapterConfiguration.getValue("compiler-driver").single()
        val expectedFlags = profile.adapterConfiguration.getValue("compiler-flags").joinToString(" ")
        val definition = projectDir.resolve(configuration.buildDefinition)
        if (!java.nio.file.Files.isRegularFile(definition, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return
        val ceiling = minOf(configuration.maximumOutputBytes, Int.MAX_VALUE.toLong() - 1L)
        require(ceiling >= 1L) { "build output ceiling is invalid" }
        val size = java.nio.file.Files.size(definition)
        require(size in 1..ceiling) {
            "Ninja build definition exceeds the admitted build output bound ($size bytes; limit=$ceiling)"
        }
        val text = readStableRegularFile(projectDir, configuration.buildDefinition, ceiling).bytes
            .toString(Charsets.UTF_8)
        require(text.lineSequence().none { it.substringBefore('#').trimStart().startsWith("include ") || it.substringBefore('#').trimStart().startsWith("subninja ") }) {
            "Ninja build definitions must not include external files"
        }
        require(text.isNotEmpty()) { "Ninja build definition must not be empty" }
        require(text.toByteArray(Charsets.UTF_8).size <= ceiling) {
            "Ninja build definition exceeds the admitted build output bound"
        }

        val assignments = text.lineSequence().mapNotNull { line ->
            NINJA_ASSIGNMENT.matchEntire(line)?.let { match ->
                match.groupValues[1] to match.groupValues[2].trim()
            }
        }.groupBy({ it.first }, { it.second })
        require(assignments["cc"] == listOf(expectedCompiler)) {
            "Ninja build definition compiler differs from the selected profile or is overridden"
        }
        require(assignments["cflags"] == listOf(expectedFlags)) {
            "Ninja build definition flags differ from the selected profile or are overridden"
        }
    }

    private val NINJA_ASSIGNMENT = Regex("^\\s*(cc|cflags)\\s*=\\s*(.*?)\\s*$")
}

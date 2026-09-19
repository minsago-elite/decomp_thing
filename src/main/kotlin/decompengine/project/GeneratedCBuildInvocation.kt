package decompengine.project

import java.nio.file.Path

/** Application-owned command and dependency description for a generated-C build. */
internal data class GeneratedCBuildInvocation(
    val command: List<String>,
    val dependencies: List<String>,
    val instructions: String,
) {
    companion object {
        fun make(configuration: ProjectBuildConfiguration) = GeneratedCBuildInvocation(
            configuration.command(),
            listOf("GNU Make", "C compiler (${configuration.compilerExecutable})", "POSIX shell", "POSIX find", "POSIX mkdir", "POSIX rm"),
            """The build requires GNU Make, the configured C compiler `${configuration.compilerExecutable}`, a POSIX shell, and the POSIX `find`, `mkdir`, and `rm` utilities. `-Werror` is mandatory. The generated Makefile maps file, macro, and debug paths to a project-relative root so identical accepted source revisions do not retain workstation paths. The build does not require analysis caches, network access, or API credentials. Per-module compiler diagnostics are written under `reports/build/modules/`; `reports/build_contract.json` maps every source to its owning module.""",
        )
    }
}

/** Compatibility entry point for existing generated-C/Make callers. */
object MakeProjectBuilder {
    fun build(projectDir: Path, configuration: ProjectBuildConfiguration = ProjectBuildConfiguration(),
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor): BuildReport =
        GeneratedCProjectBuilder.build(projectDir, configuration, profile)
    internal fun terminateBuildProcess(process: Process, graceMillis: Long) =
        GeneratedCProjectBuilder.terminateBuildProcess(process, graceMillis)
    internal fun sanitizeBuildEnvironment(environment: MutableMap<String, String>) =
        GeneratedCProjectBuilder.sanitizeBuildEnvironment(environment)
}

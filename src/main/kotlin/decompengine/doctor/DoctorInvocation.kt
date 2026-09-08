package decompengine.doctor

import decompengine.acp.AcpPreflightWorkflow
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import java.nio.file.Path

internal data class DoctorInvocation(val options: DoctorOptions, val profile: ReconstructionProfile)

/** Parses selections without inspecting the environment, probing tools, or creating output. */
internal fun parseDoctorInvocation(args: List<String>, defaultOutput: Path): DoctorInvocation {
    var toolsOnly = false
    var harnessOverride: String? = null
    var workflowOverride: AcpPreflightWorkflow? = null
    var output = defaultOutput
    var profile = ReconstructionProfiles.default
    var index = 0
    fun nextValue(message: String): String = args.getOrNull(index + 1)
        ?: throw IllegalArgumentException(message)

    while (index < args.size) {
        when (args[index]) {
            "--tools-only" -> {
                toolsOnly = true
                index++
            }
            "--harness" -> {
                harnessOverride = nextValue("--harness requires acp or legacy-openai")
                index += 2
            }
            "--workflow" -> {
                workflowOverride = AcpPreflightWorkflow.parse(
                    nextValue("--workflow requires all, patch, reconstruct, repair, or web"),
                )
                index += 2
            }
            "--output" -> {
                output = Path.of(nextValue("--output requires a directory"))
                index += 2
            }
            "--profile" -> {
                profile = ReconstructionProfiles.named(nextValue("--profile requires a profile id"))
                index += 2
            }
            else -> throw IllegalArgumentException("unexpected argument: ${args[index]}")
        }
    }
    require(!toolsOnly || harnessOverride == null) { "--tools-only cannot be combined with --harness" }
    require(!toolsOnly || workflowOverride == null) { "--tools-only cannot be combined with --workflow" }
    return DoctorInvocation(
        DoctorOptions(
            outputDir = output,
            toolsOnly = toolsOnly,
            harnessOverride = harnessOverride,
            workflowOverride = workflowOverride,
        ),
        profile,
    )
}

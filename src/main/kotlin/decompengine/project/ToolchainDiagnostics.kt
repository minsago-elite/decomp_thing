package decompengine.project

import decompengine.doctor.CommandProbe
import decompengine.doctor.DoctorCheck

/** Application-owned toolchain diagnostics prepared before commands or temporary files are used. */
internal interface ToolchainDiagnosticPolicy {
    fun prepare(profile: ReconstructionProfile): PreparedToolchainDiagnostics
}

internal interface PreparedToolchainDiagnostics {
    val versionProbes: List<ToolchainVersionProbe>
    fun checkCapabilities(commandProbe: CommandProbe): List<DoctorCheck>
}

internal data class ToolchainVersionProbe(
    val name: String,
    val command: List<String>,
    val remediation: String,
)

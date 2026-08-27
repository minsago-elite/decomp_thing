package decompengine.acp

import java.nio.file.Path
import java.time.Duration

enum class AcpHarnessKind { DIRECT, ACP }

data class AcpHarnessSelection(
    val kind: AcpHarnessKind,
    val configuration: AcpProcessConfiguration?,
)

object AcpHarnessFactory {
    fun fromEnvironment(environment: Map<String, String> = System.getenv()): AcpHarnessSelection {
        val harness = environment["ACP_HARNESS"]?.trim()?.lowercase() ?: return AcpHarnessSelection(AcpHarnessKind.DIRECT, null)
        if (harness != "acp") return AcpHarnessSelection(AcpHarnessKind.DIRECT, null)
        val executableText = environment["ACP_AGENT_EXECUTABLE"]?.trim() ?: throw IllegalArgumentException("ACP_AGENT_EXECUTABLE is required when ACP_HARNESS=acp")
        require(executableText.isNotBlank()) { "ACP_AGENT_EXECUTABLE must not be blank" }
        val executable = Path.of(executableText).toAbsolutePath().normalize()
        require(executable.isAbsolute) { "ACP executable must be absolute: $executable" }
        val argsText = environment["ACP_AGENT_ARGS"]?.trim() ?: ""
        val arguments = if (argsText.isBlank()) emptyList() else argsText.split(" ").filter { it.isNotBlank() }
        require(arguments.none { '\u0000' in it }) { "ACP argv must not contain NUL" }
        val permissionMode = environment["ACP_PERMISSION_MODE"]?.trim() ?: "default-deny"
        require(permissionMode == "default-deny") { "unknown ACP_PERMISSION_MODE: $permissionMode (expected default-deny)" }
        val decider: AcpPermissionDecider = AcpNonInteractivePermissionDecider.DEFAULT_DENY
        val timeoutText = environment["ACP_TIMEOUT_SECONDS"]?.trim()
        val timeouts = if (timeoutText != null && timeoutText.isNotBlank()) {
            val seconds = timeoutText.toLongOrNull() ?: throw IllegalArgumentException("ACP_TIMEOUT_SECONDS must be a number")
            require(seconds in 1..3600) { "ACP timeout out of range" }
            AcpLifecycleTimeouts(request = Duration.ofSeconds(seconds))
        } else AcpLifecycleTimeouts()
        val config = AcpProcessConfiguration(
            executable = executable,
            arguments = arguments,
            environment = emptyMap(),
            inheritParentEnvironment = false,
            timeouts = timeouts,
            permissionDecider = decider,
            implementationId = "acp-v1-${executable.fileName}",
        )
        return AcpHarnessSelection(AcpHarnessKind.ACP, config)
    }

    fun requireAcp(environment: Map<String, String> = System.getenv()): AcpProcessConfiguration {
        val selection = fromEnvironment(environment)
        require(selection.kind == AcpHarnessKind.ACP && selection.configuration != null) { "ACP harness not configured; set ACP_HARNESS=acp and ACP_AGENT_EXECUTABLE" }
        return selection.configuration
    }
}

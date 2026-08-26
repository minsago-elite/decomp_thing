package decompengine.acp

import java.nio.file.Path
import java.time.Duration
import java.util.Collections

/** The exact Maven Central release used for stable ACP v1 bindings and JSON-RPC plumbing. */
const val ACP_KOTLIN_SDK_VERSION: String = "0.30.1"

/** ACP v2 is a draft and is deliberately not included in this client's supported-version set. */
const val ACP_STABLE_PROTOCOL_VERSION: Int = 1

enum class AcpRequiredAgentCapability(val diagnosticName: String) {
    LOAD_SESSION("loadSession"),
    PROMPT_IMAGE("promptCapabilities.image"),
    PROMPT_AUDIO("promptCapabilities.audio"),
    PROMPT_EMBEDDED_CONTEXT("promptCapabilities.embeddedContext"),
    MCP_HTTP("mcpCapabilities.http"),
    MCP_SSE("mcpCapabilities.sse"),
    ADDITIONAL_DIRECTORIES("sessionCapabilities.additionalDirectories"),
}

data class AcpLifecycleTimeouts(
    val startup: Duration = Duration.ofSeconds(20),
    val request: Duration = Duration.ofMinutes(20),
    val cancellationGrace: Duration = Duration.ofSeconds(2),
    val transportDrainGrace: Duration = Duration.ofMillis(100),
    val shutdown: Duration = Duration.ofSeconds(5),
) {
    init {
        requirePositiveMillis("startup", startup)
        requirePositiveMillis("request", request)
        requirePositiveMillis("cancellation grace", cancellationGrace)
        requirePositiveMillis("transport drain grace", transportDrainGrace)
        requirePositiveMillis("shutdown", shutdown)
    }
}

/**
 * Subprocess settings for one ACP execution.
 *
 * [executable] is required to be an absolute normalized path. [arguments] are passed directly to
 * [ProcessBuilder], never through a shell. When [inheritParentEnvironment] is false, the child sees
 * only [environment].
 */
class AcpProcessConfiguration(
    val executable: Path,
    arguments: Collection<String> = emptyList(),
    environment: Map<String, String> = emptyMap(),
    val inheritParentEnvironment: Boolean = true,
    requiredAgentCapabilities: Collection<AcpRequiredAgentCapability> = emptySet(),
    val timeouts: AcpLifecycleTimeouts = AcpLifecycleTimeouts(),
    val maximumFrameBytes: Int = 1024 * 1024,
    val maximumStderrBytes: Int = 256 * 1024,
    val implementationId: String = "acp-v1",
) {
    val arguments: List<String> = Collections.unmodifiableList(ArrayList(arguments))
    val environment: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(environment))
    val requiredAgentCapabilities: Set<AcpRequiredAgentCapability> =
        Collections.unmodifiableSet(LinkedHashSet(requiredAgentCapabilities))

    init {
        require(executable.isAbsolute) { "ACP executable must be an absolute path: $executable" }
        require(executable == executable.normalize()) { "ACP executable must be normalized: $executable" }
        require(executable.toString().isNotBlank()) { "ACP executable must not be blank" }
        require(this.arguments.none { '\u0000' in it }) { "ACP argv must not contain NUL" }
        require(this.environment.keys.all { it.isNotBlank() && '=' !in it && '\u0000' !in it }) {
            "ACP environment variable names must be non-empty and must not contain '=' or NUL"
        }
        require(this.environment.values.none { '\u0000' in it }) { "ACP environment values must not contain NUL" }
        require(maximumFrameBytes > 0) { "maximum ACP frame size must be positive" }
        require(maximumStderrBytes > 0) { "maximum ACP stderr capture must be positive" }
        require(implementationId.isNotBlank()) { "ACP implementation id must not be blank" }
    }

    internal fun command(): List<String> = listOf(executable.toString()) + arguments
}

data class AcpProcessDiagnostics(
    val pid: Long,
    val exitCode: Int?,
    val stderr: String,
    val stderrTruncated: Boolean,
    val forcedTermination: Boolean,
    val rootTerminationRequested: Boolean,
    val remainingProcessIds: List<Long>,
)

private fun requirePositiveMillis(name: String, duration: Duration) {
    require(!duration.isZero && !duration.isNegative && duration.toMillis() > 0) {
        "$name timeout must be at least one millisecond"
    }
}

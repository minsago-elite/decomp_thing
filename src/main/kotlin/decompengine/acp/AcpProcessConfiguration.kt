package decompengine.acp

import java.nio.file.Path
import java.time.Duration
import java.util.Collections

/** The exact Maven Central release used for stable ACP v1 bindings and JSON-RPC plumbing. */
const val ACP_KOTLIN_SDK_VERSION: String = "0.30.1"

/** ACP v2 is a draft and is deliberately not included in this client's supported-version set. */
const val ACP_STABLE_PROTOCOL_VERSION: Int = 1

/** Keeps the SDK's internally unbounded message channels behind a finite adapter boundary. */
internal const val DEFAULT_MAXIMUM_ACP_PROTOCOL_FRAMES: Int = 1_024
internal const val MAXIMUM_ACP_PROTOCOL_FRAMES: Int = 4_096

enum class AcpRequiredAgentCapability(val diagnosticName: String) {
    LOAD_SESSION("loadSession"),
    PROMPT_IMAGE("promptCapabilities.image"),
    PROMPT_AUDIO("promptCapabilities.audio"),
    PROMPT_EMBEDDED_CONTEXT("promptCapabilities.embeddedContext"),
    MCP_HTTP("mcpCapabilities.http"),
    MCP_SSE("mcpCapabilities.sse"),
    ADDITIONAL_DIRECTORIES("sessionCapabilities.additionalDirectories"),
}

enum class AcpEnvironmentProvenance {
    PUBLIC,
    SECRET,
}

/** Explicit provenance is mandatory; no variable name is treated as a reliable secret oracle. */
data class AcpEnvironmentValue(
    val value: String,
    val provenance: AcpEnvironmentProvenance,
) {
    init {
        require('\u0000' !in value) { "ACP environment values must not contain NUL" }
    }
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
 * the verified process boundary, never through a shell. Public harness execution requires
 * [sandboxBoundary] and never inherits the parent environment. Each explicit environment value
 * carries trusted provenance so raw secret bytes can be excluded from terminal authority.
 */
class AcpProcessConfiguration(
    val executable: Path,
    arguments: Collection<String> = emptyList(),
    environment: Map<String, AcpEnvironmentValue> = emptyMap(),
    val inheritParentEnvironment: Boolean = false,
    requiredAgentCapabilities: Collection<AcpRequiredAgentCapability> = emptySet(),
    val timeouts: AcpLifecycleTimeouts = AcpLifecycleTimeouts(),
    val maximumFrameBytes: Int = 1024 * 1024,
    val maximumProtocolFrames: Int = DEFAULT_MAXIMUM_ACP_PROTOCOL_FRAMES,
    val maximumStderrBytes: Int = 256 * 1024,
    val implementationId: String = "acp-v1",
    val filesystemLimits: AcpFilesystemLimits = AcpFilesystemLimits(),
    val sandboxBoundary: AcpLinuxSandboxConfiguration? = null,
    val terminalPolicy: AcpTerminalExecutionPolicy? = null,
    val permissionDecider: AcpPermissionDecider = AcpNonInteractivePermissionDecider.DEFAULT_DENY,
    /** Required when [executable] is not recursively root-owned and immutable. */
    val expectedExecutableManifestSha256: String? = null,
) {
    val arguments: List<String> = Collections.unmodifiableList(
        ArrayList(requireBoundedProcessArguments(arguments)),
    )
    val environment: Map<String, AcpEnvironmentValue> = Collections.unmodifiableMap(
        LinkedHashMap(requireBoundedProcessEnvironment(environment)),
    )
    val requiredAgentCapabilities: Set<AcpRequiredAgentCapability> =
        Collections.unmodifiableSet(LinkedHashSet(requiredAgentCapabilities))

    init {
        require(executable.isAbsolute) { "ACP executable must be an absolute path: $executable" }
        require(executable == executable.normalize()) { "ACP executable must be normalized: $executable" }
        require(executable.toString().isNotBlank()) { "ACP executable must not be blank" }
        require(this.arguments.none { '\u0000' in it }) { "ACP argv must not contain NUL" }
        require(this.environment.keys.all { it.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) }) {
            "ACP environment variable names must use portable [A-Za-z_][A-Za-z0-9_]* syntax"
        }
        require(maximumFrameBytes > 0) { "maximum ACP frame size must be positive" }
        require(maximumProtocolFrames in 1..MAXIMUM_ACP_PROTOCOL_FRAMES) {
            "maximum ACP protocol frames must be between 1 and $MAXIMUM_ACP_PROTOCOL_FRAMES"
        }
        require(maximumStderrBytes > 0) { "maximum ACP stderr capture must be positive" }
        require(implementationId.isNotBlank()) { "ACP implementation id must not be blank" }
        require(sandboxBoundary == null || !inheritParentEnvironment) {
            "sandboxed ACP execution must start from a cleared, explicitly configured environment"
        }
        require(terminalPolicy == null || sandboxBoundary != null) {
            "ACP terminal policy requires the production Linux sandbox boundary"
        }
        expectedExecutableManifestSha256?.let { digest ->
            require(digest.matches(Regex("[0-9a-f]{64}"))) {
                "expected ACP executable manifest digest must be a lowercase SHA-256 value"
            }
        }
    }

    internal fun command(): List<String> = listOf(executable.toString()) + arguments

    internal fun environmentValues(): Map<String, String> = environment.mapValues { (_, binding) -> binding.value }
}

data class AcpProcessDiagnostics(
    val pid: Long,
    val exitCode: Int?,
    val stderr: String,
    val stderrTruncated: Boolean,
    /** Saturating count of bytes consumed from the agent's stdout and stderr pipes. */
    val producedOutputBytes: Long,
    val producedOutputLimitBytes: Long,
    val outputLimitExceeded: Boolean,
    val forcedTermination: Boolean,
    val rootTerminationRequested: Boolean,
    val remainingProcessIds: List<Long>,
    val containment: String,
    val networkIsolated: Boolean,
    val sandboxCleanupVerified: Boolean,
)

private fun requirePositiveMillis(name: String, duration: Duration) {
    require(!duration.isZero && !duration.isNegative && duration.toMillis() > 0) {
        "$name timeout must be at least one millisecond"
    }
}

private fun requireBoundedProcessArguments(arguments: Collection<String>): Collection<String> {
    require(arguments.size < MAXIMUM_SANDBOX_ARGUMENTS) {
        "ACP argv exceeds the authenticated argument-count limit"
    }
    var encodedBytes = 0L
    arguments.forEach { argument ->
        encodedBytes = Math.addExact(encodedBytes, utf8Length(argument) + 1L)
        require(encodedBytes <= MAXIMUM_SANDBOX_ARGUMENT_BYTES) {
            "ACP argv exceeds the authenticated byte limit"
        }
    }
    return arguments
}

private fun requireBoundedProcessEnvironment(
    environment: Map<String, AcpEnvironmentValue>,
): Map<String, AcpEnvironmentValue> {
    require(environment.size <= MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS) {
        "ACP environment exceeds the authenticated binding-count limit"
    }
    var encodedBytes = 0L
    environment.forEach { (name, binding) ->
        encodedBytes = Math.addExact(
            encodedBytes,
            utf8Length(name) + utf8Length(binding.value) + 2L,
        )
        require(encodedBytes <= MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            "ACP environment exceeds the authenticated byte limit"
        }
    }
    return environment
}

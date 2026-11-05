package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class KotlinContainedCommandRequest(
    val runDirectory: Path,
    val nonce: String,
    command: List<String>,
    environment: Map<String, String>,
    val maximumStartWaitSeconds: Long,
    val maximumWallSeconds: Long,
    val maximumStdoutBytes: Long,
    val maximumStderrBytes: Long,
    val allowInterruption: Boolean = false,
    val terminalResourcePolicySha256: String? = null,
    val retainedInputVisibilitySha256: String? = null,
    val fileDescriptorPolicy: ContainedCommandFileDescriptorPolicy? = null,
) {
    val command: List<String>
    val environment: Map<String, String>
    val fileDescriptorPolicySha256: String? = fileDescriptorPolicy?.sha256
    val maximumOpenFiles: Long? = fileDescriptorPolicy?.maximumOpenFiles
    private val encoded: ByteArray
    val canonicalBytes: ByteArray get() = encoded.copyOf()
    val sha256: String

    init {
        requireContainedCommandPath(runDirectory)
        require(nonce.matches(CONTAINED_SHA256)) { "contained command nonce is invalid" }
        val copied = arrayListOf<String>()
        for (argument in command) {
            require(copied.size < 512) { "contained command argument count is outside its bound" }
            copied.add(argument)
        }
        this.command = java.util.List.copyOf(copied)
        require(environment.size == 3) { "contained command environment differs from its fixed contract" }
        this.environment = java.util.Map.copyOf(environment)
        require(this.command.size in 2..512) { "contained command argument count is outside its bound" }
        var commandBytes = 0L
        for (argument in this.command) {
            val size = argument.toByteArray(Charsets.UTF_8).size
            require(size in 1..65536 && argument.none { it.code < 32 || it.code == 127 }) {
                "contained command argument is invalid"
            }
            commandBytes += size + 1L
            require(commandBytes <= 65536L) { "contained command exceeds its byte bound" }
        }
        val executable = Path.of(this.command.first())
        requireContainedCommandPath(executable)
        require(executable.fileName.toString() == "java" && !executable.startsWith(runDirectory)) {
            "contained command requires an external authenticated Java executable"
        }
        require(this.environment == mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC")) {
            "contained command environment differs from its fixed contract"
        }
        require(maximumStartWaitSeconds in 1L..300L && maximumWallSeconds in 1L..86400L) {
            "contained command time budget is outside its bound"
        }
        require(maximumStdoutBytes in 1L..MAXIMUM_LOG_BYTES && maximumStderrBytes in 1L..MAXIMUM_LOG_BYTES) {
            "contained command log budget is outside its bound"
        }
        val version = containedCommandRequestVersion(allowInterruption,
            terminalResourcePolicySha256, retainedInputVisibilitySha256, fileDescriptorPolicy)
        val fields = mapOf(
            "schemaVersion" to JsonPrimitive(version),
            "provider" to JsonPrimitive("kotlin-contained-command-request-v$version"),
            "runDirectory" to JsonPrimitive(runDirectory.toString()),
            "nonce" to JsonPrimitive(nonce),
            "command" to JsonArray(this.command.map(::JsonPrimitive)),
            "environment" to JsonObject(this.environment.mapValues { JsonPrimitive(it.value) }),
            "maximumStartWaitSeconds" to JsonPrimitive(maximumStartWaitSeconds),
            "maximumWallSeconds" to JsonPrimitive(maximumWallSeconds),
            "maximumStdoutBytes" to JsonPrimitive(maximumStdoutBytes),
            "maximumStderrBytes" to JsonPrimitive(maximumStderrBytes),
        )
        encoded = OracleJson.canonicalBytes(JsonObject(fields + when {
            fileDescriptorPolicy != null -> mapOf(
                "allowInterruption" to JsonPrimitive(allowInterruption),
                "terminalResourcePolicySha256" to JsonPrimitive(checkNotNull(terminalResourcePolicySha256)),
                "fileDescriptorPolicySha256" to JsonPrimitive(checkNotNull(fileDescriptorPolicySha256)),
                "maximumOpenFiles" to JsonPrimitive(checkNotNull(maximumOpenFiles)),
            ) + (retainedInputVisibilitySha256?.let {
                mapOf("retainedInputVisibilitySha256" to JsonPrimitive(it))
            } ?: emptyMap())
            retainedInputVisibilitySha256 != null -> mapOf("allowInterruption" to JsonPrimitive(allowInterruption),
                "retainedInputVisibilitySha256" to JsonPrimitive(retainedInputVisibilitySha256))
            else -> (if (allowInterruption) mapOf("allowInterruption" to JsonPrimitive(true)) else emptyMap()) +
                (terminalResourcePolicySha256?.let { mapOf("terminalResourcePolicySha256" to JsonPrimitive(it)) } ?: emptyMap())
        }), CONTAINED_REQUEST_LIMITS)
        sha256 = OracleArtifacts.sha256(encoded)
    }

    companion object {
        const val MAXIMUM_REQUEST_BYTES = 256 * 1024
        const val REQUEST_DIRECTORY = "runtime"
        const val REQUEST_FILE = "contained-command-request.json"
        const val MAXIMUM_LOG_BYTES = 64L * 1024 * 1024

        fun parse(bytes: ByteArray): KotlinContainedCommandRequest {
            val document = OracleJson.parseCanonical(bytes, CONTAINED_REQUEST_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("contained command request must be an object")
            val version = document.number("schemaVersion")
            if (version == 5L) return parseFileDescriptorRequest(document, bytes)
            require(version in setOf(1L, 2L, 3L, 4L)) { "contained command request version is unsupported" }
            val visibility = if (version == 4L) document.string("retainedInputVisibilitySha256") else null
            if (version == 4L) require(document["allowInterruption"] in setOf(JsonPrimitive(true), JsonPrimitive(false)))
            val allowInterruption = version == 2L || (version == 3L && "allowInterruption" in document) ||
                (version == 4L && document["allowInterruption"] == JsonPrimitive(true))
            require(!allowInterruption || document["allowInterruption"] == JsonPrimitive(true)) {
                "contained command requires explicit interruption admission"
            }
            require(version != 3L || "terminalResourcePolicySha256" in document) {
                "contained command v3 requires its terminal resource policy"
            }
            val terminalResourcePolicySha256 = if (version == 3L) document.string("terminalResourcePolicySha256") else null
            require(document.keys == setOf("schemaVersion", "provider", "runDirectory", "nonce", "command",
                "environment", "maximumStartWaitSeconds", "maximumWallSeconds", "maximumStdoutBytes", "maximumStderrBytes") +
                (if (version == 4L) setOf("allowInterruption", "retainedInputVisibilitySha256")
                    else (if (allowInterruption) setOf("allowInterruption") else emptySet()) +
                        (if (version == 3L) setOf("terminalResourcePolicySha256") else emptySet()))) {
                "contained command request fields differ from its closed contract"
            }
            require(document.string("provider") == "kotlin-contained-command-request-v$version") {
                "contained command request version is unsupported"
            }
            val command = document["command"] as? JsonArray
                ?: throw IllegalArgumentException("contained command arguments must be an array")
            val environment = document["environment"] as? JsonObject
                ?: throw IllegalArgumentException("contained command environment must be an object")
            return KotlinContainedCommandRequest(
                Path.of(document.string("runDirectory")), document.string("nonce"),
                command.map { it.requireString() }, environment.mapValues { it.value.requireString() },
                document.number("maximumStartWaitSeconds"), document.number("maximumWallSeconds"),
                document.number("maximumStdoutBytes"), document.number("maximumStderrBytes"),
                allowInterruption = allowInterruption,
                terminalResourcePolicySha256 = terminalResourcePolicySha256,
                retainedInputVisibilitySha256 = visibility,
            ).also { require(it.canonicalBytes.contentEquals(bytes)) { "contained command request changed during parsing" } }
        }

        private fun parseFileDescriptorRequest(document: JsonObject, bytes: ByteArray): KotlinContainedCommandRequest {
            val hasVisibility = "retainedInputVisibilitySha256" in document
            require(document.keys == setOf("schemaVersion", "provider", "runDirectory", "nonce", "command",
                "environment", "maximumStartWaitSeconds", "maximumWallSeconds", "maximumStdoutBytes", "maximumStderrBytes",
                "allowInterruption", "terminalResourcePolicySha256", "fileDescriptorPolicySha256", "maximumOpenFiles") +
                if (hasVisibility) setOf("retainedInputVisibilitySha256") else emptySet()) {
                "contained command v5 fields differ from its closed contract"
            }
            require(document.string("provider") == "kotlin-contained-command-request-v5") {
                "contained command request version is unsupported"
            }
            require(document["allowInterruption"] in setOf(JsonPrimitive(true), JsonPrimitive(false))) {
                "contained command v5 requires explicit Boolean interruption admission"
            }
            val terminal = document.string("terminalResourcePolicySha256")
            require(terminal == ContainedCommandTerminalResourceEvidence.policySha256) {
                "contained command v5 requires its exact terminal resource policy"
            }
            // Raw fields may select only this closed policy; neither a digest nor parsing grants launch authority.
            val policy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
            require(document.string("fileDescriptorPolicySha256") == policy.sha256 &&
                document.number("maximumOpenFiles") == policy.maximumOpenFiles) {
                "contained command file descriptor policy declaration is unsupported"
            }
            val visibility = if (hasVisibility) document.string("retainedInputVisibilitySha256") else null
            val command = document["command"] as? JsonArray
                ?: throw IllegalArgumentException("contained command arguments must be an array")
            val environment = document["environment"] as? JsonObject
                ?: throw IllegalArgumentException("contained command environment must be an object")
            return KotlinContainedCommandRequest(
                Path.of(document.string("runDirectory")), document.string("nonce"),
                command.map { it.requireString() }, environment.mapValues { it.value.requireString() },
                document.number("maximumStartWaitSeconds"), document.number("maximumWallSeconds"),
                document.number("maximumStdoutBytes"), document.number("maximumStderrBytes"),
                allowInterruption = document["allowInterruption"] == JsonPrimitive(true),
                terminalResourcePolicySha256 = terminal,
                retainedInputVisibilitySha256 = visibility,
                fileDescriptorPolicy = policy,
            ).also { require(it.canonicalBytes.contentEquals(bytes)) { "contained command request changed during parsing" } }
        }
    }
}

/** A typed selection or digest selects a closed contract, never execution authority. */
private fun containedCommandRequestVersion(
    allowInterruption: Boolean,
    terminalResourcePolicySha256: String?,
    retainedInputVisibilitySha256: String?,
    fileDescriptorPolicy: ContainedCommandFileDescriptorPolicy? = null,
): Int {
    require(terminalResourcePolicySha256 == null ||
        terminalResourcePolicySha256 == ContainedCommandTerminalResourceEvidence.policySha256) {
        "contained command terminal resource policy is unsupported"
    }
    require(retainedInputVisibilitySha256 == null || retainedInputVisibilitySha256.matches(CONTAINED_SHA256))
    require(fileDescriptorPolicy == null || terminalResourcePolicySha256 != null) {
        "contained command file descriptor policy requires the terminal resource policy"
    }
    require(fileDescriptorPolicy != null || terminalResourcePolicySha256 == null || retainedInputVisibilitySha256 == null) {
        "contained command terminal and visibility policies cannot be combined"
    }
    return when {
        fileDescriptorPolicy != null -> 5
        terminalResourcePolicySha256 != null -> 3
        retainedInputVisibilitySha256 != null -> 4
        allowInterruption -> 2
        else -> 1
    }
}

/** Canonical runtime fields for the same old modes; legacy null keeps its original empty map. */
internal fun containedCommandRuntimePolicyFields(
    interruptionPolicySha256: String?,
    terminalResourcePolicySha256: String?,
    retainedInputVisibility: JsonObject?,
): Map<String, JsonElement> {
    val visibilitySha256 = retainedInputVisibility?.let { OracleArtifacts.sha256(OracleJson.canonicalBytes(it)) }
    val version = containedCommandRequestVersion(interruptionPolicySha256 != null,
        terminalResourcePolicySha256, visibilitySha256)
    return buildMap {
        interruptionPolicySha256?.let { put("interruptionPolicySha256", JsonPrimitive(it)) }
        retainedInputVisibility?.let { put("retainedInputVisibility", it) }
        terminalResourcePolicySha256?.let { put("terminalResourcePolicySha256", JsonPrimitive(it)) }
        if (version != 1) put("commandRequestProvider", JsonPrimitive("kotlin-contained-command-request-v$version"))
    }
}

internal data class KotlinContainedCommandOutcome(
    val keeperPid: Long,
    val childPid: Long,
    val exitCode: Int,
    val elapsedMillis: Long,
    val stdoutBytes: Long,
    val stderrBytes: Long,
    val status: String,
    val stdoutSha256: String? = null,
    val stderrSha256: String? = null,
) {
    fun requireSuccessful(failureDiagnostics: String? = null) {
        require(status == "EXITED" && exitCode == 0) {
            buildString {
                append("contained command did not exit successfully: status=$status, exitCode=$exitCode, ")
                append("elapsedMillis=$elapsedMillis, stdoutBytes=$stdoutBytes, stderrBytes=$stderrBytes")
                if (!failureDiagnostics.isNullOrBlank()) append('\n').append(failureDiagnostics)
            }
        }
    }
}

internal object KotlinContainedCommandProtocol {
    // The bootstrap argv is unchanged; strict terminal requests v3/v5 select HMAC wire v2 after admission.
    const val VERSION = "contained-command-v1"
    const val BOOT_FILE = "contained-command.boot.json"
    const val START_FILE = "contained-command.start.json"
    const val INTERRUPT_FILE = "contained-command.interrupt.json"
    const val OUTCOME_FILE = "contained-command.outcome.json"
    const val STDOUT_FILE = "contained-command.stdout"
    const val STDERR_FILE = "contained-command.stderr"
    const val MAXIMUM_PROTOCOL_BYTES = 4096
    const val SECRET_BYTES = 32
    private val EMPTY_OUTPUT_SHA256 = OracleArtifacts.sha256(ByteArray(0))

    fun boot(secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long): ByteArray =
        encode(secret, request, "BOOT", emptyOutcome(request, keeperPid, "BOOT"))

    fun requireBoot(bytes: ByteArray, secret: ByteArray, request: KotlinContainedCommandRequest): Long =
        decode(bytes, secret, request, "BOOT", null).keeperPid

    fun start(secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long): ByteArray =
        encode(secret, request, "START", emptyOutcome(request, keeperPid, "START"))

    fun requireStart(bytes: ByteArray, secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long) {
        decode(bytes, secret, request, "START", keeperPid)
    }

    fun interrupt(secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long): ByteArray =
        encode(secret, request, "INTERRUPT", emptyOutcome(request, keeperPid, "INTERRUPT"))

    fun requireInterrupt(bytes: ByteArray, secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long) {
        decode(bytes, secret, request, "INTERRUPT", keeperPid)
    }

    fun outcome(secret: ByteArray, request: KotlinContainedCommandRequest, outcome: KotlinContainedCommandOutcome): ByteArray =
        encode(secret, request, "OUTCOME", outcome)

    fun requireOutcome(
        bytes: ByteArray,
        secret: ByteArray,
        request: KotlinContainedCommandRequest,
        keeperPid: Long,
    ): KotlinContainedCommandOutcome = decode(bytes, secret, request, "OUTCOME", keeperPid)

    private fun encode(
        secret: ByteArray,
        request: KotlinContainedCommandRequest,
        event: String,
        outcome: KotlinContainedCommandOutcome,
    ): ByteArray {
        requireOutcomeFields(request, event, outcome)
        val strict = request.terminalResourcePolicySha256 != null
        val version = if (strict) 2 else 1
        val unsigned = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(version),
            "provider" to JsonPrimitive("kotlin-contained-command-protocol-v$version"),
            "event" to JsonPrimitive(event),
            "nonce" to JsonPrimitive(request.nonce),
            "requestSha256" to JsonPrimitive(request.sha256),
            "keeperPid" to JsonPrimitive(outcome.keeperPid),
            "childPid" to JsonPrimitive(outcome.childPid),
            "exitCode" to JsonPrimitive(outcome.exitCode),
            "elapsedMillis" to JsonPrimitive(outcome.elapsedMillis),
            "stdoutBytes" to JsonPrimitive(outcome.stdoutBytes),
            "stderrBytes" to JsonPrimitive(outcome.stderrBytes),
            "status" to JsonPrimitive(outcome.status),
        ) + if (strict) mapOf("stdoutSha256" to JsonPrimitive(checkNotNull(outcome.stdoutSha256)),
            "stderrSha256" to JsonPrimitive(checkNotNull(outcome.stderrSha256))) else emptyMap())
        val authentication = authenticate(secret, OracleJson.canonicalBytes(unsigned, CONTAINED_PROTOCOL_LIMITS))
        return OracleJson.canonicalBytes(JsonObject(unsigned + ("hmacSha256" to JsonPrimitive(authentication))),
            CONTAINED_PROTOCOL_LIMITS)
    }

    private fun decode(
        bytes: ByteArray,
        secret: ByteArray,
        request: KotlinContainedCommandRequest,
        event: String,
        expectedKeeperPid: Long?,
    ): KotlinContainedCommandOutcome {
        val document = OracleJson.parseCanonical(bytes, CONTAINED_PROTOCOL_LIMITS) as? JsonObject
            ?: throw IllegalArgumentException("contained command protocol must be an object")
        val strict = request.terminalResourcePolicySha256 != null
        val version = if (strict) 2L else 1L
        require(document.keys == setOf("schemaVersion", "provider", "event", "nonce", "requestSha256",
            "keeperPid", "childPid", "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes", "status", "hmacSha256") +
            if (strict) setOf("stdoutSha256", "stderrSha256") else emptySet()) {
            "contained command protocol fields differ from its closed contract"
        }
        require(document.number("schemaVersion") == version &&
            document.string("provider") == "kotlin-contained-command-protocol-v$version" &&
            document.string("event") == event && document.string("nonce") == request.nonce &&
            document.string("requestSha256") == request.sha256) { "contained command protocol binding differs" }
        val authentication = document.string("hmacSha256")
        require(authentication.matches(CONTAINED_SHA256)) { "contained command authentication is malformed" }
        val expected = authenticate(secret, OracleJson.canonicalBytes(JsonObject(document - "hmacSha256"),
            CONTAINED_PROTOCOL_LIMITS))
        require(MessageDigest.isEqual(authentication.toByteArray(Charsets.US_ASCII), expected.toByteArray(Charsets.US_ASCII))) {
            "contained command protocol authentication failed"
        }
        val exitCode = document.number("exitCode")
        require(exitCode in 0L..255L) { "contained command exit code is invalid" }
        return KotlinContainedCommandOutcome(document.number("keeperPid"), document.number("childPid"), exitCode.toInt(),
            document.number("elapsedMillis"), document.number("stdoutBytes"), document.number("stderrBytes"),
            document.string("status"), if (strict) document.string("stdoutSha256") else null,
            if (strict) document.string("stderrSha256") else null).also {
            requireOutcomeFields(request, event, it)
            require(expectedKeeperPid == null || it.keeperPid == expectedKeeperPid) {
                "contained command keeper identity differs"
            }
        }
    }

    private fun requireOutcomeFields(request: KotlinContainedCommandRequest, event: String, outcome: KotlinContainedCommandOutcome) {
        require(outcome.keeperPid in 1L..Int.MAX_VALUE.toLong()) { "contained command keeper PID is invalid" }
        require(event != "INTERRUPT" && outcome.status != "INTERRUPTED" || request.allowInterruption) {
            "contained command request does not authorize interruption"
        }
        if (request.terminalResourcePolicySha256 != null) {
            require(outcome.stdoutSha256?.matches(CONTAINED_SHA256) == true &&
                outcome.stderrSha256?.matches(CONTAINED_SHA256) == true) {
                "strict contained command outcome lacks authenticated pipe hashes"
            }
            require((outcome.stdoutBytes != 0L || outcome.stdoutSha256 == EMPTY_OUTPUT_SHA256) &&
                (outcome.stderrBytes != 0L || outcome.stderrSha256 == EMPTY_OUTPUT_SHA256)) {
                "strict contained command empty output hash differs"
            }
        } else {
            require(outcome.stdoutSha256 == null && outcome.stderrSha256 == null) {
                "legacy contained command outcome must not claim strict pipe hashes"
            }
        }
        if (event != "OUTCOME") {
            require(event in setOf("BOOT", "START", "INTERRUPT") && outcome == emptyOutcome(request, outcome.keeperPid, event)) {
                "contained command pre-execution event contains an outcome"
            }
            return
        }
        require(outcome.childPid in 1L..Int.MAX_VALUE.toLong() && outcome.childPid != outcome.keeperPid &&
            outcome.exitCode in 0..255 && outcome.elapsedMillis in 0L..(request.maximumWallSeconds * 1000L + 15000L) &&
            outcome.stdoutBytes in 0L..request.maximumStdoutBytes && outcome.stderrBytes in 0L..request.maximumStderrBytes &&
            outcome.status in setOf("EXITED", "TIMED_OUT", "OUTPUT_LIMIT", "INTERRUPTED")) { "contained command outcome is outside its bounds" }
    }

    private fun emptyOutcome(request: KotlinContainedCommandRequest, keeperPid: Long, event: String): KotlinContainedCommandOutcome {
        val hash = if (request.terminalResourcePolicySha256 == null) null else EMPTY_OUTPUT_SHA256
        return KotlinContainedCommandOutcome(keeperPid, 0L, 0, 0L, 0L, 0L, event, hash, hash)
    }

    private fun authenticate(secret: ByteArray, bytes: ByteArray): String {
        require(secret.size == SECRET_BYTES) { "contained command bootstrap secret has the wrong size" }
        val authentication = Mac.getInstance("HmacSHA256")
        authentication.init(SecretKeySpec(secret, "HmacSHA256"))
        return authentication.doFinal(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}

private fun requireContainedCommandPath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path != Path.of("/") && path.nameCount <= 32 &&
        path.toString().toByteArray(Charsets.UTF_8).size <= 4096 && path.all { it.toString().isNotBlank() &&
            it.toString().toByteArray(Charsets.UTF_8).size <= 255 } &&
        path.toString().none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' }) {
        "contained command path is not canonical"
    }
}

private fun JsonElement.requireString(): String {
    require(this is JsonPrimitive && isString) { "contained command JSON value must be a string" }
    return content
}

private fun JsonObject.string(name: String): String = getValue(name).requireString()

private fun JsonObject.number(name: String): Long {
    val value = getValue(name)
    require(value is JsonPrimitive && !value.isString && value.content.matches(Regex("0|[1-9][0-9]*"))) {
        "contained command JSON value must be a nonnegative integer"
    }
    return value.content.toLongOrNull() ?: throw IllegalArgumentException("contained command JSON integer overflows")
}

private val CONTAINED_SHA256 = Regex("[0-9a-f]{64}")
private val CONTAINED_REQUEST_LIMITS = StrictJsonLimits(
    maximumInputBytes = KotlinContainedCommandRequest.MAXIMUM_REQUEST_BYTES,
    maximumCanonicalBytes = KotlinContainedCommandRequest.MAXIMUM_REQUEST_BYTES,
    maximumDepth = 4, maximumNodes = 1024, maximumStringBytes = 65536, maximumTotalStringBytes = 128 * 1024,
    maximumNumberCharacters = 20,
)
private val CONTAINED_PROTOCOL_LIMITS = StrictJsonLimits(
    maximumInputBytes = KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES,
    maximumCanonicalBytes = KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES,
    maximumDepth = 2, maximumNodes = 32, maximumStringBytes = 128, maximumTotalStringBytes = 1024,
    maximumNumberCharacters = 20,
)

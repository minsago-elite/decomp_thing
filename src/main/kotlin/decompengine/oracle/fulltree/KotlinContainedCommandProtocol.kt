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
) {
    val command: List<String>
    val environment: Map<String, String>
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
        encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("kotlin-contained-command-request-v1"),
            "runDirectory" to JsonPrimitive(runDirectory.toString()),
            "nonce" to JsonPrimitive(nonce),
            "command" to JsonArray(this.command.map(::JsonPrimitive)),
            "environment" to JsonObject(this.environment.mapValues { JsonPrimitive(it.value) }),
            "maximumStartWaitSeconds" to JsonPrimitive(maximumStartWaitSeconds),
            "maximumWallSeconds" to JsonPrimitive(maximumWallSeconds),
            "maximumStdoutBytes" to JsonPrimitive(maximumStdoutBytes),
            "maximumStderrBytes" to JsonPrimitive(maximumStderrBytes),
        )), CONTAINED_REQUEST_LIMITS)
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
            require(document.keys == setOf("schemaVersion", "provider", "runDirectory", "nonce", "command",
                "environment", "maximumStartWaitSeconds", "maximumWallSeconds", "maximumStdoutBytes", "maximumStderrBytes")) {
                "contained command request fields differ from its closed contract"
            }
            require(document.number("schemaVersion") == 1L &&
                document.string("provider") == "kotlin-contained-command-request-v1") {
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
            ).also { require(it.canonicalBytes.contentEquals(bytes)) { "contained command request changed during parsing" } }
        }
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
) {
    fun requireSuccessful() {
        require(status == "EXITED" && exitCode == 0) { "contained command did not exit successfully" }
    }
}

internal object KotlinContainedCommandProtocol {
    const val VERSION = "contained-command-v1"
    const val BOOT_FILE = "contained-command.boot.json"
    const val START_FILE = "contained-command.start.json"
    const val OUTCOME_FILE = "contained-command.outcome.json"
    const val STDOUT_FILE = "contained-command.stdout"
    const val STDERR_FILE = "contained-command.stderr"
    const val MAXIMUM_PROTOCOL_BYTES = 4096
    const val SECRET_BYTES = 32

    fun boot(secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long): ByteArray =
        encode(secret, request, "BOOT", emptyOutcome(keeperPid, "BOOT"))

    fun requireBoot(bytes: ByteArray, secret: ByteArray, request: KotlinContainedCommandRequest): Long =
        decode(bytes, secret, request, "BOOT", null).keeperPid

    fun start(secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long): ByteArray =
        encode(secret, request, "START", emptyOutcome(keeperPid, "START"))

    fun requireStart(bytes: ByteArray, secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long) {
        decode(bytes, secret, request, "START", keeperPid)
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
        val unsigned = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("kotlin-contained-command-protocol-v1"),
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
        ))
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
        require(document.keys == setOf("schemaVersion", "provider", "event", "nonce", "requestSha256",
            "keeperPid", "childPid", "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes", "status", "hmacSha256")) {
            "contained command protocol fields differ from its closed contract"
        }
        require(document.number("schemaVersion") == 1L &&
            document.string("provider") == "kotlin-contained-command-protocol-v1" &&
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
            document.string("status")).also {
            requireOutcomeFields(request, event, it)
            require(expectedKeeperPid == null || it.keeperPid == expectedKeeperPid) {
                "contained command keeper identity differs"
            }
        }
    }

    private fun requireOutcomeFields(request: KotlinContainedCommandRequest, event: String, outcome: KotlinContainedCommandOutcome) {
        require(outcome.keeperPid in 1L..Int.MAX_VALUE.toLong()) { "contained command keeper PID is invalid" }
        if (event != "OUTCOME") {
            require(event in setOf("BOOT", "START") && outcome == emptyOutcome(outcome.keeperPid, event)) {
                "contained command pre-execution event contains an outcome"
            }
            return
        }
        require(outcome.childPid in 1L..Int.MAX_VALUE.toLong() && outcome.childPid != outcome.keeperPid &&
            outcome.exitCode in 0..255 && outcome.elapsedMillis in 0L..(request.maximumWallSeconds * 1000L + 15000L) &&
            outcome.stdoutBytes in 0L..request.maximumStdoutBytes && outcome.stderrBytes in 0L..request.maximumStderrBytes &&
            outcome.status in setOf("EXITED", "TIMED_OUT", "OUTPUT_LIMIT")) { "contained command outcome is outside its bounds" }
    }

    private fun emptyOutcome(keeperPid: Long, event: String) = KotlinContainedCommandOutcome(keeperPid, 0L, 0, 0L, 0L, 0L, event)

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

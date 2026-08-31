package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.system.exitProcess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class ToolchainReproductionException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class LlvmToolchainReproductionVerification(
    val lockSha256: String,
    val dockerfileSha256: String,
    val buildRecordSha256: String,
    val recordedOriginImageDigest: String,
    val observedImageDigest: String,
    val platform: String,
    val sourceDateEpoch: String,
)

/**
 * Authenticates the stable LLVM toolchain recipe without treating a fresh Docker image ID as the
 * historical artifact-producing image ID. Live tool bytes and version output remain the separate
 * responsibility of the build-record verifier that runs inside the rebuilt image.
 */
internal class LlvmToolchainReproductionVerifier(
    private val faultInjector: ToolchainReproductionFaultInjector? = null,
) {
    fun verify(lockPath: Path, buildRecordPath: Path, inspectPath: Path): LlvmToolchainReproductionVerification {
        val lock = readInput(lockPath, MAXIMUM_LOCK_BYTES, "toolchain reproduction lock")
        val lockDocument = parseCanonicalObject(lock.bytes, MAXIMUM_LOCK_BYTES, "toolchain reproduction lock")
        validateSchema("toolchain-reproduction", lockDocument, "toolchain reproduction lock")
        if (lockDocument.requiredInteger("schemaVersion", "toolchain reproduction lock") != 1L) {
            reproductionFail("toolchain reproduction lock schemaVersion must be 1")
        }

        val origin = lockDocument.requiredObject("recordedOrigin", "toolchain reproduction lock")
        val expectedBuildRecordSha256 = origin.requiredString("buildRecordSha256", "recorded origin")
        requireSha256(expectedBuildRecordSha256, "recorded build record")
        val recordedOriginDigest = origin.requiredString("imageDigest", "recorded origin")
        requireImageDigest(recordedOriginDigest, "recorded origin image")

        val recipe = lockDocument.requiredObject("recipe", "toolchain reproduction lock")
        val baseImage = recipe.requiredString("baseImage", "toolchain recipe")
        if (!baseImage.matches(IMAGE_NAME)) reproductionFail("toolchain recipe base image is invalid")
        val baseImageDigest = recipe.requiredString("baseImageDigest", "toolchain recipe")
        requireImageDigest(baseImageDigest, "toolchain recipe base image")
        val dockerfileRelative = recipe.requiredString("dockerfile", "toolchain recipe")
        val dockerfilePath = resolveRelativeFile(lock.path, dockerfileRelative, "toolchain recipe Dockerfile")
        val expectedDockerfileSha256 = recipe.requiredString("dockerfileSha256", "toolchain recipe")
        requireSha256(expectedDockerfileSha256, "toolchain recipe Dockerfile")
        val platform = recipe.requiredString("platform", "toolchain recipe")
        if (platform != REQUIRED_PLATFORM) reproductionFail("toolchain recipe platform must be $REQUIRED_PLATFORM")
        val sourceDateEpoch = recipe.requiredString("sourceDateEpoch", "toolchain recipe")
        if (!sourceDateEpoch.matches(POSITIVE_DECIMAL)) {
            reproductionFail("toolchain recipe SOURCE_DATE_EPOCH must be a positive decimal string")
        }

        val dockerfile = readInput(dockerfilePath, MAXIMUM_DOCKERFILE_BYTES, "toolchain Dockerfile")
        if (dockerfile.sha256 != expectedDockerfileSha256) {
            reproductionFail(
                "Dockerfile SHA-256 mismatch: recorded $expectedDockerfileSha256, observed ${dockerfile.sha256}",
            )
        }
        verifyBaseImageReferences(dockerfile.bytes, "$baseImage@$baseImageDigest")

        val buildRecord = readInput(buildRecordPath, MAXIMUM_BUILD_RECORD_BYTES, "toolchain build record")
        if (buildRecord.sha256 != expectedBuildRecordSha256) {
            reproductionFail(
                "build-record SHA-256 mismatch: recorded $expectedBuildRecordSha256, observed ${buildRecord.sha256}",
            )
        }
        val buildDocument = parseCanonicalObject(
            buildRecord.bytes,
            MAXIMUM_BUILD_RECORD_BYTES,
            "toolchain build record",
        )
        validateSchema("build-record", buildDocument, "toolchain build record")
        verifyBuildBindings(buildDocument, recordedOriginDigest, platform, sourceDateEpoch)

        val inspect = readInput(inspectPath, MAXIMUM_INSPECT_BYTES, "Docker inspect response")
        val inspectedImage = selectInspectedImage(parseJson(inspect.bytes, MAXIMUM_INSPECT_BYTES, "Docker inspect response"))
        val observedDigest = inspectedImage.requiredString("Id", "Docker inspect response")
        requireImageDigest(observedDigest, "running image")
        if (
            inspectedImage.requiredString("Architecture", "Docker inspect response") != "amd64" ||
            inspectedImage.requiredString("Os", "Docker inspect response") != "linux"
        ) {
            reproductionFail("reproduced image platform is not linux/amd64")
        }

        faultInjector?.hit(ToolchainReproductionVerificationPoint.AFTER_INPUTS_VERIFIED)
        listOf(lock, dockerfile, buildRecord, inspect).forEach(::requireUnchanged)

        return LlvmToolchainReproductionVerification(
            lockSha256 = lock.sha256,
            dockerfileSha256 = dockerfile.sha256,
            buildRecordSha256 = buildRecord.sha256,
            recordedOriginImageDigest = recordedOriginDigest,
            observedImageDigest = observedDigest,
            platform = platform,
            sourceDateEpoch = sourceDateEpoch,
        )
    }

    private fun verifyBuildBindings(
        build: JsonObject,
        recordedOriginDigest: String,
        platform: String,
        sourceDateEpoch: String,
    ) {
        val environment = build.requiredObject("environment", "toolchain build record")
        val container = environment.requiredObject("container", "toolchain build environment")
        if (container.requiredString("digest", "toolchain build container") != recordedOriginDigest) {
            reproductionFail("toolchain reproduction lock does not match build-record origin digest")
        }
        if (container.requiredString("platform", "toolchain build container") != platform) {
            reproductionFail("toolchain reproduction lock platform does not match build record")
        }
        val variables = environment.requiredObject("variables", "toolchain build environment")
        if (variables.requiredString("SOURCE_DATE_EPOCH", "toolchain build variables") != sourceDateEpoch) {
            reproductionFail("toolchain reproduction lock SOURCE_DATE_EPOCH does not match build record")
        }
    }

    private fun verifyBaseImageReferences(bytes: ByteArray, expected: String) {
        val text = decodeUtf8(bytes, "toolchain Dockerfile")
        val references = text.lineSequence().map(String::trim).filter { line ->
            line.startsWith("FROM ", ignoreCase = true)
        }.map { line ->
            line.split(WHITESPACE).getOrNull(1)
                ?: reproductionFail("Dockerfile FROM instruction is malformed")
        }.toList()
        if (references.isEmpty() || references.any { it != expected }) {
            reproductionFail("Dockerfile FROM instructions do not match locked base image")
        }
    }

    private fun resolveRelativeFile(lockPath: Path, relative: String, label: String): Path {
        if (
            relative.startsWith('/') || '\\' in relative || relative.split('/').any { it.isEmpty() || it == "." || it == ".." }
        ) {
            reproductionFail("$label must be a normalized relative POSIX path")
        }
        val directory = lockPath.parent ?: reproductionFail("toolchain reproduction lock has no parent directory")
        val candidate = relative.split('/').fold(directory) { current, component -> current.resolve(component) }.normalize()
        if (!candidate.startsWith(directory) || candidate == directory) {
            reproductionFail("$label escapes the lock directory")
        }
        return candidate
    }

    private fun readInput(path: Path, maximumBytes: Int, label: String): AuthenticatedInput {
        val normalized = path.toAbsolutePath().normalize()
        val bytes = try {
            OracleArtifacts.read(normalized, OracleArtifactLimits(maximumBytes)).bytes
        } catch (failure: Exception) {
            throw ToolchainReproductionException("cannot read authenticated $label", failure)
        }
        return AuthenticatedInput(normalized, bytes, OracleArtifacts.sha256(bytes), maximumBytes, label)
    }

    private fun requireUnchanged(input: AuthenticatedInput) {
        val current = readInput(input.path, input.maximumBytes, input.label)
        if (!MessageDigest.isEqual(input.bytes, current.bytes)) {
            reproductionFail("${input.label} changed during verification")
        }
    }

    private fun parseCanonicalObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
        OracleJson.parseCanonical(bytes, jsonLimits(maximumBytes)) as? JsonObject
            ?: reproductionFail("$label root must be an object")
    } catch (failure: ToolchainReproductionException) {
        throw failure
    } catch (failure: Exception) {
        throw ToolchainReproductionException("$label is not strict canonical JSON", failure)
    }

    private fun parseJson(bytes: ByteArray, maximumBytes: Int, label: String): JsonElement = try {
        OracleJson.parse(bytes, jsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw ToolchainReproductionException("$label is not strict bounded JSON", failure)
    }

    private fun validateSchema(name: String, document: JsonObject, label: String) {
        try {
            OracleSchemas.validate(name, document)
        } catch (failure: Exception) {
            throw ToolchainReproductionException("$label fails its bundled schema", failure)
        }
    }

    private fun selectInspectedImage(document: JsonElement): JsonObject = when (document) {
        is JsonObject -> document
        is JsonArray -> {
            if (document.size != 1) reproductionFail("Docker inspect response must contain exactly one image")
            document.single() as? JsonObject
                ?: reproductionFail("Docker inspect response image must be an object")
        }
        else -> reproductionFail("Docker inspect response must be an object or one-element array")
    }

    private fun decodeUtf8(bytes: ByteArray, label: String): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: Exception) {
        throw ToolchainReproductionException("$label is not valid UTF-8", failure)
    }

    private fun requireSha256(value: String, label: String) {
        if (!value.matches(SHA256)) reproductionFail("$label SHA-256 is invalid")
    }

    private fun requireImageDigest(value: String, label: String) {
        if (!value.matches(IMAGE_DIGEST)) reproductionFail("$label digest is invalid")
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = 500_000,
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
    )

    private data class AuthenticatedInput(
        val path: Path,
        val bytes: ByteArray,
        val sha256: String,
        val maximumBytes: Int,
        val label: String,
    )

    private companion object {
        val SHA256 = Regex("[0-9a-f]{64}")
        val IMAGE_DIGEST = Regex("sha256:[0-9a-f]{64}")
        val IMAGE_NAME = Regex("[a-z0-9]+(?:[._/-][a-z0-9]+)*")
        val POSITIVE_DECIMAL = Regex("[1-9][0-9]*")
        val WHITESPACE = Regex("\\s+")
        const val REQUIRED_PLATFORM = "linux/amd64"
        const val MAXIMUM_LOCK_BYTES = 1024 * 1024
        const val MAXIMUM_DOCKERFILE_BYTES = 1024 * 1024
        const val MAXIMUM_BUILD_RECORD_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_INSPECT_BYTES = 16 * 1024 * 1024
    }
}

internal enum class ToolchainReproductionVerificationPoint {
    AFTER_INPUTS_VERIFIED,
}

internal fun interface ToolchainReproductionFaultInjector {
    fun hit(point: ToolchainReproductionVerificationPoint)
}

/** Stable JVM entry point replacing the Python LLVM recipe-verification authority. */
object LlvmToolchainReproductionVerifierCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        try {
            val options = ToolchainReproductionArguments.parse(arguments)
            val verified = LlvmToolchainReproductionVerifier().verify(
                options.lock,
                options.buildRecord,
                options.inspectJson,
            )
            println(successMessage(verified))
        } catch (failure: Exception) {
            System.err.println("LLVM toolchain reproduction verification failed: ${failure.message}")
            exitProcess(1)
        }
    }

    internal fun successMessage(verified: LlvmToolchainReproductionVerification): String =
        "verified stable toolchain recipe for rebuilt image ${verified.observedImageDigest} " +
            "(recorded artifact origin ${verified.recordedOriginImageDigest})"
}

private data class ToolchainReproductionArguments(
    val lock: Path,
    val buildRecord: Path,
    val inspectJson: Path,
) {
    companion object {
        fun parse(arguments: Array<String>): ToolchainReproductionArguments {
            var lock: Path? = null
            var buildRecord: Path? = null
            var inspectJson: Path? = null
            var index = 0
            while (index < arguments.size) {
                val option = arguments[index]
                if (option !in setOf("--lock", "--build-record", "--inspect-json")) {
                    reproductionFail("unknown option $option")
                }
                index++
                if (index >= arguments.size) reproductionFail("$option requires a path")
                val value = Path.of(arguments[index])
                when (option) {
                    "--lock" -> if (lock == null) lock = value else reproductionFail("--lock was repeated")
                    "--build-record" -> if (buildRecord == null) {
                        buildRecord = value
                    } else {
                        reproductionFail("--build-record was repeated")
                    }
                    "--inspect-json" -> if (inspectJson == null) {
                        inspectJson = value
                    } else {
                        reproductionFail("--inspect-json was repeated")
                    }
                }
                index++
            }
            return ToolchainReproductionArguments(
                lock ?: reproductionFail("--lock is required"),
                buildRecord ?: reproductionFail("--build-record is required"),
                inspectJson ?: reproductionFail("--inspect-json is required"),
            )
        }
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: reproductionFail("$label field $name must be an object")

private fun JsonObject.requiredString(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive ?: reproductionFail("$label field $name must be a string")
    if (!value.isString || value.content.isEmpty() || '\u0000' in value.content) {
        reproductionFail("$label field $name must be a non-empty string without NUL")
    }
    return value.content
}

private fun JsonObject.requiredInteger(name: String, label: String): Long {
    val value = this[name] as? JsonPrimitive ?: reproductionFail("$label field $name must be an integer")
    if (value.isString || value.content.any { it in ".eE" }) {
        reproductionFail("$label field $name must be an integer")
    }
    return value.content.toLongOrNull() ?: reproductionFail("$label field $name exceeds the supported integer range")
}

private fun reproductionFail(message: String): Nothing = throw ToolchainReproductionException(message)

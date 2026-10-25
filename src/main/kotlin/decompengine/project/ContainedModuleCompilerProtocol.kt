package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** One exact, independently checked source/header snapshot member. */
internal data class ContainedModuleCompilerInput(val path: String, val sha256: String, val bytes: Long) {
    init {
        requireCompilerRelativePath(path)
        requireCompilerDigest(sha256)
        require(bytes in 0..ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES) { "module compiler input size exceeds its bound" }
    }

    internal fun json() = JsonObject(mapOf("path" to JsonPrimitive(path), "sha256" to JsonPrimitive(sha256), "bytes" to JsonPrimitive(bytes)))
}

/** Closed invocation contract, not permission to execute or evidence of containment. */
internal class ContainedModuleCompilerRequest(
    val nonce: String,
    val profileId: String,
    val profileSha256: String,
    val snapshotRoot: Path,
    val sourcePath: String,
    inputs: List<ContainedModuleCompilerInput>,
    val compilerPath: Path,
    val compilerSha256: String,
    val outputDirectory: Path,
    val maximumWallMillis: Long,
    val maximumOutputBytes: Long,
) {
    val inputs: List<ContainedModuleCompilerInput>
    val snapshotSha256: String
    val sourceSha256: String
    val command: List<String>
    private val encoded: ByteArray
    val canonicalBytes: ByteArray get() = encoded.copyOf()
    val sha256: String

    init {
        listOf(nonce, profileSha256, compilerSha256).forEach(::requireCompilerDigest)
        listOf(snapshotRoot, compilerPath, outputDirectory).forEach(::requireCompilerAbsolutePath)
        require(!snapshotRoot.startsWith(outputDirectory) && !outputDirectory.startsWith(snapshotRoot) &&
            !compilerPath.startsWith(snapshotRoot) && !compilerPath.startsWith(outputDirectory)) {
            "module compiler input, executable and writable output must be separate"
        }
        requireCompilerRelativePath(sourcePath)
        val profile = ReconstructionProfiles.named(profileId)
        require(profile.sha256 == profileSha256) { "module compiler requires the exact registered built-in profile" }
        require(maximumWallMillis in 1..minOf(MAXIMUM_WALL_MILLIS, profile.budgets.buildWallClockMillis)) {
            "module compiler wall bound exceeds its registered policy"
        }
        require(maximumOutputBytes in 2..minOf(MAXIMUM_OUTPUT_BYTES, profile.budgets.buildMaximumOutputBytes)) {
            "module compiler output bound exceeds its registered policy"
        }
        require(inputs.size in 1..MAXIMUM_INPUTS) { "module compiler snapshot count exceeds its bound" }
        this.inputs = java.util.List.copyOf(inputs.sortedBy { it.path })
        require(this.inputs.map { it.path }.distinct().size == this.inputs.size) { "duplicate module compiler snapshot path" }
        require(this.inputs.sumOf { it.bytes } <= MAXIMUM_TOTAL_INPUT_BYTES) { "module compiler snapshot exceeds its aggregate bound" }
        val source = this.inputs.singleOrNull { it.path == sourcePath }
            ?: throw IllegalArgumentException("module compiler source is absent from its snapshot")
        require(source.bytes > 0) { "module compiler source must not be empty" }
        this.inputs.forEach { input ->
            val declaration = profile.layout.declarationForPath(input.path)
            if (input.path == sourcePath) {
                require(declaration.id == "module-implementation" && input.path.endsWith(".c")) {
                    "module compiler source must be the declared module implementation"
                }
            } else require(declaration.id in setOf("shared-interface", "module-interface", "module-private-interface") &&
                input.path.endsWith(".h")) { "module compiler may snapshot only declared headers beside its one source" }
        }
        sourceSha256 = source.sha256
        val manifest = JsonObject(mapOf("provider" to JsonPrimitive("module-compiler-snapshot-v1"),
            "files" to JsonArray(this.inputs.map { it.json() })))
        snapshotSha256 = decompengine.project.sha256(OracleJson.canonicalBytes(manifest, COMPILER_REQUEST_LIMITS))
        val flags = profile.adapterConfiguration.getValue("compiler-flags").map { flag ->
            if (flag == "-Iinclude") "-I${snapshotRoot.resolve("include")}" else flag
        }
        command = java.util.List.copyOf(listOf(compilerPath.toString(), "-B${compilerPath.parent}/") + flags +
            listOf("-c", snapshotRoot.resolve(sourcePath).toString(), "-o", outputDirectory.resolve(OBJECT_FILE).toString()))
        encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("contained-module-compiler-request-v1"), "schemaVersion" to JsonPrimitive(1),
            "nonce" to JsonPrimitive(nonce), "profileId" to JsonPrimitive(profileId), "profileSha256" to JsonPrimitive(profileSha256),
            "snapshotRoot" to JsonPrimitive(snapshotRoot.toString()), "sourcePath" to JsonPrimitive(sourcePath),
            "inputs" to JsonArray(this.inputs.map { it.json() }), "snapshotSha256" to JsonPrimitive(snapshotSha256),
            "compilerPath" to JsonPrimitive(compilerPath.toString()), "compilerSha256" to JsonPrimitive(compilerSha256),
            "outputDirectory" to JsonPrimitive(outputDirectory.toString()),
            "maximumWallMillis" to JsonPrimitive(maximumWallMillis), "maximumOutputBytes" to JsonPrimitive(maximumOutputBytes),
        )), COMPILER_REQUEST_LIMITS)
        sha256 = decompengine.project.sha256(encoded)
    }

    companion object {
        const val MAXIMUM_REQUEST_BYTES = 2 * 1024 * 1024
        const val MAXIMUM_INPUTS = 4096
        const val MAXIMUM_INPUT_FILE_BYTES = 16L * 1024 * 1024
        const val MAXIMUM_TOTAL_INPUT_BYTES = 128L * 1024 * 1024
        const val MAXIMUM_OBJECT_BYTES = 64L * 1024 * 1024
        const val MAXIMUM_WALL_MILLIS = 30_000L
        const val MAXIMUM_OUTPUT_BYTES = 2L * 1024 * 1024
        const val OBJECT_FILE = "module.o"
        const val STDOUT_FILE = "compiler.stdout"
        const val STDERR_FILE = "compiler.stderr"

        fun parse(bytes: ByteArray): ContainedModuleCompilerRequest {
            val root = OracleJson.parseCanonical(bytes, COMPILER_REQUEST_LIMITS).compilerObject()
            root.compilerKeys("provider", "schemaVersion", "nonce", "profileId", "profileSha256", "snapshotRoot", "sourcePath",
                "inputs", "snapshotSha256", "compilerPath", "compilerSha256", "outputDirectory", "maximumWallMillis", "maximumOutputBytes")
            require(root.compilerText("provider") == "contained-module-compiler-request-v1" && root.compilerLong("schemaVersion") == 1L) {
                "unsupported module compiler request"
            }
            val inputs = root["inputs"] as? JsonArray ?: throw IllegalArgumentException("module compiler inputs must be an array")
            require(inputs.size in 1..MAXIMUM_INPUTS) { "module compiler snapshot count exceeds its bound" }
            return ContainedModuleCompilerRequest(root.compilerText("nonce"), root.compilerText("profileId"), root.compilerText("profileSha256"),
                Path.of(root.compilerText("snapshotRoot")), root.compilerText("sourcePath"), inputs.map { value ->
                    val input = value.compilerObject()
                    input.compilerKeys("path", "sha256", "bytes")
                    ContainedModuleCompilerInput(input.compilerText("path"), input.compilerText("sha256"), input.compilerLong("bytes"))
                }, Path.of(root.compilerText("compilerPath")), root.compilerText("compilerSha256"), Path.of(root.compilerText("outputDirectory")),
                root.compilerLong("maximumWallMillis"), root.compilerLong("maximumOutputBytes")).also {
                require(it.snapshotSha256 == root.compilerText("snapshotSha256") && it.canonicalBytes.contentEquals(bytes)) {
                    "module compiler request changed during decoding"
                }
            }
        }
    }
}

/** Passive worker observations only: no result, including compiled-object, authorizes acceptance. */
internal class ContainedModuleCompilerResult(
    val requestSha256: String, val nonce: String, val profileId: String, val profileSha256: String,
    val snapshotSha256: String, val sourceSha256: String, val compilerSha256: String,
    val outcome: String, val exitCode: Int?, val signal: Int?,
    val stdoutSha256: String, val stdoutBytes: Long, val stderrSha256: String, val stderrBytes: Long,
    val objectSha256: String?, val objectBytes: Long?,
) {
    private val encoded: ByteArray
    val canonicalBytes: ByteArray get() = encoded.copyOf()
    val sha256: String

    init {
        listOf(requestSha256, nonce, profileSha256, snapshotSha256, sourceSha256, compilerSha256, stdoutSha256, stderrSha256)
            .forEach(::requireCompilerDigest)
        require(ReconstructionProfiles.named(profileId).sha256 == profileSha256) { "module compiler result profile differs from registration" }
        require(outcome in setOf("compiled-object", "compiler-failed", "compiler-signaled", "timed-out", "output-limit-exceeded",
            "execution-failed", "input-changed", "object-invalid")) { "unknown module compiler outcome" }
        require(exitCode == null || exitCode in 0..255) { "invalid raw compiler exit code" }
        require(signal == null || signal in 1..64) { "invalid raw compiler signal" }
        require(exitCode == null || signal == null) { "compiler cannot both exit normally and terminate by signal" }
        require(stdoutBytes in 0..ContainedModuleCompilerRequest.MAXIMUM_OUTPUT_BYTES / 2 &&
            stderrBytes in 0..ContainedModuleCompilerRequest.MAXIMUM_OUTPUT_BYTES / 2) { "module compiler retained logs exceed their bounds" }
        require((objectSha256 == null) == (objectBytes == null)) { "incomplete module compiler object identity" }
        objectSha256?.let(::requireCompilerDigest)
        require(objectBytes == null || objectBytes in 52..ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES) { "module compiler object exceeds its bounds" }
        require((outcome == "compiled-object") == (objectSha256 != null) &&
            (outcome != "compiled-object" || (exitCode == 0 && signal == null))) { "module compiler object outcome lacks normal successful exit" }
        require(outcome != "compiler-failed" || (exitCode != null && exitCode != 0 && signal == null))
        require(outcome != "compiler-signaled" || (exitCode == null && signal != null))
        require(outcome !in setOf("timed-out", "output-limit-exceeded", "execution-failed") || (exitCode == null && signal == null))
        require(outcome != "object-invalid" || (exitCode == 0 && signal == null))
        encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("contained-module-compiler-result-v1"), "schemaVersion" to JsonPrimitive(1),
            "authority" to JsonPrimitive("worker-observation-only-requires-authenticated-terminal-proof"),
            "requestSha256" to JsonPrimitive(requestSha256), "nonce" to JsonPrimitive(nonce), "profileId" to JsonPrimitive(profileId),
            "profileSha256" to JsonPrimitive(profileSha256), "snapshotSha256" to JsonPrimitive(snapshotSha256),
            "sourceSha256" to JsonPrimitive(sourceSha256), "compilerSha256" to JsonPrimitive(compilerSha256), "outcome" to JsonPrimitive(outcome),
            "exitCode" to (exitCode?.let(::JsonPrimitive) ?: JsonNull), "signal" to (signal?.let(::JsonPrimitive) ?: JsonNull),
            "stdoutSha256" to JsonPrimitive(stdoutSha256), "stdoutBytes" to JsonPrimitive(stdoutBytes),
            "stderrSha256" to JsonPrimitive(stderrSha256), "stderrBytes" to JsonPrimitive(stderrBytes),
            "objectSha256" to (objectSha256?.let(::JsonPrimitive) ?: JsonNull), "objectBytes" to (objectBytes?.let(::JsonPrimitive) ?: JsonNull),
        )), COMPILER_RESULT_LIMITS)
        sha256 = decompengine.project.sha256(encoded)
    }

    fun requireBinding(request: ContainedModuleCompilerRequest) {
        require(requestSha256 == request.sha256 && nonce == request.nonce && profileId == request.profileId &&
            profileSha256 == request.profileSha256 && snapshotSha256 == request.snapshotSha256 &&
            sourceSha256 == request.sourceSha256 && compilerSha256 == request.compilerSha256) { "module compiler result request binding differs" }
        require(stdoutBytes <= request.maximumOutputBytes / 2 && stderrBytes <= request.maximumOutputBytes - request.maximumOutputBytes / 2) {
            "module compiler result exceeds the requested log bound"
        }
    }

    companion object {
        const val MAXIMUM_RESULT_BYTES = 64 * 1024
        fun parse(bytes: ByteArray): ContainedModuleCompilerResult {
            val root = OracleJson.parseCanonical(bytes, COMPILER_RESULT_LIMITS).compilerObject()
            root.compilerKeys("provider", "schemaVersion", "authority", "requestSha256", "nonce", "profileId", "profileSha256",
                "snapshotSha256", "sourceSha256", "compilerSha256", "outcome", "exitCode", "signal", "stdoutSha256", "stdoutBytes",
                "stderrSha256", "stderrBytes", "objectSha256", "objectBytes")
            require(root.compilerText("provider") == "contained-module-compiler-result-v1" && root.compilerLong("schemaVersion") == 1L &&
                root.compilerText("authority") == "worker-observation-only-requires-authenticated-terminal-proof") { "unsupported module compiler result" }
            return ContainedModuleCompilerResult(root.compilerText("requestSha256"), root.compilerText("nonce"), root.compilerText("profileId"),
                root.compilerText("profileSha256"), root.compilerText("snapshotSha256"), root.compilerText("sourceSha256"), root.compilerText("compilerSha256"),
                root.compilerText("outcome"), root.compilerOptionalLong("exitCode")?.let { Math.toIntExact(it) },
                root.compilerOptionalLong("signal")?.let { Math.toIntExact(it) }, root.compilerText("stdoutSha256"), root.compilerLong("stdoutBytes"),
                root.compilerText("stderrSha256"), root.compilerLong("stderrBytes"), root.compilerOptionalText("objectSha256"), root.compilerOptionalLong("objectBytes"))
                .also { require(it.canonicalBytes.contentEquals(bytes)) { "module compiler result changed during decoding" } }
        }
    }
}

internal fun requireCompilerAbsolutePath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path.parent != null && path.toString().length <= 4096 &&
        path.toString().none { it.code < 32 || it.code == 127 }) { "module compiler path must be normalized absolute text" }
}
private fun requireCompilerRelativePath(path: String) {
    require(path.length in 1..1024 && !path.startsWith('/') && '\\' !in path && path.none { it.code < 32 || it.code == 127 } &&
        path.split('/').all { it.isNotEmpty() && it != "." && it != ".." }) { "module compiler snapshot path is invalid" }
}
internal fun requireCompilerDigest(value: String) {
    require(value.length == 64 && value.all { it in "0123456789abcdef" }) { "module compiler SHA-256 is invalid" }
}
private fun JsonElement.compilerObject() = this as? JsonObject ?: throw IllegalArgumentException("module compiler JSON must be an object")
private fun JsonObject.compilerKeys(vararg keys: String) { require(this.keys == keys.toSet()) { "module compiler fields differ from the closed contract" } }
private fun JsonObject.compilerText(name: String) = (getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("module compiler $name must be a string")
private fun JsonObject.compilerLong(name: String) = (getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
    ?: throw IllegalArgumentException("module compiler $name must be an integer")
private fun JsonObject.compilerOptionalLong(name: String) = if (getValue(name) == JsonNull) null else compilerLong(name)
private fun JsonObject.compilerOptionalText(name: String) = if (getValue(name) == JsonNull) null else compilerText(name)
private val COMPILER_REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES,
    maximumCanonicalBytes = ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES, maximumDepth = 8, maximumNodes = 40000,
    maximumStringBytes = 4096, maximumTotalStringBytes = ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES, maximumNumberCharacters = 16)
private val COMPILER_RESULT_LIMITS = StrictJsonLimits(maximumInputBytes = ContainedModuleCompilerResult.MAXIMUM_RESULT_BYTES,
    maximumCanonicalBytes = ContainedModuleCompilerResult.MAXIMUM_RESULT_BYTES, maximumDepth = 4, maximumNodes = 64,
    maximumStringBytes = 256, maximumTotalStringBytes = 4096, maximumNumberCharacters = 16)

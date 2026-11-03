package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Closed computation inputs. Neither this request nor a worker output grants execution or scoring authority. */
internal class StructuralBoundaryReplayRequestV1(
    val modelPath: Path,
    val modelBytes: Int,
    val modelSha256: String,
    val inputSha256: String,
    val functionOraclePath: Path,
    val functionOracleBytes: Int,
    val functionOracleSha256: String,
    val imageBase: ULong,
    val outputDirectory: Path,
    val operationRequestSha256: String,
    val fullExportBindingSha256: String,
) {
    init {
        listOf(modelPath, functionOraclePath, outputDirectory).forEach(::requireReplayWorkerPath)
        require(modelPath != functionOraclePath) { "boundary replay inputs must be distinct files" }
        for (input in listOf(modelPath, functionOraclePath)) {
            require(!input.startsWith(outputDirectory) && !outputDirectory.startsWith(input)) {
                "boundary replay inputs must be disjoint from the output directory"
            }
        }
        require(modelBytes in 1..MAXIMUM_MODEL_BYTES) { "boundary replay model exceeds its byte bound" }
        require(functionOracleBytes in 1..MAXIMUM_ORACLE_BYTES) { "boundary replay oracle exceeds its byte bound" }
        listOf(modelSha256, inputSha256, functionOracleSha256, operationRequestSha256, fullExportBindingSha256)
            .forEach { require(WORKER_SHA256.matches(it)) { "boundary replay request has an invalid digest" } }
    }

    val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive(PROVIDER),
        "schemaVersion" to JsonPrimitive(1),
        "modelPath" to JsonPrimitive(modelPath.toString()),
        "modelBytes" to JsonPrimitive(modelBytes),
        "modelSha256" to JsonPrimitive(modelSha256),
        "inputSha256" to JsonPrimitive(inputSha256),
        "functionOraclePath" to JsonPrimitive(functionOraclePath.toString()),
        "functionOracleBytes" to JsonPrimitive(functionOracleBytes),
        "functionOracleSha256" to JsonPrimitive(functionOracleSha256),
        "imageBase" to JsonPrimitive("0x${imageBase.toString(16)}"),
        "outputDirectory" to JsonPrimitive(outputDirectory.toString()),
        "operationRequestSha256" to JsonPrimitive(operationRequestSha256),
        "fullExportBindingSha256" to JsonPrimitive(fullExportBindingSha256),
    )), WORKER_REQUEST_LIMITS)

    companion object {
        const val PROVIDER = "structural-boundary-replay-request-v1"
        const val MAXIMUM_REQUEST_BYTES = 64 * 1024
        const val MAXIMUM_MODEL_BYTES = 512 * 1024 * 1024
        const val MAXIMUM_ORACLE_BYTES = 16 * 1024 * 1024
        private val KEYS = setOf("provider", "schemaVersion", "modelPath", "modelBytes", "modelSha256",
            "inputSha256", "functionOraclePath", "functionOracleBytes", "functionOracleSha256", "imageBase",
            "outputDirectory", "operationRequestSha256", "fullExportBindingSha256")

        fun parse(bytes: ByteArray): StructuralBoundaryReplayRequestV1 {
            val root = OracleJson.parseCanonical(bytes, WORKER_REQUEST_LIMITS).jsonObject
            require(root.keys == KEYS) { "boundary replay request does not match its closed schema" }
            fun text(name: String): String = root.getValue(name).jsonPrimitive.let {
                require(it.isString) { "boundary replay request $name must be a string" }
                it.content
            }
            fun integer(name: String): Int = root.getValue(name).jsonPrimitive.let {
                require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*"))) {
                    "boundary replay request $name must be an unsigned integer"
                }
                Math.toIntExact(it.content.toLong())
            }
            require(text("provider") == PROVIDER && integer("schemaVersion") == 1) {
                "unsupported boundary replay request version"
            }
            val base = text("imageBase")
            require(base.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) {
                "boundary replay image base must be a canonical unsigned address"
            }
            return StructuralBoundaryReplayRequestV1(
                Path.of(text("modelPath")), integer("modelBytes"), text("modelSha256"), text("inputSha256"),
                Path.of(text("functionOraclePath")), integer("functionOracleBytes"), text("functionOracleSha256"),
                base.removePrefix("0x").toULong(16), Path.of(text("outputDirectory")),
                text("operationRequestSha256"), text("fullExportBindingSha256"),
            ).also { require(it.canonicalBytes.contentEquals(bytes)) { "boundary replay request is not exactly canonical" } }
        }
    }
}

/**
 * Pure child computation over pinned inputs. The owning host must establish containment, authenticate
 * captured bytes after worker absence and independently admit any resulting evidence. This worker
 * deliberately accepts fixture truth as well as production-shaped truth and cannot certify either.
 */
internal object StructuralBoundaryReplayWorkerV1 {
    const val OBSERVATION_NAME = "boundary-observation.json"
    const val METADATA_NAME = "boundary-replay-output.json"
    const val MAXIMUM_OBSERVATION_BYTES = 64 * 1024 * 1024
    const val MAXIMUM_METADATA_BYTES = 64 * 1024

    // Fixed full-export parser policy: one 64 MiB / one-million-node function record,
    // 131072 global/type records and at most one counted node/token per bounded source byte.
    // The selected-twin boundary algorithm retains its smaller 20000-function ceiling.
    internal val MODEL_LIMITS = CanonicalProgramModelStreamingLimits(
        maximumInputBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES,
        maximumFunctions = 20_000,
        maximumGlobals = 131_072,
        maximumTypes = 131_072,
        maximumReferencesPerFunction = 1_000_000,
        maximumIdentifierCodePoints = 64 * 1024 * 1024,
        maximumPrototypeCodePoints = 64 * 1024 * 1024,
        maximumTextCodePoints = 64 * 1024 * 1024,
        maximumTotalStringBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES.toLong(),
        maximumNodes = StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES.toLong(),
        maximumTokens = StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES.toLong(),
    )

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2 && WORKER_SHA256.matches(arguments[1])) {
            "boundary replay worker requires a request path and its digest"
        }
        val bytes = readStableWorkerFile(Path.of(arguments[0]), StructuralBoundaryReplayRequestV1.MAXIMUM_REQUEST_BYTES)
        require(OracleArtifacts.sha256(bytes) == arguments[1]) { "boundary replay request differs from the launch binding" }
        run(StructuralBoundaryReplayRequestV1.parse(bytes))
    }

    fun run(request: StructuralBoundaryReplayRequestV1) {
        val outputIdentity = workerDirectoryIdentity(request.outputDirectory)
        Files.list(request.outputDirectory).use { entries ->
            val names = entries.limit(3).map { it.fileName.toString() }.toList()
            require(names.isEmpty() || names.size == 2 && names.toSet() == setOf(
                "contained-command.stdout", "contained-command.stderr")) {
                "boundary replay output directory contains files other than the launcher streams"
            }
            for (name in names) {
                val path = request.outputDirectory.resolve(name)
                require(path.toRealPath() == path) { "boundary replay launcher stream contains indirection" }
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                require(attributes.isRegularFile && attributes.fileKey() != null) {
                    "boundary replay launcher stream must be a regular file"
                }
            }
        }
        val model = readStableWorkerFile(request.modelPath, request.modelBytes)
        require(model.size == request.modelBytes && OracleArtifacts.sha256(model) == request.modelSha256) {
            "boundary replay model differs from the requested snapshot"
        }
        val oracleBefore = workerFileIdentity(request.functionOraclePath, request.functionOracleBytes)
        val oracle = StructuralRecoveryV1Inputs.loadFunctionOracle(request.functionOraclePath,
            StructuralRecoveryV1Limits(maximumJsonInputBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_ORACLE_BYTES))
        requireSameWorkerIdentity(oracleBefore, workerFileIdentity(request.functionOraclePath, request.functionOracleBytes))
        require(oracle.snapshot.size == request.functionOracleBytes && oracle.snapshot.sha256 == request.functionOracleSha256) {
            "boundary replay oracle differs from the requested snapshot"
        }
        require(oracle.artifacts.getValue("stripped").inputSha256 == request.inputSha256 &&
            oracle.artifacts.getValue("stripped").elfImageBase == request.imageBase) {
            "boundary replay oracle differs from the selected input or image base"
        }
        val observed = StructuralBoundaryReplayV1.observeSelected(oracle, "stripped", model, request.imageBase,
            modelLimits = MODEL_LIMITS)
        val replayed = StructuralBoundaryReplayV1.verifySelected(oracle, "stripped", model, request.imageBase,
            observed.canonicalBytes, modelLimits = MODEL_LIMITS)
        val observation = replayed.canonicalBytes
        require(observation.size in 1..MAXIMUM_OBSERVATION_BYTES) { "boundary replay observation exceeds its byte bound" }
        val metadata = outputMetadata(request, observation)
        verifyOutput(request, observation, metadata)
        requireSameWorkerIdentity(outputIdentity, workerDirectoryIdentity(request.outputDirectory), compareContents = false)
        publishWorkerFile(request.outputDirectory.resolve(OBSERVATION_NAME), observation)
        requireSameWorkerIdentity(outputIdentity, workerDirectoryIdentity(request.outputDirectory), compareContents = false)
        publishWorkerFile(request.outputDirectory.resolve(METADATA_NAME), metadata)
        requireSameWorkerIdentity(outputIdentity, workerDirectoryIdentity(request.outputDirectory), compareContents = false)
    }

    /**
     * Checks supplied output bytes against the request. This is a byte-binding check, not replay,
     * authenticated capture, or authority: the caller must separately own the worker execution.
     */
    fun verifyOutput(request: StructuralBoundaryReplayRequestV1, observationBytes: ByteArray, metadataBytes: ByteArray) {
        require(observationBytes.size in 1..MAXIMUM_OBSERVATION_BYTES && metadataBytes.size in 1..MAXIMUM_METADATA_BYTES) {
            "boundary replay output exceeds its byte bound"
        }
        val observation = observationBytes.copyOf()
        val metadata = metadataBytes.copyOf()
        val document = OracleJson.parse(observation, WORKER_OBSERVATION_LIMITS).jsonObject
        require(StructuralJsonEncoder(MAXIMUM_OBSERVATION_BYTES, pretty = true, ensureAscii = true)
            .encode(document).contentEquals(observation)) {
            "boundary replay observation is not in its exact canonical wire form"
        }
        require(document.keys == setOf("provider", "schemaVersion", "functionOracleSha256", "twin", "inputSha256",
            "programModelSha256", "programModelBytes", "selectedModelImageBase", "executableRvaRanges", "nearMissBytes",
            "policy", "programModelParserLimits", "excludedFunctions", "recoveredOutcomeCounts", "result",
            "complete", "scored", "releaseEligible")) { "boundary replay observation does not match its closed schema" }
        val bound = mapOf(
            "provider" to JsonPrimitive("selected-twin-boundary-observation-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "functionOracleSha256" to JsonPrimitive(request.functionOracleSha256),
            "twin" to JsonPrimitive("stripped"),
            "inputSha256" to JsonPrimitive(request.inputSha256),
            "programModelSha256" to JsonPrimitive(request.modelSha256),
            "programModelBytes" to JsonPrimitive(request.modelBytes),
            "selectedModelImageBase" to JsonPrimitive("0x${request.imageBase.toString(16)}"),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        )
        require(bound.all { (name, value) -> document[name] == value }) {
            "boundary replay observation differs from its requested inputs or authority scope"
        }
        // Exact canonical metadata comparison rejects unknown keys, altered counts/digests and
        // any attempt to promote child-authored authority, including a wholly rehashed document.
        OracleJson.parseCanonical(metadata, WORKER_REQUEST_LIMITS)
        require(outputMetadata(request, observation).contentEquals(metadata)) {
            "boundary replay metadata differs from its captured output bindings"
        }
    }

    private fun outputMetadata(request: StructuralBoundaryReplayRequestV1, observation: ByteArray): ByteArray =
        OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-boundary-replay-output-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "authority" to JsonPrimitive("untrusted-worker-computation"),
            "complete" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
            "operationRequestSha256" to JsonPrimitive(request.operationRequestSha256),
            "fullExportBindingSha256" to JsonPrimitive(request.fullExportBindingSha256),
            "modelSha256" to JsonPrimitive(request.modelSha256),
            "modelBytes" to JsonPrimitive(request.modelBytes),
            "inputSha256" to JsonPrimitive(request.inputSha256),
            "functionOracleSha256" to JsonPrimitive(request.functionOracleSha256),
            "functionOracleBytes" to JsonPrimitive(request.functionOracleBytes),
            "imageBase" to JsonPrimitive("0x${request.imageBase.toString(16)}"),
            "observationSha256" to JsonPrimitive(OracleArtifacts.sha256(observation)),
            "observationBytes" to JsonPrimitive(observation.size),
        )), WORKER_REQUEST_LIMITS)
}

private val WORKER_SHA256 = Regex("[a-f0-9]{64}")
private val WORKER_REQUEST_LIMITS = StrictJsonLimits(
    maximumInputBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_REQUEST_BYTES,
    maximumCanonicalBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_REQUEST_BYTES,
    maximumDepth = 4, maximumNodes = 128, maximumStringBytes = 4096,
    maximumTotalStringBytes = 32 * 1024, maximumNumberCharacters = 16,
)
private val WORKER_OBSERVATION_LIMITS = StrictJsonLimits(
    maximumInputBytes = StructuralBoundaryReplayWorkerV1.MAXIMUM_OBSERVATION_BYTES,
    maximumCanonicalBytes = StructuralBoundaryReplayWorkerV1.MAXIMUM_OBSERVATION_BYTES,
    maximumNodes = 1_000_000, maximumStringBytes = 4 * 1024 * 1024,
    maximumTotalStringBytes = 48 * 1024 * 1024,
)

private fun requireReplayWorkerPath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path.parent != null && path.toString().length <= 4096 &&
        path.toString().none { it.code < 32 || it.code == 127 }) { "boundary replay path must be absolute and normalized" }
}

private fun workerFileIdentity(path: Path, maximum: Int): BasicFileAttributes {
    requireReplayWorkerPath(path)
    require(path.toRealPath() == path) { "boundary replay input path contains indirection" }
    return Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).also {
        require(it.isRegularFile && it.fileKey() != null && it.size() in 1..maximum.toLong()) {
            "boundary replay input is not a bounded regular file"
        }
    }
}

private fun workerDirectoryIdentity(path: Path): BasicFileAttributes {
    requireReplayWorkerPath(path)
    require(path.toRealPath() == path) { "boundary replay output path contains indirection" }
    return Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).also {
        require(it.isDirectory && it.fileKey() != null) { "boundary replay output must be a regular directory" }
    }
}

private fun requireSameWorkerIdentity(before: BasicFileAttributes, after: BasicFileAttributes, compareContents: Boolean = true) {
    require(before.fileKey() == after.fileKey() && before.isRegularFile == after.isRegularFile &&
        before.isDirectory == after.isDirectory && (!compareContents ||
        (before.size() == after.size() && before.lastModifiedTime() == after.lastModifiedTime()))) {
        "boundary replay path changed during computation"
    }
}

private fun readStableWorkerFile(path: Path, maximum: Int): ByteArray {
    val before = workerFileIdentity(path, maximum)
    val bytes = ByteArray(before.size().toInt())
    FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) require(channel.read(buffer) >= 0) { "boundary replay input became shorter" }
        require(channel.read(ByteBuffer.allocate(1)) == -1) { "boundary replay input became longer" }
    }
    requireSameWorkerIdentity(before, workerFileIdentity(path, maximum))
    return bytes
}

private fun publishWorkerFile(path: Path, bytes: ByteArray) {
    FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
    FileChannel.open(path.parent, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
}

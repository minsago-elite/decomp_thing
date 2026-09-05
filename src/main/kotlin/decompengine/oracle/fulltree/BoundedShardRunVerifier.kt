package decompengine.oracle.fulltree

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.FilterInputStream
import java.io.InputStream
import java.io.PushbackInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

class BoundedShardRunException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Independent hard ceilings applied while authenticating a bounded-shard run. */
data class BoundedShardRunLimits(
    val maximumControlArtifactBytes: Int = 16 * 1024 * 1024,
    val maximumShards: Int = 1_000_000,
    val maximumWorkers: Int = 32,
    val maximumPerShardEntities: Long = 50_000_000L,
    val maximumWholeRunEntities: Long = 50_000_000L,
    val maximumPerShardOutputBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumWholeRunOutputBytes: Long = 64L * 1024L * 1024L * 1024L,
    val maximumDeclaredResidentBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumDeclaredPerShardSeconds: Long = 86_400L,
    val maximumDeclaredWholeRunSeconds: Long = 86_400L,
    val maximumTokensPerOutput: Long = 1_000_000_000L,
    val maximumDepth: Int = 256,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytesPerOutput: Long = 16L * 1024L * 1024L * 1024L,
    val maximumNumberCharacters: Int = 4096,
    val maximumVerificationWallClockSeconds: Long = 3600L,
    val maximumVerificationCpuSeconds: Long = 3600L,
) {
    init {
        require(maximumControlArtifactBytes in 1..64 * 1024 * 1024)
        require(maximumShards in 1..1_000_000)
        require(maximumWorkers in 1..32)
        require(maximumPerShardEntities in 1L..50_000_000L)
        require(maximumWholeRunEntities in maximumPerShardEntities..50_000_000L)
        require(maximumPerShardOutputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumWholeRunOutputBytes in maximumPerShardOutputBytes..64L * 1024L * 1024L * 1024L)
        require(maximumDeclaredResidentBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDeclaredPerShardSeconds in 1L..86_400L)
        require(maximumDeclaredWholeRunSeconds in maximumDeclaredPerShardSeconds..86_400L)
        require(maximumTokensPerOutput in 1L..1_000_000_000L)
        require(maximumDepth in 1..256)
        require(maximumStringBytes in 1..64 * 1024 * 1024)
        require(maximumTotalStringBytesPerOutput in 1L..maximumPerShardOutputBytes)
        require(maximumNumberCharacters in 1..4096)
        require(maximumVerificationWallClockSeconds in 1L..86_400L)
        require(maximumVerificationCpuSeconds in 1L..86_400L)
    }
}

data class BoundedShardOutputBinding(
    val shardId: String,
    val inputSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
)

/** Authenticated immutable values from one complete run tree. */
data class BoundedShardRunBinding(
    val root: Path,
    val run: JsonObject,
    val index: JsonObject,
    val runSha256: String,
    val indexArtifactSha256: String,
    val maximumWorkers: Int,
    val outputs: List<BoundedShardOutputBinding>,
)

internal data class BoundedShardVerifierRuntimeSample(val wallNanos: Long, val processCpuNanos: Long)

internal fun interface BoundedShardVerifierRuntime {
    fun sample(stage: String): BoundedShardVerifierRuntimeSample
}

/**
 * Read-only authentication for the generic v1 bounded-shard run format.
 *
 * Control objects are bounded before materialization. Shard outputs are strict UTF-8, duplicate-
 * rejecting canonical JSON streams: the verifier reconstructs their canonical digest without
 * retaining arrays or objects. The supplied index artifact SHA-256 is the external trust anchor;
 * the index binds the run, checkpoints, input identities, output bytes, counts, and leaf
 * commitment. Exact tree membership is rechecked before return.
 *
 * Wall/CPU enforcement is cooperative, not an operating-system hard cap. Java NIO cannot bind an
 * open descriptor to its pathname, so regular-file and directory owners remain cooperating trust
 * principals and must not perform same-owner swap-and-restore attacks during verification.
 */
object BoundedShardRunVerifier {
    fun verify(
        root: Path,
        expectedIndexArtifactSha256: String,
        limits: BoundedShardRunLimits = BoundedShardRunLimits(),
    ): BoundedShardRunBinding = exceptionBoundary {
        verifyInternal(root, expectedIndexArtifactSha256, limits, SYSTEM_RUNTIME, emptySet())
    }

    internal fun verifyWithCheckpoint(
        root: Path,
        expectedIndexArtifactSha256: String,
        limits: BoundedShardRunLimits,
        checkpoint: (String) -> Unit,
    ): BoundedShardRunBinding = exceptionBoundary {
        val runtime = BoundedShardVerifierRuntime { stage ->
            checkpoint(stage)
            SYSTEM_RUNTIME.sample(stage)
        }
        verifyInternal(root, expectedIndexArtifactSha256, limits, runtime, emptySet())
    }

    /**
     * Authenticates an embedded bounded-shard tree whose owning format has a fixed set of sibling
     * members. The additional names are implementation-owned, not accepted from a public caller;
     * the owning validator must exact-validate membership and authenticate every permitted sibling.
     */
    internal fun verifyEmbedded(
        root: Path,
        expectedIndexArtifactSha256: String,
        additionalRootMembers: Set<String>,
        limits: BoundedShardRunLimits = BoundedShardRunLimits(),
    ): BoundedShardRunBinding = exceptionBoundary {
        if (additionalRootMembers.size > MAXIMUM_EMBEDDED_ROOT_MEMBERS || additionalRootMembers.any {
                it.length !in 1..MAXIMUM_EMBEDDED_ROOT_MEMBER_CHARACTERS ||
                    !it.matches(EMBEDDED_ROOT_MEMBER) || it in ROOT_MEMBERS
            }
        ) {
            throw BoundedShardRunException("embedded bounded-shard root member name is invalid")
        }
        verifyInternal(root, expectedIndexArtifactSha256, limits, SYSTEM_RUNTIME, additionalRootMembers)
    }

    internal fun verifyForTesting(
        root: Path,
        expectedIndexArtifactSha256: String,
        limits: BoundedShardRunLimits = BoundedShardRunLimits(),
        runtime: BoundedShardVerifierRuntime,
    ): BoundedShardRunBinding = exceptionBoundary {
        verifyInternal(root, expectedIndexArtifactSha256, limits, runtime, emptySet())
    }

    private fun verifyInternal(
        rootPath: Path,
        expectedIndexArtifactSha256: String,
        limits: BoundedShardRunLimits,
        runtime: BoundedShardVerifierRuntime,
        additionalRootMembers: Set<String>,
    ): BoundedShardRunBinding {
        requireSha256(expectedIndexArtifactSha256, "bounded-shard index artifact")
        val budget = VerificationBudget(limits, runtime, runtime.sample("at bounded-shard verification entry"))
        budget.checkpoint("before bounded-shard tree authentication")

        val root = requireTrustedDirectory(rootPath, "bounded-shard run root")
        val rootParentVersion = trustedDirectoryVersion(root.parent, "bounded-shard run parent")
        val rootVersion = trustedDirectoryVersion(root, "bounded-shard run root")
        val expectedRootMembers = ROOT_MEMBERS + additionalRootMembers
        requireDirectMembership(root, expectedRootMembers, "bounded-shard run root", budget)

        val outputsDirectory = root.resolve(OUTPUTS_DIRECTORY)
        val checkpointsDirectory = root.resolve(CHECKPOINTS_DIRECTORY)
        val outputsVersion = trustedDirectoryVersion(outputsDirectory, "bounded-shard outputs directory")
        val checkpointsVersion = trustedDirectoryVersion(checkpointsDirectory, "bounded-shard checkpoints directory")
        val runPath = root.resolve(RUN_FILE)
        val indexPath = root.resolve(INDEX_FILE)
        val runVersion = trustedRegularFileVersion(runPath, "bounded-shard run contract")
        val indexVersion = trustedRegularFileVersion(indexPath, "bounded-shard run index")

        val (run, runBytes) = readControlObject(
            runPath,
            "bounded-shard run contract",
            limits.maximumControlArtifactBytes,
        )
        budget.checkpoint("after bounded-shard run contract read")
        val authenticatedRun = validateRun(run, limits)
        val runSha256 = sha256(runBytes)

        val (index, indexBytes) = readControlObject(
            indexPath,
            "bounded-shard run index",
            limits.maximumControlArtifactBytes,
            schemaName = "bounded-shard-index",
        )
        val indexArtifactSha256 = sha256(indexBytes)
        if (indexArtifactSha256 != expectedIndexArtifactSha256) {
            throw BoundedShardRunException("bounded-shard index artifact SHA-256 differs from its trust anchor")
        }
        budget.checkpoint("after bounded-shard index read")

        val indexedRecords = validateIndexEnvelope(index, runSha256, authenticatedRun, limits)
        val outputNames = authenticatedRun.shards.mapTo(linkedSetOf()) { "${it.identifier}.json" }
        requireDirectMembership(outputsDirectory, outputNames, "bounded-shard outputs directory", budget)
        requireDirectMembership(checkpointsDirectory, outputNames, "bounded-shard checkpoints directory", budget)

        val fileVersions = linkedMapOf<Path, TrustedPathVersion>()
        var totalEntities = 0L
        var totalBytes = 0L
        val leafDigest = MessageDigest.getInstance("SHA-256").apply { update(INDEX_DOMAIN) }
        val bindings = ArrayList<BoundedShardOutputBinding>(authenticatedRun.shards.size)
        authenticatedRun.shards.forEachIndexed { position, shard ->
            budget.periodicCheckpoint("while authenticating bounded-shard records")
            val record = indexedRecords[position]
            val checkpointPath = checkpointsDirectory.resolve("${shard.identifier}.json")
            val outputPath = outputsDirectory.resolve("${shard.identifier}.json")
            fileVersions[checkpointPath] = trustedRegularFileVersion(
                checkpointPath,
                "bounded-shard checkpoint ${shard.identifier}",
            )
            fileVersions[outputPath] = trustedRegularFileVersion(
                outputPath,
                "bounded-shard output ${shard.identifier}",
            )

            val (checkpoint, checkpointBytes) = readControlObject(
                checkpointPath,
                "bounded-shard checkpoint ${shard.identifier}",
                limits.maximumControlArtifactBytes,
            )
            val authenticatedRecord = validateCheckpoint(
                checkpoint,
                shard,
                runSha256,
                authenticatedRun,
                limits,
            )
            if (checkpoint != record) {
                throw BoundedShardRunException("bounded-shard index checkpoint differs for ${shard.identifier}")
            }
            leafDigest.update(MessageDigest.getInstance("SHA-256").digest(checkpointBytes))

            val output = StreamingCanonicalJson.authenticate(
                outputPath,
                "bounded-shard output ${shard.identifier}",
                authenticatedRecord.outputSha256,
                authenticatedRecord.outputBytes,
                minOf(authenticatedRun.bounds.perShardBytes, limits.maximumPerShardOutputBytes),
                limits,
                budget,
            )
            if (output.sha256 != authenticatedRecord.outputSha256 || output.bytes != authenticatedRecord.outputBytes) {
                throw BoundedShardRunException("bounded-shard output binding differs for ${shard.identifier}")
            }

            totalEntities = addExact(totalEntities, authenticatedRecord.entities, "bounded-shard entity")
            totalBytes = addExact(totalBytes, authenticatedRecord.outputBytes, "bounded-shard output byte")
            if (totalEntities > authenticatedRun.bounds.wholeRunEntities ||
                totalEntities > limits.maximumWholeRunEntities
            ) {
                throw BoundedShardRunException("bounded-shard outputs exceed the whole-run entity bound")
            }
            if (totalBytes > authenticatedRun.bounds.wholeRunBytes ||
                totalBytes > limits.maximumWholeRunOutputBytes
            ) {
                throw BoundedShardRunException("bounded-shard outputs exceed the whole-run byte bound")
            }
            bindings += BoundedShardOutputBinding(
                shardId = shard.identifier,
                inputSha256 = shard.inputSha256,
                outputSha256 = authenticatedRecord.outputSha256,
                outputBytes = authenticatedRecord.outputBytes,
                entities = authenticatedRecord.entities,
            )
        }

        val counts = index.requiredObject("counts")
        if (
            counts.keys != COUNT_FIELDS ||
            counts.requiredLong("entities") != totalEntities ||
            counts.requiredLong("serializedBytes") != totalBytes ||
            counts.requiredLong("shards") != bindings.size.toLong()
        ) {
            throw BoundedShardRunException("bounded-shard index counts do not reconcile")
        }
        if (index.requiredString("indexSha256") != leafDigest.digest().hex()) {
            throw BoundedShardRunException("bounded-shard index leaf commitment does not reconcile")
        }

        requireDirectMembership(root, expectedRootMembers, "bounded-shard run root", budget)
        requireDirectMembership(outputsDirectory, outputNames, "bounded-shard outputs directory", budget)
        requireDirectMembership(checkpointsDirectory, outputNames, "bounded-shard checkpoints directory", budget)
        ensureVersion(root.parent, rootParentVersion, "bounded-shard run parent")
        ensureVersion(root, rootVersion, "bounded-shard run root")
        ensureVersion(outputsDirectory, outputsVersion, "bounded-shard outputs directory")
        ensureVersion(checkpointsDirectory, checkpointsVersion, "bounded-shard checkpoints directory")
        ensureVersion(runPath, runVersion, "bounded-shard run contract")
        ensureVersion(indexPath, indexVersion, "bounded-shard run index")
        fileVersions.forEach { (path, version) ->
            ensureVersion(path, version, "bounded-shard member ${path.fileName}")
        }
        budget.checkpoint("after bounded-shard tree authentication")

        return BoundedShardRunBinding(
            root = root,
            run = run,
            index = index,
            runSha256 = runSha256,
            indexArtifactSha256 = indexArtifactSha256,
            maximumWorkers = authenticatedRun.bounds.maximumWorkers,
            outputs = bindings.toList(),
        )
    }

    private fun validateRun(document: JsonObject, limits: BoundedShardRunLimits): AuthenticatedRun {
        if (document.keys != RUN_FIELDS) throw BoundedShardRunException("bounded-shard run fields differ")
        if (document.requiredLong("schemaVersion") != 1L) {
            throw BoundedShardRunException("bounded-shard run schema version differs")
        }
        val runId = document.requiredString("id")
        if (!IDENTIFIER.matches(runId)) throw BoundedShardRunException("bounded-shard run ID is invalid")
        val boundObject = document.requiredObject("bounds")
        if (boundObject.keys != BOUND_FIELDS) throw BoundedShardRunException("bounded-shard run bounds differ")
        val bounds = AuthenticatedBounds(
            maximumResidentBytes = boundObject.positiveLong("maximumResidentBytes"),
            maximumShards = boundObject.positiveInt("maximumShards"),
            maximumWorkers = boundObject.positiveInt("maximumWorkers"),
            perShardBytes = boundObject.positiveLong("perShardBytes"),
            perShardEntities = boundObject.positiveLong("perShardEntities"),
            perShardSeconds = boundObject.positiveFiniteDouble("perShardSeconds"),
            perShardCpuSeconds = boundObject.positiveFiniteDouble("perShardCpuSeconds"),
            wholeRunBytes = boundObject.positiveLong("wholeRunBytes"),
            wholeRunEntities = boundObject.positiveLong("wholeRunEntities"),
            wholeRunSeconds = boundObject.positiveFiniteDouble("wholeRunSeconds"),
            wholeRunCpuSeconds = boundObject.positiveFiniteDouble("wholeRunCpuSeconds"),
        )
        if (bounds.maximumShards > limits.maximumShards) {
            throw BoundedShardRunException("bounded-shard declared shard bound exceeds verifier authority")
        }
        if (bounds.maximumWorkers > minOf(32, bounds.maximumShards, limits.maximumWorkers)) {
            throw BoundedShardRunException("bounded-shard worker bound exceeds deterministic authority")
        }
        if (bounds.perShardEntities > bounds.wholeRunEntities ||
            bounds.perShardEntities > limits.maximumPerShardEntities ||
            bounds.wholeRunEntities > limits.maximumWholeRunEntities
        ) {
            throw BoundedShardRunException("bounded-shard entity bounds are invalid")
        }
        if (bounds.perShardBytes > bounds.wholeRunBytes ||
            bounds.perShardBytes > limits.maximumPerShardOutputBytes ||
            bounds.wholeRunBytes > limits.maximumWholeRunOutputBytes
        ) {
            throw BoundedShardRunException("bounded-shard byte bounds are invalid")
        }
        if (bounds.perShardSeconds > bounds.wholeRunSeconds ||
            bounds.perShardCpuSeconds > bounds.wholeRunCpuSeconds ||
            bounds.perShardSeconds > limits.maximumDeclaredPerShardSeconds.toDouble() ||
            bounds.perShardCpuSeconds > limits.maximumDeclaredPerShardSeconds.toDouble() ||
            bounds.wholeRunSeconds > limits.maximumDeclaredWholeRunSeconds.toDouble() ||
            bounds.wholeRunCpuSeconds > limits.maximumDeclaredWholeRunSeconds.toDouble()
        ) {
            throw BoundedShardRunException("bounded-shard time bounds are invalid")
        }
        if (bounds.maximumResidentBytes > limits.maximumDeclaredResidentBytes) {
            throw BoundedShardRunException("bounded-shard resident-byte declaration exceeds verifier authority")
        }

        val shardValues = document.requiredArray("shards")
        if (shardValues.isEmpty() || shardValues.size > bounds.maximumShards || shardValues.size > limits.maximumShards) {
            throw BoundedShardRunException("bounded-shard population is outside its bound")
        }
        var previous: String? = null
        val shards = shardValues.mapIndexed { index, element ->
            val shard = element as? JsonObject
                ?: throw BoundedShardRunException("bounded-shard run shard $index is not an object")
            if (shard.keys != SHARD_INPUT_FIELDS) {
                throw BoundedShardRunException("bounded-shard run shard fields differ")
            }
            val identifier = shard.requiredString("id")
            if (!IDENTIFIER.matches(identifier)) {
                throw BoundedShardRunException("bounded-shard identifier is invalid: $identifier")
            }
            if (previous != null && FULL_TREE_CODE_POINT_ORDER.compare(previous, identifier) >= 0) {
                throw BoundedShardRunException("bounded-shard run membership is duplicated or unordered")
            }
            previous = identifier
            val inputSha256 = shard.requiredString("inputSha256")
            requireSha256(inputSha256, "bounded-shard input $identifier")
            AuthenticatedShard(identifier, inputSha256)
        }
        return AuthenticatedRun(runId, bounds, shards)
    }

    private fun validateIndexEnvelope(
        index: JsonObject,
        runSha256: String,
        run: AuthenticatedRun,
        limits: BoundedShardRunLimits,
    ): List<JsonObject> {
        if (index.keys != INDEX_FIELDS) throw BoundedShardRunException("bounded-shard index fields differ")
        if (index.requiredLong("schemaVersion") != 1L || !index.requiredBoolean("complete")) {
            throw BoundedShardRunException("bounded-shard index is not a complete v1 index")
        }
        requireSha256(index.requiredString("indexSha256"), "bounded-shard leaf commitment")
        if (index.requiredString("runSha256") != runSha256) {
            throw BoundedShardRunException("bounded-shard index does not bind its run contract")
        }
        val records = index.requiredArray("shards")
        if (records.size != run.shards.size || records.size > limits.maximumShards) {
            throw BoundedShardRunException("bounded-shard index membership is incomplete")
        }
        return records.mapIndexed { indexPosition, element ->
            val record = element as? JsonObject
                ?: throw BoundedShardRunException("bounded-shard index record $indexPosition is not an object")
            if (record.keys != CHECKPOINT_FIELDS ||
                record.requiredString("shardId") != run.shards[indexPosition].identifier
            ) {
                throw BoundedShardRunException("bounded-shard index membership is incomplete or unordered")
            }
            record
        }
    }

    private fun validateCheckpoint(
        checkpoint: JsonObject,
        shard: AuthenticatedShard,
        runSha256: String,
        run: AuthenticatedRun,
        limits: BoundedShardRunLimits,
    ): AuthenticatedCheckpoint {
        if (checkpoint.keys != CHECKPOINT_FIELDS) {
            throw BoundedShardRunException("bounded-shard checkpoint fields differ for ${shard.identifier}")
        }
        if (
            checkpoint.requiredLong("schemaVersion") != 1L ||
            checkpoint.requiredString("status") != "complete" ||
            checkpoint.requiredString("shardId") != shard.identifier ||
            checkpoint.requiredString("inputSha256") != shard.inputSha256 ||
            checkpoint.requiredString("runSha256") != runSha256
        ) {
            throw BoundedShardRunException("bounded-shard checkpoint identity differs for ${shard.identifier}")
        }
        val entities = checkpoint.requiredLong("entities")
        if (entities < 0L || entities > run.bounds.perShardEntities || entities > limits.maximumPerShardEntities) {
            throw BoundedShardRunException("bounded-shard checkpoint entity count is invalid for ${shard.identifier}")
        }
        val outputBytes = checkpoint.requiredLong("outputBytes")
        if (
            outputBytes !in 1L..run.bounds.perShardBytes ||
            outputBytes > limits.maximumPerShardOutputBytes
        ) {
            throw BoundedShardRunException("bounded-shard checkpoint byte count is invalid for ${shard.identifier}")
        }
        val outputSha256 = checkpoint.requiredString("outputSha256")
        requireSha256(outputSha256, "bounded-shard output ${shard.identifier}")
        return AuthenticatedCheckpoint(entities, outputBytes, outputSha256)
    }

    private fun readControlObject(
        path: Path,
        label: String,
        maximumBytes: Int,
        schemaName: String? = null,
    ): Pair<JsonObject, ByteArray> {
        val bytes = try {
            OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes)).bytes
        } catch (failure: Exception) {
            throw BoundedShardRunException("cannot read $label", failure)
        }
        if (bytes.isEmpty()) throw BoundedShardRunException("$label is empty")
        val document = try {
            OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as? JsonObject
                ?: throw BoundedShardRunException("$label root is not an object")
        } catch (failure: BoundedShardRunException) {
            throw failure
        } catch (failure: Exception) {
            throw BoundedShardRunException("$label is not strict canonical JSON", failure)
        }
        if (schemaName != null) {
            try {
                OracleSchemas.validate(schemaName, document)
            } catch (failure: Exception) {
                throw BoundedShardRunException("$label fails its bundled schema", failure)
            }
        }
        return document to bytes
    }

    private fun controlJsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
        maximumNumberCharacters = 4096,
    )

    private data class AuthenticatedRun(
        val identifier: String,
        val bounds: AuthenticatedBounds,
        val shards: List<AuthenticatedShard>,
    )

    private data class AuthenticatedBounds(
        val maximumResidentBytes: Long,
        val maximumShards: Int,
        val maximumWorkers: Int,
        val perShardBytes: Long,
        val perShardEntities: Long,
        val perShardSeconds: Double,
        val perShardCpuSeconds: Double,
        val wholeRunBytes: Long,
        val wholeRunEntities: Long,
        val wholeRunSeconds: Double,
        val wholeRunCpuSeconds: Double,
    )

    private data class AuthenticatedShard(val identifier: String, val inputSha256: String)
    private data class AuthenticatedCheckpoint(val entities: Long, val outputBytes: Long, val outputSha256: String)

    private data class StreamDigest(val bytes: Long, val sha256: String)

    private object StreamingCanonicalJson {
        fun authenticate(
            path: Path,
            label: String,
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Long,
            limits: BoundedShardRunLimits,
            budget: VerificationBudget,
        ): StreamDigest {
            requireSha256(expectedSha256, label)
            if (expectedBytes !in 1L..maximumBytes) throw BoundedShardRunException("$label byte binding is invalid")
            val before = trustedRegularFileVersion(path, label)
            if (before.size != expectedBytes) throw BoundedShardRunException("$label size differs from its checkpoint")
            val rawDigest = MessageDigest.getInstance("SHA-256")
            val canonical = CanonicalDigestSink(maximumBytes, budget, label)
            val bounded = MaximumInputStream(
                Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS),
                maximumBytes,
                budget,
                label,
            )
            try {
                val digested = DigestInputStream(bounded, rawDigest)
                rejectBom(digested, label).use { input ->
                    jsonFactory(limits, maximumBytes).createParser(input).use { parser ->
                        val first = parser.nextToken() ?: throw BoundedShardRunException("$label is empty")
                        val documentBudget = StreamingDocumentBudget(limits, label)
                        writeValue(parser, first, canonical, documentBudget, limits, label, 0, 1)
                        if (parser.nextToken() != null) throw BoundedShardRunException("$label has trailing JSON content")
                        canonical.writeAscii("\n")
                    }
                }
            } catch (failure: BoundedShardRunException) {
                throw failure
            } catch (failure: Exception) {
                throw BoundedShardRunException("cannot authenticate $label: ${failure.message}", failure)
            }
            ensureVersion(path, before, label)
            if (bounded.byteCount != expectedBytes) throw BoundedShardRunException("$label changed size while streaming")
            val raw = rawDigest.digest()
            val rendered = canonical.finish()
            if (canonical.byteCount != bounded.byteCount || !MessageDigest.isEqual(raw, rendered)) {
                throw BoundedShardRunException("$label is not in canonical byte form")
            }
            val sha256 = raw.hex()
            if (sha256 != expectedSha256) throw BoundedShardRunException("$label SHA-256 differs from its checkpoint")
            return StreamDigest(bounded.byteCount, sha256)
        }

        private fun writeValue(
            parser: JsonParser,
            token: JsonToken,
            sink: CanonicalDigestSink,
            budget: StreamingDocumentBudget,
            limits: BoundedShardRunLimits,
            label: String,
            indentation: Int,
            structuralDepth: Int,
        ) {
            budget.chargeNode(structuralDepth)
            when (token) {
                JsonToken.START_OBJECT -> writeObject(
                    parser,
                    sink,
                    budget,
                    limits,
                    label,
                    indentation,
                    structuralDepth,
                )
                JsonToken.START_ARRAY -> writeArray(
                    parser,
                    sink,
                    budget,
                    limits,
                    label,
                    indentation,
                    structuralDepth,
                )
                JsonToken.VALUE_STRING -> {
                    val value = parser.text
                    budget.chargeString(value)
                    sink.writeString(value)
                }
                JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> {
                    sink.writeCanonicalNumber(canonicalNumber(parser, token, limits, label))
                }
                JsonToken.VALUE_TRUE -> sink.writeAscii("true")
                JsonToken.VALUE_FALSE -> sink.writeAscii("false")
                JsonToken.VALUE_NULL -> sink.writeAscii("null")
                else -> throw BoundedShardRunException("$label contains an unsupported JSON token")
            }
        }

        private fun writeObject(
            parser: JsonParser,
            sink: CanonicalDigestSink,
            budget: StreamingDocumentBudget,
            limits: BoundedShardRunLimits,
            label: String,
            indentation: Int,
            structuralDepth: Int,
        ) {
            sink.writeAscii("{")
            var token = parser.nextToken()
            if (token == JsonToken.END_OBJECT) {
                sink.writeAscii("}")
                return
            }
            sink.writeAscii("\n")
            var first = true
            var previous: String? = null
            while (token != JsonToken.END_OBJECT) {
                if (token != JsonToken.FIELD_NAME) throw BoundedShardRunException("$label object is malformed")
                val field = parser.currentName()
                budget.chargeString(field)
                if (previous != null && FULL_TREE_CODE_POINT_ORDER.compare(previous, field) >= 0) {
                    throw BoundedShardRunException("$label object fields are duplicated or not in canonical order")
                }
                previous = field
                if (!first) sink.writeAscii(",\n")
                first = false
                sink.writeSpaces((indentation + 1) * 2)
                sink.writeString(field)
                sink.writeAscii(": ")
                val value = parser.nextToken() ?: throw BoundedShardRunException("$label field $field has no value")
                writeValue(
                    parser,
                    value,
                    sink,
                    budget,
                    limits,
                    label,
                    indentation + 1,
                    structuralDepth + 1,
                )
                token = parser.nextToken()
            }
            sink.writeAscii("\n")
            sink.writeSpaces(indentation * 2)
            sink.writeAscii("}")
        }

        private fun writeArray(
            parser: JsonParser,
            sink: CanonicalDigestSink,
            budget: StreamingDocumentBudget,
            limits: BoundedShardRunLimits,
            label: String,
            indentation: Int,
            structuralDepth: Int,
        ) {
            sink.writeAscii("[")
            var token = parser.nextToken()
            if (token == JsonToken.END_ARRAY) {
                sink.writeAscii("]")
                return
            }
            sink.writeAscii("\n")
            var first = true
            while (token != JsonToken.END_ARRAY) {
                if (!first) sink.writeAscii(",\n")
                first = false
                sink.writeSpaces((indentation + 1) * 2)
                writeValue(
                    parser,
                    token ?: throw BoundedShardRunException("$label array is incomplete"),
                    sink,
                    budget,
                    limits,
                    label,
                    indentation + 1,
                    structuralDepth + 1,
                )
                token = parser.nextToken()
            }
            sink.writeAscii("\n")
            sink.writeSpaces(indentation * 2)
            sink.writeAscii("]")
        }

        private fun canonicalNumber(
            parser: JsonParser,
            token: JsonToken,
            limits: BoundedShardRunLimits,
            label: String,
        ): ByteArray {
            val text = parser.text
            if (text.length > limits.maximumNumberCharacters) {
                throw BoundedShardRunException("$label number exceeds its character limit")
            }
            if (token == JsonToken.VALUE_NUMBER_FLOAT) {
                val number = text.toDoubleOrNull()
                    ?: throw BoundedShardRunException("$label contains an invalid number")
                if (!number.isFinite()) throw BoundedShardRunException("$label contains a non-finite number")
            } else {
                try {
                    BigInteger(text)
                } catch (failure: NumberFormatException) {
                    throw BoundedShardRunException("$label contains an invalid integer", failure)
                }
            }
            val primitive = try {
                Json.parseToJsonElement(text) as JsonPrimitive
            } catch (failure: Exception) {
                throw BoundedShardRunException("$label contains an invalid number", failure)
            }
            val encoded = try {
                OracleJson.canonicalBytes(
                    primitive,
                    StrictJsonLimits(
                        maximumInputBytes = limits.maximumNumberCharacters + 2,
                        maximumCanonicalBytes = limits.maximumNumberCharacters + 2,
                        maximumDepth = 1,
                        maximumNodes = 1,
                        maximumStringBytes = 1,
                        maximumTotalStringBytes = 1,
                        maximumNumberCharacters = limits.maximumNumberCharacters,
                    ),
                )
            } catch (failure: Exception) {
                throw BoundedShardRunException("$label number is not canonically representable", failure)
            }
            return encoded.copyOf(encoded.size - 1)
        }

        private fun jsonFactory(limits: BoundedShardRunLimits, maximumBytes: Long): JsonFactory =
            JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.AUTO_CLOSE_SOURCE)
                .streamReadConstraints(
                    StreamReadConstraints.builder()
                        .maxDocumentLength(maximumBytes)
                        .maxTokenCount(limits.maximumTokensPerOutput)
                        .maxNestingDepth(limits.maximumDepth + 1)
                        .maxStringLength(limits.maximumStringBytes)
                        .maxNameLength(limits.maximumStringBytes)
                        .maxNumberLength(limits.maximumNumberCharacters)
                        .build(),
                )
                .build()

        private fun rejectBom(input: InputStream, label: String): PushbackInputStream {
            val pushback = PushbackInputStream(input, UTF8_BOM.size)
            val prefix = pushback.readNBytes(UTF8_BOM.size)
            if (prefix.contentEquals(UTF8_BOM)) throw BoundedShardRunException("$label contains a UTF-8 BOM")
            pushback.unread(prefix)
            return pushback
        }
    }

    private class StreamingDocumentBudget(
        private val limits: BoundedShardRunLimits,
        private val label: String,
    ) {
        private var nodes = 0L
        private var totalStringBytes = 0L

        fun chargeNode(depth: Int) {
            if (depth > limits.maximumDepth) throw BoundedShardRunException("$label exceeds its nesting-depth limit")
            nodes = addExact(nodes, 1L, "$label JSON node")
            if (nodes > limits.maximumTokensPerOutput) {
                throw BoundedShardRunException("$label exceeds its JSON node limit")
            }
        }

        fun chargeString(value: String) {
            validateSurrogates(value, label)
            val bytes = value.toByteArray(StandardCharsets.UTF_8).size.toLong()
            if (bytes > limits.maximumStringBytes) throw BoundedShardRunException("$label string exceeds its byte limit")
            totalStringBytes = addExact(totalStringBytes, bytes, "$label string byte")
            if (totalStringBytes > limits.maximumTotalStringBytesPerOutput) {
                throw BoundedShardRunException("$label strings exceed their aggregate byte limit")
            }
        }
    }

    private class CanonicalDigestSink(
        private val maximumBytes: Long,
        private val budget: VerificationBudget,
        private val label: String,
    ) {
        private val digest = MessageDigest.getInstance("SHA-256")
        var byteCount = 0L
            private set

        fun writeAscii(value: String) = write(value.toByteArray(StandardCharsets.US_ASCII))
        fun writeCanonicalNumber(value: ByteArray) = write(value)

        fun writeSpaces(count: Int) {
            repeat(count) { write(SPACE) }
        }

        fun writeString(value: String) {
            writeAscii("\"")
            var index = 0
            var plainStart = 0
            while (index < value.length) {
                val current = value[index]
                when (current) {
                    '"', '\\', '\b', '\u000c', '\n', '\r', '\t' -> {
                        writePlain(value, plainStart, index)
                        writeAscii(
                            when (current) {
                                '"' -> "\\\""
                                '\\' -> "\\\\"
                                '\b' -> "\\b"
                                '\u000c' -> "\\f"
                                '\n' -> "\\n"
                                '\r' -> "\\r"
                                else -> "\\t"
                            },
                        )
                        index++
                        plainStart = index
                    }
                    else -> when {
                        current.code < 0x20 -> {
                            writePlain(value, plainStart, index)
                            writeAscii("\\u${current.code.toString(16).padStart(4, '0')}")
                            index++
                            plainStart = index
                        }
                        Character.isHighSurrogate(current) -> {
                            if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                                throw BoundedShardRunException("$label contains an unpaired high surrogate")
                            }
                            index += 2
                        }
                        Character.isLowSurrogate(current) -> {
                            throw BoundedShardRunException("$label contains an unpaired low surrogate")
                        }
                        else -> index++
                    }
                }
            }
            writePlain(value, plainStart, value.length)
            writeAscii("\"")
        }

        fun finish(): ByteArray = digest.digest()

        private fun write(value: ByteArray) {
            if (byteCount > maximumBytes - value.size.toLong()) {
                throw BoundedShardRunException("$label canonical bytes exceed their bound")
            }
            digest.update(value)
            byteCount += value.size.toLong()
            budget.chargeBytes(value.size.toLong(), "while reconstructing $label")
        }

        private fun writePlain(value: String, start: Int, end: Int) {
            if (start < end) write(value.substring(start, end).toByteArray(StandardCharsets.UTF_8))
        }

        private companion object {
            val SPACE = byteArrayOf(' '.code.toByte())
        }
    }

    private class MaximumInputStream(
        input: InputStream,
        private val maximumBytes: Long,
        private val budget: VerificationBudget,
        private val label: String,
    ) : FilterInputStream(input) {
        var byteCount = 0L
            private set

        override fun read(): Int {
            val value = super.read()
            if (value >= 0) charge(1L)
            return value
        }

        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
            if (length == 0) return 0
            val remainingWithSentinel = maximumBytes - byteCount + 1L
            val requested = minOf(length.toLong(), maxOf(1L, remainingWithSentinel)).toInt()
            val read = super.read(bytes, offset, requested)
            if (read > 0) charge(read.toLong())
            return read
        }

        private fun charge(bytes: Long) {
            byteCount = addExact(byteCount, bytes, "$label input byte")
            if (byteCount > maximumBytes) throw BoundedShardRunException("$label exceeds its byte limit")
            budget.chargeBytes(bytes, "while reading $label")
        }
    }

    private class VerificationBudget(
        limits: BoundedShardRunLimits,
        private val runtime: BoundedShardVerifierRuntime,
        private val started: BoundedShardVerifierRuntimeSample,
    ) {
        private val maximumWallNanos = TimeUnit.SECONDS.toNanos(limits.maximumVerificationWallClockSeconds)
        private val maximumCpuNanos = TimeUnit.SECONDS.toNanos(limits.maximumVerificationCpuSeconds)
        private var periodicUnits = 0L
        private var bytesUntilCheckpoint = CHECKPOINT_BYTES

        fun checkpoint(stage: String) {
            if (Thread.currentThread().isInterrupted) throw BoundedShardRunException("bounded-shard verification interrupted $stage")
            val current = runtime.sample(stage)
            val wall = current.wallNanos - started.wallNanos
            val cpu = current.processCpuNanos - started.processCpuNanos
            if (wall < 0L || wall > maximumWallNanos) {
                throw BoundedShardRunException("bounded-shard verification exceeds wall-clock bound $stage")
            }
            if (cpu < 0L || cpu > maximumCpuNanos) {
                throw BoundedShardRunException("bounded-shard verification exceeds process-CPU bound $stage")
            }
        }

        fun periodicCheckpoint(stage: String) {
            periodicUnits++
            if ((periodicUnits and 255L) == 0L) checkpoint(stage)
        }

        fun chargeBytes(bytes: Long, stage: String) {
            bytesUntilCheckpoint -= bytes
            if (bytesUntilCheckpoint <= 0L) {
                checkpoint(stage)
                bytesUntilCheckpoint = CHECKPOINT_BYTES
            }
        }
    }

    private data class TrustedPathVersion(
        val identity: Any,
        val size: Long,
        val modified: FileTime,
        val permissions: Set<PosixFilePermission>,
        val directory: Boolean,
    )

    private fun requireTrustedDirectory(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        if (normalized.fileName == null || normalized.parent == null) {
            throw BoundedShardRunException("$label must name a directory")
        }
        val real = try {
            normalized.toRealPath()
        } catch (failure: Exception) {
            throw BoundedShardRunException("$label is unavailable", failure)
        }
        if (real != normalized) throw BoundedShardRunException("$label path contains a symbolic link")
        trustedDirectoryVersion(normalized.parent, "$label parent")
        trustedDirectoryVersion(normalized, label)
        return normalized
    }

    private fun trustedDirectoryVersion(path: Path, label: String): TrustedPathVersion =
        trustedVersion(path, label, directory = true)

    private fun trustedRegularFileVersion(path: Path, label: String): TrustedPathVersion =
        trustedVersion(path, label, directory = false)

    private fun trustedVersion(path: Path, label: String, directory: Boolean): TrustedPathVersion {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw BoundedShardRunException("$label attributes are unavailable", failure)
        }
        if (attributes.isSymbolicLink || attributes.fileKey() == null ||
            (directory && !attributes.isDirectory) || (!directory && !attributes.isRegularFile)
        ) {
            throw BoundedShardRunException("$label has an invalid path type or no stable identity")
        }
        val permissions = try {
            Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                ?.readAttributes()?.permissions()?.toSet()
                ?: throw BoundedShardRunException("$label requires POSIX permissions")
        } catch (failure: BoundedShardRunException) {
            throw failure
        } catch (failure: Exception) {
            throw BoundedShardRunException("$label permissions are unavailable", failure)
        }
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw BoundedShardRunException("$label is writable by group or other principals")
        }
        return TrustedPathVersion(
            identity = attributes.fileKey(),
            size = attributes.size(),
            modified = attributes.lastModifiedTime(),
            permissions = permissions,
            directory = directory,
        )
    }

    private fun ensureVersion(path: Path, expected: TrustedPathVersion, label: String) {
        val actual = trustedVersion(path, label, expected.directory)
        if (actual != expected) throw BoundedShardRunException("$label identity, metadata, or permissions changed")
    }

    private fun requireDirectMembership(
        directory: Path,
        expectedNames: Set<String>,
        label: String,
        budget: VerificationBudget,
    ) {
        val actual = linkedSetOf<String>()
        try {
            Files.newDirectoryStream(directory).use { entries ->
                entries.forEach { path ->
                    budget.periodicCheckpoint("while checking $label membership")
                    val name = path.fileName?.toString()
                        ?: throw BoundedShardRunException("$label contains an unnamed path")
                    if (!actual.add(name)) throw BoundedShardRunException("$label contains duplicate membership")
                    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                    if (attributes.isSymbolicLink) throw BoundedShardRunException("$label contains a symbolic link")
                }
            }
        } catch (failure: BoundedShardRunException) {
            throw failure
        } catch (failure: Exception) {
            throw BoundedShardRunException("cannot enumerate $label", failure)
        }
        if (actual != expectedNames) throw BoundedShardRunException("$label membership is missing or extra")
    }

    private fun JsonObject.positiveLong(name: String): Long = requiredLong(name).also {
        if (it <= 0L) throw BoundedShardRunException("bounded-shard bound $name must be positive")
    }

    private fun JsonObject.positiveInt(name: String): Int = positiveLong(name).let {
        if (it > Int.MAX_VALUE.toLong()) throw BoundedShardRunException("bounded-shard bound $name is too large")
        it.toInt()
    }

    private fun JsonObject.positiveFiniteDouble(name: String): Double {
        val primitive = this[name] as? JsonPrimitive
            ?: throw BoundedShardRunException("bounded-shard bound $name is not numeric")
        if (primitive.isString || primitive.booleanOrNull != null) {
            throw BoundedShardRunException("bounded-shard bound $name is not numeric")
        }
        val value = primitive.content.toDoubleOrNull()
            ?: throw BoundedShardRunException("bounded-shard bound $name is invalid")
        if (!value.isFinite() || value <= 0.0) {
            throw BoundedShardRunException("bounded-shard bound $name must be positive and finite")
        }
        return value
    }

    private fun JsonObject.requiredBoolean(name: String): Boolean {
        val primitive = this[name] as? JsonPrimitive
            ?: throw BoundedShardRunException("bounded-shard field $name is not boolean")
        return primitive.booleanOrNull
            ?: throw BoundedShardRunException("bounded-shard field $name is not boolean")
    }

    private fun requireSha256(value: String, label: String) {
        if (!SHA256.matches(value)) throw BoundedShardRunException("$label SHA-256 is invalid")
    }

    private inline fun <T> exceptionBoundary(block: () -> T): T = try {
        block()
    } catch (failure: BoundedShardRunException) {
        throw failure
    } catch (failure: Exception) {
        throw BoundedShardRunException("bounded-shard run authentication failed: ${failure.message}", failure)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw BoundedShardRunException("$label count exceeds the supported range", failure)
    }

    private fun validateSurrogates(value: String, label: String) {
        var index = 0
        while (index < value.length) {
            when {
                Character.isHighSurrogate(value[index]) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                        throw BoundedShardRunException("$label contains an unpaired high surrogate")
                    }
                    index += 2
                }
                Character.isLowSurrogate(value[index]) -> {
                    throw BoundedShardRunException("$label contains an unpaired low surrogate")
                }
                else -> index++
            }
        }
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private val SYSTEM_RUNTIME = BoundedShardVerifierRuntime {
        BoundedShardVerifierRuntimeSample(
            wallNanos = System.nanoTime(),
            processCpuNanos = ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow { BoundedShardRunException("process CPU duration is unavailable") }
                .toNanos(),
        )
    }
    private val ROOT_MEMBERS = setOf(RUN_FILE, INDEX_FILE, OUTPUTS_DIRECTORY, CHECKPOINTS_DIRECTORY)
    private val EMBEDDED_ROOT_MEMBER = Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*")
    private val RUN_FIELDS = setOf("bounds", "id", "schemaVersion", "shards")
    private val BOUND_FIELDS = setOf(
        "maximumResidentBytes",
        "maximumShards",
        "maximumWorkers",
        "perShardBytes",
        "perShardCpuSeconds",
        "perShardEntities",
        "perShardSeconds",
        "wholeRunBytes",
        "wholeRunCpuSeconds",
        "wholeRunEntities",
        "wholeRunSeconds",
    )
    private val SHARD_INPUT_FIELDS = setOf("id", "inputSha256")
    private val INDEX_FIELDS = setOf("complete", "counts", "indexSha256", "runSha256", "schemaVersion", "shards")
    private val COUNT_FIELDS = setOf("entities", "serializedBytes", "shards")
    private val CHECKPOINT_FIELDS = setOf(
        "entities",
        "inputSha256",
        "outputBytes",
        "outputSha256",
        "runSha256",
        "schemaVersion",
        "shardId",
        "status",
    )
    private val IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val INDEX_DOMAIN = "bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val UTF8_BOM = byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte())
    private val UNTRUSTED_WRITE_PERMISSIONS = setOf(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )
    private const val RUN_FILE = "run.json"
    private const val INDEX_FILE = "index.json"
    private const val OUTPUTS_DIRECTORY = "outputs"
    private const val CHECKPOINTS_DIRECTORY = "checkpoints"
    private const val CHECKPOINT_BYTES = 1024L * 1024L
    private const val MAXIMUM_EMBEDDED_ROOT_MEMBERS = 8
    private const val MAXIMUM_EMBEDDED_ROOT_MEMBER_CHARACTERS = 128
}

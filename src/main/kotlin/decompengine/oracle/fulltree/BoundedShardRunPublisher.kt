package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedShardRunPublicationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** The v1 run declarations recorded by [BoundedShardRunPublisher]. */
data class BoundedShardRunPublicationBounds(
    val maximumShards: Int,
    val perShardEntities: Long,
    val wholeRunEntities: Long,
    val perShardBytes: Long,
    val wholeRunBytes: Long,
    val perShardSeconds: Double,
    val wholeRunSeconds: Double,
    val perShardCpuSeconds: Double,
    val wholeRunCpuSeconds: Double,
    val maximumResidentBytes: Long,
    val maximumWorkers: Int,
)

/** A completed output and the caller-authoritative identities that it must satisfy. */
data class BoundedShardPreparedOutput(
    val shardId: String,
    val inputSha256: String,
    val output: Path,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
)

/** Stable staged bytes presented to the caller's semantic authority before publication. */
data class BoundedShardOutputValidation(
    val runId: String,
    val shardId: String,
    val inputSha256: String,
    val output: Path,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
)

fun interface BoundedShardOutputSemanticValidator {
    fun validate(output: BoundedShardOutputValidation)
}

internal enum class BoundedShardRunPublicationStage {
    BEFORE_STAGED_VERIFICATION,
    BEFORE_ATOMIC_MOVE,
    AFTER_TARGET_ABSENCE_CHECK,
    AFTER_ATOMIC_MOVE,
    AFTER_FINAL_VERIFICATION,
}

internal fun interface BoundedShardRunPublicationProbe {
    fun checkpoint(stage: BoundedShardRunPublicationStage)
}

/**
 * Publishes already-completed shard outputs as the exact generic bounded-shard v1 tree.
 *
 * This is a publication/commit layer, not a worker executor. It authenticates stable prepared
 * bytes and binds their caller-supplied input digests and entity counts, but cannot attest how a
 * worker produced them, worker isolation, resource consumption, or shard semantics. The mandatory
 * [BoundedShardOutputSemanticValidator] is the caller's trusted semantic authority; it receives a
 * private read-only staged file whose identity and bytes are reauthenticated after the callback.
 *
 * Prepared files must be POSIX private read-only regular files (`0400`) beneath non-symlink,
 * non-group/other-writable parents. Publication uses a private sibling staging directory, freezes
 * every member read-only, verifies the staged tree, and performs a Linux `renameat2`
 * `RENAME_NOREPLACE` atomic move. A
 * second [BoundedShardRunVerifier] pass gates successful return. As with the verifier, same-owner
 * pathname swap-and-restore attacks and non-cooperating owners of any ancestor directory are trust
 * principals outside this pathname-based model.
 */
object BoundedShardRunPublisher {
    fun publish(
        target: Path,
        runId: String,
        preparedOutputs: List<BoundedShardPreparedOutput>,
        bounds: BoundedShardRunPublicationBounds,
        semanticValidator: BoundedShardOutputSemanticValidator,
        limits: BoundedShardRunLimits = BoundedShardRunLimits(),
    ): BoundedShardRunBinding = exceptionBoundary {
        publishInternal(
            target,
            runId,
            preparedOutputs,
            bounds,
            semanticValidator,
            limits,
            NOOP_PROBE,
        )
    }

    internal fun publishForTesting(
        target: Path,
        runId: String,
        preparedOutputs: List<BoundedShardPreparedOutput>,
        bounds: BoundedShardRunPublicationBounds,
        semanticValidator: BoundedShardOutputSemanticValidator,
        limits: BoundedShardRunLimits = BoundedShardRunLimits(),
        probe: BoundedShardRunPublicationProbe,
    ): BoundedShardRunBinding = exceptionBoundary {
        publishInternal(target, runId, preparedOutputs, bounds, semanticValidator, limits, probe)
    }

    private fun publishInternal(
        targetPath: Path,
        runId: String,
        preparedOutputs: List<BoundedShardPreparedOutput>,
        bounds: BoundedShardRunPublicationBounds,
        semanticValidator: BoundedShardOutputSemanticValidator,
        limits: BoundedShardRunLimits,
        probe: BoundedShardRunPublicationProbe,
    ): BoundedShardRunBinding {
        val target = normalizeTarget(targetPath)
        validateRunId(runId)
        validateBounds(bounds, limits)
        val sources = authenticateSources(preparedOutputs, bounds, limits)
        val controls = createControls(runId, sources, bounds, limits)

        Publication.create(target, sources.map { it.prepared.shardId }).use { publication ->
            publication.writeRootControl(RUN_FILE, controls.runBytes)
            val staged = sources.map { source -> publication.copyOutput(source, bounds, limits) }
            publication.freezeOutputs()

            staged.forEach { output ->
                semanticValidator.validate(
                    BoundedShardOutputValidation(
                        runId = runId,
                        shardId = output.source.prepared.shardId,
                        inputSha256 = output.source.prepared.inputSha256,
                        output = output.path,
                        outputSha256 = output.source.prepared.outputSha256,
                        outputBytes = output.source.prepared.outputBytes,
                        entities = output.source.prepared.entities,
                    ),
                )
                output.ensureStable("staged output after semantic validation")
                output.source.ensureStable("prepared output after semantic validation")
            }

            controls.checkpoints.forEach { checkpoint ->
                publication.writeCheckpoint(checkpoint.shardId, checkpoint.bytes)
            }
            publication.writeRootControl(INDEX_FILE, controls.indexBytes)
            publication.freezeTree()
            probe.checkpoint(BoundedShardRunPublicationStage.BEFORE_STAGED_VERIFICATION)
            publication.ensureCompleteTree()
            ensureSourcesStable(sources, "before staged verification")
            val stagedBinding = verify(
                publication.staging,
                controls.indexArtifactSha256,
                limits,
                "staged bounded-shard run",
            )
            requireExpectedBinding(stagedBinding, controls, sources, publication.staging, bounds)
            ensureSourcesStable(sources, "after staged verification")

            return publication.commit(
                controls = controls,
                sources = sources,
                bounds = bounds,
                limits = limits,
                probe = probe,
            )
        }
    }

    private fun authenticateSources(
        preparedOutputs: List<BoundedShardPreparedOutput>,
        bounds: BoundedShardRunPublicationBounds,
        limits: BoundedShardRunLimits,
    ): List<TrustedSource> {
        if (preparedOutputs.isEmpty() ||
            preparedOutputs.size > bounds.maximumShards ||
            preparedOutputs.size > limits.maximumShards
        ) {
            throw BoundedShardRunPublicationException("prepared shard population is outside its bound")
        }
        val indexNodes = 10L + 9L * preparedOutputs.size.toLong()
        if (indexNodes > MAXIMUM_CONTROL_NODES) {
            throw BoundedShardRunPublicationException("prepared shard population exceeds strict control limits")
        }

        val ordered = preparedOutputs.sortedWith { left, right ->
            FULL_TREE_CODE_POINT_ORDER.compare(left.shardId, right.shardId)
        }
        val identifiers = HashSet<String>()
        val paths = HashSet<Path>()
        val identities = HashSet<Any>()
        var totalEntities = 0L
        var totalBytes = 0L
        return ordered.map { prepared ->
            if (!IDENTIFIER.matches(prepared.shardId)) {
                throw BoundedShardRunPublicationException("prepared shard identifier is invalid: ${prepared.shardId}")
            }
            if (!identifiers.add(prepared.shardId)) {
                throw BoundedShardRunPublicationException("prepared shard identifiers are not unique")
            }
            requireSha256(prepared.inputSha256, "prepared input ${prepared.shardId}")
            requireSha256(prepared.outputSha256, "prepared output ${prepared.shardId}")
            if (prepared.entities !in 0L..minOf(bounds.perShardEntities, limits.maximumPerShardEntities)) {
                throw BoundedShardRunPublicationException(
                    "prepared shard entity count is outside its bound: ${prepared.shardId}",
                )
            }
            if (prepared.outputBytes !in 1L..minOf(bounds.perShardBytes, limits.maximumPerShardOutputBytes)) {
                throw BoundedShardRunPublicationException(
                    "prepared shard byte count is outside its bound: ${prepared.shardId}",
                )
            }
            totalEntities = addExact(totalEntities, prepared.entities, "prepared entity")
            totalBytes = addExact(totalBytes, prepared.outputBytes, "prepared output byte")
            if (totalEntities > bounds.wholeRunEntities || totalEntities > limits.maximumWholeRunEntities) {
                throw BoundedShardRunPublicationException("prepared shards exceed the whole-run entity bound")
            }
            if (totalBytes > bounds.wholeRunBytes || totalBytes > limits.maximumWholeRunOutputBytes) {
                throw BoundedShardRunPublicationException("prepared shards exceed the whole-run byte bound")
            }

            val path = requireTrustedSourcePath(prepared.output, "prepared output ${prepared.shardId}")
            if (!paths.add(path)) {
                throw BoundedShardRunPublicationException("prepared shard paths are not unique")
            }
            val parent = trustedDirectorySeal(path.parent, "prepared output parent ${prepared.shardId}")
            val version = trustedFileVersion(path, "prepared output ${prepared.shardId}", privateReadOnly = true)
            if (!identities.add(version.identity)) {
                throw BoundedShardRunPublicationException("prepared shard files do not have unique identities")
            }
            if (version.size != prepared.outputBytes) {
                throw BoundedShardRunPublicationException(
                    "prepared output size differs from its binding: ${prepared.shardId}",
                )
            }
            TrustedSource(prepared, path, parent, version)
        }
    }

    private fun createControls(
        runId: String,
        sources: List<TrustedSource>,
        bounds: BoundedShardRunPublicationBounds,
        limits: BoundedShardRunLimits,
    ): ControlPlan {
        val run = JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "maximumResidentBytes" to JsonPrimitive(bounds.maximumResidentBytes),
                        "maximumShards" to JsonPrimitive(bounds.maximumShards),
                        "maximumWorkers" to JsonPrimitive(bounds.maximumWorkers),
                        "perShardBytes" to JsonPrimitive(bounds.perShardBytes),
                        "perShardCpuSeconds" to JsonPrimitive(bounds.perShardCpuSeconds),
                        "perShardEntities" to JsonPrimitive(bounds.perShardEntities),
                        "perShardSeconds" to JsonPrimitive(bounds.perShardSeconds),
                        "wholeRunBytes" to JsonPrimitive(bounds.wholeRunBytes),
                        "wholeRunCpuSeconds" to JsonPrimitive(bounds.wholeRunCpuSeconds),
                        "wholeRunEntities" to JsonPrimitive(bounds.wholeRunEntities),
                        "wholeRunSeconds" to JsonPrimitive(bounds.wholeRunSeconds),
                    ),
                ),
                "id" to JsonPrimitive(runId),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    sources.map { source ->
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive(source.prepared.shardId),
                                "inputSha256" to JsonPrimitive(source.prepared.inputSha256),
                            ),
                        )
                    },
                ),
            ),
        )
        val runBytes = canonicalBytes(run, limits.maximumControlArtifactBytes, "bounded-shard run contract")
        val runSha256 = sha256(runBytes)
        val leafDigest = MessageDigest.getInstance("SHA-256")
        leafDigest.update(INDEX_DOMAIN)
        var checkpointBytes = 0L
        val checkpoints = sources.map { source ->
            val prepared = source.prepared
            val document = JsonObject(
                mapOf(
                    "entities" to JsonPrimitive(prepared.entities),
                    "inputSha256" to JsonPrimitive(prepared.inputSha256),
                    "outputBytes" to JsonPrimitive(prepared.outputBytes),
                    "outputSha256" to JsonPrimitive(prepared.outputSha256),
                    "runSha256" to JsonPrimitive(runSha256),
                    "schemaVersion" to JsonPrimitive(1),
                    "shardId" to JsonPrimitive(prepared.shardId),
                    "status" to JsonPrimitive("complete"),
                ),
            )
            val bytes = canonicalBytes(
                document,
                limits.maximumControlArtifactBytes,
                "bounded-shard checkpoint ${prepared.shardId}",
            )
            checkpointBytes = addExact(checkpointBytes, bytes.size.toLong(), "checkpoint control byte")
            if (checkpointBytes > limits.maximumControlArtifactBytes.toLong()) {
                throw BoundedShardRunPublicationException("bounded-shard index exceeds strict control limits")
            }
            leafDigest.update(MessageDigest.getInstance("SHA-256").digest(bytes))
            CheckpointPlan(prepared.shardId, document, bytes)
        }
        val totalEntities = sources.fold(0L) { total, source ->
            addExact(total, source.prepared.entities, "index entity")
        }
        val totalBytes = sources.fold(0L) { total, source ->
            addExact(total, source.prepared.outputBytes, "index output byte")
        }
        val index = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to JsonObject(
                    mapOf(
                        "entities" to JsonPrimitive(totalEntities),
                        "serializedBytes" to JsonPrimitive(totalBytes),
                        "shards" to JsonPrimitive(sources.size),
                    ),
                ),
                "indexSha256" to JsonPrimitive(leafDigest.digest().hex()),
                "runSha256" to JsonPrimitive(runSha256),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(checkpoints.map { it.document }),
            ),
        )
        val indexBytes = canonicalBytes(index, limits.maximumControlArtifactBytes, "bounded-shard index")
        return ControlPlan(
            run = run,
            runBytes = runBytes,
            runSha256 = runSha256,
            checkpoints = checkpoints,
            index = index,
            indexBytes = indexBytes,
            indexArtifactSha256 = sha256(indexBytes),
        )
    }

    private fun validateRunId(runId: String) {
        if (!IDENTIFIER.matches(runId)) {
            throw BoundedShardRunPublicationException("bounded-shard run ID must be lowercase kebab-case")
        }
    }

    private fun validateBounds(bounds: BoundedShardRunPublicationBounds, limits: BoundedShardRunLimits) {
        if (bounds.maximumShards !in 1..limits.maximumShards) {
            throw BoundedShardRunPublicationException("declared maximum shards exceeds publisher authority")
        }
        if (bounds.maximumWorkers !in 1..minOf(32, bounds.maximumShards, limits.maximumWorkers)) {
            throw BoundedShardRunPublicationException("declared maximum workers exceeds deterministic authority")
        }
        if (bounds.perShardEntities !in 1L..minOf(bounds.wholeRunEntities, limits.maximumPerShardEntities) ||
            bounds.wholeRunEntities !in bounds.perShardEntities..limits.maximumWholeRunEntities
        ) {
            throw BoundedShardRunPublicationException("declared entity bounds are invalid")
        }
        if (bounds.perShardBytes !in 1L..minOf(bounds.wholeRunBytes, limits.maximumPerShardOutputBytes) ||
            bounds.wholeRunBytes !in bounds.perShardBytes..limits.maximumWholeRunOutputBytes
        ) {
            throw BoundedShardRunPublicationException("declared byte bounds are invalid")
        }
        if (!validTimePair(
                bounds.perShardSeconds,
                bounds.wholeRunSeconds,
                limits.maximumDeclaredPerShardSeconds,
                limits.maximumDeclaredWholeRunSeconds,
            ) ||
            !validTimePair(
                bounds.perShardCpuSeconds,
                bounds.wholeRunCpuSeconds,
                limits.maximumDeclaredPerShardSeconds,
                limits.maximumDeclaredWholeRunSeconds,
            )
        ) {
            throw BoundedShardRunPublicationException("declared time bounds are invalid")
        }
        if (bounds.maximumResidentBytes !in 1L..limits.maximumDeclaredResidentBytes) {
            throw BoundedShardRunPublicationException("declared resident-byte bound exceeds publisher authority")
        }
    }

    private fun validTimePair(perShard: Double, wholeRun: Double, perLimit: Long, wholeLimit: Long): Boolean =
        perShard.isFinite() && wholeRun.isFinite() && perShard > 0.0 && wholeRun >= perShard &&
            perShard <= perLimit.toDouble() && wholeRun <= wholeLimit.toDouble()

    private fun requireExpectedBinding(
        binding: BoundedShardRunBinding,
        controls: ControlPlan,
        sources: List<TrustedSource>,
        expectedRoot: Path,
        bounds: BoundedShardRunPublicationBounds,
    ) {
        val expectedOutputs = sources.map { source ->
            val prepared = source.prepared
            BoundedShardOutputBinding(
                shardId = prepared.shardId,
                inputSha256 = prepared.inputSha256,
                outputSha256 = prepared.outputSha256,
                outputBytes = prepared.outputBytes,
                entities = prepared.entities,
            )
        }
        if (
            binding.root != expectedRoot.toAbsolutePath().normalize() ||
            binding.run != controls.run ||
            binding.index != controls.index ||
            binding.runSha256 != controls.runSha256 ||
            binding.indexArtifactSha256 != controls.indexArtifactSha256 ||
            binding.maximumWorkers != bounds.maximumWorkers ||
            binding.outputs != expectedOutputs
        ) {
            throw BoundedShardRunPublicationException("verified bounded-shard binding differs from publication plan")
        }
    }

    private fun verify(
        root: Path,
        indexArtifactSha256: String,
        limits: BoundedShardRunLimits,
        label: String,
    ): BoundedShardRunBinding = try {
        BoundedShardRunVerifier.verify(root, indexArtifactSha256, limits)
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("cannot authenticate $label", failure)
    }

    private class Publication private constructor(
        private val target: Path,
        val staging: Path,
        private val parentSeal: DirectorySeal,
        private val stagingIdentity: Any,
        private val outputDirectoryIdentity: Any,
        private val checkpointDirectoryIdentity: Any,
        shardIds: List<String>,
    ) : AutoCloseable {
        private val expectedNames = shardIds.mapTo(linkedSetOf()) { "$it.json" }
        private val intendedFiles = linkedSetOf<Path>()
        private val identities = linkedMapOf<Path, Any>()
        private val versions = linkedMapOf<Path, TrustedVersion>()
        private var committed = false
        private var published = false

        fun writeRootControl(name: String, bytes: ByteArray) {
            write(staging.resolve(name), bytes, "staged bounded-shard $name")
        }

        fun writeCheckpoint(shardId: String, bytes: ByteArray) {
            write(
                staging.resolve(CHECKPOINTS_DIRECTORY).resolve("$shardId.json"),
                bytes,
                "staged bounded-shard checkpoint $shardId",
            )
        }

        fun copyOutput(
            source: TrustedSource,
            bounds: BoundedShardRunPublicationBounds,
            limits: BoundedShardRunLimits,
        ): StagedOutput {
            source.ensureStable("prepared output before copy")
            val prepared = source.prepared
            val destination = staging.resolve(OUTPUTS_DIRECTORY).resolve("${prepared.shardId}.json")
            intendedFiles.add(relative(destination))
            val digest = MessageDigest.getInstance("SHA-256")
            var observed = 0L
            try {
                FileChannel.open(
                    destination,
                    setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_WRITABLE_FILE_PERMISSIONS),
                ).use { output ->
                    identities[relative(destination)] = fileIdentity(destination, "staged output ${prepared.shardId}")
                    FileChannel.open(source.path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
                        val buffer = ByteBuffer.allocate(COPY_BUFFER_BYTES)
                        while (true) {
                            buffer.clear()
                            val read = input.read(buffer)
                            if (read < 0) break
                            if (read == 0) continue
                            if (observed > prepared.outputBytes - read.toLong()) {
                                throw BoundedShardRunPublicationException(
                                    "prepared output exceeds its byte binding: ${prepared.shardId}",
                                )
                            }
                            observed += read.toLong()
                            if (observed > bounds.perShardBytes ||
                                observed > limits.maximumPerShardOutputBytes
                            ) {
                                throw BoundedShardRunPublicationException(
                                    "prepared output exceeds its byte bound: ${prepared.shardId}",
                                )
                            }
                            buffer.flip()
                            digest.update(buffer.asReadOnlyBuffer())
                            while (buffer.hasRemaining()) output.write(buffer)
                        }
                    }
                    output.force(true)
                }
                if (observed != prepared.outputBytes || digest.digest().hex() != prepared.outputSha256) {
                    throw BoundedShardRunPublicationException(
                        "prepared output bytes differ from their binding: ${prepared.shardId}",
                    )
                }
                source.ensureStable("prepared output after copy")
                Files.setPosixFilePermissions(destination, PRIVATE_READ_ONLY_FILE_PERMISSIONS)
                val version = trustedFileVersion(
                    destination,
                    "staged output ${prepared.shardId}",
                    privateReadOnly = true,
                )
                versions[relative(destination)] = version
                return StagedOutput(source, destination, version)
            } catch (failure: BoundedShardRunPublicationException) {
                throw failure
            } catch (failure: Exception) {
                throw BoundedShardRunPublicationException(
                    "cannot stage prepared output ${prepared.shardId}",
                    failure,
                )
            }
        }

        fun freezeOutputs() {
            Files.setPosixFilePermissions(
                staging.resolve(OUTPUTS_DIRECTORY),
                PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS,
            )
            forceDirectory(staging.resolve(OUTPUTS_DIRECTORY))
        }

        fun freezeTree() {
            Files.setPosixFilePermissions(
                staging.resolve(CHECKPOINTS_DIRECTORY),
                PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS,
            )
            forceDirectory(staging.resolve(CHECKPOINTS_DIRECTORY))
            Files.setPosixFilePermissions(staging, PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS)
            forceDirectory(staging)
        }

        fun ensureCompleteTree() {
            ensureKnownTree(staging, complete = true)
        }

        fun commit(
            controls: ControlPlan,
            sources: List<TrustedSource>,
            bounds: BoundedShardRunPublicationBounds,
            limits: BoundedShardRunLimits,
            probe: BoundedShardRunPublicationProbe,
        ): BoundedShardRunBinding {
            probe.checkpoint(BoundedShardRunPublicationStage.BEFORE_ATOMIC_MOVE)
            ensureCompleteTree()
            ensureSourcesStable(sources, "before atomic publication")
            ensureDirectorySeal(target.parent, parentSeal, "bounded-shard output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw BoundedShardRunPublicationException("bounded-shard publication target already exists")
            }
            probe.checkpoint(BoundedShardRunPublicationStage.AFTER_TARGET_ABSENCE_CHECK)
            try {
                atomicMoveNoReplace(staging, target, parentSeal)
                published = true
                forceDirectory(target.parent)
                probe.checkpoint(BoundedShardRunPublicationStage.AFTER_ATOMIC_MOVE)
                ensureDirectorySeal(target.parent, parentSeal, "bounded-shard output parent")
                ensureKnownTree(target, complete = true)
                ensureSourcesStable(sources, "after atomic publication")
                val binding = verify(
                    target,
                    controls.indexArtifactSha256,
                    limits,
                    "published bounded-shard run",
                )
                requireExpectedBinding(binding, controls, sources, target, bounds)
                probe.checkpoint(BoundedShardRunPublicationStage.AFTER_FINAL_VERIFICATION)
                ensureKnownTree(target, complete = true)
                ensureSourcesStable(sources, "after final verification")
                committed = true
                return binding
            } catch (failure: Throwable) {
                if (published) {
                    try {
                        revoke()
                    } catch (revocationFailure: Throwable) {
                        failure.addSuppressed(revocationFailure)
                    }
                }
                throw failure
            }
        }

        private fun write(path: Path, bytes: ByteArray, label: String) {
            val member = relative(path)
            intendedFiles.add(member)
            try {
                FileChannel.open(
                    path,
                    setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_WRITABLE_FILE_PERMISSIONS),
                ).use { channel ->
                    identities[member] = fileIdentity(path, label)
                    val buffer = ByteBuffer.wrap(bytes)
                    while (buffer.hasRemaining()) channel.write(buffer)
                    channel.force(true)
                }
                Files.setPosixFilePermissions(path, PRIVATE_READ_ONLY_FILE_PERMISSIONS)
                versions[member] = trustedFileVersion(path, label, privateReadOnly = true)
            } catch (failure: Exception) {
                throw BoundedShardRunPublicationException("cannot write $label", failure)
            }
        }

        private fun ensureKnownTree(root: Path, complete: Boolean) {
            ensureDirectoryIdentity(root, stagingIdentity, "bounded-shard publication directory")
            ensureDirectoryIdentity(
                root.resolve(OUTPUTS_DIRECTORY),
                outputDirectoryIdentity,
                "bounded-shard outputs directory",
            )
            ensureDirectoryIdentity(
                root.resolve(CHECKPOINTS_DIRECTORY),
                checkpointDirectoryIdentity,
                "bounded-shard checkpoints directory",
            )
            if (complete) {
                requireMembership(root, ROOT_MEMBERS, "bounded-shard publication root")
                requireMembership(root.resolve(OUTPUTS_DIRECTORY), expectedNames, "bounded-shard outputs")
                requireMembership(root.resolve(CHECKPOINTS_DIRECTORY), expectedNames, "bounded-shard checkpoints")
                if (intendedFiles.size != 2 + expectedNames.size * 2 || identities.keys != intendedFiles ||
                    versions.keys != intendedFiles
                ) {
                    throw BoundedShardRunPublicationException("bounded-shard publication members are incomplete")
                }
            } else {
                requireKnownMembership(root)
            }
            identities.forEach { (relative, identity) ->
                ensureFileIdentity(root.resolve(relative), identity, "bounded-shard staged member $relative")
            }
            if (complete) {
                versions.forEach { (relative, version) ->
                    ensureVersion(root.resolve(relative), version, "bounded-shard staged member $relative")
                }
                requirePermissions(root, PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS, "bounded-shard publication root")
                requirePermissions(
                    root.resolve(OUTPUTS_DIRECTORY),
                    PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS,
                    "bounded-shard outputs directory",
                )
                requirePermissions(
                    root.resolve(CHECKPOINTS_DIRECTORY),
                    PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS,
                    "bounded-shard checkpoints directory",
                )
            }
        }

        private fun requireKnownMembership(root: Path) {
            val rootNames = directNames(root)
            if (!ROOT_MEMBERS.containsAll(rootNames) ||
                OUTPUTS_DIRECTORY !in rootNames || CHECKPOINTS_DIRECTORY !in rootNames
            ) {
                throw BoundedShardRunPublicationException(
                    "cannot safely clean bounded-shard staging with unexpected root membership",
                )
            }
            listOf(OUTPUTS_DIRECTORY, CHECKPOINTS_DIRECTORY).forEach { directory ->
                val actual = directNames(root.resolve(directory))
                val intended = intendedFiles
                    .filter { it.nameCount == 2 && it.getName(0).toString() == directory }
                    .mapTo(linkedSetOf()) { it.fileName.toString() }
                if (!intended.containsAll(actual)) {
                    throw BoundedShardRunPublicationException(
                        "cannot safely clean bounded-shard staging with unexpected $directory membership",
                    )
                }
            }
            val intendedRootFiles = intendedFiles
                .filter { it.nameCount == 1 }
                .mapTo(linkedSetOf()) { it.fileName.toString() }
            if (!intendedRootFiles.containsAll(rootNames - setOf(OUTPUTS_DIRECTORY, CHECKPOINTS_DIRECTORY))) {
                throw BoundedShardRunPublicationException(
                    "cannot safely clean bounded-shard staging with unexpected control membership",
                )
            }
            actualFiles(root).forEach { path ->
                val relative = root.relativize(path)
                val attributes = basicAttributes(path, "bounded-shard partial member $relative")
                if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
                    throw BoundedShardRunPublicationException(
                        "cannot safely clean bounded-shard staging with an invalid member",
                    )
                }
                identities[relative]?.let { expected ->
                    if (attributes.fileKey() != expected) {
                        throw BoundedShardRunPublicationException(
                            "cannot safely clean a substituted bounded-shard staging member",
                        )
                    }
                }
            }
        }

        private fun revoke() {
            ensureKnownTree(target, complete = true)
            makeWritable(target)
            deleteKnownTree(target)
            forceDirectory(target.parent)
            published = false
        }

        override fun close() {
            if (committed || published || !Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) return
            ensureKnownTree(staging, complete = false)
            makeWritable(staging)
            deleteKnownTree(staging)
            forceDirectory(staging.parent)
        }

        private fun makeWritable(root: Path) {
            Files.setPosixFilePermissions(root, PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS)
            listOf(OUTPUTS_DIRECTORY, CHECKPOINTS_DIRECTORY).forEach { directory ->
                val path = root.resolve(directory)
                if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                    Files.setPosixFilePermissions(path, PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS)
                }
            }
            actualFiles(root).forEach { path ->
                Files.setPosixFilePermissions(path, PRIVATE_WRITABLE_FILE_PERMISSIONS)
            }
        }

        private fun deleteKnownTree(root: Path) {
            actualFiles(root).forEach(Files::delete)
            Files.delete(root.resolve(OUTPUTS_DIRECTORY))
            Files.delete(root.resolve(CHECKPOINTS_DIRECTORY))
            Files.delete(root)
        }

        private fun actualFiles(root: Path): List<Path> {
            val files = ArrayList<Path>()
            directNames(root)
                .filter { it != OUTPUTS_DIRECTORY && it != CHECKPOINTS_DIRECTORY }
                .forEach { files.add(root.resolve(it)) }
            listOf(OUTPUTS_DIRECTORY, CHECKPOINTS_DIRECTORY).forEach { directory ->
                val path = root.resolve(directory)
                directNames(path).forEach { files.add(path.resolve(it)) }
            }
            return files
        }

        private fun relative(path: Path): Path = staging.relativize(path)

        companion object {
            fun create(target: Path, shardIds: List<String>): Publication {
                val parent = requireTrustedDirectory(target.parent, "bounded-shard output parent")
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw BoundedShardRunPublicationException("bounded-shard publication target already exists")
                }
                val parentSeal = trustedDirectorySeal(parent, "bounded-shard output parent")
                forceDirectory(parent)
                var staging: Path? = null
                var stagingIdentity: Any? = null
                var outputsIdentity: Any? = null
                var checkpointsIdentity: Any? = null
                try {
                    val created = Files.createTempDirectory(
                        parent,
                        ".${target.fileName}.bounded-shard-stage-",
                        PosixFilePermissions.asFileAttribute(PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS),
                    )
                    staging = created
                    Files.setPosixFilePermissions(created, PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS)
                    stagingIdentity = directoryIdentity(created, "bounded-shard staging directory")
                    val outputs = Files.createDirectory(
                        created.resolve(OUTPUTS_DIRECTORY),
                        PosixFilePermissions.asFileAttribute(PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS),
                    )
                    outputsIdentity = directoryIdentity(outputs, "bounded-shard staging outputs")
                    val checkpoints = Files.createDirectory(
                        created.resolve(CHECKPOINTS_DIRECTORY),
                        PosixFilePermissions.asFileAttribute(PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS),
                    )
                    checkpointsIdentity = directoryIdentity(checkpoints, "bounded-shard staging checkpoints")
                    forceDirectory(created)
                    forceDirectory(parent)
                    ensureDirectorySeal(parent, parentSeal, "bounded-shard output parent")
                    return Publication(
                        target,
                        created,
                        parentSeal,
                        stagingIdentity,
                        outputsIdentity,
                        checkpointsIdentity,
                        shardIds,
                    )
                } catch (failure: Throwable) {
                    if (staging != null) {
                        try {
                            if (stagingIdentity != null) {
                                ensureDirectoryIdentity(staging, stagingIdentity, "partial bounded-shard staging")
                            }
                            if (checkpointsIdentity != null) {
                                ensureDirectoryIdentity(
                                    staging.resolve(CHECKPOINTS_DIRECTORY),
                                    checkpointsIdentity,
                                    "partial bounded-shard checkpoints",
                                )
                                Files.delete(staging.resolve(CHECKPOINTS_DIRECTORY))
                            }
                            if (outputsIdentity != null) {
                                ensureDirectoryIdentity(
                                    staging.resolve(OUTPUTS_DIRECTORY),
                                    outputsIdentity,
                                    "partial bounded-shard outputs",
                                )
                                Files.delete(staging.resolve(OUTPUTS_DIRECTORY))
                            }
                            Files.delete(staging)
                            forceDirectory(parent)
                        } catch (cleanupFailure: Throwable) {
                            failure.addSuppressed(cleanupFailure)
                        }
                    }
                    if (failure is BoundedShardRunPublicationException) throw failure
                    throw BoundedShardRunPublicationException("cannot create bounded-shard staging tree", failure)
                }
            }
        }
    }

    private data class ControlPlan(
        val run: JsonObject,
        val runBytes: ByteArray,
        val runSha256: String,
        val checkpoints: List<CheckpointPlan>,
        val index: JsonObject,
        val indexBytes: ByteArray,
        val indexArtifactSha256: String,
    )

    private data class CheckpointPlan(val shardId: String, val document: JsonObject, val bytes: ByteArray)

    private data class DirectorySeal(val identity: Any, val permissions: Set<PosixFilePermission>)

    private data class TrustedVersion(
        val identity: Any,
        val size: Long,
        val modified: FileTime,
        val permissions: Set<PosixFilePermission>,
    )

    private data class TrustedSource(
        val prepared: BoundedShardPreparedOutput,
        val path: Path,
        val parent: DirectorySeal,
        val version: TrustedVersion,
    ) {
        fun ensureStable(stage: String) {
            ensureDirectorySeal(path.parent, parent, "prepared output parent ${prepared.shardId} $stage")
            ensureVersion(path, version, "prepared output ${prepared.shardId} $stage")
        }
    }

    private data class StagedOutput(
        val source: TrustedSource,
        val path: Path,
        val version: TrustedVersion,
    ) {
        fun ensureStable(stage: String) {
            ensureVersion(path, version, "$stage ${source.prepared.shardId}")
        }
    }

    private fun ensureSourcesStable(sources: List<TrustedSource>, stage: String) {
        sources.forEach { it.ensureStable(stage) }
    }

    private fun normalizeTarget(path: Path): Path {
        val target = path.toAbsolutePath().normalize()
        if (target.fileName == null || target.parent == null) {
            throw BoundedShardRunPublicationException("bounded-shard target must name a directory")
        }
        return target
    }

    private fun requireTrustedSourcePath(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        if (normalized.fileName == null || normalized.parent == null) {
            throw BoundedShardRunPublicationException("$label must name a file")
        }
        val real = try {
            normalized.toRealPath()
        } catch (failure: Exception) {
            throw BoundedShardRunPublicationException("$label is unavailable", failure)
        }
        if (real != normalized) throw BoundedShardRunPublicationException("$label path contains a symbolic link")
        requireTrustedDirectory(normalized.parent, "$label parent")
        return normalized
    }

    private fun requireTrustedDirectory(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        if (normalized.fileName == null || normalized.parent == null) {
            throw BoundedShardRunPublicationException("$label must name a directory")
        }
        val real = try {
            normalized.toRealPath()
        } catch (failure: Exception) {
            throw BoundedShardRunPublicationException("$label is unavailable", failure)
        }
        if (real != normalized) throw BoundedShardRunPublicationException("$label path contains a symbolic link")
        trustedDirectorySeal(normalized.parent, "$label parent")
        trustedDirectorySeal(normalized, label)
        return normalized
    }

    private fun trustedDirectorySeal(path: Path, label: String): DirectorySeal {
        val attributes = basicAttributes(path, label)
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw BoundedShardRunPublicationException("$label has an invalid type or no stable identity")
        }
        val permissions = permissions(path, label)
        rejectUntrustedWrites(permissions, label)
        return DirectorySeal(attributes.fileKey(), permissions)
    }

    private fun trustedFileVersion(path: Path, label: String, privateReadOnly: Boolean = false): TrustedVersion {
        val attributes = basicAttributes(path, label)
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw BoundedShardRunPublicationException("$label has an invalid type or no stable identity")
        }
        val permissions = permissions(path, label)
        if (privateReadOnly) {
            if (permissions != PRIVATE_READ_ONLY_FILE_PERMISSIONS) {
                throw BoundedShardRunPublicationException("$label must have private read-only permissions")
            }
        } else {
            rejectUntrustedWrites(permissions, label)
        }
        return TrustedVersion(
            identity = attributes.fileKey(),
            size = attributes.size(),
            modified = attributes.lastModifiedTime(),
            permissions = permissions,
        )
    }

    private fun ensureDirectorySeal(path: Path, expected: DirectorySeal, label: String) {
        if (trustedDirectorySeal(path, label) != expected) {
            throw BoundedShardRunPublicationException("$label identity or permissions changed")
        }
    }

    private fun ensureVersion(path: Path, expected: TrustedVersion, label: String) {
        if (trustedFileVersion(path, label, privateReadOnly = expected.permissions == PRIVATE_READ_ONLY_FILE_PERMISSIONS) !=
            expected
        ) {
            throw BoundedShardRunPublicationException("$label identity, metadata, or permissions changed")
        }
    }

    private fun requireMembership(path: Path, expected: Set<String>, label: String) {
        if (directNames(path) != expected) {
            throw BoundedShardRunPublicationException("$label membership is missing or extra")
        }
    }

    private fun directNames(path: Path): Set<String> = try {
        Files.newDirectoryStream(path).use { entries -> entries.mapTo(linkedSetOf()) { it.fileName.toString() } }
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("cannot enumerate bounded-shard publication directory", failure)
    }

    private fun requirePermissions(path: Path, expected: Set<PosixFilePermission>, label: String) {
        if (permissions(path, label) != expected) {
            throw BoundedShardRunPublicationException("$label permissions differ")
        }
    }

    private fun basicAttributes(path: Path, label: String): BasicFileAttributes = try {
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("$label attributes are unavailable", failure)
    }

    private fun permissions(path: Path, label: String): Set<PosixFilePermission> = try {
        Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            ?.readAttributes()?.permissions()?.toSet()
            ?: throw BoundedShardRunPublicationException("$label requires POSIX permissions")
    } catch (failure: BoundedShardRunPublicationException) {
        throw failure
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("$label permissions are unavailable", failure)
    }

    private fun rejectUntrustedWrites(permissions: Set<PosixFilePermission>, label: String) {
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw BoundedShardRunPublicationException("$label is writable by group or other principals")
        }
    }

    private fun directoryIdentity(path: Path, label: String): Any {
        val attributes = basicAttributes(path, label)
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw BoundedShardRunPublicationException("$label has no stable directory identity")
        }
        return attributes.fileKey()
    }

    private fun ensureDirectoryIdentity(path: Path, expected: Any, label: String) {
        if (directoryIdentity(path, label) != expected) {
            throw BoundedShardRunPublicationException("$label identity changed")
        }
    }

    private fun fileIdentity(path: Path, label: String): Any {
        val attributes = basicAttributes(path, label)
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw BoundedShardRunPublicationException("$label has no stable regular-file identity")
        }
        return attributes.fileKey()
    }

    private fun ensureFileIdentity(path: Path, expected: Any, label: String) {
        if (fileIdentity(path, label) != expected) {
            throw BoundedShardRunPublicationException("$label identity changed")
        }
    }

    private fun forceDirectory(path: Path) {
        try {
            FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        } catch (failure: Exception) {
            throw BoundedShardRunPublicationException("cannot force bounded-shard publication directory", failure)
        }
    }

    private fun atomicMoveNoReplace(staging: Path, target: Path, parentSeal: DirectorySeal) {
        val parent = target.parent
        if (staging.parent != parent || staging.fileName == null || target.fileName == null) {
            throw BoundedShardRunPublicationException(
                "bounded-shard staging and target must be direct siblings",
            )
        }
        try {
            LinuxFilesystemSyscalls.requireSupported(parent)
            LinuxFilesystemSyscalls.openRoot(parent).use { descriptor ->
                descriptor.whileOpen { parentDescriptor ->
                    if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentDescriptor))) {
                        throw BoundedShardRunPublicationException(
                            "bounded-shard output parent changed before atomic publication",
                        )
                    }
                    ensureDirectorySeal(parent, parentSeal, "bounded-shard output parent")
                    LinuxFilesystemSyscalls.renameNoReplace(
                        parentDescriptor,
                        staging.fileName.toString(),
                        target.fileName.toString(),
                    )
                }
            }
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                throw BoundedShardRunPublicationException(
                    "bounded-shard publication target already exists",
                    failure,
                )
            }
            throw BoundedShardRunPublicationException(
                "filesystem cannot atomically publish bounded-shard run without replacement",
                failure,
            )
        } catch (failure: BoundedShardRunPublicationException) {
            throw failure
        } catch (failure: Exception) {
            throw BoundedShardRunPublicationException(
                "filesystem cannot atomically publish bounded-shard run without replacement",
                failure,
            )
        }
    }

    private fun canonicalBytes(document: JsonObject, maximumBytes: Int, label: String): ByteArray = try {
        OracleJson.canonicalBytes(document, jsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("$label exceeds strict JSON limits", failure)
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = MAXIMUM_CONTROL_NODES.toInt(),
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
        maximumNumberCharacters = 4096,
    )

    private fun requireSha256(value: String, label: String) {
        if (!SHA256.matches(value)) throw BoundedShardRunPublicationException("$label SHA-256 is invalid")
    }

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw BoundedShardRunPublicationException("$label count overflows", failure)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()

    private fun ByteArray.hex(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private inline fun <T> exceptionBoundary(block: () -> T): T = try {
        block()
    } catch (failure: BoundedShardRunPublicationException) {
        throw failure
    } catch (failure: Exception) {
        throw BoundedShardRunPublicationException("bounded-shard publication failed", failure)
    }

    private val NOOP_PROBE = BoundedShardRunPublicationProbe { }
    private val IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val INDEX_DOMAIN = "bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val ROOT_MEMBERS = setOf("run.json", "index.json", "outputs", "checkpoints")
    private val PRIVATE_WRITABLE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
    private val PRIVATE_READ_ONLY_FILE_PERMISSIONS = PosixFilePermissions.fromString("r--------")
    private val PRIVATE_WRITABLE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
    private val PRIVATE_READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
    private val UNTRUSTED_WRITE_PERMISSIONS = setOf(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )

    private const val COPY_BUFFER_BYTES = 1024 * 1024
    private const val MAXIMUM_CONTROL_NODES = 1_000_000L
    private const val RUN_FILE = "run.json"
    private const val INDEX_FILE = "index.json"
    private const val OUTPUTS_DIRECTORY = "outputs"
    private const val CHECKPOINTS_DIRECTORY = "checkpoints"
}

package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

internal class FullTreeCallObservationRunException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeCallObservationRunLimits(
    val shard: FullTreeCallObservationPublicationLimits = FullTreeCallObservationPublicationLimits(),
    val run: BoundedShardRunLimits = BoundedShardRunLimits(),
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
) {
    init {
        require(maximumScratchBytes in 1L..64L * 1024L * 1024L * 1024L)
    }
}

internal class FullTreeCallObservationRunPublication internal constructor(
    val root: Path,
    val runSha256: String,
    val indexArtifactSha256: String,
    val scopeSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val maximumWorkers: Int,
    outputs: List<FullTreeCallObservationPublication>,
) {
    val outputs: List<FullTreeCallObservationPublication> = Collections.unmodifiableList(outputs.toList())
    val entities: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.entities) }
    val outputBytes: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.outputBytes) }
    val authoritativeReleaseEvidence: Boolean = false
    val candidateLeaseRetained: Boolean = false
    val downstreamScoringAuthorized: Boolean = false

    override fun equals(other: Any?): Boolean = other is FullTreeCallObservationRunPublication &&
        root == other.root && runSha256 == other.runSha256 && indexArtifactSha256 == other.indexArtifactSha256 &&
        scopeSha256 == other.scopeSha256 && inventoryArtifactSha256 == other.inventoryArtifactSha256 &&
        richArtifactSha256 == other.richArtifactSha256 && maximumWorkers == other.maximumWorkers && outputs == other.outputs

    override fun hashCode(): Int = listOf(
        root, runSha256, indexArtifactSha256, scopeSha256, inventoryArtifactSha256,
        richArtifactSha256, maximumWorkers, outputs,
    ).hashCode()

    override fun toString(): String = "FullTreeCallObservationRunPublication(root=$root, indexArtifactSha256=$indexArtifactSha256)"
}

/**
 * Complete raw-input call observation with sequential workers and one shared cooperative deadline.
 * Worker counts declare an upper bound; receipts do not claim process isolation or an aggregate
 * scratch lease. Filesystem owners must cooperate, including during publication and cleanup.
 */
internal object FullTreeCallObservationRunPublisher {
    fun generateAndPublish(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        outputRoot: Path,
        maximumWorkers: Int = 1,
        limits: FullTreeCallObservationRunLimits = FullTreeCallObservationRunLimits(),
    ): FullTreeCallObservationRunPublication = translateCallRunFailure {
        val deadline = FullTreeCallObservationDeadline.startWholeRun(scope, limits.shard.control)
        val paths = CallRunPaths.authenticate(richArtifact, inventoryPath, scratchParent, outputRoot)
        withCallRunInputs(paths, scope, maximumWorkers, limits, deadline) { inputs ->
            CallRunOutputStage.create(paths.result, inputs.maximumCleanupEntries).use { stage ->
                CallRunWorkspace.create(paths.scratch, inputs.maximumCleanupEntries).use { workspace ->
                    val receipts = ArrayList<FullTreeCallObservationPublication>(inputs.shards.size)
                    val shardDeadlines = LinkedHashMap<String, FullTreeCallObservationDeadline>()
                    var preparedBytes = 0L
                    var entities = 0L
                    inputs.shards.forEach { shard ->
                        inputs.requireScratchReservation(preparedBytes, generating = true)
                        val shardDeadline = deadline.startShard(scope, limits.shard.control)
                        shardDeadlines[shard.identifier] = shardDeadline
                        val receipt = FullTreeCallObservationShardPublisher.generateAndPublishWithinDeadline(
                            paths.rich, paths.inventory, scope, shard.identifier, workspace.worker,
                            workspace.prepared.resolve("${shard.identifier}.json"), limits.shard,
                            shardDeadline,
                        )
                        inputs.requireReceipt(shard, receipt)
                        preparedBytes = Math.addExact(preparedBytes, receipt.outputBytes)
                        entities = Math.addExact(entities, receipt.entities)
                        inputs.requirePopulation(preparedBytes, entities)
                        inputs.requireScratchReservation(preparedBytes, generating = true)
                        workspace.requireWorkerEmpty()
                        inputs.verify("after generating call-observation shard ${shard.identifier}")
                        receipts += receipt
                    }
                    val expectedReceipts = receipts.associateBy { it.shardId }
                    val prepared = receipts.map { receipt ->
                        BoundedShardPreparedOutput(
                            receipt.shardId, receipt.inputSha256,
                            workspace.prepared.resolve("${receipt.shardId}.json"),
                            receipt.outputSha256, receipt.outputBytes, receipt.entities,
                        )
                    }
                    val binding = BoundedShardRunPublisher.publishWithCheckpoint(
                        target = stage.run,
                        runId = inputs.runId,
                        preparedOutputs = prepared,
                        bounds = inputs.bounds,
                        semanticValidator = BoundedShardOutputSemanticValidator { staged ->
                            val expected = expectedReceipts[staged.shardId]
                                ?: callRunFail("staged call-observation shard is outside the inventory")
                            val actual = FullTreeCallObservationShardPublisher.loadAndValidateWithinDeadline(
                                staged.output, paths.rich, paths.inventory, scope, staged.shardId,
                                workspace.worker, limits.shard, shardDeadlines.getValue(staged.shardId),
                            )
                            if (actual != expected || staged.inputSha256 != expected.inputSha256 ||
                                staged.outputSha256 != expected.outputSha256 || staged.outputBytes != expected.outputBytes ||
                                staged.entities != expected.entities
                            ) {
                                callRunFail("staged call-observation output differs from its raw derivation")
                            }
                            workspace.requireWorkerEmpty()
                            inputs.verify("after rederiving staged call-observation shard ${staged.shardId}")
                        },
                        limits = limits.run,
                        checkpoint = deadline::checkpoint,
                    )
                    stage.retainRunIdentity()
                    inputs.requireBinding(binding)
                    requireCallRunImmutable(binding.root, inputs.shards, deadline)
                    workspace.close()
                    inputs.verify("before publishing the complete call-observation run")
                    stage.commit(deadline::checkpoint) { candidate ->
                        val checked = BoundedShardRunVerifier.verifyWithCheckpoint(
                            candidate, binding.indexArtifactSha256, limits.run, deadline::checkpoint,
                        )
                        inputs.requireBinding(checked)
                        if (checked.runSha256 != binding.runSha256 || checked.outputs != binding.outputs) {
                            callRunFail("call-observation run changed at publication")
                        }
                        requireCallRunImmutable(candidate, inputs.shards, deadline)
                        inputs.verify("at complete call-observation publication")
                    }
                    inputs.receipt(paths.result, binding, receipts)
                }
            }
        }
    }

    fun loadAndValidate(
        candidateRoot: Path,
        expectedIndexArtifactSha256: String,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        maximumWorkers: Int = 1,
        limits: FullTreeCallObservationRunLimits = FullTreeCallObservationRunLimits(),
    ): FullTreeCallObservationRunPublication = translateCallRunFailure {
        loadAndValidateWithinDeadline(
            candidateRoot, expectedIndexArtifactSha256, richArtifact, inventoryPath, scope,
            scratchParent, maximumWorkers, limits,
            FullTreeCallObservationDeadline.startWholeRun(scope, limits.shard.control),
        )
    }

    internal fun loadAndValidateWithinDeadline(
        candidateRoot: Path,
        expectedIndexArtifactSha256: String,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        maximumWorkers: Int,
        limits: FullTreeCallObservationRunLimits,
        deadline: FullTreeCallObservationDeadline,
    ): FullTreeCallObservationRunPublication = translateCallRunFailure {
        deadline.requireWholeRunScope(scope)
        deadline.checkpoint("before validating the complete call-observation run")
        FullTreeScopeControl.validate(scope, limits.shard.control)
        require(expectedIndexArtifactSha256.matches(Regex("[0-9a-f]{64}"))) {
            "call-observation run index artifact hash is invalid"
        }
        val paths = CallRunPaths.authenticate(richArtifact, inventoryPath, scratchParent, candidateRoot)
        withCallRunInputs(paths, scope, maximumWorkers, limits, deadline) { inputs ->
            inputs.requireScratchReservation(0L, generating = false)
            val binding = BoundedShardRunVerifier.verifyWithCheckpoint(
                paths.result, expectedIndexArtifactSha256, limits.run, deadline::checkpoint,
            )
            inputs.requireBinding(binding)
            requireCallRunImmutable(paths.result, inputs.shards, deadline)
            CallRunWorkspace.create(paths.scratch, inputs.maximumCleanupEntries).use { workspace ->
                val receipts = binding.outputs.mapIndexed { index, output ->
                    val receipt = FullTreeCallObservationShardPublisher.loadAndValidateWithinDeadline(
                        paths.result.resolve("outputs").resolve("${output.shardId}.json"),
                        paths.rich, paths.inventory, scope, output.shardId, workspace.worker,
                        limits.shard, deadline.startShard(scope, limits.shard.control),
                    )
                    inputs.requireReceipt(inputs.shards[index], receipt)
                    if (receipt.outputSha256 != output.outputSha256 || receipt.outputBytes != output.outputBytes ||
                        receipt.entities != output.entities
                    ) {
                        callRunFail("call-observation run output differs from its raw derivation")
                    }
                    workspace.requireWorkerEmpty()
                    inputs.verify("after rederiving call-observation run shard ${output.shardId}")
                    receipt
                }
                workspace.close()
                val terminal = BoundedShardRunVerifier.verifyWithCheckpoint(
                    paths.result, expectedIndexArtifactSha256, limits.run, deadline::checkpoint,
                )
                inputs.requireBinding(terminal)
                if (terminal.runSha256 != binding.runSha256 || terminal.outputs != binding.outputs) {
                    callRunFail("call-observation run changed during raw validation")
                }
                requireCallRunImmutable(paths.result, inputs.shards, deadline)
                inputs.verify("after validating the complete call-observation run")
                inputs.receipt(paths.result, terminal, receipts)
            }
        }
    }
}

private fun <Result> withCallRunInputs(
    paths: CallRunPaths,
    scope: AuthenticatedFullTreeScope,
    maximumWorkers: Int,
    limits: FullTreeCallObservationRunLimits,
    deadline: FullTreeCallObservationDeadline,
    action: (CallRunInputs) -> Result,
): Result {
    if (maximumWorkers !in 1..minOf(limits.shard.control.maximumWorkers, limits.run.maximumWorkers)) {
        callRunFail("call-observation worker bound exceeds its implementation ceiling")
    }
    StableControlFile.open(
        paths.inventory, limits.shard.control.maximumInventoryBytes.toLong(), "call run inventory",
    ).use { inventoryGuard ->
        deadline.checkpoint("after opening call-observation run inventory")
        StableControlFile.open(
            paths.rich, limits.shard.control.maximumRichArtifactBytes, "call run rich artifact",
        ).use { artifactGuard ->
            deadline.checkpoint("after opening call-observation run artifact")
            val inventory = FullTreeInventoryControl.loadAndValidate(paths.inventory, scope, limits.shard.control)
            val inventoryBytes = OracleJson.canonicalBytes(
                inventory, controlJsonLimits(limits.shard.control.maximumInventoryBytes),
            )
            if (OracleArtifacts.sha256(inventoryBytes) != inventoryGuard.authenticatedSha256 ||
                artifactGuard.authenticatedSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")
            ) {
                callRunFail("call-observation run raw inputs differ from the authenticated controls")
            }
            val shards = FullTreeCallObservations.shardInputs(
                inventory, inventoryGuard.authenticatedSha256, scope.document, scope.sha256,
            )
            if (shards.size !in 1..limits.run.maximumShards ||
                shards.any { it.identifier.length > CALL_RUN_MAXIMUM_SHARD_NAME_CHARACTERS }
            ) {
                callRunFail("call-observation run shard population or names exceed their bounds")
            }
            val inputs = CallRunInputs(
                scope, inventoryGuard, artifactGuard, shards, minOf(maximumWorkers, shards.size), limits, deadline,
            )
            inputs.verify("after authenticating call-observation run inputs")
            return action(inputs)
        }
    }
}

private class CallRunInputs(
    private val scope: AuthenticatedFullTreeScope,
    private val inventory: StableControlFile,
    private val artifact: StableControlFile,
    val shards: List<FullTreeCallObservationShardInput>,
    private val maximumWorkers: Int,
    private val limits: FullTreeCallObservationRunLimits,
    private val deadline: FullTreeCallObservationDeadline,
) {
    private val perShard = scope.document.controlObject("bounds").controlObject("perShard")
    private val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
    val runId = "full-tree-calls-${scope.sha256.take(16)}"
    val maximumCleanupEntries: Long = Math.addExact(Math.multiplyExact(shards.size.toLong(), 4L), 64L)
    val bounds = BoundedShardRunPublicationBounds(
        maximumShards = shards.size,
        perShardEntities = perShard.controlLong("entities"),
        wholeRunEntities = wholeRun.controlLong("entities"),
        perShardBytes = perShard.controlLong("serializedBytes"),
        wholeRunBytes = wholeRun.controlLong("serializedBytes"),
        perShardSeconds = perShard.controlLong("wallClockSeconds").toDouble(),
        wholeRunSeconds = wholeRun.controlLong("wallClockSeconds").toDouble(),
        perShardCpuSeconds = perShard.controlLong("cpuSeconds").toDouble(),
        wholeRunCpuSeconds = wholeRun.controlLong("cpuSeconds").toDouble(),
        maximumResidentBytes = wholeRun.controlLong("maximumResidentBytes"),
        maximumWorkers = maximumWorkers,
    )

    init {
        val supported = limits.run
        if (bounds.perShardEntities > supported.maximumPerShardEntities ||
            bounds.wholeRunEntities > supported.maximumWholeRunEntities ||
            bounds.perShardBytes > supported.maximumPerShardOutputBytes ||
            bounds.wholeRunBytes > supported.maximumWholeRunOutputBytes ||
            bounds.maximumResidentBytes > supported.maximumDeclaredResidentBytes ||
            perShard.controlLong("wallClockSeconds") > supported.maximumDeclaredPerShardSeconds ||
            wholeRun.controlLong("wallClockSeconds") > supported.maximumDeclaredWholeRunSeconds ||
            perShard.controlLong("cpuSeconds") > supported.maximumDeclaredPerShardSeconds ||
            wholeRun.controlLong("cpuSeconds") > supported.maximumDeclaredWholeRunSeconds
        ) {
            callRunFail("call-observation scope declarations exceed supported bounded-run ceilings")
        }
    }

    fun verify(label: String) {
        deadline.checkpoint("before $label")
        FullTreeScopeControl.validate(scope, limits.shard.control)
        inventory.verifyUnchanged("call-observation run inventory $label")
        artifact.verifyUnchanged("call-observation run artifact $label")
        deadline.checkpoint("after $label")
    }

    fun requireScratchReservation(preparedBytes: Long, generating: Boolean) {
        val workerBytes = Math.addExact(
            limits.shard.control.maximumDwarfScratchBytes,
            minOf(
                limits.shard.sqlite.maximumDatabaseBytes,
                maxOf(4096L, minOf(bounds.perShardBytes, limits.shard.sqlite.maximumDatabaseBytes) * 4L),
            ),
        )
        val outputReservation = if (generating) {
            Math.addExact(
                Math.multiplyExact(preparedBytes, 2L),
                minOf(limits.shard.sqlite.maximumOutputBytes, bounds.perShardBytes),
            )
        } else {
            0L
        }
        val controls = if (generating) {
            Math.addExact(
                Math.multiplyExact(limits.run.maximumControlArtifactBytes.toLong(), 2L),
                Math.multiplyExact(shards.size.toLong(), CALL_RUN_CHECKPOINT_RESERVED_BYTES),
            )
        } else {
            0L
        }
        if (Math.addExact(Math.addExact(workerBytes, outputReservation), controls) > limits.maximumScratchBytes) {
            callRunFail("call-observation run exceeds its conservative scratch reservation")
        }
        deadline.checkpoint("after reserving bounded call-observation run scratch")
    }

    fun requirePopulation(bytes: Long, entities: Long) {
        if (bytes > minOf(bounds.wholeRunBytes, limits.run.maximumWholeRunOutputBytes) ||
            entities > minOf(bounds.wholeRunEntities, limits.run.maximumWholeRunEntities)
        ) {
            callRunFail("call-observation run population exceeds its whole-run bound")
        }
    }

    fun requireReceipt(shard: FullTreeCallObservationShardInput, receipt: FullTreeCallObservationPublication) {
        if (receipt.shardId != shard.identifier || receipt.inputSha256 != shard.inputSha256 ||
            receipt.inventoryArtifactSha256 != inventory.authenticatedSha256 ||
            receipt.richArtifactSha256 != artifact.authenticatedSha256 || receipt.scopeSha256 != scope.sha256
        ) {
            callRunFail("raw call-observation shard receipt differs from the run inputs")
        }
    }

    fun requireBinding(binding: BoundedShardRunBinding) {
        val run = binding.run
        if (run.keys != setOf("bounds", "id", "schemaVersion", "shards") ||
            run.controlString("id") != runId || run.controlLong("schemaVersion") != 1L
        ) {
            callRunFail("call-observation run contract differs from the authenticated scope")
        }
        val expectedBounds = mapOf(
            "maximumResidentBytes" to bounds.maximumResidentBytes,
            "maximumShards" to shards.size.toLong(),
            "maximumWorkers" to maximumWorkers.toLong(),
            "perShardBytes" to bounds.perShardBytes,
            "perShardCpuSeconds" to perShard.controlLong("cpuSeconds"),
            "perShardEntities" to bounds.perShardEntities,
            "perShardSeconds" to perShard.controlLong("wallClockSeconds"),
            "wholeRunBytes" to bounds.wholeRunBytes,
            "wholeRunCpuSeconds" to wholeRun.controlLong("cpuSeconds"),
            "wholeRunEntities" to bounds.wholeRunEntities,
            "wholeRunSeconds" to wholeRun.controlLong("wallClockSeconds"),
        )
        val actualBounds = run.controlObject("bounds")
        if (actualBounds.keys != expectedBounds.keys || expectedBounds.any { (name, expected) ->
                val actual = actualBounds[name] as? JsonPrimitive
                actual == null || actual.isString || actual.booleanOrNull != null ||
                    actual.content.toBigDecimalOrNull()?.compareTo(expected.toBigDecimal()) != 0
            }
        ) {
            callRunFail("call-observation run bounds differ from the authenticated scope")
        }
        val expectedShards = JsonArray(shards.map { shard ->
            JsonObject(mapOf("id" to JsonPrimitive(shard.identifier), "inputSha256" to JsonPrimitive(shard.inputSha256)))
        })
        if (run.controlArray("shards") != expectedShards || binding.maximumWorkers != maximumWorkers ||
            binding.outputs.map { it.shardId to it.inputSha256 } != shards.map { it.identifier to it.inputSha256 }
        ) {
            callRunFail("call-observation run does not cover the exact current inventory")
        }
        requirePopulation(
            binding.outputs.fold(0L) { total, output -> Math.addExact(total, output.outputBytes) },
            binding.outputs.fold(0L) { total, output -> Math.addExact(total, output.entities) },
        )
    }

    fun receipt(
        root: Path,
        binding: BoundedShardRunBinding,
        outputs: List<FullTreeCallObservationPublication>,
    ) = FullTreeCallObservationRunPublication(
        root, binding.runSha256, binding.indexArtifactSha256, scope.sha256,
        inventory.authenticatedSha256, artifact.authenticatedSha256, maximumWorkers, outputs,
    )
}

private data class CallRunPaths(val rich: Path, val inventory: Path, val scratch: Path, val result: Path) {
    companion object {
        fun authenticate(richArtifact: Path, inventoryPath: Path, scratchParent: Path, resultRoot: Path): CallRunPaths {
            val rich = richArtifact.toAbsolutePath().normalize()
            val inventory = inventoryPath.toAbsolutePath().normalize()
            val scratch = requireStableDirectory(scratchParent, "call-observation run scratch parent").first
            val result = resultRoot.toAbsolutePath().normalize()
            if (result.parent == null || result.fileName == null) callRunFail("call-observation run must name a directory")
            requireStableDirectory(result.parent, "call-observation run result parent")
            if (rich == inventory || listOf(rich, inventory, scratch).any { pathsOverlap(result, it) } ||
                listOf(rich, inventory).any { pathsOverlap(scratch, it) }
            ) {
                callRunFail("call-observation run output or scratch overlaps an input")
            }
            return CallRunPaths(rich, inventory, scratch, result)
        }
    }
}

private class CallRunWorkspace private constructor(
    private val root: Path,
    private val identity: Any,
    private val maximumEntries: Long,
    val prepared: Path,
    val worker: Path,
) : AutoCloseable {
    private var closed = false

    fun requireWorkerEmpty() {
        if (callRunAttributes(root).fileKey() != identity) callRunFail("call-observation run workspace changed identity")
        Files.newDirectoryStream(worker).use { entries ->
            if (entries.iterator().hasNext()) callRunFail("call-observation worker left scratch residue")
        }
    }

    override fun close() {
        if (closed) return
        deleteCallRunTree(root, identity, maximumEntries)
        closed = true
    }

    companion object {
        fun create(parent: Path, maximumEntries: Long): CallRunWorkspace {
            val root = Files.createTempDirectory(
                parent, ".call-observation-run-work-", PosixFilePermissions.asFileAttribute(CALL_RUN_WRITABLE_DIRECTORY),
            )
            val identity = requireNotNull(callRunAttributes(root).fileKey())
            try {
                val prepared = Files.createDirectory(
                    root.resolve("prepared"), PosixFilePermissions.asFileAttribute(CALL_RUN_WRITABLE_DIRECTORY),
                )
                val worker = Files.createDirectory(
                    root.resolve("worker"), PosixFilePermissions.asFileAttribute(CALL_RUN_WRITABLE_DIRECTORY),
                )
                return CallRunWorkspace(root, identity, maximumEntries, prepared, worker)
            } catch (failure: Throwable) {
                runCatching { deleteCallRunTree(root, identity, maximumEntries) }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class CallRunOutputStage private constructor(
    private val target: Path,
    private val parentIdentity: Any,
    private val container: Path,
    private val containerIdentity: Any,
    private val maximumEntries: Long,
) : AutoCloseable {
    val run: Path = container.resolveSibling("${container.fileName}.run")
    private var runIdentity: Any? = null
    private var published = false
    private var committed = false

    fun retainRunIdentity() {
        requireStageParent()
        runIdentity = requireNotNull(callRunAttributes(run).fileKey())
    }

    fun commit(checkpoint: (String) -> Unit, verify: (Path) -> Unit) {
        requireStageParent()
        val identity = requireNotNull(runIdentity)
        requireCallRunDirectoryIdentity(run, identity)
        verify(run)
        LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
            requireStageParent()
            LinuxFilesystemSyscalls.synchronize(parent)
            parent.whileOpen { descriptor ->
                LinuxFilesystemSyscalls.renameNoReplace(descriptor, run.fileName.toString(), target.fileName.toString())
            }
            published = true
            LinuxFilesystemSyscalls.synchronize(parent)
            requireCallRunDirectoryIdentity(target, identity)
            verify(target)
            requireStageParent()
            Files.delete(container)
            LinuxFilesystemSyscalls.synchronize(parent)
        }
        checkpoint("after complete call-observation publication cleanup")
        committed = true
    }

    private fun requireStageParent() {
        if (requireStableDirectory(target.parent, "call-observation run output parent").second != parentIdentity) {
            callRunFail("call-observation run output parent changed identity")
        }
        requireCallRunDirectoryIdentity(container, containerIdentity)
    }

    override fun close() {
        if (committed) return
        var failure: Throwable? = null
        if (runIdentity != null) {
            try {
                deleteCallRunTree(if (published) target else run, requireNotNull(runIdentity), maximumEntries)
            } catch (caught: Throwable) {
                failure = caught
            }
        }
        if (Files.exists(container, LinkOption.NOFOLLOW_LINKS)) {
            try {
                deleteCallRunTree(container, containerIdentity, maximumEntries)
            } catch (caught: Throwable) {
                if (failure == null) failure = caught else failure.addSuppressed(caught)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun create(target: Path, maximumEntries: Long): CallRunOutputStage {
            val (_, parentIdentity) = requireStableDirectory(target.parent, "call-observation run output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) callRunFail("call-observation run target already exists")
            val container = Files.createTempDirectory(
                target.parent, ".call-observation-run-stage-", PosixFilePermissions.asFileAttribute(CALL_RUN_WRITABLE_DIRECTORY),
            )
            return CallRunOutputStage(
                target, parentIdentity, container, requireNotNull(callRunAttributes(container).fileKey()), maximumEntries,
            )
        }
    }
}

private fun requireCallRunImmutable(
    root: Path,
    shards: List<FullTreeCallObservationShardInput>,
    deadline: FullTreeCallObservationDeadline,
) {
    listOf(root, root.resolve("outputs"), root.resolve("checkpoints")).forEach { directory ->
        if (Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS) != CALL_RUN_READ_ONLY_DIRECTORY) {
            callRunFail("call-observation run directory must have mode 0500")
        }
    }
    fun requireFile(path: Path) {
        deadline.checkpoint("while checking immutable call-observation run members")
        val attributes = callRunAttributes(path)
        if (!attributes.isRegularFile || attributes.isSymbolicLink ||
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != CALL_RUN_READ_ONLY_FILE ||
            (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong() != 1L
        ) {
            callRunFail("call-observation run members must be single-link mode-0400 regular files")
        }
    }
    requireFile(root.resolve("run.json"))
    requireFile(root.resolve("index.json"))
    shards.forEach { shard ->
        requireFile(root.resolve("outputs").resolve("${shard.identifier}.json"))
        requireFile(root.resolve("checkpoints").resolve("${shard.identifier}.json"))
    }
}

private fun deleteCallRunTree(root: Path, identity: Any, maximumEntries: Long) {
    requireCallRunDirectoryIdentity(root, identity)
    var entries = 0L
    fun charge(path: Path) {
        entries = Math.addExact(entries, 1L)
        if (entries > maximumEntries || root.relativize(path).nameCount > 6) {
            callRunFail("call-observation cleanup exceeds its fixed tree bound")
        }
    }
    Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
            charge(directory)
            if (!attributes.isDirectory || attributes.isSymbolicLink) callRunFail("call-observation cleanup found a link")
            Files.setPosixFilePermissions(directory, CALL_RUN_WRITABLE_DIRECTORY)
            return FileVisitResult.CONTINUE
        }

        override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
            charge(file)
            if (!attributes.isRegularFile || attributes.isSymbolicLink ||
                (Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong() != 1L
            ) {
                callRunFail("call-observation cleanup refuses linked or special files")
            }
            Files.delete(file)
            return FileVisitResult.CONTINUE
        }

        override fun postVisitDirectory(directory: Path, failure: java.io.IOException?): FileVisitResult {
            failure?.let { throw it }
            Files.delete(directory)
            return FileVisitResult.CONTINUE
        }
    })
}

private fun requireCallRunDirectoryIdentity(path: Path, expected: Any) {
    val attributes = callRunAttributes(path)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() != expected) {
        callRunFail("call-observation private directory changed identity")
    }
}

private fun callRunAttributes(path: Path): BasicFileAttributes =
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)

private fun pathsOverlap(first: Path, second: Path): Boolean = first.startsWith(second) || second.startsWith(first)

private inline fun <Result> translateCallRunFailure(action: () -> Result): Result = try {
    action()
} catch (failure: FullTreeCallObservationRunException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeCallObservationRunException("call-observation run generation or validation failed", failure)
}

private fun callRunFail(message: String): Nothing = throw FullTreeCallObservationRunException(message)

private const val CALL_RUN_MAXIMUM_SHARD_NAME_CHARACTERS = 250
private const val CALL_RUN_CHECKPOINT_RESERVED_BYTES = 4096L
private val CALL_RUN_WRITABLE_DIRECTORY = PosixFilePermissions.fromString("rwx------")
private val CALL_RUN_READ_ONLY_DIRECTORY = PosixFilePermissions.fromString("r-x------")
private val CALL_RUN_READ_ONLY_FILE = PosixFilePermissions.fromString("r--------")

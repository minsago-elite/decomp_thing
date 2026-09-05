package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.security.SecureRandom

internal class FullTreeCallObservationPublicationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeCallObservationPublicationLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val producer: FullTreeCallObservationProducerLimits = FullTreeCallObservationProducerLimits(),
    val sqlite: FullTreeCallObservationSqliteLimits = FullTreeCallObservationSqliteLimits(),
)

internal data class FullTreeCallObservationPublication(
    val shardId: String,
    val inputSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val scopeSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
    val scannedDies: Long,
) {
    val authoritativeReleaseEvidence: Boolean get() = false
    val candidateLeaseRetained: Boolean get() = false
}

internal object FullTreeCallObservationShardPublisher {
    fun generateAndPublish(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: Path,
        limits: FullTreeCallObservationPublicationLimits = FullTreeCallObservationPublicationLimits(),
    ): FullTreeCallObservationPublication = translateCallPublicationFailure {
        generateAndPublishWithinDeadline(
            richArtifact, inventoryPath, scope, shardId, scratchParent, output, limits,
            FullTreeCallObservationDeadline.start(scope, limits.control),
        )
    }

    internal fun generateAndPublishWithinDeadline(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: Path,
        limits: FullTreeCallObservationPublicationLimits,
        deadline: FullTreeCallObservationDeadline,
    ): FullTreeCallObservationPublication = translateCallPublicationFailure {
        requireDistinctControlOutput(output, "rich artifact" to richArtifact, "inventory" to inventoryPath)
        withCallPublicationInputs(richArtifact, inventoryPath, scope, shardId, limits, deadline) { inputs, budget ->
            CallObservationOutputStage.create(output).use { stage ->
                val generated = stage.write { stream ->
                    FullTreeCallObservationProducer.generateShardToWithinDeadline(
                        richArtifact, inventoryPath, scope, shardId, scratchParent, stream,
                        limits.control, limits.producer, limits.sqlite, budget,
                    )
                }
                budget.checkpoint("after first call-observation derivation")
                inputs.verify()
                val rederived = stage.openComparisonInput().use { candidate ->
                    compareCallProjection(
                        candidate, generated.outputBytes, richArtifact, inventoryPath, scope,
                        shardId, scratchParent, limits, budget,
                    )
                }
                requireEquivalentCallProjection(generated, rederived)
                stage.verifyLinkedCandidate()
                stage.publish(
                    CallObservationOutputDigest(generated.outputSha256, generated.outputBytes),
                    inputs.maximumOutputBytes, budget, inputs::verify,
                )
                inputs.receipt(generated)
            }
        }
    }

    fun loadAndValidate(
        candidate: Path,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        limits: FullTreeCallObservationPublicationLimits = FullTreeCallObservationPublicationLimits(),
    ): FullTreeCallObservationPublication = translateCallPublicationFailure {
        loadAndValidateWithinDeadline(
            candidate, richArtifact, inventoryPath, scope, shardId, scratchParent, limits,
            FullTreeCallObservationDeadline.start(scope, limits.control),
        )
    }

    internal fun loadAndValidateWithinDeadline(
        candidate: Path,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        limits: FullTreeCallObservationPublicationLimits,
        deadline: FullTreeCallObservationDeadline,
    ): FullTreeCallObservationPublication = translateCallPublicationFailure {
        requireDistinctControlOutput(candidate, "rich artifact" to richArtifact, "inventory" to inventoryPath)
        withCallPublicationInputs(richArtifact, inventoryPath, scope, shardId, limits, deadline) { inputs, budget ->
            StableControlFile.open(candidate, inputs.maximumOutputBytes, "call-observation candidate").use { guard ->
                guard.requireSingleLink("call-observation candidate")
                requireReadOnlyCandidate(candidate)
                val generated = guard.slice().use { bytes ->
                    compareCallProjection(
                        bytes, guard.size, richArtifact, inventoryPath, scope, shardId, scratchParent, limits, budget,
                    )
                }
                if (guard.authenticatedSha256 != generated.outputSha256 || guard.size != generated.outputBytes) {
                    publicationFail("call-observation candidate differs from its raw derivation")
                }
                guard.verifyUnchanged("call-observation candidate after rederivation")
                guard.requireSingleLink("call-observation candidate after rederivation")
                requireReadOnlyCandidate(candidate)
                inputs.verify()
                budget.checkpoint("after call-observation candidate validation")
                inputs.receipt(generated)
            }
        }
    }
}

private fun <Result> withCallPublicationInputs(
    richArtifact: Path,
    inventoryPath: Path,
    scope: AuthenticatedFullTreeScope,
    shardId: String,
    limits: FullTreeCallObservationPublicationLimits,
    budget: FullTreeCallObservationDeadline,
    action: (CallPublicationInputs, FullTreeCallObservationDeadline) -> Result,
): Result {
    budget.requireShardScope(scope)
    budget.checkpoint("before authenticating call-publication scope")
    FullTreeScopeControl.validate(scope, limits.control)
    val perShard = scope.document.controlObject("bounds").controlObject("perShard")
    budget.checkpoint("before authenticating call-publication inputs")
    StableControlFile.open(
        inventoryPath, limits.control.maximumInventoryBytes.toLong(), "call inventory",
    ).use { inventory ->
        StableControlFile.open(richArtifact, limits.control.maximumRichArtifactBytes, "call artifact").use { artifact ->
            val inputs = FullTreeCallObservationProducer.authenticateShardInputs(
                inventoryPath, scope, shardId, limits.control, budget::checkpoint,
            )
            if (inventory.authenticatedSha256 != inputs.inventoryArtifactSha256 ||
                artifact.authenticatedSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")
            ) {
                publicationFail("call-publication inputs differ from their authenticated scope")
            }
            val pinned = CallPublicationInputs(
                scope, inputs, inventory, artifact, limits.control,
                minOf(limits.sqlite.maximumOutputBytes, perShard.controlLong("serializedBytes")), budget,
            )
            pinned.verify()
            return action(pinned, budget)
        }
    }
}

private class CallPublicationInputs(
    private val scope: AuthenticatedFullTreeScope,
    private val inputs: FullTreeCallObservationAuthenticatedInputs,
    private val inventory: StableControlFile,
    private val artifact: StableControlFile,
    private val limits: FullTreeControlLimits,
    val maximumOutputBytes: Long,
    private val budget: FullTreeCallObservationDeadline,
) {
    fun verify() {
        budget.checkpoint("before checking call-publication input guards")
        FullTreeScopeControl.validate(scope, limits)
        inventory.verifyUnchanged("call inventory during publication")
        artifact.verifyUnchanged("call artifact during publication")
        budget.checkpoint("after checking call-publication input guards")
    }

    fun receipt(result: FullTreeCallObservationStreamResult) = FullTreeCallObservationPublication(
        inputs.shard.identifier, inputs.shard.inputSha256, inventory.authenticatedSha256,
        artifact.authenticatedSha256, scope.sha256, result.outputSha256, result.outputBytes,
        result.entities, result.scannedDies,
    )
}

private fun compareCallProjection(
    candidate: InputStream,
    expectedBytes: Long,
    richArtifact: Path,
    inventoryPath: Path,
    scope: AuthenticatedFullTreeScope,
    shardId: String,
    scratchParent: Path,
    limits: FullTreeCallObservationPublicationLimits,
    budget: FullTreeCallObservationDeadline,
): FullTreeCallObservationStreamResult {
    val comparison = CallObservationComparingOutput(candidate, expectedBytes, budget)
    val generated = FullTreeCallObservationProducer.generateShardToWithinDeadline(
        richArtifact, inventoryPath, scope, shardId, scratchParent, comparison,
        limits.control, limits.producer, limits.sqlite, budget,
    )
    comparison.finish()
    return generated
}

private class CallObservationComparingOutput(
    private val candidate: InputStream,
    private val expectedBytes: Long,
    private val budget: FullTreeCallObservationDeadline,
) : OutputStream() {
    private val buffer = ByteArray(64 * 1024)
    private var compared = 0L

    override fun write(value: Int) = write(byteArrayOf(value.toByte()))

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        if (compared > expectedBytes - length.toLong()) publicationFail("call-observation candidate is truncated")
        var cursor = offset
        while (cursor < offset + length) {
            budget.checkpoint("while comparing a rederived call observation")
            val count = minOf(buffer.size, offset + length - cursor)
            var filled = 0
            while (filled < count) {
                val read = candidate.read(buffer, filled, count - filled)
                if (read <= 0) publicationFail("call-observation candidate ended during rederivation")
                filled += read
            }
            for (index in 0 until count) {
                if (bytes[cursor + index] != buffer[index]) publicationFail("call-observation candidate contains forged bytes")
            }
            compared += count
            cursor += count
        }
    }

    fun finish() {
        if (compared != expectedBytes || candidate.read() != -1) {
            publicationFail("call-observation candidate length differs from its raw derivation")
        }
        budget.checkpoint("after comparing call-observation bytes")
    }
}

private fun requireEquivalentCallProjection(
    first: FullTreeCallObservationStreamResult,
    second: FullTreeCallObservationStreamResult,
) {
    if (first.outputSha256 != second.outputSha256 || first.outputBytes != second.outputBytes ||
        first.entities != second.entities || first.scannedDies != second.scannedDies || first.scored != second.scored
    ) {
        publicationFail("independent call-observation derivations disagree")
    }
}

private inline fun <Result> translateCallPublicationFailure(action: () -> Result): Result = try {
    action()
} catch (failure: FullTreeCallObservationPublicationException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeCallObservationPublicationException("call-observation publication or validation failed", failure)
}

private data class CallObservationOutputDigest(val sha256: String, val bytes: Long)
private class CallObservationOutputStage private constructor(
    private val target: Path,
    private val parent: Path,
    private val parentIdentity: Any,
    private val parentDescriptor: LinuxDescriptor,
    private val stageName: String,
    private val stageDescriptor: LinuxDescriptor,
) : AutoCloseable {
    private var published = false
    private var committed = false

    fun <T> write(action: (OutputStream) -> T): T {
        requireNamedIdentity(stageName, "call-observation staging output")
        val pinned = LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd)
        return FileChannel.open(
            pinned,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
        ).use { channel ->
            val stream = BufferedOutputStream(Channels.newOutputStream(channel), OUTPUT_BUFFER_BYTES)
            val result = action(stream)
            stream.flush()
            channel.force(true)
            result
        }.also {
            LinuxFilesystemSyscalls.synchronize(stageDescriptor)
            requireNamedIdentity(stageName, "call-observation staging output")
        }
    }

    fun openComparisonInput(): InputStream {
        requireNamedIdentity(stageName, "call-observation staging output before re-derivation")
        val channel = FileChannel.open(
            LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd),
            StandardOpenOption.READ,
        )
        return try {
            Channels.newInputStream(channel)
        } catch (failure: Throwable) {
            channel.close()
            throw failure
        }
    }

    fun verifyLinkedCandidate() {
        requireParentIdentity("after re-deriving staged call-observation output")
        requireNamedIdentity(stageName, "re-derived call-observation staging output")
        requireStageMode(OWNER_READ_WRITE_MODE, "re-derived call-observation staging output")
    }

    fun publish(
        expected: CallObservationOutputDigest,
        maximumBytes: Long,
        budget: FullTreeCallObservationDeadline,
        verifyInputs: () -> Unit,
    ) {
        budget.checkpoint("before verifying staged call-observation output")
        requireParentIdentity("before call-observation publication")
        requireNamedIdentity(stageName, "call-observation staging output")
        val actual = digestPinnedStage(maximumBytes, budget)
        if (actual != expected) publicationFail("staged call-observation output differs from generated bytes")

        LinuxFilesystemSyscalls.chmodPinned(stageDescriptor, OWNER_READ_ONLY_MODE)
        LinuxFilesystemSyscalls.synchronize(stageDescriptor)
        requireStageMode(OWNER_READ_ONLY_MODE, "staged call-observation output")
        requireNamedIdentity(stageName, "call-observation staging output")
        verifyInputs()
        budget.checkpoint("before atomic call-observation publication")
        requireParentIdentity("before atomic call-observation publication")
        parentDescriptor.whileOpen { parentFd ->
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                publicationFail("call-observation publication target already exists")
            }
            LinuxFilesystemSyscalls.synchronize(parentDescriptor)
            try {
                LinuxFilesystemSyscalls.renameNoReplace(
                    parentFd,
                    stageName,
                    target.fileName.toString(),
                )
            } catch (failure: LinuxSyscallException) {
                if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                    throw FullTreeCallObservationPublicationException(
                        "call-observation publication target already exists",
                        failure,
                    )
                }
                throw failure
            }
            published = true
        }
        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
        requireParentIdentity("after atomic call-observation publication")
        requireNamedIdentity(target.fileName.toString(), "published call-observation output")
        requireStageMode(OWNER_READ_ONLY_MODE, "published call-observation output")
        if (digestPinnedStage(maximumBytes, budget) != expected) {
            publicationFail("published call-observation output differs from staged bytes")
        }
        verifyInputs()
        budget.checkpoint("after verifying atomic call-observation publication")
        committed = true
    }

    private fun digestPinnedStage(
        maximumBytes: Long,
        budget: FullTreeCallObservationDeadline,
    ): CallObservationOutputDigest {
        val digest = MessageDigest.getInstance("SHA-256")
        val pinned = LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd)
        return FileChannel.open(pinned, StandardOpenOption.READ).use { channel ->
            val size = channel.size()
            if (size !in 1L..maximumBytes) {
                publicationFail("call-observation staging output exceeds its byte bound")
            }
            val buffer = ByteBuffer.allocate(OUTPUT_BUFFER_BYTES)
            var total = 0L
            while (total < size) {
                buffer.clear()
                buffer.limit(minOf(buffer.capacity().toLong(), size - total).toInt())
                val read = channel.read(buffer)
                if (read <= 0) publicationFail("call-observation staging output ended while hashing")
                digest.update(buffer.array(), 0, read)
                total = checkedAdd(total, read.toLong(), "call-observation staging byte count")
                budget.checkpoint("while hashing call-observation staging output")
            }
            if (channel.read(ByteBuffer.allocate(1)) >= 0) {
                publicationFail("call-observation staging output grew while hashing")
            }
            CallObservationOutputDigest(digest.digest().hex(), total)
        }
    }

    private fun requireParentIdentity(label: String) {
        val (_, current) = requireStableDirectory(parent, "call-observation output parent")
        if (current != parentIdentity) publicationFail("call-observation output parent changed $label")
        parentDescriptor.whileOpen { fd ->
            if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(fd))) {
                publicationFail("call-observation output parent changed $label")
            }
        }
    }

    private fun requireNamedIdentity(name: String, label: String) {
        parentDescriptor.whileOpen { parentFd ->
            val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parentFd, name)
                ?: publicationFail("$label disappeared")
            named.use {
                val pinned = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
                val observed = LinuxFilesystemSyscalls.identity(named.fd)
                if (!sameRegularFile(pinned, observed)) publicationFail("$label changed identity")
            }
        }
    }

    private fun requireStageMode(mode: Int, label: String) {
        val identity = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
        if (!identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
            identity.mode.permissions != mode
        ) {
            publicationFail("$label permissions or link count differ")
        }
    }

    override fun close() {
        var failure: Throwable? = null
        if (!committed) {
            try {
                revoke()
            } catch (cleanupFailure: Throwable) {
                failure = cleanupFailure
            }
        }
        try {
            stageDescriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        try {
            parentDescriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    private fun revoke() {
        val linkedName = if (published) target.fileName.toString() else stageName
        parentDescriptor.whileOpen { parentFd ->
            val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parentFd, linkedName)
            if (named == null) {
                if (published) publicationFail("unverified call-observation publication disappeared")
                return@whileOpen
            }
            named.use {
                val pinned = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
                val observed = LinuxFilesystemSyscalls.identity(named.fd)
                if (!sameRegularFile(pinned, observed)) {
                    publicationFail("refusing to revoke a changed call-observation output")
                }
            }
            LinuxFilesystemSyscalls.unlink(parentFd, linkedName)
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, linkedName)?.use {
                publicationFail("revoked call-observation output remains linked")
            }
        }
        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
    }

    companion object {
        fun create(targetPath: Path): CallObservationOutputStage {
            val target = targetPath.toAbsolutePath().normalize()
            if (target.parent == null || target.fileName == null) {
                publicationFail("call-observation output must name a file")
            }
            LinuxFilesystemSyscalls.requireSupported(target.parent)
            val (parent, parentIdentity) = requireStableDirectory(
                target.parent,
                "call-observation output parent",
            )
            val parentDescriptor = LinuxFilesystemSyscalls.openRoot(parent)
            try {
                parentDescriptor.whileOpen { parentFd ->
                    if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                        publicationFail("call-observation output parent changed during authorization")
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                        publicationFail("call-observation publication target already exists")
                    }
                }
                val (stageName, stageDescriptor) = createPrivateStage(parentDescriptor)
                return CallObservationOutputStage(
                    target = target,
                    parent = parent,
                    parentIdentity = parentIdentity,
                    parentDescriptor = parentDescriptor,
                    stageName = stageName,
                    stageDescriptor = stageDescriptor,
                )
            } catch (failure: Throwable) {
                parentDescriptor.close()
                throw failure
            }
        }

        private fun createPrivateStage(parent: LinuxDescriptor): Pair<String, LinuxDescriptor> {
            repeat(MAXIMUM_STAGE_NAME_ATTEMPTS) {
                val random = ByteArray(STAGE_RANDOM_BYTES).also(SECURE_RANDOM::nextBytes).hex()
                val name = ".call-observation-$random.tmp"
                val stage = try {
                    parent.whileOpen { parentFd ->
                        LinuxFilesystemSyscalls.createRegularFile(
                            parentFd,
                            name,
                            OWNER_READ_WRITE_MODE,
                        )
                    }
                } catch (failure: LinuxSyscallException) {
                    if (failure.errno == LinuxFilesystemSyscalls.EEXIST) return@repeat
                    throw failure
                }
                try {
                    LinuxFilesystemSyscalls.chmod(stage, OWNER_READ_WRITE_MODE)
                    LinuxFilesystemSyscalls.synchronize(stage)
                    val identity = LinuxFilesystemSyscalls.identity(stage.fd)
                    if (!identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
                        identity.mode.permissions != OWNER_READ_WRITE_MODE
                    ) {
                        publicationFail("call-observation staging output is not private")
                    }
                    LinuxFilesystemSyscalls.synchronize(parent)
                    return name to stage
                } catch (failure: Throwable) {
                    try {
                        parent.whileOpen { LinuxFilesystemSyscalls.unlinkIfPresent(it, name) }
                    } catch (cleanupFailure: Throwable) {
                        failure.addSuppressed(cleanupFailure)
                    }
                    stage.close()
                    throw failure
                }
            }
            publicationFail("cannot allocate a unique call-observation staging output")
        }
    }
}

private fun sameRegularFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.isRegularFile && second.isRegularFile && !first.isSymbolicLink && !second.isSymbolicLink

private fun requireReadOnlyCandidate(candidate: Path) {
    val mode = (Files.getAttribute(candidate, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    if (mode.permissions != OWNER_READ_ONLY_MODE) publicationFail("call-observation candidate must have mode 0400")
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeCallObservationPublicationException("$label overflows", failure)
}

private fun publicationFail(message: String): Nothing = throw FullTreeCallObservationPublicationException(message)

private const val OUTPUT_BUFFER_BYTES = 64 * 1024
private const val OWNER_READ_ONLY_MODE = 0x100
private const val OWNER_READ_WRITE_MODE = 0x180
private const val MAXIMUM_STAGE_NAME_ATTEMPTS = 32
private const val STAGE_RANDOM_BYTES = 16
private val SECURE_RANDOM = SecureRandom()

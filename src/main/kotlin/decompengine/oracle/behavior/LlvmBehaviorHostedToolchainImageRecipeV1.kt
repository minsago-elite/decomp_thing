package decompengine.oracle.behavior

import decompengine.oracle.fulltree.StableControlFile
import java.io.OutputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest

internal class LlvmBehaviorHostedToolchainImageRecipeV1Exception(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Retained Kotlin/JVM ownership of the exact reviewed LLVM toolchain-image recipe.
 *
 * This owner authenticates and pins only the reproduction lock, historical build record, and
 * Dockerfile. It exposes no tag, freshly built image ID, Docker executable, endpoint, command,
 * runner, build result, inspect result, image/build authority, or mutation method. A future live
 * Engine builder must accept this owner directly, perform the fresh build, independently inspect
 * the resulting exact ID, and mint a separate sealed image capability itself.
 *
 * ACP remains the first-class candidate producer/operator outside this image-recipe closure. ACP
 * is not an input here and gains no oracle, reference, policy, validation, observation, START,
 * containment, scoring, certification, image, or release authority. No Python process, script,
 * module execution, or Python-generated evidence implements or is accepted as oracle/control
 * authority here. The reviewed Dockerfile's package set includes Python; this owner makes no
 * Python-absence claim about a future image.
 */
internal sealed interface LlvmBehaviorHostedToolchainImageRecipeV1Owner : AutoCloseable {
    val reproductionLockSha256: String
    val buildRecordSha256: String
    val dockerfileSha256: String
    val dockerfileBytes: Long
    val deterministicTarSha256: String
    val deterministicTarBytes: Long
    val baseImageReference: String
    val platform: String
    val sourceDateEpoch: String

    fun requireCurrent()

    /** Emits only the descriptor-pinned reviewed Dockerfile; it performs no Docker operation. */
    fun writeDockerfileTo(output: OutputStream)

    /** Emits the fixed one-file USTAR build context; it performs no Docker operation. */
    fun writeDeterministicTarTo(output: OutputStream)

    override fun close()
}

/** Opens the exact reviewed recipe from three raw files and retains their authenticated bytes. */
internal object LlvmBehaviorHostedToolchainImageRecipeV1 {
    fun open(
        reproductionLockPath: Path,
        buildRecordPath: Path,
        dockerfilePath: Path,
    ): LlvmBehaviorHostedToolchainImageRecipeV1Owner = BoundOwner(
        reproductionLockPath,
        buildRecordPath,
        dockerfilePath,
    )

    private class BoundOwner(
        reproductionLockPath: Path,
        buildRecordPath: Path,
        dockerfilePath: Path,
    ) : LlvmBehaviorHostedToolchainImageRecipeV1Owner {
        private val state = translateRecipeFailure("open LLVM hosted toolchain-image recipe") {
            BoundRecipe.open(reproductionLockPath, buildRecordPath, dockerfilePath)
        }
        private var closed = false
        private var poisoned = false

        override val reproductionLockSha256: String
            get() = state.reproductionLockSha256
        override val buildRecordSha256: String
            get() = state.buildRecordSha256
        override val dockerfileSha256: String
            get() = state.dockerfileSha256
        override val dockerfileBytes: Long
            get() = state.dockerfileBytes
        override val deterministicTarSha256: String
            get() = state.deterministicTarSha256
        override val deterministicTarBytes: Long
            get() = state.deterministicTarBytes
        override val baseImageReference: String
            get() = REVIEWED_BASE_IMAGE_REFERENCE
        override val platform: String
            get() = REVIEWED_PLATFORM
        override val sourceDateEpoch: String
            get() = REVIEWED_SOURCE_DATE_EPOCH

        @Synchronized
        override fun requireCurrent() {
            check(!closed) { "LLVM hosted toolchain-image recipe owner is closed" }
            if (poisoned) recipeFail("LLVM hosted toolchain-image recipe owner is poisoned")
            try {
                state.requireCurrent()
            } catch (failure: Throwable) {
                poisoned = true
                if (failure is LlvmBehaviorHostedToolchainImageRecipeV1Exception) throw failure
                throw LlvmBehaviorHostedToolchainImageRecipeV1Exception(
                    "LLVM hosted toolchain-image recipe changed",
                    failure,
                )
            }
        }

        @Synchronized
        override fun writeDockerfileTo(output: OutputStream) {
            check(!closed) { "LLVM hosted toolchain-image recipe owner is closed" }
            if (poisoned) recipeFail("LLVM hosted toolchain-image recipe owner is poisoned")
            try {
                state.writeDockerfileTo(output)
            } catch (failure: Throwable) {
                poisoned = true
                if (failure is LlvmBehaviorHostedToolchainImageRecipeV1Exception) throw failure
                throw LlvmBehaviorHostedToolchainImageRecipeV1Exception(
                    "cannot emit the reviewed LLVM toolchain Dockerfile",
                    failure,
                )
            }
        }

        @Synchronized
        override fun writeDeterministicTarTo(output: OutputStream) {
            check(!closed) { "LLVM hosted toolchain-image recipe owner is closed" }
            if (poisoned) recipeFail("LLVM hosted toolchain-image recipe owner is poisoned")
            try {
                state.writeDeterministicTarTo(output)
            } catch (failure: Throwable) {
                poisoned = true
                if (failure is LlvmBehaviorHostedToolchainImageRecipeV1Exception) throw failure
                throw LlvmBehaviorHostedToolchainImageRecipeV1Exception(
                    "cannot emit the deterministic LLVM toolchain build context",
                    failure,
                )
            }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            state.close()
        }
    }
}

private class BoundRecipe private constructor(
    val reproductionLockSha256: String,
    val buildRecordSha256: String,
    val dockerfileSha256: String,
    val dockerfileBytes: Long,
    val deterministicTarSha256: String,
    val deterministicTarBytes: Long,
    private val reproductionLock: StableControlFile,
    private val buildRecord: StableControlFile,
    private val dockerfile: StableControlFile,
) : AutoCloseable {
    fun requireCurrent() {
        requireGuardCurrent(
            reproductionLock,
            reproductionLockSha256,
            "LLVM toolchain reproduction lock",
        )
        requireGuardCurrent(buildRecord, buildRecordSha256, "LLVM toolchain build record")
        requireGuardCurrent(dockerfile, dockerfileSha256, "LLVM toolchain Dockerfile")
    }

    fun writeDockerfileTo(output: OutputStream) {
        requireCurrent()
        emitReviewedDockerfile(dockerfile, dockerfileBytes, dockerfileSha256, output)
        requireCurrent()
    }

    fun writeDeterministicTarTo(output: OutputStream) {
        requireCurrent()
        val emitted = emitDeterministicBuildContextTar(
            dockerfile,
            dockerfileBytes,
            dockerfileSha256,
            output,
        )
        if (emitted.bytes != deterministicTarBytes || emitted.sha256 != deterministicTarSha256) {
            recipeFail("deterministic LLVM toolchain build-context tar changed")
        }
        requireCurrent()
    }

    override fun close() {
        var failure: Throwable? = null
        listOf(dockerfile, buildRecord, reproductionLock).forEach { guard ->
            try {
                guard.close()
            } catch (closeFailure: Throwable) {
                val previous = failure
                if (previous == null) failure = closeFailure else previous.addSuppressed(closeFailure)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(
            reproductionLockPath: Path,
            buildRecordPath: Path,
            dockerfilePath: Path,
        ): BoundRecipe {
            val paths = normalizeRecipePaths(reproductionLockPath, buildRecordPath, dockerfilePath)
            var reproductionLock: StableControlFile? = null
            var buildRecord: StableControlFile? = null
            var dockerfile: StableControlFile? = null
            try {
                reproductionLock = StableControlFile.open(
                    paths.reproductionLock,
                    MAXIMUM_REPRODUCTION_LOCK_BYTES,
                    "LLVM toolchain reproduction lock",
                )
                buildRecord = StableControlFile.open(
                    paths.buildRecord,
                    MAXIMUM_BUILD_RECORD_BYTES,
                    "LLVM toolchain build record",
                )
                dockerfile = StableControlFile.open(
                    paths.dockerfile,
                    MAXIMUM_DOCKERFILE_BYTES,
                    "LLVM toolchain Dockerfile",
                )
                requireSingleLink(reproductionLock.path, "LLVM toolchain reproduction lock")
                requireSingleLink(buildRecord.path, "LLVM toolchain build record")
                requireSingleLink(dockerfile.path, "LLVM toolchain Dockerfile")

                val lockSha256 = reproductionLock.sha256(label = "LLVM toolchain reproduction lock")
                val buildRecordSha256 = buildRecord.sha256(label = "LLVM toolchain build record")
                val dockerfileSha256 = dockerfile.sha256(label = "LLVM toolchain Dockerfile")
                requireExactSha256(lockSha256, REVIEWED_REPRODUCTION_LOCK_SHA256, "reproduction lock")
                requireExactSha256(buildRecordSha256, REVIEWED_BUILD_RECORD_SHA256, "build record")
                requireExactSha256(dockerfileSha256, REVIEWED_DOCKERFILE_SHA256, "Dockerfile")
                val deterministicTar = emitDeterministicBuildContextTar(
                    dockerfile,
                    dockerfile.size,
                    dockerfileSha256,
                    OutputStream.nullOutputStream(),
                )

                val result = BoundRecipe(
                    reproductionLockSha256 = lockSha256,
                    buildRecordSha256 = buildRecordSha256,
                    dockerfileSha256 = dockerfileSha256,
                    dockerfileBytes = dockerfile.size,
                    deterministicTarSha256 = deterministicTar.sha256,
                    deterministicTarBytes = deterministicTar.bytes,
                    reproductionLock = reproductionLock,
                    buildRecord = buildRecord,
                    dockerfile = dockerfile,
                )
                result.requireCurrent()
                return result
            } catch (failure: Throwable) {
                listOf(dockerfile, buildRecord, reproductionLock).forEach { guard ->
                    if (guard != null) runCatching { guard.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                }
                throw failure
            }
        }
    }
}

private data class RecipePaths(
    val reproductionLock: Path,
    val buildRecord: Path,
    val dockerfile: Path,
)

private fun normalizeRecipePaths(
    reproductionLockPath: Path,
    buildRecordPath: Path,
    dockerfilePath: Path,
): RecipePaths {
    val lock = requireCanonicalRecipePath(reproductionLockPath, "LLVM toolchain reproduction lock")
    val record = requireCanonicalRecipePath(buildRecordPath, "LLVM toolchain build record")
    val dockerfile = requireCanonicalRecipePath(dockerfilePath, "LLVM toolchain Dockerfile")
    if (lock.fileName.toString() != REPRODUCTION_LOCK_FILE_NAME) {
        recipeFail("LLVM toolchain reproduction lock has the wrong file name")
    }
    if (record.fileName.toString() != BUILD_RECORD_FILE_NAME) {
        recipeFail("LLVM toolchain build record has the wrong file name")
    }
    if (dockerfile.fileName.toString() != DOCKERFILE_FILE_NAME) {
        recipeFail("LLVM toolchain Dockerfile has the wrong file name")
    }
    if (lock.parent != record.parent || lock.parent != dockerfile.parent) {
        recipeFail("LLVM toolchain recipe inputs must share one authenticated directory")
    }
    return RecipePaths(lock, record, dockerfile)
}

private fun requireCanonicalRecipePath(path: Path, label: String): Path {
    if (
        path.fileSystem != FileSystems.getDefault() || !path.isAbsolute || path.normalize() != path ||
        path.fileName == null || path.parent == null
    ) {
        recipeFail("$label must be an absolute normalized default-filesystem file")
    }
    return path
}

private fun requireGuardCurrent(guard: StableControlFile, expectedSha256: String, label: String) {
    requireSingleLink(guard.path, label)
    if (guard.sha256(label = "$label terminal authentication") != expectedSha256) {
        recipeFail("$label bytes changed")
    }
    guard.verifyUnchanged(label)
    requireSingleLink(guard.path, label)
}

private fun requireSingleLink(path: Path, label: String) {
    val links = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedToolchainImageRecipeV1Exception("cannot authenticate $label link count", failure)
    }
    if (links != 1L) recipeFail("$label must be a single-link regular file")
}

private fun emitReviewedDockerfile(
    dockerfile: StableControlFile,
    expectedBytes: Long,
    expectedSha256: String,
    output: OutputStream,
): StreamEmission {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(DOCKERFILE_COPY_BUFFER_BYTES)
    var position = 0L
    while (position < expectedBytes) {
        val amount = minOf(buffer.size.toLong(), expectedBytes - position).toInt()
        val read = dockerfile.readAt(position, buffer, 0, amount)
        if (read <= 0) recipeFail("LLVM toolchain Dockerfile ended during emission")
        digest.update(buffer, 0, read)
        output.write(buffer, 0, read)
        position = Math.addExact(position, read.toLong())
    }
    val sha256 = digest.digest().toHex()
    if (position != expectedBytes || sha256 != expectedSha256) {
        recipeFail("emitted LLVM toolchain Dockerfile differs from the reviewed exact bytes")
    }
    return StreamEmission(position, sha256)
}

private fun emitDeterministicBuildContextTar(
    dockerfile: StableControlFile,
    expectedDockerfileBytes: Long,
    expectedDockerfileSha256: String,
    output: OutputStream,
): StreamEmission {
    val tar = HashingTarOutput(output)
    tar.writeHeader(
        name = TAR_DOCKERFILE_NAME,
        mode = TAR_READ_ONLY_MODE,
        size = expectedDockerfileBytes,
        modifiedSeconds = REVIEWED_SOURCE_DATE_EPOCH.toLong(),
    )
    emitReviewedDockerfile(
        dockerfile,
        expectedDockerfileBytes,
        expectedDockerfileSha256,
        tar,
    )
    tar.writeZeros(tarPadding(expectedDockerfileBytes))
    tar.writeZeros(TAR_BLOCK_BYTES * 2)
    return tar.finish()
}

private class HashingTarOutput(
    private val output: OutputStream,
) : OutputStream() {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var bytesWritten = 0L
    private var finished = false

    fun writeHeader(name: String, mode: Int, size: Long, modifiedSeconds: Long) {
        check(!finished) { "deterministic LLVM toolchain tar is already finished" }
        val header = ByteArray(TAR_BLOCK_BYTES)
        putTarAscii(header, 0, 100, name)
        putTarOctal(header, 100, 8, mode.toLong())
        putTarOctal(header, 108, 8, 0L)
        putTarOctal(header, 116, 8, 0L)
        putTarOctal(header, 124, 12, size)
        putTarOctal(header, 136, 12, modifiedSeconds)
        for (index in 148 until 156) header[index] = ' '.code.toByte()
        header[156] = TAR_REGULAR_FILE_TYPE
        putTarAscii(header, 257, 6, "ustar\u0000")
        putTarAscii(header, 263, 2, "00")
        val checksum = header.sumOf { byte -> byte.toInt() and 0xff }
        val checksumBytes = checksum.toString(8).padStart(6, '0').toByteArray(Charsets.US_ASCII)
        if (checksumBytes.size != 6) recipeFail("deterministic LLVM toolchain tar checksum overflowed")
        checksumBytes.copyInto(header, 148)
        header[154] = 0
        header[155] = ' '.code.toByte()
        write(header)
    }

    fun writeZeros(count: Int) {
        if (count > 0) write(ByteArray(count))
    }

    fun finish(): StreamEmission {
        check(!finished) { "deterministic LLVM toolchain tar is already finished" }
        finished = true
        return StreamEmission(bytesWritten, digest.digest().toHex())
    }

    override fun write(value: Int) {
        check(!finished) { "deterministic LLVM toolchain tar is already finished" }
        digest.update(value.toByte())
        output.write(value)
        bytesWritten = Math.addExact(bytesWritten, 1L)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        check(!finished) { "deterministic LLVM toolchain tar is already finished" }
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        digest.update(bytes, offset, length)
        output.write(bytes, offset, length)
        bytesWritten = Math.addExact(bytesWritten, length.toLong())
    }
}

private data class StreamEmission(
    val bytes: Long,
    val sha256: String,
)

private fun putTarAscii(target: ByteArray, offset: Int, length: Int, value: String) {
    val bytes = value.toByteArray(Charsets.US_ASCII)
    if (bytes.size > length) recipeFail("deterministic LLVM toolchain tar header field overflowed")
    bytes.copyInto(target, offset)
}

private fun putTarOctal(target: ByteArray, offset: Int, length: Int, value: Long) {
    if (value < 0L) recipeFail("deterministic LLVM toolchain tar contains a negative numeric field")
    val bytes = value.toString(8).padStart(length - 1, '0').toByteArray(Charsets.US_ASCII)
    if (bytes.size != length - 1) recipeFail("deterministic LLVM toolchain tar numeric field overflowed")
    bytes.copyInto(target, offset)
    target[offset + length - 1] = 0
}

private fun tarPadding(size: Long): Int =
    ((TAR_BLOCK_BYTES - (size % TAR_BLOCK_BYTES).toInt()) % TAR_BLOCK_BYTES)

private fun ByteArray.toHex(): String {
    val output = CharArray(size * 2)
    forEachIndexed { index, byte ->
        val value = byte.toInt() and 0xff
        output[index * 2] = HEX[value ushr 4]
        output[index * 2 + 1] = HEX[value and 0x0f]
    }
    return output.concatToString()
}

private fun requireExactSha256(actual: String, expected: String, label: String) {
    if (actual != expected) recipeFail("LLVM toolchain $label differs from the reviewed exact bytes")
}

private inline fun <T> translateRecipeFailure(label: String, action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedToolchainImageRecipeV1Exception) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorHostedToolchainImageRecipeV1Exception(
        "$label failed: ${failure.message ?: failure.javaClass.simpleName}",
        failure,
    )
}

private fun recipeFail(message: String): Nothing =
    throw LlvmBehaviorHostedToolchainImageRecipeV1Exception(message)

private const val REPRODUCTION_LOCK_FILE_NAME = "toolchain-reproduction.json"
private const val BUILD_RECORD_FILE_NAME = "build-record.json"
private const val DOCKERFILE_FILE_NAME = "build-toolchain.Dockerfile"
private const val REVIEWED_REPRODUCTION_LOCK_SHA256 =
    "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f"
private const val REVIEWED_BUILD_RECORD_SHA256 =
    "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val REVIEWED_DOCKERFILE_SHA256 =
    "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291"
private const val REVIEWED_BASE_IMAGE_REFERENCE =
    "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
private const val REVIEWED_PLATFORM = "linux/amd64"
private const val REVIEWED_SOURCE_DATE_EPOCH = "1779182222"
private const val MAXIMUM_REPRODUCTION_LOCK_BYTES = 1024L * 1024L
private const val MAXIMUM_BUILD_RECORD_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_DOCKERFILE_BYTES = 1024L * 1024L
private const val DOCKERFILE_COPY_BUFFER_BYTES = 512
private const val TAR_DOCKERFILE_NAME = "Dockerfile"
private const val TAR_BLOCK_BYTES = 512
private const val TAR_READ_ONLY_MODE = 292
private const val TAR_REGULAR_FILE_TYPE: Byte = 48
private const val HEX = "0123456789abcdef"

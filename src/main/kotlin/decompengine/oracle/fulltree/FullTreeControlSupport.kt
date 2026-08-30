package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.EnumSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeControlException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/**
 * Explicit implementation bounds for the Kotlin/JVM full-tree control plane.
 *
 * Archive-index and DWARF-metadata byte budgets charge exact UTF-8 payload bytes plus a fixed
 * per-record allowance. They bound attacker-controlled materialization but are not a JVM
 * resident-set guarantee; object-layout overhead and the cooperating process remain outside that
 * model. XZ decoder memory and on-disk DWARF scratch have independent enforced limits.
 */
data class FullTreeControlLimits(
    val maximumScopeBytes: Int = 1024 * 1024,
    val maximumSourceLockBytes: Int = 4 * 1024 * 1024,
    val maximumArtifactManifestBytes: Int = 32 * 1024 * 1024,
    val maximumBuildRecordBytes: Int = 4 * 1024 * 1024,
    val maximumInventoryBytes: Int = 32 * 1024 * 1024,
    val maximumSourceInventoryBytes: Int = 32 * 1024 * 1024,
    val maximumRichArtifactBytes: Long = 1024L * 1024L * 1024L,
    val maximumSourceArchiveBytes: Long = 512L * 1024L * 1024L,
    val maximumExpandedArchiveBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumArchiveMembers: Int = 200_000,
    val maximumArchiveMetadataBytes: Int = 1024 * 1024,
    val maximumArchivePathBytes: Int = 16 * 1024,
    val maximumArchiveIndexBytes: Long = 64L * 1024L * 1024L,
    val maximumXzDecoderMemoryKiB: Int = 256 * 1024,
    val maximumDwarfSectionBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDwarfScratchBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumDwarfMetadataBytes: Long = 256L * 1024L * 1024L,
    val maximumDwarfAttributeBytes: Int = 16 * 1024 * 1024,
    val maximumDwarfParseSteps: Long = 100_000_000L,
    val maximumCompilationUnits: Int = 1_000_000,
    val maximumAbbreviationDeclarationsPerUnit: Int = 100_000,
    val maximumAbbreviationAttributesPerUnit: Int = 10_000,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumScopeBytes in 1..64 * 1024 * 1024)
        require(maximumSourceLockBytes in 1..64 * 1024 * 1024)
        require(maximumArtifactManifestBytes in 1..64 * 1024 * 1024)
        require(maximumBuildRecordBytes in 1..64 * 1024 * 1024)
        require(maximumInventoryBytes in 1..64 * 1024 * 1024)
        require(maximumSourceInventoryBytes in 1..64 * 1024 * 1024)
        require(maximumRichArtifactBytes in 1L..1024L * 1024L * 1024L)
        require(maximumSourceArchiveBytes in 1L..512L * 1024L * 1024L)
        require(maximumExpandedArchiveBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumArchiveMembers in 1..1_000_000)
        require(maximumArchiveMetadataBytes in 1..16 * 1024 * 1024)
        require(maximumArchivePathBytes in 1..1024 * 1024)
        require(maximumArchiveIndexBytes in 1L..1024L * 1024L * 1024L)
        require(maximumXzDecoderMemoryKiB in 1..1024 * 1024)
        require(maximumDwarfSectionBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumDwarfScratchBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDwarfMetadataBytes in 1L..1024L * 1024L * 1024L)
        require(maximumDwarfAttributeBytes in 1..64 * 1024 * 1024)
        require(maximumDwarfParseSteps in 1L..1_000_000_000L)
        require(maximumCompilationUnits in 1..1_000_000)
        require(maximumAbbreviationDeclarationsPerUnit in 1..1_000_000)
        require(maximumAbbreviationAttributesPerUnit in 1..100_000)
        require(maximumWorkers in 1..32)
    }
}

internal val FULL_TREE_CODE_POINT_ORDER: Comparator<String> = Comparator { left, right ->
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftPoint = Character.codePointAt(left, leftOffset)
        val rightPoint = Character.codePointAt(right, rightOffset)
        if (leftPoint != rightPoint) return@Comparator leftPoint.compareTo(rightPoint)
        leftOffset += Character.charCount(leftPoint)
        rightOffset += Character.charCount(rightPoint)
    }
    (left.length - leftOffset).compareTo(right.length - rightOffset)
}

internal fun readCanonicalControlObject(
    path: Path,
    maximumBytes: Int,
    label: String,
    schemaName: String? = null,
): Pair<JsonObject, ByteArray> {
    val bytes = try {
        OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes)).bytes
    } catch (failure: Exception) {
        throw FullTreeControlException("cannot read authenticated $label", failure)
    }
    if (bytes.isEmpty()) throw FullTreeControlException("$label must not be empty")
    val document = try {
        OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as? JsonObject
            ?: throw FullTreeControlException("$label root must be an object")
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is not strict canonical JSON", failure)
    }
    if (schemaName != null) {
        try {
            OracleSchemas.validate(schemaName, document)
        } catch (failure: Exception) {
            throw FullTreeControlException("$label fails its bundled schema", failure)
        }
    }
    return document to bytes
}

internal fun snapshotControlObject(
    value: JsonObject,
    maximumBytes: Int,
    label: String,
    schemaName: String? = null,
): Pair<JsonObject, ByteArray> {
    val bytes = try {
        OracleJson.canonicalBytes(value, controlJsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("$label exceeds strict JSON limits", failure)
    }
    val snapshot = try {
        OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as JsonObject
    } catch (failure: Exception) {
        throw FullTreeControlException("$label cannot be snapshotted as strict canonical JSON", failure)
    }
    if (schemaName != null) {
        try {
            OracleSchemas.validate(schemaName, snapshot)
        } catch (failure: Exception) {
            throw FullTreeControlException("$label fails its bundled schema", failure)
        }
    }
    return snapshot to bytes
}

internal fun controlJsonLimits(maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
    maximumTotalStringBytes = maximumBytes,
)

internal fun publishCanonicalControl(
    path: Path,
    document: JsonObject,
    maximumBytes: Int,
): ByteArray {
    val bytes = try {
        OracleJson.canonicalBytes(document, controlJsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("control-plane output exceeds its canonical byte limit", failure)
    }
    try {
        OracleArtifacts.publishAtomically(path, bytes, OracleArtifactLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("cannot atomically publish control-plane output", failure)
    }
    return bytes
}

internal fun requireDistinctControlOutput(
    output: Path,
    vararg inputs: Pair<String, Path>,
) {
    val normalizedOutput = output.toAbsolutePath().normalize()
    inputs.forEach { (label, input) ->
        if (normalizedOutput == input.toAbsolutePath().normalize()) {
            throw FullTreeControlException("control-plane output must not replace its $label input")
        }
    }
}

/**
 * Stable bounded access to a large authenticated input.
 *
 * Java NIO cannot bind an open channel back to its pathname, so the regular-file owner and its
 * non-group-writable immediate directory owner remain cooperating trust principals. Other
 * principals cannot write the accepted file or directory.
 */
internal class StableControlFile private constructor(
    val path: Path,
    val size: Long,
    private val maximumBytes: Long,
    private val before: BasicFileAttributes,
    private val permissions: Set<PosixFilePermission>,
    private val channel: FileChannel,
) : AutoCloseable {
    fun sha256(
        checkpoint: (String) -> Unit = {},
        label: String = "large control input",
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteBuffer.allocate(1024 * 1024)
        var offset = 0L
        while (offset < size) {
            buffer.clear()
            buffer.limit(minOf(buffer.capacity().toLong(), size - offset).toInt())
            val read = channel.read(buffer, offset)
            if (read <= 0) throw FullTreeControlException("large control input ended while hashing")
            digest.update(buffer.array(), 0, read)
            offset = Math.addExact(offset, read.toLong())
            checkpoint("while hashing $label")
        }
        checkpoint("after hashing $label")
        return digest.digest().hex()
    }

    fun readExactly(offset: Long, length: Int, label: String): ByteArray {
        if (offset < 0L || length < 0 || offset > size - length.toLong()) {
            throw FullTreeControlException("$label range exceeds its authenticated input")
        }
        val result = ByteArray(length)
        val buffer = ByteBuffer.wrap(result)
        var position = offset
        while (buffer.hasRemaining()) {
            val read = channel.read(buffer, position)
            if (read <= 0) throw FullTreeControlException("$label ended during a bounded read")
            position = Math.addExact(position, read.toLong())
        }
        return result
    }

    fun slice(offset: Long = 0L, length: Long = size): InputStream {
        if (offset < 0L || length < 0L || offset > size - length) {
            throw FullTreeControlException("large control input slice exceeds its authenticated file")
        }
        return object : InputStream() {
            private var position = offset
            private var remaining = length

            override fun read(): Int {
                val single = ByteArray(1)
                return if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 0xff
            }

            override fun read(bytes: ByteArray, offsetInArray: Int, lengthInArray: Int): Int {
                if (offsetInArray < 0 || lengthInArray < 0 || offsetInArray > bytes.size - lengthInArray) {
                    throw IndexOutOfBoundsException()
                }
                if (lengthInArray == 0) return 0
                if (remaining == 0L) return -1
                val requested = minOf(lengthInArray.toLong(), remaining).toInt()
                val destination = ByteBuffer.wrap(bytes, offsetInArray, requested)
                val read = channel.read(destination, position)
                if (read <= 0) throw FullTreeControlException("large control input ended during streaming")
                position = Math.addExact(position, read.toLong())
                remaining -= read.toLong()
                return read
            }
        }
    }

    fun verifyUnchanged(label: String) {
        val after = stableRegularAttributes(path, label)
        val afterPermissions = stablePermissions(path, label)
        if (
            before.fileKey() != after.fileKey() || before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime() || permissions != afterPermissions ||
            after.size() !in 1L..maximumBytes
        ) {
            throw FullTreeControlException("$label changed identity, metadata, or permissions during use")
        }
    }

    override fun close() = channel.close()

    companion object {
        fun open(path: Path, maximumBytes: Long, label: String): StableControlFile {
            val normalized = path.toAbsolutePath().normalize()
            if (normalized.fileName == null || normalized.parent == null) {
                throw FullTreeControlException("$label must name a file")
            }
            requireStableDirectory(normalized.parent, "$label parent")
            val real = try {
                normalized.toRealPath()
            } catch (failure: Exception) {
                throw FullTreeControlException("$label is unavailable", failure)
            }
            if (real != normalized) throw FullTreeControlException("$label path contains a symbolic link")
            val before = stableRegularAttributes(normalized, label)
            if (before.size() !in 1L..maximumBytes) {
                throw FullTreeControlException("$label must contain 1..$maximumBytes bytes")
            }
            val permissions = stablePermissions(normalized, label)
            val channel = try {
                FileChannel.open(normalized, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
            } catch (failure: Exception) {
                throw FullTreeControlException("cannot open $label", failure)
            }
            return StableControlFile(normalized, before.size(), maximumBytes, before, permissions, channel)
        }
    }
}

internal fun requireStableDirectory(path: Path, label: String): Pair<Path, Any> {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = try {
        Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        throw FullTreeControlException("$label must be an identified real directory")
    }
    if (normalized.toRealPath() != normalized) throw FullTreeControlException("$label path contains a symbolic link")
    val permissions = Files.getFileAttributeView(
        normalized,
        PosixFileAttributeView::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )?.readAttributes()?.permissions()
        ?: throw FullTreeControlException("$label requires POSIX permissions")
    if (permissions.any { it in UNTRUSTED_CONTROL_WRITE_PERMISSIONS }) {
        throw FullTreeControlException("$label is writable by an untrusted principal")
    }
    return normalized to attributes.fileKey()
}

private fun stableRegularAttributes(path: Path, label: String): BasicFileAttributes {
    val attributes = try {
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw FullTreeControlException("$label attributes are unavailable", failure)
    }
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        throw FullTreeControlException("$label must be an identified regular file")
    }
    return attributes
}

private fun stablePermissions(path: Path, label: String): Set<PosixFilePermission> {
    val permissions = Files.getFileAttributeView(
        path,
        PosixFileAttributeView::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )?.readAttributes()?.permissions()
        ?: throw FullTreeControlException("$label requires POSIX permissions")
    if (permissions.any { it in UNTRUSTED_CONTROL_WRITE_PERMISSIONS }) {
        throw FullTreeControlException("$label is writable by an untrusted principal")
    }
    return HashSet(permissions)
}

internal fun JsonObject.controlObject(name: String): JsonObject = this[name] as? JsonObject
    ?: throw FullTreeControlException("control document field $name is not an object")

internal fun JsonObject.controlArray(name: String): JsonArray = this[name] as? JsonArray
    ?: throw FullTreeControlException("control document field $name is not an array")

internal fun JsonObject.controlString(name: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("control document field $name is not a string")
    if (!primitive.isString) throw FullTreeControlException("control document field $name is not a string")
    return primitive.content
}

internal fun JsonObject.controlLong(name: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("control document field $name is not an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        throw FullTreeControlException("control document field $name is not an integer")
    }
    return primitive.content.toLongOrNull()
        ?: throw FullTreeControlException("control document field $name exceeds the supported integer range")
}

internal fun JsonArray.controlObjects(label: String): List<JsonObject> = map { value ->
    value as? JsonObject ?: throw FullTreeControlException("$label contains a non-object")
}

internal fun JsonElement.controlString(label: String): String {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeControlException("$label is not a string")
    if (!primitive.isString) throw FullTreeControlException("$label is not a string")
    return primitive.content
}

internal fun requireControlDigest(value: String, label: String) {
    if (!value.matches(CONTROL_SHA256)) throw FullTreeControlException("$label digest is invalid")
}

internal fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private val CONTROL_SHA256 = Regex("[0-9a-f]{64}")
private val UNTRUSTED_CONTROL_WRITE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.GROUP_WRITE,
    PosixFilePermission.OTHERS_WRITE,
)

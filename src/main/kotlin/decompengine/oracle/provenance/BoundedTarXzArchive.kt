package decompengine.oracle.provenance

import java.io.FilterInputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.tukaani.xz.SeekableInputStream
import org.tukaani.xz.SeekableXZInputStream
import org.tukaani.xz.XZ

internal class BoundedTarXzException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Descriptor-agnostic positional access to one already authenticated regular file. */
internal interface BoundedTarXzSource {
    val size: Long

    /** Returns `-1` only at exact end of input. */
    fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int
}

internal data class BoundedTarXzLimits(
    val maximumCompressedBytes: Long = 512L * 1024L * 1024L,
    val maximumExpandedBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumDecoderMemoryKiB: Int = 256 * 1024,
    val maximumMembers: Int = 200_000,
    val maximumMetadataBytes: Int = 1024 * 1024,
    val maximumEntryBytes: Long = 512L * 1024L * 1024L,
    val maximumPathBytes: Int = 4096,
    val maximumComponentBytes: Int = 255,
    val maximumLinkBytes: Int = 255,
    val maximumIndexBytes: Long = 64L * 1024L * 1024L,
    val maximumSelectedBytes: Int = 1024 * 1024,
) {
    init {
        require(maximumCompressedBytes in 1L..512L * 1024L * 1024L)
        require(maximumExpandedBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumDecoderMemoryKiB in 1..256 * 1024)
        require(maximumMembers in 1..200_000)
        require(maximumMetadataBytes in 1..1024 * 1024)
        require(maximumEntryBytes in 1L..512L * 1024L * 1024L)
        require(maximumPathBytes in 1..4096)
        require(maximumComponentBytes in 1..255)
        require(maximumLinkBytes in 1..255)
        require(maximumIndexBytes in 1L..64L * 1024L * 1024L)
        require(maximumSelectedBytes in 0..1024 * 1024)
    }
}

internal enum class BoundedTarEntryKind {
    REGULAR,
    DIRECTORY,
    SYMBOLIC_LINK,
}

internal data class BoundedTarEntry(
    val path: String,
    val relativePath: String,
    val kind: BoundedTarEntryKind,
    val size: Long,
    val mode: Int,
    val linkTarget: String?,
)

internal data class SelectedTarEntry(
    val path: String,
    val bytes: ByteArray,
    val sha256: String,
)

internal data class BoundedTarXzSummary(
    val expandedBytes: Long,
    val memberCount: Int,
    val regularFileCount: Int,
    val directoryCount: Int,
    val symbolicLinkCount: Int,
    val selected: Map<String, SelectedTarEntry>,
)

/** Synchronous bounded access to regular-file payloads selected while the strict archive is scanned. */
internal interface BoundedTarXzRegularFileVisitor {
    fun wants(entry: BoundedTarEntry): Boolean

    /**
     * [bytes] remains owned by the scanner and may be reused after this call. Consumers must not
     * mutate it and must copy only the [length] bytes they retain.
     */
    fun onChunk(entry: BoundedTarEntry, bytes: ByteArray, length: Int, endOfEntry: Boolean)
}

/** Strict, bounded reader for the reviewed LLVM release's single-stream USTAR profile. */
internal object BoundedTarXzArchive {
    fun scan(
        source: BoundedTarXzSource,
        expectedRoot: String,
        expectedCommit: String,
        limits: BoundedTarXzLimits = BoundedTarXzLimits(),
        selectedRegularPaths: Set<String> = emptySet(),
        regularFileVisitor: BoundedTarXzRegularFileVisitor? = null,
        onEntry: (BoundedTarEntry) -> Unit = {},
    ): BoundedTarXzSummary {
        requireCanonicalRoot(expectedRoot, limits)
        if (!expectedCommit.matches(GIT_OBJECT)) archiveFail("expected archive commit is invalid")
        if (source.size !in 1L..limits.maximumCompressedBytes) {
            archiveFail("source archive exceeds its compressed-byte bound")
        }
        selectedRegularPaths.forEach { selected ->
            val canonical = canonicalMemberPath(selected, isDirectory = false, expectedRoot, limits)
            if (canonical.path != selected || canonical.parts.size < 2) {
                archiveFail("selected archive path is not canonical")
            }
        }
        requireNoXzStreamPadding(source)

        val seekableSource = PositionalSeekableInput(source)
        val xz = try {
            SeekableXZInputStream(seekableSource, limits.maximumDecoderMemoryKiB)
        } catch (failure: Exception) {
            throw BoundedTarXzException("cannot inspect the bounded XZ container", failure)
        }
        try {
            if (xz.streamCount != 1) archiveFail("source archive must contain exactly one XZ stream")
            val expectedChecks = 1 shl XZ.CHECK_CRC64
            if (xz.checkTypes != expectedChecks) archiveFail("source archive XZ stream must use only CRC64")
            if (xz.length() !in 1L..limits.maximumExpandedBytes) {
                archiveFail("source archive exceeds its expanded-byte bound")
            }
            xz.seek(0L)
            return scanTar(
                ExpandedArchiveInputStream(xz, limits.maximumExpandedBytes),
                expectedRoot,
                expectedCommit,
                limits,
                selectedRegularPaths,
                onEntry,
                regularFileVisitor,
            )
        } catch (failure: BoundedTarXzException) {
            throw failure
        } catch (failure: Exception) {
            throw BoundedTarXzException("cannot decode the bounded source tar.xz archive", failure)
        } finally {
            try {
                xz.close(false)
            } catch (_: Exception) {
                // The authenticated source owner closes its descriptor; this adapter owns no resource.
            }
        }
    }

    private fun scanTar(
        input: ExpandedArchiveInputStream,
        expectedRoot: String,
        expectedCommit: String,
        limits: BoundedTarXzLimits,
        selectedRegularPaths: Set<String>,
        onEntry: (BoundedTarEntry) -> Unit,
        regularFileVisitor: BoundedTarXzRegularFileVisitor?,
    ): BoundedTarXzSummary {
        val expectedPax = "52 comment=$expectedCommit\n".toByteArray(StandardCharsets.US_ASCII)
        check(expectedPax.size == 52)
        val entries = LinkedHashMap<String, ArchiveEntryState>()
        val selected = linkedMapOf<String, SelectedTarEntry>()
        var selectedBytes = 0L
        var indexedBytes = 0L
        var members = 0
        var regularFiles = 0
        var directories = 0
        var symbolicLinks = 0

        val paxHeader = input.readBlockOrNull(TAR_BLOCK_BYTES)
            ?: archiveFail("source archive is missing its global PAX header")
        if (paxHeader.all { it == 0.toByte() }) archiveFail("source archive is missing its global PAX header")
        validateHeaderEnvelope(paxHeader)
        val paxType = paxHeader[TYPE_OFFSET].toInt() and 0xff
        val paxName = tarPath(paxHeader)
        val paxSize = tarNumber(paxHeader, SIZE_OFFSET, SIZE_LENGTH, "global PAX size")
        val paxMode = tarNumber(paxHeader, MODE_OFFSET, MODE_LENGTH, "global PAX mode")
        val paxLink = tarTextField(paxHeader, LINK_NAME_OFFSET, LINK_NAME_LENGTH, "global PAX link target")
        if (paxType != GLOBAL_PAX_TYPE || paxName != GLOBAL_PAX_NAME ||
            paxSize != expectedPax.size.toLong() || paxMode != GLOBAL_PAX_MODE || paxLink.isNotEmpty()
        ) {
            archiveFail("source archive has an unexpected initial global PAX header")
        }
        addBounded(0L, paxSize, limits.maximumMetadataBytes.toLong(), "metadata")
        val paxPayload = input.readPayload(paxSize, limits.maximumMetadataBytes)
        if (!paxPayload.contentEquals(expectedPax)) archiveFail("source archive global PAX comment differs")
        input.skipPadding(paxSize)

        var terminated = false
        while (!terminated) {
            val header = input.readBlockOrNull(TAR_BLOCK_BYTES)
                ?: archiveFail("source archive tar stream is unterminated")
            if (header.all { it == 0.toByte() }) {
                var terminatorBlocks = 1
                val second = input.readBlockOrNull(TAR_BLOCK_BYTES)
                    ?: archiveFail("source archive tar terminator is truncated")
                if (second.any { it != 0.toByte() }) archiveFail("source archive tar terminator is malformed")
                terminatorBlocks++
                while (true) {
                    val tail = input.readBlockOrNull(TAR_BLOCK_BYTES) ?: break
                    if (tail.any { it != 0.toByte() }) {
                        archiveFail("source archive has nonzero data after its tar terminator")
                    }
                    terminatorBlocks++
                }
                if (terminatorBlocks !in MINIMUM_TERMINATOR_BLOCKS..MAXIMUM_TERMINATOR_RECORD_BLOCKS ||
                    input.consumed % TAR_RECORD_BYTES != 0L
                ) {
                    archiveFail("source archive tar terminator does not have canonical record padding")
                }
                terminated = true
                continue
            }

            validateHeaderEnvelope(header)
            val rawType = header[TYPE_OFFSET].toInt() and 0xff
            val kind = when (rawType) {
                REGULAR_TYPE -> BoundedTarEntryKind.REGULAR
                DIRECTORY_TYPE -> BoundedTarEntryKind.DIRECTORY
                SYMBOLIC_LINK_TYPE -> BoundedTarEntryKind.SYMBOLIC_LINK
                else -> archiveFail("source archive contains unsupported member type 0x${rawType.toString(16)}")
            }
            members = Math.addExact(members, 1)
            if (members > limits.maximumMembers) archiveFail("source archive exceeds its member bound")

            val rawPath = tarPath(header)
            val canonical = canonicalMemberPath(
                rawPath,
                isDirectory = kind == BoundedTarEntryKind.DIRECTORY,
                expectedRoot,
                limits,
            )
            val size = tarNumber(header, SIZE_OFFSET, SIZE_LENGTH, "tar member size")
            if (size > limits.maximumEntryBytes) archiveFail("source archive member exceeds its byte bound")
            if (kind != BoundedTarEntryKind.REGULAR && size != 0L) {
                archiveFail("source archive non-regular member has a payload")
            }
            val mode = tarNumber(header, MODE_OFFSET, MODE_LENGTH, "tar member mode")
            val validMode = when (kind) {
                BoundedTarEntryKind.REGULAR -> mode == REGULAR_MODE || mode == EXECUTABLE_MODE
                BoundedTarEntryKind.DIRECTORY -> mode == DIRECTORY_MODE
                BoundedTarEntryKind.SYMBOLIC_LINK -> mode == SYMBOLIC_LINK_MODE
            }
            if (!validMode) archiveFail("source archive member mode differs from its Git-archive type profile")

            if (entries.containsKey(canonical.path)) archiveFail("source archive duplicates ${canonical.path}")
            if (members == 1) {
                if (kind != BoundedTarEntryKind.DIRECTORY || canonical.path != expectedRoot) {
                    archiveFail("source archive root must be its first logical directory")
                }
            } else {
                if (canonical.parts.size < 2) archiveFail("source archive repeats or escapes its root")
                val parent = canonical.parts.dropLast(1).joinToString("/")
                if (entries[parent]?.kind != BoundedTarEntryKind.DIRECTORY) {
                    archiveFail("source archive member parent is absent or not a directory: ${canonical.path}")
                }
            }

            val rawLink = tarTextField(header, LINK_NAME_OFFSET, LINK_NAME_LENGTH, "tar link target")
            val resolvedLink = when (kind) {
                BoundedTarEntryKind.SYMBOLIC_LINK -> {
                    if (rawLink.isEmpty()) archiveFail("source archive symbolic link has no target")
                    resolveLink(canonical.parts, rawLink, expectedRoot, limits)
                }
                else -> {
                    if (rawLink.isNotEmpty()) archiveFail("source archive non-link member has a link target")
                    null
                }
            }
            indexedBytes = addBounded(
                indexedBytes,
                canonical.path.toByteArray(StandardCharsets.US_ASCII).size.toLong() +
                    (rawLink.toByteArray(StandardCharsets.US_ASCII).size.toLong()) + INDEX_ENTRY_OVERHEAD_BYTES,
                limits.maximumIndexBytes,
                "index",
            )
            entries[canonical.path] = ArchiveEntryState(kind, resolvedLink)
            val entry = BoundedTarEntry(
                path = canonical.path,
                relativePath = canonical.parts.drop(1).joinToString("/"),
                kind = kind,
                size = size,
                mode = mode.toInt(),
                linkTarget = rawLink.ifEmpty { null },
            )
            onEntry(entry)

            when (kind) {
                BoundedTarEntryKind.REGULAR -> {
                    regularFiles++
                    val visitor = regularFileVisitor?.takeIf { it.wants(entry) }
                    if (canonical.path in selectedRegularPaths) {
                        selectedBytes = addBounded(
                            selectedBytes,
                            size,
                            limits.maximumSelectedBytes.toLong(),
                            "selected-content",
                        )
                        val bytes = input.readPayload(size, limits.maximumSelectedBytes)
                        selected[canonical.path] = SelectedTarEntry(
                            canonical.path,
                            bytes,
                            MessageDigest.getInstance("SHA-256").digest(bytes).hex(),
                        )
                        // Keep the selected snapshot and its recorded digest isolated from a
                        // hostile callback even though callbacks are contractually read-only.
                        visitor?.onChunk(entry, bytes.copyOf(), bytes.size, true)
                    } else if (visitor != null) {
                        input.visitPayload(size) { bytes, length, endOfEntry ->
                            visitor.onChunk(entry, bytes, length, endOfEntry)
                        }
                    } else {
                        input.skipPayload(size)
                    }
                }
                BoundedTarEntryKind.DIRECTORY -> directories++
                BoundedTarEntryKind.SYMBOLIC_LINK -> symbolicLinks++
            }
            input.skipPadding(size)
        }
        if (entries[expectedRoot]?.kind != BoundedTarEntryKind.DIRECTORY) {
            archiveFail("source archive root directory is absent")
        }
        validateLinks(entries, expectedRoot)
        if (selected.keys != selectedRegularPaths) {
            archiveFail("source archive is missing selected regular files")
        }
        return BoundedTarXzSummary(
            expandedBytes = input.consumed,
            memberCount = members,
            regularFileCount = regularFiles,
            directoryCount = directories,
            symbolicLinkCount = symbolicLinks,
            selected = selected.toMap(),
        )
    }

    private fun validateHeaderEnvelope(header: ByteArray) {
        validateTarChecksum(header)
        if (!header.copyOfRange(MAGIC_OFFSET, MAGIC_OFFSET + MAGIC.size).contentEquals(MAGIC) ||
            !header.copyOfRange(VERSION_OFFSET, VERSION_OFFSET + VERSION.size).contentEquals(VERSION)
        ) {
            archiveFail("source archive member is not canonical USTAR")
        }
        if (header.copyOfRange(USTAR_RESERVED_OFFSET, TAR_BLOCK_BYTES).any { it != 0.toByte() }) {
            archiveFail("source archive USTAR header has nonzero reserved bytes")
        }
        val uid = tarNumber(header, UID_OFFSET, UID_LENGTH, "tar member uid")
        val gid = tarNumber(header, GID_OFFSET, GID_LENGTH, "tar member gid")
        if (uid != 0L || gid != 0L) archiveFail("source archive member ownership is not normalized")
        tarNumber(header, MTIME_OFFSET, MTIME_LENGTH, "tar member modification time")
        val user = tarTextField(header, USER_NAME_OFFSET, USER_GROUP_NAME_LENGTH, "tar user name")
        val group = tarTextField(header, GROUP_NAME_OFFSET, USER_GROUP_NAME_LENGTH, "tar group name")
        if (user != ROOT_OWNER || group != ROOT_OWNER) {
            archiveFail("source archive member owner names are not normalized")
        }
        val deviceMajor = tarNumber(header, DEVICE_MAJOR_OFFSET, DEVICE_NUMBER_LENGTH, "tar device major")
        val deviceMinor = tarNumber(header, DEVICE_MINOR_OFFSET, DEVICE_NUMBER_LENGTH, "tar device minor")
        if (deviceMajor != 0L || deviceMinor != 0L) archiveFail("source archive member has device metadata")
    }

    private fun validateTarChecksum(header: ByteArray) {
        val expected = tarNumber(header, CHECKSUM_OFFSET, CHECKSUM_LENGTH, "tar checksum")
        var actual = 0L
        header.indices.forEach { index ->
            actual += if (index in CHECKSUM_OFFSET until CHECKSUM_OFFSET + CHECKSUM_LENGTH) {
                0x20
            } else {
                header[index].toInt() and 0xff
            }
        }
        if (actual != expected) archiveFail("source archive tar checksum differs")
    }

    private fun tarPath(header: ByteArray): String {
        val name = tarTextField(header, NAME_OFFSET, NAME_LENGTH, "tar member name")
        val prefix = tarTextField(header, PREFIX_OFFSET, PREFIX_LENGTH, "tar member prefix")
        if (name.isEmpty()) archiveFail("tar member name is empty")
        if (prefix.isEmpty()) return name
        val path = "$prefix/$name"
        if (path.toByteArray(StandardCharsets.US_ASCII).size <= NAME_LENGTH) {
            archiveFail("tar member path uses a noncanonical USTAR prefix")
        }
        val separator = path.indices.reversed().firstOrNull { index ->
            index != path.lastIndex && path[index] == '/' &&
                path.substring(0, index).toByteArray(StandardCharsets.US_ASCII).size <= PREFIX_LENGTH &&
                path.substring(index + 1).toByteArray(StandardCharsets.US_ASCII).size <= NAME_LENGTH
        } ?: archiveFail("tar member path does not fit canonical USTAR fields")
        if (path.substring(0, separator) != prefix || path.substring(separator + 1) != name) {
            archiveFail("tar member path has a noncanonical USTAR split")
        }
        return path
    }

    private fun tarTextField(header: ByteArray, offset: Int, length: Int, label: String): String {
        var end = offset + length
        for (index in offset until offset + length) {
            val byte = header[index].toInt() and 0xff
            if (byte == 0) {
                end = index
                if ((index + 1 until offset + length).any { header[it] != 0.toByte() }) {
                    archiveFail("$label has nonzero bytes after its terminator")
                }
                break
            }
            if (byte !in PRINTABLE_ASCII) archiveFail("$label is not printable ASCII")
        }
        return header.copyOfRange(offset, end).toString(StandardCharsets.US_ASCII)
    }

    private fun tarNumber(header: ByteArray, offset: Int, length: Int, label: String): Long {
        val bytes = header.copyOfRange(offset, offset + length)
        if (bytes.first().toInt() and 0x80 != 0) archiveFail("$label uses unsupported base-256 encoding")
        if (bytes.last() != 0.toByte() || bytes.dropLast(1).any { it.toInt().toChar() !in '0'..'7' }) {
            archiveFail("$label is not fixed-width canonical octal")
        }
        return bytes.copyOfRange(0, bytes.lastIndex).toString(StandardCharsets.US_ASCII).toLongOrNull(8)
            ?: archiveFail("$label overflows")
    }

    private fun canonicalMemberPath(
        rawPath: String,
        isDirectory: Boolean,
        expectedRoot: String,
        limits: BoundedTarXzLimits,
    ): CanonicalPath {
        val encoded = rawPath.toByteArray(StandardCharsets.US_ASCII)
        if (rawPath.isEmpty() || encoded.size > limits.maximumPathBytes ||
            rawPath.any { it.code !in PRINTABLE_ASCII } || '\\' in rawPath || rawPath.startsWith('/')
        ) {
            archiveFail("source archive contains an unsafe or overlong path")
        }
        val normalized = if (isDirectory) {
            if (!rawPath.endsWith('/') || rawPath.endsWith("//")) {
                archiveFail("source archive directory path is not canonical")
            }
            rawPath.dropLast(1)
        } else {
            if (rawPath.endsWith('/')) archiveFail("source archive non-directory path ends with a slash")
            rawPath
        }
        if (normalized.isEmpty() || "//" in normalized) archiveFail("source archive path has an empty component")
        val parts = normalized.split('/')
        if (parts.any { component ->
                component.isEmpty() || component == "." || component == ".." ||
                    component.toByteArray(StandardCharsets.US_ASCII).size > limits.maximumComponentBytes
            }
        ) {
            archiveFail("source archive path has an unsafe or overlong component")
        }
        if (parts.first() != expectedRoot) archiveFail("source archive path is outside its locked root")
        return CanonicalPath(normalized, parts)
    }

    private fun requireCanonicalRoot(root: String, limits: BoundedTarXzLimits) {
        if (root.contains('/') || root.contains('\\') || root.isEmpty() ||
            root.any { it.code !in PRINTABLE_ASCII } || root in setOf(".", "..") ||
            root.toByteArray(StandardCharsets.US_ASCII).size > minOf(limits.maximumPathBytes, limits.maximumComponentBytes)
        ) {
            archiveFail("expected archive root is not canonical")
        }
    }

    private fun resolveLink(
        linkParts: List<String>,
        rawTarget: String,
        expectedRoot: String,
        limits: BoundedTarXzLimits,
    ): String {
        val encoded = rawTarget.toByteArray(StandardCharsets.US_ASCII)
        if (rawTarget.isEmpty() || encoded.size > limits.maximumLinkBytes || rawTarget.startsWith('/') ||
            rawTarget.endsWith('/') || "//" in rawTarget || '\\' in rawTarget ||
            rawTarget.any { it.code !in PRINTABLE_ASCII }
        ) {
            archiveFail("source archive symbolic link target is unsafe or overlong")
        }
        val targetParts = rawTarget.split('/')
        if (targetParts.any { it.isEmpty() || it == "." || it.toByteArray(StandardCharsets.US_ASCII).size > limits.maximumComponentBytes }) {
            archiveFail("source archive symbolic link target has an unsafe component")
        }
        val resolved = linkParts.dropLast(1).toMutableList()
        targetParts.forEach { component ->
            if (component == "..") {
                if (resolved.size <= 1) archiveFail("source archive symbolic link escapes its root")
                resolved.removeLast()
            } else {
                resolved += component
            }
        }
        if (resolved.firstOrNull() != expectedRoot) archiveFail("source archive symbolic link escapes its root")
        return resolved.joinToString("/")
    }

    private fun validateLinks(entries: Map<String, ArchiveEntryState>, expectedRoot: String) {
        val completed = HashSet<String>()
        entries.filterValues { it.kind == BoundedTarEntryKind.SYMBOLIC_LINK }.forEach { (path, _) ->
            if (path in completed) return@forEach
            var current = path
            val chain = ArrayList<String>()
            val active = HashSet<String>()
            while (true) {
                if (current in completed) break
                if (!active.add(current)) archiveFail("source archive contains a symbolic-link cycle")
                val state = entries[current] ?: archiveFail("source archive contains a dangling symbolic link")
                if (state.kind != BoundedTarEntryKind.SYMBOLIC_LINK) break
                chain += current
                val target = state.resolvedLink ?: archiveFail("source archive symbolic link has no resolved target")
                requireDirectoryPrefixes(target, entries, expectedRoot)
                current = target
            }
            completed += chain
        }
    }

    private fun requireDirectoryPrefixes(
        path: String,
        entries: Map<String, ArchiveEntryState>,
        expectedRoot: String,
    ) {
        val parts = path.split('/')
        if (parts.firstOrNull() != expectedRoot) archiveFail("source archive symbolic link escapes its root")
        val prefix = StringBuilder(parts.first())
        for (end in 1 until parts.size) {
            if (entries[prefix.toString()]?.kind != BoundedTarEntryKind.DIRECTORY) {
                archiveFail("source archive symbolic link traverses a non-directory")
            }
            prefix.append('/').append(parts[end])
        }
    }

    private fun requireNoXzStreamPadding(source: BoundedTarXzSource) {
        if (source.size < XZ_STREAM_FOOTER_BYTES) archiveFail("source archive is too short to contain an XZ stream")
        val suffix = ByteArray(2)
        readExactly(source, source.size - suffix.size, suffix, 0, suffix.size)
        if (!suffix.contentEquals(XZ_FOOTER_MAGIC)) {
            archiveFail("source archive has XZ stream padding or trailing data")
        }
    }

    private fun readExactly(
        source: BoundedTarXzSource,
        position: Long,
        destination: ByteArray,
        offset: Int,
        length: Int,
    ) {
        var cursor = position
        var written = offset
        while (written < offset + length) {
            val read = source.read(cursor, destination, written, offset + length - written)
            if (read <= 0) archiveFail("source archive ended during a positional read")
            cursor = Math.addExact(cursor, read.toLong())
            written += read
        }
    }

    private fun addBounded(current: Long, added: Long, maximum: Long, label: String): Long {
        val result = try {
            Math.addExact(current, added)
        } catch (failure: ArithmeticException) {
            throw BoundedTarXzException("source archive $label byte count overflows", failure)
        }
        if (result > maximum) archiveFail("source archive exceeds its $label byte bound")
        return result
    }

    private data class ArchiveEntryState(
        val kind: BoundedTarEntryKind,
        val resolvedLink: String?,
    )

    private data class CanonicalPath(val path: String, val parts: List<String>)

    private val GIT_OBJECT = Regex("[0-9a-f]{40}")
    private val MAGIC = byteArrayOf('u'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), 'a'.code.toByte(), 'r'.code.toByte(), 0)
    private val VERSION = byteArrayOf('0'.code.toByte(), '0'.code.toByte())
    private val XZ_FOOTER_MAGIC = byteArrayOf('Y'.code.toByte(), 'Z'.code.toByte())
    private val PRINTABLE_ASCII = 0x20..0x7e
    private const val TAR_BLOCK_BYTES = 512
    private const val TAR_RECORD_BYTES = 20L * TAR_BLOCK_BYTES
    private const val MINIMUM_TERMINATOR_BLOCKS = 2
    private const val MAXIMUM_TERMINATOR_RECORD_BLOCKS = 21
    private const val XZ_STREAM_FOOTER_BYTES = 12
    private const val INDEX_ENTRY_OVERHEAD_BYTES = 64L
    private const val NAME_OFFSET = 0
    private const val NAME_LENGTH = 100
    private const val MODE_OFFSET = 100
    private const val MODE_LENGTH = 8
    private const val UID_OFFSET = 108
    private const val UID_LENGTH = 8
    private const val GID_OFFSET = 116
    private const val GID_LENGTH = 8
    private const val SIZE_OFFSET = 124
    private const val SIZE_LENGTH = 12
    private const val MTIME_OFFSET = 136
    private const val MTIME_LENGTH = 12
    private const val CHECKSUM_OFFSET = 148
    private const val CHECKSUM_LENGTH = 8
    private const val TYPE_OFFSET = 156
    private const val LINK_NAME_OFFSET = 157
    private const val LINK_NAME_LENGTH = 100
    private const val MAGIC_OFFSET = 257
    private const val VERSION_OFFSET = 263
    private const val USER_NAME_OFFSET = 265
    private const val GROUP_NAME_OFFSET = 297
    private const val USER_GROUP_NAME_LENGTH = 32
    private const val DEVICE_MAJOR_OFFSET = 329
    private const val DEVICE_MINOR_OFFSET = 337
    private const val DEVICE_NUMBER_LENGTH = 8
    private const val PREFIX_OFFSET = 345
    private const val PREFIX_LENGTH = 155
    private const val USTAR_RESERVED_OFFSET = 500
    private const val REGULAR_TYPE = '0'.code
    private const val SYMBOLIC_LINK_TYPE = '2'.code
    private const val DIRECTORY_TYPE = '5'.code
    private const val GLOBAL_PAX_TYPE = 'g'.code
    private const val GLOBAL_PAX_NAME = "pax_global_header"
    private const val GLOBAL_PAX_MODE = 0x1b6L
    private const val REGULAR_MODE = 0x1b4L
    private const val EXECUTABLE_MODE = 0x1fdL
    private const val DIRECTORY_MODE = 0x1fdL
    private const val SYMBOLIC_LINK_MODE = 0x1ffL
    private const val ROOT_OWNER = "root"
}

private class PositionalSeekableInput(private val source: BoundedTarXzSource) : SeekableInputStream() {
    private var cursor = 0L

    override fun length(): Long = source.size

    override fun position(): Long = cursor

    override fun seek(position: Long) {
        if (position !in 0L..source.size) archiveFail("XZ decoder sought outside its authenticated source")
        cursor = position
    }

    override fun read(): Int {
        val single = ByteArray(1)
        return if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 0xff
    }

    override fun read(destination: ByteArray, offset: Int, length: Int): Int {
        if (offset < 0 || length < 0 || offset > destination.size - length) throw IndexOutOfBoundsException()
        if (length == 0) return 0
        if (cursor == source.size) return -1
        val read = source.read(cursor, destination, offset, length)
        if (read <= 0) archiveFail("source archive ended during an XZ positional read")
        cursor = Math.addExact(cursor, read.toLong())
        return read
    }
}

private class ExpandedArchiveInputStream(
    input: SeekableXZInputStream,
    private val maximumBytes: Long,
) : FilterInputStream(input) {
    var consumed: Long = 0L
        private set

    fun readBlockOrNull(size: Int): ByteArray? {
        val first = read()
        if (first < 0) return null
        val result = ByteArray(size)
        result[0] = first.toByte()
        readExactly(result, 1, size - 1)
        return result
    }

    fun readPayload(size: Long, maximumMaterializedBytes: Int): ByteArray {
        if (size !in 0L..maximumMaterializedBytes.toLong()) {
            archiveFail("source archive selected payload exceeds its materialization bound")
        }
        val result = ByteArray(size.toInt())
        readExactly(result, 0, result.size)
        return result
    }

    fun skipPayload(size: Long) {
        if (size < 0L) archiveFail("source archive member size is negative")
        var remaining = size
        val buffer = ByteArray(64 * 1024)
        while (remaining > 0L) {
            val read = read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read < 0) archiveFail("source archive member is truncated")
            remaining -= read.toLong()
        }
    }

    fun visitPayload(size: Long, visitor: (ByteArray, Int, Boolean) -> Unit) {
        if (size < 0L) archiveFail("source archive member size is negative")
        val buffer = ByteArray(64 * 1024)
        if (size == 0L) {
            visitor(buffer, 0, true)
            return
        }
        var remaining = size
        while (remaining > 0L) {
            val read = read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read < 0) archiveFail("source archive member is truncated")
            remaining -= read.toLong()
            visitor(buffer, read, remaining == 0L)
        }
    }

    fun skipPadding(size: Long) {
        val remainder = size % 512L
        if (remainder != 0L) {
            val padding = ByteArray((512L - remainder).toInt())
            readExactly(padding, 0, padding.size)
            if (padding.any { it != 0.toByte() }) archiveFail("source archive member padding is nonzero")
        }
    }

    override fun read(): Int {
        val single = ByteArray(1)
        return if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 0xff
    }

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        val remaining = maximumBytes - consumed
        if (remaining == 0L) return -1
        var read: Int
        do {
            read = super.read(bytes, offset, minOf(length.toLong(), remaining).toInt())
        } while (read == 0)
        if (read > 0) consumed += read.toLong()
        return read
    }

    private fun readExactly(bytes: ByteArray, offset: Int, length: Int) {
        var position = offset
        while (position < offset + length) {
            val read = read(bytes, position, offset + length - position)
            if (read < 0) archiveFail("source archive tar stream is truncated at expanded byte $consumed")
            position += read
        }
    }
}

private fun archiveFail(message: String): Nothing = throw BoundedTarXzException(message)

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

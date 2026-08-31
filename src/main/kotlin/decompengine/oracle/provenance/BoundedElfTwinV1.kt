package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

internal class BoundedElfTwinV1Exception(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

internal data class BoundedElfTwinV1Limits(
    val maximumFileBytes: Long = 1024L * 1024L * 1024L,
    val maximumProgramHeaders: Int = 4_096,
    val maximumSectionHeaders: Int = 131_072,
    val maximumStringTableBytes: Int = 16 * 1024 * 1024,
    val maximumNameBytes: Int = 4 * 1024,
    val maximumAggregateNameBytes: Long = 16L * 1024L * 1024L,
    val maximumNotePayloadBytes: Int = 16 * 1024 * 1024,
    val maximumAggregateNoteBytes: Long = 32L * 1024L * 1024L,
    val maximumNotes: Int = 4_096,
    val maximumBuildIds: Int = 64,
    val maximumRangeBytes: Long = 1024L * 1024L * 1024L,
    val maximumExecutableBytes: Long = 1024L * 1024L * 1024L,
    val maximumAggregateHashedBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumCommitmentBytes: Long = 64L * 1024L * 1024L,
    val maximumSteps: Long = 10_000_000L,
    val readBufferBytes: Int = 64 * 1024,
) {
    init {
        require(maximumFileBytes > 0L)
        require(maximumProgramHeaders > 0)
        require(maximumSectionHeaders > 0)
        require(maximumStringTableBytes > 0)
        require(maximumNameBytes > 0 && maximumNameBytes <= maximumStringTableBytes)
        require(maximumAggregateNameBytes > 0L)
        require(maximumNotePayloadBytes > 0)
        require(maximumAggregateNoteBytes >= maximumNotePayloadBytes.toLong())
        require(maximumNotes > 0)
        require(maximumBuildIds > 0 && maximumBuildIds <= maximumNotes)
        require(maximumRangeBytes > 0L && maximumRangeBytes <= maximumFileBytes)
        require(maximumExecutableBytes > 0L)
        require(maximumAggregateHashedBytes >= maximumFileBytes)
        require(maximumCommitmentBytes > 0L)
        require(maximumSteps > 0L)
        require(readBufferBytes in 1..(1024 * 1024))
    }
}

internal data class BoundedElfHeaderV1(
    val elfClass: String,
    val dataEncoding: String,
    val identVersion: Int,
    val osAbi: Int,
    val osAbiName: String,
    val abiVersion: Int,
    val type: ULong,
    val typeName: String,
    val machine: ULong,
    val machineName: String,
    val version: ULong,
    val entryPoint: ULong,
    val programHeaderOffset: ULong,
    val sectionHeaderOffset: ULong,
    val flags: ULong,
    val headerSize: Int,
    val programHeaderEntrySize: Int,
    val programHeaderCount: Int,
    val sectionHeaderEntrySize: Int,
    val sectionHeaderCount: Int,
    val sectionNameTableIndex: Int,
)

internal data class BoundedElfIdentityV1(
    val elfClass: String,
    val dataEncoding: String,
    val identVersion: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val type: ULong,
    val machine: ULong,
    val version: ULong,
    val entryPoint: ULong,
    val flags: ULong,
)

internal data class BoundedElfProgramHeaderV1(
    val index: Int,
    val type: ULong,
    val typeName: String,
    val flags: ULong,
    val flagNames: String,
    val offset: ULong,
    val virtualAddress: ULong,
    val physicalAddress: ULong,
    val fileSize: ULong,
    val memorySize: ULong,
    val alignment: ULong,
    val contentSha256: String,
)

internal data class BoundedElfSectionV1(
    val index: Int,
    val name: String,
    val type: ULong,
    val typeName: String,
    val flags: ULong,
    val address: ULong,
    val offset: ULong,
    val size: ULong,
    val link: ULong,
    val info: ULong,
    val alignment: ULong,
    val entrySize: ULong,
    val allocated: Boolean,
    val executable: Boolean,
    val fileBacked: Boolean,
    val contentSha256: String?,
)

internal data class BoundedElfSymbolTableV1(
    val section: String,
    val entries: ULong,
)

internal data class BoundedElfMetadataV1(
    val hasDwarf: Boolean,
    val dwarfSections: List<String>,
    val hasStaticSymbols: Boolean,
    val staticSymbolTables: List<BoundedElfSymbolTableV1>,
    val hasDynamicSymbols: Boolean,
    val dynamicSymbolTables: List<BoundedElfSymbolTableV1>,
)

internal data class BoundedElfExecutableLoadV1(
    val selector: String,
    val segmentIndexes: List<Int>,
    val bytes: Long,
    val sha256: String,
)

internal data class BoundedElfInspectionV1(
    val header: BoundedElfHeaderV1,
    val identity: BoundedElfIdentityV1,
    val buildIds: List<String>,
    val programHeaders: List<BoundedElfProgramHeaderV1>,
    val sections: List<BoundedElfSectionV1>,
    val metadata: BoundedElfMetadataV1,
    val executableLoad: BoundedElfExecutableLoadV1,
)

internal data class BoundedElfArtifactV1(
    val path: Path,
    val bytes: Long,
    val sha256: String,
    val elf: BoundedElfInspectionV1,
)

internal data class BoundedElfMetadataDeltaV1(
    val fullOnlySections: List<String>,
    val strippedOnlySections: List<String>,
    val changedCommonSections: List<String>,
    val removedDwarfSections: List<String>,
    val removedStaticSymbolTables: List<BoundedElfSymbolTableV1>,
)

internal data class BoundedElfEquivalenceV1(
    val buildId: String,
    val elfIdentity: BoundedElfIdentityV1,
    val programHeadersSha256: String,
    val allocatedSectionsSha256: String,
    val executableLoad: BoundedElfExecutableLoadV1,
    val metadataDelta: BoundedElfMetadataDeltaV1,
)

internal data class BoundedElfTwinResultV1(
    val full: BoundedElfArtifactV1,
    val stripped: BoundedElfArtifactV1,
    val equivalence: BoundedElfEquivalenceV1,
)

internal enum class BoundedElfTwinV1Checkpoint {
    AFTER_FULL_INSPECTION,
    AFTER_STRIPPED_INSPECTION,
    BEFORE_TERMINAL_REVALIDATION,
}

internal fun interface BoundedElfTwinV1FaultInjector {
    fun hit(checkpoint: BoundedElfTwinV1Checkpoint)
}

/**
 * Bounded, descriptor-pinned implementation of the legacy Python ELF-twin v1 contract.
 *
 * Successful calls return only in-memory facts. No file is created or published. Path selection,
 * parsing, and terminal byte authentication stay bound to open descriptors. A cooperating same-UID
 * writer can always perform an indistinguishable, completely restored transient mutation; this
 * boundary detects substitution and every mutation observable at its phase and terminal checks.
 */
internal object BoundedElfTwinV1 {
    fun inspect(
        path: Path,
        limits: BoundedElfTwinV1Limits = BoundedElfTwinV1Limits(),
    ): BoundedElfArtifactV1 = translateFailure("inspect ELF artifact") {
        PinnedElfFile.open(path, limits).use { pinned ->
            val state = inspectPinned(pinned, limits)
            val finalSha256 = state.reader.hashComplete("terminal complete ELF")
            if (finalSha256 != state.artifact.sha256) elfFail("ELF bytes changed while being inspected")
            pinned.requireCurrent()
            state.artifact
        }
    }

    fun inspectTwin(
        fullPath: Path,
        strippedPath: Path,
        limits: BoundedElfTwinV1Limits = BoundedElfTwinV1Limits(),
        faultInjector: BoundedElfTwinV1FaultInjector? = null,
    ): BoundedElfTwinResultV1 = translateFailure("inspect ELF twin") {
        PinnedElfFile.open(fullPath, limits).use { fullPinned ->
            PinnedElfFile.open(strippedPath, limits).use { strippedPinned ->
                if (sameObject(fullPinned.identity, strippedPinned.identity)) {
                    elfFail("full and stripped artifacts resolve to the same file")
                }
                fullPinned.requireCurrent()
                strippedPinned.requireCurrent()

                val full = inspectPinned(fullPinned, limits)
                faultInjector?.hit(BoundedElfTwinV1Checkpoint.AFTER_FULL_INSPECTION)
                fullPinned.requireCurrent()
                strippedPinned.requireCurrent()

                val stripped = inspectPinned(strippedPinned, limits)
                faultInjector?.hit(BoundedElfTwinV1Checkpoint.AFTER_STRIPPED_INSPECTION)
                fullPinned.requireCurrent()
                strippedPinned.requireCurrent()

                val equivalence = deriveEquivalence(full.artifact, stripped.artifact, limits)
                faultInjector?.hit(BoundedElfTwinV1Checkpoint.BEFORE_TERMINAL_REVALIDATION)

                val terminalFull = full.reader.hashComplete("terminal full ELF")
                val terminalStripped = stripped.reader.hashComplete("terminal stripped ELF")
                if (terminalFull != full.artifact.sha256) {
                    elfFail("full ELF bytes changed while the twin was inspected")
                }
                if (terminalStripped != stripped.artifact.sha256) {
                    elfFail("stripped ELF bytes changed while the twin was inspected")
                }
                fullPinned.requireCurrent()
                strippedPinned.requireCurrent()
                BoundedElfTwinResultV1(full.artifact, stripped.artifact, equivalence)
            }
        }
    }

    private fun inspectPinned(
        pinned: PinnedElfFile,
        limits: BoundedElfTwinV1Limits,
    ): InspectedState {
        pinned.requireCurrent()
        val budget = ElfBudget(limits)
        val reader = ElfRangeReader(pinned.channel, pinned.size, limits, budget)
        val completeSha256 = reader.hashComplete("initial complete ELF")
        val elf = ElfParser(reader, limits, budget).inspect()
        pinned.requireCurrent()
        return InspectedState(
            BoundedElfArtifactV1(pinned.path, pinned.size, completeSha256, elf),
            reader,
        )
    }
}

private data class InspectedState(
    val artifact: BoundedElfArtifactV1,
    val reader: ElfRangeReader,
)

private class PinnedElfFile private constructor(
    val path: Path,
    private val parentPath: Path,
    private val name: String,
    private val parent: LinuxDescriptor,
    private val descriptor: LinuxDescriptor,
    val identity: LinuxFileIdentity,
    val channel: FileChannel,
    val size: Long,
) : AutoCloseable {
    fun requireCurrent() {
        val parentNow = LinuxFilesystemSyscalls.identity(parent.fd)
        if (!sameDirectory(parent.identity, parentNow)) elfFail("ELF parent descriptor identity changed")
        val realParent = try {
            parentPath.toRealPath()
        } catch (failure: IOException) {
            throw BoundedElfTwinV1Exception("ELF parent path is unavailable", failure)
        }
        if (realParent != parentPath ||
            !Files.isSameFile(parentPath, LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd))
        ) {
            elfFail("ELF parent pathname changed")
        }

        val descriptorNow = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameFile(identity, descriptorNow)) elfFail("ELF descriptor identity changed")
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { named ->
            if (!sameFile(identity, LinuxFilesystemSyscalls.identity(named.fd))) {
                elfFail("ELF pathname changed")
            }
        } ?: elfFail("ELF pathname disappeared")
        if (channel.size() != size) elfFail("ELF size changed")
    }

    override fun close() {
        try {
            channel.close()
        } finally {
            try {
                descriptor.close()
            } finally {
                parent.close()
            }
        }
    }

    companion object {
        fun open(path: Path, limits: BoundedElfTwinV1Limits): PinnedElfFile {
            val absolute = path.toAbsolutePath().normalize()
            val parentPath = absolute.parent ?: elfFail("ELF path has no parent")
            val name = absolute.fileName?.toString() ?: elfFail("ELF path has no file name")
            if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
                elfFail("ELF file name is invalid")
            }
            val realParent = try {
                parentPath.toRealPath()
            } catch (failure: IOException) {
                throw BoundedElfTwinV1Exception("ELF parent path is unavailable", failure)
            }
            if (realParent != parentPath) elfFail("ELF parent path contains a symbolic link")
            LinuxFilesystemSyscalls.requireSupported(realParent)
            val parent = LinuxFilesystemSyscalls.openRoot(realParent)
            try {
                val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                    ?: elfFail("ELF artifact is unavailable")
                try {
                    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink) {
                        elfFail("ELF artifact is not a non-symlink regular file")
                    }
                    val channel = FileChannel.open(
                        LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
                        StandardOpenOption.READ,
                    )
                    try {
                        val size = channel.size()
                        if (size !in 1L..limits.maximumFileBytes) {
                            elfFail("ELF artifact exceeds its file-byte bound")
                        }
                        return PinnedElfFile(
                            absolute,
                            realParent,
                            name,
                            parent,
                            descriptor,
                            identity,
                            channel,
                            size,
                        ).also { it.requireCurrent() }
                    } catch (failure: Throwable) {
                        channel.close()
                        throw failure
                    }
                } catch (failure: Throwable) {
                    descriptor.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                parent.close()
                throw failure
            }
        }
    }
}

private class ElfBudget(private val limits: BoundedElfTwinV1Limits) {
    private var steps = 0L
    private var hashedBytes = 0L
    private var aggregateNameBytes = 0L
    private var aggregateNoteBytes = 0L
    private var notes = 0
    private var buildIds = 0

    fun step(label: String, count: Long = 1L) {
        steps = addBounded(steps, count, limits.maximumSteps, "$label step")
    }

    fun hashBytes(bytes: Long, label: String) {
        hashedBytes = addBounded(
            hashedBytes,
            bytes,
            limits.maximumAggregateHashedBytes,
            "$label aggregate hashed-byte",
        )
    }

    fun nameBytes(bytes: Int) {
        aggregateNameBytes = addBounded(
            aggregateNameBytes,
            bytes.toLong(),
            limits.maximumAggregateNameBytes,
            "section-name byte",
        )
    }

    fun notePayload(bytes: Int) {
        aggregateNoteBytes = addBounded(
            aggregateNoteBytes,
            bytes.toLong(),
            limits.maximumAggregateNoteBytes,
            "ELF note payload byte",
        )
    }

    fun note() {
        notes++
        if (notes > limits.maximumNotes) elfFail("ELF note count exceeds its bound")
    }

    fun buildId() {
        buildIds++
        if (buildIds > limits.maximumBuildIds) elfFail("GNU Build ID count exceeds its bound")
    }
}

private class ElfRangeReader(
    private val channel: FileChannel,
    val fileBytes: Long,
    private val limits: BoundedElfTwinV1Limits,
    private val budget: ElfBudget,
) {
    fun readExact(offset: Long, bytes: Int, label: String): ByteArray {
        requireRange(offset, bytes.toLong(), label)
        val result = ByteArray(bytes)
        var consumed = 0
        while (consumed < bytes) {
            budget.step(label)
            val destination = ByteBuffer.wrap(result, consumed, bytes - consumed)
            val read = channel.read(destination, offset + consumed)
            if (read <= 0) elfFail("$label ended during descriptor-bound reading")
            consumed += read
        }
        return result
    }

    fun readBounded(offset: ULong, bytes: ULong, maximum: Int, label: String): ByteArray {
        val count = boundedLong(bytes, label)
        if (count > maximum.toLong()) elfFail("$label exceeds its byte bound")
        return readExact(boundedLong(offset, label), count.toInt(), label)
    }

    fun hashComplete(label: String): String = hashRange(0L, fileBytes, label)

    fun hashRange(
        offset: Long,
        bytes: Long,
        label: String,
        additionalDigest: MessageDigest? = null,
    ): String {
        requireRange(offset, bytes, label)
        if (bytes > limits.maximumRangeBytes) elfFail("$label exceeds the individual range-byte bound")
        budget.hashBytes(bytes, label)
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(limits.readBufferBytes)
        var consumed = 0L
        while (consumed < bytes) {
            budget.step(label)
            val requested = minOf(buffer.size.toLong(), bytes - consumed).toInt()
            val destination = ByteBuffer.wrap(buffer, 0, requested)
            val read = channel.read(destination, offset + consumed)
            if (read <= 0) elfFail("$label ended during descriptor-bound hashing")
            digest.update(buffer, 0, read)
            additionalDigest?.update(buffer, 0, read)
            consumed = Math.addExact(consumed, read.toLong())
        }
        return digest.digest().hex()
    }

    fun requireRange(offset: Long, bytes: Long, label: String) {
        if (offset < 0L || bytes < 0L || offset > fileBytes || bytes > fileBytes - offset) {
            elfFail("$label file range is outside the ELF: offset=$offset, size=$bytes, file=$fileBytes")
        }
    }
}

private enum class ElfByteOrder { LITTLE, BIG }

private enum class ElfClass(
    val identifier: Int,
    val display: String,
    val headerBytes: Int,
    val programBytes: Int,
    val sectionBytes: Int,
) {
    ELF32(1, "ELF32", 36, 32, 40),
    ELF64(2, "ELF64", 48, 56, 64),
}

private class UnsignedCursor(
    private val bytes: ByteArray,
    private val order: ElfByteOrder,
) {
    private var offset = 0

    fun u16(): ULong {
        requireAvailable(2)
        val first = bytes[offset].toInt() and 0xff
        val second = bytes[offset + 1].toInt() and 0xff
        offset += 2
        return (if (order == ElfByteOrder.LITTLE) first or (second shl 8) else (first shl 8) or second)
            .toULong()
    }

    fun u32(): ULong {
        requireAvailable(4)
        var result = 0UL
        if (order == ElfByteOrder.LITTLE) {
            repeat(4) { index ->
                result = result or ((bytes[offset + index].toInt() and 0xff).toULong() shl (8 * index))
            }
        } else {
            repeat(4) { index -> result = (result shl 8) or (bytes[offset + index].toInt() and 0xff).toULong() }
        }
        offset += 4
        return result
    }

    fun u64(): ULong {
        requireAvailable(8)
        var result = 0UL
        if (order == ElfByteOrder.LITTLE) {
            repeat(8) { index ->
                result = result or ((bytes[offset + index].toInt() and 0xff).toULong() shl (8 * index))
            }
        } else {
            repeat(8) { index -> result = (result shl 8) or (bytes[offset + index].toInt() and 0xff).toULong() }
        }
        offset += 8
        return result
    }

    private fun requireAvailable(count: Int) {
        if (offset > bytes.size - count) elfFail("ELF structure is truncated")
    }
}

private data class RawElfHeader(
    val type: ULong,
    val machine: ULong,
    val version: ULong,
    val entryPoint: ULong,
    val programOffset: ULong,
    val sectionOffset: ULong,
    val flags: ULong,
    val headerSize: Int,
    val programEntrySize: Int,
    val programCountRaw: Int,
    val sectionEntrySize: Int,
    val sectionCountRaw: Int,
    val sectionNamesRaw: Int,
)

private data class RawSection(
    val nameOffset: ULong,
    val type: ULong,
    val flags: ULong,
    val address: ULong,
    val offset: ULong,
    val size: ULong,
    val link: ULong,
    val info: ULong,
    val alignment: ULong,
    val entrySize: ULong,
)

private data class RawProgram(
    val type: ULong,
    val flags: ULong,
    val offset: ULong,
    val virtualAddress: ULong,
    val physicalAddress: ULong,
    val fileSize: ULong,
    val memorySize: ULong,
    val alignment: ULong,
)

private class ElfParser(
    private val reader: ElfRangeReader,
    private val limits: BoundedElfTwinV1Limits,
    private val budget: ElfBudget,
) {
    fun inspect(): BoundedElfInspectionV1 {
        if (reader.fileBytes < ELF_IDENT_BYTES) elfFail("artifact is not an ELF file")
        val ident = reader.readExact(0L, ELF_IDENT_BYTES, "ELF identification")
        if (!ident.copyOfRange(0, 4).contentEquals(ELF_MAGIC)) elfFail("artifact is not an ELF file")
        val elfClass = ElfClass.entries.singleOrNull { it.identifier == ident[4].toInt() and 0xff }
            ?: elfFail("unsupported ELF class ${ident[4].toInt() and 0xff}")
        val byteOrder = when (ident[5].toInt() and 0xff) {
            1 -> ElfByteOrder.LITTLE
            2 -> ElfByteOrder.BIG
            else -> elfFail("unsupported ELF data encoding ${ident[5].toInt() and 0xff}")
        }
        val dataEncoding = if (byteOrder == ElfByteOrder.LITTLE) "little-endian" else "big-endian"
        val identVersion = ident[6].toInt() and 0xff
        val osAbi = ident[7].toInt() and 0xff
        val abiVersion = ident[8].toInt() and 0xff
        val rawHeader = parseHeader(elfClass, byteOrder)
        val expectedHeaderSize = ELF_IDENT_BYTES + elfClass.headerBytes
        if (identVersion != 1 || rawHeader.version != 1UL) {
            elfFail("ELF identification and header versions must both be 1")
        }
        if (rawHeader.headerSize !in expectedHeaderSize..reader.fileBytes) {
            elfFail("ELF header size is invalid")
        }

        fun rawSection(index: Int): RawSection {
            if (rawHeader.sectionOffset == 0UL || rawHeader.sectionEntrySize < elfClass.sectionBytes) {
                elfFail("ELF section-header table metadata is invalid")
            }
            val offset = tableOffset(
                rawHeader.sectionOffset,
                index,
                rawHeader.sectionEntrySize,
                "section header $index",
            )
            return parseSection(
                reader.readExact(offset, elfClass.sectionBytes, "section header $index"),
                elfClass,
                byteOrder,
            )
        }

        val needsSectionZero = rawHeader.sectionOffset != 0UL &&
            (rawHeader.sectionCountRaw == 0 || rawHeader.programCountRaw == PN_XNUM ||
                rawHeader.sectionNamesRaw == SHN_XINDEX)
        val sectionZero = if (needsSectionZero) rawSection(0) else null
        val sectionCount = if (rawHeader.sectionCountRaw == 0) {
            boundedCount(sectionZero?.size ?: elfFail("extended section count has no section zero"), limits.maximumSectionHeaders, "section-header")
        } else {
            boundedCount(rawHeader.sectionCountRaw.toULong(), limits.maximumSectionHeaders, "section-header")
        }
        val programCount = if (rawHeader.programCountRaw == PN_XNUM) {
            boundedCount(sectionZero?.info ?: elfFail("extended program count has no section zero"), limits.maximumProgramHeaders, "program-header")
        } else {
            boundedCount(rawHeader.programCountRaw.toULong(), limits.maximumProgramHeaders, "program-header")
        }
        val sectionNamesIndex = if (rawHeader.sectionNamesRaw == SHN_XINDEX) {
            boundedCount(sectionZero?.link ?: elfFail("extended section-name index has no section zero"), limits.maximumSectionHeaders, "section-name table index")
        } else {
            rawHeader.sectionNamesRaw
        }
        if (sectionCount <= 0) elfFail("oracle ELF must have a section-header table")
        if (rawHeader.sectionEntrySize < elfClass.sectionBytes) {
            elfFail("ELF section-header entry size is too small")
        }
        requireTableRange(
            rawHeader.sectionOffset,
            sectionCount,
            rawHeader.sectionEntrySize,
            "section-header table",
        )
        if (programCount > 0) {
            if (rawHeader.programOffset == 0UL || rawHeader.programEntrySize < elfClass.programBytes) {
                elfFail("ELF program-header table metadata is invalid")
            }
            requireTableRange(
                rawHeader.programOffset,
                programCount,
                rawHeader.programEntrySize,
                "program-header table",
            )
        }
        if (sectionNamesIndex <= 0 || sectionNamesIndex >= sectionCount) {
            elfFail("ELF section-name string-table index is invalid")
        }

        val rawSections = ArrayList<RawSection>(sectionCount)
        repeat(sectionCount) { index ->
            budget.step("section header")
            rawSections += rawSection(index)
        }
        val namesHeader = rawSections[sectionNamesIndex]
        if (namesHeader.type != SHT_STRTAB) elfFail("ELF section-name table is not SHT_STRTAB")
        val sectionNames = reader.readBounded(
            namesHeader.offset,
            namesHeader.size,
            limits.maximumStringTableBytes,
            "section-name string table",
        )

        val sections = ArrayList<BoundedElfSectionV1>(sectionCount)
        val sectionBuildIds = ArrayList<String>()
        rawSections.forEachIndexed { index, raw ->
            budget.step("section")
            val name = readName(sectionNames, raw.nameOffset, index)
            val fileBacked = raw.type != SHT_NOBITS
            val contentSha256 = if (fileBacked) {
                reader.hashRange(
                    boundedLong(raw.offset, "section $index ($name) offset"),
                    boundedLong(raw.size, "section $index ($name) size"),
                    "section $index ($name)",
                )
            } else {
                null
            }
            sections += BoundedElfSectionV1(
                index = index,
                name = name,
                type = raw.type,
                typeName = named(SECTION_TYPE_NAMES, raw.type, "SHT"),
                flags = raw.flags,
                address = raw.address,
                offset = raw.offset,
                size = raw.size,
                link = raw.link,
                info = raw.info,
                alignment = raw.alignment,
                entrySize = raw.entrySize,
                allocated = raw.flags and SHF_ALLOC != 0UL,
                executable = raw.flags and SHF_EXECINSTR != 0UL,
                fileBacked = fileBacked,
                contentSha256 = contentSha256,
            )
            if (raw.type == SHT_NOTE && name == ".note.gnu.build-id") {
                val payload = reader.readBounded(
                    raw.offset,
                    raw.size,
                    limits.maximumNotePayloadBytes,
                    "section $index ($name) note payload",
                )
                budget.notePayload(payload.size)
                sectionBuildIds += parseGnuBuildIds(payload, byteOrder, "section $index ($name)")
            }
        }

        val programs = ArrayList<BoundedElfProgramHeaderV1>(programCount)
        val noteSegments = ArrayList<Pair<RawProgram, String>>()
        val executableIndexes = ArrayList<Int>()
        val executableDigest = MessageDigest.getInstance("SHA-256")
        var executableBytes = 0L
        repeat(programCount) { index ->
            budget.step("program header")
            val offset = tableOffset(
                rawHeader.programOffset,
                index,
                rawHeader.programEntrySize,
                "program header $index",
            )
            val raw = parseProgram(
                reader.readExact(offset, elfClass.programBytes, "program header $index"),
                elfClass,
                byteOrder,
            )
            val rangeOffset = boundedLong(raw.offset, "program segment $index offset")
            val rangeBytes = boundedLong(raw.fileSize, "program segment $index size")
            if (raw.type == PT_LOAD) {
                if (raw.memorySize < raw.fileSize) {
                    elfFail("PT_LOAD segment $index has p_memsz smaller than p_filesz")
                }
                if (raw.alignment !in setOf(0UL, 1UL)) {
                    if (!isPowerOfTwo(raw.alignment) || raw.offset % raw.alignment != raw.virtualAddress % raw.alignment) {
                        elfFail("PT_LOAD segment $index has invalid alignment")
                    }
                }
            }
            val executable = raw.type == PT_LOAD && raw.flags and PF_X != 0UL && raw.fileSize > 0UL
            if (executable) {
                executableIndexes += index
                executableBytes = addBounded(
                    executableBytes,
                    rangeBytes,
                    limits.maximumExecutableBytes,
                    "executable PT_LOAD byte",
                )
            }
            val contentSha256 = reader.hashRange(
                rangeOffset,
                rangeBytes,
                "program segment $index",
                if (executable) executableDigest else null,
            )
            programs += BoundedElfProgramHeaderV1(
                index = index,
                type = raw.type,
                typeName = named(PROGRAM_TYPE_NAMES, raw.type, "PT"),
                flags = raw.flags,
                flagNames = programFlags(raw.flags),
                offset = raw.offset,
                virtualAddress = raw.virtualAddress,
                physicalAddress = raw.physicalAddress,
                fileSize = raw.fileSize,
                memorySize = raw.memorySize,
                alignment = raw.alignment,
                contentSha256 = contentSha256,
            )
            if (raw.type == PT_NOTE) noteSegments += raw to "PT_NOTE segment $index"
        }

        val buildIds = ArrayList(sectionBuildIds)
        if (buildIds.isEmpty()) {
            noteSegments.forEach { (raw, label) ->
                val payload = reader.readBounded(
                    raw.offset,
                    raw.fileSize,
                    limits.maximumNotePayloadBytes,
                    "$label payload",
                )
                budget.notePayload(payload.size)
                buildIds += parseGnuBuildIds(payload, byteOrder, label)
            }
        }
        buildIds.forEach { id ->
            if (id.length !in 8..128 || id.length % 2 != 0 || id.any { it !in '0'..'9' && it !in 'a'..'f' }) {
                elfFail("GNU Build ID has an invalid format")
            }
        }

        val dwarfSections = sections.asSequence().map { it.name }.filter(::isDwarfSection).sorted().toList()
        val staticSymbols = symbolTables(sections, SHT_SYMTAB)
        val dynamicSymbols = symbolTables(sections, SHT_DYNSYM)
        val header = BoundedElfHeaderV1(
            elfClass = elfClass.display,
            dataEncoding = dataEncoding,
            identVersion = identVersion,
            osAbi = osAbi,
            osAbiName = OS_ABI_NAMES[osAbi] ?: "ELFOSABI_0x${osAbi.toString(16)}",
            abiVersion = abiVersion,
            type = rawHeader.type,
            typeName = named(ELF_TYPE_NAMES, rawHeader.type, "ET"),
            machine = rawHeader.machine,
            machineName = named(MACHINE_NAMES, rawHeader.machine, "EM"),
            version = rawHeader.version,
            entryPoint = rawHeader.entryPoint,
            programHeaderOffset = rawHeader.programOffset,
            sectionHeaderOffset = rawHeader.sectionOffset,
            flags = rawHeader.flags,
            headerSize = rawHeader.headerSize,
            programHeaderEntrySize = rawHeader.programEntrySize,
            programHeaderCount = programCount,
            sectionHeaderEntrySize = rawHeader.sectionEntrySize,
            sectionHeaderCount = sectionCount,
            sectionNameTableIndex = sectionNamesIndex,
        )
        val identity = BoundedElfIdentityV1(
            elfClass = header.elfClass,
            dataEncoding = header.dataEncoding,
            identVersion = header.identVersion,
            osAbi = header.osAbi,
            abiVersion = header.abiVersion,
            type = header.type,
            machine = header.machine,
            version = header.version,
            entryPoint = header.entryPoint,
            flags = header.flags,
        )
        return BoundedElfInspectionV1(
            header = header,
            identity = identity,
            buildIds = buildIds,
            programHeaders = programs,
            sections = sections,
            metadata = BoundedElfMetadataV1(
                hasDwarf = dwarfSections.isNotEmpty(),
                dwarfSections = dwarfSections,
                hasStaticSymbols = staticSymbols.isNotEmpty(),
                staticSymbolTables = staticSymbols,
                hasDynamicSymbols = dynamicSymbols.isNotEmpty(),
                dynamicSymbolTables = dynamicSymbols,
            ),
            executableLoad = BoundedElfExecutableLoadV1(
                selector = EXECUTABLE_SELECTOR,
                segmentIndexes = executableIndexes,
                bytes = executableBytes,
                sha256 = executableDigest.digest().hex(),
            ),
        )
    }

    private fun parseHeader(elfClass: ElfClass, order: ElfByteOrder): RawElfHeader {
        val cursor = UnsignedCursor(
            reader.readExact(ELF_IDENT_BYTES.toLong(), elfClass.headerBytes, "ELF header"),
            order,
        )
        val type = cursor.u16()
        val machine = cursor.u16()
        val version = cursor.u32()
        val entryPoint = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val programOffset = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val sectionOffset = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val flags = cursor.u32()
        return RawElfHeader(
            type,
            machine,
            version,
            entryPoint,
            programOffset,
            sectionOffset,
            flags,
            cursor.u16().toInt(),
            cursor.u16().toInt(),
            cursor.u16().toInt(),
            cursor.u16().toInt(),
            cursor.u16().toInt(),
            cursor.u16().toInt(),
        )
    }

    private fun parseSection(bytes: ByteArray, elfClass: ElfClass, order: ElfByteOrder): RawSection {
        val cursor = UnsignedCursor(bytes, order)
        val name = cursor.u32()
        val type = cursor.u32()
        val flags = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val address = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val offset = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val size = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val link = cursor.u32()
        val info = cursor.u32()
        val alignment = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        val entrySize = if (elfClass == ElfClass.ELF32) cursor.u32() else cursor.u64()
        return RawSection(name, type, flags, address, offset, size, link, info, alignment, entrySize)
    }

    private fun parseProgram(bytes: ByteArray, elfClass: ElfClass, order: ElfByteOrder): RawProgram {
        val cursor = UnsignedCursor(bytes, order)
        val type = cursor.u32()
        return if (elfClass == ElfClass.ELF32) {
            val offset = cursor.u32()
            val virtualAddress = cursor.u32()
            val physicalAddress = cursor.u32()
            val fileSize = cursor.u32()
            val memorySize = cursor.u32()
            val flags = cursor.u32()
            val alignment = cursor.u32()
            RawProgram(type, flags, offset, virtualAddress, physicalAddress, fileSize, memorySize, alignment)
        } else {
            val flags = cursor.u32()
            RawProgram(
                type,
                flags,
                cursor.u64(),
                cursor.u64(),
                cursor.u64(),
                cursor.u64(),
                cursor.u64(),
                cursor.u64(),
            )
        }
    }

    private fun readName(table: ByteArray, rawOffset: ULong, index: Int): String {
        if (rawOffset > Int.MAX_VALUE.toULong()) elfFail("section $index name offset is outside its string table")
        val offset = rawOffset.toInt()
        if (offset < 0 || offset >= table.size) {
            if (offset == 0 && table.isEmpty()) return ""
            elfFail("section $index name offset $rawOffset is outside its string table")
        }
        var end = offset
        while (end < table.size && table[end] != 0.toByte()) {
            if (end - offset >= limits.maximumNameBytes) {
                elfFail("section $index name exceeds its byte bound")
            }
            budget.step("section name byte")
            end++
        }
        if (end == table.size) elfFail("section $index name is not NUL terminated")
        val length = end - offset
        if (length > limits.maximumNameBytes) elfFail("section $index name exceeds its byte bound")
        budget.nameBytes(length)
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(table, offset, length))
                .toString()
        } catch (failure: Exception) {
            throw BoundedElfTwinV1Exception("section $index name is not UTF-8", failure)
        }
    }

    private fun parseGnuBuildIds(payload: ByteArray, order: ElfByteOrder, label: String): List<String> {
        val result = ArrayList<String>()
        var offset = 0
        while (offset < payload.size) {
            budget.step("ELF note")
            if (allZeroNoteRemainder(payload, offset)) break
            if (payload.size - offset < NOTE_HEADER_BYTES) elfFail("$label has a truncated ELF note header")
            val cursor = UnsignedCursor(payload.copyOfRange(offset, offset + NOTE_HEADER_BYTES), order)
            val nameSize = boundedInt(cursor.u32(), limits.maximumNotePayloadBytes, "$label note name")
            val descriptorSize = boundedInt(cursor.u32(), limits.maximumNotePayloadBytes, "$label note descriptor")
            val noteType = cursor.u32()
            offset += NOTE_HEADER_BYTES
            val nameEnd = addIndex(offset, nameSize, payload.size, "$label note name")
            val name = payload.copyOfRange(offset, nameEnd)
            offset = alignNote(nameEnd, payload.size, "$label note name padding")
            val descriptorEnd = addIndex(offset, descriptorSize, payload.size, "$label note descriptor")
            val descriptor = payload.copyOfRange(offset, descriptorEnd)
            offset = alignNote(descriptorEnd, payload.size, "$label note descriptor padding")
            budget.note()
            if (noteType == NT_GNU_BUILD_ID && name.rstripNul().contentEquals(GNU_NOTE_NAME)) {
                if (descriptor.size !in 4..64) elfFail("$label contains an invalid GNU Build ID length")
                budget.buildId()
                result += descriptor.hex()
            }
        }
        return result
    }

    private fun allZeroNoteRemainder(payload: ByteArray, offset: Int): Boolean {
        for (index in offset until payload.size) {
            budget.step("ELF note trailing byte")
            if (payload[index] != 0.toByte()) return false
        }
        return true
    }

    private fun tableOffset(base: ULong, index: Int, entryBytes: Int, label: String): Long {
        val baseLong = boundedLong(base, "$label table offset")
        val relative = try {
            Math.multiplyExact(index.toLong(), entryBytes.toLong())
        } catch (failure: ArithmeticException) {
            elfFail("$label offset overflows")
        }
        return try {
            Math.addExact(baseLong, relative)
        } catch (failure: ArithmeticException) {
            elfFail("$label offset overflows")
        }
    }

    private fun requireTableRange(base: ULong, count: Int, entryBytes: Int, label: String) {
        val bytes = try {
            Math.multiplyExact(count.toLong(), entryBytes.toLong())
        } catch (failure: ArithmeticException) {
            elfFail("$label byte length overflows")
        }
        reader.requireRange(boundedLong(base, label), bytes, label)
    }
}

private fun deriveEquivalence(
    full: BoundedElfArtifactV1,
    stripped: BoundedElfArtifactV1,
    limits: BoundedElfTwinV1Limits,
): BoundedElfEquivalenceV1 {
    if (full.sha256 == stripped.sha256) elfFail("stripping did not change the complete artifact bytes")
    if (full.bytes <= stripped.bytes) elfFail("stripped artifact must be smaller than the DWARF-rich artifact")
    if (full.elf.identity != stripped.elf.identity) {
        elfFail("full and stripped artifacts have different ELF identities")
    }
    if (full.elf.header.elfClass != "ELF64" || full.elf.header.machine != 62UL) {
        elfFail("the oracle pair must be x86-64 ELF64")
    }
    if (full.elf.header.dataEncoding != "little-endian") {
        elfFail("the oracle pair must use little-endian ELF encoding")
    }
    if (full.elf.header.type !in setOf(2UL, 3UL)) {
        elfFail("the oracle artifact must be ET_EXEC or ET_DYN")
    }
    if (full.elf.buildIds.size != 1 || stripped.elf.buildIds.size != 1) {
        elfFail("each oracle artifact must contain exactly one GNU Build ID")
    }
    if (full.elf.buildIds.single() != stripped.elf.buildIds.single()) {
        elfFail("stripping changed the GNU Build ID")
    }

    val fullProgramLayout = full.elf.programHeaders.map(::programLayout)
    val strippedProgramLayout = stripped.elf.programHeaders.map(::programLayout)
    if (fullProgramLayout != strippedProgramLayout) {
        elfFail("stripping changed the ELF program-header layout")
    }
    if (full.elf.executableLoad.segmentIndexes.isEmpty()) {
        elfFail("oracle artifact has no file-backed executable PT_LOAD segment")
    }
    if (full.elf.executableLoad != stripped.elf.executableLoad) {
        elfFail("stripping changed file-backed PT_LOAD/PF_X bytes")
    }

    val fullAllocated = full.elf.sections.filter { it.allocated }.map(::allocatedSection)
    val strippedAllocated = stripped.elf.sections.filter { it.allocated }.map(::allocatedSection)
    if (fullAllocated != strippedAllocated) {
        elfFail("stripping changed allocated sections or their contents")
    }

    val fullMetadata = full.elf.metadata
    val strippedMetadata = stripped.elf.metadata
    val missingDwarf = listOf("info", "abbrev", "line").filterNot { component ->
        fullMetadata.dwarfSections.any { name -> hasDwarfComponent(name, component) }
    }
    if (missingDwarf.isNotEmpty()) {
        elfFail("full artifact is not DWARF-rich; missing sections for $missingDwarf")
    }
    if (!fullMetadata.hasStaticSymbols) elfFail("full artifact has no static symbol table")
    if (strippedMetadata.hasDwarf) elfFail("stripped artifact still contains DWARF sections")
    if (strippedMetadata.hasStaticSymbols) {
        elfFail("stripped artifact still contains a static symbol table")
    }

    val fullNonallocated = nonallocatedByName(full.elf)
    val strippedNonallocated = nonallocatedByName(stripped.elf)
    val fullNames = fullNonallocated.keys
    val strippedNames = strippedNonallocated.keys
    val commonNames = fullNames intersect strippedNames
    val changedCommon = commonNames.filter { fullNonallocated[it] != strippedNonallocated[it] }.sorted()
    return BoundedElfEquivalenceV1(
        buildId = full.elf.buildIds.single(),
        elfIdentity = full.elf.identity,
        programHeadersSha256 = legacyCompactAsciiSha256(
            fullProgramLayout.map(::programLayoutJson),
            limits.maximumCommitmentBytes,
        ),
        allocatedSectionsSha256 = legacyCompactAsciiSha256(
            fullAllocated.map(::allocatedSectionJson),
            limits.maximumCommitmentBytes,
        ),
        executableLoad = full.elf.executableLoad,
        metadataDelta = BoundedElfMetadataDeltaV1(
            fullOnlySections = (fullNames - strippedNames).sorted(),
            strippedOnlySections = (strippedNames - fullNames).sorted(),
            changedCommonSections = changedCommon,
            removedDwarfSections = fullMetadata.dwarfSections,
            removedStaticSymbolTables = fullMetadata.staticSymbolTables,
        ),
    )
}

private data class ProgramLayout(
    val index: Int,
    val type: ULong,
    val typeName: String,
    val flags: ULong,
    val flagNames: String,
    val offset: ULong,
    val virtualAddress: ULong,
    val physicalAddress: ULong,
    val fileSize: ULong,
    val memorySize: ULong,
    val alignment: ULong,
)

private data class AllocatedSection(
    val name: String,
    val type: ULong,
    val flags: ULong,
    val address: ULong,
    val size: ULong,
    val link: ULong,
    val info: ULong,
    val alignment: ULong,
    val entrySize: ULong,
    val fileBacked: Boolean,
    val contentSha256: String?,
)

private fun programLayout(value: BoundedElfProgramHeaderV1) = ProgramLayout(
    value.index,
    value.type,
    value.typeName,
    value.flags,
    value.flagNames,
    value.offset,
    value.virtualAddress,
    value.physicalAddress,
    value.fileSize,
    value.memorySize,
    value.alignment,
)

private fun allocatedSection(value: BoundedElfSectionV1) = AllocatedSection(
    value.name,
    value.type,
    value.flags,
    value.address,
    value.size,
    value.link,
    value.info,
    value.alignment,
    value.entrySize,
    value.fileBacked,
    value.contentSha256,
)

private fun programLayoutJson(value: ProgramLayout): Map<String, Any?> = mapOf(
    "index" to value.index,
    "type" to value.type,
    "typeName" to value.typeName,
    "flags" to value.flags,
    "flagNames" to value.flagNames,
    "offset" to value.offset,
    "virtualAddress" to value.virtualAddress,
    "physicalAddress" to value.physicalAddress,
    "fileSize" to value.fileSize,
    "memorySize" to value.memorySize,
    "alignment" to value.alignment,
)

private fun allocatedSectionJson(value: AllocatedSection): Map<String, Any?> = mapOf(
    "name" to value.name,
    "type" to value.type,
    "flags" to value.flags,
    "address" to value.address,
    "size" to value.size,
    "link" to value.link,
    "info" to value.info,
    "alignment" to value.alignment,
    "entrySize" to value.entrySize,
    "fileBacked" to value.fileBacked,
    "contentSha256" to value.contentSha256,
)

private fun nonallocatedByName(elf: BoundedElfInspectionV1): Map<String, List<BoundedElfSectionV1>> {
    val result = linkedMapOf<String, MutableList<BoundedElfSectionV1>>()
    elf.sections.forEach { section ->
        if (!section.allocated && section.name.isNotEmpty()) {
            result.getOrPut(section.name) { ArrayList() } += section
        }
    }
    return result
}

/** Exactly Python json.dumps(ensure_ascii=True, separators=(",", ":"), sort_keys=True). */
internal fun legacyCompactAsciiSha256(value: Any?, maximumBytes: Long): String {
    val sink = LegacyAsciiDigest(maximumBytes)
    sink.value(value)
    return sink.finish()
}

private class LegacyAsciiDigest(private val maximumBytes: Long) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var bytes = 0L

    fun value(value: Any?) {
        when (value) {
            null -> ascii("null")
            is Boolean -> ascii(if (value) "true" else "false")
            is String -> string(value)
            is Byte, is Short, is Int, is Long -> ascii(value.toString())
            is UByte, is UShort, is UInt, is ULong -> ascii(value.toString())
            is Map<*, *> -> objectValue(value)
            is Iterable<*> -> arrayValue(value)
            else -> elfFail("legacy commitment contains an unsupported ${value::class.simpleName} value")
        }
    }

    fun finish(): String = digest.digest().hex()

    private fun objectValue(value: Map<*, *>) {
        val entries = value.entries.map { entry ->
            val key = entry.key as? String ?: elfFail("legacy commitment object key is not a string")
            key to entry.value
        }.sortedBy { it.first }
        ascii("{")
        entries.forEachIndexed { index, (key, fieldValue) ->
            if (index > 0) ascii(",")
            string(key)
            ascii(":")
            value(fieldValue)
        }
        ascii("}")
    }

    private fun arrayValue(value: Iterable<*>) {
        ascii("[")
        value.forEachIndexed { index, element ->
            if (index > 0) ascii(",")
            value(element)
        }
        ascii("]")
    }

    private fun string(value: String) {
        ascii("\"")
        value.forEach { current ->
            when (current) {
                '\"' -> ascii("\\\"")
                '\\' -> ascii("\\\\")
                '\b' -> ascii("\\b")
                '\u000c' -> ascii("\\f")
                '\n' -> ascii("\\n")
                '\r' -> ascii("\\r")
                '\t' -> ascii("\\t")
                else -> when {
                    current.code < 0x20 || current.code >= 0x80 -> {
                        ascii("\\u")
                        ascii(current.code.toString(16).padStart(4, '0'))
                    }
                    else -> ascii(current.toString())
                }
            }
        }
        ascii("\"")
    }

    private fun ascii(value: String) {
        val encoded = value.toByteArray(StandardCharsets.US_ASCII)
        bytes = addBounded(bytes, encoded.size.toLong(), maximumBytes, "legacy commitment byte")
        digest.update(encoded)
    }
}

private fun symbolTables(
    sections: List<BoundedElfSectionV1>,
    type: ULong,
): List<BoundedElfSymbolTableV1> = sections.mapNotNull { section ->
    if (section.type == type && section.entrySize > 0UL) {
        BoundedElfSymbolTableV1(section.name, section.size / section.entrySize)
    } else {
        null
    }
}

private fun isDwarfSection(name: String): Boolean =
    name.startsWith(".debug_") || name.startsWith(".zdebug_") ||
        name.startsWith(".gnu.debuglto_") || name.startsWith(".gnu.linkonce.wi.")

private fun hasDwarfComponent(name: String, component: String): Boolean =
    name == ".debug_$component" || name == ".zdebug_$component" ||
        name.startsWith(".gnu.debuglto_.debug_$component")

private fun programFlags(flags: ULong): String = buildString(3) {
    append(if (flags and 4UL != 0UL) 'R' else '-')
    append(if (flags and 2UL != 0UL) 'W' else '-')
    append(if (flags and 1UL != 0UL) 'E' else '-')
}

private fun named(names: Map<ULong, String>, value: ULong, prefix: String): String =
    names[value] ?: "${prefix}_0x${value.toString(16)}"

private fun boundedLong(value: ULong, label: String): Long {
    if (value > Long.MAX_VALUE.toULong()) elfFail("$label exceeds the supported signed range")
    return value.toLong()
}

private fun boundedInt(value: ULong, maximum: Int, label: String): Int {
    if (value > maximum.toULong()) elfFail("$label exceeds its bound")
    return value.toInt()
}

private fun boundedCount(value: ULong, maximum: Int, label: String): Int =
    boundedInt(value, maximum, "$label count")

private fun addBounded(current: Long, increment: Long, maximum: Long, label: String): Long {
    if (increment < 0L || current > maximum - increment) elfFail("$label budget exceeded")
    return current + increment
}

private fun addIndex(offset: Int, bytes: Int, maximum: Int, label: String): Int {
    if (bytes < 0 || offset < 0 || offset > maximum || bytes > maximum - offset) {
        elfFail("$label range is outside its note payload")
    }
    return offset + bytes
}

private fun alignNote(offset: Int, maximum: Int, label: String): Int {
    val aligned = (offset.toLong() + 3L) and -4L
    if (aligned > maximum.toLong()) elfFail("$label is truncated")
    return aligned.toInt()
}

private fun ByteArray.rstripNul(): ByteArray {
    var end = size
    while (end > 0 && this[end - 1] == 0.toByte()) end--
    return copyOf(end)
}

private fun ByteArray.hex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun isPowerOfTwo(value: ULong): Boolean = value > 0UL && value and (value - 1UL) == 0UL

private fun sameObject(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId

private fun sameFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile && right.isRegularFile && !left.isDirectory && !right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun sameDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isDirectory && right.isDirectory && !left.isRegularFile && !right.isRegularFile &&
        !left.isSymbolicLink && !right.isSymbolicLink

private inline fun <T> translateFailure(operation: String, action: () -> T): T = try {
    action()
} catch (failure: BoundedElfTwinV1Exception) {
    throw failure
} catch (failure: Exception) {
    throw BoundedElfTwinV1Exception("could not $operation: ${failure.message ?: failure::class.simpleName}", failure)
}

private fun elfFail(message: String): Nothing = throw BoundedElfTwinV1Exception(message)

private const val ELF_IDENT_BYTES = 16
private const val PN_XNUM = 0xffff
private const val SHN_XINDEX = 0xffff
private const val NOTE_HEADER_BYTES = 12
private const val EXECUTABLE_SELECTOR = "PT_LOAD with PF_X and nonzero p_filesz"
private const val PT_LOAD = 1UL
private const val PT_NOTE = 4UL
private const val PF_X = 1UL
private const val SHT_SYMTAB = 2UL
private const val SHT_STRTAB = 3UL
private const val SHT_NOTE = 7UL
private const val SHT_NOBITS = 8UL
private const val SHT_DYNSYM = 11UL
private const val SHF_ALLOC = 2UL
private const val SHF_EXECINSTR = 4UL
private const val NT_GNU_BUILD_ID = 3UL
private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
private val GNU_NOTE_NAME = byteArrayOf('G'.code.toByte(), 'N'.code.toByte(), 'U'.code.toByte())

private val OS_ABI_NAMES = mapOf(
    0 to "ELFOSABI_SYSV",
    1 to "ELFOSABI_HPUX",
    2 to "ELFOSABI_NETBSD",
    3 to "ELFOSABI_GNU",
    6 to "ELFOSABI_SOLARIS",
    7 to "ELFOSABI_AIX",
    8 to "ELFOSABI_IRIX",
    9 to "ELFOSABI_FREEBSD",
    12 to "ELFOSABI_OPENBSD",
)

private val ELF_TYPE_NAMES = mapOf(
    0UL to "ET_NONE",
    1UL to "ET_REL",
    2UL to "ET_EXEC",
    3UL to "ET_DYN",
    4UL to "ET_CORE",
)

private val MACHINE_NAMES = mapOf(
    0UL to "EM_NONE",
    3UL to "EM_386",
    8UL to "EM_MIPS",
    20UL to "EM_PPC",
    21UL to "EM_PPC64",
    40UL to "EM_ARM",
    62UL to "EM_X86_64",
    183UL to "EM_AARCH64",
    243UL to "EM_RISCV",
)

private val PROGRAM_TYPE_NAMES = mapOf(
    0UL to "PT_NULL",
    1UL to "PT_LOAD",
    2UL to "PT_DYNAMIC",
    3UL to "PT_INTERP",
    4UL to "PT_NOTE",
    5UL to "PT_SHLIB",
    6UL to "PT_PHDR",
    7UL to "PT_TLS",
    0x6474e550UL to "PT_GNU_EH_FRAME",
    0x6474e551UL to "PT_GNU_STACK",
    0x6474e552UL to "PT_GNU_RELRO",
    0x6474e553UL to "PT_GNU_PROPERTY",
)

private val SECTION_TYPE_NAMES = mapOf(
    0UL to "SHT_NULL",
    1UL to "SHT_PROGBITS",
    2UL to "SHT_SYMTAB",
    3UL to "SHT_STRTAB",
    4UL to "SHT_RELA",
    5UL to "SHT_HASH",
    6UL to "SHT_DYNAMIC",
    7UL to "SHT_NOTE",
    8UL to "SHT_NOBITS",
    9UL to "SHT_REL",
    10UL to "SHT_SHLIB",
    11UL to "SHT_DYNSYM",
    14UL to "SHT_INIT_ARRAY",
    15UL to "SHT_FINI_ARRAY",
    16UL to "SHT_PREINIT_ARRAY",
    17UL to "SHT_GROUP",
    18UL to "SHT_SYMTAB_SHNDX",
    0x6ffffff6UL to "SHT_GNU_HASH",
    0x6ffffffdUL to "SHT_GNU_VERDEF",
    0x6ffffffeUL to "SHT_GNU_VERNEED",
    0x6fffffffUL to "SHT_GNU_VERSYM",
)

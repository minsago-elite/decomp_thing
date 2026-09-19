package decompengine.binary

import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.TimeUnit

/** Host ceilings for positional metadata inspection, independent of the artifact's file size. */
internal data class BoundedElfMetadataLimits(
    val maximumInputBytes: Long = 1024L * 1024 * 1024,
    /** Maximum table count; extended-count and linked-table lookups allow two extra visits. */
    val maximumSectionHeaders: Int = 131_072,
    val maximumScannedSymbols: Long = 2_000_000,
    val maximumRetainedSymbols: Int = 100_000,
    val maximumNameBytes: Int = 16 * 1024,
    val maximumNameByteVisits: Long = 64L * 1024 * 1024,
    val maximumRetainedNameBytes: Long = 16L * 1024 * 1024,
    val maximumModeledMetadataBytes: Long = 64L * 1024 * 1024,
    val maximumMetadataReadBytes: Long = 256L * 1024 * 1024,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumWallClockMillis: Long = 600_000,
) {
    init {
        require(maximumInputBytes in 1L..1024L * 1024 * 1024)
        require(maximumSectionHeaders in 1..131_072)
        require(maximumScannedSymbols in 1L..2_000_000L)
        require(maximumRetainedSymbols in 1..100_000)
        require(maximumNameBytes in 1..16 * 1024)
        require(maximumNameByteVisits in 1L..64L * 1024 * 1024)
        require(maximumRetainedNameBytes in 1L..16L * 1024 * 1024)
        require(maximumModeledMetadataBytes in MINIMUM_MODELED_METADATA_BYTES..64L * 1024 * 1024) {
            "ELF metadata memory limit cannot fit its fixed working set or exceeds the host ceiling"
        }
        require(maximumMetadataReadBytes in 1L..256L * 1024 * 1024)
        require(maximumWorkUnits in 1L..100_000_000L)
        require(maximumWallClockMillis in 1L..600_000L)
    }

    companion object {
        /** Includes fixed read/hash/native buffers and decoding scratch; not a whole-JVM RSS bound. */
        const val MINIMUM_MODELED_METADATA_BYTES: Long = 8L * 1024 * 1024
    }
}

internal class BoundedElfMetadataLimitException(message: String) : IllegalArgumentException(message)

internal data class BoundedElfMetadataUsage(
    val sectionHeadersVisited: Long,
    val symbolsScanned: Long,
    val symbolsRetained: Long,
    val nameBytesVisited: Long,
    val retainedNameBytes: Long,
    val modeledMetadataBytes: Long,
    /** Charges requested bytes, including cache hits, plus bytes fetched on cache refills. */
    val metadataReadBytes: Long,
    val workUnits: Long,
)

internal data class BoundedElfMetadataInspection(
    val metadata: ElfMetadata,
    val symbolInventory: SymbolInventory,
    val inputBytes: Long,
    val inputSha256: String,
    val usage: BoundedElfMetadataUsage,
)

/** Header and first dynamic-symbol inventory, without loading the artifact or a string table. */
internal object BoundedElfMetadataReader {
    fun read(
        path: Path,
        limits: BoundedElfMetadataLimits = BoundedElfMetadataLimits(),
        checkpoint: (String) -> Unit = {},
    ): BoundedElfMetadataInspection {
        val budget = MetadataBudget(limits, checkpoint)
        budget.checkpoint("before opening ELF metadata input")
        try {
            return StableControlFile.openWithCheckpoint(
                path, limits.maximumInputBytes, "ELF metadata input", budget::checkpoint,
            ).use { file ->
                val (metadata, inventory) = MetadataParser(file, limits, budget).read()
                budget.checkpoint("before terminal ELF metadata verification")
                file.verifyUnchanged("ELF metadata input")
                budget.requireTime("before returning ELF metadata")
                BoundedElfMetadataInspection(
                    metadata, inventory, file.size, file.authenticatedSha256, budget.snapshot(),
                )
            }
        } catch (failure: FullTreeControlException) {
            // Initial authentication wraps callback failures after releasing its selected resources.
            val cause = failure.cause
            if (cause is BoundedElfMetadataLimitException) throw cause
            if (cause is InterruptedException) throw cause
            throw failure
        }
    }
}

private class MetadataParser(
    private val file: StableControlFile,
    private val limits: BoundedElfMetadataLimits,
    private val budget: MetadataBudget,
) {
    private val records = MetadataWindow(file, budget)
    private val names = MetadataWindow(file, budget)
    private val nameScratch = ByteArray(limits.maximumNameBytes)
    private var is64 = false
    private var order = ByteOrder.LITTLE_ENDIAN

    fun read(): Pair<ElfMetadata, SymbolInventory> {
        budget.step("ELF header")
        val header = records.bytes(0, minOf(64L, file.size).toInt())
        val metadata = ElfMetadataReader.read(header)
        is64 = metadata.format == "ELF64"
        order = if (metadata.endianness == "little") ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val buffer = ByteBuffer.wrap(header).order(order)
        val sectionOffset = if (is64) buffer.getLong(40).toULong() else buffer.getInt(32).toUInt().toULong()
        // Legacy authored headers may retain counts without a section table.
        if (sectionOffset == 0UL) return metadata to SymbolInventory.EMPTY
        val sectionEntryBytes = buffer.getShort(if (is64) 58 else 46).toUShort().toInt()
        if (sectionEntryBytes == 0) return metadata to SymbolInventory.EMPTY
        requireElf(sectionEntryBytes >= if (is64) 64 else 40, "section-header entry is too short")
        val tableStart = fileRange(sectionOffset, 0UL, "section-header table")
        val rawCount = metadata.sectionHeaderCount.toInt()
        val sectionCount = if (rawCount == 0) {
            val extended = section(tableStart).size
            if (extended == 0UL) return metadata to SymbolInventory.EMPTY
            budget.admitSectionCount(extended)
            extended.toInt()
        } else {
            budget.admitSectionCount(rawCount.toULong())
            rawCount
        }
        fileRange(sectionOffset, sectionCount.toULong() * sectionEntryBytes.toULong(), "section-header table")
        var dynamic: MetadataSection? = null
        for (index in 0 until sectionCount) {
            val candidate = section(tableStart + index.toLong() * sectionEntryBytes)
            if (candidate.type == 11L) {
                dynamic = candidate
                break
            }
        }
        val symbols = dynamic ?: return metadata to SymbolInventory.EMPTY
        requireElf(symbols.link < sectionCount.toLong(), "dynamic symbol string-table link is outside the section table")
        val strings = section(tableStart + symbols.link * sectionEntryBytes)
        requireElf(strings.type == 3L, "dynamic symbols do not reference a string table")
        requireElf(symbols.flags and 0x800UL == 0UL && strings.flags and 0x800UL == 0UL,
            "compressed dynamic metadata is unsupported")
        val symbolStart = fileRange(symbols.offset, symbols.size, "dynamic symbol table")
        val stringStart = fileRange(strings.offset, strings.size, "dynamic string table")
        val symbolBytes = if (is64) 24 else 16
        requireElf(symbols.entrySize >= symbolBytes.toULong() && symbols.size % symbols.entrySize == 0UL,
            "dynamic symbol entry size is invalid")
        val symbolCount = symbols.size / symbols.entrySize
        budget.admitSymbolCount(symbolCount)
        val functions = ArrayList<UnresolvedSymbol>()
        val objects = ArrayList<UnresolvedSymbol>()
        val other = ArrayList<UnresolvedSymbol>()
        for (index in 0 until symbolCount.toLong()) {
            budget.symbol()
            // The complete table range and count were admitted before narrowing unsigned offsets.
            val position = symbolStart + (index.toULong() * symbols.entrySize).toLong()
            val symbol = ByteBuffer.wrap(records.bytes(position, symbolBytes)).order(order)
            val nameOffset = symbol.getInt(0).toUInt().toLong()
            val info = symbol.get(if (is64) 4 else 12).toInt() and 0xff
            val sectionIndex = symbol.getShort(if (is64) 6 else 14).toUShort().toInt()
            if (sectionIndex != 0 || nameOffset == 0L) continue
            requireElf(nameOffset.toULong() < strings.size, "symbol name is outside its string table")
            val length = readName(stringStart + nameOffset, stringStart + strings.size.toLong())
            if (length == 0) continue
            budget.retain(length)
            val kind = when (info and 0xf) {
                2 -> SymbolKind.FUNCTION
                1 -> SymbolKind.OBJECT
                else -> SymbolKind.OTHER
            }
            val binding = when (info ushr 4) {
                0 -> SymbolBinding.LOCAL
                1 -> SymbolBinding.GLOBAL
                2 -> SymbolBinding.WEAK
                else -> SymbolBinding.UNKNOWN
            }
            val size = if (is64) symbol.getLong(16).toULong() else symbol.getInt(8).toUInt().toULong()
            val record = UnresolvedSymbol(String(nameScratch, 0, length, Charsets.UTF_8), kind, binding, size)
            when (kind) {
                SymbolKind.FUNCTION -> functions.add(record)
                SymbolKind.OBJECT -> objects.add(record)
                SymbolKind.OTHER -> other.add(record)
            }
        }
        budget.checkpoint("before copying ELF metadata inventory")
        return metadata to SymbolInventory(immutable(functions), immutable(objects), immutable(other))
    }

    private fun section(offset: Long): MetadataSection {
        budget.section()
        val bytes = records.bytes(offset, if (is64) 64 else 40)
        val buffer = ByteBuffer.wrap(bytes).order(order)
        fun word(position: Int): ULong = buffer.getInt(position).toUInt().toULong()
        return MetadataSection(
            type = word(4).toLong(),
            flags = if (is64) buffer.getLong(8).toULong() else word(8),
            offset = if (is64) buffer.getLong(24).toULong() else word(16),
            size = if (is64) buffer.getLong(32).toULong() else word(20),
            link = word(if (is64) 40 else 24).toLong(),
            entrySize = if (is64) buffer.getLong(56).toULong() else word(36),
        )
    }

    private fun readName(start: Long, end: Long): Int {
        var position = start
        var length = 0
        while (position < end) {
            budget.nameByte()
            val value = names.byte(position++)
            if (value == 0.toByte()) return length
            if (length == nameScratch.size) throw BoundedElfMetadataLimitException("ELF symbol name exceeds its byte limit")
            nameScratch[length++] = value
        }
        throw InvalidElfException("ELF symbol name is unterminated")
    }

    private fun fileRange(offset: ULong, length: ULong, subject: String): Long {
        val size = file.size.toULong()
        requireElf(offset <= size && length <= size - offset, "$subject is outside the admitted input")
        return offset.toLong()
    }

    private fun <T> immutable(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
}

private data class MetadataSection(
    val type: Long,
    val flags: ULong,
    val offset: ULong,
    val size: ULong,
    val link: Long,
    val entrySize: ULong,
)

private class MetadataWindow(private val file: StableControlFile, private val budget: MetadataBudget) {
    private var start = -1L
    private var contents = ByteArray(0)

    fun bytes(offset: Long, length: Int): ByteArray {
        requireRange(offset, length)
        budget.readBytes(length.toLong())
        if (length == 0) return ByteArray(0)
        load(offset, length)
        val index = (offset - start).toInt()
        return contents.copyOfRange(index, index + length)
    }

    fun byte(offset: Long): Byte {
        requireRange(offset, 1)
        budget.readBytes(1)
        load(offset, 1)
        return contents[(offset - start).toInt()]
    }

    private fun load(offset: Long, length: Int) {
        if (offset >= start && offset <= start + contents.size - length) return
        val count = minOf(METADATA_WINDOW_BYTES.toLong(), file.size - offset).toInt()
        budget.readBytes(count.toLong())
        budget.checkpoint("before filling ELF metadata window")
        contents = file.readExactly(offset, count, "ELF metadata window")
        start = offset
    }

    private fun requireRange(offset: Long, length: Int) {
        requireElf(length in 0..METADATA_WINDOW_BYTES && offset >= 0 && offset <= file.size - length,
            "metadata read is outside the admitted input")
    }
}

private class MetadataBudget(
    private val limits: BoundedElfMetadataLimits,
    private val callerCheckpoint: (String) -> Unit,
) {
    private val started = System.nanoTime()
    private val wallNanos = TimeUnit.MILLISECONDS.toNanos(limits.maximumWallClockMillis)
    private var sections = 0L
    private var scanned = 0L
    private var retained = 0L
    private var nameVisits = 0L
    private var retainedNames = 0L
    private var modeledBytes = BoundedElfMetadataLimits.MINIMUM_MODELED_METADATA_BYTES
    private var readBytes = 0L
    private var work = 0L

    fun checkpoint(subject: String) {
        requireTime(subject)
        callerCheckpoint(subject)
        requireTime(subject)
    }

    fun requireTime(subject: String) {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("ELF metadata inspection cancelled")
        val elapsed = System.nanoTime() - started
        if (elapsed < 0 || elapsed >= wallNanos) {
            throw BoundedElfMetadataLimitException("ELF metadata elapsed-time limit exceeded: $subject")
        }
    }

    fun step(subject: String) {
        work = charge(work, 1, limits.maximumWorkUnits, "parse work")
        if (work == 1L || work % 256L == 0L) checkpoint(subject)
    }

    fun admitSectionCount(count: ULong) {
        if (count > limits.maximumSectionHeaders.toULong()) {
            throw BoundedElfMetadataLimitException("ELF section count exceeds its limit")
        }
    }

    fun admitSymbolCount(count: ULong) {
        if (count > limits.maximumScannedSymbols.toULong()) {
            throw BoundedElfMetadataLimitException("ELF dynamic symbol count exceeds its limit")
        }
    }

    fun section() {
        sections = charge(sections, 1, limits.maximumSectionHeaders.toLong() + 2L, "section visits")
        step("ELF section headers")
    }

    fun symbol() {
        scanned = charge(scanned, 1, limits.maximumScannedSymbols, "symbol visits")
        step("ELF dynamic symbols")
    }

    fun nameByte() {
        nameVisits = charge(nameVisits, 1, limits.maximumNameByteVisits, "name-byte visits")
        step("ELF symbol names")
    }

    fun readBytes(count: Long) {
        readBytes = charge(readBytes, count, limits.maximumMetadataReadBytes, "metadata reads")
    }

    fun retain(nameBytes: Int) {
        retained = charge(retained, 1, limits.maximumRetainedSymbols.toLong(), "retained symbols")
        retainedNames = charge(retainedNames, nameBytes.toLong(), limits.maximumRetainedNameBytes, "retained name bytes")
        // Includes strings, records, growing lists, and the final defensive list copies.
        modeledBytes = charge(modeledBytes, 256L + 4L * nameBytes, limits.maximumModeledMetadataBytes, "modeled metadata bytes")
    }

    fun snapshot() = BoundedElfMetadataUsage(sections, scanned, retained, nameVisits,
        retainedNames, modeledBytes, readBytes, work)

    private fun charge(current: Long, count: Long, maximum: Long, subject: String): Long {
        if (count < 0 || current > maximum - count) {
            throw BoundedElfMetadataLimitException("ELF metadata $subject limit exceeded")
        }
        return current + count
    }
}

private fun requireElf(condition: Boolean, message: String) {
    if (!condition) throw InvalidElfException("ELF $message")
}

private const val METADATA_WINDOW_BYTES = 64 * 1024

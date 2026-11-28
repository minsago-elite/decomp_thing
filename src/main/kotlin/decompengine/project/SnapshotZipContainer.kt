package decompengine.project

import java.io.IOException
import java.io.InterruptedIOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.ClosedByInterruptException
import java.util.Arrays
import java.util.zip.ZipEntry
import org.apache.commons.compress.archivers.zip.ZipFile
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel

/** Directory identity to match against the JDK streaming extractor, in local-header order. */
internal data class SnapshotZipEntry(val name: String, val size: Long, val crc: Long) {
    fun matches(entry: ZipEntry): Boolean =
        name == entry.name && entry.method == ZipEntry.STORED && size == entry.size &&
            size == entry.compressedSize && crc == entry.crc
}

internal class SnapshotZipContainer(private val bytes: ByteArray) {
    private val fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

    private fun u16(at: Int) = fields.getShort(at).toInt() and 0xffff
    private fun u32(at: Int) = Integer.toUnsignedLong(fields.getInt(at))
    private fun u64(at: Int) = fields.getLong(at).also { require(it >= 0) }

    private data class Directory(val start: Int, val end: Int, val count: Long)

    private fun directory(): Directory {
        // Use the same backwards signature search as Commons, then require that its comment ends at EOF.
        val last = bytes.size - 22
        val end = (last downTo maxOf(0, last - 0xffff)).firstOrNull { u32(it) == END }
        require(end != null && bytes.size - end - 22 == u16(end + 20))
        val locator = end - 20
        val zip64 = locator >= 0 && u32(locator) == ZIP64_LOCATOR
        val disk = u16(end + 4)
        val directoryDisk = u16(end + 6)
        val diskEntries = u16(end + 8).toLong()
        var count = u16(end + 10).toLong()
        var length = u32(end + 12)
        var offset = u32(end + 16)
        var directoryEnd = end
        if (zip64) {
            require(u32(locator + 4) == 0L && u32(locator + 16) == 1L)
            directoryEnd = extent(0, u64(locator + 8), locator)
            extent(directoryEnd, 56, locator)
            require(u32(directoryEnd) == ZIP64_END && u64(directoryEnd + 4) == (locator - directoryEnd - 12).toLong())
            require(u32(directoryEnd + 16) == 0L && u32(directoryEnd + 20) == 0L)
            resolved(disk.toLong(), 0xffff, 0)
            resolved(directoryDisk.toLong(), 0xffff, 0)
            val total = u64(directoryEnd + 32)
            require(u64(directoryEnd + 24) == total)
            resolved(diskEntries, 0xffff, total)
            count = resolved(count, 0xffff, total)
            length = resolved(length, UINT_MAX, u64(directoryEnd + 40))
            offset = resolved(offset, UINT_MAX, u64(directoryEnd + 48))
        } else {
            require(disk == 0 && directoryDisk == 0 && diskEntries == count)
        }
        val start = extent(0, offset, directoryEnd)
        require(extent(start, length, directoryEnd) == directoryEnd)
        return Directory(start, directoryEnd, count)
    }

    /** Find the ZIP64 values while validating the framing of every extra, including unknown IDs. */
    private fun zip64Extra(start: Int, end: Int): Zip64Values {
        var cursor = start
        var values = Zip64Values(0, 0)
        while (cursor < end) {
            val data = extent(cursor, 4, end)
            val next = extent(data, u16(cursor + 2).toLong(), end)
            if (u16(cursor) == 1) values = Zip64Values(data, next)
            cursor = next
        }
        return values
    }

    private inner class Zip64Values(private var cursor: Int, private val end: Int) {
        fun longIfRequired(value: Long): Long {
            if (value != UINT_MAX) return value
            val next = extent(cursor, 8, end)
            return u64(cursor).also { cursor = next }
        }

        fun disk(value: Int): Long {
            if (value != 0xffff) return value.toLong()
            extent(cursor, 4, end)
            return u32(cursor)
        }

        fun localSizes(size: Long, compressed: Long): Pair<Long, Long> {
            if (size != UINT_MAX && compressed != UINT_MAX) return size to compressed
            // A local ZIP64 extra contains both sizes, including when just one header field needs it.
            extent(cursor, 16, end)
            val actualSize = if (size == UINT_MAX) u64(cursor) else size
            val actualCompressed = if (compressed == UINT_MAX) u64(cursor + 8) else compressed
            return actualSize to actualCompressed
        }
    }

    private data class Record(
        val local: Int, val nameStart: Int, val nameEnd: Int, val flags: Int, val size: Long, val crc: Long,
    )

    private fun records(directory: Directory, limits: ArchivalBundleLimits): List<Record> {
        require(directory.count <= limits.maximumEntries) { "snapshot ZIP directory exceeds the entry limit" }
        val records = mutableListOf<Record>()
        var cursor = directory.start
        var remaining = limits.maximumTotalBytes
        while (cursor < directory.end && records.size < directory.count) {
            val name = extent(cursor, 46, directory.end)
            require(u32(cursor) == CENTRAL_HEADER)
            val extra = extent(name, u16(cursor + 28).toLong(), directory.end)
            val comment = extent(extra, u16(cursor + 30).toLong(), directory.end)
            val values = zip64Extra(extra, comment)
            val size = values.longIfRequired(u32(cursor + 24))
            val compressed = values.longIfRequired(u32(cursor + 20))
            val local = extent(0, values.longIfRequired(u32(cursor + 42)), directory.start)
            require(values.disk(u16(cursor + 34)) == 0L)
            require(u16(cursor + 10) == ZipEntry.STORED && size == compressed)
            require(size <= limits.maximumFileBytes && size <= remaining)
            remaining -= size
            val crc = u32(cursor + 16)
            require(size != 0L || crc == 0L)
            records += Record(local, name, extra, u16(cursor + 8), size, crc)
            cursor = extent(comment, u16(cursor + 32).toLong(), directory.end)
        }
        require(records.size.toLong() == directory.count)
        // A directory may finish with a length-delimited digital signature.
        if (cursor < directory.end) {
            val data = extent(cursor, 6, directory.end)
            require(u32(cursor) == DIGITAL_SIGNATURE)
            cursor = extent(data, u16(cursor + 4).toLong(), directory.end)
        }
        require(cursor == directory.end)
        return records.sortedBy { it.local }
    }

    private fun localData(record: Record, limit: Int): Int {
        val at = record.local
        val name = extent(at, 30, limit)
        require(u32(at) == LOCAL_HEADER && u16(at + 6) == record.flags)
        require(u16(at + 8) == ZipEntry.STORED && u32(at + 14) == record.crc)
        val extra = extent(name, u16(at + 26).toLong(), limit)
        require(Arrays.equals(bytes, name, extra, bytes, record.nameStart, record.nameEnd))
        val data = extent(extra, u16(at + 28).toLong(), limit)
        val (size, compressed) = zip64Extra(extra, data).localSizes(u32(at + 22), u32(at + 18))
        require(size == record.size && compressed == record.size)
        return data
    }

    fun validate(limits: ArchivalBundleLimits): List<SnapshotZipEntry> {
        val directory = directory()
        val physical = records(directory, limits)
        var cursor = 0
        val dataOffsets = physical.map { record ->
            require(record.local == cursor)
            val data = localData(record, directory.start)
            cursor = extent(data, record.size, directory.start)
            data
        }
        require(cursor == directory.start)

        // Only open Commons once its chosen directory and actual record count have been bounded.
        try {
            SeekableInMemoryByteChannel(bytes).use { channel ->
                ZipFile.builder().setSeekableByteChannel(channel).setCharset(Charsets.UTF_8)
                    .setUseUnicodeExtraFields(false).setIgnoreLocalFileHeader(false).get().use { zip ->
                        val entries = zip.entriesInPhysicalOrder
                        val expected = physical.mapIndexed { index, record ->
                            require(entries.hasMoreElements())
                            val entry = entries.nextElement()
                            require(zip.canReadEntryData(entry) && entry.localHeaderOffset == record.local.toLong() &&
                                entry.dataOffset == dataOffsets[index].toLong() && entry.rawFlag == record.flags)
                            require(entry.method == ZipEntry.STORED && entry.size == record.size &&
                                entry.compressedSize == record.size && entry.crc == record.crc)
                            val raw = entry.rawName
                            require(Arrays.equals(bytes, record.nameStart, record.nameEnd, raw, 0, raw.size))
                            SnapshotZipEntry(entry.name, entry.size, entry.crc)
                        }
                        require(!entries.hasMoreElements())
                        return expected
                    }
            }
        } catch (failure: IOException) {
            if (failure is InterruptedIOException || failure is ClosedByInterruptException) throw failure
            throw IllegalArgumentException("invalid snapshot ZIP directory")
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("invalid snapshot ZIP directory")
        }
    }

    companion object {
        private const val UINT_MAX = 0xffff_ffffL
        private const val LOCAL_HEADER = 0x04034b50L
        private const val CENTRAL_HEADER = 0x02014b50L
        private const val DIGITAL_SIGNATURE = 0x05054b50L
        private const val END = 0x06054b50L
        private const val ZIP64_END = 0x06064b50L
        private const val ZIP64_LOCATOR = 0x07064b50L

        internal fun extent(start: Int, length: Long, limit: Int): Int {
            require(start in 0..limit && length in 0..(limit - start).toLong())
            return start + length.toInt()
        }

        private fun resolved(field: Long, sentinel: Long, value: Long): Long {
            require(field == sentinel || field == value)
            return value
        }
    }
}

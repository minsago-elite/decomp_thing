package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.provenance.BoundedTarXzSource
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Collections
import org.tukaani.xz.SeekableInputStream
import org.tukaani.xz.SeekableXZInputStream
import org.tukaani.xz.XZ

internal class GccSourceArchiveException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** The reviewed GCC POSIX/PAX profile is distinct from the existing LLVM Git-archive profile. */
internal data class GccSourceArchiveLimits(
    val maximumCompressedBytes: Long = 512L * 1024 * 1024,
    val maximumExpandedBytes: Long = 4L * 1024 * 1024 * 1024,
    val maximumDecoderMemoryKiB: Int = 256 * 1024,
    val maximumLogicalMembers: Int = 200_000,
    val maximumPaxHeaders: Int = 200_000,
    val maximumRawHeaders: Int = 400_000,
    val maximumPaxRecordBytes: Int = 1024 * 1024,
    val maximumTotalPaxBytes: Long = 32L * 1024 * 1024,
    val maximumEntryBytes: Long = 512L * 1024 * 1024,
    val maximumPathBytes: Int = 4096,
    val maximumComponentBytes: Int = 255,
    val maximumIndexBytes: Long = 64L * 1024 * 1024,
    val maximumSelectedBytes: Int = 1024 * 1024,
    val maximumWorkUnits: Long = 100_000_000,
) {
    init {
        require(maximumCompressedBytes in 1..512L * 1024 * 1024)
        require(maximumExpandedBytes in 1..4L * 1024 * 1024 * 1024)
        require(maximumDecoderMemoryKiB in 1..256 * 1024)
        require(maximumLogicalMembers in 1..200_000 && maximumPaxHeaders in 1..200_000)
        require(maximumRawHeaders in 1..400_000)
        require(maximumPaxRecordBytes in 1..1024 * 1024)
        require(maximumTotalPaxBytes in 1..32L * 1024 * 1024)
        require(maximumEntryBytes in 1..512L * 1024 * 1024)
        require(maximumPathBytes in 1..4096 && maximumComponentBytes in 1..255)
        require(maximumIndexBytes in 1..64L * 1024 * 1024)
        require(maximumSelectedBytes in 0..1024 * 1024)
        require(maximumWorkUnits in 1..100_000_000)
    }
}

internal class GccSourceArchiveContent(bytes: ByteArray) {
    private val stored = bytes.copyOf()
    val bytes: ByteArray get() = stored.copyOf()
    val size: Int get() = stored.size
    val sha256: String = OracleArtifacts.sha256(stored)
}

internal class GccSourceArchiveSummary internal constructor(
    val expandedBytes: Long,
    val logicalMembers: Int,
    val regularFiles: Int,
    val directories: Int,
    val paxHeaders: Int,
    val rawHeaders: Int,
    val paxPayloadBytes: Long,
    val maximumPaxPayloadBytes: Int,
    val paxPathOverrides: Int,
    val paxLongPathOverrides: Int,
    val paxUtf8PathOverrides: Int,
    val indexBytesCharged: Long,
    val workUnitsCharged: Long,
    selected: Map<String, GccSourceArchiveContent>,
) {
    val selected: Map<String, GccSourceArchiveContent> = Collections.unmodifiableMap(LinkedHashMap(selected))
}

/**
 * Scans the exact GCC release's USTAR envelopes with one local PAX record per logical member.
 * Only mtime/atime/ctime and the necessary long path are supported. No extraction or source
 * ownership follows from this structural scan; the caller separately authenticates the bytes.
 */
internal object GccSourceArchive {
    private val timestamp = Regex("[1-9][0-9]{0,9}\\.[0-9]{1,9}")
    // The only non-ASCII names in the exact reviewed release. Strict UTF-8 makes
    // equality byte-exact; no Unicode normalization, replacement or case folding occurs.
    private val utf8RelativePaths = setOf(
        "gcc/testsuite/gdc.test/runnable/imports/你好.d",
        "gcc/testsuite/go.test/test/fixedbugs/issue27836.dir/Äfoo.go",
        "gcc/testsuite/go.test/test/fixedbugs/issue27836.dir/Ämain.go",
    )

    fun scan(
        source: BoundedTarXzSource,
        expectedRoot: String,
        selectedRegularPaths: Set<String>,
        limits: GccSourceArchiveLimits = GccSourceArchiveLimits(),
        checkpoint: () -> Unit = {},
    ): GccSourceArchiveSummary {
        require(expectedRoot.isNotEmpty() && expectedRoot.length <= limits.maximumComponentBytes &&
            expectedRoot.all { it.code in 33..126 && it != '/' && it != '\\' } && expectedRoot !in setOf(".", ".."))
        require(selectedRegularPaths.size <= 32)
        selectedRegularPaths.forEach { canonical(it, false, expectedRoot, limits) }
        require(source.size in 12..limits.maximumCompressedBytes) { "GCC source compressed bytes exceed their bound" }
        val input = GccSourceSeekableInput(source, checkpoint)
        val footer = ByteArray(2)
        input.seek(source.size - 2)
        var footerRead = 0
        while (footerRead < footer.size) {
            val count = input.read(footer, footerRead, footer.size - footerRead)
            require(count > 0) { "GCC source XZ footer is truncated" }
            footerRead += count
        }
        require(footer.contentEquals(byteArrayOf(89, 90))) {
            "GCC source has XZ padding or trailing data"
        }
        input.seek(0)
        val xz = try { SeekableXZInputStream(input, limits.maximumDecoderMemoryKiB) } catch (failure: Exception) {
            throw GccSourceArchiveException("cannot open bounded GCC source XZ", failure)
        }
        try {
            require(xz.streamCount == 1 && xz.checkTypes == 1 shl XZ.CHECK_CRC64) {
                "GCC source must use one CRC64 XZ stream"
            }
            require(xz.length() in 1..limits.maximumExpandedBytes) { "GCC source expanded bytes exceed their bound" }
            xz.seek(0)
            return Scanner(xz, expectedRoot, selectedRegularPaths, limits, checkpoint).scan()
        } catch (failure: GccSourceArchiveException) {
            throw failure
        } catch (failure: Exception) {
            throw GccSourceArchiveException("invalid bounded GCC source archive", failure)
        } finally {
            xz.close(false) // The source owner retains its descriptor.
        }
    }

    private class Scanner(
        private val input: InputStream,
        private val root: String,
        private val wanted: Set<String>,
        private val limits: GccSourceArchiveLimits,
        private val checkpoint: () -> Unit,
    ) {
        private var expanded = 0L
        private var work = 0L
        private var rawHeaders = 0
        private var paxHeaders = 0
        private var totalPax = 0L
        private var largestPax = 0
        private var pathOverrides = 0
        private var longPathOverrides = 0
        private var utf8PathOverrides = 0
        private var members = 0
        private var regular = 0
        private var directories = 0
        private var indexBytes = 0L
        private var selectedBytes = 0L
        private val entries = HashMap<String, Boolean>() // true is a directory; no links are accepted.
        private val selected = linkedMapOf<String, GccSourceArchiveContent>()
        private val transfer = ByteArray(64 * 1024)

        fun scan(): GccSourceArchiveSummary {
            while (true) {
                val pax = block()
                if (pax.all { it == 0.toByte() }) {
                    var zeroBlocks = 1
                    while (true) {
                        val next = blockOrNull() ?: break
                        require(next.all { it == 0.toByte() }) { "nonzero data follows GCC tar terminator" }
                        zeroBlocks++
                        require(zeroBlocks <= 21) { "GCC tar padding exceeds one record" }
                    }
                    require(zeroBlocks >= 2 && expanded % 10240L == 0L) { "noncanonical GCC tar termination" }
                    break
                }
                countHeader()
                val p = header(pax, metadata = true)
                require(++paxHeaders <= limits.maximumPaxHeaders) { "GCC PAX header count exceeds its bound" }
                require(p.size in 1..limits.maximumPaxRecordBytes.toLong()) { "GCC PAX record exceeds its resident bound" }
                totalPax = add(totalPax, p.size, limits.maximumTotalPaxBytes, "aggregate PAX payload")
                largestPax = maxOf(largestPax, p.size.toInt())
                val fields = parsePax(payload(p.size.toInt()))
                if ("path" in fields) pathOverrides++
                padding(p.size)
                val logical = block()
                countHeader()
                val h = header(logical, metadata = false)
                require(++members <= limits.maximumLogicalMembers) { "GCC logical member count exceeds its bound" }
                val directory = h.kind == '5'
                val path = fields["path"] ?: h.name
                val pathBytes = path.toByteArray(UTF_8)
                charge(pathBytes.size.toLong())
                require(h.name.toByteArray(UTF_8).contentEquals(pathBytes.copyOf(minOf(100, pathBytes.size)))) {
                    "GCC PAX path does not bind the following USTAR name"
                }
                require(("path" in fields) == (pathBytes.size > 100 || path.any { it.code > 127 })) {
                    "GCC PAX path override does not match the closed name profile"
                }
                val canonical = canonical(path, directory, root, limits)
                if (pathBytes.size > 100) longPathOverrides++
                if (path.any { it.code > 127 }) utf8PathOverrides++
                val parent = canonical.substringBeforeLast('/', ".")
                val base = canonical.substringAfterLast('/')
                val envelope = "$parent/PaxHeaders/$base".toByteArray(UTF_8)
                require(p.name.toByteArray(UTF_8).contentEquals(envelope.copyOf(minOf(100, envelope.size)))) {
                    "GCC PAX envelope names another member"
                }
                val mtime = fields.getValue("mtime").substringBefore('.').toLong()
                require(h.mtime == mtime && p.mtime == mtime) { "GCC PAX modification time differs from its member" }
                require(h.size <= limits.maximumEntryBytes && (!directory || h.size == 0L)) {
                    "GCC logical member size exceeds its type or byte bound"
                }
                require(canonical !in entries) { "GCC source repeats a logical member" }
                if (members == 1) require(directory && canonical == root) { "GCC source must begin with its root directory" }
                else require(canonical != root && entries[parent] == true) { "GCC source member lacks its directory parent" }
                indexBytes = add(indexBytes, 96L + canonical.toByteArray(UTF_8).size, limits.maximumIndexBytes, "path index")
                entries[canonical] = directory
                if (directory) directories++ else {
                    regular++
                    if (canonical in wanted) {
                        selectedBytes = add(selectedBytes, h.size, limits.maximumSelectedBytes.toLong(), "selected content")
                        selected[canonical] = GccSourceArchiveContent(payload(h.size.toInt()))
                    } else discard(h.size)
                }
                padding(h.size)
            }
            require(entries[root] == true && selected.keys == wanted) { "GCC source lacks its root or locked regular contents" }
            checkpoint()
            return GccSourceArchiveSummary(expanded, members, regular, directories, paxHeaders, rawHeaders,
                totalPax, largestPax, pathOverrides, longPathOverrides, utf8PathOverrides, indexBytes, work, selected)
        }

        private fun countHeader() {
            require(++rawHeaders <= limits.maximumRawHeaders) { "GCC raw header count exceeds its bound" }
            charge(1)
        }

        private fun parsePax(bytes: ByteArray): Map<String, String> {
            charge(bytes.size.toLong())
            val result = linkedMapOf<String, String>()
            var cursor = 0
            while (cursor < bytes.size) {
                val start = cursor
                while (cursor < bytes.size && bytes[cursor] != 32.toByte()) cursor++
                require(cursor - start in 1..7 && cursor < bytes.size && bytes[start] != 48.toByte()) { "invalid GCC PAX length" }
                val lengthText = ascii(bytes, start, cursor - start)
                require(lengthText.all { it in '0'..'9' }) { "invalid GCC PAX length digits" }
                val length = requireNotNull(lengthText.toIntOrNull())
                require(length > cursor - start + 3 && length <= bytes.size - start) { "GCC PAX record length escapes its payload" }
                val end = start + length
                require(bytes[end - 1] == 10.toByte()) { "GCC PAX record has no newline" }
                // Bound both fields before materializing strings, including rejected records.
                val keyStart = cursor + 1
                var split = keyStart
                while (split < minOf(end - 1, keyStart + 6) && bytes[split] != 61.toByte()) split++
                require(split - keyStart in 1..5 && split < end - 1 && bytes[split] == 61.toByte()) {
                    "GCC PAX record has no bounded key separator"
                }
                val key = ascii(bytes, keyStart, split - keyStart)
                require(key in setOf("path", "mtime", "atime", "ctime") && key !in result) { "GCC PAX key is unsupported or duplicated" }
                val valueLength = end - split - 2
                require(valueLength in (if (key == "path") 1..limits.maximumPathBytes else 3..20)) {
                    "GCC PAX field exceeds its bound"
                }
                val value = if (key == "path") utf8(bytes, split + 1, valueLength) else ascii(bytes, split + 1, valueLength)
                if (key != "path") require(value.matches(timestamp) &&
                    value.substringBefore('.').toLong() <= 0x1ffffffffL) { "GCC PAX timestamp is not canonical" }
                result[key] = value
                cursor = end
            }
            require(result.keys.toList() == if ("path" in result) listOf("path", "mtime", "atime", "ctime")
                else listOf("mtime", "atime", "ctime")) { "GCC PAX fields are incomplete or out of order" }
            return result
        }

        private fun block(): ByteArray = blockOrNull() ?: throw GccSourceArchiveException("GCC tar stream is truncated")
        private fun blockOrNull(): ByteArray? {
            val result = ByteArray(512)
            val first = read(result, 0, result.size)
            if (first < 0) return null
            var position = first
            while (position < result.size) {
                val count = read(result, position, result.size - position)
                require(count > 0) { "GCC tar block is truncated" }
                position += count
            }
            return result
        }
        private fun payload(size: Int): ByteArray {
            val result = ByteArray(size)
            var position = 0
            while (position < size) {
                val count = read(result, position, minOf(size - position, transfer.size))
                require(count > 0) { "GCC tar payload is truncated" }
                position += count
            }
            return result
        }
        private fun discard(size: Long) {
            var remaining = size
            while (remaining > 0) {
                val count = read(transfer, 0, minOf(remaining, transfer.size.toLong()).toInt())
                require(count > 0) { "GCC tar payload is truncated" }
                remaining -= count
            }
        }
        private fun padding(size: Long) {
            val amount = ((512 - size % 512) % 512).toInt()
            require(payload(amount).all { it == 0.toByte() }) { "GCC tar payload padding is nonzero" }
        }
        private fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            checkpoint()
            charge(1)
            var count = input.read(bytes, offset, length)
            // XZ 1.12 returns zero once while transitioning its final block to EOF.
            // Permit exactly that transition, with the same work/deadline charging.
            if (count == 0 && length > 0) {
                checkpoint()
                charge(1)
                count = input.read(bytes, offset, length)
            }
            require(count != 0 || length == 0) { "GCC source decoder made no progress" }
            if (count > 0) expanded = add(expanded, count.toLong(), limits.maximumExpandedBytes, "expanded bytes")
            return count
        }
        private fun charge(amount: Long) { work = add(work, amount, limits.maximumWorkUnits, "work") }
    }

    private data class Header(val name: String, val kind: Char, val size: Long, val mtime: Long)
    private fun header(bytes: ByteArray, metadata: Boolean): Header {
        require(bytes.size == 512 && bytes.copyOfRange(257, 265).contentEquals("ustar\u000000".toByteArray(US_ASCII))) {
            "GCC source header is not its reviewed USTAR profile"
        }
        require(bytes.copyOfRange(329, 512).all { it == 0.toByte() }) { "GCC source header has device, prefix or reserved metadata" }
        require(text(bytes, 157, 100).isEmpty()) { "GCC source header carries a link" }
        require(bytes[154] == 0.toByte() && bytes[155] == 32.toByte()) { "GCC checksum encoding differs" }
        val checksum = ascii(bytes, 148, 6).also { require(it.all { c -> c in '0'..'7' }) }.toLong(8)
        val actual = bytes.indices.sumOf { if (it in 148..155) 32L else (bytes[it].toInt() and 255).toLong() }
        require(checksum == actual) { "GCC source header checksum differs" }
        val kind = (bytes[156].toInt() and 255).toChar()
        val mode = number(bytes, 100, 8)
        if (metadata) {
            require(kind == 'x' && mode == 0x1a4L && number(bytes, 108, 8) == 0L && number(bytes, 116, 8) == 0L &&
                text(bytes, 265, 32).isEmpty() && text(bytes, 297, 32).isEmpty()) { "GCC local PAX envelope differs" }
        } else {
            require(kind in setOf('0', '5') && number(bytes, 108, 8) == 1000L && number(bytes, 116, 8) == 100L &&
                text(bytes, 265, 32) == "rguenther" && text(bytes, 297, 32) == "users" &&
                (if (kind == '5') mode == 0x1edL else mode in setOf(0x1a4L, 0x1edL))) { "GCC logical member profile differs" }
        }
        return Header(text(bytes, 0, 100, name = true), kind, number(bytes, 124, 12), number(bytes, 136, 12))
    }
    private fun number(bytes: ByteArray, offset: Int, length: Int): Long {
        require(bytes[offset + length - 1] == 0.toByte()) { "GCC tar number has no NUL terminator" }
        val value = ascii(bytes, offset, length - 1)
        require(value.all { it in '0'..'7' }) { "GCC tar number is not fixed-width octal" }
        return requireNotNull(value.toLongOrNull(8))
    }
    private fun text(bytes: ByteArray, offset: Int, length: Int, name: Boolean = false): String {
        var end = offset
        while (end < offset + length && bytes[end] != 0.toByte()) end++
        require((end until offset + length).all { bytes[it] == 0.toByte() }) { "GCC tar text has bytes after its terminator" }
        return if (name) utf8(bytes, offset, end - offset) else ascii(bytes, offset, end - offset)
    }
    private fun utf8(bytes: ByteArray, offset: Int, length: Int): String = UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes, offset, length)).toString()
    private fun ascii(bytes: ByteArray, offset: Int, length: Int): String {
        require((offset until offset + length).all { (bytes[it].toInt() and 255) in 32..126 }) { "GCC metadata is not printable ASCII" }
        return String(bytes, offset, length, US_ASCII)
    }
    private fun canonical(path: String, directory: Boolean, root: String, limits: GccSourceArchiveLimits): String {
        require(path.isNotEmpty() && path.toByteArray(UTF_8).size <= limits.maximumPathBytes &&
            (path.all { it.code in 32..126 } || path.removePrefix("$root/") in utf8RelativePaths) &&
            '\\' !in path && !path.startsWith('/') && path.endsWith('/') == directory) { "GCC source path is not canonical" }
        val value = if (directory) path.dropLast(1) else path
        val parts = value.split('/')
        require(parts.first() == root && parts.size <= 64 && parts.all {
            it.isNotEmpty() && it !in setOf(".", "..") && it.toByteArray(UTF_8).size <= limits.maximumComponentBytes
        }) { "GCC source path escapes its root or component bounds" }
        return value
    }
    private fun add(value: Long, amount: Long, maximum: Long, label: String): Long {
        require(amount >= 0 && value <= maximum - amount) { "GCC source $label exceeds its bound" }
        return value + amount
    }
}

private class GccSourceSeekableInput(private val source: BoundedTarXzSource, private val checkpoint: () -> Unit) : SeekableInputStream() {
    private var cursor = 0L
    override fun length(): Long = source.size
    override fun position(): Long = cursor
    override fun seek(position: Long) { require(position in 0..source.size); cursor = position }
    override fun read(): Int { val byte = ByteArray(1); return if (read(byte, 0, 1) < 0) -1 else byte[0].toInt() and 255 }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        checkpoint()
        require(offset >= 0 && length >= 0 && offset <= bytes.size - length)
        if (length == 0) return 0
        if (cursor == source.size) return -1
        val requested = minOf(length.toLong(), source.size - cursor).toInt()
        val count = source.read(cursor, bytes, offset, requested)
        require(count in 1..requested) { "GCC archive positional source made invalid progress" }
        cursor += count
        return count
    }
    override fun close() = Unit
}

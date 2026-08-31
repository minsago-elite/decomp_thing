package decompengine.oracle.provenance

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZ
import org.tukaani.xz.XZOutputStream
import org.junit.jupiter.api.Assumptions.assumeTrue

class BoundedTarXzArchiveTest {
    @Test
    fun `optional frozen LLVM release matches the strict archive profile and locked markers`() {
        val configured = System.getenv("DECOMP_LLVM_SOURCE_ARCHIVE")
            ?.takeIf(String::isNotBlank)
            ?.let(Path::of)
        assumeTrue(configured != null && Files.isRegularFile(configured), "set DECOMP_LLVM_SOURCE_ARCHIVE")
        val archive = requireNotNull(configured)
        FileChannel.open(archive, StandardOpenOption.READ).use { channel ->
            val source = object : BoundedTarXzSource {
                override val size: Long = channel.size()

                override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
                    channel.read(ByteBuffer.wrap(destination, offset, length), position)
            }
            val selectedPaths = REAL_MARKERS.keys
            val summary = BoundedTarXzArchive.scan(source, ROOT, COMMIT, selectedRegularPaths = selectedPaths)
            assertEquals(2_161_858_560L, summary.expandedBytes)
            assertEquals(184_819, summary.memberCount)
            assertEquals(169_003, summary.regularFileCount)
            assertEquals(15_797, summary.directoryCount)
            assertEquals(19, summary.symbolicLinkCount)
            assertEquals(selectedPaths, summary.selected.keys)
            REAL_MARKERS.forEach { (path, identity) ->
                val marker = summary.selected.getValue(path)
                assertEquals(identity.first, marker.bytes.size)
                assertEquals(identity.second, marker.sha256)
            }
        }
    }

    @Test
    fun `strict archive scans deterministically and streams selected marker content`() {
        val tar = validTar()
        val archive = compress(tar)
        val firstEntries = mutableListOf<BoundedTarEntry>()
        val secondEntries = mutableListOf<BoundedTarEntry>()

        val first = scan(archive, selected = setOf(MARKER_PATH), onEntry = firstEntries::add)
        val second = scan(archive, selected = setOf(MARKER_PATH), onEntry = secondEntries::add)

        assertEquals(firstEntries, secondEntries)
        assertEquals(
            listOf(ROOT, "$ROOT/dir", TARGET_PATH, MARKER_PATH, "$ROOT/dir/link"),
            firstEntries.map(BoundedTarEntry::path),
        )
        assertEquals(5, first.memberCount)
        assertEquals(2, first.regularFileCount)
        assertEquals(2, first.directoryCount)
        assertEquals(1, first.symbolicLinkCount)
        assertEquals(tar.size.toLong(), first.expandedBytes)
        assertEquals(first.expandedBytes, second.expandedBytes)
        val marker = first.selected.getValue(MARKER_PATH)
        assertContentEquals(MARKER_BYTES, marker.bytes)
        assertEquals(sha256(MARKER_BYTES), marker.sha256)
        assertContentEquals(marker.bytes, second.selected.getValue(MARKER_PATH).bytes)
        assertEquals(marker.sha256, second.selected.getValue(MARKER_PATH).sha256)
    }

    @Test
    fun `regular payload visitor streams only selected entries and terminates each payload`() {
        val archive = compress(validTar())
        val chunks = linkedMapOf<String, ByteArrayOutputStream>()
        val endings = linkedMapOf<String, Int>()
        val visitor = object : BoundedTarXzRegularFileVisitor {
            override fun wants(entry: BoundedTarEntry): Boolean =
                entry.relativePath == "target" || entry.relativePath == "dir/marker.txt"

            override fun onChunk(
                entry: BoundedTarEntry,
                bytes: ByteArray,
                length: Int,
                endOfEntry: Boolean,
            ) {
                chunks.getOrPut(entry.path, ::ByteArrayOutputStream).write(bytes, 0, length)
                if (endOfEntry) endings[entry.path] = endings.getOrDefault(entry.path, 0) + 1
            }
        }

        BoundedTarXzArchive.scan(
            source = ByteArrayTarXzSource(archive),
            expectedRoot = ROOT,
            expectedCommit = COMMIT,
            regularFileVisitor = visitor,
        )

        assertContentEquals(TARGET_BYTES, chunks.getValue(TARGET_PATH).toByteArray())
        assertContentEquals(MARKER_BYTES, chunks.getValue(MARKER_PATH).toByteArray())
        assertEquals(mapOf(TARGET_PATH to 1, MARKER_PATH to 1), endings)
    }

    @Test
    fun `visitor mutation cannot corrupt a selected snapshot or its digest`() {
        val archive = compress(validTar())
        val visitor = object : BoundedTarXzRegularFileVisitor {
            override fun wants(entry: BoundedTarEntry): Boolean = entry.path == MARKER_PATH

            override fun onChunk(
                entry: BoundedTarEntry,
                bytes: ByteArray,
                length: Int,
                endOfEntry: Boolean,
            ) {
                if (length != 0) bytes[0] = (bytes[0].toInt() xor 0x7f).toByte()
            }
        }

        val summary = BoundedTarXzArchive.scan(
            source = ByteArrayTarXzSource(archive),
            expectedRoot = ROOT,
            expectedCommit = COMMIT,
            selectedRegularPaths = setOf(MARKER_PATH),
            regularFileVisitor = visitor,
        )

        val selected = summary.selected.getValue(MARKER_PATH)
        assertContentEquals(MARKER_BYTES, selected.bytes)
        assertEquals(sha256(MARKER_BYTES), selected.sha256)
    }

    @Test
    fun `XZ stream check trailing and decoder bounds fail closed`() {
        val tar = validTar()
        val valid = compress(tar)
        val corrupt = valid.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x40).toByte() }
        val trailingMagic = valid + byteArrayOf(0, 0, 'Y'.code.toByte(), 'Z'.code.toByte())
        listOf(
            compress(tar, XZ.CHECK_CRC32),
            valid + valid,
            valid + ByteArray(4),
            valid + byteArrayOf(1, 2, 3, 4),
            trailingMagic,
            corrupt,
        ).forEach(::assertRejected)

        assertRejected(valid, BoundedTarXzLimits(maximumCompressedBytes = valid.size.toLong() - 1L))
        assertRejected(valid, BoundedTarXzLimits(maximumExpandedBytes = tar.size.toLong() - 1L))
        assertRejected(valid, BoundedTarXzLimits(maximumDecoderMemoryKiB = 1))
    }

    @Test
    fun `global PAX and canonical USTAR envelope mutations fail closed`() {
        val wrongCommit = "0".repeat(40)
        val noPax = tar(defaultEntries, includePax = false)
        val secondPax = TarEntry("pax_global_header", 'g', PAX_BYTES, mode = 0x1b6)
        val wrongPaxName = tar(defaultEntries, paxName = "other_global_header")
        val wrongPaxPayload = tar(defaultEntries, paxCommit = wrongCommit)
        listOf(noPax, wrongPaxName, wrongPaxPayload, tar(listOf(secondPax) + defaultEntries)).forEach {
            assertRejected(compress(it))
        }
        assertRejected(compress(validTar()), BoundedTarXzLimits(maximumMetadataBytes = PAX_BYTES.size - 1))

        val checksum = validTar().copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val badMagic = mutateHeader(validTar(), ROOT_HEADER_BLOCK) { it[257] = 'X'.code.toByte() }
        val base256 = mutateHeader(validTar(), ROOT_HEADER_BLOCK) {
            it[100] = 0x80.toByte()
        }
        val noncanonicalOctal = mutateHeader(validTar(), ROOT_HEADER_BLOCK) {
            it[107] = ' '.code.toByte()
        }
        val posixChecksum = posixChecksumTerminator(validTar(), ROOT_HEADER_BLOCK)
        val nonzeroUid = mutateHeader(validTar(), ROOT_HEADER_BLOCK) { writeOctal(it, 108, 8, 1) }
        val nonRootOwner = mutateHeader(validTar(), ROOT_HEADER_BLOCK) {
            writeText(it, 265, 32, "nobody")
        }
        val reserved = mutateHeader(validTar(), ROOT_HEADER_BLOCK) { it[500] = 1 }
        listOf(checksum, badMagic, base256, noncanonicalOctal, posixChecksum, nonzeroUid, nonRootOwner, reserved).forEach {
            assertRejected(compress(it))
        }
    }

    @Test
    fun `member type mode path parent duplicate payload and terminator mutations fail closed`() {
        val root = directory(ROOT)
        val unsafeArchives = listOf(
            tar(listOf(regular(ROOT, byteArrayOf()))),
            tar(listOf(directory("wrong-root"))),
            tar(listOf(root, regular("$ROOT/missing/file", byteArrayOf(1)))),
            tar(listOf(root, regular("$ROOT/file", byteArrayOf(1)), regular("$ROOT/file", byteArrayOf(2)))),
            tar(listOf(root, TarEntry("$ROOT/unknown", '7', byteArrayOf()))),
            tar(listOf(root, TarEntry("$ROOT/nul", '\u0000', byteArrayOf()))),
            tar(listOf(root, regular("/$ROOT/file", byteArrayOf()))),
            tar(listOf(root, regular("$ROOT//file", byteArrayOf()))),
            tar(listOf(root, regular("$ROOT/./file", byteArrayOf()))),
            tar(listOf(root, regular("$ROOT/../file", byteArrayOf()))),
            tar(listOf(root, regular("$ROOT\\file", byteArrayOf()))),
            tar(listOf(root, TarEntry("$ROOT/dir", '5', byteArrayOf()))),
            tar(listOf(root, TarEntry("$ROOT/file/", '0', byteArrayOf()))),
            tar(listOf(root, TarEntry("$ROOT/dir/", '5', byteArrayOf(1)))),
            tar(listOf(root, TarEntry("$ROOT/file", '0', byteArrayOf(), link = "target"))),
            tar(listOf(root, TarEntry("$ROOT/file", '0', byteArrayOf(), mode = 0x1ff))),
            tar(defaultEntries, nonzeroPaddingPath = TARGET_PATH),
            tar(defaultEntries, terminatorBlocks = 0),
            tar(defaultEntries, terminatorBlocks = 1),
            tar(defaultEntries, terminatorBlocks = 2),
            tar(defaultEntries, tail = ByteArray(512).also { it[0] = 1 }),
            tar(defaultEntries, tail = ByteArray(512)),
            tar(defaultEntries, tail = byteArrayOf(0)),
        )
        unsafeArchives.forEach { assertRejected(compress(it)) }

        assertRejected(
            compress(validTar()),
            BoundedTarXzLimits(maximumMembers = 1),
        )
        assertRejected(
            compress(validTar()),
            BoundedTarXzLimits(maximumEntryBytes = TARGET_BYTES.size.toLong() - 1L),
        )
        assertRejected(
            compress(validTar()),
            BoundedTarXzLimits(maximumIndexBytes = 1),
        )
        assertRejected(
            compress(validTar()),
            BoundedTarXzLimits(maximumPathBytes = ROOT.length + 1),
        )
        val longComponent = "x".repeat(ROOT.length + 1)
        assertRejected(
            compress(tar(listOf(root, directory("$ROOT/$longComponent/")))),
            BoundedTarXzLimits(maximumComponentBytes = ROOT.length),
        )
    }

    @Test
    fun `symbolic links must resolve within root without dangling cycles or unsafe prefixes`() {
        val root = directory(ROOT)
        val unsafe = listOf(
            tar(listOf(root, symlink("$ROOT/link", "/target"))),
            tar(listOf(root, directory("$ROOT/dir/"), symlink("$ROOT/dir/link", "../../target"))),
            tar(listOf(root, symlink("$ROOT/link", "missing"))),
            tar(listOf(root, symlink("$ROOT/a", "b"), symlink("$ROOT/b", "a"))),
            tar(
                listOf(
                    root,
                    regular("$ROOT/file", TARGET_BYTES),
                    symlink("$ROOT/link", "file/child"),
                ),
            ),
            tar(listOf(root, regular(TARGET_PATH, TARGET_BYTES), symlink("$ROOT/link", "./target"))),
            tar(listOf(root, regular(TARGET_PATH, TARGET_BYTES), symlink("$ROOT/link", "target/"))),
            tar(listOf(root, regular(TARGET_PATH, TARGET_BYTES), symlink("$ROOT/link", "target\\child"))),
        )
        unsafe.forEach { assertRejected(compress(it)) }
        assertRejected(
            compress(validTar()),
            BoundedTarXzLimits(maximumLinkBytes = 3),
        )
    }

    @Test
    fun `selected marker and implementation hard bounds fail closed`() {
        val valid = compress(validTar())
        assertFailsWith<BoundedTarXzException> {
            scan(
                valid,
                limits = BoundedTarXzLimits(maximumSelectedBytes = MARKER_BYTES.size - 1),
                selected = setOf(MARKER_PATH),
            )
        }
        assertFailsWith<BoundedTarXzException> { scan(valid, selected = setOf("$ROOT/missing")) }
        assertFailsWith<BoundedTarXzException> { scan(valid, selected = setOf("$ROOT/dir")) }

        assertFailsWith<IllegalArgumentException> {
            BoundedTarXzLimits(maximumExpandedBytes = 8L * 1024L * 1024L * 1024L + 1L)
        }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumMembers = 200_001) }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumMetadataBytes = 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> {
            BoundedTarXzLimits(maximumEntryBytes = 512L * 1024L * 1024L + 1L)
        }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumPathBytes = 4097) }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumComponentBytes = 256) }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumLinkBytes = 256) }
        assertFailsWith<IllegalArgumentException> {
            BoundedTarXzLimits(maximumIndexBytes = 64L * 1024L * 1024L + 1L)
        }
        assertFailsWith<IllegalArgumentException> { BoundedTarXzLimits(maximumDecoderMemoryKiB = 256 * 1024 + 1) }
    }

    private fun scan(
        archive: ByteArray,
        limits: BoundedTarXzLimits = BoundedTarXzLimits(),
        selected: Set<String> = emptySet(),
        onEntry: (BoundedTarEntry) -> Unit = {},
    ): BoundedTarXzSummary = BoundedTarXzArchive.scan(
        source = ByteArrayTarXzSource(archive),
        expectedRoot = ROOT,
        expectedCommit = COMMIT,
        limits = limits,
        selectedRegularPaths = selected,
        onEntry = onEntry,
    )

    private fun assertRejected(
        archive: ByteArray,
        limits: BoundedTarXzLimits = BoundedTarXzLimits(),
    ) {
        assertFailsWith<BoundedTarXzException> { scan(archive, limits) }
    }

    private fun validTar(): ByteArray = tar(defaultEntries)

    private val defaultEntries: List<TarEntry>
        get() = listOf(
            directory(ROOT),
            directory("$ROOT/dir/"),
            regular(TARGET_PATH, TARGET_BYTES),
            regular(MARKER_PATH, MARKER_BYTES),
            symlink("$ROOT/dir/link", "../target"),
        )

    private fun tar(
        entries: List<TarEntry>,
        includePax: Boolean = true,
        paxName: String = "pax_global_header",
        paxCommit: String = COMMIT,
        nonzeroPaddingPath: String? = null,
        terminatorBlocks: Int? = null,
        tail: ByteArray = byteArrayOf(),
    ): ByteArray {
        val output = ByteArrayOutputStream()
        if (includePax) {
            val payload = "52 comment=$paxCommit\n".toByteArray(StandardCharsets.US_ASCII)
            writeEntry(output, TarEntry(paxName, 'g', payload, mode = 0x1b6), null)
        }
        entries.forEach { entry -> writeEntry(output, entry, nonzeroPaddingPath) }
        val blocksBeforeTerminator = output.size() / TAR_BLOCK_BYTES
        val recordRemainder = blocksBeforeTerminator % TAR_RECORD_BLOCKS
        val canonicalTerminatorBlocks = (TAR_RECORD_BLOCKS - recordRemainder).let { if (it < 2) it + TAR_RECORD_BLOCKS else it }
        repeat(terminatorBlocks ?: canonicalTerminatorBlocks) { output.write(ByteArray(TAR_BLOCK_BYTES)) }
        output.write(tail)
        return output.toByteArray()
    }

    private fun writeEntry(output: ByteArrayOutputStream, entry: TarEntry, nonzeroPaddingPath: String?) {
        output.write(header(entry))
        output.write(entry.data)
        val padding = (TAR_BLOCK_BYTES - entry.data.size % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES
        if (padding != 0) {
            val bytes = ByteArray(padding)
            if (entry.path == nonzeroPaddingPath) bytes[0] = 1
            output.write(bytes)
        }
    }

    private fun header(entry: TarEntry): ByteArray {
        val header = ByteArray(TAR_BLOCK_BYTES)
        val (name, prefix) = splitUstarPath(entry.path)
        writeText(header, 0, 100, name)
        writeOctal(header, 100, 8, entry.mode ?: defaultMode(entry.type))
        writeOctal(header, 108, 8, 0)
        writeOctal(header, 116, 8, 0)
        writeOctal(header, 124, 12, entry.data.size.toLong())
        writeOctal(header, 136, 12, 946_684_800L)
        repeat(8) { header[148 + it] = ' '.code.toByte() }
        header[156] = entry.type.code.toByte()
        writeText(header, 157, 100, entry.link)
        writeText(header, 257, 6, "ustar", terminate = true)
        writeText(header, 263, 2, "00", terminate = false)
        writeText(header, 265, 32, "root")
        writeText(header, 297, 32, "root")
        writeOctal(header, 329, 8, 0)
        writeOctal(header, 337, 8, 0)
        writeText(header, 345, 155, prefix)
        writeChecksum(header)
        return header
    }

    private fun mutateHeader(
        source: ByteArray,
        block: Int,
        mutation: (ByteArray) -> Unit,
    ): ByteArray {
        val result = source.copyOf()
        val offset = block * TAR_BLOCK_BYTES
        val header = result.copyOfRange(offset, offset + TAR_BLOCK_BYTES)
        mutation(header)
        writeChecksum(header)
        header.copyInto(result, offset)
        return result
    }

    private fun posixChecksumTerminator(source: ByteArray, block: Int): ByteArray {
        val result = source.copyOf()
        val offset = block * TAR_BLOCK_BYTES + 148
        val value = result.copyOfRange(offset, offset + 7)
            .toString(StandardCharsets.US_ASCII)
            .toLong(8)
            .toString(8)
            .padStart(6, '0')
        value.toByteArray(StandardCharsets.US_ASCII).copyInto(result, offset)
        result[offset + 6] = 0
        result[offset + 7] = ' '.code.toByte()
        return result
    }

    private fun writeChecksum(header: ByteArray) {
        repeat(8) { header[148 + it] = ' '.code.toByte() }
        val checksum = header.sumOf { it.toInt() and 0xff }.toLong()
        writeOctal(header, 148, 8, checksum)
    }

    private fun writeOctal(header: ByteArray, offset: Int, length: Int, value: Number) {
        val encoded = value.toLong().toString(8).padStart(length - 1, '0')
        require(encoded.length == length - 1)
        encoded.toByteArray(StandardCharsets.US_ASCII).copyInto(header, offset)
        header[offset + length - 1] = 0
    }

    private fun writeText(
        header: ByteArray,
        offset: Int,
        length: Int,
        value: String,
        terminate: Boolean = true,
    ) {
        val encoded = value.toByteArray(StandardCharsets.US_ASCII)
        require(encoded.size <= length - if (terminate) 1 else 0)
        header.fill(0, offset, offset + length)
        encoded.copyInto(header, offset)
    }

    private fun splitUstarPath(path: String): Pair<String, String> {
        val encoded = path.toByteArray(StandardCharsets.US_ASCII)
        if (encoded.size <= 99) return path to ""
        val separator = path.indices.reversed().firstOrNull { index ->
            path[index] == '/' &&
                path.substring(0, index).toByteArray(StandardCharsets.US_ASCII).size <= 154 &&
                path.substring(index + 1).toByteArray(StandardCharsets.US_ASCII).size <= 99
        } ?: error("test path does not fit canonical USTAR")
        return path.substring(separator + 1) to path.substring(0, separator)
    }

    private fun compress(tar: ByteArray, checkType: Int = XZ.CHECK_CRC64): ByteArray {
        val output = ByteArrayOutputStream()
        XZOutputStream(output, LZMA2Options(1), checkType).use { it.write(tar) }
        return output.toByteArray()
    }

    private fun directory(path: String): TarEntry =
        TarEntry(if (path.endsWith('/')) path else "$path/", '5', byteArrayOf(), mode = 0x1fd)

    private fun regular(path: String, bytes: ByteArray): TarEntry = TarEntry(path, '0', bytes, mode = 0x1b4)

    private fun symlink(path: String, target: String): TarEntry =
        TarEntry(path, '2', byteArrayOf(), link = target, mode = 0x1ff)

    private fun defaultMode(type: Char): Int = when (type) {
        'g' -> 0x1b6
        '5' -> 0x1fd
        '2' -> 0x1ff
        else -> 0x1b4
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private data class TarEntry(
        val path: String,
        val type: Char,
        val data: ByteArray,
        val link: String = "",
        val mode: Int? = null,
    )

    private class ByteArrayTarXzSource(private val bytes: ByteArray) : BoundedTarXzSource {
        override val size: Long = bytes.size.toLong()

        override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
            if (position == size) return -1
            assertTrue(position in 0 until size)
            val count = minOf(length, bytes.size - position.toInt())
            bytes.copyInto(destination, offset, position.toInt(), position.toInt() + count)
            return count
        }
    }

    private companion object {
        const val TAR_BLOCK_BYTES = 512
        const val TAR_RECORD_BLOCKS = 20
        const val ROOT_HEADER_BLOCK = 2
        const val ROOT = "llvm-project-22.1.6.src"
        const val COMMIT = "fc4aad7b5db3fff421df9a9637605b9ca5667881"
        const val TARGET_PATH = "$ROOT/target"
        const val MARKER_PATH = "$ROOT/dir/marker.txt"
        val TARGET_BYTES = "target".toByteArray(StandardCharsets.US_ASCII)
        val MARKER_BYTES = "marker\n".toByteArray(StandardCharsets.US_ASCII)
        val PAX_BYTES = "52 comment=$COMMIT\n".toByteArray(StandardCharsets.US_ASCII)
        val REAL_MARKERS = linkedMapOf(
            "$ROOT/cmake/Modules/LLVMVersion.cmake" to
                (325 to "d4d0c96de203f7994decedf4d2024b1cf84abb0d140f7568d5324516e84af8ae"),
            "$ROOT/LICENSE.TXT" to
                (15_141 to "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee"),
            "$ROOT/clang/LICENSE.TXT" to
                (15_140 to "ebcd9bbf783a73d05c53ba4d586b8d5813dcdf3bbec50265860ccc885e606f47"),
        )
    }
}

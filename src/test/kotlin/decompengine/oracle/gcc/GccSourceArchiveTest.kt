package decompengine.oracle.gcc

import decompengine.oracle.provenance.BoundedTarXzSource
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import kotlin.test.*
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZ
import org.tukaani.xz.XZOutputStream

/** Compact authored GCC-format controls, separate from the actual signed-release qualification. */
class GccSourceArchiveTest {
    @Test
    fun `local PAX archive scans deterministically and retains immutable selected bytes`() {
        val raw = fixture()
        val encoded = compress(raw)
        var checkpoints = 0
        val first = scan(encoded, checkpoint = { checkpoints++ })
        val second = scan(encoded)
        assertEquals(3, first.logicalMembers)
        assertEquals(1, first.directories)
        assertEquals(2, first.regularFiles)
        assertEquals(3, first.paxHeaders)
        assertEquals(6, first.rawHeaders)
        assertEquals(raw.size.toLong(), first.expandedBytes)
        assertEquals(first.workUnitsCharged, second.workUnitsCharged)
        assertEquals(first.indexBytesCharged, second.indexBytesCharged)
        assertEquals(first.paxPayloadBytes, second.paxPayloadBytes)
        assertEquals(SELECTED, first.selected.keys)
        assertContentEquals(FIRST, first.selected.getValue(FILE_A).bytes)
        assertEquals(sha(FIRST), first.selected.getValue(FILE_A).sha256)
        first.selected.getValue(FILE_A).bytes.fill(0)
        assertContentEquals(FIRST, first.selected.getValue(FILE_A).bytes)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (first.selected as MutableMap<String, GccSourceArchiveContent>).clear()
        }
        encoded.fill(0)
        assertContentEquals(SECOND, first.selected.getValue(FILE_B).bytes)
        assertTrue(checkpoints > 10)
    }

    @Test
    fun `long PAX paths bind the exact hundred byte USTAR name and envelope`() {
        val longPath = "$ROOT/${"a".repeat(110)}"
        val pair = member(longPath, bytes = FIRST)
        val encoded = compress(tar(root(), pair))
        val result = scan(encoded, setOf(longPath))
        assertContentEquals(FIRST, result.selected.getValue(longPath).bytes)
        assertTrue(result.maximumPaxPayloadBytes > TIMES.sumOf { paxLine(it.first, it.second).size })
        assertRejected(compress(tar(root(), member(longPath, bytes = FIRST, headerName = longPath.take(99) + "z"))), setOf(longPath))
        assertRejected(compress(tar(root(), member(longPath, bytes = FIRST, envelopeName = "$ROOT/PaxHeaders/wrong"))), setOf(longPath))
        assertRejected(compress(tar(root(), member(longPath, bytes = FIRST, paxFields = TIMES))), setOf(longPath))
        val exactHundred = "$ROOT/${"b".repeat(100 - ROOT.length - 1)}"
        assertEquals(100, exactHundred.length)
        assertContentEquals(FIRST, scan(compress(tar(root(), member(exactHundred, bytes = FIRST))), setOf(exactHundred))
            .selected.getValue(exactHundred).bytes)
    }

    @Test
    fun `only the three exact UTF8 filenames retain PAX binding and byte counted bounds`() {
        val relativePaths = listOf("gcc/testsuite/gdc.test/runnable/imports/你好.d",
            "gcc/testsuite/go.test/test/fixedbugs/issue27836.dir/Äfoo.go",
            "gcc/testsuite/go.test/test/fixedbugs/issue27836.dir/Ämain.go")
        for (relative in relativePaths) {
            val path = "$ROOT/$relative"
            val encoded = compress(pathFixture(path))
            val result = scan(encoded, setOf(path))
            assertContentEquals(FIRST, result.selected.getValue(path).bytes)
            assertEquals(setOf(path), result.selected.keys)
            assertEquals(1, result.paxPathOverrides)
            val components = path.split('/')
            val canonicalPaths = (1..components.size).map { components.take(it).joinToString("/") }
            val expectedIndexBytes = canonicalPaths.sumOf { 96L + it.toByteArray(UTF_8).size }
            assertEquals(expectedIndexBytes, result.indexBytesCharged)
            val exact = GccSourceArchiveLimits(maximumPathBytes = path.toByteArray(UTF_8).size,
                maximumComponentBytes = components.maxOf { it.toByteArray(UTF_8).size },
                maximumPaxRecordBytes = defaultPax(path).size, maximumIndexBytes = expectedIndexBytes)
            assertContentEquals(FIRST, scan(encoded, setOf(path), exact).selected.getValue(path).bytes)
            for (limited in listOf(exact.copy(maximumPathBytes = exact.maximumPathBytes - 1),
                exact.copy(maximumComponentBytes = exact.maximumComponentBytes - 1),
                exact.copy(maximumPaxRecordBytes = exact.maximumPaxRecordBytes - 1),
                exact.copy(maximumIndexBytes = exact.maximumIndexBytes - 1))) {
                assertRejected(encoded, emptySet(), limited)
            }
            // These names fit in the USTAR field but still require the exact UTF-8 PAX path.
            assertTrue(path.toByteArray(UTF_8).size < 100)
            assertRejected(compress(pathFixture(path, member(path, bytes = FIRST, paxFields = TIMES))), emptySet())
            val malformedPax = defaultPax(path).also { bytes ->
                bytes[bytes.indexOfFirst { (it.toInt() and 255) >= 128 }] = 0xff.toByte()
            }
            assertRejected(compress(pathFixture(path, member(path, bytes = FIRST, paxPayload = malformedPax))), emptySet())
            for (offset in listOf(0, logicalHeaderOffset(defaultPax(path)))) {
                val malformedHeader = member(path, bytes = FIRST)
                val nameByte = (offset until offset + 100).first { (malformedHeader[it].toInt() and 255) >= 128 }
                malformedHeader[nameByte] = 0xff.toByte()
                checksum(malformedHeader, offset)
                assertRejected(compress(pathFixture(path, malformedHeader)), emptySet())
            }
            val nearby = if ('好' in path) path.replace('好', ('好'.code + 1).toChar()) else path.replace('Ä', 'Å')
            assertRejected(compress(pathFixture(nearby)), emptySet())
            if ('Ä' in path) {
                val decomposed = path.replace("Ä", "A\u0308")
                assertRejected(compress(pathFixture(decomposed)), emptySet())
            }
            val parent = path.substringBeforeLast('/')
            val wrongEnvelope = "$parent/PaxHeaders/${path.substringAfterLast('/').replace('.', '_')}"
            assertRejected(compress(pathFixture(path, member(path, bytes = FIRST, envelopeName = wrongEnvelope))), emptySet())
        }
    }

    @Test
    fun `unsafe duplicate missing parent and nonroot first members refuse`() {
        for (path in listOf("/$ROOT/a", "$ROOT/../a", "$ROOT/./a", "$ROOT//a", "$ROOT/a\\b", "elsewhere/a", "$ROOT/a/")) {
            assertRejected(compress(tar(root(), member(path, bytes = FIRST))), emptySet())
        }
        assertRejected(compress(tar(root(), member(FILE_A), member(FILE_A))), emptySet())
        assertRejected(compress(tar(root(), member("$ROOT/missing/child"))), emptySet())
        assertRejected(compress(tar(member(FILE_A))), emptySet())
        assertRejected(compress(tar(root(), member(FILE_A), member("$FILE_A/child"))), emptySet())
        assertRejected(compress(tar(root(), member(FILE_A))), setOf(FILE_B))
        assertRejected(compress(tar(root())), setOf(ROOT))
    }

    @Test
    fun `only reviewed regular directory and local PAX types and ownership metadata are accepted`() {
        for (kind in listOf('1', '2', '3', '4', '6', '7', 'g', 'x', 'L', '\u0000')) {
            assertRejected(compress(tar(root(), member(FILE_A, kind = kind))), emptySet())
        }
        assertRejected(compress(tar(root(), member("$ROOT/dir/", kind = '5', bytes = FIRST))), emptySet())
        assertRejected(compress(tar(root(), member(FILE_A, metadataKind = 'g'))), emptySet())
        // Repair the checksum so each refusal reaches the changed semantic header field.
        for ((offset, replacement) in listOf(108 to "0000000\u0000", 116 to "0000000\u0000", 265 to "other",
            297 to "other", 100 to "0000777\u0000", 157 to "target", 345 to "prefix")) {
            val pair = member(FILE_A)
            patchHeader(pair, logicalHeaderOffset(defaultPax(FILE_A)), offset, replacement.toByteArray(US_ASCII))
            assertRejected(compress(tar(root(), pair)), emptySet())
        }
        for ((offset, replacement) in listOf(108 to "0001750\u0000", 116 to "0000144\u0000", 265 to "rguenther", 297 to "users")) {
            val pair = member(FILE_A)
            patchHeader(pair, 0, offset, replacement.toByteArray(US_ASCII))
            assertRejected(compress(tar(root(), pair)), emptySet())
        }
    }

    @Test
    fun `PAX unknown duplicate absent and reordered fields refuse`() {
        val bad = listOf(
            TIMES + ("comment" to "unsupported"),
            TIMES + TIMES.first(),
            TIMES.dropLast(1),
            TIMES.reversed(),
            listOf("path" to FILE_A) + TIMES,
            listOf(TIMES[0], "mtime" to EPOCH_TEXT, TIMES[2]),
        )
        bad.forEach { fields -> assertRejected(compress(tar(root(), member(FILE_A, paxFields = fields))), emptySet()) }
        val longPath = "$ROOT/${"x".repeat(110)}"
        assertRejected(compress(tar(root(), member(longPath, paxFields = TIMES + ("path" to longPath)))), emptySet())
        val escaping = "$ROOT/../${"x".repeat(110)}"
        assertRejected(compress(tar(root(), member(escaping))), emptySet())
    }

    @Test
    fun `PAX lengths ascii timestamps and member modification time must agree`() {
        val valid = defaultPax(FILE_A)
        val corrupt = listOf(
            valid.copyOf().also { it[0] = '0'.code.toByte() },
            valid.copyOf().also { it[0] = '9'.code.toByte() },
            valid.copyOf().also { it[valid.lastIndex] = 'x'.code.toByte() },
            valid.copyOf().also { it[12] = 0xff.toByte() },
            valid + byteArrayOf(10),
            "3 a\n".toByteArray(),
        )
        corrupt.forEach { pax -> assertRejected(compress(tar(root(), member(FILE_A, paxPayload = pax))), emptySet()) }
        for (timestamp in listOf("0.1", "01.1", "1786090800", "1786090800.", "1786090800.1234567890",
            "-1.2", "1e9.2", "8589934592.1")) {
            assertRejected(compress(tar(root(), member(FILE_A, paxFields = listOf("mtime" to timestamp) + TIMES.drop(1)))), emptySet())
        }
        assertRejected(compress(tar(root(), member(FILE_A, logicalMtime = EPOCH + 1))), emptySet())
        assertRejected(compress(tar(root(), member(FILE_A, envelopeMtime = EPOCH + 1))), emptySet())
    }

    @Test
    fun `tar framing checksum numeric fields padding and terminator are strict`() {
        val pair = member(FILE_A, bytes = FIRST)
        val checksum = pair.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertRejected(compress(tar(root(), checksum)), emptySet())
        for ((offset, replacement) in listOf(257 to "ustar 00", 100 to "      0\u0000", 124 to "00000000003 ")) {
            val changed = pair.copyOf()
            patchHeader(changed, logicalHeaderOffset(defaultPax(FILE_A)), offset, replacement.toByteArray(US_ASCII))
            assertRejected(compress(tar(root(), changed)), emptySet())
        }
        val padded = pair.copyOf().also { it[512 + defaultPax(FILE_A).size] = 1 }
        assertRejected(compress(tar(root(), padded)), emptySet())
        val filePadding = pair.copyOf().also { it[logicalHeaderOffset(defaultPax(FILE_A)) + 512 + FIRST.size] = 1 }
        assertRejected(compress(tar(root(), filePadding)), emptySet())
        val raw = fixture()
        assertRejected(compress(raw.copyOf(raw.size - 1)))
        assertRejected(compress(raw + ByteArray(10240))) // More than one tar-record terminator padding.
        val nonzeroTail = raw.copyOf().also { it[it.lastIndex] = 1 }
        assertRejected(compress(nonzeroTail))
        assertRejected(compress(ByteArray(10240)), emptySet())
        assertRejected(compress(tar(header(ROOT + "/", '5', 0, metadata = false))), emptySet()) // Missing local PAX.
    }

    @Test
    fun `XZ corruption concatenation padding trailing garbage and alternate checksum refuse`() {
        val valid = compress(fixture())
        for (bytes in listOf(valid.copyOf(valid.size - 1), valid + byteArrayOf(0, 0, 0, 0),
            valid + valid, valid + byteArrayOf(1, 2, 3), valid.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() })) {
            assertRejected(bytes)
        }
        assertRejected(compress(fixture(), XZ.CHECK_CRC32))
        assertRejected(compress(fixture(), XZ.CHECK_NONE))
    }

    @Test
    fun `resident aggregate PAX and logical raw header counts enforce exact and one over bounds`() {
        val encoded = compress(fixture())
        val measured = scan(encoded)
        val exact = GccSourceArchiveLimits(maximumPaxRecordBytes = measured.maximumPaxPayloadBytes,
            maximumTotalPaxBytes = measured.paxPayloadBytes, maximumLogicalMembers = measured.logicalMembers,
            maximumPaxHeaders = measured.paxHeaders, maximumRawHeaders = measured.rawHeaders)
        assertEquals(measured.logicalMembers, scan(encoded, limits = exact).logicalMembers)
        listOf(exact.copy(maximumPaxRecordBytes = exact.maximumPaxRecordBytes - 1),
            exact.copy(maximumTotalPaxBytes = exact.maximumTotalPaxBytes - 1),
            exact.copy(maximumLogicalMembers = exact.maximumLogicalMembers - 1),
            exact.copy(maximumPaxHeaders = exact.maximumPaxHeaders - 1),
            exact.copy(maximumRawHeaders = exact.maximumRawHeaders - 1)).forEach { assertRejected(encoded, limits = it) }
    }

    @Test
    fun `index selected content work expanded compressed and entry limits retain exact boundaries`() {
        val raw = fixture()
        val encoded = compress(raw)
        val measured = scan(encoded)
        val selectedBytes = FIRST.size + SECOND.size
        val exact = GccSourceArchiveLimits(maximumCompressedBytes = encoded.size.toLong(), maximumExpandedBytes = raw.size.toLong(),
            maximumIndexBytes = measured.indexBytesCharged, maximumSelectedBytes = selectedBytes,
            maximumWorkUnits = measured.workUnitsCharged, maximumEntryBytes = SECOND.size.toLong())
        assertEquals(measured.workUnitsCharged, scan(encoded, limits = exact).workUnitsCharged)
        listOf(exact.copy(maximumCompressedBytes = exact.maximumCompressedBytes - 1),
            exact.copy(maximumExpandedBytes = exact.maximumExpandedBytes - 1),
            exact.copy(maximumIndexBytes = exact.maximumIndexBytes - 1),
            exact.copy(maximumSelectedBytes = exact.maximumSelectedBytes - 1),
            exact.copy(maximumWorkUnits = exact.maximumWorkUnits - 1),
            exact.copy(maximumEntryBytes = exact.maximumEntryBytes - 1)).forEach { assertRejected(encoded, limits = it) }
        assertTrue(scan(encoded, emptySet(), GccSourceArchiveLimits(maximumSelectedBytes = 0)).selected.isEmpty())
        assertRejected(encoded, limits = GccSourceArchiveLimits(maximumSelectedBytes = 0))
    }

    @Test
    fun `path component selected population and decoder memory bounds fail closed`() {
        val component = "a".repeat(110)
        val longPath = "$ROOT/$component"
        val encoded = compress(tar(root(), member(longPath, bytes = FIRST)))
        val exact = GccSourceArchiveLimits(maximumPathBytes = longPath.length, maximumComponentBytes = component.length)
        assertContentEquals(FIRST, scan(encoded, setOf(longPath), exact).selected.getValue(longPath).bytes)
        assertRejected(encoded, emptySet(), exact.copy(maximumPathBytes = exact.maximumPathBytes - 1))
        assertRejected(encoded, emptySet(), exact.copy(maximumComponentBytes = exact.maximumComponentBytes - 1))
        assertRejected(encoded, (0..32).mapTo(linkedSetOf()) { "$ROOT/file$it" })
        assertContentEquals(FIRST, scan(encoded, setOf(longPath), exact.copy(maximumDecoderMemoryKiB = 8192)).selected.getValue(longPath).bytes)
        assertRejected(encoded, setOf(longPath), exact.copy(maximumDecoderMemoryKiB = 1))
        assertFailsWith<IllegalArgumentException> { GccSourceArchiveLimits(maximumDecoderMemoryKiB = 0) }
        assertFailsWith<IllegalArgumentException> { GccSourceArchiveLimits(maximumRawHeaders = 400001) }
    }

    @Test
    fun `short positional reads remain valid while nonprogress and checkpoint cancellation refuse`() {
        val encoded = compress(fixture())
        val partial = object : BoundedTarXzSource {
            override val size = encoded.size.toLong()
            override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
                val count = minOf(length, 1, encoded.size - position.toInt())
                encoded.copyInto(destination, offset, position.toInt(), position.toInt() + count)
                return count
            }
        }
        assertContentEquals(FIRST, GccSourceArchive.scan(partial, ROOT, SELECTED).selected.getValue(FILE_A).bytes)
        val noProgress = object : BoundedTarXzSource {
            override val size = encoded.size.toLong()
            override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertFailsWith<IllegalArgumentException> { GccSourceArchive.scan(noProgress, ROOT, SELECTED) }
        var calls = 0
        assertFailsWith<IllegalArgumentException> {
            scan(encoded, checkpoint = { calls++; if (calls == 5) throw IllegalArgumentException("cancelled fixture") })
        }
        assertEquals(5, calls)
    }

    private fun scan(bytes: ByteArray, selected: Set<String> = SELECTED, limits: GccSourceArchiveLimits = GccSourceArchiveLimits(),
        checkpoint: () -> Unit = {}) = GccSourceArchive.scan(BytesSource(bytes), ROOT, selected, limits, checkpoint)
    private fun assertRejected(bytes: ByteArray, selected: Set<String> = SELECTED,
        limits: GccSourceArchiveLimits = GccSourceArchiveLimits()) {
        assertFailsWith<IllegalArgumentException> { scan(bytes, selected, limits) }
    }
    private fun fixture() = tar(root(), member(FILE_A, bytes = FIRST), member(FILE_B, bytes = SECOND))
    private fun root() = member("$ROOT/", kind = '5')
    private fun pathFixture(path: String, leaf: ByteArray = member(path, bytes = FIRST)): ByteArray {
        val components = path.split('/')
        val parents = (1 until components.size).map { member(components.take(it).joinToString("/") + "/", kind = '5') }
        return tar(*(parents + leaf).toTypedArray())
    }
    private fun defaultPax(path: String): ByteArray = pax((if (path.toByteArray(UTF_8).size > 100 || path.any { it.code > 127 })
        listOf("path" to path) else emptyList()) + TIMES)
    private fun pax(fields: List<Pair<String, String>>) = ByteArrayOutputStream().also { out ->
        fields.forEach { out.write(paxLine(it.first, it.second)) }
    }.toByteArray()
    private fun paxLine(key: String, value: String): ByteArray {
        val suffix = " $key=$value\n"
        val suffixBytes = suffix.toByteArray(UTF_8).size
        var length = suffixBytes + 1
        while (length != suffixBytes + length.toString().length) length = suffixBytes + length.toString().length
        return "$length$suffix".toByteArray(UTF_8)
    }
    private fun member(path: String, kind: Char = '0', bytes: ByteArray = byteArrayOf(),
        paxFields: List<Pair<String, String>>? = null, paxPayload: ByteArray? = null,
        headerName: String = path.take(100), envelopeName: String? = null, metadataKind: Char = 'x',
        logicalMtime: Long = EPOCH, envelopeMtime: Long = EPOCH): ByteArray {
        val canonical = if (kind == '5') path.removeSuffix("/") else path
        val parent = canonical.substringBeforeLast('/', ".")
        val base = canonical.substringAfterLast('/')
        val payload = paxPayload ?: paxFields?.let(::pax) ?: defaultPax(path)
        return ByteArrayOutputStream().also { out ->
            out.write(header(envelopeName ?: "$parent/PaxHeaders/$base".take(100), metadataKind,
                payload.size.toLong(), metadata = true, mtime = envelopeMtime))
            out.write(payload); out.write(ByteArray(padding(payload.size)))
            out.write(header(headerName, kind, bytes.size.toLong(), metadata = false, mtime = logicalMtime))
            out.write(bytes); out.write(ByteArray(padding(bytes.size)))
        }.toByteArray()
    }
    private fun logicalHeaderOffset(pax: ByteArray) = 512 + pax.size + padding(pax.size)
    private fun padding(size: Int) = (512 - size % 512) % 512
    private fun header(name: String, kind: Char, size: Long, metadata: Boolean, mtime: Long = EPOCH): ByteArray {
        val bytes = ByteArray(512)
        fun text(offset: Int, value: String) { value.toByteArray(UTF_8).copyInto(bytes, offset) }
        fun number(offset: Int, length: Int, value: Long) = text(offset, value.toString(8).padStart(length - 1, '0'))
        check(name.toByteArray(UTF_8).size <= 100)
        text(0, name); number(100, 8, if (metadata || kind != '5') 420 else 493)
        number(108, 8, if (metadata) 0 else 1000); number(116, 8, if (metadata) 0 else 100)
        number(124, 12, size); number(136, 12, mtime); bytes[156] = kind.code.toByte()
        text(257, "ustar\u000000")
        if (!metadata) { text(265, "rguenther"); text(297, "users") }
        checksum(bytes, 0)
        return bytes
    }
    private fun checksum(bytes: ByteArray, start: Int) {
        for (offset in 148..155) bytes[start + offset] = 32
        val sum = (start until start + 512).sumOf { bytes[it].toInt() and 255 }
        sum.toString(8).padStart(6, '0').toByteArray(US_ASCII).copyInto(bytes, start + 148)
        bytes[start + 154] = 0; bytes[start + 155] = 32
    }
    private fun patchHeader(bytes: ByteArray, headerOffset: Int, fieldOffset: Int, replacement: ByteArray) {
        replacement.copyInto(bytes, headerOffset + fieldOffset)
        checksum(bytes, headerOffset)
    }
    private fun tar(vararg members: ByteArray): ByteArray = ByteArrayOutputStream().also { out ->
        members.forEach(out::write)
        out.write(ByteArray(1024))
        val remaining = (10240 - out.size() % 10240) % 10240
        out.write(ByteArray(remaining))
    }.toByteArray()
    private fun compress(bytes: ByteArray, check: Int = XZ.CHECK_CRC64): ByteArray = ByteArrayOutputStream().also { out ->
        val options = LZMA2Options(1).also { it.dictSize = 64 * 1024 }
        XZOutputStream(out, options, check).use { it.write(bytes) }
    }.toByteArray()
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    private class BytesSource(private val bytes: ByteArray) : BoundedTarXzSource {
        override val size = bytes.size.toLong()
        override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
            if (position >= bytes.size) return -1
            val count = minOf(length, bytes.size - position.toInt())
            bytes.copyInto(destination, offset, position.toInt(), position.toInt() + count)
            return count
        }
    }
    companion object {
        private const val ROOT = "gcc-16.2.0"
        private const val FILE_A = "$ROOT/marker-a"
        private const val FILE_B = "$ROOT/marker-b"
        private const val EPOCH = 1786090800L
        private const val EPOCH_TEXT = "1786090800.734417531"
        private val TIMES = listOf("mtime" to EPOCH_TEXT, "atime" to "1786090803.900341753", "ctime" to "1786090803.899467497")
        private val FIRST = byteArrayOf(1, 2, 3)
        private val SECOND = byteArrayOf(4, 5, 6, 7, 8)
        private val SELECTED = setOf(FILE_A, FILE_B)
    }
}

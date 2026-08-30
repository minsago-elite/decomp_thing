package decompengine.oracle.fulltree

import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class FullTreeDwarfSupportTest {
    @Test
    fun `ULEB128 rejects tenth-byte overflow without rejecting maximum signed long`() {
        val overflow = ByteArray(10) { index -> if (index == 9) 0x02 else 0x80.toByte() }
        assertFailsWith<FullTreeControlException> {
            cursor(section(overflow)).readUleb128()
        }

        val maximum = ByteArray(9) { index -> if (index == 8) 0x7f else 0xff.toByte() }
        assertEquals(Long.MAX_VALUE, cursor(section(maximum)).readUleb128())
    }

    @Test
    fun `compilation-unit cursor remains bound to its section and range`() {
        val bytes = byteArrayOf(
            0x08, 0x00, 0x00, 0x00, // 32-bit unit length
            0x04, 0x00, // DWARF v4
            0x00, 0x00, 0x00, 0x00, // abbreviation offset
            0x08, // address size
            0x01, // first DIE abbreviation code
        )
        val info = section(bytes, ".debug_info")
        val header = FullTreeDwarfCompilationUnitHeaders(
            info,
            maximumUnits = 1L,
            parseBudget = FullTreeDwarfParseBudget(32L),
        ).next()

        val die = header.dieCursor(info)
        assertEquals(11L, die.position)
        assertEquals(12L, die.limit)
        assertEquals(1L, die.readUleb128())
        assertFailsWith<FullTreeControlException> { die.skip(1L) }

        val substituted = section(bytes.copyOf(), "substituted .debug_info")
        assertFailsWith<FullTreeControlException> { header.dieCursor(substituted) }

        val bounded = FullTreeDwarfSectionCursor(info, 4L, 10L, "bounded test cursor")
        bounded.narrowLimit(8L)
        assertEquals(8L, bounded.limit)
        assertFailsWith<FullTreeControlException> { bounded.narrowLimit(9L) }
        assertFailsWith<FullTreeControlException> { bounded.narrowLimit(3L) }
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfSectionCursor(info, 0L, info.size + 1L, "widened test cursor")
        }
    }

    @Test
    fun `abbreviation tables validate flags duplicates and exact-limit terminators`() {
        val exactLimits = FullTreeControlLimits(
            maximumAbbreviationDeclarationsPerUnit = 1,
            maximumAbbreviationAttributesPerUnit = 1,
        )
        val exact = byteArrayOf(
            0x01, 0x11, 0x01, // code, tag, has children
            0x03, 0x08, // one attribute
            0x00, 0x00, // attribute terminator after the exact maximum
            0x00, // table terminator after the exact maximum
        )
        val visited = ArrayList<FullTreeDwarfAbbreviationDeclaration>()
        FullTreeDwarfAbbreviations(
            section(exact, ".debug_abbrev exact limits"),
            0L,
            exactLimits,
            FullTreeDwarfParseBudget(32L),
        ).visit(visited::add)
        assertEquals(1, visited.size)
        assertEquals(1L, visited.single().code)
        assertEquals(1, visited.single().hasChildren)
        assertEquals(listOf(3L), visited.single().attributes.map { it.name })

        val invalidChildren = byteArrayOf(0x01, 0x11, 0x02, 0x00, 0x00, 0x00)
        assertFailsWith<FullTreeControlException> {
            abbreviations(invalidChildren).visit { }
        }

        val duplicate = byteArrayOf(
            0x01, 0x11, 0x00, 0x00, 0x00,
            0x01, 0x12, 0x01, 0x00, 0x00,
            0x00,
        )
        assertFailsWith<FullTreeControlException> {
            abbreviations(duplicate).required(1L)
        }
    }

    @Test
    fun `section callback and inline byte boundaries are defensive`() {
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfSection(
                size = 0L,
                byteOrder = ByteOrder.LITTLE_ENDIAN,
                label = "empty test section",
                readWindow = { _, _ -> ByteArray(0) },
            )
        }

        listOf(-1, 1).forEach { difference ->
            val malformed = FullTreeDwarfSection(
                size = 2L,
                byteOrder = ByteOrder.LITTLE_ENDIAN,
                label = "malformed callback section",
                readWindow = { _, requested -> ByteArray(requested + difference) },
            )
            assertFailsWith<FullTreeControlException> { malformed.byte(0L) }
        }

        val callbackFailure = FullTreeDwarfSection(
            size = 1L,
            byteOrder = ByteOrder.LITTLE_ENDIAN,
            label = "failing callback section",
            readWindow = { _, _ -> throw IllegalStateException("injected callback failure") },
        )
        val wrapped = assertFailsWith<FullTreeControlException> { callbackFailure.byte(0L) }
        assertIs<IllegalStateException>(wrapped.cause)

        val backing = byteArrayOf(1, 2)
        val copiedSection = FullTreeDwarfSection(
            size = backing.size.toLong(),
            byteOrder = ByteOrder.LITTLE_ENDIAN,
            label = "copied callback section",
            readWindow = { _, _ -> backing },
        )
        assertEquals(1, copiedSection.byte(0L))
        backing[1] = 9
        assertEquals(2, copiedSection.byte(1L))

        val source = "stable".toByteArray()
        val inline = FullTreeDwarfInlineStringValue(source)
        source[0] = 'X'.code.toByte()
        assertContentEquals("stable".toByteArray(), inline.bytes)
        val exposed = inline.bytes
        exposed[1] = 'X'.code.toByte()
        assertContentEquals("stable".toByteArray(), inline.bytes)
    }

    @Test
    fun `scratch absence fails first close while successful later closes are idempotent`(): Unit =
        inTemporaryDirectory { directory ->
            val missing = FullTreeDwarfScratch.create(directory)
            val missingRoot = onlyScratchRoot(directory)
            Files.delete(missingRoot)
            assertFailsWith<FullTreeControlException> { missing.close() }

            val idempotent = FullTreeDwarfScratch.create(directory)
            val idempotentRoot = onlyScratchRoot(directory)
            idempotent.createFile("idempotent test").use { channel ->
                assertTrue(channel.isOpen)
            }
            idempotent.close()
            assertFalse(Files.exists(idempotentRoot))
            idempotent.close()
        }

    private fun abbreviations(bytes: ByteArray) = FullTreeDwarfAbbreviations(
        section(bytes, ".debug_abbrev"),
        0L,
        FullTreeControlLimits(),
        FullTreeDwarfParseBudget(128L),
    )

    private fun cursor(section: FullTreeDwarfSection) = FullTreeDwarfSectionCursor(
        section,
        0L,
        section.size,
        "test cursor",
    )

    private fun section(bytes: ByteArray, label: String = "test section") = FullTreeDwarfSection(
        size = bytes.size.toLong(),
        byteOrder = ByteOrder.LITTLE_ENDIAN,
        label = label,
        readWindow = { offset, length ->
            bytes.copyOfRange(offset.toInt(), Math.addExact(offset.toInt(), length))
        },
    )

    private fun onlyScratchRoot(parent: Path): Path = Files.list(parent).use { paths ->
        paths.filter { it.fileName.toString().startsWith(".full-tree-inventory-scratch-") }
            .toList().single()
    }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val container = createTempDirectory("full-tree-dwarf-support-test-")
        val directory = Files.createDirectory(container.resolve("workspace"))
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return try {
            block(directory)
        } finally {
            val paths = Files.walk(container).use { it.toList() }
            paths.filter { Files.isDirectory(it) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}

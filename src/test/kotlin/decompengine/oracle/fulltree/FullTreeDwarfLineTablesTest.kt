package decompengine.oracle.fulltree

import java.io.ByteArrayOutputStream
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class FullTreeDwarfLineTablesTest {
    @Test
    fun `DWARF v2 uses one-based files comp-dir fallback and POSIX normalization`() {
        val prologue = legacyPrologue(
            version = 2,
            directories = listOf("/root/a/../b//", "include"),
            files = listOf(
                LegacyFile("main.cpp", 0),
                LegacyFile("./header.hpp", 1),
                LegacyFile("/absolute/file.cpp", 99),
            ),
        )
        val table = read(lineUnit(2, prologue))

        assertEquals(2, table.version)
        assertNull(table.resolveDeclarationPath(0, 2, "/build"))
        assertEquals(
            "/build/main.cpp",
            table.resolveDeclarationPath(1, 2, "/build/./objects/.."),
        )
        assertEquals("/root/b/header.hpp", table.resolveDeclarationPath(2, 2, "/unused"))
        assertEquals("/absolute/file.cpp", table.resolveDeclarationPath(3, 2, null))
        assertNull(table.resolveDeclarationPath(4, 2, "/build"))
        assertEquals("//server/root/main.cpp", table.resolveDeclarationPath(1, 2, "//server/root"))
    }

    @Test
    fun `DWARF v4 consumes maximum-operations field and keeps legacy indices`() {
        val table = read(
            lineUnit(
                4,
                legacyPrologue(
                    version = 4,
                    directories = listOf("relative/./source"),
                    files = listOf(LegacyFile("four.c", 1)),
                ),
            ),
        )

        assertEquals(4, table.version)
        assertEquals("relative/source/four.c", table.resolveDeclarationPath(1, 4, "/unused"))
    }

    @Test
    fun `DWARF v5 resolves zero-based line-strp and strp paths`() {
        val (lineStrings, directoryOffsets) = stringTable("/project/src", "relative/./include")
        val (strings, fileOffsets) = stringTable("zero.cpp", "nested.hpp", "/absolute/v5.cpp")
        val prologue = v5Prologue(
            directoryFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_LINE_STRP)),
            directories = directoryOffsets.map { offset -> entry { u32(offset) } },
            fileFormats = listOf(
                Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRP),
                Format(DW_LNCT_DIRECTORY_INDEX, FULL_TREE_DW_FORM_DATA1),
            ),
            files = listOf(
                entry { u32(fileOffsets[0]); u8(0) },
                entry { u32(fileOffsets[1]); u8(1) },
                entry { u32(fileOffsets[2]); u8(255) },
            ),
        )
        val table = read(
            lineUnit(5, prologue),
            strings = strings,
            lineStrings = lineStrings,
        )

        assertEquals("/project/src/zero.cpp", table.resolveDeclarationPath(0, 5, "/unused"))
        assertEquals("relative/include/nested.hpp", table.resolveDeclarationPath(1, 5, "/unused"))
        assertEquals("/absolute/v5.cpp", table.resolveDeclarationPath(2, 5, null))
        assertNull(table.resolveDeclarationPath(3, 5, "/unused"))
    }

    @Test
    fun `DWARF v5 safely resolves every standard strx width`() {
        val (strings, stringOffsets) = stringTable("indexed.cpp")
        val offsets = bytes {
            u32(0xfeedfaceL)
            u32(stringOffsets.single())
        }
        val forms = listOf(
            FULL_TREE_DW_FORM_STRX,
            FULL_TREE_DW_FORM_STRX1,
            FULL_TREE_DW_FORM_STRX2,
            FULL_TREE_DW_FORM_STRX3,
            FULL_TREE_DW_FORM_STRX4,
        )
        forms.forEach { form ->
            val encodedIndex = entry {
                when (form) {
                    FULL_TREE_DW_FORM_STRX -> uleb(0)
                    FULL_TREE_DW_FORM_STRX1 -> u8(0)
                    FULL_TREE_DW_FORM_STRX2 -> u16(0)
                    FULL_TREE_DW_FORM_STRX3 -> uint(0, 3)
                    FULL_TREE_DW_FORM_STRX4 -> u32(0)
                }
                uleb(0)
                repeat(16) { u8(it) }
            }
            val prologue = v5Prologue(
                directoryFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING)),
                directories = listOf(entry { string("/indexed") }),
                fileFormats = listOf(
                    Format(DW_LNCT_PATH, form),
                    Format(DW_LNCT_DIRECTORY_INDEX, FULL_TREE_DW_FORM_UDATA),
                    Format(DW_LNCT_MD5, FULL_TREE_DW_FORM_DATA16),
                ),
                files = listOf(encodedIndex),
            )
            val table = read(
                lineUnit(5, prologue),
                strings = strings,
                stringOffsets = offsets,
                stringOffsetsBase = 4,
            )
            assertEquals(
                "/indexed/indexed.cpp",
                table.resolveDeclarationPath(0, 5, "/unused"),
                "form 0x${form.toString(16)}",
            )
        }
    }

    @Test
    fun `missing v5 directory index returns null without hiding an absolute file`() {
        val prologue = v5Prologue(
            directoryFormats = emptyList(),
            directories = emptyList(),
            fileFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING)),
            files = listOf(
                entry { string("relative.cpp") },
                entry { string("/absolute.cpp") },
            ),
        )
        val table = read(lineUnit(5, prologue))

        assertNull(table.resolveDeclarationPath(0, 5, "/fallback-must-not-apply"))
        assertEquals("/absolute.cpp", table.resolveDeclarationPath(1, 5, null))
    }

    @Test
    fun `malformed v5 formats UTF-8 and entry bounds fail closed`() {
        val duplicate = v5Prologue(
            directoryFormats = listOf(
                Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING),
                Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING),
            ),
            directories = emptyList(),
            fileFormats = emptyList(),
            files = emptyList(),
        )
        assertFailsWith<FullTreeControlException> { read(lineUnit(5, duplicate)) }

        val unsupported = v5Prologue(
            directoryFormats = emptyList(),
            directories = emptyList(),
            fileFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_BLOCK1)),
            files = emptyList(),
        )
        assertFailsWith<FullTreeControlException> { read(lineUnit(5, unsupported)) }

        val malformedUtf8 = v5Prologue(
            directoryFormats = emptyList(),
            directories = emptyList(),
            fileFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING)),
            files = listOf(byteArrayOf(0xc3.toByte(), 0x28, 0)),
        )
        assertFailsWith<FullTreeControlException> { read(lineUnit(5, malformedUtf8)) }

        val tooMany = v5Prologue(
            directoryFormats = listOf(Format(DW_LNCT_PATH, FULL_TREE_DW_FORM_STRING)),
            directories = listOf(entry { string("one") }, entry { string("two") }),
            fileFormats = emptyList(),
            files = emptyList(),
        )
        assertFailsWith<FullTreeControlException> {
            read(
                lineUnit(5, tooMany),
                limits = FullTreeDwarfLineTableLimits(maximumDirectories = 1),
            )
        }
    }

    @Test
    fun `truncated headers format mismatches and aggregate path bounds fail closed`() {
        val valid = lineUnit(
            2,
            legacyPrologue(
                version = 2,
                directories = listOf("directory"),
                files = listOf(LegacyFile("file.c", 1)),
            ),
        )
        assertFailsWith<FullTreeControlException> { read(valid.copyOf(valid.size - 1)) }
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfLineTables.read(
                FullTreeDwarfLineTableSections(section(valid, ".debug_line")),
                statementListOffset = 0,
                compilationUnitOffsetSize = 8,
                stringOffsetsBase = null,
                parseBudget = FullTreeDwarfParseBudget(100),
            )
        }
        assertFailsWith<FullTreeControlException> {
            read(
                valid,
                limits = FullTreeDwarfLineTableLimits(maximumAggregatePathBytes = 4),
            )
        }
        assertFailsWith<FullTreeControlException> {
            read(
                valid,
                limits = FullTreeDwarfLineTableLimits(maximumParseSteps = 1),
            )
        }

        val empty = lineUnit(2, legacyPrologue(version = 2, directories = emptyList(), files = emptyList()))
        val aggregate = FullTreeDwarfParseBudget(11)
        read(empty, parseBudget = aggregate)
        assertFailsWith<FullTreeControlException> { read(empty, parseBudget = aggregate) }
    }

    private fun read(
        line: ByteArray,
        strings: ByteArray? = null,
        lineStrings: ByteArray? = null,
        stringOffsets: ByteArray? = null,
        stringOffsetsBase: Long? = null,
        limits: FullTreeDwarfLineTableLimits = FullTreeDwarfLineTableLimits(),
        parseBudget: FullTreeDwarfParseBudget = FullTreeDwarfParseBudget(limits.maximumParseSteps),
    ): FullTreeDwarfLineTable = FullTreeDwarfLineTables.read(
        FullTreeDwarfLineTableSections(
            line = section(line, ".debug_line"),
            strings = strings?.let { section(it, ".debug_str") },
            lineStrings = lineStrings?.let { section(it, ".debug_line_str") },
            stringOffsets = stringOffsets?.let { section(it, ".debug_str_offsets") },
        ),
        statementListOffset = 0,
        compilationUnitOffsetSize = 4,
        stringOffsetsBase = stringOffsetsBase,
        parseBudget = parseBudget,
        limits = limits,
    )

    private fun lineUnit(version: Int, prologue: ByteArray): ByteArray {
        val body = bytes {
            u16(version)
            if (version >= 5) {
                u8(8)
                u8(0)
            }
            u32(prologue.size.toLong())
            raw(prologue)
        }
        return bytes {
            u32(body.size.toLong())
            raw(body)
        }
    }

    private fun legacyPrologue(
        version: Int,
        directories: List<String>,
        files: List<LegacyFile>,
    ): ByteArray = bytes {
        fixedPrologue(version)
        directories.forEach(::string)
        u8(0)
        files.forEach { file ->
            string(file.name)
            uleb(file.directoryIndex)
            uleb(0)
            uleb(0)
        }
        u8(0)
    }

    private fun v5Prologue(
        directoryFormats: List<Format>,
        directories: List<ByteArray>,
        fileFormats: List<Format>,
        files: List<ByteArray>,
    ): ByteArray = bytes {
        fixedPrologue(5)
        u8(directoryFormats.size)
        directoryFormats.forEach { format ->
            uleb(format.contentType)
            uleb(format.form)
        }
        uleb(directories.size.toLong())
        directories.forEach(::raw)
        u8(fileFormats.size)
        fileFormats.forEach { format ->
            uleb(format.contentType)
            uleb(format.form)
        }
        uleb(files.size.toLong())
        files.forEach(::raw)
    }

    private fun ByteWriter.fixedPrologue(version: Int) {
        u8(1)
        if (version >= 4) u8(1)
        u8(1)
        u8(0xfb)
        u8(14)
        u8(1)
    }

    private fun stringTable(vararg values: String): Pair<ByteArray, List<Long>> {
        val offsets = ArrayList<Long>()
        val output = ByteWriter()
        values.forEach { value ->
            offsets += output.size.toLong()
            output.string(value)
        }
        return output.toByteArray() to offsets
    }

    private fun section(bytes: ByteArray, label: String): FullTreeDwarfSection = FullTreeDwarfSection(
        size = bytes.size.toLong(),
        byteOrder = ByteOrder.LITTLE_ENDIAN,
        label = label,
        readWindow = { offset, length ->
            bytes.copyOfRange(offset.toInt(), offset.toInt() + length)
        },
    )

    private fun bytes(write: ByteWriter.() -> Unit): ByteArray = ByteWriter().apply(write).toByteArray()

    private fun entry(write: ByteWriter.() -> Unit): ByteArray = bytes(write)

    private data class LegacyFile(val name: String, val directoryIndex: Long)
    private data class Format(val contentType: Long, val form: Long)

    private class ByteWriter {
        private val output = ByteArrayOutputStream()

        val size: Int
            get() = output.size()

        fun u8(value: Int) {
            output.write(value and 0xff)
        }

        fun u16(value: Int) = uint(value.toLong(), 2)

        fun u32(value: Long) = uint(value, 4)

        fun uint(value: Long, width: Int) {
            repeat(width) { index -> output.write(((value ushr (index * 8)) and 0xff).toInt()) }
        }

        fun uleb(value: Int) = uleb(value.toLong())

        fun uleb(value: Long) {
            var remaining = value
            do {
                var byte = (remaining and 0x7f).toInt()
                remaining = remaining ushr 7
                if (remaining != 0L) byte = byte or 0x80
                output.write(byte)
            } while (remaining != 0L)
        }

        fun string(value: String) {
            raw(value.toByteArray(Charsets.UTF_8))
            u8(0)
        }

        fun raw(value: ByteArray) {
            output.write(value)
        }

        fun toByteArray(): ByteArray = output.toByteArray()
    }

    private companion object {
        const val DW_LNCT_PATH = 0x01L
        const val DW_LNCT_DIRECTORY_INDEX = 0x02L
        const val DW_LNCT_MD5 = 0x05L
    }
}

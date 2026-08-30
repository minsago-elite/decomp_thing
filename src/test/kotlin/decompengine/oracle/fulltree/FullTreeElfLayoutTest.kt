package decompengine.oracle.fulltree

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FullTreeElfLayoutTest {
    @Test
    fun `executable membership merges overlaps and keeps logarithmic boundary semantics`() {
        val membership = FullTreeElfExecutableMembership.fromSorted(
            listOf(
                FullTreeElfExecutableRange(0UL, 100UL),
                FullTreeElfExecutableRange(50UL, 60UL),
                FullTreeElfExecutableRange(100UL, 120UL),
                FullTreeElfExecutableRange(200UL, 210UL),
            ),
        )
        assertTrue(membership.contains(0UL))
        assertTrue(membership.contains(90UL))
        assertTrue(membership.contains(119UL))
        assertTrue(membership.contains(200UL))
        assertTrue(!membership.contains(120UL))
        assertTrue(!membership.contains(199UL))
        assertTrue(!membership.contains(210UL))
        assertFailsWith<FullTreeControlException> {
            FullTreeElfExecutableMembership.fromSorted(
                listOf(
                    FullTreeElfExecutableRange(10UL, 20UL),
                    FullTreeElfExecutableRange(0UL, 5UL),
                ),
            )
        }
    }

    @Test
    fun `scanner covers ELF32 ELF64 both byte orders extended numbering and SHNDX`() =
        inControlTemporaryDirectory { directory ->
            val variants = listOf(
                TestElfVariant(is64Bit = true, littleEndian = true, extendedNumbering = false, shndx = false),
                TestElfVariant(is64Bit = true, littleEndian = false, extendedNumbering = true, shndx = true),
                TestElfVariant(is64Bit = false, littleEndian = true, extendedNumbering = false, shndx = true),
                TestElfVariant(is64Bit = false, littleEndian = false, extendedNumbering = false, shndx = false),
                TestElfVariant(
                    is64Bit = true,
                    littleEndian = true,
                    extendedNumbering = false,
                    shndx = false,
                    extendedProgramNumbering = true,
                ),
            )
            variants.forEachIndexed { index, variant ->
                val bytes = FullTreeElfTestBytes.build(
                    variant,
                    listOf(
                        TestElfSymbol("first", 0x100UL),
                        TestElfSymbol("second", 0x110UL),
                        TestElfSymbol("external", null),
                    ),
                )
                val path = writeElf(directory.resolve("variant-$index.elf"), bytes)
                val symbols = arrayListOf<FullTreeElfFunctionSymbol>()
                StableControlFile.open(path, bytes.size.toLong(), "test ELF").use { source ->
                    val layout = FullTreeElfLayout.scanFunctions(source, "test", consume = symbols::add)
                    assertEquals(if (variant.is64Bit) 2 else 1, layout.elfClass)
                    assertEquals(if (variant.littleEndian) 1 else 2, layout.byteOrder)
                    assertEquals("ET_DYN", layout.elfType)
                    assertEquals(4L, layout.scannedSymbols)
                    assertEquals(0x400000UL, layout.imageBase)
                    assertEquals(1, layout.executableRanges.size)
                    assertEquals(0UL, layout.executableRanges.single().start)
                    assertEquals(bytes.size.toULong(), layout.executableRanges.single().endExclusive)
                    source.verifyUnchanged("test ELF")
                }
                assertEquals(listOf("first", "second", "external"), symbols.map { it.name })
                assertEquals(listOf(0x100UL, 0x110UL, null), symbols.map { it.rva })
                assertTrue(symbols.all { it.locator.startsWith("test:section[2]=.symtab:symbol[") })
            }
        }

    @Test
    fun `scanner rejects malformed UTF-8 truncation and symbol or parse limit excess`() =
        inControlTemporaryDirectory { directory ->
            val valid = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL), TestElfSymbol("external", null)),
            )
            val invalidUtf8 = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
                invalidFirstNameUtf8 = true,
            )
            assertScanRejected(writeElf(directory.resolve("invalid-utf8.elf"), invalidUtf8))
            assertScanRejected(writeElf(directory.resolve("truncated.elf"), valid.copyOf(valid.size - 1)))

            val bounded = writeElf(directory.resolve("bounded.elf"), valid)
            StableControlFile.open(bounded, valid.size.toLong(), "bounded ELF").use { source ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeElfLayout.scanFunctions(
                        source,
                        "bounded",
                        FullTreeElfLayoutLimits(maximumSymbols = 2),
                    ) {}
                }
            }
            StableControlFile.open(bounded, valid.size.toLong(), "bounded ELF").use { source ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeElfLayout.scanFunctions(
                        source,
                        "bounded",
                        FullTreeElfLayoutLimits(maximumTotalSectionNameBytes = 1),
                    ) {}
                }
            }
            StableControlFile.open(bounded, valid.size.toLong(), "bounded ELF").use { source ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeElfLayout.scanFunctions(
                        source,
                        "bounded",
                        FullTreeElfLayoutLimits(maximumParseSteps = 2),
                    ) {}
                }
            }
            Unit
        }

    @Test
    fun `scanner rejects malformed extended symbol-index companions`() =
        inControlTemporaryDirectory { directory ->
            val missing = FullTreeElfTestBytes.build(
                TestElfVariant(true, false, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL, forceExtendedIndex = true)),
            )
            assertScanRejected(writeElf(directory.resolve("missing-shndx.elf"), missing))

            val invalid = FullTreeElfTestBytes.build(
                TestElfVariant(false, true, extendedNumbering = false, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                // The companion's only defined-symbol entry names a section beyond e_shnum.
                val companionOffset = FullTreeElfTestBytes.shndxOffset(bytes)
                FullTreeElfTestBytes.put32(bytes, companionOffset + 4, 0xfffffff0L, littleEndian = true)
            }
            assertScanRejected(writeElf(directory.resolve("invalid-shndx.elf"), invalid))

            val invalidTarget = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.shndxLinkFieldOffset(bytes),
                    1,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("invalid-shndx-target.elf"), invalidTarget))

            val nonFunctionMissing = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("object", 0x100UL, forceExtendedIndex = true, type = 1)),
            )
            assertScanRejected(writeElf(directory.resolve("non-function-missing-shndx.elf"), nonFunctionMissing))

            val nonXindexWord = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.shndxOffset(bytes) + 4,
                    1,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("non-xindex-word.elf"), nonXindexWord))

            listOf(
                FullTreeElfTestBytes.SHNDX_ENTRY_SIZE_FIELD to 0L,
                FullTreeElfTestBytes.SHNDX_INFO_FIELD to 1L,
                FullTreeElfTestBytes.SHNDX_SIZE_FIELD to 4L,
                FullTreeElfTestBytes.SHNDX_ALIGNMENT_FIELD to 1L,
            ).forEachIndexed { index, (field, value) ->
                val malformed = FullTreeElfTestBytes.build(
                    TestElfVariant(true, true, extendedNumbering = false, shndx = true),
                    listOf(TestElfSymbol("defined", 0x100UL)),
                ).also { bytes ->
                    FullTreeElfTestBytes.put32(
                        bytes,
                        FullTreeElfTestBytes.shndxFieldOffset(bytes, field),
                        value,
                        littleEndian = true,
                    )
                }
                assertScanRejected(writeElf(directory.resolve("malformed-shndx-field-$index.elf"), malformed))
            }

            val duplicate = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = true, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also(FullTreeElfTestBytes::duplicateShndxSection)
            assertScanRejected(writeElf(directory.resolve("duplicate-shndx.elf"), duplicate))

            val lowExtendedIndex = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = true, shndx = true),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.shndxOffset(bytes) + 4,
                    1,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("low-extended-index.elf"), lowExtendedIndex))
        }

    @Test
    fun `section zero and extended numbering are reciprocal and threshold strict`() =
        inControlTemporaryDirectory { directory ->
            val nonNullZero = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.sectionFieldOffset(bytes, 0, 4, 4),
                    1,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("nonnull-section-zero.elf"), nonNullZero))

            val unrequestedCount = FullTreeElfTestBytes.build(
                TestElfVariant(false, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.sectionFieldOffset(bytes, 0, 20, 32),
                    5,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("unrequested-section-count.elf"), unrequestedCount))

            val belowThreshold = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put16(bytes, 60, 0, littleEndian = true)
                FullTreeElfTestBytes.put64(
                    bytes,
                    FullTreeElfTestBytes.sectionFieldOffset(bytes, 0, 32, 32),
                    5UL,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("below-threshold-section-count.elf"), belowThreshold))

            val reservedDirectName = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes -> FullTreeElfTestBytes.put16(bytes, 62, 0xff00, littleEndian = true) }
            assertScanRejected(writeElf(directory.resolve("reserved-direct-shstrndx.elf"), reservedDirectName))

            listOf(
                "unrequested-name-index" to Pair(40, 4L),
                "unrequested-program-count" to Pair(44, 1L),
            ).forEach { (name, fieldAndValue) ->
                val bytes = FullTreeElfTestBytes.build(
                    TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                    listOf(TestElfSymbol("defined", 0x100UL)),
                ).also { mutation ->
                    FullTreeElfTestBytes.put32(
                        mutation,
                        FullTreeElfTestBytes.sectionFieldOffset(mutation, 0, fieldAndValue.first - 16, fieldAndValue.first),
                        fieldAndValue.second,
                        littleEndian = true,
                    )
                }
                assertScanRejected(writeElf(directory.resolve("$name.elf"), bytes))
            }

            val belowThresholdNameIndex = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put16(bytes, 62, 0xffff, littleEndian = true)
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.sectionFieldOffset(bytes, 0, 24, 40),
                    4,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("below-threshold-shstrndx.elf"), belowThresholdNameIndex))

            val belowThresholdProgramCount = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            ).also { bytes ->
                FullTreeElfTestBytes.put16(bytes, 56, 0xffff, littleEndian = true)
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.sectionFieldOffset(bytes, 0, 28, 44),
                    1,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("below-threshold-phnum.elf"), belowThresholdProgramCount))
        }

    @Test
    fun `ELF32 range width and reserved symbol indexes are explicit`() =
        inControlTemporaryDirectory { directory ->
            val onePast = FullTreeElfTestBytes.build(
                TestElfVariant(false, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("external", null)),
            ).also { bytes ->
                val program = FullTreeElfTestBytes.programHeaderOffset(bytes)
                FullTreeElfTestBytes.put32(bytes, program + 8, 0xfffffff0L, littleEndian = true)
                FullTreeElfTestBytes.put32(bytes, program + 12, 0xfffffff0L, littleEndian = true)
                FullTreeElfTestBytes.put32(bytes, program + 16, 0, littleEndian = true)
                FullTreeElfTestBytes.put32(bytes, program + 20, 16, littleEndian = true)
            }
            val onePastPath = writeElf(directory.resolve("elf32-one-past.elf"), onePast)
            StableControlFile.open(onePastPath, onePast.size.toLong(), "ELF32 one-past").use { source ->
                val observed = arrayListOf<FullTreeElfFunctionSymbol>()
                val layout = FullTreeElfLayout.scanFunctions(source, "one-past", consume = observed::add)
                assertEquals(0xfffffff0UL, layout.imageBase)
                assertEquals(16UL, layout.executableRanges.single().endExclusive)
                assertEquals(listOf("external"), observed.map { it.name })
            }

            val wrapped = onePast.copyOf().also { bytes ->
                FullTreeElfTestBytes.put32(
                    bytes,
                    FullTreeElfTestBytes.programHeaderOffset(bytes) + 20,
                    17,
                    littleEndian = true,
                )
            }
            assertScanRejected(writeElf(directory.resolve("elf32-wrapped.elf"), wrapped))

            listOf(0xff00, 0xfff2).forEachIndexed { index, reserved ->
                val bytes = FullTreeElfTestBytes.build(
                    TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                    listOf(TestElfSymbol("reserved", 0x100UL, sectionIndex = reserved)),
                )
                assertScanRejected(writeElf(directory.resolve("reserved-symbol-$index.elf"), bytes))
            }

            val absolute = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("absolute", 0x100UL, sectionIndex = 0xfff1)),
            )
            val absolutePath = writeElf(directory.resolve("absolute-symbol.elf"), absolute)
            StableControlFile.open(absolutePath, absolute.size.toLong(), "absolute ELF").use { source ->
                val observed = arrayListOf<FullTreeElfFunctionSymbol>()
                FullTreeElfLayout.scanFunctions(source, "absolute", consume = observed::add)
                assertEquals(listOf("absolute"), observed.map { it.name })
                assertEquals(listOf(0x100UL), observed.map { it.rva })
            }
        }

    private fun assertScanRejected(path: Path) {
        StableControlFile.open(path, Files.size(path), "rejected ELF").use { source ->
            assertFailsWith<FullTreeControlException> {
                FullTreeElfLayout.scanFunctions(source, "rejected") {}
            }
        }
    }
}

internal data class TestElfVariant(
    val is64Bit: Boolean,
    val littleEndian: Boolean,
    val extendedNumbering: Boolean,
    val shndx: Boolean,
    val extendedProgramNumbering: Boolean = false,
)

internal data class TestElfSymbol(
    val name: String,
    val rva: ULong?,
    val forceExtendedIndex: Boolean = false,
    val sectionIndex: Int? = null,
    val type: Int = 2,
)

internal object FullTreeElfTestBytes {
    const val SHNDX_INFO_FIELD = 1
    const val SHNDX_ENTRY_SIZE_FIELD = 2
    const val SHNDX_SIZE_FIELD = 3
    const val SHNDX_ALIGNMENT_FIELD = 4
    private const val BASE = 0x400000L
    private const val MINIMUM_CODE_OFFSET = 0x100
    private const val CODE_BYTES = 0x100
    private const val EXTENDED_SYMBOL_SECTION_INDEX = 0xff00
    // Two above SHN_LORESERVE leave a high text index and a distinct extended shstrtab index.
    private const val EXTENDED_SECTION_COUNT = 0xff02
    private const val EXTENDED_PROGRAM_COUNT = 0xffff

    fun build(
        variant: TestElfVariant,
        symbols: List<TestElfSymbol>,
        invalidFirstNameUtf8: Boolean = false,
    ): ByteArray {
        require(symbols.isNotEmpty())
        val headerBytes = if (variant.is64Bit) 64 else 52
        val programBytes = if (variant.is64Bit) 56 else 32
        val sectionBytes = if (variant.is64Bit) 64 else 40
        val symbolBytes = if (variant.is64Bit) 24 else 16
        val programOffset = headerBytes
        val programCount = if (variant.extendedProgramNumbering) EXTENDED_PROGRAM_COUNT else 1
        val codeOffset = maxOf(
            MINIMUM_CODE_OFFSET,
            align(programOffset + programCount * programBytes, 16),
        )

        val stringTable = ByteArrayOutputStream().apply { write(0) }
        val stringOffsets = symbols.map { symbol ->
            val offset = stringTable.size()
            stringTable.write(symbol.name.toByteArray(Charsets.UTF_8))
            stringTable.write(0)
            offset
        }
        val strings = stringTable.toByteArray().also { bytes ->
            if (invalidFirstNameUtf8) bytes[stringOffsets.first()] = 0xff.toByte()
        }

        val sectionNames = listOf(".text", ".symtab", ".strtab", ".shstrtab", ".symtab_shndx")
        val sectionStringTable = ByteArrayOutputStream().apply { write(0) }
        val sectionNameOffsets = sectionNames.associateWith { name ->
            sectionStringTable.size().also {
                sectionStringTable.write(name.toByteArray(Charsets.US_ASCII))
                sectionStringTable.write(0)
            }
        }
        val sectionStrings = sectionStringTable.toByteArray()
        val symbolCount = symbols.size + 1
        val symbolTableBytes = symbolCount * symbolBytes
        val stringOffset = codeOffset + CODE_BYTES
        val symbolOffset = align(stringOffset + strings.size, if (variant.is64Bit) 8 else 4)
        val extendedOffset = if (variant.shndx) symbolOffset + symbolTableBytes else -1
        val sectionStringOffset = align(
            if (variant.shndx) extendedOffset + symbolCount * 4 else symbolOffset + symbolTableBytes,
            4,
        )
        val minimumSectionCount = if (variant.shndx) 6 else 5
        val sectionCount = if (variant.extendedNumbering) EXTENDED_SECTION_COUNT else minimumSectionCount
        val sectionNameIndex = if (variant.extendedNumbering) sectionCount - 1 else 4
        val sectionOffset = align(sectionStringOffset + sectionStrings.size, if (variant.is64Bit) 8 else 4)
        val totalBytes = sectionOffset + sectionCount * sectionBytes
        val result = ByteArray(totalBytes)
        strings.copyInto(result, stringOffset)
        sectionStrings.copyInto(result, sectionStringOffset)

        result[0] = 0x7f
        result[1] = 'E'.code.toByte()
        result[2] = 'L'.code.toByte()
        result[3] = 'F'.code.toByte()
        result[4] = (if (variant.is64Bit) 2 else 1).toByte()
        result[5] = (if (variant.littleEndian) 1 else 2).toByte()
        result[6] = 1.toByte()
        put16(result, 16, 3, variant.littleEndian)
        put16(result, 18, if (variant.is64Bit) 62 else 3, variant.littleEndian)
        put32(result, 20, 1, variant.littleEndian)
        if (variant.is64Bit) {
            put64(result, 24, (BASE + codeOffset).toULong(), variant.littleEndian)
            put64(result, 32, programOffset.toULong(), variant.littleEndian)
            put64(result, 40, sectionOffset.toULong(), variant.littleEndian)
            put32(result, 48, 0, variant.littleEndian)
            put16(result, 52, headerBytes, variant.littleEndian)
            put16(result, 54, programBytes, variant.littleEndian)
            put16(result, 56, if (variant.extendedProgramNumbering) 0xffff else 1, variant.littleEndian)
            put16(result, 58, sectionBytes, variant.littleEndian)
            put16(result, 60, if (variant.extendedNumbering) 0 else sectionCount, variant.littleEndian)
            put16(result, 62, if (variant.extendedNumbering) 0xffff else sectionNameIndex, variant.littleEndian)
        } else {
            put32(result, 24, BASE + codeOffset.toLong(), variant.littleEndian)
            put32(result, 28, programOffset.toLong(), variant.littleEndian)
            put32(result, 32, sectionOffset.toLong(), variant.littleEndian)
            put32(result, 36, 0, variant.littleEndian)
            put16(result, 40, headerBytes, variant.littleEndian)
            put16(result, 42, programBytes, variant.littleEndian)
            put16(result, 44, if (variant.extendedProgramNumbering) 0xffff else 1, variant.littleEndian)
            put16(result, 46, sectionBytes, variant.littleEndian)
            put16(result, 48, if (variant.extendedNumbering) 0 else sectionCount, variant.littleEndian)
            put16(result, 50, if (variant.extendedNumbering) 0xffff else sectionNameIndex, variant.littleEndian)
        }
        writeProgramHeader(result, programOffset, totalBytes, variant)

        writeSection(
            result,
            sectionOffset,
            variant,
            SectionRecord(
                name = 0,
                type = 0,
                flags = 0,
                address = 0,
                offset = 0,
                size = if (variant.extendedNumbering) sectionCount.toLong() else 0,
                link = if (variant.extendedNumbering) sectionNameIndex else 0,
                info = if (variant.extendedProgramNumbering) programCount else 0,
                alignment = 0,
                entrySize = 0,
            ),
        )
        writeSection(
            result,
            sectionOffset + sectionBytes,
            variant,
            SectionRecord(
                sectionNameOffsets.getValue(".text"), 1, 6, BASE + codeOffset,
                codeOffset.toLong(), CODE_BYTES.toLong(), 0, 0, 16, 0,
            ),
        )
        if (variant.extendedNumbering) {
            writeSection(
                result,
                sectionOffset + sectionBytes * EXTENDED_SYMBOL_SECTION_INDEX,
                variant,
                SectionRecord(
                    sectionNameOffsets.getValue(".text"), 1, 6, BASE + codeOffset,
                    codeOffset.toLong(), CODE_BYTES.toLong(), 0, 0, 16, 0,
                ),
            )
        }
        writeSection(
            result,
            sectionOffset + sectionBytes * 2,
            variant,
            SectionRecord(
                sectionNameOffsets.getValue(".symtab"), 2, 0, 0,
                symbolOffset.toLong(), symbolTableBytes.toLong(), 3, 1,
                if (variant.is64Bit) 8 else 4, symbolBytes.toLong(),
            ),
        )
        writeSection(
            result,
            sectionOffset + sectionBytes * 3,
            variant,
            SectionRecord(
                sectionNameOffsets.getValue(".strtab"), 3, 0, 0,
                stringOffset.toLong(), strings.size.toLong(), 0, 0, 1, 0,
            ),
        )
        writeSection(
            result,
            sectionOffset + sectionBytes * sectionNameIndex,
            variant,
            SectionRecord(
                sectionNameOffsets.getValue(".shstrtab"), 3, 0, 0,
                sectionStringOffset.toLong(), sectionStrings.size.toLong(), 0, 0, 1, 0,
            ),
        )
        if (variant.shndx) {
            writeSection(
                result,
                sectionOffset + sectionBytes * 5,
                variant,
                SectionRecord(
                    sectionNameOffsets.getValue(".symtab_shndx"), 18, 0, 0,
                    extendedOffset.toLong(), (symbolCount * 4).toLong(), 2, 0, 4, 4,
                ),
            )
        }

        symbols.forEachIndexed { index, symbol ->
            val symbolIndex = index + 1
            val offset = symbolOffset + symbolIndex * symbolBytes
            val extendedIndex = symbol.sectionIndex == null && symbol.rva != null &&
                (symbol.forceExtendedIndex || variant.shndx && variant.extendedNumbering)
            val rawSectionIndex = symbol.sectionIndex
                ?: if (symbol.rva == null) 0 else if (extendedIndex) 0xffff else 1
            if (variant.is64Bit) {
                put32(result, offset, stringOffsets[index].toLong(), variant.littleEndian)
                result[offset + 4] = ((1 shl 4) or symbol.type).toByte()
                put16(
                    result,
                    offset + 6,
                    rawSectionIndex,
                    variant.littleEndian,
                )
                put64(result, offset + 8, symbol.rva?.let { BASE.toULong() + it } ?: 0UL, variant.littleEndian)
            } else {
                put32(result, offset, stringOffsets[index].toLong(), variant.littleEndian)
                put32(result, offset + 4, symbol.rva?.let { BASE.toULong() + it }?.toLong() ?: 0, variant.littleEndian)
                result[offset + 12] = ((1 shl 4) or symbol.type).toByte()
                put16(
                    result,
                    offset + 14,
                    rawSectionIndex,
                    variant.littleEndian,
                )
            }
            if (variant.shndx) {
                put32(
                    result,
                    extendedOffset + symbolIndex * 4,
                    if (extendedIndex) EXTENDED_SYMBOL_SECTION_INDEX.toLong() else 0,
                    variant.littleEndian,
                )
            }
        }
        return result
    }

    fun shndxOffset(bytes: ByteArray): Int {
        val littleEndian = bytes[5].toInt() == 1
        val is64 = bytes[4].toInt() == 2
        val sectionOffset = if (is64) read64(bytes, 40, littleEndian).toInt() else read32(bytes, 32, littleEndian).toInt()
        val sectionSize = read16(bytes, if (is64) 58 else 46, littleEndian)
        val offsetField = sectionOffset + sectionSize * 5 + if (is64) 24 else 16
        return if (is64) read64(bytes, offsetField, littleEndian).toInt() else read32(bytes, offsetField, littleEndian).toInt()
    }

    fun shndxLinkFieldOffset(bytes: ByteArray): Int {
        val littleEndian = bytes[5].toInt() == 1
        val is64 = bytes[4].toInt() == 2
        val sectionOffset = if (is64) {
            read64(bytes, 40, littleEndian).toInt()
        } else {
            read32(bytes, 32, littleEndian).toInt()
        }
        val sectionSize = read16(bytes, if (is64) 58 else 46, littleEndian)
        return sectionOffset + sectionSize * 5 + if (is64) 40 else 24
    }

    fun shndxFieldOffset(bytes: ByteArray, field: Int): Int = when (field) {
        SHNDX_INFO_FIELD -> sectionFieldOffset(bytes, 5, 28, 44)
        SHNDX_ENTRY_SIZE_FIELD -> sectionFieldOffset(bytes, 5, 36, 56)
        SHNDX_SIZE_FIELD -> sectionFieldOffset(bytes, 5, 20, 32)
        SHNDX_ALIGNMENT_FIELD -> sectionFieldOffset(bytes, 5, 32, 48)
        else -> error("unsupported SHNDX test field")
    }

    fun sectionFieldOffset(bytes: ByteArray, index: Int, elf32Field: Int, elf64Field: Int): Int {
        val littleEndian = bytes[5].toInt() == 1
        val is64 = bytes[4].toInt() == 2
        val sectionOffset = if (is64) {
            read64(bytes, 40, littleEndian).toInt()
        } else {
            read32(bytes, 32, littleEndian).toInt()
        }
        val sectionSize = read16(bytes, if (is64) 58 else 46, littleEndian)
        return sectionOffset + sectionSize * index + if (is64) elf64Field else elf32Field
    }

    fun programHeaderOffset(bytes: ByteArray): Int {
        val littleEndian = bytes[5].toInt() == 1
        return if (bytes[4].toInt() == 2) {
            read64(bytes, 32, littleEndian).toInt()
        } else {
            read32(bytes, 28, littleEndian).toInt()
        }
    }

    fun duplicateShndxSection(bytes: ByteArray) {
        val littleEndian = bytes[5].toInt() == 1
        val is64 = bytes[4].toInt() == 2
        val sectionSize = read16(bytes, if (is64) 58 else 46, littleEndian)
        val source = sectionFieldOffset(bytes, 5, 0, 0)
        val destination = sectionFieldOffset(bytes, 6, 0, 0)
        bytes.copyInto(bytes, destination, source, source + sectionSize)
    }

    fun put32(bytes: ByteArray, offset: Int, value: Long, littleEndian: Boolean) {
        repeat(4) { index ->
            val shift = if (littleEndian) index * 8 else (3 - index) * 8
            bytes[offset + index] = (value ushr shift).toByte()
        }
    }

    private fun writeProgramHeader(bytes: ByteArray, offset: Int, totalBytes: Int, variant: TestElfVariant) {
        put32(bytes, offset, 1, variant.littleEndian)
        if (variant.is64Bit) {
            put32(bytes, offset + 4, 5, variant.littleEndian)
            put64(bytes, offset + 8, 0UL, variant.littleEndian)
            put64(bytes, offset + 16, BASE.toULong(), variant.littleEndian)
            put64(bytes, offset + 24, BASE.toULong(), variant.littleEndian)
            put64(bytes, offset + 32, totalBytes.toULong(), variant.littleEndian)
            put64(bytes, offset + 40, totalBytes.toULong(), variant.littleEndian)
            put64(bytes, offset + 48, 0x1000UL, variant.littleEndian)
        } else {
            put32(bytes, offset + 4, 0, variant.littleEndian)
            put32(bytes, offset + 8, BASE, variant.littleEndian)
            put32(bytes, offset + 12, BASE, variant.littleEndian)
            put32(bytes, offset + 16, totalBytes.toLong(), variant.littleEndian)
            put32(bytes, offset + 20, totalBytes.toLong(), variant.littleEndian)
            put32(bytes, offset + 24, 5, variant.littleEndian)
            put32(bytes, offset + 28, 0x1000, variant.littleEndian)
        }
    }

    private fun writeSection(bytes: ByteArray, offset: Int, variant: TestElfVariant, record: SectionRecord) {
        put32(bytes, offset, record.name.toLong(), variant.littleEndian)
        put32(bytes, offset + 4, record.type.toLong(), variant.littleEndian)
        if (variant.is64Bit) {
            put64(bytes, offset + 8, record.flags.toULong(), variant.littleEndian)
            put64(bytes, offset + 16, record.address.toULong(), variant.littleEndian)
            put64(bytes, offset + 24, record.offset.toULong(), variant.littleEndian)
            put64(bytes, offset + 32, record.size.toULong(), variant.littleEndian)
            put32(bytes, offset + 40, record.link.toLong(), variant.littleEndian)
            put32(bytes, offset + 44, record.info.toLong(), variant.littleEndian)
            put64(bytes, offset + 48, record.alignment.toULong(), variant.littleEndian)
            put64(bytes, offset + 56, record.entrySize.toULong(), variant.littleEndian)
        } else {
            put32(bytes, offset + 8, record.flags, variant.littleEndian)
            put32(bytes, offset + 12, record.address, variant.littleEndian)
            put32(bytes, offset + 16, record.offset, variant.littleEndian)
            put32(bytes, offset + 20, record.size, variant.littleEndian)
            put32(bytes, offset + 24, record.link.toLong(), variant.littleEndian)
            put32(bytes, offset + 28, record.info.toLong(), variant.littleEndian)
            put32(bytes, offset + 32, record.alignment, variant.littleEndian)
            put32(bytes, offset + 36, record.entrySize, variant.littleEndian)
        }
    }

    fun put16(bytes: ByteArray, offset: Int, value: Int, littleEndian: Boolean) {
        if (littleEndian) {
            bytes[offset] = value.toByte()
            bytes[offset + 1] = (value ushr 8).toByte()
        } else {
            bytes[offset] = (value ushr 8).toByte()
            bytes[offset + 1] = value.toByte()
        }
    }

    fun put64(bytes: ByteArray, offset: Int, value: ULong, littleEndian: Boolean) {
        repeat(8) { index ->
            val shift = if (littleEndian) index * 8 else (7 - index) * 8
            bytes[offset + index] = (value shr shift).toByte()
        }
    }

    private fun read16(bytes: ByteArray, offset: Int, littleEndian: Boolean): Int =
        if (littleEndian) {
            (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)
        } else {
            ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
        }

    private fun read32(bytes: ByteArray, offset: Int, littleEndian: Boolean): Long {
        var value = 0L
        repeat(4) { index ->
            val source = if (littleEndian) offset + 3 - index else offset + index
            value = (value shl 8) or (bytes[source].toLong() and 0xff)
        }
        return value
    }

    private fun read64(bytes: ByteArray, offset: Int, littleEndian: Boolean): ULong {
        var value = 0UL
        repeat(8) { index ->
            val source = if (littleEndian) offset + 7 - index else offset + index
            value = (value shl 8) or (bytes[source].toULong() and 0xffUL)
        }
        return value
    }

    private fun align(value: Int, alignment: Int): Int = (value + alignment - 1) / alignment * alignment

    private data class SectionRecord(
        val name: Int,
        val type: Int,
        val flags: Long,
        val address: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val info: Int,
        val alignment: Long,
        val entrySize: Long,
    )
}

internal fun writeElf(path: Path, bytes: ByteArray): Path = path.also {
    Files.write(it, bytes)
    Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rw-r--r--"))
}

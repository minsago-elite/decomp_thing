package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class FullTreeElfFunctionExtentsTest {
    @Test
    fun `raw function extents retain aliases unnamed imports zero sizes outside ranges and IFUNC in every ELF encoding`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            for (is64 in listOf(false, true)) for (little in listOf(false, true)) {
                val bytes = FullTreeElfTestBytes.build(TestElfVariant(is64, little, false, false), listOf(
                    TestElfSymbol("function", 0x110UL), TestElfSymbol("alias", 0x110UL),
                    TestElfSymbol("", 0x120UL), TestElfSymbol("import", null),
                    TestElfSymbol("zero", 0x140UL), TestElfSymbol("outside", 0x100000UL),
                    TestElfSymbol("resolver", 0x150UL, type = 10), TestElfSymbol("object", 0x160UL, type = 1),
                    TestElfSymbol("nonallocated", 0x170UL, sectionIndex = 3),
                ))
                extentSize(bytes, 1, 16UL)
                extentSize(bytes, 2, 16UL)
                extentSize(bytes, 3, 4UL)
                extentSize(bytes, 4, 7UL)
                extentSize(bytes, 6, 4UL)
                extentSize(bytes, 7, 8UL)
                // A literal STN name offset zero must remain, not just an empty string-table entry.
                FullTreeElfTestBytes.put32(bytes, extentOffset(bytes, 3), 0, little)
                val path = writeElf(directory.resolve("raw-$is64-$little.elf"), bytes)
                val (layout, functions) = extentScan(path)
                assertEquals(if (is64) 2 else 1, layout.elfClass)
                assertEquals(if (little) 1 else 2, layout.byteOrder)
                assertEquals(if (is64) 62 else 3, layout.machine)
                assertEquals("ET_DYN", layout.elfType)
                assertEquals(0x400000UL, layout.imageBase)
                assertEquals(10L, layout.scannedSymbols)
                assertEquals(listOf("function", "alias", "", "import", "zero", "outside", "resolver", "nonallocated"),
                    functions.map { it.name })
                assertEquals(8, functions.map { it.locator }.distinct().size)
                assertEquals(0x110UL, functions[0].rva)
                assertEquals(functions[0].rva, functions[1].rva)
                assertEquals(16UL, functions[0].size)
                assertEquals(0x400110UL, functions[0].value)
                assertEquals(0UL, functions[4].size)
                assertEquals(0x100000UL, functions[5].rva)
                assertEquals(10, functions[6].type)
                assertEquals(FullTreeElfSymbolSectionKind.UNDEFINED, functions[3].sectionKind)
                assertEquals(0L, functions[3].resolvedSectionIndex)
                assertEquals(7UL, functions[3].size)
                assertNull(functions[3].rva)
                assertNull(functions[3].sectionFileOffset)
                assertEquals(".strtab", functions.last().sectionName)
                assertEquals(0UL, functions.last().sectionFlags)
                val normal = functions.first()
                assertEquals(1, normal.rawSectionIndex)
                assertEquals(1L, normal.resolvedSectionIndex)
                assertEquals(FullTreeElfSymbolSectionKind.DEFINED, normal.sectionKind)
                assertEquals(".text", normal.sectionName)
                assertEquals(1L, normal.sectionType)
                assertEquals(6UL, normal.sectionFlags)
                assertEquals(0x400100UL, normal.sectionAddress)
                assertEquals(0x100UL, normal.sectionSize)
                assertEquals(0x100L, normal.sectionFileOffset)
                val segment = layout.loadedMemory.single()
                assertEquals(0, segment.index)
                assertEquals(5L, segment.flags)
                assertEquals(0UL, segment.fileOffset)
                assertEquals(0x400000UL, segment.virtualAddress)
                assertEquals(bytes.size.toULong(), segment.fileSize)
                assertEquals(bytes.size.toULong(), segment.memorySize)
                assertEquals(0x400000UL + bytes.size.toULong(), segment.fileEndExclusive)
            }
        }

    @Test
    fun `special section indexes and raw non-address values are retained without claiming ownership`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            val bytes = FullTreeElfTestBytes.build(TestElfVariant(true, true, false, false), listOf(
                TestElfSymbol("undefined", null),
                TestElfSymbol("common", 0UL, sectionIndex = 0xfff2),
                TestElfSymbol("absolute", 0x110UL, sectionIndex = 0xfff1),
                TestElfSymbol("reserved", 0x120UL, sectionIndex = 0xff00),
                TestElfSymbol("below_base", 0UL),
            ))
            extentValue(bytes, 1, 0x400110UL)
            extentValue(bytes, 2, 16UL)
            extentValue(bytes, 5, 1UL)
            extentSize(bytes, 3, ULong.MAX_VALUE)
            val functions = extentScan(writeElf(directory.resolve("special.elf"), bytes)).second
            assertEquals(listOf(FullTreeElfSymbolSectionKind.UNDEFINED, FullTreeElfSymbolSectionKind.COMMON,
                FullTreeElfSymbolSectionKind.ABSOLUTE, FullTreeElfSymbolSectionKind.RESERVED,
                FullTreeElfSymbolSectionKind.DEFINED), functions.map { it.sectionKind })
            assertEquals(listOf(0L, 0xfff2L, 0xfff1L, 0xff00L, 1L), functions.map { it.resolvedSectionIndex })
            assertEquals(0x110UL, functions[0].rva, "RVA is arithmetic only, even for undefined records")
            assertNull(functions[1].rva)
            assertNull(functions[4].rva)
            assertEquals(ULong.MAX_VALUE, functions[2].size, "raw overflow extent must reach the independent classifier")
            functions.take(4).forEach {
                assertNull(it.sectionName); assertNull(it.sectionType); assertNull(it.sectionFlags)
                assertNull(it.sectionAddress); assertNull(it.sectionSize); assertNull(it.sectionFileOffset)
            }
        }

    @Test
    fun `extended section indexes preserve resolved headers and full symbol metadata`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            for (variant in listOf(TestElfVariant(true, true, true, true), TestElfVariant(false, false, true, true))) {
                val bytes = FullTreeElfTestBytes.build(variant, listOf(TestElfSymbol("extended", 0x110UL, type = 10)))
                val symbol = extentOffset(bytes, 1)
                bytes[symbol + if (variant.is64Bit) 4 else 12] = 0x2a // STB_WEAK | GNU_IFUNC.
                bytes[symbol + if (variant.is64Bit) 5 else 13] = 0xa2.toByte()
                extentSize(bytes, 1, 12UL)
                val function = extentScan(writeElf(directory.resolve("extended-${variant.is64Bit}.elf"), bytes)).second.single()
                assertEquals(0xffff, function.rawSectionIndex)
                assertEquals(0xff00L, function.resolvedSectionIndex)
                assertEquals(FullTreeElfSymbolSectionKind.DEFINED, function.sectionKind)
                assertEquals(".text", function.sectionName)
                assertEquals(0x100L, function.sectionFileOffset)
                assertEquals(10, function.type)
                assertEquals(2, function.binding)
                assertEquals(2, function.visibility)
                assertEquals(0xa2, function.other)
                assertEquals(12UL, function.size)
            }
        }

    @Test
    fun `extent scanning preserves frozen function and object scan output and immutable layout lists`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            val bytes = FullTreeElfTestBytes.build(TestElfVariant(true, true, false, false), listOf(
                TestElfSymbol("function", 0x110UL), TestElfSymbol("", 0x120UL),
                TestElfSymbol("resolver", 0x130UL, type = 10), TestElfSymbol("object", 0x140UL, type = 1),
                TestElfSymbol("import", null),
            ))
            val path = writeElf(directory.resolve("frozen.elf"), bytes)
            StableControlFile.open(path, Files.size(path), "frozen").use { file ->
                fun functions(): Pair<FullTreeElfLayoutObservation, List<FullTreeElfFunctionSymbol>> {
                    val observed = arrayListOf<FullTreeElfFunctionSymbol>()
                    return FullTreeElfLayout.scanFunctions(file, "frozen", consume = observed::add) to observed
                }
                fun objects(): Pair<String, List<String>> {
                    val observed = arrayListOf<FullTreeElfObjectSymbol>()
                    val layout = FullTreeElfLayout.scanObjects(file, "frozen", consume = observed::add)
                    return layout.toJson().toString() to observed.map { it.toJson().toString() }
                }
                val oldFunctions = functions()
                val oldObjects = objects()
                val raw = arrayListOf<FullTreeElfFunctionExtent>()
                val layout = FullTreeElfLayout.scanFunctionExtents(file, "frozen", consume = raw::add)
                assertEquals(oldFunctions, functions())
                assertEquals(oldObjects, objects())
                assertEquals(listOf("function", "import"), oldFunctions.second.map { it.name })
                assertEquals(listOf("function", "", "resolver", "import"), raw.map { it.name })
                assertFailsWith<UnsupportedOperationException> { (layout.loadedMemory as MutableList<*>).clear() }
                assertFailsWith<UnsupportedOperationException> { (layout.executableRanges as MutableList<*>).clear() }
                assertEquals(1, layout.loadedMemory.size)
            }
        }

    @Test
    fun `malformed symbols and every existing parser budget refuse a complete extent observation`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            val variant = TestElfVariant(true, true, false, false)
            val bytes = FullTreeElfTestBytes.build(variant, listOf(TestElfSymbol("bounded", 0x110UL)))
            val path = writeElf(directory.resolve("bounded.elf"), bytes)
            for (limits in listOf(
                FullTreeElfLayoutLimits(maximumSymbols = 1), FullTreeElfLayoutLimits(maximumParseSteps = 1),
                FullTreeElfLayoutLimits(maximumSectionHeaders = 4), FullTreeElfLayoutLimits(maximumFunctionNameBytes = 3),
                FullTreeElfLayoutLimits(maximumLocatorBytes = 1),
            )) assertFailsWith<FullTreeControlException> { extentScan(path, limits) }
            val badUtf8 = FullTreeElfTestBytes.build(variant, listOf(TestElfSymbol("bad", 0x110UL)), invalidFirstNameUtf8 = true)
            assertFailsWith<FullTreeControlException> { extentScan(writeElf(directory.resolve("bad-name.elf"), badUtf8)) }
            val missingSection = bytes.copyOf()
            FullTreeElfTestBytes.put16(missingSection, extentOffset(missingSection, 1) + 6, 99, true)
            assertFailsWith<FullTreeControlException> { extentScan(writeElf(directory.resolve("bad-section.elf"), missingSection)) }
            val relocatable = bytes.copyOf()
            FullTreeElfTestBytes.put16(relocatable, 16, 1, true)
            assertFailsWith<FullTreeControlException> { extentScan(writeElf(directory.resolve("relocatable.o"), relocatable)) }
        }

    @Test
    fun `cancellation propagates and source replacement prevents successful extent return`(): Unit =
        inInterfaceFixtureDirectory { directory ->
            val bytes = FullTreeElfTestBytes.build(TestElfVariant(true, true, false, false),
                listOf(TestElfSymbol("function", 0x110UL)))
            val path = writeElf(directory.resolve("source.elf"), bytes)
            val cancel = IllegalStateException("authored cancellation")
            val failure = assertFailsWith<IllegalStateException> { extentScan(path, checkpoint = { throw cancel }) }
            assertSame(cancel, failure)
            val replacement = writeElf(directory.resolve("replacement.elf"), bytes)
            var result: FullTreeElfFunctionExtentLayout? = null
            var consumed = 0
            StableControlFile.open(path, Files.size(path), "replace").use { file ->
                assertFailsWith<FullTreeControlException> {
                    result = FullTreeElfLayout.scanFunctionExtents(file, "replace") {
                        consumed++
                        Files.move(replacement, path, StandardCopyOption.REPLACE_EXISTING)
                    }
                }
            }
            assertEquals(1, consumed)
            assertNull(result, "streamed facts have no authority when the complete scan fails")
            assertTrue(Files.readAllBytes(path).contentEquals(bytes))
        }
}

private fun extentScan(
    path: Path,
    limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
    checkpoint: (String) -> Unit = {},
): Pair<FullTreeElfFunctionExtentLayout, List<FullTreeElfFunctionExtent>> =
    StableControlFile.open(path, Files.size(path), "extent fixture").use { file ->
        val observed = arrayListOf<FullTreeElfFunctionExtent>()
        FullTreeElfLayout.scanFunctionExtents(file, "extent fixture", limits, checkpoint, observed::add) to observed
    }

private fun extentOffset(bytes: ByteArray, index: Int): Int =
    FullTreeElfTestBytes.symbolTableOffset(bytes) + index * if (bytes[4].toInt() == 2) 24 else 16

private fun extentSize(bytes: ByteArray, index: Int, value: ULong) =
    extentWord(bytes, extentOffset(bytes, index) + if (bytes[4].toInt() == 2) 16 else 8, value)

private fun extentValue(bytes: ByteArray, index: Int, value: ULong) =
    extentWord(bytes, extentOffset(bytes, index) + if (bytes[4].toInt() == 2) 8 else 4, value)

private fun extentWord(bytes: ByteArray, offset: Int, value: ULong) {
    val little = bytes[5].toInt() == 1
    if (bytes[4].toInt() == 2) FullTreeElfTestBytes.put64(bytes, offset, value, little)
    else FullTreeElfTestBytes.put32(bytes, offset, value.toLong(), little)
}

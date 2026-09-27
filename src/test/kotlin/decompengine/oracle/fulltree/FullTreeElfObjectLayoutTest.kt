package decompengine.oracle.fulltree

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FullTreeElfObjectLayoutTest {
    @Test
    fun `object scan covers both ELF classes byte orders and extended section indexes`() =
        inInterfaceFixtureDirectory { directory ->
            val variants = listOf(
                TestElfVariant(true, true, false, false),
                TestElfVariant(true, false, false, true),
                TestElfVariant(false, true, false, true),
                TestElfVariant(false, false, false, false),
                TestElfVariant(true, false, true, true),
            )
            variants.forEachIndexed { index, variant ->
                val bytes = objectBytes(variant, listOf(
                    TestElfSymbol("object_first", 0x110UL, type = 1),
                    TestElfSymbol("object_alias", 0x110UL, type = 1),
                    TestElfSymbol("function_only", 0x130UL, type = 2),
                ))
                setSymbolSize(bytes, 1, 8UL)
                setSymbolSize(bytes, 2, 8UL)
                val path = writeElf(directory.resolve("objects-$index.elf"), bytes)
                val (layout, symbols) = scanObjects(path)
                StableControlFile.open(path, bytes.size.toLong(), "object layout parity").use { source ->
                    val core = FullTreeElfLayout.scanLayout(source, "object layout parity")
                    assertEquals(core.elfClass, layout.elfClass)
                    assertEquals(core.byteOrder, layout.byteOrder)
                    assertEquals(core.elfType, layout.elfType)
                    assertEquals(core.machine, layout.machine)
                    assertEquals(core.osAbi, layout.osAbi)
                    assertEquals(core.abiVersion, layout.abiVersion)
                    assertEquals(core.imageBase, layout.imageBase)
                    assertEquals(core.executableRanges, layout.executableRanges)
                }
                assertEquals(4L, layout.scannedSymbols)
                assertEquals(listOf("object_first", "object_alias"), symbols.map { it.name })
                assertEquals(listOf(0x110UL, 0x110UL), symbols.map { it.rva })
                assertEquals(2, symbols.map { it.locator }.distinct().size)
                symbols.forEach { symbol ->
                    assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, symbol.storage)
                    assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbol.sectionKind)
                    assertEquals(1, symbol.type)
                    assertEquals(1, symbol.binding)
                    assertEquals(0, symbol.visibility)
                    assertEquals(0, symbol.other)
                    assertEquals(8UL, symbol.size)
                    assertEquals(".text", symbol.sectionName)
                    assertEquals(3UL, symbol.sectionFlags)
                    assertEquals(1L, symbol.sectionType)
                    assertEquals(0x400100UL, symbol.sectionAddress)
                    assertEquals(0x100UL, symbol.sectionSize)
                    assertEquals(listOf(0), symbol.segmentIndices)
                    assertEquals(if (variant.extendedNumbering) 0xffff else 1, symbol.rawSectionIndex)
                    assertEquals(if (variant.extendedNumbering) 0xff00L else 1L, symbol.resolvedSectionIndex)
                }
                val segment = layout.loadedMemory.single()
                assertEquals(0, segment.index)
                assertEquals(5L, segment.flags)
                assertEquals(0UL, segment.fileOffset)
                assertEquals(0x400000UL, segment.virtualAddress)
                assertEquals(bytes.size.toULong(), segment.fileSize)
                assertEquals(bytes.size.toULong(), segment.memorySize)
                assertEquals(0x400000UL + bytes.size.toULong(), segment.endExclusive)
                assertEquals(0x400000UL + bytes.size.toULong(), segment.fileEndExclusive)
                assertEquals(0UL, segment.rva)
                assertEquals(0x1000UL, segment.alignment)
                assertEquals(JsonPrimitive("0x1000"), segment.toJson()["alignment"])
                assertTrue(layout.tlsSegments.isEmpty())
                val repeated = scanObjects(path)
                assertEquals(layout.toJson(), repeated.first.toJson())
                assertEquals(symbols.map { it.toJson() }, repeated.second.map { it.toJson() })
            }
        }

    @Test
    fun `raw zero and one alignments remain distinct from missing alignment evidence`() =
        inInterfaceFixtureDirectory { directory ->
            objectElfVariants().forEachIndexed { index, variant ->
                listOf(0UL, 1UL).forEach { alignment ->
                    val bytes = objectBytes(variant, listOf(TestElfSymbol("object", 0x110UL, type = 1)))
                    addTlsProgram(bytes)
                    val program = FullTreeElfTestBytes.programHeaderOffset(bytes)
                    val stride = if (variant.is64Bit) 56 else 32
                    val field = if (variant.is64Bit) 48 else 28
                    putWord(bytes, program + field, alignment)
                    putWord(bytes, program + stride + field, alignment)
                    val layout = scanObjects(writeElf(directory.resolve("alignment-$index-$alignment.elf"), bytes)).first
                    listOf(layout.loadedMemory.single(), layout.tlsSegments.single()).forEach { segment ->
                        assertEquals(alignment, segment.alignment)
                        assertEquals(JsonPrimitive("0x${alignment.toString(16)}"), segment.toJson()["alignment"])
                    }
                }
            }
            val withoutAlignment = FullTreeElfMemorySegment(
                index = 0, flags = 5L, fileOffset = 0UL, virtualAddress = 0x400000UL,
                fileSize = 0x80UL, memorySize = 0x100UL, endExclusive = 0x400100UL,
                fileEndExclusive = 0x400080UL, rva = 0UL,
            )
            assertNull(withoutAlignment.alignment)
            assertEquals(JsonNull, withoutAlignment.toJson()["alignment"])
        }

    @Test
    fun `invalid segment alignment is rejected only by the object storage scan`() =
        inInterfaceFixtureDirectory { directory ->
            objectElfVariants().forEachIndexed { index, variant ->
                listOf(false, true).forEach { tls ->
                    listOf(false, true).forEach { nonPowerOfTwo ->
                        val bytes = objectBytes(variant, listOf(
                            TestElfSymbol("object", 0x110UL, type = 1),
                            TestElfSymbol("function_only", 0x130UL, type = 2),
                        ))
                        if (tls) addTlsProgram(bytes)
                        val stride = if (variant.is64Bit) 56 else 32
                        val program = FullTreeElfTestBytes.programHeaderOffset(bytes) + if (tls) stride else 0
                        val field = if (variant.is64Bit) 48 else 28
                        when {
                            nonPowerOfTwo -> putWord(bytes, program + field, 3UL)
                            tls -> {
                                putWord(bytes, program + field, 8UL)
                                // p_vaddr ends in 0x100; p_offset ends in 0x104, so residues differ.
                                putWord(bytes, program + if (variant.is64Bit) 8 else 4, 0x104UL)
                            }
                            else -> putWord(bytes, program + field, 0x800000UL)
                        }
                        val path = writeElf(directory.resolve("invalid-alignment-$index-$tls-$nonPowerOfTwo.elf"), bytes)
                        assertObjectScanRejected(path)
                        StableControlFile.open(path, bytes.size.toLong(), "legacy alignment compatibility").use { source ->
                            val core = FullTreeElfLayout.scanLayout(source, "legacy alignment compatibility")
                            val functions = arrayListOf<FullTreeElfFunctionSymbol>()
                            val observed = FullTreeElfLayout.scanFunctions(source, "legacy alignment compatibility",
                                consume = functions::add)
                            assertEquals(core.imageBase, observed.imageBase)
                            assertEquals(core.executableRanges, observed.executableRanges)
                            assertEquals(listOf("function_only"), functions.map { it.name })
                            assertEquals(listOf(0x130UL), functions.map { it.rva })
                        }
                    }
                }
            }
        }

    @Test
    fun `binding visibility and architecture-specific other bits survive extraction`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("weak_hidden", 0x110UL, type = 1)))
            val symbol = symbolOffset(bytes, 1)
            bytes[symbol + 4] = 0x21 // STB_WEAK | STT_OBJECT.
            bytes[symbol + 5] = 0xa2.toByte() // Preserve upper bits independently of STV_HIDDEN.
            setSymbolSize(bytes, 1, 4UL)
            val observed = scanObjects(writeElf(directory.resolve("visibility.elf"), bytes)).second.single()
            assertEquals(2, observed.binding)
            assertEquals(2, observed.visibility)
            assertEquals(0xa2, observed.other)
            assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, observed.storage)
        }

    @Test
    fun `undefined common absolute and reserved indexes retain distinct non-address storage facts`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(
                TestElfSymbol("undefined", null, type = 1),
                TestElfSymbol("common", 0UL, sectionIndex = 0xfff2, type = 1),
                TestElfSymbol("absolute", 0UL, sectionIndex = 0xfff1, type = 1),
                TestElfSymbol("reserved", 0UL, sectionIndex = 0xff00, type = 1),
            ))
            setSymbolValue(bytes, 2, 16UL) // SHN_COMMON st_value is alignment, not a virtual address.
            setSymbolSize(bytes, 2, 32UL)
            setSymbolValue(bytes, 3, 0x400110UL) // Even an address inside PT_LOAD remains SHN_ABS.
            setSymbolSize(bytes, 3, 4UL)
            val observed = scanObjects(writeElf(directory.resolve("special-indexes.elf"), bytes)).second
            assertEquals(listOf(
                FullTreeElfSymbolSectionKind.UNDEFINED,
                FullTreeElfSymbolSectionKind.COMMON,
                FullTreeElfSymbolSectionKind.ABSOLUTE,
                FullTreeElfSymbolSectionKind.RESERVED,
            ), observed.map { it.sectionKind })
            assertEquals(listOf(
                FullTreeElfObjectStorage.UNDEFINED,
                FullTreeElfObjectStorage.COMMON,
                FullTreeElfObjectStorage.ABSOLUTE,
                FullTreeElfObjectStorage.UNMAPPED,
            ), observed.map { it.storage })
            assertEquals(listOf(0, 0xfff2, 0xfff1, 0xff00), observed.map { it.rawSectionIndex })
            assertEquals(16UL, observed[1].value)
            assertEquals(32UL, observed[1].size)
            assertEquals(0x400110UL, observed[2].value)
            observed.forEach { symbol ->
                assertNull(symbol.rva)
                assertNull(symbol.sectionName)
                assertTrue(symbol.segmentIndices.isEmpty())
            }
            assertTrue(observed.last().reasons.isNotEmpty())
        }

    @Test
    fun `zero sized objects retain their size without borrowing a neighboring symbol extent`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(
                TestElfSymbol("zero", 0x110UL, type = 1),
                TestElfSymbol("next", 0x118UL, type = 1),
                TestElfSymbol("section_end", 0x200UL, type = 1),
            ))
            setSymbolSize(bytes, 2, 8UL)
            val observed = scanObjects(writeElf(directory.resolve("zero-sized.elf"), bytes)).second
            assertEquals(0UL, observed[0].size)
            assertEquals(0x110UL, observed[0].rva)
            assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, observed[0].storage)
            assertTrue(observed[0].reasons.isNotEmpty())
            assertEquals(8UL, observed[1].size)
            assertNull(observed[2].rva)
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, observed[2].storage)
        }

    @Test
    fun `zero sized PROGBITS at the file-backed end cannot claim the following zero-fill byte`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(
                TestElfSymbol("last_file_byte", 0x10fUL, type = 1),
                TestElfSymbol("first_zero_fill_byte", 0x110UL, type = 1),
            ))
            val program = FullTreeElfTestBytes.programHeaderOffset(bytes)
            putWord(bytes, program + 32, 0x110UL) // p_filesz ends at the second symbol's value.
            val (layout, symbols) = scanObjects(writeElf(directory.resolve("zero-sized-file-end.elf"), bytes))
            val segment = layout.loadedMemory.single()
            assertEquals(0x400110UL, segment.fileEndExclusive)
            assertTrue(segment.endExclusive > segment.fileEndExclusive)
            assertEquals(0UL, symbols[0].size)
            assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, symbols[0].storage)
            assertEquals(0x10fUL, symbols[0].rva)
            val atFileEnd = symbols[1]
            assertEquals(segment.fileEndExclusive, atFileEnd.value)
            assertEquals(0UL, atFileEnd.size)
            assertEquals(1L, atFileEnd.sectionType) // SHT_PROGBITS still extends through this address.
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, atFileEnd.storage)
            assertNull(atFileEnd.rva)
            assertTrue(atFileEnd.segmentIndices.isEmpty())
            assertTrue(atFileEnd.reasons.isNotEmpty())
        }

    @Test
    fun `positive object extents must fit both their section and a load segment`() =
        inInterfaceFixtureDirectory { directory ->
            val sectionCrossing = objectBytes(symbols = listOf(
                TestElfSymbol("inside", 0x1f8UL, type = 1),
                TestElfSymbol("crosses_section", 0x1fcUL, type = 1),
            ))
            setSymbolSize(sectionCrossing, 1, 8UL)
            setSymbolSize(sectionCrossing, 2, 8UL)
            val sectionObjects = scanObjects(writeElf(directory.resolve("section-crossing.elf"), sectionCrossing)).second
            assertEquals(0x1f8UL, sectionObjects[0].rva)
            assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, sectionObjects[0].storage)
            assertNull(sectionObjects[1].rva)
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, sectionObjects[1].storage)
            assertTrue(sectionObjects[1].reasons.isNotEmpty())

            val loadCrossing = objectBytes(symbols = listOf(TestElfSymbol("crosses_load", 0x110UL, type = 1)))
            setSymbolSize(loadCrossing, 1, 16UL)
            val program = FullTreeElfTestBytes.programHeaderOffset(loadCrossing)
            putWord(loadCrossing, program + 32, 0x118UL)
            putWord(loadCrossing, program + 40, 0x118UL)
            val loadObject = scanObjects(writeElf(directory.resolve("load-crossing.elf"), loadCrossing)).second.single()
            assertNull(loadObject.rva)
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, loadObject.storage)
            assertTrue(loadObject.reasons.isNotEmpty())
        }

    @Test
    fun `overflowing symbol ranges remain unresolved in both ELF address widths`() =
        inInterfaceFixtureDirectory { directory ->
            listOf(TestElfVariant(true, false, false, false), TestElfVariant(false, true, false, false))
                .forEachIndexed { index, variant ->
                    val bytes = objectBytes(variant, listOf(TestElfSymbol("overflow", 0x110UL, type = 1)))
                    val value = if (variant.is64Bit) ULong.MAX_VALUE - 7UL else 0xfffffff8UL
                    setSymbolValue(bytes, 1, value)
                    setSymbolSize(bytes, 1, 16UL)
                    val symbol = scanObjects(writeElf(directory.resolve("overflow-$index.elf"), bytes)).second.single()
                    assertEquals(value, symbol.value)
                    assertEquals(16UL, symbol.size)
                    assertNull(symbol.rva)
                    assertEquals(FullTreeElfObjectStorage.UNMAPPED, symbol.storage)
                    assertTrue(symbol.reasons.isNotEmpty())
                }
        }

    @Test
    fun `nonallocated sections do not become mapped objects merely by sharing a load address`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("nonalloc", 0x110UL, type = 1)))
            putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 8, 8), 0UL)
            setSymbolSize(bytes, 1, 4UL)
            val symbol = scanObjects(writeElf(directory.resolve("nonalloc.elf"), bytes)).second.single()
            assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbol.sectionKind)
            assertEquals(FullTreeElfObjectStorage.NONALLOC, symbol.storage)
            assertEquals(0UL, symbol.sectionFlags)
            assertNull(symbol.rva)
            assertTrue(symbol.segmentIndices.isEmpty())
        }

    @Test
    fun `inactive sections preserve raw metadata without acquiring storage from valid-looking addresses`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("inactive_section", 0x110UL, type = 1)))
            setSymbolSize(bytes, 1, 4UL)
            FullTreeElfTestBytes.put32(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 4, 4), 0, true)
            val symbol = scanObjects(writeElf(directory.resolve("inactive-section.elf"), bytes)).second.single()
            assertEquals(1, symbol.rawSectionIndex)
            assertEquals(1L, symbol.resolvedSectionIndex)
            assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbol.sectionKind)
            assertEquals(".text", symbol.sectionName)
            assertEquals(0L, symbol.sectionType) // SHT_NULL at a nonzero header index is still inactive.
            assertEquals(3UL, symbol.sectionFlags)
            assertEquals(0x400100UL, symbol.sectionAddress)
            assertEquals(0x100UL, symbol.sectionSize)
            assertEquals(0x400110UL, symbol.value)
            assertEquals(4UL, symbol.size)
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, symbol.storage)
            assertNull(symbol.rva)
            assertTrue(symbol.segmentIndices.isEmpty())
            assertTrue("inactive_section_has_no_storage" in symbol.reasons)
        }

    @Test
    fun `matching virtual addresses cannot hide mismatched section and segment file offsets`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("wrong_file_storage", 0x110UL, type = 1)))
            setSymbolSize(bytes, 1, 4UL)
            putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 16, 24), 0x108UL)
            val symbol = scanObjects(writeElf(directory.resolve("offset-mismatch.elf"), bytes)).second.single()
            assertEquals(0x400110UL, symbol.value)
            assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbol.sectionKind)
            assertEquals(FullTreeElfObjectStorage.UNMAPPED, symbol.storage)
            assertNull(symbol.rva)
            assertTrue(symbol.segmentIndices.isEmpty())
            assertTrue(symbol.reasons.isNotEmpty())
        }

    @Test
    fun `TLS symbols use template offsets and never manufacture process-relative addresses`() =
        inInterfaceFixtureDirectory { directory ->
            objectElfVariants()
                .forEachIndexed { index, variant ->
                    val bytes = appendTlsBssSection(objectBytes(variant, listOf(
                        TestElfSymbol("tls_initialized", 0UL, type = 6),
                        TestElfSymbol("tls_bss", 0UL, sectionIndex = 5, type = 6),
                        TestElfSymbol("tls_outside", 0UL, type = 6),
                    )))
                    addTlsProgram(bytes)
                    putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 8, 8), 0x403UL)
                    putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 20, 32), 0x40UL)
                    setSymbolValue(bytes, 1, 8UL)
                    setSymbolValue(bytes, 2, 0x60UL)
                    setSymbolValue(bytes, 3, 0x7fUL)
                    (1..3).forEach { setSymbolSize(bytes, it, 4UL) }
                    val (layout, symbols) = scanObjects(writeElf(directory.resolve("tls-$index.elf"), bytes))
                    assertEquals(1, layout.loadedMemory.size)
                    val tls = layout.tlsSegments.single()
                    assertEquals(1, tls.index)
                    assertEquals(0x400100UL, tls.virtualAddress)
                    assertEquals(0x40UL, tls.fileSize)
                    assertEquals(0x80UL, tls.memorySize)
                    assertEquals(0x400180UL, tls.endExclusive)
                    assertEquals(4UL, tls.alignment)
                    assertEquals(JsonPrimitive("0x4"), tls.toJson()["alignment"])
                    assertEquals(listOf(8UL, 0x60UL, 0x7fUL), symbols.map { it.value })
                    symbols.take(2).forEach { symbol ->
                        assertEquals(6, symbol.type)
                        assertEquals(FullTreeElfObjectStorage.TLS, symbol.storage)
                        assertEquals(listOf(1), symbol.segmentIndices)
                        assertNull(symbol.rva)
                    }
                    assertEquals(FullTreeElfObjectStorage.UNMAPPED, symbols[2].storage)
                    assertNull(symbols[2].rva)
                    assertTrue(symbols[2].reasons.isNotEmpty())
                }
        }

    @Test
    fun `malformed TLS template and load ranges fail before observations escape`() =
        inInterfaceFixtureDirectory { directory ->
            val invalidTemplate = objectBytes(symbols = listOf(TestElfSymbol("tls", 0UL, type = 6)))
            addTlsProgram(invalidTemplate)
            val tls = FullTreeElfTestBytes.programHeaderOffset(invalidTemplate) + 56
            putWord(invalidTemplate, tls + 32, 0x81UL) // p_filesz > p_memsz.
            assertObjectScanRejected(writeElf(directory.resolve("invalid-tls.elf"), invalidTemplate))

            val overflowingLoad = objectBytes(symbols = listOf(TestElfSymbol("object", 0x110UL, type = 1)))
            val load = FullTreeElfTestBytes.programHeaderOffset(overflowingLoad)
            putWord(overflowingLoad, load + 16, ULong.MAX_VALUE - 7UL)
            putWord(overflowingLoad, load + 32, 0UL)
            putWord(overflowingLoad, load + 40, 16UL)
            assertObjectScanRejected(writeElf(directory.resolve("overflowing-load.elf"), overflowingLoad))
        }

    @Test
    fun `object traversal rejects malformed extended section companions and invalid ordinary indexes`() =
        inInterfaceFixtureDirectory { directory ->
            val missing = objectBytes(symbols = listOf(TestElfSymbol("object", 0x110UL, forceExtendedIndex = true, type = 1)))
            assertObjectScanRejected(writeElf(directory.resolve("missing-shndx.elf"), missing))

            val nonExtendedWord = objectBytes(TestElfVariant(true, false, false, true), listOf(
                TestElfSymbol("object", 0x110UL, type = 1),
            ))
            FullTreeElfTestBytes.put32(nonExtendedWord, FullTreeElfTestBytes.shndxOffset(nonExtendedWord) + 4, 1, false)
            assertObjectScanRejected(writeElf(directory.resolve("unexpected-shndx-word.elf"), nonExtendedWord))

            val invalidCompanion = objectBytes(TestElfVariant(false, true, false, true), listOf(
                TestElfSymbol("object", 0x110UL, type = 1),
            ))
            FullTreeElfTestBytes.put32(invalidCompanion, FullTreeElfTestBytes.shndxLinkFieldOffset(invalidCompanion), 1, true)
            assertObjectScanRejected(writeElf(directory.resolve("invalid-shndx-link.elf"), invalidCompanion))

            val shortCompanion = objectBytes(TestElfVariant(true, true, false, true), listOf(
                TestElfSymbol("object", 0x110UL, type = 1),
            ))
            putWord(shortCompanion, FullTreeElfTestBytes.shndxFieldOffset(shortCompanion, FullTreeElfTestBytes.SHNDX_SIZE_FIELD), 4UL)
            assertObjectScanRejected(writeElf(directory.resolve("short-shndx.elf"), shortCompanion))

            val invalidOrdinary = objectBytes(symbols = listOf(TestElfSymbol("object", 0x110UL, sectionIndex = 99, type = 1)))
            assertObjectScanRejected(writeElf(directory.resolve("invalid-index.elf"), invalidOrdinary))
        }

    @Test
    fun `object names locators aggregate symbols and parser steps enforce existing limits`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(
                TestElfSymbol("object_name", 0x110UL, type = 1),
                TestElfSymbol("second_name", 0x118UL, type = 1),
            ))
            val path = writeElf(directory.resolve("bounded.elf"), bytes)
            listOf(
                FullTreeElfLayoutLimits(maximumSymbols = 2),
                FullTreeElfLayoutLimits(maximumFunctionNameBytes = 3),
                FullTreeElfLayoutLimits(maximumFunctionNameCodePoints = 3),
                FullTreeElfLayoutLimits(maximumLocatorBytes = 3),
                FullTreeElfLayoutLimits(maximumSectionNameBytes = 3),
                FullTreeElfLayoutLimits(maximumTotalSectionNameBytes = 3),
                FullTreeElfLayoutLimits(maximumParseSteps = 2),
            ).forEach { limits -> assertObjectScanRejected(path, limits) }
            val invalidName = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, false, false),
                listOf(TestElfSymbol("object_name", 0x110UL, type = 1)),
                invalidFirstNameUtf8 = true,
            )
            assertObjectScanRejected(writeElf(directory.resolve("invalid-name.elf"), invalidName))
            val unicode = objectBytes(symbols = listOf(TestElfSymbol("\u03b1\u03b2", 0x110UL, type = 1)))
            val unicodePath = writeElf(directory.resolve("unicode.elf"), unicode)
            assertEquals("\u03b1\u03b2", scanObjects(unicodePath,
                FullTreeElfLayoutLimits(maximumFunctionNameBytes = 4, maximumFunctionNameCodePoints = 2)).second.single().name)
            assertObjectScanRejected(unicodePath, FullTreeElfLayoutLimits(maximumFunctionNameBytes = 3))
            assertObjectScanRejected(unicodePath, FullTreeElfLayoutLimits(maximumFunctionNameCodePoints = 1))
        }

    @Test
    fun `object observations cannot escape a changed stable source`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("object", 0x110UL, type = 1)))
            val path = writeElf(directory.resolve("changing.elf"), bytes)
            StableControlFile.open(path, bytes.size.toLong(), "changing object ELF").use { source ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeElfLayout.scanObjects(source, "changing object ELF", checkpoint = {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
                    }) {}
                }
            }
        }

    @Test
    fun `published layout membership and symbol reasons cannot be mutated`() =
        inInterfaceFixtureDirectory { directory ->
            val bytes = objectBytes(symbols = listOf(TestElfSymbol("object", 0x110UL, type = 1)))
            setSymbolSize(bytes, 1, 4UL)
            val (layout, symbols) = scanObjects(writeElf(directory.resolve("immutable.elf"), bytes))
            val originalLayout = layout.toJson()
            val originalSymbol = symbols.single().toJson()
            assertFailsWith<UnsupportedOperationException> {
                (layout.loadedMemory as MutableList<FullTreeElfMemorySegment>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                (layout.tlsSegments as MutableList<FullTreeElfMemorySegment>).add(layout.loadedMemory.single())
            }
            assertFailsWith<UnsupportedOperationException> {
                (layout.executableRanges as MutableList<FullTreeElfExecutableRange>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                (symbols.single().segmentIndices as MutableList<Int>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                (symbols.single().reasons as MutableList<String>).clear()
            }
            assertEquals(originalLayout, layout.toJson())
            assertEquals(originalSymbol, symbols.single().toJson())
        }

    @Test
    fun `compiled objects preserve BSS TLS local visibility aliases and stripped dynamic symbols`() =
        inInterfaceFixtureDirectory { directory ->
            val source = directory.resolve("objects.c")
            Files.writeString(source, """
                int object_initialized = 7;
                int object_bss;
                static int object_local = 3;
                __attribute__((visibility("hidden"))) int object_hidden = 9;
                _Thread_local int object_tls = 11;
                _Thread_local int object_tls_bss;
                extern int object_alias __attribute__((alias("object_initialized")));
                int object_use(void) {
                    return object_initialized + object_bss + object_local + object_hidden
                        + object_tls + object_tls_bss;
                }
            """.trimIndent())
            val artifact = directory.resolve("objects.so")
            runObjectCommand(directory, listOf("cc", "-std=c11", "-O0", "-g", "-shared", "-fPIC",
                source.toString(), "-o", artifact.toString()))
            val (layout, symbols) = scanObjects(artifact)
            assertEquals("ET_DYN", layout.elfType)
            assertTrue(layout.loadedMemory.isNotEmpty())
            assertEquals(1, layout.tlsSegments.size)
            val byName = symbols.groupBy { it.name }
            val initialized = byName.getValue("object_initialized")
            assertEquals(2, initialized.size, "both SYMTAB and DYNSYM records must be retained")
            assertEquals(2, initialized.map { it.locator }.distinct().size)
            assertEquals(1, initialized.map { it.rva }.distinct().size)
            initialized.forEach { symbol ->
                assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, symbol.storage)
                assertEquals(4UL, symbol.size)
                assertNotNull(symbol.rva)
            }
            assertEquals(initialized.map { it.rva }.toSet(), byName.getValue("object_alias").map { it.rva }.toSet())
            byName.getValue("object_bss").forEach { symbol ->
                assertEquals(8L, symbol.sectionType) // SHT_NOBITS: memory storage without a file payload.
                assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, symbol.storage)
                assertNotNull(symbol.rva)
            }
            val local = byName.getValue("object_local").single()
            assertEquals(0, local.binding)
            assertEquals(FullTreeElfObjectStorage.MAPPED_LOAD, local.storage)
            byName.getValue("object_hidden").forEach { symbol ->
                // A shared-object linker may localize hidden globals and clear their visibility.
                assertTrue(symbol.visibility == 2 || symbol.binding == 0)
                assertFalse(symbol.locator.contains("=.dynsym:"))
            }
            listOf("object_tls", "object_tls_bss").forEach { name ->
                byName.getValue(name).forEach { symbol ->
                    assertEquals(6, symbol.type)
                    assertEquals(FullTreeElfObjectStorage.TLS, symbol.storage)
                    assertNull(symbol.rva)
                    assertTrue(symbol.segmentIndices.isNotEmpty())
                }
            }
            byName.getValue("object_tls_bss").forEach { assertEquals(8L, it.sectionType) }
            assertFalse(byName.containsKey("object_use"))

            val stripped = directory.resolve("objects-stripped.so")
            runObjectCommand(directory, listOf("strip", "--strip-all", "-o", stripped.toString(), artifact.toString()))
            val strippedObjects = scanObjects(stripped).second
            assertFalse(strippedObjects.any { it.name == "object_local" })
            assertFalse(strippedObjects.any { it.name == "object_hidden" })
            listOf("object_initialized", "object_alias", "object_bss", "object_tls", "object_tls_bss").forEach { name ->
                val symbol = strippedObjects.single { it.name == name }
                assertTrue(symbol.locator.contains("=.dynsym:"))
                val original = byName.getValue(name).first()
                assertEquals(original.value, symbol.value)
                assertEquals(original.size, symbol.size)
                assertEquals(original.storage, symbol.storage)
                assertEquals(original.rva, symbol.rva)
            }
        }
}

private fun objectElfVariants(): List<TestElfVariant> = listOf(
    TestElfVariant(true, true, false, false),
    TestElfVariant(true, false, false, false),
    TestElfVariant(false, true, false, false),
    TestElfVariant(false, false, false, false),
)

private fun objectBytes(
    variant: TestElfVariant = TestElfVariant(true, true, false, false),
    symbols: List<TestElfSymbol>,
): ByteArray = FullTreeElfTestBytes.build(variant, symbols).also { bytes ->
    putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 8, 8), 3UL)
    if (variant.extendedNumbering) {
        putWord(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 0xff00, 8, 8), 3UL)
    }
}

private fun scanObjects(
    path: Path,
    limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
): Pair<FullTreeElfObjectLayoutObservation, List<FullTreeElfObjectSymbol>> =
    StableControlFile.open(path, Files.size(path), "object fixture").use { source ->
        val symbols = arrayListOf<FullTreeElfObjectSymbol>()
        val layout = FullTreeElfLayout.scanObjects(source, "object fixture", limits, consume = symbols::add)
        source.verifyUnchanged("object fixture")
        layout to symbols
    }

private fun assertObjectScanRejected(path: Path, limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits()) {
    assertFailsWith<FullTreeControlException> { scanObjects(path, limits) }
}

private fun symbolOffset(bytes: ByteArray, index: Int): Int =
    FullTreeElfTestBytes.symbolTableOffset(bytes) + index * if (bytes[4].toInt() == 2) 24 else 16

private fun setSymbolSize(bytes: ByteArray, index: Int, size: ULong) =
    putWord(bytes, symbolOffset(bytes, index) + if (bytes[4].toInt() == 2) 16 else 8, size)

private fun setSymbolValue(bytes: ByteArray, index: Int, value: ULong) =
    putWord(bytes, symbolOffset(bytes, index) + if (bytes[4].toInt() == 2) 8 else 4, value)

private fun putWord(bytes: ByteArray, offset: Int, value: ULong) {
    val littleEndian = bytes[5].toInt() == 1
    if (bytes[4].toInt() == 2) FullTreeElfTestBytes.put64(bytes, offset, value, littleEndian)
    else FullTreeElfTestBytes.put32(bytes, offset, value.toLong(), littleEndian)
}

private fun addTlsProgram(bytes: ByteArray) {
    val is64 = bytes[4].toInt() == 2
    val littleEndian = bytes[5].toInt() == 1
    FullTreeElfTestBytes.put16(bytes, if (is64) 56 else 44, 2, littleEndian)
    val offset = FullTreeElfTestBytes.programHeaderOffset(bytes) + if (is64) 56 else 32
    FullTreeElfTestBytes.put32(bytes, offset, 7, littleEndian) // PT_TLS.
    FullTreeElfTestBytes.put32(bytes, offset + if (is64) 4 else 24, 4, littleEndian)
    putWord(bytes, offset + if (is64) 8 else 4, 0x100UL)
    putWord(bytes, offset + if (is64) 16 else 8, 0x400100UL)
    putWord(bytes, offset + if (is64) 24 else 12, 0x400100UL)
    putWord(bytes, offset + if (is64) 32 else 16, 0x40UL)
    putWord(bytes, offset + if (is64) 40 else 20, 0x80UL)
    putWord(bytes, offset + if (is64) 48 else 28, 4UL)
}

private fun appendTlsBssSection(original: ByteArray): ByteArray {
    val is64 = original[4].toInt() == 2
    val littleEndian = original[5].toInt() == 1
    val sectionBytes = if (is64) 64 else 40
    val bytes = original.copyOf(original.size + sectionBytes)
    FullTreeElfTestBytes.put16(bytes, if (is64) 60 else 48, 6, littleEndian)
    val source = FullTreeElfTestBytes.sectionFieldOffset(bytes, 1, 0, 0)
    val target = FullTreeElfTestBytes.sectionFieldOffset(bytes, 5, 0, 0)
    bytes.copyInto(bytes, target, source, source + sectionBytes)
    FullTreeElfTestBytes.put32(bytes, target + 4, 8, littleEndian) // SHT_NOBITS.
    putWord(bytes, target + 8, 0x403UL) // SHF_WRITE | SHF_ALLOC | SHF_TLS.
    putWord(bytes, target + if (is64) 16 else 12, 0x400140UL)
    putWord(bytes, target + if (is64) 24 else 16, 0x140UL)
    putWord(bytes, target + if (is64) 32 else 20, 0x40UL)
    return bytes
}

private fun runObjectCommand(directory: Path, command: List<String>) {
    val diagnostics = directory.resolve("object-command.log")
    val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true)
        .redirectOutput(diagnostics.toFile()).apply {
            environment()["TMPDIR"] = directory.toString()
            environment()["TMP"] = directory.toString()
            environment()["TEMP"] = directory.toString()
        }.start()
    try {
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "object fixture command exceeded its bounded runtime")
        val message = Files.newInputStream(diagnostics).use { it.readNBytes(16_384).toString(Charsets.UTF_8) }
        assertEquals(0, process.exitValue(), message)
    } finally {
        if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
    }
}

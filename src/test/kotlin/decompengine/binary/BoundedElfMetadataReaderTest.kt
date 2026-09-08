package decompengine.binary

import decompengine.jobs.elfFixture
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.fulltree.FullTreeElfTestBytes
import decompengine.oracle.fulltree.TestElfSymbol
import decompengine.oracle.fulltree.TestElfVariant
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.oracle.fulltree.writeElf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BoundedElfMetadataReaderTest {
    @Test
    fun `positional metadata preserves ELF class byte order and ordinary symtab emptiness`() = inControlTemporaryDirectory { root ->
        for ((index, variant) in variants.withIndex()) {
            val bytes = FullTreeElfTestBytes.build(variant, listOf(
                TestElfSymbol("authored_defined", 0x100UL), TestElfSymbol("authored_undefined", null),
            ))
            val input = writeElf(root.resolve("ordinary-$index.elf"), bytes)

            val result = BoundedElfMetadataReader.read(input)

            assertEquals(ElfMetadataReader.read(bytes), result.metadata)
            assertEquals(if (variant.is64Bit) "ELF64" else "ELF32", result.metadata.format)
            assertEquals(if (variant.littleEndian) "little" else "big", result.metadata.endianness)
            assertTrue(result.symbolInventory.isEmpty)
            assertEquals(bytes.size.toLong(), result.inputBytes)
            assertEquals(OracleArtifacts.sha256(bytes), result.inputSha256)
            assertEquals(0, result.usage.symbolsScanned.toInt())
        }
    }

    @Test
    fun `header only input preserves metadata counts and empty inventory`() = inControlTemporaryDirectory { root ->
        val bytes = elfFixture()
        val input = writeElf(root.resolve("header-only.elf"), bytes)

        val result = BoundedElfMetadataReader.read(input)

        assertEquals(ElfMetadataReader.read(bytes), result.metadata)
        assertEquals(5.toUShort(), result.metadata.sectionHeaderCount)
        assertTrue(result.symbolInventory.isEmpty)
        assertEquals(0, result.usage.sectionHeadersVisited.toInt())
        assertEquals(OracleArtifacts.sha256(bytes), result.inputSha256)
    }

    @Test
    fun `dynamic inventory retains order duplicates binding and unsigned size in all layouts`() = inControlTemporaryDirectory { root ->
        for ((index, variant) in variants.withIndex()) {
            val bytes = dynamicFixture(variant)
            val input = writeElf(root.resolve("dynamic-$index.elf"), bytes)

            val result = BoundedElfMetadataReader.read(input)

            assertEquals(ElfMetadataReader.read(bytes), result.metadata)
            assertEquals(expectedInventory, result.symbolInventory)
            assertEquals(7, result.usage.symbolsScanned.toInt())
            assertEquals(5, result.usage.symbolsRetained.toInt())
            val expectedNameBytes = expectedInventory.all.sumOf { it.name.toByteArray().size }.toLong()
            assertEquals(expectedNameBytes, result.usage.retainedNameBytes)
            assertEquals(expectedNameBytes + 5, result.usage.nameBytesVisited)
            assertFailsWith<UnsupportedOperationException> {
                (result.symbolInventory.functions as MutableList<UnresolvedSymbol>).clear()
            }
            assertEquals(ElfSymbolInventoryReader.read(bytes, result.metadata), result.symbolInventory)
            if (!variant.is64Bit) {
                // ELF32 st_size is the recorded unsigned value, not the 16-byte entry size.
                assertEquals(0x80000001UL, result.symbolInventory.objects.single().size)
            }
        }
    }

    @Test
    fun `small explicit budgets reject ordinary metadata instead of returning partial inventories`() = inControlTemporaryDirectory { root ->
        val bytes = dynamicFixture(variants.first())
        val input = writeElf(root.resolve("budgeted.elf"), bytes)
        val complete = BoundedElfMetadataReader.read(input)
        assertEquals(expectedInventory, complete.symbolInventory)
        val defaults = BoundedElfMetadataLimits()
        val cases = listOf(
            "input bytes" to defaults.copy(maximumInputBytes = bytes.size.toLong() - 1),
            "sections" to defaults.copy(maximumSectionHeaders = 1),
            "scanned symbols" to defaults.copy(maximumScannedSymbols = 1),
            "retained symbols" to defaults.copy(maximumRetainedSymbols = 1),
            "name length" to defaults.copy(maximumNameBytes = 3),
            "repeated cached name visits" to defaults.copy(maximumNameByteVisits = complete.usage.nameBytesVisited - 1),
            "retained names" to defaults.copy(maximumRetainedNameBytes = complete.usage.retainedNameBytes - 1),
            "modeled metadata" to defaults.copy(maximumModeledMetadataBytes = complete.usage.modeledMetadataBytes - 1),
            "metadata reads" to defaults.copy(maximumMetadataReadBytes = complete.usage.metadataReadBytes - 1),
            "parse work" to defaults.copy(maximumWorkUnits = complete.usage.workUnits - 1),
        )
        for ((description, limits) in cases) {
            assertFailsWith<IllegalArgumentException>(description) { BoundedElfMetadataReader.read(input, limits) }
        }
    }

    @Test
    fun `metadata reads stay within fixed windows when ordinary trailing bytes grow the file`() = inControlTemporaryDirectory { root ->
        val headerAndTables = FullTreeElfTestBytes.build(variants.first(), listOf(TestElfSymbol("authored", 0x100UL)))
        val bytes = headerAndTables.copyOf(1024 * 1024 + 17)
        val input = writeElf(root.resolve("padded.elf"), bytes)

        val result = BoundedElfMetadataReader.read(input)

        assertEquals(bytes.size.toLong(), result.inputBytes)
        assertEquals(OracleArtifacts.sha256(bytes), result.inputSha256)
        assertEquals(ElfMetadataReader.read(bytes), result.metadata)
        assertTrue(result.symbolInventory.isEmpty)
        assertTrue(result.usage.metadataReadBytes <= 2L * 64 * 1024)
        assertTrue(result.usage.metadataReadBytes < result.inputBytes)
    }

    @Test
    fun `initial authentication interruption remains cancellation`() = inControlTemporaryDirectory { root ->
        val input = writeElf(root.resolve("cancelled.elf"), elfFixture())
        try {
            assertFailsWith<InterruptedException> {
                BoundedElfMetadataReader.read(input) { stage ->
                    if (stage == "while hashing ELF metadata input initial authentication") Thread.currentThread().interrupt()
                }
            }
        } finally {
            Thread.interrupted()
        }
        assertTrue(BoundedElfMetadataReader.read(input).symbolInventory.isEmpty)
    }

    @Test
    fun `elapsed budget includes terminal authentication`() = inControlTemporaryDirectory { root ->
        val input = writeElf(root.resolve("deadline.elf"), elfFixture())
        var reachedTerminalAuthentication = false
        val failure = assertFailsWith<BoundedElfMetadataLimitException> {
            BoundedElfMetadataReader.read(input, BoundedElfMetadataLimits(maximumWallClockMillis = 250)) { stage ->
                if (stage == "before ELF metadata input terminal authentication") {
                    reachedTerminalAuthentication = true
                    Thread.sleep(300)
                }
            }
        }
        assertTrue(reachedTerminalAuthentication)
        assertTrue(failure.message.orEmpty().contains("elapsed-time limit exceeded"))
    }

    private fun dynamicFixture(variant: TestElfVariant): ByteArray {
        val symbols = listOf(
            TestElfSymbol("authored_fn", null),
            TestElfSymbol("weak_fn", null),
            TestElfSymbol("authored_object", null, type = 1),
            TestElfSymbol("authored_other", null, type = 0),
            TestElfSymbol("authored_defined", 0x100UL),
            TestElfSymbol("authored_fn", null),
        )
        val bytes = FullTreeElfTestBytes.build(variant, symbols)
        // Author the same ordinary table as SHT_DYNSYM; section names do not select its meaning.
        FullTreeElfTestBytes.put32(bytes, FullTreeElfTestBytes.sectionFieldOffset(bytes, 2, 4, 4), 11, variant.littleEndian)
        val table = FullTreeElfTestBytes.symbolTableOffset(bytes)
        val entryBytes = if (variant.is64Bit) 24 else 16
        val bindings = listOf(1, 2, 0, 3, 1, 1)
        val sizes = listOf(0UL, 8UL, 0x80000001UL, 3UL, 4UL, 0UL)
        for (index in symbols.indices) {
            val entry = table + (index + 1) * entryBytes
            bytes[entry + if (variant.is64Bit) 4 else 12] = ((bindings[index] shl 4) or symbols[index].type).toByte()
            if (variant.is64Bit) FullTreeElfTestBytes.put64(bytes, entry + 16, sizes[index], variant.littleEndian)
            else FullTreeElfTestBytes.put32(bytes, entry + 8, sizes[index].toLong(), variant.littleEndian)
        }
        return bytes
    }

    private val variants = listOf(true, false).flatMap { is64 ->
        listOf(true, false).map { little -> TestElfVariant(is64, little, extendedNumbering = false, shndx = false) }
    }

    private val expectedInventory = SymbolInventory(
        functions = listOf(
            UnresolvedSymbol("authored_fn", SymbolKind.FUNCTION, SymbolBinding.GLOBAL, 0UL),
            UnresolvedSymbol("weak_fn", SymbolKind.FUNCTION, SymbolBinding.WEAK, 8UL),
            UnresolvedSymbol("authored_fn", SymbolKind.FUNCTION, SymbolBinding.GLOBAL, 0UL),
        ),
        objects = listOf(UnresolvedSymbol("authored_object", SymbolKind.OBJECT, SymbolBinding.LOCAL, 0x80000001UL)),
        other = listOf(UnresolvedSymbol("authored_other", SymbolKind.OTHER, SymbolBinding.UNKNOWN, 3UL)),
    )
}

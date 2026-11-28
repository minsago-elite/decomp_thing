package decompengine.oracle.externalcalls

import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfFunctionSymbol
import decompengine.oracle.fulltree.FullTreeElfLayout
import decompengine.oracle.fulltree.FullTreeElfLayoutLimits
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonPrimitive

class BoundedElfDynamicBindingsV1Test {
    @Test
    fun `raw inventory preserves null unnamed weak NOTYPE defined IFUNC and version identities`(): Unit = withDynamicFixture { directory ->
        val fixture = DynamicBindingElfFixtureV1()
        val inventory = scan(directory, fixture.bytes)
        assertEquals(8, inventory.dynamicSymbols.size)
        val symbols = inventory.dynamicSymbols
        assertEquals(0L, symbols[0].symbolIndex)
        assertEquals("", symbols[0].name)
        assertEquals(0, symbols[0].raw.info)
        assertEquals(FullTreeElfSymbolSectionKind.UNDEFINED, symbols[1].raw.sectionKind)
        assertEquals(0x400220UL, symbols[1].raw.value, "undefined does not imply a zero st_value")
        assertEquals(0, symbols[2].type)
        assertEquals(2, symbols[2].binding)
        assertEquals(10, symbols[3].type)
        assertEquals("", symbols[4].name)
        assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbols[4].raw.sectionKind)
        assertEquals(FullTreeElfSymbolSectionKind.DEFINED, symbols[5].raw.sectionKind)
        assertEquals("required-version", symbols[5].version!!.kind, "copy-relocation definitions may carry VERNEED")
        assertEquals(0x8003, symbols[6].version!!.raw)
        assertTrue(symbols[6].version!!.hidden)
        assertEquals("LIB_TEST_1", symbols[6].version!!.name)
        assertEquals("libc.so.6", symbols[1].version!!.providerRequest)
        assertEquals(listOf("libc.so.6"), inventory.neededLibraries)
        assertEquals(listOf("BASE_VERSION"), inventory.versionDefinitions.single().parentNames)
        assertTrue(inventory.dynamicEntries.last().tag == 0UL)
        assertEquals(2, inventory.programHeaders.size)
        assertEquals(12, inventory.sections.size)
        val json = inventory.toJson()
        listOf("complete", "releaseEligible", "negativeCompleteness").forEach { assertEquals(JsonPrimitive(false), json[it]) }
        assertEquals(JsonPrimitive("section-declared-dynsym"), json["symbolPopulationBasis"])
        assertTrue("runtime-provider-and-interposition-unresolved" in inventory.unsupportedReasons)
        val baseDefinition = DynamicBindingElfFixtureV1()
        baseDefinition.word16(0x762, 1); baseDefinition.word16(0x764, 1)
        baseDefinition.word16(0x706, 1); baseDefinition.word16(0x70c, 1)
        val unversioned = scan(directory, baseDefinition.bytes).dynamicSymbols[6].version!!
        assertEquals("global-unversioned", unversioned.kind)
        assertNull(unversioned.name, "VERDEF base index 1 must not turn an unversioned symbol into a versioned import")
        assertNull(unversioned.providerRequest)
    }

    @Test
    fun `relocation inventory keeps weak null unsupported IFUNC and competing physical slots`(): Unit = withDynamicFixture { directory ->
        val inventory = scan(directory, DynamicBindingElfFixtureV1().bytes)
        assertEquals(10, inventory.relocations.size)
        val relas = inventory.relocations.filter { it.sectionIndex == 4 }
        assertEquals(listOf(8L, 6L, 6L, 6L, 6L, 6L), relas.map { it.type })
        assertTrue("unsupported-relocation-type" in relas[0].dispositions)
        assertTrue("weak-import-may-resolve-null" in relas[1].dispositions)
        assertTrue("ifunc-runtime-resolution-unresolved" in relas[2].dispositions)
        assertTrue("defined-symbol-runtime-binding-unresolved" in relas[3].dispositions)
        assertTrue("non-function-symbol-reference" in relas[4].dispositions)
        assertTrue("null-symbol-reference" in relas[5].dispositions)
        val plt = inventory.relocations.filter { it.sectionIndex == 5 }
        assertEquals(listOf(1L, 1L, 4L, 0L), plt.map { it.symbolIndex })
        assertEquals(0x800L, plt.first().slotFileOffset)
        assertEquals(listOf("jmprel"), plt.first().dynamicTables)
        assertTrue(plt.take(2).all { "competing-relocation-slot" in it.dispositions })
        assertTrue("irelative-runtime-resolver-unresolved" in plt.last().dispositions)
        assertEquals(0x400240L, plt.last().addend)
        assertNull(relas[0].slotFileOffset, "unsupported destination width must not get a guessed mapping")
        for (tag in listOf(36UL, 0x6000000fUL, 0x6fffe000UL, 0x60001234UL)) {
            val unsupported = DynamicBindingElfFixtureV1(); unsupported.tagType(1UL, tag)
            val reasons = scan(directory, unsupported.bytes).unsupportedReasons
            assertTrue(reasons.any { it == "packed-relr-relocations-not-expanded" ||
                it == "android-packed-relocations-not-expanded" || it == "unclassified-dynamic-tag" })
        }
    }

    @Test
    fun `overlapping RELA and JMPREL membership is retained once and REL keeps unknown implicit addend`(): Unit = withDynamicFixture { directory ->
        val same = DynamicBindingElfFixtureV1()
        same.tag(7UL, 0x400600UL); same.tag(8UL, 96UL)
        val inventory = scan(directory, same.bytes)
        assertEquals(10, inventory.relocations.size)
        assertEquals(listOf("rela", "jmprel"), inventory.relocations.first { it.sectionIndex == 5 }.dynamicTables)
        assertTrue(inventory.relocations.filter { it.sectionIndex == 4 }.all { it.dynamicTables.isEmpty() })
        val rel = DynamicBindingElfFixtureV1()
        rel.word32(rel.section(4) + 4, 9)
        rel.word64(rel.section(4) + 32, 16UL)
        rel.word64(rel.section(4) + 56, 16UL)
        rel.tagType(7UL, 17UL); rel.tagType(8UL, 18UL); rel.tagType(9UL, 19UL)
        rel.tag(18UL, 16UL); rel.tag(19UL, 16UL)
        val implicit = scan(directory, rel.bytes).relocations.single { it.sectionIndex == 4 }
        assertNull(implicit.addend)
        assertEquals(listOf("rel"), implicit.dynamicTables)
        val relativePrefix = DynamicBindingElfFixtureV1()
        relativePrefix.tagType(1UL, 0x6ffffff9UL); relativePrefix.tag(0x6ffffff9UL, 1UL)
        assertEquals(10, scan(directory, relativePrefix.bytes).relocations.size)
        relativePrefix.tag(0x6ffffff9UL, 2UL)
        assertFailsWith<FullTreeControlException> { scan(directory, relativePrefix.bytes) }
        relativePrefix.tag(0x6ffffff9UL, 999UL)
        assertFailsWith<FullTreeControlException> { scan(directory, relativePrefix.bytes) }
    }

    @Test
    fun `unmapped zero filled and ambiguous slots retain their raw references`(): Unit = withDynamicFixture { directory ->
        val fixture = DynamicBindingElfFixtureV1()
        fixture.word64(0x600, 0x900000UL)
        fixture.word64(0x618, 0x400f08UL)
        fixture.word64(0x40 + 40, 0x1000UL) // extend only LOAD memory, never file storage
        val inventory = scan(directory, fixture.bytes)
        val entries = inventory.relocations.filter { it.sectionIndex == 5 }
        assertTrue("unmapped-slot" in entries[0].dispositions)
        assertTrue("zero-filled-slot" in entries[1].dispositions)
        assertNull(entries[0].slotFileOffset)
        assertNull(entries[1].slotFileOffset)
    }

    @Test
    fun `malformed dynamic tags links pointers widths and dangling relocation symbols fail closed`(): Unit = withDynamicFixture { directory ->
        val mutations: List<(DynamicBindingElfFixtureV1) -> Unit> = listOf(
            { it.tagType(1UL, 6UL) }, // duplicate singleton
            { it.tag(5UL, 0x400301UL) },
            { it.tag(11UL, 32UL) },
            { it.tag(8UL, 23UL) },
            { it.tag(20UL, 123UL) },
            { it.word64(0x608, (999UL shl 32) or 7UL) },
            { it.word32(it.section(4) + 40, 2) },
            { it.word64(0x78 + 8, 0x901UL) },
            { it.word64(it.section(10) + 24, 0x901UL) },
            { it.word64(0x900 + 16 * 16, 1UL) }, // lose DT_NULL
        )
        mutations.forEachIndexed { index, mutation ->
            val fixture = DynamicBindingElfFixtureV1(); mutation(fixture)
            assertFailsWith<FullTreeControlException>("mutation $index") { scan(directory, fixture.bytes) }
        }
    }

    @Test
    fun `GNU version chains hashes dangling indices and counts are validated before return`(): Unit = withDynamicFixture { directory ->
        val mutations: List<(DynamicBindingElfFixtureV1) -> Unit> = listOf(
            { it.word16(0x702, 9) },
            { it.word32(0x720 + 12, 4) },
            { it.word32(0x720 + 8, 4) },
            { it.word16(0x720 + 2, 2) },
            { it.word32(0x730 + 12, 4) },
            { it.word32(0x730, 0) },
            { it.word32(0x760 + 12, 4) },
            { it.word16(0x760 + 4, 2) }, // requirement/definition index collision
            { it.tag(0x6fffffffUL, 2UL) },
            { it.word64(it.section(6) + 32, 14UL) },
            { it.word32(it.section(6) + 40, 2) },
            { it.word16(0x700, 1) },
        )
        mutations.forEachIndexed { index, mutation ->
            val fixture = DynamicBindingElfFixtureV1(); mutation(fixture)
            assertFailsWith<FullTreeControlException>("version mutation $index") { scan(directory, fixture.bytes) }
        }
    }

    @Test
    fun `overlapping LOAD ownership and metadata section overlap cannot select an arbitrary source`(): Unit = withDynamicFixture { directory ->
        val fixture = DynamicBindingElfFixtureV1()
        fixture.word16(56, 3)
        fixture.bytes.copyInto(fixture.bytes, 0xb0, 0x40, 0x78)
        assertFailsWith<FullTreeControlException> { scan(directory, fixture.bytes) }
        val overlap = DynamicBindingElfFixtureV1()
        overlap.word64(overlap.section(6) + 16, 0x400400UL)
        overlap.word64(overlap.section(6) + 24, 0x400UL)
        overlap.tag(0x6ffffff0UL, 0x400400UL)
        assertFailsWith<FullTreeControlException> { scan(directory, overlap.bytes) }
    }

    @Test
    fun `resource identity cancellation and changed source boundaries fail before successful return`(): Unit = withDynamicFixture { directory ->
        val bytes = DynamicBindingElfFixtureV1().bytes
        val limits = listOf(
            ElfDynamicBindingLimitsV1(maximumDynamicEntries = 1), ElfDynamicBindingLimitsV1(maximumDynamicSymbols = 1),
            ElfDynamicBindingLimitsV1(maximumRelocations = 1), ElfDynamicBindingLimitsV1(maximumVersionRecords = 1),
            ElfDynamicBindingLimitsV1(maximumStringBytes = 1), ElfDynamicBindingLimitsV1(maximumTotalStringBytes = 1),
            ElfDynamicBindingLimitsV1(maximumReadBytes = 1), ElfDynamicBindingLimitsV1(maximumWorkUnits = 1),
            ElfDynamicBindingLimitsV1(maximumOutputBytes = 1),
            ElfDynamicBindingLimitsV1(layout = FullTreeElfLayoutLimits(maximumProgramHeaders = 1)),
        )
        limits.forEach { assertFailsWith<FullTreeControlException> { scan(directory, bytes, it) } }
        val path = directory.resolve("identity.elf"); Files.write(path, bytes)
        StableControlFile.open(path, bytes.size.toLong(), "dynamic test").use { file ->
            assertFailsWith<IllegalArgumentException> { BoundedElfDynamicBindingsV1.scan(file, "0".repeat(64)) }
            val cancellation = IllegalStateException("authored cancellation")
            val actual = assertFailsWith<IllegalStateException> {
                BoundedElfDynamicBindingsV1.scan(file, file.authenticatedSha256, checkpoint = { throw cancellation })
            }
            assertSame(cancellation, actual)
        }
        val replacement = directory.resolve("replacement.elf"); Files.write(replacement, bytes)
        StableControlFile.open(path, bytes.size.toLong(), "dynamic test").use { file ->
            assertFailsWith<FullTreeControlException> {
                BoundedElfDynamicBindingsV1.scan(file, file.authenticatedSha256, checkpoint = { phase ->
                    if (phase == "after dynamic-binding inventory") Files.move(replacement, path, StandardCopyOption.REPLACE_EXISTING)
                })
            }
        }
    }

    @Test
    fun `raw seam preserves frozen function observations and has immutable output collections`(): Unit = withDynamicFixture { directory ->
        val path = directory.resolve("frozen.elf"); Files.write(path, DynamicBindingElfFixtureV1().bytes)
        StableControlFile.open(path, Files.size(path), "frozen").use { file ->
            fun functions(): List<FullTreeElfFunctionSymbol> = arrayListOf<FullTreeElfFunctionSymbol>().also {
                FullTreeElfLayout.scanFunctions(file, "frozen", consume = it::add)
            }
            val before = functions()
            val inventory = BoundedElfDynamicBindingsV1.scan(file, file.authenticatedSha256)
            assertEquals(before, functions())
            assertFailsWith<UnsupportedOperationException> { (inventory.dynamicSymbols as MutableList<*>).clear() }
            assertFailsWith<UnsupportedOperationException> { (inventory.relocations.first().dynamicTables as MutableList<*>).clear() }
            assertFalse(inventory.dynamicSymbols.isEmpty())
        }
    }
}

private fun scan(directory: Path, bytes: ByteArray, limits: ElfDynamicBindingLimitsV1 = ElfDynamicBindingLimitsV1()): ElfDynamicBindingInventoryV1 {
    val path = directory.resolve("input.elf"); Files.write(path, bytes)
    return StableControlFile.open(path, bytes.size.toLong(), "dynamic fixture").use { file ->
        BoundedElfDynamicBindingsV1.scan(file, file.authenticatedSha256, limits)
    }
}

internal fun withDynamicFixture(action: (Path) -> Unit) {
    val root = Path.of("build", "dynamic-binding-tests").toAbsolutePath(); Files.createDirectories(root)
    val directory = Files.createTempDirectory(root, "fixture-")
    try { action(directory) } finally { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
}

/** Fully authored ELF; no compiler, recovered facts, external runtime or host oracle is involved. */
internal class DynamicBindingElfFixtureV1 {
    val bytes = ByteArray(0xf00)
    private val tags = linkedMapOf<ULong, Int>()
    private val names = linkedMapOf<String, Int>()
    init {
        byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1).copyInto(bytes)
        word16(16, 3); word16(18, 62); word32(20, 1)
        word64(32, 0x40UL); word64(40, 0xc00UL)
        word16(52, 64); word16(54, 56); word16(56, 2); word16(58, 64); word16(60, 12); word16(62, 11)
        word32(0x40, 1); word32(0x44, 7); word64(0x50, 0x400000UL)
        word64(0x60, bytes.size.toULong()); word64(0x68, bytes.size.toULong()); word64(0x70, 0x1000UL)
        var stringOffset = 1
        listOf("puts", "weak_name", "resolver", "copied", "local_export", "external_data", "libc.so.6", "GLIBC_X", "LIB_TEST_1", "BASE_VERSION").forEach { name ->
            names[name] = stringOffset; val encoded = name.toByteArray(); encoded.copyInto(bytes, 0x300 + stringOffset); stringOffset += encoded.size + 1
        }
        var sectionNameOffset = 1
        val sectionNames = listOf("", ".text", ".dynstr", ".dynsym", ".rela.dyn", ".rela.plt", ".gnu.version", ".gnu.version_r", ".gnu.version_d", ".got", ".dynamic", ".shstrtab")
        sectionNames.forEachIndexed { index, name ->
            if (index != 0) { word32(section(index), sectionNameOffset.toLong()); val encoded = name.toByteArray(); encoded.copyInto(bytes, 0xb00 + sectionNameOffset); sectionNameOffset += encoded.size + 1 }
        }
        header(1, 1, 6UL, 0x200, 0x100, 0, 0, 16, 0)
        header(2, 3, 2UL, 0x300, stringOffset, 0, 0, 1, 0)
        header(3, 11, 2UL, 0x400, 8 * 24, 2, 1, 8, 24)
        header(4, 4, 2UL, 0x500, 6 * 24, 3, 9, 8, 24)
        header(5, 4, 2UL, 0x600, 4 * 24, 3, 9, 8, 24)
        header(6, 0x6fffffff, 2UL, 0x700, 16, 3, 0, 2, 2)
        header(7, 0x6ffffffe, 2UL, 0x720, 32, 2, 1, 4, 0)
        header(8, 0x6ffffffd, 2UL, 0x760, 36, 2, 1, 4, 0)
        header(9, 1, 3UL, 0x800, 0x100, 0, 0, 8, 0)
        header(11, 3, 0UL, 0xb00, sectionNameOffset, 0, 0, 1, 0)
        symbol(1, "puts", 0x12, 0, 0x400220UL, 0UL)
        symbol(2, "weak_name", 0x20, 0, 0UL, 0UL)
        symbol(3, "resolver", 0x1a, 1, 0x400240UL, 16UL)
        symbol(4, "", 0x10, 1, 0x400250UL, 0UL)
        symbol(5, "copied", 0x11, 1, 0x400260UL, 8UL)
        symbol(6, "local_export", 0x12, 1, 0x400270UL, 16UL)
        symbol(7, "external_data", 0x11, 0, 0UL, 0UL)
        listOf(0, 2, 1, 3, 1, 2, 0x8003, 1).forEachIndexed { index, version -> word16(0x700 + index * 2, version) }
        word16(0x720, 1); word16(0x722, 1); word32(0x724, names.getValue("libc.so.6").toLong()); word32(0x728, 16)
        word32(0x730, hash("GLIBC_X")); word16(0x736, 2); word32(0x738, names.getValue("GLIBC_X").toLong())
        word16(0x760, 1); word16(0x764, 3); word16(0x766, 2); word32(0x768, hash("LIB_TEST_1")); word32(0x76c, 20)
        word32(0x774, names.getValue("LIB_TEST_1").toLong()); word32(0x778, 8); word32(0x77c, names.getValue("BASE_VERSION").toLong())
        listOf(Triple(0, 8, 0x820), Triple(2, 6, 0x828), Triple(3, 6, 0x830), Triple(5, 6, 0x838), Triple(7, 6, 0x840), Triple(0, 6, 0x848)).forEachIndexed { index, value ->
            relocation(0x500 + index * 24, value.first, value.second, value.third, 0UL)
        }
        listOf(Triple(1, 7, 0x800), Triple(1, 7, 0x800), Triple(4, 7, 0x808), Triple(0, 37, 0x810)).forEachIndexed { index, value ->
            relocation(0x600 + index * 24, value.first, value.second, value.third, if (value.second == 37) 0x400240UL else 0UL)
        }
        val dynamic = listOf(1UL to names.getValue("libc.so.6").toULong(), 5UL to 0x400300UL, 10UL to stringOffset.toULong(),
            6UL to 0x400400UL, 11UL to 24UL, 7UL to 0x400500UL, 8UL to 144UL, 9UL to 24UL,
            23UL to 0x400600UL, 2UL to 96UL, 20UL to 7UL, 0x6ffffff0UL to 0x400700UL,
            0x6ffffffeUL to 0x400720UL, 0x6fffffffUL to 1UL, 0x6ffffffcUL to 0x400760UL, 0x6ffffffdUL to 1UL, 0UL to 0UL)
        dynamic.forEachIndexed { index, pair -> val offset = 0x900 + index * 16; tags[pair.first] = offset; word64(offset, pair.first); word64(offset + 8, pair.second) }
        header(10, 6, 3UL, 0x900, dynamic.size * 16, 2, 0, 8, 16)
        word32(0x78, 2); word32(0x7c, 6); word64(0x80, 0x900UL); word64(0x88, 0x400900UL)
        word64(0x98, (dynamic.size * 16).toULong()); word64(0xa0, (dynamic.size * 16).toULong()); word64(0xa8, 8UL)
    }
    fun section(index: Int): Int = 0xc00 + index * 64
    fun tag(tag: ULong, value: ULong) { word64(tags.getValue(tag) + 8, value) }
    fun tagType(old: ULong, replacement: ULong) { val offset = tags.remove(old)!!; word64(offset, replacement); tags[replacement] = offset }
    fun word16(offset: Int, value: Int) { repeat(2) { bytes[offset + it] = (value ushr (8 * it)).toByte() } }
    fun word32(offset: Int, value: Long) { repeat(4) { bytes[offset + it] = (value ushr (8 * it)).toByte() } }
    fun word64(offset: Int, value: ULong) { repeat(8) { bytes[offset + it] = (value shr (8 * it)).toByte() } }
    private fun header(index: Int, type: Long, flags: ULong, offset: Int, size: Int, link: Int, info: Int, align: Int, width: Int) {
        val at = section(index); word32(at + 4, type); word64(at + 8, flags); word64(at + 16, if (flags and 2UL != 0UL) 0x400000UL + offset.toULong() else 0UL)
        word64(at + 24, offset.toULong()); word64(at + 32, size.toULong()); word32(at + 40, link.toLong()); word32(at + 44, info.toLong()); word64(at + 48, align.toULong()); word64(at + 56, width.toULong())
    }
    private fun symbol(index: Int, name: String, info: Int, section: Int, value: ULong, size: ULong) {
        val at = 0x400 + index * 24; word32(at, (names[name] ?: 0).toLong()); bytes[at + 4] = info.toByte(); word16(at + 6, section); word64(at + 8, value); word64(at + 16, size)
    }
    private fun relocation(at: Int, symbol: Int, type: Int, slot: Int, addend: ULong) { word64(at, 0x400000UL + slot.toULong()); word64(at + 8, (symbol.toULong() shl 32) or type.toULong()); word64(at + 16, addend) }
    private fun hash(name: String): Long {
        var value = 0L
        name.toByteArray().forEach { byte -> value = (value shl 4) + (byte.toInt() and 255); val high = value and 0xf0000000L; if (high != 0L) value = value xor (high ushr 24); value = value and high.inv() }
        return value
    }
}

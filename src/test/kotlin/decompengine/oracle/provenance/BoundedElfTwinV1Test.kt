package decompengine.oracle.provenance

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BoundedElfTwinV1Test {
    @Test
    fun `frozen rich and stripped twins reproduce literal v1 facts and commitments`() = withFrozenPair { pair ->
        val result = BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped)

        assertEquals(16_592L, result.full.bytes)
        assertEquals(FULL_SHA256, result.full.sha256)
        assertEquals(14_320L, result.stripped.bytes)
        assertEquals(STRIPPED_SHA256, result.stripped.sha256)
        assertEquals("ELF64", result.full.elf.header.elfClass)
        assertEquals("little-endian", result.full.elf.header.dataEncoding)
        assertEquals(3UL, result.full.elf.header.type)
        assertEquals("ET_DYN", result.full.elf.header.typeName)
        assertEquals(62UL, result.full.elf.header.machine)
        assertEquals("EM_X86_64", result.full.elf.header.machineName)
        assertEquals(14, result.full.elf.header.programHeaderCount)
        assertEquals(35, result.full.elf.header.sectionHeaderCount)
        assertEquals(27, result.stripped.elf.header.sectionHeaderCount)
        assertEquals(listOf(BUILD_ID), result.full.elf.buildIds)
        assertEquals(listOf(BUILD_ID), result.stripped.elf.buildIds)
        assertEquals(24, result.full.elf.sections.count { it.allocated })
        assertEquals(24, result.stripped.elf.sections.count { it.allocated })

        val text = result.full.elf.sections.single { it.name == ".text" }
        assertEquals(12, text.index)
        assertEquals(1UL, text.type)
        assertEquals(6UL, text.flags)
        assertEquals(4_160UL, text.address)
        assertEquals(4_160UL, text.offset)
        assertEquals(264UL, text.size)
        assertTrue(text.allocated)
        assertTrue(text.executable)
        assertEquals("da746e130546512d3e2a219f8effe15fb9fe8e6f1827ee2be342dcd9d4aa19f8", text.contentSha256)

        assertEquals(
            listOf(
                ".debug_abbrev",
                ".debug_aranges",
                ".debug_info",
                ".debug_line",
                ".debug_line_str",
                ".debug_str",
            ),
            result.full.elf.metadata.dwarfSections,
        )
        assertEquals(listOf(BoundedElfSymbolTableV1(".symtab", 25UL)), result.full.elf.metadata.staticSymbolTables)
        assertEquals(listOf(BoundedElfSymbolTableV1(".dynsym", 6UL)), result.full.elf.metadata.dynamicSymbolTables)
        assertFalse(result.stripped.elf.metadata.hasDwarf)
        assertFalse(result.stripped.elf.metadata.hasStaticSymbols)
        assertTrue(result.stripped.elf.metadata.hasDynamicSymbols)

        assertEquals(BUILD_ID, result.equivalence.buildId)
        assertEquals(PROGRAM_HEADERS_SHA256, result.equivalence.programHeadersSha256)
        assertEquals(ALLOCATED_SECTIONS_SHA256, result.equivalence.allocatedSectionsSha256)
        assertEquals(
            BoundedElfExecutableLoadV1(
                selector = "PT_LOAD with PF_X and nonzero p_filesz",
                segmentIndexes = listOf(3),
                bytes = 341,
                sha256 = EXECUTABLE_LOAD_SHA256,
            ),
            result.equivalence.executableLoad,
        )
        assertEquals(
            listOf(
                ".debug_abbrev",
                ".debug_aranges",
                ".debug_info",
                ".debug_line",
                ".debug_line_str",
                ".debug_str",
                ".strtab",
                ".symtab",
            ),
            result.equivalence.metadataDelta.fullOnlySections,
        )
        assertEquals(emptyList(), result.equivalence.metadataDelta.strippedOnlySections)
        assertEquals(listOf(".shstrtab"), result.equivalence.metadataDelta.changedCommonSections)
        assertEquals(
            result.full.elf.metadata.dwarfSections,
            result.equivalence.metadataDelta.removedDwarfSections,
        )
        assertEquals(
            listOf(BoundedElfSymbolTableV1(".symtab", 25UL)),
            result.equivalence.metadataDelta.removedStaticSymbolTables,
        )
    }

    @Test
    fun `frozen derivation is deterministic across repeated descriptor-bound inspections`() = withFrozenPair { pair ->
        val first = BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped)
        val second = BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped)

        assertEquals(first, second)
        assertEquals(PROGRAM_HEADERS_SHA256, second.equivalence.programHeadersSha256)
        assertEquals(ALLOCATED_SECTIONS_SHA256, second.equivalence.allocatedSectionsSha256)
    }

    @Test
    fun `legacy compact ASCII encoder preserves Python v1 sorting escaping and unsigned integers`() {
        val value = mapOf(
            "z" to "é😀\n",
            "a" to listOf(null, true, false, ULong.MAX_VALUE),
        )

        assertEquals(
            "8b86db6c46580656fae3f2ae6052e1bcc3e3bdd38787bf28b210cfcc7c79a624",
            legacyCompactAsciiSha256(value, 1_024),
        )
        assertFailsWith<BoundedElfTwinV1Exception> { legacyCompactAsciiSha256(value, 8) }
    }

    @Test
    fun `inspection supports both classes byte orders and extended counts`() = withTemporaryDirectory { root ->
        val profiles = listOf(
            SyntheticProfile(is64Bit = false, byteOrder = ByteOrder.LITTLE_ENDIAN, extended = false),
            SyntheticProfile(is64Bit = false, byteOrder = ByteOrder.BIG_ENDIAN, extended = false),
            SyntheticProfile(is64Bit = true, byteOrder = ByteOrder.LITTLE_ENDIAN, extended = false),
            SyntheticProfile(is64Bit = true, byteOrder = ByteOrder.BIG_ENDIAN, extended = true),
        )

        profiles.forEachIndexed { index, profile ->
            val path = root.resolve("synthetic-$index.elf")
            Files.write(path, syntheticElf(profile))
            val inspected = BoundedElfTwinV1.inspect(path)

            assertEquals(if (profile.is64Bit) "ELF64" else "ELF32", inspected.elf.header.elfClass)
            assertEquals(
                if (profile.byteOrder == ByteOrder.LITTLE_ENDIAN) "little-endian" else "big-endian",
                inspected.elf.header.dataEncoding,
            )
            assertEquals(2, inspected.elf.header.sectionHeaderCount)
            assertEquals(0, inspected.elf.header.programHeaderCount)
            assertEquals(1, inspected.elf.header.sectionNameTableIndex)
            assertEquals(listOf("", ".shstrtab"), inspected.elf.sections.map { it.name })
            assertEquals(emptyList(), inspected.elf.buildIds)
            assertEquals(0L, inspected.elf.executableLoad.bytes)
            assertEquals(EMPTY_SHA256, inspected.elf.executableLoad.sha256)
        }
    }

    @Test
    fun `section build ID authority falls back to PT_NOTE only when the named section is absent`() =
        withFrozenPair { pair ->
            val bytes = Files.readAllBytes(pair.full)
            val marker = ".note.gnu.build-id".toByteArray()
            val markerOffset = bytes.indexOf(marker)
            assertTrue(markerOffset >= 0)
            bytes[markerOffset + marker.lastIndex] = 'D'.code.toByte()
            Files.write(pair.full, bytes)

            val inspected = BoundedElfTwinV1.inspect(pair.full)
            assertEquals(listOf(BUILD_ID), inspected.elf.buildIds)
            assertTrue(inspected.elf.sections.none { it.name == ".note.gnu.build-id" })
        }

    @Test
    fun `code data and build ID mutations fail exact twin equivalence`() = withFrozenPair { pair ->
        val cases = listOf(
            Mutation("code", TEXT_OFFSET) { failure ->
                assertTrue(failure.message.orEmpty().contains("PT_LOAD/PF_X"))
            },
            Mutation("data", DATA_OFFSET) { failure ->
                assertTrue(failure.message.orEmpty().contains("allocated sections"))
            },
            Mutation("build-id", BUILD_ID_DESCRIPTOR_OFFSET) { failure ->
                assertTrue(failure.message.orEmpty().contains("GNU Build ID"))
            },
        )
        val original = Files.readAllBytes(pair.stripped)
        cases.forEach { mutation ->
            val mutated = original.copyOf()
            mutated[mutation.offset] = (mutated[mutation.offset].toInt() xor 1).toByte()
            Files.write(pair.stripped, mutated)
            val failure = assertFailsWith<BoundedElfTwinV1Exception>(mutation.label) {
                BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped)
            }
            mutation.check(failure)
            Files.write(pair.stripped, original)
        }
    }

    @Test
    fun `stripped static metadata is rejected even when allocated bytes remain exact`() = withFrozenPair { pair ->
        val stripped = Files.readAllBytes(pair.stripped)
        putUInt32(stripped, STRIPPED_COMMENT_SECTION_HEADER + 4, 2, ByteOrder.LITTLE_ENDIAN)
        Files.write(pair.stripped, stripped)

        val failure = assertFailsWith<BoundedElfTwinV1Exception> {
            BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped)
        }
        assertTrue(failure.message.orEmpty().contains("static symbol table"))
    }

    @Test
    fun `malformed counts ranges names notes and truncation fail closed`() = withFrozenPair { pair ->
        val full = Files.readAllBytes(pair.full)
        val stripped = Files.readAllBytes(pair.stripped)
        val malformed = listOf(
            "extended section count" to full.copyOf().also { bytes ->
                putUInt16(bytes, ELF64_SECTION_COUNT_OFFSET, 0, ByteOrder.LITTLE_ENDIAN)
                putUInt64(bytes, FULL_SECTION_TABLE_OFFSET + ELF64_SECTION_SIZE_FIELD, 131_073L, ByteOrder.LITTLE_ENDIAN)
            },
            "program range" to stripped.copyOf().also { bytes ->
                putUInt64(
                    bytes,
                    ELF64_PROGRAM_TABLE_OFFSET + EXECUTABLE_PROGRAM_INDEX * ELF64_PROGRAM_HEADER_BYTES + ELF64_PROGRAM_OFFSET_FIELD,
                    bytes.size.toLong() - 10L,
                    ByteOrder.LITTLE_ENDIAN,
                )
            },
            "invalid UTF-8 name" to full.copyOf().also { bytes ->
                bytes[FULL_SECTION_NAME_TABLE_OFFSET + 1] = 0xff.toByte()
            },
            "oversized note name" to full.copyOf().also { bytes ->
                putUInt32(bytes, BUILD_ID_NOTE_OFFSET, 0x00ff_ffff, ByteOrder.LITTLE_ENDIAN)
            },
            "truncation" to full.copyOf(full.size - 1),
        )

        malformed.forEachIndexed { index, (label, bytes) ->
            val path = pair.root.resolve("malformed-$index.elf")
            Files.write(path, bytes)
            assertFailsWith<BoundedElfTwinV1Exception>(label) { BoundedElfTwinV1.inspect(path) }
        }
    }

    @Test
    fun `all explicit parser and commitment budgets fail closed below the frozen requirements`() =
        withFrozenPair { pair ->
            val fullBytes = Files.size(pair.full)
            val cases = listOf(
                "file bytes" to BoundedElfTwinV1Limits(
                    maximumFileBytes = fullBytes - 1,
                    maximumRangeBytes = fullBytes - 1,
                ),
                "program count" to BoundedElfTwinV1Limits(maximumProgramHeaders = 13),
                "section count" to BoundedElfTwinV1Limits(maximumSectionHeaders = 34),
                "name bytes" to BoundedElfTwinV1Limits(maximumNameBytes = 4),
                "note bytes" to BoundedElfTwinV1Limits(maximumNotePayloadBytes = 32),
                "aggregate hashes" to BoundedElfTwinV1Limits(
                    maximumFileBytes = fullBytes,
                    maximumRangeBytes = fullBytes,
                    maximumAggregateHashedBytes = fullBytes,
                ),
                "steps" to BoundedElfTwinV1Limits(maximumSteps = 1),
                "commitment bytes" to BoundedElfTwinV1Limits(maximumCommitmentBytes = 16),
            )

            cases.forEach { (label, limits) ->
                assertFailsWith<BoundedElfTwinV1Exception>(label) {
                    if (label == "commitment bytes") {
                        BoundedElfTwinV1.inspectTwin(pair.full, pair.stripped, limits)
                    } else {
                        BoundedElfTwinV1.inspect(pair.full, limits)
                    }
                }
            }
        }

    @Test
    fun `same-file aliases path substitution and terminal same-inode mutation are rejected`() {
        withFrozenPair { pair ->
            val alias = pair.root.resolve("full-hard-link.elf")
            Files.createLink(alias, pair.full)
            assertFailsWith<BoundedElfTwinV1Exception> {
                BoundedElfTwinV1.inspectTwin(pair.full, alias)
            }

            val displaced = pair.root.resolve("stripped-displaced.elf")
            assertFailsWith<BoundedElfTwinV1Exception> {
                BoundedElfTwinV1.inspectTwin(
                    pair.full,
                    pair.stripped,
                    faultInjector = BoundedElfTwinV1FaultInjector { checkpoint ->
                        if (checkpoint == BoundedElfTwinV1Checkpoint.AFTER_FULL_INSPECTION) {
                            Files.move(pair.stripped, displaced, StandardCopyOption.ATOMIC_MOVE)
                            Files.copy(displaced, pair.stripped)
                        }
                    },
                )
            }
        }

        withFrozenPair { pair ->
            val original = Files.readAllBytes(pair.full)
            val mutated = original.copyOf().also { bytes ->
                bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            }
            val failure = assertFailsWith<BoundedElfTwinV1Exception> {
                BoundedElfTwinV1.inspectTwin(
                    pair.full,
                    pair.stripped,
                    faultInjector = BoundedElfTwinV1FaultInjector { checkpoint ->
                        if (checkpoint == BoundedElfTwinV1Checkpoint.BEFORE_TERMINAL_REVALIDATION) {
                            Files.write(pair.full, mutated)
                        }
                    },
                )
            }
            assertTrue(failure.message.orEmpty().contains("bytes changed"))
            assertNotEquals(FULL_SHA256, sha256(mutated))
        }
    }

    private fun withFrozenPair(action: (FrozenPair) -> Unit) = withTemporaryDirectory { root ->
        val full = root.resolve("full.elf")
        val stripped = root.resolve("stripped.elf")
        Files.write(full, frozenBytes("/oracle/elf-twin-v1/full.elf.b64"))
        Files.write(stripped, frozenBytes("/oracle/elf-twin-v1/stripped.elf.b64"))
        action(FrozenPair(root, full, stripped))
    }

    private fun withTemporaryDirectory(action: (Path) -> Unit) {
        val root = createTempDirectory("bounded-elf-twin-v1-")
        try {
            action(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun frozenBytes(resource: String): ByteArray = Base64.getMimeDecoder().decode(
        checkNotNull(javaClass.getResourceAsStream(resource)) { "missing frozen resource $resource" }.use {
            it.readBytes()
        },
    )

    private fun syntheticElf(profile: SyntheticProfile): ByteArray {
        val headerBytes = if (profile.is64Bit) 64 else 52
        val sectionBytes = if (profile.is64Bit) 64 else 40
        val programBytes = if (profile.is64Bit) 56 else 32
        val names = byteArrayOf(0) + ".shstrtab".toByteArray() + byteArrayOf(0)
        val sectionOffset = headerBytes
        val namesOffset = sectionOffset + 2 * sectionBytes
        val result = ByteArray(namesOffset + names.size)
        result[0] = 0x7f
        result[1] = 'E'.code.toByte()
        result[2] = 'L'.code.toByte()
        result[3] = 'F'.code.toByte()
        result[4] = if (profile.is64Bit) 2 else 1
        result[5] = if (profile.byteOrder == ByteOrder.LITTLE_ENDIAN) 1 else 2
        result[6] = 1
        val header = ByteBuffer.wrap(result).order(profile.byteOrder)
        header.position(16)
        header.putShort(1)
        header.putShort(if (profile.is64Bit) 62 else 3)
        header.putInt(1)
        if (profile.is64Bit) {
            header.putLong(0x1234)
            header.putLong(0)
            header.putLong(sectionOffset.toLong())
        } else {
            header.putInt(0x1234)
            header.putInt(0)
            header.putInt(sectionOffset)
        }
        header.putInt(0x55)
        header.putShort(headerBytes.toShort())
        header.putShort(programBytes.toShort())
        header.putShort(if (profile.extended) 0xffff.toShort() else 0)
        header.putShort(sectionBytes.toShort())
        header.putShort(if (profile.extended) 0 else 2)
        header.putShort(if (profile.extended) 0xffff.toShort() else 1)

        val sectionZero = ByteBuffer.wrap(result, sectionOffset, sectionBytes).slice().order(profile.byteOrder)
        putSection(
            sectionZero,
            profile.is64Bit,
            name = 0,
            type = 0,
            offset = 0,
            size = if (profile.extended) 2 else 0,
            link = if (profile.extended) 1 else 0,
            info = 0,
            alignment = 0,
        )
        val namesSection = ByteBuffer.wrap(result, sectionOffset + sectionBytes, sectionBytes)
            .slice().order(profile.byteOrder)
        putSection(
            namesSection,
            profile.is64Bit,
            name = 1,
            type = 3,
            offset = namesOffset,
            size = names.size,
            link = 0,
            info = 0,
            alignment = 1,
        )
        names.copyInto(result, namesOffset)
        return result
    }

    private fun putSection(
        target: ByteBuffer,
        is64Bit: Boolean,
        name: Int,
        type: Int,
        offset: Int,
        size: Int,
        link: Int,
        info: Int,
        alignment: Int,
    ) {
        target.putInt(name)
        target.putInt(type)
        if (is64Bit) {
            target.putLong(0)
            target.putLong(0)
            target.putLong(offset.toLong())
            target.putLong(size.toLong())
            target.putInt(link)
            target.putInt(info)
            target.putLong(alignment.toLong())
            target.putLong(0)
        } else {
            target.putInt(0)
            target.putInt(0)
            target.putInt(offset)
            target.putInt(size)
            target.putInt(link)
            target.putInt(info)
            target.putInt(alignment)
            target.putInt(0)
        }
    }

    private fun putUInt16(bytes: ByteArray, offset: Int, value: Int, order: ByteOrder) {
        ByteBuffer.wrap(bytes, offset, 2).order(order).putShort(value.toShort())
    }

    private fun putUInt32(bytes: ByteArray, offset: Int, value: Int, order: ByteOrder) {
        ByteBuffer.wrap(bytes, offset, 4).order(order).putInt(value)
    }

    private fun putUInt64(bytes: ByteArray, offset: Int, value: Long, order: ByteOrder) {
        ByteBuffer.wrap(bytes, offset, 8).order(order).putLong(value)
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        for (offset in 0..size - needle.size) {
            if (needle.indices.all { index -> this[offset + index] == needle[index] }) return offset
        }
        return -1
    }

    private fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

    private data class FrozenPair(val root: Path, val full: Path, val stripped: Path)
    private data class SyntheticProfile(val is64Bit: Boolean, val byteOrder: ByteOrder, val extended: Boolean)
    private data class Mutation(
        val label: String,
        val offset: Int,
        val check: (BoundedElfTwinV1Exception) -> Unit,
    )

    private companion object {
        const val FULL_SHA256 = "28105cb58b619f88d8718e8cf30c0c3471b7f0c8825e95e171eebc940954b859"
        const val STRIPPED_SHA256 = "252d14c411b629fb9d4d7ca4334382ac771b28b5e5868e22c5f654a5980e6c77"
        const val BUILD_ID = "01736da25e781713aa42bddf9af30c9f0a2e007d"
        const val PROGRAM_HEADERS_SHA256 = "b355b6bb3e011fb505b68f70b35ad85cd0588491b6ca9111a37456910d631e3a"
        const val ALLOCATED_SECTIONS_SHA256 = "c286ebb12b3dff7cd296d4648a105677417a501aa01f1916adcd0003dac14042"
        const val EXECUTABLE_LOAD_SHA256 = "495a7021699aeaea47feb63932d5bc974c55575745498c138e479b5467b9839e"
        const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        const val TEXT_OFFSET = 0x1040
        const val DATA_OFFSET = 0x3000
        const val BUILD_ID_NOTE_OFFSET = 0x350
        const val BUILD_ID_DESCRIPTOR_OFFSET = 0x360
        const val FULL_SECTION_TABLE_OFFSET = 14_352
        const val FULL_SECTION_NAME_TABLE_OFFSET = 0x36b1
        const val STRIPPED_COMMENT_SECTION_HEADER = 12_592 + 25 * 64
        const val ELF64_SECTION_COUNT_OFFSET = 60
        const val ELF64_SECTION_SIZE_FIELD = 32
        const val ELF64_PROGRAM_TABLE_OFFSET = 64
        const val ELF64_PROGRAM_HEADER_BYTES = 56
        const val ELF64_PROGRAM_OFFSET_FIELD = 8
        const val EXECUTABLE_PROGRAM_INDEX = 3
    }
}

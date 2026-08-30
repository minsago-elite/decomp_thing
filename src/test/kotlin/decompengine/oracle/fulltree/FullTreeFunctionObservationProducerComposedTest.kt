package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionObservationProducerComposedTest {
    @Test
    fun `composed ELF resolves reference chains ranges and non-emitted evidence`() =
        inControlTemporaryDirectory { root ->
            val controls = createFullTreeControlFixture(root.resolve("controls"))
            val artifactBytes = ComposedFunctionObservationElf.build()
            val artifact = writeElf(root.resolve("reference-chain.elf"), artifactBytes.bytes)
            val scope = scopeForArtifact(
                controls.authenticatedScope(),
                OracleArtifacts.sha256(artifactBytes.bytes),
                artifactBytes.bytes.size.toLong(),
            )
            val inventoryPath = root.resolve("reference-chain-inventory.json")
            val inventory = FullTreeInventoryControl.generateAndPublish(
                artifact,
                scope,
                inventoryPath,
                maximumWorkers = 1,
            )
            val shardId = inventory.inventory.controlArray("shards").single().let {
                (it as JsonObject).controlString("id")
            }
            assertEquals("clang-lib-reference", shardId)
            val producerLimits = smallShardLimits()

            val first = FullTreeFunctionObservationProducer.generateShardWithLimits(
                richArtifact = artifact,
                inventoryPath = inventoryPath,
                scope = scope,
                shardId = shardId,
                scratchParent = root,
                controlLimits = FullTreeControlLimits(),
                producerLimits = producerLimits,
            )
            val second = FullTreeFunctionObservationProducer.generateShardWithLimits(
                richArtifact = artifact,
                inventoryPath = inventoryPath,
                scope = scope,
                shardId = shardId,
                scratchParent = root,
                controlLimits = FullTreeControlLimits(),
                producerLimits = producerLimits,
            )

            assertEquals(6L, first.scannedDies)
            assertEquals(2L, first.entities)
            assertEquals(first.outputSha256, second.outputSha256)
            assertTrue(
                FullTreeFunctionObservations.canonicalEnvelopeBytes(first.document).contentEquals(
                    FullTreeFunctionObservations.canonicalEnvelopeBytes(second.document),
                ),
            )
            assertEquals(
                JsonObject(
                    mapOf(
                        "emittedRvas" to JsonPrimitive(1),
                        "nonEmitted" to JsonPrimitive(1),
                        "nonEmittedDies" to JsonPrimitive(1),
                        "scannedDies" to JsonPrimitive(6),
                        "units" to JsonPrimitive(1),
                    ),
                ),
                first.document.controlObject("counts"),
            )

            val unit = inventory.inventory.controlArray("units").single() as JsonObject
            assertEquals("source/clang/lib/Reference/reference-chain.c", unit.controlString("sourcePath"))
            val unitId = unit.controlString("id")

            val emitted = first.document.controlArray("emitted").single() as JsonObject
            assertEquals("0x180", emitted.controlString("rva"))
            assertEquals(listOf(unitId), emitted.controlArray("ownerUnitIds").map { (it as JsonPrimitive).content })
            assertAlias(
                emitted.controlArray("aliases").single() as JsonObject,
                artifactBytes.emittedDieOffset,
                artifactBytes.declarationDieOffset,
                unitId,
            )
            assertDeclaration(
                emitted.controlArray("declarations").single() as JsonObject,
                unit.controlString("sourcePath"),
            )

            val nonEmitted = first.document.controlArray("nonEmitted").single() as JsonObject
            assertEquals(
                listOf("inline-no-emitted-range"),
                nonEmitted.controlArray("reasonCodes").map { (it as JsonPrimitive).content },
            )
            assertEquals(listOf(unitId), nonEmitted.controlArray("unitIds").map { (it as JsonPrimitive).content })
            val die = nonEmitted.controlArray("dieOffsets").single() as JsonObject
            assertEquals(hex(artifactBytes.nonEmittedDieOffset), die.controlString("dieOffset"))
            assertEquals(unitId, die.controlString("unitId"))
            assertAlias(
                nonEmitted.controlArray("aliases").single() as JsonObject,
                artifactBytes.nonEmittedDieOffset,
                artifactBytes.declarationDieOffset,
                unitId,
            )
            assertDeclaration(
                nonEmitted.controlObject("declaration"),
                unit.controlString("sourcePath"),
            )
        }

    private fun assertAlias(
        alias: JsonObject,
        originalDieOffset: Int,
        declarationDieOffset: Int,
        unitId: String,
    ) {
        assertEquals("chained_target", alias.controlString("name"))
        val evidence = alias.controlArray("evidence").single() as JsonObject
        assertEquals("dwarf-subprogram", evidence.controlString("kind"))
        assertEquals(
            "rich:.debug_info:die=${hex(originalDieOffset)}:DW_AT_name@${hex(declarationDieOffset)}",
            evidence.controlString("locator"),
        )
        assertEquals(unitId, evidence.controlString("unitId"))
    }

    private fun smallShardLimits() = FullTreeFunctionObservationProducerLimits(
        dieLimits = FullTreeDwarfDieLimits(
            maximumPhysicalRecords = 6,
            maximumNonNullRecords = 5,
            maximumAttributes = 15,
            maximumTreeDepth = 1,
            maximumRetainedBytes = 64 * 1024,
        ),
        lineTableLimits = FullTreeDwarfLineTableLimits(
            maximumUnitBytes = 1,
            maximumDirectories = 1,
            maximumFiles = 1,
            maximumEntryFormats = 1,
            maximumPathBytes = 1,
            maximumPathCharacters = 1,
            maximumAggregatePathBytes = 1,
            maximumParseSteps = 1,
        ),
        accumulatorLimits = FullTreeFunctionObservationAccumulatorLimits(
            maximumScannedDies = 6,
            maximumSubprograms = 2,
            maximumEntities = 2,
            maximumEmittedRvas = 1,
            maximumNonEmittedGroups = 1,
            maximumAliasesPerSubprogram = 1,
            maximumEvidencePerAliasPerSubprogram = 1,
            maximumAliasesPerEntity = 1,
            maximumEvidencePerAliasPerEntity = 1,
            maximumDeclarationsPerRva = 1,
            maximumOwnersPerEntity = 1,
            maximumNameCodePoints = 64,
            maximumLocatorCodePoints = 256,
            maximumRetainedBytes = 64 * 1024,
        ),
        elfLayoutLimits = FullTreeElfLayoutLimits(
            maximumProgramHeaders = 1,
            maximumSectionHeaders = 6,
            maximumSymbolTables = 1,
            maximumSymbols = 1,
            maximumSectionNameBytes = 32,
            maximumTotalSectionNameBytes = 128,
            maximumFunctionNameBytes = 64,
            maximumFunctionNameCodePoints = 64,
            maximumLocatorBytes = 256,
            maximumParseSteps = 64,
        ),
        maximumReferenceChainEntries = 3,
        maximumCachedCompilationUnits = 1,
    )

    private fun assertDeclaration(declaration: JsonObject, unitSourcePath: String) {
        assertEquals(1L, declaration.controlLong("fileIndex"))
        assertEquals(37L, declaration.controlLong("line"))
        assertEquals(9L, declaration.controlLong("column"))
        assertEquals(JsonNull, declaration["sourcePath"])
        assertEquals(JsonNull, declaration["externalPathSha256"])
        assertEquals(unitSourcePath, declaration.controlString("unitSourcePath"))
    }

    private fun scopeForArtifact(
        original: AuthenticatedFullTreeScope,
        artifactSha256: String,
        artifactBytes: Long,
    ): AuthenticatedFullTreeScope {
        val originalArtifacts = original.artifactManifest.controlObject("artifacts")
        val full = JsonObject(originalArtifacts.controlObject("full").toMutableMap().apply {
            this["bytes"] = JsonPrimitive(artifactBytes)
            this["sha256"] = JsonPrimitive(artifactSha256)
        })
        val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
            this["artifacts"] = JsonObject(originalArtifacts.toMutableMap().apply {
                this["full"] = full
            })
        })
        val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
        val oracle = original.document.controlObject("oracle")
        val document = JsonObject(original.document.toMutableMap().apply {
            this["oracle"] = JsonObject(oracle.toMutableMap().apply {
                this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                this["richArtifactSha256"] = JsonPrimitive(artifactSha256)
            })
        })
        return AuthenticatedFullTreeScope(
            document = document,
            sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(document)),
            sourceLock = original.sourceLock,
            sourceLockSha256 = original.sourceLockSha256,
            artifactManifest = manifest,
            artifactManifestSha256 = manifestSha256,
        )
    }

    private fun hex(value: Int): String = "0x${value.toString(16)}"
}

private data class ComposedFunctionObservationArtifact(
    val bytes: ByteArray,
    val declarationDieOffset: Int,
    val emittedDieOffset: Int,
    val nonEmittedDieOffset: Int,
)

private object ComposedFunctionObservationElf {
    private const val IMAGE_BASE = 0x400000L
    private const val ELF_HEADER_BYTES = 64
    private const val PROGRAM_HEADER_BYTES = 56
    private const val SECTION_HEADER_BYTES = 64
    private const val TEXT_OFFSET = 0x100
    private const val TEXT_BYTES = 0x100

    fun build(): ComposedFunctionObservationArtifact {
        val dwarf = dwarfSections()
        val sectionNames = listOf(".text", ".debug_info", ".debug_abbrev", ".debug_ranges", ".shstrtab")
        val nameTable = ByteArrayOutputStream().apply { write(0) }
        val nameOffsets = sectionNames.associateWith { name ->
            nameTable.size().also {
                nameTable.write(name.toByteArray(Charsets.US_ASCII))
                nameTable.write(0)
            }
        }
        val shstrtab = nameTable.toByteArray()

        val infoOffset = align(TEXT_OFFSET + TEXT_BYTES, 8)
        val abbreviationOffset = align(infoOffset + dwarf.info.size, 1)
        val rangesOffset = align(abbreviationOffset + dwarf.abbreviations.size, 8)
        val shstrtabOffset = align(rangesOffset + dwarf.ranges.size, 1)
        val sectionTableOffset = align(shstrtabOffset + shstrtab.size, 8)
        val sectionCount = 6
        val totalBytes = sectionTableOffset + sectionCount * SECTION_HEADER_BYTES
        val result = ByteArray(totalBytes)
        ByteArray(TEXT_BYTES) { 0x90.toByte() }.copyInto(result, TEXT_OFFSET)
        dwarf.info.copyInto(result, infoOffset)
        dwarf.abbreviations.copyInto(result, abbreviationOffset)
        dwarf.ranges.copyInto(result, rangesOffset)
        shstrtab.copyInto(result, shstrtabOffset)

        result[0] = 0x7f
        result[1] = 'E'.code.toByte()
        result[2] = 'L'.code.toByte()
        result[3] = 'F'.code.toByte()
        result[4] = 2 // ELF64
        result[5] = 1 // little-endian
        result[6] = 1 // current ELF version
        put16(result, 16, 2) // ET_EXEC
        put16(result, 18, 62) // EM_X86_64
        put32(result, 20, 1)
        put64(result, 24, IMAGE_BASE + 0x180L)
        put64(result, 32, ELF_HEADER_BYTES.toLong())
        put64(result, 40, sectionTableOffset.toLong())
        put16(result, 52, ELF_HEADER_BYTES)
        put16(result, 54, PROGRAM_HEADER_BYTES)
        put16(result, 56, 1)
        put16(result, 58, SECTION_HEADER_BYTES)
        put16(result, 60, sectionCount)
        put16(result, 62, 5)

        val program = ELF_HEADER_BYTES
        put32(result, program, 1) // PT_LOAD
        put32(result, program + 4, 5) // PF_R | PF_X
        put64(result, program + 8, 0L)
        put64(result, program + 16, IMAGE_BASE)
        put64(result, program + 24, IMAGE_BASE)
        put64(result, program + 32, totalBytes.toLong())
        put64(result, program + 40, totalBytes.toLong())
        put64(result, program + 48, 0x1000L)

        writeSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES,
            nameOffsets.getValue(".text"),
            type = 1,
            flags = 6L,
            address = IMAGE_BASE + TEXT_OFFSET,
            fileOffset = TEXT_OFFSET,
            size = TEXT_BYTES,
            alignment = 16,
        )
        writeSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 2,
            nameOffsets.getValue(".debug_info"),
            type = 1,
            fileOffset = infoOffset,
            size = dwarf.info.size,
        )
        writeSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 3,
            nameOffsets.getValue(".debug_abbrev"),
            type = 1,
            fileOffset = abbreviationOffset,
            size = dwarf.abbreviations.size,
        )
        writeSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 4,
            nameOffsets.getValue(".debug_ranges"),
            type = 1,
            fileOffset = rangesOffset,
            size = dwarf.ranges.size,
            alignment = 8,
        )
        writeSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 5,
            nameOffsets.getValue(".shstrtab"),
            type = 3,
            fileOffset = shstrtabOffset,
            size = shstrtab.size,
        )
        return ComposedFunctionObservationArtifact(
            bytes = result,
            declarationDieOffset = dwarf.declarationDieOffset,
            emittedDieOffset = dwarf.emittedDieOffset,
            nonEmittedDieOffset = dwarf.nonEmittedDieOffset,
        )
    }

    private fun dwarfSections(): ComposedDwarfSections {
        val abbreviations = ByteArrayOutputStream().apply {
            abbreviation(
                code = 1,
                tag = 0x11,
                hasChildren = true,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x1bL to FULL_TREE_DW_FORM_STRING,
                    0x25L to FULL_TREE_DW_FORM_STRING,
                    0x13L to FULL_TREE_DW_FORM_DATA2,
                ),
            )
            abbreviation(
                code = 2,
                tag = 0x2e,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x3aL to FULL_TREE_DW_FORM_DATA1,
                    0x3bL to FULL_TREE_DW_FORM_DATA1,
                    0x39L to FULL_TREE_DW_FORM_DATA1,
                    0x3cL to FULL_TREE_DW_FORM_FLAG_PRESENT,
                ),
            )
            abbreviation(
                code = 3,
                tag = 0x2e,
                attributes = listOf(
                    0x47L to FULL_TREE_DW_FORM_REF4,
                    0x3cL to FULL_TREE_DW_FORM_FLAG_PRESENT,
                ),
            )
            abbreviation(
                code = 4,
                tag = 0x2e,
                attributes = listOf(
                    0x31L to FULL_TREE_DW_FORM_REF4,
                    0x55L to FULL_TREE_DW_FORM_SEC_OFFSET,
                ),
            )
            abbreviation(
                code = 5,
                tag = 0x2e,
                attributes = listOf(
                    0x31L to FULL_TREE_DW_FORM_REF4,
                    0x20L to FULL_TREE_DW_FORM_DATA1,
                ),
            )
            write(0)
        }.toByteArray()

        val dies = ByteArrayOutputStream()
        dies.write(uleb(1))
        dies.write(utf8z("reference-chain.c"))
        dies.write(utf8z("/fixture/source-tree/clang/lib/Reference"))
        dies.write(utf8z("Kotlin composed producer fixture"))
        dies.write(unsigned(0x000cL, 2)) // DW_LANG_C99

        val declarationDieOffset = 11 + dies.size()
        dies.write(uleb(2))
        dies.write(utf8z("chained_target"))
        dies.write(byteArrayOf(1, 37, 9))

        val specificationDieOffset = 11 + dies.size()
        dies.write(uleb(3))
        dies.write(unsigned(declarationDieOffset.toLong(), 4))

        val emittedDieOffset = 11 + dies.size()
        dies.write(uleb(4))
        dies.write(unsigned(specificationDieOffset.toLong(), 4))
        dies.write(unsigned(0L, 4))

        val nonEmittedDieOffset = 11 + dies.size()
        dies.write(uleb(5))
        dies.write(unsigned(specificationDieOffset.toLong(), 4))
        dies.write(1)
        dies.write(0) // terminate the root's children

        val dieBytes = dies.toByteArray()
        val unitBody = unsigned(4L, 2) + unsigned(0L, 4) + byteArrayOf(8) + dieBytes
        val info = unsigned(unitBody.size.toLong(), 4) + unitBody
        val ranges = range(IMAGE_BASE + 0x140L, IMAGE_BASE + 0x140L) +
            range(IMAGE_BASE + 0x180L, IMAGE_BASE + 0x190L) +
            range(0L, 0L)
        return ComposedDwarfSections(
            info = info,
            abbreviations = abbreviations,
            ranges = ranges,
            declarationDieOffset = declarationDieOffset,
            emittedDieOffset = emittedDieOffset,
            nonEmittedDieOffset = nonEmittedDieOffset,
        )
    }

    private fun ByteArrayOutputStream.abbreviation(
        code: Long,
        tag: Long,
        hasChildren: Boolean = false,
        attributes: List<Pair<Long, Long>>,
    ) {
        write(uleb(code))
        write(uleb(tag))
        write(if (hasChildren) 1 else 0)
        attributes.forEach { (name, form) ->
            write(uleb(name))
            write(uleb(form))
        }
        write(0)
        write(0)
    }

    private fun writeSection(
        result: ByteArray,
        offset: Int,
        nameOffset: Int,
        type: Int,
        flags: Long = 0L,
        address: Long = 0L,
        fileOffset: Int,
        size: Int,
        alignment: Int = 1,
    ) {
        put32(result, offset, nameOffset.toLong())
        put32(result, offset + 4, type.toLong())
        put64(result, offset + 8, flags)
        put64(result, offset + 16, address)
        put64(result, offset + 24, fileOffset.toLong())
        put64(result, offset + 32, size.toLong())
        put64(result, offset + 48, alignment.toLong())
    }

    private fun range(start: Long, end: Long): ByteArray = unsigned(start, 8) + unsigned(end, 8)

    private fun unsigned(value: Long, width: Int): ByteArray =
        ByteArray(width) { index -> (value ushr (index * 8)).toByte() }

    private fun uleb(value: Long): ByteArray {
        require(value >= 0L)
        var remaining = value
        val result = ByteArrayOutputStream()
        do {
            var current = (remaining and 0x7fL).toInt()
            remaining = remaining ushr 7
            if (remaining != 0L) current = current or 0x80
            result.write(current)
        } while (remaining != 0L)
        return result.toByteArray()
    }

    private fun utf8z(value: String): ByteArray = value.toByteArray(Charsets.UTF_8) + byteArrayOf(0)

    private fun align(value: Int, alignment: Int): Int =
        Math.addExact(value, alignment - 1) / alignment * alignment

    private fun put16(bytes: ByteArray, offset: Int, value: Int) {
        repeat(2) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }

    private fun put32(bytes: ByteArray, offset: Int, value: Long) {
        repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }

    private fun put64(bytes: ByteArray, offset: Int, value: Long) {
        repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }
}

private data class ComposedDwarfSections(
    val info: ByteArray,
    val abbreviations: ByteArray,
    val ranges: ByteArray,
    val declarationDieOffset: Int,
    val emittedDieOffset: Int,
    val nonEmittedDieOffset: Int,
)

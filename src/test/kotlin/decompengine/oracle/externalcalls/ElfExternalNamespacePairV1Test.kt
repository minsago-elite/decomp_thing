package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ElfExternalNamespacePairV1Test {
    @Test
    fun `exact artifact pins yield explicit immutable namespace and slot correspondence without runtime authority`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            fixture.withPair { pair ->
                assertEquals(10, pair.slots.size)
                val first = assertNotNull(pair.slotAtRva(0x800UL))
                assertTrue(first.eligible)
                assertEquals("paired-static-import-request", first.disposition)
                assertNotEquals(first.richImportId, first.strippedImportId)
                assertEquals(first.richImportId, pair.slotAtRva(0x818UL)!!.richImportId)
                val identity = pairFixtureObject("schemaVersion" to JsonPrimitive(1), "namespace" to JsonPrimitive("elf-static-import-request-v1"),
                    "inputSha256" to JsonPrimitive(fixture.richSha), "symbolTableSectionIndex" to JsonPrimitive(3), "symbolIndex" to JsonPrimitive(1),
                    "name" to JsonPrimitive("puts"), "type" to JsonPrimitive(2), "binding" to JsonPrimitive(1), "visibility" to JsonPrimitive(0),
                    "version" to pairFixtureObject("raw" to JsonPrimitive(2), "index" to JsonPrimitive(2), "hidden" to JsonPrimitive(false),
                        "kind" to JsonPrimitive("required-version"), "name" to JsonPrimitive("GLIBC_X"), "providerRequest" to JsonPrimitive("libc.so.6")),
                    "weakMayRemainNull" to JsonPrimitive(false), "ifuncImplementationUnresolved" to JsonPrimitive(false),
                    "runtimeProviderAvailable" to JsonPrimitive(false), "runtimeImplementationAvailable" to JsonPrimitive(false),
                    "interpositionUnresolved" to JsonPrimitive(true))
                assertEquals("ext-${OracleArtifacts.sha256(OracleJson.canonicalBytes(identity))}", first.richImportId)
                assertEquals("0000000000000000", first.slotBytesHex)
                assertEquals("unresolved-weak-runtime-target", pair.slotAtRva(0x828UL)!!.disposition)
                assertEquals("unresolved-ifunc-runtime-implementation", pair.slotAtRva(0x830UL)!!.disposition)
                assertEquals("unresolved-null-symbol-index", pair.slotAtRva(0x848UL)!!.disposition)
                assertNotNull(pair.slotAtRva(0x828UL)!!.richImportId)
                assertEquals(2, (pair.richNamespace.getValue("entries") as JsonArray).size)
                for (flag in listOf("complete", "releaseEligible", "negativeCompleteness", "runtimeProviderAvailable", "runtimeImplementationAvailable"))
                    assertEquals(JsonPrimitive(false), pair.receipt[flag])
                assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(pair.receipt)), pair.receiptSha256)
                assertFailsWith<UnsupportedOperationException> { (pair.slots as MutableList<*>).clear() }
                val row = (pair.receipt.getValue("slots") as JsonArray).first() as JsonObject
                val coverage = row.getValue("richWriteCoverage") as JsonObject
                val entry = coverage.entries.first { it.key == "candidateActive" } as MutableMap.MutableEntry<String, JsonElement>
                assertFailsWith<UnsupportedOperationException> { entry.setValue(JsonPrimitive(false)) }
                assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(pair.receipt)), pair.receiptSha256)
                pair.requireCurrent()
            }
        }

    @Test
    fun `section renumbering and relocated file storage preserve runtime table identities and distinct locators`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            pairFixtureSwapSections(fixture.strippedElf, 2, 3)
            fixture.write()
            fixture.withPair { pair ->
                val slot = assertNotNull(pair.slotAtRva(0x800UL))
                assertTrue(slot.eligible)
                assertEquals(3, slot.richSymbol.tableSectionIndex)
                assertEquals(2, slot.strippedSymbol.tableSectionIndex)
                assertNotEquals(slot.richSymbol.raw.locator, slot.strippedSymbol.raw.locator)
            }
            fixture.strippedTransform = ::pairFixtureMoveFileStorage
            fixture.write()
            fixture.withPair { pair ->
                val slot = pair.slotAtRva(0x800UL)!!
                assertTrue(slot.eligible)
                assertEquals(0x800L, slot.richRelocation.slotFileOffset)
                assertEquals(0x1800L, slot.strippedRelocation.slotFileOffset)
                val code = assertNotNull(pair.proveCodeBytes(0x200UL, byteArrayOf(0xff.toByte(), 0x25, 0xfa.toByte(), 5, 0, 0)))
                assertEquals(0x200L, code.richFileOffset)
                assertEquals(0x1200L, code.strippedFileOffset)
            }
        }

    @Test
    fun `spelling raw flags version provider relocation and symbol ordinal mutations never use fallback matching`(): Unit {
        val mutations: List<(DynamicBindingElfFixtureV1) -> Unit> = listOf(
            { it.bytes[0x301] = 'q'.code.toByte() },
            { it.bytes[0x41c] = 0x10 },
            { it.bytes[0x41d] = 4 },
            { it.word16(0x702, 0x8002) },
            { bytes -> val at = pairFixtureFind(bytes.bytes, "libc.so.6"); bytes.bytes[at] = 'x'.code.toByte() },
            { it.word16(0x734, 2) },
            { it.word64(0x610, 1UL) },
            { it.word64(0x600, 0x400858UL) },
            { pairFixtureReindexSymbols(it) },
        )
        mutations.forEachIndexed { index, mutate ->
            withElfExternalNamespacePairFixtureV1 { fixture ->
                mutate(fixture.strippedElf); fixture.write()
                assertFails("logical mutation $index") { fixture.withPair {} }
            }
        }
    }

    @Test
    fun `safe slot bytes must match and competing or globally unknown writes remain unresolved`(): Unit {
        withElfExternalNamespacePairFixtureV1 { fixture ->
            fixture.strippedElf.bytes[0x800] = 1; fixture.write()
            val error = assertFailsWith<IllegalArgumentException> { fixture.withPair {} }
            assertTrue(error.message!!.contains("pointer-slot bytes differ"))
        }
        withElfExternalNamespacePairFixtureV1 { fixture ->
            for (elf in listOf(fixture.richElf, fixture.strippedElf)) elf.word64(0x500, 0x400804UL)
            fixture.write()
            fixture.withPair { pair ->
                val slot = pair.slotAtRva(0x800UL)!!
                assertFalse(slot.eligible)
                assertTrue(slot.richWriteCoverage.overlappingWrite)
                assertEquals("unresolved-relocation-write-coverage", slot.disposition)
            }
        }
        withElfExternalNamespacePairFixtureV1 { fixture ->
            for (elf in listOf(fixture.richElf, fixture.strippedElf)) elf.word64(0x508, 0x1234UL)
            fixture.write()
            fixture.withPair { pair ->
                assertFalse(pair.slotAtRva(0x800UL)!!.eligible)
                assertTrue(pair.slotAtRva(0x800UL)!!.richWriteCoverage.unknownWriteWidth)
            }
        }
    }

    @Test
    fun `a dependency string unused by symbols or versions is still part of the logical pairing proof`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            pairFixtureAddNeededOnly(fixture.richElf)
            val offset = pairFixtureAddNeededOnly(fixture.strippedElf)
            fixture.write()
            fixture.withPair { pair ->
                assertEquals(listOf("libc.so.6", "unused-dependency.so"), pair.richInventory.neededLibraries)
                assertTrue(pair.slotAtRva(0x800UL)!!.eligible)
            }
            fixture.strippedElf.bytes[offset] = 'x'.code.toByte()
            fixture.write()
            val error = assertFailsWith<IllegalArgumentException> { fixture.withPair {} }
            assertTrue(error.message!!.contains("logical dynamic metadata differs"))
        }

    @Test
    fun `code proof is bounded byte correspondence and never invents ownership or hidden instruction boundaries`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            fixture.strippedElf.bytes[0x206] = 1
            fixture.write()
            fixture.withPair { pair ->
                val prefix = assertNotNull(pair.codeWindowAtRva(0x200UL))
                assertEquals(6, prefix.length)
                val frozen = prefix.bytes
                frozen[0] = 0
                assertEquals(0xff.toByte(), prefix.bytes[0])
                assertNotNull(pair.proveCodeBytes(0x200UL, prefix.bytes))
                assertNull(pair.proveCodeBytes(0x200UL, ByteArray(7)))
                assertNull(pair.codeWindowAtRva(0x800UL), "writable GOT has no executable section ownership")
                assertNull(pair.codeWindowAtRva(ULong.MAX_VALUE))
                assertFailsWith<IllegalArgumentException> { pair.proveCodeBytes(0x200UL, ByteArray(16)) }
                assertFailsWith<IllegalArgumentException> { pair.proveCodeBytes(0x200UL, byteArrayOf()) }
            }
        }

    @Test
    fun `manifest pins close substitution while original locations and asserted equivalence do not supply facts`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            fixture.withHandles { manifest, rich, stripped ->
                assertFailsWith<IllegalArgumentException> { ElfExternalNamespacePairV1.prove(manifest, "0".repeat(64), rich, stripped) }
                assertFailsWith<IllegalArgumentException> { ElfExternalNamespacePairV1.prove(manifest, fixture.manifestSha, stripped, rich) }
            }
            val document = OracleJson.parseCanonical(Files.readAllBytes(fixture.manifest)) as JsonObject
            val artifacts = document.getValue("artifacts") as JsonObject
            val full = artifacts.getValue("full") as JsonObject
            val changed = JsonObject(document + ("artifacts" to JsonObject(artifacts + ("full" to JsonObject(full + ("sha256" to JsonPrimitive("0".repeat(64))))))))
            Files.write(fixture.manifest, OracleJson.canonicalBytes(changed))
            fixture.manifestSha = OracleArtifacts.sha256(Files.readAllBytes(fixture.manifest))
            assertFailsWith<IllegalArgumentException> { fixture.withPair {} }
        }

    @Test
    fun `work output read cancellation and lifetime code quotas fail closed`(): Unit = withElfExternalNamespacePairFixtureV1 { fixture ->
        for (limits in listOf(
            ElfExternalNamespacePairLimitsV1(maximumManifestBytes = 1),
            ElfExternalNamespacePairLimitsV1(maximumWorkUnits = 16),
            ElfExternalNamespacePairLimitsV1(maximumReadBytes = 16),
            ElfExternalNamespacePairLimitsV1(maximumOutputBytes = 1),
        )) assertFails { fixture.withPair(limits) {} }
        val cancellation = IllegalStateException("authored pair cancellation")
        val observed = assertFailsWith<IllegalStateException> { fixture.withPair(checkpoint = { throw cancellation }) {} }
        assertSame(cancellation, observed)
        assertFailsWith<IllegalArgumentException> {
            fixture.withPair(ElfExternalNamespacePairLimitsV1(maximumWallMillis = 1), checkpoint = { Thread.sleep(3) }) {}
        }
        fixture.withPair(ElfExternalNamespacePairLimitsV1(maximumCodeProofs = 1)) { pair ->
            assertNotNull(pair.codeWindowAtRva(0x200UL))
            assertFailsWith<IllegalArgumentException> { pair.codeWindowAtRva(0x200UL) }
        }
        // Reserve both parser-owned terminal authentication passes before scanning. With this
        // quota, the metadata reservations plus manifest fit, but the terminal byte reads do not.
        val quota = Files.size(fixture.manifest) * 2 + fixture.richElf.bytes.size * 4 - 1
        var beganScan = false
        assertFailsWith<IllegalArgumentException> {
            fixture.withPair(ElfExternalNamespacePairLimitsV1(maximumReadBytes = quota), checkpoint = {
                if (it == "while parsing dynamic ELF metadata") beganScan = true
            }) {}
        }
        assertFalse(beganScan, "unfunded scanner authentication reads must be rejected before either scan")
    }

    @Test
    fun `descriptor path substitution and use after close cannot retain a pair capability`(): Unit = withElfExternalNamespacePairFixtureV1 { fixture ->
        lateinit var closed: ElfExternalNamespacePairV1
        fixture.withPair { closed = it }
        assertFails { closed.codeWindowAtRva(0x200UL) }
        fixture.withPair { pair ->
            val substitute = Files.write(fixture.root.resolve("substitute.elf"), fixture.richElf.bytes)
            Files.move(substitute, fixture.rich, StandardCopyOption.REPLACE_EXISTING)
            assertFailsWith<FullTreeControlException> { pair.slotAtRva(0x800UL) }
            assertFailsWith<FullTreeControlException> { pair.requireCurrent() }
        }
    }

    @Test
    fun `identical explicitly pinned twin bytes are supported without inventing a stripping requirement`(): Unit =
        withElfExternalNamespacePairFixtureV1 { fixture ->
            fixture.richElf.bytes.copyInto(fixture.strippedElf.bytes); fixture.write()
            assertEquals(fixture.richSha, fixture.strippedSha)
            fixture.withPair { pair ->
                assertTrue(pair.slotAtRva(0x800UL)!!.eligible)
                assertEquals(pair.richNamespaceSha256, pair.strippedNamespaceSha256)
            }
        }
}

/** Authored ELF bytes and exact pins. No source-call report, recovered graph, or fabricated pair instance. */
internal class ElfExternalNamespacePairFixtureV1(val root: Path) {
    val richElf = DynamicBindingElfFixtureV1().also(::pairFixtureProgram)
    val strippedElf = DynamicBindingElfFixtureV1().also(::pairFixtureProgram).also { it.bytes[0xbff] = 1 }
    var strippedTransform: (ByteArray) -> ByteArray = { it }
    val rich: Path = root.resolve("pair-rich.elf")
    val stripped: Path = root.resolve("pair-stripped.elf")
    val manifest: Path = root.resolve("pair-manifest.json")
    lateinit var richSha: String; private set
    lateinit var strippedSha: String; private set
    lateinit var manifestSha: String
    init { write() }
    fun write() {
        Files.write(rich, richElf.bytes)
        Files.write(stripped, strippedTransform(strippedElf.bytes.copyOf()))
        richSha = OracleArtifacts.sha256(Files.readAllBytes(rich))
        strippedSha = OracleArtifacts.sha256(Files.readAllBytes(stripped))
        // This authored closed-schema shell has no source/build authority. Only the exact byte
        // pins below are premises; the pair independently scans all ELF facts instead of relying
        // on the shell's deliberately inert source/equivalence summaries or original paths.
        val template = pairFixtureManifestShell()
        val originals = template.getValue("artifacts") as JsonObject
        fun artifact(name: String, file: Path, sha: String): JsonObject = JsonObject((originals.getValue(name) as JsonObject) + mapOf(
            "path" to JsonPrimitive("not-dereferenced-$name.elf"), "bytes" to JsonPrimitive(Files.size(file)), "sha256" to JsonPrimitive(sha)))
        val document = JsonObject(template + ("artifacts" to pairFixtureObject("full" to artifact("full", rich, richSha),
            "stripped" to artifact("stripped", stripped, strippedSha))))
        val bytes = OracleJson.canonicalBytes(document)
        Files.write(manifest, bytes); manifestSha = OracleArtifacts.sha256(bytes)
    }
    fun withPair(limits: ElfExternalNamespacePairLimitsV1 = ElfExternalNamespacePairLimitsV1(), checkpoint: (String) -> Unit = {},
        action: (ElfExternalNamespacePairV1) -> Unit) {
        withHandles { manifest, rich, stripped -> action(ElfExternalNamespacePairV1.prove(manifest, manifestSha, rich, stripped, limits, checkpoint)) }
    }
    fun withHandles(action: (StableControlFile, StableControlFile, StableControlFile) -> Unit) {
        StableControlFile.open(manifest, Files.size(manifest), "authored pair manifest").use { m ->
            StableControlFile.open(rich, Files.size(rich), "authored pair rich").use { r ->
                StableControlFile.open(stripped, Files.size(stripped), "authored pair stripped").use { s -> action(m, r, s) }
            }
        }
    }
}
internal fun withElfExternalNamespacePairFixtureV1(action: (ElfExternalNamespacePairFixtureV1) -> Unit) {
    withDynamicFixture { action(ElfExternalNamespacePairFixtureV1(it)) }
}
private fun pairFixtureProgram(elf: DynamicBindingElfFixtureV1) {
    elf.word64(0x618, 0x400818UL)
    byteArrayOf(0xff.toByte(), 0x25, 0xfa.toByte(), 5, 0, 0).copyInto(elf.bytes, 0x200)
    byteArrayOf(0xe8.toByte(), 0x8b.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xc3.toByte()).copyInto(elf.bytes, 0x270)
}
private fun pairFixtureObject(vararg entries: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*entries))
private fun pairFixtureFind(bytes: ByteArray, value: String): Int {
    val target = value.toByteArray()
    return (0..bytes.size - target.size).first { offset -> target.indices.all { bytes[offset + it] == target[it] } }
}
private fun pairFixtureSwapSections(elf: DynamicBindingElfFixtureV1, a: Int, b: Int) {
    fun mapped(index: Int) = when (index) { a -> b; b -> a; else -> index }
    val first = elf.bytes.copyOfRange(elf.section(a), elf.section(a) + 64)
    val second = elf.bytes.copyOfRange(elf.section(b), elf.section(b) + 64)
    first.copyInto(elf.bytes, elf.section(b)); second.copyInto(elf.bytes, elf.section(a))
    repeat(12) { index ->
        val at = elf.section(index)
        val link = pairFixtureRead32(elf.bytes, at + 40)
        elf.word32(at + 40, mapped(link).toLong())
        val type = pairFixtureRead32(elf.bytes, at + 4)
        if (type == 4 || type == 9) elf.word32(at + 44, mapped(pairFixtureRead32(elf.bytes, at + 44)).toLong())
    }
    repeat(8) { index ->
        val at = 0x400 + index * 24 + 6
        val section = (elf.bytes[at].toInt() and 255) or ((elf.bytes[at + 1].toInt() and 255) shl 8)
        if (section in 1..11) elf.word16(at, mapped(section))
    }
}
private fun pairFixtureMoveFileStorage(original: ByteArray): ByteArray {
    val bytes = ByteArray(original.size + 0x1000)
    original.copyInto(bytes); original.copyInto(bytes, 0x1000)
    fun put64(offset: Int, value: Long) { repeat(8) { bytes[offset + it] = (value ushr (it * 8)).toByte() } }
    put64(0x48, 0x1000); put64(0x80, 0x1900)
    for (index in 1..11) {
        val at = 0xc00 + index * 64 + 24
        val old = (0..7).fold(0L) { acc, i -> acc or ((original[at + i].toLong() and 255) shl (i * 8)) }
        put64(at, old + 0x1000)
    }
    return bytes
}
private fun pairFixtureRead32(bytes: ByteArray, offset: Int): Int = (0..3).fold(0) { acc, i -> acc or ((bytes[offset + i].toInt() and 255) shl (8 * i)) }
private fun pairFixtureAddNeededOnly(elf: DynamicBindingElfFixtureV1): Int {
    val size = pairFixtureRead32(elf.bytes, elf.section(2) + 32)
    val value = "unused-dependency.so".toByteArray()
    value.copyInto(elf.bytes, 0x300 + size)
    elf.bytes[0x300 + size + value.size] = 0
    val total = (size + value.size + 1).toULong()
    elf.word64(elf.section(2) + 32, total); elf.tag(10UL, total)
    elf.word64(0xa00, 1UL); elf.word64(0xa08, size.toULong())
    elf.word64(0xa10, 0UL); elf.word64(0xa18, 0UL)
    elf.word64(elf.section(10) + 32, 288UL)
    elf.word64(0x98, 288UL); elf.word64(0xa0, 288UL)
    return 0x300 + size
}
private fun pairFixtureReindexSymbols(elf: DynamicBindingElfFixtureV1) {
    val first = elf.bytes.copyOfRange(0x418, 0x430)
    val second = elf.bytes.copyOfRange(0x430, 0x448)
    first.copyInto(elf.bytes, 0x430); second.copyInto(elf.bytes, 0x418)
    val version = elf.bytes.copyOfRange(0x702, 0x704)
    elf.bytes.copyInto(elf.bytes, 0x702, 0x704, 0x706); version.copyInto(elf.bytes, 0x704)
    for ((begin, count) in listOf(0x500 to 6, 0x600 to 4)) repeat(count) { index ->
        val at = begin + index * 24 + 8
        val type = pairFixtureRead32(elf.bytes, at).toUInt().toULong()
        val symbol = pairFixtureRead32(elf.bytes, at + 4)
        val swapped = when (symbol) { 1 -> 2; 2 -> 1; else -> symbol }
        elf.word64(at, (swapped.toULong() shl 32) or type)
    }
}

/** Generic schema shape, intentionally independent of every retained benchmark/profile. */
private fun pairFixtureManifestShell(): JsonObject {
    fun number(value: Long) = JsonPrimitive(value)
    fun text(value: String) = JsonPrimitive(value)
    fun flag(value: Boolean) = JsonPrimitive(value)
    fun array(vararg values: JsonElement) = JsonArray(values.toList())
    val sha = "0".repeat(64)
    val identity = pairFixtureObject("class" to text("ELF64"), "dataEncoding" to text("little-endian"),
        "identVersion" to number(1), "osAbi" to number(0), "abiVersion" to number(0), "type" to number(3),
        "machine" to number(62), "version" to number(1), "entryPoint" to number(0), "flags" to number(0))
    val header = JsonObject(identity + mapOf("osAbiName" to text("ELFOSABI_SYSV"), "typeName" to text("ET_DYN"),
        "machineName" to text("EM_X86_64"), "programHeaderOffset" to number(64), "sectionHeaderOffset" to number(3072),
        "headerSize" to number(64), "programHeaderEntrySize" to number(56), "programHeaderCount" to number(2),
        "sectionHeaderEntrySize" to number(64), "sectionHeaderCount" to number(12), "sectionNameTableIndex" to number(11)))
    val program = pairFixtureObject("index" to number(0), "type" to number(1), "typeName" to text("PT_LOAD"),
        "flags" to number(7), "flagNames" to text("RWE"), "offset" to number(0), "virtualAddress" to number(0x400000),
        "physicalAddress" to number(0), "fileSize" to number(0xf00), "memorySize" to number(0xf00),
        "alignment" to number(0x1000), "contentSha256" to text(sha))
    val section = pairFixtureObject("index" to number(1), "name" to text(".text"), "type" to number(1),
        "typeName" to text("SHT_PROGBITS"), "flags" to number(6), "address" to number(0x400200), "offset" to number(0x200),
        "size" to number(0x100), "link" to number(0), "info" to number(0), "alignment" to number(16), "entrySize" to number(0),
        "allocated" to flag(true), "executable" to flag(true), "fileBacked" to flag(true), "contentSha256" to text(sha))
    val metadata = pairFixtureObject("hasDwarf" to flag(false), "dwarfSections" to array(), "hasStaticSymbols" to flag(false),
        "staticSymbolTables" to array(), "hasDynamicSymbols" to flag(true),
        "dynamicSymbolTables" to array(pairFixtureObject("section" to text(".dynsym"), "entries" to number(8))))
    val load = pairFixtureObject("selector" to text("PT_LOAD with PF_X and nonzero p_filesz"),
        "segmentIndexes" to array(number(0)), "bytes" to number(0xf00), "sha256" to text(sha))
    val elf = pairFixtureObject("header" to header, "identity" to identity, "buildIds" to array(text("01020304")),
        "programHeaders" to array(program), "sections" to array(section), "metadata" to metadata, "executableLoad" to load)
    val artifact = pairFixtureObject("path" to text("unused.elf"), "bytes" to number(1), "sha256" to text(sha), "elf" to elf)
    fun input(path: String) = pairFixtureObject("path" to text(path), "bytes" to number(1), "sha256" to text(sha))
    val delta = pairFixtureObject("fullOnlySections" to array(), "strippedOnlySections" to array(), "changedCommonSections" to array(),
        "removedDwarfSections" to array(), "removedStaticSymbolTables" to array(pairFixtureObject("section" to text("unused-summary"), "entries" to number(0))))
    return pairFixtureObject("schemaVersion" to number(1),
        "oracle" to pairFixtureObject("id" to text("authored-pair"), "version" to text("1.0.0"), "sourceRevision" to text("0".repeat(40))),
        "inputs" to pairFixtureObject("sourceLock" to input("unused-source.json"), "buildRecord" to input("unused-build.json")),
        "artifacts" to pairFixtureObject("full" to artifact, "stripped" to artifact),
        "equivalence" to pairFixtureObject("buildId" to text("01020304"), "elfIdentity" to identity,
            "programHeadersSha256" to text(sha), "allocatedSectionsSha256" to text(sha), "executableLoad" to load, "metadataDelta" to delta))
}

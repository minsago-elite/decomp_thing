package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfCanonicalShardWriter
import decompengine.oracle.fulltree.parseCanonicalDwarfShard
import decompengine.oracle.structural.DwarfSysvAmd64InterfaceProjection
import decompengine.oracle.structural.DwarfSysvAmd64Classification
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactScanner
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.BoundedDwarfInterfaceTypeResolver
import decompengine.oracle.fulltree.DwarfInterfaceFact
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.DwarfInterfaceFunctionFacts
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class GccDriverDwarfInterfaceEvidenceTest {
    @Test
    fun `RVA mapping retains missing ambiguous and excluded facts without name inference`() {
        val records = JsonArray(listOf(
            oracle("unique", "0x3000"), oracle("ambiguous", "0x3010"), oracle("missing", "0x3020"),
            oracle("excluded", "0x3040", true), oracle("inline", null, true),
        ))
        val facts = listOf(
            function(0x3000UL, "die-1", "unrelated-name"),
            function(0x3010UL, "die-2"), function(0x3010UL, "die-3"),
            function(0x3020UL, "die-4", executable = false),
            function(0x3040UL, "die-5"), function(0x3999UL, "die-6", "missing"),
        )
        val projection = GccDriverDwarfInterfaceEvidence.mapFunctions(records, facts)
        val coverage = projection.getValue("coverage").jsonObject
        fun count(field: String, value: Int) = assertEquals(JsonPrimitive(value), coverage.getValue(field), field)
        count("oracleRecords", 5)
        count("scoredPhysicalFunctions", 3)
        count("excludedRecords", 2)
        count("uniqueRawDwarfFunctions", 1)
        count("ambiguousDwarfFunctions", 1)
        count("missingDwarfFunctions", 1)
        count("addressMatchedDwarfFunctions", 2)
        count("uniqueWithKnownRawReturnType", 1)
        count("uniqueWithKnownRawCallingConvention", 0)
        count("observableNeutralAbiFunctions", 0)
        count("unresolvedAbiFunctions", 3)
        val mapped = projection.getValue("functions").jsonArray.map { it.jsonObject }
        assertEquals(JsonArray(listOf(JsonPrimitive("die-1"))), mapped[0].getValue("candidateDieLocators"))
        assertEquals(JsonArray(listOf(JsonPrimitive("die-2"), JsonPrimitive("die-3"))), mapped[1].getValue("candidateDieLocators"))
        assertEquals(JsonArray(emptyList()), mapped[2].getValue("candidateDieLocators"))
        assertEquals(JsonPrimitive("no-physical-rva"), mapped[4].getValue("dwarfMatch"))
        assertTrue(mapped.all { it.getValue("projectedAbiLocator") == JsonNull })
        assertEquals(records[3].jsonObject.getValue("exclusion"), mapped[3].getValue("exclusion"))
        assertEquals(JsonArray(listOf(JsonPrimitive("die-4"), JsonPrimitive("die-6"))),
            projection.getValue("unmatchedRawCandidateDieLocators"))
        assertContentEquals(OracleJson.canonicalBytes(projection), OracleJson.canonicalBytes(
            GccDriverDwarfInterfaceEvidence.mapFunctions(records, facts.reversed())))
    }

    @Test
    fun `driver capture rejects a same-size changed checked control before scanning`() = temporary { temp ->
        val path = temp.resolve("oracle/targets/sysv-amd64-v1.json")
        Files.createDirectories(path.parent)
        val checked = Files.readAllBytes(repositoryRoot().resolve("oracle/targets/sysv-amd64-v1.json"))
        val changed = checked.decodeToString().replace("\"addressBits\": 64", "\"addressBits\": 32").toByteArray()
        assertEquals(checked.size, changed.size)
        assertNotEquals(OracleArtifacts.sha256(checked), OracleArtifacts.sha256(changed))
        Files.write(path, changed)
        val failure = assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.capture(temp, Files.createDirectory(temp.resolve("scratch")))
        }
        assertTrue(failure.message.orEmpty().contains("targetAbi differs from its checked identity"))
    }

    @Test
    fun `driver capture rejects aliased checked control paths`() = temporary { temp ->
        val path = temp.resolve("oracle/targets/sysv-amd64-v1.json")
        Files.createDirectories(path.parent)
        val bytes = Files.readAllBytes(repositoryRoot().resolve("oracle/targets/sysv-amd64-v1.json"))
        val actual = Files.write(temp.resolve("target.json"), bytes)
        Files.createSymbolicLink(path, actual)
        assertFailsWith<Exception> {
            GccDriverDwarfInterfaceEvidence.capture(temp, Files.createDirectory(temp.resolve("scratch")))
        }
    }

    @Test
    fun `checked rich GCC driver produces repeatable raw DWARF interface evidence`() {
        assumeTrue(System.getenv("DECOMP_REQUIRE_GCC_DWARF_INTERFACES") == "true", "actual GCC DWARF qualification is opt-in")
        val root = repositoryRoot()
        val destination = (System.getenv("DECOMP_GCC_DWARF_EVIDENCE_ROOT")?.let(Path::of)
            ?: root.resolve("build/gcc-driver-dwarf-interfaces")).toAbsolutePath().normalize()
        require(destination.startsWith(root) && destination != root) { "qualification output must remain inside the repository" }
        Files.createDirectories(destination, PRIVATE_DIRECTORY)
        val scratch = Files.createDirectories(destination.resolve("scratch"), PRIVATE_DIRECTORY)
        val started = System.nanoTime()
        val first = GccDriverDwarfInterfaceEvidence.capture(root, scratch)
        val firstBytes = first.canonicalBytes()
        val originalFirstByte = firstBytes[0]
        firstBytes[0] = 0
        assertEquals(originalFirstByte, first.canonicalBytes()[0], "publication must return defensive byte copies")
        val second = GccDriverDwarfInterfaceEvidence.capture(root, scratch)
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        assertEquals(first.partNames, second.partNames)
        first.partNames.forEach { name -> assertContentEquals(first.partBytes(name), second.partBytes(name), name) }
        val parts = first.partNames.map { it to first.partBytes(it) }
        GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts)
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.reversed()) }
        val changedPart = parts.first().second.copyOf().also { it[it.lastIndex] = 0 }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), listOf(parts.first().first to changedPart) + parts.drop(1))
        }
        val document = OracleJson.parseCanonical(first.canonicalBytes(), GccDriverDwarfInterfaceEvidence.EVIDENCE_JSON_LIMITS).jsonObject
        listOf("complete", "scored", "productionVerified", "releaseEligible").forEach {
            assertEquals(JsonPrimitive(false), document.getValue(it), it)
        }
        val coverage = document.getValue("coverage").jsonObject
        assertEquals(JsonPrimitive(12_844), coverage.getValue("oracleRecords"))
        assertEquals(JsonPrimitive(3_284), coverage.getValue("scoredPhysicalFunctions"))
        assertEquals(JsonPrimitive(9_560), coverage.getValue("excludedRecords"))
        val observable = coverage.getValue("observableNeutralAbiFunctions").jsonPrimitive.content.toInt()
        assertTrue(observable > 0 && observable <= 3_284, "actual neutral projection must produce measured observability")
        assertEquals(3_284 - observable, coverage.getValue("unresolvedAbiFunctions").jsonPrimitive.content.toInt())
        assertTrue(coverage.getValue("uniqueRawDwarfFunctions").jsonPrimitive.content.toInt() > 0)
        fun records(kind: String) = parts.filter { it.first.contains("-$kind-") }.flatMap {
            parseCanonicalDwarfShard(it.second).records
        }
        val metadata = records("metadata").single()
        assertEquals(JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER), metadata.getValue("schema"))
        assertTrue(records("functions").isNotEmpty())
        assertTrue(records("types").isNotEmpty())
        assertTrue(records("globals").isNotEmpty())
        assertTrue(records("globalProjection").isNotEmpty())
        val candidateIds = records("functions").map { it.getValue("locator").jsonPrimitive.content }.toSet()
        records("oracleFunctions").forEach { record ->
            record.getValue("candidateDieLocators").jsonArray.forEach { assertTrue(it.jsonPrimitive.content in candidateIds) }
        }
        val tamperResults = exerciseCheckedInputTampering(root, destination, document) +
            listOf("missing-shard-rejected", "altered-shard-rejected", "reordered-shards-rejected")
        first.visitParts { relative, bytes ->
            val path = destination.resolve(relative)
            Files.createDirectories(path.parent, PRIVATE_DIRECTORY)
            OracleArtifacts.publishAtomically(path, bytes, OracleArtifactLimits(GccDriverDwarfInterfaceEvidence.SHARD_LIMITS.maximumShardBytes))
        }
        OracleArtifacts.publishAtomically(destination.resolve(GccDriverDwarfInterfaceEvidence.EVIDENCE_NAME), first.canonicalBytes(),
            OracleArtifactLimits(GccDriverDwarfInterfaceEvidence.MAXIMUM_EVIDENCE_BYTES))
        val qualification = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-driver-dwarf-interface-qualification-v2"),
            "evidenceSha256" to JsonPrimitive(first.sha256), "evidenceBytes" to JsonPrimitive(first.canonicalBytes().size),
            "deterministicRepeat" to JsonPrimitive(true), "deterministicBundleParts" to JsonPrimitive(first.partNames.size), "tamperChecks" to JsonArray(tamperResults.map(::JsonPrimitive)),
            "elapsedMillis" to JsonPrimitive((System.nanoTime() - started) / 1_000_000),
            "producerSourceRevision" to (System.getenv("GITHUB_SHA")?.let(::JsonPrimitive) ?: JsonNull),
            "javaRuntimeVersion" to JsonPrimitive(System.getProperty("java.runtime.version")),
            "javaVendor" to JsonPrimitive(System.getProperty("java.vendor")),
            "osName" to JsonPrimitive(System.getProperty("os.name")), "osArch" to JsonPrimitive(System.getProperty("os.arch")),
            "compiledClassResources" to JsonArray(listOf(
                BoundedDwarfInterfaceFactScanner::class.java, BoundedDwarfInterfaceTypeResolver::class.java,
                BoundedDwarfInterfaceFacts::class.java, GccDriverDwarfInterfaceEvidence::class.java,
                DwarfSysvAmd64InterfaceProjection::class.java, DwarfSysvAmd64Classification::class.java,
                GccDriverDwarfGlobalProjection::class.java, BoundedDwarfCanonicalShardWriter::class.java,
            ).map(::compiledClassIdentity)),
            "identityScope" to JsonPrimitive("bounded classpath resource bytes read during qualification; not a signed or complete runtime closure"),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
        OracleArtifacts.publishAtomically(destination.resolve(GccDriverDwarfInterfaceEvidence.QUALIFICATION_NAME),
            OracleJson.canonicalBytes(qualification))
        println("GCC raw DWARF interface evidence retained at $destination; ${first.sha256}")
    }

    @Test
    fun `small v2 bundle rejects missing altered reordered and rehashed reordered parts`() {
        val base = JsonObject(mapOf("schemaVersion" to JsonPrimitive(2),
            "provider" to JsonPrimitive("gcc-driver-dwarf-interface-evidence-v2"),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false)))
        val kinds = listOf("metadata", "functions", "types", "typeChildren", "globals", "objectSymbols", "strippedObjects",
            "projectedTypes", "projectedFunctions", "projectedGlobalTypes", "oracleFunctions", "unmatchedFunctions", "globalProjection")
        fun bundle(order: List<String> = kinds) = GccDriverDwarfInterfaceEvidence.pack(base) { consume ->
            val writer = BoundedDwarfCanonicalShardWriter(GccDriverDwarfInterfaceEvidence.SHARD_LIMITS, consume)
            order.forEach { writer.write(it, if (it == "typeChildren") emptySequence()
                else sequenceOf(JsonObject(mapOf("identity" to JsonPrimitive(it))))) }
            writer.finish()
        }
        val first = bundle(); val second = bundle()
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        val parts = first.partNames.map { it to first.partBytes(it) }
        parts.forEach { (name, bytes) -> assertContentEquals(bytes, second.partBytes(name)) }
        GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts)
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.reversed()) }
        val altered = parts.first().second.copyOf().also { it[it.lastIndex] = 0 }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), listOf(parts.first().first to altered) + parts.drop(1))
        }
        val manifest = OracleJson.parseCanonical(first.canonicalBytes()).jsonObject
        val descriptors = manifest.getValue("parts").jsonArray
        assertEquals(JsonPrimitive(0), descriptors.single {
            it.jsonObject["kind"] == JsonPrimitive("typeChildren")
        }.jsonObject["recordCount"])
        assertFailsWith<IllegalArgumentException> { bundle(kinds - "typeChildren") }
        assertFailsWith<IllegalArgumentException> { bundle((kinds - "typeChildren") + "typeChildren") }
        assertFailsWith<IllegalArgumentException> { bundle(kinds.map { if (it == "typeChildren") "unknownChildren" else it }) }
        val changedManifest = OracleJson.canonicalBytes(JsonObject(manifest + ("parts" to JsonArray(descriptors.reversed()))))
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(changedManifest, parts.reversed()) }
        for (numeric in listOf("ordinal", "recordCount")) {
            val changed = JsonObject(descriptors.first().jsonObject +
                (numeric to JsonPrimitive(descriptors.first().jsonObject.getValue(numeric).jsonPrimitive.content)))
            val typedManifest = OracleJson.canonicalBytes(JsonObject(manifest +
                ("parts" to JsonArray(listOf(changed) + descriptors.drop(1)))))
            assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(typedManifest, parts) }
        }
        val copy = first.partBytes(first.partNames.first()); copy[0] = 0
        assertNotEquals(0, first.partBytes(first.partNames.first())[0].toInt())
    }

    private fun exerciseCheckedInputTampering(root: Path, destination: Path, document: JsonObject): List<String> {
        val fixture = Files.createTempDirectory(destination, "tamper-", PRIVATE_DIRECTORY)
        try {
            document.getValue("inputs").jsonObject.values.forEach { value ->
                val relative = value.jsonObject.getValue("path").jsonPrimitive.content
                val path = fixture.resolve(relative)
                Files.createDirectories(path.parent)
                Files.copy(root.resolve(relative), path)
            }
            val scratch = Files.createDirectory(fixture.resolve("scratch"), PRIVATE_DIRECTORY)
            val full = fixture.resolve("oracle/gcc/16.2.0/artifacts/gcc-driver.full")
            flipLastByte(full)
            val wrongBytes = assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.capture(fixture, scratch) }
            assertTrue(wrongBytes.message.orEmpty().contains("rich differs from its checked identity"))
            flipLastByte(full)
            var replaced = false
            val replacedControl = assertFailsWith<Exception> {
                GccDriverDwarfInterfaceEvidence.capture(fixture, scratch) { stage ->
                    if (stage == "before scanning checked GCC driver interfaces") {
                        val target = fixture.resolve("oracle/targets/sysv-amd64-v1.json")
                        val saved = target.resolveSibling("old-target.json")
                        Files.move(target, saved)
                        Files.copy(saved, target)
                        replaced = true
                    }
                }
            }
            assertTrue(replaced, "retained identity attack did not execute")
            assertTrue(replacedControl.message.orEmpty().contains("changed") || replacedControl.message.orEmpty().contains("mutation"),
                "wrong rejection: ${replacedControl.message}")
            return listOf("same-size-rich-byte-tamper-rejected", "same-content-control-path-replacement-rejected")
        } finally { deleteTree(fixture) }
    }

    private fun compiledClassIdentity(type: Class<*>): JsonObject {
        val resource = "/${type.name.replace('.', '/')}.class"
        val bytes = requireNotNull(type.getResourceAsStream(resource)).use { it.readNBytes(4 * 1024 * 1024 + 1) }
        require(bytes.isNotEmpty() && bytes.size <= 4 * 1024 * 1024)
        return JsonObject(mapOf("class" to JsonPrimitive(type.name), "resource" to JsonPrimitive(resource),
            "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
    }

    private fun flipLastByte(path: Path) = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
        val value = ByteBuffer.allocate(1)
        assertEquals(1, channel.read(value, channel.size() - 1))
        value.array()[0] = (value.array()[0].toInt() xor 1).toByte()
        value.rewind()
        assertEquals(1, channel.write(value, channel.size() - 1))
        channel.force(true)
    }

    private fun oracle(id: String, rva: String?, excluded: Boolean = false) = JsonObject(mapOf(
        "id" to JsonPrimitive(id), "rva" to (rva?.let(::JsonPrimitive) ?: JsonNull),
        "aliases" to JsonArray(listOf(JsonObject(mapOf("name" to JsonPrimitive(id))))),
        "exclusion" to if (excluded) JsonObject(mapOf("kind" to JsonPrimitive("reviewed"), "reason" to JsonPrimitive("retained reason"))) else JsonNull,
    ))

    private fun function(rva: ULong, locator: String, name: String = "raw-name", executable: Boolean = true): DwarfInterfaceFunctionFacts {
        val absent = DwarfInterfaceFact<String>(DwarfInterfaceFactState.ABSENT)
        return DwarfInterfaceFunctionFacts(rva, 0x400000UL + rva, executable, locator,
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(name)), absent, absent, absent, absent, absent, absent,
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf("raw-type-id")), emptyList(),
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(locator)), emptyList(),
            DwarfInterfaceFact(DwarfInterfaceFactState.ABSENT), emptyList(), emptyList())
    }

    private fun repositoryRoot(): Path = Path.of("").toAbsolutePath().normalize()
    private fun temporary(block: (Path) -> Unit) {
        val parent = Files.createDirectories(repositoryRoot().resolve("build/test-tmp"), PRIVATE_DIRECTORY)
        val directory = Files.createTempDirectory(parent, "gcc-interface-", PRIVATE_DIRECTORY)
        try { block(directory) } finally { deleteTree(directory) }
    }
    private fun deleteTree(directory: Path) = Files.walk(directory).use { paths ->
        paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }
    private companion object {
        val PRIVATE_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    }
}

package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.io.ByteArrayOutputStream
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZ
import org.tukaani.xz.XZOutputStream

class FullTreeGeneratedFileInventoryControlTest {
    @Test
    fun `selective snapshot is deterministic integrity verified unreceipted and ACP first class`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createGeneratedFixture(directory.resolve("fixture"))
            val firstPath = directory.resolve("generated-first.json")
            val secondPath = directory.resolve("generated-second.json")

            val first = generate(fixture, firstPath)
            val second = generate(fixture, secondPath)

            assertContentEquals(Files.readAllBytes(firstPath), Files.readAllBytes(secondPath))
            assertEquals(first.outputSha256, second.outputSha256)
            assertEquals(first.reportSha256, second.reportSha256)
            assertEquals(3, first.registry.generatedFiles.size)
            assertEquals(2, first.registry.generatedHeaders.size)
            assertEquals(1, first.registry.generatedTranslationUnits.size)
            assertEquals(EXPECTED_PATHS, first.registry.canonicalGeneratedFilePaths)
            assertEquals(EXPECTED_PATHS.drop(1), first.registry.canonicalGeneratedHeaderPaths)
            assertFalse(first.registry.generationReceiptBound)
            assertEquals(fixtureSha256(fixture.archive), first.registry.archiveSha256)
            assertEquals(fixtureSha256(fixture.provenance), first.registry.provenanceSha256)

            val zero = first.registry.requireGeneratedFile(GENERATED_INC)
            assertEquals(0L, zero.bytes)
            assertEquals(sha256(byteArrayOf()), zero.sha256)
            val generatedUnit = first.registry.generatedTranslationUnits.single()
            assertEquals("cu-52db46961f4d6b928aa25c36872c8137", generatedUnit.unitId)
            assertEquals(generatedUnit.moduleId, generatedUnit.unitId)
            assertEquals(generatedUnit, first.registry.requireGeneratedTranslationUnit(generatedUnit.unitId))

            val document = parseControlObject(firstPath)
            val authority = document.controlObject("authority")
            assertEquals("unreceipted-generated-snapshot", authority.controlString("status"))
            assertFalse(authority.getValue("snapshotBytesAuthenticated").toString().toBoolean())
            assertTrue(authority.getValue("snapshotBytesIntegrityVerified").toString().toBoolean())
            assertFalse(authority.getValue("generationReceiptBound").toString().toBoolean())
            assertFalse(authority.getValue("generatedHeaderPopulationComplete").toString().toBoolean())
            assertFalse(authority.getValue("releaseEligible").toString().toBoolean())
            val acp = document.controlObject("acpBoundary")
            assertEquals("first-class-candidate-producer-operator", acp.controlString("role"))
            assertEquals("not-an-input-to-generated-snapshot-v1", acp.controlString("candidateLineageAdmission"))
            listOf(
                "oracleAuthority",
                "referenceAuthoringAuthority",
                "policyAuthoringAuthority",
                "validationAuthority",
                "observationAuthoringAuthority",
                "startAuthority",
                "containmentAuthority",
                "terminalAbsenceAuthority",
                "scoringAuthority",
                "certificationAuthority",
                "releaseAuthority",
            ).forEach { field -> assertFalse(acp.getValue(field).toString().toBoolean()) }

            val counts = document.controlObject("counts")
            assertEquals(5L, counts.controlLong("archiveDirectories"))
            assertEquals(8L, counts.controlLong("archiveMembers"))
            assertEquals(3L, counts.controlLong("archiveRegularFiles"))
            assertEquals(4L, counts.controlLong("blockers"))
            assertEquals(60L, counts.controlLong("generatedFileBytes"))
            assertEquals(3L, counts.controlLong("generatorActionOutputReferences"))
            assertEquals(2L, counts.controlLong("generatorActions"))
            assertEquals(12L, counts.controlLong("outputRecords"))
            assertEquals(36L, counts.controlLong("workUnits"))

            val loaded = load(fixture, firstPath)
            assertEquals(first.registry.artifactSha256, loaded.artifactSha256)
            assertEquals(first.registry.generatedFiles, loaded.generatedFiles)
        }

    @Test
    fun `registry state is immutable and constructor has no trusted-object seam`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createGeneratedFixture(directory.resolve("immutable"))
            val registry = generate(fixture, directory.resolve("generated.json")).registry

            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.generatedFiles as MutableList<FullTreeGeneratedFile>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.canonicalGeneratedHeaderPaths as MutableList<String>) += "generated/forged.h"
            }
            assertFailsWith<FullTreeControlException> {
                registry.requireGeneratedTranslationUnit("cu-00000000000000000000000000000000")
            }
            assertFailsWith<FullTreeControlException> {
                registry.requireGeneratedFile("generated/../forged.h")
            }
            assertFailsWith<IllegalArgumentException> {
                Proxy.newProxyInstance(
                    FullTreeGeneratedFileRegistry::class.java.classLoader,
                    arrayOf(FullTreeGeneratedFileRegistry::class.java),
                ) { _, _, _ -> null }
            }

            val implementation = Class.forName(
                "decompengine.oracle.fulltree.FullTreeGeneratedFileInventoryControl\$ValidatedGeneratedFileRegistry",
            )
            implementation.declaredConstructors.forEach { constructor ->
                assertTrue(constructor.parameterTypes.all { type ->
                    type == Path::class.java ||
                        type == FullTreeGeneratedFileInventoryLimits::class.java ||
                        type == Boolean::class.javaPrimitiveType ||
                        type.name == "kotlin.jvm.internal.DefaultConstructorMarker"
                })
                assertFalse(constructor.parameterTypes.any { type ->
                    type == ByteArray::class.java ||
                        JsonObject::class.java.isAssignableFrom(type) ||
                        Collection::class.java.isAssignableFrom(type) ||
                        FullTreeGeneratedFileRegistry::class.java.isAssignableFrom(type)
                })
            }
            FullTreeGeneratedFileInventoryControl::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && it.name in setOf("generateAndPublish", "loadAndValidate") }
                .forEach { method ->
                    assertTrue(method.parameterTypes.all { type ->
                        type == Path::class.java || type == FullTreeGeneratedFileInventoryLimits::class.java
                    })
                }
        }

    @Test
    fun `concrete schemas close both producer and file branches and reject unsafe expansion`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createGeneratedFixture(directory.resolve("schema"))
            val provenance = parseControlObject(fixture.provenance)
            val output = directory.resolve("generated.json")
            generate(fixture, output)
            val inventory = parseControlObject(output)

            OracleSchemas.validate("full-tree-generated-file-provenance", provenance)
            OracleSchemas.validate("full-tree-generated-file-inventory", inventory)

            val files = provenance.controlArray("files").controlObjects("files")
            val unsafeFile = JsonObject(files.first() + ("sourcePath" to JsonPrimitive("generated/../escape.h")))
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-generated-file-provenance",
                    JsonObject(provenance + ("files" to JsonArray(listOf(unsafeFile) + files.drop(1)))),
                )
            }
            val expandedFile = JsonObject(files.first() + ("unexpected" to JsonPrimitive(true)))
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-generated-file-provenance",
                    JsonObject(provenance + ("files" to JsonArray(listOf(expandedFile) + files.drop(1)))),
                )
            }
            val buildGraph = provenance.controlObject("buildGraph")
            val wrongCmake = JsonObject(
                buildGraph.controlObject("cmakeTool") + ("role" to JsonPrimitive("buildGenerator")),
            )
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-generated-file-provenance",
                    JsonObject(
                        provenance +
                            ("buildGraph" to JsonObject(buildGraph + ("cmakeTool" to wrongCmake))),
                    ),
                )
            }
            val generatedFiles = inventory.controlArray("generatedFiles").controlObjects("generated files")
            val expandedHeader = JsonObject(generatedFiles[1] + ("moduleId" to JsonPrimitive("cu-" + "0".repeat(32))))
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-generated-file-inventory",
                    JsonObject(
                        inventory +
                            ("generatedFiles" to JsonArray(
                                listOf(generatedFiles.first(), expandedHeader) + generatedFiles.drop(2),
                            )),
                    ),
                )
            }
        }

    @Test
    fun `sidecar semantic tampering validly rehashed output forgery and lowering bounds fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createGeneratedFixture(directory.resolve("fail-closed"))
            val output = directory.resolve("generated.json")
            generate(fixture, output)

            val validOutput = parseControlObject(output)
            val forgedAuthority = JsonObject(
                validOutput.controlObject("authority") + ("snapshotBytesAuthenticated" to JsonPrimitive(true)),
            )
            writeControlObject(
                output,
                rehash(JsonObject(validOutput + ("authority" to forgedAuthority))),
            )
            assertFailsWith<FullTreeControlException> { load(fixture, output) }

            val sidecar = parseControlObject(fixture.provenance)
            val actions = sidecar.controlArray("actions").controlObjects("actions").toMutableList()
            val firstProducer = actions.first().controlObject("producer")
            actions[0] = JsonObject(
                actions.first() +
                    ("producer" to JsonObject(
                        firstProducer + ("runnerIdentitySha256" to JsonPrimitive("f".repeat(64))),
                    )),
            )
            val forgedActions = JsonArray(actions)
            val forgedGraph = fullTreeGeneratedBuildGraphSha256(
                sidecar.controlObject("buildGraph"),
                forgedActions,
            )
            writeControlObject(
                fixture.provenance,
                rehash(
                    JsonObject(
                        sidecar +
                            mapOf(
                                "actions" to forgedActions,
                                "buildGraphProvenanceSha256" to JsonPrimitive(forgedGraph),
                            ),
                    ),
                ),
            )
            assertFailsWith<FullTreeControlException> {
                generate(fixture, directory.resolve("forged-sidecar.json"))
            }

            val fresh = createGeneratedFixture(directory.resolve("bounded"))
            listOf(
                FullTreeGeneratedFileInventoryLimits(maximumArchiveMembers = 7),
                FullTreeGeneratedFileInventoryLimits(maximumGeneratedHeaders = 1),
                FullTreeGeneratedFileInventoryLimits(maximumGeneratedFiles = 2),
                FullTreeGeneratedFileInventoryLimits(maximumTotalGeneratedFileBytes = 59),
                FullTreeGeneratedFileInventoryLimits(maximumGeneratorActions = 1),
                FullTreeGeneratedFileInventoryLimits(maximumActionOutputReferences = 2),
                FullTreeGeneratedFileInventoryLimits(maximumOutputRecords = 11),
                FullTreeGeneratedFileInventoryLimits(maximumWorkUnits = 35),
                FullTreeGeneratedFileInventoryLimits(maximumSerializedBytes = 1),
            ).forEachIndexed { index, limits ->
                assertFailsWith<IllegalArgumentException> {
                    generate(fresh, directory.resolve("bounded-$index.json"), limits)
                }
            }
            assertFailsWith<FullTreeControlException> {
                generate(fresh, fresh.archive)
            }
        }

    private fun generate(
        fixture: GeneratedFixture,
        output: Path,
        limits: FullTreeGeneratedFileInventoryLimits = FullTreeGeneratedFileInventoryLimits(),
    ): FullTreeGeneratedFileInventoryGeneration = FullTreeGeneratedFileInventoryControl.generateAndPublish(
        fixture.archive,
        fixture.provenance,
        fixture.control.scope,
        fixture.control.sourceLock,
        fixture.control.manifest,
        fixture.control.buildRecord,
        fixture.control.inventory,
        fixture.control.sourceInventory,
        fixture.planning,
        output,
        limits,
    )

    private fun load(fixture: GeneratedFixture, output: Path): FullTreeGeneratedFileRegistry =
        FullTreeGeneratedFileInventoryControl.loadAndValidate(
            output,
            fixture.archive,
            fixture.provenance,
            fixture.control.scope,
            fixture.control.sourceLock,
            fixture.control.manifest,
            fixture.control.buildRecord,
            fixture.control.inventory,
            fixture.control.sourceInventory,
            fixture.planning,
        )

    internal companion object {
        const val GENERATED_CPP = "generated/tools/clang/lib/Basic/Generated.cpp"
        const val GENERATED_HEADER = "generated/tools/clang/lib/Basic/Generated.h"
        const val GENERATED_INC = "generated/tools/clang/lib/Basic/Generated.inc"
        val CPP_BYTES = "int generated(void) { return 7; }\n".toByteArray(StandardCharsets.US_ASCII)
        val HEADER_BYTES = "#define GENERATED_VALUE 7\n".toByteArray(StandardCharsets.US_ASCII)
        val EXPECTED_PATHS = listOf(GENERATED_CPP, GENERATED_HEADER, GENERATED_INC)
    }
}

internal data class GeneratedFixture(
    val control: FullTreeControlFixture,
    val planning: Path,
    val archive: Path,
    val provenance: Path,
)

internal fun createGeneratedFixture(root: Path): GeneratedFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val planning = root.resolve("planning.json")
    FullTreePlanningInventoryControl.generateAndPublish(
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        planning,
    )
    val buildRecord = parseControlObject(control.buildRecord)
    val epoch = buildRecord.controlObject("environment").controlObject("variables")
        .controlString("SOURCE_DATE_EPOCH").toLong()
    val archiveBytes = generatedArchive(epoch)
    val archive = root.resolve("generated.tar.xz")
    Files.write(archive, archiveBytes)
    Files.setPosixFilePermissions(archive, PosixFilePermissions.fromString("rw-r--r--"))
    val provenance = root.resolve("generated-provenance.json")
    writeControlObject(
        provenance,
        generatedProvenance(buildRecord, control.buildRecord, archiveBytes),
    )
    return GeneratedFixture(control, planning, archive, provenance)
}

private fun generatedProvenance(
    buildRecord: JsonObject,
    buildRecordPath: Path,
    archiveBytes: ByteArray,
): JsonObject {
    val commands = buildRecord.controlObject("commands")
    val configureSha256 = fullTreeGeneratedConfigureCommandSha256(commands.controlArray("configure"))
    val compileSha256 = fullTreeGeneratedCompileCommandSha256(commands.controlArray("compile"))
    val tools = buildRecord.controlArray("tools").controlObjects("tools")
    val cmakeTool = generatedToolBinding(tools.single { it.controlString("role") == "buildSystem" })
    val ninjaTool = generatedToolBinding(tools.single { it.controlString("role") == "buildGenerator" })
    val buildGraph = JsonObject(
        mapOf(
            "buildDirectory" to buildRecord.controlObject("directories").getValue("build"),
            "buildRecordSha256" to JsonPrimitive(fixtureSha256(buildRecordPath)),
            "buildSystem" to JsonPrimitive("cmake-ninja"),
            "cmakeCacheBytes" to JsonPrimitive(5),
            "cmakeCacheSha256" to JsonPrimitive(sha256("cache".toByteArray(StandardCharsets.US_ASCII))),
            "cmakeTool" to cmakeTool,
            "compileCommandSha256" to JsonPrimitive(compileSha256),
            "configureCommandSha256" to JsonPrimitive(configureSha256),
            "ninjaManifestBytes" to JsonPrimitive(5),
            "ninjaManifestSha256" to JsonPrimitive(sha256("ninja".toByteArray(StandardCharsets.US_ASCII))),
            "ninjaTool" to ninjaTool,
            "sourceDateEpoch" to JsonPrimitive(
                buildRecord.controlObject("environment").controlObject("variables")
                    .controlString("SOURCE_DATE_EPOCH").toLong(),
            ),
        ),
    )
    val cmakeProducer = JsonObject(
        mapOf(
            "cmakeOriginSha256" to JsonPrimitive(sha256("cmake-origin".toByteArray(StandardCharsets.US_ASCII))),
            "generatorCommandSha256" to JsonPrimitive(
                sha256("cmake-producer-command".toByteArray(StandardCharsets.US_ASCII)),
            ),
            "generatorIdentitySha256" to JsonPrimitive(
                sha256("cmake-generator".toByteArray(StandardCharsets.US_ASCII)),
            ),
            "kind" to JsonPrimitive("cmake-configure"),
            "ninjaDisposition" to JsonPrimitive("not-a-ninja-edge"),
            "runnerIdentitySha256" to JsonPrimitive(fullTreeGeneratedToolIdentitySha256(cmakeTool)),
        ),
    )
    val ninjaOutputs = listOf(
        FullTreeGeneratedFileInventoryControlTest.GENERATED_HEADER,
        FullTreeGeneratedFileInventoryControlTest.GENERATED_INC,
    )
    val ninjaCommandSha256 = sha256("ninja-edge-command".toByteArray(StandardCharsets.US_ASCII))
    val ninjaGeneratorSha256 = sha256("ninja-edge-generator".toByteArray(StandardCharsets.US_ASCII))
    val ninjaOriginSha256 = sha256("ninja-cmake-origin".toByteArray(StandardCharsets.US_ASCII))
    val ninjaRunnerSha256 = fullTreeGeneratedToolIdentitySha256(ninjaTool)
    val ninjaProducer = JsonObject(
        mapOf(
            "cmakeOriginSha256" to JsonPrimitive(ninjaOriginSha256),
            "generatorCommandSha256" to JsonPrimitive(ninjaCommandSha256),
            "generatorIdentitySha256" to JsonPrimitive(ninjaGeneratorSha256),
            "kind" to JsonPrimitive("ninja-edge"),
            "ninjaEdgeSha256" to JsonPrimitive(
                sha256("canonical-full-ninja-edge-record".toByteArray(StandardCharsets.US_ASCII)),
            ),
            "runnerIdentitySha256" to JsonPrimitive(ninjaRunnerSha256),
        ),
    )
    val actions = JsonArray(
        listOf(
            JsonObject(
                mapOf(
                    "outputPaths" to JsonArray(
                        listOf(JsonPrimitive(FullTreeGeneratedFileInventoryControlTest.GENERATED_CPP)),
                    ),
                    "producer" to cmakeProducer,
                ),
            ),
            JsonObject(
                mapOf(
                    "outputPaths" to JsonArray(ninjaOutputs.map(::JsonPrimitive)),
                    "producer" to ninjaProducer,
                ),
            ),
        ),
    )
    val files = JsonArray(
        listOf(
            generatedProvenanceFile(
                FullTreeGeneratedFileInventoryControlTest.GENERATED_CPP,
                FullTreeGeneratedFileInventoryControlTest.CPP_BYTES,
            ),
            generatedProvenanceFile(
                FullTreeGeneratedFileInventoryControlTest.GENERATED_HEADER,
                FullTreeGeneratedFileInventoryControlTest.HEADER_BYTES,
            ),
            generatedProvenanceFile(FullTreeGeneratedFileInventoryControlTest.GENERATED_INC, byteArrayOf()),
        ),
    )
    val withoutHash = JsonObject(
        mapOf(
            "actions" to actions,
            "authority" to JsonObject(
                mapOf(
                    "generationReceiptBound" to JsonPrimitive(false),
                    "releaseEligible" to JsonPrimitive(false),
                    "status" to JsonPrimitive("unreceipted-generated-snapshot-provenance"),
                ),
            ),
            "buildGraph" to buildGraph,
            "buildGraphProvenanceSha256" to JsonPrimitive(
                fullTreeGeneratedBuildGraphSha256(buildGraph, actions),
            ),
            "files" to files,
            "kind" to JsonPrimitive("full-tree-generated-file-provenance-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "snapshot" to JsonObject(
                mapOf(
                    "archiveBytes" to JsonPrimitive(archiveBytes.size),
                    "archiveRoot" to JsonPrimitive("generated"),
                    "archiveSha256" to JsonPrimitive(sha256(archiveBytes)),
                ),
            ),
        ),
    )
    return rehash(withoutHash)
}

private fun generatedToolBinding(tool: JsonObject): JsonObject = JsonObject(
    mapOf(
        "executableBytes" to tool.getValue("executableBytes"),
        "executableSha256" to tool.getValue("executableSha256"),
        "path" to tool.getValue("path"),
        "role" to tool.getValue("role"),
        "versionOutputSha256" to JsonPrimitive(
            sha256(tool.controlString("versionOutput").toByteArray(StandardCharsets.UTF_8)),
        ),
    ),
)

private fun generatedProvenanceFile(path: String, bytes: ByteArray): JsonObject = JsonObject(
    mapOf(
        "bytes" to JsonPrimitive(bytes.size),
        "sha256" to JsonPrimitive(sha256(bytes)),
        "sourcePath" to JsonPrimitive(path),
    ),
)

private fun rehash(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(64 * 1024 * 1024)),
    )
    return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
}

private fun generatedArchive(mtime: Long): ByteArray {
    val entries = listOf(
        GeneratedTarEntry("generated/", '5'),
        GeneratedTarEntry("generated/tools/", '5'),
        GeneratedTarEntry("generated/tools/clang/", '5'),
        GeneratedTarEntry("generated/tools/clang/lib/", '5'),
        GeneratedTarEntry("generated/tools/clang/lib/Basic/", '5'),
        GeneratedTarEntry(
            FullTreeGeneratedFileInventoryControlTest.GENERATED_CPP,
            '0',
            FullTreeGeneratedFileInventoryControlTest.CPP_BYTES,
        ),
        GeneratedTarEntry(
            FullTreeGeneratedFileInventoryControlTest.GENERATED_HEADER,
            '0',
            FullTreeGeneratedFileInventoryControlTest.HEADER_BYTES,
        ),
        GeneratedTarEntry(FullTreeGeneratedFileInventoryControlTest.GENERATED_INC, '0'),
    )
    val tar = ByteArrayOutputStream()
    entries.forEach { entry ->
        tar.write(generatedTarHeader(entry, mtime))
        tar.write(entry.bytes)
        repeat((512 - entry.bytes.size % 512) % 512) { tar.write(0) }
    }
    val remainder = (tar.size() / 512) % 20
    val terminatorBlocks = (20 - remainder).let { if (it < 2) it + 20 else it }
    repeat(terminatorBlocks) { tar.write(ByteArray(512)) }
    val compressed = ByteArrayOutputStream()
    XZOutputStream(compressed, LZMA2Options(1), XZ.CHECK_CRC64).use { it.write(tar.toByteArray()) }
    return compressed.toByteArray()
}

private fun generatedTarHeader(entry: GeneratedTarEntry, mtime: Long): ByteArray {
    val header = ByteArray(512)
    generatedTarText(header, 0, 100, entry.path)
    generatedTarOctal(header, 100, 8, if (entry.kind == '5') 0x1fd else 0x1b4)
    generatedTarOctal(header, 108, 8, 0)
    generatedTarOctal(header, 116, 8, 0)
    generatedTarOctal(header, 124, 12, entry.bytes.size.toLong())
    generatedTarOctal(header, 136, 12, mtime)
    repeat(8) { header[148 + it] = ' '.code.toByte() }
    header[156] = entry.kind.code.toByte()
    generatedTarText(header, 257, 6, "ustar")
    "00".toByteArray(StandardCharsets.US_ASCII).copyInto(header, 263)
    generatedTarText(header, 265, 32, "root")
    generatedTarText(header, 297, 32, "root")
    generatedTarOctal(header, 329, 8, 0)
    generatedTarOctal(header, 337, 8, 0)
    val checksum = header.sumOf { it.toInt() and 0xff }.toLong()
    generatedTarOctal(header, 148, 8, checksum)
    return header
}

private fun generatedTarText(header: ByteArray, offset: Int, length: Int, value: String) {
    val bytes = value.toByteArray(StandardCharsets.US_ASCII)
    require(bytes.size < length)
    bytes.copyInto(header, offset)
}

private fun generatedTarOctal(header: ByteArray, offset: Int, length: Int, value: Number) {
    val bytes = value.toLong().toString(8).padStart(length - 1, '0').toByteArray(StandardCharsets.US_ASCII)
    require(bytes.size == length - 1)
    bytes.copyInto(header, offset)
    header[offset + length - 1] = 0
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes).joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private data class GeneratedTarEntry(
    val path: String,
    val kind: Char,
    val bytes: ByteArray = byteArrayOf(),
)

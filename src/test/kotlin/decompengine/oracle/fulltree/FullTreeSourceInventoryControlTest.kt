package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeSourceInventoryControlTest {
    @Test
    fun `streamed tar xz source inventory is byte-identical to frozen Python v1 across workers`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val serialOutput = directory.resolve("serial-source-inventory.json")
            val parallelOutput = directory.resolve("parallel-source-inventory.json")

            val serial = FullTreeSourceInventoryControl.generateAndPublish(
                fixture.sourceArchive,
                scope,
                fixture.buildRecord,
                fixture.inventory,
                serialOutput,
                maximumWorkers = 1,
            )
            val parallel = FullTreeSourceInventoryControl.generateAndPublish(
                fixture.sourceArchive,
                scope,
                fixture.buildRecord,
                fixture.inventory,
                parallelOutput,
                maximumWorkers = 2,
            )

            val frozen = Files.readAllBytes(fixture.sourceInventory)
            val serialBytes = Files.readAllBytes(serialOutput)
            assertTrue(frozen.contentEquals(serialBytes))
            assertTrue(serialBytes.contentEquals(Files.readAllBytes(parallelOutput)))
            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreeSourceInventoryControl.configurationSha256)
            assertEquals(FROZEN_REPORT_SHA256, serial.reportSha256)
            assertEquals(FROZEN_ARCHIVE_SHA256, serial.sourceArchiveSha256)
            assertEquals(FROZEN_REPORT_ARTIFACT_SHA256, serial.outputSha256)
            assertEquals(serial.report, parallel.report)
        }

    @Test
    fun `source inventory semantic ownership exclusion order count and binding mutations fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val build = parseControlObject(fixture.buildRecord)
            val inventory = parseControlObject(fixture.inventory)
            val original = parseControlObject(fixture.sourceInventory)

            val removedLinked = original.controlArray("sourceUnits").controlObjects("source units")
                .filterNot { it.controlString("classification") == "linked" }
            val badCoverage = rehashReport(
                JsonObject(original.toMutableMap().apply {
                    this["sourceUnits"] = JsonArray(removedLinked)
                    this["counts"] = JsonObject(original.controlObject("counts").toMutableMap().apply {
                        this["candidateTranslationUnits"] = JsonPrimitive(3)
                        this["linkedSourceUnits"] = JsonPrimitive(0)
                    })
                }),
            )
            val sourceUnits = original.controlArray("sourceUnits").controlObjects("source units").toMutableList()
            val sourceOnlyIndex = sourceUnits.indexOfFirst { it.controlString("classification") == "source-only" }
            sourceUnits[sourceOnlyIndex] = JsonObject(sourceUnits[sourceOnlyIndex].toMutableMap().apply {
                this["reasonCode"] = JsonPrimitive("not-selected-by-authenticated-build-graph")
            })
            val badReason = rehashReport(JsonObject(original.toMutableMap().apply {
                this["sourceUnits"] = JsonArray(sourceUnits)
            }))
            val badTablegenOrder = rehashReport(JsonObject(original.toMutableMap().apply {
                this["tablegenInputs"] = JsonArray(original.controlArray("tablegenInputs").reversed())
            }))
            val generated = original.controlArray("generatedCompilationUnits")
                .controlObjects("generated units").toMutableList()
            generated[0] = JsonObject(generated[0].toMutableMap().apply {
                this["shardId"] = JsonPrimitive("clang-lib-driver")
            })
            val badGenerated = rehashReport(JsonObject(original.toMutableMap().apply {
                this["generatedCompilationUnits"] = JsonArray(generated)
            }))
            val badBinding = rehashReport(JsonObject(original.toMutableMap().apply {
                this["oracle"] = JsonObject(original.controlObject("oracle").toMutableMap().apply {
                    this["inventoryIndexSha256"] = JsonPrimitive("0".repeat(64))
                })
            }))
            listOf(badCoverage, badReason, badTablegenOrder, badGenerated, badBinding).forEach { mutation ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeSourceInventoryControl.validate(mutation, scope, build, inventory)
                }
            }
        }

    @Test
    fun `source archive symlink permission compressed expanded member and worker bounds fail closed`() =
        inControlTemporaryDirectory { directory ->
            val symlinked = createFullTreeControlFixture(directory.resolve("symlink"))
            val real = symlinked.root.resolve("archive-real.tar.xz")
            Files.move(symlinked.sourceArchive, real)
            Files.createSymbolicLink(symlinked.sourceArchive, real.fileName)
            assertSourceGenerationFails(symlinked, directory.resolve("symlink-output.json"))

            val writable = createFullTreeControlFixture(directory.resolve("writable"))
            Files.setPosixFilePermissions(writable.sourceArchive, PosixFilePermissions.fromString("rw-rw-r--"))
            assertSourceGenerationFails(writable, directory.resolve("writable-output.json"))

            val modeChanged = createFullTreeControlFixture(directory.resolve("mode-changed"))
            StableControlFile.open(
                modeChanged.sourceArchive,
                Files.size(modeChanged.sourceArchive),
                "mode-changing source archive fixture",
            ).use { archive ->
                archive.sha256()
                Files.setPosixFilePermissions(
                    modeChanged.sourceArchive,
                    PosixFilePermissions.fromString("rw-rw-r--"),
                )
                assertFailsWith<FullTreeControlException> {
                    archive.verifyUnchanged("mode-changing source archive fixture")
                }
            }

            val collision = createFullTreeControlFixture(directory.resolve("collision"))
            val collisionHash = fixtureSha256(collision.sourceArchive)
            assertFailsWith<FullTreeControlException> {
                FullTreeSourceInventoryControl.generateAndPublish(
                    collision.sourceArchive,
                    collision.authenticatedScope(),
                    collision.buildRecord,
                    collision.inventory,
                    collision.sourceArchive,
                    1,
                )
            }
            assertEquals(collisionHash, fixtureSha256(collision.sourceArchive))

            val bounded = createFullTreeControlFixture(directory.resolve("bounded"))
            val variants = listOf(
                FullTreeControlLimits(maximumSourceArchiveBytes = Files.size(bounded.sourceArchive) - 1L),
                FullTreeControlLimits(maximumExpandedArchiveBytes = 1024L),
                FullTreeControlLimits(maximumArchiveMembers = 1),
                FullTreeControlLimits(maximumArchiveIndexBytes = 1L),
                FullTreeControlLimits(maximumXzDecoderMemoryKiB = 1),
                FullTreeControlLimits(maximumWorkers = 1),
                FullTreeControlLimits(maximumSourceInventoryBytes = Files.size(bounded.sourceInventory).toInt() - 1),
            )
            variants.forEachIndexed { index, limits ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeSourceInventoryControl.generateAndPublish(
                        bounded.sourceArchive,
                        bounded.authenticatedScope(limits),
                        bounded.buildRecord,
                        bounded.inventory,
                        directory.resolve("bounded-output-$index.json"),
                        maximumWorkers = if (limits.maximumWorkers == 1) 2 else 1,
                        limits = limits,
                    )
                }
                assertFalse(Files.exists(directory.resolve("bounded-output-$index.json")))
            }
        }

    @Test
    fun `frozen validator authenticates checked bytes without Python runtime authority`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val report = FullTreeSourceInventoryControl.loadAndValidate(
                fixture.sourceInventory,
                fixture.authenticatedScope(),
                fixture.buildRecord,
                fixture.inventory,
            )
            assertEquals(FROZEN_REPORT_SHA256, report.controlString("reportSha256"))
            assertEquals(FROZEN_REPORT_ARTIFACT_SHA256, fixtureSha256(fixture.sourceInventory))
        }

    @Test
    fun `streamed source archive rejects parent traversal before indexing`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val archivePath = directory.resolve("unsafe-source.tar.xz")
            Files.write(
                archivePath,
                Base64.getMimeDecoder().decode(fullTreeControlResource("unsafe-source.tar.xz.b64")),
            )
            Files.setPosixFilePermissions(archivePath, PosixFilePermissions.fromString("rw-r--r--"))
            StableControlFile.open(
                archivePath,
                Files.size(archivePath),
                "unsafe source archive fixture",
            ).use { archive ->
                assertFailsWith<FullTreeControlException> {
                    SourceTarIndex.read(archive, fixture.authenticatedScope(), FullTreeControlLimits())
                }
            }
        }

    private fun assertSourceGenerationFails(fixture: FullTreeControlFixture, output: java.nio.file.Path) {
        assertFailsWith<FullTreeControlException> {
            FullTreeSourceInventoryControl.generateAndPublish(
                fixture.sourceArchive,
                fixture.authenticatedScope(),
                fixture.buildRecord,
                fixture.inventory,
                output,
                1,
            )
        }
        assertFalse(Files.exists(output))
    }

    private fun rehashReport(report: JsonObject): JsonObject {
        val withoutHash = JsonObject(report.filterKeys { it != "reportSha256" })
        val hash = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash))
        return JsonObject(report.toMutableMap().apply { this["reportSha256"] = JsonPrimitive(hash) })
    }

    private companion object {
        /*
         * One-time migration provenance: the frozen inventory and report resources were emitted by
         * the checked-in historical v1 Python generators from the adjacent frozen ELF and tar.xz.
         * Production and tests consume only inert bytes and never import or invoke Python.
         */
        const val FROZEN_CONFIGURATION_SHA256 =
            "88b4745bb5dc3136f35c9a3ed0456cbd9292c12e5b89e7ae48476d97b5b4692d"
        const val FROZEN_REPORT_SHA256 = "af2cb5e6ce26e028a07784f0bace089123749612c8690c3dee3659fcbc44d2aa"
        const val FROZEN_ARCHIVE_SHA256 = "0caa68b1a7612f1766de5bd66f73bc89c33e8b384953904434c8bded2f6ce419"
        const val FROZEN_REPORT_ARTIFACT_SHA256 =
            "a79a1791dcf0e8e4a5a5cc590881614d546e78f025d857619af895f580e55b21"
    }
}

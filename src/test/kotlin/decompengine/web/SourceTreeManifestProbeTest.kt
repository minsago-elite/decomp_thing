package decompengine.web

import decompengine.project.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.function.LongSupplier
import kotlinx.serialization.json.*
import kotlin.test.*
import org.junit.jupiter.api.condition.EnabledIfSystemProperty

class SourceTreeManifestProbeTest {
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private fun file(path: String, profile: ReconstructionProfile = this.profile, accepted: Boolean? = true): GeneratedFileEvidence {
        val declaration = profile.layout.declarationForPath(path)
        return GeneratedFileEvidence(path, "a".repeat(64), "probe-control", "b".repeat(64),
            listOf("entity-a", "entity-b"), accepted, declaration.roles, declaration.contentKind)
    }
    private fun document(profile: ReconstructionProfile = this.profile): JsonObject = Json.parseToJsonElement(
        SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = "input",
            files = listOf(file("include/modules/a.h", profile, null), file("src/modules/a.c", profile, false)),
            unresolvedEntityIds = listOf("missing-a"), unresolvedImplementationIds = listOf("missing-b")).toJson(),
    ).jsonObject

    private fun JsonObject.with(name: String, value: JsonElement) = JsonObject(this + (name to value))
    private fun JsonObject.firstFile(vararg fields: Pair<String, JsonElement>): JsonObject {
        val files = getValue("files").jsonArray
        return with("files", JsonArray(listOf(JsonObject(files[0].jsonObject + fields)) + files.drop(1)))
    }
    private fun collector(): ManifestAllocationCollector {
        var nanos = 0L
        var bytes = 0L
        return ManifestAllocationCollector(LongSupplier { ++nanos }, LongSupplier { bytes += 10; bytes })
    }
    private fun assertValue(expected: SourceTreeManifest, actual: SourceTreeManifest) {
        assertEquals(expected.schemaVersion, actual.schemaVersion)
        assertEquals(expected.profileId, actual.profileId)
        assertEquals(expected.profileSha256, actual.profileSha256)
        assertEquals(expected.inputSha256, actual.inputSha256)
        assertEquals(expected.unresolvedEntityIds, actual.unresolvedEntityIds)
        assertEquals(expected.unresolvedImplementationIds, actual.unresolvedImplementationIds)
        assertEquals(expected.editablePaths, actual.editablePaths)
        assertEquals(expected.files.size, actual.files.size)
        expected.files.zip(actual.files).forEach { (a, b) ->
            assertEquals(listOf(a.path, a.sha256, a.generator, a.promptSha256, a.entityIds,
                a.acceptedImplementation, a.roles, a.contentKind),
                listOf(b.path, b.sha256, b.generator, b.promptSha256, b.entityIds,
                    b.acceptedImplementation, b.roles, b.contentKind))
        }
        assertContentEquals(expected.toJson().toByteArray(), actual.toJson().toByteArray())
    }

    @Test fun `null and enabled probes preserve make and ninja values and bytes`() {
        for (profile in listOf(this.profile, GeneratedCNinjaReconstructionProfile.descriptor)) {
            val root = document(profile)
            val baseline = SourceTreeManifestReader.parse(root, profile)
            val probe = collector()
            assertValue(baseline, SourceTreeManifestReader.parse(root, profile, probe))
            assertValue(baseline, SourceTreeManifestReader.parse(root.toString(), profile))
            val stages = probe.snapshot(100).getValue("stages").jsonObject
            for (stage in SourceTreeManifestStage.entries) {
                val expected = if (stage == SourceTreeManifestStage.FILE_FIELDS || stage == SourceTreeManifestStage.FILE_EVIDENCE_INIT) 2 else 1
                assertEquals(expected, stages.getValue(stage.marker).jsonObject.getValue("segments").jsonPrimitive.int)
            }
        }
    }

    @Test fun `probe preserves exact first refusal and closes every failure stage`() {
        val root = document()
        val cases = listOf(
            root.with("extra", JsonNull).with("schemaVersion", JsonPrimitive(2)) to "source tree manifest fields do not match schema version 3",
            root.with("schemaVersion", JsonPrimitive("3")).with("profileId", JsonNull) to "source tree manifest schemaVersion must be an integer",
            root.with("schemaVersion", JsonPrimitive(2)) to "unsupported source tree manifest schemaVersion: 2",
            root.firstFile("extra" to JsonNull, "roles" to JsonNull) to "source tree manifest file fields do not match schema version 3",
            root.firstFile("roles" to JsonArray(listOf(JsonPrimitive(2))), "path" to JsonNull) to "source tree manifest file roles must be strings",
            root.firstFile("roles" to JsonArray(listOf(JsonPrimitive("editable"), JsonPrimitive("editable")))) to "source tree manifest file roles must be unique and sorted",
            root.firstFile("entityIds" to JsonArray(listOf(JsonPrimitive("z"), JsonPrimitive("a"))), "acceptedImplementation" to JsonPrimitive("true")) to "source tree manifest entity IDs must be unique and sorted",
            root.firstFile("acceptedImplementation" to JsonPrimitive("true"), "path" to JsonNull) to "source tree manifest acceptance value must be Boolean or null",
            root.firstFile("path" to JsonNull, "sha256" to JsonNull) to "source tree manifest path must be a string",
            root.firstFile("path" to JsonPrimitive("../bad"), "contentKind" to JsonNull) to "source tree manifest contentKind must be a string",
            root.firstFile("sha256" to JsonPrimitive("BAD"), "generator" to JsonPrimitive("")) to "source tree manifest file hash is invalid: include/modules/a.h",
            root.with("files", JsonArray(root.getValue("files").jsonArray.reversed())).with("unresolvedEntityIds", JsonNull) to "source tree manifest files must be unique and sorted",
            root.with("inputSha256", JsonNull).with("unresolvedEntityIds", JsonNull) to "source tree manifest inputSha256 must be a string",
            root.with("unresolvedEntityIds", JsonArray(listOf(JsonPrimitive("z"), JsonPrimitive("a")))).with("unresolvedImplementationIds", JsonNull) to "source tree manifest unresolvedEntityIds must be unique and sorted",
            root.with("profileId", JsonPrimitive("!")).with("profileSha256", JsonPrimitive("bad")) to "source tree manifest profile ID is invalid",
            root.with("profileSha256", JsonPrimitive("bad")) to "source tree manifest profile digest is invalid",
            root.with("profileId", JsonPrimitive("other")).firstFile("roles" to JsonArray(listOf(JsonPrimitive("evidence")))) to "source tree manifest reconstruction profile does not match the expected profile",
            root.firstFile("roles" to JsonArray(listOf(JsonPrimitive("evidence")))) to "source tree manifest file policy does not match the reconstruction profile: include/modules/a.h",
        )
        for ((record, message) in cases) {
            val baseline = assertFails { SourceTreeManifestReader.parse(record, profile, null) }
            val probe = collector()
            val measured = assertFails { SourceTreeManifestReader.parse(record, profile, probe) }
            assertEquals(message, baseline.message)
            assertEquals(baseline.javaClass, measured.javaClass)
            assertEquals(baseline.message, measured.message)
            // snapshot refuses an active stage; every failed path must have been closed in finally.
            val snapshot = probe.snapshot(100)
            assertTrue(snapshot.getValue("measuredNanos").jsonPrimitive.long > 0)
        }
        // A constructor refusal in the first file precedes a field refusal in the second file.
        val files = root.getValue("files").jsonArray
        val badFiles = JsonArray(listOf(files[0].jsonObject.with("sha256", JsonPrimitive("bad")),
            files[1].jsonObject.with("extra", JsonNull)))
        for (probe in listOf(null, collector())) {
            assertEquals("source tree manifest file hash is invalid: include/modules/a.h",
                assertFails { SourceTreeManifestReader.parse(root.with("files", badFiles), profile, probe) }.message)
        }
    }

    @Test fun `throwing callbacks cannot become validation authority`() {
        val probe = object : SourceTreeManifestProbe {
            override fun start(stage: SourceTreeManifestStage) { error("broken diagnostic start") }
            override fun end() { throw AssertionError("broken diagnostic end") }
        }
        val root = document()
        assertValue(SourceTreeManifestReader.parse(root, profile), SourceTreeManifestReader.parse(root, profile, probe))
        val bad = root.with("schemaVersion", JsonPrimitive(2))
        val expected = assertFails { SourceTreeManifestReader.parse(bad, profile) }
        val actual = assertFails { SourceTreeManifestReader.parse(bad, profile, probe) }
        assertEquals(expected.javaClass, actual.javaClass)
        assertEquals(expected.message, actual.message)
    }

    @Test fun `diagnostic callbacks do not swallow interruption or cancellation`() {
        for (atEnd in listOf(false, true)) {
            for (failure in listOf(InterruptedException("diagnostic interrupt"),
                    java.util.concurrent.CancellationException("diagnostic cancellation"))) {
                val wasInterrupted = Thread.interrupted()
                try {
                    val probe = object : SourceTreeManifestProbe {
                        override fun start(stage: SourceTreeManifestStage) { if (!atEnd) throw failure }
                        override fun end() { if (atEnd) throw failure }
                    }
                    assertSame(failure, assertFails { SourceTreeManifestReader.parse(document(), profile, probe) })
                    if (failure is InterruptedException) assertTrue(Thread.currentThread().isInterrupted)
                } finally {
                    Thread.interrupted()
                    if (wasInterrupted) Thread.currentThread().interrupt()
                }
            }
        }
    }

    @Test fun `collector transitions accumulate exclusive intervals without double counting`() {
        var time = 0L
        var allocation = 0L
        val probe = ManifestAllocationCollector(LongSupplier { time }, LongSupplier { allocation })
        probe.start(SourceTreeManifestStage.ROOT)
        time = 10; allocation = 100
        probe.start(SourceTreeManifestStage.FILE_FIELDS)
        time = 30; allocation = 300
        probe.start(SourceTreeManifestStage.FILE_EVIDENCE_INIT)
        time = 60; allocation = 600
        probe.end()
        probe.end() // Outer finally must not count the already closed file stage again.
        time = 80; allocation = 800 // Unmeasured callback/bookkeeping gap.
        probe.start(SourceTreeManifestStage.FILE_FIELDS)
        time = 120; allocation = 1200
        probe.end()
        val snapshot = probe.snapshot(120)
        assertEquals(100L, snapshot.getValue("measuredNanos").jsonPrimitive.long)
        assertEquals(1000L, snapshot.getValue("measuredAllocatedBytes").jsonPrimitive.long)
        val fields = snapshot.getValue("stages").jsonObject.getValue("manifest-file-fields").jsonObject
        assertEquals(60L, fields.getValue("nanos").jsonPrimitive.long)
        assertEquals(600L, fields.getValue("allocatedBytes").jsonPrimitive.long)
        assertEquals(2, fields.getValue("segments").jsonPrimitive.int)
        probe.reset()
        assertEquals(0L, probe.snapshot(0).getValue("measuredNanos").jsonPrimitive.long)
    }

    @EnabledIfSystemProperty(named = "decompengine.structure.attributionFixture", matches = ".+")
    @Test fun `pinned manifest preserves all values and counts all 8338 files`() {
        val root = Path.of(System.getProperty("decompengine.structure.attributionFixture"))
        val manifest = root.resolve("${"f".repeat(32)}/reports/runs/run_structure_scale/source-tree/source_tree_manifest.json")
        val document = Json.parseToJsonElement(Files.readString(manifest)).jsonObject
        val baseline = SourceTreeManifestReader.parse(document, profile)
        val probe = collector()
        assertValue(baseline, SourceTreeManifestReader.parse(document, profile, probe))
        assertEquals(8338, baseline.files.size)
        val stages = probe.snapshot(100000).getValue("stages").jsonObject
        for (stage in listOf(SourceTreeManifestStage.FILE_FIELDS, SourceTreeManifestStage.FILE_EVIDENCE_INIT)) {
            assertEquals(8338, stages.getValue(stage.marker).jsonObject.getValue("segments").jsonPrimitive.int)
        }
    }
    @EnabledIfSystemProperty(named = "decompengine.structure.attributionFixture", matches = ".+")
    @Test fun `pinned seed preserves retained charges structure version and first inventory page`() {
        val seed = requireNotNull(System.getProperty("decompengine.structure.attributionFixture"))
        val output = Path.of(System.getProperty("decompengine.structure.attributionPageOutput"))
        WebJobService(decompengine.jobs.JobStore(Path.of(seed)), JobAnalyzer { _, _ -> error("No execution") },
            JobReconstructor { _, _ -> error("No execution") }).use { service ->
            service.initializeExistingStorage()
            val evidence = service.javaClass.getDeclaredField("sourceCatalogEvidence").also { it.isAccessible = true }
                .get(service) as WebSourceCatalogEvidence
            val method = service.javaClass.getDeclaredMethod("revisionSourceReference", String::class.java,
                String::class.java, String::class.java).also { it.isAccessible = true }
            val job = "f".repeat(32); val run = "run_structure_scale"; val revision = "revision_structure_scale"
            val ref = method.invoke(service, job, run, revision) as WebRevisionSourceReference
            val cache = WebProgramStructureCache()
            var charge: WebStructureRetention? = null
            var index: WebProgramStructureIndex? = null
            val pages = WebProgramStructurePages { _, _, _, project ->
                evidence.readStructureDiagnosed(ref, cache, { _, _ -> }, { charge = it }) { built, model ->
                    index = built
                    project(built, model)
                }
            }
            val first = pages.functions("owner", job, run, revision, "limit=100")
            val built = assertNotNull(index)
            assertEquals(1, built.collisions.size)
            assertEquals(83_217_618L, assertNotNull(charge).bytes)
            assertEquals(83_217_618L, built.retainedBytes)
            val retained = cache.candidates(WebProgramStructureCache.Prefix(job, run, revision, ref.sourceSha256, built.inputSha256)).single()
            assertEquals(87_028_741L, retained.retainedBytes)
            assertEquals("available", first.getValue("state").jsonPrimitive.content)
            assertEquals(100_000, first.getValue("totalFunctions").jsonPrimitive.int)
            val normalized = JsonObject(first + ("page" to JsonObject(first.getValue("page").jsonObject - "nextCursor")))
            val probe = collector()
            val measuredCache = WebProgramStructureCache()
            val measuredPages = WebProgramStructurePages { _, _, _, project ->
                evidence.readStructureDiagnosed(ref, measuredCache, null, null, probe) { measured, model ->
                    project(measured, model)
                }
            }
            val measured = measuredPages.functions("owner", job, run, revision, "limit=100")
            val normalizedMeasured = JsonObject(measured + ("page" to JsonObject(measured.getValue("page").jsonObject - "nextCursor")))
            assertEquals(normalized.toString(), normalizedMeasured.toString())
            assertEquals(8338, probe.snapshot(0).getValue("stages").jsonObject
                .getValue("manifest-file-fields").jsonObject.getValue("segments").jsonPrimitive.int)

            Files.writeString(output, normalized.toString())
            val baseline = Path.of(requireNotNull(System.getProperty("decompengine.structure.attributionPageBaseline")))
            assertEquals(Files.readString(baseline), normalized.toString())
            val paths = built.sourceFileIds.keys.toList()
            assertEquals(paths.withIndex().associate { (index, path) -> path to revisionSourceFileId(ref, index, path) },
                built.sourceFileIds)
            val seedPaths = Files.walk(Path.of(seed)).use { files ->
                files.filter { Files.isRegularFile(it) }.sorted().map { Path.of(seed).relativize(it).toString() }.toList()
            }
            assertEquals(8344, seedPaths.size)
            assertEquals(seedPaths.withIndex().associate { (index, path) -> path to revisionSourceFileId(ref, index, path) }
                .entries.toList(), revisionSourceFileIds(ref, seedPaths).entries.toList())
        }
    }

}

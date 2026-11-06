package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.project.*
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

/** Real pinned readers with deterministic growth/replacement hooks, not null body mocks. */
class WebSourceSearchReadBudgetTest {
    @Test fun `search limits grown and late-failing bodies to the admitted reservation including empty files`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/source-search-budget").toAbsolutePath())
        val root = createTempDirectory(parent, "pinned-")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("inert.elf", elfFixture())
            val run = "run_1"
            val source = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/$run/source-tree"))
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            // Five one-byte commitments formerly authorized 40 MiB while charging only five bytes.
            val bodies = linkedMapOf("Makefile" to byteArrayOf()).apply {
                repeat(5) { put("src/modules/u_$it.c", byteArrayOf('x'.code.toByte())) }
            }
            val files = bodies.map { (path, bytes) ->
                val declaration = profile.layout.declarationForPath(path)
                GeneratedFileEvidence(path, WebExplorationArtifact.sha256(bytes), "fixture",
                    acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) false else null,
                    roles = declaration.roles, contentKind = declaration.contentKind)
            }
            val commitment = files.joinToString("") { "${it.path.length}:${it.path}:${bodies.getValue(it.path).size}:${it.sha256}\n" }
            val reference = WebRevisionSourceReference(job.id, run, "revision_1", revisionSourceDigest(commitment), "version_1")
            Files.write(source.resolve("source_tree_manifest.json"), SourceTreeManifest(profileId = profile.id,
                profileSha256 = profile.sha256, inputSha256 = store.readInput(job.id).sha256,
                files = files, unresolvedEntityIds = emptyList()).toJson().toByteArray())
            val reports = Files.createDirectories(source.resolve("reports"))
            Files.writeString(reports.resolve("build_contract.json"), buildJsonObject {
                put("schemaVersion", 3); put("sourceRevisionSha256", reference.sourceSha256)
                put("sourceInputs", JsonArray(files.map { file -> buildJsonObject {
                    put("path", file.path); put("bytes", bodies.getValue(file.path).size); put("sha256", file.sha256)
                } }))
            }.toString())
            val evidence = WebSourceCatalogEvidence(listOf(profile), store::readInput, store::readArtifact)
            for (mode in listOf("valid", "oversized", "growth", "replacement", "valid")) {
                var authorizedWork = 0L
                var completedReads = 0
                val engine = WebRevisionSourceSearch({ _, _, _, scan ->
                    evidence.search(reference, { jobId, runId, path, maximum ->
                        val expected = bodies.getValue(path)
                        assertEquals(maxOf(1L, expected.size.toLong()), maximum)
                        authorizedWork += maximum + 1 // Includes the syscall overflow probe on a growing file.
                        val target = source.resolve(path)
                        Files.createDirectories(target.parent)
                        Files.write(target, expected)
                        when (mode) {
                            "oversized" -> {
                                java.io.RandomAccessFile(target.toFile(), "rw").use { it.setLength(8L * 1024 * 1024) }
                                store.readSourceInput(jobId, runId, path, maximum)
                            }
                            "growth", "replacement" -> readStableRegularFile(root,
                                "$jobId/reports/runs/$runId/source-tree/$path", maximum,
                                afterAuthorization = {
                                    if (mode == "growth") java.io.RandomAccessFile(target.toFile(), "rw").use {
                                        it.setLength(8L * 1024 * 1024)
                                    }
                                }, afterRead = {
                                    completedReads++
                                    // Keep the original inode alive so the new path cannot reuse it.
                                    Files.move(target, target.resolveSibling("${target.fileName}.old"))
                                    Files.write(target, expected)
                                })
                            else -> store.readSourceInput(jobId, runId, path, maximum)
                        }
                    }, scan)
                }, deadlineNanos = 60_000_000_000)
                val page = engine.search("owner", job.id, run, "revision_1", "q=absent")
                val progress = page.getValue("progress").jsonObject
                assertEquals("complete", page.getValue("status").jsonPrimitive.content)
                assertEquals(12L, authorizedWork)
                assertEquals(authorizedWork, progress.getValue("scannedBytes").jsonPrimitive.long)
                assertTrue(authorizedWork <= page.getValue("limits").jsonObject.getValue("maxScannedBytes").jsonPrimitive.long)
                val valid = mode == "valid"
                assertEquals(if (valid) 6 else 0, progress.getValue("scannedFiles").jsonPrimitive.int)
                assertEquals(if (valid) 0 else 6, progress.getValue("unavailableFiles").jsonPrimitive.int)
                assertEquals(if (mode == "replacement") 6 else 0, completedReads,
                    "growth must be refused before body completion; replacement must fail after the real read")
                evidence.readRevision(reference) // Both capture and search admissions were released.
            }
        } finally { root.toFile().deleteRecursively() }
    }
}

package decompengine.web

import decompengine.jobs.*
import decompengine.project.*
import decompengine.repair.StableComparison
import decompengine.repair.StableRegularFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.serialization.json.*
import kotlin.test.*

/** Real store/service reads only; no listener, workflow execution or compiler. */
class WebStructureStreamingStoreTest {
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private class Fixture(val root: Path, val store: JobStore, val job: String, val run: String, val revision: String,
        val manifest: Path, val descriptor: Path) {
        fun service() = WebJobService(store, JobAnalyzer { _, _ -> error("No execution") },
            JobReconstructor { _, _ -> error("No execution") }).also { it.initializeExistingStorage() }
        fun read(service: WebJobService) = service.readProgramStructure(job, run, revision) { index, _ -> index }
    }

    private fun withFixture(action: (Fixture) -> Unit) {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/536-cache-streaming/tmp")), "store-")
        try {
            val store = JobStore(root)
            val input = elfFixture()
            val job = store.createFromUpload("structure.elf", input)
            val attempt = WorkflowAttemptStore.open(root).use { owner ->
                val current = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                val queued = owner.create(job.id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u))).attempt
                owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
            }
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            val sources = sortedMapOf("Makefile" to "all:\n".toByteArray(), "include/decomp_types.h" to "// types\n".toByteArray())
            val sourceSha = sha(sources.entries.joinToString("") { (path, bytes) -> "${path.length}:$path:${bytes.size}:${sha(bytes)}\n" }.toByteArray())
            val revision = webSourceRevisionId(sourceSha)
            val records = sources + ("reports/program_model.json" to RecoveredProgramModel(2, sha(input),
                listOf(RecoveredFunction("fn_0000000000401000", "main", 0x401000u, "int main(void)", null)), emptyList(), emptyList()).toJson().toByteArray())
            val sourceRoot = Files.createDirectories(root.resolve("${job.id}/reports/runs/${attempt.runId}/source-tree"))
            for ((path, bytes) in records) Files.write(Files.createDirectories(sourceRoot.resolve(path).parent).resolve(Path.of(path).fileName), bytes)
            val manifest = Files.writeString(sourceRoot.resolve("source_tree_manifest.json"), SourceTreeManifest(
                profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = sha(input),
                files = records.map { (path, bytes) ->
                    val declaration = profile.layout.declarationForPath(path)
                    GeneratedFileEvidence(path, sha(bytes), "streaming-store-fixture", roles = declaration.roles, contentKind = declaration.contentKind)
                }, unresolvedEntityIds = emptyList()).toJson())
            val descriptor = Files.writeString(sourceRoot.resolve("reports/build_contract.json"), buildJsonObject {
                put("schemaVersion", 3); put("sourceRevisionSha256", sourceSha)
                put("sourceInputs", JsonArray(sources.map { (path, bytes) -> buildJsonObject {
                    put("path", path); put("bytes", bytes.size); put("sha256", sha(bytes))
                } }))
            }.toString())
            WorkflowAttemptStore.open(root).use { owner -> owner.transition(job.id, attempt.runId, attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate(revision, sourceSha))) }
            action(Fixture(root, store, job.id, attempt.runId, revision, manifest, descriptor))
        } finally { root.toFile().deleteRecursively() }
    }

    private fun field(target: Any, name: String) = target.javaClass.getDeclaredField(name).also { it.isAccessible = true }
    private class Counts(val events: MutableList<String>)
    private fun count(service: WebJobService): Counts {
        val evidence = field(service, "sourceCatalogEvidence").get(service)
        val events = mutableListOf<String>()
        @Suppress("UNCHECKED_CAST")
        val read = field(evidence, "readArtifact").get(evidence) as (String, String, Long) -> StableRegularFile
        @Suppress("UNCHECKED_CAST")
        val compare = field(evidence, "compareArtifact").get(evidence) as (String, String, Long, StableRegularFile) -> StableComparison
        field(evidence, "readArtifact").set(evidence, { job: String, path: String, max: Long ->
            events += "read:$path"; read(job, path, max)
        })
        field(evidence, "compareArtifact").set(evidence, { job: String, path: String, max: Long, expected: StableRegularFile ->
            events += "compare:$path"; compare(job, path, max, expected)
        })
        return Counts(events)
    }

    @Test fun `service streams hits and rebuilds stable edits and identical inode replacements`() = withFixture { fixture ->
        fixture.service().use { service ->
            val counts = count(service)
            val first = fixture.read(service)
            counts.events.clear()
            assertSame(first, fixture.read(service))
            assertEquals(2, counts.events.size)
            assertTrue(counts.events.all { it.startsWith("compare:") })
            Files.write(fixture.manifest, Files.readAllBytes(fixture.manifest) + byteArrayOf(10))
            val changed = fixture.read(service)
            assertNotEquals(first.structureVersion, changed.structureVersion)
            val replacement = Files.write(fixture.manifest.resolveSibling("replacement.json"), Files.readAllBytes(fixture.manifest))
            Files.move(replacement, fixture.manifest, StandardCopyOption.REPLACE_EXISTING)
            counts.events.clear()
            val rebound = fixture.read(service)
            assertNotSame(changed, rebound)
            assertEquals(changed.structureVersion, rebound.structureVersion)
            assertEquals(1, counts.events.count { it.startsWith("read:") && it.endsWith("/source_tree_manifest.json") })
            assertEquals(1, counts.events.count { it.startsWith("read:") && it.endsWith("/build_contract.json") })
            assertEquals(1, counts.events.count { it.startsWith("read:") && it.endsWith("/program_model.json") })
            counts.events.clear()
            assertSame(rebound, fixture.read(service))
            assertEquals(2, counts.events.size)
            assertTrue(counts.events.all { it.startsWith("compare:") })
        }
    }

    @Test fun `service preserves comparison interruption without fallback or clearing the flag`() = withFixture { fixture ->
        fixture.service().use { service ->
            fixture.read(service)
            val counts = count(service)
            val evidence = field(service, "sourceCatalogEvidence").get(service)
            for ((failure, interrupt) in listOf(InterruptedException("comparison interrupted") to false,
                java.util.concurrent.CancellationException("comparison cancelled") to false,
                JobStoreException("interrupted store read") to true)) {
                field(evidence, "compareArtifact").set(evidence, { _: String, _: String, _: Long, _: StableRegularFile ->
                    if (interrupt) Thread.currentThread().interrupt()
                    throw failure
                })
                try {
                    assertSame(failure, assertFails { fixture.read(service) })
                    assertEquals(interrupt, Thread.currentThread().isInterrupted)
                    assertTrue(counts.events.isEmpty(), "comparison exception must not trigger a fallback read")
                } finally { Thread.interrupted() }
            }
        }
    }

    @Test fun `warm unavailable linked and oversized metadata refuse exactly like cold reads without fallback`() {
        for (descriptor in listOf(false, true)) for (kind in listOf("missing", "hardlink", "symlink", "oversize")) {
            withFixture { fixture ->
                fixture.service().use { service ->
                    fixture.read(service)
                    val counts = count(service)
                    val path = if (descriptor) fixture.descriptor else fixture.manifest
                    val backup = path.resolveSibling("backup.json")
                    when (kind) {
                        "missing" -> Files.delete(path)
                        "hardlink" -> Files.createLink(backup, path)
                        "symlink" -> { Files.move(path, backup); Files.createSymbolicLink(path, backup.fileName) }
                        "oversize" -> java.io.RandomAccessFile(path.toFile(), "rw").use { it.setLength(WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES + 1) }
                    }
                    val warm = assertFailsWith<WebAccessDenied> { fixture.read(service) }
                    assertEquals(503, warm.status, "$descriptor $kind")
                    assertEquals("PROGRAM_STRUCTURE_UNAVAILABLE", warm.code)
                    assertEquals(if (descriptor) 2 else 1, counts.events.size)
                    assertTrue(counts.events.all { it.startsWith("compare:") })
                    field(service, "programStructureCache").set(service, WebProgramStructureCache())
                    val cold = assertFailsWith<WebAccessDenied> { fixture.read(service) }
                    assertEquals(warm.status, cold.status, "$descriptor $kind")
                    assertEquals(warm.code, cold.code, "$descriptor $kind")
                }
            }
        }
    }
}

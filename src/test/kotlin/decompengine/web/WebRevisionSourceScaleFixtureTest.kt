package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.WorkflowAttemptStore
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class WebRevisionSourceScaleFixtureTest {
    @Test fun `packaged source tree fixture is accepted by the real store catalog and revision readers at the D0 limit`() = withRoot { root ->
        val seeded = seed(root, "25000")
        assertEquals(25_000, seeded.fileCount)

        WorkflowAttemptStore.open(root).use { attempts ->
            val inspection = assertIs<decompengine.jobs.WorkflowJobInspection.Available>(attempts.inspect(seeded.jobId))
            val attempt = assertNotNull(inspection.snapshot.attempts.singleOrNull())
            assertEquals(decompengine.jobs.WorkflowKind.RECONSTRUCT, attempt.workflow)
            assertEquals(decompengine.jobs.WorkflowRunState.COMPLETED, attempt.state)
            assertEquals(seeded.revisionId, attempt.candidate?.revisionId)
            assertEquals(seeded.sourceSha256, attempt.candidate?.sourceSha256)
        }

        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> })
        try {
            service.initializeExistingStorage()
            val catalog = service.readSourceCatalog(seeded.jobId, seeded.runId)
            assertEquals(25_000, catalog.files.size)
            assertEquals("Makefile", catalog.files.first().path)
            assertEquals("src/modules/m_24998.c", catalog.files.last().path)

            val catalogPage = WebSourceCatalogPages(service::readSourceCatalog)
                .page("fixture-session", seeded.jobId, seeded.runId, "limit=200")
            assertEquals(25_000, catalogPage.getValue("totalFiles").jsonPrimitive.int)
            assertEquals(200, catalogPage.getValue("items").jsonArray.size)

            val revision = service.readRevisionSources(seeded.jobId, seeded.runId, seeded.revisionId)
            assertEquals(25_000, revision.files.size)
            assertEquals(seeded.sourceSha256, revision.reference.sourceSha256)
            val revisionPage = WebRevisionSourcePages(service::readRevisionSources)
                .page("fixture-session", seeded.jobId, seeded.runId, seeded.revisionId, "limit=200")
            assertEquals(25_000, revisionPage.getValue("totalFiles").jsonPrimitive.int)
            assertEquals(200, revisionPage.getValue("items").jsonArray.size)

            val sourceRoot = root.resolve(seeded.jobId).resolve("reports/runs/${seeded.runId}/source-tree")
            for (path in listOf("src/modules/m_00000.c", "src/modules/m_24998.c")) {
                val declared = revision.files.single { it.evidence.path == path }.evidence
                val bytes = Files.readAllBytes(sourceRoot.resolve(path))
                assertEquals(declared.sha256, sha256(bytes))
            }
        } finally { service.close() }
    }

    @Test fun `packaged source tree fixture above the D0 file ceiling is explicitly refused`() = withRoot { root ->
        val seeded = seed(root, "25001")
        assertEquals(25_001, seeded.fileCount)
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> })
        try {
            service.initializeExistingStorage()
            assertEquals("SOURCE_CATALOG_UNAVAILABLE", assertFailsWith<WebAccessDenied> {
                service.readSourceCatalog(seeded.jobId, seeded.runId)
            }.code)
            assertEquals("SOURCE_REVISION_UNAVAILABLE", assertFailsWith<WebAccessDenied> {
                service.readRevisionSources(seeded.jobId, seeded.runId, seeded.revisionId)
            }.code)
        } finally { service.close() }
    }

    private data class Seeded(val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String, val fileCount: Int)

    private fun seed(root: Path, count: String): Seeded {
        val script = Path.of("scripts/packaged-source-tree-fixture.mjs").toAbsolutePath()
        val process = ProcessBuilder("node", script.toString(), "--root", root.toString(), "--files", count)
            .directory(Path.of("").toAbsolutePath().toFile())
            .redirectErrorStream(true)
            .start()
        if (!process.waitFor(180, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Timed-out source fixture seeder did not terminate")
            error("Source fixture seeder exceeded three minutes")
        }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        assertEquals(0, process.exitValue(), output)
        val json = Json.parseToJsonElement(output.trim()).jsonObject
        return Seeded(
            json.getValue("jobId").jsonPrimitive.content,
            json.getValue("runId").jsonPrimitive.content,
            json.getValue("revisionId").jsonPrimitive.content,
            json.getValue("sourceSha256").jsonPrimitive.content,
            json.getValue("fileCount").jsonPrimitive.int,
        )
    }

    private fun withRoot(block: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/source-tree-scale").toAbsolutePath())
        val root = Files.createTempDirectory(parent, "fixture-")
        try { block(root) } finally { root.toFile().deleteRecursively() }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}

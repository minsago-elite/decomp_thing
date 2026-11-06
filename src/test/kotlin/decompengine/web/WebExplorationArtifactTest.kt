package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class WebExplorationArtifactTest {
    @Test fun `artifact identity is job run and byte bound and rejects replacement`() {
        val root = createTempDirectory("web-artifact-identity-")
        val store = JobStore(root)
        val first = store.createFromUpload("first.elf", elfFixture())
        val other = store.createFromUpload("other.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(first.id) as WorkflowJobInspection.Available).snapshot
            owner.create(first.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE,
                WorkflowExecutionLimits(1000u, 1000u, 1024u, 0u))).attempt
        }
        val report = Files.createDirectories(root.resolve(first.id).resolve("reports/runs/${run.runId}")).resolve("exploration.json")
        val bytes = "{\"private_fixture\":\"<script>inert</script>\"}".toByteArray()
        Files.write(report, bytes)
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("execution") }, JobReconstructor { _, _ -> error("execution") })
        try {
            service.initializeExistingStorage()
            val artifacts = WebJobArtifactStore(service)
            val descriptor = WebExplorationArtifact.descriptor(first.id, run.runId, bytes, "/nested/")
            val id = descriptor.getValue("artifactId").jsonPrimitive.content
            assertTrue(id.length <= 128)
            assertTrue(descriptor.getValue("contentHref").jsonPrimitive.content.startsWith("/nested/api/v1/jobs/${first.id}/artifacts/"))
            // The report descriptor and the general catalog name the same digest-bound artifact.
            val selection = resolveWebArtifact(artifacts, first.id, id)
            assertEquals(WebArtifactFamily.EXPLORATION, selection.family); assertEquals(run.runId, selection.attempt.runId)
            val catalog = WebArtifactCatalog(artifacts)
            assertEquals(descriptor.getValue("artifactId"), catalog.detail(first.id, id, "/nested/").getValue("artifactId"))
            val streamed = java.io.ByteArrayOutputStream()
            val digest = artifacts.stream(first.id, run.runId, selection.family.path, {}, { buffer, count -> streamed.write(buffer, 0, count) }, {})
            assertContentEquals(bytes, streamed.toByteArray()); assertEquals(selection.sha256, digest.sha256)
            assertFailsWith<WebAccessDenied> { resolveWebArtifact(artifacts, other.id, id) }
            assertFailsWith<WebAccessDenied> { resolveWebArtifact(artifacts, first.id, "../exploration.json") }
            Files.writeString(report, "replacement")
            assertEquals("ARTIFACT_CHANGED", assertFailsWith<WebAccessDenied> { catalog.detail(first.id, id, "/nested/") }.code)
        } finally { service.close(); root.toFile().deleteRecursively() }
    }
}

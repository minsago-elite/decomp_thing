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
            val descriptor = WebExplorationArtifact.descriptor(first.id, run.runId, bytes, "/nested/")
            val id = descriptor.getValue("artifactId").jsonPrimitive.content
            assertTrue(id.length <= 128)
            assertTrue(descriptor.getValue("contentHref").jsonPrimitive.content.startsWith("/nested/api/v1/jobs/${first.id}/artifacts/"))
            assertContentEquals(bytes, WebExplorationArtifact.read(service, first.id, id))
            assertFailsWith<WebAccessDenied> { WebExplorationArtifact.read(service, other.id, id) }
            assertFailsWith<WebAccessDenied> { WebExplorationArtifact.read(service, first.id, "../exploration.json") }
            Files.writeString(report, "replacement")
            assertEquals("ARTIFACT_CHANGED", assertFailsWith<WebJobServiceException> { WebExplorationArtifact.read(service, first.id, id) }.code)
        } finally { service.close(); root.toFile().deleteRecursively() }
    }
}

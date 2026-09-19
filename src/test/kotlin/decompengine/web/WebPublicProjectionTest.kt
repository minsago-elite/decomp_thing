package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.WorkflowStoreDiagnostic
import decompengine.jobs.elfFixture
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class WebPublicProjectionTest {
    @Test
    fun `legacy and v1 job projections and version exclude private persisted fields`() {
        val root = createTempDirectory("web-public-job-")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }).use { service ->
                service.initializeExistingStorage()
                val presentation = service.presentation(job.id)
                val firstPrivate = presentation.copy(job = presentation.job.copy(
                    binaryPath = Path.of("/PRIVATE_HOST_ROOT/ENV_SECRET/input.elf"),
                    statusMessage = "ENV_SECRET=private IllegalStateException(/PRIVATE_HOST_ROOT)",
                ))
                val secondPrivate = firstPrivate.copy(job = firstPrivate.job.copy(
                    binaryPath = Path.of("/ANOTHER_PRIVATE_ROOT/input.elf"),
                    statusMessage = "API_TOKEN=other raw exception details",
                ))

                val firstLegacy = legacyJobPresentation(firstPrivate.job)
                val secondLegacy = legacyJobPresentation(secondPrivate.job)
                val firstV1 = webJob(firstPrivate)
                val secondV1 = webJob(secondPrivate)
                assertEquals(firstLegacy, secondLegacy)
                assertEquals(firstV1, secondV1)
                assertEquals(firstV1.getValue("version"), secondV1.getValue("version"))
                for (wire in listOf(firstLegacy.toString(), firstV1.toString())) {
                    for (privateValue in listOf("binary_path", "status_message", "PRIVATE_HOST_ROOT", "ENV_SECRET", "IllegalStateException")) {
                        assertFalse(wire.contains(privateValue), privateValue)
                    }
                }

                val publicChange = webJob(firstPrivate.copy(job = firstPrivate.job.copy(filename = "changed.elf")))
                assertNotEquals(firstV1.getValue("version"), publicChange.getValue("version"))
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `unknown diagnostic codes and persisted messages collapse to a fixed public classification`() {
        val privateCode = "ENV_SECRET=/PRIVATE_HOST_ROOT IllegalStateException"
        val diagnostic = publicWebDiagnostic("job_fixture", privateCode)
        val workflow = publicWorkflowDiagnostic(privateCode)
        val persisted = WorkflowStoreDiagnostic("CORRUPT_WORKFLOW_STATE",
            "ENV_SECRET=private IllegalStateException(/PRIVATE_HOST_ROOT)")
        val projectedPersisted = publicWorkflowDiagnostic(persisted.code)

        assertEquals("JOB_STORAGE_UNAVAILABLE", diagnostic.code)
        assertEquals("JOB_STORAGE_UNAVAILABLE", workflow.code)
        assertEquals("Job storage is unavailable. Inspect storage before retrying.", diagnostic.message)
        assertEquals(diagnostic.message, workflow.message)
        assertFalse(diagnostic.toString().contains("PRIVATE"))
        assertFalse(workflow.toString().contains("ENV_SECRET"))
        assertEquals("CORRUPT_WORKFLOW_STATE", projectedPersisted.code)
        assertFalse(projectedPersisted.message.contains("ENV_SECRET"))
        assertFalse(projectedPersisted.message.contains("PRIVATE_HOST_ROOT"))
        assertEquals("CORRUPT_LEGACY_JOB", publicWebDiagnosticCode("CORRUPT_LEGACY_JOB"))
    }
}

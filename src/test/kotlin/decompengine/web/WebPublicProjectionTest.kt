package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowStoreDiagnostic
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
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

    @Test
    fun `every persisted ELF category rejects private prose before either job DTO is built`() {
        val root = createTempDirectory("web-public-elf-categories-")
        try {
            val job = JobStore(root).createFromUpload("fixture.elf", elfFixture())
            val private = "ENV_SECRET=/PRIVATE_HOST_ROOT IllegalStateException"
            val injected = listOf(
                job.metadata.copy(format = private),
                job.metadata.copy(endianness = private),
                job.metadata.copy(osAbi = private),
                job.metadata.copy(objectType = private),
                job.metadata.copy(machine = private),
            )
            for (metadata in injected) {
                val historical = job.copy(metadata = metadata)
                assertFailsWith<IllegalArgumentException> { legacyJobPresentation(historical) }
                assertFailsWith<IllegalArgumentException> { webJob(historical) }
                assertFailsWith<IllegalArgumentException> { renderJob(historical) }
            }
            val validLimits = job.copy(metadata = job.metadata.copy(
                osAbi = "unknown(255)", objectType = "unknown(65535)", machine = "unknown(65535)",
            ))
            val legacy = legacyJobPresentation(validLimits).getValue("metadata").jsonObject
            val versioned = webJob(validLimits).getValue("binary").jsonObject
            assertEquals("unknown(255)", legacy.getValue("os_abi").jsonPrimitive.content)
            assertEquals("unknown(65535)", legacy.getValue("object_type").jsonPrimitive.content)
            assertEquals("unknown(65535)", legacy.getValue("machine").jsonPrimitive.content)
            assertEquals("unknown(255)", versioned.getValue("osAbi").jsonPrimitive.content)
            assertEquals("unknown(65535)", versioned.getValue("objectType").jsonPrimitive.content)
            assertEquals("unknown(65535)", versioned.getValue("machine").jsonPrimitive.content)
            val validLow = job.copy(metadata = job.metadata.copy(
                osAbi = "unknown(1)", objectType = "unknown(0)", machine = "unknown(0)",
            ))
            legacyJobPresentation(validLow)
            webJob(validLow)
            for (metadata in listOf(
                job.metadata.copy(osAbi = "unknown(256)"), job.metadata.copy(osAbi = "unknown(0)"),
                job.metadata.copy(objectType = "unknown(65536)"), job.metadata.copy(objectType = "unknown(2)"),
                job.metadata.copy(machine = "unknown(65536)"), job.metadata.copy(machine = "unknown(62)"),
                job.metadata.copy(machine = "unknown(01)"),
            )) assertFailsWith<IllegalArgumentException> { webJob(job.copy(metadata = metadata)) }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `durable public version is an allowlisted opaque version and rejects stored prose`() {
        val root = createTempDirectory("web-public-version-")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            WorkflowAttemptStore.open(root).use { owner ->
                val initial = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                owner.create(job.id, initial.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u)))
            }
            WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }).use { service ->
                service.initializeExistingStorage()
                val public = service.presentation(job.id)
                val snapshot = checkNotNull(public.snapshot)
                val version = snapshot.version
                assertEquals(version, webJob(public).getValue("version").jsonPrimitive.content)
                val privateChange = public.copy(job = public.job.copy(
                    binaryPath = Path.of("/PRIVATE_HOST_ROOT/input.elf"),
                    statusMessage = "ENV_SECRET=private IllegalStateException",
                ))
                assertEquals(version, webJob(privateChange).getValue("version").jsonPrimitive.content)
                val unsafe = public.copy(snapshot = snapshot.copy(version = "ENV_SECRET=/PRIVATE_HOST_ROOT"))
                assertFailsWith<IllegalArgumentException> { webJob(unsafe) }
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}

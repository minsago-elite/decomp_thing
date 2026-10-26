package decompengine.web.packaged

import decompengine.jobs.JobStore
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.elfFixture
import decompengine.web.DurableWebWorkflowContext
import decompengine.web.DurableWebWorkflowOutcome
import decompengine.web.WebArchiveEvidence
import decompengine.web.WebSourceEvidence
import decompengine.web.defaultWebSourceProfiles
import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Keeps the packaged fake-engine lane's output a real verified source archive without a browser or JVM launch. */
class PackagedFakeEngineTest {
    private fun attempt(jobId: String, runId: String) = WorkflowAttempt(runId, jobId, WorkflowKind.RECONSTRUCT, WorkflowRunState.RUNNING,
        "version_fixture", Instant.EPOCH, Instant.EPOCH, null, null, null, null, PackagedFakeReconstruction.LIMITS, null, null, null, null)

    @Test
    fun `released fixture attempts publish a verified generated archive and disk-full attempts fail without one`() {
        val root = Files.createTempDirectory("packaged-fake-engine-")
        try {
            val store = JobStore(root.resolve("jobs"))
            val job = store.createFromUpload("fixture.elf", elfFixture())
            val control = Files.createDirectories(root.resolve("control"))
            val adapter = PackagedFakeReconstruction(control, emptyList())
            Files.writeString(control.resolve("run_fixture.step"), "3")
            val reports = store.runReportsDirectory(job.id, "run_fixture", create = true)
            val outcome = assertIs<DurableWebWorkflowOutcome.Completed>(adapter.execute(DurableWebWorkflowContext(job, attempt(job.id, "run_fixture"), reports)))
            val candidate = outcome.candidate!!
            assertTrue(candidate.revisionId.startsWith("revision_") && candidate.sourceSha256.matches(Regex("[a-f0-9]{64}")))
            val sources = WebSourceEvidence(store, defaultWebSourceProfiles(), store::readArtifact)
            val archive = WebArchiveEvidence(store, sources, store::readArtifact).read(job.id, reportPrefix = "reports/runs/run_fixture")
            assertEquals(archive.sha256, archive.bytes.let { bytes ->
                java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) } })
            assertTrue(Files.exists(control.resolve("run_fixture.completed")))

            Files.writeString(control.resolve("run_full.step"), "3")
            Files.writeString(control.resolve("run_full.enospc"), "")
            val full = store.runReportsDirectory(job.id, "run_full", create = true)
            assertFailsWith<java.io.IOException> { adapter.execute(DurableWebWorkflowContext(job, attempt(job.id, "run_full"), full)) }
            assertTrue(Files.exists(control.resolve("run_full.enospc")) && Files.notExists(full.resolve("source-tree.zip")))
        } finally {
            root.toFile().walkBottomUp().forEach { it.setWritable(true) }
            root.toFile().deleteRecursively()
        }
    }
}

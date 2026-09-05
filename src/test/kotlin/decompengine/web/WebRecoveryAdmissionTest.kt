package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.elfFixture
import java.nio.file.Files
import kotlin.io.path.*
import kotlin.test.*

class WebRecoveryAdmissionTest {
    @Test fun `incomplete startup recovery releases ownership and listener without changing statuses`() {
        val root = createTempDirectory("web-recovery-admission-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        val broken = root.resolve("a".repeat(32)).createDirectory()
        broken.resolve("job.json").writeText("private-invalid-record")
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        try {
            val failure = assertFailsWith<JobStoreException> { server.start() }
            assertEquals("Job recovery inspection is incomplete; no recovery statuses were changed", failure.message)
            assertEquals("analyzing", store.get(job.id).status)
            assertEquals("private-invalid-record", broken.resolve("job.json").readText())
        } finally { server.stop(0) }
        // Explicitly retain the invalid fixture outside the published-job namespace.
        Files.move(broken, root.resolve("retained-invalid"))
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            assertEquals("failed", store.get(job.id).status)
            assertEquals("private-invalid-record", root.resolve("retained-invalid/job.json").readText())
        } finally { replacement.stop(0) }
    }
}

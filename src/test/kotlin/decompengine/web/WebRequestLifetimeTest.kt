package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WebRequestLifetimeTest {
    @Test
    fun `an admitted handler retains ownership through its last write and exceptional exit`() {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-request-ownership").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "web-request-ownership-")
        val server = UploadServer("127.0.0.1", 0, root)
        server.start()
        val store = JobStore(root)
        val job = store.createFromUpload("benign.elf", elfFixture())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable>()
        val handler = Thread {
            try {
                server.withActiveRequest {
                    entered.countDown()
                    check(release.await(15, TimeUnit.SECONDS))
                    store.updateStatus(job.id, "complete", "Final admitted-handler write")
                    error("Fixture response failure")
                }
            } catch (problem: Throwable) {
                failure.set(problem)
            } finally {
                finished.countDown()
            }
        }
        handler.start()
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val stopped = assertFailsWith<IllegalStateException> { server.stop() }
            assertEquals("HTTP requests remain active after server stop", stopped.message)
            val refused = assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            assertEquals("Job store already has a live web server owner", refused.message)
            assertEquals("uploaded", store.get(job.id).status)
            assertFalse(server.withActiveRequest { error("late request must not run") })

            release.countDown()
            assertTrue(finished.await(5, TimeUnit.SECONDS))
            assertEquals("Fixture response failure", failure.get()?.message)
            val replacement = UploadServer("127.0.0.1", 0, root)
            try {
                replacement.start()
                assertEquals("complete", store.get(job.id).status)
                assertEquals("Final admitted-handler write", store.get(job.id).statusMessage)
                val metadata = root.resolve(job.id).resolve("job.json")
                val before = Files.readAllBytes(metadata)
                // A late cleanup retry from the old server must not release its replacement's lease.
                server.stop()
                assertFalse(server.withActiveRequest {
                    store.updateStatus(job.id, "failed", "Old owner must never publish this write")
                })
                assertContentEquals(before, Files.readAllBytes(metadata))
                val contender = assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
                assertEquals("Job store already has a live web server owner", contender.message)
                assertTrue(replacement.withActiveRequest { })
            } finally {
                replacement.stop()
            }
        } finally {
            release.countDown()
            handler.join(5000)
            server.stop()
            root.toFile().deleteRecursively()
        }
    }
}

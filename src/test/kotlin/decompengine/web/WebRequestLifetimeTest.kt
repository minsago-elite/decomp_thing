package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebRequestLifetimeTest {
    @Test
    fun `an admitted handler retains ownership through its last write and exceptional exit`() {
        val root = createTempDirectory("web-request-ownership-")
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
            val contender = UploadServer("127.0.0.1", 0, root)
            val refused = assertFailsWith<IllegalStateException> { contender.start() }
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
            } finally {
                replacement.stop()
            }
        } finally {
            release.countDown()
            handler.join(5000)
            server.stop()
        }
    }
}

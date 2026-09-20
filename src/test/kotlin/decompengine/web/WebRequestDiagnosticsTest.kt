package decompengine.web

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WebRequestDiagnosticsTest {
    @Test
    fun `diagnostic lines contain only generated IDs fixed status and allowlisted codes`() {
        val id = "123e4567-e89b-42d3-a456-426614174000"
        val lines = CopyOnWriteArrayList<String>()
        val first = CountDownLatch(1)
        recordWebRequestFailure(id, 401, "SESSION_REQUIRED") { lines += it; first.countDown() }
        assert(first.await(2, TimeUnit.SECONDS))
        assertEquals("web-http-failure request_id=$id status=401 code=SESSION_REQUIRED", lines.single())
        val second = CountDownLatch(1)
        recordWebRequestFailure(id, 503, "PRIVATE_PATH=/tmp/secret; TOKEN=canary") { lines += it; second.countDown() }
        assert(second.await(2, TimeUnit.SECONDS))
        assertEquals("web-http-failure request_id=$id status=503 code=UNCLASSIFIED", lines.last())
        assertFalse(lines.joinToString().contains("/tmp/secret"))
        assertFalse(lines.joinToString().contains("TOKEN"))
        recordWebRequestFailure("private_id=canary", 503, "INTERNAL_ERROR") { lines += it }
        assertEquals(2, lines.size)
        // A failed diagnostic sink cannot change the fixed public response path.
        recordWebRequestFailure(id, 500, "INTERNAL_ERROR") { throw IllegalStateException("log unavailable") }
    }
}

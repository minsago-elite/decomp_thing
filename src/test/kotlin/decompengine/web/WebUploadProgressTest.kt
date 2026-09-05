package decompengine.web

import kotlin.test.*

class WebUploadProgressTest {
    @Test fun `progress is session bound monotonic and only publication supplies a job identity`() {
        val progress = WebUploadProgress()
        val id = "a".repeat(32)
        val transfer = progress.begin("owner", id, null)
        transfer.received(64)
        assertEquals(64, progress.read("owner", id)?.receivedBytes)
        assertNull(progress.read("other", id))
        assertFailsWith<IllegalArgumentException> { transfer.received(63) }
        transfer.validating()
        assertEquals("validating", progress.read("owner", id)?.state)
        assertNull(progress.read("owner", id)?.jobId)
        transfer.finish("b".repeat(32)); transfer.finish()
        assertEquals("published", progress.read("owner", id)?.state)
        assertEquals("b".repeat(32), progress.read("owner", id)?.jobId)
        transfer.received(100)
        assertEquals(64, progress.read("owner", id)?.receivedBytes)
    }
    @Test fun `capacity never evicts active transfers and terminal observations expire`() {
        var now = 0L
        val progress = WebUploadProgress(1) { now }
        val id = "a".repeat(32)
        val transfer = progress.begin("owner", id, 100)
        assertEquals(409, assertFailsWith<WebAccessDenied> { progress.begin("owner", id, null) }.status)
        assertEquals(503, assertFailsWith<WebAccessDenied> { progress.begin("owner", "b".repeat(32), null) }.status)
        transfer.finish()
        assertEquals("unconfirmed", progress.read("owner", id)?.state)
        now = 120_000_000_000
        assertNull(progress.read("owner", id))
        progress.begin("owner", id, null)
    }
}

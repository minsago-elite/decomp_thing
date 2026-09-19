package decompengine.web

import java.nio.file.Path
import kotlin.test.*

class WebUploadStorageTest {
    private val unit = WebUploadStorage.RESERVATION_BYTES

    @Test fun `overlapping reservations share one scan and completed charges persist until quiescent`() {
        var scans = 0
        var retained = 0L
        val gate = WebUploadStorage(Path.of("unused"), 2 * unit, { scans++; retained }, { Long.MAX_VALUE })
        val first = gate.reserve()
        val second = gate.reserve()
        assertEquals(1, scans)
        first.close()
        first.close()
        assertEquals("UPLOAD_STORAGE", assertFailsWith<WebJobServiceException> { gate.reserve() }.code)
        retained = unit
        second.close()
        gate.reserve().use { assertEquals(2, scans) }
    }

    @Test fun `retained bytes and free capacity each independently deny before reservation`() {
        val full = WebUploadStorage(Path.of("unused"), unit, { 1 }, { Long.MAX_VALUE })
        assertFailsWith<WebJobServiceException> { full.reserve() }
        var free = WebUploadStorage.FREE_HEADROOM_BYTES + unit - 1
        val gate = WebUploadStorage(Path.of("unused"), 2 * unit, { 0 }, { free })
        assertFailsWith<WebJobServiceException> { gate.reserve() }
        free++
        gate.reserve().use {
            assertFailsWith<WebJobServiceException> { gate.reserve() }
        }
        gate.reserve().close()
    }

    @Test fun `failed accounting is not cached and errors do not expose private diagnostics`() {
        var fails = true
        val gate = WebUploadStorage(Path.of("unused"), unit, { if (fails) error("private path") else 0 }, { Long.MAX_VALUE })
        val failure = assertFailsWith<WebJobServiceException> { gate.reserve() }
        assertFalse(failure.message.orEmpty().contains("private path"))
        fails = false
        gate.reserve().close()
    }
}

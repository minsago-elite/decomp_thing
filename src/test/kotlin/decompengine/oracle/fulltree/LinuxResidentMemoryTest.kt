package decompengine.oracle.fulltree

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LinuxResidentMemoryTest {
    @Test
    fun `self sample exposes positive monotonic Linux resident counters`() {
        val sample = LinuxResidentMemory.sampleSelf()
        assertTrue(sample.currentBytes > 0L)
        assertTrue(sample.highWaterBytes >= sample.currentBytes)
    }

    @Test
    fun `resident parser accepts exact kernel units and rejects substitutions`() {
        assertEquals(12_345L * 1024L, LinuxResidentMemory.parseKibibytes("VmHWM:\t12345 kB", "VmHWM"))
        assertFailsWith<IllegalStateException> {
            LinuxResidentMemory.parseKibibytes("VmHWM:\t12345 MB", "VmHWM")
        }
        assertFailsWith<IllegalStateException> {
            LinuxResidentMemory.parseKibibytes("VmHWM:\t-1 kB", "VmHWM")
        }
    }
}

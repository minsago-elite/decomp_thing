package decompengine.exploration

import java.io.IOException
import kotlin.test.*

/** In-memory interrupt-state model only; never alter a thread or open a file/controller. */
class ExplorationFailureRetentionTest {
    @Test fun `bounded retention restores prior interrupts and preserves interrupts arriving during retention`() {
        for (prior in listOf(false, true)) for (arriving in listOf(false, true)) {
            var pending = prior; var takes = 0; var restores = 0; var writes = 0
            val original = InterruptedException("private")
            assertSame(original, assertFailsWith<InterruptedException> {
                retainExplorationFailure(original,
                    takeInterrupt = { takes++; pending.also { pending = false } },
                    restoreInterrupt = { restores++; pending = true },
                    retain = { assertFalse(pending); writes++; if (arriving) pending = true })
            })
            assertEquals(prior || arriving, pending)
            assertEquals(1, takes); assertEquals(if (prior) 1 else 0, restores); assertEquals(1, writes)
        }
    }

    @Test fun `failed retention restores interrupted state and suppresses only a distinct error once`() {
        for (same in listOf(false, true)) {
            var pending = true; var writes = 0; var restores = 0
            val original = IOException("original")
            val retention = if (same) original else IOException("retention")
            assertSame(original, assertFailsWith<IOException> {
                retainExplorationFailure(original,
                    takeInterrupt = { pending.also { pending = false } },
                    restoreInterrupt = { restores++; pending = true },
                    retain = { writes++; assertFalse(pending); throw retention })
            })
            assertTrue(pending); assertEquals(1, writes); assertEquals(1, restores)
            assertEquals(if (same) emptyList() else listOf(retention), original.suppressed.toList())
        }
    }
}

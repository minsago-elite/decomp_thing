package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class StableControlFileCheckpointTest {
    @Test
    fun `initial and terminal authentication deliver bounded read checkpoints`() = inControlTemporaryDirectory { root ->
        val bytes = ByteArray(1024 * 1024 + 17) { index -> index.toByte() }
        val input = root.resolve("authored-control.bin")
        writeAuthoredFile(input, bytes)
        val checkpoints = mutableListOf<String>()
        val label = "authored control"

        StableControlFile.openWithCheckpoint(input, bytes.size.toLong(), label) { checkpoints += it }.use { file ->
            assertEquals(OracleArtifacts.sha256(bytes), file.authenticatedSha256)
            assertContentEquals(bytes, file.readExactly(0, bytes.size, label))
            file.verifyUnchanged(label)
        }

        assertEquals(
            listOf(
                "before $label initial authentication",
                "while hashing $label initial authentication",
                "while hashing $label initial authentication",
                "after hashing $label initial authentication",
                "before $label terminal authentication",
                "while hashing $label terminal authentication",
                "while hashing $label terminal authentication",
                "after hashing $label terminal authentication",
            ),
            checkpoints,
        )
    }

    @Test
    fun `initial checkpoint failures preserve their cause and allow ordinary reopening`() = inControlTemporaryDirectory { root ->
        val bytes = "Authored ordinary control input\n".toByteArray()
        val input = root.resolve("initial-control.txt")
        writeAuthoredFile(input, bytes)
        val label = "initial control"
        val stages = listOf(
            "before $label initial authentication",
            "while hashing $label initial authentication",
            "after hashing $label initial authentication",
        )
        for ((index, stopAt) in stages.withIndex()) {
            val checkpoints = mutableListOf<String>()
            val stopped = IllegalStateException("authored checkpoint failure")

            val failure = assertFailsWith<FullTreeControlException> {
                StableControlFile.openWithCheckpoint(input, bytes.size.toLong(), label) { checkpoint ->
                    checkpoints += checkpoint
                    if (checkpoint == stopAt) throw stopped
                }.close()
            }

            assertSame(stopped, failure.cause)
            assertEquals(stages.take(index + 1), checkpoints)
            val observed = checkpoints.toList()
            StableControlFile.open(input, bytes.size.toLong(), label).use { file ->
                assertContentEquals(bytes, file.readExactly(0, bytes.size, label))
                file.verifyUnchanged(label)
            }
            assertEquals(observed, checkpoints)
        }
    }

    @Test
    fun `terminal checkpoint cancellation closes the handle without cleanup callbacks`() = inControlTemporaryDirectory { root ->
        val bytes = "Authored terminal control input\n".toByteArray()
        val input = root.resolve("terminal-control.txt")
        writeAuthoredFile(input, bytes)
        val label = "terminal control"
        val checkpoints = mutableListOf<String>()
        val cancelled = CancellationException("authored checkpoint cancellation")
        val file = StableControlFile.openWithCheckpoint(input, bytes.size.toLong(), label) { checkpoint ->
            checkpoints += checkpoint
            if (checkpoint == "while hashing $label terminal authentication") throw cancelled
        }

        val failure = assertFailsWith<CancellationException> {
            file.use { it.verifyUnchanged(label) }
        }

        assertSame(cancelled, failure)
        assertEquals(
            listOf(
                "before $label initial authentication",
                "while hashing $label initial authentication",
                "after hashing $label initial authentication",
                "before $label terminal authentication",
                "while hashing $label terminal authentication",
            ),
            checkpoints,
        )
        val observed = checkpoints.toList()
        file.close()
        assertEquals(observed, checkpoints)
        assertFailsWith<IllegalStateException> { file.authenticatedSha256 }
        StableControlFile.open(input, bytes.size.toLong(), label).use { reopened ->
            assertContentEquals(bytes, reopened.readExactly(0, bytes.size, label))
            reopened.verifyUnchanged(label)
        }
        assertEquals(observed, checkpoints)
    }

    private fun writeAuthoredFile(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    }
}

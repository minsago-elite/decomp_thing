package decompengine.jobs

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JobMetadataPublicationTest {
    @Test fun `failure before write preserves prior metadata`() = verify(Fault.BEFORE_WRITE)
    @Test fun `partial private write preserves prior metadata`() = verify(Fault.PARTIAL_WRITE)
    @Test fun `unforced private write preserves prior metadata`() = verify(Fault.BEFORE_FILE_FORCE)
    @Test fun `forced private write preserves prior metadata`() = verify(Fault.AFTER_FILE_FORCE)
    @Test fun `failure before replacement preserves prior metadata`() = verify(Fault.BEFORE_REPLACE)
    @Test fun `failure after replacement retains complete new metadata`() = verify(Fault.AFTER_REPLACE)
    @Test fun `failure before directory force retains complete new metadata`() = verify(Fault.BEFORE_DIRECTORY_FORCE)
    @Test fun `failure after directory force retains complete new metadata`() = verify(Fault.AFTER_DIRECTORY_FORCE)

    private fun verify(fault: Fault) {
        val root = createTempDirectory("job-metadata-fault-")
        val initial = JobStore(root).createFromUpload("benign.elf", elfFixture())
        val record = root.resolve(initial.id).resolve("job.json")
        val priorBytes = record.readBytes()
        fun fail(): Nothing = throw IOException("injected $fault")
        val publisher = object : JobMetadataPublisher {
            override fun writeAndForce(temporary: Path, bytes: ByteArray) {
                when (fault) {
                    Fault.BEFORE_WRITE -> fail()
                    Fault.PARTIAL_WRITE -> {
                        Files.write(temporary, bytes.copyOf(bytes.size / 2))
                        fail()
                    }
                    Fault.BEFORE_FILE_FORCE -> {
                        Files.write(temporary, bytes)
                        fail()
                    }
                    else -> Unit
                }
                AtomicJobMetadataPublisher.writeAndForce(temporary, bytes)
                if (fault == Fault.AFTER_FILE_FORCE) fail()
            }

            override fun replace(temporary: Path, destination: Path) {
                if (fault == Fault.BEFORE_REPLACE) fail()
                AtomicJobMetadataPublisher.replace(temporary, destination)
                if (fault == Fault.AFTER_REPLACE) fail()
            }

            override fun confirmDirectory(directory: Path) {
                if (fault == Fault.BEFORE_DIRECTORY_FORCE) fail()
                AtomicJobMetadataPublisher.confirmDirectory(directory)
                if (fault == Fault.AFTER_DIRECTORY_FORCE) fail()
            }
        }
        val store = JobStore(root, AtomicUploadPublisher, publisher)
        val failure = assertFailsWith<IOException> { store.updateStatus(initial.id, "analyzing", "new metadata") }
        assertEquals("injected $fault", failure.message)
        val recovered = JobStore(root).get(initial.id)
        if (fault in setOf(Fault.AFTER_REPLACE, Fault.BEFORE_DIRECTORY_FORCE, Fault.AFTER_DIRECTORY_FORCE)) {
            assertEquals("analyzing", recovered.status)
            assertEquals("new metadata", recovered.statusMessage)
        } else {
            assertEquals(initial, recovered)
            assertContentEquals(priorBytes, record.readBytes())
        }
        assertContentEquals(elfFixture(), recovered.binaryPath.readBytes())
        Files.list(record.parent).use { entries ->
            assertTrue(entries.noneMatch { it.fileName.toString().startsWith(".job-metadata-") })
        }
    }

    private enum class Fault {
        BEFORE_WRITE, PARTIAL_WRITE, BEFORE_FILE_FORCE, AFTER_FILE_FORCE,
        BEFORE_REPLACE, AFTER_REPLACE, BEFORE_DIRECTORY_FORCE, AFTER_DIRECTORY_FORCE,
    }
}

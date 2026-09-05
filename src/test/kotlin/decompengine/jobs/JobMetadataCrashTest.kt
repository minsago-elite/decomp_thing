package decompengine.jobs

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JobMetadataCrashTest {
    @Test fun `death before metadata write preserves the old record`() = verify(MetadataCrashPoint.BEFORE_WRITE)
    @Test fun `death after partial metadata write preserves the old record`() = verify(MetadataCrashPoint.PARTIAL_WRITE)
    @Test fun `death before file force preserves the old record`() = verify(MetadataCrashPoint.BEFORE_FILE_FORCE)
    @Test fun `death after file force preserves the old record`() = verify(MetadataCrashPoint.AFTER_FILE_FORCE)
    @Test fun `death before replacement preserves the old record`() = verify(MetadataCrashPoint.BEFORE_REPLACE)
    @Test fun `death after replacement preserves the new record`() = verify(MetadataCrashPoint.AFTER_REPLACE)
    @Test fun `death before directory force preserves the new record`() = verify(MetadataCrashPoint.BEFORE_DIRECTORY_FORCE)
    @Test fun `death after directory force preserves the new record`() = verify(MetadataCrashPoint.AFTER_DIRECTORY_FORCE)

    private fun verify(point: MetadataCrashPoint) {
        val root = createTempDirectory("job-metadata-crash-")
        val jobs = root.resolve("jobs")
        val initial = JobStore(jobs).createFromUpload("benign.elf", elfFixture())
        val record = jobs.resolve(initial.id).resolve("job.json")
        val previous = record.readBytes()
        val log = root.resolve("child.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            JobMetadataCrashFixture::class.java.name, root.toString(), initial.id, point.name,
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "child JVM did not terminate at $point")
            assertEquals(86, process.exitValue(), log.readText())
            assertEquals(point.name, root.resolve("crash-point").readText())
            assertFalse(root.resolve("finally-ran").exists())
            val store = JobStore(jobs)
            val recovered = store.get(initial.id)
            if (point.published) {
                assertEquals("analyzing", recovered.status)
                assertEquals("crash candidate", recovered.statusMessage)
            } else {
                assertEquals(initial, recovered)
                assertContentEquals(previous, record.readBytes())
            }
            assertContentEquals(elfFixture(), recovered.binaryPath.readBytes())
            val remnants = Files.list(record.parent).use { entries ->
                entries.filter { it.fileName.toString().startsWith(".job-metadata-") }.toList()
            }
            assertEquals(if (point.published) 0 else 1, remnants.size)
            assertEquals(listOf(initial.id), store.list().map { it.id })
            store.recoverInterruptedJobs()
            assertEquals(if (point.published) "failed" else "uploaded", store.get(initial.id).status)
            // Recovery must not promote a private candidate or claim it was safely reclaimed.
            remnants.forEach { assertTrue(it.exists()) }
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

internal enum class MetadataCrashPoint(val published: Boolean = false) {
    BEFORE_WRITE, PARTIAL_WRITE, BEFORE_FILE_FORCE, AFTER_FILE_FORCE, BEFORE_REPLACE,
    AFTER_REPLACE(true), BEFORE_DIRECTORY_FORCE(true), AFTER_DIRECTORY_FORCE(true),
}

/** Test-only abrupt exit; never included in the production application. */
object JobMetadataCrashFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args[0])
        val point = MetadataCrashPoint.valueOf(args[2])
        fun crash(): Nothing {
            Files.writeString(root.resolve("crash-point"), point.name)
            Runtime.getRuntime().halt(86)
            error("halt returned")
        }
        val publisher = object : JobMetadataPublisher {
            override fun writeAndForce(temporary: Path, bytes: ByteArray) {
                when (point) {
                    MetadataCrashPoint.BEFORE_WRITE -> crash()
                    MetadataCrashPoint.PARTIAL_WRITE -> {
                        Files.write(temporary, bytes.copyOf(bytes.size / 2))
                        crash()
                    }
                    MetadataCrashPoint.BEFORE_FILE_FORCE -> {
                        Files.write(temporary, bytes)
                        crash()
                    }
                    else -> Unit
                }
                AtomicJobMetadataPublisher.writeAndForce(temporary, bytes)
                if (point == MetadataCrashPoint.AFTER_FILE_FORCE) crash()
            }

            override fun replace(temporary: Path, destination: Path) {
                if (point == MetadataCrashPoint.BEFORE_REPLACE) crash()
                AtomicJobMetadataPublisher.replace(temporary, destination)
                if (point == MetadataCrashPoint.AFTER_REPLACE) crash()
            }

            override fun confirmDirectory(directory: Path) {
                if (point == MetadataCrashPoint.BEFORE_DIRECTORY_FORCE) crash()
                AtomicJobMetadataPublisher.confirmDirectory(directory)
                if (point == MetadataCrashPoint.AFTER_DIRECTORY_FORCE) crash()
            }
        }
        try {
            JobStore(root.resolve("jobs"), AtomicUploadPublisher, publisher)
                .updateStatus(args[1], "analyzing", "crash candidate")
            error("crash point was not reached")
        } finally {
            Files.writeString(root.resolve("finally-ran"), "unexpected cleanup")
        }
    }
}

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

class JobUploadCrashTest {
    @Test fun `death before input write keeps the upload private`() = verify(UploadCrashPoint.BEFORE_INPUT_WRITE)
    @Test fun `death after partial input keeps the upload private`() = verify(UploadCrashPoint.PARTIAL_INPUT_WRITE)
    @Test fun `death before input force keeps the upload private`() = verify(UploadCrashPoint.BEFORE_INPUT_FORCE)
    @Test fun `death after input force keeps the upload private`() = verify(UploadCrashPoint.AFTER_INPUT_FORCE)
    @Test fun `death before metadata write keeps the upload private`() = verify(UploadCrashPoint.BEFORE_METADATA_WRITE)
    @Test fun `death after partial metadata keeps the upload private`() = verify(UploadCrashPoint.PARTIAL_METADATA_WRITE)
    @Test fun `death after metadata force keeps the upload private`() = verify(UploadCrashPoint.AFTER_METADATA_FORCE)
    @Test fun `death after metadata replacement keeps the upload private`() = verify(UploadCrashPoint.AFTER_METADATA_REPLACE)
    @Test fun `death before stage force keeps the upload private`() = verify(UploadCrashPoint.BEFORE_STAGE_FORCE)
    @Test fun `death after stage force keeps the upload private`() = verify(UploadCrashPoint.AFTER_STAGE_FORCE)
    @Test fun `death before upload rename keeps the upload private`() = verify(UploadCrashPoint.BEFORE_UPLOAD_RENAME)
    @Test fun `death after upload rename leaves a complete job`() = verify(UploadCrashPoint.AFTER_UPLOAD_RENAME)
    @Test fun `death before store force leaves a complete job`() = verify(UploadCrashPoint.BEFORE_STORE_FORCE)
    @Test fun `death after store force leaves a complete job`() = verify(UploadCrashPoint.AFTER_STORE_FORCE)

    private fun verify(point: UploadCrashPoint) {
        val root = createTempDirectory("job-upload-crash-")
        val jobs = root.resolve("jobs")
        val existing = JobStore(jobs).createFromUpload("existing.elf", elfFixture())
        val log = root.resolve("child.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            JobUploadCrashFixture::class.java.name, root.toString(), point.name,
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "child did not terminate at $point")
            assertEquals(87, process.exitValue(), log.readText())
            assertEquals(point.name, root.resolve("crash-point").readText())
            assertFalse(root.resolve("finally-ran").exists())
            val store = JobStore(jobs)
            assertEquals(existing, store.get(existing.id))
            val published = store.list().filter { it.id != existing.id }
            assertEquals(if (point.published) 1 else 0, published.size)
            published.forEach { job ->
                assertEquals("uploaded", job.status)
                assertEquals("candidate.elf", job.filename)
                assertEquals(existing.metadata, job.metadata)
                assertEquals(elfFixture().size, job.sizeBytes)
                assertContentEquals(elfFixture(), job.binaryPath.readBytes())
                assertTrue(Files.isExecutable(job.binaryPath))
            }
            val stages = Files.list(jobs).use { entries ->
                entries.filter { it.fileName.toString().startsWith(".upload-") }.toList()
            }
            assertEquals(if (point.published) 0 else 1, stages.size)
            store.recoverInterruptedJobs()
            assertEquals((published.map { it.id } + existing.id).toSet(), store.list().map { it.id }.toSet())
            assertEquals(existing, store.get(existing.id))
            stages.forEach { assertTrue(it.exists()) }
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

internal enum class UploadCrashPoint(val published: Boolean = false) {
    BEFORE_INPUT_WRITE, PARTIAL_INPUT_WRITE, BEFORE_INPUT_FORCE, AFTER_INPUT_FORCE,
    BEFORE_METADATA_WRITE, PARTIAL_METADATA_WRITE, AFTER_METADATA_FORCE, AFTER_METADATA_REPLACE,
    BEFORE_STAGE_FORCE, AFTER_STAGE_FORCE, BEFORE_UPLOAD_RENAME,
    AFTER_UPLOAD_RENAME(true), BEFORE_STORE_FORCE(true), AFTER_STORE_FORCE(true),
}

/** Benign test-only publication crashes; never linked into the production application. */
object JobUploadCrashFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args[0])
        val point = UploadCrashPoint.valueOf(args[1])
        fun crash(): Nothing {
            Files.writeString(root.resolve("crash-point"), point.name)
            Runtime.getRuntime().halt(87)
            error("halt returned")
        }
        val upload = object : UploadPublisher {
            override fun writeAndForceInput(input: Path, bytes: ByteArray) {
                when (point) {
                    UploadCrashPoint.BEFORE_INPUT_WRITE -> crash()
                    UploadCrashPoint.PARTIAL_INPUT_WRITE -> {
                        Files.write(input, bytes.copyOf(bytes.size / 2))
                        crash()
                    }
                    UploadCrashPoint.BEFORE_INPUT_FORCE -> {
                        Files.write(input, bytes)
                        crash()
                    }
                    else -> Unit
                }
                AtomicUploadPublisher.writeAndForceInput(input, bytes)
                if (point == UploadCrashPoint.AFTER_INPUT_FORCE) crash()
            }

            override fun publish(staging: Path, destination: Path) {
                if (point == UploadCrashPoint.BEFORE_UPLOAD_RENAME) crash()
                AtomicUploadPublisher.publish(staging, destination)
                if (point == UploadCrashPoint.AFTER_UPLOAD_RENAME) crash()
            }

            override fun confirmDirectory(root: Path) {
                if (point == UploadCrashPoint.BEFORE_STORE_FORCE) crash()
                AtomicUploadPublisher.confirmDirectory(root)
                if (point == UploadCrashPoint.AFTER_STORE_FORCE) crash()
            }
        }
        val metadata = object : JobMetadataPublisher {
            override fun writeAndForce(temporary: Path, bytes: ByteArray) {
                if (point == UploadCrashPoint.BEFORE_METADATA_WRITE) crash()
                if (point == UploadCrashPoint.PARTIAL_METADATA_WRITE) {
                    Files.write(temporary, bytes.copyOf(bytes.size / 2))
                    crash()
                }
                AtomicJobMetadataPublisher.writeAndForce(temporary, bytes)
                if (point == UploadCrashPoint.AFTER_METADATA_FORCE) crash()
            }

            override fun replace(temporary: Path, destination: Path) {
                AtomicJobMetadataPublisher.replace(temporary, destination)
                if (point == UploadCrashPoint.AFTER_METADATA_REPLACE) crash()
            }

            override fun confirmDirectory(directory: Path) {
                if (point == UploadCrashPoint.BEFORE_STAGE_FORCE) crash()
                AtomicJobMetadataPublisher.confirmDirectory(directory)
                if (point == UploadCrashPoint.AFTER_STAGE_FORCE) crash()
            }
        }
        try {
            JobStore(root.resolve("jobs"), upload, metadata).createFromUpload("candidate.elf", elfFixture())
            error("crash point was not reached")
        } finally {
            Files.writeString(root.resolve("finally-ran"), "unexpected cleanup")
        }
    }
}

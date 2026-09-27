package decompengine.jobs

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JobStoreDirectoriesCrashTest {
    @Test fun `death before first directory force leaves no upload`() = verify("BEFORE_FIRST_FORCE")
    @Test fun `death after store force leaves no upload`() = verify("AFTER_FIRST_FORCE")
    @Test fun `death after parent force leaves no upload`() = verify("AFTER_PARENT_FORCE")
    @Test fun `death after all ancestor forces leaves no upload`() = verify("AFTER_ALL_FORCE")

    private fun verify(point: String) {
        val root = createTempDirectory("job-directory-crash-")
        val jobs = root.resolve("new/nested/jobs")
        assertFalse(jobs.exists())
        runChild(root, point, 88)
        assertEquals(point, root.resolve("crash-point").readText())
        assertFalse(root.resolve("finally-$point").exists())
        assertTrue(jobs.exists())
        Files.list(jobs).use { assertEquals(0L, it.count()) }
        assertTrue(JobStore(jobs).list().isEmpty())
        assertEquals(JobRecoveryInventory(0, 0, 0, 0, 0, true), JobStore(jobs).recoveryInventory())

        // A new JVM must confirm even the directories left by the previous process.
        runChild(root, "RESUME", 0)
        assertTrue(root.resolve("finally-RESUME").exists())
        val expected = generateSequence(jobs.toRealPath()) { it.parent }.map { it.toString() }.toList()
        assertEquals(expected, root.resolve("confirmed").readLines())
        val store = JobStore(jobs)
        val job = store.get(root.resolve("published-id").readText())
        assertEquals(listOf(job), store.list())
        assertEquals("uploaded", job.status)
        assertContentEquals(elfFixture(), job.binaryPath.readBytes())
        assertEquals(0, store.recoveryInventory().retainedUploadStages)
    }

    private fun runChild(root: Path, mode: String, exit: Int) {
        val log = root.resolve("child-$mode.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            JobStoreDirectoriesCrashFixture::class.java.name, root.toString(), mode,
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "directory fixture did not terminate: $mode")
            assertEquals(exit, process.exitValue(), log.readText())
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

/** Benign test-only directory preparation and publication; never executes uploaded code. */
object JobStoreDirectoriesCrashFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args[0])
        val mode = args[1]
        fun crash(): Nothing {
            Files.writeString(root.resolve("crash-point"), mode)
            Runtime.getRuntime().halt(88)
            error("halt returned")
        }
        val directories = JobStoreDirectories { store ->
            val confirmed = mutableListOf<String>()
            prepareJobStoreDirectories(store) { directory ->
                if (mode == "BEFORE_FIRST_FORCE" && confirmed.isEmpty()) crash()
                forceJobStoreDirectory(directory)
                confirmed.add(directory.toString())
                if (mode == "AFTER_FIRST_FORCE" && confirmed.size == 1) crash()
                if (mode == "AFTER_PARENT_FORCE" && confirmed.size == 2) crash()
            }
            if (mode == "AFTER_ALL_FORCE") crash()
            check(mode == "RESUME")
            Files.write(root.resolve("confirmed"), confirmed)
        }
        try {
            val job = JobStore(root.resolve("new/nested/jobs"), AtomicUploadPublisher, storeDirectories = directories)
                .createFromUpload("benign.elf", elfFixture())
            Files.writeString(root.resolve("published-id"), job.id)
        } finally {
            Files.writeString(root.resolve("finally-$mode"), "ordinary exit")
        }
    }
}

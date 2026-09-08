package decompengine.jobs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.*

class UploadStagingRecoveryTest {
    @Test fun `cleanup removes only private staging and leaves published jobs and unrelated hidden entries`() = withRoot { root ->
        val job = StagedJobUpload(root).publish { it.write(elfFixture()); "inert.elf" }.job
        Files.createDirectory(root.resolve(".unrelated"))
        val stage = stage(root, ".upload-stream-v1-123")
        stage.resolve("input.elf").writeText("partial upload")
        stage.resolve("job.json").writeText("incomplete metadata")
        WorkflowAttemptStore.open(root).use { assertEquals(1, UploadStagingRecovery.recover(root)) }
        assertEquals(job, JobStore(root).get(job.id))
        assertTrue(Files.isDirectory(root.resolve(".unrelated")))
        assertFalse(Files.exists(stage))
        WorkflowAttemptStore.open(root).use { assertEquals(0, UploadStagingRecovery.recover(root)) }
    }
    @Test fun `ambiguous historical stages retain all bytes across repeated recovery`() = withRoot { root ->
        val historical = stage(root, ".upload-123")
        val retained = mapOf("input.elf" to "unconfirmed input", "job.json" to "unconfirmed metadata",
            "upload-receipt.json" to "historical receipt")
        retained.forEach { (name, content) -> historical.resolve(name).writeText(content) }
        val current = stage(root, ".upload-stream-v1-456")
        current.resolve("input.elf").writeText("unpublished current upload")
        repeat(2) { attempt ->
            WorkflowAttemptStore.open(root).use {
                assertEquals(if (attempt == 0) 1 else 0, UploadStagingRecovery.recover(root))
            }
            retained.forEach { (name, content) -> assertEquals(content, Files.readString(historical.resolve(name))) }
            assertEquals(1, JobStore(root).recoveryInventory().retainedUploadStages)
        }
        assertFalse(Files.exists(current))
    }
    @Test fun `unexpected entries links and permissions refuse cleanup without touching retained data`() {
        for (variant in listOf("extra", "symlink", "hardlink", "directory", "permissions", "root-link")) withRoot { root ->
            val stage = stage(root, ".upload-stream-v1-123")
            val outside = root.resolve("outside").also { it.writeText("preserve") }
            when (variant) {
                "extra" -> stage.resolve("notes.txt").writeText("preserve")
                "symlink" -> Files.createSymbolicLink(stage.resolve("input.elf"), outside)
                "hardlink" -> Files.createLink(stage.resolve("input.elf"), outside)
                "directory" -> Files.createDirectory(stage.resolve("input.elf"))
                "permissions" -> Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("rwxr-xr-x"))
                "root-link" -> { Files.delete(stage); Files.createSymbolicLink(stage, root) }
            }
            WorkflowAttemptStore.open(root).use {
                assertEquals("UPLOAD_STAGING_RECOVERY_REQUIRED", assertFailsWith<WorkflowStoreException> { UploadStagingRecovery.recover(root) }.code)
            }
            assertEquals("preserve", Files.readString(outside))
            assertTrue(Files.exists(stage))
            if (Files.isSymbolicLink(stage)) Files.delete(stage)
        }
    }
    @Test fun `too many orphan candidates are rejected before cleanup`() = withRoot { root ->
        repeat(257) { stage(root, ".upload-stream-v1-$it") }
        WorkflowAttemptStore.open(root).use { assertFailsWith<WorkflowStoreException> { UploadStagingRecovery.recover(root) } }
        assertTrue(Files.exists(root.resolve(".upload-stream-v1-0")))
    }
    @Test fun `killed publisher cleanup preserves post-rename receipt and never recovers partial jobs`() {
        for (point in listOf("DURING_BINARY", "AFTER_BINARY_SYNC", "AFTER_METADATA_SYNC", "BEFORE_RENAME", "AFTER_RENAME")) withRoot { root ->
            val reached = root.resolve("reached")
            val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djna.nosys=true", "-Djna.nounpack=true",
                "-Djna.boot.library.path=${System.getProperty("jna.boot.library.path")}",
                "-Ddecompengine.oracle.nativeLibraryDirectory=${System.getProperty("decompengine.oracle.nativeLibraryDirectory")}",
                "-cp", System.getProperty("java.class.path"), UploadCrashProbe::class.java.name, root.toString(), point)
                .redirectErrorStream(true).redirectOutput(root.resolve("probe.log").toFile()).start()
            try {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                while (!Files.exists(reached) && process.isAlive && System.nanoTime() < deadline) Thread.sleep(10)
                assertTrue(Files.exists(reached), Files.readString(root.resolve("probe.log")))
                assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
                process.destroyForcibly(); assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                WorkflowAttemptStore.open(root).use {
                    val cleaned = UploadStagingRecovery.recover(root)
                    assertEquals(if (point == "AFTER_RENAME") 0 else 1, cleaned)
                    assertEquals(if (point == "AFTER_RENAME") 1 else 0, JobStore(root).jobIds().size)
                    val result = StagedJobUpload(root).publish(KEY) { output -> output.write(elfFixture()); "inert.elf" }
                    assertEquals(point == "AFTER_RENAME", result.replayed)
                    assertEquals(1, JobStore(root).jobIds().size)
                }
            } finally { if (process.isAlive) { process.destroyForcibly(); process.waitFor(10, TimeUnit.SECONDS) } }
        }
    }
    private fun stage(root: Path, name: String) = Files.createDirectory(root.resolve(name),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun withRoot(block: (Path) -> Unit) {
        val root = createTempDirectory("upload-recovery-")
        try { block(root) } finally { root.toFile().deleteRecursively() }
    }
    companion object { const val KEY = "crash_qualification_fixture_key" }
}

/** Separate inert publisher process; the parent kills it without running finally/shutdown cleanup. */
object UploadCrashProbe {
    @JvmStatic fun main(args: Array<String>) {
        val root = Path.of(args[0]); val point = args[1]
        fun pause() { root.resolve("reached").writeText("ready"); while (true) Thread.sleep(1000) }
        WorkflowAttemptStore.open(root).use {
            StagedJobUpload(root) { if (it.name == point) pause() }.publish(UploadStagingRecoveryTest.KEY) { output ->
                output.write(elfFixture())
                if (point == "DURING_BINARY") pause()
                "inert.elf"
            }
        }
    }
}

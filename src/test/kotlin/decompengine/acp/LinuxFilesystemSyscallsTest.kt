package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LinuxFilesystemSyscallsTest {
    @Test
    fun `filesystem capacity is read through the pinned directory descriptor`() {
        withLinuxDirectory("linux-syscall-capacity-") { path, directory ->
            val capacity = LinuxFilesystemSyscalls.filesystemCapacity(directory)
            val store = Files.getFileStore(path)

            assertEquals(store.totalSpace, capacity.totalBytes)
            assertTrue(capacity.fragmentBytes > 0L)
            assertTrue(capacity.availableBytes in 0L..capacity.totalBytes)
            assertTrue(capacity.totalInodes > 0L)
            assertTrue(capacity.availableInodes in 0L..capacity.totalInodes)
            assertTrue(capacity.maximumNameBytes >= 255L)
            assertFalse(capacity.readOnly)
        }
    }

    @Test
    fun `regular files can be opened reopened and synchronized through descriptors`() {
        withLinuxDirectory("linux-syscall-regular-") { _, directory ->
            val content = "descriptor-owned-state".toByteArray()
            LinuxFilesystemSyscalls.createRegularFile(directory.fd, "state", OWNER_READ_WRITE).use { created ->
                LinuxFilesystemSyscalls.write(created, content) {}
                LinuxFilesystemSyscalls.synchronize(created)
            }
            LinuxFilesystemSyscalls.synchronize(directory)

            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "state")!!.use { authorized ->
                LinuxFilesystemSyscalls.openReadableFrom(authorized).use { readable ->
                    assertContentEquals(content, LinuxFilesystemSyscalls.read(readable, content.size + 1) {})
                }
                LinuxFilesystemSyscalls.reopenWritable(authorized).use { writable ->
                    LinuxFilesystemSyscalls.synchronize(writable)
                }
                LinuxFilesystemSyscalls.reopenReadWrite(authorized).use { readWrite ->
                    assertContentEquals(content, LinuxFilesystemSyscalls.read(readWrite, content.size + 1) {})
                    LinuxFilesystemSyscalls.synchronize(readWrite)
                }
            }

            assertNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "missing"))
        }
    }

    @Test
    fun `symbolic links fifos and directories are rejected without blocking`() {
        withLinuxDirectory("linux-syscall-special-") { path, directory ->
            Files.writeString(path.resolve("target"), "regular")
            Files.createSymbolicLink(path.resolve("link"), Path.of("target"))
            Files.createDirectory(path.resolve("child"))
            createFifo(path.resolve("fifo"))

            listOf("link", "fifo", "child").forEach { name ->
                assertCompletesPromptly("inspect $name") {
                    assertFailsWith<IOException> {
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)?.close()
                    }
                }
                LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)!!.use { authorized ->
                    assertCompletesPromptly("reopen $name for reading") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.openReadableFrom(authorized).close()
                        }
                    }
                    assertCompletesPromptly("reopen $name for writing") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.reopenWritable(authorized).close()
                        }
                    }
                    assertCompletesPromptly("reopen $name for reading and writing") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.reopenReadWrite(authorized).close()
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `exclusive locks expose a nonblocking deadline primitive and explicit unlock`() {
        withLinuxDirectory("linux-syscall-lock-") { _, directory ->
            LinuxFilesystemSyscalls.createRegularFile(directory.fd, "graph.lock", OWNER_READ_WRITE).use { first ->
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "graph.lock")!!.use { authorized ->
                    LinuxFilesystemSyscalls.reopenReadWrite(authorized).use { second ->
                        var firstLocked = false
                        var secondLocked = false
                        try {
                            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(first))
                            firstLocked = true

                            assertFalse(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                            assertFalse(tryUntil(second, Duration.ofMillis(25)))

                            LinuxFilesystemSyscalls.unlock(first)
                            firstLocked = false
                            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                            secondLocked = true
                        } finally {
                            if (secondLocked) LinuxFilesystemSyscalls.unlock(second)
                            if (firstLocked) LinuxFilesystemSyscalls.unlock(first)
                        }
                    }
                }
            }
            LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, ".").use { first ->
                LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, ".").use { second ->
                    assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(first))
                    try {
                        assertFalse(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                    } finally {
                        LinuxFilesystemSyscalls.unlock(first)
                    }
                    assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                    LinuxFilesystemSyscalls.unlock(second)
                }
            }
        }
    }

    @Test
    fun `constrained root lookup admits only the reviewed native LP64 ABIs`() {
        for (architecture in listOf("amd64", "x86_64", "aarch64")) {
            assertTrue(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 8, 8))
            assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 4, 4))
            assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 8, 4))
        }
        assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", "x32", 8, 8))
        assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Windows", "amd64", 8, 8))
    }

    @Test
    fun `constrained lookup retries share eight attempts and only ENOSYS selects fallback`() {
        var attempts = 0
        assertEquals(19L, LinuxFilesystemSyscalls.boundedConstrainedPathAttempt {
            attempts++
            if (attempts == 8) 19L to 0 else -1L to if (attempts % 2 == 0) 4 else 11
        })
        assertEquals(8, attempts)
        attempts = 0
        assertFailsWith<IOException> {
            LinuxFilesystemSyscalls.boundedConstrainedPathAttempt {
                attempts++
                -1L to if (attempts % 2 == 0) 4 else 11
            }
        }
        assertEquals(8, attempts)
        for (error in listOf(1, 2, 13, 18, 20, 22, 40, 7)) {
            attempts = 0
            val failure = assertFailsWith<LinuxSyscallException> {
                LinuxFilesystemSyscalls.boundedConstrainedPathAttempt { attempts++; -1L to error }
            }
            assertEquals(error, failure.errno)
            assertEquals(1, attempts)
        }
        attempts = 0
        assertNull(LinuxFilesystemSyscalls.boundedConstrainedPathAttempt { attempts++; -1L to 38 })
        assertEquals(1, attempts)
    }

    @Test
    fun `constrained root lookup preserves regular directory and final symlink descriptor kinds`() {
        // These native controls are deliberately not a fallback-as-pass: the required supported lane
        // must actually exercise openat2. Separate pure controls establish ENOSYS/ABI refusal behavior.
        val path = createTempDirectory(Files.createDirectories(Path.of("build")).toAbsolutePath(),
            "constrained-root-").normalize()
        try {
            Files.createDirectory(path.resolve("directory"))
            Files.writeString(path.resolve("regular"), "owned")
            Files.createSymbolicLink(path.resolve("link"), Path.of("regular"))
            Files.createSymbolicLink(path.resolve("ancestor"), Path.of("directory"))
            LinuxFilesystemSyscalls.openRoot(path).use { anchor ->
                for (name in listOf("regular", "directory", "link")) {
                    val opened = LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, name)
                        ?: throw IOException("required constrained-lookup lane is unsupported")
                    opened.use {
                        val expected = LinuxFilesystemSyscalls.openPathAtOrNull(anchor.fd, name)!!
                        expected.use { original ->
                            assertEquals(original.identity.key, it.identity.key)
                            assertEquals(original.identity.mountId, it.identity.mountId)
                            assertEquals(name == "link", it.identity.isSymbolicLink)
                        }
                    }
                }
                // Kernel NO_SYMLINKS rejects an intermediate symlink; final O_PATH symlinks are
                // returned and must be rejected by the root-location identity/type guard.
                assertFailsWith<LinuxSyscallException> {
                    LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, "ancestor/missing")
                }
                assertFailsWith<LinuxSyscallException> {
                    LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, "missing")
                }
            }
        } finally {
            path.toFile().deleteRecursively()
        }
    }

    private fun withLinuxDirectory(prefix: String, action: (Path, LinuxDescriptor) -> Unit) {
        val path = createTempDirectory(prefix).toAbsolutePath().normalize()
        try {
            LinuxFilesystemSyscalls.requireSupported(path)
            LinuxFilesystemSyscalls.openRoot(path).use { directory -> action(path, directory) }
        } finally {
            path.toFile().deleteRecursively()
        }
    }

    private fun createFifo(path: Path) {
        val process = ProcessBuilder("mkfifo", path.toString()).redirectErrorStream(true).start()
        val completed = process.waitFor(5, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly()
        assertTrue(completed, "mkfifo did not complete")
        assertEquals(0, process.exitValue(), process.inputStream.bufferedReader().readText())
    }

    private fun assertCompletesPromptly(operation: String, action: () -> Unit) {
        val started = System.nanoTime()
        action()
        val elapsed = Duration.ofNanos(System.nanoTime() - started)
        assertTrue(elapsed < Duration.ofSeconds(2), "$operation blocked for $elapsed")
    }

    private fun tryUntil(descriptor: LinuxDescriptor, wait: Duration): Boolean {
        val deadline = System.nanoTime() + wait.toNanos()
        do {
            if (LinuxFilesystemSyscalls.tryExclusiveLock(descriptor)) return true
            Thread.sleep(1)
        } while (System.nanoTime() < deadline)
        return false
    }

    private companion object {
        const val OWNER_READ_WRITE = 0x180 // 0600
    }
}

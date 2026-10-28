package decompengine.repair

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import kotlin.test.*

/** Actual descriptor reads and deterministic publication races; no worker or analyzer execution. */
class StableLogReadTest {
    @Test fun `only initial absence is missing not denied identity or atomic publication races`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/stable-log-read"))
        val root = Files.createTempDirectory(parent, "read-")
        try {
            assertFailsWith<StableRegularFileAbsentException> { readStableRegularFile(root, "reports/build.log", 1024) }
            val reports = Files.createDirectory(root.resolve("reports"))
            val log = reports.resolve("build.log")
            assertFailsWith<StableRegularFileAbsentException> { readStableRegularFile(root, "reports/build.log", 1024) }
            Files.createSymbolicLink(log, reports.resolve("absent"))
            assertFailsWith<IllegalArgumentException> { readStableRegularFile(root, "reports/build.log", 1024) }
            Files.delete(log)
            Files.createDirectory(log)
            assertFailsWith<IllegalArgumentException> { readStableRegularFile(root, "reports/build.log", 1024) }
            Files.delete(log)
            for (remove in listOf(false, true)) {
                Files.writeString(log, "old recording")
                assertFailsWith<IllegalArgumentException> {
                    readStableRegularFile(root, "reports/build.log", 1024, afterRead = {
                        if (remove) Files.delete(log) else {
                            val next = Files.writeString(reports.resolve("next.log"), "new recording")
                            Files.move(next, log, ATOMIC_MOVE, REPLACE_EXISTING)
                        }
                    })
                }
                // A later successful capture is allowed; no bytes from the obsolete descriptor escape.
                if (!remove) assertEquals("new recording", readStableRegularFile(root, "reports/build.log", 1024).bytes.decodeToString())
            }
            // ENOENT in a stale pinned parent is not absence in the selected namespace.
            var checkpoints = 0
            assertFailsWith<IllegalArgumentException> {
                readStableRegularFile(root, "reports/build.log", 1024, cancellationCheck = {
                    checkpoints++
                    if (checkpoints == 4) {
                        Files.move(reports, root.resolve("detached-reports"), ATOMIC_MOVE)
                        Files.createDirectory(reports)
                        Files.writeString(log, "published in replacement parent")
                    }
                })
            }
            assertTrue(checkpoints >= 4)
        } finally { root.toFile().deleteRecursively() }
    }
}

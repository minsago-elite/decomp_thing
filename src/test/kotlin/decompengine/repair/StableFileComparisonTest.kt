package decompengine.repair

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.APPEND
import kotlin.test.*

class StableFileComparisonTest {
    @Test fun stableChangesAndFullStream() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/comparison")), "stable-")
        val path = root.resolve("input")
        val bytes = ByteArray(180000) { (it % 251).toByte() }
        Files.write(path, bytes)
        val expected = readStableRegularFile(root, "input", 200000)
        var baseline = 0
        assertEquals(StableComparison.SAME, compareStableRegularFile(root, "input", 200000, expected) { baseline++ })
        val changedContents = listOf(0, bytes.size / 2, bytes.lastIndex)
            .map { index -> bytes.copyOf().also { it[index]++ } } + listOf(bytes.copyOf(179999), bytes.copyOf(180001))
        for (changed in changedContents) {
            Files.write(path, changed)
            var checks = 0
            assertEquals(StableComparison.DIFFERENT, compareStableRegularFile(root, "input", 200000, expected) { checks++ })
            assertEquals(baseline, checks)
        }
        Files.move(path, root.resolve("old"))
        Files.write(path, bytes)
        assertEquals(StableComparison.DIFFERENT, compareStableRegularFile(root, "input", 200000, expected))
        assertFailsWith<RepairBudgetExceededException> { compareStableRegularFile(root, "input", 10, expected) }
        val interrupted = InterruptedException("same instance")
        assertSame(interrupted, assertFailsWith<InterruptedException> {
            compareStableRegularFile(root, "input", 200000, expected) { throw interrupted }
        })
        val interruptedRead = java.io.InterruptedIOException("same read interruption")
        assertSame(interruptedRead, assertFailsWith<java.io.InterruptedIOException> {
            compareStableRegularFile(root, "input", 200000, expected) { throw interruptedRead }
        })
        for (relative in listOf("../input", "/input", "a/../input", "./input"))
            assertFailsWith<IllegalArgumentException> { compareStableRegularFile(root, relative, 200000, expected) }
        Files.createLink(root.resolve("link"), path)
        assertFailsWith<StableFileUnavailableException> { compareStableRegularFile(root, "input", 200000, expected) }
        Files.delete(path)
        assertFailsWith<StableFileUnavailableException> { compareStableRegularFile(root, "input", 200000, expected) }
        Files.createSymbolicLink(path, Path.of("old"))
        assertFailsWith<StableFileUnavailableException> { compareStableRegularFile(root, "input", 200000, expected) }
    }

    @Test fun concurrentChangesAndRestoredMtime() {
        for (mutation in listOf("rewrite", "restore", "append", "budget", "rename", "hardlink")) {
            val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/comparison")), "race-")
            val path = root.resolve("input")
            val bytes = ByteArray(180000) { (it % 251).toByte() }
            Files.write(path, bytes)
            val expected = readStableRegularFile(root, "input", 200000)
            val mtime = Files.getLastModifiedTime(path)
            var checks = 0
            val action = {
                compareStableRegularFile(root, "input", if (mutation == "budget") 180000 else 200000, expected) {
                    if (++checks == 3) when (mutation) {
                        "rewrite" -> Files.write(path, bytes.copyOf().also { it[it.lastIndex]++ })
                        "restore" -> {
                            Files.write(path, bytes.copyOf().also { it[0]++ })
                            Files.write(path, bytes)
                            Files.setLastModifiedTime(path, mtime)
                        }
                        "append", "budget" -> Files.write(path, byteArrayOf(1), APPEND)
                        "rename" -> { Files.move(path, root.resolve("old")); Files.write(path, bytes) }
                        "hardlink" -> Files.createLink(root.resolve("link"), path)
                    }
                }
            }
            if (mutation == "budget") assertFailsWith<RepairBudgetExceededException> { action() }
            else assertFailsWith<StableFileChangedException>(mutation) { action() }
        }
    }
}

package decompengine.repair

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class StableFileVerificationTest {
    @Test fun growthDuringVerificationPreservesBudgetRefusal() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/stream-verify")), "growth-")
        val path = root.resolve("input")
        val bytes = ByteArray(180000) { (it % 251).toByte() }
        Files.write(path, bytes)
        val captured = readStableRegularFile(root, "input", 200000)
        for (maximum in listOf(180000L, 200000L)) {
            Files.write(path, bytes)
            var checks = 0
            val action = {
                verifyStableRegularFile(root, "input", maximum, captured) {
                    if (++checks == 3) Files.write(path, byteArrayOf(1), java.nio.file.StandardOpenOption.APPEND)
                }
            }
            if (maximum == bytes.size.toLong()) assertFailsWith<RepairBudgetExceededException> { action() }
            else assertFailsWith<StableFileChangedException> { action() }
        }
    }

    @Test fun capturedVerificationControls() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/stream-verify")), "control-")
        val path = root.resolve("input")
        val bytes = ByteArray(180000) { (it % 251).toByte() }
        Files.write(path, bytes)
        val captured = readStableRegularFile(root, "input", 200000)
        fun verify() = verifyStableRegularFile(root, "input", 200000, captured)
        verify()
        for (index in listOf(0, bytes.size / 2, bytes.lastIndex)) {
            Files.write(path, bytes.copyOf().also { it[index] = (it[index] + 1).toByte() })
            assertFailsWith<StableFileChangedException> { verify() }
        }
        for (size in listOf(bytes.size - 1, bytes.size + 1)) {
            Files.write(path, bytes.copyOf(size))
            assertFailsWith<StableFileChangedException> { verify() }
        }
        Files.write(path, bytes)
        assertFailsWith<RepairBudgetExceededException> { verifyStableRegularFile(root, "input", 10, captured) }
        assertFailsWith<InterruptedException> {
            verifyStableRegularFile(root, "input", 200000, captured) { throw InterruptedException() }
        }
        var checks = 0
        assertFailsWith<StableFileChangedException> {
            verifyStableRegularFile(root, "input", 200000, captured) {
                if (++checks == 3) Files.write(path, bytes.copyOf().also { it[it.lastIndex] = -1 })
            }
        }
        Files.write(path, bytes)
        val link = Files.createLink(root.resolve("hardlink"), path)
        assertFailsWith<StableFileChangedException> { verify() }
        Files.delete(link)
        Files.move(path, root.resolve("old"))
        Files.write(path, bytes)
        assertFailsWith<StableFileChangedException> { verify() }
        Files.delete(path)
        Files.createSymbolicLink(path, Path.of("old"))
        assertFails { verify() }
    }
}

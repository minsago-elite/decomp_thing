package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledAnalysisStateCaptureTest {
    @Test
    fun `stopped project manifest retains nested empty directories identities and streamed file contents`() = fixture { path, run, state ->
        Files.createDirectories(path.resolve("state/project/empty"))
        Files.writeString(path.resolve("state/project/database"), "authored-state")
        val first = GccBundledAnalysisStateCapture.capture(run, state)
        assertEquals(3, first.entryCount)
        assertEquals(14, first.totalBytes)
        val document = OracleJson.parseCanonical(first.canonicalBytes).jsonObject
        assertEquals("non-authoritative-byte-assessment", document.getValue("authority").jsonPrimitive.content)
        assertContentEquals(first.canonicalBytes, GccBundledAnalysisStateCapture.capture(run, state).canonicalBytes)
        first.canonicalBytes.fill(0)
        assertTrue(first.canonicalBytes.first().toInt() != 0)
    }

    @Test
    fun `same path changed bytes and replacement inode cannot match the original state manifest`() = fixture { path, run, state ->
        val file = path.resolve("state/database")
        Files.writeString(file, "first-state")
        val first = GccBundledAnalysisStateCapture.capture(run, state)
        Files.writeString(file, "other-state")
        val changed = GccBundledAnalysisStateCapture.capture(run, state)
        assertNotEquals(first.sha256, changed.sha256)
        Files.move(file, path.resolve("original"))
        Files.writeString(file, "other-state")
        assertNotEquals(changed.sha256, GccBundledAnalysisStateCapture.capture(run, state).sha256)
        assertEquals("other-state", Files.readString(path.resolve("original")))
    }

    @Test
    fun `retained manifest revalidation rejects same-size edits restored bytes and inventory changes`() {
        for (change in listOf("content", "restored", "added", "removed", "replacement")) fixture { path, run, state ->
            val file = path.resolve("state/database")
            Files.writeString(file, "first-state")
            val retained = GccBundledAnalysisStateCapture.capture(run, state)
            GccBundledAnalysisStateCapture.requireUnchanged(run, state, retained)
            when (change) {
                "content" -> Files.writeString(file, "other-state")
                "restored" -> {
                    Files.writeString(file, "other-state")
                    Files.writeString(file, "first-state")
                }
                "added" -> Files.createDirectory(path.resolve("state/new-empty-directory"))
                "removed" -> Files.delete(file)
                "replacement" -> {
                    Files.move(file, path.resolve("retained-old"))
                    Files.writeString(file, "first-state")
                }
            }
            assertFails(change) { GccBundledAnalysisStateCapture.requireUnchanged(run, state, retained) }
        }
    }

    @Test
    fun `linked files directories and hardlinks fail without modifying their targets`() {
        for (kind in listOf("file", "directory", "hardlink")) fixture { path, run, state ->
            val target = path.resolve("external")
            if (kind == "directory") Files.createDirectory(target) else Files.writeString(target, "retained")
            val link = path.resolve("state/entry")
            if (kind == "hardlink") Files.createLink(link, target) else Files.createSymbolicLink(link, target)
            assertFails { GccBundledAnalysisStateCapture.capture(run, state) }
            assertTrue(Files.exists(target))
            if (kind != "directory") assertEquals("retained", Files.readString(target))
        }
    }

    @Test
    fun `state capture enforces count depth aggregate and sparse logical-size bounds`() = fixture { path, run, state ->
        Files.createDirectories(path.resolve("state/one/two"))
        val data = path.resolve("state/one/two/data")
        Files.writeString(data, "12345678")
        for (limits in listOf(GccAnalysisStateCaptureLimits(maximumEntries = 2),
            GccAnalysisStateCaptureLimits(maximumDepth = 2), GccAnalysisStateCaptureLimits(maximumTotalBytes = 7))) {
            assertFails { GccBundledAnalysisStateCapture.capture(run, state, limits) }
        }
        RandomAccessFile(data.toFile(), "rw").use { it.setLength(1024L * 1024 * 1024) }
        assertFails { GccBundledAnalysisStateCapture.capture(run, state, GccAnalysisStateCaptureLimits(maximumFileBytes = 16)) }
        assertEquals(1024L * 1024 * 1024, Files.size(data))
    }

    @Test
    fun `empty untrusted and replaced state roots never acquire a resume manifest`() = fixture { path, run, state ->
        assertFails { GccBundledAnalysisStateCapture.capture(run, state) }
        val data = path.resolve("state/data")
        Files.writeString(data, "data")
        Files.setPosixFilePermissions(data, PosixFilePermissions.fromString("rw-rw-rw-"))
        assertFails { GccBundledAnalysisStateCapture.capture(run, state) }
        Files.move(path.resolve("state"), path.resolve("old-state"))
        Files.createDirectory(path.resolve("state"))
        Files.writeString(path.resolve("state/new-data"), "data")
        assertFails { GccBundledAnalysisStateCapture.capture(run, state) }
        assertEquals("data", Files.readString(path.resolve("old-state/data")))
    }

    private fun fixture(action: (Path, LinuxDescriptor, LinuxFileIdentity) -> Unit) {
        val path = Files.createTempDirectory("gcc-stopped-state-")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        try {
            val state = Files.createDirectory(path.resolve("state"))
            Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwx------"))
            val identity = LinuxFilesystemSyscalls.openRoot(state).use { it.identity }
            LinuxFilesystemSyscalls.openRoot(path).use { action(path, it, identity) }
        } finally {
            Files.walk(path).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}

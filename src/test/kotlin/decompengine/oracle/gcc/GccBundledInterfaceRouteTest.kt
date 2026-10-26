package decompengine.oracle.gcc

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GccBundledInterfaceRouteTest {
    @Test
    fun `interface command selects only the fresh driver with the unchanged scratch policy`() {
        val selected = GccBundledCliOptions.parse(arguments(), nativeInterfaceObservations = true)
        assertEquals("gcc-engine-interface-observations", selected.commandName)
        assertEquals("driver", selected.engineId)
        assertTrue(selected.nativeInterfaceObservations)
        assertFalse(selected.nativeCallObservations)
        assertFalse(selected.fullRecoveryExport)
        assertFalse(selected.runtimeDiagnostics)
        assertEquals(null, selected.resumeAfterCheckpoint)
        assertEquals(64L * 1024 * 1024 * 1024, selected.diskPolicy.maximumFilesystemBytes)
        assertEquals(1_000_000L, selected.diskPolicy.maximumFilesystemInodes)
        assertEquals("driver", GccBundledCliOptions.engineUsage(false, nativeInterfaceObservations = true))
    }

    @Test
    fun `interface command refuses wrong engines mixed modes and resume before filesystem access`() {
        for (engine in listOf("cc1", "lto1")) {
            assertFailsWith<IllegalArgumentException> { GccBundledCliOptions.parse(arguments(engine), nativeInterfaceObservations = true) }
        }
        assertFailsWith<IllegalArgumentException> {
            GccBundledCliOptions.parse(arguments(), fullRecoveryExport = true, nativeInterfaceObservations = true)
        }
        assertFailsWith<IllegalArgumentException> {
            GccBundledCliOptions.parse(arguments(), nativeCallObservations = true, nativeInterfaceObservations = true)
        }
        assertFailsWith<IllegalArgumentException> {
            GccBundledCliOptions.parse(arguments(), fullRecoveryExport = true, runtimeDiagnostics = true, nativeInterfaceObservations = true)
        }
        assertFailsWith<IllegalArgumentException> {
            GccBundledCliOptions.parse(arguments() + listOf("--resume-after-checkpoint", "512"), nativeInterfaceObservations = true)
        }
    }

    @Test
    fun `interface route cannot widen the selected disk and inode allowances`() {
        for ((flag, value) in listOf(
            "--scratch-max-bytes" to (64L * 1024 * 1024 * 1024 + 1).toString(),
            "--scratch-max-inodes" to "1000001", "--scratch-min-bytes" to "1", "--scratch-min-inodes" to "1",
        )) assertFailsWith<IllegalArgumentException>(flag) {
            GccBundledCliOptions.parse(arguments() + listOf(flag, value), nativeInterfaceObservations = true)
        }
        val tighter = GccBundledCliOptions.parse(arguments() + listOf("--scratch-max-bytes", (32L * 1024 * 1024 * 1024).toString()),
            nativeInterfaceObservations = true)
        assertEquals(32L * 1024 * 1024 * 1024, tighter.diskPolicy.maximumFilesystemBytes)
    }

    @Test
    fun `existing full native and planning command selections do not acquire interface mode`() {
        val full = GccBundledCliOptions.parse(arguments(), fullRecoveryExport = true)
        val native = GccBundledCliOptions.parse(arguments(), nativeCallObservations = true)
        val planning = GccBundledCliOptions.parse(arguments("cc1"))
        assertEquals(listOf("gcc-engine-full-export", "gcc-engine-native-calls", "gcc-engine-plan"),
            listOf(full.commandName, native.commandName, planning.commandName))
        listOf(full, native, planning).forEach { assertFalse(it.nativeInterfaceObservations) }
        assertFailsWith<IllegalArgumentException> { GccBundledCliOptions.parse(arguments()) }
    }

    private fun arguments(engine: String = "driver"): List<String> {
        val root = Path.of("build/interface-route-authored").toAbsolutePath().normalize()
        return listOf(engine, root.resolve("stripped").toString(), "--profile", root.resolve("profile.json").toString(),
            "--ghidra-archive", root.resolve("archive.zip").toString(), "--output", root.resolve("output").toString(),
            "--scratch", root.resolve("scratch").toString())
    }
}

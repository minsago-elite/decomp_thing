package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFails

class GccBundledReplayReportsV1Test {
    @Test fun `full and native output subdirectories are admitted once then frozen exactly`() {
        for (subdirectories in listOf(listOf("program_model.json.export"),
            listOf("program_model.json.export", "native-calls-v1"))) {
            fixture { root ->
                Files.createDirectory(root.resolve("reports"))
                LinuxFilesystemSyscalls.openRoot(root).use { run ->
                    val prepared = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { it.identity }
                    Files.writeString(root.resolve("reports/program_model.json"), "{}")
                    Files.writeString(root.resolve("reports/program_model.json.progress.json"), "{}")
                    subdirectories.forEach { Files.createDirectory(root.resolve("reports").resolve(it)) }
                    val frozen = GccBundledReplayReportsV1.capture(run, prepared, subdirectories.size == 2)
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                        frozen.requireCurrent(reports)
                        Files.createDirectory(root.resolve("reports/late-subdirectory"))
                        assertFails { frozen.requireCurrent(reports) }
                    }
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                        assertFails { frozen.requireCurrent(reports) }
                    }
                }
            }
        }
    }

    @Test fun `a replacement directory cannot borrow prepared ownership or a frozen pin`() = fixture { root ->
        Files.createDirectory(root.resolve("reports"))
        LinuxFilesystemSyscalls.openRoot(root).use { run ->
            val prepared = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { it.identity }
            completeReports(root)
            val frozen = GccBundledReplayReportsV1.capture(run, prepared)
            Files.move(root.resolve("reports"), root.resolve("former"))
            Files.createDirectory(root.resolve("reports"))
            assertFails { GccBundledReplayReportsV1.capture(run, prepared) }
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { assertFails { frozen.requireCurrent(it) } }
        }
    }

    @Test fun `initial normalization changes only link count and never ownership fields`() = fixture { root ->
        Files.createDirectory(root.resolve("reports"))
        LinuxFilesystemSyscalls.openRoot(root).use { run ->
            val prepared = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { it.identity }
            completeReports(root)
            // btrfs reports a constant directory link count; exercise stale-count handling there too.
            GccBundledReplayReportsV1.capture(run, prepared.copy(linkCount = prepared.linkCount + 1))
            assertFails { GccBundledReplayReportsV1.capture(run, prepared.copy(uid = prepared.uid + 1)) }
            assertFails { GccBundledReplayReportsV1.capture(run, prepared.copy(mode = prepared.mode xor 1)) }
        }
    }

    private fun completeReports(root: Path) {
        Files.createDirectory(root.resolve("reports/program_model.json.export"))
        Files.writeString(root.resolve("reports/program_model.json"), "{}")
        Files.writeString(root.resolve("reports/program_model.json.progress.json"), "{}")
    }

    private fun fixture(action: (Path) -> Unit) {
        val base = Files.createDirectories(Path.of("build/task-tmp/replay-reports-tests").toAbsolutePath())
        val root = Files.createTempDirectory(base, "reports-").toRealPath()
        try { action(root) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}

package decompengine.oracle.reference

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.fulltree.KotlinContainedCommandProtocol
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/** Filesystem admission controls only: raw report bytes do not confer reference authority. */
class ReferenceCorpusReportReaderTest {
    @Test
    fun `exact three file report with empty logs returns only observation bytes`(): Unit {
        withReports { fixture ->
            assertContentEquals(OBSERVATIONS, fixture.read())
            assertEquals(REPORT_NAMES.toSet(), Files.list(fixture.reports).use { entries ->
                entries.map { it.fileName.toString() }.toList().toSet()
            })
        }
    }

    @Test
    fun `nonempty binary diagnostic logs are admitted by authenticated sizes only`(): Unit {
        val stdout = byteArrayOf(0, -1, -128, 10)
        val stderr = "{\"referenceAuthority\":true}".toByteArray() + byteArrayOf(0, -2)
        withReports(stdout, stderr) { fixture ->
            assertContentEquals(OBSERVATIONS, fixture.read(stdout.size.toLong(), stderr.size.toLong()))
            assertContentEquals(stdout, Files.readAllBytes(fixture.file(STDOUT)))
            assertContentEquals(stderr, Files.readAllBytes(fixture.file(STDERR)))
        }
    }

    @Test
    fun `sparse diagnostic logs at the maximum byte count are admitted`(): Unit {
        withReports { fixture ->
            LOG_NAMES.forEach { name -> resize(fixture.file(name), MAXIMUM_LOG_BYTES) }
            assertContentEquals(OBSERVATIONS, fixture.read(MAXIMUM_LOG_BYTES, MAXIMUM_LOG_BYTES))
        }
    }

    @Test
    fun `each required report entry must be present`(): Unit {
        for (name in REPORT_NAMES) {
            withReports { fixture ->
                Files.delete(fixture.file(name))
                assertFails("missing $name") { fixture.read() }
            }
        }
    }

    @Test
    fun `unexpected report entries are rejected`(): Unit {
        withReports { fixture ->
            Files.write(fixture.file("unexpected.json"), OBSERVATIONS)
            assertFails { fixture.read() }
        }
    }

    @Test
    fun `each report entry rejects symbolic links even to matching owned files`(): Unit {
        for (name in REPORT_NAMES) {
            withReports { fixture ->
                val target = fixture.root.resolve("target")
                Files.move(fixture.file(name), target)
                Files.createSymbolicLink(fixture.file(name), target)
                assertFails("symbolic link $name") { fixture.read() }
            }
        }
    }

    @Test
    fun `each report entry rejects directories`(): Unit {
        for (name in REPORT_NAMES) {
            withReports { fixture ->
                Files.delete(fixture.file(name))
                Files.createDirectory(fixture.file(name))
                setMode(fixture.file(name), if (name == OBSERVATION_FILE) "r--------" else "rw-------")
                try {
                    assertFails("directory $name") { fixture.read() }
                } finally {
                    setMode(fixture.file(name), "rwx------")
                }
            }
        }
    }

    @Test
    fun `each report entry rejects an additional hard link outside reports`(): Unit {
        for (name in REPORT_NAMES) {
            withReports { fixture ->
                Files.createLink(fixture.root.resolve("alias"), fixture.file(name))
                assertFails("additional link $name") { fixture.read() }
            }
        }
    }

    @Test
    fun `report entries cannot alias one another`(): Unit {
        for ((source, alias) in listOf(STDOUT to STDERR, OBSERVATION_FILE to STDOUT, OBSERVATION_FILE to STDERR)) {
            withReports { fixture ->
                Files.delete(fixture.file(alias))
                Files.createLink(fixture.file(alias), fixture.file(source))
                val stdoutBytes = Files.size(fixture.file(STDOUT))
                val stderrBytes = Files.size(fixture.file(STDERR))
                assertFails("$source aliases $alias") { fixture.read(stdoutBytes, stderrBytes) }
            }
        }
    }

    @Test
    fun `diagnostic logs require exact owner read write mode`(): Unit {
        for (name in LOG_NAMES) {
            for (mode in listOf("r--------", "rw-r--r--", "rwx------", "---------")) {
                withReports { fixture ->
                    setMode(fixture.file(name), mode)
                    assertFails("$name mode $mode") { fixture.read() }
                }
            }
        }
    }

    @Test
    fun `observations retain exact immutable owner read mode`(): Unit {
        for (mode in listOf("rw-------", "r--r--r--", "r-x------", "---------")) {
            withReports { fixture ->
                setMode(fixture.file(OBSERVATION_FILE), mode)
                assertFails("observations mode $mode") { fixture.read() }
            }
        }
    }

    @Test
    fun `reports directory requires exact owner read write execute mode`(): Unit {
        for (mode in listOf("rw-------", "rwxr-x---", "rwxrwxrwx")) {
            withReports { fixture ->
                setMode(fixture.reports, mode)
                assertFails("reports mode $mode") { fixture.read() }
            }
        }
    }

    @Test
    fun `reports descriptor rejects metadata changed since it was opened`(): Unit {
        withReports { fixture ->
            setMode(fixture.reports, "rwxr-x---")
            LinuxFilesystemSyscalls.openRoot(fixture.reports).use { reports ->
                setMode(fixture.reports, "rwx------")
                assertFails { ReferenceCorpusReportReader.read(reports, 0, 0) }
            }
        }
    }

    @Test
    fun `each diagnostic size must match its own authenticated outcome count`(): Unit {
        withReports(byteArrayOf(1, 2), byteArrayOf(3, 4, 5, 6)) { fixture ->
            for ((stdoutBytes, stderrBytes) in listOf(1L to 4L, 3L to 4L, 2L to 3L, 2L to 5L, 4L to 2L, 3L to 3L)) {
                assertFails("counts $stdoutBytes and $stderrBytes") { fixture.read(stdoutBytes, stderrBytes) }
            }
        }
    }

    @Test
    fun `authenticated log counts reject negative and over limit values`(): Unit {
        withReports { fixture ->
            for (count in listOf(-1L, Long.MIN_VALUE, MAXIMUM_LOG_BYTES + 1, Long.MAX_VALUE)) {
                assertFails("stdout count $count") { fixture.read(count, 0) }
                assertFails("stderr count $count") { fixture.read(0, count) }
            }
        }
    }

    @Test
    fun `each sparse log beyond the maximum byte count is rejected`(): Unit {
        for (name in LOG_NAMES) {
            withReports { fixture ->
                resize(fixture.file(name), MAXIMUM_LOG_BYTES + 1)
                val stdoutBytes = if (name == STDOUT) MAXIMUM_LOG_BYTES else 0L
                val stderrBytes = if (name == STDERR) MAXIMUM_LOG_BYTES else 0L
                assertFails("oversized $name") { fixture.read(stdoutBytes, stderrBytes) }
            }
        }
    }

    @Test
    fun `observation manifest at the existing maximum byte count is admitted`(): Unit {
        withReports { fixture ->
            replaceWithSparseObservation(fixture, ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES.toLong())
            val bytes = fixture.read()
            assertEquals(ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES, bytes.size)
            assertTrue(bytes.all { it == 0.toByte() })
        }
    }

    @Test
    fun `observation manifest beyond the existing maximum byte count is rejected`(): Unit {
        withReports { fixture ->
            replaceWithSparseObservation(fixture, ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES.toLong() + 1)
            assertFails { fixture.read() }
        }
    }

    private class ReportsFixture(val root: Path, val reports: Path) {
        fun file(name: String): Path = reports.resolve(name)

        fun read(stdoutBytes: Long = 0, stderrBytes: Long = 0): ByteArray =
            LinuxFilesystemSyscalls.openRoot(reports).use { descriptor ->
                ReferenceCorpusReportReader.read(descriptor, stdoutBytes, stderrBytes)
            }
    }

    private fun withReports(stdout: ByteArray = byteArrayOf(), stderr: ByteArray = byteArrayOf(),
        action: (ReportsFixture) -> Unit): Unit {
        val base = Files.createDirectories(Path.of("build", "reference-report-tests").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(base, "reports-")
        val reports = root.resolve("reports")
        try {
            Files.createDirectory(reports)
            setMode(reports, "rwx------")
            val fixture = ReportsFixture(root, reports)
            for ((name, bytes) in listOf(OBSERVATION_FILE to OBSERVATIONS, STDOUT to stdout, STDERR to stderr)) {
                Files.write(fixture.file(name), bytes)
                setMode(fixture.file(name), if (name == OBSERVATION_FILE) "r--------" else "rw-------")
            }
            action(fixture)
        } finally {
            if (Files.isDirectory(reports)) setMode(reports, "rwx------")
            Files.walk(root).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun replaceWithSparseObservation(fixture: ReportsFixture, bytes: Long): Unit {
        val path = fixture.file(OBSERVATION_FILE)
        Files.delete(path)
        resize(path, bytes)
        setMode(path, "r--------")
    }

    private fun resize(path: Path, bytes: Long): Unit {
        RandomAccessFile(path.toFile(), "rw").use { it.setLength(bytes) }
    }

    private fun setMode(path: Path, mode: String): Unit {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode))
    }

    private companion object {
        const val OBSERVATION_FILE = ReferenceCorpusWorker.OBSERVATIONS_FILE
        const val STDOUT = KotlinContainedCommandProtocol.STDOUT_FILE
        const val STDERR = KotlinContainedCommandProtocol.STDERR_FILE
        const val MAXIMUM_LOG_BYTES = KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES
        val LOG_NAMES = listOf(STDOUT, STDERR)
        val REPORT_NAMES = listOf(OBSERVATION_FILE, STDOUT, STDERR)
        val OBSERVATIONS = "opaque observation bytes\n".toByteArray()
    }
}

package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FullTreeWorkerFailureOwnershipTest {
    @Test
    fun `invalid START preserves parent runtime scratch and protocol evidence`() =
        assertFailurePreservesParentTree(validStart = false)

    @Test
    fun `failure after START preserves parent runtime scratch and protocol evidence`() =
        assertFailurePreservesParentTree(validStart = true)

    private fun assertFailurePreservesParentTree(validStart: Boolean) =
        inControlTemporaryDirectory { root ->
            val run = Files.createDirectory(root.resolve("run-$validStart"))
            Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwx------"))
            val runtime = Files.createDirectory(run.resolve("runtime"))
            val scratch = Files.createDirectory(run.resolve("scratch"))
            Files.createDirectory(run.resolve("tmp"))
            val parentRuntime = runtime.resolve("classpath-0.jar")
            Files.writeString(parentRuntime, "parent-owned authenticated runtime sentinel")
            Files.setPosixFilePermissions(parentRuntime, PosixFilePermissions.fromString("r--------"))
            val scratchEvidence = scratch.resolve("retained-observation")
            Files.writeString(scratchEvidence, "partial scratch evidence")
            val nonce = "a".repeat(64)
            val start = run.resolve("parent.start")
            Files.writeString(start, if (validStart) "START\t1\t$nonce\n" else "INVALID\t1\t$nonce\n")
            Files.setPosixFilePermissions(start, PosixFilePermissions.fromString("r--------"))
            val inputs = (0..4).map { index ->
                root.resolve("input-$validStart-$index.json").also { input ->
                    Files.writeString(input, "invalid scope input")
                    Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("r--------"))
                }
            }
            val runtimeIdentity = Files.getAttribute(parentRuntime, "unix:ino")
            val native = Path.of(System.getProperty("decompengine.oracle.nativeLibraryDirectory"))
            val command = listOf(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx128m") +
                isolatedObservationJvmTemporaryArguments(run, native) + listOf(
                    "-classpath", System.getProperty("java.class.path"),
                    FullTreeFunctionObservationIsolatedWorker::class.java.name, "1", nonce,
                ) + inputs.map(Path::toString) + listOf("clang-lib-driver", run.toString())
            val process = ProcessBuilder(command).directory(run.toFile()).redirectErrorStream(true).apply {
                environment().clear()
                environment()["HOME"] = run.toString()
                environment()["TMPDIR"] = run.resolve("tmp").toString()
            }.start()
            try {
                process.outputStream.close()
                assertTrue(process.waitFor(15, TimeUnit.SECONDS), "worker failure exit exceeded its test bound")
                val output = process.inputStream.readNBytes(8193)
                assertTrue(output.size <= 8192)
                assertEquals(73, process.exitValue(), output.toString(Charsets.UTF_8))
                assertEquals("parent-owned authenticated runtime sentinel", Files.readString(parentRuntime))
                assertEquals(runtimeIdentity, Files.getAttribute(parentRuntime, "unix:ino"))
                assertEquals(PosixFilePermissions.fromString("r--------"), Files.getPosixFilePermissions(parentRuntime))
                assertEquals("partial scratch evidence", Files.readString(scratchEvidence))
                val failure = Files.readString(run.resolve("worker.failure"))
                assertTrue(failure.startsWith("FAIL\t1\t$nonce\t"))
                if (validStart) {
                    assertTrue(failure.contains("FullTreeControlException"), failure)
                } else {
                    assertTrue(failure.endsWith("\tisolated worker protocol parent.start is invalid\n"), failure)
                }
                assertEquals("BOOT\t1\t$nonce\n", Files.readString(run.resolve("worker.boot")))
                assertEquals(
                    setOf("runtime", "scratch", "tmp", "parent.start", "worker.boot", "worker.failure"),
                    Files.newDirectoryStream(run).use { stream -> stream.map { it.fileName.toString() }.toSet() },
                )
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS), "worker test child was not reaped")
                }
            }
        }
}

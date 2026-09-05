package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FullTreeWorkerFailureOwnershipTest {
    @Test
    fun `invalid START preserves parent runtime scratch and protocol evidence`() =
        assertFailurePreservesParentTree(validStart = false)

    @Test
    fun `failure after START preserves parent runtime scratch and protocol evidence`() =
        assertFailurePreservesParentTree(validStart = true)

    @Test
    fun `START may follow BOOT verification beyond the former thirty second window`() =
        assertFailurePreservesParentTree(validStart = true, startDelayMillis = 31_000L, maximumStartWaitSeconds = 45L)

    @Test
    fun `missing START expires within the supplied bound without deleting parent evidence`() =
        assertFailurePreservesParentTree(validStart = true, startDelayMillis = null, maximumStartWaitSeconds = 1L)

    @Test
    fun `legacy request without an explicit START bound is not silently upgraded`() =
        assertFailurePreservesParentTree(validStart = true, legacyRequest = true)

    @Test
    fun `admission shares the existing aggregate lifetime without enlarging it`() {
        assertEquals(361L, isolatedObservationServiceRuntimeSeconds(1L))
        assertEquals(1_560L, isolatedObservationServiceRuntimeSeconds(1_200L))
        assertEquals(2_160L, isolatedObservationServiceRuntimeSeconds(1_800L))
        listOf(0L, -1L, Long.MAX_VALUE, Long.MAX_VALUE / 1_000_000_000L).forEach { wallSeconds ->
            assertFailsWith<FullTreeFunctionObservationIsolationException> {
                isolatedObservationServiceRuntimeSeconds(wallSeconds)
            }
        }
    }

    @Test
    fun `START wait bounds reject noncanonical nonpositive and overflowing values`() {
        listOf("", "0", "-1", "+1", "01", " 1", "1 ", "1.0", "1e2", "1\n", Long.MAX_VALUE.toString(),
            "9223372036854775808", "9223372037").forEach { value ->
            assertFailsWith<FullTreeFunctionObservationIsolationException>(value) {
                parseIsolatedObservationStartWaitSeconds(value)
            }
        }
        assertEquals(1L, parseIsolatedObservationStartWaitSeconds("1"))
        assertEquals(1_560L, parseIsolatedObservationStartWaitSeconds("1560"))
    }

    private fun assertFailurePreservesParentTree(
        validStart: Boolean,
        startDelayMillis: Long? = 0L,
        maximumStartWaitSeconds: Long = 5L,
        legacyRequest: Boolean = false,
    ) =
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
            fun publishStart() {
                val pending = root.resolve("start.pending")
                Files.writeString(pending, if (validStart) "START\t1\t$nonce\n" else "INVALID\t1\t$nonce\n")
                Files.setPosixFilePermissions(pending, PosixFilePermissions.fromString("r--------"))
                Files.move(pending, start, StandardCopyOption.ATOMIC_MOVE)
            }
            if (startDelayMillis == 0L) publishStart()
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
                    FullTreeFunctionObservationIsolatedWorker::class.java.name,
                    if (legacyRequest) "1" else "2", nonce,
                ) + inputs.map(Path::toString) +
                listOf("clang-lib-driver", run.toString()) +
                if (legacyRequest) emptyList() else listOf(maximumStartWaitSeconds.toString())
            val process = ProcessBuilder(command).directory(run.toFile()).redirectErrorStream(true).apply {
                environment().clear()
                environment()["HOME"] = run.toString()
                environment()["TMPDIR"] = run.resolve("tmp").toString()
            }.start()
            try {
                process.outputStream.close()
                if (startDelayMillis != null && startDelayMillis > 0L) {
                    val bootDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10L)
                    while (!Files.exists(run.resolve("worker.boot")) && System.nanoTime() < bootDeadline && process.isAlive) {
                        Thread.sleep(20L)
                    }
                    assertTrue(Files.exists(run.resolve("worker.boot")), "worker did not publish BOOT")
                    Thread.sleep(startDelayMillis)
                    publishStart()
                }
                assertTrue(process.waitFor(15, TimeUnit.SECONDS), "worker failure exit exceeded its test bound")
                val output = process.inputStream.readNBytes(8193)
                assertTrue(output.size <= 8192)
                assertEquals(73, process.exitValue(), output.toString(Charsets.UTF_8))
                assertEquals("parent-owned authenticated runtime sentinel", Files.readString(parentRuntime))
                assertEquals(runtimeIdentity, Files.getAttribute(parentRuntime, "unix:ino"))
                assertEquals(PosixFilePermissions.fromString("r--------"), Files.getPosixFilePermissions(parentRuntime))
                assertEquals("partial scratch evidence", Files.readString(scratchEvidence))
                if (legacyRequest) {
                    assertTrue(Files.notExists(run.resolve("worker.boot")))
                    assertTrue(Files.notExists(run.resolve("worker.failure")))
                    assertEquals(
                        setOf("runtime", "scratch", "tmp", "parent.start"),
                        Files.newDirectoryStream(run).use { stream -> stream.map { it.fileName.toString() }.toSet() },
                    )
                    return@inControlTemporaryDirectory
                }
                val failure = Files.readString(run.resolve("worker.failure"))
                assertTrue(failure.startsWith("FAIL\t1\t$nonce\t"))
                if (startDelayMillis == null) {
                    assertTrue(failure.endsWith("\tisolated worker protocol parent.start timed out\n"), failure)
                } else if (validStart) {
                    assertTrue(failure.contains("FullTreeControlException"), failure)
                } else {
                    assertTrue(failure.endsWith("\tisolated worker protocol parent.start is invalid\n"), failure)
                }
                assertEquals("BOOT\t1\t$nonce\n", Files.readString(run.resolve("worker.boot")))
                assertEquals(
                    setOf("runtime", "scratch", "tmp", "worker.boot", "worker.failure") +
                        if (startDelayMillis == null) emptySet() else setOf("parent.start"),
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

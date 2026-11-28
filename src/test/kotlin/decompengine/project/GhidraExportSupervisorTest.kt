package decompengine.project

import decompengine.analysis.ExportSupervisorHelper
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Exports through the real built supervisor, authenticated as production authenticates it. */
class GhidraExportSupervisorTest {
    @Test
    fun `successful export gives leftovers SIGTERM then SIGKILL and records supervisor ownership`() =
        inControlTemporaryDirectory { root ->
            val input = root.resolve("input.bin")
            val inputBytes = "fixture executable bytes".toByteArray()
            Files.write(input, inputBytes)
            val modelBytes = RecoveredProgramModel(inputSha256 = sha256(inputBytes), functions = emptyList()).toJson().toByteArray()
            val polite = root.resolve("polite")
            val politeExited = root.resolve("polite-exited")
            val stubborn = root.resolve("stubborn")
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { invocation ->
                    val modelCandidate = Path.of(invocation.postScripts.single().arguments.last())
                    Files.write(modelCandidate, modelBytes)
                    Files.setPosixFilePermissions(modelCandidate, PosixFilePermissions.fromString("rw-------"))
                    // The worker succeeds but leaves one leftover that honours SIGTERM and one that ignores it.
                    // Each leftover installs its trap before the worker exits, so SIGTERM cannot arrive first.
                    listOf("/bin/sh", "-c",
                        "(trap 'touch \"$politeExited\"; exit 0' TERM; touch '$root/polite-ready'; while :; do sleep 0.05; done) & " +
                            "echo \$! > '$polite'; (trap '' TERM; touch '$root/stubborn-ready'; exec sleep 30) & " +
                            "echo \$! > '$stubborn'; while [ ! -e '$root/polite-ready' ] || [ ! -e '$root/stubborn-ready' ]; do sleep 0.01; done; exit 0")
                },
                limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(10), terminationGrace = Duration.ofMillis(300)),
            )

            val model = analyzer.analyze(input, root.resolve("analysis"))

            assertEquals(sha256(inputBytes), model.inputSha256)
            assertTrue(politeExited.exists(), "a leftover first receives SIGTERM")
            assertFalse(alive(pid(polite)))
            assertFalse(alive(pid(stubborn)), "a TERM-ignoring leftover is killed after the grace")
            val usage = Json.parseToJsonElement(root.resolve("analysis/reports/ghidra_resource_usage.json").readText()).jsonObject
            assertEquals("supervisor", usage.getValue("processOwnership").jsonPrimitive.content)
        }

    @Test
    fun `an unauthenticated supervisor fails the export before any worker starts`() {
        // Another program, and the real supervisor with one byte changed so only its digest differs.
        val genuine = Files.readAllBytes(ExportSupervisorHelper.verifiedDefaultArtifact())
        val tampered = genuine.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        for (impostorBytes in listOf(Files.readAllBytes(Path.of("/bin/true")), tampered)) refusesImpostor(impostorBytes)
    }

    private fun refusesImpostor(impostorBytes: ByteArray) = inControlTemporaryDirectory { root ->
        val impostor = Files.createDirectory(root.resolve("libexec")).resolve(ExportSupervisorHelper.BINARY_NAME)
        Files.write(impostor, impostorBytes)
        Files.setPosixFilePermissions(impostor, PosixFilePermissions.fromString("rwxr-xr-x"))
        val marker = root.resolve("worker-started")
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            { listOf("/bin/sh", "-c", "touch '$marker'") },
            GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { command, work ->
                startSupervisedExportProcess(ExportSupervisorHelper.commandAt(impostor, command, 0), work)
            },
        )

        val failure = assertFailsWith<Throwable> { analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis")) }

        assertTrue(generateSequence(failure) { it.cause }.any {
            it.message.orEmpty().contains("export supervisor does not match the defining application's build")
        }, failure.stackTraceToString())
        assertFalse(marker.exists(), "no worker may start under an unauthenticated supervisor")
    }

    @Test
    fun `the packaged supervisor authenticates from the development build`() {
        val helper = ExportSupervisorHelper.verifiedDefaultArtifact()
        assertEquals(ExportSupervisorHelper.BINARY_NAME, helper.fileName.toString())
        assertTrue(ExportSupervisorHelper.required("Linux"))
        assertFalse(ExportSupervisorHelper.required("Mac OS X"))
    }

    /** Run by verifyExportSupervisorInstalled against the installed application JAR and libexec helper. */
    object InstalledProbe {
        @JvmStatic fun main(arguments: Array<String>) {
            require(arguments.size == 1)
            val root = Path.of(arguments[0]).toAbsolutePath().normalize()
            require(root.startsWith(Path.of("").toAbsolutePath().normalize()))
            Files.createDirectories(root)
            require(System.getProperty(ExportSupervisorHelper.HELPER_PROPERTY) == null)
            val origin = Path.of(ExportSupervisorHelper::class.java.protectionDomain.codeSource.location.toURI()).toAbsolutePath().normalize()
            require(Files.isRegularFile(origin, LinkOption.NOFOLLOW_LINKS) && origin.fileName.toString().endsWith(".jar") &&
                origin.parent.fileName.toString() == "lib") { "probe requires the installed application JAR as its code origin" }
            val helper = ExportSupervisorHelper.verifiedDefaultArtifact()
            require(helper.parent == origin.parent.parent.resolve("libexec")) { "probe requires the installed default libexec supervisor" }
            val marker = root.resolve("installed-worker-ran")
            Files.deleteIfExists(marker)
            val supervisor = startSupervisedExportProcess(
                ExportSupervisorHelper.command(listOf("/bin/sh", "-c", "touch '$marker'"), 0), root,
            )
            supervisor.outputStream.write("1\n".toByteArray())
            supervisor.outputStream.flush()
            require(supervisor.waitFor(10, TimeUnit.SECONDS)) { "installed supervisor did not exit" }
            supervisor.outputStream.close()
            require(supervisor.exitValue() == 0 && marker.exists()) {
                "installed supervisor did not run its worker to completion (status ${supervisor.exitValue()})"
            }
            Files.delete(marker)
            println("installed export supervisor ${helper.fileName} authenticated and supervised a worker")
        }
    }

    private fun pid(file: Path): Long {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            if (file.exists()) file.readText().trim().toLongOrNull()?.let { return it }
            Thread.sleep(5)
        }
        error("no PID was written to $file")
    }

    private fun alive(pid: Long): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (!ProcessHandle.of(pid).map { it.isAlive }.orElse(false)) return false
            Thread.sleep(5)
        }
        return true
    }
}

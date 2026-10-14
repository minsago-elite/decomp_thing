package decompengine.analysis

import decompengine.project.sha256
import java.nio.file.Files
import java.nio.file.Path
import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.api.parallel.Resources

@ResourceLock(Resources.SYSTEM_PROPERTIES)
class BundledGhidraVerificationProcessTest {
    @Test
    fun `bounded verifier returns the authenticated sorted library inventory`() = withFixture { bundle ->
        val actual = BundledGhidraVerificationProcess().verifyAndGetLibraries(bundle.root) {}

        assertEquals(listOf(
            bundle.release.resolve("Ghidra/Features/Base/lib/Base.jar"),
            bundle.release.resolve("Ghidra/Features/Decompiler/lib/A.jar"),
            bundle.release.resolve("Ghidra/Features/DecompilerDependent/lib/B.jar"),
        ), actual)
    }

    @Test
    fun `default verifier forwards separated parent directories and preserves bounded JVM options`() = withFixture { bundle ->
        val workingDirectory = Path.of("").toAbsolutePath().normalize()
        val home = bundle.root.resolve("parent home = kept").createDirectories()
        val temporary = bundle.root.resolve("parent temp").createDirectories()
        val nativeTemporary = bundle.root.resolve("native temp").createDirectories()
        withParentDirectoryProperties(mapOf(
            "user.home" to home.toString(),
            "java.io.tmpdir" to workingDirectory.relativize(temporary).toString(),
            "jna.tmpdir" to nativeTemporary.toString(),
            "decompengine.unrelated.parent.property" to "not-forwarded",
        )) {
            val captured = CompletableFuture<List<String>>()
            val verifier = BundledGhidraVerificationProcess(processStarter = { command, root ->
                captured.complete(command)
                ProcessBuilder(command).directory(root.toFile()).start()
            })
            assertEquals(3, verifier.verifyAndGetLibraries(bundle.root) {}.size)
            val command = captured.get(1, TimeUnit.SECONDS)
            assertEquals(listOf(
                "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$nativeTemporary",
            ), command.filter { it.startsWith("-Duser.home=") || it.startsWith("-Djava.io.tmpdir=") || it.startsWith("-Djna.tmpdir=") })
            for (option in listOf("-Xmx256m", "-XX:MaxMetaspaceSize=128m", "-XX:+DisableAttachMechanism", "-XX:-UsePerfData")) {
                assertEquals(1, command.count { it == option })
            }
            assertFalse(command.any { it.contains("decompengine.unrelated.parent.property") || it.contains("not-forwarded") })
            assertEquals(bundle.root.toString(), command.last())
        }
    }

    @Test
    fun `default verifier omits absent JNA directory and rejects invalid directories before process launch`() = withFixture { bundle ->
        withParentDirectoryProperties(mapOf("jna.tmpdir" to null)) {
            val verifier = BundledGhidraVerificationProcess(processStarter = { command, root ->
                assertFalse(command.any { it.startsWith("-Djna.tmpdir=") })
                ProcessBuilder(command).directory(root.toFile()).start()
            })
            assertEquals(3, verifier.verifyAndGetLibraries(bundle.root) {}.size)
        }
        val invalidValues = listOf<String?>(null, "", " \t", "bad\npath", "bad\u0000path", "bad\u007fpath")
        for (name in listOf("user.home", "java.io.tmpdir", "jna.tmpdir")) {
            for (value in invalidValues.filterNot { name == "jna.tmpdir" && it == null }) {
                withParentDirectoryProperties(mapOf(name to value)) {
                    val verifier = BundledGhidraVerificationProcess(processStarter = { _, _ ->
                        throw AssertionError("invalid directory reached process launch")
                    })
                    val failure = assertFailsWith<IllegalArgumentException> { verifier.verifyAndGetLibraries(bundle.root) {} }
                    assertTrue(failure.message.orEmpty().contains(name), failure.message)
                }
            }
        }
    }

    @Test
    fun `shared deadline kills a blocked verifier process and reaps its child`() = withFixture { bundle ->
        val pidFile = bundle.root.resolve("verifier.pid")
        val deadline = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(250), "fixture verifier")
        val verifier = BundledGhidraVerificationProcess(commandFactory = {
            listOf(
                "/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10",
                "authored-verifier", pidFile.toString(),
            )
        })
        val started = System.nanoTime()

        val failure = assertFailsWith<GhidraAnalysisException> {
            verifier.verifyAndGetLibraries(bundle.root, deadline::checkpoint)
        }

        assertTrue(failure.message.orEmpty().contains("fixture verifier exceeded 250 milliseconds"))
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "blocked verifier outlived the shared deadline")
        assertTrue(pidFile.toFile().isFile, "blocked verifier did not record its owned child")
        val pid = pidFile.readText().trim().toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false), "verifier child is still alive")
    }

    @Test
    fun `shared deadline includes process launch and reaps a late worker`() = withFixture { bundle ->
        val releaseLaunch = CountDownLatch(1)
        val launched = CompletableFuture<Process>()
        val deadline = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(250), "fixture launch")
        val verifier = BundledGhidraVerificationProcess(
            commandFactory = { listOf("/bin/sleep", "10") },
            processStarter = { command, root ->
                check(releaseLaunch.await(5, TimeUnit.SECONDS))
                ProcessBuilder(command).directory(root.toFile()).start().also(launched::complete)
            },
        )
        val started = System.nanoTime()

        val failure = try {
            assertFailsWith<GhidraAnalysisException> {
                verifier.verifyAndGetLibraries(bundle.root, deadline::checkpoint)
            }
        } finally {
            releaseLaunch.countDown()
        }

        assertTrue(failure.message.orEmpty().contains("fixture launch exceeded 250 milliseconds"))
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "blocked launch outlived the shared deadline")
        val worker = launched.get(2, TimeUnit.SECONDS)
        worker.onExit().get(2, TimeUnit.SECONDS)
        assertFalse(worker.isAlive, "late verifier worker is still alive")
    }

    @Test
    fun `blocked launches exhaust only the dedicated bounded launch pool`() {
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val verifier = BundledGhidraVerificationProcess(
            commandFactory = { listOf("/bin/true") },
            processStarter = { _, _ ->
                entered.countDown()
                release.await(5, TimeUnit.SECONDS)
                throw IOException("fixture launch stopped")
            },
            maximumWallMillis = 250,
        )
        val callers = List(2) {
            Thread { runCatching { verifier.verifyAndGetLibraries(Path.of("/")) {} } }.apply { start() }
        }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS), "both launch slots were not occupied")
            val rejected = assertFailsWith<GhidraAnalysisException> {
                verifier.verifyAndGetLibraries(Path.of("/")) {}
            }
            assertTrue(rejected.message.orEmpty().contains("launch capacity is exhausted"))
        } finally {
            release.countDown()
            callers.forEach { caller ->
                caller.join(2_000)
                assertFalse(caller.isAlive, "fixture verification caller remained blocked")
            }
        }
    }

    @Test
    fun `capture saturation stops the owned verifier process`() = withFixture { bundle ->
        val limitedCapture = ThreadPoolExecutor(
            0, 1, 60L, TimeUnit.SECONDS, SynchronousQueue(),
            { task -> Thread(task, "fixture-verifier-capture").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        val launched = CompletableFuture<Process>()
        try {
            val verifier = BundledGhidraVerificationProcess(
                commandFactory = { listOf("/bin/sleep", "10") },
                processStarter = { command, root ->
                    ProcessBuilder(command).directory(root.toFile()).start().also(launched::complete)
                },
                captureExecutor = limitedCapture,
            )
            val failure = assertFailsWith<GhidraAnalysisException> {
                verifier.verifyAndGetLibraries(bundle.root) {}
            }
            assertTrue(failure.message.orEmpty().contains("capture capacity is exhausted"))
            val worker = launched.get(2, TimeUnit.SECONDS)
            assertFalse(worker.isAlive, "verifier worker survived rejected capture")
        } finally {
            limitedCapture.shutdownNow()
        }
    }

    @Test
    fun `inventory protocol rejects extra output and escaping paths`() = withFixture { bundle ->
        val header = "${BundledGhidraVerificationProcess.INVENTORY_PROVIDER}\n${BundledGhidra.VERSION}\n"
        val extraOutput = BundledGhidraVerificationProcess(commandFactory = {
            listOf("/usr/bin/printf", "${header}path/lib/a.jar\nextra\n")
        })
        val escapingPath = BundledGhidraVerificationProcess(commandFactory = {
            listOf("/usr/bin/printf", "${header}../lib/a.jar\n")
        })

        assertFailsWith<IllegalArgumentException> { extraOutput.verifyAndGetLibraries(bundle.root) {} }
        assertFailsWith<IllegalArgumentException> { escapingPath.verifyAndGetLibraries(bundle.root) {} }
    }

    private fun withFixture(block: (BundledGhidra) -> Unit) {
        val parent = Path.of("build/bundled-ghidra-directory-tests").toAbsolutePath().normalize().createDirectories()
        val root = createTempDirectory(parent, "bundled-ghidra-verifier-")
        try {
            val files = linkedMapOf(
                "decomp-ghidra-bridge.jar" to "bridge fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Base/lib/Base.jar" to "library fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Decompiler/lib/A.jar" to "first sorted fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/DecompilerDependent/lib/B.jar" to "second sorted fixture\n",
                "helpers/lib/Unrelated.jar" to "non-Ghidra fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/application.properties" to
                    "application.version=${BundledGhidra.VERSION}\napplication.release.name=PUBLIC\n",
            )
            files.forEach { (relative, content) ->
                root.resolve(relative).also { path ->
                    path.parent.createDirectories()
                    path.writeText(content)
                }
            }
            root.resolve("bundle.sha256").writeText(files.toSortedMap().entries.joinToString("") { (relative, content) ->
                "${sha256(content.toByteArray())}  $relative\n"
            })
            val home = root.resolve("home").createDirectories()
            val temporary = root.resolve("tmp").createDirectories()
            withParentDirectoryProperties(mapOf(
                "user.home" to home.toString(), "java.io.tmpdir" to temporary.toString(), "jna.tmpdir" to temporary.toString(),
            )) { block(BundledGhidra.at(root)) }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun withParentDirectoryProperties(values: Map<String, String?>, block: () -> Unit) {
        val previous = values.keys.associateWith(System::getProperty)
        try {
            values.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
            block()
        } finally {
            previous.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
        }
    }
}

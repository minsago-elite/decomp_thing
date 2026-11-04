package decompengine.project

import decompengine.analysis.GhidraInvocationTestProcess
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.stream.Stream
import kotlin.test.*
import kotlinx.serialization.json.*

/** All fixtures are synthetic; these controls cannot establish installed or native acceptance. */
class GhidraInvocationQualificationControlsTest {
    private val q = InvocationQualification
    private val one = InvocationQualification.Identity(101, "1")
    private val two = InvocationQualification.Identity(102, "2")

    @Test fun `installed probe classpath keeps whole test location after application jars`() {
        val repository = Path.of("").toAbsolutePath().normalize()
        val jars = listOf(repository.resolve("build/install/app/lib/app.jar"),
            repository.resolve("build/install/app/lib/dependency.jar"))
        val tests = Path.of(GhidraInstalledInvocationProbe::class.java.protectionDomain.codeSource.location.toURI())
        val entries = q.installedProbeClasspath(jars, tests).split(java.io.File.pathSeparator)
        assertEquals(jars.map { it.toString() } + listOf(tests.toString()), entries)
        assertEquals(tests.toString(), entries.last())
        assertEquals(3, entries.size)
    }

    @Test fun `complete inventory requires exactly one identity across every poll`() {
        val inventory = InvocationQualification.Inventory()
        inventory.poll(listOf(one, two)) { it == one }
        inventory.poll(listOf(one)) { true }
        inventory.finish()
        assertFails { InvocationQualification.Inventory().apply { poll(listOf(two)) { false }; finish() } }
        assertFails { InvocationQualification.Inventory().poll(listOf(one, two)) { true } }
        assertFails { InvocationQualification.Inventory().apply { poll(listOf(one)) { true }; poll(listOf(two)) { true } } }
        assertFails { InvocationQualification.Inventory().poll(List(257) { one }) { true } }
        assertFails { InvocationQualification.Inventory().poll(listOf(one)) { error("authored read failure") } }
        // PID reuse is a second identity too.
        assertFails { InvocationQualification.Inventory().apply {
            poll(listOf(one)) { true }; poll(listOf(one.copy(start = "3"))) { true }
        } }
    }

    @Test fun `private atomic evidence writer bounds bytes and preserves previous target`() = fixture { root ->
        val path = root.resolve("evidence.json")
        Files.writeString(path, "prior")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
        q.publish(path, byteArrayOf(1, 2, 3), 3)
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(path))
        assertFails { q.publish(path, byteArrayOf(1, 2, 3, 4), 3) }
        assertContentEquals(byteArrayOf(1, 2, 3), Files.readAllBytes(path))
        assertEquals(listOf("java", "argument"), q.command("java\u0000argument\u0000".toByteArray()))
        assertFails { q.command(byteArrayOf(0xC0.toByte(), 0xAF.toByte(), 0)) }
        assertFails { q.command("missing terminator".toByteArray()) }
        assertFails { q.bytes(ByteArrayInputStream(ByteArray(65537)), 65536) }
        assertEquals(65536, q.bytes(ByteArrayInputStream(ByteArray(65536)), 65536).size)
    }

    @Test fun `matching pins pass and missing changed or staged exporter pins refuse`() {
        val expected = buildJsonObject { put("app", "a"); put("bridge", "b"); put("manifest", "m"); put("exporter", "e") }
        q.verifyExporterBytes(byteArrayOf(1), byteArrayOf(1), byteArrayOf(1), byteArrayOf(1))
        assertFails { q.verifyExporterBytes(byteArrayOf(1), byteArrayOf(1), byteArrayOf(1), byteArrayOf(2)) }
        val matching = mapOf("app" to "a", "bridge" to "b", "manifest" to "m", "exporter" to "e")
        q.verifyPins(expected, matching)
        matching.keys.forEach { key ->
            assertFails { q.verifyPins(expected, matching - key) }
            assertFails { q.verifyPins(expected, matching + (key to "stale")) }
        }
    }

    private fun report() = buildJsonObject {
        put("schemaVersion", 2); put("analysisOutcome", "succeeded")
        put("invocation", buildJsonObject {
            put("status", "captured"); put("commandKind", "bundled-java"); put("processStarterKind", "default-process-builder")
            put("observation", "process-starter-returned-and-exit-value"); put("commandDisclosure", "qualified-worker-fields-only")
            put("analysisArgumentOffset", 2); put("exitCode", 0)
        })
    }
    @Test fun `schema offset main freshness outcome and dot diagnostics are required`() {
        val good = report()
        q.validateResult(good, listOf("main"), true, "authored bounded diagnostics")
        assertFails { q.validateResult(good, listOf("somethingElse"), true, "") }
        assertFails { q.validateResult(good, listOf("main"), false, "") }
        assertFails { q.validateResult(good, listOf("main"), true, "Path element starting with '.' is not permitted") }
        for ((key, wrong) in listOf("schemaVersion" to JsonPrimitive(1), "analysisOutcome" to JsonPrimitive("failed"))) {
            assertFails { q.validateResult(JsonObject(good + (key to wrong)), listOf("main"), true, "") }
        }
        for ((key, wrong) in listOf("analysisArgumentOffset" to JsonPrimitive(0), "exitCode" to JsonPrimitive(1),
            "observation" to JsonPrimitive("invented"), "processStarterKind" to JsonPrimitive("injected"))) {
            val invocation = JsonObject(good.getValue("invocation").jsonObject + (key to wrong))
            assertFails { q.validateResult(JsonObject(good + ("invocation" to invocation)), listOf("main"), true, "") }
        }
        assertFails { q.observedProject(listOf("release", "await-parent-launch", "analyze", "/wrong", "p", "i", "s"), 101) }
    }

    @Test fun `observer settlement requires acknowledgement and preserves primary failure`() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val observer = Thread {
            started.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(started.await(1, TimeUnit.SECONDS))
            val primary = IllegalStateException("authored primary")
            val failure = assertFailsWith<IllegalStateException> {
                q.owned(cleanup = { q.settle(observer, {}, 10) }) { throw primary }
            }
            assertSame(primary, failure)
            assertEquals(1, failure.suppressed.size)
        } finally { release.countDown(); q.settle(observer, {}) }
        assertFalse(observer.isAlive)
        val settled = Thread {}.apply { start() }
        q.settle(settled, {})
    }

    @Test fun `compiler ownership rejects timeout interruption overflow and unsettled descendants`() {
        class ControlledProcess(val interrupt: Boolean = false, val hang: Boolean = false, val overflow: Boolean = false) : Process() {
            var killed = false
            private val stream = ByteArrayInputStream(ByteArray(if (overflow) 65537 else 0))
            override fun getInputStream() = stream
            override fun getErrorStream() = ByteArrayInputStream(byteArrayOf())
            override fun getOutputStream() = java.io.ByteArrayOutputStream()
            override fun isAlive() = hang && !killed
            override fun destroy() { killed = true }
            override fun destroyForcibly(): Process { killed = true; return this }
            override fun exitValue() = 0
            override fun waitFor() = 0
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                if (interrupt && !killed) throw InterruptedException("authored interruption")
                return !isAlive
            }
        }
        for (process in listOf(ControlledProcess(hang = true), ControlledProcess(interrupt = true), ControlledProcess(overflow = true))) {
            assertFails { q.runOwned(process, { emptyList() }, 10, cleanupMillis = 100) }
            assertTrue(process.killed)
        }
        val childAlive = AtomicBoolean(true)
        val base = GhidraInvocationTestProcess().toHandle()
        val child = object : ProcessHandle by base {
            override fun isAlive() = childAlive.get()
            override fun destroyForcibly(): Boolean { childAlive.set(false); return true }
        }
        q.runOwned(ControlledProcess(), { if (childAlive.get()) listOf(child) else emptyList() }, 1000)
        assertFalse(childAlive.get(), "surviving descendant must be killed even after its parent exits")
        val stubborn = object : ProcessHandle by base {
            override fun isAlive() = true
            override fun destroyForcibly() = false
        }
        assertFails { q.runOwned(ControlledProcess(), { listOf(stubborn) }, 1000, cleanupMillis = 10) }
        assertFails { q.runOwned(ControlledProcess(), { error("authored inventory iteration failure") }, 1000, cleanupMillis = 10) }
    }

    private fun fixture(body: (Path) -> Unit) {
        val parent = Path.of("build/orchestration/ghidra-invocation-remediation/pure-fixtures")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "control-")
        try { body(root) } finally { root.toFile().deleteRecursively() }
    }
}

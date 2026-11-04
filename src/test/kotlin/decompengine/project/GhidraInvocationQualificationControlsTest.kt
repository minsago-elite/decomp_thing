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

    @Test fun `child failures retain only fixed phase category and numeric source anchors`() = fixture { root ->
        val canary = "SECRET_CANARY_COMMAND_TOKEN_RAW_GHIDRA_MESSAGE"
        val original = IllegalStateException(canary)
        val record = q.childFailure(InvocationQualification.Phase.RESULT_VALIDATION, original)
        val path = root.resolve("child-failure.json")
        q.publishFailure(path, record, original)
        val bytes = Files.readAllBytes(path)
        assertTrue(bytes.size <= InvocationQualification.FAILURE_RECORD_LIMIT)
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(path))
        assertContains(bytes.toString(Charsets.UTF_8), "result_validation")
        assertContains(bytes.toString(Charsets.UTF_8), "assertion")
        assertFalse(bytes.toString(Charsets.UTF_8).contains(canary))
        val decoded = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        assertEquals("unknown", decoded.getValue("cleanup").jsonPrimitive.content)
        assertTrue(decoded.getValue("sourceAnchors").jsonArray.all {
            val anchor = it.jsonObject
            anchor.getValue("file").jsonPrimitive.content in setOf(
                "GhidraInvocationQualificationSupport.kt", "GhidraDotDirectoryInvocationQualificationTest.kt") &&
                anchor.getValue("line").jsonPrimitive.int in 1..10000
        })
        val failedPublication = IllegalStateException(canary)
        q.publishFailure(root, record, failedPublication) // directory target refuses replacement
        assertTrue(failedPublication.suppressed.single().message == "Invocation qualification diagnostic publication failed")
        assertFalse(failedPublication.suppressed.single().message!!.contains(canary))
        assertFalse(Files.exists(root.resolve("provenance.json")), "failure must not synthesize success provenance")
    }

    @Test fun `outer process failure facts are bounded and preserve original when sink fails`() {
        class Finished(private val code: Int, private val stream: java.io.InputStream = ByteArrayInputStream(byteArrayOf())) : Process() {
            override fun getInputStream() = stream
            override fun getErrorStream(): java.io.InputStream = ByteArrayInputStream(byteArrayOf())
            override fun getOutputStream(): java.io.OutputStream = java.io.ByteArrayOutputStream()
            override fun isAlive() = false
            override fun destroy() {}
            override fun destroyForcibly(): Process = this
            override fun exitValue() = code
            override fun waitFor() = code
            override fun waitFor(timeout: Long, unit: TimeUnit) = true
        }
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val original = assertFails {
            q.runOwned(Finished(7), { emptyList() }, 100, diagnosticSink = facts::add)
        }
        assertEquals(1, facts.size)
        assertEquals("abnormal_exit", facts.single().category.wire)
        assertEquals(7, facts.single().exitCode)
        assertTrue(facts.single().readerSettled)
        assertTrue(facts.single().processSettled && facts.single().descendantsSettled)
        assertEquals(0, facts.single().capturedBytes)
        assertNotNull(facts.single().capturedSha256)
        val successFacts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        assertContentEquals(byteArrayOf(1, 2), q.runOwned(Finished(0, ByteArrayInputStream(byteArrayOf(1, 2))),
            { emptyList() }, 100, diagnosticSink = successFacts::add))
        assertTrue(successFacts.isEmpty(), "success leaves the existing success path intact")
        val readerFacts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val canary = "PRIVATE_READER_FAILURE_CANARY"
        val badStream = object : java.io.InputStream() { override fun read(): Int = throw java.io.IOException(canary) }
        assertFails { q.runOwned(Finished(0, badStream), { emptyList() }, 100, diagnosticSink = readerFacts::add) }
        assertEquals("reader_failure", readerFacts.single().category.wire)
        assertFalse(readerFacts.single().json().toString().contains(canary))
        val injectedPrimary = IllegalStateException("ORIGINAL_FAILURE_CANARY")
        val sinkPrimary = assertFailsWith<IllegalStateException> {
            q.runOwned(Finished(0), { emptyList() }, 100, failure = java.util.concurrent.atomic.AtomicReference(injectedPrimary),
                reader = Thread {}, diagnosticSink = { error("SINK_FAILURE_CANARY") })
        }
        assertSame(injectedPrimary, sinkPrimary, "evidence failure must not replace the original throwable")
        assertTrue(sinkPrimary.suppressed.single().message == "Invocation qualification diagnostic publication failed")
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
            override fun getErrorStream(): java.io.InputStream = ByteArrayInputStream(byteArrayOf())
            override fun getOutputStream(): java.io.OutputStream = java.io.ByteArrayOutputStream()
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
        for ((process, expected) in listOf(ControlledProcess(hang = true) to "timeout",
            ControlledProcess(interrupt = true) to "interrupted")) {
            val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
            assertFails { q.runOwned(process, { emptyList() }, 10, cleanupMillis = 100, diagnosticSink = facts::add) }
            if (expected == "interrupted") assertTrue(Thread.interrupted(), "caller interrupt status restored")
            assertTrue(process.killed)
            assertEquals(expected, facts.single().category.wire, facts.single().toString())
            assertTrue(facts.single().readerSettled && facts.single().processSettled && facts.single().descendantsSettled)
            if (expected == "output_bound") {
                assertEquals(65536, facts.single().capturedBytes)
                assertEquals(64, facts.single().capturedSha256?.length)
            }
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
        val cleanupFacts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        assertFails { q.runOwned(ControlledProcess(), { listOf(stubborn) }, 1000, cleanupMillis = 10,
            diagnosticSink = cleanupFacts::add) }
        assertEquals("cleanup_failure", cleanupFacts.single().category.wire)
        assertFalse(cleanupFacts.single().descendantsSettled, "a failed cleanup is never reported settled")
        assertFails { q.runOwned(ControlledProcess(), { error("authored inventory iteration failure") }, 1000, cleanupMillis = 10) }
    }

    private open class Synthetic(
        private val input: java.io.InputStream = ByteArrayInputStream(byteArrayOf()), private val code: Int = 0,
    ) : Process() {
        var killed = false
        override fun getInputStream() = input
        override fun getErrorStream(): java.io.InputStream = ByteArrayInputStream(byteArrayOf())
        override fun getOutputStream(): java.io.OutputStream = java.io.ByteArrayOutputStream()
        override fun isAlive() = false
        override fun destroy() { killed = true }
        override fun destroyForcibly(): Process { killed = true; return this }
        override fun exitValue() = code
        override fun waitFor() = code
        override fun waitFor(timeout: Long, unit: TimeUnit) = true
    }
    private fun failureOf(process: Process): Pair<Throwable, InvocationQualification.ProcessDiagnostic> {
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val thrown = assertFails { q.runOwned(process, { emptyList() }, 2000, diagnosticSink = facts::add) }
        return thrown to facts.single()
    }

    @Test fun `wire values preserve nonnull exit digest and unavailable capture`() {
        val (_, observed) = failureOf(Synthetic(ByteArrayInputStream(byteArrayOf()), 7))
        val wire = Json.parseToJsonElement(observed.json().toString()).jsonObject
        assertEquals(7, wire.getValue("exitCode").jsonPrimitive.int)
        assertEquals(0, wire.getValue("capturedBytes").jsonPrimitive.int)
        assertEquals(q.digest(byteArrayOf()), wire.getValue("capturedSha256").jsonPrimitive.content)
        val getter = java.io.IOException("SECRET_GETTER")
        val (_, unavailable) = failureOf(object : Synthetic() {
            override fun getInputStream(): java.io.InputStream = throw getter
            override fun exitValue(): Int = throw IllegalThreadStateException()
        })
        val unknown = Json.parseToJsonElement(unavailable.json().toString()).jsonObject
        listOf("exitCode", "capturedBytes", "capturedSha256").forEach { assertEquals(JsonNull, unknown[it]) }
        assertFalse(unknown.toString().contains("SECRET"))
    }

    @Test fun `incremental capture retains prefix on read failure and exact bound`() {
        val supplied = byteArrayOf(10, 20, 30)
        val original = java.io.IOException("PRIVATE_PREFIX")
        var delivered = false
        val partial = object : java.io.InputStream() {
            override fun read(): Int = error("bulk only")
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (delivered) throw original
                delivered = true; supplied.copyInto(b, off); return supplied.size
            }
        }
        val (thrown, facts) = failureOf(Synthetic(partial))
        assertSame(original, thrown)
        assertEquals(3, facts.capturedBytes); assertEquals(q.digest(supplied), facts.capturedSha256)
        assertEquals("reader_failure", facts.primaryCategory?.wire)
        val exact = ByteArray(65536) { (it % 251).toByte() }
        val (_, bounded) = failureOf(Synthetic(ByteArrayInputStream(exact), 7))
        assertEquals(exact.size, bounded.capturedBytes); assertEquals(q.digest(exact), bounded.capturedSha256)
    }

    @Test fun `overflow has its own reader handshake and full allowance`() {
        val sentinel = CountDownLatch(1)
        val bytes = ByteArray(65537) { (it % 251).toByte() }
        val input = object : ByteArrayInputStream(bytes) {
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val n = super.read(b, off, len)
                if (available() == 0) sentinel.countDown()
                return n
            }
        }
        val process = object : Synthetic(input) {
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                assertTrue(sentinel.await(1, TimeUnit.SECONDS)); return true
            }
        }
        val (_, facts) = failureOf(process)
        assertEquals("output_bound", facts.category.wire)
        assertEquals(65536, facts.capturedBytes)
        assertEquals(q.digest(bytes.copyOf(65536)), facts.json().getValue("capturedSha256").jsonPrimitive.content)
        assertFalse(facts.cleanupFailure)
    }

    @Test fun `late overflow cannot rewrite established reader deadline failure`() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val readDone = CountDownLatch(1)
        val stream = object : ByteArrayInputStream(ByteArray(65537)) {
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                entered.countDown(); assertTrue(release.await(2, TimeUnit.SECONDS))
                val n = super.read(b, off, len)
                if (available() == 0) readDone.countDown()
                return n
            }
        }
        val process = object : Synthetic(stream) {
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                assertTrue(entered.await(1, TimeUnit.SECONDS)); return true
            }
            override fun destroyForcibly(): Process {
                release.countDown(); assertTrue(readDone.await(1, TimeUnit.SECONDS)); return super.destroyForcibly()
            }
        }
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        try {
            assertFails { q.runOwned(process, { emptyList() }, 100, cleanupMillis = 1000, diagnosticSink = facts::add) }
            assertEquals("assertion", facts.single().primaryCategory?.wire)
            assertEquals(65536, facts.single().capturedBytes)
            assertTrue(facts.single().readerSettled)
        } finally { release.countDown() }
    }

    @Test fun `failure publisher refuses existing files symlinks and oversize privately`() = fixture { root ->
        val original = IllegalStateException("PRIVATE_ORIGINAL")
        val record = q.childFailure(InvocationQualification.Phase.INPUT_COMPILE, original)
        val target = root.resolve("record.json")
        q.writeFailure(target, record)
        val before = Files.readAllBytes(target)
        q.publishFailure(target, record, original)
        assertContentEquals(before, Files.readAllBytes(target))
        val link = Files.createSymbolicLink(root.resolve("link.json"), target)
        q.publishFailure(link, record, original)
        assertTrue(Files.isSymbolicLink(link)); assertContentEquals(before, Files.readAllBytes(target))
        val large = buildJsonObject { put("padding", "x".repeat(4096)) }
        q.publishFailure(root.resolve("large.json"), large, original)
        assertFalse(Files.exists(root.resolve("large.json")))
        assertEquals(3, original.suppressed.size)
        assertTrue(original.suppressed.all { it.message == "Invocation qualification diagnostic publication failed" })
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target))
        assertEquals("unknown", record.getValue("cleanup").jsonPrimitive.content)
    }

    @Test fun `cleanup facts ignore unrelated suppression and preserve independent results`() {
        val primary = IllegalStateException("PRIVATE_PRIMARY").apply { addSuppressed(java.io.IOException("unrelated")) }
        var calls = 0
        val process = object : Synthetic() {
            override fun waitFor(timeout: Long, unit: TimeUnit) = killed
            override fun isAlive() = !killed
        }
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        assertSame(primary, assertFails { q.runOwned(process, {
            if (++calls == 1) throw primary else emptyList()
        }, 2000, diagnosticSink = facts::add) })
        val observed = facts.single()
        assertFalse(observed.cleanupFailure); assertEquals("assertion", observed.primaryCategory?.wire)
        listOf(observed.processCleanup, observed.descendantCleanup, observed.readerCleanup,
            observed.closerCleanup, observed.inputCleanup, observed.errorCleanup, observed.outputCleanup).forEach {
            assertTrue(it.attempted && it.acknowledged && it.succeeded == true)
        }
        val enumError = java.io.IOException("PRIVATE_ENUMERATION")
        val failed = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        assertSame(enumError, assertFails { q.runOwned(Synthetic(), { throw enumError }, 2000, diagnosticSink = failed::add) })
        assertTrue(failed.single().processSettled); assertFalse(failed.single().descendantsSettled)
        assertEquals(false, failed.single().descendantCleanup.succeeded)
        assertTrue(failed.single().closerCleanup.succeeded == true)
        assertEquals(null, failed.single().primaryCategory)
        assertEquals("cleanup_failure", failed.single().category.wire)
    }

    @Test fun `failed final descendant inventory invalidates earlier settlement`() {
        for (bodyFails in listOf(false, true)) {
            val original = java.io.IOException("PRIVATE_BODY")
            val inventoryError = java.io.IOException("PRIVATE_FINAL_INVENTORY")
            val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
            var calls = 0
            val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
            if (bodyFails) failure.set(original)
            val thrown = assertFails {
                q.runOwned(Synthetic(), {
                    if (++calls == 1) emptyList() else throw inventoryError
                }, 2000, failure = failure, diagnosticSink = facts::add)
            }
            assertEquals(2, calls)
            val observed = facts.single()
            assertFalse(observed.descendantsSettled)
            assertTrue(observed.descendantCleanup.attempted)
            assertTrue(observed.descendantCleanup.acknowledged)
            assertEquals(false, observed.descendantCleanup.succeeded)
            assertTrue(observed.cleanupFailure)
            assertTrue(observed.processSettled)
            assertTrue(observed.readerSettled)
            assertEquals(true, observed.closerCleanup.succeeded)
            if (bodyFails) {
                assertSame(original, thrown)
                assertTrue(thrown.suppressed.any { it === inventoryError })
                assertEquals("reader_failure", observed.primaryCategory?.wire)
            } else {
                assertSame(inventoryError, thrown)
                assertEquals(null, observed.primaryCategory)
                assertEquals("cleanup_failure", observed.category.wire)
            }
        }
    }

    @Test fun `closer catches each getter and close and preserves original error`() {
        for (badIndex in 0..2) for (failGetter in listOf(false, true)) {
            val original = java.io.IOException("PRIVATE_CLOSE")
            val acquired = BooleanArray(3); val closed = BooleanArray(3)
            var inputReads = 0
            val process = object : Synthetic() {
                fun get(index: Int): java.io.InputStream {
                    acquired[index] = true
                    if (badIndex == index && failGetter) throw original
                    return object : ByteArrayInputStream(byteArrayOf()) {
                        override fun close() { closed[index] = true; if (badIndex == index) throw original }
                    }
                }
                override fun getInputStream(): java.io.InputStream =
                    if (++inputReads == 1) ByteArrayInputStream(byteArrayOf()) else get(0)
                override fun getErrorStream() = get(1)
                override fun getOutputStream(): java.io.OutputStream {
                    acquired[2] = true
                    if (badIndex == 2 && failGetter) throw original
                    return object : java.io.ByteArrayOutputStream() {
                        override fun close() { closed[2] = true; if (badIndex == 2) throw original }
                    }
                }
            }
            val (thrown, facts) = failureOf(process)
            assertSame(original, thrown); assertTrue(acquired.all { it })
            assertTrue(closed.indices.filter { it != badIndex }.all { closed[it] })
            assertTrue(facts.cleanupFailure); assertEquals("cleanup_failure", facts.category.wire)
            assertNull(facts.primaryCategory)
            assertTrue(facts.closerCleanup.acknowledged); assertEquals(false, facts.closerCleanup.succeeded)
            assertTrue(facts.readerSettled && facts.processSettled && facts.descendantsSettled)
        }
    }

    @Test fun `setup start and post acquisition failures retain ownership and safe diagnostics`() = fixture { root ->
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val notDirectory = root.resolve("not-directory"); Files.writeString(notDirectory, "x")
        var starts = 0
        assertFails { q.run(listOf("PRIVATE_COMMAND"), notDirectory, 1, diagnosticSink = facts::add,
            starter = { starts++; error("must not start") }) }
        assertEquals(0, starts); assertFalse(facts.single().processAcquired)
        assertEquals("setup", facts.single().phase.wire); assertNull(facts.single().capturedBytes)
        val startError = java.io.IOException("PRIVATE_START")
        facts.clear()
        assertSame(startError, assertFails { q.run(listOf("PRIVATE_COMMAND"), root, 1, diagnosticSink = facts::add,
            starter = { starts++; throw startError }) })
        assertEquals("process_start", facts.single().phase.wire)
        assertFalse(facts.single().processCleanup.attempted)
        assertEquals(JsonNull, facts.single().json()["exitCode"])
        val postError = java.io.IOException("PRIVATE_PID")
        val process = object : Synthetic() { override fun pid(): Long = throw postError }
        facts.clear()
        assertSame(postError, assertFails { q.run(listOf("PRIVATE_COMMAND"), root, 1, diagnosticSink = facts::add,
            starter = { process }, memberSource = { emptyList() }) })
        assertTrue(process.killed); assertTrue(facts.single().processSettled)
        assertFalse(facts.single().readerCleanup.attempted); assertNull(facts.single().capturedBytes)
        assertTrue(facts.single().closerCleanup.succeeded == true)
        val setupError = java.io.IOException("PRIVATE_SETUP")
        q.setupFailure(setupError, InvocationQualification.Phase.SETUP) { error("PRIVATE_SINK") }
        assertEquals("Invocation qualification diagnostic publication failed", setupError.suppressed.single().message)
        facts.forEach { assertFalse(it.json().toString().contains("PRIVATE")) }
    }

    @Test fun `actual wait interruption preserves throwable and restores caller status after cleanup`() {
        val entered = CountDownLatch(1)
        val caught = java.util.concurrent.atomic.AtomicReference<InterruptedException>()
        val returned = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val restored = AtomicBoolean()
        val process = object : Synthetic() {
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                if (killed) return true
                entered.countDown()
                try { CountDownLatch(1).await() }
                catch (problem: InterruptedException) { caught.set(problem); throw problem }
                return false
            }
        }
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val caller = Thread {
            try { q.runOwned(process, { emptyList() }, 2000, diagnosticSink = facts::add) }
            catch (problem: Throwable) { returned.set(problem); restored.set(Thread.currentThread().isInterrupted) }
            finally { Thread.interrupted() }
        }
        try {
            caller.start(); assertTrue(entered.await(1, TimeUnit.SECONDS)); caller.interrupt(); caller.join(3000)
            assertFalse(caller.isAlive); assertNotNull(caught.get()); assertSame(caught.get(), returned.get())
            assertTrue(restored.get()); assertTrue(process.killed)
            assertEquals("interrupted", facts.single().primaryCategory?.wire)
            assertTrue(facts.single().readerSettled && facts.single().closerCleanup.succeeded == true)
        } finally { caller.interrupt(); caller.join(3000) }
        assertFalse(caller.isAlive)
    }

    @Test fun `unacknowledged reader and closer cannot report successful cleanup`() {
        for (blockedCloser in listOf(false, true)) {
            val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
            fun block() {
                entered.countDown()
                try { while (release.count > 0) try { release.await() } catch (_: InterruptedException) {} }
                finally { done.countDown() }
            }
            val stream = object : java.io.InputStream() {
                override fun read(): Int { if (!blockedCloser) block(); return -1 }
                override fun close() { if (blockedCloser) block() }
            }
            val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
            try {
                assertFails { q.runOwned(Synthetic(stream), { emptyList() }, 100, cleanupMillis = 100,
                    diagnosticSink = facts::add) }
                assertEquals(0L, entered.count)
                val fact = if (blockedCloser) facts.single().closerCleanup else facts.single().readerCleanup
                assertTrue(fact.attempted); assertFalse(fact.acknowledged); assertTrue(facts.single().cleanupFailure)
            } finally {
                release.countDown(); assertTrue(done.await(1, TimeUnit.SECONDS))
                // Join the actual owned threads after releasing the synthetic stubborn operation.
                Thread.getAllStackTraces().keys.filter {
                    it.name in setOf("invocation-controlled-capture", "invocation-stream-close")
                }.forEach { it.join(2000); assertFalse(it.isAlive) }
            }
        }
    }

    @Test fun `process reap failure does not erase descendant reader or closer success`() {
        val original = java.io.IOException("PRIVATE_REAP")
        val process = object : Synthetic() {
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                if (killed) throw original
                return true
            }
        }
        val (thrown, facts) = failureOf(process)
        assertSame(original, thrown)
        assertTrue(facts.processCleanup.attempted && facts.processCleanup.acknowledged)
        assertEquals(false, facts.processCleanup.succeeded); assertFalse(facts.processSettled)
        assertTrue(facts.descendantCleanup.succeeded == true && facts.descendantsSettled)
        assertTrue(facts.readerCleanup.succeeded == true && facts.closerCleanup.succeeded == true)
        assertTrue(facts.cleanupFailure); assertNull(facts.primaryCategory)
    }

    @Test fun `reader join interruption retains captured prefix and restores status`() {
        val processWait = CountDownLatch(1); val readerBlocked = CountDownLatch(1); val release = CountDownLatch(1)
        val returned = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val restored = AtomicBoolean(); var supplied = false
        val stream = object : java.io.InputStream() {
            override fun read(): Int = error("bulk only")
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (!supplied) { supplied = true; b[off] = 42; return 1 }
                readerBlocked.countDown(); assertTrue(release.await(2, TimeUnit.SECONDS)); return -1
            }
        }
        val process = object : Synthetic(stream) {
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                if (!killed) { assertTrue(readerBlocked.await(1, TimeUnit.SECONDS)); processWait.countDown() }
                return true
            }
            override fun destroyForcibly(): Process { release.countDown(); return super.destroyForcibly() }
        }
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        val caller = Thread {
            try { q.runOwned(process, { emptyList() }, 2000, diagnosticSink = facts::add) }
            catch (problem: Throwable) { returned.set(problem); restored.set(Thread.currentThread().isInterrupted) }
            finally { Thread.interrupted() }
        }
        try {
            caller.start(); assertTrue(processWait.await(1, TimeUnit.SECONDS)); caller.interrupt(); caller.join(3000)
            assertFalse(caller.isAlive); assertTrue(returned.get() is InterruptedException); assertTrue(restored.get())
            assertEquals("interrupted", facts.single().primaryCategory?.wire)
            assertEquals(1, facts.single().capturedBytes); assertEquals(q.digest(byteArrayOf(42)), facts.single().capturedSha256)
            assertTrue(facts.single().readerSettled && facts.single().closerCleanup.succeeded == true)
        } finally { release.countDown(); caller.interrupt(); caller.join(3000) }
        assertFalse(caller.isAlive)
    }

    @Test fun `inventory failure still destroys retained synthetic descendants`() {
        val base = GhidraInvocationTestProcess().toHandle()
        val alive = AtomicBoolean(true)
        val retained = object : ProcessHandle by base {
            override fun isAlive() = alive.get()
            override fun destroyForcibly(): Boolean { alive.set(false); return true }
        }
        val original = java.io.IOException("PRIVATE_INVENTORY")
        val facts = mutableListOf<InvocationQualification.ProcessDiagnostic>()
        assertSame(original, assertFails { q.runOwned(Synthetic(), { throw original }, 2000,
            retainedMembers = { listOf(retained) }, diagnosticSink = facts::add) })
        assertFalse(alive.get()); assertTrue(facts.single().processSettled)
        assertFalse(facts.single().descendantsSettled); assertEquals(false, facts.single().descendantCleanup.succeeded)
    }

    private fun fixture(body: (Path) -> Unit) {
        val parent = Path.of("build/orchestration/ghidra-invocation-failure-remediation/pure-fixtures")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "control-")
        try { body(root) } finally { root.toFile().deleteRecursively() }
    }
}

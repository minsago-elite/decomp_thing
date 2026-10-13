package decompengine.analysis

import decompengine.project.ProgramModelJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileTime
import java.security.MessageDigest
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Tests use a benign child for blocked native I/O, never a production-worker test mode. */
class BoundedProgramModelAcquisitionProcessTest {
    @Test
    fun `actual bounded helper preserves canonical bytes at the exact model and 64MiB resident bounds`() = fixture { f ->
        val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = (0 until 256).map { index ->
            RecoveredFunction("fn_$index", "fixture_$index", 0x401000UL + index.toULong() * 16UL,
                "int fixture_$index(void)", "int fixture_$index(void) { return $index; }\n")
        })
        val bytes = model.toJson().toByteArray()
        assertTrue(bytes.size > 64 * 1024, "must cross a bounded acquisition chunk")
        Files.write(f.model, bytes)
        val acquired = f.reader().read(f.model, f.root, bytes.size.toLong(), RESIDENT_BYTES, deadline(5_000))
        assertContentEquals(bytes, acquired)
        assertEquals(model, ProgramModelJson.readCanonical(acquired))
        assertContentEquals(bytes, Files.readAllBytes(f.model), "acquisition must preserve the authored canonical model")
        assertContentEquals(PRIOR_REPORT, Files.readAllBytes(f.report))
        f.assertReleased()
    }

    @Test
    fun `real FIFO native read is killed at the shared deadline with previous evidence preserved`() = fixture { f ->
        f.fifo()
        val call = f.call(f.reader("fifo"), 1_500)
        f.assertNativePipeRead()
        call.join()
        assertTrue(call.failure.get() is GhidraAnalysisException, "shared deadline must reject blocked model I/O")
        f.assertChildAbsent()
        f.assertReleased()
        f.assertPriorEvidence()
    }

    @Test
    fun `partial frame followed by real FIFO native read is discarded on timeout`() = fixture { f ->
        f.fifo()
        val call = f.call(f.reader("partial-fifo"), 1_500)
        f.assertNativePipeRead()
        call.join()
        assertTrue(call.failure.get() is GhidraAnalysisException)
        assertEquals(null, call.result.get(), "partial model must never become an admitted result")
        f.assertChildAbsent()
        f.assertReleased()
        f.assertPriorEvidence()
    }

    @Test
    fun `caller cancellation kills real native FIFO read and remains an interruption`() = fixture { f ->
        f.fifo()
        val call = f.call(f.reader("fifo"), 10_000)
        f.assertNativePipeRead()
        val interruptedAt = System.nanoTime()
        call.thread.interrupt()
        call.join()
        assertTrue(System.nanoTime() - interruptedAt < TimeUnit.MILLISECONDS.toNanos(1_500),
            "cancellation must return within the single 1s cleanup allowance plus 500ms scheduling tolerance")
        assertTrue(call.failure.get() is InterruptedException, "caller cancellation must keep its classification")
        f.assertChildAbsent()
        f.assertReleased()
        f.assertPriorEvidence()
    }

    @Test
    fun `descendant holding framed output open is killed with its observed parent lineage`() = fixture { f ->
        f.fifo()
        val call = f.call(f.reader("descendant-fifo"), 1_500)
        f.assertNativePipeRead()
        awaitCondition(1_000, "benign parent did not finish its valid frame") { Files.exists(f.root.resolve("parent.ready")) }
        call.join()
        assertTrue(call.failure.get() is GhidraAnalysisException, "a valid frame with an open inherited pipe is not a finished result")
        assertEquals(null, call.result.get())
        f.assertChildAbsent()
        val parentPid = Files.readString(f.root.resolve("parent.pid")).toLong()
        assertFalse(ProcessHandle.of(parentPid).map { it.isAlive }.orElse(false))
        f.assertReleased()
        f.assertPriorEvidence()
    }

    @Test
    fun `late launch retains ownership and refuses capacity until its real child exits`() = fixture { f ->
        f.fifo()
        val releaseLaunch = CountDownLatch(1)
        val started = CompletableFuture<Process>()
        val launches = AtomicInteger()
        val reader = f.reader("fifo", cleanupMillis = 150, starter = { command, work ->
            launches.incrementAndGet()
            f.start(command, work).also {
                started.complete(it)
                awaitIgnoringInterrupts(releaseLaunch)
            }
        })
        val call = f.call(reader, 700)
        val process = started.get(2, TimeUnit.SECONDS)
        try {
            f.assertNativePipeRead()
            call.join()
            assertTrue(call.failure.get() is GhidraAnalysisException)
            assertTrue(process.isAlive, "the withheld handle must still be owned as an unresolved launch")
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
            assertEquals(1, launches.get(), "unconfirmed cleanup must refuse another launch")
        } finally {
            releaseLaunch.countDown()
        }
        f.assertChildAbsent()
        f.assertReleased()
        f.assertPriorEvidence()
    }

    @Test
    fun `failed process termination retains ownership and refuses another invocation`() = fixture { f ->
        f.fifo()
        val realProcess = AtomicReference<Process?>()
        val reader = f.reader("fifo", cleanupMillis = 100, starter = { command, work ->
            val child = f.start(command, work).also(realProcess::set)
            val handle = object : ProcessHandle by child.toHandle() {
                override fun destroyForcibly(): Boolean = false
            }
            ProcessView(child, handle = handle)
        })
        val call = f.call(reader, 700)
        f.assertNativePipeRead()
        try {
            call.join()
            assertTrue(call.failure.get() is GhidraAnalysisException)
            assertTrue(assertNotNull(realProcess.get()).isAlive)
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
        } finally {
            realProcess.get()?.toHandle()?.destroyForcibly()
        }
        f.assertChildAbsent()
        f.assertReleased()
    }

    @Test
    fun `starter throwing after creating a real PID retains unknown launch ownership and refuses capacity`() = fixture { f ->
        f.fifo()
        val child = AtomicReference<Process?>()
        val starts = AtomicInteger()
        val reader = f.reader("fifo", cleanupMillis = 100, starter = { command, work ->
            starts.incrementAndGet()
            child.set(f.start(command, work))
            throw java.io.IOException("fixture starter lost its native launch result")
        })
        assertFailsWith<java.io.IOException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
        try {
            f.assertNativePipeRead()
            assertTrue(assertNotNull(child.get()).isAlive)
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
            assertEquals(1, starts.get(), "a starter exception cannot prove native launch absence")
        } finally {
            child.get()?.toHandle()?.destroyForcibly()
        }
        f.assertChildAbsent()
        assertEquals(1, f.ownership.retainedInvocations(), "test-only knowledge of a PID cannot settle production's unknown handle")
        f.assertPriorEvidence()
    }

    @Test
    fun `blocked host capture is retained after child exit until its actual finally completes`() = fixture { f ->
        val releaseRead = CountDownLatch(1)
        val enteredRead = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val stream = object : InputStream() {
            override fun read(): Int {
                enteredRead.countDown()
                awaitIgnoringInterrupts(releaseRead)
                return -1
            }
            override fun close() { closed.set(true) }
        }
        val reader = f.reader("valid", cleanupMillis = 100, starter = { _, work ->
            ProcessView(f.start(listOf("/usr/bin/true"), work), stdout = stream)
        })
        val call = f.call(reader, 400)
        assertTrue(enteredRead.await(2, TimeUnit.SECONDS))
        try {
            call.join()
            assertTrue(call.failure.get() is GhidraAnalysisException)
            assertFalse(closed.get(), "the caller must not synchronously close a blocked capture")
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
        } finally {
            releaseRead.countDown()
        }
        f.assertReleased()
        assertTrue(closed.get(), "actual capture completion must acknowledge stream close")
    }

    @Test
    fun `a failed stream close retains its strong stream reference and refuses capacity`() = fixture { f ->
        val closeAttempted = AtomicBoolean(false)
        val reader = f.reader("valid", cleanupMillis = 100, starter = { command, work ->
            val child = f.start(command, work)
            val stream = object : FilterInputStream(child.inputStream) {
                override fun close() {
                    closeAttempted.set(true)
                    super.close()
                    throw java.io.IOException("fixture cannot acknowledge stream closure")
                }
            }
            ProcessView(child, stdout = stream)
        })
        assertFailsWith<IllegalArgumentException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000))
        }
        assertTrue(closeAttempted.get())
        assertEquals(1, f.ownership.retainedInvocations())
        assertFailsWith<IllegalArgumentException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
    }

    @Test
    fun `controller observation failure still stops known real PID and retains incomplete inventory`() = fixture { f ->
        f.fifo()
        val stopAttempted = AtomicBoolean(false)
        val child = AtomicReference<Process?>()
        val reader = f.reader("fifo", cleanupMillis = 100, starter = { command, work ->
            val real = f.start(command, work).also(child::set)
            val handle = object : ProcessHandle by real.toHandle() {
                override fun descendants(): java.util.stream.Stream<ProcessHandle> =
                    throw java.io.IOException("fixture descendant observation failed")
                override fun destroyForcibly(): Boolean {
                    stopAttempted.set(true)
                    return real.toHandle().destroyForcibly()
                }
            }
            ProcessView(real, handle = handle)
        })
        val started = System.nanoTime()
        val failure = assertFailsWith<Exception> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000))
        }
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "controller failure must surface without waiting for its original deadline")
        assertTrue(stopAttempted.get(), "incomplete observation must not skip known-root termination")
        awaitCondition(2_000, "known real root remains alive after failed inventory observation") { !assertNotNull(child.get()).isAlive }
        assertTrue(throwables(failure).any { it.message.orEmpty().contains("fixture descendant observation failed") },
            "the controller failure must remain observable")
        assertEquals(1, f.ownership.retainedInvocations(), "root death cannot prove the incomplete descendant inventory absent")
        assertFailsWith<IllegalArgumentException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
        f.assertPriorEvidence()
    }

    @Test
    fun `stdin close failure after real helper exit is surfaced and retains closure ownership`() = fixture { f ->
        val closeAttempted = AtomicBoolean(false)
        val reader = f.reader("valid", cleanupMillis = 100, starter = { command, work ->
            val child = f.start(command, work)
            val stdin = object : FilterOutputStream(child.outputStream) {
                override fun close() {
                    closeAttempted.set(true)
                    super.close()
                    throw java.io.IOException("fixture stdin closure was not acknowledged")
                }
            }
            ProcessView(child, stdin = stdin)
        })
        val failure = assertFailsWith<java.io.IOException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000))
        }
        assertTrue(closeAttempted.get())
        assertTrue(failure.message.orEmpty().contains("fixture stdin closure was not acknowledged"))
        f.assertChildAbsent()
        assertEquals(1, f.ownership.retainedInvocations())
        assertFailsWith<IllegalArgumentException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
        f.assertPriorEvidence()
    }

    @Test
    fun `first and second capture admission rejection release only unadmitted jobs and allow later reads`() {
        for (rejectAt in listOf(1, 2)) fixture { f ->
            val submissions = AtomicInteger()
            val starts = AtomicInteger()
            val rejecting = Executor { runnable ->
                if (submissions.incrementAndGet() == rejectAt) throw RejectedExecutionException("fixture rejection")
                f.capture.execute(runnable)
            }
            val reader = f.reader("valid", capture = rejecting, starter = { command, work ->
                starts.incrementAndGet(); f.start(command, work)
            })
            assertFailsWith<GhidraAnalysisException>("capture rejection $rejectAt") {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
            assertEquals(0, starts.get())
            f.assertReleased()
            assertContentEquals(WORKER_BYTES, f.reader("valid").read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000)))
            f.assertReleased()
        }
    }

    @Test
    fun `launch executor rejection releases preadmitted capture jobs and permits a later read`() = fixture { f ->
        val starts = AtomicInteger()
        val reader = f.reader("valid", launch = BoundedAnalysisProcessLaunch(Executor {
            throw RejectedExecutionException("fixture launch rejection")
        }), starter = { command, work -> starts.incrementAndGet(); f.start(command, work) })
        assertFailsWith<GhidraAnalysisException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
        assertEquals(0, starts.get())
        f.assertReleased()
        assertContentEquals(WORKER_BYTES, f.reader("valid").read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000)))
        f.assertReleased()
    }

    @Test
    fun `actual shared two-slot launch saturation rejects without leaking admitted model ownership`() = fixture { f ->
        val shared = ANALYSIS_PROCESS_LAUNCH_EXECUTOR as ThreadPoolExecutor
        awaitCondition(2_000, "shared launch executor has earlier active work") { shared.activeCount == 0 }
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val starts = AtomicInteger()
        val reader = f.reader("valid", launch = BoundedAnalysisProcessLaunch(), starter = { command, work ->
            starts.incrementAndGet(); f.start(command, work)
        })
        try {
            repeat(2) {
                shared.execute { entered.countDown(); awaitIgnoringInterrupts(release) }
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS), "both actual global launch slots must be occupied")
            assertEquals(2, shared.activeCount)
            assertFailsWith<GhidraAnalysisException> {
                reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
            }
            assertEquals(0, starts.get(), "capacity rejection must not call the native starter")
            f.assertReleased()
        } finally {
            release.countDown()
        }
        awaitCondition(2_000, "shared launch slots did not finish their actual tasks") { shared.activeCount == 0 }
        assertContentEquals(WORKER_BYTES, reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000)))
        assertEquals(1, starts.get())
        f.assertReleased()
    }

    @Test
    fun `deadline consumed after capture admission rejects launcher checkpoint and releases ownership`() = fixture { f ->
        val submissions = AtomicInteger()
        val starts = AtomicInteger()
        val capture = Executor { runnable ->
            f.capture.execute(runnable)
            if (submissions.incrementAndGet() == 2) {
                Thread.sleep(150) // Admission expiry fixture only; native-I/O tests use real child FIFO reads.
            }
        }
        val reader = f.reader("valid", capture = capture, starter = { command, work ->
            starts.incrementAndGet(); f.start(command, work)
        })
        val failure = assertFailsWith<GhidraAnalysisException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(100))
        }
        assertEquals(2, submissions.get(), "both captures must be admitted before the launcher deadline gate")
        assertTrue(failure.message.orEmpty().contains("before admitting export process launch"))
        assertEquals(0, starts.get())
        f.assertReleased()
        assertContentEquals(WORKER_BYTES, f.reader("valid").read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000)))
        f.assertReleased()
    }

    @Test
    fun `control admission rejection releases captures before any process is started`() = fixture { f ->
        val starts = AtomicInteger()
        val reader = f.reader("valid", control = Executor {
            throw RejectedExecutionException("fixture control rejection")
        }, starter = { command, work -> starts.incrementAndGet(); f.start(command, work) })
        assertFailsWith<GhidraAnalysisException> {
            reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(1_000))
        }
        assertEquals(0, starts.get())
        f.assertReleased()
        assertContentEquals(WORKER_BYTES, f.reader("valid").read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000)))
        f.assertReleased()
    }

    @Test
    fun `frame failures reject digest truncation trailing bytes output overflow and nonzero exit`() {
        val modes = listOf("bad-magic", "oversize", "bad-digest", "trailing", "truncated", "bad-footer", "nonzero", "diagnostic-overflow")
        for (mode in modes) fixture { f ->
            assertFailsWith<IllegalArgumentException>(mode) {
                f.reader(mode).read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, deadline(3_000))
            }
            f.assertChildAbsent()
            f.assertReleased()
            f.assertPriorEvidence()
        }
    }

    @Test
    fun `actual worker rejects empty oversized symlink and nonregular model inputs without changing evidence`() = fixture { f ->
        val cases = listOf(
            f.root.resolve("empty").also { Files.write(it, byteArrayOf()) } to MAX_BYTES,
            f.root.resolve("oversized").also { Files.write(it, ByteArray(17)) } to 16L,
            f.root.resolve("symlink").also { Files.createSymbolicLink(it, f.model.fileName) } to MAX_BYTES,
            f.root.resolve("directory").also { Files.createDirectory(it) } to MAX_BYTES,
        )
        for ((path, maximum) in cases) {
            assertFailsWith<IllegalArgumentException>(path.fileName.toString()) {
                f.reader().read(path, f.root, maximum, RESIDENT_BYTES, deadline(3_000))
            }
            f.assertReleased()
        }
        f.assertPriorEvidence()
    }

    @Test
    fun `already consumed deadline and invalid byte budgets reject before any launch`() = fixture { f ->
        val starts = AtomicInteger()
        val reader = f.reader("valid", starter = { command, work -> starts.incrementAndGet(); f.start(command, work) })
        val expired = deadline(1)
        Thread.sleep(5) // Deadline fixture only; blocked-I/O tests use an actual child FIFO read.
        assertFailsWith<GhidraAnalysisException> { reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES, expired) }
        assertFailsWith<IllegalArgumentException> { reader.read(f.model, f.root, MAX_BYTES, RESIDENT_BYTES - 1, deadline(500)) }
        assertFailsWith<IllegalArgumentException> {
            reader.read(f.model, f.root, BoundedProgramModelAcquisitionProcess.MAXIMUM_MODEL_BYTES + 1, RESIDENT_BYTES, deadline(500))
        }
        assertEquals(0, starts.get())
        f.assertReleased()
    }

    @Test
    fun `worker terminal stability rejects replacement growth shrink and same-size mutation`() {
        for (mutation in listOf("replace", "grow", "shrink", "modify")) fixture { f ->
            val bytes = ByteArray(3 * 64 * 1024) { (it % 251).toByte() }
            Files.write(f.model, bytes)
            val beforeTime = Files.getLastModifiedTime(f.model)
            var checkpoints = 0
            val outputBytes = ByteArrayOutputStream()
            assertFailsWith<IllegalArgumentException>(mutation) {
                BoundedProgramModelAcquisitionWorker.writeStableModel(f.model, MAX_BYTES, DataOutputStream(outputBytes)) {
                    if (++checkpoints == 3) when (mutation) {
                        "replace" -> {
                            val replacement = f.root.resolve("replacement")
                            Files.write(replacement, bytes)
                            Files.setLastModifiedTime(replacement, beforeTime)
                            Files.move(replacement, f.model, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                        }
                        "grow" -> Files.write(f.model, byteArrayOf(1), StandardOpenOption.APPEND)
                        "shrink" -> FileChannel.open(f.model, StandardOpenOption.WRITE).use { it.truncate(10) }
                        "modify" -> {
                            FileChannel.open(f.model, StandardOpenOption.WRITE).use { it.write(ByteBuffer.wrap(byteArrayOf(99)), 64 * 1024L) }
                            Files.setLastModifiedTime(f.model, FileTime.fromMillis(beforeTime.toMillis() + 2_000))
                        }
                    }
                }
            }
            assertFalse(outputBytes.toByteArray().takeLast(36).take(4).toByteArray().contentEquals(byteArrayOf(0x45, 0x4e, 0x44, 0x4d)),
                "a rejected snapshot must not carry the terminal model commitment")
        }
    }

    @Test
    fun `worker streams exact bytes and digest with bounded chunks without writing model or report`() = fixture { f ->
        val bytes = ByteArray(3 * 64 * 1024 + 19) { (it % 251).toByte() }
        Files.write(f.model, bytes)
        val output = ByteArrayOutputStream()
        var checkpoints = 0
        BoundedProgramModelAcquisitionWorker.writeStableModel(f.model, bytes.size.toLong(), DataOutputStream(output)) { checkpoints++ }
        val input = java.io.DataInputStream(output.toByteArray().inputStream())
        assertEquals(FRAME_MAGIC, input.readInt()); assertEquals(1, input.readInt()); assertEquals(bytes.size.toLong(), input.readLong())
        assertContentEquals(bytes, input.readNBytes(bytes.size))
        assertEquals(FRAME_END, input.readInt())
        assertContentEquals(MessageDigest.getInstance("SHA-256").digest(bytes), input.readNBytes(32))
        assertEquals(-1, input.read())
        assertTrue(checkpoints >= 7)
        assertContentEquals(bytes, Files.readAllBytes(f.model))
        assertContentEquals(PRIOR_REPORT, Files.readAllBytes(f.report))
    }

    private fun fixture(test: (AcquisitionFixture) -> Unit) {
        val parent = Path.of("build", "model-acquisition-test-fixtures").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val f = AcquisitionFixture(Files.createTempDirectory(parent, "fixture-"))
        try { test(f) } finally { f.close() }
    }

    private class AcquisitionFixture(val root: Path) : AutoCloseable {
        val model = root.resolve("model.json")
        val report = root.resolve("prior-report.json")
        val pidFile = root.resolve("worker.pid")
        val fifoPath = root.resolve("blocked-model.fifo")
        val ownership = ProgramModelAcquisitionOwnership(1)
        val capture = pool(4, "fixture-model-capture")
        val control = pool(2, "fixture-model-control")
        val launches = pool(2, "fixture-model-launch")
        private val launch = BoundedAnalysisProcessLaunch(launches)
        private val processes = java.util.concurrent.CopyOnWriteArrayList<Process>()
        init { Files.write(model, PRIOR_MODEL); Files.write(report, PRIOR_REPORT) }

        fun reader(mode: String? = null, cleanupMillis: Long = 1_000, capture: Executor = this.capture,
            control: Executor = this.control, launch: BoundedAnalysisProcessLaunch = this.launch,
            starter: (List<String>, Path) -> Process = ::start): BoundedProgramModelAcquisitionProcess =
            if (mode == null) BoundedProgramModelAcquisitionProcess(processStarter = starter, ownership = ownership,
                captureExecutor = capture, controlExecutor = control, launch = launch, cleanupMillis = cleanupMillis)
            else BoundedProgramModelAcquisitionProcess(commandFactory = { _, _, _, _ -> workerCommand(root, mode) },
                processStarter = starter, ownership = ownership, captureExecutor = capture, controlExecutor = control,
                launch = launch, cleanupMillis = cleanupMillis)

        fun start(command: List<String>, work: Path): Process = ProcessBuilder(command).directory(work.toFile()).apply {
            listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH").forEach(environment()::remove)
            environment()["TMPDIR"] = root.toString(); environment()["HOME"] = root.toString()
        }.start().also(processes::add)

        fun fifo() {
            val process = start(listOf("/usr/bin/mkfifo", fifoPath.toString()), root)
            assertTrue(process.waitFor(2, TimeUnit.SECONDS)); assertEquals(0, process.exitValue())
        }

        fun call(reader: BoundedProgramModelAcquisitionProcess, allowanceMillis: Long): AcquisitionCall {
            val result = AtomicReference<ByteArray?>()
            val failure = AtomicReference<Throwable?>()
            val started = System.nanoTime()
            val thread = Thread {
                try { result.set(reader.read(model, root, MAX_BYTES, RESIDENT_BYTES, deadline(allowanceMillis))) }
                catch (caught: Throwable) { failure.set(caught) }
            }.apply { isDaemon = true; start() }
            return AcquisitionCall(thread, result, failure, started, allowanceMillis)
        }

        fun assertNativePipeRead() {
            awaitCondition(2_000, "the benign JVM never reached native FIFO read") {
                if (!Files.exists(pidFile)) false else {
                    val pid = Files.readString(pidFile).trim().toLongOrNull()
                    if (pid == null) false else {
                        val tasks = Path.of("/proc", pid.toString(), "task")
                        if (!Files.isDirectory(tasks)) false else Files.list(tasks).use { tids ->
                            tids.anyMatch { tid -> runCatching { Files.readString(tid.resolve("wchan")).contains("pipe_read") }.getOrDefault(false) }
                        }
                    }
                }
            }
        }

        fun assertChildAbsent() {
            val pid = if (Files.exists(pidFile)) Files.readString(pidFile).trim().toLong() else null
            awaitCondition(3_000, "helper PID remains alive after owned cleanup") {
                (pid == null || ProcessHandle.of(pid).map { !it.isAlive }.orElse(true)) && processes.none { it.isAlive }
            }
        }

        fun assertReleased() = awaitCondition(3_000, "actual launch, process, capture and control ownership was not released") {
            ownership.retainedInvocations() == 0 && capture.activeCount == 0 && control.activeCount == 0 && launches.activeCount == 0
        }
        fun assertPriorEvidence() {
            assertContentEquals(PRIOR_MODEL, Files.readAllBytes(model))
            assertContentEquals(PRIOR_REPORT, Files.readAllBytes(report))
        }
        override fun close() {
            if (Files.exists(pidFile)) Files.readString(pidFile).trim().toLongOrNull()?.let { pid ->
                ProcessHandle.of(pid).ifPresent { if (it.isAlive) it.destroyForcibly() }
            }
            processes.forEach { if (it.isAlive) it.toHandle().destroyForcibly() }
            processes.forEach { it.waitFor(2, TimeUnit.SECONDS) }
            capture.shutdownNow(); control.shutdownNow(); launches.shutdownNow()
            capture.awaitTermination(2, TimeUnit.SECONDS); control.awaitTermination(2, TimeUnit.SECONDS); launches.awaitTermination(2, TimeUnit.SECONDS)
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private class AcquisitionCall(val thread: Thread, val result: AtomicReference<ByteArray?>,
        val failure: AtomicReference<Throwable?>, private val started: Long, private val allowanceMillis: Long) {
        fun join() {
            thread.join(allowanceMillis + 2_000)
            assertFalse(thread.isAlive, "model acquisition caller outlived the single cleanup allowance")
            assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(allowanceMillis + 1_500),
                "caller used a renewed deadline or unbounded cleanup")
        }
    }

    private class ProcessView(private val child: Process, private val stdout: InputStream = child.inputStream,
        private val stdin: OutputStream = child.outputStream,
        private val handle: ProcessHandle = child.toHandle()) : Process() {
        override fun getOutputStream(): OutputStream = stdin
        override fun getInputStream(): InputStream = stdout
        override fun getErrorStream(): InputStream = child.errorStream
        override fun waitFor(): Int = child.waitFor()
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = child.waitFor(timeout, unit)
        override fun exitValue(): Int = child.exitValue()
        override fun destroy() { child.destroy() }
        override fun destroyForcibly(): Process { child.destroyForcibly(); return this }
        override fun isAlive(): Boolean = child.isAlive
        override fun toHandle(): ProcessHandle = handle
    }
}

/** Only the test classpath exposes scenarios; the production worker has no test controls. */
internal object ModelAcquisitionBenignTestWorker {
    @JvmStatic fun main(arguments: Array<String>) {
        val mode = arguments[0]
        val root = Path.of(arguments[1])
        val output = DataOutputStream(System.out)
        if (mode == "fifo" || mode == "partial-fifo") {
            FileChannel.open(root.resolve("blocked-model.fifo"), StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
                Files.writeString(root.resolve("worker.pid"), ProcessHandle.current().pid().toString())
                if (mode == "partial-fifo") {
                    output.writeInt(FRAME_MAGIC); output.writeInt(1); output.writeLong(4); output.writeByte(1); output.flush()
                }
                channel.read(ByteBuffer.allocate(1)) // Actual native pipe read, with no writer supplying bytes.
            }
            return
        }
        if (mode == "descendant-fifo") {
            Files.writeString(root.resolve("parent.pid"), ProcessHandle.current().pid().toString())
            ProcessBuilder(workerCommand(root, "fifo")).directory(root.toFile()).inheritIO().start()
            val limit = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (!Files.exists(root.resolve("worker.pid")) && System.nanoTime() < limit) Thread.sleep(5)
            require(Files.exists(root.resolve("worker.pid")))
            output.writeInt(FRAME_MAGIC); output.writeInt(1); output.writeLong(WORKER_BYTES.size.toLong())
            output.write(WORKER_BYTES); output.writeInt(FRAME_END)
            output.write(MessageDigest.getInstance("SHA-256").digest(WORKER_BYTES)); output.flush()
            Files.writeString(root.resolve("parent.ready"), "frame complete")
            Thread.sleep(200) // Discovery window only; actual descendant pipe read holds the EOF open.
            return
        }
        Files.writeString(root.resolve("worker.pid"), ProcessHandle.current().pid().toString())
        if (mode == "diagnostic-overflow") { System.err.write(ByteArray(64 * 1024 + 1)); System.err.flush() }
        output.writeInt(if (mode == "bad-magic") 0 else FRAME_MAGIC); output.writeInt(1)
        output.writeLong(if (mode == "oversize") Long.MAX_VALUE else WORKER_BYTES.size.toLong())
        if (mode == "truncated") { output.write(WORKER_BYTES, 0, 2); output.flush(); return }
        output.write(WORKER_BYTES)
        output.writeInt(if (mode == "bad-footer") 0 else FRAME_END)
        output.write(if (mode == "bad-digest") ByteArray(32) else MessageDigest.getInstance("SHA-256").digest(WORKER_BYTES))
        if (mode == "trailing") output.writeByte(1)
        output.flush()
        if (mode == "nonzero") kotlin.system.exitProcess(7)
    }
}

private const val FRAME_MAGIC = 0x4d4f444c
private const val FRAME_END = 0x454e444d
private const val MAX_BYTES = 2L * 1024 * 1024
private const val RESIDENT_BYTES = 64L * 1024 * 1024
private val WORKER_BYTES = "benign model byte fixture\n".toByteArray()
private val PRIOR_MODEL = "previous canonical model evidence\n".toByteArray()
private val PRIOR_REPORT = "previous report evidence\n".toByteArray()
private fun deadline(milliseconds: Long): AnalysisDeadline = AnalysisDeadline.start(
    TimeUnit.MILLISECONDS.toNanos(milliseconds), "model acquisition fixture",
)
private fun pool(threads: Int, name: String): ThreadPoolExecutor = ThreadPoolExecutor(
    0, threads, 60, TimeUnit.SECONDS, SynchronousQueue(),
    { runnable -> Thread(runnable, name).apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy(),
)
private fun workerCommand(root: Path, mode: String): List<String> {
    val javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java").toString()
    val classpath = listOf(ModelAcquisitionBenignTestWorker::class.java, Unit::class.java)
        .map { Path.of(it.protectionDomain.codeSource.location.toURI()).toString() }.distinct().joinToString(java.io.File.pathSeparator)
    return listOf(javaExecutable, "-Xms8m", "-Xmx32m", "-XX:-UsePerfData", "-XX:+DisableAttachMechanism",
        "-Djava.io.tmpdir=$root", "-Djna.tmpdir=$root", "-Duser.home=$root", "-cp", classpath,
        ModelAcquisitionBenignTestWorker::class.java.name, mode, root.toString())
}
private fun awaitCondition(milliseconds: Long, message: String, condition: () -> Boolean) {
    val limit = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(milliseconds)
    while (!condition() && System.nanoTime() < limit) Thread.sleep(10)
    assertTrue(condition(), message)
}
private fun awaitIgnoringInterrupts(latch: CountDownLatch) {
    while (true) try { latch.await(); return } catch (_: InterruptedException) { }
}
private fun throwables(root: Throwable): List<Throwable> {
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
    fun visit(value: Throwable): List<Throwable> = if (!seen.add(value)) emptyList() else
        listOf(value) + (value.cause?.let(::visit) ?: emptyList()) + value.suppressed.flatMap(::visit)
    return visit(root)
}

package decompengine.analysis

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Pipe writes are native; their candidate creation proof is injected separately from close/delete seams. */
class BoundedAnalysisArtifactStagingProcessTest {
    @Test
    fun `ZipFS report parent is refused before admission without converting provider text to a host path`() = fixture { f ->
        val archive = f.root.resolve("provider-path.zip")
        val hostParent = f.root.resolve("provider-shadow")
        val hostTarget = hostParent.resolve("analysis-report.json")
        val admissions = AtomicInteger()
        val checkpoints = AtomicInteger()
        val commands = AtomicInteger()
        val renders = AtomicInteger()
        val refusal = Executor { admissions.incrementAndGet(); throw RejectedExecutionException("provider path reached admission") }
        val stager = f.stager(capture = refusal, transfer = refusal, control = refusal,
            launch = BoundedAnalysisProcessLaunch(refusal), command = { _, _ -> commands.incrementAndGet(); listOf("/bin/true") })
        assertFalse(Files.exists(hostParent, LinkOption.NOFOLLOW_LINKS))
        FileSystems.newFileSystem(archive, mapOf("create" to "true")).use { zip ->
            // An erroneous host-path conversion is confined to this repository-owned fixture.
            val parent = zip.getPath(hostParent.toString()).toAbsolutePath().normalize()
            assertEquals(hostParent, Path.of(parent.toString()))
            assertTrue(hostParent.startsWith(f.root))
            val prior = parent.resolve("analysis-report.json")
            Files.createDirectories(parent)
            Files.write(prior, PRIOR_STAGING_REPORT, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            val failure = assertFailsWith<IllegalArgumentException> {
                stager.withStagedReport(parent, REPORT_BYTES.size.toLong(), checkpoint = { checkpoints.incrementAndGet() },
                    render = { renders.incrementAndGet(); it.write(REPORT_BYTES) }, publish = f::publish)
            }
            assertTrue(failure.message.orEmpty().contains("requires the default filesystem"))
            assertContentEquals(PRIOR_STAGING_REPORT, Files.readAllBytes(prior))
            Files.list(parent).use { paths ->
                assertEquals(listOf("analysis-report.json"), paths.map { it.fileName.toString() }.toList(),
                    "provider refusal must not create a private candidate inside the ZIP")
            }
        }
        assertEquals(0, checkpoints.get(), "provider refusal must precede the first checkpoint")
        assertEquals(0, admissions.get())
        assertEquals(0, commands.get())
        assertEquals(0, renders.get())
        assertEquals(0, f.starts.get())
        assertEquals(0, f.ownership.retainedInvocations())
        assertFalse(Files.exists(hostParent, LinkOption.NOFOLLOW_LINKS), "provider text must not create a host directory or candidates")
        assertFalse(Files.exists(hostTarget, LinkOption.NOFOLLOW_LINKS))
        f.assertReleased()
        f.assertUnpublished()
        f.assertNoCandidates()
    }

    @Test
    fun `actual fixed helper preserves supplied symlink dotdot parent traversal when staging and publishing`() = fixture { f ->
        val outer = Files.createDirectory(f.root.resolve("outer"))
        val target = Files.createDirectory(f.root.resolve("target"))
        val child = Files.createDirectory(target.resolve("child"))
        val link = Files.createSymbolicLink(outer.resolve("link"), child)
        val suppliedParent = link.resolve("..")
        val targetReport = target.resolve("analysis-report.json")
        val outerReport = outer.resolve("analysis-report.json")
        val outerPrior = "{\"prior\":\"lexical outer report\"}\n".toByteArray()
        Files.write(targetReport, PRIOR_STAGING_REPORT, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        Files.write(outerReport, outerPrior, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        assertEquals(outer, suppliedParent.normalize())
        assertTrue(Files.isSameFile(suppliedParent, target), "the real symlink followed by dotdot must traverse to target")
        f.stager().withStagedReport(suppliedParent, REPORT_BYTES.size.toLong(), stagingDeadline(5_000)::checkpoint,
            render = { it.write(REPORT_BYTES) }, publish = { staged ->
                f.published.incrementAndGet()
                val physicalCandidate = target.resolve(staged.fileName.toString())
                assertEquals(suppliedParent, staged.parent)
                assertTrue(Files.isSameFile(staged, physicalCandidate))
                assertFalse(Files.exists(outer.resolve(staged.fileName.toString()), LinkOption.NOFOLLOW_LINKS),
                    "candidate creation must preserve the supplied filesystem traversal")
                assertContentEquals(REPORT_BYTES, Files.readAllBytes(physicalCandidate))
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(physicalCandidate))
                assertContentEquals(PRIOR_STAGING_REPORT, Files.readAllBytes(targetReport))
                assertContentEquals(outerPrior, Files.readAllBytes(outerReport))
                Files.move(staged, suppliedParent.resolve("analysis-report.json"),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            })
        assertEquals(1, f.published.get())
        assertContentEquals(REPORT_BYTES, Files.readAllBytes(targetReport))
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(targetReport))
        assertContentEquals(outerPrior, Files.readAllBytes(outerReport))
        f.assertPriorReport()
        f.assertChildAbsent()
        f.assertReleased()
        for (directory in listOf(outer, target)) Files.list(directory).use { paths ->
            assertFalse(paths.anyMatch { it.fileName.toString().startsWith(".json-report-stage-") },
                "private candidate remains after normal publication in $directory")
        }
        f.assertNoCandidates()
    }

    @Test
    fun `actual fixed helper stages exact bounded bytes privately before caller publication`() = fixture { f ->
        val report = authoredReport(128 * 1024 + 19)
        f.stager().withStagedReport(f.root, report.size.toLong(), stagingDeadline(5_000)::checkpoint,
            render = { it.write(report) }, publish = { staged ->
                f.published.incrementAndGet()
                f.assertPriorReport()
                assertContentEquals(report, Files.readAllBytes(staged))
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(staged))
                assertTrue(staged.parent == f.root && staged.fileName.toString().startsWith(".json-report-stage-"))
                assertTrue(f.processes.none { it.isAlive }, "a receipt must arrive after the fixed helper exits and closes staging")
                Files.move(staged, f.report, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            })
        assertEquals(1, f.published.get())
        assertContentEquals(report, Files.readAllBytes(f.report))
        f.assertReleased()
        f.assertNoCandidates()
    }

    @Test
    fun `actual fixed helper cannot publish refused rendering or an exceeded report allowance`() {
        for (overflow in listOf(false, true)) fixture { f ->
            val report = authoredReport(32 * 1024)
            val refusal = IOException("authored report rendering refused")
            val failure = assertFailsWith<Exception> {
                f.stager().withStagedReport(f.root, if (overflow) report.size.toLong() - 1 else report.size.toLong(),
                    stagingDeadline(5_000)::checkpoint, render = {
                        it.write(report)
                        if (!overflow) throw refusal
                    }, publish = f::publish)
            }
            if (overflow) assertTrue(failure is IllegalArgumentException) else assertSame(refusal, failure)
            f.assertChildAbsent()
            f.assertUnpublished()
            f.assertReleased()
            f.assertNoCandidates()
        }
    }

    @Test
    fun `actual native stdin backpressure with injected creation proof times out and kills its PID`() = fixture { f ->
        val call = f.call(f.sleepStager(), 1_500)
        f.assertNativePipeWrites(1)
        call.join()
        assertTrue(call.failure.get() is GhidraAnalysisException, "the original shared deadline must reject native pipe backpressure")
        assertFalse(call.renderFinished.get(), "the bounded render queue must not consume the entire MiB input")
        f.assertChildAbsent()
        f.assertReleased()
        f.assertUnpublished()
        f.assertNoCandidates()
    }

    @Test
    fun `actual native stdin backpressure with injected creation proof keeps cancellation and kills its PID`() = fixture { f ->
        val call = f.call(f.sleepStager(), 10_000)
        f.assertNativePipeWrites(1)
        val cancelledAt = System.nanoTime()
        call.thread.interrupt()
        call.join()
        assertTrue(System.nanoTime() - cancelledAt < TimeUnit.MILLISECONDS.toNanos(1_500),
            "cancellation must return within the single 1s cleanup allowance plus scheduling tolerance")
        assertTrue(call.failure.get() is InterruptedException, "caller cancellation must retain its classification")
        assertFalse(call.renderFinished.get())
        f.assertChildAbsent()
        f.assertReleased()
        f.assertUnpublished()
        f.assertNoCandidates()
    }

    @Test
    fun `actual two-owner admission cap with injected creation proof refuses a third native pipe invocation`() = fixture(2) { f ->
        val stager = f.sleepStager()
        val first = f.call(stager, 10_000)
        val second = f.call(stager, 10_000)
        try {
            f.assertNativePipeWrites(2)
            assertEquals(2, f.ownership.retainedInvocations())
            assertFailsWith<GhidraAnalysisException> {
                stager.withStagedReport(f.root, STAGING_INPUT_BYTES, stagingDeadline(1_000)::checkpoint,
                    render = { it.write(REPORT_BYTES) }, publish = f::publish)
            }
            assertEquals(2, f.starts.get(), "ownership admission must refuse capacity before creating another PID")
        } finally {
            first.thread.interrupt()
            second.thread.interrupt()
            first.join()
            second.join()
        }
        assertTrue(first.failure.get() is InterruptedException)
        assertTrue(second.failure.get() is InterruptedException)
        f.assertChildAbsent()
        f.assertReleased()
        f.assertUnpublished()
        f.assertNoCandidates()
    }

    @Test
    fun `injected late native launch retains capacity until its real handle returns and is stopped`() = fixture { f ->
        val releaseLaunch = CountDownLatch(1)
        val started = CompletableFuture<Process>()
        val stager = f.sleepStager(cleanupMillis = 150, starter = { command ->
            f.start(command).also { started.complete(it); stagingAwaitIgnoringInterrupts(releaseLaunch) }
        })
        val call = f.call(stager, 500)
        try {
            val child = started.get(2, TimeUnit.SECONDS)
            call.join()
            assertTrue(call.failure.get() is GhidraAnalysisException)
            assertTrue(child.isAlive, "the withheld native handle remains a live unresolved launch")
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> { f.stageSmall(stager) }
            assertEquals(1, f.starts.get())
            f.assertUnpublished()
        } finally {
            releaseLaunch.countDown()
        }
        f.assertChildAbsent()
        f.assertReleased()
        f.assertUnpublished()
    }

    @Test
    fun `injected starter losing a real PID retains unknown launch and refuses further capacity`() = fixture { f ->
        val lost = IOException("authored starter lost its native launch handle")
        val stager = f.sleepStager(cleanupMillis = 100, starter = { command ->
            f.start(command)
            throw lost
        })
        val failure = assertFailsWith<IOException> { f.stageSmall(stager) }
        assertSame(lost, failure, "cleanup must not replace the original starter failure")
        val child = f.processes.single()
        try {
            assertTrue(child.isAlive)
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> { f.stageSmall(stager) }
            assertEquals(1, f.starts.get())
            f.assertUnpublished()
        } finally {
            child.toHandle().destroyForcibly()
        }
        f.assertChildAbsent()
        assertEquals(1, f.ownership.retainedInvocations(), "test knowledge of a PID cannot prove production's unknown handle absent")
        f.assertUnpublished()
    }

    @Test
    fun `actual fixed helper CREATE_NEW collision preserves the prior candidate and report`() = fixture { f ->
        val collided = AtomicReference<Path?>()
        val stager = f.stager(cleanupMillis = 150, starter = { command ->
            val staged = Path.of(command[command.lastIndex - 1])
            Files.write(staged, PRIOR_STAGING_REPORT, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            collided.set(staged)
            f.start(command)
        })
        assertFailsWith<Exception> { f.stageSmall(stager) }
        f.assertChildAbsent()
        assertContentEquals(PRIOR_STAGING_REPORT, Files.readAllBytes(assertNotNull(collided.get())),
            "CREATE_NEW refusal must not authorize deletion of the preexisting candidate")
        assertEquals(1, f.ownership.retainedInvocations(), "OPENING without CREATED cannot prove candidate ownership")
        assertFailsWith<IllegalArgumentException> { f.stageSmall(stager) }
        assertEquals(1, f.starts.get())
        f.assertUnpublished()
    }

    @Test
    fun `injected blocked stdout close retains staging after the actual helper exits`() = fixture { f ->
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val stager = f.stager(cleanupMillis = 100, starter = { command ->
            val child = f.start(command)
            val stdout = object : FilterInputStream(child.inputStream) {
                override fun close() {
                    closeEntered.countDown()
                    stagingAwaitIgnoringInterrupts(releaseClose)
                    super.close()
                    closed.set(true)
                }
            }
            StagingProcessView(child, stdout = stdout)
        })
        val call = f.call(stager, 1_500, REPORT_BYTES)
        try {
            assertTrue(closeEntered.await(2, TimeUnit.SECONDS), "authored close seam was not entered")
            call.join()
            assertTrue(call.failure.get() is GhidraAnalysisException)
            f.assertChildAbsent()
            assertFalse(closed.get(), "the caller must not invent acknowledgement for the blocked stream close")
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> { f.stageSmall(stager) }
            f.assertUnpublished()
        } finally {
            releaseClose.countDown()
        }
        f.assertReleased()
        assertTrue(closed.get())
        f.assertNoCandidates()
        f.assertUnpublished()
    }

    @Test
    fun `injected blocked candidate deletion retains staging and returns within its cleanup allowance`() = fixture { f ->
        val deleteEntered = CountDownLatch(1)
        val releaseDelete = CountDownLatch(1)
        val creationObserved = CountDownLatch(1)
        val deleted = AtomicBoolean(false)
        val refusal = IOException("authored rendering refusal after staging exists")
        val refusedAt = AtomicReference<Long?>()
        val stager = f.stager(cleanupMillis = 150, starter = { command ->
            val child = f.start(command)
            StagingProcessView(child, stdout = CreationReceiptObserver(child.inputStream, creationObserved))
        }, deleteStaged = { staged ->
            deleteEntered.countDown()
            stagingAwaitIgnoringInterrupts(releaseDelete)
            Files.deleteIfExists(staged)
            deleted.set(true)
        })
        try {
            val failure = assertFailsWith<IOException> {
                stager.withStagedReport(f.root, REPORT_BYTES.size.toLong(), stagingDeadline(5_000)::checkpoint,
                    render = {
                        it.write(REPORT_BYTES)
                        assertTrue(creationObserved.await(2_500, TimeUnit.MILLISECONDS), "actual helper never returned its creation proof")
                        assertTrue(f.candidates.any { path -> Files.exists(path) })
                        refusedAt.set(System.nanoTime())
                        throw refusal
                    }, publish = f::publish)
            }
            assertSame(refusal, failure)
            assertTrue(System.nanoTime() - assertNotNull(refusedAt.get()) < TimeUnit.MILLISECONDS.toNanos(650),
                "blocked deletion must return within the single 150ms cleanup allowance plus scheduling tolerance")
            assertTrue(deleteEntered.await(2, TimeUnit.SECONDS))
            assertFalse(deleted.get())
            assertEquals(1, f.ownership.retainedInvocations())
            assertFailsWith<IllegalArgumentException> { f.stageSmall(stager) }
            f.assertUnpublished()
        } finally {
            releaseDelete.countDown()
        }
        f.assertChildAbsent()
        f.assertReleased()
        assertTrue(deleted.get())
        f.assertNoCandidates()
        f.assertUnpublished()
    }

    @Test
    fun `injected forged trailing and incomplete receipts never admit caller publication`() {
        val correct = stagingReceipt(REPORT_BYTES)
        val badDigest = correct.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val unsupported = correct.copyOf().also { it[7] = 2 }
        for (receipt in listOf(badDigest, correct + byteArrayOf(7), correct.copyOf(correct.size - 7), unsupported,
            stagingReceipt(REPORT_BYTES, reportedBytes = 0), stagingReceipt(REPORT_BYTES, reportedBytes = Long.MAX_VALUE))) fixture { f ->
            val stager = f.stager(command = { _, _ -> listOf("/bin/true") }, starter = { command ->
                StagingProcessView(f.start(command), stdout = ByteArrayInputStream(receipt), stdin = ByteArrayOutputStream())
            })
            assertFailsWith<Exception> { f.stageSmall(stager) }
            f.assertChildAbsent()
            f.assertReleased()
            f.assertUnpublished()
            f.assertNoCandidates()
        }
    }

    @Test
    fun `injected capture transfer control and launch admission refusals allow capacity reuse after admitted tasks finish`() {
        for (rejected in listOf("capture-first", "capture-second", "transfer", "control", "launch")) fixture { f ->
            val captureSubmissions = AtomicInteger()
            val capture = Executor { task ->
                val submission = captureSubmissions.incrementAndGet()
                if ((rejected == "capture-first" && submission == 1) || (rejected == "capture-second" && submission == 2)) {
                    throw RejectedExecutionException("authored capture admission refusal")
                }
                f.capture.execute(task)
            }
            val rejection = Executor { throw RejectedExecutionException("authored $rejected admission refusal") }
            val stager = f.stager(capture = capture,
                transfer = if (rejected == "transfer") rejection else f.transfer,
                control = if (rejected == "control") rejection else f.control,
                launch = if (rejected == "launch") BoundedAnalysisProcessLaunch(rejection) else f.launch)
            assertFailsWith<GhidraAnalysisException>(rejected) { f.stageSmall(stager) }
            assertEquals(0, f.starts.get(), "known admission refusal must precede native process creation")
            f.assertReleased()
            f.assertUnpublished()
            f.stageSmall(f.stager())
            assertEquals(1, f.published.get(), "settled admission refusal must permit a later fixed-helper invocation")
            f.assertReleased()
            f.assertNoCandidates()
        }
    }

    private fun fixture(owners: Int = 1, test: (StagingFixture) -> Unit) = inControlTemporaryDirectory { root ->
        val fixture = StagingFixture(root, owners)
        try { test(fixture) } finally { fixture.close() }
    }

    private class StagingFixture(val root: Path, owners: Int) : AutoCloseable {
        val report = root.resolve("analysis-report.json")
        val ownership = AnalysisArtifactStagingOwnership(owners)
        val transferThreads = CopyOnWriteArrayList<Thread>()
        val transfer = stagingPool(2, "stage-write", transferThreads)
        val capture = stagingPool(4, "stage-capture")
        val control = stagingPool(2, "stage-control")
        val launches = stagingPool(2, "stage-launch")
        val launch = BoundedAnalysisProcessLaunch(launches)
        val processes = CopyOnWriteArrayList<Process>()
        private val callers = CopyOnWriteArrayList<Thread>()
        val candidates = CopyOnWriteArrayList<Path>()
        val starts = AtomicInteger()
        val published = AtomicInteger()
        init { Files.write(report, PRIOR_STAGING_REPORT) }

        fun stager(cleanupMillis: Long = 1_000, capture: Executor = this.capture, transfer: Executor = this.transfer,
            control: Executor = this.control, launch: BoundedAnalysisProcessLaunch = this.launch,
            command: ((Path, Long) -> List<String>)? = null, starter: (List<String>) -> Process = ::start,
            deleteStaged: (Path) -> Unit = { Files.deleteIfExists(it) }): BoundedAnalysisArtifactStagingProcess =
            if (command == null) BoundedAnalysisArtifactStagingProcess(processStarter = starter, ownership = ownership,
                captureExecutor = capture, transferExecutor = transfer, controlExecutor = control, launch = launch,
                cleanupMillis = cleanupMillis, deleteStaged = deleteStaged)
            else BoundedAnalysisArtifactStagingProcess(commandFactory = command, processStarter = starter, ownership = ownership,
                captureExecutor = capture, transferExecutor = transfer, controlExecutor = control, launch = launch,
                cleanupMillis = cleanupMillis, deleteStaged = deleteStaged)

        fun sleepStager(cleanupMillis: Long = 1_000, starter: ((List<String>) -> Process)? = null): BoundedAnalysisArtifactStagingProcess {
            if (starter != null) return stager(cleanupMillis = cleanupMillis,
                command = { _, _ -> listOf("/bin/sleep", "30") }, starter = starter)
            // Production settles creation before invoking render. This seam creates the actual
            // private candidate and injects only its matching creation prefix. The sleep child
            // still owns the real unread stdin pipe; no bytes or completion receipt are forged.
            val candidateForLaunch = ThreadLocal<Path>()
            return stager(cleanupMillis = cleanupMillis, command = { staged, _ ->
                candidateForLaunch.set(staged)
                listOf("/bin/sleep", "30")
            }, starter = { command ->
                val staged = requireNotNull(candidateForLaunch.get())
                candidateForLaunch.remove()
                Files.newByteChannel(staged, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { }
                candidates.add(staged)
                val attributes = Files.readAttributes(staged, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                check(attributes.isRegularFile)
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(staged))
                val proof = stagingCreationPrefix(requireNotNull(attributes.fileKey()).toString())
                val child = start(command)
                StagingProcessView(child, stdout = SequenceInputStream(ByteArrayInputStream(proof), child.inputStream))
            })
        }

        fun start(command: List<String>): Process {
            starts.incrementAndGet()
            command.getOrNull(command.size - 2)?.let { candidate ->
                if (candidate.contains(".json-report-stage-")) candidates.add(Path.of(candidate))
            }
            return ProcessBuilder(command).directory(root.toFile()).apply {
                listOf("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS").forEach(environment()::remove)
                environment()["TMPDIR"] = root.toString()
            }.start().also(processes::add)
        }

        fun publish(staged: Path) {
            published.incrementAndGet()
            Files.move(staged, report, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        }

        fun stageSmall(stager: BoundedAnalysisArtifactStagingProcess) = stager.withStagedReport(root,
            REPORT_BYTES.size.toLong(), stagingDeadline(5_000)::checkpoint, render = { it.write(REPORT_BYTES) }, publish = ::publish)

        fun call(stager: BoundedAnalysisArtifactStagingProcess, allowanceMillis: Long,
            bytes: ByteArray = ByteArray(STAGING_INPUT_BYTES.toInt()) { (it % 127).toByte() }): StagingCall {
            val failure = AtomicReference<Throwable?>()
            val renderFinished = AtomicBoolean(false)
            val started = System.nanoTime()
            val thread = Thread {
                try {
                    stager.withStagedReport(root, bytes.size.toLong(), stagingDeadline(allowanceMillis)::checkpoint,
                        render = { it.write(bytes); renderFinished.set(true) }, publish = ::publish)
                } catch (caught: Throwable) { failure.set(caught) }
            }.apply { isDaemon = true; name = "stage-fixture-caller"; callers.add(this); start() }
            return StagingCall(thread, failure, renderFinished, started, allowanceMillis)
        }

        fun assertNativePipeWrites(expected: Int) = stagingAwaitCondition(1_200, "actual report transfer did not reach native stdin pipe backpressure") {
            processes.count { it.isAlive } == expected && transferThreads.count { thread ->
                thread.stackTrace.any { frame -> frame.isNativeMethod && frame.className == "java.io.FileOutputStream" && frame.methodName == "writeBytes" }
            } >= expected && nativePipeWriterCount() >= expected
        }

        private fun nativePipeWriterCount(): Long = Files.list(Path.of("/proc/self/task")).use { tids ->
            tids.filter { tid -> runCatching {
                Files.readString(tid.resolve("comm")).trim() == "stage-write" && Files.readString(tid.resolve("wchan")).contains("pipe_write")
            }.getOrDefault(false) }.count()
        }

        fun assertChildAbsent() = stagingAwaitCondition(3_000, "owned helper PID remains alive after cleanup") {
            processes.all { process -> !process.isAlive && ProcessHandle.of(process.pid()).map { !it.isAlive }.orElse(true) }
        }

        fun assertReleased() = stagingAwaitCondition(3_000, "actual staging tasks did not finish and release their bounded ownership") {
            ownership.retainedInvocations() == 0 && transfer.activeCount == 0 && capture.activeCount == 0 &&
                control.activeCount == 0 && launches.activeCount == 0
        }

        fun assertPriorReport() = assertContentEquals(PRIOR_STAGING_REPORT, Files.readAllBytes(report))
        fun assertUnpublished() { assertEquals(0, published.get()); assertPriorReport() }
        fun assertNoCandidates() = Files.list(root).use { paths ->
            assertFalse(paths.anyMatch { it.fileName.toString().startsWith(".json-report-stage-") }, "private staging candidate was not removed")
        }

        override fun close() {
            callers.forEach { if (it.isAlive) it.interrupt() }
            callers.forEach { it.join(2_000) }
            processes.forEach { if (it.isAlive) it.toHandle().destroyForcibly() }
            processes.forEach { it.waitFor(2, TimeUnit.SECONDS) }
            listOf(transfer, capture, control, launches).forEach { it.shutdownNow() }
            listOf(transfer, capture, control, launches).forEach { it.awaitTermination(2, TimeUnit.SECONDS) }
            assertFalse(callers.any { it.isAlive }, "a fixture caller remains active before its repository directory is removed")
        }
    }

    private class StagingCall(val thread: Thread, val failure: AtomicReference<Throwable?>,
        val renderFinished: AtomicBoolean, private val started: Long, private val allowanceMillis: Long) {
        fun join() {
            thread.join(allowanceMillis + 2_000)
            assertFalse(thread.isAlive, "report staging caller outlived the single cleanup allowance")
            assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(allowanceMillis + 1_500),
                "report staging renewed the original allowance or waited for unbounded cleanup")
            assertNotNull(failure.get(), "the refused staging operation must report its failure")
        }
    }

    private class StagingProcessView(private val child: Process, private val stdout: InputStream = child.inputStream,
        private val stdin: OutputStream = child.outputStream) : Process() {
        override fun getInputStream(): InputStream = stdout
        override fun getOutputStream(): OutputStream = stdin
        override fun getErrorStream(): InputStream = child.errorStream
        override fun waitFor(): Int = child.waitFor()
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = child.waitFor(timeout, unit)
        override fun exitValue(): Int = child.exitValue()
        override fun destroy() { child.destroy() }
        override fun destroyForcibly(): Process { child.destroyForcibly(); return this }
        override fun isAlive(): Boolean = child.isAlive
        override fun toHandle(): ProcessHandle = child.toHandle()
    }

    /** Observes only the bounded CREATED prefix; it does not substitute a receipt or stage bytes. */
    private class CreationReceiptObserver(private val source: InputStream, private val created: CountDownLatch) : FilterInputStream(source) {
        private val prefix = ByteArrayOutputStream()
        override fun read(): Int = source.read().also { value -> if (value >= 0) observe(byteArrayOf(value.toByte()), 0, 1) }
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int = source.read(bytes, offset, length).also { amount ->
            if (amount > 0) observe(bytes, offset, amount)
        }
        private fun observe(bytes: ByteArray, offset: Int, length: Int) {
            if (created.count == 0L) return
            prefix.write(bytes, offset, minOf(length, 276 - prefix.size()))
            if (prefix.size() < 20) return
            val input = DataInputStream(ByteArrayInputStream(prefix.toByteArray()))
            if (input.readInt() != 0x53544752 || input.readInt() != 1 || input.readInt() != 0x4f50454e ||
                input.readInt() != 0x43524541) return
            val identityLength = input.readInt()
            if (identityLength in 1..256 && prefix.size() >= 20 + identityLength) created.countDown()
        }
    }
}

private const val STAGING_INPUT_BYTES = 2L * 1024 * 1024
private val REPORT_BYTES = authoredReport(32 * 1024 + 7)
private val PRIOR_STAGING_REPORT = "{\"previous\":\"authored report evidence\"}\n".toByteArray()
private fun authoredReport(minimumBytes: Int): ByteArray {
    val value = "{\"benign\":\"" + "report fixture ".repeat(minimumBytes / 15 + 1) + "\"}\n"
    return value.toByteArray()
}
private fun stagingDeadline(milliseconds: Long) = AnalysisDeadline.start(
    TimeUnit.MILLISECONDS.toNanos(milliseconds), "report staging control fixture")
private fun stagingPool(threads: Int, name: String, retainedThreads: MutableList<Thread>? = null) = ThreadPoolExecutor(
    0, threads, 60, TimeUnit.SECONDS, SynchronousQueue(), { task ->
        Thread(task, name).apply { isDaemon = true; retainedThreads?.add(this) }
    }, ThreadPoolExecutor.AbortPolicy())
private fun stagingReceipt(bytes: ByteArray, reportedBytes: Long = bytes.size.toLong()): ByteArray = ByteArrayOutputStream().also { output ->
    DataOutputStream(output).use { receipt ->
        receipt.write(stagingCreationPrefix("authored-test-file-identity"))
        receipt.writeInt(0x434f4d50); receipt.writeLong(reportedBytes)
        receipt.write(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}.toByteArray()
private fun stagingCreationPrefix(fileKey: String): ByteArray = ByteArrayOutputStream().also { output ->
    val identity = fileKey.toByteArray(Charsets.US_ASCII)
    require(identity.size in 1..256 && fileKey.all { it.code in 0x20..0x7e })
    DataOutputStream(output).use { receipt ->
        receipt.writeInt(0x53544752); receipt.writeInt(1); receipt.writeInt(0x4f50454e)
        receipt.writeInt(0x43524541); receipt.writeInt(identity.size); receipt.write(identity)
    }
}.toByteArray()
private fun stagingAwaitCondition(milliseconds: Long, message: String, condition: () -> Boolean) {
    val cutoff = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(milliseconds)
    while (!condition() && System.nanoTime() < cutoff) Thread.sleep(10)
    assertTrue(condition(), message)
}
private fun stagingAwaitIgnoringInterrupts(latch: CountDownLatch) {
    while (true) try { latch.await(); return } catch (_: InterruptedException) { }
}

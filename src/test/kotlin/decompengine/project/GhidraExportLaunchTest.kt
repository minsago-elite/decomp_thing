package decompengine.project

import decompengine.analysis.ANALYSIS_PROCESS_LAUNCH_EXECUTOR
import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.BundledGhidraVerificationProcess
import decompengine.analysis.BoundedAnalysisProcessLaunch
import decompengine.analysis.GhidraAnalysisException
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.reflect.Proxy
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class GhidraExportLaunchTest {
    @Test
    fun `unconfirmed retained descendant quarantines launch and preserves prior model`() = inControlTemporaryDirectory { root ->
        val work = root.resolve("analysis")
        val reports = work.resolve("reports")
        Files.createDirectories(reports)
        val priorModel = "previous accepted model bytes\n".toByteArray()
        val priorCalls = "previous call evidence\n".toByteArray()
        reports.resolve("program_model.json").writeBytes(priorModel)
        reports.resolve("program_model_calls.json").writeBytes(priorCalls)
        val child = fixtureHandle(1002L, initialAlive = true, refusesTermination = true)
        val clock = AtomicLong()
        val launches = AtomicInteger()
        val controller = BoundedAnalysisProcessLaunch()
        val process = FixtureOwnedProcess(fixtureHandle(1001L, initialAlive = true, refusesTermination = false))
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> launches.incrementAndGet(); process },
        ).withProcessLifecycleForTests(controller) { owned, grace ->
            ExportProcessTree(
                owned, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { _, retain -> retain(child) },
            )
        }

        val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), work) }

        assertTrue(failure.message.orEmpty().contains("exceeded") || failure.message.orEmpty().contains("could not prove"), failure.toString())
        assertTrue(controller.hasQuarantinedOwner())
        assertEquals(1, launches.get())
        assertContentEquals(priorModel, reports.resolve("program_model.json").readBytes())
        assertContentEquals(priorCalls, reports.resolve("program_model_calls.json").readBytes())
        assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("second-analysis")) }
        assertEquals(1, launches.get(), "quarantine must refuse before another process is admitted")
    }

    @Test
    fun `process tree confirms known exit and retains yielded handles when observation later fails`() {
        val exited = FixtureOwnedProcess(fixtureHandle(2001L, initialAlive = true, refusesTermination = false))
        val clock = AtomicLong()
        val confirmed = ExportProcessTree(
            exited, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { _, _ -> },
        ).terminate()
        assertTrue(confirmed.confirmedAbsent)

        val stubborn = fixtureHandle(2003L, initialAlive = true, refusesTermination = true)
        val stuck = FixtureOwnedProcess(fixtureHandle(2002L, initialAlive = true, refusesTermination = false))
        val failedObservation = ExportProcessTree(
            stuck, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { _, retain ->
                retain(stubborn)
                throw java.io.IOException("fixture snapshot failed after one yielded child")
            },
        ).let { tree -> tree.terminate() to tree.retainedHandleCount() }
        assertFalse(failedObservation.first.confirmedAbsent)
        assertTrue(generateSequence(failedObservation.first.failure) { it.cause }
            .any { it.message.orEmpty().contains("fixture snapshot failed") })
        assertEquals(2, failedObservation.second, "root and already-yielded child must remain retained")
    }

    @Test
    fun `operation failure remains primary with unconfirmed cleanup suppressed`() = inControlTemporaryDirectory { root ->
        val primary = IllegalStateException("authored process wait failure")
        val process = FixtureOwnedProcess(
            fixtureHandle(3001L, initialAlive = true, refusesTermination = false), primary,
        )
        val clock = AtomicLong()
        val controller = BoundedAnalysisProcessLaunch()
        val child = fixtureHandle(3002L, initialAlive = true, refusesTermination = true)
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> process },
        ).withProcessLifecycleForTests(controller) { owned, grace ->
            ExportProcessTree(
                owned, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { _, retain -> retain(child) },
            )
        }

        val failure = assertFailsWith<IllegalStateException> {
            analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis"))
        }

        assertTrue(failure === primary, "cleanup failure must not replace the operation failure")
        assertTrue(failure.suppressed.any { it.message.orEmpty().contains("could not prove absence") })
        assertTrue(controller.hasQuarantinedOwner())
    }

    @Test
    fun `stream close failure quarantines process admission`() = inControlTemporaryDirectory { root ->
        val reports = root.resolve("analysis/reports")
        Files.createDirectories(reports)
        val priorModel = "prior model survives stream close failure\n".toByteArray()
        reports.resolve("program_model.json").writeBytes(priorModel)
        val closeFailure = java.io.IOException("fixture stream close failed")
        val process = FixtureOwnedProcess(
            fixtureHandle(4001L, initialAlive = true, refusesTermination = false),
            streamCloseFailure = closeFailure,
        )
        val clock = AtomicLong()
        val controller = BoundedAnalysisProcessLaunch()
        val launches = AtomicInteger()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> launches.incrementAndGet(); process },
        ).withProcessLifecycleForTests(controller) { owned, grace ->
            ExportProcessTree(
                owned, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { _, _ -> },
            )
        }

        val failure = assertFailsWith<java.io.IOException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis")) }

        assertTrue(failure === closeFailure, "the first output-stream failure must remain primary")
        assertTrue(failure.suppressed.any { generateSequence(it) { cause -> cause.cause }.any { cause -> cause === closeFailure } })
        assertTrue(controller.hasQuarantinedOwner())
        assertContentEquals(priorModel, reports.resolve("program_model.json").readBytes())
        assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("second-analysis")) }
        assertEquals(1, launches.get())
    }

    @Test
    fun `concurrent unconfirmed owners are all retained and repeated reports coalesce`() = inControlTemporaryDirectory { root ->
        val processes = listOf(
            FixtureOwnedProcess(fixtureHandle(5001L, initialAlive = true, refusesTermination = false)),
            FixtureOwnedProcess(fixtureHandle(5002L, initialAlive = true, refusesTermination = false)),
        )
        val children = listOf(
            fixtureHandle(5011L, initialAlive = true, refusesTermination = true),
            fixtureHandle(5012L, initialAlive = true, refusesTermination = true),
        )
        val processIndex = AtomicInteger()
        val launches = AtomicInteger()
        val bothLaunchesEntered = CountDownLatch(processes.size)
        val clock = AtomicLong()
        val controller = BoundedAnalysisProcessLaunch()
        val childrenByProcess = java.util.IdentityHashMap<Process, ProcessHandle>().apply {
            processes.forEachIndexed { index, process -> put(process, children[index]) }
        }
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ ->
                launches.incrementAndGet()
                val index = processIndex.getAndIncrement()
                bothLaunchesEntered.countDown()
                check(bothLaunchesEntered.await(5, TimeUnit.SECONDS)) { "both owned workers did not enter the launch gate" }
                processes[index]
            },
        ).withProcessLifecycleForTests(controller) { owned, grace ->
            ExportProcessTree(
                owned, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { _, retain -> retain(checkNotNull(childrenByProcess[owned])) },
            )
        }
        val outcomes = arrayOfNulls<Throwable>(processes.size)
        val callers = processes.indices.map { index ->
            Thread {
                try { analyzer.analyze(root.resolve("unused-$index"), root.resolve("analysis-$index")) }
                catch (failure: Throwable) { outcomes[index] = failure }
            }
        }
        callers.forEach(Thread::start)
        callers.forEach { it.join(5_000) }

        assertTrue(callers.none(Thread::isAlive), "both cleanup paths must finish within their fake original windows")
        outcomes.forEach { assertIs<GhidraAnalysisException>(it) }
        assertEquals(processes.size, controller.quarantinedProcessCount())
        processes.forEach { process ->
            assertTrue(controller.hasQuarantinedProcess(process))
            assertTrue(controller.retainedQuarantineReferenceCount(process) >= 2,
                "each process and its cleanup owner must remain retained")
        }
        assertEquals(processes.size, launches.get())

        val existingProcess = processes.first()
        val duplicateOwner = Any()
        val additionalOwner = Any()
        val firstReport = IllegalStateException("duplicate cleanup report")
        val secondReport = IllegalStateException("second cleanup report")
        controller.quarantineUnconfirmedCleanup(firstReport, existingProcess, duplicateOwner)
        val afterFirstReport = controller.retainedQuarantineReferenceCount(existingProcess)
        controller.quarantineUnconfirmedCleanup(firstReport, existingProcess, duplicateOwner)
        assertEquals(afterFirstReport, controller.retainedQuarantineReferenceCount(existingProcess),
            "re-reporting the same process owner must coalesce by identity")
        controller.quarantineUnconfirmedCleanup(secondReport, existingProcess, duplicateOwner)
        controller.quarantineUnconfirmedCleanup(secondReport, existingProcess, additionalOwner)
        assertEquals(afterFirstReport + 1, controller.retainedQuarantineReferenceCount(existingProcess))
        assertTrue(controller.quarantinedFailureCount(existingProcess) >= 3)

        assertFailsWith<GhidraAnalysisException> {
            analyzer.analyze(root.resolve("unused-third"), root.resolve("analysis-third"))
        }
        assertEquals(processes.size, launches.get(), "quarantine must refuse before a third process starter runs")
    }

    @Test
    fun `shared deadline refuses blocked process launch before it returns and preserves prior evidence`(): Unit =
        inControlTemporaryDirectory { root ->
            val reports = root.resolve("analysis/reports")
            Files.createDirectories(reports)
            val model = reports.resolve("program_model.json")
            val report = reports.resolve("ghidra_analysis.json")
            val previous = "prior accepted evidence\n".toByteArray()
            model.writeBytes(previous)
            report.writeBytes(previous)
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val launched = CompletableFuture<Process>()
            val failure = AtomicReference<Throwable?>()
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                { listOf("/bin/sleep", "30") },
                GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
                processStarter = { command, work ->
                    entered.countDown()
                    awaitIgnoringInterrupts(release)
                    ProcessBuilder(command).directory(work.toFile()).start().also(launched::complete)
                },
            )
            val caller = Thread {
                try {
                    analyzer.analyzeWithDeadline(root.resolve("authored-input"), root.resolve("analysis"),
                        AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(250), "launch parent"))
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            }
            preserveFixtureFailure({
                caller.start()
                assertTrue(entered.await(2, TimeUnit.SECONDS), "process launch did not start")
                caller.join(1_500)
                assertFalse(caller.isAlive, "caller remained inside processStarter after its admitted deadline")
                assertIs<GhidraAnalysisException>(failure.get())
                assertContentEquals(previous, model.readBytes())
                assertContentEquals(previous, report.readBytes())
            }, {
                release.countDown()
                caller.join(2_000)
            }, {
                val process = launched.get(2, TimeUnit.SECONDS)
                preserveFixtureFailure({
                    process.onExit().get(2, TimeUnit.SECONDS)
                    assertFalse(process.isAlive, "late export worker survived cancellation")
                }, {
                    ensureStopped(process)
                })
                assertContentEquals(previous, model.readBytes())
                assertContentEquals(previous, report.readBytes())
            }, {
                awaitLaunchPoolIdle()
            })
        }

    @Test
    fun `expired parent never activates an already started worker whose handle is withheld`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = GatedExportFixture(root)
            val starter = BlockedStartedWorker()
            val caller = ExportCall {
                fixture.analyzer(starter::start).analyzeWithDeadline(fixture.input, fixture.work, deadline(250))
            }
            preserveFixtureFailure({
                caller.thread.start()
                assertTrue(starter.entered.await(2, TimeUnit.SECONDS), "gated worker did not reach its stdin wait")
                assertTrue(starter.launched.get(2, TimeUnit.SECONDS).isAlive, "fixture worker did not remain gated")
                caller.assertFailure<GhidraAnalysisException>()
                fixture.assertPriorEvidence()
            }, {
                starter.release.countDown()
                caller.thread.join(2_000)
            }, {
                starter.assertLateWorkerReaped()
                fixture.assertPriorEvidence()
            }, {
                awaitLaunchPoolIdle()
            })
        }

    @Test
    fun `budget binding preserves the custom starter and permit for a timely canonical export`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = GatedExportFixture(root)
            val starts = AtomicInteger()
            val launched = AtomicReference<Process?>()
            val analyzer = fixture.analyzer { command, work ->
                starts.incrementAndGet()
                ProcessBuilder(command).directory(work.toFile()).start().also { process ->
                    launched.set(process)
                    assertWorkerReady(process)
                    fixture.assertPriorEvidence()
                }
            }.withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(
                exportWallClockMillis = 3_000,
                exportMaximumResidentBytes = 64L * 1024 * 1024,
            ))
            preserveFixtureFailure({
                val actual = analyzer.analyzeWithDeadline(fixture.input, fixture.work, deadline(5_000))

                assertEquals(fixture.expected, actual)
                assertEquals(1, starts.get(), "budget binding discarded the custom process starter")
                assertContentEquals(fixture.canonicalBytes, fixture.model.readBytes())
                assertEquals("activated\n", fixture.activation.readText())
                assertEquals("new analysis evidence\n", fixture.report.readText())
                val usage = fixture.work.resolve("reports/ghidra_resource_usage.json").readText()
                assertTrue(usage.contains("\"wallClockMillisLimit\":3000"))
                assertTrue(usage.contains("\"maximumResidentBytesLimit\":67108864"))
                assertFalse(checkNotNull(launched.get()).isAlive)
            }, {
                launched.get()?.let(::ensureStopped)
            }, {
                awaitLaunchPoolIdle()
            })
        }

    @Test
    fun `caller interruption abandons withheld handle without activating its late worker`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = GatedExportFixture(root)
            val starter = BlockedStartedWorker()
            val caller = ExportCall {
                fixture.analyzer(starter::start).analyzeWithDeadline(fixture.input, fixture.work, deadline(5_000))
            }
            preserveFixtureFailure({
                caller.thread.start()
                assertTrue(starter.entered.await(2, TimeUnit.SECONDS), "gated worker did not reach its stdin wait")
                caller.thread.interrupt()
                caller.assertFailure<InterruptedException>()
                fixture.assertPriorEvidence()
            }, {
                starter.release.countDown()
                caller.thread.join(2_000)
            }, {
                starter.assertLateWorkerReaped()
                fixture.assertPriorEvidence()
            }, {
                awaitLaunchPoolIdle()
            })
        }

    @Test
    fun `two abandoned launchers reject further export and verifier admission until late cleanup`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixtures = List(2) { GatedExportFixture(root.resolve("worker-$it")) }
            val starters = List(2) { BlockedStartedWorker() }
            val callers = fixtures.zip(starters).map { (fixture, starter) ->
                ExportCall {
                    fixture.analyzer(starter::start).analyzeWithDeadline(fixture.input, fixture.work, deadline(250))
                }
            }
            val unexpectedExportStart = AtomicBoolean()
            val unexpectedVerifierStart = AtomicBoolean()
            val thirdFixture = GatedExportFixture(root.resolve("rejected-worker"))
            val rejectedExport = ExportCall {
                thirdFixture.analyzer { _, _ ->
                    unexpectedExportStart.set(true)
                    error("saturated pool must reject before starting another export")
                }.analyzeWithDeadline(thirdFixture.input, thirdFixture.work, deadline(5_000))
            }
            val verifier = BundledGhidraVerificationProcess(
                commandFactory = { listOf("/bin/false") },
                processStarter = { _, _ ->
                    unexpectedVerifierStart.set(true)
                    error("saturated shared pool must reject before starting the verifier")
                },
                maximumWallMillis = 5_000,
            )
            val rejectedVerifier = ExportCall { verifier.verifyAndGetLibraries(root) {} }
            preserveFixtureFailure({
                callers.forEach { it.thread.start() }
                starters.forEach { starter ->
                    assertTrue(starter.entered.await(2, TimeUnit.SECONDS), "both launch slots must be occupied")
                }
                callers.forEach { it.assertFailure<GhidraAnalysisException>() }
                fixtures.forEach { it.assertPriorEvidence() }
                // Expired callers must leave their uninterruptible launch tasks occupying the fixed cap.
                for (rejected in listOf(rejectedExport, rejectedVerifier)) {
                    rejected.thread.start()
                    val failure = rejected.assertFailure<GhidraAnalysisException>(1_000)
                    assertTrue(failure.message.orEmpty().contains("launch capacity is exhausted"))
                }
                assertFalse(unexpectedExportStart.get())
                assertFalse(unexpectedVerifierStart.get())
                thirdFixture.assertPriorEvidence()
            }, {
                starters.forEach { it.release.countDown() }
            }, {
                // Preserve each caller's failure while still attempting the remaining owned joins.
                preserveFixtureFailure({}, *(callers + rejectedExport + rejectedVerifier).map { caller ->
                    {
                        if (caller.thread.isAlive) caller.thread.interrupt()
                        caller.thread.join(2_000)
                    }
                }.toTypedArray())
            }, {
                // Release every starter even when one assertion fails, then reap every real worker.
                preserveFixtureFailure({
                    starters[0].assertLateWorkerReaped()
                }, {
                    starters[1].assertLateWorkerReaped()
                })
                (fixtures + thirdFixture).forEach { it.assertPriorEvidence() }
            }, {
                awaitLaunchPoolIdle()
            })
        }

    @Test
    fun `fixture cleanup preserves body failure and ordered later failures without self suppression`() {
        val order = mutableListOf<String>()
        val bodyFailure = IllegalStateException("authored body failure")
        val firstCleanup = IllegalArgumentException("authored first cleanup failure")
        val secondCleanup = UnsupportedOperationException("authored second cleanup failure")
        val actual = runCatching {
            preserveFixtureFailure({
                order += "body"
                throw bodyFailure
            }, {
                order += "first cleanup"
                throw firstCleanup
            }, {
                order += "second cleanup"
                throw secondCleanup
            })
        }.exceptionOrNull()
        assertTrue(actual === bodyFailure, "cleanup must not replace the original body failure")
        assertEquals(listOf("body", "first cleanup", "second cleanup"), order)
        assertEquals(listOf(firstCleanup, secondCleanup), bodyFailure.suppressed.toList())

        val cleanupOnly = IllegalStateException("authored cleanup-only failure")
        val laterCleanup = IllegalArgumentException("authored later cleanup failure")
        order.clear()
        val successfulBody = runCatching {
            preserveFixtureFailure({
                order += "successful body"
            }, {
                order += "first cleanup"
                throw cleanupOnly
            }, {
                order += "second cleanup"
                throw laterCleanup
            })
        }.exceptionOrNull()
        assertTrue(successfulBody === cleanupOnly, "a successful body must still fail on cleanup failure")
        assertEquals(listOf("successful body", "first cleanup", "second cleanup"), order)
        assertEquals(listOf(laterCleanup), cleanupOnly.suppressed.toList())

        val sharedFailure = IllegalStateException("authored shared failure")
        val selfSuppression = runCatching {
            preserveFixtureFailure({ throw sharedFailure }, { throw sharedFailure })
        }.exceptionOrNull()
        assertTrue(selfSuppression === sharedFailure)
        assertTrue(sharedFailure.suppressed.isEmpty(), "the same throwable must not suppress itself")
    }

    private class GatedExportFixture(root: Path) {
        val work = root.resolve("analysis")
        val input = root.resolve("authored-input")
        val model = work.resolve("reports/program_model.json")
        val report = work.resolve("reports/ghidra_analysis.json")
        val activation = root.resolve("activation-marker")
        private val canonical = root.resolve("canonical-model.json")
        private val prior = "prior accepted evidence\n".toByteArray()
        private val inactive = "not activated\n".toByteArray()
        private val inputBytes = "authored local input\n".toByteArray()
        val expected = RecoveredProgramModel(
            inputSha256 = sha256(inputBytes),
            functions = listOf(RecoveredFunction(
                id = "fn_authored", name = "authored", address = 0x401000UL,
                prototype = "int authored(void)", decompiledC = "int authored(void) { return 7; }\n",
            )),
        )
        val canonicalBytes = expected.toJson().toByteArray()

        init {
            Files.createDirectories(model.parent)
            input.writeBytes(inputBytes)
            canonical.writeBytes(canonicalBytes)
            model.writeBytes(prior)
            report.writeBytes(prior)
            activation.writeBytes(inactive)
        }

        fun analyzer(starter: (List<String>, Path) -> Process) = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { invocation ->
                val scriptArguments = invocation.postScripts.single().arguments
                assertEquals(model.toAbsolutePath().normalize(), Path.of(scriptArguments[3]))
                assertEquals("owned-model-candidate-v1", scriptArguments[4])
                listOf("/bin/sh", "-c", """
                    printf 'ready\n'
                    IFS= read -r permit || exit 70
                    [ "${'$'}permit" = 1 ] || exit 71
                    printf 'activated\n' > "${'$'}1"
                    cp "${'$'}2" "${'$'}3"
                    printf 'new analysis evidence\n' > "${'$'}4"
                """.trimIndent(), "gated-export", activation.toString(), canonical.toString(), scriptArguments.last(), report.toString())
            },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = starter,
            requiresLaunchPermit = true,
        )

        fun assertPriorEvidence() {
            assertContentEquals(prior, model.readBytes())
            assertContentEquals(prior, report.readBytes())
            assertContentEquals(inactive, activation.readBytes())
        }
    }

    private class BlockedStartedWorker {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val launched = CompletableFuture<Process>()

        fun start(command: List<String>, work: Path): Process {
            val process = ProcessBuilder(command).directory(work.toFile()).start()
            launched.complete(process)
            assertWorkerReady(process)
            entered.countDown()
            awaitIgnoringInterrupts(release)
            return process
        }

        fun assertLateWorkerReaped() {
            val process = launched.get(2, TimeUnit.SECONDS)
            preserveFixtureFailure({
                process.onExit().get(2, TimeUnit.SECONDS)
                assertFalse(process.isAlive, "late gated worker survived cancellation")
                assertFalse(ProcessHandle.of(process.pid()).map { it.isAlive }.orElse(false), "late PID remains live")
            }, {
                ensureStopped(process)
            })
        }
    }

    private class ExportCall(operation: () -> Any) {
        val failure = AtomicReference<Throwable?>()
        val elapsedNanos = AtomicLong()
        val thread = Thread {
            val started = System.nanoTime()
            try {
                operation()
            } catch (caught: Throwable) {
                failure.set(caught)
            } finally {
                elapsedNanos.set(System.nanoTime() - started)
            }
        }

        inline fun <reified T : Throwable> assertFailure(maximumMillis: Long = 2_000): T {
            thread.join(maximumMillis - 100)
            assertFalse(thread.isAlive, "caller did not return within its bounded launch allowance")
            assertTrue(elapsedNanos.get() < TimeUnit.MILLISECONDS.toNanos(maximumMillis), "launch did not return promptly")
            return assertIs<T>(failure.get())
        }
    }

    private class FixtureOwnedProcess(
        private val handle: ProcessHandle,
        private val waitFailure: Throwable? = null,
        private val streamCloseFailure: Throwable? = null,
    ) : Process() {
        private val alive = AtomicBoolean(true)
        private val output = object : ByteArrayOutputStream() {
            override fun close() { streamCloseFailure?.let { throw it }; super.close() }
        }
        private val input = fixtureStream()
        private val error = fixtureStream()
        private fun fixtureStream() = object : ByteArrayInputStream(byteArrayOf()) {
            override fun close() { streamCloseFailure?.let { throw it }; super.close() }
        }
        override fun getOutputStream(): java.io.OutputStream = output
        override fun getInputStream(): java.io.InputStream = input
        override fun getErrorStream(): java.io.InputStream = error
        override fun waitFor(): Int = if (alive.get()) throw IllegalThreadStateException() else 70
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            waitFailure?.let { throw it }
            return false
        }
        override fun exitValue(): Int = if (alive.get()) throw IllegalThreadStateException() else 70
        override fun destroy(): Unit { alive.set(false) }
        override fun destroyForcibly(): Process { alive.set(false); return this }
        override fun isAlive(): Boolean = alive.get()
        override fun toHandle(): ProcessHandle = handle
    }

    private fun fixtureHandle(pid: Long, initialAlive: Boolean, refusesTermination: Boolean): ProcessHandle {
        val alive = AtomicBoolean(initialAlive)
        lateinit var handle: ProcessHandle
        handle = Proxy.newProxyInstance(
            ProcessHandle::class.java.classLoader,
            arrayOf(ProcessHandle::class.java),
        ) { _, method, arguments ->
            when (method.name) {
                "pid" -> pid
                "isAlive" -> alive.get()
                "destroy", "destroyForcibly" -> {
                    if (!refusesTermination) alive.set(false)
                    !refusesTermination
                }
                "supportsNormalTermination" -> true
                "parent" -> java.util.Optional.empty<ProcessHandle>()
                "children", "descendants" -> java.util.stream.Stream.empty<ProcessHandle>()
                "onExit" -> CompletableFuture.completedFuture(handle)
                "compareTo" -> java.lang.Long.compare(pid, (arguments!![0] as ProcessHandle).pid())
                "toString" -> "FixtureProcessHandle[$pid]"
                "hashCode" -> pid.hashCode()
                "equals" -> handle === arguments?.get(0)
                else -> null
            }
        } as ProcessHandle
        return handle
    }

    private companion object {
        // Fixture-only: keep the first failure and attempt every already-owned cleanup action in order.
        private fun preserveFixtureFailure(body: () -> Unit, vararg cleanup: () -> Unit) {
            var failure: Throwable? = null
            try {
                body()
            } catch (caught: Throwable) {
                failure = caught
            }
            for (step in cleanup) {
                try {
                    step()
                } catch (caught: Throwable) {
                    val primary = failure
                    if (primary == null) failure = caught
                    else if (primary !== caught) primary.addSuppressed(caught)
                }
            }
            failure?.let { throw it }
        }

        fun deadline(milliseconds: Long) = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(milliseconds), "launch parent")

        fun assertWorkerReady(process: Process) {
            assertContentEquals("ready\n".toByteArray(), process.inputStream.readNBytes(6), "shell did not reach the permit gate")
        }

        fun ensureStopped(process: Process) {
            if (process.isAlive) process.destroyForcibly()
            assertTrue(process.waitFor(2, TimeUnit.SECONDS), "fixture process could not be reaped")
        }

        fun awaitLaunchPoolIdle() {
            val pool = ANALYSIS_PROCESS_LAUNCH_EXECUTOR as ThreadPoolExecutor
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (pool.activeCount != 0 && System.nanoTime() < end) Thread.yield()
            assertEquals(0, pool.activeCount, "late launch cleanup must finish before another test begins")
        }

        fun awaitIgnoringInterrupts(latch: CountDownLatch) {
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (latch.count != 0L) {
                val remaining = end - System.nanoTime()
                check(remaining > 0) { "fixture launch was not released" }
                try { latch.await(remaining, TimeUnit.NANOSECONDS) } catch (_: InterruptedException) { }
            }
        }
    }
}

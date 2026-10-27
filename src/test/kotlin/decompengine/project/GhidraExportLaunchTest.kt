package decompengine.project

import decompengine.analysis.ANALYSIS_PROCESS_LAUNCH_EXECUTOR
import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.BundledGhidraVerificationProcess
import decompengine.analysis.GhidraAnalysisException
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class GhidraExportLaunchTest {
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
            val failures = FixtureFailures()
            try {
                caller.thread.start()
                assertTrue(starter.entered.await(2, TimeUnit.SECONDS), "gated worker did not reach its stdin wait")
                caller.interrupt()
                caller.assertFailure<InterruptedException>()
                fixture.assertPriorEvidence()
            } catch (failure: Throwable) {
                failures.record(failure)
            } finally {
                failures.attempt { starter.release.countDown() }
                failures.attempt { caller.thread.join(2_000) }
                failures.attempt { starter.assertLateWorkerReaped() }
                failures.attempt { fixture.assertPriorEvidence() }
                failures.attempt { awaitLaunchPoolIdle() }
            }
            failures.finish(listOf(starter), listOf(caller))
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
            val failures = FixtureFailures()
            try {
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
            } catch (failure: Throwable) {
                failures.record(failure)
            } finally {
                starters.forEach { starter -> failures.attempt { starter.release.countDown() } }
                (callers + rejectedExport + rejectedVerifier).forEach { caller ->
                    failures.attempt { if (caller.thread.isAlive) caller.interrupt() }
                    failures.attempt { caller.thread.join(2_000) }
                }
                // Release every starter even when one assertion fails, then reap every real worker.
                starters.forEach { starter -> failures.attempt { starter.assertLateWorkerReaped() } }
                (fixtures + thirdFixture).forEach { fixture ->
                    failures.attempt { fixture.assertPriorEvidence() }
                }
                failures.attempt { awaitLaunchPoolIdle() }
            }
            failures.finish(starters, callers + rejectedExport + rejectedVerifier)
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
                assertEquals(model.toAbsolutePath().normalize(), Path.of(invocation.postScripts.single().arguments.last()))
                listOf("/bin/sh", "-c", """
                    printf 'ready\n'
                    IFS= read -r permit || exit 70
                    [ "${'$'}permit" = 1 ] || exit 71
                    printf 'activated\n' > "${'$'}1"
                    cp "${'$'}2" "${'$'}3"
                    printf 'new analysis evidence\n' > "${'$'}4"
                """.trimIndent(), "gated-export", activation.toString(), canonical.toString(), model.toString(), report.toString())
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
        val startFailure = AtomicReference<Throwable?>()
        private val startStage = AtomicInteger()
        private var cleanupStage = 0
        private var cleanupFailedAt = 0
        private var stopAttempted = false
        private var stopCompleted = false

        fun start(command: List<String>, work: Path): Process {
            try {
                startStage.set(1)
                val process = ProcessBuilder(command).directory(work.toFile()).start()
                launched.complete(process)
                startStage.set(2)
                assertWorkerReady(process)
                startStage.set(3)
                entered.countDown()
                awaitIgnoringInterrupts(release)
                startStage.set(4)
                return process
            } catch (failure: Throwable) {
                startFailure.set(failure)
                throw failure
            }
        }

        fun assertLateWorkerReaped() {
            val failures = FixtureFailures()
            try {
                cleanupStage = 1
                val process = launched.get(2, TimeUnit.SECONDS)
                try {
                    cleanupStage = 2
                    process.onExit().get(2, TimeUnit.SECONDS)
                    cleanupStage = 3
                    assertFalse(process.isAlive, "late gated worker survived cancellation")
                    cleanupStage = 4
                    assertFalse(ProcessHandle.of(process.pid()).map { it.isAlive }.orElse(false), "late PID remains live")
                    cleanupStage = 5
                } catch (failure: Throwable) {
                    cleanupFailedAt = cleanupStage
                    failures.record(failure)
                } finally {
                    failures.attempt {
                        stopAttempted = true
                        ensureStopped(process)
                        stopCompleted = true
                    }
                }
            } catch (failure: Throwable) {
                cleanupFailedAt = cleanupStage
                failures.record(failure)
            }
            failures.throwIfFailed()
        }

        // Only fixture-owned state; no process/environment/output inspection or late signaling.
        fun state(index: Int): String =
            "worker=$index,startStage=${startStage.get()},startFailed=${startFailure.get() != null}," +
                "entered=${entered.count},release=${release.count},handleDone=${launched.isDone}," +
                "handleCancelled=${launched.isCancelled},handleExceptional=${launched.isCompletedExceptionally}," +
                "cleanupStage=$cleanupStage,cleanupFailedAt=$cleanupFailedAt," +
                "stopAttempted=$stopAttempted,stopCompleted=$stopCompleted"
    }

    /** Keeps the first observed failure and every distinct, finite fixture cleanup failure. */
    private class FixtureFailures {
        private var primary: Throwable? = null
        private val retained = ArrayList<Throwable>()

        fun record(failure: Throwable) {
            if (retained.any { it === failure }) return
            retained.add(failure)
            val first = primary
            if (first == null) primary = failure else first.addSuppressed(failure)
        }

        fun attempt(action: () -> Unit) {
            try { action() } catch (failure: Throwable) { record(failure) }
        }

        fun throwIfFailed() { primary?.let { throw it } }

        fun finish(workers: List<BlockedStartedWorker>, callers: List<ExportCall>) {
            if (primary == null) return
            // Expected caller failures are context only when an assertion/cleanup has failed.
            workers.forEach { it.startFailure.get()?.let(::record) }
            callers.forEach { it.failure.get()?.let(::record) }
            workers.forEachIndexed { index, worker -> record(FixtureState(worker.state(index))) }
            callers.forEachIndexed { index, caller -> record(FixtureState(caller.state(index))) }
            throwIfFailed()
        }
    }

    private class FixtureState(message: String) : RuntimeException(message.take(512), null, false, false)

    private class ExportCall(operation: () -> Any) {
        val failure = AtomicReference<Throwable?>()
        val elapsedNanos = AtomicLong()
        private val started = AtomicBoolean()
        private val completed = AtomicBoolean()
        private val interruptRequested = AtomicBoolean()
        val thread = Thread {
            this.started.set(true)
            val started = System.nanoTime()
            try {
                operation()
            } catch (caught: Throwable) {
                failure.set(caught)
            } finally {
                elapsedNanos.set(System.nanoTime() - started)
                completed.set(true)
            }
        }

        fun interrupt() {
            interruptRequested.set(true)
            thread.interrupt()
        }

        fun state(index: Int): String =
            "caller=$index,started=${started.get()},completed=${completed.get()}," +
                "interruptRequested=${interruptRequested.get()},failurePresent=${failure.get() != null}"

        inline fun <reified T : Throwable> assertFailure(maximumMillis: Long = 2_000): T {
            thread.join(maximumMillis - 100)
            assertFalse(thread.isAlive, "caller did not return within its bounded launch allowance")
            assertTrue(elapsedNanos.get() < TimeUnit.MILLISECONDS.toNanos(maximumMillis), "launch did not return promptly")
            return assertIs<T>(failure.get())
        }
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

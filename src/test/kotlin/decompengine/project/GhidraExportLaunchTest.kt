package decompengine.project

import decompengine.analysis.ANALYSIS_PROCESS_LAUNCH_EXECUTOR
import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.BundledGhidraVerificationProcess
import decompengine.analysis.BoundedAnalysisProcessLaunch
import decompengine.analysis.GhidraAnalysisException
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.reflect.Proxy
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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
        val rootHandle = fixtureHandle(1001L, initialAlive = true, refusesTermination = false)
        val child = fixtureHandle(1002L, initialAlive = true, refusesTermination = true, parent = rootHandle)
        val clock = AtomicLong()
        val launches = AtomicInteger()
        val controller = BoundedAnalysisProcessLaunch()
        val process = FixtureOwnedProcess(rootHandle)
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
    fun `process tree waits for Java exit acknowledgement after native handle exits`() {
        val handleAlive = AtomicBoolean(true)
        val processAlive = AtomicBoolean(true)
        val handle = fixtureHandle(2000L, initialAlive = true, refusesTermination = false, alive = handleAlive)
        val process = object : Process() {
            override fun getOutputStream(): java.io.OutputStream = ByteArrayOutputStream()
            override fun getInputStream(): java.io.InputStream = ByteArrayInputStream(byteArrayOf())
            override fun getErrorStream(): java.io.InputStream = ByteArrayInputStream(byteArrayOf())
            override fun waitFor(): Int = if (processAlive.get()) throw IllegalThreadStateException() else 70
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
                processAlive.set(false)
                return true
            }
            override fun exitValue(): Int = if (processAlive.get()) throw IllegalThreadStateException() else 70
            override fun destroy() { handleAlive.set(false) }
            override fun destroyForcibly(): Process { handleAlive.set(false); return this }
            override fun isAlive(): Boolean = processAlive.get()
            override fun toHandle(): ProcessHandle = handle
        }
        val cleanup = ExportProcessTree(
            process, Duration.ZERO, sleepNanos = {},
            descendantObservation = { _, _ -> },
        ).terminate()

        assertTrue(cleanup.confirmedAbsent)
        assertFalse(process.isAlive)
        assertFalse(handle.isAlive)
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

        val stuckRoot = fixtureHandle(2002L, initialAlive = true, refusesTermination = false)
        val stubborn = fixtureHandle(2003L, initialAlive = true, refusesTermination = true, parent = stuckRoot)
        val stuck = FixtureOwnedProcess(stuckRoot)
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
    fun `monitor observed child remains owned after it disappears from root snapshots`() {
        for (refusesTermination in listOf(false, true)) {
            val process = FixtureOwnedProcess(fixtureHandle(2301L, initialAlive = true, refusesTermination = false))
            val child = fixtureHandle(2302L, initialAlive = true, refusesTermination = refusesTermination, parent = process.toHandle())
            val observations = AtomicInteger()
            val clock = AtomicLong()
            val tree = ExportProcessTree(
                process, Duration.ofMillis(100), nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { _, retain ->
                    if (observations.getAndIncrement() == 0) retain(child)
                },
            )

            tree.residentBytes() // Only the resource monitor sees the child before reparenting.
            assertEquals(2, tree.retainedHandleCount())
            assertEquals(null, tree.remainingCleanupNanosOrNull(), "monitoring must not start the cleanup window")
            val result = tree.terminate()

            assertEquals(!refusesTermination, result.confirmedAbsent)
            assertEquals(refusesTermination, child.isAlive)
            assertEquals(2, tree.retainedHandleCount(), "later empty snapshots must not forget the child")
            assertEquals(null, result.failure, "a live child is not an observation failure")
            assertEquals(if (refusesTermination) TimeUnit.MILLISECONDS.toNanos(5_100) else 0L, clock.get())
            val observationsAtCutoff = observations.get()
            tree.residentBytes()
            assertEquals(observationsAtCutoff, observations.get(), "a settled cleanup proof must not be mutated by a queued monitor")
            assertEquals(result, tree.terminate(), "repeated cleanup must not renew its window")
        }
    }

    @Test
    fun `monitor observation failure retains yielded child and remains fail closed`() {
        val process = FixtureOwnedProcess(fixtureHandle(2401L, initialAlive = true, refusesTermination = false))
        val child = fixtureHandle(2402L, initialAlive = true, refusesTermination = false, parent = process.toHandle())
        val observations = AtomicInteger()
        val clock = AtomicLong()
        val tree = ExportProcessTree(
            process, Duration.ZERO, nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { _, retain ->
                if (observations.getAndIncrement() == 0) {
                    retain(child)
                    throw java.io.IOException("fixture monitor stream failed after yielding child")
                }
            },
        )

        val failure = assertFailsWith<GhidraAnalysisException> { tree.residentBytes() }
        assertEquals(2, tree.retainedHandleCount())
        assertEquals(null, tree.remainingCleanupNanosOrNull())
        val result = tree.terminate()
        assertFalse(result.confirmedAbsent, "later successful snapshots cannot erase a failed observation")
        assertTrue(result.failure === failure)
        assertFalse(child.isAlive, "the partially observed child must still be signalled")
        assertEquals(TimeUnit.SECONDS.toNanos(5), clock.get())
    }

    @Test
    fun `monitor inventory enforces existing handle bound without dropping retained identities`() {
        val process = FixtureOwnedProcess(fixtureHandle(2501L, initialAlive = true, refusesTermination = false))
        val children = (1..32).map {
            fixtureHandle(2510L + it, initialAlive = true, refusesTermination = false, parent = process.toHandle())
        }
        val observations = AtomicInteger()
        val clock = AtomicLong()
        val tree = ExportProcessTree(
            process, Duration.ZERO, nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { _, retain ->
                if (observations.getAndIncrement() == 0) children.forEach(retain)
            },
        )

        val failure = assertFailsWith<GhidraAnalysisException> { tree.residentBytes() }
        assertTrue(failure.cause?.message.orEmpty().contains("exceeded 32 retained handles"))
        assertEquals(32, tree.retainedHandleCount(), "the existing limit includes the root")
        val result = tree.terminate()
        assertFalse(result.confirmedAbsent)
        assertTrue(result.failure === failure)
        assertTrue(children.take(31).none { it.isAlive }, "all retained identities must be signalled")
        assertTrue(children.last().isAlive, "an unretained handle must not be signalled")
        assertEquals(TimeUnit.SECONDS.toNanos(5), clock.get())
    }

    @Test
    fun `actual export monitor retains a reparented survivor and refuses subsequent admission`() =
        inControlTemporaryDirectory { root ->
            val reports = root.resolve("analysis/reports")
            Files.createDirectories(reports)
            val priorModel = "accepted model before monitor observation\n".toByteArray()
            val priorCalls = "accepted calls before monitor observation\n".toByteArray()
            reports.resolve("program_model.json").writeBytes(priorModel)
            reports.resolve("program_model_calls.json").writeBytes(priorCalls)
            val monitored = CountDownLatch(1)
            val reparented = AtomicBoolean()
            val rootHandle = fixtureHandle(2601L, initialAlive = true, refusesTermination = false)
            val child = fixtureHandle(2602L, initialAlive = true, refusesTermination = true, parent = rootHandle)
            val process = FixtureOwnedProcess(
                rootHandle,
                beforeWait = {
                    check(monitored.await(3, TimeUnit.SECONDS)) { "actual resource monitor did not observe the child" }
                    reparented.set(true)
                },
            )
            val clock = AtomicLong()
            val controller = BoundedAnalysisProcessLaunch()
            val launches = AtomicInteger()
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { listOf("fixture-owned-export") },
                limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
                processStarter = { _, _ -> launches.incrementAndGet(); process },
            ).withProcessLifecycleForTests(controller) { owned, grace ->
                ExportProcessTree(owned, grace, nanoTime = clock::get,
                    sleepNanos = { nanos -> clock.addAndGet(nanos) },
                    descendantObservation = { _, retain ->
                        if (!reparented.get()) {
                            retain(child)
                            monitored.countDown()
                        }
                    },
                )
            }

            assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis")) }
            assertEquals(0L, monitored.count, "the actual executeExport monitor must feed the cleanup inventory")
            assertTrue(reparented.get())
            assertTrue(child.isAlive)
            assertTrue(controller.hasQuarantinedProcess(process))
            val owner = assertIs<ExportProcessCleanupOwner>(controller.retainedQuarantineOwnerForTests(process))
            assertEquals(2, owner.processTree.retainedHandleCount())
            assertFalse(owner.processTree.terminate().confirmedAbsent, "a monitor-observed survivor cannot count as absent")
            assertEquals(TimeUnit.SECONDS.toNanos(5), clock.get())
            assertContentEquals(priorModel, reports.resolve("program_model.json").readBytes())
            assertContentEquals(priorCalls, reports.resolve("program_model_calls.json").readBytes())
            assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("second-analysis")) }
            assertEquals(1, launches.get())
        }

    @Test
    fun `interrupted cleanup waits still confirm later exit and restore interruption`() {
        for (grace in listOf(Duration.ZERO, Duration.ofMillis(100))) {
            val childAlive = AtomicBoolean(true)
            val rootHandle = fixtureHandle(2101L, initialAlive = true, refusesTermination = false)
            val child = fixtureHandle(2102L, initialAlive = true, refusesTermination = true, alive = childAlive, parent = rootHandle)
            val process = FixtureOwnedProcess(rootHandle)
            val clock = AtomicLong()
            val waits = AtomicInteger()
            val tree = ExportProcessTree(
                process, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos ->
                    clock.addAndGet(nanos)
                    if (waits.incrementAndGet() == 1) throw InterruptedException("fixture cleanup wait interrupted")
                    childAlive.set(false)
                },
                descendantObservation = { _, retain -> retain(child) },
            )
            try {
                // Both entry and in-flight interruption must be preserved, not treated as unknown liveness.
                Thread.currentThread().interrupt()
                val result = tree.terminate()
                assertTrue(result.confirmedAbsent)
                assertEquals(null, result.failure)
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals(2, waits.get(), "exit observations must not exhaust the cleanup window")
                assertEquals(TimeUnit.MILLISECONDS.toNanos(50), clock.get())
                assertEquals(result, tree.terminate(), "cached cleanup must preserve the caller interrupt too")
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }
    }

    @Test
    fun `interrupted cleanup preserves operation failure without quarantining a confirmed owner`() = inControlTemporaryDirectory { root ->
        val primary = IllegalStateException("authored wait failure before interrupted cleanup")
        val process = FixtureOwnedProcess(fixtureHandle(2201L, initialAlive = true, refusesTermination = false), primary)
        val childAlive = AtomicBoolean(true)
        val child = fixtureHandle(2202L, initialAlive = true, refusesTermination = true, alive = childAlive, parent = process.toHandle())
        val clock = AtomicLong()
        val waits = AtomicInteger()
        val controller = BoundedAnalysisProcessLaunch()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> process },
        ).withProcessLifecycleForTests(controller) { owned, grace ->
            ExportProcessTree(owned, grace, nanoTime = clock::get,
                sleepNanos = { nanos ->
                    clock.addAndGet(nanos)
                    if (waits.incrementAndGet() == 1) throw InterruptedException("fixture cleanup wait interrupted")
                    childAlive.set(false)
                },
                descendantObservation = { _, retain -> retain(child) },
            )
        }
        try {
            val failure = assertFailsWith<IllegalStateException> {
                analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis"))
            }
            assertTrue(failure === primary)
            assertFalse(controller.hasQuarantinedOwner())
            assertTrue(Thread.currentThread().isInterrupted)
            Thread.interrupted()
            val next = FixtureOwnedProcess(fixtureHandle(2203L, initialAlive = false, refusesTermination = false))
            assertTrue(controller.start({}, { next }, { error("admitted process must not use late cleanup") }) === next)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `process tree retains a new process identity that reuses a dead handle PID`() {
        val rootHandle = fixtureHandle(6201L, initialAlive = true, refusesTermination = false)
        val rootProcess = FixtureOwnedProcess(rootHandle)
        val oldAlive = AtomicBoolean(true)
        val oldDeadHandle = fixtureHandle(
            6210L, initialAlive = true, refusesTermination = true, alive = oldAlive, parent = rootHandle, startMillis = 6_210_000L,
        )
        val newLiveHandle = fixtureHandle(
            6210L, initialAlive = true, refusesTermination = true, parent = rootHandle, startMillis = 6_210_500L,
        )
        assertEquals(oldDeadHandle.pid(), newLiveHandle.pid())
        val observations = AtomicInteger()
        val clock = AtomicLong()
        val tree = ExportProcessTree(
            rootProcess, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { _, retain ->
                if (observations.getAndIncrement() == 0) {
                    retain(oldDeadHandle)
                    oldAlive.set(false) // Exits after being retained; the root then reuses its PID.
                } else retain(newLiveHandle)
            },
        )
        // Both identities are observed while the owned root is alive, as the resource monitor does.
        tree.residentBytes()
        tree.residentBytes()
        assertEquals(3, tree.retainedHandleCount())

        val result = tree.terminate()

        assertFalse(result.confirmedAbsent, "the later live identity must not be hidden by its reused PID")
        assertTrue(newLiveHandle.isAlive)
        assertEquals(3, tree.retainedHandleCount(), "root and both distinct same-PID handles must remain retained")
    }

    @Test
    fun `descendants enumerated through a reused root PID are refused and never signalled`() {
        for (boundBeforeReuse in listOf(true, false)) {
            val table = FixtureProcessTable()
            val owned = table.spawn(7001L, startMillis = 1_000L, parent = null)
            val process = FixtureOwnedProcess(table.bound(owned))
            val clock = AtomicLong()
            fun processTree() = ExportProcessTree(
                process, Duration.ZERO,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
            )
            val boundTree = if (boundBeforeReuse) processTree().also { it.residentBytes() } else null
            // The owned root exits and is reaped; an unrelated process tree then reuses its PID.
            process.destroy()
            table.exit(owned)
            val stranger = table.spawn(7001L, startMillis = 2_000L, parent = null)
            val strangerChild = table.spawn(7002L, startMillis = 2_100L, parent = stranger)
            table.spawn(7003L, startMillis = 2_200L, parent = strangerChild)
            val tree = boundTree ?: processTree()
            assertEquals(listOf(7002L, 7003L), table.bound(owned).descendants().map { it.pid() }.toList(),
                "a stale root handle enumerates the PID's new holder, as OpenJDK does")

            val result = tree.terminate()

            assertEquals(emptyList(), table.signalled.toList(), "no process outside the owned launch may be signalled")
            assertTrue(result.confirmedAbsent, "the owned root is absent; refused processes are not owned")
            assertEquals(null, result.failure)
            assertEquals(1, tree.retainedHandleCount(), "only the owned root may remain retained")
            assertEquals(
                listOf(7002L to 2_100L, 7003L to 2_200L),
                result.refusedHandles.map { it.pid to it.startInstant?.toEpochMilli() },
                "refused handles must be recorded in the cleanup evidence",
            )
            assertTrue(result.diagnostic.orEmpty().startsWith("refused handles: 7002@2100"), result.diagnostic)
        }
    }

    @Test
    fun `retained descendant handle is not signalled after its PID is reused`() {
        val table = FixtureProcessTable()
        val owned = table.spawn(7101L, startMillis = 1_000L, parent = null)
        val ownedChild = table.spawn(7102L, startMillis = 1_100L, parent = owned)
        val process = FixtureOwnedProcess(table.bound(owned))
        val clock = AtomicLong()
        val tree = ExportProcessTree(
            process, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            // Retain handles without a recorded start time: they signal whichever process holds the PID.
            descendantObservation = { root, retain ->
                root.descendants().use { stream -> stream.forEach { retain(table.byPid(it.pid())) } }
            },
        )
        tree.residentBytes()
        assertEquals(2, tree.retainedHandleCount())
        // The owned child exits and an unrelated process reuses its PID before cleanup.
        table.exit(ownedChild)
        val stranger = table.spawn(7102L, startMillis = 3_000L, parent = null)

        val result = tree.terminate()

        assertEquals(listOf(owned), table.signalled.toList(), "only the owned root may be signalled")
        assertTrue(table.holder(7102L) === stranger)
        assertTrue(result.confirmedAbsent, "the retained identity is absent even though its PID is live")
        assertEquals(null, result.failure)
        assertEquals(
            listOf(ExportProcessRefusal(7102L, java.time.Instant.ofEpochMilli(3_000L), "reuses the PID of retained 7102@1100")),
            result.refusedHandles,
        )
    }

    @Test
    fun `grandchild reparented between the scan and its admission stays retained and blocks absence`() {
        for (stubborn in listOf(true, false)) {
            val table = FixtureProcessTable()
            val owned = table.spawn(7201L, startMillis = 1_000L, parent = null)
            val child = table.spawn(7202L, startMillis = 1_100L, parent = owned)
            val grandchild = table.spawn(7203L, startMillis = 1_200L, parent = child, stubborn = stubborn)
            val process = FixtureOwnedProcess(table.bound(owned), onDestroy = { table.exit(owned) })
            val clock = AtomicLong()
            val tree = ExportProcessTree(
                process, Duration.ZERO,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { root, retain ->
                    val snapshot = root.descendants().use { it.toList() }
                    // The child exits after the snapshot; init adopts the grandchild before admission.
                    if (table.holder(child.pid) === child) table.exit(child)
                    snapshot.forEach(retain)
                },
            )

            val result = tree.terminate()

            assertEquals(table.init.pid, grandchild.parentPid, "the grandchild was reparented to init")
            assertEquals(listOf(grandchild), table.signalled.distinct(), "a possibly owned survivor is signalled after its recheck")
            assertEquals(2, tree.retainedHandleCount(), "root and the reparented grandchild remain retained")
            assertEquals(emptyList(), result.refusedHandles)
            assertEquals(!stubborn, result.confirmedAbsent, "a live possibly owned survivor keeps cleanup unconfirmed")
            if (stubborn) {
                assertTrue(result.diagnostic.orEmpty().contains("possible-descendant=7203"), result.diagnostic)
                assertEquals(TimeUnit.SECONDS.toNanos(5), clock.get())
            }
        }
    }

    @Test
    fun `reparented survivor quarantines export admission without open pipes`() = inControlTemporaryDirectory { root ->
        val table = FixtureProcessTable()
        val owned = table.spawn(7251L, startMillis = 1_000L, parent = null)
        val child = table.spawn(7252L, startMillis = 1_100L, parent = owned)
        table.spawn(7253L, startMillis = 1_200L, parent = child, stubborn = true)
        // Fixture streams are empty in-memory buffers, so no pipe keeps capture unsettled.
        val process = FixtureOwnedProcess(table.bound(owned), onDestroy = { table.exit(owned) })
        val clock = AtomicLong()
        val launches = AtomicInteger()
        val controller = BoundedAnalysisProcessLaunch()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> launches.incrementAndGet(); process },
        ).withProcessLifecycleForTests(controller) { started, grace ->
            ExportProcessTree(
                started, grace,
                nanoTime = clock::get,
                sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = { handle, retain ->
                    val snapshot = handle.descendants().use { it.toList() }
                    if (table.holder(child.pid) === child) table.exit(child)
                    snapshot.forEach(retain)
                },
            )
        }

        val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis")) }

        assertTrue(generateSequence(failure as Throwable) { it.cause }.plus(failure.suppressed.asSequence())
            .any { it.message.orEmpty().contains("possible-descendant=7253") }, failure.stackTraceToString())
        assertTrue(controller.hasQuarantinedOwner(), "cleanup must not report absence while the survivor lives")
        assertFailsWith<GhidraAnalysisException> { analyzer.analyze(root.resolve("unused-input"), root.resolve("second")) }
        assertEquals(1, launches.get())
    }

    @Test
    fun `unavailable root identity leaves descendants possibly owned and the root to its Process`() {
        val table = FixtureProcessTable()
        val owned = table.spawn(7301L, startMillis = 1_000L, parent = null, unreadable = true)
        val child = table.spawn(7302L, startMillis = 1_100L, parent = owned)
        val processSignals = AtomicInteger()
        val process = FixtureOwnedProcess(table.bound(owned), onDestroy = { processSignals.incrementAndGet(); table.exit(owned) })
        val clock = AtomicLong()
        val tree = ExportProcessTree(process, Duration.ZERO, nanoTime = clock::get, sleepNanos = { nanos -> clock.addAndGet(nanos) })

        val result = tree.terminate()

        assertEquals(listOf(child), table.signalled.toList(), "only the rechecked descendant is signalled through a handle")
        assertEquals(1, processSignals.get(), "the root is signalled only through its owned Process")
        assertTrue(result.confirmedAbsent)
        assertEquals(
            listOf(ExportProcessRefusal(7301L, null, "root identity could not be rechecked before signalling")),
            result.refusedHandles,
        )
    }

    @Test
    fun `known limit - same-tick PID reuse is not told apart by start instant (launch-bound ownership is tracked in #2009)`() {
        val table = FixtureProcessTable()
        val owned = table.spawn(7401L, startMillis = 1_000L, parent = null)
        val ownedChild = table.spawn(7402L, startMillis = 1_100L, parent = owned)
        val process = FixtureOwnedProcess(table.bound(owned), onDestroy = { table.exit(owned) })
        val clock = AtomicLong()
        val tree = ExportProcessTree(
            process, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { root, retain ->
                root.descendants().use { stream -> stream.forEach { retain(table.byPid(it.pid())) } }
            },
        )
        tree.residentBytes()
        table.exit(ownedChild)
        // An unrelated process reuses the PID within the same clock tick, so its start instant matches.
        val sameTickStranger = table.spawn(7402L, startMillis = 1_100L, parent = null)

        tree.terminate()

        assertTrue(sameTickStranger in table.signalled,
            "this records the known limit: a start instant cannot tell a same-tick reuse apart")
    }

    @Test
    fun `identity change during admission is recorded apart from failed ancestry`() {
        val table = FixtureProcessTable()
        val owned = table.spawn(7501L, startMillis = 1_000L, parent = null)
        val child = table.spawn(7502L, startMillis = 1_100L, parent = owned)
        val process = FixtureOwnedProcess(table.bound(owned), onDestroy = { table.exit(owned) })
        val clock = AtomicLong()
        table.beforeParentRead = { pid ->
            if (pid == child.pid && table.holder(pid) === child) {
                table.exit(child)
                table.spawn(child.pid, startMillis = 4_000L, parent = null)
            }
        }
        val tree = ExportProcessTree(
            process, Duration.ZERO,
            nanoTime = clock::get,
            sleepNanos = { nanos -> clock.addAndGet(nanos) },
            descendantObservation = { root, retain ->
                root.descendants().use { stream -> stream.forEach { retain(table.byPid(it.pid())) } }
            },
        )

        val result = tree.terminate()

        assertEquals(1, tree.retainedHandleCount(), "the changed PID is not retained")
        assertEquals(
            listOf(ExportProcessRefusal(7502L, java.time.Instant.ofEpochMilli(1_100L), "PID changed identity to 7502@4000 during admission")),
            result.refusedHandles,
        )
        assertTrue(table.signalled.none { it.pid == child.pid })
    }

    @Test
    fun `export publishes refusal evidence in the resource report on success and failure`() = inControlTemporaryDirectory { root ->
        fun refusalPids(work: Path): List<Long> {
            val usage = kotlinx.serialization.json.Json.parseToJsonElement(
                work.resolve("reports/ghidra_resource_usage.json").readText(),
            ) as JsonObject
            assertEquals(JsonPrimitive(false), usage["refusedProcessHandlesTruncated"])
            return (usage.getValue("refusedProcessHandles") as JsonArray).map { refusal ->
                val fields = refusal as JsonObject
                assertTrue((fields.getValue("reason") as JsonPrimitive).content.startsWith("parent "), refusal.toString())
                (fields.getValue("pid") as JsonPrimitive).content.toLong()
            }
        }
        // A replacement process holds the launched root's PID; its child is refused, never signalled.
        fun replacementObservation(
            table: FixtureProcessTable,
            visible: () -> Boolean = { true },
        ): (ProcessHandle, (ProcessHandle) -> Unit) -> Unit {
            var replacementChild: FixtureProcessTable.Entry? = null
            return { handle, retain ->
                if (visible()) {
                    val child = replacementChild ?: table.spawn(9_100_002L, startMillis = 2_000L,
                        parent = table.spawn(handle.pid(), startMillis = 1L, parent = null)).also { replacementChild = it }
                    retain(table.bound(child))
                }
            }
        }

        val input = root.resolve("input.bin")
        val inputBytes = "fixture executable bytes".toByteArray()
        Files.write(input, inputBytes)
        val inputSha256 = sha256(inputBytes)
        val modelBytes = RecoveredProgramModel(inputSha256 = inputSha256, functions = emptyList()).toJson().toByteArray()
        val successTable = FixtureProcessTable()
        val succeeded = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { invocation ->
                val modelCandidate = Path.of(invocation.postScripts.single().arguments.last())
                Files.write(modelCandidate, modelBytes)
                Files.setPosixFilePermissions(modelCandidate, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
                listOf("/bin/true")
            },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { command, work -> ProcessBuilder(command).directory(work.toFile()).start() },
        ).withProcessLifecycleForTests(BoundedAnalysisProcessLaunch()) { started, grace ->
            // Appear only after the report is first published, so cleanup must republish it.
            ExportProcessTree(started, grace, descendantObservation = replacementObservation(successTable) {
                Files.exists(root.resolve("success/reports/ghidra_resource_usage.json"))
            })
        }
        succeeded.analyze(input, root.resolve("success"))
        assertEquals(listOf(9_100_002L), refusalPids(root.resolve("success")), "evidence survives a successful export")
        assertEquals(emptyList(), successTable.signalled.toList())

        val primary = IllegalStateException("authored process wait failure")
        val failureTable = FixtureProcessTable()
        val failedProcess = FixtureOwnedProcess(fixtureHandle(8001L, initialAlive = true, refusesTermination = false), primary)
        val failed = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { listOf("fixture-owned-export") },
            limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO),
            processStarter = { _, _ -> failedProcess },
        ).withProcessLifecycleForTests(BoundedAnalysisProcessLaunch()) { started, grace ->
            val clock = AtomicLong()
            ExportProcessTree(started, grace, nanoTime = clock::get, sleepNanos = { nanos -> clock.addAndGet(nanos) },
                descendantObservation = replacementObservation(failureTable))
        }
        assertTrue(assertFailsWith<IllegalStateException> { failed.analyze(input, root.resolve("failure")) } === primary)
        assertEquals(listOf(9_100_002L), refusalPids(root.resolve("failure")), "evidence survives a failed export")
        assertEquals(emptyList(), failureTable.signalled.toList())
    }

    @Test
    fun `operation failure remains primary with unconfirmed cleanup suppressed`() = inControlTemporaryDirectory { root ->
        val primary = IllegalStateException("authored process wait failure")
        val process = FixtureOwnedProcess(
            fixtureHandle(3001L, initialAlive = true, refusesTermination = false), primary,
        )
        val clock = AtomicLong()
        val controller = BoundedAnalysisProcessLaunch()
        val child = fixtureHandle(3002L, initialAlive = true, refusesTermination = true, parent = process.toHandle())
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
    fun `stream close submission failure preserves primary and quarantines retained cleanup owner`() =
        inControlTemporaryDirectory { root ->
            val primary = IllegalStateException("authored process wait failure")
            val rejected = java.util.concurrent.RejectedExecutionException("fixture close submission rejected")
            val process = FixtureOwnedProcess(
                fixtureHandle(4101L, initialAlive = true, refusesTermination = false),
                waitFailure = primary,
            )
            val clock = AtomicLong()
            val controller = BoundedAnalysisProcessLaunch()
            val launches = AtomicInteger()
            val closeSubmissions = AtomicInteger()
            val closeActions = AtomicInteger()
            val modelCandidate = AtomicReference<Path?>()
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { invocation ->
                    modelCandidate.set(Path.of(invocation.postScripts.single().arguments.last()))
                    listOf("fixture-owned-export")
                },
                limits = GhidraProgramModelExportLimits(
                    wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO,
                ),
                processStarter = { _, _ -> launches.incrementAndGet(); process },
            ).withProcessLifecycleForTests(controller) { owned, grace ->
                ExportProcessTree(
                    owned, grace,
                    // Cleanup settlement uses real bounded sleeps; advance the injected clock
                    // on each remaining-window read so the rejected close expires deterministically.
                    nanoTime = { clock.getAndAdd(TimeUnit.SECONDS.toNanos(1)) },
                    sleepNanos = { nanos -> clock.addAndGet(nanos) },
                    descendantObservation = { _, _ -> },
                )
            }.withStreamCloseSubmitterForTests { task ->
                if (closeSubmissions.getAndIncrement() == 0) throw rejected
                closeActions.incrementAndGet()
                task.run()
                CompletableFuture.completedFuture(null)
            }

            val failure = assertFailsWith<IllegalStateException> {
                analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis"))
            }

            assertTrue(failure === primary, "a close-task submission failure must not replace the operation failure")
            assertTrue(failure.suppressed.any {
                generateSequence(it) { cause -> cause.cause }.any { cause -> cause === rejected }
            }, "the rejected stream-close submission must remain visible")
            assertEquals(3, closeSubmissions.get(), "cleanup must continue submitting closures for every stream")
            assertEquals(2, closeActions.get(), "all non-rejected stream-close tasks must execute")
            assertTrue(controller.hasQuarantinedProcess(process))
            val owner = assertIs<ExportProcessCleanupOwner>(controller.retainedQuarantineOwnerForTests(process))
            assertEquals(listOf(checkNotNull(modelCandidate.get())), owner.outputCandidates)
            assertEquals(3, owner.streams.size)
            assertTrue(owner.tasks.isNotEmpty(), "the quarantine owner must retain its capture/close task set")
            assertTrue(owner.taskSettlements.any { !it.get() }, "the rejected close remains explicitly unsettled")

            assertFailsWith<GhidraAnalysisException> {
                analyzer.analyze(root.resolve("unused-next-input"), root.resolve("next-analysis"))
            }
            assertEquals(1, launches.get(), "quarantine must refuse admission before another process starts")
        }

    @Test
    fun `queued monitor and capture tasks run after stream closure before the cleanup cutoff`() =
        inControlTemporaryDirectory { root ->
            val primary = IllegalStateException("authored process wait failure")
            val process = FixtureOwnedProcess(
                fixtureHandle(4201L, initialAlive = true, refusesTermination = false),
                waitFailure = primary,
            )
            val clock = AtomicLong()
            val controller = BoundedAnalysisProcessLaunch()
            val taskExecutor = QueuedExecutor()
            val queuedBeforeDrain = AtomicInteger()
            val drainedQueuedTasks = AtomicBoolean()
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { listOf("fixture-owned-export") },
                limits = GhidraProgramModelExportLimits(
                    wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO,
                ),
                processStarter = { _, _ -> process },
            ).withProcessLifecycleForTests(controller) { owned, grace ->
                ExportProcessTree(
                    owned, grace,
                    // Settlement uses real bounded sleeps; this clock advances each time the
                    // existing cleanup window is read, without adding time to that window.
                    nanoTime = { clock.getAndAdd(TimeUnit.SECONDS.toNanos(1)) },
                    sleepNanos = { nanos -> clock.addAndGet(nanos) },
                    descendantObservation = { _, _ -> },
                )
            }.withAnalysisTaskExecutorForTests(taskExecutor).withStreamCloseSubmitterForTests { task ->
                task.run()
                if (drainedQueuedTasks.compareAndSet(false, true)) {
                    queuedBeforeDrain.set(taskExecutor.pendingCount())
                    taskExecutor.runQueued()
                }
                CompletableFuture.completedFuture(null)
            }

            val failure = assertFailsWith<IllegalStateException> {
                analyzer.analyze(root.resolve("unused-input"), root.resolve("analysis"))
            }

            assertTrue(failure === primary, "the process operation failure remains primary")
            assertEquals(3, queuedBeforeDrain.get(), "monitor and both captures should be queued before cleanup drains them")
            assertEquals(3, taskExecutor.completedCount())
            assertEquals(0, taskExecutor.pendingCount(), "every queued body must actually run")
            assertFalse(controller.hasQuarantinedOwner(), "settled tasks must not poison subsequent process admission")
            assertFalse(process.isAlive)
        }

    @Test
    fun `returned call-site receipt names the readable published artifact`() = inControlTemporaryDirectory { root ->
        val input = root.resolve("input.bin")
        val inputBytes = "fixture executable bytes".toByteArray()
        Files.write(input, inputBytes)
        val inputSha256 = sha256(inputBytes)
        val modelBytes = RecoveredProgramModel(inputSha256 = inputSha256, functions = emptyList())
            .toJson().toByteArray()
        val publishedCallOutput = root.resolve("analysis/reports/program_model_calls.json")
            .toAbsolutePath().normalize()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { invocation ->
                val callArguments = invocation.postScripts.last().arguments
                val callCandidate = Path.of(callArguments.last())
                val modelCandidate = Path.of(invocation.postScripts.first().arguments.last())
                Files.write(modelCandidate, modelBytes)
                Files.setPosixFilePermissions(
                    modelCandidate,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                )
                val callBytes = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "analysisToolSha256" to JsonPrimitive(callArguments[1]),
                    "calls" to JsonArray(emptyList()),
                    "exporterSha256" to JsonPrimitive(callArguments[0]),
                    "imageBaseAddress" to JsonPrimitive("0x0"),
                    "inputSha256" to JsonPrimitive(inputSha256),
                    "programModelSha256" to JsonPrimitive(sha256(modelBytes)),
                    "schemaVersion" to JsonPrimitive(1),
                )))
                Files.write(callCandidate, callBytes)
                Files.setPosixFilePermissions(
                    callCandidate,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                )
                listOf("/bin/true")
            },
            limits = GhidraProgramModelExportLimits(
                wallClockTimeout = Duration.ofSeconds(5), terminationGrace = Duration.ZERO,
            ),
            processStarter = { command, work -> ProcessBuilder(command).directory(work.toFile()).start() },
        )

        val result = analyzer.analyzeWithCallSites(input, root.resolve("analysis"))

        assertEquals(publishedCallOutput, result.callSites.path)
        assertTrue(Files.isRegularFile(result.callSites.path))
        val reread = RecoveredCallSites.read(
            result.callSites.path,
            result.callSites.artifactSha256,
            result.callSites.bindings,
        ) {}
        assertEquals(publishedCallOutput, reread.path)
        assertEquals(result.callSites.artifactSha256, reread.artifactSha256)
        assertEquals(result.callSites.bindings, reread.bindings)
    }

    @Test
    fun `concurrent unconfirmed owners are all retained and repeated reports coalesce`() = inControlTemporaryDirectory { root ->
        val processes = listOf(
            FixtureOwnedProcess(fixtureHandle(5001L, initialAlive = true, refusesTermination = false)),
            FixtureOwnedProcess(fixtureHandle(5002L, initialAlive = true, refusesTermination = false)),
        )
        val children = listOf(
            fixtureHandle(5011L, initialAlive = true, refusesTermination = true, parent = processes[0].toHandle()),
            fixtureHandle(5012L, initialAlive = true, refusesTermination = true, parent = processes[1].toHandle()),
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
    fun `quarantine publication is not blocked by an admitted executor submission`() {
        val submissionEntered = CountDownLatch(1)
        val releaseSubmission = CountDownLatch(1)
        val executorCalls = AtomicInteger()
        val executor = Executor { task ->
            executorCalls.incrementAndGet()
            submissionEntered.countDown()
            releaseSubmission.await()
            Thread(task, "fixture-blocked-submission").apply { isDaemon = true; start() }
        }
        val controller = BoundedAnalysisProcessLaunch(executor)
        val admittedProcess = FixtureOwnedProcess(fixtureHandle(6001L, initialAlive = true, refusesTermination = false))
        val failedProcess = FixtureOwnedProcess(fixtureHandle(6002L, initialAlive = true, refusesTermination = false))
        val starterCalls = AtomicInteger()
        val admittedResult = AtomicReference<Process?>()
        val admittedFailure = AtomicReference<Throwable?>()
        val launchThread = Thread {
            try {
                admittedResult.set(controller.start(
                    checkpoint = {},
                    processStarter = { starterCalls.incrementAndGet(); admittedProcess },
                    stopLateProcess = {},
                ))
            } catch (failure: Throwable) {
                admittedFailure.set(failure)
            }
        }

        try {
            launchThread.start()
            assertTrue(submissionEntered.await(3, TimeUnit.SECONDS), "admitted call did not reach executor submission")

            val cleanupFailure = IllegalStateException("second process cleanup was unconfirmed")
            val owner = Any()
            val quarantineReturned = CountDownLatch(1)
            val quarantineThread = Thread {
                controller.quarantineUnconfirmedCleanup(cleanupFailure, failedProcess, owner)
                quarantineReturned.countDown()
            }
            quarantineThread.start()
            assertTrue(quarantineReturned.await(3, TimeUnit.SECONDS),
                "quarantine publication must complete while executor submission remains blocked")
            assertTrue(launchThread.isAlive, "the original admission should still be blocked in submit")

            val refused = assertFailsWith<GhidraAnalysisException> {
                controller.start(
                    checkpoint = {},
                    processStarter = { error("quarantined admission must not run") },
                    stopLateProcess = {},
                )
            }
            assertTrue(refused.cause === cleanupFailure)
            assertEquals(0, starterCalls.get())
            assertEquals(1, executorCalls.get())

            releaseSubmission.countDown()
            launchThread.join(3_000)
            quarantineThread.join(3_000)
            assertFalse(launchThread.isAlive)
            assertFalse(quarantineThread.isAlive)
            assertTrue(admittedFailure.get() == null, admittedFailure.get()?.toString().orEmpty())
            assertTrue(admittedResult.get() === admittedProcess,
                "a process whose admission linearized before quarantine must complete ownership transfer")
            assertEquals(1, starterCalls.get())
            assertEquals(1, executorCalls.get(), "the refused call must not submit to the executor")
            assertTrue(controller.hasQuarantinedProcess(failedProcess))
        } finally {
            releaseSubmission.countDown()
            launchThread.join(3_000)
        }
    }

    @Test
    fun `quarantine publication is not blocked by an inline admitted process starter`() {
        val starterEntered = CountDownLatch(1)
        val releaseStarter = CountDownLatch(1)
        val executor = Executor { task -> task.run() }
        val controller = BoundedAnalysisProcessLaunch(executor)
        val admittedProcess = FixtureOwnedProcess(fixtureHandle(6101L, initialAlive = true, refusesTermination = false))
        val failedProcess = FixtureOwnedProcess(fixtureHandle(6102L, initialAlive = true, refusesTermination = false))
        val starterCalls = AtomicInteger()
        val admittedResult = AtomicReference<Process?>()
        val admittedFailure = AtomicReference<Throwable?>()
        var quarantineThread: Thread? = null
        val launchThread = Thread {
            try {
                admittedResult.set(controller.start(
                    checkpoint = {},
                    processStarter = {
                        starterCalls.incrementAndGet()
                        starterEntered.countDown()
                        releaseStarter.await()
                        admittedProcess
                    },
                    stopLateProcess = {},
                ))
            } catch (failure: Throwable) {
                admittedFailure.set(failure)
            }
        }

        try {
            launchThread.start()
            assertTrue(starterEntered.await(3, TimeUnit.SECONDS), "inline executor did not enter the admitted starter")
            val cleanupFailure = IllegalStateException("another owned process cleanup was unconfirmed")
            val quarantineReturned = CountDownLatch(1)
            val publisher = Thread {
                controller.quarantineUnconfirmedCleanup(cleanupFailure, failedProcess, Any())
                quarantineReturned.countDown()
            }
            quarantineThread = publisher
            publisher.start()
            assertTrue(quarantineReturned.await(3, TimeUnit.SECONDS),
                "inline process creation must not hold the quarantine lock")
            assertTrue(launchThread.isAlive, "the inline process starter should still be blocked")
            assertFailsWith<GhidraAnalysisException> {
                controller.start(
                    checkpoint = {},
                    processStarter = { error("quarantined admission must not run") },
                    stopLateProcess = {},
                )
            }
            assertEquals(1, starterCalls.get())
        } finally {
            releaseStarter.countDown()
            launchThread.join(3_000)
            quarantineThread?.join(3_000)
        }

        assertFalse(launchThread.isAlive)
        assertTrue(admittedFailure.get() == null, admittedFailure.get()?.toString().orEmpty())
        assertTrue(admittedResult.get() === admittedProcess,
            "the launch admitted before quarantine must still transfer its returned process")
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
        private val beforeWait: () -> Unit = {},
        private val onDestroy: () -> Unit = {},
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
            beforeWait()
            waitFailure?.let { throw it }
            return false
        }
        override fun exitValue(): Int = if (alive.get()) throw IllegalThreadStateException() else 70
        override fun destroy(): Unit { if (alive.getAndSet(false)) onDestroy() }
        override fun destroyForcibly(): Process { if (alive.getAndSet(false)) onDestroy(); return this }
        override fun isAlive(): Boolean = alive.get()
        override fun toHandle(): ProcessHandle = handle
    }

    private class QueuedExecutor : java.util.concurrent.Executor {
        private val tasks = java.util.ArrayDeque<Runnable>()
        private val completed = AtomicInteger()

        override fun execute(command: Runnable) {
            synchronized(tasks) { tasks.addLast(command) }
        }

        fun pendingCount(): Int = synchronized(tasks) { tasks.size }
        fun completedCount(): Int = completed.get()

        fun runQueued() {
            while (true) {
                val task = synchronized(tasks) { if (tasks.isEmpty()) null else tasks.removeFirst() } ?: return
                try { task.run() } finally { completed.incrementAndGet() }
            }
        }
    }

    private fun fixtureHandle(
        pid: Long,
        initialAlive: Boolean,
        refusesTermination: Boolean,
        alive: AtomicBoolean = AtomicBoolean(initialAlive),
        parent: ProcessHandle? = null,
        startMillis: Long = pid,
    ): ProcessHandle {
        lateinit var handle: ProcessHandle
        handle = Proxy.newProxyInstance(
            ProcessHandle::class.java.classLoader,
            arrayOf(ProcessHandle::class.java),
        ) { _, method, arguments ->
            when (method.name) {
                "pid" -> pid
                "isAlive" -> alive.get()
                "info" -> fixtureInfo(startMillis.takeIf { alive.get() })
                "destroy", "destroyForcibly" -> {
                    if (!refusesTermination) alive.set(false)
                    !refusesTermination
                }
                "supportsNormalTermination" -> true
                "parent" -> java.util.Optional.ofNullable(parent)
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

    /**
     * Deterministic native process table in which an exited PID can be reused by an unrelated process.
     * [bound] handles behave like OpenJDK handles with a recorded start time; [byPid] handles resolve
     * whichever process holds the PID when used, as a handle without a recorded start time would.
     */
    private class FixtureProcessTable {
        /** [stubborn] processes survive signals; [unreadable] ones report no start instant. */
        class Entry(val pid: Long, val startMillis: Long, @Volatile var parentPid: Long?, val stubborn: Boolean, val unreadable: Boolean) {
            override fun toString() = "FixtureProcess[$pid@$startMillis]"
        }

        private val holders = HashMap<Long, Entry>()
        val signalled = java.util.concurrent.CopyOnWriteArrayList<Entry>()
        /** Adopts the children of every exited fixture process, as init does without a subreaper. */
        val init: Entry = spawn(1L, startMillis = 1L, parent = null)
        @Volatile
        var beforeParentRead: (Long) -> Unit = {}

        @Synchronized
        fun spawn(pid: Long, startMillis: Long, parent: Entry?, stubborn: Boolean = false, unreadable: Boolean = false): Entry {
            check(pid !in holders) { "PID $pid is still held" }
            return Entry(pid, startMillis, parent?.pid, stubborn, unreadable).also { holders[pid] = it }
        }

        @Synchronized
        fun exit(entry: Entry) {
            check(holders.remove(entry.pid, entry)) { "$entry does not hold its PID" }
            holders.values.filter { it.parentPid == entry.pid }.forEach { it.parentPid = init.pid }
        }

        @Synchronized
        fun holder(pid: Long): Entry? = holders[pid]

        @Synchronized
        private fun children(parent: Entry): List<Entry> =
            holders.values.filter { it.parentPid == parent.pid && it.startMillis >= parent.startMillis }.sortedBy { it.pid }

        fun bound(entry: Entry): ProcessHandle = handle(entry.pid) { holder(entry.pid)?.takeIf { it === entry } }

        fun byPid(pid: Long): ProcessHandle = handle(pid) { holder(pid) }

        private fun handle(pid: Long, resolve: () -> Entry?): ProcessHandle {
            lateinit var handle: ProcessHandle
            handle = Proxy.newProxyInstance(
                ProcessHandle::class.java.classLoader,
                arrayOf(ProcessHandle::class.java),
            ) { _, method, arguments ->
                when (method.name) {
                    "pid" -> pid
                    "isAlive" -> resolve() != null
                    "info" -> fixtureInfo(resolve()?.takeUnless { it.unreadable }?.startMillis)
                    "parent" -> {
                        beforeParentRead(pid)
                        java.util.Optional.ofNullable(resolve()?.parentPid?.let(::holder)?.let(::bound))
                    }
                    // Like OpenJDK, enumerate breadth-first from whichever process holds this PID now.
                    "descendants" -> generateSequence(listOfNotNull(holder(pid))) { level ->
                        level.flatMap(::children).takeIf { it.isNotEmpty() }
                    }.drop(1).flatten().map(::bound).toList().stream()
                    "children" -> java.util.stream.Stream.empty<ProcessHandle>()
                    "destroy", "destroyForcibly" -> resolve()?.let {
                        signalled.add(it)
                        if (!it.stubborn) exit(it)
                        true
                    } ?: false
                    "supportsNormalTermination" -> true
                    "onExit" -> CompletableFuture.completedFuture(handle)
                    "compareTo" -> java.lang.Long.compare(pid, (arguments!![0] as ProcessHandle).pid())
                    "toString" -> "FixtureTableHandle[$pid]"
                    "hashCode" -> pid.hashCode()
                    "equals" -> handle === arguments?.get(0)
                    else -> null
                }
            } as ProcessHandle
            return handle
        }
    }

    private companion object {
        fun fixtureInfo(startMillis: Long?): ProcessHandle.Info = Proxy.newProxyInstance(
            ProcessHandle.Info::class.java.classLoader,
            arrayOf(ProcessHandle.Info::class.java),
        ) { _, method, _ ->
            when (method.name) {
                "startInstant" -> java.util.Optional.ofNullable(startMillis?.let(java.time.Instant::ofEpochMilli))
                "toString" -> "FixtureProcessInfo[$startMillis]"
                "hashCode" -> startMillis.hashCode()
                "equals" -> false
                else -> java.util.Optional.empty<Any>()
            }
        } as ProcessHandle.Info

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

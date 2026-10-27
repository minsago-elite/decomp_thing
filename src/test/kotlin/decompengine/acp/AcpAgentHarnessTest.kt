package decompengine.acp

import com.agentclientprotocol.model.LATEST_PROTOCOL_VERSION
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.execute
import decompengine.agent.executeReceipt
import decompengine.repair.CapturedRepairStagingAuthority
import decompengine.repair.RepairResourceBudget
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ArchivalProjectAuditor
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.ReconstructionProfiles
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.ReconstructionAdapters
import decompengine.project.budgetedAnalyzer
import java.nio.file.Path
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.collect
import org.junit.jupiter.api.Timeout

@Timeout(value = 60, unit = TimeUnit.SECONDS)
class AcpAgentHarnessTest {
    private fun assertFixtureManifestAcquisitionBounds() {
        val events = List(3) { java.io.IOException("host mounts changed during runtime manifest") }
        var attempts = 0
        val digest = "a".repeat(64)
        assertEquals(digest, acquireFixtureRuntimeManifest {
            val attempt = attempts++
            if (attempt < 2) throw events[attempt]
            digest
        })
        assertEquals(3, attempts)

        attempts = 0
        val persistent = assertFailsWith<java.io.IOException> {
            acquireFixtureRuntimeManifest { throw events[attempts++] }
        }
        assertSame(events.last(), persistent, "persistent instability preserves the last original refusal")
        assertEquals(3, attempts)

        listOf(
            java.io.IOException("runtime manifest input changed"),
            IllegalStateException("host mounts changed during runtime manifest"),
        ).forEach { other ->
            attempts = 0
            val failure = assertFailsWith<Exception> {
                acquireFixtureRuntimeManifest {
                    attempts++
                    throw other
                }
            }
            assertSame(other, failure)
            assertEquals(1, attempts, "other failures propagate immediately")
        }
        println("acp-fixture-manifest-acquisition transientAttempts=3 persistentAttempts=3 otherFailures=immediate")
    }

    @Test
    fun `durable session failure context retains only bounded owned facts and the original receipt`() {
        val phaseType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcomeType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val diagnosticType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = diagnosticType.getDeclaredConstructor(phaseType, outcomeType, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java, String::class.java).apply { isAccessible = true }
        for (phase in DurableSessionPhase.entries) {
            for (stage in listOf("CONSTRUCTING", "ADMITTED")) {
                val admission = "mount-admission-v1 stage=$stage initialMounts=12 initialControls=2 owner=true initialFast=false"
                val witness = constructor.newInstance(
                    phaseType.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
                    outcomeType.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null, admission) as Throwable
                val native = java.io.IOException("PRIVATE-cause /PRIVATE/path").apply { addSuppressed(witness) }
                val originalSuppressed = native.suppressed
                val facts = AgentFailure(AgentFailureKind.UNAVAILABLE, "PRIVATE-failure", details = mapOf("PRIVATE" to "PRIVATE"))
                val outcome = AgentExecutionOutcome.Failed(facts)
                val evidence = AcpInvocationEvidenceSnapshot(
                    null, AcpExecutionLifecyclePhase.REQUEST_BOUND, AcpExecutionCleanupDisposition.UNVERIFIED,
                    null, null, null, emptyList(), emptyList(), emptyList(), null,
                    AcpExecutionEvidenceCompleteness(false, false, false), null,
                )
                val receipt = AgentExecutionReceipt(AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION,
                    "a".repeat(64), "b".repeat(64)), outcome, evidence, native)
                var calls = 0
                var original: AgentExecutionException? = null
                val asserted = assertFailsWith<AssertionError> {
                    withDurableSessionFailureContext(phase) {
                        calls++
                        try { receipt.requireResult() } catch (failure: AgentExecutionException) {
                            original = failure
                            throw failure
                        }
                    }
                }
                assertEquals(1, calls)
                val retained = assertNotNull(original)
                assertSame(retained, asserted.cause)
                assertSame(receipt, retained.receipt)
                assertSame(facts, retained.failure)
                assertSame(native, retained.cause)
                assertSame(outcome, receipt.outcome)
                assertSame(evidence, receipt.providerEvidence)
                assertSame(native, receipt.failureCause)
                assertContentEquals(originalSuppressed, native.suppressed)
                assertTrue(retained.suppressed.isEmpty())
                val context = asserted.message.orEmpty()
                assertTrue(context.startsWith(phase.label + " [phase=REQUEST_BOUND;kind=UNAVAILABLE;cleanup=UNVERIFIED"), context)
                assertTrue(requireNotNull(contextMountWitness().message) in context, context)
                assertTrue(admission in context, context)
                assertFalse("PRIVATE" in context || "/" in context, context)
                assertTrue(context.length <= 4096 && context.all { it.code in 32..126 })
            }
        }
    }

    @Test
    fun `durable session context never retries and preserves unexpected or unrenderable failures`() {
        for (phase in DurableSessionPhase.entries) {
            val returned = Any()
            var calls = 0
            assertSame(returned, withDurableSessionFailureContext(phase) { calls++; returned })
            assertEquals(1, calls)
            val unexpected = listOf(java.io.IOException("PRIVATE"), InterruptedException("PRIVATE"),
                java.util.concurrent.CancellationException("PRIVATE"), AssertionError("PRIVATE"))
            for (original in unexpected) {
                calls = 0
                val thrown = assertFailsWith<Throwable> {
                    withDurableSessionFailureContext(phase) { calls++; throw original }
                }
                assertSame(original, thrown)
                assertEquals(1, calls)
            }
            val opaque = object : java.io.IOException("PRIVATE") {
                override fun getStackTrace(): Array<StackTraceElement> = throw AssertionError("PRIVATE-rendering")
            }
            val original = AgentExecutionException(AgentFailure(AgentFailureKind.UNAVAILABLE, "PRIVATE"), opaque)
            calls = 0
            val thrown = assertFailsWith<AgentExecutionException> {
                withDurableSessionFailureContext(phase) { calls++; throw original }
            }
            assertSame(original, thrown)
            assertSame(opaque, thrown.cause)
            assertTrue(thrown.suppressed.isEmpty())
            assertEquals(1, calls)
        }
    }

    @Test
    fun `session preference failure context retains only the existing closed mount witness`() {
        val cause = java.io.IOException("PRIVATE-message /PRIVATE/path").apply {
            stackTrace = arrayOf(StackTraceElement("decompengine.acp.PRIVATE-class", "PRIVATE-method", "PRIVATE-file", 123))
            addSuppressed(contextMountWitness())
            addSuppressed(java.io.IOException("PRIVATE-suppressed"))
        }
        val failure = AgentExecutionException(decompengine.agent.AgentFailure(AgentFailureKind.CONFIGURATION,
            "PRIVATE-failure", details = mapOf("PRIVATE-key" to "PRIVATE-value")), cause)
        val context = sessionPreferencePhaseFailureContext("known-case", failure, null)
        assertTrue("phase=missing;kind=CONFIGURATION;cleanup=missing" in context, context)
        assertTrue("mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA" in context, context)
        assertFalse("PRIVATE" in context || "/" in context, context)
        assertTrue(context.length <= 4096 && context.all { it.code in 32..126 })
        val phase = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val type = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = type.getDeclaredConstructor(phase, outcome, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java, String::class.java).apply { isAccessible = true }
        val constructing = "mount-admission-v1 stage=CONSTRUCTING initialMounts=12 initialControls=2 owner=true initialFast=false"
        val admitted = "mount-admission-v1 stage=ADMITTED initialMounts=7 initialControls=0 owner=false initialFast=true"
        for (admission in listOf(null, constructing, admitted, "PRIVATE /PRIVATE/path", "x".repeat(257), admitted + "\nPRIVATE")) {
            val diagnostic = constructor.newInstance(
                phase.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
                outcome.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null, admission) as Throwable
            val bounded = sessionPreferencePhaseFailureContext("known-case", AgentExecutionException(
                decompengine.agent.AgentFailure(AgentFailureKind.CONFIGURATION, "PRIVATE"), diagnostic), null)
            assertTrue(requireNotNull(contextMountWitness().message) in bounded, bounded)
            if (admission == constructing || admission == admitted) assertTrue(requireNotNull(admission) in bounded, bounded)
            else assertFalse("mount-admission-v1" in bounded, bounded)
            assertFalse("PRIVATE" in bounded || "/" in bounded, bounded)
            assertTrue(bounded.length <= 4096 && bounded.all { it.code in 32..126 })
        }
    }

    @Test
    fun `session preference failure context bounds cycles frame prefixes and suppressed witness inspection`() {
        val first = java.io.IOException("PRIVATE-first")
        val second = IllegalStateException("PRIVATE-second")
        first.initCause(second); second.initCause(first)
        first.stackTrace = (List(64) { StackTraceElement("PRIVATE-class", "PRIVATE-method", "PRIVATE-file", 1) } +
            StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "LinuxBubblewrapBoundary.kt", 4321)).toTypedArray()
        first.addSuppressed(Throwable("mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA"))
        first.addSuppressed(Throwable("PRIVATE-suppressed"))
        first.addSuppressed(contextMountWitness()) // Beyond the fixed two-suppression inspection bound.
        val failure = AgentExecutionException(decompengine.agent.AgentFailure(AgentFailureKind.CONFIGURATION, "PRIVATE"), first)
        val context = sessionPreferencePhaseFailureContext("known-case", failure, null)
        assertFalse("PRIVATE" in context || "mount-event-v1" in context || "4321" in context, context)
        assertTrue(context.length <= 4096 && context.all { it.code in 32..126 })
        assertTrue(Regex(";cause\\[").findAll(context).count() <= 8)
    }

    private fun contextMountWitness(): Throwable {
        val phase = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val type = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = type.getDeclaredConstructor(phase, outcome, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java).apply { isAccessible = true }
        return constructor.newInstance(phase.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
            outcome.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null) as Throwable
    }

    @Test
    fun `reused cleanup latch is inert across two receipts and never accumulates timing records`() {
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(0, 1) })
        val cleanup = AcpCleanupProofFailure("authored retained cleanup failure")
        val facts = decompengine.agent.AgentFailure(AgentFailureKind.INTERNAL, "authored unresolved cleanup")
        val stored = Class.forName("decompengine.acp.AcpAgentHarnessKt")
            .getDeclaredMethod("mappedPrelaunchFailure", decompengine.agent.AgentFailure::class.java,
                Throwable::class.java, RuntimeCopyStatistics.Prefix::class.java)
            .apply { isAccessible = true }.invoke(null, facts, cleanup, prefix) as AgentExecutionException
        val originalSuppressed = stored.suppressed.toList()
        assertEquals(1, originalSuppressed.size)
        val root = Path.of(".").toAbsolutePath().normalize()
        val harness = AcpAgentHarness(AcpProcessConfiguration(
            executable = root.resolve("build/inert-never-launched-acp"), sandboxBoundary = null,
        )) // No live harness/fixture/Python/user-runtime/gate-helper discovery.
        @Suppress("UNCHECKED_CAST")
        val latch = AcpAgentHarness::class.java.getDeclaredField("unresolvedCleanupFailure")
            .apply { isAccessible = true }.get(harness) as java.util.concurrent.atomic.AtomicReference<AgentExecutionException?>
        latch.set(stored)
        var callbacks = 0
        val request = AgentExecutionRequest(
            objective = "inert retained cleanup refusal", workspaceRoots = listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()),
            cancellation = AgentCancellation { callbacks++; error("scheduler/cancellation must not be reached") },
        )
        repeat(2) {
            val receipt = harness.executeReceipt(request) { callbacks++; error("event/model callback must not be reached") }
            assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
            assertTrue(receipt.failureCause === stored)
            assertTrue((receipt.outcome as AgentExecutionOutcome.Failed).failure === facts)
            val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
            assertEquals(AcpExecutionLifecyclePhase.REQUEST_BOUND, evidence.phaseReached)
            assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, evidence.cleanupDisposition)
            assertNull(evidence.diagnostics)
            assertNull(evidence.sandboxEvidence)
            assertTrue(latch.get() === stored)
            assertEquals(originalSuppressed, stored.suppressed.toList())
        }
        assertEquals(0, callbacks)
        assertTrue(stored.cause === cleanup)
    }

    @Test
    fun `stdout owner retains accounted EOF without a second read after teardown`() {
        val bytes = "trailing output already accounted".toByteArray()
        val input = object : java.io.InputStream() {
            val reads = AtomicInteger()
            override fun read(): Int {
                val index = reads.getAndIncrement()
                if (index < bytes.size) return bytes[index].toInt() and 0xff
                if (index == bytes.size) return -1
                throw java.io.IOException("a second EOF read is unavailable after teardown")
            }
        }

        val observation = observeClosingStdout(input)

        assertTrue(observation.naturallyDrained)
        assertEquals(bytes.size + 1, input.reads.get(), "proved EOF must suppress a redundant reader")
        assertEquals(bytes.size.toLong(), observation.output.observedBytes)
        assertFalse(observation.output.limitExceeded)
    }

    @Test
    fun `stdout read failure without EOF never proves produced output drained`() {
        val input = object : java.io.InputStream() {
            override fun read(): Int = throw java.io.IOException("no EOF was observed")
        }

        val observation = observeClosingStdout(input)

        assertFalse(observation.naturallyDrained)
        assertEquals(0L, observation.output.observedBytes)
        assertFalse(observation.output.limitExceeded)
    }

    @Test
    fun `stdout EOF after forced descriptor closure never certifies unread output`() {
        val observation = observeClosingStdout(java.io.ByteArrayInputStream(byteArrayOf()), forcedClose = true)

        assertFalse(observation.naturallyDrained)
        assertEquals(0L, observation.output.observedBytes)
    }

    @Test
    fun `stdout EOF proof cannot finish before terminal latch and owner release`() {
        val bytes = "unterminated JSON-RPC frame".toByteArray()
        val eofObserved = CountDownLatch(1)
        val releaseEof = CountDownLatch(1)
        lateinit var control: Pair<Class<*>, Any>
        val input = object : java.io.InputStream() {
            var index = 0
            override fun read(): Int {
                if (index < bytes.size) return bytes[index++].toInt() and 0xff
                // Hold the existing EOF-publication boundary before the consumer can process
                // its terminal frame and finally block. This is a non-native state control.
                control.first.getDeclaredMethod("recordStdoutEof").apply { isAccessible = true }
                    .invoke(control.second)
                eofObserved.countDown()
                if (!releaseEof.await(3, TimeUnit.SECONDS)) throw java.io.IOException("EOF barrier was not released")
                return -1
            }
        }
        control = newStdoutAccountingControl(input)
        val (type, running) = control
        fun field(name: String): Any = type.getDeclaredField(name).apply { isAccessible = true }.get(running)
        val finished = field("stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>
        val terminal = field("failure") as java.util.concurrent.atomic.AtomicReference<*>
        val owner = field("stdoutOwnership") as java.util.concurrent.atomic.AtomicReference<*>
        val frames = type.getDeclaredMethod("stdoutFrames", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val flow = frames.invoke(running, 4096, 128) as kotlinx.coroutines.flow.Flow<String>
        val executor = Executors.newSingleThreadExecutor()
        val execution = executor.submit {
            kotlinx.coroutines.runBlocking { flow.collect { error("an unterminated frame must not dispatch") } }
        }
        try {
            assertTrue(eofObserved.await(3, TimeUnit.SECONDS))
            assertTrue((field("stdoutNaturallyDrained") as AtomicBoolean).get())
            assertFalse(finished.isDone, "EOF proof must not finish the still-owned consumer")
            assertNull(terminal.get(), "terminal processing is held behind the EOF barrier")
            assertEquals("FRAME_CONSUMER", owner.get().toString())

            releaseEof.countDown()
            execution.get(3, TimeUnit.SECONDS)

            assertTrue(finished.isDone)
            assertEquals("UNCLAIMED", owner.get().toString())
            assertEquals("AcpMalformedFrameFailure", assertNotNull(terminal.get()).javaClass.simpleName)
            assertTrue((terminal.get() as Throwable).message.orEmpty().contains("unterminated"))
        } finally {
            releaseEof.countDown()
            try { execution.get(3, TimeUnit.SECONDS) } finally { executor.shutdownNow() }
        }
    }

    @Test
    fun `shutdown close cannot invalidate EOF returned before its publication`() = withReturnedStdoutEof { control, release, execution, closes ->
        val (type, running) = control
        val close = type.getDeclaredMethod("tryCloseStdout").apply { isAccessible = true }
        assertEquals(false, close.invoke(running), "a returned read still owns the publication boundary")
        assertEquals(0, closes.get())
        assertFalse((stdoutControlField(control, "stdoutClosedForUnblocking") as AtomicBoolean).get())
        assertFalse((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
        assertFalse((stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).isDone)

        release.countDown()
        execution.get(3, TimeUnit.SECONDS)

        assertTrue((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
        assertTrue((stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).isDone)
        assertEquals(true, close.invoke(running))
        assertEquals(1, closes.get())
        assertFalse((stdoutControlField(control, "stdoutClosedForUnblocking") as AtomicBoolean).get())
    }

    @Test
    fun `actual stdout closure before a read never certifies synthetic EOF`() {
        val closed = AtomicBoolean()
        val reads = AtomicInteger()
        val input = object : java.io.InputStream() {
            override fun read(): Int { reads.incrementAndGet(); return if (closed.get()) -1 else 42 }
            override fun close() { closed.set(true) }
        }
        val control = newStdoutAccountingControl(input)
        val (type, running) = control
        assertEquals(true, type.getDeclaredMethod("tryCloseStdout").apply { isAccessible = true }.invoke(running))
        assertTrue(closed.get())
        (stdoutControlField(control, "closing") as AtomicBoolean).set(true)
        collectStdoutControl(control)
        (stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).get(1, TimeUnit.SECONDS)
        assertFalse((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
        assertEquals(0, reads.get(), "a closed stream cannot supply a positive EOF witness")
    }

    @Test
    fun `unfinished stdout owner requires cleanup failure and retains admission`() = withReturnedStdoutEof { control, release, execution, _ ->
        val (type, running) = control
        val cleanup = type.getDeclaredMethod("stdoutReaderCleanupFailure").apply { isAccessible = true }
        val failure = assertIs<AgentExecutionException>(cleanup.invoke(running))
        assertEquals(AgentFailureKind.INTERNAL, failure.failure.kind)
        assertEquals(mapOf("phase" to "stdout-drain", "reason" to "readerUnfinished"), failure.failure.details)
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(maximumActive = 1))
        val permit = assertNotNull(scheduler.acquire("held-stdout", AgentCancellation.NONE) { false })
        // The production cleanup latch charges this unfinished owner even after its native
        // process absence proof. This state control exercises the retained admission policy.
        permit.finish(cleanupUnverified = true)
        val rejected = assertFailsWith<AgentExecutionException> {
            scheduler.acquire("another-workspace", AgentCancellation.NONE) { false }
        }
        assertEquals(AgentFailureKind.UNAVAILABLE, rejected.failure.kind)
        assertEquals("cleanupUnverified", rejected.failure.details["reason"])
        release.countDown()
        execution.get(3, TimeUnit.SECONDS)
        assertNull(cleanup.invoke(running), "the owner eventually relinquishes its stream")
        assertEquals(1, scheduler.snapshot().quarantined, "late completion cannot release a retained slot")
    }

    @Test
    fun `stdout refusal preserves skipped EOF operand separately from later observation`() {
        val control = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        val ownedEof = stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean
        // This inactive in-memory control has no stdout reader. A skipped operand must
        // not dereference even a poisoned reference; restore it before later observation.
        setStdoutControlField(control, "stdoutNaturallyDrained", null)
        val decision = try { stdoutRefusalDecision(control) as Enum<*> } finally {
            setStdoutControlField(control, "stdoutNaturallyDrained", ownedEof)
        }
        assertEquals("FINISHED_FALSE_EOF_NOT_READ", decision.name)
        assertTrue(stdoutControlField(control, "stdoutNaturallyDrained") === ownedEof)
        ownedEof.set(true)
        recordStdoutSnapshot(control, 0, "WAIT_TIMEOUT")
        recordStdoutSnapshot(control, 2, decision.name)
        setStdoutControlField(control, "stdoutFirstWaitMillis", 100L)
        val record = freezeStdoutFacts(control)
        assertTrue(record.contains("s3=FINISHED_FALSE_EOF_NOT_READ/UNCLAIMED/false/true/"), record)
        assertTrue(record.contains("finalMs=NOT_ALLOCATED"), record)
        assertTrue(record.contains("s2=NOT_REACHED"), record)
        assertFalse((stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).isDone)
        @Suppress("UNCHECKED_CAST")
        val completed = stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<Unit>
        completed.complete(Unit)
        ownedEof.set(false)
        assertEquals("NATURAL_EOF_FALSE", (stdoutRefusalDecision(control) as Enum<*>).name)
        ownedEof.set(true)
        assertNull(stdoutRefusalDecision(control))
    }

    @Test
    fun `stdout snapshots retain only three owned samples allocations and first IO code`() {
        val control = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        val produced = stdoutControlField(control, "producedOutput")
        produced.javaClass.getDeclaredMethod("record", Int::class.javaPrimitiveType).apply { isAccessible = true }.invoke(produced, 7)
        setStdoutControlField(control, "stdoutFirstWaitMillis", 100L)
        setStdoutControlField(control, "stdoutFinalWaitMillis", 41L)
        recordStdoutSnapshot(control, 0, "WAIT_TIMEOUT")
        (stdoutControlField(control, "stdoutClosedForUnblocking") as AtomicBoolean).set(true)
        recordStdoutSnapshot(control, 1, "CLOSE_CLOSED")
        @Suppress("UNCHECKED_CAST")
        val completedReader = stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<Unit>
        completedReader.complete(Unit)
        recordStdoutSnapshot(control, 2, "NATURAL_EOF_FALSE")
        val record = freezeStdoutFacts(control)
        assertTrue(record.startsWith("ACP_STDOUT_SHUTDOWN_V1 firstMs=100 finalMs=41 "), record)
        assertTrue(record.contains("s1=WAIT_TIMEOUT/UNCLAIMED/false/false/false/NONE/7/4096/false"), record)
        assertTrue(record.contains("s2=CLOSE_CLOSED/UNCLAIMED/false/false/true/NONE/7/4096/false"), record)
        assertEquals(3, Regex(" s[123]=").findAll(record).count())
        assertEquals(record, validatedStdoutFacts(record))
        (stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).set(true)
        recordStdoutSnapshot(control, 3, "WAIT_COMPLETED")
        assertEquals(record, freezeStdoutFacts(control), "frozen facts cannot resample or re-render later state")
        val invalidSlot = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        recordStdoutSnapshot(invalidSlot, 3, "WAIT_COMPLETED")
        assertEquals("ACP_STDOUT_SHUTDOWN_V1 DIAGNOSTIC_UNAVAILABLE", freezeStdoutFacts(invalidSlot))
    }

    @Test
    fun `stdout wait and close classifications use only existing result types`() {
        for ((failure, expected) in listOf(
            null to "WAIT_COMPLETED",
            java.util.concurrent.TimeoutException("not retained") to "WAIT_TIMEOUT",
            InterruptedException("not retained") to "WAIT_INTERRUPTED",
            ExecutionException(IllegalStateException("not retained")) to "WAIT_EXECUTION_ERROR",
            IllegalStateException("not retained") to "WAIT_OTHER_ERROR",
        )) assertEquals(expected, (stdoutFactsCall("waitOperation", failure) as Enum<*>).name)
        for ((closed, failure, expected) in listOf(
            Triple(true, null, "CLOSE_CLOSED"), Triple(false, null, "CLOSE_NOT_ACQUIRED"),
            Triple(null, java.io.IOException("not retained"), "CLOSE_IO_ERROR"),
            Triple(null, IllegalStateException("not retained"), "CLOSE_OTHER_ERROR"),
        )) assertEquals(expected, (stdoutFactsCall("closeOperation", closed, failure) as Enum<*>).name)
    }

    @Test
    fun `stdout physical and guard IO classifications never create EOF or replace original IO`() {
        val physical = java.io.IOException("untrusted IO text must not enter facts")
        val directRead = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        val sameRead = assertFailsWith<java.lang.reflect.InvocationTargetException> {
            directRead.first.declaredMethods.single { it.name == "readStdout" }.apply { isAccessible = true }
                .invoke(directRead.second, { throw physical })
        }
        assertTrue(sameRead.targetException === physical)
        assertEquals("READ_IO", firstStdoutIOException(directRead))
        val readControl = newStdoutAccountingControl(object : java.io.InputStream() {
            override fun read(): Int = throw physical
        })
        (stdoutControlField(readControl, "closing") as AtomicBoolean).set(true)
        collectStdoutControl(readControl)
        assertEquals("READ_IO", firstStdoutIOException(readControl))
        assertFalse((stdoutControlField(readControl, "stdoutNaturallyDrained") as AtomicBoolean).get())
        val closeControl = newStdoutAccountingControl(object : java.io.InputStream() {
            override fun read(): Int = -1
            override fun close() { throw physical }
        })
        val thrown = assertFailsWith<java.lang.reflect.InvocationTargetException> {
            closeControl.first.getDeclaredMethod("tryCloseStdout").apply { isAccessible = true }.invoke(closeControl.second)
        }
        assertTrue(thrown.targetException === physical, "classification rethrows the same IO object")
        assertEquals("CLOSE_IO", firstStdoutIOException(closeControl))
        (stdoutControlField(closeControl, "closing") as AtomicBoolean).set(true)
        collectStdoutControl(closeControl)
        assertEquals("CLOSE_IO", firstStdoutIOException(closeControl), "the first code is sticky")
        assertFalse((stdoutControlField(closeControl, "stdoutNaturallyDrained") as AtomicBoolean).get())
        val guardControl = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        guardControl.first.getDeclaredMethod("tryCloseStdout").apply { isAccessible = true }.invoke(guardControl.second)
        (stdoutControlField(guardControl, "closing") as AtomicBoolean).set(true)
        collectStdoutControl(guardControl)
        assertEquals("FORCED_CLOSED_GUARD", firstStdoutIOException(guardControl))
    }

    @Test
    fun `stdout observations distinguish consumer between reads from delayed raw drainer`() {
        val bytes = "{\"jsonrpc\":\"2.0\",\"method\":\"authored\",\"params\":{}}\n".toByteArray()
        val control = newStdoutAccountingControl(java.io.ByteArrayInputStream(bytes))
        setStdoutControlField(control, "stdoutFirstWaitMillis", 100L)
        val frames = control.first.getDeclaredMethod("stdoutFrames", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }.invoke(control.second, 4096, 128)
        @Suppress("UNCHECKED_CAST")
        val flow = frames as kotlinx.coroutines.flow.Flow<String>
        var deliveries = 0
        kotlinx.coroutines.runBlocking {
            flow.collect {
                deliveries++
                // Collector delivery is between reads, outside the read/publication lock.
                recordStdoutSnapshot(control, 0, "WAIT_TIMEOUT")
                (stdoutControlField(control, "closing") as AtomicBoolean).set(true)
                control.first.getDeclaredMethod("startShutdownStdoutDrain").apply { isAccessible = true }.invoke(control.second)
                assertEquals("FRAME_CONSUMER", ((stdoutControlField(control, "stdoutOwnership") as java.util.concurrent.atomic.AtomicReference<*>).get() as Enum<*>).name)
                assertFalse((stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).isDone)
                assertEquals(true, control.first.getDeclaredMethod("tryCloseStdout").apply { isAccessible = true }.invoke(control.second))
                recordStdoutSnapshot(control, 1, "CLOSE_CLOSED")
                assertTrue((stdoutControlField(control, "stdoutClosedForUnblocking") as AtomicBoolean).get())
                assertFalse((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
            }
        }
        assertEquals(1, deliveries)
        val decision = stdoutRefusalDecision(control) as Enum<*>
        recordStdoutSnapshot(control, 2, decision.name)
        val facts = freezeStdoutFacts(control)
        assertTrue(facts.contains("s1=WAIT_TIMEOUT/FRAME_CONSUMER/false/false/false/NONE/${bytes.size}/4096/false"), facts)
        assertTrue(facts.contains("s2=CLOSE_CLOSED/FRAME_CONSUMER/false/false/true/NONE/${bytes.size}/4096/false"), facts)
        assertFalse((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
    }

    @Test
    fun `stdout lock busy classification keeps returned EOF publication protected`() = withReturnedStdoutEof { control, _, _, _ ->
        val read = control.first.declaredMethods.single { it.name == "readStdout" }.apply { isAccessible = true }
        val refused = assertFailsWith<java.lang.reflect.InvocationTargetException> {
            read.invoke(control.second, { error("busy read must not execute") })
        }
        assertIs<java.io.IOException>(refused.targetException)
        assertEquals("READ_LOCK_BUSY", firstStdoutIOException(control))
        assertFalse((stdoutControlField(control, "stdoutClosedForUnblocking") as AtomicBoolean).get())
        assertFalse((stdoutControlField(control, "stdoutNaturallyDrained") as AtomicBoolean).get())
    }

    @Test
    fun `stdout facts grammar refuses payloads unknowns overflow and noncanonical numbers`() {
        val record = authoredStdoutFacts()
        assertTrue(record.length <= 2048)
        assertTrue(record.all { it.code in 32..126 })
        assertEquals(record, validatedStdoutFacts(record))
        for (invalid in listOf(
            record + " extra=raw-secret", record + " ", record + "/", record.replace("firstMs=100", "firstMs=0100"),
            record.replace("finalMs=41", "finalMs=-1"), record.replace("/UNCLAIMED/", "/raw/path/"),
            record.replace("/NONE/", "/UNKNOWN_IO/"), record.replace("/false/", "/arbitrary/"),
            record.replace("/4096/", "/9223372036854775808/"), record.replace("s1=WAIT_TIMEOUT", "s1=NATURAL_EOF_FALSE"),
            record.replace("s3=NATURAL_EOF_FALSE", "s3=WAIT_COMPLETED"), record + "\nraw-secret", "x".repeat(2049),
        )) assertNull(validatedStdoutFacts(invalid))
        assertEquals("ACP_STDOUT_SHUTDOWN_V1 DIAGNOSTIC_UNAVAILABLE", validatedStdoutFacts("ACP_STDOUT_SHUTDOWN_V1 DIAGNOSTIC_UNAVAILABLE"))
        val extreme = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        setStdoutControlField(extreme, "stdoutFirstWaitMillis", Long.MAX_VALUE)
        setStdoutControlField(extreme, "stdoutFinalWaitMillis", Long.MAX_VALUE)
        val budget = stdoutControlField(extreme, "producedOutput")
        (budget.javaClass.getDeclaredField("observed").apply { isAccessible = true }.get(budget) as java.util.concurrent.atomic.AtomicLong).set(Long.MAX_VALUE)
        (budget.javaClass.getDeclaredField("limitExceeded").apply { isAccessible = true }.get(budget) as AtomicBoolean).set(true)
        recordStdoutSnapshot(extreme, 0, "WAIT_EXECUTION_ERROR")
        recordStdoutSnapshot(extreme, 1, "CLOSE_NOT_ACQUIRED")
        recordStdoutSnapshot(extreme, 2, "FINISHED_FALSE_EOF_NOT_READ")
        val maximum = freezeStdoutFacts(extreme)
        assertTrue(maximum.length <= 1530)
        assertTrue(maximum.contains(Long.MAX_VALUE.toString()))
        assertEquals(maximum, validatedStdoutFacts(maximum))
    }

    @Test
    fun `stdout safe suppression preserves original exception and bounded printed evidence`() {
        val control = authoredStdoutControl()
        val record = freezeStdoutFacts(control)
        val cause = java.io.IOException("authored cause").apply { stackTrace = emptyArray() }
        val original = AgentExecutionException(AgentFailure(AgentFailureKind.INTERNAL, "authored original"), cause).apply { stackTrace = emptyArray() }
        val earlier = IllegalStateException("existing cleanup").apply { stackTrace = emptyArray() }
        original.addSuppressed(earlier)
        val attach = control.first.getDeclaredMethod("attachStdoutShutdownFacts", Throwable::class.java).apply { isAccessible = true }
        assertNull(attach.invoke(control.second, original))
        attach.invoke(control.second, original)
        assertTrue(original.cause === cause)
        assertEquals(2, original.suppressed.size)
        assertTrue(original.suppressed[0] === earlier)
        assertEquals(record, original.suppressed[1].message)
        assertEquals(0, original.suppressed[1].stackTrace.size)
        val printed = StringBuilder()
        val writer = object : java.io.Writer() {
            override fun write(chars: CharArray, offset: Int, length: Int) {
                check(printed.length + length <= 4096) { "bounded synthetic stack output" }
                printed.append(chars, offset, length)
            }
            override fun flush() = Unit
            override fun close() = Unit
        }
        original.printStackTrace(java.io.PrintWriter(writer))
        assertTrue(printed.toString().contains(record))
        assertTrue(printed.toString().contains("authored original"))
        val unavailable = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf()))
        recordStdoutSnapshot(unavailable, 3, "WAIT_COMPLETED")
        unavailable.first.getDeclaredMethod("freezeStdoutShutdownFacts").apply { isAccessible = true }.invoke(unavailable.second)
        val failed = AgentExecutionException(AgentFailure(AgentFailureKind.INTERNAL, "same failure"))
        unavailable.first.getDeclaredMethod("attachStdoutShutdownFacts", Throwable::class.java).apply { isAccessible = true }.invoke(unavailable.second, failed)
        assertEquals("ACP_STDOUT_SHUTDOWN_V1 DIAGNOSTIC_UNAVAILABLE", failed.suppressed.single().message)
    }

    @Test
    fun `fatal cleanup publication keeps winner facts immutable across losing executions`() {
        // Exercise both deterministic CAS orderings through the real publication seam.
        // No RunningAcpProcess is constructed: even its inert stream fixture starts a reader.
        for (winnerIndex in 0..1) {
            val harness = AcpAgentHarness(AcpProcessConfiguration(
                executable = Path.of("/home/june/decomp_thing/build/authored-not-executed"),
            ))
            val facts = listOf("authored first process shutdown facts", "authored second process shutdown facts")
            assertFalse(facts[0] == facts[1], "contenders must carry distinct process facts")
            val causes = listOf(java.io.IOException("first local cause"), java.io.IOException("second local cause"))
            val failures = causes.mapIndexed { index, cause ->
                AgentExecutionException(AgentFailure(AgentFailureKind.INTERNAL, "local cleanup $index"), cause).also {
                    it.addSuppressed(IllegalStateException("earlier cleanup $index"))
                    it.addSuppressed(IllegalArgumentException("primary failure $index"))
                }
            }
            val publish = AcpAgentHarness::class.java.declaredMethods.single { it.name == "publishFatalCleanup" }
                .apply { isAccessible = true }
            val selected = AcpAgentHarness::class.java.getDeclaredField("unresolvedCleanupFailure")
                .apply { isAccessible = true }.get(harness) as java.util.concurrent.atomic.AtomicReference<*>
            val attachments = mutableListOf<Int>()
            fun attach(index: Int): (Throwable) -> Unit = { owned ->
                assertTrue(owned === failures[index], "attachment must target its local failure")
                assertFalse(selected.get() === owned, "facts must be complete before publication")
                owned.addSuppressed(IllegalStateException(facts[index]))
                attachments += index
            }
            val loserIndex = 1 - winnerIndex
            val winner = failures[winnerIndex]
            assertTrue(publish.invoke(harness, winner, attach(winnerIndex)) === winner)
            val publishedSuppressed = winner.suppressed
            assertEquals(3, publishedSuppressed.size)
            assertEquals("earlier cleanup $winnerIndex", publishedSuppressed[0].message)
            assertEquals("primary failure $winnerIndex", publishedSuppressed[1].message)
            assertEquals(facts[winnerIndex], publishedSuppressed[2].message)

            assertTrue(publish.invoke(harness, failures[loserIndex], attach(loserIndex)) === winner)
            assertTrue(winner.cause === causes[winnerIndex])
            assertContentEquals(publishedSuppressed, winner.suppressed, "loser cannot mutate an already returned failure")
            assertEquals(facts[loserIndex], failures[loserIndex].suppressed.last().message)
            assertFalse(winner.suppressed.any { it.message == facts[loserIndex] })
            assertEquals(listOf(winnerIndex, loserIndex), attachments)
            assertTrue(selected.get() === winner, "sticky refusal retains the original selected exception")
        }
        for (throwAttachment in listOf(false, true)) {
            val harness = AcpAgentHarness(AcpProcessConfiguration(
                executable = Path.of("/home/june/decomp_thing/build/authored-not-executed"),
            ))
            val cause = java.io.IOException("preserved local cause")
            val failure = AgentExecutionException(AgentFailure(AgentFailureKind.INTERNAL, "local cleanup"), cause)
            val primary = IllegalStateException("preserved primary")
            failure.addSuppressed(primary)
            var attachmentTarget: Throwable? = null
            val attach: ((Throwable) -> Unit)? = if (throwAttachment) {
                { owned ->
                    attachmentTarget = owned
                    throw AssertionError("authored diagnostic attachment failure")
                }
            } else null // Same no-diagnostic fallback used if method-reference allocation fails.
            val publish = AcpAgentHarness::class.java.declaredMethods.single { it.name == "publishFatalCleanup" }
                .apply { isAccessible = true }
            assertTrue(publish.invoke(harness, failure, attach) === failure)
            if (throwAttachment) assertTrue(attachmentTarget === failure) else assertNull(attachmentTarget)
            assertTrue(failure.cause === cause)
            assertContentEquals(arrayOf<Throwable>(primary), failure.suppressed)
            val selected = AcpAgentHarness::class.java.getDeclaredField("unresolvedCleanupFailure")
                .apply { isAccessible = true }.get(harness) as java.util.concurrent.atomic.AtomicReference<*>
            assertTrue(selected.get() === failure, "failed or absent diagnostics cannot prevent sticky publication")
        }
    }

    @Test
    fun `stop refusal assertion keeps closed mode cause phase without arbitrary failure text`() {
        val record = authoredStdoutFacts()
        val evidence = AcpInvocationEvidenceSnapshot(
            null, AcpExecutionLifecyclePhase.PROMPT_COMPLETED, AcpExecutionCleanupDisposition.UNVERIFIED,
            null, null, null, emptyList(), emptyList(), emptyList(), null,
            AcpExecutionEvidenceCompleteness(false, false, false), null,
        )
        val raw = "UNREGISTERED-SYNTHETIC-SECRET /private/raw/path"
        for (mode in listOf("stop-max-tokens", "stop-max-turn-requests", "stop-refusal")) {
            val failure = AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, raw,
                details = mapOf("stdoutShutdownV1" to record, "raw" to raw))
            val cause = AgentExecutionException(failure, java.io.IOException(raw))
            val receipt = AgentExecutionReceipt(AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)),
                AgentExecutionOutcome.Failed(failure), evidence, cause)
            val context = safeStopFailureContext(mode, receipt)
            assertTrue(context.length <= 3072)
            assertTrue(context.contains("mode=$mode"))
            assertTrue(context.contains("phase=PROMPT_COMPLETED"))
            assertTrue(context.contains("cleanup=UNVERIFIED"))
            assertTrue(context.contains("cause=AGENT_EXECUTION/IO_OTHER"))
            assertTrue(context.contains(record))
            assertFalse(context.contains(raw))
            val asserted = assertFailsWith<AssertionError> { assertIs<AgentExecutionOutcome.Returned>(receipt.outcome, context) }
            assertTrue(asserted.message.orEmpty().contains("mode=$mode"))
            assertFalse(asserted.message.orEmpty().contains(raw))
            assertTrue(receipt.outcome is AgentExecutionOutcome.Failed)
        }
        val unknownFailure = AgentFailure(AgentFailureKind.INTERNAL, raw)
        val opaqueCause = IllegalStateException(raw, java.io.IOException(raw))
        val opaqueReceipt = AgentExecutionReceipt(AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)),
            AgentExecutionOutcome.Failed(unknownFailure), failureCause = opaqueCause)
        assertTrue(safeStopFailureContext("stop-refusal", opaqueReceipt).contains("cause=OTHER/NONE"))
        for (invalid in listOf(raw, record + " extra=" + raw, "x".repeat(2049))) {
            val failure = AgentFailure(AgentFailureKind.INTERNAL, raw, details = mapOf("stdoutShutdownV1" to invalid))
            val receipt = AgentExecutionReceipt(AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)), AgentExecutionOutcome.Failed(failure))
            val context = safeStopFailureContext(raw, receipt)
            assertTrue(context.contains("mode=UNKNOWN"))
            assertTrue(context.contains("facts=NOT_AVAILABLE"))
            assertFalse(context.contains(raw))
        }

        // Already-retained observations only: no process, filesystem or timing trial.
        val prefix = assertNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(12L, 0L) })
        prefix.start(RuntimeCopyStatistics.Prefix.Phase.LAUNCH_PINNING)
        prefix.failureCurrent(RuntimeCopyStatistics.Prefix.Failure.TIMEOUT)
        prefix.finish(RuntimeCopyStatistics.Prefix.Phase.LAUNCH_PINNING, false)
        val observation = assertNotNull(prefix.failureDiagnostic())
        val original = assertNotNull(observation.message)
        val timeout = AgentFailure(AgentFailureKind.TIMEOUT, raw)
        val cause = AgentExecutionException(timeout, java.io.IOException(raw)).apply { addSuppressed(observation) }
        val receipt = AgentExecutionReceipt(AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)),
            AgentExecutionOutcome.Failed(timeout), evidence, cause)
        val retainedOutcome = receipt.outcome
        val context = safeStopFailureContext("stop-refusal", receipt)
        assertTrue(context.contains("prefix=supported=true,first=LAUNCH_PINNING,kind=TIMEOUT,elapsedNs=12,remainingNs=0,lastEntered=LAUNCH_PINNING,lastReturned=ENTRY"), context)
        assertTrue(context.contains("cleanup=UNVERIFIED"))
        assertTrue(context.length <= 3072)
        assertFalse(context.contains(raw))
        assertSame(cause, receipt.failureCause)
        assertSame(observation, cause.suppressed.single())
        assertEquals(original, observation.message)
        assertSame(retainedOutcome, receipt.outcome)
        assertSame(timeout, assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure)

        var foreignMessageReads = 0
        val foreign = object : java.io.IOException() {
            override val message: String get() { foreignMessageReads++; error(raw) }
        }
        for (diagnostics in listOf(
            arrayOf(java.io.IOException(raw)),
            arrayOf(java.io.IOException(original.replace("firstObservedFailure=LAUNCH_PINNING", "firstObservedFailure=$raw"))),
            arrayOf(java.io.IOException(original.replace("failureElapsedNs=12", "failureElapsedNs=9223372036854775808"))),
            arrayOf(java.io.IOException(original.replace("failureRemainingNs=0", "failureRemainingNs=00"))),
            arrayOf(java.io.IOException("x".repeat(8193))),
            arrayOf(IllegalStateException(original)),
            arrayOf(foreign),
            arrayOf(observation, java.io.IOException(original)),
            Array(5) { java.io.IOException(original) },
        )) {
            val rejected = AgentExecutionException(timeout).apply { diagnostics.forEach(::addSuppressed) }
            val untrusted = AgentExecutionReceipt(receipt.requestBinding, receipt.outcome, evidence, rejected)
            val rejectedContext = safeStopFailureContext("stop-refusal", untrusted)
            assertTrue(rejectedContext.contains("prefix=NOT_AVAILABLE"), rejectedContext)
            assertFalse(rejectedContext.contains(raw))
        }
        assertEquals(0, foreignMessageReads)
        val nested = AgentExecutionException(timeout, java.io.IOException(raw).apply { addSuppressed(observation) })
        assertTrue(safeStopFailureContext("stop-refusal", AgentExecutionReceipt(receipt.requestBinding, receipt.outcome, evidence, nested)).contains("prefix=NOT_AVAILABLE"))
        val unregistered = java.io.IOException(raw).apply { addSuppressed(observation) }
        assertTrue(safeStopFailureContext("stop-refusal", AgentExecutionReceipt(receipt.requestBinding, receipt.outcome, evidence, unregistered)).contains("prefix=NOT_AVAILABLE"))
        val tailed = AgentExecutionException(timeout).apply { addSuppressed(java.io.IOException(original + raw)) }
        val projected = safeStopFailureContext("stop-refusal", AgentExecutionReceipt(receipt.requestBinding, receipt.outcome, evidence, tailed))
        assertTrue(projected.contains("prefix=supported=true,first=LAUNCH_PINNING"))
        assertFalse(projected.contains(raw), "unselected phase/leaf text is never rendered")
    }

    private fun stdoutFactsCall(name: String, vararg arguments: Any?): Any? {
        val type = Class.forName("decompengine.acp.StdoutShutdownFacts")
        val instance = type.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
        return type.declaredMethods.single { it.name == name && it.parameterCount == arguments.size }
            .apply { isAccessible = true }.invoke(instance, *arguments)
    }

    private fun validatedStdoutFacts(value: String?): String? = stdoutFactsCall("validated", value) as String?

    private fun setStdoutControlField(control: Pair<Class<*>, Any>, name: String, value: Any?) {
        control.first.getDeclaredField(name).apply { isAccessible = true }.set(control.second, value)
    }

    private fun stdoutRefusalDecision(control: Pair<Class<*>, Any>): Any? =
        control.first.getDeclaredMethod("stdoutShutdownRefusalDecision").apply { isAccessible = true }.invoke(control.second)

    private fun recordStdoutSnapshot(control: Pair<Class<*>, Any>, slot: Int, operation: String) {
        val type = Class.forName("decompengine.acp.StdoutShutdownOperation")
        val value = type.enumConstants.single { (it as Enum<*>).name == operation }
        control.first.getDeclaredMethod("recordStdoutShutdownSnapshot", Int::class.javaPrimitiveType, type)
            .apply { isAccessible = true }.invoke(control.second, slot, value)
    }

    private fun freezeStdoutFacts(control: Pair<Class<*>, Any>): String {
        control.first.getDeclaredMethod("freezeStdoutShutdownFacts").apply { isAccessible = true }.invoke(control.second)
        return control.first.getDeclaredMethod("stdoutShutdownFailureFacts").apply { isAccessible = true }.invoke(control.second) as String
    }

    private fun authoredStdoutControl(): Pair<Class<*>, Any> = newStdoutAccountingControl(java.io.ByteArrayInputStream(byteArrayOf())).also { control ->
        setStdoutControlField(control, "stdoutFirstWaitMillis", 100L)
        setStdoutControlField(control, "stdoutFinalWaitMillis", 41L)
        recordStdoutSnapshot(control, 0, "WAIT_TIMEOUT")
        recordStdoutSnapshot(control, 1, "CLOSE_NOT_ACQUIRED")
        @Suppress("UNCHECKED_CAST")
        val completedReader = stdoutControlField(control, "stdoutDrainFinished") as java.util.concurrent.CompletableFuture<Unit>
        completedReader.complete(Unit)
        recordStdoutSnapshot(control, 2, "NATURAL_EOF_FALSE")
    }

    private fun authoredStdoutFacts(): String = freezeStdoutFacts(authoredStdoutControl())

    private fun firstStdoutIOException(control: Pair<Class<*>, Any>): String =
        ((stdoutControlField(control, "stdoutFirstIOException") as java.util.concurrent.atomic.AtomicReference<*>).get() as Enum<*>).name

    private fun safeStopFailureContext(mode: String, receipt: AgentExecutionReceipt): String {
        val safeMode = when (mode) { "stop-max-tokens", "stop-max-turn-requests", "stop-refusal" -> mode; else -> "UNKNOWN" }
        val failure = (receipt.outcome as? AgentExecutionOutcome.Failed)?.failure
        val evidence = receipt.providerEvidence as? AcpInvocationEvidenceSnapshot
        fun causeCode(value: Throwable?): String {
            if (value == null) return "NONE"
            if (value is AgentExecutionException) return "AGENT_EXECUTION"
            val known = listOf("AcpOutputLimitFailure" to "ACP_OUTPUT_LIMIT", "AcpTransportFailure" to "ACP_TRANSPORT", "AcpPhaseTimeout" to "ACP_TIMEOUT", "AcpIdleTimeout" to "ACP_TIMEOUT")
            for ((name, code) in known) if (runCatching { Class.forName("decompengine.acp.$name").isInstance(value) }.getOrDefault(false)) return code
            return when (value) { is java.io.IOException -> "IO_OTHER"; is Error -> "ERROR"; else -> "OTHER" }
        }
        return runCatching {
            val facts = validatedStdoutFacts(failure?.details?.get("stdoutShutdownV1")) ?: "NOT_AVAILABLE"
            val retainedCause = receipt.failureCause
            // Only the known final wrapper has its direct cause inspected; no foreign getter/graph.
            val directCause = (retainedCause as? AgentExecutionException)?.cause
            val fields = listOf("ACP_STOP_V1", "mode=$safeMode", "kind=${failure?.kind?.name ?: "NOT_FAILED"}",
                "phase=${evidence?.phaseReached?.name ?: "UNKNOWN"}", "cleanup=${evidence?.cleanupDisposition?.name ?: "UNKNOWN"}",
                "cause=${causeCode(retainedCause)}/${causeCode(directCause)}", "facts=$facts",
                "prefix=${retainedPrefixFailureContext(retainedCause as? AgentExecutionException)}")
            val output = StringBuilder(512)
            for ((index, field) in fields.withIndex()) {
                if (field.any { it.code !in 32..126 } || output.length + field.length + (if (index == 0) 0 else 1) > 3072) return@runCatching "ACP_STOP_V1 DIAGNOSTIC_UNAVAILABLE"
                if (index > 0) output.append(' ')
                output.append(field)
            }
            output.toString()
        }.getOrDefault("ACP_STOP_V1 DIAGNOSTIC_UNAVAILABLE")
    }

    /** Project only a closed header from an existing mapped wrapper; never traverse its cause graph,
     * render phase/leaf payloads, resample a clock or interpret these observations as cleanup proof. */
    private fun retainedPrefixFailureContext(mapped: AgentExecutionException?): String = runCatching {
        val diagnostics = mapped?.suppressed ?: return@runCatching "NOT_AVAILABLE"
        if (diagnostics.size > 4) return@runCatching "NOT_AVAILABLE"
        val candidates = diagnostics.filter { it.javaClass == java.io.IOException::class.java }.mapNotNull {
            it.message?.takeIf { text -> text.length <= 8192 && text.startsWith("acp-prelaunch-prefix-observation-v1;") }
        }
        if (candidates.size != 1) return@runCatching "NOT_AVAILABLE"
        val phase = "(?:" + RuntimeCopyStatistics.Prefix.Phase.entries.joinToString("|") { it.name } + "|unobserved)"
        val kind = "(?:" + RuntimeCopyStatistics.Prefix.Failure.entries.joinToString("|") { it.name } + "|unobserved)"
        val number = "(?:-1|0|[1-9][0-9]{0,18})"
        val header = Regex("\\Aacp-prelaunch-prefix-observation-v1;supported=(true|false);" +
            "firstObservedFailure=($phase),kind=($kind),failureElapsedNs=($number),failureRemainingNs=($number);" +
            "lastEntered=($phase);lastReturned=($phase);states=0-unseen/1-active/2-returned/3-threw;")
        val fields = header.find(candidates.single())?.groupValues ?: return@runCatching "NOT_AVAILABLE"
        if (fields[4].toLongOrNull() == null || fields[5].toLongOrNull() == null) return@runCatching "NOT_AVAILABLE"
        "supported=${fields[1]},first=${fields[2]},kind=${fields[3]},elapsedNs=${fields[4]},remainingNs=${fields[5]}," +
            "lastEntered=${fields[6]},lastReturned=${fields[7]}"
    }.getOrDefault("NOT_AVAILABLE")

    private fun stdoutControlField(control: Pair<Class<*>, Any>, name: String): Any =
        control.first.getDeclaredField(name).apply { isAccessible = true }.get(control.second)

    private fun collectStdoutControl(control: Pair<Class<*>, Any>) {
        val method = control.first.getDeclaredMethod("stdoutFrames", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val flow = method.invoke(control.second, 4096, 128) as kotlinx.coroutines.flow.Flow<String>
        kotlinx.coroutines.runBlocking { flow.collect { error("a closing reader must not dispatch protocol frames") } }
    }

    private fun withReturnedStdoutEof(
        block: (Pair<Class<*>, Any>, CountDownLatch, java.util.concurrent.Future<*>, AtomicInteger) -> Unit,
    ) {
        val returnedEof = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closes = AtomicInteger()
        val input = object : java.io.InputStream() {
            override fun read(): Int = -1
            override fun close() { closes.incrementAndGet() }
        }
        val control = newStdoutAccountingControl(input)
        (stdoutControlField(control, "closing") as AtomicBoolean).set(true)
        val observer: () -> Unit = {
            returnedEof.countDown()
            if (!release.await(3, TimeUnit.SECONDS)) throw java.io.IOException("post-read EOF barrier was not released")
        }
        control.first.getDeclaredField("stdoutEofPublicationObserver").apply { isAccessible = true }
            .set(control.second, observer)
        val executor = Executors.newSingleThreadExecutor()
        val execution = executor.submit { collectStdoutControl(control) }
        try {
            assertTrue(returnedEof.await(3, TimeUnit.SECONDS), "the raw read never returned EOF")
            block(control, release, execution, closes)
        } finally {
            release.countDown()
            try { execution.get(3, TimeUnit.SECONDS) } finally { executor.shutdownNow() }
        }
    }

    private data class StdoutDrainObservation(
        val naturallyDrained: Boolean,
        val output: AcpProducedOutputEvidence,
    )

    /** Invokes existing private stream accounting; it cannot launch or control a native process. */
    private fun observeClosingStdout(input: java.io.InputStream, forcedClose: Boolean = false): StdoutDrainObservation {
        val (type, running) = newStdoutAccountingControl(input)
        fun field(name: String): Any = type.getDeclaredField(name).apply { isAccessible = true }.get(running)
        (field("closing") as AtomicBoolean).set(true)
        if (forcedClose) (field("stdoutClosedForUnblocking") as AtomicBoolean).set(true)
        val frames = type.getDeclaredMethod("stdoutFrames", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val flow = frames.invoke(running, 4096, 128) as kotlinx.coroutines.flow.Flow<String>
        kotlinx.coroutines.runBlocking { flow.collect { error("closing accounting must not dispatch protocol frames") } }
        (field("stdoutDrainFinished") as java.util.concurrent.CompletableFuture<*>).get(1, TimeUnit.SECONDS)
        (field("stderrDrainFinished") as java.util.concurrent.CompletableFuture<*>).get(1, TimeUnit.SECONDS)
        val output = type.getDeclaredMethod("outputEvidence").apply { isAccessible = true }
            .invoke(running) as AcpProducedOutputEvidence
        return StdoutDrainObservation((field("stdoutNaturallyDrained") as AtomicBoolean).get(), output)
    }

    private fun newStdoutAccountingControl(input: java.io.InputStream): Pair<Class<*>, Any> {
        val process = object : Process() {
            override fun getInputStream(): java.io.InputStream = input
            override fun getErrorStream(): java.io.InputStream = java.io.ByteArrayInputStream(byteArrayOf())
            override fun getOutputStream(): java.io.OutputStream = java.io.ByteArrayOutputStream()
            override fun waitFor(): Int = 0
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true
            override fun exitValue(): Int = 0
            override fun isAlive(): Boolean = false
            override fun destroy() = Unit
            override fun destroyForcibly(): Process = this
            override fun pid(): Long = Long.MAX_VALUE
            override fun toHandle(): ProcessHandle = throw UnsupportedOperationException("not a native process")
            override fun onExit(): java.util.concurrent.CompletableFuture<Process> = java.util.concurrent.CompletableFuture()
        }
        val type = Class.forName("decompengine.acp.RunningAcpProcess")
        val constructor = type.declaredConstructors.single().apply { isAccessible = true }
        val running = constructor.newInstance(
            process, null, AcpProcessContainment.LINUX_BUBBLEWRAP_CGROUP_V2, 64, 4096L, ProtocolActivity(),
        )
        return type to running
    }

    @Test
    fun `public Make and Ninja archival reconstruction follows ACP file roles through verified rebuild`() {
        val temp = createTempDirectory("acp-archival-role-workflow-")
        val binary = temp.resolve("authored.elf")
        val binaryBytes = byteArrayOf(9, 8, 7)
        Files.write(binary, binaryBytes)

        for (base in ReconstructionProfiles.builtIn) {
            val profile = base
            val model = RecoveredProgramModel(
                inputSha256 = sha256(binaryBytes),
                functions = listOf(
                    RecoveredFunction(
                        "fn_0000000000001000",
                        "decomp_engine_main",
                        0x1000UL,
                        "int decomp_engine_main(void)",
                        "int decomp_engine_main(void) { return 0; }",
                    ),
                ),
            )
            val implementationPath = profile.layout.declaration("module-implementation")
                .materialize(mapOf("module" to "decomp"))
            val harness = harness(
                mode = "reconstruction-role-policy",
                sentinel = implementationPath,
            )
            val factoryProvenance = AcpHarnessProvenance(
                harness = "acp",
                implementationId = "scripted-acp-v1",
                agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
                acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
                configurationSha256 = "0".repeat(64),
                deprecated = false,
            )
            val output = temp.resolve(base.id)
            val result = try {
                ArchivalReconstructionService(
                    budgetedAnalyzer { supplied, _ ->
                        assertEquals(binary, supplied)
                        model
                    },
                    BoundedLlmModuleReconstructor(
                        harness,
                        harnessProvenanceDescriptor = factoryProvenance.stableDescriptor,
                    ),
                    profile = profile,
                ).reconstruct(binary, output)
            } catch (failure: Exception) {
                val checkpoint = output.resolve("source-tree").resolve(
                    profile.layout.declaration("module-evidence").materialize(mapOf("module" to "decomp")),
                )
                val checkpointDiagnostics = runCatching {
                    if (!Files.isRegularFile(checkpoint)) "<missing>" else {
                        val maximumBytes = 16 * 1024
                        val bytes = Files.newInputStream(checkpoint).use { it.readNBytes(maximumBytes + 1) }
                        bytes.take(maximumBytes).toByteArray().toString(Charsets.UTF_8) +
                            if (bytes.size > maximumBytes) "\n<truncated>" else ""
                    }
                }.getOrElse { "<unreadable: ${it.javaClass.simpleName}>" }
                throw AssertionError(
                    "public ${base.id} ACP reconstruction failed; diagnostics=${harness.latestDiagnostics()}; " +
                        "sandbox=${harness.latestSandboxEvidence()}; checkpoint=$checkpointDiagnostics",
                    failure,
                )
            }

            assertEquals(0, result.build.returnCode)
            assertTrue(requireNotNull(result.bundle.audit).unresolvedEntityIds.isEmpty())
            assertTrue(requireNotNull(harness.latestAcpExecutionEvidence()).sandboxEvidence.networkIsolated)
            val extracted = temp.resolve("${base.id}-extracted")
            ArchivalBundleVerifier.extractAndVerify(result.bundle.archivePath, extracted, profile = profile)
            val rebuilt = ReconstructionAdapters.resolve(profile).build(extracted, profile)
            assertEquals(0, rebuilt.returnCode)
            assertEquals(ArchivalProjectAuditor.audit(result.projectDir, profile).toJson(),
                ArchivalProjectAuditor.audit(extracted, profile).toJson())
        }
    }

    @Test
    fun `public harness fails closed before launch when the outer sandbox is absent`() {
        val fixture = fixture()
        val harness = AcpAgentHarness(
            AcpProcessConfiguration(executable = Path.of("/usr/bin/true")),
        )

        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request) }

        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertTrue(failure.failure.message.contains("sandbox"))
        val receipt = assertNotNull(failure.receipt)
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH, invocation.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.UNVERIFIED, invocation.cleanupDisposition)
        assertNull(invocation.completeExecutionEvidence)
        assertNull(harness.latestDiagnostics())
        assertNull(harness.latestSandboxEvidence(), "failed launch must not claim successful containment")
    }

    @Test
    fun `production bytecode exposes no launcher boundary or test mode bypass`() {
        val fixture = fixture()
        val harness = AcpAgentHarness(
            AcpProcessConfiguration(
                executable = Path.of("/usr/bin/true"),
                sandboxBoundary = missingSandboxConfiguration(),
            ),
        )

        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request) }

        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertNull(harness.latestSandboxEvidence())
        val bytecode = javap(AcpAgentHarness::class.java) + "\n" + javap(AcpTerminalBroker::class.java)
        listOf(
            "uncontainedForTesting",
            "withBoundaryForTesting",
            "openWithTestBoundary",
            "TEST_ONLY_UNCONTAINED",
            "AcpProcessSandboxBoundary",
            "AcpTerminalSandboxBoundary",
            "boundaryFactory",
            "launchMode",
        ).forEach { forbidden -> assertFalse(forbidden in bytecode, bytecode) }
        val harnessConstructors = AcpAgentHarness::class.java.declaredConstructors.toList()
        assertEquals(1, harnessConstructors.size)
        assertEquals(listOf(AcpProcessConfiguration::class.java), harnessConstructors.single().parameterTypes.toList())
        listOf(AcpAgentHarness::class.java, AcpTerminalBroker::class.java).forEach { type ->
            val callableParameterTypes = type.declaredConstructors.flatMap { it.parameterTypes.toList() } +
                type.declaredMethods.flatMap { it.parameterTypes.toList() }
            assertTrue(
                callableParameterTypes.none(::isForbiddenExecutionSeamType),
                "$type accepts ${callableParameterTypes.filter(::isForbiddenExecutionSeamType)}",
            )
        }
        assertTrue(AcpTerminalBroker::class.java.isSealed)
        assertTrue(AcpTerminalBroker::class.java.permittedSubclasses.all { permitted ->
            java.lang.reflect.Modifier.isPrivate(permitted.modifiers)
        })
        val acpTestMethods = listOf(
            AcpAgentHarnessTest::class.java,
            AcpPermissionPolicyTest::class.java,
            AcpSandboxPolicyTest::class.java,
            AcpTerminalBrokerTest::class.java,
            LinuxBubblewrapBoundaryTest::class.java,
        ).flatMap { type ->
            type.declaredMethods.filter { method ->
                method.annotations.any { annotation ->
                    annotation.annotationClass.java.name == "org.junit.jupiter.api.Test"
                }
            }
        }
        assertEquals(102, acpTestMethods.size, acpTestMethods.joinToString { it.name })
        assertTrue(
            acpTestMethods.all { it.returnType == Void.TYPE },
            acpTestMethods.filter { it.returnType != Void.TYPE }.joinToString {
                "${it.declaringClass.simpleName}.${it.name}:${it.returnType.name}"
            },
        )
    }

    @Test
    fun `pinned SDK negotiates stable v1 and streams one subprocess turn without shell interpretation`() {
        assertEquals(1, LATEST_PROTOCOL_VERSION)
        assertEquals("0.30.1", ACP_KOTLIN_SDK_VERSION)
        val fixture = fixture()
        val shellMarker = fixture.workspace.resolve("shell-was-interpreted")
        val sentinel = "\$(touch $shellMarker)"
        val harness = harness("success", sentinel = sentinel)
        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()

        val result = try {
            harness.execute(fixture.request, events::add)
        } catch (failure: Exception) {
            throw AssertionError(
                "canonical live ACP fixture failed; diagnostics=${harness.latestDiagnostics()}; " +
                    "sandbox=${harness.latestSandboxEvidence()}",
                failure,
            )
        }

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("fixture-session", result.session?.sessionId)
        assertEquals("scripted-acp-v1", result.session?.harnessId)
        assertEquals("editing fixture", result.summary)
        assertEquals(11, result.usage?.inputTokens)
        assertEquals(7, result.usage?.outputTokens)
        assertEquals(3, result.usage?.cachedInputTokens)
        assertEquals(1, result.usage?.toolCalls)
        assertEquals("new source\n", fixture.source.readText())
        assertFalse(shellMarker.exists(), "argv was interpreted by a shell")
        assertEquals(events.indices.map(Int::toLong), events.map { it.sequence })
        assertTrue(events.any { it is AgentMessageEvent && it.textDelta == "editing fixture" })
        assertTrue(events.any { it is AgentPlanEvent })
        assertTrue(events.any { it is AgentToolEvent && it.status == AgentToolStatus.SUCCEEDED })
        val change = events.filterIsInstance<AgentFileChangeEvent>().single().change
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
        assertEquals("src/module.c", change.path.relativePath)

        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertEquals(0, diagnostics.exitCode)
        assertTrue(diagnostics.stderr.contains("fixture-stderr:$sentinel"))
        assertFalse(diagnostics.stderrTruncated)
        assertFalse(diagnostics.forcedTermination)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `fragmented stdout writes are assembled into complete protocol frames`() {
        val fixture = fixture(genericContract = true)
        val harness = harness("fragmented-stdout")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("updated artifact\n", fixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, fixture.forbiddenCanary.readText())
        assertCleanTermination(harness)
    }

    @Test
    fun `configured session preferences use advertised setters in deterministic order while defaults send none`() {
        val configuredFixture = fixture(genericContract = true)
        val configuredHarness = harness(
            mode = "session-preferences",
            sentinel = "preferences-success",
            sessionPreferences = AcpSessionPreferences(
                modelId = "model-safe",
                modeId = "mode-safe",
                configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                ),
            ),
        )

        val configuredResult = configuredHarness.execute(configuredFixture.request)

        assertEquals(AgentStopReason.COMPLETED, configuredResult.stopReason)
        assertEquals("updated artifact\n", configuredFixture.source.readText())
        assertCleanTermination(configuredHarness, "configured session preferences", configuredFixture)

        val defaultFixture = fixture(genericContract = true)
        val defaultHarness = harness(
            mode = "session-preferences",
            sentinel = "preferences-default",
        )

        val defaultResult = defaultHarness.execute(defaultFixture.request)

        assertEquals(AgentStopReason.COMPLETED, defaultResult.stopReason)
        assertEquals("updated artifact\n", defaultFixture.source.readText())
        assertCleanTermination(defaultHarness, "default session preferences", defaultFixture)
    }

    @Test
    fun `removed later config option stops the real setter flow before prompt and workspace changes`() {
        val fixture = fixture(genericContract = true)
        val harness = harness(
            mode = "session-preferences-config-removes-next",
            sessionPreferences = AcpSessionPreferences(configOptions = listOf(
                AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
            )),
        )
        val events = mutableListOf<AgentExecutionEvent>()
        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request, events::add) }
        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
        assertEquals("currentInventoryMismatch", failure.failure.details["reason"])
        assertEquals("1", failure.failure.details["preferenceIndex"])
        assertEquals("original artifact\n", fixture.source.readText())
        assertTrue(events.isEmpty())
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached)
        assertNull(invocation.wirePromptSha256)
        assertCleanTermination(harness, "removed later option", fixture, failure = failure, events = events)
    }

    @Test
    fun `unknown absent and mistyped session preferences fail before every setter prompt and workspace operation`() {
        data class RejectedPreference(
            val label: String,
            val mode: String,
            val preferences: AcpSessionPreferences,
            val secretCanary: String,
        )

        val cases = listOf(
            RejectedPreference(
                "unknown model",
                "session-preferences",
                AcpSessionPreferences(modelId = "model-secret-canary"),
                "model-secret-canary",
            ),
            RejectedPreference(
                "unknown mode",
                "session-preferences",
                AcpSessionPreferences(modeId = "mode-secret-canary"),
                "mode-secret-canary",
            ),
            RejectedPreference(
                "unknown option",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference(
                        "option-secret-canary",
                        AcpSessionConfigValue.BooleanValue(false),
                    ),
                )),
                "option-secret-canary",
            ),
            RejectedPreference(
                "unknown select value",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference(
                        "reasoning",
                        AcpSessionConfigValue.Select("value-secret-canary"),
                    ),
                )),
                "value-secret-canary",
            ),
            RejectedPreference(
                "mismatched option type",
                "session-preferences",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "not-present",
            ),
            RejectedPreference(
                "pipelined update cannot expand session new authority",
                "session-preferences-pipelined-update",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("late-option", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "late-option",
            ),
            RejectedPreference(
                "pipelined work cannot run while invalid preferences are rejected",
                "session-preferences-pipelined-work",
                AcpSessionPreferences(modelId = "model-secret-canary"),
                "model-secret-canary",
            ),
            RejectedPreference(
                "absent model capability",
                "session-preferences-no-models",
                AcpSessionPreferences(modelId = "model-safe"),
                "not-present",
            ),
            RejectedPreference(
                "absent mode capability",
                "session-preferences-no-modes",
                AcpSessionPreferences(modeId = "mode-safe"),
                "not-present",
            ),
            RejectedPreference(
                "absent config capability",
                "session-preferences-no-config-options",
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                )),
                "not-present",
            ),
        )

        cases.forEach { case ->
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode = case.mode,
                sentinel = "preferences-reject",
                sessionPreferences = case.preferences,
            )
            val events = mutableListOf<AgentExecutionEvent>()

            val failure = assertFailsWith<AgentExecutionException>(case.label) {
                harness.execute(fixture.request, events::add)
            }

            assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind, case.label)
            assertEquals("original artifact\n", fixture.source.readText(), case.label)
            assertTrue(events.isEmpty(), case.label)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
            val phaseContext = if (invocation.phaseReached == AcpExecutionLifecyclePhase.SESSION_CREATED) {
                case.label
            } else {
                try {
                    sessionPreferencePhaseFailureContext(case.label, failure, invocation)
                } catch (_: Throwable) {
                    case.label // Diagnostic construction cannot replace the original phase check.
                }
            }
            assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached, phaseContext)
            assertNull(invocation.wirePromptSha256, case.label)
            assertFalse(failure.stackTraceToString().contains(case.secretCanary), case.label)
            assertFalse(invocation.toString().contains(case.secretCanary), case.label)
            assertCleanTermination(
                harness = harness,
                context = case.label,
                fixture = fixture,
                failure = failure,
                events = events,
            )
        }

        // Cancel from the setter wait itself instead of using a timing delay that could fire
        // during sandbox startup on a contended host. The hanging wire peer proves teardown does
        // not depend on a setter response.
        val cancellationFixture = fixture(genericContract = true)
        val setterWaitObserved = AtomicBoolean(false)
        val setterCancellation = AgentCancellation {
            val insideSetterWait = Thread.currentThread().stackTrace.any { frame ->
                frame.className == AcpAgentHarness::class.java.name &&
                    frame.methodName.startsWith("awaitSessionPreferenceSetter")
            }
            if (insideSetterWait) setterWaitObserved.set(true)
            insideSetterWait
        }
        val cancellationHarness = harness(
            mode = "session-preferences-setter-timeout",
            sentinel = "preference-setter-cancel",
            sessionPreferences = AcpSessionPreferences(modelId = "model-safe"),
            timeouts = timeouts(request = 3_000),
        )
        val cancellationEvents = mutableListOf<AgentExecutionEvent>()

        val cancellationReceipt = cancellationHarness.executeReceipt(
            cancellationFixture.request.withCancellation(setterCancellation),
            cancellationEvents::add,
        )
        val cancelled = assertIs<AgentExecutionOutcome.Returned>(cancellationReceipt.outcome).result

        assertTrue(setterWaitObserved.get())
        assertEquals(AgentStopReason.CANCELLED, cancelled.stopReason)
        assertEquals("fixture-session", cancelled.session?.sessionId)
        assertEquals("original artifact\n", cancellationFixture.source.readText())
        assertTrue(cancellationEvents.isEmpty())
        val cancellationEvidence = assertIs<AcpInvocationEvidenceSnapshot>(cancellationReceipt.providerEvidence)
        assertNull(cancellationEvidence.wirePromptSha256)
        assertCleanTermination(
            harness = cancellationHarness,
            context = "setter cancellation",
            fixture = cancellationFixture,
            events = cancellationEvents,
        )
    }

    @Test
    fun `session preference setter errors and timeouts are bounded redacted and cleaned before prompt`() {
        data class SetterFailureCase(
            val label: String,
            val mode: String,
            val expectedKind: AgentFailureKind,
            val timeouts: AcpLifecycleTimeouts,
            val preferences: AcpSessionPreferences,
        )
        val cases = listOf(
            SetterFailureCase(
                "setter error",
                "session-preferences-setter-error",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(modelId = "model-safe"),
            ),
            SetterFailureCase(
                "setter timeout",
                "session-preferences-setter-timeout",
                AgentFailureKind.TIMEOUT,
                timeouts(request = 200),
                AcpSessionPreferences(modelId = "model-safe"),
            ),
            SetterFailureCase(
                "config setter inconsistent postcondition",
                "session-preferences-config-inconsistent",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                )),
            ),
            SetterFailureCase(
                "later config setter cannot revert an earlier configured option",
                "session-preferences-config-reverts-earlier",
                AgentFailureKind.PROTOCOL,
                timeouts(),
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                    AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
                )),
            ),
        )

        cases.forEach { case ->
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode = case.mode,
                sentinel = "preference-setter",
                sessionPreferences = case.preferences,
                timeouts = case.timeouts,
            )
            val events = mutableListOf<AgentExecutionEvent>()

            val failure = assertFailsWith<AgentExecutionException>(case.label) {
                harness.execute(fixture.request, events::add)
            }

            assertEquals(case.expectedKind, failure.failure.kind, case.label)
            assertEquals("original artifact\n", fixture.source.readText(), case.label)
            assertTrue(events.isEmpty(), case.label)
            assertFalse(failure.stackTraceToString().contains("setter-secret-canary"), case.label)
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(failure.receipt?.providerEvidence)
            assertEquals(AcpExecutionLifecyclePhase.SESSION_CREATED, invocation.phaseReached, case.label)
            assertNull(invocation.wirePromptSha256, case.label)
            assertCleanTermination(
                harness = harness,
                context = case.label,
                fixture = fixture,
                failure = failure,
                events = events,
            )
        }
    }

    @Test
    fun `stable v1 stop reasons map to the program neutral execution contract`() {
        mapOf(
            "stop-max-tokens" to AgentStopReason.LIMIT_EXHAUSTED,
            "stop-max-turn-requests" to AgentStopReason.LIMIT_EXHAUSTED,
            "stop-refusal" to AgentStopReason.REFUSED,
        ).forEach { (mode, expected) ->
            val fixture = fixture(genericContract = true)
            val harness = harness(mode)

            val receipt = harness.executeReceipt(fixture.request)
            val result = assertIs<AgentExecutionOutcome.Returned>(receipt.outcome, safeStopFailureContext(mode, receipt)).result
            val invocation = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)

            assertEquals(expected, result.stopReason, mode)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, mode)
            assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, invocation.phaseReached, mode)
            assertNotNull(invocation.completeExecutionEvidence, mode)
            assertEquals("original artifact\n", fixture.source.readText(), mode)
            assertEquals(FORBIDDEN_CANARY_CONTENT, fixture.forbiddenCanary.readText(), mode)
            assertCleanTermination(harness, mode)
        }
    }

    @Test
    fun `overlapping receipts retain their own request prompt and provider evidence`() {
        // Require both live invocations to remain inside their event callbacks until the test releases them.
        val firstFixture = fixture(idleMillis = 30_000, wallMillis = 60_000)
        val secondFixture = fixture(idleMillis = 30_000, wallMillis = 60_000)
        val firstRequest = firstFixture.request.withContextMarker("first-turn-marker")
        val secondRequest = secondFixture.request.withContextMarker("second-turn-marker")
        // The fixture holds stdin open after its response so concurrent receipt checks do not race
        // an immediate successful process exit against final-response delivery.
        val harness = harness(
            "overlapping-success",
            timeouts = timeouts(startup = 15_000, request = 45_000, shutdown = 3_000),
        )
        val callbacksEntered = CountDownLatch(2)
        val releaseCallbacks = CountDownLatch(1)
        val activeCallbacks = AtomicInteger()
        val executor = Executors.newFixedThreadPool(2)

        fun submit(request: AgentExecutionRequest) = executor.submit<AgentExecutionReceipt> {
            val firstCallback = AtomicBoolean(true)
            harness.executeReceipt(request) {
                if (firstCallback.compareAndSet(true, false)) {
                    activeCallbacks.incrementAndGet()
                    callbacksEntered.countDown()
                    try {
                        check(releaseCallbacks.await(20, TimeUnit.SECONDS)) {
                            "overlapping ACP invocation callback was not released"
                        }
                    } finally {
                        activeCallbacks.decrementAndGet()
                    }
                }
            }
        }

        try {
            val firstFuture = submit(firstRequest)
            val secondFuture = submit(secondRequest)
            val bothCallbacksEntered = callbacksEntered.await(20, TimeUnit.SECONDS)
            val heldCallbackCount = activeCallbacks.get()
            val bothInvocationsHeld = !firstFuture.isDone && !secondFuture.isDone
            releaseCallbacks.countDown()
            val first = firstFuture.get(75, TimeUnit.SECONDS)
            val second = secondFuture.get(75, TimeUnit.SECONDS)
            val firstEvidence = assertIs<AcpInvocationEvidenceSnapshot>(first.providerEvidence)
            val secondEvidence = assertIs<AcpInvocationEvidenceSnapshot>(second.providerEvidence)
            val outcomes = listOf("first" to first, "second" to second).joinToString("; ") { (label, receipt) ->
                val failure = (receipt.outcome as? AgentExecutionOutcome.Failed)?.failure
                val evidence = receipt.providerEvidence as AcpInvocationEvidenceSnapshot
                val diagnostics = evidence.diagnostics
                "$label: failureKind=${failure?.kind} failureMessage=${failure?.message} failureDetails=${failure?.details} " +
                    "${evidence.summaryForTest()} exitCode=${diagnostics?.exitCode} " +
                    "forcedTermination=${diagnostics?.forcedTermination} " +
                    "rootTerminationRequested=${diagnostics?.rootTerminationRequested} " +
                    "remainingProcesses=${diagnostics?.remainingProcessIds?.size} " +
                    "outputLimitExceeded=${diagnostics?.outputLimitExceeded} " +
                    "cause=${boundedPreparationCauseForTest(receipt.failureCause)}"
            }

            assertTrue(bothCallbacksEntered, "both contained invocations must reach callbacks; $outcomes")
            assertEquals(2, heldCallbackCount, "both callbacks must remain held simultaneously; $outcomes")
            assertTrue(bothInvocationsHeld, "neither invocation may finish before callback release; $outcomes")
            assertEquals(AgentExecutionRequestBinding.capture(firstRequest), first.requestBinding, outcomes)
            assertEquals(AgentExecutionRequestBinding.capture(secondRequest), second.requestBinding, outcomes)
            assertEquals(expectedWirePromptSha256(firstRequest), firstEvidence.wirePromptSha256, outcomes)
            assertEquals(expectedWirePromptSha256(secondRequest), secondEvidence.wirePromptSha256, outcomes)
            assertFalse(firstEvidence.wirePromptSha256 == secondEvidence.wirePromptSha256, outcomes)
            assertEquals(AgentStopReason.COMPLETED, completedStopReasonForTest("first", first, firstEvidence, outcomes))
            assertEquals(AgentStopReason.COMPLETED, completedStopReasonForTest("second", second, secondEvidence, outcomes))
            assertEquals(
                firstEvidence.wirePromptSha256,
                assertNotNull(firstEvidence.completeExecutionEvidence, "first: ${firstEvidence.summaryForTest()}").wirePromptSha256,
            )
            assertEquals(
                secondEvidence.wirePromptSha256,
                assertNotNull(secondEvidence.completeExecutionEvidence, "second: ${secondEvidence.summaryForTest()}").wirePromptSha256,
            )
            assertEquals("new source\n", firstFixture.source.readText())
            assertEquals("new source\n", secondFixture.source.readText())
            assertEquals(FORBIDDEN_CANARY_CONTENT, firstFixture.forbiddenCanary.readText())
            assertEquals(FORBIDDEN_CANARY_CONTENT, secondFixture.forbiddenCanary.readText())
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, firstEvidence.cleanupDisposition, outcomes)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, secondEvidence.cleanupDisposition, outcomes)
            listOf("first" to firstEvidence, "second" to secondEvidence).forEach { (label, evidence) ->
                val diagnostics = assertNotNull(evidence.diagnostics, "$label: $outcomes")
                assertTrue(diagnostics.remainingProcessIds.isEmpty(), "$label: $outcomes")
                assertTrue(diagnostics.sandboxCleanupVerified, "$label: $outcomes")
                assertProcessStopped(diagnostics.pid)
            }
        } finally {
            releaseCallbacks.countDown()
            executor.shutdownNow()
        }
    }

    private fun AcpInvocationEvidenceSnapshot.summaryForTest(): String =
        "phase=$phaseReached cleanup=$cleanupDisposition audits=$completeness " +
            "negotiated=${negotiatedAgent != null} diagnostics=${diagnostics != null} " +
            "sandbox=${sandboxEvidence != null}"

    /** Fixed source labels only: exception messages, file names and process data are never rendered. */
    private fun boundedPreparationCauseForTest(failure: Throwable?): String {
        if (failure == null) return "none"
        val allowedTypes = setOf(
            "decompengine.agent.AgentExecutionException", "decompengine.acp.AcpCleanupProofFailure",
            "decompengine.acp.AcpPhaseTimeout", "decompengine.acp.RequestedAcpCancellation",
            "java.io.IOException", "java.lang.IllegalArgumentException", "java.lang.IllegalStateException",
            "java.lang.SecurityException", "java.lang.InterruptedException", "java.lang.UnsupportedOperationException",
            "java.nio.file.AccessDeniedException", "java.nio.file.FileAlreadyExistsException",
            "java.nio.file.FileSystemException", "java.nio.file.NoSuchFileException",
            "java.util.concurrent.CancellationException", "java.util.concurrent.ExecutionException",
            "java.util.concurrent.TimeoutException", "com.sun.jna.LastErrorException",
        )
        val allowedClasses = setOf(
            "AcpAgentHarness", "ProductionAcpSandboxExecution", "LinuxBubblewrapBoundary",
            "LinuxBubblewrapBoundary\$Companion", "LinuxBubblewrapBoundaryKt",
            "RuntimePrivateControlScope", "RuntimePrivateControlScope\$Companion",
            "PinnedControlDirectory", "PinnedControlDirectory\$Companion", "PinnedSandboxControlTemporaryParent",
            "PinnedSecurityExecutable", "PinnedSecurityExecutable\$Companion",
            "PinnedSystemdBusEndpoint", "PinnedSystemdBusEndpoint\$Companion",
            "LinuxFilesystemSyscalls", "LinuxFilesystemSyscallsKt", "LinuxBoundedSessionProcessKt",
        )
        val methodName = Regex("[A-Za-z_\$<>][A-Za-z0-9_\$<>-]{0,95}")
        val seen = ArrayList<Throwable>(6)
        val rendered = ArrayList<String>(6)
        var cause: Throwable? = failure
        while (cause != null && seen.size < 6 && seen.none { it === cause }) {
            val current = requireNotNull(cause)
            seen += current
            val type = current.javaClass.name.takeIf { it in allowedTypes } ?: "other"
            val frames = current.stackTrace.asSequence().take(64).mapNotNull { frame ->
                val sourceClass = frame.className.removePrefix("decompengine.acp.")
                if (!frame.className.startsWith("decompengine.acp.") || sourceClass !in allowedClasses ||
                    !methodName.matches(frame.methodName) || frame.lineNumber !in 1..20_000
                ) null else "$sourceClass.${frame.methodName}:${frame.lineNumber}"
            }.take(3).joinToString(",")
            rendered += "$type[$frames]"
            cause = current.cause
        }
        if (cause != null) rendered += "truncated"
        return rendered.joinToString(" -> ").take(2048)
    }

    private fun completedStopReasonForTest(
        label: String,
        receipt: AgentExecutionReceipt,
        evidence: AcpInvocationEvidenceSnapshot,
        outcomes: String,
    ): AgentStopReason {
        val failure = (receipt.outcome as? AgentExecutionOutcome.Failed)?.failure
        return assertIs<AgentExecutionOutcome.Returned>(
            receipt.outcome,
            "$label: ${evidence.summaryForTest()} " +
                "failureKind=${failure?.kind} failureMessage=${failure?.message} " +
                "failureDetails=${failure?.details} " +
                "causeType=${receipt.failureCause?.javaClass?.name} " +
                "nestedCauseType=${receipt.failureCause?.cause?.javaClass?.name}; outcomes=$outcomes",
        ).result.stopReason
    }

    @Test
    fun `fake agent permission request uses offered default denial and metadata-only evidence`() {
        val fixture = fixture()
        val request = fixture.request.withPolicy(
            AgentAccessPolicy(
                fixture.request.accessPolicy.pathRules,
                fixture.request.accessPolicy.allowedOperations + AgentOperation.REQUEST_PERMISSION,
            ),
        )
        val harness = harness("permission-default-deny")
        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()

        val result = harness.execute(request, events::add)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val permission = events.filterIsInstance<AgentPermissionEvent>().single()
        assertEquals(AgentPermissionDecision.DENY, permission.decision)
        assertEquals("reject", permission.selectedOptionId)
        assertEquals(2, result.usage?.toolCalls)
        assertEquals(
            1,
            events.filterIsInstance<AgentToolEvent>().count { it.toolCallId == "permission-tool" },
            "permission callback ToolCallUpdate must be translated and counted exactly once",
        )
        val evidence = harness.latestPermissionAudit().single()
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, evidence.reason)
        assertFalse(evidence.authorityExpanded)
        assertFalse(evidence.toString().contains("Run exact fixture command"))
    }

    @Test
    fun `fake agent exercises official terminal create wait output release and tool correlation`() {
        val parent = createTempDirectory("acp-terminal-wire-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("project", parent)
        val source = staging.path.resolve("contract/artifact.txt")
        source.parent.createDirectories()
        source.writeText("original artifact\n")
        val forbiddenCanary = staging.path.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val pathRule = AgentPathRule(
            AgentWorkspacePath("project", "contract/artifact.txt"),
            setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
        )
        val request = AgentExecutionRequest(
            objective = "exercise the protocol fixture",
            workspaceRoots = listOf(staging.workspaceRoot),
            contextInputs = listOf(decompengine.agent.AgentContextInput("contract", "protocol evidence")),
            accessPolicy = AgentAccessPolicy(
                listOf(pathRule),
                setOf(
                    AgentOperation.READ_FILE,
                    AgentOperation.WRITE_FILE,
                    AgentOperation.EXECUTE_COMMAND,
                    AgentOperation.REQUEST_PERMISSION,
                ),
            ),
        )
        val terminalArgument = "wire-terminal"
        val terminalPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(ECHO),
                    listOf(terminalArgument),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(3),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val harness = harness(
            "terminal-lifecycle",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )

        val events = mutableListOf<decompengine.agent.AgentExecutionEvent>()
        val result = try {
            harness.execute(request, events::add)
        } catch (failure: AgentExecutionException) {
            throw AssertionError(
                "terminal wire fixture failed; metadata-only audit=${harness.latestTerminalAudit()}",
                failure,
            )
        }

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        val reasons = harness.latestTerminalAudit().map { it.reason }.toSet()
        assertTrue(AcpTerminalAuditReason.CREATED in reasons)
        assertTrue(AcpTerminalAuditReason.TOOL_BOUND in reasons)
        assertTrue(AcpTerminalAuditReason.EXIT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.OUTPUT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.RELEASED in reasons)
        assertTrue(harness.latestTerminalAudit().all { it.networkIsolated })
        assertEquals(1, result.usage?.toolCalls)
        assertEquals(
            1,
            events.filterIsInstance<AgentToolEvent>().count { it.toolCallId == "terminal-tool" },
            "permission callback terminal binding must validate and count its tool call exactly once",
        )
        assertEquals(AgentPermissionDecision.DENY, events.filterIsInstance<AgentPermissionEvent>().single().decision)
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, harness.latestPermissionAudit().single().reason)
        val evidence = assertNotNull(harness.latestSandboxEvidence())
        assertTrue(evidence.outerAgentContained)
        assertEquals(
            listOf(AcpSandboxLaunchPurpose.OUTER_AGENT, AcpSandboxLaunchPurpose.TERMINAL),
            evidence.launches.map { it.purpose },
        )

        val orphanHarness = harness(
            "terminal-cancelled-orphan",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val orphanFailure = executeExpectingCleanFailure(
            orphanHarness,
            request,
            "orphan terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.PROTOCOL, orphanFailure.failure.kind)
        assertTrue(orphanFailure.message.orEmpty().contains("orphan terminal"))
        assertTrue(orphanHarness.latestTerminalAudit().any {
            it.reason == AcpTerminalAuditReason.UNBOUND_TERMINAL
        })

        val crossSessionHarness = harness(
            "terminal-cross-session-hang",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val crossSessionFailure = executeExpectingCleanFailure(
            crossSessionHarness,
            request,
            "cross-session terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(
            AgentFailureKind.PROTOCOL,
            crossSessionFailure.failure.kind,
            "fatal terminal callback violations must win even when the peer leaves session/prompt pending",
        )
        assertTrue(
            crossSessionFailure.message.orEmpty().contains("crossed session boundaries"),
            crossSessionFailure.message,
        )
        assertTrue(crossSessionHarness.latestTerminalAudit().none {
            it.reason == AcpTerminalAuditReason.CROSS_SESSION
        }, "raw session correlation must fail before SDK or terminal-broker dispatch")

        val missingSessionHarness = harness(
            "terminal-missing-session-hang",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )
        val missingSessionFailure = executeExpectingCleanFailure(
            missingSessionHarness,
            request,
            "missing-session terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingSessionFailure.failure.kind)
        assertTrue(
            missingSessionFailure.message.orEmpty().contains("requires string params.sessionId"),
            missingSessionFailure.message,
        )
        assertTrue(missingSessionHarness.latestTerminalAudit().isEmpty())

        source.writeText("original artifact\n")
        val nearWallPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(SLEEP),
                    listOf("30"),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(10),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val nearWallHarness = harness(
            "terminal-near-wall",
            sentinel = "wire",
            timeouts = timeouts(request = 5_000, shutdown = 1_000),
            terminalPolicy = nearWallPolicy,
        )
        val nearWallFailure = executeExpectingCleanFailure(
            nearWallHarness,
            request.withWallClockTimeout(Duration.ofSeconds(3)),
            "near-wall terminal",
            forbiddenCanary = forbiddenCanary,
        )
        assertEquals(AgentFailureKind.TIMEOUT, nearWallFailure.failure.kind)
        assertEquals("near-wall terminal requested\n", source.readText(), "fixture never reached terminal/create")
        val nearWallAudit = nearWallHarness.latestTerminalAudit()
        val deadlineTermination = nearWallAudit.firstOrNull { it.reason == AcpTerminalAuditReason.TIMEOUT }
        assertNotNull(deadlineTermination, "near-wall terminal work did not observe the shared execution deadline")
        nearWallAudit.firstOrNull { it.reason == AcpTerminalAuditReason.CREATED }?.let { created ->
            assertTrue(
                created.sequence < deadlineTermination.sequence,
                "execution-wide timeout evidence must follow a successfully created terminal",
            )
        }
    }

    @Test
    fun `fake agent exercises terminal create kill wait output and release lifecycle`() {
        val parent = createTempDirectory("acp-terminal-kill-wire-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("project", parent)
        val artifact = staging.path.resolve("contract/artifact.txt")
        artifact.parent.createDirectories()
        artifact.writeText("original artifact\n")
        val forbiddenCanary = staging.path.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val request = AgentExecutionRequest(
            objective = "exercise the protocol fixture",
            workspaceRoots = listOf(staging.workspaceRoot),
            contextInputs = listOf(
                decompengine.agent.AgentContextInput("contract", "protocol evidence"),
            ),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "contract/artifact.txt"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
                setOf(
                    AgentOperation.READ_FILE,
                    AgentOperation.EXECUTE_COMMAND,
                    AgentOperation.REQUEST_PERMISSION,
                ),
            ),
        )
        val terminalPolicy = AcpTerminalExecutionPolicy(
            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            listOf(
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(SLEEP),
                    listOf("30"),
                    staging.path,
                ),
            ),
            AcpTerminalLimits(
                maximumConcurrentTerminals = 1,
                maximumTerminalCreates = 1,
                maximumDuration = Duration.ofSeconds(3),
                resourceLimits = AcpSandboxResourceLimits(maximumCpuSeconds = 3),
            ),
        )
        val harness = harness(
            "terminal-kill-lifecycle",
            timeouts = timeouts(request = 5_000),
            terminalPolicy = terminalPolicy,
        )

        val result = harness.execute(request)

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        val reasons = harness.latestTerminalAudit().map { it.reason }.toSet()
        assertTrue(AcpTerminalAuditReason.CREATED in reasons)
        assertTrue(AcpTerminalAuditReason.TOOL_BOUND in reasons)
        assertTrue(AcpTerminalAuditReason.KILLED in reasons)
        assertTrue(AcpTerminalAuditReason.EXIT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.OUTPUT_OBSERVED in reasons)
        assertTrue(AcpTerminalAuditReason.RELEASED in reasons)
        assertTrue(harness.latestTerminalAudit().all { it.networkIsolated })
        assertEquals(AcpPermissionAuditOutcome.DENIED, harness.latestPermissionAudit().single().outcome)
        assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, harness.latestPermissionAudit().single().reason)
        assertEquals(1, result.usage?.toolCalls)
        assertEquals("original artifact\n", artifact.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, forbiddenCanary.readText())
        assertCleanTermination(harness)
    }

    @Test
    fun `unsupported versions and missing configured capabilities fail actionably`() {
        val versionFixture = fixture(genericContract = true)
        val versionHarness = harness("unsupported-version")
        val versionFailure = executeExpectingCleanFailure(
            versionHarness,
            versionFixture.request,
            "unsupported version",
            versionFixture,
        )
        assertEquals(
            AgentFailureKind.PROTOCOL,
            versionFailure.failure.kind,
            "${versionFailure.message}; ${versionFailure.failure.details}; cause=${versionFailure.cause}",
        )
        assertTrue(versionFailure.message.orEmpty().contains("stable v1"))
        assertEquals("2", versionFailure.failure.details["offeredVersion"])

        val capabilityFixture = fixture(genericContract = true)
        val capabilityHarness = harness(
            "success",
            requiredCapabilities = setOf(AcpRequiredAgentCapability.LOAD_SESSION),
        )
        val capabilityFailure = executeExpectingCleanFailure(
            capabilityHarness,
            capabilityFixture.request,
            "missing required capability",
            capabilityFixture,
        )
        assertEquals(AgentFailureKind.CONFIGURATION, capabilityFailure.failure.kind)
        assertEquals("loadSession", capabilityFailure.failure.details["missingCapabilities"])

        val missingVersionFixture = fixture(genericContract = true)
        val missingVersionHarness = harness("missing-protocol-version")
        val missingVersion = executeExpectingCleanFailure(
            missingVersionHarness,
            missingVersionFixture.request,
            "missing protocol version",
            missingVersionFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingVersion.failure.kind)
    }

    @Test
    fun `unknown duplicate and late JSON-RPC response ids are rejected before SDK dispatch`() {
        listOf("unknown-response-id", "duplicate-response-id", "late-response-id").forEach { mode ->
            val fixture = fixture(genericContract = true)
            val harness = harness(mode)
            val failure = executeExpectingCleanFailure(harness, fixture.request, mode, fixture)

            assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind, mode)
            assertTrue(failure.message.orEmpty().contains("response id"), mode)
        }
    }

    @Test
    fun `pipelined callback ids unknown peer methods and denied writes follow JSON-RPC`() {
        val pipelinedFixture = fixture(genericContract = true)
        val pipelinedHarness = harness("pipelined-callbacks")

        val pipelined = pipelinedHarness.execute(pipelinedFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, pipelined.stopReason)
        assertEquals(listOf(0L, 1L), pipelinedHarness.latestFilesystemAudit().map { it.sequence })
        assertEquals(
            setOf("contract/artifact.txt"),
            pipelinedHarness.latestFilesystemAudit().map { assertNotNull(it.policyPath).relativePath }.toSet(),
        )
        assertEquals("original artifact\n", pipelinedFixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, pipelinedFixture.forbiddenCanary.readText())
        assertCleanTermination(pipelinedHarness, "pipelined callbacks")

        val unknownFixture = fixture(genericContract = true)
        val unknownHarness = harness("unknown-methods")

        val unknown = unknownHarness.execute(unknownFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, unknown.stopReason)
        assertTrue(unknownHarness.latestFilesystemAudit().isEmpty())
        assertEquals("original artifact\n", unknownFixture.source.readText())
        assertEquals(FORBIDDEN_CANARY_CONTENT, unknownFixture.forbiddenCanary.readText())
        assertCleanTermination(unknownHarness, "unknown methods")

        val deniedFixture = fixture(genericContract = true)
        val canaryBefore = Files.readAllBytes(deniedFixture.forbiddenCanary)
        val deniedHarness = harness("forbidden-write")

        val denied = deniedHarness.execute(deniedFixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, denied.stopReason)
        assertTrue(canaryBefore.contentEquals(Files.readAllBytes(deniedFixture.forbiddenCanary)))
        val denial = deniedHarness.latestFilesystemAudit().single()
        assertEquals("fs/write_text_file", denial.method)
        assertEquals("forbidden-canary.txt", assertNotNull(denial.policyPath).relativePath)
        assertEquals(AcpFilesystemAuditOutcome.DENIED, denial.outcome)
        assertEquals(AcpFilesystemAuditReason.POLICY_DENIED, denial.reason)
        assertFalse(denial.toString().contains(deniedFixture.workspace.toString()))
        assertFalse(denial.toString().contains("attempted overwrite payload"))
        assertCleanTermination(deniedHarness, "denied write")
    }

    @Test
    fun `malformed stdout clean EOF and nonzero crashes are distinct failures`() {
        val malformedInitializeFixture = fixture(genericContract = true)
        val malformedInitializeHarness = harness("malformed-initialize")
        val malformedInitialize = executeExpectingCleanFailure(
            malformedInitializeHarness,
            malformedInitializeFixture.request,
            "malformed initialize",
            malformedInitializeFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, malformedInitialize.failure.kind)

        val malformedFixture = fixture(genericContract = true)
        val malformedHarness = harness("malformed-prompt")
        val malformed = executeExpectingCleanFailure(
            malformedHarness,
            malformedFixture.request,
            "malformed prompt",
            malformedFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, malformed.failure.kind)
        assertTrue(malformed.message.orEmpty().contains("malformed JSON-RPC"))

        listOf(
            "contaminated-prompt",
            "missing-jsonrpc-prompt",
            "wrong-jsonrpc-prompt",
            "numeric-jsonrpc-prompt",
            "result-and-error-prompt",
        ).forEach { mode ->
            val strictFixture = fixture(genericContract = true)
            val strictHarness = harness(mode)
            val strictFailure = executeExpectingCleanFailure(
                strictHarness,
                strictFixture.request,
                mode,
                strictFixture,
            )
            assertEquals(AgentFailureKind.PROTOCOL, strictFailure.failure.kind, mode)
            assertTrue(strictFailure.message.orEmpty().contains("malformed JSON-RPC"), mode)
        }

        val invalidUtf8Fixture = fixture(genericContract = true)
        val invalidUtf8Harness = harness("invalid-utf8-prompt")
        val invalidUtf8 = executeExpectingCleanFailure(
            invalidUtf8Harness,
            invalidUtf8Fixture.request,
            "invalid UTF-8",
            invalidUtf8Fixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, invalidUtf8.failure.kind)
        assertTrue(invalidUtf8.message.orEmpty().contains("invalid UTF-8"))

        val invalidUpdateFixture = fixture(genericContract = true)
        val invalidUpdateHarness = harness("invalid-update")
        val invalidUpdate = executeExpectingCleanFailure(
            invalidUpdateHarness,
            invalidUpdateFixture.request,
            "invalid update",
            invalidUpdateFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, invalidUpdate.failure.kind)
        assertTrue(invalidUpdate.message.orEmpty().contains("empty tool call id"))

        val negativeUsageFixture = fixture(genericContract = true)
        val negativeUsageHarness = harness("negative-usage")
        val negativeUsage = executeExpectingCleanFailure(
            negativeUsageHarness,
            negativeUsageFixture.request,
            "negative usage",
            negativeUsageFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, negativeUsage.failure.kind)
        assertTrue(negativeUsage.message.orEmpty().contains("invalid prompt usage"))

        val missingUsageFixture = fixture(genericContract = true)
        val missingUsageHarness = harness("missing-usage")
        val missingUsage = executeExpectingCleanFailure(
            missingUsageHarness,
            missingUsageFixture.request.withTokenLimits(1_000, 1_000),
            "missing usage",
            missingUsageFixture,
        )
        assertEquals(AgentFailureKind.PROTOCOL, missingUsage.failure.kind)
        assertTrue(missingUsage.message.orEmpty().contains("inputTokens,outputTokens"))

        val eofFixture = fixture(genericContract = true)
        val eofHarness = harness("eof-prompt")
        val eof = executeExpectingCleanFailure(eofHarness, eofFixture.request, "clean EOF", eofFixture)
        assertEquals(AgentFailureKind.TRANSPORT, eof.failure.kind)

        val crashFixture = fixture(genericContract = true)
        val crashHarness = harness("crash-prompt")
        val crash = executeExpectingCleanFailure(crashHarness, crashFixture.request, "prompt crash", crashFixture)
        assertEquals(AgentFailureKind.PROCESS_CRASH, crash.failure.kind)
        assertEquals("23", crash.failure.details["exitCode"])

        val initializeCrashFixture = fixture(genericContract = true)
        val initializeCrashHarness = harness("crash-after-initialize")
        val initializeCrash = executeExpectingCleanFailure(
            initializeCrashHarness,
            initializeCrashFixture.request,
            "initialize crash",
            initializeCrashFixture,
        )
        assertEquals(AgentFailureKind.PROCESS_CRASH, initializeCrash.failure.kind)
        assertEquals("17", initializeCrash.failure.details["exitCode"])
    }

    @Test
    fun `literal physical newline inside a JSON string fails closed and cleans containment`() {
        assertFixtureManifestAcquisitionBounds()
        val fixture = fixture(genericContract = true, wallMillis = 2_000)
        val harness = harness(
            "physical-newline-in-string",
            timeouts = timeouts(request = 1_000, shutdown = 600),
        )

        val failure = assertBoundedCleanProtocolFailure(fixture, harness, maximumWallMillis = 5_000)

        assertTrue(failure.message.orEmpty().contains("malformed JSON-RPC"), failure.message)
    }

    @Test
    fun `startup request and idle waits are independently bounded`() {
        val startupFixture = fixture(genericContract = true)
        val startupHarness = harness(
            "no-initialize",
            timeouts = timeouts(startup = 180, request = 1_000),
        )
        val startup = executeExpectingCleanFailure(
            startupHarness,
            startupFixture.request,
            "initialize timeout",
            startupFixture,
        )
        assertEquals(AgentFailureKind.TIMEOUT, startup.failure.kind)
        assertTrue(startup.message.orEmpty().contains("initialize"))

        val requestFixture = fixture(genericContract = true)
        val requestHarness = harness(
            "no-session-response",
            timeouts = timeouts(startup = 1_000, request = 180),
        )
        val request = executeExpectingCleanFailure(
            requestHarness,
            requestFixture.request,
            "session request timeout",
            requestFixture,
        )
        assertEquals(AgentFailureKind.TIMEOUT, request.failure.kind)
        assertTrue(request.message.orEmpty().contains("session/new"))

        val idleFixture = fixture(idleMillis = 150, genericContract = true)
        val idleHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 1_000, request = 2_000),
        )
        val idle = executeExpectingCleanFailure(idleHarness, idleFixture.request, "idle timeout", idleFixture)
        assertEquals(AgentFailureKind.TIMEOUT, idle.failure.kind)
        assertTrue(idle.message.orEmpty().contains("idle"))
        val idleDiagnostics = assertNotNull(idleHarness.latestDiagnostics())
        assertFalse(idleDiagnostics.forcedTermination)

        // The wall budget includes the authenticated workspace snapshot and outer sandbox launch.
        // Leave enough headroom for a contended hosted runner while keeping idle out of contention.
        val wallFixture = fixture(idleMillis = 20_000, wallMillis = 5_000, genericContract = true)
        val wallHarness = harness(
            "wait-for-cancel",
            timeouts = timeouts(startup = 2_000, request = 10_000),
        )
        val wall = executeExpectingCleanFailure(wallHarness, wallFixture.request, "wall timeout", wallFixture)
        assertEquals(AgentFailureKind.TIMEOUT, wall.failure.kind)
        assertTrue(wall.message.orEmpty().contains("wall-clock"), wall.message)
    }

    @Test
    fun `a blocking event callback cannot prevent the wall deadline and process cleanup`() {
        // The callback must be reached before the wall clock expires; prelaunch containment can
        // legitimately take seconds under hosted contention and is part of the same wall budget.
        val fixture = fixture(idleMillis = 20_000, wallMillis = 5_000, genericContract = true)
        val harness = harness(
            "update-then-hang",
            timeouts = timeouts(startup = 2_000, request = 10_000, shutdown = 600),
        )
        val events = mutableListOf<AgentExecutionEvent>()
        val callbackEntered = CountDownLatch(1)
        val releaseCallback = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(fixture.request) { event ->
                    events += event
                    callbackEntered.countDown()
                    releaseCallback.await()
                }
            }
            val callbackObserved = callbackEntered.await(10, TimeUnit.SECONDS)
            if (!callbackObserved) {
                // Observe only an already completed future; keep the existing waits and wall budget.
                val completed = execution.isDone
                var completedWithoutCallback = false
                var completionFailure: Throwable? = null
                if (completed) {
                    try {
                        execution.get()
                        completedWithoutCallback = true
                    } catch (wrapped: ExecutionException) {
                        completionFailure = wrapped.cause ?: wrapped
                    } catch (cancelled: java.util.concurrent.CancellationException) {
                        completionFailure = cancelled
                    }
                }
                val invocation = (completionFailure as? AgentExecutionException)?.receipt?.providerEvidence as? AcpInvocationEvidenceSnapshot
                assertTrue(callbackObserved, "fixture never delivered an event; completed=$completed " +
                    "completedWithoutCallback=$completedWithoutCallback " +
                    "invocation=${invocation?.summaryForTest() ?: "unavailable"} " +
                    "cause=${boundedPreparationCauseForTest(completionFailure)}")
            }

            val failure = try {
                execution.get(10, TimeUnit.SECONDS)
                error("execution unexpectedly succeeded")
            } catch (wrapped: ExecutionException) {
                wrapped.cause as? AgentExecutionException ?: throw wrapped
            }
            assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
            assertTrue(failure.message.orEmpty().contains("wall-clock"))
            assertCleanTermination(
                harness = harness,
                context = "blocked callback timeout",
                fixture = fixture,
                failure = failure,
                events = events,
            )
        } finally {
            releaseCallback.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun `caller cancellation sends session cancel and returns a cancelled result`() {
        val fixture = fixture(includeReadyPath = true, genericContract = true)
        val cancellation = AgentCancellationSource()
        val request = fixture.request.withCancellation(cancellation)
        val ready = fixture.workspace.resolve("ready")
        val harness = harness(
            "wait-for-cancel",
            ready = ready,
            timeouts = timeouts(startup = 1_000, request = 3_000),
        )
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        val readyAcknowledged = CountDownLatch(1)
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(request) { event ->
                    events += event
                    if (event is AgentMessageEvent && event.textDelta == "cooperative-cancellation-ready") {
                        readyAcknowledged.countDown()
                    }
                }
            }
            // Publication precedes callback completion; cancel only after the peer confirms that
            // the official write response arrived, so cancellation cannot roll readiness back.
            assertTrue(readyAcknowledged.await(3, TimeUnit.SECONDS), "fixture never acknowledged the ready write")
            assertTrue(ready.exists(), "fixture never reached session/prompt")
            assertEquals("ready\n", ready.readText())
            cancellation.cancel()

            val result = try {
                execution.get(3, TimeUnit.SECONDS)
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            }
            assertEquals(AgentStopReason.CANCELLED, result.stopReason)
            assertEquals("original artifact\n", fixture.source.readText())
            assertEquals(AgentFileChangeKind.CREATED, result.changes.single().kind)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination)
            assertCleanTermination(
                harness = harness,
                context = "cooperative cancellation",
                fixture = fixture,
                events = events,
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `caller cancellation remains bounded when the in-flight agent ignores cancel and term`() {
        val fixture = fixture(includeReadyPath = true)
        val cancellation = AgentCancellationSource()
        val ready = fixture.workspace.resolve("ready")
        val harness = harness(
            "ignore-cancel",
            ready = ready,
            timeouts = timeouts(startup = 1_000, request = 3_000, shutdown = 600),
        )
        val executor = Executors.newSingleThreadExecutor()
        val readyAcknowledged = CountDownLatch(1)
        try {
            val execution = executor.submit<decompengine.agent.AgentExecutionResult> {
                harness.execute(fixture.request.withCancellation(cancellation)) { event ->
                    if (event is AgentMessageEvent && event.textDelta == "uncooperative-cancellation-ready") {
                        readyAcknowledged.countDown()
                    }
                }
            }
            // The peer acknowledges the ready write and installs its TERM handler before this
            // event, so cancellation exercises the intended uncooperative lifecycle.
            assertTrue(readyAcknowledged.await(3, TimeUnit.SECONDS), "fixture never acknowledged uncooperative readiness")
            assertTrue(ready.exists(), "fixture never reached session/prompt")
            assertEquals("ready\n", ready.readText())
            cancellation.cancel()

            val result = try {
                execution.get(3, TimeUnit.SECONDS)
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            }
            assertEquals(AgentStopReason.CANCELLED, result.stopReason)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertTrue(diagnostics.forcedTermination)
            assertTrue(diagnostics.rootTerminationRequested)
            assertTrue(diagnostics.remainingProcessIds.isEmpty())
            assertProcessStopped(diagnostics.pid)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `shutdown deadline forcibly terminates an agent that ignores stdin EOF`() {
        val fixture = fixture()
        val harness = harness(
            "success-hang",
            timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 240),
        )

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.forcedTermination)
        assertTrue(diagnostics.rootTerminationRequested)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `a final prompt response followed by a natural nonzero exit remains a process crash`() {
        mapOf(
            "response-then-crash" to "31",
            "response-then-delayed-crash" to "32",
        ).forEach { (mode, expectedExit) ->
            val fixture = fixture(genericContract = true)
            val harness = harness(
                mode,
                timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 1_000),
            )

            val failure = executeExpectingCleanFailure(harness, fixture.request, mode, fixture)

            assertEquals(AgentFailureKind.PROCESS_CRASH, failure.failure.kind, mode)
            assertEquals(expectedExit, failure.failure.details["exitCode"], mode)
            val diagnostics = assertNotNull(harness.latestDiagnostics())
            assertFalse(diagnostics.forcedTermination, mode)
            assertFalse(diagnostics.rootTerminationRequested, mode)
            assertEquals(expectedExit.toInt(), diagnostics.exitCode, mode)
        }
    }

    @Test
    fun `forced shutdown repeatedly discovers and terminates subprocess descendants`() {
        val fixture = fixture(includeReadyPath = true)
        val childPidPath = fixture.workspace.resolve("ready")
        val harness = harness(
            "success-child-hang",
            ready = childPidPath,
            timeouts = timeouts(startup = 1_000, request = 2_000, shutdown = 600),
        )

        val result = harness.execute(fixture.request)

        assertTrue(childPidPath.readText().trim().toLong() > 0L)
        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.forcedTermination)
        assertTrue(diagnostics.rootTerminationRequested)
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `stdout frame total and retained stderr sizes are bounded independently`() {
        val frameFixture = fixture(genericContract = true)
        val frameHarness = harness("oversized-frame-prompt", maximumFrameBytes = 1_024)
        val frameFailure = executeExpectingCleanFailure(
            frameHarness,
            frameFixture.request,
            "individual frame limit",
            frameFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, frameFailure.failure.kind)
        assertTrue(frameFailure.message.orEmpty().contains("frame limit"))

        val totalFixture = fixture(maximumOutputBytes = 1_024, genericContract = true)
        val totalHarness = harness("oversized-frame-prompt", maximumFrameBytes = 128 * 1024)
        val totalFailure = executeExpectingCleanFailure(
            totalHarness,
            totalFixture.request,
            "aggregate stdout limit",
            totalFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, totalFailure.failure.kind)
        assertTrue(totalFailure.message.orEmpty().contains("execution limit"))

        val stderrFixture = fixture(genericContract = true)
        val stderrHarness = harness("stderr-overflow")
        val stderrEvents = mutableListOf<AgentExecutionEvent>()
        stderrHarness.execute(stderrFixture.request, stderrEvents::add)
        val diagnostics = assertNotNull(stderrHarness.latestDiagnostics())
        assertTrue(diagnostics.stderrTruncated)
        assertTrue(diagnostics.stderr.toByteArray().size <= 64 * 1024)
        assertCleanTermination(
            harness = stderrHarness,
            context = "retained stderr limit",
            fixture = stderrFixture,
            events = stderrEvents,
        )

        val aggregateLimit = 16L * 1024
        val floodFixture = fixture(maximumOutputBytes = aggregateLimit, genericContract = true)
        val floodHarness = harness(
            "stderr-flood",
            timeouts = timeouts(request = 2_000, shutdown = 1_000),
        )
        val floodFailure = executeExpectingCleanFailure(
            floodHarness,
            floodFixture.request,
            "stderr flood",
            floodFixture,
        )
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, floodFailure.failure.kind)
        assertTrue(floodFailure.message.orEmpty().contains("stdout and stderr"))
        val floodDiagnostics = assertNotNull(floodHarness.latestDiagnostics())
        assertEquals(aggregateLimit, floodDiagnostics.producedOutputLimitBytes)
        assertTrue(floodDiagnostics.producedOutputBytes > aggregateLimit)
        assertTrue(floodDiagnostics.outputLimitExceeded)
        assertTrue(floodDiagnostics.rootTerminationRequested)
        val floodEvidence = assertNotNull(floodHarness.latestSandboxEvidence())
        assertEquals(floodDiagnostics.producedOutputBytes, floodEvidence.outerProcessOutput?.observedBytes)
        assertTrue(floodEvidence.outerProcessOutput?.limitExceeded == true)

        listOf("response-then-stderr-burst", "response-then-stdout-burst").forEach { mode ->
            val shutdownBurstFixture = fixture(
                maximumOutputBytes = aggregateLimit,
                genericContract = true,
            )
            val shutdownBurstHarness = harness(
                mode,
                timeouts = timeouts(request = 2_000, shutdown = 1_200),
            )
            val shutdownBurstFailure = executeExpectingCleanFailure(
                shutdownBurstHarness,
                shutdownBurstFixture.request,
                mode,
                shutdownBurstFixture,
            )
            assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, shutdownBurstFailure.failure.kind, mode)
            val shutdownBurstDiagnostics = assertNotNull(shutdownBurstHarness.latestDiagnostics(), mode)
            assertTrue(shutdownBurstDiagnostics.outputLimitExceeded, mode)
            assertTrue(shutdownBurstDiagnostics.producedOutputBytes > aggregateLimit, mode)
            assertTrue(
                shutdownBurstHarness.latestSandboxEvidence()?.outerProcessOutput?.limitExceeded == true,
                mode,
            )
        }
    }

    @Test
    fun `protocol frame flood is bounded before SDK dispatch and leaves no process or workspace residue`() {
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(Path.of("/usr/bin/true"), maximumProtocolFrames = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumProtocolFrames = MAXIMUM_ACP_PROTOCOL_FRAMES + 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumFrameBytes = MAXIMUM_ACP_FRAME_BYTES + 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProcessConfiguration(
                Path.of("/usr/bin/true"),
                maximumStderrBytes = MAXIMUM_ACP_STDERR_BYTES + 1,
            )
        }

        val fixture = fixture(
            wallMillis = 2_000,
            maximumOutputBytes = Long.MAX_VALUE,
            genericContract = true,
        )
        val harness = harness(
            "protocol-frame-flood",
            timeouts = timeouts(request = 1_000, shutdown = 600),
            maximumProtocolFrames = 8,
        )
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        try {
            val execution = executor.submit<AgentExecutionException> {
                assertFailsWith { harness.execute(fixture.request, events::add) }
            }
            val failure = try {
                execution.get(5, TimeUnit.SECONDS)
            } catch (wrapped: ExecutionException) {
                throw wrapped.cause ?: wrapped
            }

            assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, failure.failure.kind)
            assertTrue(failure.message.orEmpty().contains("8-frame protocol limit"), failure.message)
            assertEquals("original artifact\n", fixture.source.readText())
            assertCleanTermination(
                harness = harness,
                context = "protocol frame flood",
                fixture = fixture,
                failure = failure,
                events = events,
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `workspace snapshots stream large files and observe prelaunch cancellation and wall time`() {
        val largeFixture = fixture()
        largeFixture.source.writeText("x".repeat(2 * 1024 * 1024))

        val largeResult = harness("success").execute(largeFixture.request)

        assertEquals(AgentFileChangeKind.MODIFIED, largeResult.changes.single().kind)
        assertNotNull(largeResult.changes.single().beforeSha256)

        val cancellation = AgentCancellation {
            // Admission also polls cancellation. Target the actual snapshot boundary rather
            // than depending on how many cancellation checks precede workspace traversal.
            Thread.currentThread().stackTrace.any { frame ->
                frame.className == "decompengine.acp.WorkspaceSnapshotBudget" && frame.methodName == "checkpoint"
            }
        }
        val cancelledFixture = fixture()
        val cancelledHarness = harness("success")

        val cancelledReceipt = cancelledHarness.executeReceipt(
            cancelledFixture.request.withCancellation(cancellation),
        )
        val cancelled = assertIs<AgentExecutionOutcome.Returned>(cancelledReceipt.outcome).result
        val cancelledEvidence = assertIs<AcpInvocationEvidenceSnapshot>(cancelledReceipt.providerEvidence)

        assertEquals(AgentStopReason.CANCELLED, cancelled.stopReason)
        assertTrue(cancelled.summary.orEmpty().contains("initial workspace snapshot"))
        assertEquals(AcpExecutionLifecyclePhase.WORKSPACE_SNAPSHOT, cancelledEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, cancelledEvidence.cleanupDisposition)
        assertNull(cancelledEvidence.diagnostics)
        assertNull(cancelledEvidence.completeExecutionEvidence)
        assertEquals(null, cancelledHarness.latestDiagnostics())

        val launchCancellationObserved = java.util.concurrent.atomic.AtomicBoolean(false)
        val launchCancellation = AgentCancellation {
            val duringActualBoundaryLaunch = Thread.currentThread().stackTrace.any { frame ->
                frame.className == LinuxBubblewrapBoundary::class.java.name && frame.methodName == "launch"
            }
            if (duringActualBoundaryLaunch) launchCancellationObserved.set(true)
            duringActualBoundaryLaunch
        }
        val launchCancelledHarness = harness("success")
        val launchFixture = fixture()
        val launchReceipt = launchCancelledHarness.executeReceipt(
            launchFixture.request.withCancellation(launchCancellation),
        )
        val launchCancelled = assertIs<AgentExecutionOutcome.Returned>(launchReceipt.outcome).result
        val launchEvidence = assertIs<AcpInvocationEvidenceSnapshot>(launchReceipt.providerEvidence)
        assertTrue(launchCancellationObserved.get(), "fixture did not reach the real sandbox launch checkpoint")
        assertEquals(AgentStopReason.CANCELLED, launchCancelled.stopReason)
        assertTrue(launchCancelled.summary.orEmpty().contains("sandbox launch"))
        assertEquals(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH, launchEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.UNVERIFIED, launchEvidence.cleanupDisposition)
        assertNull(launchEvidence.completeExecutionEvidence)
        assertNull(launchCancelledHarness.latestDiagnostics())
        assertNull(launchCancelledHarness.latestSandboxEvidence())

        for (rootCheckpoint in listOf(true, false)) {
            val authorityCancellationObserved = java.util.concurrent.atomic.AtomicBoolean(false)
            val authorityCancellation = AgentCancellation {
                val frames = Thread.currentThread().stackTrace.filter {
                    it.className == "decompengine.acp.AcpFilesystemBroker\$Companion"
                }
                val atRoot = frames.any { it.methodName.startsWith("openRoot") }
                val selected = if (rootCheckpoint) atRoot else !atRoot && frames.any { it.methodName.startsWith("open") }
                if (selected) authorityCancellationObserved.set(true)
                selected
            }
            val authorityHarness = harness("success")
            val authorityFixture = fixture()
            val authorityReceipt = authorityHarness.executeReceipt(
                authorityFixture.request.withCancellation(authorityCancellation),
            )
            val authorityResult = assertIs<AgentExecutionOutcome.Returned>(
                authorityReceipt.outcome,
                "rootCheckpoint=$rootCheckpoint " +
                    "failureKind=${(authorityReceipt.outcome as? AgentExecutionOutcome.Failed)?.failure?.kind} " +
                    "${(authorityReceipt.providerEvidence as? AcpInvocationEvidenceSnapshot)?.summaryForTest()} " +
                    "cause=${boundedPreparationCauseForTest(authorityReceipt.failureCause)}",
            ).result
            val authorityEvidence = assertIs<AcpInvocationEvidenceSnapshot>(authorityReceipt.providerEvidence)
            assertTrue(authorityCancellationObserved.get(), "actual filesystem authority checkpoint was not reached")
            assertEquals(AgentStopReason.CANCELLED, authorityResult.stopReason)
            assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, authorityEvidence.phaseReached)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, authorityEvidence.cleanupDisposition)
            assertNull(authorityEvidence.negotiatedAgent)
            assertNull(authorityEvidence.completeExecutionEvidence)
            assertNull(authorityEvidence.wirePromptSha256)
            assertNull(authorityResult.session)
            val authorityDiagnostics = assertNotNull(authorityEvidence.diagnostics)
            assertTrue(authorityDiagnostics.remainingProcessIds.isEmpty())
            assertTrue(authorityDiagnostics.sandboxCleanupVerified)
            assertProcessStopped(authorityDiagnostics.pid)
        }

        val evidenceCancellationObserved = java.util.concurrent.atomic.AtomicBoolean(false)
        val evidenceCancellation = AgentCancellation {
            val duringEvidenceConstruction = Thread.currentThread().stackTrace.any { frame ->
                frame.className == LinuxBubblewrapBoundary::class.java.name && frame.methodName == "evidence"
            }
            if (duringEvidenceConstruction) evidenceCancellationObserved.set(true)
            duringEvidenceConstruction
        }
        val evidenceCancelledHarness = harness("success")
        val evidenceFixture = fixture()
        val evidenceReceipt = evidenceCancelledHarness.executeReceipt(
            evidenceFixture.request.withCancellation(evidenceCancellation),
        )
        val evidenceCancelled = assertIs<AgentExecutionOutcome.Returned>(evidenceReceipt.outcome).result
        val invocation = assertIs<AcpInvocationEvidenceSnapshot>(evidenceReceipt.providerEvidence)
        assertTrue(
            evidenceCancellationObserved.get(),
            "fixture did not reach post-launch evidence construction",
        )
        assertEquals(AgentStopReason.CANCELLED, evidenceCancelled.stopReason)
        assertEquals(AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT, invocation.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition)
        assertNull(invocation.completeExecutionEvidence)
        val evidenceCancellationDiagnostics = assertNotNull(invocation.diagnostics)
        assertTrue(evidenceCancellationDiagnostics.remainingProcessIds.isEmpty())
        assertTrue(evidenceCancellationDiagnostics.sandboxCleanupVerified)
        assertProcessStopped(evidenceCancellationDiagnostics.pid)

        val timeoutFixture = fixture()
        val timeoutHarness = harness("success")
        val timeout = assertFailsWith<AgentExecutionException> {
            timeoutHarness.execute(timeoutFixture.request.withWallClockTimeout(Duration.ofNanos(1)))
        }
        assertEquals(AgentFailureKind.TIMEOUT, timeout.failure.kind)
        assertEquals(mapOf("phase" to "scheduler", "reason" to "requestDeadline"), timeout.failure.details)
        val timeoutEvidence = assertIs<AcpInvocationEvidenceSnapshot>(assertNotNull(timeout.receipt).providerEvidence)
        assertEquals(AcpExecutionLifecyclePhase.REQUEST_BOUND, timeoutEvidence.phaseReached)
        assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, timeoutEvidence.cleanupDisposition)
        assertNull(timeoutEvidence.completeExecutionEvidence)
        assertEquals(null, timeoutHarness.latestDiagnostics())

    }

    @Test
    fun `authentication-required JSON-RPC error is typed and does not leak the process`() {
        val fixture = fixture(genericContract = true)
        val harness = harness("auth-required")
        val failure = executeExpectingCleanFailure(harness, fixture.request, "authentication required", fixture)

        assertEquals(AgentFailureKind.AUTHENTICATION, failure.failure.kind)
        assertEquals("-32000", failure.failure.details["rpcCode"])
        assertTrue(failure.message.orEmpty().contains("configure the external agent"))
    }

    @Test
    fun `official ACP filesystem callbacks enforce policy and retain metadata-only audit`() {
        val fixture = fixture()
        val harness = harness("fs-read-write")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals("new source through broker\n", fixture.source.readText())
        assertEquals(AgentFileChangeKind.MODIFIED, result.changes.single().kind)
        val audit = harness.latestFilesystemAudit()
        assertEquals(listOf(0L, 1L), audit.map { it.sequence })
        assertEquals(List(2) { "fixture-session" }, audit.map { it.sessionId })
        assertEquals(listOf("fs/read_text_file", "fs/write_text_file"), audit.map { it.method })
        assertEquals(List(2) { "src/module.c" }, audit.map { assertNotNull(it.policyPath).relativePath })
        assertTrue(audit.all { it.outcome == AcpFilesystemAuditOutcome.ALLOWED })
        assertFalse(audit.toString().contains(fixture.workspace.toString()))
        assertFalse(audit.toString().contains("new source through broker"))
        assertProcessStopped(assertNotNull(harness.latestDiagnostics()).pid)
    }

    @Test
    fun `captured repair writes traverse ACP without a writable host workspace`() {
        val harness = harness("repair-direct-write")
        val initial = mapOf("src/module.c" to "old source\n".toByteArray())
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))

        val execution = CapturedRepairStagingAuthority.execute(
            harness = harness,
            initialFiles = initial,
            writablePaths = initial.keys,
            budget = RepairResourceBudget(),
            requestFactory = ::capturedRepairRequest,
            onEvent = {},
        )

        assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
        assertContentEquals("new source\n".toByteArray(), execution.files.getValue("src/module.c"))
        val change = execution.result.changes.single()
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
        assertEquals("src/module.c", change.path.relativePath)
        val write = harness.latestFilesystemAudit().single()
        assertEquals("fs/write_text_file", write.method)
        assertEquals(AcpFilesystemAuditOutcome.ALLOWED, write.outcome)
        assertEquals(AcpFilesystemAuditReason.COMPLETED, write.reason)

        // The direct sandbox write in this fixture is intentionally different from the callback
        // body above. It dies with the namespace and cannot enter the host-owned captured result.
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
        val evidence = assertNotNull(harness.latestSandboxEvidence())
        assertTrue(evidence.outerAgentContained)
        assertTrue(evidence.networkIsolated)
        assertTrue(evidence.cgroupV2PidsLimited)
        assertTrue(evidence.cgroupV2MemoryLimited)
        assertTrue(evidence.cgroupV2CpuLimited)
        assertTrue(evidence.authorities.isEmpty(), "captured repair must not bind a host staging authority")
        assertEquals(AcpSandboxLaunchPurpose.OUTER_AGENT, evidence.launches.single().purpose)
        assertTrue(evidence.outerAgentLimits.maximumFileBytes > 0)
        assertTrue(evidence.outerAgentLimits.maximumAddressSpaceBytes > 0)
        assertTrue(evidence.outerAgentLimits.maximumCpuSeconds > 0)
    }

    @Test
    fun `captured repair rejects an oversized ACP write and permits a bounded retry`() {
        val harness = harness("repair-quota-retry")
        val initial = mapOf("src/module.c" to "old source\n".toByteArray())

        val execution = CapturedRepairStagingAuthority.execute(
            harness = harness,
            initialFiles = initial,
            writablePaths = initial.keys,
            budget = RepairResourceBudget(maximumPatchBytes = 4),
            requestFactory = ::capturedRepairRequest,
            onEvent = {},
        )

        assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
        assertContentEquals("fit\n".toByteArray(), execution.files.getValue("src/module.c"))
        assertContentEquals("old source\n".toByteArray(), initial.getValue("src/module.c"))
        assertEquals(4L, execution.result.changes.single().sizeBytes)
        assertEquals(
            listOf(AcpFilesystemAuditOutcome.DENIED, AcpFilesystemAuditOutcome.ALLOWED),
            harness.latestFilesystemAudit().map { it.outcome },
        )
        assertEquals(
            listOf(AcpFilesystemAuditReason.RESOURCE_LIMIT, AcpFilesystemAuditReason.COMPLETED),
            harness.latestFilesystemAudit().map { it.reason },
        )
        assertFalse(Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
        val diagnostics = assertNotNull(harness.latestDiagnostics())
        assertTrue(diagnostics.remainingProcessIds.isEmpty())
        assertTrue(diagnostics.sandboxCleanupVerified)
        assertProcessStopped(diagnostics.pid)
    }

    @Test
    fun `filesystem capability advertisement is frozen to each workflow allowlist`() {
        val readFixture = fixture()
        val readRequest = readFixture.request.withPolicy(
            AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "src/module.c"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
            ),
        )
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-read-only").execute(readRequest).stopReason)

        val writeFixture = fixture()
        val writeRequest = writeFixture.request.withPolicy(
            AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("project", "src/module.c"),
                        setOf(AgentOperation.WRITE_FILE),
                    ),
                ),
            ),
        )
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-write-only").execute(writeRequest).stopReason)

        val disabledFixture = fixture()
        val disabledRequest = disabledFixture.request.withPolicy(AgentAccessPolicy(emptyList()))
        assertEquals(AgentStopReason.NO_CHANGES, harness("fs-cap-none").execute(disabledRequest).stopReason)
    }

    @Test
    fun `filesystem containment denial crosses the official JSON-RPC boundary without path disclosure`() {
        val fixture = fixture()
        val harness = harness("fs-denied-outside")

        val result = harness.execute(fixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, result.stopReason)
        assertEquals("old source\n", fixture.source.readText())
        val decision = harness.latestFilesystemAudit().single()
        assertEquals("fixture-session", decision.sessionId)
        assertEquals("fs/read_text_file", decision.method)
        assertEquals(AcpFilesystemAuditOutcome.DENIED, decision.outcome)
        assertEquals(AcpFilesystemAuditReason.OUTSIDE_WORKSPACE, decision.reason)
        assertNull(decision.policyPath)
        assertFalse(decision.toString().contains(fixture.workspace.parent.toString()))
    }

    @Test
    fun `durable session reload uses the advertised stable v1 method across fresh processes`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        withDurableSessionFailureContext(DurableSessionPhase.NEW) {
            harness("session-persistence", sentinel = "expect-new").executeReceipt(request).requireResult()
        }
        val restored = withDurableSessionFailureContext(DurableSessionPhase.LOAD) {
            harness("session-persistence", sentinel = "expect-load").executeReceipt(request).requireResult()
        }
        assertTrue(restored.summary.orEmpty().contains("session/load"))
        assertEquals("fixture-session", restored.session?.resumeReference)
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals(2, journal.completedTurns)
            assertEquals("load-advertised-completed-session", journal.decision)
        }
        assertEquals("old source\n", fixture.source.readText())
    }

    @Test
    fun `agent without load records fresh session fallback instead of conversation restoration`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        repeat(2) { harness("session-persistence-no-load", sentinel = "expect-new").executeReceipt(request).requireResult() }
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals(2, journal.completedTurns)
            assertEquals("new-load-unsupported-project-evidence", journal.decision)
        }
    }

    @Test
    fun `failed load is retained and explicit new-session policy is required before retry`() {
        val fixture = fixture(wallMillis = 15_000, idleMillis = 3_000)
        val continuation = continuation(fixture)
        val request = fixture.request.withContinuation(continuation)
        harness("session-persistence-load-fails", sentinel = "expect-new").executeReceipt(request).requireResult()
        val failure = harness("session-persistence-load-fails", sentinel = "expect-load").executeReceipt(request)
        assertIs<AgentExecutionOutcome.Failed>(failure.outcome)
        val exception = assertFailsWith<AgentExecutionException> { failure.requireResult() }
        assertTrue(generateSequence<Throwable>(exception) { it.cause }.any { it is decompengine.agent.AgentSessionRecoveryException })
        decompengine.agent.AgentSessionJournal.open(continuation).use { journal ->
            assertEquals("load-failed-no-implicit-fallback", journal.decision)
            assertEquals(1, journal.completedTurns)
        }
        val recreated = decompengine.agent.AgentSessionContinuation(
            continuation.directory, continuation.workflowSha256, continuation.taskId,
            continuation.workspaceFiles, policy = decompengine.agent.AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE,
        )
        harness("session-persistence-load-fails", sentinel = "expect-new")
            .executeReceipt(request.withContinuation(recreated)).requireResult()
        decompengine.agent.AgentSessionJournal.open(recreated).use { journal ->
            assertEquals("new-explicit-project-evidence", journal.decision)
            assertEquals(2, journal.completedTurns)
        }
    }

    private fun continuation(fixture: Fixture) = decompengine.agent.AgentSessionContinuation(
        createTempDirectory("acp-durable-session-"), "a".repeat(64), "module",
        mapOf(AgentWorkspacePath("project", "src/module.c") to sha256(Files.readAllBytes(fixture.source))),
    )

    private fun AgentExecutionRequest.withContinuation(continuation: decompengine.agent.AgentSessionContinuation) =
        AgentExecutionRequest(objective, workspaceRoots, contextInputs, accessPolicy, limits, cancellation, continuation)

    private data class Fixture(
        val workspace: Path,
        val source: Path,
        val forbiddenCanary: Path,
        val request: AgentExecutionRequest,
    )

    private fun capturedRepairRequest(root: AgentWorkspaceRoot): AgentExecutionRequest =
        AgentExecutionRequest(
            objective = "edit the fixture",
            workspaceRoots = listOf(root),
            contextInputs = listOf(AgentContextInput("compiler", "compiler evidence")),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath(root.id, "src/module.c"),
                        setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                    ),
                ),
            ),
            limits = AgentExecutionLimits(
                wallClockTimeout = Duration.ofSeconds(5),
                idleTimeout = Duration.ofSeconds(1),
                maxTurns = 1,
                maxToolCalls = 4,
                maxOutputBytes = 128L * 1024,
            ),
        )

    private enum class DurableSessionPhase(val label: String) {
        NEW("durable-session-new"), LOAD("durable-session-load"),
    }

    // Same operation exactly once. Rendering failure must leave the original typed failure intact.
    private fun <T> withDurableSessionFailureContext(phase: DurableSessionPhase, operation: () -> T): T = try {
        operation()
    } catch (failure: AgentExecutionException) {
        val context = try {
            sessionPreferencePhaseFailureContext(phase.label, failure,
                failure.receipt?.providerEvidence as? AcpInvocationEvidenceSnapshot)
        } catch (_: Throwable) {
            throw failure
        }
        throw AssertionError(context, failure)
    }

    // Failure-only context: fixed labels/sites and an existing closed scalar mount witness.
    // Stack/suppressed accessors snapshot arrays; inspected entries and rendered output are bounded.
    private fun sessionPreferencePhaseFailureContext(
        label: String,
        failure: AgentExecutionException,
        invocation: AcpInvocationEvidenceSnapshot?,
    ): String = buildString {
        append(label)
        append(" [phase=").append(invocation?.phaseReached?.name ?: "missing")
        append(";kind=").append(failure.failure.kind.name)
        append(";cleanup=").append(invocation?.cleanupDisposition?.name ?: "missing")
        val witness = Regex("mount-event-v1 phase=(CHECKPOINT|CONTROL_ADMISSION|REFRESH) " +
            "generation=(NOT_EVALUATED|MISMATCH_ALREADY_OBSERVED) outcome=(EVENT|INVALID_DESCRIPTOR|SYSCALL_ERROR) " +
            "rc=(NA|-?[0-9]{1,10}) revents=(NA|[0-9]{1,5}) errno=(NA|-?[0-9]{1,10})")
        val admission = Regex("mount-admission-v1 stage=(CONSTRUCTING|ADMITTED) " +
            "initialMounts=[0-9]{1,10} initialControls=[0-9]{1,10} owner=(true|false) initialFast=(true|false)")
        val pending = java.util.ArrayDeque<Throwable>()
        val seen = ArrayList<Throwable>(8)
        pending.add(failure)
        failure.receipt?.failureCause?.let { pending.add(it) }
        var emitted = 0
        while (pending.isNotEmpty() && seen.size < 8) {
            val observed = pending.removeFirst()
            if (seen.any { it === observed }) continue
            val depth = seen.size
            seen.add(observed)
            val category = when (observed) {
                is java.io.IOException -> "IOException"
                is java.util.concurrent.CancellationException -> "CancellationException"
                is IllegalArgumentException -> "IllegalArgumentException"
                is IllegalStateException -> "IllegalStateException"
                is SecurityException -> "SecurityException"
                is java.util.concurrent.TimeoutException -> "TimeoutException"
                is InterruptedException -> "InterruptedException"
                is ExecutionException -> "ExecutionException"
                is AssertionError -> "AssertionError"
                is Error -> "Error"
                is RuntimeException -> "RuntimeException"
                is Exception -> "Exception"
                else -> "Throwable"
            }
            append(";cause[").append(depth).append("]=").append(category)
            if (emitted < 64) {
                val frames = observed.stackTrace
                var index = 0
                while (index < minOf(frames.size, 64) && emitted < 64) {
                    val frame = frames[index++]
                    if (frame.className.startsWith("decompengine.")) {
                        val component = when (frame.fileName) {
                            "AcpAgentHarness.kt" -> "Harness"
                            "LinuxBubblewrapBoundary.kt" -> "Boundary"
                            "LinuxFilesystemSyscalls.kt" -> "Syscalls"
                            else -> "Other"
                        }
                        append(',').append(component).append(':').append(frame.lineNumber)
                        emitted++
                    }
                }
            }
            if (observed.javaClass.name == "decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic") {
                observed.message?.takeIf { it.length <= 512 && witness.matches(it) }?.let {
                    append(";witness=").append(it)
                    val admissionRecord = try {
                        (observed.javaClass.getDeclaredField("admissionContext").apply { isAccessible = true }.get(observed) as? String)
                            ?.takeIf { value -> value.length <= 256 && admission.matches(value) }
                    } catch (_: Throwable) { null }
                    if (admissionRecord != null) append(";admission=").append(admissionRecord)
                }
            }
            observed.cause?.let { if (pending.size < 16) pending.add(it) }
            observed.suppressed.take(2).forEach { if (pending.size < 16) pending.add(it) }
        }
        append(']')
    }.take(4096)

    private fun fixture(
        idleMillis: Long = 1_000,
        includeReadyPath: Boolean = false,
        wallMillis: Long = 5_000,
        maximumOutputBytes: Long = 128 * 1024,
        genericContract: Boolean = false,
    ): Fixture {
        val workspace = createTempDirectory("acp-harness-").toAbsolutePath().normalize()
        val sourceRelativePath = if (genericContract) "contract/artifact.txt" else "src/module.c"
        val source = workspace.resolve(sourceRelativePath)
        source.parent.createDirectories()
        source.writeText(if (genericContract) "original artifact\n" else "old source\n")
        val forbiddenCanary = workspace.resolve("forbidden-canary.txt")
        forbiddenCanary.writeText(FORBIDDEN_CANARY_CONTENT)
        val rules = mutableListOf(
            AgentPathRule(
                AgentWorkspacePath("project", sourceRelativePath),
                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
            ),
        )
        if (includeReadyPath) {
            rules += AgentPathRule(
                AgentWorkspacePath("project", "ready"),
                setOf(AgentOperation.CREATE_FILE, AgentOperation.WRITE_FILE),
            )
        }
        return Fixture(
            workspace,
            source,
            forbiddenCanary,
            AgentExecutionRequest(
                objective = if (genericContract) "exercise the protocol fixture" else "edit the fixture",
                workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
                contextInputs = listOf(
                    if (genericContract) {
                        decompengine.agent.AgentContextInput("contract", "protocol evidence")
                    } else {
                        decompengine.agent.AgentContextInput("compiler", "compiler evidence")
                    },
                ),
                accessPolicy = AgentAccessPolicy(rules),
                limits = AgentExecutionLimits(
                    wallClockTimeout = Duration.ofMillis(wallMillis),
                    idleTimeout = Duration.ofMillis(idleMillis),
                    maxTurns = 1,
                    maxToolCalls = 4,
                    maxOutputBytes = maximumOutputBytes,
                ),
            ),
        )
    }

    private fun AgentExecutionRequest.withCancellation(source: AgentCancellationSource): AgentExecutionRequest =
        withCancellation(source.cancellation)

    private fun AgentExecutionRequest.withCancellation(
        cancellation: AgentCancellation,
    ): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            limits,
            cancellation,
        )

    private fun AgentExecutionRequest.withWallClockTimeout(timeout: Duration): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            AgentExecutionLimits(
                wallClockTimeout = timeout,
                idleTimeout = limits.idleTimeout,
                maxTurns = limits.maxTurns,
                maxToolCalls = limits.maxToolCalls,
                maxOutputBytes = limits.maxOutputBytes,
                maxInputTokens = limits.maxInputTokens,
                maxOutputTokens = limits.maxOutputTokens,
            ),
            cancellation,
        )

    private fun AgentExecutionRequest.withTokenLimits(input: Long?, output: Long?): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            accessPolicy,
            AgentExecutionLimits(
                wallClockTimeout = limits.wallClockTimeout,
                idleTimeout = limits.idleTimeout,
                maxTurns = limits.maxTurns,
                maxToolCalls = limits.maxToolCalls,
                maxOutputBytes = limits.maxOutputBytes,
                maxInputTokens = input,
                maxOutputTokens = output,
            ),
            cancellation,
        )

    private fun AgentExecutionRequest.withPolicy(policy: AgentAccessPolicy): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs,
            policy,
            limits,
            cancellation,
        )

    private fun AgentExecutionRequest.withContextMarker(marker: String): AgentExecutionRequest =
        AgentExecutionRequest(
            objective,
            workspaceRoots,
            contextInputs + AgentContextInput("turn-marker", marker),
            accessPolicy,
            limits,
            cancellation,
        )

    private fun expectedWirePromptSha256(request: AgentExecutionRequest): String = sha256(
        buildString {
            appendLine(request.objective)
            if (request.contextInputs.isNotEmpty()) {
                appendLine()
                appendLine("Context inputs (immutable):")
                request.contextInputs.forEach { context ->
                    append("--- ").append(context.id).append(" [").append(context.mediaType).append(']')
                    context.description?.let { append(" — ").append(it) }
                    appendLine()
                    appendLine(context.content)
                }
            }
        }.toByteArray(),
    )

    /** Acquire trusted fixture input before constructing a harness or starting protocol work. */
    private fun acquireFixtureRuntimeManifest(calculate: () -> String): String {
        var attempt = 1
        while (true) {
            try {
                return calculate()
            } catch (failure: java.io.IOException) {
                if (attempt == 3 || failure.message != "host mounts changed during runtime manifest") throw failure
                attempt++
            }
        }
    }

    private fun harness(
        mode: String,
        sentinel: String = "literal-argv",
        ready: Path? = null,
        requiredCapabilities: Set<AcpRequiredAgentCapability> = emptySet(),
        timeouts: AcpLifecycleTimeouts = timeouts(),
        maximumFrameBytes: Int = 64 * 1024,
        maximumProtocolFrames: Int = DEFAULT_MAXIMUM_ACP_PROTOCOL_FRAMES,
        terminalPolicy: AcpTerminalExecutionPolicy? = null,
        sessionPreferences: AcpSessionPreferences = AcpSessionPreferences(),
    ): AcpAgentHarness {
        requireLiveSandboxHost()
        val script = Path.of(requireNotNull(javaClass.getResource("/acp/fake_acp_v1_agent.py")).toURI())
        val arguments = mutableListOf("-S", AGENT_SCRIPT_DESTINATION.toString(), mode, sentinel)
        ready?.let { arguments += it.toString() }
        return AcpAgentHarness(
            AcpProcessConfiguration(
                executable = PYTHON,
                arguments = arguments,
                requiredAgentCapabilities = requiredCapabilities,
                timeouts = timeouts,
                maximumFrameBytes = maximumFrameBytes,
                maximumProtocolFrames = maximumProtocolFrames,
                maximumStderrBytes = 64 * 1024,
                implementationId = "scripted-acp-v1",
                sandboxBoundary = liveSandboxConfiguration(
                    listOf(
                        AcpSandboxReadOnlyMount(
                            script,
                            AGENT_SCRIPT_DESTINATION,
                            acquireFixtureRuntimeManifest { calculateAcpRuntimeManifestSha256(script) },
                        ),
                    ),
                ),
                terminalPolicy = terminalPolicy,
                sessionPreferences = sessionPreferences,
            ),
        ).bindFactoryProvenance(
            AcpHarnessProvenance(
                harness = "acp",
                implementationId = "scripted-acp-v1",
                agentExecutionContractVersion = decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION,
                acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
                configurationSha256 = "0".repeat(64),
                deprecated = false,
            ),
        )
    }

    private fun timeouts(
        startup: Long = 1_000,
        request: Long = 5_000,
        shutdown: Long = 600,
    ): AcpLifecycleTimeouts = AcpLifecycleTimeouts(
        startup = Duration.ofMillis(startup),
        request = Duration.ofMillis(request),
        cancellationGrace = Duration.ofMillis(300),
        transportDrainGrace = Duration.ofMillis(80),
        shutdown = Duration.ofMillis(shutdown),
    )

    private fun missingSandboxConfiguration(): AcpLinuxSandboxConfiguration =
        AcpLinuxSandboxConfiguration(
            bubblewrapExecutable = Path.of("/definitely-absent/decomp-bwrap"),
            resourceLimiterExecutable = Path.of("/definitely-absent/decomp-prlimit"),
            scopeSupervisorExecutable = Path.of("/definitely-absent/decomp-systemd-run"),
            scopeInspectorExecutable = Path.of("/definitely-absent/decomp-systemctl"),
            environmentFdOpenerExecutable = Path.of("/definitely-absent/decomp-bash"),
            sandboxGateHelperExecutable = Path.of("/definitely-absent/decomp-gate-helper"),
            launcherRuntimeMounts = emptyList(),
            agentRuntimeMounts = emptyList(),
            systemdUserRuntimeDirectory = Path.of("/definitely-absent/decomp-runtime"),
            expectedBubblewrapSha256 = "0".repeat(64),
            expectedResourceLimiterSha256 = "0".repeat(64),
            expectedScopeSupervisorSha256 = "0".repeat(64),
            expectedScopeInspectorSha256 = "0".repeat(64),
            expectedEnvironmentFdOpenerSha256 = "0".repeat(64),
            expectedSandboxGateHelperSha256 = "0".repeat(64),
            expectedSandboxGateHelperManifestSha256 = "0".repeat(64),
        )

    private fun liveSandboxConfiguration(
        agentRuntimeMounts: Collection<AcpSandboxReadOnlyMount>,
    ): AcpLinuxSandboxConfiguration = AcpLinuxSandboxConfiguration(
        bubblewrapExecutable = BWRAP,
        resourceLimiterExecutable = PRLIMIT,
        scopeSupervisorExecutable = SYSTEMD_RUN,
        scopeInspectorExecutable = SYSTEMCTL,
        environmentFdOpenerExecutable = BASH,
        sandboxGateHelperExecutable = GATE_HELPER,
        // Protected dynamic-loader/runtime destinations are immutable boundary closure, never
        // request-selected terminal mounts. They are pinned once and evidenced for every launch.
        launcherRuntimeMounts = PYTHON_RUNTIME_MOUNTS,
        agentRuntimeMounts = agentRuntimeMounts,
        systemdUserRuntimeDirectory = USER_RUNTIME,
        agentResourceLimits = AcpSandboxResourceLimits(
            maximumProcesses = 16,
            maximumOpenFiles = 128,
            maximumFileBytes = 64L * 1024 * 1024,
            maximumAddressSpaceBytes = 512L * 1024 * 1024,
            maximumCpuSeconds = 20,
        ),
        expectedBubblewrapSha256 = sha256(BWRAP),
        expectedResourceLimiterSha256 = sha256(PRLIMIT),
        expectedScopeSupervisorSha256 = sha256(SYSTEMD_RUN),
        expectedScopeInspectorSha256 = sha256(SYSTEMCTL),
        expectedEnvironmentFdOpenerSha256 = sha256(BASH),
        expectedSandboxGateHelperSha256 = sha256(GATE_HELPER),
        expectedSandboxGateHelperManifestSha256 = acquireFixtureRuntimeManifest { calculateAcpRuntimeManifestSha256(GATE_HELPER) },
    )

    private fun requireLiveSandboxHost() {
        AcpLiveContractHost.requireCapability(
            PYTHON_RUNTIME.isSuccess,
            message = {
                "system Python runtime discovery failed: " +
                    (PYTHON_RUNTIME.exceptionOrNull()?.message ?: "unknown failure")
            },
        )
        val missing = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, PYTHON, ECHO, SLEEP, CC)
            .filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(
            missing.isEmpty(),
            message = { "live ACP harness sandbox tools are unavailable: $missing" },
        )
        AcpLiveContractHost.requireCapability(
            Files.exists(USER_RUNTIME.resolve("bus")),
            message = { "systemd user bus is unavailable" },
        )
        AcpLiveContractHost.requireCapability(
            Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")),
            message = { "cgroup v2 is unavailable" },
        )
        AcpLiveContractHost.requireCapability(
            Files.isExecutable(GATE_HELPER),
            message = { "static ACP gate helper could not be built" },
        )
    }

    private fun javap(type: Class<*>): String {
        val executable = Path.of(System.getProperty("java.home"), "bin", "javap")
        val classPath = Path.of(requireNotNull(type.protectionDomain.codeSource).location.toURI()).toString()
        val process = ProcessBuilder(
            executable.toString(),
            "-p",
            "-classpath",
            classPath,
            type.name,
        ).redirectErrorStream(true).start()
        val exited = process.waitFor(10, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(3, TimeUnit.SECONDS)
        }
        val output = process.inputStream.readAllBytes().toString(Charsets.UTF_8)
        assertTrue(exited, "javap timed out")
        assertEquals(0, process.exitValue(), output)
        return output
    }

    private fun isForbiddenExecutionSeamType(type: Class<*>): Boolean =
        listOf("Boundary", "Launcher", "TestMode").any(type.name::contains)

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun assertBoundedCleanProtocolFailure(
        fixture: Fixture,
        harness: AcpAgentHarness,
        maximumWallMillis: Long,
    ): AgentExecutionException {
        val executor = Executors.newSingleThreadExecutor()
        val events = mutableListOf<AgentExecutionEvent>()
        val startedAt = System.nanoTime()
        val execution = executor.submit<AgentExecutionException> {
            assertFailsWith { harness.execute(fixture.request, events::add) }
        }
        val failure = try {
            execution.get(maximumWallMillis, TimeUnit.MILLISECONDS)
        } catch (wrapped: ExecutionException) {
            throw wrapped.cause ?: wrapped
        } finally {
            execution.cancel(true)
            executor.shutdownNow()
        }
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
        assertTrue(
            elapsedMillis <= maximumWallMillis + 250,
            "protocol failure exceeded its bounded wall time: $elapsedMillis ms",
        )
        assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind)
        assertCleanTermination(
            harness = harness,
            context = "protocol failure",
            fixture = fixture,
            failure = failure,
            events = events,
        )
        return failure
    }

    private fun executeExpectingCleanFailure(
        harness: AcpAgentHarness,
        request: AgentExecutionRequest,
        context: String,
        fixture: Fixture? = null,
        forbiddenCanary: Path? = fixture?.forbiddenCanary,
    ): AgentExecutionException {
        val events = mutableListOf<AgentExecutionEvent>()
        val failure = assertFailsWith<AgentExecutionException>(context) {
            harness.execute(request, events::add)
        }
        val receipt = assertNotNull(failure.receipt, "$context receipt")
        assertEquals(AgentExecutionRequestBinding.capture(request), receipt.requestBinding, context)
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome, context)
        assertCleanTermination(
            harness = harness,
            context = context,
            fixture = fixture,
            forbiddenCanary = forbiddenCanary,
            failure = failure,
            events = events,
        )
        return failure
    }

    /** Existing receipt metadata only: no process queries, exception text, stderr or request content. */
    private fun cleanupFailureDiagnostic(
        invocation: AcpInvocationEvidenceSnapshot,
        failure: AgentExecutionException,
    ): String {
        val diagnostics = invocation.diagnostics
        val output = invocation.sandboxEvidence?.outerProcessOutput
        val allowedCauseTypes = setOf(
            "decompengine.agent.AgentExecutionException", "decompengine.acp.AcpCleanupProofFailure",
            "decompengine.acp.AcpOutputLimitFailure", "decompengine.acp.AcpPhaseTimeout",
            "decompengine.acp.AcpEofFailure", "decompengine.acp.AcpProcessExitedFailure",
            "java.io.IOException", "java.lang.IllegalStateException", "java.lang.InterruptedException",
            "java.util.concurrent.TimeoutException", "java.util.concurrent.ExecutionException",
        )
        val seen = ArrayList<Throwable>(6)
        val causeTypes = ArrayList<String>(6)
        var cause: Throwable? = failure
        while (cause != null && seen.size < 6 && seen.none { it === cause }) {
            val current = requireNotNull(cause)
            seen += current
            causeTypes += current.javaClass.name.takeIf { it in allowedCauseTypes } ?: "other"
            cause = current.cause
        }
        return ("cleanupDiagnostic phase=${invocation.phaseReached} cleanup=${invocation.cleanupDisposition} " +
            "failureKind=${failure.failure.kind} failedOutcome=${failure.receipt?.outcome is AgentExecutionOutcome.Failed} " +
            "audits=${invocation.completeness} negotiated=${invocation.negotiatedAgent != null} " +
            "wirePromptPresent=${invocation.wirePromptSha256 != null} sandbox=${invocation.sandboxEvidence != null} " +
            "completeEvidence=${invocation.completeExecutionEvidence != null} diagnostics=${diagnostics != null} " +
            "exitCode=${diagnostics?.exitCode} forcedTermination=${diagnostics?.forcedTermination} " +
            "rootTerminationRequested=${diagnostics?.rootTerminationRequested} " +
            "remainingPidCount=${diagnostics?.remainingProcessIds?.size} " +
            "remainingPidsFirst8=${diagnostics?.remainingProcessIds?.take(8)} " +
            "sandboxCleanupVerified=${diagnostics?.sandboxCleanupVerified} " +
            "producedBytes=${diagnostics?.producedOutputBytes} producedLimit=${diagnostics?.producedOutputLimitBytes} " +
            "outputLimitExceeded=${diagnostics?.outputLimitExceeded} stderrTruncated=${diagnostics?.stderrTruncated} " +
            "outerObserved=${output?.observedBytes} outerLimit=${output?.maximumBytes} outerExceeded=${output?.limitExceeded} " +
            "stdoutEof=unknown stderrEof=unknown shutdownBudget=unknown " +
            "causeClasses=$causeTypes causeTailUnknown=${cause != null} suppressedCauses=unknown").take(4096)
    }

    private fun assertCleanTermination(
        harness: AcpAgentHarness,
        context: String = "execution",
        fixture: Fixture? = null,
        forbiddenCanary: Path? = fixture?.forbiddenCanary,
        failure: AgentExecutionException? = null,
        events: Collection<AgentExecutionEvent> = emptyList(),
    ) {
        // Keep every assertion and process observation below unchanged; enrich only its message.
        @Suppress("NAME_SHADOWING")
        val context = if (failure == null) context else safeCleanupFailureContext(context, failure)
        val invocation = failure?.receipt?.providerEvidence as? AcpInvocationEvidenceSnapshot
        if (failure != null) {
            assertNotNull(invocation, "$context invocation evidence")
            val cleanupContext = if (invocation.cleanupDisposition != AcpExecutionCleanupDisposition.VERIFIED) {
                try {
                    "$context " + cleanupFailureDiagnostic(invocation, failure)
                } catch (_: Throwable) {
                    "diagnostic-unavailable"
                }
            } else context
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, invocation.cleanupDisposition, cleanupContext)
            assertNull(invocation.completeExecutionEvidence, "$context failed outcome archive evidence")
        }
        val diagnostics = assertNotNull(invocation?.diagnostics ?: harness.latestDiagnostics(), context)
        assertTrue(diagnostics.remainingProcessIds.isEmpty(), context)
        assertTrue(diagnostics.sandboxCleanupVerified, context)
        assertProcessStopped(diagnostics.pid)
        forbiddenCanary?.let { canary ->
            assertEquals(FORBIDDEN_CANARY_CONTENT, canary.readText(), context)
        }

        val evidence = assertNotNull(
            invocation?.sandboxEvidence ?: harness.latestSandboxEvidence(),
            "$context sandbox evidence",
        )
        val filesystemEvidence = invocation?.filesystemAudit ?: harness.latestFilesystemAudit()
        val permissionEvidence = invocation?.permissionAudit ?: harness.latestPermissionAudit()
        val terminalEvidence = invocation?.terminalAudit ?: harness.latestTerminalAudit()
        val secretSurfaces = linkedMapOf<String, Any?>(
            "failure message" to failure?.failure?.message,
            "failure details" to failure?.failure?.details,
            "diagnostics" to diagnostics,
            "events" to events,
            "filesystem audit" to filesystemEvidence,
            "permission audit" to permissionEvidence,
            "terminal audit" to terminalEvidence,
            "sandbox evidence" to listOf(
                evidence.provider,
                evidence.providerVersion,
                evidence.providerExecutableSha256,
                evidence.providerExecutableMode,
                evidence.resourceLimiterSha256,
                evidence.scopeSupervisorSha256,
                evidence.scopeInspectorSha256,
                evidence.environmentFdOpenerSha256,
                evidence.securityExecutables,
                evidence.outerAgentLimits,
                evidence.runtimeClosureLimits,
                evidence.cgroupV2PidsLimited,
                evidence.cgroupV2MemoryLimited,
                evidence.cgroupV2CpuLimited,
                evidence.networkIsolated,
                evidence.outerAgentContained,
                evidence.nestedUserNamespacesDisabled,
                evidence.newSession,
                evidence.dieWithParent,
                evidence.policySha256,
                evidence.terminalLimits,
                evidence.launches,
                evidence.authorities,
                evidence.terminalAudit,
                evidence.outerProcessOutput,
                evidence.evidenceSha256,
            ),
        )
        secretSurfaces.forEach { (label, surface) ->
            assertFalse(
                surface.toString().contains(PARENT_SECRET_CANARY),
                "$context retained parent-secret bytes in $label",
            )
        }
    }

    private fun assertProcessStopped(pid: Long) {
        assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false), "process $pid is still alive")
    }

    private companion object {
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val CC: Path = Path.of("/usr/bin/cc")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val PYTHON_RUNTIME: Result<AcpPythonRuntimeLayout> by lazy {
            runCatching { AcpLiveContractHost.discoverPythonRuntime() }
        }
        val PYTHON: Path get() = PYTHON_RUNTIME.getOrThrow().executable
        val ECHO: Path = Path.of("/usr/bin/echo")
        val SLEEP: Path = Path.of("/usr/bin/sleep")
        val AGENT_SCRIPT_DESTINATION: Path = Path.of("/decomp-acp-test/fake_acp_v1_agent.py")
        const val FORBIDDEN_CANARY_CONTENT: String = "forbidden canary must remain unchanged\n"
        val PARENT_SECRET_CANARY: String by lazy {
            requireNotNull(System.getenv("DECOMP_ACP_PARENT_SECRET_CANARY")) {
                "Gradle must inject the ACP parent-secret canary into the test process"
            }
        }
        val GATE_HELPER: Path by lazy(::productionAcpGateHelper)
        val PYTHON_RUNTIME_MOUNTS: List<AcpSandboxReadOnlyMount> by lazy {
            val runtime = PYTHON_RUNTIME.getOrThrow()
            runtime.nativeRuntimeMounts + runtime.stdlibMounts(
                listOf(
                    "encodings", "json", "re", "collections",
                    "_collections_abc.py", "abc.py", "codecs.py", "copyreg.py", "enum.py",
                    "functools.py", "keyword.py", "operator.py", "reprlib.py", "types.py", "zipimport.py",
                ),
            )
        }
    }
}

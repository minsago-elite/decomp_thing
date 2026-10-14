package decompengine.acp

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import java.util.IdentityHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Component controls for the real boundary; these do not qualify a factory or provider adapter. */
class AcpProviderGuardianBoundaryTest {
    @Test
    fun `default configuration has no guardian and remains provider disabled`() = withFixture { fixture ->
        assertNull(AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
        assertNull(AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
        assertSame(AcpProviderTransportPolicy.DISABLED, fixture.configuration.providerTransportPolicy)
        assertEquals(256, AcpSandboxResourceLimits().maximumOpenFiles)
    }

    @Test
    fun `descriptor binds exact executable manifests argv configuration and private state identity`() = withFixture { fixture ->
        val descriptor = fixture.bind()
        assertEquals(CONFIGURATION_SHA, descriptor.factoryConfigurationSha256)
        assertEquals(fixture.artifact.executableSha256, descriptor.guardianExecutableSha256)
        assertEquals(digest(fixture.child), descriptor.childExecutableSha256)
        assertEquals(digest(fixture.codex), descriptor.codexExecutableSha256)
        assertEquals(fixture.artifact.runtimeManifestSha256, descriptor.guardianManifestSha256)
        assertEquals(calculateAcpRuntimeManifestSha256(fixture.child), descriptor.childManifestSha256)
        assertEquals(calculateAcpRuntimeManifestSha256(fixture.codex), descriptor.codexManifestSha256)
        assertEquals(listOf("/decomp-acp-internal/provider-guardian", "--state-root", ACP_PROVIDER_STATE_ROOT.toString(),
            "--codex-path", fixture.codex.toString(), "--", fixture.child.toString(), "idle"), descriptor.command)
        assertEquals(orderedDigest(descriptor.command), descriptor.orderedArgumentsSha256)
        assertEquals(digest(ACP_PROVIDER_STATE_ROOT.toString().toByteArray()), descriptor.privateStateRootSha256)
        assertEquals(setOf(descriptor.guardianMount.destination, fixture.child, fixture.codex),
            descriptor.runtimeMounts.map { it.destination }.toSet())
        assertSame(descriptor, AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
        assertFailsWith<IllegalStateException> { AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration) }
        val launch = fixture.launch(descriptor)
        descriptor.requireLaunchMatches(fixture.sandbox, launch)
        descriptor.requireLaunchAuthority(fixture.sandbox, launch)
        assertFailsWith<IllegalStateException> { descriptor.requireLaunchAuthority(fixture.sandbox, launch) }
    }

    @Test
    fun `forged replayed wrong receiver and wrong purpose permits cannot bind a guardian`() = withFixture { fixture ->
        val forged = forgedPermit()
        assertFailsWith<IllegalArgumentException> { fixture.bind(forged) }
        withOwnedPermit(Any()) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit) }
            assertFalse(registryContains(permit))
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit) }
        }
        withOwnedPermit(fixture.configuration, AcpProviderQualificationPurpose.PROCESS_CONFIGURATION) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit) }
            assertFalse(registryContains(permit))
        }
        withOwnedPermit(fixture.configuration) { permit ->
            fixture.bind(permit)
            assertFalse(registryContains(permit))
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit) }
        }
        assertNotNull(AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
    }

    @Test
    fun `descriptor JVM surface cannot expose mutable registries and copied construction grants no authority`() = withFixture { fixture ->
        val descriptor = fixture.bind()
        val surfaces = listOf(AcpProviderGuardianLaunchDescriptor::class.java,
            AcpProviderGuardianLaunchDescriptor.Companion::class.java) + AcpProviderGuardianLaunchDescriptor::class.java.declaredClasses.toList()
        surfaces.forEach { type ->
            assertTrue(type.methods.none { java.util.Map::class.java.isAssignableFrom(it.returnType) },
                "public JVM method exposes mutable descriptor authority on ${type.name}")
            assertTrue(type.fields.none { java.util.Map::class.java.isAssignableFrom(it.type) },
                "public JVM field exposes mutable descriptor authority on ${type.name}")
        }
        val constructor = AcpProviderGuardianLaunchDescriptor::class.java.constructors.singleOrNull {
            it.isSynthetic && it.parameterCount == 9
        } ?: error("expected Kotlin synthetic constructor control is absent")
        val copied = constructor.newInstance(fixture.configuration, descriptor.guardianMount, descriptor.childMount,
            descriptor.codexMount, descriptor.factoryConfigurationSha256, descriptor.guardianExecutableSha256,
            descriptor.childExecutableSha256, descriptor.codexExecutableSha256, null) as AcpProviderGuardianLaunchDescriptor
        assertFailsWith<IllegalArgumentException> { copied.requireLaunchMatches(fixture.sandbox, fixture.launch(copied)) }
        assertFailsWith<IllegalStateException> { copied.requireLaunchAuthority(fixture.sandbox, fixture.launch(copied)) }
        assertSame(descriptor, AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
    }

    @Test
    fun `launch refuses changed owner resource tuple mount argv state root purpose or stdin`() = withFixture { fixture ->
        val descriptor = fixture.bind()
        val launch = fixture.launch(descriptor)
        val altered: List<() -> AcpSandboxLaunch> = listOf(
            { launch.copy(command = launch.command + "extra") },
            { launch.copy(readOnlyMounts = launch.readOnlyMounts.dropLast(1)) },
            { launch.copy(readOnlyMounts = launch.readOnlyMounts.reversed()) },
            { launch.copy(emptyDirectories = emptyList()) },
            { launch.copy(emptyDirectories = listOf(ACP_PROVIDER_STATE_ROOT, ACP_PROVIDER_STATE_ROOT.resolve("extra"))) },
            { launch.copy(emptyDirectories = listOf(Path.of("/tmp/other-provider-state"))) },
            { launch.copy(purpose = AcpSandboxLaunchPurpose.TERMINAL) },
            { launch.copy(stdinDisposition = AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC) },
            { launch.copy(resourceLimits = LIMITS.copy(maximumProcesses = 31)) },
            { launch.copy(resourceLimits = LIMITS.copy(maximumOpenFiles = 127)) },
            { launch.copy(resourceLimits = LIMITS.copy(maximumAddressSpaceBytes = LIMITS.maximumAddressSpaceBytes - 1)) },
            { launch.copy(guardianDescriptor = null) },
        )
        altered.forEach { candidate ->
            assertFailsWith<IllegalArgumentException> { descriptor.requireLaunchMatches(fixture.sandbox, candidate()) }
        }
        assertFailsWith<IllegalArgumentException> { descriptor.requireLaunchMatches(configuration(fixture.codexMount), launch) }
        descriptor.requireLaunchMatches(fixture.sandbox, launch)
        assertSame(descriptor, AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
    }

    @Test
    fun `binding refuses a changed guardian hash malformed configuration hash or stale executable manifest`() = withFixture { fixture ->
        withOwnedPermit(fixture.configuration) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit, guardianSha = "0".repeat(64)) }
        }
        withOwnedPermit(fixture.configuration) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit, configurationSha = "NOT-A-DIGEST") }
        }
        Files.write(fixture.child, Files.readAllBytes(fixture.child) + 1.toByte())
        withOwnedPermit(fixture.configuration) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit) }
        }
        assertNull(AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
    }

    @Test
    fun `binding requires the exact resource profile and a declared distinct Codex mount`() = withFixture { fixture ->
        listOf(LIMITS.copy(maximumProcesses = 31), LIMITS.copy(maximumOpenFiles = 256),
            LIMITS.copy(maximumAddressSpaceBytes = LIMITS.maximumAddressSpaceBytes * 2)).forEach { limits ->
            val config = fixture.processConfiguration(configuration(fixture.codexMount, limits))
            withOwnedPermit(config) { permit ->
                assertFailsWith<IllegalArgumentException> { fixture.bind(permit, config) }
            }
        }
        val undeclared = fixture.processConfiguration(configuration(null))
        withOwnedPermit(undeclared) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit, undeclared) }
        }
        val sameAsChild = AcpSandboxReadOnlyMount(fixture.child, fixture.child,
            calculateAcpRuntimeManifestSha256(fixture.child))
        val same = fixture.processConfiguration(configuration(sameAsChild))
        withOwnedPermit(same) { permit ->
            assertFailsWith<IllegalArgumentException> { fixture.bind(permit, same, codexMount = sameAsChild) }
        }
    }

    @Test
    fun `production gate launches exact guardian topology and authenticates native cleanup after natural child exit`() =
        withLiveFixture("echo") { fixture, boundary, sandboxed, running ->
            val input = running.stdout()
            assertFailsWith<IllegalStateException> { running.stdout() }
            assertFailsWith<IllegalStateException> { input.close() }
            val setup = channelSetup()
            val authenticator = AcpProviderCleanupAuthenticator.fromSetup(setup)
            running.write(AcpProviderFrameTag.CHANNEL_OPEN, setup)
            setup.fill(0)
            assertEquals("ECHO_READY\n", running.readAcp(input))
            val sample = observeQuiescentPeak(fixture, sandboxed)
            running.write(AcpProviderFrameTag.ACP_BYTES, "guardian-boundary-echo\n".toByteArray())
            val echoed = ByteArrayOutputStream()
            var cleanup: AcpProviderCleanupReceipt? = null
            while (true) {
                val frame = running.read(input) ?: break
                when (frame.tag) {
                    AcpProviderFrameTag.ACP_BYTES -> echoed.write(frame.payload)
                    AcpProviderFrameTag.CHANNEL_CLEANUP -> {
                        assertNull(cleanup)
                        cleanup = frame.consumeCleanupPayload(authenticator, PROFILE.bounds.cleanupTimeout.toMillis())
                    }
                    else -> error("unexpected frame ${frame.tag}")
                }
            }
            input.close()
            assertFailsWith<IllegalStateException> { running.stdout() }
            running.assertNaturalEmptyStderr()
            running.assertRawOutputCount()
            val receipt = assertNotNull(cleanup)
            assertEquals("guardian-boundary-echo\n", echoed.toString(Charsets.UTF_8))
            assertEquals(AcpProviderCleanupCause.NORMAL, receipt.cause)
            assertEquals(AcpProviderChildExitKind.EXITED, receipt.childExitKind)
            assertEquals(0, receipt.childExitCode)
            assertEquals(0L, receipt.rawWaitStatus)
            assertTrue(receipt.nativeCleanupVerified, receipt.toString())
            assertFalse(receipt.sigtermSent)
            assertFalse(receipt.sigkillSent)
            assertBoundaryGone(sandboxed, sample)
            assertEquals(0, sandboxed.process.exitValue())
            val launch = boundary.evidence(null).launches.single()
            assertEquals(LIMITS, launch.resourceLimits)
            assertEquals(fixture.artifact.runtimeManifestSha256, launch.executableMount.configuredManifestSha256)
            assertEquals(128L, launch.effectiveRlimits.openFilesSoft)
            assertEquals(128L, launch.effectiveRlimits.openFilesHard)
            assertEquals(32L, launch.controllers.pidsMax)
            assertEquals(2_147_483_648L, launch.controllers.memoryMaxBytes)
            assertEquals(0L, launch.controllers.memorySwapMaxBytes)
            assertTrue(launch.controllers.memoryOomGroup)
            with(launch.effectiveRlimits) {
                // NPROC is a host-real-UID backstop; the exact per-sandbox task cap is pids.max.
                assertTrue(processesSoft >= LIMITS.maximumProcesses.toLong())
                assertEquals(processesSoft, processesHard)
                assertEquals(2_147_483_648L, addressSpaceSoft)
                assertEquals(2_147_483_648L, addressSpaceHard)
                assertEquals(LIMITS.maximumFileBytes, fileBytesSoft)
                assertEquals(LIMITS.maximumFileBytes, fileBytesHard)
                assertEquals(0L, coreBytesSoft)
                assertEquals(0L, coreBytesHard)
                assertEquals(LIMITS.maximumCpuSeconds.toLong(), cpuSecondsSoft)
                assertEquals(LIMITS.maximumCpuSeconds.toLong(), cpuSecondsHard)
            }
            println("GUARDIAN_BOUNDARY_RESOURCES limits=${launch.resourceLimits} controllers=${launch.controllers} rlimits=${launch.effectiveRlimits}")
        }

    @Test
    fun `guardian signal progresses while asynchronous buffered close waits for the real JDK writer monitor`() =
        withLiveFixture("idle") { fixture, _, sandboxed, running ->
            val input = running.stdout()
            val setup = channelSetup()
            val authenticator = AcpProviderCleanupAuthenticator.fromSetup(setup)
            running.write(AcpProviderFrameTag.CHANNEL_OPEN, setup)
            setup.fill(0)
            assertEquals("IDLE_READY\n", running.readAcp(input))
            val sample = observeQuiescentPeak(fixture, sandboxed)
            val acquired = CountDownLatch(1)
            val release = CountDownLatch(1)
            val writerDone = CompletableFuture<Unit>()
            val output = running.stdin()
            // This is the actual JDK process stream monitor. It is a controlled writer checkpoint,
            // not a claim that the kernel pipe is full or that close never flushes buffered bytes.
            Thread.ofVirtual().name("guardian-boundary-held-writer").start {
                try {
                    synchronized(output) {
                        running.write(AcpProviderFrameTag.ACP_BYTES, byteArrayOf(0x61))
                        acquired.countDown()
                        check(release.await(8, TimeUnit.SECONDS)) { "writer checkpoint release timed out" }
                    }
                    writerDone.complete(Unit)
                } catch (failure: Throwable) { writerDone.completeExceptionally(failure) }
            }
            try {
                assertTrue(acquired.await(2, TimeUnit.SECONDS), "writer did not reach its real-stream checkpoint")
                val close = running.beginInputClose()
                assertSame(close, running.beginInputClose())
                assertFalse(close.isDone, "buffered close unexpectedly bypassed the held writer monitor")
                val signal = running.signal()
                assertSame(signal, running.signal())
                assertEquals("DELIVERED", signal.get(2, TimeUnit.SECONDS).toString())
                assertFalse(close.isDone, "signal must not join the unfinished input close")
                var receipt: AcpProviderCleanupReceipt? = null
                while (true) {
                    val frame = running.read(input) ?: break
                    assertEquals(AcpProviderFrameTag.CHANNEL_CLEANUP, frame.tag)
                    assertNull(receipt)
                    receipt = frame.consumeCleanupPayload(authenticator, PROFILE.bounds.cleanupTimeout.toMillis())
                }
                input.close()
                running.assertNaturalEmptyStderr()
                running.assertRawOutputCount()
                val observed = assertNotNull(receipt)
                assertEquals(AcpProviderCleanupCause.GUARDIAN_SIGNAL, observed.cause)
                assertEquals(AcpProviderChildExitKind.SIGTERM, observed.childExitKind)
                assertEquals(15, observed.childSignal)
                assertEquals(15L, observed.rawWaitStatus)
                assertTrue(observed.sigtermSent)
                assertTrue(observed.nativeCleanupVerified, observed.toString())
                assertFalse(close.isDone, "cleanup receipt must remain independent of the held writer monitor")
                println("GUARDIAN_BOUNDARY_INPUT_CLOSE control=real-jdk-writer-monitor kernelFullPipeQualified=false noFlushQualified=false")
            } finally {
                release.countDown()
                writerDone.get(2, TimeUnit.SECONDS)
                running.beginInputClose().handle { _, _ -> Unit }.get(2, TimeUnit.SECONDS)
            }
            assertBoundaryGone(sandboxed, sample)
            assertEquals(130, sandboxed.process.exitValue())
        }

    @Test
    fun `guardian pure frame guards preserve accounting enforce session and redact refused input before cleanup`() =
        withLiveFixture("idle") { fixture, _, sandboxed, running ->
            val input = running.stdout()
            val authenticator = initializeIdleChannel(running, input)
            val sample = observeQuiescentPeak(fixture, sandboxed)
            val before = running.outputCount()
            running.outbound("""{"jsonrpc":"2.0","id":"private-init","method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{}}}""")
            running.inbound("""{"jsonrpc":"2.0","id":"private-init","result":{"protocolVersion":1,"agentCapabilities":{}}}""")
            running.outbound("""{"jsonrpc":"2.0","id":"private-session","method":"session/new","params":{"cwd":"/tmp","mcpServers":[]}}""")
            running.inbound("""{"jsonrpc":"2.0","id":"private-session","result":{"sessionId":"guarded-session"}}""")
            assertEquals("guarded-session", running.boundSession())
            val validNotification = """{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"guarded-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"ok"}}}}"""
            running.inbound(validNotification)
            val pending = """{"jsonrpc":"2.0","id":"private-pending","method":"session/prompt","params":{"sessionId":"guarded-session","prompt":[]}}"""
            running.outbound(pending)
            val outbound = assertFailsWith<AcpProtocolFailure> { running.outbound(pending) }
            assertEquals("guardian ACP outbound frame admission refused", outbound.message)
            assertNull(outbound.cause)
            val denied = listOf(
                """{"jsonrpc":"2.0","id":"private-init","result":{}}""",
                """{"jsonrpc":"2.0","id":"private-unknown","result":{}}""",
                validNotification.replace("guarded-session", "private-other-session"),
                """{"private":"private-malformed"}""",
            )
            denied.forEach { frame ->
                val failure = assertFailsWith<Exception> { running.inbound(frame) }
                assertEquals("AcpMalformedFrameFailure", failure.javaClass.simpleName)
                assertEquals("guardian ACP inbound frame admission refused", failure.message)
                assertNull(failure.cause)
            }
            assertEquals(before, running.outputCount(), "pure admission must not consume or produce pipe bytes")
            val latched = assertNotNull(running.failure())
            running.markClosing()
            assertSame(latched, running.failure())
            val lateInbound = assertFailsWith<AcpProtocolFailure> { running.inbound(validNotification) }
            val lateOutbound = assertFailsWith<AcpProtocolFailure> { running.outbound(pending) }
            listOf(lateInbound, lateOutbound).forEach {
                assertEquals("guardian ACP admission is revoked", it.message)
                assertNull(it.cause)
            }
            assertEquals(before, running.outputCount())
            assertFalse(running.guardianExited())
            assertEquals("DELIVERED", running.signal().get(2, TimeUnit.SECONDS).toString())
            val receipt = drainIdleReceipt(running, input, authenticator)
            assertTrue(receipt.nativeCleanupVerified)
            val completion = running.finishIo()
            assertEquals(AcpGuardianStderrObservation.EMPTY, completion.stderrObservation)
            assertTrue(completion.stdoutAccountingVerified)
            assertTrue(completion.diagnostics.stderr.isEmpty())
            assertFalse(completion.diagnostics.stderrTruncated)
            assertFalse(completion.diagnostics.forcedTermination)
            assertTrue(completion.diagnostics.rootTerminationRequested)
            assertFalse(completion.diagnostics.sandboxCleanupVerified, "I/O completion cannot manufacture boundary proof")
            assertEquals(running.outputCount(), completion.diagnostics.producedOutputBytes)
            assertSame(latched, running.failure(), "closing and successful I/O cleanup must retain the preexisting failure")
            assertFailsWith<IllegalStateException> { running.finishIo() }
            assertBoundaryGone(sandboxed, sample)
            assertTrue(running.guardianExited())
        }

    @Test
    fun `forced guardian pidfd kill is independent and remains forced with no native cleanup receipt`() =
        withLiveFixture("idle") { fixture, _, sandboxed, running ->
            val input = running.stdout()
            initializeIdleChannel(running, input)
            val sample = observeQuiescentPeak(fixture, sandboxed)
            running.markClosing()
            val acquired = CountDownLatch(1)
            val release = CountDownLatch(1)
            val writerDone = CompletableFuture<Unit>()
            val output = running.stdin()
            Thread.ofVirtual().name("guardian-boundary-kill-held-writer").start {
                try {
                    synchronized(output) {
                        running.write(AcpProviderFrameTag.ACP_BYTES, byteArrayOf(0x61))
                        acquired.countDown()
                        check(release.await(8, TimeUnit.SECONDS)) { "kill writer checkpoint release timed out" }
                    }
                    writerDone.complete(Unit)
                } catch (failure: Throwable) { writerDone.completeExceptionally(failure) }
            }
            try {
                assertTrue(acquired.await(2, TimeUnit.SECONDS))
                val close = running.beginInputClose()
                val killed = running.forceSignal()
                assertSame(killed, running.forceSignal())
                assertEquals("DELIVERED", killed.get(2, TimeUnit.SECONDS).toString())
                assertFalse(close.isDone, "forced pidfd signal must not wait for the writer monitor")
                assertNull(running.read(input), "SIGKILL cannot emit an authenticated native cleanup receipt")
                input.close()
                running.assertNaturalEmptyStderr()
                running.assertRawOutputCount()
                val completion = running.finishIo(forced = false)
                assertEquals(AcpGuardianStderrObservation.EMPTY, completion.stderrObservation)
                assertTrue(completion.stdoutAccountingVerified)
                assertTrue(completion.diagnostics.forcedTermination, "the private KILL latch must override a false caller argument")
                assertTrue(completion.diagnostics.rootTerminationRequested)
                assertFalse(completion.diagnostics.sandboxCleanupVerified)
                assertFalse(close.isDone, "I/O completion must not join the held buffered input close")
                println("GUARDIAN_BOUNDARY_FORCED_KILL nativeReceiptObserved=false nativeCleanupQualified=false callerForced=false diagnosticsForced=true")
            } finally {
                release.countDown()
                writerDone.get(2, TimeUnit.SECONDS)
                running.beginInputClose().handle { _, _ -> Unit }.get(2, TimeUnit.SECONDS)
            }
            assertBoundaryGone(sandboxed, sample)
            assertTrue(running.guardianExited())
        }

    @Test
    fun `legacy shutdown refuses guardian before work and missing accounted EOF remains unverified after late EOF`() =
        withLiveFixture("idle") { fixture, _, sandboxed, running ->
            val input = running.stdout()
            val authenticator = initializeIdleChannel(running, input)
            val sample = observeQuiescentPeak(fixture, sandboxed)
            val before = running.outputCount()
            val ownership = running.stdoutOwnership()
            assertFalse(running.closing())
            assertFalse(running.shutdownStarted())
            val refusal = assertFailsWith<IllegalStateException> { running.legacyShutdown() }
            assertEquals("guardian execution requires its upper-owned cleanup path", refusal.message)
            assertNull(refusal.cause)
            assertFalse(running.closing())
            assertFalse(running.shutdownStarted())
            assertEquals(ownership, running.stdoutOwnership())
            assertEquals(before, running.outputCount())
            running.markClosing()
            assertEquals("DELIVERED", running.signal().get(2, TimeUnit.SECONDS).toString())
            val receipt = drainIdleReceipt(running, input, authenticator, observeEof = false)
            assertTrue(receipt.nativeCleanupVerified)
            running.assertNaturalEmptyStderr()
            val atReceipt = running.outputCount()
            val incomplete = running.finishIo()
            assertEquals(AcpGuardianStderrObservation.EMPTY, incomplete.stderrObservation)
            assertFalse(incomplete.stdoutAccountingVerified, "a receipt without the owner's EOF observation cannot certify stdout accounting")
            assertFalse(incomplete.diagnostics.sandboxCleanupVerified)
            assertEquals(ownership, running.stdoutOwnership(), "finalization must not steal or read the router's stream")
            assertEquals(atReceipt, running.outputCount())
            assertEquals("AcpOutputLimitFailure", assertNotNull(running.failure()).javaClass.simpleName)
            assertNull(running.read(input))
            input.close()
            running.assertRawOutputCount()
            assertFalse(incomplete.stdoutAccountingVerified, "late EOF must not rewrite the immutable first result")
            assertFailsWith<IllegalStateException> { running.finishIo() }
            assertBoundaryGone(sandboxed, sample)
            println("GUARDIAN_BOUNDARY_LATE_EOF firstStdoutAccountingVerified=false lateEofObserved=true finalizationRetryRefused=true")
        }

    @Test
    fun `guardian closing precedes exit callback publication and preserves prior failures idempotently`() =
        withLiveFixture("idle") { fixture, _, sandboxed, running ->
            val input = running.stdout()
            val authenticator = initializeIdleChannel(running, input)
            val sample = observeQuiescentPeak(fixture, sandboxed)

            // These memory-only Process controls exercise the private lower lifecycle. Their
            // streams never touch the native process; its sole real I/O owner remains running.
            val racingProcess = ClosingExitPublicationProcess()
            val racing = Running(sandboxed, racingProcess)
            racingProcess.publishOnNextLivenessProbe = true
            racing.markClosing()
            racingProcess.publishExit()
            assertTrue(racing.closing())
            assertNull(racing.failure(), "expected cleanup must publish closing before an exit callback can fail it")
            racing.markClosing()
            assertNull(racing.failure(), "repeated cleanup must not synthesize a new process-exit failure")
            racing.assertNaturalEmptyStderr()

            val priorProcess = ClosingExitPublicationProcess()
            val prior = Running(sandboxed, priorProcess)
            priorProcess.publishExit()
            val observedBeforeCleanup = assertNotNull(prior.failure())
            assertEquals("AcpProcessExitedFailure", observedBeforeCleanup.javaClass.simpleName)
            prior.markClosing()
            prior.markClosing()
            assertSame(observedBeforeCleanup, prior.failure(), "cleanup must retain an already published failure")
            prior.assertNaturalEmptyStderr()

            val rejectedProcess = ClosingExitPublicationProcess()
            val rejected = Running(null, rejectedProcess)
            assertFailsWith<IllegalStateException> { rejected.markClosing() }
            assertFalse(rejected.closing(), "owner rejection must not publish cleanup intent")
            assertNull(rejected.failure(), "owner rejection must not synthesize an exit observation")
            rejectedProcess.publishExit()
            assertEquals("AcpProcessExitedFailure", assertNotNull(rejected.failure()).javaClass.simpleName)
            rejected.assertNaturalEmptyStderr()

            running.markClosing()
            assertFalse(running.guardianExited(), "cleanup intent is not guardian exit evidence")
            assertFalse(sandboxed.boundaryCleanupFacts().finalMembershipZero,
                "cleanup intent is not final boundary membership evidence")
            assertEquals("DELIVERED", running.signal().get(2, TimeUnit.SECONDS).toString())
            assertTrue(drainIdleReceipt(running, input, authenticator).nativeCleanupVerified)
            input.close()
            running.assertNaturalEmptyStderr()
            assertBoundaryGone(sandboxed, sample)
        }

    /** Deterministic exit publication at the old isAlive-before-closing boundary; no native I/O. */
    private class ClosingExitPublicationProcess : Process() {
        private val exit = CompletableFuture<Process>()
        private var alive = true
        var publishOnNextLivenessProbe = false
        fun publishExit() { alive = false; exit.complete(this) }
        override fun isAlive(): Boolean {
            val sampledAlive = alive
            if (publishOnNextLivenessProbe) {
                publishOnNextLivenessProbe = false
                publishExit()
            }
            return sampledAlive
        }
        override fun onExit(): CompletableFuture<Process> = exit
        override fun exitValue(): Int { check(!alive); return 17 }
        override fun getInputStream(): InputStream = InputStream.nullInputStream()
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun getOutputStream(): OutputStream = OutputStream.nullOutputStream()
        override fun waitFor(): Int = exitValue()
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = !alive
        override fun destroy() = Unit
        override fun destroyForcibly(): Process = this
        override fun pid(): Long = Long.MAX_VALUE
        override fun toHandle(): ProcessHandle = throw UnsupportedOperationException("memory-only lifecycle control")
    }

    private fun initializeIdleChannel(running: Running, input: InputStream): AcpProviderCleanupAuthenticator {
        val setup = channelSetup()
        val authenticator = AcpProviderCleanupAuthenticator.fromSetup(setup)
        running.write(AcpProviderFrameTag.CHANNEL_OPEN, setup)
        setup.fill(0)
        assertEquals("IDLE_READY\n", running.readAcp(input))
        return authenticator
    }

    private fun drainIdleReceipt(running: Running, input: InputStream, authenticator: AcpProviderCleanupAuthenticator,
        observeEof: Boolean = true): AcpProviderCleanupReceipt {
        val frame = assertNotNull(running.read(input))
        assertEquals(AcpProviderFrameTag.CHANNEL_CLEANUP, frame.tag)
        val receipt = frame.consumeCleanupPayload(authenticator, PROFILE.bounds.cleanupTimeout.toMillis())
        if (observeEof) {
            assertNull(running.read(input))
            input.close()
            running.assertNaturalEmptyStderr()
            running.assertRawOutputCount()
        }
        return receipt
    }

    private data class Fixture(val root: Path, val child: Path, val codex: Path,
        val artifact: AcpProviderGuardianArtifact, val mode: String) {
        val codexMount = AcpSandboxReadOnlyMount(codex, codex, calculateAcpRuntimeManifestSha256(codex))
        val sandbox = configuration(codexMount)
        val configuration = processConfiguration(sandbox)
        fun processConfiguration(sandbox: AcpLinuxSandboxConfiguration) = AcpProcessConfiguration(
            executable = child, arguments = listOf(mode), sandboxBoundary = sandbox,
            expectedExecutableManifestSha256 = calculateAcpRuntimeManifestSha256(child),
        )
        fun bind(permit: AcpProviderQualificationPermit, config: AcpProcessConfiguration = configuration,
            guardianSha: String = artifact.executableSha256, configurationSha: String = CONFIGURATION_SHA,
            codexMount: AcpSandboxReadOnlyMount = this.codexMount): AcpProviderGuardianLaunchDescriptor =
            AcpProviderGuardianLaunchDescriptor.authenticateAndBind(config, artifact, guardianSha, codexMount, configurationSha, permit)
        fun bind(): AcpProviderGuardianLaunchDescriptor = withOwnedPermit(configuration) { bind(it) }
        fun launch(descriptor: AcpProviderGuardianLaunchDescriptor) = AcpSandboxLaunch(
            command = descriptor.command, environment = emptyMap(), workingDirectory = Path.of("/tmp"),
            resourceLimits = LIMITS, maximumWallDuration = Duration.ofSeconds(15),
            readOnlyMounts = descriptor.runtimeMounts, stagingRoots = emptyList(),
            purpose = AcpSandboxLaunchPurpose.OUTER_AGENT, emptyDirectories = listOf(ACP_PROVIDER_STATE_ROOT),
            guardianDescriptor = descriptor,
        )
    }

    /** Reflection uses the existing lower constructor; null ownership exercises fail-closed admission. */
    private class Running(sandboxed: AcpSandboxedProcess?, process: Process = requireNotNull(sandboxed).process) {
        private val type = Class.forName("decompengine.acp.RunningAcpProcess")
        private val instance = type.declaredConstructors.single().apply { isAccessible = true }.newInstance(
            process, sandboxed, AcpProcessContainment.LINUX_BUBBLEWRAP_CGROUP_V2,
            1024, 1024L * 1024, ProtocolActivity(),
        )
        private var rawFrameBytes = 0L
        fun assertNaturalEmptyStderr() {
            val finished = type.getDeclaredField("stderrDrainFinished").apply { isAccessible = true }.get(instance) as CompletableFuture<*>
            finished.get(2, TimeUnit.SECONDS)
            val natural = type.getDeclaredField("stderrNaturallyDrained").apply { isAccessible = true }.get(instance) as AtomicBoolean
            assertTrue(natural.get(), "guardian stderr owner did not observe natural EOF")
            val capture = type.getDeclaredField("stderrCapture").apply { isAccessible = true }.get(instance)
            val text = capture.javaClass.getDeclaredMethod("text").apply { isAccessible = true }.invoke(capture) as String
            assertTrue(text.isEmpty(), "guardian emitted stderr bytes")
            assertEquals(false, capture.javaClass.getDeclaredMethod("truncated").apply { isAccessible = true }.invoke(capture))
        }
        fun outputCount(): Long {
            val budget = type.getDeclaredField("producedOutput").apply { isAccessible = true }.get(instance)
            return budget.javaClass.getDeclaredMethod("observedBytes").apply { isAccessible = true }.invoke(budget) as Long
        }
        fun assertRawOutputCount() {
            assertEquals(rawFrameBytes, outputCount(), "all ACPP header and payload bytes must remain in the aggregate output budget")
        }
        private fun call(name: String, vararg arguments: Any?): Any? = try {
            type.declaredMethods.single { it.name == name && it.parameterCount == arguments.size }
                .apply { isAccessible = true }.invoke(instance, *arguments)
        } catch (failure: InvocationTargetException) { throw failure.targetException }
        private fun field(name: String): Any? = type.getDeclaredField(name).apply { isAccessible = true }.get(instance)
        fun inbound(frame: String) { call("validateGuardianInboundFrame", frame) }
        fun outbound(frame: String) { call("validateGuardianOutboundFrame", frame) }
        fun markClosing() { call("markGuardianClosing") }
        fun guardianExited() = call("guardianExited") as Boolean
        fun finishIo(forced: Boolean = false) = call("finishGuardianIo", Duration.ofSeconds(2), forced, false) as AcpGuardianIoCompletion
        fun legacyShutdown() { call("shutdown", null, null, Duration.ofSeconds(1), null) }
        fun closing() = (field("closing") as AtomicBoolean).get()
        fun shutdownStarted() = (field("shutdownStarted") as AtomicBoolean).get()
        fun stdoutOwnership() = field("stdoutOwnership").toString()
        fun failure() = (field("failure") as java.util.concurrent.atomic.AtomicReference<*>).get() as Throwable?
        fun boundSession() = (field("sessionId") as java.util.concurrent.atomic.AtomicReference<*>).get() as String?
        @Suppress("UNCHECKED_CAST")
        fun forceSignal() = call("requestGuardianForcedTermination") as CompletableFuture<Any>
        fun stdout() = call("claimGuardianStdout") as InputStream
        fun stdin() = call("guardianStdin") as OutputStream
        @Suppress("UNCHECKED_CAST")
        fun beginInputClose() = call("beginGuardianInputAbort") as CompletableFuture<Unit>
        @Suppress("UNCHECKED_CAST")
        fun signal() = call("requestGuardianTermination") as CompletableFuture<Any>
        fun write(tag: AcpProviderFrameTag, payload: ByteArray) {
            val output = stdin()
            AcpProviderBrokerProtocol.writeFrame(output, AcpProviderFrame(tag, 0, payload, AcpProviderProtocolVersion.V2),
                65536, AcpProviderFrameDirection.HOST_TO_GUARDIAN)
            output.flush()
        }
        fun read(input: InputStream): AcpProviderFrame? {
            val result = CompletableFuture<AcpProviderFrame?>()
            Thread.ofVirtual().name("guardian-boundary-frame-read").start {
                try { result.complete(AcpProviderBrokerProtocol.readFrame(input, 65536,
                    AcpProviderFrameDirection.GUARDIAN_TO_HOST, AcpProviderProtocolVersion.V2)) }
                catch (failure: Throwable) { result.completeExceptionally(failure) }
            }
            return result.get(6, TimeUnit.SECONDS).also { frame ->
                if (frame != null) rawFrameBytes += AcpProviderBrokerProtocol.HEADER_BYTES + frame.payloadSize
            }
        }
        fun readAcp(input: InputStream): String {
            val frame = assertNotNull(read(input))
            assertEquals(AcpProviderFrameTag.ACP_BYTES, frame.tag)
            return frame.payload.toString(Charsets.UTF_8)
        }
    }

    private fun withLiveFixture(mode: String, action: (Fixture, LinuxBubblewrapBoundary, AcpSandboxedProcess, Running) -> Unit) {
        requireLiveHost()
        withFixture(mode, compileChild = true) { fixture ->
            val descriptor = fixture.bind()
            assertSame(descriptor, AcpProviderGuardianLaunchDescriptor.claimForLaunch(fixture.configuration))
            LinuxBubblewrapBoundary.prepare(fixture.sandbox).use { boundary ->
                val sandboxed = boundary.launch(fixture.launch(descriptor), false) {}
                try { action(fixture, boundary, sandboxed, Running(sandboxed)) }
                finally {
                    if (sandboxed.process.isAlive) sandboxed.destroyForcibly()
                    sandboxed.awaitCleanup(Duration.ofSeconds(6))
                    sandboxed.process.inputStream.close()
                    sandboxed.process.errorStream.close()
                    sandboxed.process.outputStream.close()
                }
            }
        }
    }

    private fun observeQuiescentPeak(fixture: Fixture, sandboxed: AcpSandboxedProcess): Int {
        val identity = sandboxed.scopeIdentity
        // Both selected fixture modes create no process/thread after their READY marker. Read the
        // exact kernel cumulative leaf peak after that barrier, before allowing child exit/signal.
        val peak = Files.readString(identity.cgroupPath.resolve("pids.peak")).trim().toInt()
        val sampledAt = System.nanoTime()
        assertTrue(peak in 1..31, "actual production guardian topology must retain task headroom: $peak")
        val retained = sandboxed.boundaryCleanupFacts()
        assertEquals(peak, retained.observedTaskPeak)
        assertTrue(assertNotNull(retained.lastTaskPeakObservationNanos) >= sampledAt)
        val pinnedIdentity = assertNotNull(retained.cgroupIdentitySha256)
        assertTrue(pinnedIdentity.matches(Regex("[0-9a-f]{64}")))
        println("GUARDIAN_BOUNDARY_PEAK phase=quiescent-ready noFurtherBirths=true peak=$peak sampledAtMonotonicNanos=$sampledAt " +
            "pinnedCgroupIdentitySha256=$pinnedIdentity retainedSampleMonotonicNanos=${retained.lastTaskPeakObservationNanos} " +
            "fixtureSourceSha256=${digest(Files.readAllBytes(fixtureSource()))} childSha256=${digest(fixture.child)}")
        return peak
    }

    private fun assertBoundaryGone(sandboxed: AcpSandboxedProcess, sample: Int) {
        assertTrue(sandboxed.process.waitFor(6, TimeUnit.SECONDS), "outer sandbox process did not exit")
        sandboxed.awaitCleanup(Duration.ofSeconds(6))
        val facts = sandboxed.boundaryCleanupFacts()
        assertNotNull(facts.observedTaskPeak)
        assertTrue(facts.observedTaskPeak!! >= sample && facts.observedTaskPeak!! in 1..31)
        assertTrue(facts.finalMembershipZero)
        assertTrue(facts.cgroupRemoved)
        assertTrue(facts.scopeRemoved)
        assertFalse(Files.exists(sandboxed.scopeIdentity.cgroupPath, LinkOption.NOFOLLOW_LINKS))
    }

    private fun withFixture(mode: String = "idle", compileChild: Boolean = false, action: (Fixture) -> Unit) {
        val parent = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
            .resolve("build/guardian-launch-boundary-verification/tests")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "fixture-")
        var fixture: Fixture? = null
        try {
            val guardian = productionAcpProviderGuardian()
            val checksum = Path.of(requireNotNull(System.getProperty("decompengine.acp.providerGuardianChecksum")))
            val trusted = requireNotNull(System.getProperty("decompengine.acp.providerGuardianExpectedSha256"))
            val artifact = AcpProviderGuardianArtifact.authenticate(guardian, checksum, trusted)
            val child = root.resolve("fixture-child")
            val codex = root.resolve("fixture-codex")
            if (compileChild) compileFixture(child) else Files.copy(guardian, child)
            Files.copy(child, codex)
            Files.setPosixFilePermissions(child, PosixFilePermissions.fromString("rwxr-xr-x"))
            Files.setPosixFilePermissions(codex, PosixFilePermissions.fromString("rwxr-xr-x"))
            fixture = Fixture(root, child, codex, artifact, mode)
            action(fixture)
        } finally {
            fixture?.let { runCatching { AcpProviderGuardianLaunchDescriptor.claimForLaunch(it.configuration) } }
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun compileFixture(target: Path) {
        val compiler = Path.of("/usr/bin/cc")
        AcpLiveContractHost.requireCapability(Files.isExecutable(compiler), { "guardian boundary fixture requires /usr/bin/cc" })
        val sourceHash = digest(Files.readAllBytes(fixtureSource()))
        val log = target.resolveSibling("fixture-compile.log")
        val process = ProcessBuilder(compiler.toString(), "-static", "-O2", "-Wall", "-Wextra", "-Werror",
            "-Wl,--build-id=none", fixtureSource().toString(), "-o", target.toString())
            .redirectErrorStream(true).redirectOutput(log.toFile()).also {
                it.environment().clear()
                it.environment()["PATH"] = "/usr/bin:/bin"
                it.environment()["TMPDIR"] = target.parent.toString()
            }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "static guardian fixture compilation timed out")
            assertEquals(0, process.exitValue(), Files.readString(log))
            assertEquals(sourceHash, digest(Files.readAllBytes(fixtureSource())), "fixture source changed during compilation")
        } finally {
            if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(2, TimeUnit.SECONDS)) }
        }
    }

    private fun requireLiveHost() {
        val missing = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH).filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(missing.isEmpty(), { "guardian boundary tools unavailable: $missing" })
        AcpLiveContractHost.requireCapability(Files.exists(USER_RUNTIME.resolve("bus")), { "systemd user bus unavailable" })
        AcpLiveContractHost.requireCapability(Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")), { "cgroup v2 unavailable" })
    }

    private companion object {
        val PROFILE = AcpProviderQualificationProfile.CREDENTIAL_FREE
        val LIMITS = AcpSandboxResourceLimits(maximumProcesses = 32, maximumOpenFiles = 128, maximumAddressSpaceBytes = 2_147_483_648L)
        const val CONFIGURATION_SHA = "1111111111111111111111111111111111111111111111111111111111111111"
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val USER_RUNTIME: Path by lazy { Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}") }
        fun configuration(codexMount: AcpSandboxReadOnlyMount?, limits: AcpSandboxResourceLimits = LIMITS): AcpLinuxSandboxConfiguration {
            val gate = productionAcpGateHelper()
            return AcpLinuxSandboxConfiguration(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH, gate,
                emptyList(), listOfNotNull(codexMount), USER_RUNTIME, agentResourceLimits = limits,
                expectedBubblewrapSha256 = digest(BWRAP), expectedResourceLimiterSha256 = digest(PRLIMIT),
                expectedScopeSupervisorSha256 = digest(SYSTEMD_RUN), expectedScopeInspectorSha256 = digest(SYSTEMCTL),
                expectedEnvironmentFdOpenerSha256 = digest(BASH), expectedSandboxGateHelperSha256 = digest(gate),
                expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(gate))
        }
        fun fixtureSource(): Path = Path.of(requireNotNull(AcpProviderGuardianBoundaryTest::class.java.getResource("/acp/provider_guardian_fixture.c")).toURI())
        fun channelSetup(): ByteArray = ByteBuffer.allocate(AcpProviderBrokerProtocol.CHANNEL_SETUP_V2_BYTES).order(ByteOrder.BIG_ENDIAN).apply {
            put(ByteArray(32) { 0x41 }); put(ByteArray(32) { 0x42 }); put(ByteArray(32) { 0x43 })
            val bounds = PROFILE.bounds
            listOf(bounds.maximumRequestBytes, bounds.maximumResponseBytes, bounds.maximumHeaderBytes, bounds.maximumHeaderFields,
                bounds.maximumChunkBytes, bounds.maximumQueuedChunks, bounds.maximumRequests, bounds.maximumOutputTokens).forEach(::putInt)
            putLong(bounds.overallTimeout.toMillis()); putLong(bounds.idleTimeout.toMillis()); putLong(bounds.cleanupTimeout.toMillis())
            putInt(AcpProviderBrokerProtocol.TERMINAL_CLEANUP_RECEIPT_FEATURE)
        }.array()
        fun digest(path: Path): String = digest(Files.readAllBytes(path))
        fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        fun orderedDigest(values: List<String>): String = digest(values.joinToString("") { "${it.length}:$it;" }.toByteArray(Charsets.UTF_8))
        fun forgedPermit(): AcpProviderQualificationPermit = AcpHarnessFactory::class.java.declaredClasses.single { it.simpleName == "FactoryProviderPermit" }
            .getDeclaredConstructor().apply { isAccessible = true }.newInstance() as AcpProviderQualificationPermit
        @Suppress("UNCHECKED_CAST")
        fun registry(): IdentityHashMap<AcpProviderQualificationPermit, Any> = AcpHarnessFactory::class.java.getDeclaredField("providerPermits")
            .apply { isAccessible = true }.get(AcpHarnessFactory) as IdentityHashMap<AcpProviderQualificationPermit, Any>
        fun registryContains(permit: AcpProviderQualificationPermit): Boolean = registry().let { synchronized(it) { it.containsKey(permit) } }
        fun <T> withOwnedPermit(consumer: Any, purpose: AcpProviderQualificationPurpose = AcpProviderQualificationPurpose.GUARDIAN_LAUNCH_DESCRIPTOR,
            action: (AcpProviderQualificationPermit) -> T): T {
            val permit = forgedPermit()
            val type = AcpHarnessFactory::class.java.declaredClasses.single { it.simpleName == "ProviderPermitRecord" }
            val record = type.getDeclaredConstructor(Any::class.java, AcpProviderQualificationPurpose::class.java, String::class.java)
                .apply { isAccessible = true }.newInstance(consumer, purpose, null)
            val registry = registry()
            synchronized(registry) { check(registry.put(permit, record) == null) }
            return try { action(permit) } finally { synchronized(registry) { registry.remove(permit) } }
        }
    }
}

package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.elfFixture
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.extension.ExtendWith
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.TreeMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WebFailedStartupQueuedRequestTest {
    @Test
    fun `cancelled start dispatches and refuses a complete queued HTTP request before cleanup continues`() {
        exerciseQueuedFailedStart(false)
    }

    @Test
    fun `thrown startup guard preserves exception and suppressed identity while refusing queued HTTP`() {
        exerciseQueuedFailedStart(true)
    }

    private fun exerciseQueuedFailedStart(exerciseFailureIdentity: Boolean) {
        val fixture = Fixture(if (exerciseFailureIdentity) "thrown-guard" else "cancelled-guard")
        val cancellation = AtomicBoolean(false)
        val scriptedFailure = IllegalArgumentException("scripted startup guard failure")
        val suppressedSentinel = IllegalStateException("preexisting suppressed sentinel")
        if (exerciseFailureIdentity) scriptedFailure.addSuppressed(suppressedSentinel)
        var primary: Throwable? = null
        // This scope precedes root, seed leases, server, socket and replacement acquisition.
        try {
            fixture.prepare()
            assertEquals(null, incompletePriorCase.get(), "prior fixture cleanup INCOMPLETE; do not stack owners")
            fixture.createRoot()
            val root = assertNotNull(fixture.root)
            val store = JobStore(root)
            val job = store.createFromUpload("queued-startup.elf", elfFixture())
            val acceptedBytes = "retained accepted source\n".toByteArray()
            val reportBytes = "retained terminal report\n".toByteArray()
            val reports = store.reportsDirectory(job.id)
            val sourcePath = reports.resolve("source-tree").resolve("revision_accepted.c")
            val reportPath = reports.resolve("accepted").resolve("artifact_accepted.txt")
            Files.createDirectories(sourcePath.parent)
            Files.createDirectories(reportPath.parent)
            Files.write(sourcePath, acceptedBytes)
            Files.write(reportPath, reportBytes)
            assertEquals(sourcePath, store.resolveArtifact(job.id, "reports/source-tree/revision_accepted.c"))
            assertEquals(reportPath, store.resolveArtifact(job.id, "reports/accepted/artifact_accepted.txt"))
            seedAcceptedTerminalAttempt(root, job.id, acceptedBytes, reportBytes)
            fixture.expectedManifest = manifest(root)
            fixture.checkManifest("seeded")

            val old = fixture.construct("old") {
                UploadServer("127.0.0.1", 0, root,
                    analyzer = JobAnalyzer { _, _ -> fixture.analyzerInvocations.incrementAndGet() },
                    reconstructor = JobReconstructor { _, _ -> fixture.reconstructorInvocations.incrementAndGet() },
                    uiMode = WebUiMode.SPA, basePath = "/w/", durableAdapters = emptyList(),
                    startupCancellation = {
                        if (cancellation.get()) {
                            if (exerciseFailureIdentity) throw scriptedFailure
                            true
                        } else false
                    })
            }
            // Construction prepares Git's empty configuration. Admit exactly that known empty
            // file, without recapturing or accepting changes to any retained terminal artifact.
            fixture.expectedManifest = assertNotNull(fixture.expectedManifest) + (".git-runtime/empty-config" to byteArrayOf())
            fixture.event("constructor-empty-git-config-expected", "path" to ".git-runtime/empty-config", "bytes" to "0")
            fixture.checkManifest("after-constructor")
            val nonce = java.util.UUID.randomUUID().toString().replace("-", "")
            val requestPath = "/w/api/v1/jobs/${job.id}"
            val requestTarget = "$requestPath?queued=$nonce"
            val probe = WebFailedStartupProbe(nonce, "GET", requestPath)
            fixture.probe = probe
            old.server.installFailedStartupProbe(probe)

            val client = Socket()
            fixture.sockets.add(client) // Publish before connect/configuration/write can fail.
            client.soTimeout = 3000
            val uri = URI(requestTarget)
            assertEquals(listOf("", "w", "api", "v1", "jobs", job.id), requestPath.split('/'))
            assertEquals(requestPath, uri.rawPath, "queued request must address the exact retained job")
            assertEquals("queued=$nonce", uri.rawQuery)
            assertEquals("$requestPath?queued=$nonce", uri.toASCIIString())
            assertFalse(uri.isAbsolute)
            assertEquals(null, uri.rawAuthority)
            assertEquals(null, uri.rawFragment)
            assertTrue(requestTarget.all { it.code in 33..126 && !it.isWhitespace() }, "request target contains whitespace/control bytes")
            fixture.event("queued-target-validated", "target" to requestTarget, "jobId" to job.id)
            // Socket writes have no SO_TIMEOUT; the controller only awaits this daemon task.
            fixture.operation("queued-socket-write", deadlineAfter(3)) {
                client.connect(InetSocketAddress("127.0.0.1", old.port), 3000)
                val request = "GET $requestTarget HTTP/1.1\r\nHost: 127.0.0.1:${old.port}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
                assertTrue(request.size <= 2048)
                client.getOutputStream().write(request)
                client.getOutputStream().flush()
                fixture.event("queued-request-flushed", "bytes" to request.size.toString())
            }
            cancellation.set(true)
            fixture.event("startup-cancellation-set")
            fixture.starter = fixture.launch("failed-start") {
                try { old.server.start() } catch (failure: Throwable) { fixture.startFailure.set(failure) }
            }

            val deadline = deadlineAfter(3)
            val cleanupArrived = probe.cleanupDispatcherStarted.await(remaining(deadline), TimeUnit.NANOSECONDS)
            fixture.observeProbe("cleanup-wait-returned")
            assertTrue(cleanupArrived, "CONTRACT_C: cleanup dispatcher was not observed")
            val cleanup = assertNotNull(probe.cleanup.get())
            assertTrue(cleanup.dispatcherStarted)
            assertFalse(cleanup.lifecycleLockHeld, "CONTRACT_A: cleanup dispatcher observation ran while lifecycleLock was held")
            assertTrue(assertNotNull(fixture.starter).thread.isAlive, "starter must remain at the cleanup gate")
            // The observer has separate outcome latches. A short bounded controller wait checks
            // either record, so B is reported promptly instead of waiting three seconds for REFUSED.
            while (probe.admitted.get() == null && probe.refused.get() == null && remaining(deadline) > 0) {
                probe.refusedObserved.await(minOf(remaining(deadline), TimeUnit.MILLISECONDS.toNanos(10)), TimeUnit.NANOSECONDS)
            }
            fixture.observeProbe("route-outcome-before-release")
            assertEquals(0, probe.admittedCount.get(), "CONTRACT_B: the real queued exchange was ADMITTED")
            assertEquals(null, probe.admitted.get(), "CONTRACT_B: the real queued exchange was ADMITTED")
            assertNotNull(probe.refused.get(), "the real queued HTTP exchange was not refused before cleanup continued")
            assertEquals(1, probe.refusedCount.get(), "exactly one matching refusal is required")
            assertEquals(WebFailedStartupProbe.RouteRecord(nonce, "GET", requestPath, WebFailedStartupProbe.Outcome.REFUSED), probe.refused.get())
            fixture.assertNoInvocations()
            fixture.assertBothExcluded("paused", deadline)
            fixture.checkManifest("paused")
            fixture.event("gate-contract-assertions-complete")

            fixture.releaseStartup()
            fixture.assertQueuedRemoteClose(client)
            fixture.assertStartupFailure(exerciseFailureIdentity, scriptedFailure, suppressedSentinel)
            fixture.assertNoInvocations()
            fixture.checkManifest("after-failed-start")
            // Positive-path release checks happen BEFORE explicit fixture cleanup could mask a leak.
            fixture.assertReleased("failed-start", old.port)
            fixture.stop(old, "old-explicit-cleanup")

            val replacement = fixture.construct("replacement") {
                UploadServer("127.0.0.1", old.port, root,
                    uiMode = WebUiMode.SPA, basePath = "/w/", durableAdapters = emptyList())
            }
            fixture.operation("replacement-start") { replacement.server.start() }
            fixture.authenticatedJobsGet(replacement.server, job.id, "replacement-before-retry")
            fixture.assertBothExcluded("replacement-before-retry")
            fixture.checkManifest("replacement-before-retry")
            // A stale stop must not revoke the new owner's registry entries or listener.
            fixture.stop(old, "old-stale-retry-with-replacement-live")
            fixture.checkManifest("replacement-after-retry")
            fixture.assertBothExcluded("replacement-after-retry")
            fixture.authenticatedJobsGet(replacement.server, job.id, "replacement-after-retry")
            fixture.stop(replacement, "replacement-stop")
            fixture.assertReleased("replacement-stopped", old.port)
            fixture.checkManifest("positive-end")
        } catch (failure: Throwable) {
            primary = failure
        } finally {
            // No assertions here can bypass a later release, check, or the independent receipt.
            fixture.finish(primary, exerciseFailureIdentity, scriptedFailure, suppressedSentinel)
        }
        primary?.let { failure ->
            fixture.errors.forEach { if (it !== failure) failure.addSuppressed(it) }
            throw failure
        }
        if (fixture.errors.isNotEmpty()) {
            throw AssertionError("queued startup fixture observation/teardown failed; receipt=${fixture.receiptPath}").also { failure ->
                fixture.errors.forEach(failure::addSuppressed)
            }
        }
    }

    private class Task<T>(val name: String, action: () -> T) {
        val result = AtomicReference<Result<T>?>()
        val thread = Thread({ result.set(runCatching(action)) }, "queued-startup-$name").apply { isDaemon = true }
        fun await(deadline: Long): T {
            val left = remaining(deadline)
            if (left > 0 && thread.isAlive) TimeUnit.NANOSECONDS.timedJoin(thread, left)
            check(!thread.isAlive) { "task $name INCOMPLETE after bounded wait" }
            return checkNotNull(result.get()) { "task $name did not publish an outcome" }.getOrThrow()
        }
    }

    private class OwnedServer(val name: String, val server: UploadServer) {
        val port get() = server.serverPort
        var stopTask: Task<Unit>? = null
        var stopped = false
    }

    private inner class Fixture(val mode: String) {
        var root: Path? = null
        var receiptPath: Path? = null
        var expectedManifest: Map<String, ByteArray>? = null
        var probe: WebFailedStartupProbe? = null
        var starter: Task<Unit>? = null
        val startFailure = AtomicReference<Throwable?>()
        val analyzerInvocations = AtomicInteger()
        val reconstructorInvocations = AtomicInteger()
        val sockets = CopyOnWriteArrayList<Socket>()
        val servers = CopyOnWriteArrayList<OwnedServer>()
        val tasks = CopyOnWriteArrayList<Task<*>>()
        val httpClients = CopyOnWriteArrayList<HttpClient>()
        val responseStreams = CopyOnWriteArrayList<InputStream>()
        val errors = mutableListOf<Throwable>()
        private val events = mutableListOf<JsonObject>()
        private val manifestObservations = mutableListOf<JsonObject>()
        private val probeObservations = mutableListOf<JsonObject>()
        private val startedAt = System.nanoTime()
        private var eventOverflow = false
        private var gateReleased = false
        private var identityChecked = false
        private var queuedRemoteOutcome = "NOT_OBSERVED"
        private var sourcePins: JsonObject = buildJsonObject { }

        fun prepare() {
            val evidenceParent = Files.createDirectories(Path.of("build/orchestration/queued-startup/remediation/runs").toAbsolutePath())
            val run = Files.createTempDirectory(evidenceParent, "$mode-")
            receiptPath = run.resolve("receipt.json")
            sourcePins = sourceHashes()
        }

        fun createRoot() {
            val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-failed-startup").toAbsolutePath())
            root = createTempDirectory(temporaryRoot, "web-failed-startup-")
            event("root-created", "root" to root.toString())
        }

        @Synchronized
        fun event(name: String, vararg facts: Pair<String, String>) {
            if (events.size >= 256) { eventOverflow = true; return }
            events += buildJsonObject {
                put("ordinal", events.size + 1)
                put("elapsedNanos", System.nanoTime() - startedAt)
                put("event", name)
                facts.forEach { (key, value) -> put(key, value.take(4096)) }
            }
        }

        fun <T> launch(name: String, action: () -> T): Task<T> {
            check(tasks.size < 64) { "fixture task count exceeded" }
            val task = Task(name, action)
            tasks.add(task) // Registration precedes Thread.start, including start failure.
            event("task-launched", "operation" to name)
            task.thread.start()
            return task
        }

        fun <T> operation(name: String, deadline: Long = deadlineAfter(5), action: () -> T): T {
            val task = launch(name, action)
            try {
                return task.await(deadline).also { event("operation-complete", "operation" to name) }
            } catch (failure: Throwable) {
                task.thread.interrupt() // Cancellation request is NOT evidence of task termination.
                event("operation-failed", "operation" to name, "failure" to describe(failure))
                throw failure
            }
        }

        fun construct(name: String, deadline: Long = deadlineAfter(5), factory: () -> UploadServer): OwnedServer = operation("construct-$name", deadline) {
            event("constructor-called", "server" to name)
            val returned = try { factory() } catch (failure: Throwable) {
                event("constructor-failed-no-returned-handle", "server" to name, "failure" to describe(failure))
                throw failure // No claim of fixture cleanup for an unassigned production handle.
            }
            val owned = OwnedServer(name, returned)
            servers.add(owned)
            event("server-registered", "server" to name, "port" to owned.port.toString())
            owned
        }

        private fun probeSnapshot(phase: String): JsonObject = buildJsonObject {
            val current = probe
            val cleanup = current?.cleanup?.get()
            put("phase", phase)
            put("elapsedNanos", System.nanoTime() - startedAt)
            put("gateReleasedByController", gateReleased)
            put("permitCount", current?.permitStop?.count?.let(::JsonPrimitive) ?: JsonNull)
            put("cleanup", cleanup?.let { buildJsonObject {
                put("dispatcherStarted", it.dispatcherStarted); put("lifecycleLockHeld", it.lifecycleLockHeld)
            } } ?: JsonNull)
            fun route(record: WebFailedStartupProbe.RouteRecord?) = record?.let { buildJsonObject {
                put("nonce", it.nonce); put("method", it.method); put("path", it.path); put("outcome", it.outcome.name)
            } } ?: JsonNull
            put("admitted", route(current?.admitted?.get()))
            put("refused", route(current?.refused?.get()))
            put("admittedCount", current?.admittedCount?.get() ?: 0)
            put("refusedCount", current?.refusedCount?.get() ?: 0)
            put("admissionFinallyFinished", current?.admissionFinallyFinished?.get()?.let { buildJsonObject {
                put("nonce", it.nonce); put("method", it.method); put("path", it.path); put("completedNanos", it.completedNanos)
            } } ?: JsonNull)
            put("admissionFinallyFinishedCount", current?.admissionFinallyFinishedCount?.get() ?: 0)
            put("admittedCompletionRequired", current?.admittedCompletionRequired?.get() ?: false)
            put("cleanupDeadlineNanos", current?.cleanupDeadlineNanos?.get() ?: 0)
            put("cleanupReturnedNanos", current?.cleanupReturnedNanos?.get() ?: 0)
            put("observerFailure", current?.observerFailure?.get()?.let(::JsonPrimitive) ?: JsonNull)
        }

        fun observeProbe(phase: String) {
            check(probeObservations.size < 16) { "probe receipt bound exceeded" }
            probeObservations.add(probeSnapshot(phase))
            event("probe-snapshot", "phase" to phase, "index" to (probeObservations.size - 1).toString())
        }

        private fun assertProbeCompletion() {
            val current = probe ?: return
            val entry = current.admitted.get()
            if (entry == null) {
                assertEquals(0, current.admissionFinallyFinishedCount.get())
                assertEquals(null, current.admissionFinallyFinished.get())
                assertFalse(current.admittedCompletionRequired.get())
                return
            }
            val completion = assertNotNull(current.admissionFinallyFinished.get(), "admitted request accounting completion was not observed")
            assertEquals(1, current.admittedCount.get())
            assertEquals(1, current.admissionFinallyFinishedCount.get())
            assertEquals(listOf(entry.nonce, entry.method, entry.path), listOf(completion.nonce, completion.method, completion.path))
            assertTrue(current.admittedCompletionRequired.get())
            assertTrue(current.cleanupReturnedNanos.get() != 0L)
            assertTrue(current.cleanupReturnedNanos.get() - completion.completedNanos >= 0,
                "cleanup probe returned before admission accounting finished")
            assertTrue(current.cleanupDeadlineNanos.get() - completion.completedNanos >= 0,
                "admission accounting exceeded the original shared watchdog")
            assertEquals(null, current.observerFailure.get())
            event("admitted-completion-before-shutdown", "completedNanos" to completion.completedNanos.toString(),
                "cleanupReturnedNanos" to current.cleanupReturnedNanos.get().toString())
        }

        private fun releaseGate() {
            // Capture atomics without assertions; always open the gate even if evidence fails.
            if (!gateReleased) {
                try { observeProbe("immediately-before-controller-release") }
                catch (failure: Throwable) { errors.add(failure) }
                finally {
                    probe?.permitStop?.countDown()
                    gateReleased = true
                }
                event("gate-released")
            }
        }

        private fun releaseGateAndClients() {
            releaseGate()
            sockets.forEachIndexed { index, socket ->
                independent("client-close-$index") {
                    socket.close()
                    check(socket.isClosed)
                    event("client-closed-locally", "index" to index.toString())
                }
            }
        }

        fun releaseStartup() {
            releaseGate()
            starter?.let {
                it.await(deadlineAfter(5))
                event("starter-terminated")
            }
        }

        fun assertQueuedRemoteClose(client: Socket) {
            val deadline = deadlineAfter(3)
            queuedRemoteOutcome = operation("queued-remote-close", deadline) {
                check(!client.isClosed) { "remote closure must be observed before local close" }
                client.soTimeout = TimeUnit.NANOSECONDS.toMillis(remaining(deadline)).coerceIn(1, 3000).toInt()
                try {
                    val byte = client.getInputStream().read()
                    assertEquals(-1, byte, "queued refusal must close without application response bytes")
                    "REMOTE_EOF"
                } catch (reset: SocketException) {
                    check(!client.isClosed) { "local close is not remote reset evidence" }
                    check(reset.message == "Connection reset") { "unexpected socket error: ${reset.message}" }
                    "REMOTE_RESET"
                }
            }
            event("queued-remote-close-observed", "outcome" to queuedRemoteOutcome)
            client.close()
            check(client.isClosed)
        }

        fun assertStartupFailure(identity: Boolean, expected: Throwable, sentinel: Throwable) {
            if (identityChecked) return
            val failure = assertNotNull(startFailure.get(), "start unexpectedly succeeded")
            event("startup-failure-observed", "failure" to describe(failure),
                "originalIdentity" to (failure === expected).toString(),
                "suppressed" to failure.suppressed.joinToString { describe(it) },
                "sentinelIdentity" to (failure.suppressed.singleOrNull() === sentinel).toString())
            if (identity) {
                assertSame(expected, failure)
                assertEquals(listOf(sentinel), failure.suppressed.toList(), "cleanup changed the original suppressed failures")
            } else {
                assertIs<IllegalStateException>(failure)
                assertEquals("Web server startup cancelled", failure.message)
                assertTrue(failure.suppressed.isEmpty(), "clean cleanup must not suppress another failure")
            }
            assertEquals(null, probe?.observerFailure?.get(), "the observation gate watchdog/interruption must remain clear")
            identityChecked = true
        }

        fun assertNoInvocations() {
            event("invocations-observed", "analyzerInvocations" to analyzerInvocations.get().toString(),
                "reconstructorInvocations" to reconstructorInvocations.get().toString())
            assertEquals(0, analyzerInvocations.get(), "refused HTTP must not invoke analyzer")
            assertEquals(0, reconstructorInvocations.get(), "refused HTTP must not invoke reconstructor")
        }

        fun checkManifest(phase: String) {
            val expected = expectedManifest ?: return
            val actual = manifest(assertNotNull(root))
            check(manifestObservations.size < 16) { "manifest receipt bound exceeded" }
            manifestObservations.add(buildJsonObject { put("phase", phase); put("files", manifestJson(actual)) })
            event("manifest-observed", "phase" to phase, "index" to (manifestObservations.size - 1).toString())
            assertEquals(expected.keys, actual.keys, "terminal artifact paths changed ($phase)")
            expected.forEach { (path, bytes) -> assertContentEquals(bytes, actual.getValue(path), "terminal bytes changed at $path ($phase)") }
        }

        fun assertBothExcluded(phase: String, deadline: Long = deadlineAfter(5)) {
            val dataRoot = assertNotNull(root)
            var webFailure: Throwable? = null
            // A returned unexpected contender is immediately owned, even when the assertion fails.
            try {
                construct("contender-$phase", deadline) {
                    UploadServer("127.0.0.1", 0, dataRoot, uiMode = WebUiMode.SPA, basePath = "/w/", durableAdapters = emptyList())
                }
            } catch (failure: Throwable) { webFailure = failure }
            var workflowFailure: Throwable? = null
            try { operation("workflow-exclusion-$phase", deadline) { WorkflowAttemptStore.open(dataRoot).use { } } }
            catch (failure: Throwable) { workflowFailure = failure }
            event("lease-exclusions", "phase" to phase, "web" to describe(webFailure), "workflow" to describe(workflowFailure))
            assertEquals("OWNERSHIP_CONFLICT", assertIs<WebJobStoreOwnershipException>(webFailure).code, "web exclusion ($phase)")
            assertEquals("OWNERSHIP_CONFLICT", assertIs<WorkflowStoreException>(workflowFailure).code, "workflow exclusion ($phase)")
        }

        fun stop(owned: OwnedServer, operation: String) {
            check(starter?.thread?.isAlive != true) { "refuse concurrent stop while starter is alive" }
            check(owned.stopTask?.thread?.isAlive != true) { "previous stop for ${owned.name} remains live" }
            owned.stopped = false
            event("stop-called", "server" to owned.name, "operation" to operation)
            val task = launch(operation) { owned.server.stop() }
            owned.stopTask = task
            task.await(deadlineAfter(5))
            owned.stopped = true
            event("stop-complete", "server" to owned.name, "operation" to operation)
        }

        fun assertReleased(phase: String, port: Int) {
            val failures = mutableListOf<Throwable>()
            releaseChecks(phase, port) { name, action ->
                try { action() } catch (failure: Throwable) {
                    event("release-check-failed", "operation" to name, "failure" to describe(failure))
                    failures.add(failure)
                }
            }
            if (failures.isNotEmpty()) throw AssertionError("ownership/listener release failed ($phase)").also { error ->
                failures.forEach(error::addSuppressed)
            }
        }

        private fun releaseChecks(phase: String, port: Int?, check: (String, () -> Unit) -> Unit) {
            val dataRoot = root ?: return
            // Separate attempts: a failed workflow check cannot suppress web or listener evidence.
            check("workflow-release-$phase") {
                operation("workflow-release-$phase") { WorkflowAttemptStore.open(dataRoot).use { } }
                event("lease-free", "phase" to phase, "lease" to "workflow")
            }
            check("web-release-$phase") {
                operation("web-release-$phase") { WebJobStoreOwnership.acquire(dataRoot).use { } }
                event("lease-free", "phase" to phase, "lease" to "web")
            }
            if (port != null) check("listener-release-$phase") {
                operation("listener-release-$phase") {
                    ServerSocket().use { listener ->
                        listener.reuseAddress = true
                        listener.bind(InetSocketAddress("127.0.0.1", port))
                    }
                }
                event("listener-free", "phase" to phase, "port" to port.toString())
            } else event("listener-release-unknown", "phase" to phase, "reason" to "no returned server/port; constructor cleanup not claimed")
        }

        private fun independent(name: String, action: () -> Unit) {
            try {
                action()
                event("independent-check-passed", "operation" to name)
            } catch (failure: Throwable) {
                errors.add(failure)
                event("independent-check-failed", "operation" to name, "failure" to describe(failure))
            }
        }

        fun finish(primary: Throwable?, identity: Boolean, expected: Throwable, sentinel: Throwable) {
            // No throwing assertion is allowed to short circuit these independent stages.
            releaseGateAndClients()
            independent("starter-join") { releaseStartup() }
            independent("final-probe-observation") { observeProbe("outer-finalizer") }
            if (starter != null && starter?.thread?.isAlive == false) {
                independent("startup-failure-identity") { assertStartupFailure(identity, expected, sentinel) }
            }
            // Cancel any HTTP/write/acquisition task and independently await real thread exit.
            val pending = tasks.filter { it !== starter && it.thread.isAlive }
            pending.forEach { it.thread.interrupt() }
            disconnectConnections("outer-finalizer")
            val taskDeadline = deadlineAfter(5)
            pending.forEach { task -> independent("join-${task.name}") { task.await(taskDeadline) } }
            if (starter?.thread?.isAlive == true) {
                independent("cleanup-blocked") { error("cleanup INCOMPLETE: starter alive; stop not attempted concurrently") }
            } else {
                servers.toList().asReversed().forEach { owned ->
                    if (!owned.stopped) independent("final-stop-${owned.name}") { stop(owned, "final-stop-${owned.name}") }
                }
            }
            independent("after-final-stops-probe") { observeProbe("after-final-stops") }
            independent("admitted-completion-before-shutdown") { assertProbeCompletion() }
            releaseChecks("outer-finalizer", servers.firstOrNull()?.port, ::independent)
            // Check any other bound port independently, including unexpected contender returns.
            servers.map { it.port }.distinct().drop(1).forEach { port ->
                independent("extra-listener-$port") {
                    operation("extra-listener-$port") { ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress("127.0.0.1", port)) } }
                    event("listener-free", "phase" to "outer-finalizer", "port" to port.toString())
                }
            }
            independent("final-invocations") { assertNoInvocations() }
            independent("final-manifest") { checkManifest("outer-finalizer") }
            independent("task-quiescence") {
                check(tasks.none { it.thread.isAlive }) { "cleanup INCOMPLETE: surviving tasks ${tasks.filter { it.thread.isAlive }.map { it.name }}" }
                check(servers.all { it.stopped }) { "cleanup INCOMPLETE: returned server stop not confirmed" }
                check(sockets.all { it.isClosed }) { "cleanup INCOMPLETE: client still open" }
                check(responseStreams.isEmpty()) { "cleanup INCOMPLETE: HTTP response still owned" }
                check(httpClients.isEmpty()) { "cleanup INCOMPLETE: HTTP client termination not confirmed" }
                check(!eventOverflow) { "fixture event bound exceeded" }
            }
            // Retain roots even on green: no deletion can hide late work or unproven cleanup.
            event("root-retained", "root" to root.toString())
            if (errors.isNotEmpty()) incompletePriorCase.compareAndSet(null, receiptPath.toString())
            independent("write-receipt") { writeReceipt(primary) }
            if (errors.isNotEmpty()) incompletePriorCase.compareAndSet(null, receiptPath.toString())
        }

        private fun writeReceipt(primary: Throwable?) {
            val path = receiptPath ?: return
            val snapshot = synchronized(this) { events.toList() }
            val receipt = buildJsonObject {
                put("schemaVersion", 1)
                put("caseClass", "decompengine.web.WebFailedStartupQueuedRequestTest")
                put("caseMethod", if (mode == "thrown-guard")
                    "thrown startup guard preserves exception and suppressed identity while refusing queued HTTP()" else
                    "cancelled start dispatches and refuses a complete queued HTTP request before cleanup continues()")
                put("mode", mode)
                put("root", root?.toString()?.let(::JsonPrimitive) ?: JsonNull)
                put("rootDisposition", "RETAINED")
                put("primaryFailure", failureJson(primary))
                put("independentFailures", JsonArray(errors.map(::failureJson)))
                put("sourceHashesAtStart", sourcePins)
                put("sourceHashesAtFinish", sourceHashes())
                put("includedManifest", expectedManifest?.let(::manifestJson) ?: JsonNull)
                put("manifestObservations", JsonArray(manifestObservations.toList()))
                put("probeObservations", JsonArray(probeObservations.toList()))
                put("constructorBoundary", "Only returned handles are fixture-owned; a throwing constructor's internal cleanup is not claimed")
                put("excludedPaths", JsonArray(listOf(".web-owner.lock", ".workflow-owner.lock").map(::JsonPrimitive)))
                put("analyzerInvocations", analyzerInvocations.get())
                put("reconstructorInvocations", reconstructorInvocations.get())
                put("submissionCounts", "NOT_INSTRUMENTED; actual route REFUSED is the admission boundary")
                put("queuedRemoteOutcome", queuedRemoteOutcome)
                put("socketDisposition", if (sockets.all { it.isClosed }) "LOCALLY_CLOSED" else "OPEN_OR_UNKNOWN")
                put("events", JsonArray(snapshot))
                put("eventOverflow", eventOverflow)
                put("eventCounts", buildJsonObject {
                    snapshot.groupingBy { it.getValue("event").jsonPrimitive.content }.eachCount().forEach { (event, count) -> put(event, count) }
                })
                put("operationCounts", buildJsonObject {
                    tasks.groupingBy { it.name }.eachCount().forEach { (operation, count) -> put(operation, count) }
                })
                put("tasks", JsonArray(tasks.map { task -> buildJsonObject {
                    put("operation", task.name); put("alive", task.thread.isAlive); put("daemon", task.thread.isDaemon)
                    put("outcome", task.result.get()?.let { if (it.isSuccess) "RETURNED" else "THREW" } ?: "NO_OUTCOME")
                    put("failure", failureJson(task.result.get()?.exceptionOrNull()))
                } }))
                put("servers", JsonArray(servers.map { owned -> buildJsonObject {
                    put("name", owned.name); put("port", owned.port); put("boundedStopReturned", owned.stopped)
                } }))
                put("fixtureCleanup", when {
                    errors.isNotEmpty() || tasks.any { it.thread.isAlive } -> "INCOMPLETE_OR_OBSERVATION_FAILED"
                    servers.isEmpty() -> "NO_RETURNED_SERVER; listener/constructor cleanup UNVERIFIED"
                    else -> "RETURNED_HANDLES_TASKS_LEASES_LISTENERS_OBSERVED_RELEASED"
                })
                put("scope", "Fixture observations only; no secure/native cleanup, historical deadlock, or full #987 qualification")
            }.toString()
            check(receipt.toByteArray().size <= 512 * 1024) { "receipt exceeds 512 KiB" }
            Files.writeString(path, receipt + "\n")
            println("queued-startup-receipt $path")
        }

        private fun disconnectConnections(phase: String) {
            responseStreams.toList().forEachIndexed { index, stream ->
                independent("close-response-$phase-$index") {
                    operation("close-response-$phase-$index") { stream.close() }
                    responseStreams.remove(stream)
                }
            }
            httpClients.toList().forEachIndexed { index, client ->
                independent("shutdown-http-$phase-$index") {
                    operation("shutdown-http-$phase-$index") {
                        client.shutdownNow()
                        check(client.awaitTermination(Duration.ofSeconds(3))) { "HTTP client did not terminate" }
                    }
                    httpClients.remove(client)
                }
            }
        }

        fun authenticatedJobsGet(server: UploadServer, jobId: String, phase: String) {
            val deadline = deadlineAfter(3) // One overall budget for bootstrap, POST, GET and parsing.
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build()
            httpClients.add(client)
            val task = launch("http-$phase") {
                val origin = "http://127.0.0.1:${server.serverPort}"
                fun exchange(path: String, method: String, body: ByteArray?, headers: Map<String, String>): Pair<HttpResponse<InputStream>, String> {
                    check(remaining(deadline) > 0) { "HTTP overall deadline expired" }
                    val request = HttpRequest.newBuilder(URI("$origin$path"))
                        .timeout(Duration.ofNanos(remaining(deadline).coerceAtLeast(1)))
                    headers.forEach { (name, value) -> request.header(name, value) }
                    request.method(method, body?.let(HttpRequest.BodyPublishers::ofByteArray) ?: HttpRequest.BodyPublishers.noBody())
                    val response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream())
                    val stream = response.body()
                    responseStreams.add(stream)
                    try {
                        event("http-status", "phase" to phase, "method" to method, "path" to path, "status" to response.statusCode().toString())
                        assertEquals(200, response.statusCode())
                        return response to boundedResponse(stream, deadline)
                    } finally {
                        stream.close()
                        responseStreams.remove(stream)
                    }
                }
                try {
                    val body = "{\"token\":\"${server.issueBrowserBootstrap().token}\"}".toByteArray()
                    assertTrue(body.size <= 4096)
                    val (session, sessionBody) = exchange("/w/api/v1/session", "POST", body,
                        mapOf("Origin" to origin, "Content-Type" to "application/json"))
                    val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
                    val csrf = envelope(sessionBody, "session").getValue("csrfToken").jsonPrimitive.content
                    val (_, jobsBody) = exchange("/w/api/v1/jobs", "GET", null,
                        mapOf("Accept" to "application/json", "Cookie" to cookie, "X-CSRF-Token" to csrf))
                    val data = envelope(jobsBody, "jobs")
                    val ids = data.getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }
                    event("authenticated-jobs", "phase" to phase, "jobIds" to ids.toString())
                    assertEquals(listOf(jobId), ids, "replacement must return the exact retained jobId in the jobs envelope")
                    check(remaining(deadline) > 0) { "HTTP overall deadline expired" }
                } finally {
                    client.shutdownNow()
                    check(client.awaitTermination(Duration.ofNanos(remaining(deadline)))) { "HTTP client termination exceeded overall deadline" }
                    httpClients.remove(client)
                }
            }
            try { task.await(deadline) } catch (failure: Throwable) {
                task.thread.interrupt()
                // Close owned bodies and await client termination on bounded, registered tasks.
                disconnectConnections(phase)
                throw failure
            }
        }
    }

    private fun seedAcceptedTerminalAttempt(root: Path, jobId: String, source: ByteArray, report: ByteArray) {
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(source)
            .joinToString("") { "%02x".format(it) }
        WorkflowAttemptStore.open(root).use { attempts ->
            val initial = (attempts.inspect(jobId) as decompengine.jobs.WorkflowJobInspection.Available).snapshot
            val queued = attempts.create(jobId, initial.version,
                NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)))
            val started = attempts.transition(jobId, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val completed = attempts.transition(jobId, started.attempt.runId, started.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                    WorkflowCandidate("revision_accepted", sha)))
            val acceptance = WorkflowAcceptanceReference(jobId, completed.attempt.runId, "revision_accepted", sha,
                "graph_accepted", "artifact_accepted", java.security.MessageDigest.getInstance("SHA-256").digest(report)
                    .joinToString("") { "%02x".format(it) })
            attempts.recordAcceptedRevision(jobId, completed.attempt.runId, completed.snapshot.version,
                completed.attempt.version, acceptance)
        }
    }

    private fun manifest(root: Path): Map<String, ByteArray> = TreeMap<String, ByteArray>().also { captured ->
        var total = 0
        Files.walk(root).use { paths ->
            val iterator = paths.iterator()
            var entries = 0
            while (iterator.hasNext()) {
                check(++entries <= 128) { "fixture manifest entry bound exceeded" }
                val path = iterator.next()
                if (!Files.isRegularFile(path)) continue
                val relative = root.relativize(path).toString().replace('\\', '/')
                if (relative in setOf(".web-owner.lock", ".workflow-owner.lock")) continue
                val bytes = Files.newInputStream(path).use { it.readNBytes(256 * 1024 + 1) }
                check(bytes.size <= 256 * 1024) { "fixture manifest file bound exceeded" }
                total += bytes.size
                check(total <= 1024 * 1024) { "fixture manifest total bound exceeded" }
                captured[relative] = bytes
            }
        }
    }

    private fun manifestJson(manifest: Map<String, ByteArray>) = buildJsonObject {
        manifest.forEach { (path, bytes) -> put(path, buildJsonObject { put("bytes", bytes.size); put("sha256", sha256(bytes)) }) }
    }

    private fun sourceHashes() = buildJsonObject {
        for (source in listOf("src/main/kotlin/decompengine/web/UploadServer.kt",
            "src/test/kotlin/decompengine/web/WebFailedStartupQueuedRequestTest.kt", "scripts/verify-web-job-recovery.py")) {
            val path = Path.of(source)
            put(source, try {
                if (Files.isRegularFile(path)) {
                    val bytes = Files.newInputStream(path).use { it.readNBytes(2 * 1024 * 1024 + 1) }
                    if (bytes.size <= 2 * 1024 * 1024) sha256(bytes) else "UNAVAILABLE_SIZE_BOUND"
                } else "UNAVAILABLE"
            } catch (failure: Exception) { "UNAVAILABLE: ${failure.javaClass.name}" })
        }
    }

    private fun boundedResponse(input: InputStream, deadline: Long): String {
        val output = ByteArrayOutputStream()
        run {
            val buffer = ByteArray(4096)
            while (true) {
                check(remaining(deadline) > 0) { "HTTP overall deadline expired" }
                val read = input.read(buffer, 0, minOf(buffer.size, 64 * 1024 + 1 - output.size()))
                if (read < 0) break
                output.write(buffer, 0, read)
                check(output.size() <= 64 * 1024) { "HTTP response exceeds 64 KiB" }
            }
        }
        check(remaining(deadline) > 0) { "HTTP overall deadline expired" }
        return output.toString(Charsets.UTF_8.name())
    }

    private fun envelope(body: String, kind: String): JsonObject {
        val parsed = Json.parseToJsonElement(body).jsonObject
        assertEquals("1", parsed.getValue("apiVersion").jsonPrimitive.content)
        assertEquals(kind, parsed.getValue("kind").jsonPrimitive.content)
        return parsed.getValue("data").jsonObject
    }

    private fun failureJson(failure: Throwable?) = failure?.let {
        buildJsonObject {
            put("class", it.javaClass.name)
            put("message", it.message.orEmpty().take(4096))
            put("stack", JsonArray(it.stackTrace.take(12).map { frame -> JsonPrimitive(frame.toString()) }))
            put("suppressed", JsonArray(it.suppressed.take(8).map { error -> JsonPrimitive(describe(error)) }))
        }
    } ?: JsonNull

    companion object {
        private val incompletePriorCase = AtomicReference<String?>()
        private fun deadlineAfter(seconds: Long) = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        private fun remaining(deadline: Long): Long = (deadline - System.nanoTime()).coerceAtLeast(0)
        private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        private fun describe(failure: Throwable?) = failure?.let { "${it.javaClass.name}: ${it.message.orEmpty().take(1024)}" } ?: "NONE"
    }
}

package decompengine.web

import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessProvenance
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.jobs.InvalidUploadException
import decompengine.jobs.Job
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.UploadPublicationUncertainException
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.ProgressRedactor
import decompengine.jobs.BestEffortProgressJournal
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.ReconstructionAdapters
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ModuleReconstructor
import decompengine.project.ReconstructionProfiles
import decompengine.project.ReconstructionProfile
import decompengine.project.verifyAcpExecutionReceiptDocument
import decompengine.repair.TRACE_REPAIR_ACP_RECEIPT_KIND
import decompengine.repair.TRACE_REPAIR_ACP_TASK_FIELD
import decompengine.repair.validateRepairHistoryProjection
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import kotlin.io.path.pathString

/** Classify document paths only; the shell still enforces its existing method and asset policy. */
internal fun canonicalSpaDocumentPath(base: String, path: String): String? {
    val id = "[A-Za-z0-9][A-Za-z0-9_-]{0,127}"
    return when (path) {
        base, "${base}runtime", "${base}upload" -> path
        base.removeSuffix("/").ifEmpty { "/" } -> base
        "${base}runtime/" -> "${base}runtime"
        "${base}upload/" -> "${base}upload"
        else -> path.takeIf { it.startsWith("${base}jobs/") &&
            it.removePrefix("${base}jobs/").matches(Regex("[0-9a-f]{32}(?:/git|/runs(?:/$id(?:/(?:activity|evidence)|/revisions/$id/(?:sources|source-files)/$id)?)?)?/?")) }?.removeSuffix("/")
    }
}

fun interface JobAnalyzer {
    fun analyze(job: Job, reportsDir: Path)
}

fun interface JobReconstructor {
    fun reconstruct(job: Job, reportsDir: Path)
}

class AutomaticJobAnalyzer : JobAnalyzer {
    override fun analyze(job: Job, reportsDir: Path) {
        AutomaticExplorer().explore(
            binaryPath = job.binaryPath,
            seedInputs = listOf(CandidateInput("seed_default", CandidateSource.SEED)),
            reportsDir = reportsDir,
        )
    }
}

class SourceTreeJobReconstructor(
    private val environment: Map<String, String> = System.getenv(),
    private val analyzer: decompengine.project.ProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer.bundled(),
) : JobReconstructor {
    override fun reconstruct(job: Job, reportsDir: Path) {
        BestEffortProgressJournal(reportsDir, "reconstruction", environment.values).use { progress ->
            try {
                val strategy = selectWebReconstructionStrategy(environment, progress)
                java.nio.file.Files.createDirectories(reportsDir)
                java.nio.file.Files.writeString(
                    reportsDir.resolve(WEB_RECONSTRUCTION_HARNESS_REPORT),
                    renderWebReconstructionHarnessSelection(strategy),
                )
                ArchivalReconstructionService(
                    analyzer,
                    strategy.reconstructor,
                    profile = strategy.profile,
                    progress = progress,
                ).reconstruct(job.binaryPath, reportsDir)
            } catch (failure: Exception) {
                progress.phase(AgentWorkflowPhase.FAILED)
                throw failure
            }
        }
    }
}

internal enum class WebReconstructionMode(val configurationValue: String) {
    AGENT("agent"),
    EVIDENCE_ONLY("evidence-only"),
}

internal data class WebReconstructionStrategy(
    val mode: WebReconstructionMode,
    val reconstructor: ModuleReconstructor,
    val harnessProvenance: AcpHarnessProvenance?,
    val profile: ReconstructionProfile,
)

/** Resolves exactly one web reconstruction mode without credential-based fallbacks. */
internal fun selectWebReconstructionStrategy(
    environment: Map<String, String>,
    progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
    profile: ReconstructionProfile = ReconstructionProfiles.default,
): WebReconstructionStrategy {
    val configuredMode = environment[WEB_RECONSTRUCTION_MODE_ENVIRONMENT] ?: WebReconstructionMode.AGENT.configurationValue
    return when (configuredMode) {
        WebReconstructionMode.AGENT.configurationValue -> {
            val selection = AcpHarnessFactory.fromEnvironment(environment)
            WebReconstructionStrategy(
                WebReconstructionMode.AGENT,
                BoundedLlmModuleReconstructor(
                    selection.createHarness(),
                    harnessProvenanceDescriptor = selection.provenance.stableDescriptor,
                    progress = progress,
                ),
                selection.provenance,
                profile,
            )
        }
        WebReconstructionMode.EVIDENCE_ONLY.configurationValue -> {
            val selectedProfile = ReconstructionAdapters.resolve(profile).evidenceOnlyProfile(profile)
            WebReconstructionStrategy(
                WebReconstructionMode.EVIDENCE_ONLY,
                ReconstructionAdapters.resolve(selectedProfile).evidenceOnlyReconstructor(selectedProfile),
                null,
                selectedProfile,
            )
        }
        else -> throw IllegalArgumentException(
            "$WEB_RECONSTRUCTION_MODE_ENVIRONMENT must be exactly " +
                "${WebReconstructionMode.AGENT.configurationValue} or " +
                WebReconstructionMode.EVIDENCE_ONLY.configurationValue,
        )
    }
}

/** Stable, non-secret selection metadata. This does not claim that an ACP session has run. */
internal fun renderWebReconstructionHarnessSelection(strategy: WebReconstructionStrategy): String {
    val selection = strategy.harnessProvenance?.let { provenance ->
        buildJsonObject {
            put("stableDescriptor", provenance.stableDescriptor)
            put("harness", provenance.harness)
            put("implementationId", provenance.implementationId)
            put("agentExecutionContractVersion", provenance.agentExecutionContractVersion)
            put(
                "acpProtocolVersion",
                provenance.acpProtocolVersion?.let(::JsonPrimitive) ?: JsonNull,
            )
            put("acpSdkVersion", provenance.acpSdkVersion?.let(::JsonPrimitive) ?: JsonNull)
            put(
                "configurationSha256",
                provenance.configurationSha256?.let(::JsonPrimitive) ?: JsonNull,
            )
            put("deprecated", provenance.deprecated)
        }
    }
    val report = buildJsonObject {
        put("schemaVersion", 1)
        put("mode", strategy.mode.configurationValue)
        put("selection", selection ?: JsonNull)
    }
    return Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), report) + "\n"
}

private const val WEB_RECONSTRUCTION_MODE_ENVIRONMENT = "WEB_RECONSTRUCTION_MODE"
private const val WEB_RECONSTRUCTION_HARNESS_REPORT = "reconstruction_harness_selection.json"

enum class WebUiMode { LEGACY, SPA }

class UploadServer(
    host: String,
    port: Int,
    dataDir: Path,
    analyzer: JobAnalyzer = AutomaticJobAnalyzer(),
    reconstructor: JobReconstructor = SourceTreeJobReconstructor(),
    executor: Executor? = null,
    uiMode: WebUiMode = WebUiMode.LEGACY,
    basePath: String = "/",
    devFrontendOrigin: String? = null,
    sourceProfiles: List<ReconstructionProfile> = defaultWebSourceProfiles(),
    sensitiveValues: Collection<String> = System.getenv().values,
    private val listenBacklog: Int = 64,
    private val authenticationInspector: (decompengine.agent.AgentCancellation) -> decompengine.acp.AcpAuthenticationInventory = defaultWebAuthenticationInspector(),
    private val requestShutdownTimeoutMs: Long = 1000,
    private val requestDiagnosticOutput: (String) -> Unit = System.err::println,
    // Test-owned clocks exercise expiry through the real HTTP/browser path; production uses the system clock.
    webAccessClock: WebAccessClock? = null,
    private val startupCancellation: () -> Boolean = { false },
    // Operator-admitted directory whose immediate children may be imported by name; never browser-selected.
    gitImportRoot: Path? = null,
    // Operator-allowed remote destinations and server-side credentials (#585, #586); closed by default.
    gitRemotePolicy: decompengine.git.GitRemotePolicy = decompengine.git.GitRemotePolicy(),
) {
    init {
        require(listenBacklog in 1..4096) { "HTTP listen backlog must be between 1 and 4096" }
        require(requestShutdownTimeoutMs in 0..5000) { "HTTP request shutdown wait must be between zero and five seconds" }
        check(!Thread.currentThread().isInterrupted && !startupCancellation()) { "Web server startup cancelled" }
    }
    private val diagnosticRedactor = ProgressRedactor(sensitiveValues)
    private val authenticationInspectionLock = Any()
    private var authenticationInspectionId: String? = null
    private val authenticationInspectionCancellation = java.util.concurrent.atomic.AtomicBoolean(false)
    private val authenticationInspectionResult = java.util.concurrent.atomic.AtomicReference(
        "{\"status\":\"idle\",\"loginSupported\":false}")
    private val authenticationInspectionWorker = java.util.concurrent.atomic.AtomicReference<Thread>()
    // Verify trusted application bytes before binding a listening socket.
    private val spaAssets = when (uiMode) {
        WebUiMode.SPA -> {
            require(java.net.InetAddress.getByName(host).isLoopbackAddress) {
                "the SPA preview currently requires a loopback host"
            }
            // Validate the explicit origin spelling before binding, including
            // when an ephemeral port is requested. No origin comes from HTTP.
            LocalWebAccessConfiguration(webOrigin(host, port.takeIf { it != 0 } ?: 1), basePath,
                setOfNotNull(devFrontendOrigin))
            EmbeddedWebAssets.load(basePath = basePath)
        }
        WebUiMode.LEGACY -> {
            require(java.net.InetAddress.getByName(host).isLoopbackAddress) {
                "legacy browser access requires a loopback host until a remote access profile is qualified"
            }
            LocalWebAccessConfiguration(webOrigin(host, port.takeIf { it != 0 } ?: 1), basePath)
            require(basePath == "/") { "--base-path is supported by --ui spa" }
            require(devFrontendOrigin == null) { "--dev-frontend-origin requires --ui spa" }
            null
        }
    }
    // Acquire cooperative ownership before binding so a refused contender never occupies a listener.
    private val ownership: WebJobStoreOwnership = WebJobStoreOwnership.acquire(dataDir.toAbsolutePath().normalize())
    private val server = try {
        HttpServer.create(InetSocketAddress(host, port), listenBacklog)
    } catch (failure: Throwable) {
        try { ownership.close() } catch (cleanup: Throwable) {
            if (cleanup !== failure) failure.addSuppressed(cleanup)
        }
        throw failure
    }
    private val store = JobStore(dataDir)
    private val admittedSourceProfiles = sourceProfiles.toList()
    private val jobs = WebJobService(store, analyzer, reconstructor, executor,
        attemptStoreFactory = { root ->
            // Storage creation is the upgrade point: claim the cross-JVM web lock as the root appears.
            ownership.ensureLockFile()
            WorkflowAttemptStore.open(root)
        },
        progressRetentionIntervalMs = if (uiMode == WebUiMode.SPA) 1000 else null,
        shutdownTimeoutMs = 5000, failureDiagnostic = { diagnostic(it, "Background operation failed") },
        sourceProfiles = admittedSourceProfiles)
    private val sourceEvidence = WebSourceEvidence(store, admittedSourceProfiles, jobs::readArtifact)
    private val archiveEvidence = WebArchiveEvidence(store, sourceEvidence, jobs::readArtifact)
    private val access = LocalWebAccess(LocalWebAccessConfiguration(webOrigin(host, server.address.port), basePath,
        setOfNotNull(devFrontendOrigin)), webAccessClock ?: SystemWebAccessClock,
        requestDiagnosticOutput = requestDiagnosticOutput)
    private val jobMutations = WebJobMutationBoundary(access, jobs)
    private val legacySessions = WebSessionController(access)
    internal val streamResources = WebStreamResources()
    private val harnessReadiness = WebHarnessReadinessProjector()
    private val agentPreflight = WebAgentPreflight(configurationIdentity = {
        (authenticationInspector as? WebObservedAuthenticationInspector)?.configurationIdentity()
    }) { cancellation ->
        check(withActiveRequest {
            authenticationInspector(decompengine.agent.AgentCancellation {
                stopRequested.get() || cancellation.isCancellationRequested()
            })
            val selectedConfiguration =
                (authenticationInspector as? WebObservedAuthenticationInspector)?.configurationIdentity()
            if (selectedConfiguration != null && !stopRequested.get() && !cancellation.isCancellationRequested()) {
                harnessReadiness.inspect()
            }
        }) { "Server is stopping" }
    }
    private val gitAvailability = decompengine.git.GitRuntime.detect()
    private val gitRepositories = decompengine.git.ManagedGitRepositories(store.storageRoot, gitAvailability,
        jobs::gitSourceSnapshot, gitImportRoot, acceptance = decompengine.git.GitAcceptanceResolver(jobs::gitAcceptance),
        activity = decompengine.git.GitJobActivity(jobs::gitRunActivity), remotePolicy = gitRemotePolicy)
    private val api = spaAssets?.let { WebApiController(access, it, jobs, jobMutations, streamResources,
        harnessReadiness = harnessReadiness, agentPreflight = agentPreflight,
        git = WebGitCapability(gitAvailability, gitRepositories)) }
    // A request that finds every worker and queue slot taken is answered by this tiny pool with a stable 429
    // instead of a reset connection. It has no queue, so overload still never buffers more than the main pool does;
    // when it too is busy the rejection propagates and the dispatcher closes the connection, as before.
    private val overloadResponders = ThreadPoolExecutor(
        2, 2, 0, TimeUnit.MILLISECONDS, java.util.concurrent.SynchronousQueue(),
        { task -> Thread(task, OVERLOAD_RESPONDER_THREAD).apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val requestExecutor = ThreadPoolExecutor(
        16, 16, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(64),
        { task -> Thread(task, "decomp-web-http").apply { isDaemon = true } },
        { task, executor ->
            if (executor.isShutdown) throw java.util.concurrent.RejectedExecutionException("web request executor is shut down")
            overloadResponders.execute(task)
        },
    )
    private val requestDeadlines = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "decomp-web-deadline").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }
    private val lifecycleLock = Any()
    private var stopping = false
    private var started = false
    private var activeRequests = 0
    private val requestsDrained = java.util.concurrent.CountDownLatch(1)
    private val stopRequested = java.util.concurrent.atomic.AtomicBoolean(false)
    val serverPort: Int get() = server.address.port
    val browserOrigin: String = devFrontendOrigin ?: webOrigin(host, serverPort)

    /** The CLI calls this explicitly; no HTTP route can issue a local link. */
    fun issueBrowserBootstrap(): WebBootstrapToken {
        return access.issueBootstrap()
    }

    init {
        jobs.onQuiescent = {
            try {
                releaseOwnershipIfIdle()
            } catch (_: Exception) {
                System.err.println("Web request cleanup did not release store ownership; recovery is required")
            }
        }
        try {
            jobs.initializeExistingStorage(startupRecoveryLimitsForWeb(uiMode)) { stopRequested.get() || startupCancellation() }
            // Interrupted repository operations become explicit outcomes before any request is served.
            gitRepositories.recover(store.jobIds())
        } catch (failure: Throwable) {
            stopRequested.set(true)
            stopping = true
            fun cleanup(action: () -> Unit): Boolean {
                return try { action(); true } catch (problem: Throwable) {
                    if (problem !== failure) failure.addSuppressed(problem)
                    false
                }
            }
            // HttpServer.stop alone does not release an unstarted bound listener. No application
            // context is installed yet; close admission before starting its dispatcher for teardown.
            cleanup { server.start() }
            cleanup { server.stop(0) }
            cleanup { requestExecutor.shutdownNow() }
            cleanup { requestDeadlines.shutdownNow() }
            cleanup { streamResources.shutdown() }
            cleanup { access.close() }
            // Outer ownership must remain retained if service cleanup cannot confirm quiescence.
            if (cleanup { jobs.close() }) cleanup { ownership.close() }
            throw failure
        }
        server.executor = requestExecutor
        server.createContext("/") { exchange ->
            if (Thread.currentThread().name == OVERLOAD_RESPONDER_THREAD) {
                // Admitted only to be refused: no routing, no deadline, no session or storage access.
                exchange.responseHeaders.set("Connection", "close")
                access.sendDenied(exchange, WebAccessDenied(429, "SERVER_BUSY", "The workbench is handling its maximum number of requests. Retry shortly."))
                return@createContext
            }
            val upload = exchange.requestMethod == "POST" &&
                exchange.requestHeaders.getFirst("Content-Type")?.startsWith("multipart/form-data", true) == true
            val deadline = requestDeadlines.schedule({ exchange.close() }, if (upload) 120 else 30, TimeUnit.SECONDS)
            try { route(exchange) } finally { deadline.cancel(false) }
        }
    }

    fun start() {
        var cleanupRequired = false
        try {
            synchronized(lifecycleLock) {
                check(!started && !stopping) { "Web server cannot be started again" }
                cleanupRequired = true
                try {
                    // Recovery never rewrites historical metadata here; startup must not report
                    // success when a cancellation signal or a late interrupt preceded the listener.
                    check(!stopRequested.get() && !startupCancellation() && !Thread.currentThread().isInterrupted) { "Web server startup cancelled" }
                    server.start()
                    started = true
                } catch (failure: Exception) {
                    // Close admission before releasing the lock to perform failed-start cleanup.
                    stopping = true
                    throw failure
                }
            }
        } catch (failure: Exception) {
            // A queued handler may need lifecycleLock while the dispatcher is stopped.
            // Unwind startup's outer lock before performing listener/worker cleanup.
            if (cleanupRequired) {
                try { stop() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
            }
            throw failure
        }
    }

    /** Publish cancellation before waiting for lifecycle work; stop completes resource cleanup. */
    internal fun requestStop() {
        jobs.signalShutdown()
        stopRequested.set(true)
        authenticationInspectionCancellation.set(true)
        agentPreflight.requestStop()
        jobs.beginShutdown()
    }

    /** Latch that resolves once requestStop has published its signal; test evidence helper. */
    internal fun requestStopSignalled(): java.util.concurrent.CountDownLatch {
        val latch = java.util.concurrent.CountDownLatch(1)
        Thread({
            while (!stopRequested.get()) Thread.sleep(10)
            latch.countDown()
        }, "stop-signal-probe").apply { isDaemon = true; start() }
        return latch
    }

    fun stop(delaySeconds: Int = 0) {
        require(delaySeconds >= 0) { "shutdown delay must be nonnegative" }
        // Signal recovery and the job service even while start or a queued callback holds
        // lifecycleLock through filesystem operations: no queued operation may begin and no
        // completion may be published after the stop signal is observable.
        requestStop()
        val callerWasInterrupted = Thread.currentThread().isInterrupted
        val inspection = synchronized(lifecycleLock) {
            stopping = true
            if (activeRequests == 0) requestsDrained.countDown()
            // JDK HttpServer.stop does not release a bound listener before start. Start its
            // dispatcher only after closing request admission, then close it below. This also
            // covers failed ownership/recovery admission and explicit stop-before-start.
            if (!started) {
                server.start()
                started = true
            }
            authenticationInspectionCancellation.set(true)
            authenticationInspectionWorker.get()
        }
        val streamsClosed = streamResources.shutdown()
        server.stop(delaySeconds)
        if (!streamsClosed && !streamResources.shutdown()) System.err.println("Event stream shutdown did not complete cleanly.")
        requestExecutor.shutdownNow()
        overloadResponders.shutdownNow()
        requestDeadlines.shutdownNow()
        harnessReadiness.close()
        agentPreflight.close()
        access.close()
        gitRepositories.close()
        jobs.close()
        var inspectionWaitInterrupted = false
        try {
            check(inspection === null || inspection !== Thread.currentThread()) { "Inspection cannot await its own shutdown" }
            // The provider owns its cleanup deadlines. Do not truncate them with a web timeout,
            // including when the shutdown caller is interrupted while cleanup is still running.
            while (inspection?.isAlive == true) {
                try { inspection.join() } catch (_: InterruptedException) { inspectionWaitInterrupted = true }
            }
        } catch (exception: Exception) {
            if (exception is InterruptedException) Thread.currentThread().interrupt()
        }
        // Interrupting the executor does not mean admitted handlers have finished their finally blocks.
        // Admission is closed, so reaching zero here is permanent. Never hold lifecycleLock while waiting.
        var requestWaitInterrupted = false
        val requestDeadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(requestShutdownTimeoutMs)
        while (requestsDrained.count != 0L) {
            val remaining = requestDeadline - System.nanoTime()
            if (remaining <= 0) break
            try { requestsDrained.await(remaining, TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) { requestWaitInterrupted = true }
        }
        if (callerWasInterrupted || inspectionWaitInterrupted || requestWaitInterrupted) Thread.currentThread().interrupt()
        if (!releaseOwnershipIfIdle()) throw IllegalStateException("HTTP requests remain active after server stop")
    }

    /** Admission covers the whole handler, including upload publication and error handling. */
    internal fun withActiveRequest(action: () -> Unit): Boolean {
        synchronized(lifecycleLock) {
            if (stopping || stopRequested.get()) return false
            activeRequests++
            // stop() publishes stopRequested outside lifecycleLock, so a handler that read
            // the flag before the signal must still be refused when the signal preceded this
            // reservation instead of staying admitted past the stop request.
            if (stopRequested.get()) {
                activeRequests--
                return false
            }
        }
        try {
            action()
            return true
        } finally {
            synchronized(lifecycleLock) {
                activeRequests--
                if (stopping && activeRequests == 0) requestsDrained.countDown()
            }
            try {
                releaseOwnershipIfIdle()
            } catch (_: Exception) {
                System.err.println("Web request cleanup did not release store ownership; recovery is required")
            }
        }
    }

    private fun releaseOwnershipIfIdle(): Boolean {
        // Sample service quiescence before taking the lifecycle lock; stopping closes the service to new work.
        val jobsIdle = jobs.isIdle()
        return synchronized(lifecycleLock) {
            if (stopping && activeRequests == 0 && jobsIdle && streamResources.snapshot().active == 0) {
                ownership.close()
                true
            } else false
        }
    }

    private fun route(exchange: HttpExchange) {
        if (!withActiveRequest { routeAdmitted(exchange) }) exchange.close()
    }

    private fun handleAuthenticationInspection(exchange: HttpExchange) {
        if (exchange.requestHeaders.getFirst("X-Decomp-Operator-Action") != "inspect-auth") {
            sendCorrelatedLegacyJsonProblem(exchange, 400, "OPERATOR_INSPECTION_REJECTED",
                "{\"error\":\"Explicit operator inspection is required.\"}", requestDiagnosticOutput)
            return
        }
        val admission = synchronized(authenticationInspectionLock) {
            if (authenticationInspectionResult.get() == AUTH_INSPECTION_RUNNING) {
                409 to authenticationInspectionSnapshot()
            } else {
                authenticationInspectionId = java.util.UUID.randomUUID().toString()
                authenticationInspectionResult.set(AUTH_INSPECTION_RUNNING)
                try {
                    synchronized(lifecycleLock) {
                        authenticationInspectionCancellation.set(false)
                        // requestStop signals outside this lock; never clear its signal after checking it.
                        check(!stopping && !stopRequested.get()) { "Server is stopping" }
                        val worker = Thread({
                            var result = AUTH_INSPECTION_FAILED
                            try {
                                withActiveRequest { result = inspectAuthenticationMethods() }
                            } catch (_: Exception) {
                                result = AUTH_INSPECTION_FAILED
                            } finally {
                                synchronized(authenticationInspectionLock) {
                                    authenticationInspectionResult.set(result)
                                }
                            }
                        }, "decomp-web-auth-inspection").apply { isDaemon = true }
                        authenticationInspectionWorker.set(worker)
                        worker.start()
                    }
                    202 to authenticationInspectionSnapshot(AUTH_INSPECTION_RUNNING)
                } catch (_: Exception) {
                    authenticationInspectionResult.set(AUTH_INSPECTION_FAILED)
                    503 to authenticationInspectionSnapshot()
                }
            }
        }
        if (admission.first >= 400) sendCorrelatedLegacyJsonProblem(exchange, admission.first,
            if (admission.first == 503) "OPERATOR_INSPECTION_UNAVAILABLE" else "OPERATOR_INSPECTION_REJECTED",
            admission.second, requestDiagnosticOutput)
        else exchange.sendJson(admission.first, admission.second)
    }

    private fun authenticationInspectionSnapshot(result: String? = null): String = synchronized(authenticationInspectionLock) {
        // Every payload here is an internally serialized object; identity is an application-generated UUID.
        (result ?: authenticationInspectionResult.get()).dropLast(1) +
            ",\"inspectionId\":" + (authenticationInspectionId?.let { "\"$it\"" } ?: "null") + "}"
    }

    private fun inspectAuthenticationMethods(): String = try {
        val inventory = authenticationInspector(decompengine.agent.AgentCancellation {
            stopRequested.get() || authenticationInspectionCancellation.get()
        })
        buildJsonObject {
            put("status", "ready")
            put("inventoryCommitment", inventory.commitment)
            put("inventoryFormat", inventory.commitmentFormat)
            put("inventoryScope", inventory.commitmentScope)
            put("logoutAdvertised", inventory.logoutAdvertised)
            put("logoutSupported", inventory.logoutSupported)
            put("loginSupported", false)
            put("methods", kotlinx.serialization.json.buildJsonArray {
                inventory.methods.forEach { method -> add(buildJsonObject {
                    put("idPreview", diagnosticRedactor.text(method.idPreview, 128))
                    put("namePreview", diagnosticRedactor.text(method.namePreview, 128))
                    put("descriptionPreview", diagnosticRedactor.text(method.descriptionPreview.orEmpty(), 256))
                    put("variant", method.variant)
                    put("loginSupported", false)
                }) }
            })
        }.toString()
    } catch (_: decompengine.acp.AcpPreflightCancelledException) { AUTH_INSPECTION_CANCELLED }
      catch (_: Exception) { AUTH_INSPECTION_FAILED }

    private fun handleAuthenticationCancellation(exchange: HttpExchange) {
        if (exchange.requestHeaders.getFirst("X-Decomp-Operator-Action") != "cancel-auth-inspection") {
            sendCorrelatedLegacyJsonProblem(exchange, 400, "OPERATOR_INSPECTION_REJECTED",
                "{\"error\":\"Explicit operator cancellation is required.\"}", requestDiagnosticOutput)
            return
        }
        val requestedId = exchange.requestHeaders["X-Decomp-Inspection-Id"]?.singleOrNull()
        val response = synchronized(authenticationInspectionLock) {
            when {
                authenticationInspectionResult.get() != AUTH_INSPECTION_RUNNING ->
                    409 to "{\"error\":\"No authentication inspection is running.\"}"
                requestedId == null ->
                    400 to "{\"error\":\"An exact inspection identity is required.\"}"
                requestedId != authenticationInspectionId ->
                    409 to "{\"error\":\"The selected inspection is no longer running.\"}"
                else -> {
                    authenticationInspectionCancellation.set(true)
                    202 to authenticationInspectionSnapshot("{\"status\":\"cancellation-requested\",\"loginSupported\":false}")
                }
            }
        }
        if (response.first >= 400) sendCorrelatedLegacyJsonProblem(exchange, response.first,
            "OPERATOR_INSPECTION_REJECTED", response.second, requestDiagnosticOutput)
        else exchange.sendJson(response.first, response.second)
    }

    private fun routeAdmitted(exchange: HttpExchange) {
        spaAssets?.let { assets ->
            try {
                if (api?.route(exchange) == true) return
                checkNotNull(access).authorize(exchange, WebEndpointPolicy.publicRead())
                routeSpaPreview(exchange, assets)
            } catch (failure: WebAccessDenied) {
                checkNotNull(access).sendDenied(exchange, failure)
            }
            return
        }
        val segments = exchange.requestURI.path.split('/').filter(String::isNotBlank)
        try {
            access.authorize(exchange, WebEndpointPolicy.transport(setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")))
            if (exchange.requestURI.rawPath == "/api/v1/session") {
                legacySessions.handle(exchange)
                return
            }
            if (exchange.requestURI.rawPath == "/api/v1/session/csrf") {
                val credentials = access.csrfForSession(exchange)
                requireNoWebApiQuery(exchange)
                requireJsonAccept(exchange)
                sendWebApiResponse(exchange, 200, "session", buildJsonObject {
                    put("csrfToken", credentials.csrfToken)
                    put("expiresAt", credentials.session.expiresAt.toString())
                    put("idleExpiresAt", credentials.session.idleExpiresAt.toString())
                })
                return
            }
            val legacyJsonRead = segments.size in 3..4 && segments.take(2) == listOf("api", "jobs") &&
                (segments.size == 3 || segments[3] == "events")
            val publicPage = exchange.requestURI.rawPath in setOf("/login", "/assets/app.css")
            val mutation = exchange.requestMethod in setOf("POST", "PUT", "PATCH", "DELETE")
            val legacyJobMutation = exchange.requestMethod == "POST" && (
                segments == listOf("jobs") ||
                    (segments.size == 3 && segments[0] == "jobs" && segments[2] in setOf("explore", "reconstruct"))
                )
            val policy = when {
                publicPage -> WebEndpointPolicy.publicRead()
                legacyJsonRead -> WebEndpointPolicy.privateRead(allowHead = true)
                mutation && segments == listOf("jobs") && exchange.requestMethod == "POST" -> WebEndpointPolicy.multipartUpload()
                mutation -> WebEndpointPolicy.jsonMutation(exchange.requestMethod)
                else -> WebEndpointPolicy.privateRead(allowHead = true)
            }
            // Persisted job mutations authorize through WebJobMutationBoundary in their handler.
            // Other requests, including in-memory operator actions and unknown mutation routes,
            // still receive the ordinary shared access policy here.
            if (!legacyJobMutation) access.authorize(exchange, policy)
            if (exchange.requestURI.rawPath == "/login") {
                exchange.sendHtml(200, renderLegacyLogin(), listOf(LEGACY_LOGIN_SCRIPT))
                return
            }
            if (legacyJsonRead) requireJsonAccept(exchange)
            if (exchange.requestMethod == "POST" && segments == listOf("jobs")) exchange.requestsLegacyJson()
            when {
                exchange.requestMethod in setOf("GET", "HEAD") && segments.isEmpty() ->
                    renderJobDashboard(exchange)
                exchange.requestMethod in setOf("GET", "HEAD") && segments == listOf("assets", "app.css") ->
                    exchange.sendBytes(200, APP_CSS.toByteArray(), "text/css; charset=utf-8", cache = true)
                exchange.requestMethod == "GET" && segments == listOf("api", "recovery") ->
                    exchange.sendJson(200, jobs.recoveryInventory().toJson().toString())
                exchange.requestMethod == "POST" && segments == listOf("api", "operator", "auth-methods", "cancel") ->
                    handleAuthenticationCancellation(exchange)
                exchange.requestMethod == "GET" && segments == listOf("api", "operator", "auth-methods") ->
                    exchange.sendJson(200, authenticationInspectionSnapshot())
                exchange.requestMethod == "POST" && segments == listOf("api", "operator", "auth-methods") ->
                    handleAuthenticationInspection(exchange)
                exchange.requestMethod == "POST" && segments == listOf("jobs") -> handlePostJob(exchange)
                exchange.requestMethod in setOf("GET", "HEAD") && segments.size == 2 && segments[0] == "jobs" ->
                    handleJob(exchange, decode(segments[1]))
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "explore" ->
                    handleExplore(exchange, segments[1])
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "reconstruct" ->
                    handleReconstruct(exchange, segments[1])
                exchange.requestMethod in setOf("GET", "HEAD") && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "source" ->
                    handleSource(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod in setOf("GET", "HEAD") && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "artifacts" ->
                    handleArtifact(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod in setOf("GET", "HEAD") && segments.size == 3 && segments[0] == "api" && segments[1] == "jobs" ->
                    exchange.sendJson(200, encodeJob(jobs.get(decode(segments[2]))))
                exchange.requestMethod in setOf("GET", "HEAD") && segments.size == 4 && segments[0] == "api" && segments[1] == "jobs" && segments[3] == "events" -> {
                    val job = jobs.get(decode(segments[2]))
                    val runId = exchange.requestURI.rawQuery?.let {
                        require(it.matches(Regex("runId=[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "Only an exact workflow attempt selection is supported" }
                        it.removePrefix("runId=")
                    }
                    exchange.sendJson(200, readLegacyProgress(job.id, runId).toString())
                }
                else -> legacyError(exchange, 404, "NOT_FOUND", "The requested route does not exist.", requestDiagnosticOutput) {
                    renderErrorPage(404, "Page not found", "The requested route does not exist.")
                }
            }
        } catch (exception: WebAccessDenied) {
            if (exchange.requestURI.rawPath.startsWith("/api/v1/")) {
                access.sendDenied(exchange, exception)
                return
            }
            access.deniedHeaders(exchange, exception)
            if (exception.status == 401 && !exchange.requestURI.path.startsWith("/api/") &&
                exchange.requestMethod in setOf("GET", "HEAD")) {
                exchange.sendHtml(401, renderLegacyLogin(), listOf(LEGACY_LOGIN_SCRIPT))
                return
            }

            legacyError(exchange, exception.status, exception.code, exception.message ?: "The request was invalid.", requestDiagnosticOutput) {
                renderErrorPage(exception.status, "Invalid request", exception.message ?: "The request was invalid.")
            }
        } catch (exception: WebJobServiceException) {
            val status = if (exception.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND")) 404 else 503
            val code = if (status == 404 || exception.code in setOf("PROGRESS_UNAVAILABLE", "UPLOAD_CAPACITY", "JOB_RECORD_UNAVAILABLE", "RECOVERY_INSPECTION_BUSY")) exception.code else "JOB_STORAGE_UNAVAILABLE"
            legacyError(exchange, status, code, when (code) {
                "PROGRESS_UNAVAILABLE" -> "The retained progress journal is unavailable. Missing data does not establish an empty history."
                "UPLOAD_CAPACITY" -> "Upload capacity is temporarily unavailable. Retry shortly."
                "JOB_RECORD_UNAVAILABLE", "RECOVERY_INSPECTION_BUSY" -> publicWebDiagnosticMessage(code)
                "JOB_STORAGE_UNAVAILABLE" -> "Job storage is unavailable. Inspect storage before retrying."
                else -> "The requested job or attempt is unavailable."
            }, requestDiagnosticOutput) {
                renderErrorPage(status, "Job storage unavailable", "${publicWebDiagnosticCode(exception.code)}: ${publicWebDiagnosticMessage(exception.code)}")
            }
        } catch (exception: JobStoreException) {
            legacyError(exchange, 404, "JOB_NOT_FOUND", "The requested job is unavailable.", requestDiagnosticOutput) {
                renderErrorPage(404, "Job not found", "The requested job is unavailable.")
            }
        } catch (exception: IllegalArgumentException) {
            legacyError(exchange, 400, "INVALID_REQUEST", "The request was invalid.", requestDiagnosticOutput) {
                renderErrorPage(400, "Invalid request", "The request was invalid or the requested source or artifact is unavailable.")
            }
        } catch (exception: Exception) {
            if (exchange.responseCode != -1) {
                exchange.close()
            } else if (exchange.requestURI.rawPath in setOf("/api/v1/session", "/api/v1/session/csrf")) {
                // These compatibility routes produce v1 envelopes even in legacy presentation mode.
                access.sendDenied(exchange, WebAccessDenied(500, "INTERNAL_ERROR", "The request could not be completed."))
            } else {
                legacyError(exchange, 500, "INTERNAL_ERROR", "The operation failed.", requestDiagnosticOutput) {
                    renderErrorPage(500, "Unexpected error", "The operation failed. Private diagnostic details are withheld.")
                }
            }
        }
    }

    private fun renderJobDashboard(exchange: HttpExchange) {
        val rows = jobs.dashboardRows()
        val recovery = try {
            jobs.recoveryInventory()
        } catch (failure: WebJobServiceException) {
            if (failure.code == "RECOVERY_INSPECTION_BUSY") null else throw failure
        }
        exchange.sendHtml(200, renderDashboardDocument(
            rows.jobs,
            rows.unavailable,
            recovery,
        ))
    }

    private fun routeSpaPreview(exchange: HttpExchange, assets: EmbeddedWebAssets) {
        val path = exchange.requestURI.rawPath
        if (path.startsWith(assets.assetPrefix)) {
            assets.serveAsset(exchange)
            return
        }
        val base = assets.basePath
        val canonical = canonicalSpaDocumentPath(base, path)
        if (canonical != null) {
            if (path != canonical && exchange.requestMethod in setOf("GET", "HEAD")) {
                val query = exchange.requestURI.rawQuery?.let { "?$it" }.orEmpty()
                exchange.responseHeaders.set("Location", canonical + query)
                exchange.responseHeaders.set("Cache-Control", "no-store")
                exchange.applyWebSecurityHeaders()
                exchange.sendResponseHeaders(308, -1)
                exchange.close()
            } else {
                assets.serveShell(exchange)
            }
            return
        }
        checkNotNull(access).sendDenied(exchange, WebAccessDenied(404, "NOT_FOUND", "The requested route is unavailable."))
    }

    private fun handlePostJob(exchange: HttpExchange) {
        try {
            val mutation = jobMutations.authorizeUpload(exchange)
            handleAuthorizedUploadRequest(exchange, mutation, requestDiagnosticOutput)
        } catch (exception: InvalidUploadException) {
            legacyError(exchange, 400, "INVALID_UPLOAD", "Upload a supported Linux ELF binary.", requestDiagnosticOutput) {
                renderErrorPage(400, "Unsupported binary", "Upload a supported Linux ELF binary.")
            }
        }
    }

    private fun handleExplore(exchange: HttpExchange, encodedJobId: String) {
        val mutation = jobMutations.authorizeLegacyStart(exchange)
        schedule(exchange, mutation, decode(encodedJobId), WebWorkflow.EXPLORE)
    }

    private fun handleReconstruct(exchange: HttpExchange, encodedJobId: String) {
        val mutation = jobMutations.authorizeLegacyStart(exchange)
        schedule(exchange, mutation, decode(encodedJobId), WebWorkflow.RECONSTRUCT)
    }

    private fun schedule(
        exchange: HttpExchange,
        mutation: AuthorizedLegacyWebJobStart,
        jobId: String,
        workflow: WebWorkflow,
    ) {
        when (mutation.start(jobId, workflow)) {
            is WebWorkflowAdmission.Started -> exchange.redirect("/jobs/$jobId")
            WebWorkflowAdmission.AlreadyRunning -> exchange.sendHtml(
                409, renderErrorPage(409, "Analysis already running", "This job already has an active background operation."),
            )
            WebWorkflowAdmission.Unavailable -> {
                exchange.responseHeaders.set("Retry-After", "1")
                exchange.sendHtml(503, renderErrorPage(503, "Workers unavailable", "Workflow capacity is unavailable. Retry shortly."))
            }
        }
    }

    private fun diagnostic(failure: Exception, fallback: String): String =
        diagnosticRedactor.text(failure.message ?: fallback, maximumCharacters = 480)

    /** A queued operation can be claimed once, either by a worker or by shutdown. */
    private fun readLegacyProgress(jobId: String, runId: String?): kotlinx.serialization.json.JsonObject {
        val bytes = jobs.readProgressJournal(jobId, runId)
        return try { legacyProgressPresentation(AgentProgressJournal.decode(bytes)) } catch (_: Exception) {
            throw WebJobServiceException("PROGRESS_UNAVAILABLE", "The retained progress journal is unavailable.")
        }
    }

    private fun handleJob(exchange: HttpExchange, jobId: String) {
        val view = jobs.presentation(jobId)
        val query = parseRecordedRepairHistoryQuery(exchange.requestURI.rawQuery)
        val reports = query.runId?.let { jobs.reportContext(jobId, it) } ?: view.reports
        val recorded = jobs.readRecordedRepairHistory(jobId, reports.runId)
        val page = try {
            decompengine.repair.recordedRepairHistoryPage(recorded, query.selection, MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS)
        } catch (failure: decompengine.repair.RepairRecordedSelectionFailure) {
            val status = if (failure.problem == decompengine.repair.RepairRecordedSelectionProblem.OUT_OF_RANGE) 400 else 409
            exchange.sendHtml(status, renderErrorPage(status, "History selection unavailable", requireNotNull(failure.message)))
            return
        }
        // Resolve all page/stale checks before any report, evidence or receipt payload work.
        val source = runCatching { archiveEvidence.read(jobId, reportPrefix = reports.artifactPrefix).source }
            .recoverCatching { sourceEvidence.read(jobId, reports.artifactPrefix).view() }
        val progress = runCatching { readLegacyProgress(jobId, reports.runId) }.getOrNull()
        // The fixed reader already captured diagnostic H once. Never reread it as display input.
        val legacyOnly = recorded.status == decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED
        val repairHistory = if (legacyOnly) readLegacyJsonReport(jobId, reports, LegacyJsonReport.REPAIR_HISTORY) else null
        val artifacts = runCatching { jobs.listArtifactSummaries(jobId, reports.runId, recorded, page) }.getOrNull()
        val repairEvidenceStates = repairHistory?.let { history -> artifacts?.let {
            repairEvidenceArtifactStates(jobId, reports, history, it)
        } }
        val recordedView = if (legacyOnly) null else recordedRepairEvidenceView(jobId, reports, recorded, artifacts, page, query.validationCasePageNumber)
        exchange.sendHtml(200, renderJobDocument(view.job, reports, view.diagnostics, source.getOrNull(), source.isFailure,
            progressSnapshot = progress,
            explorationReport = readLegacyJsonReport(jobId, reports, LegacyJsonReport.EXPLORATION),
            repairHistory = repairHistory,
            reconstructionProgress = readLegacyJsonReport(jobId, reports, LegacyJsonReport.RECONSTRUCTION_PROGRESS),
            artifacts = artifacts,
            repairEvidenceArtifactStates = repairEvidenceStates?.first,
            repairReceiptBindingStates = repairEvidenceStates?.second,
            recordedRepairHistory = recordedView))
    }

    /** Links need the same checked listing; receipt integrity is checked per canonical attempt. */
    private fun recordedRepairEvidenceView(jobId: String, context: WebReportContext,
        recorded: decompengine.repair.RepairHistoryReadResult, artifacts: List<WebArtifactSummary>?,
        page: decompengine.repair.RepairRecordedHistoryPage?, validationCasePageNumber: Int = 1): RecordedRepairHistoryView {
        val snapshot = recorded.snapshot?.takeIf { recorded.status == decompengine.repair.RepairHistoryReadStatus.RECORDED }
            ?: return RecordedRepairHistoryView(recorded, runId = context.runId)
        val selected = requireNotNull(page)
        require(selected.snapshot === snapshot) { "Recorded history page does not match its capture." }
        val targets = recordedRepairArtifactReferences(snapshot, selected).mapNotNull { reference ->
            recordedRepairEvidenceTarget(reference, snapshot, context, artifacts)?.let { reference to it }
        }.toMap()
        val captured = mutableMapOf<String, Result<ByteArray>>()
        var remainingWorkBytes = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES
        var readAttempts = 0
        fun readOnce(target: String, maximumBytes: Long = MAX_REPAIR_EVIDENCE_PRESENTATION_BYTES): Result<ByteArray> = captured.getOrPut(target) {
            val reserved = recordedRepairEvidenceReadReservation(maximumBytes, remainingWorkBytes)
            if (reserved == 0L || readAttempts >= 128) Result.failure(IllegalStateException("Repair evidence presentation allowance exhausted"))
            else {
                // Bound calls and captured payloads. Failed reads retain their full reservation.
                // This is a presentation allowance, not a hard RSS or execution-time guarantee.
                readAttempts++
                remainingWorkBytes -= reserved
                runCatching { jobs.readArtifact(jobId, target, reserved).bytes }.onSuccess { bytes ->
                    remainingWorkBytes += reserved - bytes.size
                }
            }
        }
        val normalBindings = buildList {
            if (selected.selection.evidenceAttempt != null) selected.evidenceAttempts.forEach { attempt ->
                attempt.validationObservation?.let { add(attempt.identity to it) }
            }
            selected.evidenceRuns.forEach { run -> run.baselineValidationObservation?.let { add(run.identity to it) } }
        }
        val observations = normalBindings.associate { (owner, binding) ->
            val primary = targets[binding.primary.artifact]?.let { readOnce(it, binding.primary.bytes).getOrNull() }
            val diff = binding.diff?.let { artifact -> targets[artifact.artifact]?.let { readOnce(it, artifact.bytes).getOrNull() } }
            owner to checkedRecordedRepairValidationObservation(binding, primary, diff, validationCasePageNumber)
        }
        val observedArtifactStates = buildMap {
            normalBindings.forEach { (owner, binding) ->
                val detail = observations.getValue(owner)
                put(binding.primary.artifact, detail.primaryState)
                binding.diff?.let { put(it.artifact, detail.diffState ?: RepairEvidenceArtifactState.UNAVAILABLE) }
            }
        }
        val genericReferences = buildSet {
            selected.evidenceAttempts.forEach { attempt ->
                attempt.before?.artifact?.let(::add); attempt.after?.artifact?.let(::add)
                attempt.invocation?.artifact?.let(::add)
            }
        }
        val evidence = targets.filterKeys { it in genericReferences }.mapValues { (reference, target) ->
            observedArtifactStates[reference]?.let { return@mapValues it }
            val bytes = readOnce(target).getOrElse { return@mapValues RepairEvidenceArtifactState.UNAVAILABLE }
            if (target.endsWith(".json") && runCatching { decompengine.oracle.core.OracleJson.parse(bytes) }.isFailure)
                RepairEvidenceArtifactState.CORRUPT else RepairEvidenceArtifactState.AVAILABLE
        }
        val receipts = selected.evidenceAttempts.filter { it.invocation != null }.associate { attempt ->
            val invocation = requireNotNull(attempt.invocation)
            val target = targets[invocation.artifact]
            val bytes = if (target == null || attempt.identity.rawIdentityWithheld) null else readOnce(target).getOrNull()
            val state = if (bytes == null) RepairEvidenceArtifactState.UNAVAILABLE else {
                val valid = runCatching {
                    require(sha256Hex(bytes) == invocation.receiptSha256)
                    val verified = verifyAcpExecutionReceiptDocument(bytes, TRACE_REPAIR_ACP_RECEIPT_KIND,
                        TRACE_REPAIR_ACP_TASK_FIELD, attempt.identity.value)
                    require(invocation.receiptSchemaVersion == 2)
                    require(verified.requestSha256 == invocation.requestSha256)
                    require(verified.resultChangesSha256 == invocation.resultChangesSha256)
                    require(decompengine.repair.recordedRepairTerminalSha256(verified.terminalOutcome) == invocation.terminalSha256)
                    require(verified.releaseComplete == invocation.receiptReleaseComplete)
                }.isSuccess
                if (valid) RepairEvidenceArtifactState.AVAILABLE else RepairEvidenceArtifactState.CORRUPT
            }
            attempt.identity to state
        }
        val diagnostics = selected.evidenceRuns.mapNotNull { run ->
            run.validationDiagnostic?.let { binding ->
                val primary = targets[binding.receipt]?.let { readOnce(it, binding.receiptBytes).getOrNull() }
                val diagnostic = targets[binding.diagnostic]?.let { readOnce(it, binding.diagnosticBytes.toLong()).getOrNull() }
                run.identity to checkedRecordedRepairValidationDiagnostic(binding, primary, diagnostic)
            }
        }.toMap()
        return RecordedRepairHistoryView(recorded, targets, evidence, receipts, selected, context.runId, diagnostics, observations,
            validationCasePageNumber)
    }

    private data class RepairReceiptExpectation(
        val receiptSha256: String,
        val receiptSchemaVersion: Int,
        val requestSha256: String,
        val resultChangesSha256: String,
        val terminalOutcome: String,
        val releaseComplete: Boolean,
        val attemptId: String,
    )

    /**
     * The history projection supplies paths, never authority. Links and these bounded integrity
     * reads are limited to the same checked artifact listing used by the download route.
     */
    private fun repairEvidenceArtifactStates(
        jobId: String,
        context: WebReportContext,
        history: JsonObject,
        artifacts: List<WebArtifactSummary>,
    ): Pair<Map<String, RepairEvidenceArtifactState>, Map<RepairReceiptBindingIdentity, RepairEvidenceArtifactState>> {
        val evidenceReferences = linkedSetOf<String>()
        val receiptReferences = linkedMapOf<RepairReceiptBindingIdentity, Pair<String, RepairReceiptExpectation?>>()
        for (record in history.getValue("iterations").jsonArray.map { it.jsonObject }) {
            for (field in listOf("before", "after")) {
                val evidence = record[field] as? JsonObject ?: continue
                val artifactPath = (evidence["artifactPath"] as? JsonPrimitive)?.contentOrNull
                val target = safeRepairEvidenceTarget(artifactPath, context, artifacts)
                    ?: continue
                evidenceReferences += target
            }
            val binding = record["agentInvocation"] as? JsonObject ?: continue
            val receiptPath = (binding["receiptPath"] as? JsonPrimitive)?.contentOrNull ?: continue
            val target = safeRepairEvidenceTarget(receiptPath, context, artifacts) ?: continue
            val identity = repairReceiptBindingIdentity(record) ?: continue
            val attemptId = identity.revisionId
                ?.takeIf { it.matches(Regex("revision_[0-9]{8}_[a-f0-9]{16}")) }
            val expectation = if (attemptId == null) null else runCatching {
                RepairReceiptExpectation(
                    requireNotNull(identity.receiptSha256),
                    requireNotNull(identity.receiptSchemaVersion),
                    requireNotNull(identity.requestSha256),
                    requireNotNull(identity.resultChangesSha256),
                    requireNotNull(identity.terminalOutcome),
                    requireNotNull(identity.receiptReleaseComplete),
                    attemptId,
                )
            }.getOrNull()
            receiptReferences[identity] = target to expectation
        }

        val artifactBytes = mutableMapOf<String, Result<ByteArray>>()
        fun readOnce(relativePath: String): Result<ByteArray> = artifactBytes.getOrPut(relativePath) {
            runCatching { jobs.readArtifact(jobId, relativePath, MAX_REPAIR_EVIDENCE_PRESENTATION_BYTES).bytes }
        }
        val evidenceStates = evidenceReferences.associateWith { relativePath ->
            val bytes = readOnce(relativePath).getOrElse { return@associateWith RepairEvidenceArtifactState.UNAVAILABLE }
            if (relativePath.endsWith(".json")) {
                if (runCatching { decompengine.oracle.core.OracleJson.parse(bytes) }.isSuccess)
                    RepairEvidenceArtifactState.AVAILABLE else RepairEvidenceArtifactState.CORRUPT
            } else RepairEvidenceArtifactState.AVAILABLE
        }
        val receiptStates = receiptReferences.mapValues { (_, reference) ->
            val (relativePath, receipt) = reference
            val bytes = readOnce(relativePath).getOrElse { return@mapValues RepairEvidenceArtifactState.UNAVAILABLE }
            if (receipt == null) {
                RepairEvidenceArtifactState.CORRUPT
            } else {
                val valid = runCatching {
                    require(sha256Hex(bytes) == receipt.receiptSha256)
                    val verified = verifyAcpExecutionReceiptDocument(
                        bytes, TRACE_REPAIR_ACP_RECEIPT_KIND, TRACE_REPAIR_ACP_TASK_FIELD, receipt.attemptId,
                    )
                    require(receipt.receiptSchemaVersion == 2)
                    require(verified.requestSha256 == receipt.requestSha256)
                    require(verified.resultChangesSha256 == receipt.resultChangesSha256)
                    require(verified.terminalOutcome == receipt.terminalOutcome)
                    require(verified.releaseComplete == receipt.releaseComplete)
                }.isSuccess
                if (valid) RepairEvidenceArtifactState.AVAILABLE else RepairEvidenceArtifactState.CORRUPT
            }
        }
        return evidenceStates to receiptStates
    }

    private fun sha256Hex(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private enum class LegacyJsonReport(val filename: String) {
        EXPLORATION("exploration.json"), REPAIR_HISTORY("repair_history.json"),
        RECONSTRUCTION_PROGRESS("reconstruction_progress.json"),
    }

    private fun readLegacyJsonReport(jobId: String, context: WebReportContext, report: LegacyJsonReport): kotlinx.serialization.json.JsonObject? =
        runCatching {
            val root = decompengine.oracle.core.OracleJson.parse(jobs.readArtifact(jobId,
                "${context.artifactPrefix}/${report.filename}", 1_048_576).bytes).jsonObject
            if (report == LegacyJsonReport.REPAIR_HISTORY) validateRepairHistoryProjection(root)
            root
        }.getOrNull()

    private fun handleSource(exchange: HttpExchange, jobId: String, relativePath: String) {
        require(relativePath.isNotBlank()) { "source path must not be blank" }
        val normalized = relativePath.replace('\\', '/')
        require(!normalized.startsWith('/') && normalized.split('/').none { it.isBlank() || it == ".." || it == "." }) {
            "source path must remain inside the generated tree"
        }
        val runId = exchange.requestURI.rawQuery?.let {
            require(it.matches(Regex("runId=[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "Only an exact workflow attempt selection is supported" }
            it.removePrefix("runId=")
        }
        val context = jobs.reportContext(jobId, runId)
        val source = sourceEvidence.read(jobId, context.artifactPrefix)
        val text = source.text(normalized)
        val currentBuild = runCatching { archiveEvidence.read(jobId, reportPrefix = context.artifactPrefix) }.getOrNull()
        exchange.sendHtml(200, renderSourceFile(
            jobs.get(jobId),
            normalized,
            text,
            context,
            source.manifestDocument,
            source.confidence,
            currentBuild?.manifestDocument == source.manifestDocument,
            source.moduleId(normalized),
        ))
    }

    private fun handleArtifact(exchange: HttpExchange, jobId: String, relativePath: String) {
        if (relativePath.endsWith("/source-tree.zip")) {
            val expected = exchange.requestURI.rawQuery?.let { query ->
                require(query.startsWith("sha256=") && '&' !in query) { "archive query must contain only one SHA-256 digest" }
                decode(query.removePrefix("sha256="))
            }
            val verified = archiveEvidence.read(jobId, expected, relativePath.removeSuffix("/source-tree.zip"))
            exchange.responseHeaders.add("ETag", "\"${verified.sha256}\"")
            exchange.sendUntrustedAttachment(200, verified.bytes, "application/zip", "source-tree.zip")
            return
        }
        val limit = if (isProgressJournalArtifact(relativePath)) AgentProgressJournal.MAXIMUM_READ_BYTES.toLong() else MAX_ARTIFACT_BYTES
        val artifact = jobs.readArtifact(jobId, relativePath, limit)
        val name = Path.of(relativePath).fileName
        exchange.sendUntrustedAttachment(200, progressArtifactProjection(relativePath, artifact.bytes), contentType(name), name.toString())
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)

    private companion object {
        const val MAX_ARTIFACT_BYTES = 64L * 1024 * 1024
        const val MAX_REPAIR_EVIDENCE_PRESENTATION_BYTES = 16L * 1024 * 1024
    }
}

private const val MAX_UPLOAD_BYTES = 32L * 1024 * 1024
private const val OVERLOAD_RESPONDER_THREAD = "decomp-web-overload"

private fun encodeJob(job: Job): String = Json.encodeToString(JsonElement.serializer(), legacyJobPresentation(job))

private fun webOrigin(host: String, port: Int): String {
    val authority = if (':' in host && !host.startsWith('[')) "[$host]" else host
    return "http://$authority:$port"
}

/** Legacy response adapter. Its caller must mint the typed mutation capability first. */
internal fun handleAuthorizedUploadRequest(
    exchange: HttpExchange,
    mutation: AuthorizedWebJobUpload,
    requestDiagnosticOutput: (String) -> Unit = System.err::println,
) {
    try {
        val declaredLength = exchange.requestHeaders.getFirst("Content-Length")?.toLongOrNull()
        require(declaredLength == null || declaredLength <= MAX_UPLOAD_BYTES) { "upload exceeds the 32 MiB limit" }
        val contentType = exchange.requestHeaders.getFirst("Content-Type") ?: ""
        val job = mutation.uploadMultipartReceipt(exchange.requestBody, contentType).job
        if (exchange.requestsLegacyJson()) {
            exchange.sendJson(201, encodeJob(job))
        } else {
            exchange.redirect("/jobs/${job.id}")
        }
    } catch (exception: WebJobServiceException) {
        val uncertain = exception.cause as? decompengine.jobs.UploadPublicationUncertain
        if (exception.code != "RECOVERY_REQUIRED" || uncertain == null) throw exception
        exchange.responseHeaders.set("Location", "/jobs/${uncertain.jobId}")
        if (exchange.requestsLegacyJson()) {
            sendCorrelatedLegacyJsonProblem(exchange, 409, "RECOVERY_REQUIRED",
                uploadPublicationProblem(uncertain.jobId).toString(), requestDiagnosticOutput)
        } else {
            exchange.sendHtml(409, renderUploadPublicationUncertainPage(uncertain.jobId))
        }
    }
}

/** Pure lifecycle coordinator: registration precedes the same single construction and start. */
internal fun <T : Any> startWebServerLifecycle(
    registerShutdown: (() -> Unit) -> (() -> Unit), create: (() -> Boolean) -> T,
    start: (T) -> Unit, stop: (T) -> Unit,
): T {
    val stopping = java.util.concurrent.atomic.AtomicBoolean(false)
    val published = java.util.concurrent.atomic.AtomicReference<T>()
    val removeHook = registerShutdown {
        stopping.set(true)
        published.get()?.let(stop)
    }
    fun cancelled() = stopping.get() || Thread.currentThread().isInterrupted
    try {
        check(!cancelled()) { "Web server startup cancelled" }
        val server = create(::cancelled)
        published.set(server)
        check(!cancelled()) { "Web server startup cancelled" }
        start(server)
        check(!cancelled()) { "Web server startup cancelled" }
        return server
    } catch (failure: Throwable) {
        var removeFailure: Throwable? = null
        var stopFailure: Throwable? = null
        try { removeHook() } catch (problem: Throwable) { removeFailure = problem }
        published.get()?.let { server -> try { stop(server) } catch (problem: Throwable) { stopFailure = problem } }
        if (removeFailure == null && stopFailure == null) throw failure
        // Never grow a retained primary failure's suppression list. Cleanup diagnostics own a fresh wrapper.
        val incomplete = try {
            IllegalStateException("Web startup cleanup did not complete; preserve storage before retrying.", failure).also { wrapper ->
                removeFailure?.let { if (it !== failure) wrapper.addSuppressed(it) }
                stopFailure?.let { if (it !== failure) wrapper.addSuppressed(it) }
            }
        } catch (_: Throwable) { throw failure }
        throw incomplete
    }
}

/** CLI factory form makes constructor recovery observe shutdown before the server exists. */
internal fun startWebServerWithShutdownHook(create: (() -> Boolean) -> UploadServer): UploadServer {
    val runtime = Runtime.getRuntime()
    return startWebServerLifecycle(registerShutdown = { action ->
        val hook = Thread({
            try { action() } catch (_: Exception) {
                System.err.println("Web shutdown did not complete cleanly; recovery is required")
            }
        }, "decomp-web-shutdown")
        runtime.addShutdownHook(hook)
        val remove: () -> Unit = {
            try { runtime.removeShutdownHook(hook) } catch (_: IllegalStateException) { }
            Unit
        }
        remove
    }, create = create, start = { it.start() }, stop = { it.stop() })
}

/** CLI lifecycle: allow owned workers to record interruption before the JVM exits. */
internal fun startWebServerWithShutdownHook(server: UploadServer) {
    val runtime = Runtime.getRuntime()
    val hook = Thread({
        try {
            server.stop()
        } catch (_: Exception) {
            System.err.println("Web shutdown did not complete cleanly; recovery is required")
        }
    }, "decomp-web-shutdown")
    runtime.addShutdownHook(hook)
    try {
        server.start()
    } catch (failure: Exception) {
        try { runtime.removeShutdownHook(hook) } catch (_: IllegalStateException) { }
        try { server.stop() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
        throw failure
    }
}

data class Upload(val filename: String, val content: ByteArray)

object MultipartUpload {
    fun parse(body: ByteArray, contentType: String): Upload {
        val bytes = ByteArrayOutputStream()
        val upload = StreamingMultipartUpload.copy(body.inputStream(), contentType, bytes)
        return Upload(upload.filename, bytes.toByteArray())
    }
}

private fun java.io.InputStream.readLimited(maxBytes: Long): ByteArray {
    val result = ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    var total = 0L
    while (true) {
        val read = read(buffer)
        if (read < 0) break
        total += read
        require(total <= maxBytes) { "upload exceeds the 32 MiB limit" }
        result.write(buffer, 0, read)
    }
    return result.toByteArray()
}

private fun HttpExchange.redirect(location: String) {
    responseHeaders.set("Location", location)
    responseHeaders.set("Cache-Control", "no-store")
    applyWebSecurityHeaders()
    sendResponseHeaders(303, -1)
    close()
}

internal fun HttpExchange.sendHtml(status: Int, document: WebApplicationDocument) =
    sendHtml(status, document.body, document.trustedInlineScripts)

internal fun HttpExchange.sendHtml(
    status: Int,
    body: String,
    trustedInlineScripts: Iterable<String> = listOf(LEGACY_SESSION_SCRIPT),
) =
    sendBytes(
        status,
        body.toByteArray(StandardCharsets.UTF_8),
        "text/html; charset=utf-8",
        contentSecurityPolicy = webApplicationContentSecurityPolicy(trustedInlineScripts),
    )

internal fun HttpExchange.sendJson(status: Int, body: String) =
    sendBytes(status, body.toByteArray(StandardCharsets.UTF_8), "application/json; charset=utf-8")

private fun HttpExchange.sendBytes(
    status: Int,
    body: ByteArray,
    contentType: String,
    cache: Boolean = false,
    contentSecurityPolicy: String = WEB_INERT_CONTENT_SECURITY_POLICY,
) {
    responseHeaders.set("Content-Type", contentType)
    applyWebSecurityHeaders(contentSecurityPolicy)
    responseHeaders.set("Cache-Control", if (cache) "public, max-age=3600" else "no-store")
    responseHeaders.set("Content-Length", body.size.toString())

    if (requestMethod == "HEAD") {
        sendResponseHeaders(status, -1)
        close()
    } else {
        sendResponseHeaders(status, body.size.toLong())
        responseBody.use { it.write(body) }
    }
}

private fun HttpExchange.sendUntrustedAttachment(
    status: Int,
    body: ByteArray,
    contentType: String,
    filename: String,
) {
    responseHeaders.set("Content-Disposition", attachmentDisposition(filename))
    responseHeaders.set(
        "Content-Security-Policy",
        "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'",
    )
    sendBytes(status, body, contentType)
}

internal fun attachmentDisposition(filename: String): String {
    val fallback = filename.asSequence()
        .map { character ->
            if (character.code in 0x21..0x7e && (character.isLetterOrDigit() || character in "._-")) character else '_'
        }
        .joinToString("")
        .take(128)
        .trim('.')
        .ifBlank { "artifact.bin" }
    val encoded = URLEncoder.encode(filename, StandardCharsets.UTF_8)
        .replace("+", "%20")
        .replace("*", "%2A")
    return "attachment; filename=\"$fallback\"; filename*=UTF-8''$encoded"
}

private fun contentType(path: Path): String = when (path.fileName.toString().substringAfterLast('.', "")) {
    "json" -> "application/json; charset=utf-8"
    "zip" -> "application/zip"
    "log", "txt", "c", "h", "md" -> "text/plain; charset=utf-8"
    else -> "application/octet-stream"
}

private const val AUTH_INSPECTION_FAILED = "{\"status\":\"failed\",\"loginSupported\":false,\"error\":\"Authentication inspection is unavailable. Check ACP configuration and cleanup.\"}"

private const val AUTH_INSPECTION_RUNNING = "{\"status\":\"inspecting\",\"loginSupported\":false}"

private const val AUTH_INSPECTION_CANCELLED = "{\"status\":\"cancelled\",\"loginSupported\":false}"

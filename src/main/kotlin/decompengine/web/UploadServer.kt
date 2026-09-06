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
import decompengine.jobs.toJson
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.EvidenceModuleReconstructor
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ModuleReconstructor
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ReconstructionProfile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import kotlin.io.path.pathString

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
)

/** Resolves exactly one web reconstruction mode without credential-based fallbacks. */
internal fun selectWebReconstructionStrategy(
    environment: Map<String, String>,
    progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
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
            )
        }
        WebReconstructionMode.EVIDENCE_ONLY.configurationValue -> WebReconstructionStrategy(
            WebReconstructionMode.EVIDENCE_ONLY,
            EvidenceModuleReconstructor(),
            null,
        )
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
    sourceProfiles: List<ReconstructionProfile> = listOf(GeneratedCMakeReconstructionProfile.descriptor),
    sensitiveValues: Collection<String> = System.getenv().values,
    private val listenBacklog: Int = 64,
    private val authenticationInspector: (decompengine.agent.AgentCancellation) -> decompengine.acp.AcpAuthenticationInventory = defaultWebAuthenticationInspector(),
) {
    init { require(listenBacklog in 1..4096) { "HTTP listen backlog must be between 1 and 4096" } }
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
            require(basePath == "/") { "--base-path is supported by --ui spa" }
            require(devFrontendOrigin == null) { "--dev-frontend-origin requires --ui spa" }
            null
        }
    }
    // Acquire cooperative ownership before binding so a refused contender never occupies a listener.
    private val ownership: WebJobStoreOwnership = WebJobStoreOwnership.acquire(dataDir.toAbsolutePath().normalize())
    private val server = HttpServer.create(InetSocketAddress(host, port), listenBacklog)
    private val store = JobStore(dataDir)
    private val jobs = WebJobService(store, analyzer, reconstructor, executor,
        attemptStoreFactory = { root ->
            // Storage creation is the upgrade point: claim the cross-JVM web lock as the root appears.
            ownership.ensureLockFile()
            WorkflowAttemptStore.open(root)
        },
        shutdownTimeoutMs = 5000, failureDiagnostic = { diagnostic(it, "Background operation failed") })
    private val sourceEvidence = WebSourceEvidence(store, sourceProfiles, jobs::readArtifact)
    private val archiveEvidence = WebArchiveEvidence(store, sourceEvidence, jobs::readArtifact)
    private val access = spaAssets?.let {
        LocalWebAccess(LocalWebAccessConfiguration(webOrigin(host, server.address.port), basePath,
            setOfNotNull(devFrontendOrigin)))
    }
    private val api = access?.let { WebApiController(it, checkNotNull(spaAssets), jobs) }
    private val requestExecutor = ThreadPoolExecutor(
        16, 16, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(64),
        { task -> Thread(task, "decomp-web-http").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val requestDeadlines = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "decomp-web-deadline").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }
    private val lifecycleLock = Any()
    private var stopping = false
    private var started = false
    private var activeRequests = 0
    private val startupCancellation = java.util.concurrent.atomic.AtomicBoolean(false)
    val serverPort: Int get() = server.address.port
    val browserOrigin: String = devFrontendOrigin ?: webOrigin(host, serverPort)

    /** The CLI calls this explicitly; no HTTP route can issue a local link. */
    fun issueBrowserBootstrap(): WebBootstrapToken = checkNotNull(access) { "Browser sessions require --ui spa" }.issueBootstrap()

    init {
        jobs.onQuiescent = {
            try {
                releaseOwnershipIfIdle()
            } catch (_: Exception) {
                System.err.println("Web request cleanup did not release store ownership; recovery is required")
            }
        }
        try {
            jobs.initializeExistingStorage()
        } catch (failure: Throwable) {
            server.stop(0)
            requestExecutor.shutdownNow()
            requestDeadlines.shutdownNow()
            access?.close()
            jobs.close()
            ownership.close()
            throw failure
        }
        server.executor = requestExecutor
        server.createContext("/") { exchange ->
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

    fun stop(delaySeconds: Int = 0) {
        require(delaySeconds >= 0) { "shutdown delay must be nonnegative" }
        // Signal recovery even while start holds lifecycleLock through filesystem operations.
        startupCancellation.set(true)
        val callerWasInterrupted = Thread.currentThread().isInterrupted
        val inspection = synchronized(lifecycleLock) {
>>>>>>> fe706797 (Propagate shutdown cancellation into web startup recovery [skip ci])
            stopping = true
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
        jobs.beginShutdown()
        server.stop(delaySeconds)
        requestExecutor.shutdownNow()
        requestDeadlines.shutdownNow()
        access?.close()
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
        if (inspectionWaitInterrupted) Thread.currentThread().interrupt()
        if (!releaseOwnershipIfIdle()) throw IllegalStateException("HTTP requests remain active after server stop")
    }

    /** Admission covers the whole handler, including upload publication and error handling. */
    internal fun withActiveRequest(action: () -> Unit): Boolean {
        synchronized(lifecycleLock) {
            if (stopping || startupCancellation.get()) return false
            activeRequests++
            // stop() publishes startupCancellation outside lifecycleLock, so a handler that read
            // the flag before the signal must still be refused when the signal preceded this
            // reservation instead of staying admitted past the stop request.
            if (startupCancellation.get()) {
                activeRequests--
                return false
            }
        }
        try {
            action()
            return true
        } finally {
            synchronized(lifecycleLock) { activeRequests-- }
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
            if (stopping && activeRequests == 0 && jobsIdle) {
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
            exchange.sendJson(400, "{\"error\":\"Explicit operator inspection is required.\"}")
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
                        check(!stopping) { "Server is stopping" }
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
        exchange.sendJson(admission.first, admission.second)
    }

    private fun authenticationInspectionSnapshot(result: String? = null): String = synchronized(authenticationInspectionLock) {
        // Every payload here is an internally serialized object; identity is an application-generated UUID.
        (result ?: authenticationInspectionResult.get()).dropLast(1) +
            ",\"inspectionId\":" + (authenticationInspectionId?.let { "\"$it\"" } ?: "null") + "}"
    }

    private fun inspectAuthenticationMethods(): String = try {
        val inventory = authenticationInspector(decompengine.agent.AgentCancellation { authenticationInspectionCancellation.get() })
        buildJsonObject {
            put("status", "ready")
            put("inventorySha256", inventory.sha256)
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
            exchange.sendJson(400, "{\"error\":\"Explicit operator cancellation is required.\"}")
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
        exchange.sendJson(response.first, response.second)
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
            when {
                exchange.requestMethod == "GET" && segments.isEmpty() ->
                    renderJobDashboard(exchange)
                exchange.requestMethod == "GET" && segments == listOf("assets", "app.css") ->
                    exchange.sendBytes(200, APP_CSS.toByteArray(), "text/css; charset=utf-8", cache = true)
                exchange.requestMethod == "GET" && segments == listOf("api", "recovery") ->
                    exchange.sendJson(200, store.recoveryInventory().toJson().toString())
                exchange.requestMethod == "POST" && segments == listOf("api", "operator", "auth-methods", "cancel") ->
                    handleAuthenticationCancellation(exchange)
                exchange.requestMethod == "GET" && segments == listOf("api", "operator", "auth-methods") ->
                    exchange.sendJson(200, authenticationInspectionSnapshot())
                exchange.requestMethod == "POST" && segments == listOf("api", "operator", "auth-methods") ->
                    handleAuthenticationInspection(exchange)
                exchange.requestMethod == "POST" && segments == listOf("jobs") -> handlePostJob(exchange)
                exchange.requestMethod == "GET" && segments.size == 2 && segments[0] == "jobs" ->
                    handleJob(exchange, decode(segments[1]))
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "explore" ->
                    handleExplore(exchange, decode(segments[1]))
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "reconstruct" ->
                    handleReconstruct(exchange, decode(segments[1]))
                exchange.requestMethod == "GET" && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "source" ->
                    handleSource(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod == "GET" && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "artifacts" ->
                    handleArtifact(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod == "GET" && segments.size == 3 && segments[0] == "api" && segments[1] == "jobs" ->
                    exchange.sendJson(200, encodeJob(jobs.get(decode(segments[2]))))
                exchange.requestMethod == "GET" && segments.size == 4 && segments[0] == "api" && segments[1] == "jobs" && segments[3] == "events" -> {
                    val job = jobs.get(decode(segments[2]))
                    val runId = exchange.requestURI.rawQuery?.let {
                        require(it.matches(Regex("runId=[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "Only an exact workflow attempt selection is supported" }
                        it.removePrefix("runId=")
                    }
                    val snapshot = AgentProgressJournal.read(jobs.reportContext(job.id, runId).reportsDirectory)
                    exchange.sendJson(200, snapshot?.toString() ?: "{\"schemaVersion\":1,\"displayOnly\":true,\"nextSequence\":0,\"queueDropped\":0,\"historyDropped\":0,\"truncated\":false,\"events\":[]}")
                }
                else -> exchange.sendHtml(404, renderErrorPage(404, "Page not found", "The requested route does not exist."))
            }
        } catch (exception: WebJobServiceException) {
            val status = if (exception.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND")) 404 else 503
            exchange.sendHtml(status, renderErrorPage(status, "Job storage unavailable", "${exception.code}: ${exception.message}"))
        } catch (exception: JobStoreException) {
            exchange.sendHtml(404, renderErrorPage(404, "Job not found", diagnostic(exception, "The job does not exist.")))
        } catch (exception: IllegalArgumentException) {
            exchange.sendHtml(400, renderErrorPage(400, "Invalid request", diagnostic(exception, "The request was invalid.")))
        } catch (exception: Exception) {
            exchange.sendHtml(500, renderErrorPage(500, "Unexpected error", diagnostic(exception, "The operation failed.")))
        }
    }

    private fun renderJobDashboard(exchange: HttpExchange) {
        val inspections = jobs.listInspections()
        exchange.sendHtml(200, renderDashboard(
            inspections.filterIsInstance<WebJobInspection.Available>().map { it.presentation.job },
            inspections.filterIsInstance<WebJobInspection.Unavailable>().map { it.diagnostic },
            store.recoveryInventory(),
        ))
    }

    private fun routeSpaPreview(exchange: HttpExchange, assets: EmbeddedWebAssets) {
        val path = exchange.requestURI.rawPath
        if (path.startsWith(assets.assetPrefix)) {
            assets.serveAsset(exchange)
            return
        }
        val base = assets.basePath
        val canonical = when (path) {
            base, "${base}runtime", "${base}upload" -> path
            base.removeSuffix("/").ifEmpty { "/" } -> base
            "${base}runtime/" -> "${base}runtime"
            "${base}upload/" -> "${base}upload"
            else -> path.takeIf { it.startsWith("${base}jobs/") &&
                it.removePrefix("${base}jobs/").matches(Regex("[0-9a-f]{32}(?:/runs(?:/[A-Za-z0-9][A-Za-z0-9_-]{0,127})?)?/?")) }?.removeSuffix("/")
        }
        if (canonical != null) {
            if (path != canonical && exchange.requestMethod in setOf("GET", "HEAD")) {
                val query = exchange.requestURI.rawQuery?.let { "?$it" }.orEmpty()
                exchange.responseHeaders.set("Location", canonical + query)
                exchange.responseHeaders.set("Cache-Control", "no-store")
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
            handleUploadRequest(exchange, jobs)
        } catch (exception: InvalidUploadException) {
            exchange.sendHtml(400, renderErrorPage(400, "Unsupported binary", diagnostic(exception, "Upload a Linux ELF binary.")))
        }
    }

    private fun handleExplore(exchange: HttpExchange, jobId: String) {
        schedule(exchange, jobId, WebWorkflow.EXPLORE)
    }

    private fun handleReconstruct(exchange: HttpExchange, jobId: String) {
        schedule(exchange, jobId, WebWorkflow.RECONSTRUCT)
    }

    private fun schedule(
        exchange: HttpExchange,
        jobId: String,
        workflow: WebWorkflow,
    ) {
        when (jobs.start(jobId, workflow)) {
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
    private fun handleJob(exchange: HttpExchange, jobId: String) {
        val view = jobs.presentation(jobId)
        val source = runCatching { archiveEvidence.read(jobId, reportPrefix = view.reports.artifactPrefix).source }
            .recoverCatching { sourceEvidence.read(jobId, view.reports.artifactPrefix).view() }
        exchange.sendHtml(200, renderJob(view.job, view.reports, view.diagnostics, source.getOrNull(), source.isFailure))
    }

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
        ))
    }

    private fun handleArtifact(exchange: HttpExchange, jobId: String, relativePath: String) {
        if (relativePath.endsWith("/source-tree.zip")) {
            val expected = exchange.requestURI.rawQuery?.let { query ->
                require(query.startsWith("sha256=") && '&' !in query) { "archive query must contain only one SHA-256 digest" }
                decode(query.removePrefix("sha256="))
            }
            val verified = archiveEvidence.read(jobId, expected, relativePath.removeSuffix("/source-tree.zip"))
            exchange.responseHeaders.add("Content-Disposition", "attachment; filename=\"source-tree.zip\"")
            exchange.responseHeaders.add("ETag", "\"${verified.sha256}\"")
            exchange.sendBytes(200, verified.bytes, "application/zip")
            return
        }
        val artifact = jobs.readArtifact(jobId, relativePath, MAX_ARTIFACT_BYTES)
        val name = Path.of(relativePath).fileName
        exchange.responseHeaders.add("Content-Disposition", "attachment; filename=\"${name.toString().replace("\"", "")}\"")
        exchange.sendBytes(200, artifact.bytes, contentType(name))
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)

    private companion object {
        const val MAX_ARTIFACT_BYTES = 64L * 1024 * 1024
    }
}

private const val MAX_UPLOAD_BYTES = 32L * 1024 * 1024

private fun encodeJob(job: Job): String = Json.encodeToString(JsonElement.serializer(), job.toJson())

private fun webOrigin(host: String, port: Int): String {
    val authority = if (':' in host && !host.startsWith('[')) "[$host]" else host
    return "http://$authority:$port"
}

/** Shared HTTP upload handler; the server owns admission and general error redaction around it. */
internal fun handleUploadRequest(exchange: HttpExchange, jobs: WebJobService) {
    try {
        val declaredLength = exchange.requestHeaders.getFirst("Content-Length")?.toLongOrNull()
        require(declaredLength == null || declaredLength <= MAX_UPLOAD_BYTES) { "upload exceeds the 32 MiB limit" }
        val contentType = exchange.requestHeaders.getFirst("Content-Type") ?: ""
        val job = jobs.uploadMultipart(exchange.requestBody, contentType)
        if ((exchange.requestHeaders.getFirst("Accept") ?: "").contains("application/json")) {
            exchange.sendJson(201, encodeJob(job))
        } else {
            exchange.redirect("/jobs/${job.id}")
        }
    } catch (exception: WebJobServiceException) {
        val uncertain = exception.cause as? decompengine.jobs.UploadPublicationUncertain
        if (exception.code != "RECOVERY_REQUIRED" || uncertain == null) throw exception
        exchange.responseHeaders.set("Location", "/jobs/${uncertain.jobId}")
        if ((exchange.requestHeaders.getFirst("Accept") ?: "").contains("application/json")) {
            exchange.sendJson(409, uploadPublicationProblem(uncertain.jobId).toString())
        } else {
            exchange.sendHtml(409, renderUploadPublicationUncertainPage(uncertain.jobId))
        }
    }
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
    responseHeaders.add("Location", location)
    sendResponseHeaders(303, -1)
    close()
}

private fun HttpExchange.sendHtml(status: Int, body: String) =
    sendBytes(status, body.toByteArray(StandardCharsets.UTF_8), "text/html; charset=utf-8")

private fun HttpExchange.sendJson(status: Int, body: String) =
    sendBytes(status, body.toByteArray(StandardCharsets.UTF_8), "application/json; charset=utf-8")

private fun HttpExchange.sendBytes(
    status: Int,
    body: ByteArray,
    contentType: String,
    cache: Boolean = false,
) {
    responseHeaders.add("Content-Type", contentType)
    responseHeaders.add("X-Content-Type-Options", "nosniff")
    responseHeaders.add("Referrer-Policy", "no-referrer")
    responseHeaders.add(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    )
    responseHeaders.add("Cache-Control", if (cache) "public, max-age=3600" else "no-store")
    sendResponseHeaders(status, body.size.toLong())
    responseBody.use { it.write(body) }
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

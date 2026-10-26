package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.JobStoreException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.time.Clock
import java.util.UUID

/** Versioned presentation only. Job paths and workflow adapters never enter a JSON response. */
internal class WebApiController(
    private val access: LocalWebAccess,
    private val assets: EmbeddedWebAssets,
    private val jobs: WebJobService,
    private val jobMutations: WebJobMutationBoundary,
    streamResources: WebStreamResources,
    clock: Clock = Clock.systemUTC(),
    private val harnessReadiness: WebHarnessReadinessProjector = WebHarnessReadinessProjector(),
    private val agentPreflight: WebAgentPreflight = WebAgentPreflight { error("No agent preflight is configured.") },
    private val git: WebGitCapability = WebGitCapability.detect(),
    archiveEvidence: WebArchiveEvidence? = null,
) : AutoCloseable {
    private val prefix = "${assets.basePath}api/v1/"
    private val applicationBuildId = applicationBuildId()
    // The build hash is stable across restarts; this identity belongs to one listener lifetime.
    private val serverInstanceId = UUID.randomUUID().toString()
    private val sessions = WebSessionController(access)
    private val uploadProgress = WebUploadProgress()
    private val progressPins = WebProgressPinController(access, jobs, jobMutations)
    private val workflowStarts = WebWorkflowStartController(jobs, jobMutations, assets.basePath) { request ->
        webAdmissionPrerequisites(jobs.durableRegistrations(), request, readiness().prerequisites, harnessReadiness::inspectSandbox)
    }
    private val cancellations = WebCancellationController(jobMutations, assets.basePath)
    private val recoveries = WebRecoveryController(jobs, jobMutations, assets.basePath) { workflow, harness ->
        webAdmissionPrerequisites(jobs.durableRegistrations(), workflow, harness, readiness().prerequisites, harnessReadiness::inspectSandbox)
    }
    private val agentPreflights = WebAgentPreflightController(access, agentPreflight, assets.basePath)
    private val gitRoutes = WebGitController(access, jobs, jobMutations, git, assets.basePath)
    private val runPages = WebRunPages { jobId ->
        when (val inspection = jobs.inspectDurableJob(jobId)) {
            is decompengine.jobs.WorkflowJobInspection.Available -> inspection.snapshot
            is decompengine.jobs.WorkflowJobInspection.Unavailable -> throw WebJobServiceException(inspection.diagnostic.code, inspection.diagnostic.message)
        }
    }
    private val progressPages = WebProgressPages()
    private val sourceCatalogPages = WebSourceCatalogPages(jobs::readSourceCatalog)
    private val revisionSourcePages = WebRevisionSourcePages(jobs::readRevisionSources)
    private val revisionDirectoryPages = WebRevisionDirectoryPages(jobs::readRevisionSources)
    private val revisionFileMetadata = WebRevisionFileMetadata(jobs::readRevisionFileMetadata)
    private val revisionSourceSearch = WebRevisionSourceSearch(jobs::searchRevisionSources)
    private val revisionSourceDiffs = WebRevisionSourceDiffs(jobs::readRevisionSources, content = { job, run, revision, file, metadataVersion ->
        jobs.readRevisionSourceFile(job, run, revision, file, WebSourceReadPurpose.PREVIEW, metadataVersion)
    })
    private val artifactStore = WebJobArtifactStore(jobs)
    private val artifactCatalog = WebArtifactCatalog(artifactStore)
    private val sourceArchives = archiveEvidence?.let { evidence ->
        WebSourceArchives(jobs::readRevisionSources, jobs::getAttempt, artifactStore, { job, run ->
            try { jobs.readArtifact(job, "reports/runs/$run/source-tree/reports/build_contract.json", 1_048_576).bytes }
            catch (failure: Exception) { if (failure is InterruptedException) throw failure; null }
        }, { job, run, digest -> evidence.read(job, digest, "reports/runs/$run") },
            java.util.concurrent.Executors.newSingleThreadExecutor { task -> Thread(task, "decomp-archive-verifier").apply { isDaemon = true } },
            jobs::revisionSourceReference, clock)
    }
    private val artifactContent = WebArtifactContent(artifactStore)
    internal val artifactDownloads = WebArtifactDownloads()
    private val revisionValidationReports = WebRevisionValidationReports(jobs::readRecordedValidationReport)
    private val eventStream = WebEventStream(access, streamResources, progressPages, read = { jobId, runId ->
        readWebProgress(jobs, jobId, runId).second
    }, clock = clock, deleted = { jobId -> jobs.deletedJob(jobId) != null })
    private val jobPages = WebJobPages(jobs::collectionRecords, checkpointedSource = jobs::collectionRecordsWithProgress)
    private val lifecycle = WebJobLifecycleController(access, jobs, jobMutations, assets.basePath, jobPages::invalidate)

    // One private resource pattern per line, so independent route additions merge cleanly.
    // One private resource pattern per line, so independent route additions merge cleanly.
    // One private resource pattern per line, so independent route additions merge cleanly.
    private val privateResources = listOf(
        "(?:jobs|uploads)/[^/]+",
        "jobs/[^/]+/runs",
        "jobs/[^/]+/runs/[^/]+",
        "jobs/[^/]+/runs/[^/]+/reports/(?:exploration|revision-validation)",
        "jobs/[^/]+/runs/[^/]+/validation-history",
        "jobs/[^/]+/runs/[^/]+/source-catalog",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/sources",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-directories/[^/]+",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-files/[^/]+(?:/(?:chunk|content))?",
        "jobs/[^/]+/runs/[^/]+/snapshot",
        "jobs/[^/]+/runs/[^/]+/events",
        "jobs/[^/]+/runs/[^/]+/progress-pin",
        "jobs/[^/]+/runs/[^/]+/cancel",
        "jobs/[^/]+/runs/[^/]+/recover",
        "jobs/[^/]+/runs/[^/]+/controls",
        "jobs/[^/]+/artifacts/[^/]+/content",
        "jobs/[^/]+/runs/[^/]+/queue-position",
        "jobs/[^/]+/repositories(?:/[^/]+(?:/operations/[^/]+)?)?",
        "jobs/[^/]+/(?:deletion-preview|operations/[^/]+)",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-search",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-diff(?:/(?:file|patch))?",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-archive",
        "jobs/[^/]+/runs/[^/]+/revisions/[^/]+/archive-verifications(?:/[^/]+)?",
        "jobs/[^/]+/artifacts(?:/[^/]+)?",
    ).map(::Regex)

    fun route(exchange: HttpExchange): Boolean {
        val path = exchange.requestURI.rawPath
        if (!path.startsWith("${assets.basePath}api/")) return false
        val resource = path.removePrefix(prefix)
        if (!path.startsWith(prefix) || !(resource in setOf("session", "bootstrap", "jobs", "recovery", "agent/preflight", "storage", "storage/maintenance-preview") || privateResources.any { resource.matches(it) })) {
            try {
                val policy = if (exchange.requestMethod in setOf("POST", "PUT", "PATCH", "DELETE")) {
                    WebEndpointPolicy.jsonMutation(exchange.requestMethod)
                } else WebEndpointPolicy.privateRead(allowHead = true)
                access.authorize(exchange, policy)
                access.sendDenied(exchange, WebAccessDenied(404, "NOT_FOUND", "The requested API route is unavailable."))
            } catch (failure: WebAccessDenied) {
                access.sendDenied(exchange, failure)
            } catch (_: Exception) {
                if (exchange.responseCode != -1) exchange.close()
                else access.sendDenied(exchange, WebAccessDenied(500, "INTERNAL_ERROR", "The request could not be completed."))
            }
            return true
        }
        try {
            when {
                resource == "session" -> sessions.handle(exchange)
                resource == "recovery" -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireNoWebApiQuery(exchange)
                    requireJsonAccept(exchange)
                    sendWebApiResponse(exchange, 200, "recovery", jobs.recoveryInventory().toJson())
                }
                resource == "jobs" && exchange.requestMethod == "POST" -> {
                    val mutation = jobMutations.authorizeUpload(exchange)
                    requireNoWebApiQuery(exchange)
                    requireJsonAccept(exchange)
                    val key = singleUploadHeader(exchange, "Idempotency-Key")
                    if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Upload requires one 16–128 character idempotency key.")
                    if (exchange.requestHeaders.containsKey("If-Match")) throw WebAccessDenied(400, "INVALID_HEADER", "Upload creates a new job and does not accept If-Match.")
                    val length = singleUploadHeader(exchange, "Content-Length")
                    if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) throw WebAccessDenied(400, "INVALID_HEADER", "The upload Content-Length is invalid.")
                    val uploadId = singleUploadHeader(exchange, "X-Upload-ID")
                    if (uploadId != null && !uploadId.matches(Regex("[a-f0-9]{32}"))) throw WebAccessDenied(400, "INVALID_UPLOAD_ID", "Upload progress requires one canonical transfer identity.")
                    val progress = uploadId?.let { uploadProgress.begin(mutation.sessionId, it, length?.toLong()?.takeIf { size -> size <= StreamingMultipartUpload.MAX_REQUEST_BYTES }) }
                    val result = try {
                        mutation.uploadMultipartReceipt(exchange.requestBody, checkNotNull(singleUploadHeader(exchange, "Content-Type")), key, progress)
                            .also { progress?.finish(it.job.id) }
                    } finally { progress?.finish() }
                    exchange.responseHeaders.set("Location", "${assets.basePath}api/v1/jobs/${result.job.id}")
                    if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
                    sendWebApiResponse(exchange, 201, "job", webJob(result.job))
                }
                resource.startsWith("uploads/") -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val id = resource.removePrefix("uploads/")
                    if (!id.matches(Regex("[a-f0-9]{32}"))) throw WebAccessDenied(404, "NOT_FOUND", "Upload progress is unavailable.")
                    val progress = uploadProgress.read(session.sessionId, id) ?: throw WebAccessDenied(404, "NOT_FOUND", "Upload progress is unavailable or expired.")
                    sendWebApiResponse(exchange, 200, "uploadProgress", buildJsonObject {
                        put("uploadId", progress.uploadId); put("receivedBytes", progress.receivedBytes.toString())
                        put("totalBytes", progress.totalBytes?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
                        put("state", progress.state); put("jobId", progress.jobId?.let { JsonPrimitive(it) } ?: JsonNull)
                    })
                }
                resource.matches(Regex("jobs/[^/]+/artifacts/[^/]+/content")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireNoWebApiQuery(exchange)
                    if (!acceptsWebMediaType(exchange, "application/octet-stream")) {
                        throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/octet-stream.")
                    }
                    val parts = resource.split('/')
                    jobs.downloadLease(parts[1]).use {
                        artifactDownloads.admit(session.sessionId) { artifactContent.send(exchange, parts[1], parts[3]) }
                    }
                }
                resource.matches(Regex("jobs/[^/]+/artifacts/[^/]+")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "artifact", artifactCatalog.detail(parts[1], parts[3], assets.basePath, webExchangeCancellation(exchange)))
                }
                resource.matches(Regex("jobs/[^/]+/artifacts")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireJsonAccept(exchange)
                    sendWebApiResponse(exchange, 200, "artifacts", artifactCatalog.page(session.sessionId, resource.split('/')[1],
                        exchange.requestURI.rawQuery, assets.basePath, webExchangeCancellation(exchange)))
                }
                resource == "agent/preflight" -> agentPreflights.handle(exchange)
                resource.matches(Regex("jobs/[^/]+/repositories(?:/[^/]+(?:/operations/[^/]+)?)?")) -> gitRoutes.handle(exchange, resource.split('/'))
                resource == "storage" || resource == "storage/maintenance-preview" -> lifecycle.storage(exchange, resource != "storage")
                resource.matches(Regex("jobs/[^/]+/deletion-preview")) -> lifecycle.deletionPreview(exchange, resource.split('/')[1])
                resource.matches(Regex("jobs/[^/]+/operations/[^/]+")) -> {
                    val parts = resource.split('/')
                    lifecycle.operation(exchange, parts[1], parts[3])
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/cancel")) -> {
                    val parts = resource.split('/')
                    cancellations.handle(exchange, parts[1], parts[3])
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/recover")) -> {
                    val parts = resource.split('/')
                    recoveries.handle(exchange, parts[1], parts[3])
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/controls")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    val controls = jobs.attemptControls(parts[1], parts[3])
                    exchange.responseHeaders.set("ETag", "\"${controls.attempt.version}\"")
                    sendWebApiResponse(exchange, 200, "attemptControls", controls.toJson())
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/progress-pin")) -> {
                    val parts = resource.split('/')
                    progressPins.handle(exchange, parts[1], parts[3])
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/(?:snapshot|events)")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    val parts = resource.split('/')
                    val snapshot = parts[4] == "snapshot"
                    if (!snapshot) WebProgressQuery.parse(exchange.requestURI.rawQuery)
                    val explicitPoll = exchange.requestURI.rawQuery?.split('&')?.any { it.substringBefore('=') == "transport" } == true
                    if (!snapshot && !explicitPoll && acceptsWebMediaType(exchange, "text/event-stream", explicit = true)) {
                        eventStream.open(exchange, session, parts[1], parts[3], "${prefix}jobs/${parts[1]}/runs/${parts[3]}/snapshot")
                        return true
                    }
                    requireJsonAccept(exchange)
                    if (snapshot) requireNoWebApiQuery(exchange)
                    else {
                        if (exchange.requestHeaders.containsKey("Last-Event-ID")) throw WebAccessDenied(
                            400, "UNSUPPORTED_HEADER", "Polling resumes with after or cursor; Last-Event-ID is reserved for streams.",
                        )
                    }
                    val (attempt, bytes) = readWebProgress(jobs, parts[1], parts[3])
                    if (snapshot) {
                        val boundary = progressPages.boundary(session.sessionId, parts[1], parts[3], bytes)
                        sendWebApiResponse(exchange, 200, "snapshot", buildJsonObject {
                            put("run", webRun(attempt))
                            put("throughCursor", boundary.throughCursor?.let(::JsonPrimitive) ?: JsonNull)
                            put("throughSequence", boundary.throughSequence?.let(::JsonPrimitive) ?: JsonNull)
                            put("oldestCursor", boundary.oldestCursor?.let(::JsonPrimitive) ?: JsonNull)
                            put("progress", buildJsonObject {
                                put("authority", "observations"); put("nextSequence", boundary.nextSequence)
                                put("queueDropped", boundary.queueDropped); put("historyDropped", boundary.historyDropped)
                                put("retainedEventCount", boundary.retainedEventCount)
                            })
                        })
                    } else sendWebApiResponse(exchange, 200, "events", progressPages.page(session.sessionId, parts[1], parts[3], bytes, exchange.requestURI.rawQuery, "${prefix}jobs/${parts[1]}/runs/${parts[3]}/snapshot"))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-files/[^/]+")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireJsonAccept(exchange)
                    requireNoWebApiQuery(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "revisionFile", revisionFileMetadata.read(parts[1], parts[3], parts[5], parts[7],
                        sourceInventoryIncludesManifest(exchange.requestHeaders["X-Decomp-Source-Inventory"])))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-files/[^/]+/(?:chunk|content)")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    if (exchange.requestHeaders.keys.any { it.equals("Range", true) || it.startsWith("If-", true) }) {
                        throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Source reads use explicit chunk offsets and do not support Range or conditional headers.")
                    }
                    val parts = resource.split('/')
                    if (parts[8] == "chunk") {
                        requireJsonAccept(exchange)
                        val query = WebSourceChunkQuery.parse(exchange.requestURI.rawQuery)
                        val content = jobs.readRevisionSourceFile(parts[1], parts[3], parts[5], parts[7], WebSourceReadPurpose.PREVIEW, query.metadataVersion)
                        sendWebApiResponse(exchange, 200, "sourceChunk", content.chunk(query))
                    } else jobs.downloadLease(parts[1]).use {
                        val metadataVersion = parseWebSourceDownloadVersion(exchange.requestURI.rawQuery)
                        if (!acceptsWebMediaType(exchange, "application/octet-stream")) {
                            throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/octet-stream.")
                        }
                        val content = jobs.readRevisionSourceFile(parts[1], parts[3], parts[5], parts[7], WebSourceReadPurpose.DOWNLOAD, metadataVersion)
                        sendWebAttachment(exchange, content.download(), content.downloadName, content.verifiedDownloadHeaders())
                    }
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-directories/[^/]+")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "revisionDirectory", revisionDirectoryPages.page(session.sessionId,
                        parts[1], parts[3], parts[5], parts[7], exchange.requestURI.rawQuery,
                        sourceInventoryIncludesManifest(exchange.requestHeaders["X-Decomp-Source-Inventory"])))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-search")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "sourceSearch",
                        revisionSourceSearch.search(session.sessionId, parts[1], parts[3], parts[5], exchange.requestURI.rawQuery))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-diff(?:/file)?")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    val query = exchange.requestURI.rawQuery
                    if (parts.size == 7) sendWebApiResponse(exchange, 200, "sourceDiff",
                        revisionSourceDiffs.summary(session.sessionId, parts[1], parts[3], parts[5], query))
                    else sendWebApiResponse(exchange, 200, "sourceFileDiff", revisionSourceDiffs.file(parts[1], parts[3], parts[5], query))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-diff/patch")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    if (exchange.requestHeaders.keys.any { it.equals("Range", true) || it.startsWith("If-", true) }) {
                        throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Source patches do not support Range or conditional headers.")
                    }
                    if (!acceptsWebMediaType(exchange, "application/octet-stream")) {
                        throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/octet-stream.")
                    }
                    val parts = resource.split('/')
                    val patch = revisionSourceDiffs.patch(parts[1], parts[3], parts[5], exchange.requestURI.rawQuery)
                    sendWebAttachment(exchange, patch.bytes, patch.fileName, patch.headers)
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-archive")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireJsonAccept(exchange); requireNoWebApiQuery(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "sourceArchive", archives().status(assets.basePath, parts[1], parts[3], parts[5]))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/archive-verifications")) && exchange.requestMethod == "POST" -> {
                    access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST"))
                    requireJsonAccept(exchange); requireNoWebApiQuery(exchange)
                    val key = singleUploadHeader(exchange, "Idempotency-Key")
                    if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
                        throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Archive verification requires one 16–128 character idempotency key.")
                    }
                    if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) }) {
                        throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Archive verification binds the displayed digest in its body, not in conditional headers.")
                    }
                    val parts = resource.split('/')
                    val started = archives().start(parts[1], parts[3], parts[5], readArchiveVerificationRequest(exchange), key)
                    exchange.responseHeaders.set("Location", "${prefix}jobs/${parts[1]}/runs/${parts[3]}/revisions/${parts[5]}/archive-verifications/${started.record.operationId}")
                    if (started.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
                    sendWebApiResponse(exchange, 202, "operation", webArchiveOperation(started.record))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/archive-verifications/[^/]+")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireJsonAccept(exchange); requireNoWebApiQuery(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "operation", webArchiveOperation(archives().operation(parts[1], parts[3], parts[5], parts[7])))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/revisions/[^/]+/sources")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true)))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "revisionSources",
                        revisionSourcePages.page(session.sessionId, parts[1], parts[3], parts[5], exchange.requestURI.rawQuery,
                            sourceInventoryIncludesManifest(exchange.requestHeaders["X-Decomp-Source-Inventory"])))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/source-catalog")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "sourceCatalog",
                        sourceCatalogPages.page(session.sessionId, parts[1], parts[3], exchange.requestURI.rawQuery))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/validation-history")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "validationHistory", revisionValidationReports.history(
                        parts[1], parts[3], exchange.requestURI.rawQuery, jobs::readValidationHistory))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/reports/revision-validation")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                    requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    val query = exchange.requestURI.rawQuery
                    val report = if (query?.split('&')?.any { it.substringBefore('=') == "historyFailureRun" } == true)
                        revisionValidationReports.failure(parts[1], parts[3], query, jobs::readRecordedValidationFailureReport)
                    else revisionValidationReports.read(parts[1], parts[3], query)
                    sendWebApiResponse(exchange, 200, "report", report)
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/reports/exploration")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    val attempt = jobs.getAttempt(parts[1], parts[3])
                    val bytes = try { jobs.readArtifact(parts[1], "reports/runs/${attempt.runId}/exploration.json", 1_048_576).bytes }
                        catch (_: JobStoreException) { null }
                    if (jobs.getAttempt(parts[1], parts[3]).version != attempt.version) throw WebJobServiceException("REPORT_CHANGED", "The attempt changed during this read. Refresh its evidence.")
                    sendWebApiResponse(exchange, 200, "report", webExplorationReport(parts[1], parts[3], bytes, assets.basePath))
                }
                resource.matches(Regex("jobs/[^/]+/runs")) && exchange.requestMethod == "POST" -> {
                    workflowStarts.handle(exchange, resource.split('/')[1])
                }
                resource.matches(Regex("jobs/[^/]+/runs")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireJsonAccept(exchange)
                    sendWebApiResponse(exchange, 200, "runs", runPages.page(session.sessionId, resource.split('/')[1], exchange.requestURI.rawQuery))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/queue-position")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "queuePosition", webQueuePosition(parts[1], parts[3], jobs.queuePosition(parts[1], parts[3])))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    sendWebApiResponse(exchange, 200, "run", webRun(jobs.getAttempt(parts[1], parts[3])))
                }
                resource == "jobs" -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireJsonAccept(exchange)
                    val (query, cursor) = WebJobQuery.parse(exchange.requestURI.rawQuery)
                    sendWebApiResponse(exchange, 200, "jobs", jobPages.page(session.sessionId, query, cursor))
                }
                resource == "bootstrap" -> {
                    val credentials = access.csrfForSession(exchange)
                    requireNoWebApiQuery(exchange)
                    requireJsonAccept(exchange)
                    sendWebApiResponse(exchange, 200, "bootstrap", bootstrap(credentials))
                }
                exchange.requestMethod == "PATCH" -> lifecycle.patch(exchange, resource.removePrefix("jobs/"))
                exchange.requestMethod == "DELETE" -> lifecycle.delete(exchange, resource.removePrefix("jobs/"))
                else -> {
                    if (exchange.requestMethod != "GET") {
                        access.authorize(exchange, WebEndpointPolicy.transport(setOf("GET", "PATCH", "DELETE")))
                    }
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoWebApiQuery(exchange)
                    requireJsonAccept(exchange)
                    val selected = resource.removePrefix("jobs/")
                    if (jobs.deletedJob(selected) != null) throw WebAccessDenied(410, "RESOURCE_GONE", "This job was deleted. Only its deletion record is retained.")
                    val value = webJob(jobs.presentation(selected))
                    val etag = "\"${value.getValue("version").let { (it as JsonPrimitive).content }}\""
                    exchange.responseHeaders.set("ETag", etag)
                    if (exchange.requestHeaders.getFirst("If-None-Match") == etag) {
                        webApiHeaders(exchange, UUID.randomUUID().toString())
                        exchange.sendResponseHeaders(304, -1)
                        exchange.close()
                    } else sendWebApiResponse(exchange, 200, "job", value)
                }
            }
        } catch (failure: WebAccessDenied) {
            access.sendDenied(exchange, failure)
        } catch (_: decompengine.jobs.UploadIdempotencyConflict) {
            access.sendDenied(exchange, WebAccessDenied(409, "IDEMPOTENCY_CONFLICT", "The upload key was already used for different content or filename."))
        } catch (_: decompengine.jobs.UploadReceiptUnavailable) {
            access.sendDenied(exchange, WebAccessDenied(503, "UPLOAD_RECEIPT_UNAVAILABLE", "The retained upload receipt is unavailable. Inspect storage before retrying."))
        } catch (failure: UploadBodyException) {
            val status = when (failure.reasonCode) { "UPLOAD_TOO_LARGE" -> 413; "UNSUPPORTED_MEDIA_TYPE" -> 415; else -> 400 }
            access.sendDenied(exchange, WebAccessDenied(status, failure.reasonCode, failure.message ?: "The upload body is invalid."))
        } catch (_: decompengine.jobs.InvalidUploadException) {
            access.sendDenied(exchange, WebAccessDenied(422, "INVALID_ELF", "Upload a supported ELF binary with a complete header."))
        } catch (failure: WebJobServiceException) {
            val uncertain = failure.cause as? decompengine.jobs.UploadPublicationUncertain
            if (failure.code == "RECOVERY_REQUIRED" && uncertain != null && uncertain.jobId.matches(Regex("[a-f0-9]{32}"))) {
                exchange.responseHeaders.set("Location", "${assets.basePath}api/v1/jobs/${uncertain.jobId}")
                access.sendDenied(exchange, WebAccessDenied(409, "RECOVERY_REQUIRED", publicWebDiagnosticMessage(failure.code)))
            } else if (failure.code == "UPLOAD_KEY_RETIRED") {
                access.sendDenied(exchange, WebAccessDenied(410, "RESOURCE_GONE", "The job created with this upload key was deleted. Upload again with a new key."))
            } else if (failure.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND") && deletedJobResource(resource)) {
                access.sendDenied(exchange, WebAccessDenied(410, "RESOURCE_GONE", "This job was deleted. Only its deletion record is retained."))
            } else {
                val status = if (failure.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND")) 404 else if (failure.code == "ARTIFACT_CHANGED") 409 else 503
                access.sendDenied(exchange, WebAccessDenied(status, if (status == 404) "NOT_FOUND" else publicWebDiagnosticCode(failure.code),
                    publicWebDiagnosticMessage(failure.code)))
            }
        } catch (_: JobStoreException) {
            access.sendDenied(exchange, if (deletedJobResource(resource)) WebAccessDenied(410, "RESOURCE_GONE", "This job was deleted. Only its deletion record is retained.")
                else WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable."))
        } catch (_: Exception) {
            if (exchange.responseCode != -1) exchange.close()
            else access.sendDenied(exchange, WebAccessDenied(500, "INTERNAL_ERROR", "The request could not be completed."))
        }
        return true
    }

    private fun bootstrap(credentials: WebSessionCredentials): JsonObject = buildJsonObject {
        put("apiVersions", JsonArray(listOf(JsonPrimitive(1))))
        put("applicationBuildId", applicationBuildId)
        put("uiBuildId", assets.manifest.buildId)
        put("serverInstanceId", serverInstanceId)
        put("basePath", assets.basePath)
        put("readiness", "degraded")
        put("sessionExpiresAt", credentials.session.expiresAt.toString())
        put("csrfToken", credentials.csrfToken)
        val readiness = readiness()
        put("capabilities", JsonArray(webWorkflowCapabilities(jobs.durableRegistrations(), readiness) + harnessCapability(readiness) + git.capabilities()))
        // Configured ceilings for the API profile; unavailable resources remain
        // unavailable until their adapters enforce these limits and are enabled.
        put("limits", buildJsonObject {
            put("requestDeadlineMs", "30000")
            put("uploadDeadlineMs", "120000")
            put("downloadIdleMs", "120000")
            put("maxJsonBytes", "1048576")
            put("maxUploadBytes", StreamingMultipartUpload.MAX_REQUEST_BYTES.toString())
            // The chunk reader enforces 4..131072 bytes per range over digest-verified inputs of at most 8 MiB.
            put("maxSourceChunkBytes", WebRevisionSourceContent.MAXIMUM_CHUNK_BYTES.toString())
            put("maxLogChunkBytes", "0")
            put("maxEventCount", "1024")
            put("maxEventBytes", "2097152")
            put("terminalEventRetentionMs", if (jobs.progressRetentionStatus().enabled) decompengine.jobs.AgentProgressJournalRetention.DEFAULT_TERMINAL_RETENTION.toMillis().toString() else "0")
            put("defaultPageLimit", 50)
            put("maxPageLimit", 200)
        })
        put("runtime", buildJsonObject {
            put("javaVersion", Runtime.version().toString().take(64))
            put("osName", when (System.getProperty("os.name").lowercase()) {
                "linux" -> "linux"
                "mac os x" -> "macos"
                else -> if (System.getProperty("os.name").lowercase().startsWith("windows")) "windows" else "unknown"
            })
            put("architecture", when (System.getProperty("os.arch").lowercase()) {
                "amd64", "x86_64" -> "x86_64"
                "aarch64", "arm64" -> "aarch64"
                else -> "unknown"
            })
            put("gitVersion", git.versionJson())
            put("scheduler", webSchedulerSnapshot(jobs.schedulerSnapshot()))
            put("progressRetention", webProgressRetentionStatus(jobs.progressRetentionStatus()))
        })
    }

    // Configuration-only and cached: reports whether a harness is selectable, never that a workflow can run.
    // Passive on page load: helper checks fold in only from a recent explicit operator inspection.
    private fun readiness(): WebHarnessReadiness = harnessReadiness.current().withAgentInspection(agentPreflight.snapshot())

    private fun harnessCapability(readiness: WebHarnessReadiness): JsonObject {
        return buildJsonObject {
            put("id", "harness")
            put("state", readiness.state)
            put("reasonCode", readiness.reasonCode?.let { JsonPrimitive(it) } ?: JsonNull)
            put("message", readiness.message)
            put("workflows", JsonArray(emptyList()))
            put("agentContractVersion", JsonNull)
            put("limits", JsonNull)
            put("launch", JsonNull)
        }
    }

    /** Reached only after a handler authorized the session and a service read found no job. */
    private fun deletedJobResource(resource: String): Boolean {
        val jobId = Regex("jobs/([0-9a-f]{32})(?:/.*)?").matchEntire(resource)?.groupValues?.get(1) ?: return false
        return try { jobs.deletedJob(jobId) != null } catch (_: Exception) { false }
    }

    private fun archives(): WebSourceArchives = sourceArchives
        ?: throw WebAccessDenied(503, "ARCHIVE_VERIFICATION_UNAVAILABLE", "Source archive verification is unavailable in this server.")

    override fun close() { sourceArchives?.close() }

    private fun singleUploadHeader(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256) throw WebAccessDenied(400, "INVALID_HEADER", "An upload header is duplicated or too long.")
        return values.single()
    }
}

private fun applicationBuildId(): String {
    val source = WebApiController::class.java.protectionDomain.codeSource.location
    if (source.protocol != "file") return "unavailable"
    val path = java.nio.file.Path.of(source.toURI())
    if (!java.nio.file.Files.isRegularFile(path)) return "development"
    val digest = MessageDigest.getInstance("SHA-256")
    java.nio.file.Files.newInputStream(path).use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val size = input.read(buffer)
            if (size < 0) break
            digest.update(buffer, 0, size)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/** Bounded in-memory attachment: inert octet stream, encoded filename, and bodyless HEAD. */
private fun sendWebAttachment(exchange: HttpExchange, bytes: ByteArray, fileName: String, headers: Map<String, String>) {
    val name = java.net.URLEncoder.encode(fileName, Charsets.UTF_8).replace("+", "%20").replace("*", "%2A")
    webApiHeaders(exchange, UUID.randomUUID().toString())
    exchange.responseHeaders.set("Content-Type", "application/octet-stream")
    exchange.responseHeaders.set("Content-Disposition", "attachment; filename=\"source.bin\"; filename*=UTF-8''$name")
    exchange.responseHeaders.set("Content-Security-Policy", "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'")
    exchange.responseHeaders.set("Content-Length", bytes.size.toString())
    headers.forEach { (key, value) -> exchange.responseHeaders.set(key, value) }
    try {
        if (exchange.requestMethod == "HEAD" || bytes.isEmpty()) exchange.sendResponseHeaders(200, -1)
        else {
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
    } finally { exchange.close() }
}

/** Strict bounded `archiveVerificationRequest` body: the one archive digest the caller displayed. */
private fun readArchiveVerificationRequest(exchange: HttpExchange): String {
    val bytes = exchange.requestBody.use { it.readNBytes(1025) }
    if (bytes.size > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The archive verification request exceeds its 1024-byte limit.")
    val value = try { decompengine.oracle.core.OracleJson.parse(bytes, decompengine.oracle.core.StrictJsonLimits(1024, 1024, 4, 8, 128, 512, 8)) }
        catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The archive verification request must be bounded strict JSON.") }
    fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", "Archive verification accepts only one canonical archiveSha256.")
    // HTTP carries the validated request data only, as for the other JSON mutations.
    val data = value as? JsonObject ?: invalid()
    if (data.keys != setOf("archiveSha256")) invalid()
    return (data["archiveSha256"] as? JsonPrimitive)?.takeIf { it.isString && it.content.matches(Regex("[a-f0-9]{64}")) }?.content ?: invalid()
}

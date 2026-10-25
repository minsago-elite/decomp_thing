package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.git.GitOperationRecord
import decompengine.git.GitRepositoryRecord
import decompengine.git.GitRepositoryRequest
import decompengine.git.GitWorkspaceView
import decompengine.git.GitWorkspaceVersions
import decompengine.git.GitMappingView
import decompengine.git.ManagedGitException
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Managed repository routes (#571-#573): `GET`/`POST J/repositories`, `GET G` and
 * `GET G/operations/{operationId}`. Every route is capability-gated; reads never run a write,
 * fetch or checkout, and the mutation boundary authorizes before any body or service read.
 */
internal class WebGitController(
    private val access: LocalWebAccess,
    private val jobs: WebJobService,
    private val jobMutations: WebJobMutationBoundary,
    private val git: WebGitCapability,
    private val basePath: String,
) {
    private val reads = WebGitReads { git.repositories() }
    private val operations = WebGitOperations({ git.repositories() }, basePath)

    fun handle(exchange: HttpExchange, parts: List<String>) {
        val jobId = parts[1]
        val workspaceChange = parts.size == 5 && parts[4] == "operations"
        val cancel = parts.size == 7 && parts[4] == "operations" && parts[6] == "cancel"
        if (cancel) {
            if (exchange.requestMethod != "POST") throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "Cancellation is requested with POST.", setOf("POST"))
            return cancel(exchange, jobMutations.authorizeGitRepository(exchange), jobId, parts[3], parts[5])
        }
        val mutation = if ((parts.size == 3 || workspaceChange) && exchange.requestMethod == "POST") jobMutations.authorizeGitRepository(exchange) else null
        if (mutation == null) {
            access.authorize(exchange, WebEndpointPolicy.privateRead())
            if (exchange.requestMethod != "GET") throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "This repository resource is read-only.",
                if (parts.size == 3 || workspaceChange) setOf("GET", "POST") else setOf("GET"))
            if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-None-Match", true) }) {
                throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Repository reads do not support conditional headers.")
            }
        }
        if (workspaceChange && mutation == null) throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "Repository operations are created with POST.", setOf("POST"))
        val read = parts.size == 5 && !workspaceChange && parts[4] != "worktrees"
        val nested = parts.size == 6 && parts[4] in setOf("worktrees", "provenance", "exports", "conflicts") ||
            parts.size == 5 && parts[4] == "worktrees"
        if (!read && !(nested && parts[4] == "conflicts")) requireNoWebApiQuery(exchange)
        if (!(nested && parts[4] == "exports")) requireJsonAccept(exchange)
        if (!jobId.matches(JOB) || (if (read || workspaceChange || nested) listOfNotNull(parts[3], parts.getOrNull(5)?.takeIf { parts[4] == "worktrees" }) else parts.drop(3).filterIndexed { index, _ -> index != 1 }).any { !it.matches(ID) }) {
            throw WebAccessDenied(404, "NOT_FOUND", "The requested repository resource is unavailable.")
        }
        // A job must exist before any repository fact is disclosed; it also supplies the job version guard.
        jobs.presentation(jobId)
        val repositories = git.repositories()
        try {
            when {
                workspaceChange -> operations.handle(exchange, checkNotNull(mutation), jobId, parts[3])
                mutation != null -> {
                    val match = header(exchange, "If-Match")
                        ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "Creating a repository requires the current job version in If-Match.")
                    if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\""))) {
                        throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong job version.")
                    }
                    val key = header(exchange, "Idempotency-Key")
                    if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
                        throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Creating a repository requires one bounded idempotency key.")
                    }
                    if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) }) {
                        throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for repository creation.")
                    }
                    val request = readRequest(exchange)
                    val expected = match.removeSurrounding("\"")
                    // Keyed replay precedes the fresh guard, so an old If-Match still replays its original result.
                    val admission = mutation.request(repositories, jobId, request, key) {
                        val current = (webJob(jobs.presentation(jobId)).getValue("version") as JsonPrimitive).content
                        if (current != expected) throw WebAccessDenied(412, "VERSION_CONFLICT", "The job changed. Refresh it before creating a repository.")
                    }
                    val operation = admission.operation
                    exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/$jobId/repositories/${operation.repositoryId}/operations/${operation.operationId}")
                    exchange.responseHeaders.set("ETag", "\"${operation.version}\"")
                    if (admission.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
                    sendWebApiResponse(exchange, 202, "operation", webGitOperation(operation))
                }
                parts.size == 3 -> {
                    val listing = repositories.listing(jobId)
                    sendWebApiResponse(exchange, 200, "gitRepositories", buildJsonObject {
                        put("jobId", jobId)
                        put("repositories", JsonArray(listing.repositories.map(::webGitRepositorySummary)))
                        put("operations", JsonArray(listing.operations.map(::webGitOperation)))
                    })
                }
                read -> reads.handle(exchange, jobId, parts[3], parts[4])
                nested -> reads.nested(exchange, jobId, parts[3], parts[4], parts.getOrNull(5))
                parts.size == 4 -> {
                    val workspace = webGitWorkspace(repositories.workspace(jobId, parts[3]))
                    val etag = "\"${(workspace.getValue("worktreeVersion") as JsonPrimitive).content}\""
                    exchange.responseHeaders.set("ETag", etag)
                    sendWebApiResponse(exchange, 200, "gitWorkspace", workspace)
                }
                else -> {
                    val operation = repositories.operation(jobId, parts[3], parts[5])
                    exchange.responseHeaders.set("ETag", "\"${operation.version}\"")
                    sendWebApiResponse(exchange, 200, "operation", webGitOperation(operation))
                }
            }
        } catch (failure: ManagedGitException) {
            throw webGitDenied(failure)
        }
    }

    /**
     * `POST G/operations/{id}/cancel` (#594): stop a queued or running transfer. `If-Match` names
     * the operation version that was reviewed; a finished operation is returned unchanged.
     */
    private fun cancel(exchange: HttpExchange, mutation: AuthorizedWebGitRepository, jobId: String, repositoryId: String, operationId: String) {
        requireNoWebApiQuery(exchange)
        requireJsonAccept(exchange)
        if (!jobId.matches(JOB) || listOf(repositoryId, operationId).any { !it.matches(ID) }) {
            throw WebAccessDenied(404, "NOT_FOUND", "The requested repository resource is unavailable.")
        }
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "Cancelling requires the reviewed operation version in If-Match.")
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Cancelling requires one bounded idempotency key.")
        }
        val bytes = exchange.requestBody.use { it.readNBytes(257) }
        val body = try { OracleJson.parse(bytes, StrictJsonLimits(256, 256, 2, 4, 64, 256, 4)) } catch (_: Exception) {
            throw WebAccessDenied(400, "MALFORMED_JSON", "The cancellation must be bounded strict JSON.")
        }
        if (body !is JsonObject || body.keys != setOf("action") || (body["action"] as? JsonPrimitive)?.content != "git.cancel") {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "A cancellation contains only {\"action\": \"git.cancel\"}.")
        }
        jobs.presentation(jobId)
        val repositories = git.repositories()
        val operation = try {
            val current = repositories.operation(jobId, repositoryId, operationId)
            if (match != "\"${current.version}\"") throw WebAccessDenied(412, "VERSION_CONFLICT", "The operation changed. Read it again before cancelling.")
            mutation.cancel(repositories, jobId, repositoryId, operationId)
        } catch (failure: ManagedGitException) { throw webGitDenied(failure) }
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/$jobId/repositories/$repositoryId/operations/$operationId")
        sendWebApiResponse(exchange, 202, "operation", webGitOperation(operation))
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }

    private fun readRequest(exchange: HttpExchange): GitRepositoryRequest {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > MAX_BODY) tooLarge()
        val bytes = exchange.requestBody.use { it.readNBytes(MAX_BODY + 1) }
        if (bytes.size > MAX_BODY) tooLarge()
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 2, 8, MAX_STRING_BYTES, MAX_BODY, 16)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The repository request must be bounded strict JSON.") }
        val body = value as? JsonObject ?: invalid()
        return when (text(body["action"])) {
            "git.init" -> {
                if (body.keys != setOf("action", "runId", "revisionId", "initialBranch")) invalid()
                val branch = body["initialBranch"].let { if (it == JsonNull) null else text(it).takeIf { name -> name.length in 1..200 } ?: invalid() }
                GitRepositoryRequest.Init(id(body["runId"]), id(body["revisionId"]), branch)
            }
            "git.attach" -> {
                if (body.keys != setOf("action", "sourceName")) invalid()
                GitRepositoryRequest.Attach(text(body["sourceName"]).takeIf { it.matches(SOURCE_NAME) } ?: invalid())
            }
            "git.clone" -> {
                if (body.keys != setOf("action", "url", "remoteName", "branch")) invalid()
                val branch = body["branch"].let { if (it == JsonNull) null else text(it).takeIf { name -> name.length in 1..200 } ?: invalid() }
                decompengine.git.GitCloneRequest(text(body["url"]).takeIf { it.length in 1..2048 } ?: invalid(),
                    text(body["remoteName"]).takeIf { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) } ?: invalid(), branch)
            }
            else -> invalid()
        }
    }

    private fun text(value: JsonElement?): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun id(value: JsonElement?): String = text(value).takeIf { it.matches(ID) } ?: invalid()
    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The repository request exceeds its 4096-byte limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
        "The repository request must contain only a declared action: init with its run, revision and branch, attach with one admitted source name, or clone with its URL, remote name and branch.")

    private companion object {
        const val MAX_BODY = 4096
        // Room for the largest declared field: a 2048-character clone URL.
        const val MAX_STRING_BYTES = 2048
        val JOB = Regex("[0-9a-f]{32}")
        val ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
        val SOURCE_NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    }
}

/** Fixed public status for every service refusal; messages are the service's path-free texts. */
internal fun webGitDenied(failure: ManagedGitException): WebAccessDenied {
    val message = failure.message?.take(500) ?: "The repository request could not be completed."
    return when (failure.code) {
        "CAPABILITY_UNAVAILABLE", "IMPORT_UNAVAILABLE", "SERVER_DRAINING" -> WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", message)
        "NOT_FOUND" -> WebAccessDenied(404, "NOT_FOUND", message)
        "REPOSITORY_EXISTS", "WORKTREE_BUSY", "IDEMPOTENCY_CONFLICT", "REF_CHANGED", "WORKTREE_CHANGED", "INDEX_CHANGED",
        "SELECTION_CHANGED", "SELECTION_OVERLAP", "CONFLICTED", "NOTHING_TO_COMMIT", "ACTIVE_RUN", "WORKTREE_DIRTY", "BRANCH_EXISTS", "TAG_EXISTS",
        "BRANCH_UNMERGED", "BRANCH_CURRENT", "WORKTREE_UNMERGED", "WORKTREE_PRIMARY", "SWITCH_REFUSED", "REF_CONFLICT",
        "REMOTE_EXISTS", "NOT_CANCELLABLE", "MERGE_IN_PROGRESS", "NOTHING_TO_INTEGRATE", "FAST_FORWARD_UNAVAILABLE", "NO_MERGE",
        "CONTENT_CHANGED", "DETACHED", "NO_COMMITS", "MERGE_REFUSED", "ABORT_REFUSED", "PUSH_UNCONFIRMED", "REMOTE_CHANGED", "NON_FAST_FORWARD",
        "NOTHING_TO_PUSH", "PUSH_REJECTED", "GITHUB_NOT_BOUND", "GITHUB_READ_ONLY", "BRANCH_NOT_PUBLISHED", "PR_UNCONFIRMED" ->
            WebAccessDenied(409, failure.code, message)
        "GITHUB_UNAVAILABLE" -> WebAccessDenied(503, failure.code, message)
        "STRATEGY_UNSUPPORTED", "UNSUPPORTED_CONFLICT", "UNRESOLVED_MARKERS" -> WebAccessDenied(422, failure.code, message)
        "TRANSPORT_UNSUPPORTED", "CREDENTIAL_IN_URL", "DESTINATION_NOT_ALLOWED" -> WebAccessDenied(422, failure.code, message)
        "REMOTES_UNAVAILABLE", "HOST_KEY_UNVERIFIED", "CREDENTIAL_UNAVAILABLE" -> WebAccessDenied(503, failure.code, message)
        "QUOTA_EXCEEDED" -> WebAccessDenied(429, "QUOTA_EXCEEDED", message)
        "VALIDATION_FAILED", "SOURCE_REVISION_UNAVAILABLE", "IMPORT_SOURCE_UNAVAILABLE", "EXCLUDED_PATH", "NOTHING_SELECTED",
        "STATUS_INCOMPLETE", "SIZE_EXCEEDED", "PATCH_UNAVAILABLE" -> WebAccessDenied(422, failure.code, message)
        "SIGNING_UNAVAILABLE" -> WebAccessDenied(503, failure.code, message)
        "REPOSITORY_UNSUPPORTED", "REPOSITORY_CORRUPT", "REPOSITORY_CONFIG_UNTRUSTED", "REPOSITORY_UNAVAILABLE" ->
            WebAccessDenied(503, failure.code, message)
        else -> WebAccessDenied(503, "STORAGE_UNAVAILABLE", "Repository storage is unavailable. Preserve it and inspect the server.")
    }
}

internal fun webGitRefId(repositoryId: String, name: String) = GitWorkspaceVersions.refId(repositoryId, name)

internal fun webGitRefVersion(name: String, objectId: String) = GitWorkspaceVersions.refVersion(name, objectId)

internal fun webGitOperation(operation: GitOperationRecord): JsonObject = buildJsonObject {
    put("operationId", operation.operationId)
    put("jobId", operation.jobId)
    put("repositoryId", operation.repositoryId)
    put("worktreeId", operation.worktreeId)
    put("action", operation.action.wireName)
    put("state", operation.state.wireName)
    put("version", operation.version)
    put("createdAt", operation.createdAt.toString())
    put("endedAt", operation.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
    put("resultObjectId", operation.resultObjectId?.let(::JsonPrimitive) ?: JsonNull)
    put("recoveryRequired", operation.recoveryRequired)
    put("message", operation.message)
    put("progress", operation.progress?.let { progress ->
        buildJsonObject { put("phase", progress.phase); put("percent", progress.percent?.let(::JsonPrimitive) ?: JsonNull) }
    } ?: JsonNull)
}

internal fun webGitRepositorySummary(repository: GitRepositoryRecord): JsonObject = buildJsonObject {
    put("repositoryId", repository.repositoryId)
    put("worktreeId", repository.worktreeId)
    put("operationId", repository.operationId)
    put("origin", repository.origin)
    put("objectFormat", repository.objectFormat.wireName)
    put("trackingPolicy", repository.trackingPolicy)
    put("createdAt", repository.createdAt.toString())
    put("runId", repository.runId?.let(::JsonPrimitive) ?: JsonNull)
    put("candidateRevisionId", repository.candidateRevisionId?.let(::JsonPrimitive) ?: JsonNull)
}

/**
 * Ref IDs are stable per repository and name; versions change with the observed object. HEAD's
 * branch is always listed, even when the 200-ref bound truncates the rest.
 */
internal fun webGitWorkspace(view: GitWorkspaceView): JsonObject {
    val record = view.record
    val observation = view.observation
    val head = observation.head
    return buildJsonObject {
        put("repositoryId", record.repositoryId)
        put("worktreeId", view.worktreeId)
        put("repositoryVersion", GitWorkspaceVersions.repositoryVersion(record, observation))
        put("worktreeVersion", GitWorkspaceVersions.worktreeVersion(observation))
        put("objectFormat", observation.objectFormat.wireName)
        put("origin", record.origin)
        put("trackingPolicy", record.trackingPolicy)
        put("headObjectId", head.objectId?.let(::JsonPrimitive) ?: JsonNull)
        put("headRefId", GitWorkspaceVersions.headRefId(record, observation)?.let(::JsonPrimitive) ?: JsonNull)
        put("headState", head.state.wireName)
        put("headRefName", head.refName?.let(::JsonPrimitive) ?: JsonNull)
        put("candidateRevisionId", record.candidateRevisionId?.let(::JsonPrimitive) ?: JsonNull)
        put("dirty", observation.dirty)
        put("refs", JsonArray(GitWorkspaceVersions.refs(observation).map { ref ->
            buildJsonObject {
                put("refId", GitWorkspaceVersions.refId(record.repositoryId, ref.name)); put("displayName", ref.name)
                put("objectId", ref.objectId); put("version", GitWorkspaceVersions.refVersion(ref.name, ref.objectId))
            }
        }))
        // A commit maps to a reconstruction revision only through an explicit, validated record.
        put("mapping", view.mapping?.let(::webGitMapping) ?: JsonNull)
    }
}

internal fun webGitMapping(mapping: GitMappingView): JsonObject = buildJsonObject {
    put("repositoryId", mapping.record.repositoryId)
    put("objectId", mapping.record.objectId)
    put("revisionId", mapping.record.revisionId)
    put("sourceSha256", mapping.record.sourceSha256)
    put("archiveArtifactId", JsonNull)
    put("acceptance", mapping.acceptance)
    put("acceptanceArtifactId", mapping.acceptanceArtifactId?.let(::JsonPrimitive) ?: JsonNull)
}

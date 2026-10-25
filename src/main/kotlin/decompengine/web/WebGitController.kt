package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.git.GitHeadState
import decompengine.git.GitOperationRecord
import decompengine.git.GitRefObservation
import decompengine.git.GitRepositoryRecord
import decompengine.git.GitRepositoryRequest
import decompengine.git.GitWorkspaceView
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
import java.security.MessageDigest

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

    fun handle(exchange: HttpExchange, parts: List<String>) {
        val jobId = parts[1]
        val mutation = if (parts.size == 3 && exchange.requestMethod == "POST") jobMutations.authorizeGitRepository(exchange) else null
        if (mutation == null) {
            access.authorize(exchange, WebEndpointPolicy.privateRead())
            if (exchange.requestMethod != "GET") throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "This repository resource is read-only.",
                if (parts.size == 3) setOf("GET", "POST") else setOf("GET"))
            if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-None-Match", true) }) {
                throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Repository reads do not support conditional headers.")
            }
        }
        val read = parts.size == 5
        if (!read) requireNoWebApiQuery(exchange)
        requireJsonAccept(exchange)
        if (!jobId.matches(JOB) || (if (read) listOf(parts[3]) else parts.drop(3).filterIndexed { index, _ -> index != 1 }).any { !it.matches(ID) }) {
            throw WebAccessDenied(404, "NOT_FOUND", "The requested repository resource is unavailable.")
        }
        // A job must exist before any repository fact is disclosed; it also supplies the job version guard.
        jobs.presentation(jobId)
        val repositories = git.repositories()
        try {
            when {
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
            else -> invalid()
        }
    }

    private fun text(value: JsonElement?): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun id(value: JsonElement?): String = text(value).takeIf { it.matches(ID) } ?: invalid()
    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The repository request exceeds its 2048-byte limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
        "The repository request must contain only a declared action with its run, revision and branch, or one admitted source name.")

    private companion object {
        const val MAX_BODY = 2048
        // Room for the largest declared field: a 200-character branch name of 4-byte UTF-8 characters.
        const val MAX_STRING_BYTES = 800
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
        "REPOSITORY_EXISTS", "WORKTREE_BUSY", "IDEMPOTENCY_CONFLICT" -> WebAccessDenied(409, failure.code, message)
        "QUOTA_EXCEEDED" -> WebAccessDenied(429, "QUOTA_EXCEEDED", message)
        "VALIDATION_FAILED", "SOURCE_REVISION_UNAVAILABLE", "IMPORT_SOURCE_UNAVAILABLE", "PATCH_UNAVAILABLE" -> WebAccessDenied(422, failure.code, message)
        "REPOSITORY_UNSUPPORTED", "REPOSITORY_CORRUPT", "REPOSITORY_CONFIG_UNTRUSTED", "REPOSITORY_UNAVAILABLE" ->
            WebAccessDenied(503, failure.code, message)
        else -> WebAccessDenied(503, "STORAGE_UNAVAILABLE", "Repository storage is unavailable. Preserve it and inspect the server.")
    }
}

private fun digest(prefix: String, text: String): String = prefix + MessageDigest.getInstance("SHA-256")
    .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(32)

internal fun webGitRefId(repositoryId: String, name: String) = digest("ref_", "$repositoryId\n$name")

internal fun webGitRefVersion(name: String, objectId: String) = digest("ref_v_", "$name\n$objectId")

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
    fun refId(name: String) = webGitRefId(record.repositoryId, name)
    val headRef = if (head.state == GitHeadState.ATTACHED) GitRefObservation(checkNotNull(head.refName), checkNotNull(head.objectId)) else null
    val refs = (listOfNotNull(headRef) + observation.refs.filter { it != headRef }).take(200)
    val refsText = refs.joinToString("") { "${it.name}\u0000${it.objectId}\n" }
    return buildJsonObject {
        put("repositoryId", record.repositoryId)
        put("worktreeId", record.worktreeId)
        put("repositoryVersion", digest("repository_v_", "${record.repositoryId}\n${record.operationId}\n${observation.refsTruncated}\n$refsText"))
        put("worktreeVersion", digest("worktree_v_", observation.statusDigest))
        put("objectFormat", observation.objectFormat.wireName)
        put("origin", record.origin)
        put("trackingPolicy", record.trackingPolicy)
        put("headObjectId", head.objectId?.let(::JsonPrimitive) ?: JsonNull)
        put("headRefId", headRef?.let { JsonPrimitive(refId(it.name)) } ?: JsonNull)
        put("headState", head.state.wireName)
        put("headRefName", head.refName?.let(::JsonPrimitive) ?: JsonNull)
        put("candidateRevisionId", record.candidateRevisionId?.let(::JsonPrimitive) ?: JsonNull)
        put("dirty", observation.dirty)
        put("refs", JsonArray(refs.map { ref ->
            buildJsonObject {
                put("refId", refId(ref.name)); put("displayName", ref.name); put("objectId", ref.objectId)
                put("version", webGitRefVersion(ref.name, ref.objectId))
            }
        }))
        // No commit is mapped to a source revision until an explicit, validated commit records one.
        put("mapping", JsonNull)
    }
}

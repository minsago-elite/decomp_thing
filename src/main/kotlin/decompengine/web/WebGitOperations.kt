package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.git.GitCommitRequest
import decompengine.git.GitGuards
import decompengine.git.GitRepositoryRequest
import decompengine.git.GitStageRequest
import decompengine.git.ManagedGitException
import decompengine.git.ManagedGitRepositories
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * `POST G/operations` (#576, #577): a closed typed intent with its reviewed guards and the exact
 * file identities it acts on. `If-Match` must name the guarded work-tree version. The server
 * rechecks every guard before Git runs; viewing never stages, commits or contacts a remote.
 */
internal class WebGitOperations(private val repositories: () -> ManagedGitRepositories, private val basePath: String) {
    fun handle(exchange: HttpExchange, mutation: AuthorizedWebGitRepository, jobId: String, repositoryId: String) {
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "A repository change requires the reviewed work-tree version in If-Match.")
        if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\""))) {
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong work-tree version.")
        }
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "A repository change requires one bounded idempotency key.")
        }
        if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) }) {
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for repository changes.")
        }
        val (request, guards) = readRequest(exchange)
        if (match.removeSurrounding("\"") != guards.worktreeVersion) {
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must name the same work-tree version as the request guards.")
        }
        val service = repositories()
        val operation = try {
            val admission = mutation.requestWorkspace(service, jobId, repositoryId, request, key)
            if (admission.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
            // Small local actions usually finish quickly; the durable operation stays authoritative.
            if (admission.replayed) admission.operation
            else service.awaitOperation(jobId, repositoryId, admission.operation.operationId, 3000)
        } catch (failure: ManagedGitException) { throw webGitDenied(failure) }
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/$jobId/repositories/$repositoryId/operations/${operation.operationId}")
        exchange.responseHeaders.set("ETag", "\"${operation.version}\"")
        sendWebApiResponse(exchange, 202, "operation", webGitOperation(operation))
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }

    private fun readRequest(exchange: HttpExchange): Pair<GitRepositoryRequest, GitGuards> {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > MAX_BODY) tooLarge()
        val bytes = exchange.requestBody.use { it.readNBytes(MAX_BODY + 1) }
        if (bytes.size > MAX_BODY) tooLarge()
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 3, 256, 40 * 1024, MAX_BODY, 16)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The repository change must be bounded strict JSON.") }
        val body = value as? JsonObject ?: invalid()
        val action = text(body["action"])
        val expected = when (action) {
            "git.stage", "git.unstage" -> setOf("action", "worktreeId", "guards", "selectedFileIds")
            "git.commit" -> setOf("action", "worktreeId", "guards", "selectedFileIds", "message")
            else -> invalid()
        }
        if (body.keys != expected) invalid()
        val worktreeId = id(body["worktreeId"])
        val guards = guards(body["guards"])
        val files = (body["selectedFileIds"] as? JsonArray)?.map { element ->
            text(element).takeIf { it.matches(Regex("file_[0-9a-f]{32}")) } ?: invalid()
        }?.takeIf { it.size in 1..200 && it.toSet().size == it.size } ?: invalid()
        val request = if (action == "git.commit") GitCommitRequest(worktreeId, guards, files, text(body["message"]))
            else GitStageRequest(worktreeId, guards, files, action == "git.stage")
        return request to guards
    }

    private fun guards(value: JsonElement?): GitGuards {
        val guards = value as? JsonObject ?: invalid()
        if (guards.keys != setOf("repositoryVersion", "worktreeVersion", "expectedHeadObjectId", "expectedRefId", "expectedRefObjectId")) invalid()
        fun objectId(element: JsonElement?): String? = if (element == JsonNull) null
            else text(element).takeIf { it.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}")) } ?: invalid()
        return GitGuards(id(guards["repositoryVersion"]), id(guards["worktreeVersion"]), objectId(guards["expectedHeadObjectId"]),
            guards["expectedRefId"].let { if (it == JsonNull) null else id(it) }, objectId(guards["expectedRefObjectId"]))
    }

    private fun text(value: JsonElement?): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun id(value: JsonElement?): String = text(value).takeIf { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")) } ?: invalid()
    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The repository change exceeds its 64 KiB limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
        "The repository change must contain only a declared action, its work tree, full guards, selected file identities and, for a commit, a message.")

    private companion object { const val MAX_BODY = 64 * 1024 }
}

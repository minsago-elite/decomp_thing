package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.git.GitCommitRequest
import decompengine.git.GitGuards
import decompengine.git.GitOperationAction
import decompengine.git.GitRefRequest
import decompengine.git.GitRepositoryRequest
import decompengine.git.GitStageRequest
import decompengine.git.GitSyncRequest
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
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 4, 1024, MAX_BODY, MAX_BODY, 16)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The repository change must be bounded strict JSON.") }
        val body = value as? JsonObject ?: invalid()
        val action = text(body["action"])
        val expected = when (action) {
            "git.stage", "git.unstage" -> setOf("action", "worktreeId", "guards", "selectedFileIds")
            "git.commit" -> setOf("action", "worktreeId", "guards", "selectedFileIds", "message")
            "git.branch.create" -> setOf("action", "worktreeId", "guards", "name", "startObjectId")
            "git.switch" -> setOf("action", "worktreeId", "guards", "refId", "objectId")
            "git.branch.delete" -> setOf("action", "worktreeId", "guards", "refId", "expectedObjectId")
            "git.tag" -> setOf("action", "worktreeId", "guards", "name", "targetObjectId")
            "git.worktree.add" -> setOf("action", "worktreeId", "guards", "startObjectId", "branchName", "runId")
            "git.worktree.remove" -> setOf("action", "worktreeId", "guards")
            "git.remote.add" -> setOf("action", "worktreeId", "guards", "name", "url")
            "git.remote.remove", "git.fetch" -> setOf("action", "worktreeId", "guards", "remoteId")
            "git.merge" -> setOf("action", "worktreeId", "guards", "trackingRefId", "targetObjectId", "strategy")
            "git.merge.abort" -> setOf("action", "worktreeId", "guards")
            "git.conflict.save" -> setOf("action", "worktreeId", "guards", "fileId", "expectedSha256", "resolution", "content")
            "git.conflict.complete" -> setOf("action", "worktreeId", "guards", "files")
            "git.push" -> setOf("action", "worktreeId", "guards", "remoteId", "localRefId", "remoteBranch", "localObjectId", "expectedRemoteObjectId")
            "git.push.reconcile" -> setOf("action", "worktreeId", "guards", "pushOperationId")
            "github.pr.create" -> setOf("action", "worktreeId", "guards", "remoteId", "headBranch", "baseBranch", "title", "body")
            "github.pr.reconcile" -> setOf("action", "worktreeId", "guards", "prOperationId")
            else -> invalid()
        }
        if (body.keys != expected) invalid()
        val worktreeId = id(body["worktreeId"])
        val guards = guards(body["guards"])
        GitOperationAction.entries.singleOrNull { it.wireName == action && it in GitRefRequest.ACTIONS }?.let { kind ->
            fun nullableId(key: String) = body[key].let { if (it == JsonNull) null else id(it) }
            fun name(key: String) = body[key].let { if (it == JsonNull) null else text(it).takeIf { name -> name.length in 1..200 } ?: invalid() }
            val request = when (kind) {
                GitOperationAction.BRANCH_CREATE -> GitRefRequest(kind, worktreeId, guards, name = name("name") ?: invalid(),
                    objectId = objectId(body["startObjectId"]) ?: invalid())
                GitOperationAction.SWITCH -> GitRefRequest(kind, worktreeId, guards, refId = nullableId("refId"), objectId = objectId(body["objectId"]))
                GitOperationAction.BRANCH_DELETE -> GitRefRequest(kind, worktreeId, guards, refId = nullableId("refId") ?: invalid(),
                    objectId = objectId(body["expectedObjectId"]) ?: invalid())
                GitOperationAction.TAG -> GitRefRequest(kind, worktreeId, guards, name = name("name") ?: invalid(),
                    objectId = objectId(body["targetObjectId"]) ?: invalid())
                GitOperationAction.WORKTREE_ADD -> GitRefRequest(kind, worktreeId, guards, name = name("branchName"),
                    objectId = objectId(body["startObjectId"]) ?: invalid(), runId = nullableId("runId"))
                else -> GitRefRequest(kind, worktreeId, guards)
            }
            return request to guards
        }
        GitOperationAction.entries.singleOrNull { it.wireName == action && it in GitSyncRequest.ACTIONS }?.let { kind ->
            fun digest(element: JsonElement?) = text(element).takeIf { it == "absent" || it.matches(Regex("[0-9a-f]{64}")) } ?: invalid()
            var content: String? = null
            val parameters = when (kind) {
                GitOperationAction.MERGE -> mapOf("trackingRefId" to id(body["trackingRefId"]),
                    "targetObjectId" to (objectId(body["targetObjectId"]) ?: invalid()),
                    "strategy" to (text(body["strategy"]).takeIf { it in setOf("fast-forward", "merge") } ?: invalid()))
                GitOperationAction.MERGE_ABORT -> emptyMap()
                GitOperationAction.PUSH -> mapOf("remoteId" to id(body["remoteId"]), "localRefId" to id(body["localRefId"]),
                    "remoteBranch" to (text(body["remoteBranch"]).takeIf { it.length in 1..200 } ?: invalid()),
                    "localObjectId" to (objectId(body["localObjectId"]) ?: invalid()), "expectedRemoteObjectId" to objectId(body["expectedRemoteObjectId"]))
                GitOperationAction.PUSH_RECONCILE -> mapOf("pushOperationId" to id(body["pushOperationId"]))
                GitOperationAction.GITHUB_PR_CREATE -> {
                    content = text(body["body"]).takeIf { it.length <= 65536 } ?: invalid()
                    mapOf("remoteId" to id(body["remoteId"]), "headBranch" to (text(body["headBranch"]).takeIf { it.length in 1..200 } ?: invalid()),
                        "baseBranch" to (text(body["baseBranch"]).takeIf { it.length in 1..200 } ?: invalid()),
                        "title" to (text(body["title"]).takeIf { it.length in 1..256 } ?: invalid()))
                }
                GitOperationAction.GITHUB_PR_RECONCILE -> mapOf("prOperationId" to id(body["prOperationId"]))
                GitOperationAction.CONFLICT_SAVE -> {
                    val resolution = text(body["resolution"]).takeIf { it in setOf("ours", "theirs", "base", "text") } ?: invalid()
                    content = body["content"].let { if (it == JsonNull) null else text(it) }
                    if ((resolution == "text") != (content != null)) invalid()
                    mapOf("fileId" to id(body["fileId"]), "expectedSha256" to digest(body["expectedSha256"]), "resolution" to resolution)
                }
                GitOperationAction.CONFLICT_COMPLETE -> {
                    val files = (body["files"] as? JsonArray)?.takeIf { it.size in 1..200 } ?: invalid()
                    content = files.joinToString("") { element ->
                        val file = element as? JsonObject ?: invalid()
                        if (file.keys != setOf("fileId", "sha256")) invalid()
                        "${id(file["fileId"])} ${digest(file["sha256"])}\n"
                    }
                    emptyMap()
                }
                GitOperationAction.REMOTE_ADD -> mapOf(
                    "name" to (text(body["name"]).takeIf { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) } ?: invalid()),
                    "url" to (text(body["url"]).takeIf { it.length in 1..2048 } ?: invalid()))
                else -> mapOf("remoteId" to id(body["remoteId"]))
            }
            return GitSyncRequest(kind, worktreeId, guards, parameters, content) to guards
        }
        val files = (body["selectedFileIds"] as? JsonArray)?.map { element ->
            text(element).takeIf { it.matches(Regex("file_[0-9a-f]{32}")) } ?: invalid()
        }?.takeIf { it.size in 1..200 && it.toSet().size == it.size } ?: invalid()
        val request = if (action == "git.commit") GitCommitRequest(worktreeId, guards, files, text(body["message"]))
            else GitStageRequest(worktreeId, guards, files, action == "git.stage")
        return request to guards
    }

    private fun objectId(element: JsonElement?): String? = if (element == JsonNull) null
        else text(element).takeIf { it.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}")) } ?: invalid()

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
    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The repository change exceeds its 1 MiB limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
        "The repository change must contain only a declared action, its work tree, full guards and that action's declared fields.")

    // A conflict resolution carries up to 256 KiB of text, which JSON escaping can expand.
    private companion object { const val MAX_BODY = 1024 * 1024 }
}

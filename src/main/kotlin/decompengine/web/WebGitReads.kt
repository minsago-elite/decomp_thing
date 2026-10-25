package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.git.GitDiffFile
import decompengine.git.GitDiffScope
import decompengine.git.GitHeadState
import decompengine.git.GitPath
import decompengine.git.GitStatusEntry
import decompengine.git.ManagedGitException
import decompengine.git.ManagedGitRepositories
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URLDecoder

/**
 * Bounded Git reads (#574, #575): `GET G/status`, `G/history`, `G/diff` and `G/refs`. Pages are
 * anchored to an exact object or work-tree version, so a moving ref cannot shift a later page;
 * a changed anchor answers `409` and asks for a fresh first page. Paths are display strings with
 * unambiguous escapes, and files are selected by opaque per-work-tree identities.
 */
internal class WebGitReads(private val repositories: () -> ManagedGitRepositories) {
    fun handle(exchange: HttpExchange, jobId: String, repositoryId: String, resource: String) {
        val query = parseQuery(exchange.requestURI.rawQuery, when (resource) {
            "status" -> setOf("worktree", "cursor", "limit")
            "refs" -> setOf("cursor", "limit")
            "history" -> setOf("worktree", "start", "cursor", "limit")
            else -> setOf("worktree", "scope", "commit", "file", "cursor", "limit")
        })
        val limit = query["limit"]?.let { value ->
            value.takeIf { it.matches(Regex("[1-9][0-9]{0,2}")) }?.toInt()?.takeIf { it <= 200 }
                ?: throw WebAccessDenied(422, "VALIDATION_FAILED", "limit must be an integer from 1 to 200.")
        } ?: 50
        val worktree = query["worktree"]?.also {
            if (!it.matches(Regex("worktree_[0-9a-f]{32}"))) throw WebAccessDenied(422, "VALIDATION_FAILED", "worktree must be a registered work-tree identity.")
        }
        try {
            when (resource) {
                "status" -> sendWebApiResponse(exchange, 200, "gitStatus", status(jobId, repositoryId, query["cursor"], limit, worktree))
                "history" -> sendWebApiResponse(exchange, 200, "gitHistory", history(jobId, repositoryId, query, limit, worktree))
                "diff" -> sendWebApiResponse(exchange, 200, "gitDiff", diff(jobId, repositoryId, query, limit, worktree))
                else -> sendWebApiResponse(exchange, 200, "gitRefs", refs(jobId, repositoryId, query["cursor"], limit))
            }
        } catch (failure: ManagedGitException) {
            throw webGitDenied(failure)
        }
    }

    /** `G/worktrees`, `G/worktrees/{id}`, `G/provenance/{objectId}` and `G/exports/{objectId}`. */
    fun nested(exchange: HttpExchange, jobId: String, repositoryId: String, resource: String, item: String?) {
        if (!exchange.requestURI.rawQuery.isNullOrEmpty()) throw WebAccessDenied(400, "VALIDATION_FAILED", "This endpoint does not accept query parameters.")
        val service = repositories()
        try {
            when {
                resource == "worktrees" && item == null -> sendWebApiResponse(exchange, 200, "gitWorktrees", buildJsonObject {
                    put("repositoryId", repositoryId)
                    put("worktrees", JsonArray(service.worktrees(jobId, repositoryId).map { view ->
                        val head = view.observation.head
                        buildJsonObject {
                            put("worktreeId", view.worktreeId); put("primary", view.primary)
                            put("ownerRunId", view.ownerRunId?.let(::JsonPrimitive) ?: JsonNull)
                            put("worktreeVersion", decompengine.git.GitWorkspaceVersions.worktreeVersion(view.observation))
                            put("headState", head.state.wireName)
                            put("headObjectId", head.objectId?.let(::JsonPrimitive) ?: JsonNull)
                            put("headRefName", head.refName?.let(::JsonPrimitive) ?: JsonNull)
                            put("dirty", view.observation.dirty)
                        }
                    }))
                })
                resource == "worktrees" -> {
                    val workspace = webGitWorkspace(service.workspace(jobId, repositoryId, item))
                    exchange.responseHeaders.set("ETag", "\"${(workspace.getValue("worktreeVersion") as JsonPrimitive).content}\"")
                    sendWebApiResponse(exchange, 200, "gitWorkspace", workspace)
                }
                resource == "provenance" -> {
                    requireObjectIdText(checkNotNull(item))
                    val view = service.provenance(jobId, repositoryId, item)
                    sendWebApiResponse(exchange, 200, "gitProvenance", buildJsonObject {
                        put("repositoryId", repositoryId); put("objectId", item); put("objectFormat", view.record.objectFormat.wireName)
                        put("committedAt", view.commit.committedAt.toString()); put("subject", view.commit.subject)
                        put("refNames", JsonArray(view.refNames.take(200).map(::JsonPrimitive)))
                        put("mapping", view.mapping?.let(::webGitMapping) ?: JsonNull)
                        put("worktreeDirtyAtCommit", view.mapping?.record?.worktreeDirty?.let(::JsonPrimitive) ?: JsonNull)
                        put("export", buildJsonObject {
                            put("sha256", view.export.sha256); put("sizeBytes", view.export.bytes.size.toString())
                            put("files", view.export.blobs.size); put("skippedEntries", view.export.skippedEntries)
                            put("verification", if (view.verified) "tree-blob-ids-match" else "mismatch")
                        })
                    })
                }
                else -> {
                    requireObjectIdText(checkNotNull(item))
                    if (!acceptsWebMediaType(exchange, "application/zip")) throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/zip.")
                    val export = service.export(jobId, repositoryId, item)
                    webApiHeaders(exchange, java.util.UUID.randomUUID().toString())
                    exchange.responseHeaders.set("Content-Type", "application/zip")
                    exchange.responseHeaders.set("Content-Disposition", "attachment; filename=\"source-${item.take(12)}.zip\"")
                    exchange.responseHeaders.set("X-Source-Export-SHA256", export.sha256)
                    exchange.responseHeaders.set("Content-Length", export.bytes.size.toString())
                    try {
                        if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(200, -1)
                        else { exchange.sendResponseHeaders(200, export.bytes.size.toLong()); exchange.responseBody.use { it.write(export.bytes) } }
                    } finally { exchange.close() }
                }
            }
        } catch (failure: ManagedGitException) {
            throw webGitDenied(failure)
        }
    }

    private fun status(jobId: String, repositoryId: String, cursor: String?, limit: Int, worktree: String?): JsonObject {
        val service = repositories()
        val view = service.workspace(jobId, repositoryId, worktree)
        val busy = service.busy(jobId)
        val workspace = webGitWorkspace(view)
        val version = (workspace.getValue("worktreeVersion") as JsonPrimitive).content
        val entries = view.observation.status.entries
        // The version ignores ignored-file noise, but pages list ignored entries too: anchor pages to
        // the version plus every listed path and state, so any change to the listing ends the walk.
        val anchor = "status_v_" + decompengine.git.GitStorage.sha256(buildString {
            append(version).append('\n')
            entries.forEach { append(it.path.fileId(view.worktreeId)).append(it.ignored).append(it.untracked).append(it.staged).append(it.unstaged).append('\n') }
        }).take(32)
        val offset = anchoredOffset(cursor, anchor)
        val counts = buildJsonObject {
            put("staged", entries.count { it.staged != decompengine.git.GitIndexChange.NONE })
            put("unstaged", entries.count { it.unstaged != decompengine.git.GitIndexChange.NONE })
            put("untracked", entries.count { it.untracked }); put("ignored", entries.count { it.ignored })
            put("conflicted", entries.count { it.conflict != null })
        }
        val (page, next) = budgeted(entries.drop(offset), limit) { statusEntry(it, view.worktreeId) }
        val head = view.observation.head
        val notices = buildList {
            if (head.state == GitHeadState.UNBORN) add("unborn" to "The branch has no commits yet. Stage source files and commit to create its first commit.")
            if (head.state == GitHeadState.DETACHED) add("detached" to "HEAD is detached at an exact commit. Create a branch before committing so new work stays reachable.")
            if (entries.any { it.conflict != null }) add("conflicted" to "Unmerged paths must be resolved in the work tree before a commit.")
            if (view.observation.dirty) add("dirty" to "The work tree has uncommitted changes. Review, stage and commit them, or keep them; nothing is discarded automatically.")
            else add("clean" to "The work tree matches HEAD apart from ignored files.")
            if (busy) add("busy" to "A repository operation is running. Reads stay available; changes wait until it finishes.")
            if (!view.observation.status.complete) add("incomplete" to "Status output exceeded its bound, so this listing is incomplete.")
        }
        return buildJsonObject {
            put("repositoryId", view.record.repositoryId); put("worktreeId", view.worktreeId)
            put("repositoryVersion", workspace.getValue("repositoryVersion")); put("worktreeVersion", version)
            put("headState", head.state.wireName)
            put("headObjectId", head.objectId?.let(::JsonPrimitive) ?: JsonNull)
            put("headRefName", head.refName?.let(::JsonPrimitive) ?: JsonNull)
            put("busy", busy); put("complete", view.observation.status.complete)
            put("counts", counts)
            put("notices", JsonArray(notices.map { (code, message) -> buildJsonObject { put("code", code); put("message", message) } }))
            put("entries", JsonArray(page))
            put("nextCursor", next?.let { JsonPrimitive("$anchor~${offset + it}") } ?: JsonNull)
        }
    }

    private fun history(jobId: String, repositoryId: String, query: Map<String, String>, limit: Int, worktree: String?): JsonObject {
        val cursor = query["cursor"]
        if (cursor != null && query["start"] != null) throw WebAccessDenied(400, "INVALID_CURSOR", "Use start for a first page or cursor for a later one, not both.")
        val (start, offset) = if (cursor != null) {
            val match = Regex("([0-9a-f]{40}|[0-9a-f]{64})~(0|[1-9][0-9]{0,6})").matchEntire(cursor)
                ?: throw WebAccessDenied(400, "INVALID_CURSOR", "The history cursor is invalid.")
            match.groupValues[1] to match.groupValues[2].toInt()
        } else (query["start"]?.also { requireObjectIdText(it) }) to 0
        val (origin, page) = repositories().history(jobId, repositoryId, start, offset, limit, worktree)
        val record = repositories().repository(jobId, repositoryId)
        val mappings = repositories().mappings(jobId, repositoryId, page.entries.map { it.objectId })
        return buildJsonObject {
            put("repositoryId", repositoryId); put("worktreeId", worktree ?: record.worktreeId)
            put("startObjectId", origin?.let(::JsonPrimitive) ?: JsonNull)
            put("entries", JsonArray(page.entries.map { entry ->
                buildJsonObject {
                    put("objectId", entry.objectId)
                    put("parentObjectIds", JsonArray(entry.parentObjectIds.take(64).map(::JsonPrimitive)))
                    put("authorName", entry.authorName); put("authorEmail", entry.authorEmail)
                    put("authoredAt", entry.authoredAt.toString()); put("committedAt", entry.committedAt.toString())
                    put("subject", entry.subject); put("subjectTruncated", entry.subjectTruncated)
                    // A Git commit maps to a reconstruction revision only through an explicit, validated record.
                    put("mapping", mappings[entry.objectId]?.let(::webGitMapping) ?: JsonNull)
                }
            }))
            put("nextCursor", if (page.more && origin != null) JsonPrimitive("$origin~${offset + page.entries.size}") else JsonNull)
        }
    }

    private fun diff(jobId: String, repositoryId: String, query: Map<String, String>, limit: Int, worktree: String?): JsonObject {
        val scope = GitDiffScope.entries.singleOrNull { it.wireName == query["scope"] }
            ?: throw WebAccessDenied(422, "VALIDATION_FAILED", "scope must be staged, unstaged or commit.")
        val commit = query["commit"]?.also { requireObjectIdText(it) }
        if ((scope == GitDiffScope.COMMIT) != (commit != null)) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "A commit diff needs exactly one full commit ID; other scopes take none.")
        }
        val file = query["file"]?.also {
            if (!it.matches(Regex("file_[0-9a-f]{32}"))) throw WebAccessDenied(422, "VALIDATION_FAILED", "file must be a file identity from this repository.")
        }
        val service = repositories()
        fun version() = (webGitWorkspace(service.workspace(jobId, repositoryId, worktree)).getValue("worktreeVersion") as JsonPrimitive).content
        // A staged or unstaged listing must belong to the version its cursor names: observe the
        // version on both sides of the comparison and retry once if the work tree moved meanwhile.
        fun consistent(): Pair<decompengine.git.GitDiffView, String> {
            if (commit != null) return service.diff(jobId, repositoryId, scope, commit, file, worktree) to commit
            repeat(2) {
                val before = version()
                val listing = service.diff(jobId, repositoryId, scope, null, file, worktree)
                if (version() == before) return listing to before
            }
            throw WebAccessDenied(409, "REF_CHANGED", "The work tree kept changing during the diff read. Read it again.")
        }
        val (view, anchor) = consistent()
        val offset = anchoredOffset(query["cursor"], anchor)
        val worktreeId = view.worktreeId
        // A selected file is read alone: its listing entry and its bounded patch.
        val (page, next) = view.patch?.let { listOf(diffFile(it.first, worktreeId)) to null }
            ?: budgeted(view.listing.files.drop(offset), limit) { diffFile(it, worktreeId) }
        return buildJsonObject {
            put("repositoryId", repositoryId); put("worktreeId", worktreeId); put("scope", scope.wireName)
            put("commitObjectId", commit?.let(::JsonPrimitive) ?: JsonNull)
            put("parentObjectId", view.parent?.let(::JsonPrimitive) ?: JsonNull)
            put("files", JsonArray(page)); put("complete", view.listing.complete)
            put("nextCursor", next?.let { JsonPrimitive("$anchor~${offset + it}") } ?: JsonNull)
            put("patch", view.patch?.let { (selected, patch) ->
                buildJsonObject {
                    put("fileId", selected.path.fileId(worktreeId)); put("text", patch.text)
                    put("truncated", patch.truncated); put("binary", patch.binary)
                }
            } ?: JsonNull)
        }
    }

    private fun refs(jobId: String, repositoryId: String, cursor: String?, limit: Int): JsonObject {
        val offset = cursor?.let { value ->
            value.takeIf { it.matches(Regex("refs~(0|[1-9][0-9]{0,5})")) }?.substringAfter('~')?.toInt()
                ?: throw WebAccessDenied(400, "INVALID_CURSOR", "The refs cursor is invalid.")
        } ?: 0
        val service = repositories()
        val head = service.workspace(jobId, repositoryId).observation.head
        val (record, page) = service.refs(jobId, repositoryId, offset, limit)
        val (entries, more) = page
        return buildJsonObject {
            put("repositoryId", record.repositoryId)
            put("refs", JsonArray(entries.map { ref ->
                buildJsonObject {
                    put("refId", webGitRefId(record.repositoryId, ref.name))
                    put("kind", if (ref.name.startsWith("refs/tags/")) "tag" else "branch")
                    put("displayName", ref.name); put("objectId", ref.objectId)
                    put("peeledObjectId", ref.peeledObjectId?.let(::JsonPrimitive) ?: JsonNull)
                    put("version", webGitRefVersion(ref.name, ref.objectId))
                    put("current", head.state == GitHeadState.ATTACHED && head.refName == ref.name)
                }
            }))
            put("nextCursor", if (more) JsonPrimitive("refs~${offset + entries.size}") else JsonNull)
        }
    }

    private fun statusEntry(entry: GitStatusEntry, worktreeId: String) = buildJsonObject {
        put("fileId", entry.path.fileId(worktreeId))
        path(entry.path, entry.originalPath)
        put("staged", entry.staged.wireName); put("unstaged", entry.unstaged.wireName)
        put("untracked", entry.untracked); put("ignored", entry.ignored)
        put("conflict", entry.conflict?.wireName?.let(::JsonPrimitive) ?: JsonNull)
        put("submodule", entry.submodule)
    }

    private fun diffFile(file: GitDiffFile, worktreeId: String) = buildJsonObject {
        put("fileId", file.path.fileId(worktreeId))
        path(file.path, file.originalPath)
        put("change", file.change.wireName)
        put("oldObjectId", file.oldObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("newObjectId", file.newObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("oldMode", file.oldMode); put("newMode", file.newMode); put("binary", file.binary)
        put("additions", file.additions?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        put("deletions", file.deletions?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        put("newSizeBytes", file.newSizeBytes?.toString()?.let(::JsonPrimitive) ?: JsonNull)
    }

    private fun kotlinx.serialization.json.JsonObjectBuilder.path(path: GitPath, original: GitPath?) {
        put("path", path.display); put("pathEscaped", path.exact == null || path.display != path.exact)
        put("originalPath", original?.display?.let(::JsonPrimitive) ?: JsonNull)
    }

    /** Fill a page by count and by an approximate JSON byte budget; returns the next offset step. */
    private fun <T> budgeted(items: List<T>, limit: Int, render: (T) -> JsonObject): Pair<List<JsonObject>, Int?> {
        val page = mutableListOf<JsonObject>()
        var bytes = 0
        for (item in items) {
            if (page.size == limit) break
            val rendered = render(item)
            val size = rendered.toString().length * 2
            if (page.isNotEmpty() && bytes + size > PAGE_BUDGET) break
            page += rendered; bytes += size
        }
        return page to (page.size.takeIf { it < items.size })
    }

    private fun anchoredOffset(cursor: String?, anchor: String): Int {
        if (cursor == null) return 0
        val (value, offset) = cursor.split('~').takeIf { it.size == 2 && it[1].matches(Regex("0|[1-9][0-9]{0,6}")) }
            ?: throw WebAccessDenied(400, "INVALID_CURSOR", "The cursor is invalid.")
        if (value != anchor) throw WebAccessDenied(409, "REF_CHANGED", "The repository changed since this page began. Read the first page again.")
        return offset.toInt()
    }

    private fun requireObjectIdText(value: String) {
        if (!value.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}"))) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Object IDs must be full lowercase hexadecimal; abbreviations are not accepted.")
        }
    }

    private fun parseQuery(raw: String?, allowed: Set<String>): Map<String, String> {
        if (raw.isNullOrEmpty()) return emptyMap()
        if (raw.length > 1024) throw WebAccessDenied(400, "VALIDATION_FAILED", "The query is too long.")
        val values = LinkedHashMap<String, String>()
        for (part in raw.split('&')) {
            val name = part.substringBefore('=')
            val value = try { URLDecoder.decode(part.substringAfter('=', ""), Charsets.UTF_8) } catch (_: IllegalArgumentException) {
                throw WebAccessDenied(400, "VALIDATION_FAILED", "The query is malformed.")
            }
            if (name !in allowed || name in values || value.isEmpty() || '=' !in part) {
                throw WebAccessDenied(400, "VALIDATION_FAILED", "The query contains an unsupported, repeated or empty parameter.")
            }
            values[name] = value
        }
        return values
    }

    private companion object { const val PAGE_BUDGET = 256 * 1024 }
}

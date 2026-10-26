package decompengine.web

import decompengine.git.GitConflictEntry
import decompengine.git.ManagedGitRepositories.GitConflictFileView
import decompengine.git.ManagedGitRepositories.GitConflictView
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** A bounded display label, never a filesystem identity. Long names retain their full opaque ID. */
internal fun webGitConflictEntry(entry: GitConflictEntry, worktreeId: String): JsonObject {
    val fileId = entry.path.fileId(worktreeId)
    val display = entry.path.display
    val suffix = "... [truncated; $fileId]"
    val path = if (display.length <= 1024) display else {
        var end = 1024 - suffix.length
        if (display[end - 1].isHighSurrogate()) end--
        display.substring(0, end) + suffix
    }
    return buildJsonObject {
        put("fileId", fileId); put("path", path); put("pathEscaped", path != entry.path.exact)
        put("baseObjectId", entry.baseObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("oursObjectId", entry.oursObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("theirsObjectId", entry.theirsObjectId?.let(::JsonPrimitive) ?: JsonNull)
    }
}

/** Bound both count (in the service) and encoded bytes, reserving the shared response envelope. */
internal fun webGitConflicts(repositoryId: String, view: GitConflictView, byteLimit: Int = 1024 * 1024 - 1024): JsonObject {
    fun page(files: List<JsonObject>, nextOffset: Int?) = buildJsonObject {
        put("repositoryId", repositoryId); put("worktreeId", view.worktreeId); put("mergeInProgress", view.mergeInProgress)
        put("integration", view.integration?.let { record ->
            buildJsonObject {
                put("operationId", record.operationId); put("strategy", record.strategy.wireName); put("branch", record.branch)
                put("headBeforeObjectId", record.headBefore); put("targetObjectId", record.target)
                put("trackingRefName", record.trackingRef); put("startedAt", record.startedAt.toString())
            }
        } ?: JsonNull)
        put("files", JsonArray(files))
        put("offset", view.offset); put("totalCount", view.totalCount)
        put("nextOffset", nextOffset?.let(::JsonPrimitive) ?: JsonNull)
    }
    val selected = mutableListOf<JsonObject>()
    // Reserve the widest possible integer continuation, including the metadata and empty array.
    var bytes = page(emptyList(), Int.MAX_VALUE).toString().toByteArray(Charsets.UTF_8).size
    for (entry in view.files) {
        val file = webGitConflictEntry(entry, view.worktreeId)
        val size = file.toString().toByteArray(Charsets.UTF_8).size + if (selected.isEmpty()) 0 else 1
        if (bytes + size > byteLimit) break
        selected += file
        bytes += size
    }
    // Bounded labels guarantee at least one entry fits the production budget. Never return a
    // non-advancing continuation if a future metadata change violates that invariant.
    check(view.files.isEmpty() || selected.isNotEmpty()) { "A conflict entry exceeds the page byte budget" }
    val next = (view.offset + selected.size).takeIf { it < view.totalCount }
    return page(selected, next)
}

/** Budget encoded UTF-8, not source bytes: JSON escaping can multiply each of the four sides. */
internal fun webGitConflictDetail(repositoryId: String, view: GitConflictFileView, file: JsonObject): JsonObject {
    fun detail(omitText: Boolean): JsonObject {
        val supported = !omitText && view.ours != null && view.theirs != null && (view.current != null || view.currentSize == null)
        return buildJsonObject {
            put("repositoryId", repositoryId); put("worktreeId", view.worktreeId); put("file", file)
            put("base", view.base?.takeUnless { omitText }?.let(::JsonPrimitive) ?: JsonNull)
            put("ours", view.ours?.takeUnless { omitText }?.let(::JsonPrimitive) ?: JsonNull)
            put("theirs", view.theirs?.takeUnless { omitText }?.let(::JsonPrimitive) ?: JsonNull)
            put("current", view.current?.takeUnless { omitText }?.let(::JsonPrimitive) ?: JsonNull)
            put("currentSha256", view.currentSha256); put("currentSizeBytes", view.currentSize?.toString()?.let(::JsonPrimitive) ?: JsonNull)
            put("supported", supported)
            put("reason", when {
                omitText -> JsonPrimitive("Text omitted because its JSON encoding exceeds the response byte limit; resolve this file outside the workbench.")
                supported -> JsonNull
                else -> JsonPrimitive("A side is binary, deleted or larger than 256 KiB; resolve this file outside the workbench.")
            })
        }
    }
    val complete = detail(false)
    // Reserve 1 KiB for the fixed version/kind/UUID envelope used by sendWebApiResponse.
    // Its global 1 MiB ceiling is unchanged; no truncated text is presented as a full side.
    return if (complete.toString().toByteArray(Charsets.UTF_8).size <= 1024 * 1024 - 1024) complete else detail(true)
}

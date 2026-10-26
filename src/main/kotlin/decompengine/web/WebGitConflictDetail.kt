package decompengine.web

import decompengine.git.ManagedGitRepositories.GitConflictFileView
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

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

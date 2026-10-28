package decompengine.web

import decompengine.git.GitAvailability
import decompengine.git.GitRuntime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Git is an optional runtime prerequisite detected once per listener. Bootstrap reports the
 * sanitized version and a capability state; neither ever contains the executable path.
 */
internal class WebGitCapability(val availability: GitAvailability) {
    /** Numeric version only, also when the detected version is too old to use. */
    val version: String? get() = availability.version?.display

    fun capability(): JsonObject = buildJsonObject {
        put("id", "git")
        when (val current = availability) {
            is GitAvailability.Available -> {
                // The adapter is qualified, but no managed repository route is served yet.
                put("state", "unsupported")
                put("reasonCode", "GIT_WORKSPACE_UNIMPLEMENTED")
                put("message", "Git ${current.version.display} is available; managed repositories are not served yet.")
            }
            is GitAvailability.Unavailable -> {
                put("state", "unavailable")
                put("reasonCode", current.reasonCode)
                put("message", current.message)
            }
        }
        put("workflows", JsonArray(emptyList()))
        put("agentContractVersion", JsonNull)
        put("limits", JsonNull)
    }

    fun versionJson() = version?.let(::JsonPrimitive) ?: JsonNull

    companion object {
        fun detect(): WebGitCapability = WebGitCapability(GitRuntime.detect())
    }
}

package decompengine.web

import decompengine.git.GitAvailability
import decompengine.git.GitRuntime
import decompengine.git.ManagedGitRepositories
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Git is an optional runtime prerequisite detected once per listener. Bootstrap reports the
 * sanitized version and capability states; neither ever contains the executable or a path.
 */
internal class WebGitCapability(
    val availability: GitAvailability,
    private val managed: ManagedGitRepositories? = null,
) {
    /** Numeric version only, also when the detected version is too old to use. */
    val version: String? get() = availability.version?.display

    fun capabilities(): List<JsonObject> {
        val current = availability
        val git = when {
            current is GitAvailability.Unavailable -> Triple("unavailable", current.reasonCode, current.message)
            managed == null -> Triple("unavailable", "GIT_REPOSITORIES_UNCONFIGURED", "Managed repositories are not configured for this listener.")
            else -> Triple("supported", null, "Git ${current.version?.display} is available for managed source repositories.")
        }
        val import = when {
            git.first != "supported" -> Triple("unavailable", git.second, git.third)
            managed?.importConfigured != true -> Triple("unavailable", "GIT_IMPORT_UNCONFIGURED",
                "Repository import needs an operator-configured import root on the server.")
            else -> Triple("supported", null, "Repositories placed under the server's import root can be imported by name.")
        }
        // Commits are always unsigned: no signing key handle exists, and hooks never run.
        val signing = Triple("unsupported", "GIT_SIGNING_UNSUPPORTED",
            "Commits are created unsigned with the server identity; no signing key handle is configured.")
        return listOf(entry("git", git), entry("git-import", import), entry("git-signing", signing))
    }

    /** The managed registry, or an explicit unavailable refusal for every Git route. */
    fun repositories(): ManagedGitRepositories {
        val current = availability
        if (current is GitAvailability.Unavailable) throw WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", current.message)
        return managed ?: throw WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", "Managed repositories are not configured for this listener.")
    }

    fun versionJson() = version?.let(::JsonPrimitive) ?: JsonNull

    private fun entry(id: String, state: Triple<String, String?, String>) = buildJsonObject {
        put("id", id)
        put("state", state.first)
        put("reasonCode", state.second?.let(::JsonPrimitive) ?: JsonNull)
        put("message", state.third)
        put("workflows", JsonArray(emptyList()))
        put("agentContractVersion", JsonNull)
        put("limits", JsonNull)
    }

    companion object {
        fun detect(): WebGitCapability = WebGitCapability(GitRuntime.detect())
    }
}

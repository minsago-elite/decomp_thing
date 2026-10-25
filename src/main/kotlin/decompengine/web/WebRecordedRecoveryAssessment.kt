package decompengine.web

import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifest
import kotlinx.serialization.json.*

/** Fixed scalar commitments from the captured manifest; no model, source, oracle or receipt reads. */
internal object WebRecordedRecoveryAssessment {
    const val MAXIMUM_BYTES = 64 * 1024

    fun unavailable(): JsonObject = envelope(null)

    fun project(profile: ReconstructionProfile, manifest: SourceTreeManifest): JsonObject {
        require(profile.id == manifest.profileId && profile.sha256 == manifest.profileSha256)
        if (manifest.schemaVersion == 3) return unavailable()
        require(manifest.schemaVersion == 4)
        val summary = requireNotNull(manifest.recordedRecoverySummary)
        require(summary.canonicalBytes.size <= MAXIMUM_BYTES)
        val document = summary.toJsonObject()
        val bindings = document.getValue("bindings").jsonObject
        require(bindings["inputSha256"] == if (manifest.inputSha256.matches(Regex("[0-9a-f]{64}")))
            JsonPrimitive(manifest.inputSha256) else JsonNull)
        fun commitment(id: String): String {
            val path = profile.layout.declaration(id).materialize()
            val file = requireNotNull(manifest.files.singleOrNull { it.path == path })
            require(ProjectFileRole.EVIDENCE in file.roles && ProjectFileRole.BUILD_INPUT !in file.roles &&
                file.contentKind == ProjectContentKind.UTF8_TEXT)
            return file.sha256
        }
        require(bindings.getValue("modelSha256").jsonPrimitive.content == commitment("program-model-evidence"))
        require(bindings.getValue("planSha256").jsonPrimitive.content == commitment("module-plan-evidence"))
        require(document.getValue("confidenceSha256").jsonPrimitive.content == commitment("confidence-evidence"))
        return envelope(document)
    }

    private fun envelope(summary: JsonObject?): JsonObject = buildJsonObject {
        put("schemaVersion", 1); put("authority", "reported-assessment")
        put("origin", "recorded-origin-unverified")
        put("state", if (summary == null) "unavailable" else "recorded")
        put("reason", if (summary == null) JsonPrimitive("legacy-manifest") else JsonNull)
        put("summary", summary ?: JsonNull)
    }
}

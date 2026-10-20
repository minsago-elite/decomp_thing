package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ModulePlanJson
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifest
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.*

internal data class WebRevisionFileMetadataSnapshot(
    val source: WebRevisionSourceSnapshot,
    val recordedModule: JsonObject?,
)

/** A manifest-bound generation declaration, never an execution or acceptance attestation. */
internal object WebRecordedModuleProvenance {
    const val MAXIMUM_BYTES = 16 * 1024 * 1024
    private val MODULE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    private val DECIMAL = Regex("0|[1-9][0-9]{0,18}")
    private val LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_BYTES, maximumCanonicalBytes = MAXIMUM_BYTES,
        maximumDepth = 32, maximumNodes = 1_000_000,
        maximumStringBytes = 16 * 1024, maximumTotalStringBytes = MAXIMUM_BYTES,
    )

    data class EvidenceFiles(val plan: GeneratedFileEvidence, val generation: GeneratedFileEvidence)

    fun evidenceFiles(profile: ReconstructionProfile, manifest: SourceTreeManifest,
        selected: WebRevisionSourceFile): EvidenceFiles? {
        if (profile.id != manifest.profileId || profile.sha256 != manifest.profileSha256 ||
            manifest.files.none { it === selected.evidence } ||
            ProjectFileRole.MODULE_IMPLEMENTATION !in selected.evidence.roles ||
            selected.evidence.contentKind != ProjectContentKind.UTF8_TEXT) return null
        return try {
            fun declared(id: String): GeneratedFileEvidence? {
                val path = profile.layout.declaration(id).materialize()
                return manifest.files.singleOrNull { it.path == path }?.takeIf {
                    ProjectFileRole.EVIDENCE in it.roles && ProjectFileRole.BUILD_INPUT !in it.roles &&
                        it.contentKind == ProjectContentKind.UTF8_TEXT
                }
            }
            val plan = declared("module-plan-evidence") ?: return null
            val generation = declared("confidence-evidence") ?: return null
            if (plan.path == generation.path) null else EvidenceFiles(plan, generation)
        } catch (_: IllegalArgumentException) { null }
    }

    /** Only scalars from the explicitly joined row escape; arbitrary strings and checkpoint paths do not. */
    fun project(profile: ReconstructionProfile, manifest: SourceTreeManifest, selected: WebRevisionSourceFile,
        planBytes: ByteArray, generationBytes: ByteArray): JsonObject? = try {
        val files = evidenceFiles(profile, manifest, selected)
        if (files == null || planBytes.size !in 1..MAXIMUM_BYTES || generationBytes.size !in 1..MAXIMUM_BYTES ||
            WebExplorationArtifact.sha256(planBytes) != files.plan.sha256 ||
            WebExplorationArtifact.sha256(generationBytes) != files.generation.sha256) null
        else projectBound(profile, manifest, selected, files, planBytes, generationBytes)
    } catch (failure: Exception) {
        if (failure is CancellationException || failure is InterruptedException) throw failure
        null
    }

    private fun projectBound(profile: ReconstructionProfile, manifest: SourceTreeManifest,
        selected: WebRevisionSourceFile, files: EvidenceFiles, planBytes: ByteArray,
        generationBytes: ByteArray): JsonObject {
        val plan = ModulePlanJson.readCanonical(planBytes, MAXIMUM_BYTES)
        require(plan.modules.size in 1..WebSourceCatalogSnapshot.MAXIMUM_FILES)
        val ids = plan.modules.map { it.id }
        require(ids.all { MODULE_ID.matches(it) } && ids.distinct().size == ids.size)
        val paths = plan.modules.flatMap { listOf(it.sourcePath, it.headerPath) }
        require(paths.distinct().size == paths.size)
        val module = requireNotNull(plan.modules.singleOrNull { it.sourcePath == selected.evidence.path })
        require(module.sourcePath == profile.layout.declaration("module-implementation")
            .materialize(mapOf("module" to module.id)))
        val root = OracleJson.parse(generationBytes, LIMITS) as? JsonObject
            ?: error("Generation record is unavailable.")
        require(root.number("schemaVersion") == 2L)
        val generation = root.objectField("sourceGenerationBudgetEvidence")
        require(generation.number("schemaVersion") == 1L)
        val declaredProfile = generation.objectField("selectedProfile")
        require(declaredProfile.text("id") == profile.id && declaredProfile.text("sha256") == profile.sha256)
        fun rows(owner: JsonObject, field: String): Map<String, JsonObject> {
            val values = owner["modules"] as? JsonArray ?: error("Generation modules are unavailable.")
            require(values.size == ids.size)
            val entries = values.map { it as? JsonObject ?: error("Generation module is unavailable.") }
            val keys = entries.map { it.text(field) }
            require(keys.distinct().size == keys.size && keys.toSet() == ids.toSet())
            return keys.zip(entries).toMap()
        }
        val revision = rows(root, "id").getValue(module.id).objectField("revisionEvidence")
        require(revision.text("sourcePath") == selected.evidence.path &&
            revision.text("sourceSha256") == selected.evidence.sha256 &&
            revision.text("inputBinarySha256") == manifest.inputSha256)
        val accepted = revision["acceptedImplementation"] as? JsonPrimitive
            ?: error("Generation disposition is unavailable.")
        require(!accepted.isString && accepted.booleanOrNull == selected.evidence.acceptedImplementation)
        val budget = rows(generation, "moduleId").getValue(module.id)
        require(budget.text("outcome") == if (selected.evidence.acceptedImplementation == true) "accepted" else "unresolved")
        require(budget.number("sourceBytes") == selected.sizeBytes)
        val characters = budget.optionalNumber("promptCharacters")
        val maximum = budget.optionalNumber("promptBudgetCharacters")
        require((characters == null) == (maximum == null))
        if (characters != null && maximum != null) {
            require(maximum in 1..profile.budgets.reconstructionMaximumContextCharacters.toLong() && characters <= maximum)
        }
        return buildJsonObject {
            put("authority", "reported-generation"); put("moduleId", module.id)
            put("implementationSha256", selected.evidence.sha256)
            put("planSha256", files.plan.sha256); put("generationEvidenceSha256", files.generation.sha256)
            put("promptCharacters", characters?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
            put("promptBudgetCharacters", maximum?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
        }
    }

    private fun JsonObject.objectField(name: String): JsonObject =
        this[name] as? JsonObject ?: error("Generation field is unavailable.")
    private fun JsonObject.text(name: String): String = (this[name] as? JsonPrimitive)
        ?.takeIf { it.isString }?.content ?: error("Generation field is unavailable.")
    private fun JsonObject.number(name: String): Long {
        val value = this[name] as? JsonPrimitive ?: error("Generation count is unavailable.")
        require(!value.isString && DECIMAL.matches(value.content))
        return requireNotNull(value.longOrNull)
    }
    private fun JsonObject.optionalNumber(name: String): Long? =
        if (this[name] === JsonNull) null else number(name)
}

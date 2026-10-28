package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.assessment.HeuristicScoreInterpretation
import decompengine.project.*
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
import io.github.optimumcode.json.schema.JsonSchema
import io.github.optimumcode.json.schema.ValidationError
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.*
import kotlin.test.assertTrue

/**
 * Synthetic persisted revisions of one job, read through the real capture path with synchronous callbacks only:
 * no store, listener, compiler or browser is opened. Each revision commits a program model, a module plan and,
 * unless omitted, a confidence record rendered like the producer's schema-2 record.
 */
internal class WebStructureFixture {
    val jobId = "a".repeat(32)
    val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val inputBytes = "input".toByteArray()
    val inputSha = sha(inputBytes)
    private var inode = 10L
    val files = HashMap<String, StableRegularFile>()
    val reads: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())
    private val references = HashMap<Pair<String, String>, WebRevisionSourceReference>()
    private val evidence = WebSourceCatalogEvidence(listOf(profile), { captured(inputBytes).copy(identity = INPUT_IDENTITY) }) { _, path, maximum ->
        reads += path
        val file = files[path] ?: error("Unexpected read $path")
        if (file.bytes.size > maximum) throw RepairBudgetExceededException("fixture exceeds $maximum")
        file
    }
    val cache = WebProgramStructureCache(capacity = 4)
    val pages = WebProgramStructurePages { job, run, revision, project ->
        val reference = references[run to revision] ?: throw WebAccessDenied(404, "REVISION_NOT_FOUND", "No such revision.")
        check(job == jobId)
        evidence.readStructure(reference, cache, project)
    }

    fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun captured(bytes: ByteArray) = StableRegularFile(bytes, sha(bytes),
        LinuxFileIdentity(LinuxFileKey(1, inode++), 0x8180, 1000, 1000, 1, 1, true, false, false))

    fun model(functions: List<RecoveredFunction>, globals: List<RecoveredGlobal> = emptyList(), types: List<RecoveredType> = emptyList(),
        schema: Int = 2) = RecoveredProgramModel(schema, inputSha, functions, globals, types)

    fun planned(id: String, functions: List<String>, globals: List<String> = emptyList(), types: List<String> = emptyList()) =
        PlannedModule(id, "src/modules/$id.c", "include/modules/$id.h", functions, globals, types, emptyList())

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    /** The producer's schema-2 confidence layout for [model] and [plan], with optional overrides for negative cases. */
    fun confidence(model: RecoveredProgramModel, plan: ModulePlan, accepted: Set<String>, unresolvedImplementations: List<String> = emptyList(),
        projectScore: String? = null, completedModules: Int = plan.modules.size, generation: Boolean = true): ByteArray {
        val statuses = model.functions.associate { it.id to it.status } + model.globals.associate { it.id to it.status } +
            model.types.associate { it.id to it.status }
        val all = model.functions.map { it.status } + model.globals.map { it.status } + model.types.map { it.status }
        val unresolved = (model.functions.map { it.id to it.status } + model.globals.map { it.id to it.status } + model.types.map { it.id to it.status })
            .filter { model.isRecoveryUnresolved(it.second) }.map { it.first }
        fun ids(values: Collection<String>) = JsonArray(values.distinct().sorted().map(::JsonPrimitive))
        val text = buildJsonObject {
            put("schemaVersion", 2)
            put("basis", "recovery evidence only; behavioral equivalence is not implied")
            put("scoreMeaning", "structural recovery heuristic; not implementation acceptance or measured behavioral confidence")
            put("scoreInterpretation", Json.parseToJsonElement(HeuristicScoreInterpretation.STRUCTURAL_RECOVERY.toJson()))
            put("recoveryAssessment", model.unassessedRecoveryAssessment(sha(model.toJson().toByteArray())))
            put("projectScore", JsonUnquotedLiteral(projectScore ?: StructuralRecoveryScore.render(all)))
            put("modules", JsonArray(plan.modules.sortedBy { it.id }.map { module ->
                val owned = module.functionIds + module.globalIds + module.typeIds
                buildJsonObject {
                    put("id", module.id)
                    put("score", JsonUnquotedLiteral(StructuralRecoveryScore.render(owned.mapNotNull(statuses::get))))
                    put("unresolvedRecoveryEntityIds", ids(owned.filter { it in unresolved }))
                    put("unresolvedImplementationIds", ids(owned.filter { it in unresolvedImplementations }))
                    put("revisionEvidence", buildJsonObject { put("sourcePath", module.sourcePath) })
                }
            }))
            put("unresolvedRecoveryEntityIds", ids(unresolved)); put("unresolvedImplementationIds", ids(unresolvedImplementations))
            put("unresolvedEntityIds", ids(unresolved + unresolvedImplementations))
            put("semanticPlanningBudgetEvidence", buildJsonObject { put("schemaVersion", 1) })
            if (generation) put("sourceGenerationBudgetEvidence", buildJsonObject {
                put("schemaVersion", 1)
                put("outcome", buildJsonObject {
                    put("plannedModules", plan.modules.size); put("completedModules", completedModules)
                    put("acceptedModules", accepted.size); put("unresolvedModules", completedModules - accepted.size)
                })
                put("modules", JsonArray(emptyList()))
            })
        }
        return text.toString().toByteArray()
    }

    /** Persist one revision of this job; records left null are not committed by its manifest. */
    fun revision(runId: String, revisionId: String, model: RecoveredProgramModel?, plan: ModulePlan?,
        accepted: Set<String> = emptySet(), confidence: ByteArray? = model?.let { m -> plan?.let { confidence(m, it, accepted) } },
        modelBytes: ByteArray? = model?.toJson()?.toByteArray()): WebRevisionSourceReference {
        val modules = plan?.modules?.map { it.id }.orEmpty()
        val sources = (listOf("Makefile", "include/decomp_types.h") + modules.flatMap { listOf("src/modules/$it.c", "include/modules/$it.h") })
            .associateWith { "// $it\n".toByteArray() }
        val records = buildMap {
            putAll(sources)
            modelBytes?.let { put("reports/program_model.json", it) }
            plan?.let { put("reports/module_plan.json", it.toJson().toByteArray()) }
            confidence?.let { put("reports/confidence.json", it) }
        }
        val sourceSha = revisionSourceDigest(sources.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${path.length}:$path:${bytes.size}:${sha(bytes)}\n" })
        val unresolved = model?.let { m ->
            (m.functions.map { it.id to it.status } + m.globals.map { it.id to it.status } + m.types.map { it.id to it.status })
                .filter { m.isRecoveryUnresolved(it.second) }.map { it.first }.sorted()
        }.orEmpty()
        val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha,
            files = records.toSortedMap().map { (path, bytes) ->
                val declaration = profile.layout.declarationForPath(path)
                val module = path.removePrefix("src/modules/").removeSuffix(".c")
                GeneratedFileEvidence(path, sha(bytes), "fixture",
                    acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) module in accepted else null,
                    roles = declaration.roles, contentKind = declaration.contentKind)
            }, unresolvedEntityIds = unresolved, unresolvedImplementationIds = emptyList()).toJson().toByteArray()
        val descriptor = buildJsonObject {
            put("schemaVersion", 3); put("sourceRevisionSha256", sourceSha)
            put("sourceInputs", JsonArray(sources.toSortedMap().map { (path, bytes) -> buildJsonObject {
                put("path", path); put("bytes", bytes.size); put("sha256", sha(bytes))
            } }))
        }.toString().toByteArray()
        val root = "reports/runs/$runId/source-tree"
        (records.mapKeys { "$root/${it.key}" } + mapOf("$root/source_tree_manifest.json" to manifest,
            "$root/reports/build_contract.json" to descriptor)).forEach { (path, bytes) -> files[path] = captured(bytes) }
        return WebRevisionSourceReference(jobId, runId, revisionId, sourceSha, "version_$runId").also { references[runId to revisionId] = it }
    }

    private val schema: JsonObject = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json"))).jsonObject

    /** Validate a produced DTO with the shared producer schema, the same definition the browser decoder uses. */
    fun assertContract(kind: String, data: JsonObject) {
        val document = JsonObject(schema - "oneOf" + ("allOf" to JsonArray(listOf(buildJsonObject { put("\$ref", "#/definitions/$kind") }))))
        val errors = mutableListOf<ValidationError>()
        assertTrue(JsonSchema.fromDefinition(document.toString()).validate(data, errors::add), "$kind: ${errors.take(3)}")
    }

    private companion object {
        val INPUT_IDENTITY = LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)
    }
}

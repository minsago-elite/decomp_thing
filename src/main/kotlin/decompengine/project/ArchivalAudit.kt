package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.readBytes
import kotlin.io.path.writeText

data class ArchivalAudit(
    val entityCount: Int,
    val missingModelProvenance: List<String>,
    val missingSourceProvenance: List<String>,
    val unresolvedEntityIds: List<String>,
    val behaviorReportCount: Int,
    val behaviorMatched: Boolean?,
    val sandboxReported: Boolean,
    val networkIsolation: Set<Boolean>,
    val moduleRevisionSha256: Map<String, String>,
    val unresolvedBehaviorReportIds: List<String>,
) {
    val provenanceComplete: Boolean get() = missingModelProvenance.isEmpty() && missingSourceProvenance.isEmpty()
    val universalEquivalenceClaim: Boolean = false

    fun toJson(): String = """
        {
          "entityCount": $entityCount,
          "provenanceComplete": $provenanceComplete,
          "missingModelProvenance": [${missingModelProvenance.sorted().joinToString(",") { "\"$it\"" }}],
          "missingSourceProvenance": [${missingSourceProvenance.sorted().joinToString(",") { "\"$it\"" }}],
          "unresolvedEntityIds": [${unresolvedEntityIds.sorted().joinToString(",") { "\"$it\"" }}],
          "behaviorReportCount": $behaviorReportCount,
          "behaviorMatched": ${behaviorMatched ?: "null"},
          "sandboxReported": $sandboxReported,
          "networkIsolationObserved": [${networkIsolation.sorted().joinToString(",")}],
          "moduleBehaviorEvidence": [${moduleRevisionSha256.toSortedMap().entries.joinToString(",") { (id, hash) -> "{\"moduleId\":\"$id\",\"sourceRevisionSha256\":\"$hash\",\"scope\":\"project-observed behavior\"}" }}],
          "unresolvedBehaviorReportIds": [${unresolvedBehaviorReportIds.sorted().joinToString(",") { "\"$it\"" }}],
          "universalEquivalenceClaim": false,
          "limitation": "Confidence is bounded by recovered structure and observed behavior; untested behavior remains unresolved."
        }
    """.trimIndent() + "\n"
}

object ArchivalProjectAuditor {
    fun audit(projectDir: Path): ArchivalAudit {
        val modelPath = projectDir.resolve("reports/program_model.json")
        require(modelPath.isRegularFile()) { "project is missing reports/program_model.json" }
        val model = ProgramModelJson.read(modelPath.readText())
        val planText = projectDir.resolve("reports/module_plan.json").readText()
        val planJson = Json.parseToJsonElement(planText).jsonObject
        val manifestText = projectDir.resolve("source_tree_manifest.json").readText()
        val entities = model.functions.map { it.id } + model.globals.map { it.id } + model.types.map { it.id }
        val ownedEntities = model.functions.map { it.id } + model.globals.map { it.id }
        val missingModel = ownedEntities.filter { it !in planText || it !in manifestText } +
            model.types.map { it.id }.filter { it !in manifestText }
        val sourceText = Files.walk(projectDir.resolve("src")).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".c") }
                .map { it.readText() }.toList().joinToString("\n")
        }
        val headerText = Files.walk(projectDir.resolve("include")).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".h") }
                .map { it.readText() }.toList().joinToString("\n")
        }
        val missingSource = (model.functions.map { it.id }.filter { it !in sourceText } +
            model.globals.map { it.id }.filter { it !in sourceText && it !in headerText } +
            model.types.map { it.id }.filter { it !in headerText }).distinct()
        val behavior = Files.walk(projectDir.resolve("reports")).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".behavior.json") }
                .toList().mapNotNull { path -> runCatching { Json.parseToJsonElement(path.readText()).jsonObject }.getOrNull() }
        }
        val matches = behavior.mapNotNull { it["matches"]?.jsonPrimitive?.booleanOrNull }
        val networks = behavior.mapNotNull { it["networkIsolated"]?.jsonPrimitive?.booleanOrNull }.toSet()
        val moduleRevisions = planJson["modules"]?.let { modules ->
            modules.jsonArray.associate { element ->
                val module = element.jsonObject
                val id = module.getValue("id").jsonPrimitive.content
                val source = module.getValue("sourcePath").jsonPrimitive.content
                id to sha256(projectDir.resolve(source).readBytes())
            }
        }.orEmpty()
        val unresolvedBehavior = behavior.filter { it["matches"]?.jsonPrimitive?.booleanOrNull == false }
            .mapNotNull { it["id"]?.jsonPrimitive?.content }
        val audit = ArchivalAudit(
            entityCount = entities.size,
            missingModelProvenance = missingModel,
            missingSourceProvenance = missingSource,
            unresolvedEntityIds = model.functions.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.globals.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.types.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id },
            behaviorReportCount = behavior.size,
            behaviorMatched = matches.takeIf { it.isNotEmpty() }?.all { it },
            sandboxReported = behavior.isNotEmpty() && behavior.all { it["sandbox"]?.jsonPrimitive?.content == "bubblewrap" },
            networkIsolation = networks,
            moduleRevisionSha256 = moduleRevisions,
            unresolvedBehaviorReportIds = unresolvedBehavior,
        )
        projectDir.resolve("reports/archival_audit.json").writeText(audit.toJson())
        return audit
    }
}

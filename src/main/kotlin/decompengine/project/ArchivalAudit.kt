package decompengine.project

import decompengine.repair.readStableRegularFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText

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
          "missingModelProvenance": [${missingModelProvenance.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "missingSourceProvenance": [${missingSourceProvenance.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "unresolvedEntityIds": [${unresolvedEntityIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "behaviorReportCount": $behaviorReportCount,
          "behaviorMatched": ${behaviorMatched ?: "null"},
          "sandboxReported": $sandboxReported,
          "networkIsolationObserved": [${networkIsolation.sorted().joinToString(",")}],
          "moduleBehaviorEvidence": [${moduleRevisionSha256.toSortedMap().entries.joinToString(",") { (id, hash) -> "{\"moduleId\":${JsonPrimitive(id)},\"sourceRevisionSha256\":${JsonPrimitive(hash)},\"scope\":\"project-observed behavior\"}" }}],
          "unresolvedBehaviorReportIds": [${unresolvedBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "universalEquivalenceClaim": false,
          "limitation": "Confidence is bounded by recovered structure and observed behavior; untested behavior remains unresolved."
        }
    """.trimIndent() + "\n"
}

object ArchivalProjectAuditor {
    fun audit(
        projectDir: Path,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ): ArchivalAudit {
        val maximumFileBytes = minOf(profile.budgets.archiveMaximumFileBytes, Int.MAX_VALUE.toLong() - 1L)
        val manifestSnapshot = readStableRegularFile(projectDir, "source_tree_manifest.json", maximumFileBytes)
        val manifest = SourceTreeManifestReader.parse(manifestSnapshot.bytes.decodeToString(throwOnInvalidSequence = true), profile)
        require(manifest.files.size <= profile.budgets.archiveMaximumEntries) { "audit manifest exceeds the file-count bound" }
        val modelPath = profile.layout.declaration("program-model-evidence").materialize()
        val planPath = profile.layout.declaration("module-plan-evidence").materialize()
        val files = manifest.files.associateBy { it.path }
        val hashes = linkedMapOf<String, String>()
        var totalBytes = manifestSnapshot.bytes.size.toLong()
        var modelText: String? = null
        var planText: String? = null
        for (file in manifest.files) {
            val snapshot = readStableRegularFile(projectDir, file.path, maximumFileBytes)
            totalBytes = Math.addExact(totalBytes, snapshot.bytes.size.toLong())
            require(totalBytes <= profile.budgets.archiveMaximumTotalBytes) { "audit input exceeds the aggregate byte bound" }
            require(snapshot.sha256 == file.sha256) { "audit manifest hash differs from current file: ${file.path}" }
            hashes[file.path] = snapshot.sha256
            if (file.path == modelPath) modelText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
            if (file.path == planPath) planText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
        }
        require(modelText != null && planText != null) { "audit requires manifest-bound program model and module plan" }
        UniqueJsonObjectKeyValidator(modelText).validate()
        val model = ProgramModelJson.read(modelText)
        require(manifest.inputSha256 == model.inputSha256) { "audit manifest and model input identities differ" }
        UniqueJsonObjectKeyValidator(planText).validate()
        val planJson = Json.parseToJsonElement(planText).jsonObject
        require(planJson.keys == setOf("schemaVersion", "modules", "dependencyCycles") &&
            !planJson.getValue("schemaVersion").jsonPrimitive.isString &&
            planJson.getValue("schemaVersion").jsonPrimitive.intOrNull == 2
        ) { "audit requires a closed schema-2 module plan" }
        val entities = model.functions.map { it.id } + model.globals.map { it.id } + model.types.map { it.id }
        val entitySet = entities.toSet()
        val functionIds = model.functions.mapTo(hashSetOf()) { it.id }
        val globalIds = model.globals.mapTo(hashSetOf()) { it.id }
        val typeIds = model.types.mapTo(hashSetOf()) { it.id }
        require(entitySet.size == entities.size) { "audit model entity identities are not unique" }
        require((manifest.unresolvedEntityIds + manifest.unresolvedImplementationIds +
            manifest.files.flatMap { it.entityIds }).all { it in entitySet }
        ) { "audit manifest references an unknown model entity" }
        val planned = mutableSetOf<String>()
        val moduleRevisions = linkedMapOf<String, String>()
        val implementationOwners = mutableSetOf<String>()
        for (element in planJson.getValue("modules").jsonArray) {
            val module = element.jsonObject
            require(module.keys == setOf("id", "sourcePath", "headerPath", "functionIds", "globalIds", "typeIds", "boundaryEvidence")) {
                "audit module fields differ from schema 2"
            }
            fun text(name: String): String = module.getValue(name).jsonPrimitive.let {
                require(it.isString) { "audit module $name must be a string" }
                it.content
            }
            fun identifiers(name: String, expected: Set<String>): List<String> = module.getValue(name).jsonArray.map {
                require(it.jsonPrimitive.isString && it.jsonPrimitive.content in expected) { "audit module $name references an unknown entity" }
                it.jsonPrimitive.content
            }.also { require(it.distinct().size == it.size) { "audit module $name contains duplicates" } }
            val functions = identifiers("functionIds", functionIds)
            val globals = identifiers("globalIds", globalIds)
            val types = identifiers("typeIds", typeIds)
            require(module.getValue("boundaryEvidence").jsonArray.all { it.jsonPrimitive.isString }) {
                "audit module boundary evidence must contain only strings"
            }
            val owned = functions + globals
            require(owned.all(implementationOwners::add)) { "audit module implementation ownership is duplicated" }
            planned += owned + types
            val identifier = text("id")
            val source = text("sourcePath")
            require(source == profile.layout.declaration("module-implementation").materialize(mapOf("module" to identifier)) &&
                text("headerPath") == profile.layout.declaration("module-interface").materialize(mapOf("module" to identifier))
            ) { "audit module paths do not match its profile-bound identity" }
            val file = requireNotNull(files[source]) { "audit module source is absent from its manifest: $source" }
            require(ProjectFileRole.MODULE_IMPLEMENTATION in file.roles && file.entityIds.toSet() == owned.toSet()) {
                "audit module source roles or entity ownership differ from the manifest: $source"
            }
            val header = requireNotNull(files[text("headerPath")]) { "audit module header is absent from its manifest" }
            require(ProjectFileRole.PUBLIC_INTERFACE in header.roles) { "audit module header has no declared interface role" }
            require(moduleRevisions.put(identifier, hashes.getValue(source)) == null) { "audit module IDs are duplicated" }
        }
        for (cycle in planJson.getValue("dependencyCycles").jsonArray) {
            val members = cycle.jsonArray.map {
                require(it.jsonPrimitive.isString && it.jsonPrimitive.content in moduleRevisions) { "audit dependency cycle references an unknown module" }
                it.jsonPrimitive.content
            }
            require(members.isNotEmpty() && members.distinct().size == members.size) { "audit dependency cycle is empty or duplicated" }
        }
        val declared = manifest.files.flatMapTo(hashSetOf()) { it.entityIds }
        val missingModel = entities.filter { it !in planned || it !in declared }
        val implementations = manifest.files.filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
        val interfaces = manifest.files.filter { ProjectFileRole.PUBLIC_INTERFACE in it.roles || ProjectFileRole.PRIVATE_INTERFACE in it.roles }
        val implementedIds = implementations.flatMapTo(hashSetOf()) { it.entityIds }
        val interfaceIds = interfaces.flatMapTo(hashSetOf()) { it.entityIds }
        val missingSource = (model.functions.map { it.id }.filter { it !in implementedIds } +
            model.globals.map { it.id }.filter { it !in implementedIds && it !in interfaceIds } +
            model.types.map { it.id }.filter { it !in interfaceIds }).distinct()
        val behavior = Files.walk(projectDir.resolve("reports")).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".behavior.json") }
                .toList().mapNotNull { path -> runCatching { Json.parseToJsonElement(path.readText()).jsonObject }.getOrNull() }
        }
        val matches = behavior.mapNotNull { it["matches"]?.jsonPrimitive?.booleanOrNull }
        val networks = behavior.mapNotNull { it["networkIsolated"]?.jsonPrimitive?.booleanOrNull }.toSet()
        val unresolvedBehavior = behavior.filter { it["matches"]?.jsonPrimitive?.booleanOrNull == false }
            .mapNotNull { it["id"]?.jsonPrimitive?.content }
        val audit = ArchivalAudit(
            entityCount = entities.size,
            missingModelProvenance = missingModel,
            missingSourceProvenance = missingSource,
            unresolvedEntityIds = (model.functions.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.globals.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                model.types.filter { it.status != RecoveryStatus.RECOVERED }.map { it.id } +
                manifest.unresolvedEntityIds + manifest.unresolvedImplementationIds +
                implementations.filter { it.acceptedImplementation != true }.flatMap { it.entityIds } +
                missingModel + missingSource).distinct().sorted(),
            behaviorReportCount = behavior.size,
            behaviorMatched = matches.takeIf { it.isNotEmpty() }?.all { it },
            sandboxReported = behavior.isNotEmpty() && behavior.all { it["sandbox"]?.jsonPrimitive?.content == "bubblewrap" },
            networkIsolation = networks,
            moduleRevisionSha256 = moduleRevisions,
            unresolvedBehaviorReportIds = unresolvedBehavior,
        )
        require(readStableRegularFile(projectDir, "source_tree_manifest.json", maximumFileBytes).sha256 == manifestSnapshot.sha256) {
            "audit manifest changed during verification"
        }
        for ((relative, expectedHash) in hashes) {
            require(readStableRegularFile(projectDir, relative, maximumFileBytes).sha256 == expectedHash) {
                "audit input changed before publication: $relative"
            }
        }
        writeProjectEvidenceAtomically(projectDir.resolve("reports/archival_audit.json"), audit.toJson())
        return audit
    }
}

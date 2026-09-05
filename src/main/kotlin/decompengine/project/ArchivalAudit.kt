package decompengine.project

import decompengine.repair.readStableRegularFile
import decompengine.validation.BehaviorEvidence
import decompengine.validation.BehaviorProjectContext
import decompengine.validation.boolean
import decompengine.validation.string
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

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
    val behaviorEvidenceProblems: Map<String, String> = emptyMap(),
    val projectBehaviorReportIds: List<String> = emptyList(),
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
          "moduleSourceRevisions": [${moduleRevisionSha256.toSortedMap().entries.joinToString(",") { (id, hash) -> "{\"moduleId\":${JsonPrimitive(id)},\"sourceRevisionSha256\":${JsonPrimitive(hash)}}" }}],
          "moduleBehaviorEvidence": [],
          "moduleExecutionCoverage": "not-observed",
          "projectBehaviorReportIds": [${projectBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "isolationAssurance": "local requests only; no retained production containment evidence",
          "behaviorEvidenceProblems": {${behaviorEvidenceProblems.toSortedMap().entries.joinToString(",") { (path, problem) -> "${JsonPrimitive(path)}:${JsonPrimitive(problem)}" }}},
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
        fun discoverBehaviorReports(): List<Path> {
            val reports = projectDir.resolve("reports")
            if (!Files.exists(reports, LinkOption.NOFOLLOW_LINKS)) return emptyList()
            require(!Files.isSymbolicLink(reports)) { "behavior reports directory is a symbolic link" }
            return Files.walk(reports, 32).use { stream ->
                val entries = stream.limit(profile.budgets.archiveMaximumEntries.toLong() + 1L).toList()
                require(entries.size <= profile.budgets.archiveMaximumEntries) { "behavior report inventory exceeds its bound" }
                for (entry in entries) {
                    require(!Files.isSymbolicLink(entry) || entry.fileName.toString().endsWith(".behavior.json")) {
                        "behavior report inventory contains a link: $entry"
                    }
                    if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) && reports.relativize(entry).nameCount >= 32) {
                        require(Files.newDirectoryStream(entry).use { !it.iterator().hasNext() }) {
                            "behavior report inventory exceeds its depth bound"
                        }
                    }
                }
                entries.filter { it.fileName.toString().endsWith(".behavior.json") }.sorted()
            }
        }
        val behaviorPaths = discoverBehaviorReports()
        val problems = linkedMapOf<String, String>()
        val verifiedBehavior = linkedMapOf<String, Boolean>()
        val behaviorHashes = linkedMapOf<String, String>()
        val reportIds = hashSetOf<String>()
        var currentProjectRecord: JsonObject? = null
        var behaviorBytes = 0L
        for (path in behaviorPaths) {
            val relative = projectDir.relativize(path).toString()
            try {
                val snapshot = readStableRegularFile(projectDir, relative, minOf(maximumFileBytes, BehaviorEvidence.MAXIMUM_REPORT_BYTES))
                behaviorBytes = Math.addExact(behaviorBytes, snapshot.bytes.size.toLong())
                require(behaviorBytes <= profile.budgets.archiveMaximumTotalBytes - totalBytes) {
                    "behavior report bytes exceed the remaining aggregate bound"
                }
                val record = BehaviorEvidence.decode(snapshot.bytes)
                val current = currentProjectRecord
                if (current == null) {
                    BehaviorEvidence.requireProjectCurrent(record, BehaviorProjectContext(projectDir, profile))
                    currentProjectRecord = record
                } else {
                    require(record.getValue("projectRevision") == current.getValue("projectRevision")) {
                        "behavior evidence refers to a stale or foreign project revision"
                    }
                }
                val identifier = record.string("id")
                require(reportIds.add(identifier)) { "behavior report ID is duplicated" }
                verifiedBehavior[relative] = record.boolean("matches")
                behaviorHashes[relative] = snapshot.sha256
            } catch (failure: Exception) {
                if (failure is InterruptedException) throw failure
                problems[relative] = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
            }
        }
        if (behaviorPaths.isEmpty()) problems["no-behavior-evidence"] = "No revision-bound behavior record is available"
        val unresolvedBehavior = problems.keys + verifiedBehavior.filterValues { !it }.keys
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
            behaviorReportCount = behaviorPaths.size,
            behaviorMatched = when {
                verifiedBehavior.values.any { !it } -> false
                problems.isNotEmpty() || verifiedBehavior.isEmpty() -> null
                else -> true
            },
            sandboxReported = verifiedBehavior.isNotEmpty() && problems.isEmpty(),
            networkIsolation = emptySet(),
            moduleRevisionSha256 = moduleRevisions,
            unresolvedBehaviorReportIds = unresolvedBehavior.sorted(),
            behaviorEvidenceProblems = problems,
            projectBehaviorReportIds = verifiedBehavior.keys.sorted(),
        )
        require(readStableRegularFile(projectDir, "source_tree_manifest.json", maximumFileBytes).sha256 == manifestSnapshot.sha256) {
            "audit manifest changed during verification"
        }
        for ((relative, expectedHash) in hashes) {
            require(readStableRegularFile(projectDir, relative, maximumFileBytes).sha256 == expectedHash) {
                "audit input changed before publication: $relative"
            }
        }
        require(discoverBehaviorReports() == behaviorPaths) { "behavior report inventory changed during audit" }
        for ((relative, expectedHash) in behaviorHashes) {
            val snapshot = readStableRegularFile(projectDir, relative, minOf(maximumFileBytes, BehaviorEvidence.MAXIMUM_REPORT_BYTES))
            require(snapshot.sha256 == expectedHash) { "behavior report changed before audit publication" }
        }
        currentProjectRecord?.let { BehaviorEvidence.requireProjectCurrent(it, BehaviorProjectContext(projectDir, profile)) }
        writeProjectEvidenceAtomically(projectDir.resolve("reports/archival_audit.json"), audit.toJson())
        return audit
    }
}

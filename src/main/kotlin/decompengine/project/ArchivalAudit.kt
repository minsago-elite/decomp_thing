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
    val moduleCompilationEvidenceProblems: Map<String, String> = emptyMap(),
    val requiredCorpusSha256: List<String> = emptyList(),
    val observedPortableCorpusSha256: List<String> = emptyList(),
    val recoveryAssessment: JsonObject? = null,
) {
    val provenanceComplete: Boolean get() = missingModelProvenance.isEmpty() && missingSourceProvenance.isEmpty()
    val universalEquivalenceClaim: Boolean = false

    fun toJson(): String = """
        {
          "entityCount": $entityCount,
          "recoveryAssessment": ${recoveryAssessment ?: "null"},
          "provenanceComplete": $provenanceComplete,
          "missingModelProvenance": [${missingModelProvenance.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "missingSourceProvenance": [${missingSourceProvenance.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "unresolvedEntityIds": [${unresolvedEntityIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "behaviorReportCount": $behaviorReportCount,
          "requiredCorpusSha256": [${requiredCorpusSha256.joinToString(",") { JsonPrimitive(it).toString() }}],
          "observedPortableCorpusSha256": [${observedPortableCorpusSha256.joinToString(",") { JsonPrimitive(it).toString() }}],
          "behaviorMatched": ${behaviorMatched ?: "null"},
          "sandboxReported": $sandboxReported,
          "networkIsolationObserved": [${networkIsolation.sorted().joinToString(",")}],
          "moduleSourceRevisions": [${moduleRevisionSha256.toSortedMap().entries.joinToString(",") { (id, hash) -> "{\"moduleId\":${JsonPrimitive(id)},\"sourceRevisionSha256\":${JsonPrimitive(hash)}}" }}],
          "moduleBehaviorEvidence": [],
          "moduleCompilationEvidenceProblems": {${moduleCompilationEvidenceProblems.toSortedMap().entries.joinToString(",") { (id, problem) -> "${JsonPrimitive(id)}:${JsonPrimitive(problem)}" }}},
          "moduleExecutionCoverage": "not-observed",
          "projectBehaviorReportIds": [${projectBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "isolationAssurance": "local requests only; no retained production containment evidence",
          "behaviorEvidenceProblems": {${behaviorEvidenceProblems.toSortedMap().entries.joinToString(",") { (path, problem) -> "${JsonPrimitive(path)}:${JsonPrimitive(problem)}" }}},
          "unresolvedBehaviorReportIds": [${unresolvedBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "universalEquivalenceClaim": false,
          "limitation": "Extraction, compilation and local behavior observations do not establish calibrated recovery accuracy; untested behavior remains unresolved."
        }
    """.trimIndent() + "\n"
}

internal fun snapshotRequiredBehaviorCorpora(required: Set<String>): Set<String> {
    require(required.size <= 1024) { "audit required corpus count exceeds its bound" }
    val snapshot = required.toSet()
    require(snapshot.all { it.matches(Regex("[0-9a-f]{64}")) }) { "audit required corpus identities must be lowercase SHA-256" }
    return snapshot
}

object ArchivalProjectAuditor {
    fun audit(
        projectDir: Path,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        requiredCorpusSha256: Set<String> = emptySet(),
    ): ArchivalAudit {
        val requiredCorpora = snapshotRequiredBehaviorCorpora(requiredCorpusSha256)
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
        val compilationProblems = linkedMapOf<String, String>()
        val compilationUnresolved = mutableSetOf<String>()
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
            if (file.acceptedImplementation == true) {
                try {
                    val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to identifier))
                    val expectedHash = requireNotNull(hashes[checkpointPath]) { "module compiler checkpoint is absent from the manifest" }
                    val snapshot = readStableRegularFile(projectDir, checkpointPath, maximumFileBytes)
                    require(snapshot.sha256 == expectedHash) { "module compiler checkpoint changed during audit" }
                    val checkpointText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
                    UniqueJsonObjectKeyValidator(checkpointText).validate()
                    val checkpoint = Json.parseToJsonElement(checkpointText).jsonObject
                    require(checkpoint.getValue("schemaVersion") == JsonPrimitive(5)) {
                        "module checkpoint lacks the supported compiler acceptance schema"
                    }
                    require(checkpoint.boolean("accepted")) { "module checkpoint does not record acceptance" }
                    require(checkpoint.getValue("issues").jsonArray.isEmpty()) {
                        "accepted module checkpoint retains unresolved reconstruction issues"
                    }
                    val acceptedEntities = checkpoint.getValue("entityStatuses").jsonArray.map { element ->
                        val status = element.jsonObject
                        require(status.keys == setOf("id", "status") && status.string("status") == "accepted") {
                            "module checkpoint entity status does not record acceptance"
                        }
                        status.string("id")
                    }
                    require(acceptedEntities.size == acceptedEntities.toSet().size && acceptedEntities.toSet() == owned.toSet()) {
                        "module checkpoint entity ownership differs from the module plan"
                    }
                    require(checkpoint.string("sourceSha256") == hashes.getValue(source)) { "module checkpoint does not bind the current source" }
                    val compilation = checkpoint.getValue("compilation").jsonObject
                    require(compilation.string("sourceSha256") == hashes.getValue(source)) { "compiler evidence does not bind the current source" }
                    require(compilation.string("outcome") == "passed" && compilation.getValue("returnCode") == JsonPrimitive(0)) {
                        "module compiler gate did not pass"
                    }
                    val command = compilation.getValue("command").jsonArray.map {
                        require(it.jsonPrimitive.isString) { "compiler argument must be a string" }
                        it.jsonPrimitive.content
                    }
                    require(command == GeneratedCModuleValidation.command(profile, source)) { "compiler command differs from the reconstruction profile" }
                } catch (failure: Exception) {
                    if (failure is InterruptedException) throw failure
                    compilationProblems[identifier] = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
                    compilationUnresolved += owned
                }
            }
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
        val observedCorpora = sortedSetOf<String>()
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
                require(record.getValue("schemaVersion").jsonPrimitive.intOrNull == 4) {
                    "behavior record lacks independent local completion evidence"
                }
                val portable = record.getValue("schemaVersion").jsonPrimitive.intOrNull in setOf(3, 4)
                val corpus = record.string("corpusSha256")
                if (requiredCorpora.isNotEmpty()) {
                    require(portable && corpus in requiredCorpora) { "behavior report does not match a required portable corpus" }
                }
                verifiedBehavior[relative] = record.boolean("matches")
                behaviorHashes[relative] = snapshot.sha256
                if (portable) observedCorpora += corpus
            } catch (failure: Exception) {
                if (failure is InterruptedException) throw failure
                problems[relative] = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
            }
        }
        if (behaviorPaths.isEmpty()) problems["no-behavior-evidence"] = "No revision-bound behavior record is available"
        for (missing in (requiredCorpora - observedCorpora).sorted()) {
            problems["missing-corpus:$missing"] = "No current revision-bound report covers the required corpus"
        }
        val unresolvedBehavior = problems.keys + verifiedBehavior.filterValues { !it }.keys
        val audit = ArchivalAudit(
            entityCount = entities.size,
            missingModelProvenance = missingModel,
            missingSourceProvenance = missingSource,
            unresolvedEntityIds = (model.functions.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.globals.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.types.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
                manifest.unresolvedEntityIds + manifest.unresolvedImplementationIds +
                implementations.filter { it.acceptedImplementation != true }.flatMap { it.entityIds } +
                missingModel + missingSource + compilationUnresolved).distinct().sorted(),
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
            moduleCompilationEvidenceProblems = compilationProblems,
            requiredCorpusSha256 = requiredCorpora.sorted(),
            observedPortableCorpusSha256 = observedCorpora.toList(),
            recoveryAssessment = model.unassessedRecoveryAssessment(sha256(modelText.toByteArray(Charsets.UTF_8))),
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

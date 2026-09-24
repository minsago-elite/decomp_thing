package decompengine.project

import decompengine.repair.readStableRegularFile
import decompengine.validation.BehaviorEvidence
import decompengine.validation.BehaviorProjectContext
import decompengine.validation.boolean
import decompengine.validation.string
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Locale

data class ArchivePublicationLimits(
    val maximumEntries: Int,
    val maximumFileBytes: Long,
    val maximumTotalBytes: Long,
) {
    init {
        require(maximumEntries > 0) { "archive publication entry limit must be positive" }
        require(maximumFileBytes > 0) { "archive publication file limit must be positive" }
        require(maximumTotalBytes >= maximumFileBytes) {
            "archive publication total limit must be at least the file limit"
        }
    }

    internal fun toJson(): String = """
        {"maximumEntries":$maximumEntries,"maximumFileBytes":$maximumFileBytes,"maximumTotalBytes":$maximumTotalBytes}
    """.trimIndent()

    companion object {
        fun from(limits: ArchivalBundleLimits): ArchivePublicationLimits = ArchivePublicationLimits(
            limits.maximumEntries, limits.maximumFileBytes, limits.maximumTotalBytes,
        )

        fun from(budgets: ReconstructionBudgets): ArchivePublicationLimits = ArchivePublicationLimits(
            budgets.archiveMaximumEntries, budgets.archiveMaximumFileBytes, budgets.archiveMaximumTotalBytes,
        )
    }
}

data class ArchivePublicationEvidence(
    val profileId: String,
    val profileSha256: String,
    val profileLimits: ArchivePublicationLimits,
    val hostLimits: ArchivePublicationLimits,
    val effectiveLimits: ArchivePublicationLimits,
    val outcome: String,
) {
    init {
        require(profileId.isNotBlank()) { "archive publication profile ID must not be blank" }
        require(profileSha256.matches(Regex("[0-9a-f]{64}"))) {
            "archive publication profile digest is invalid"
        }
        require(outcome.isNotBlank()) { "archive publication outcome must not be blank" }
        require(effectiveLimits.maximumEntries <= profileLimits.maximumEntries)
        require(effectiveLimits.maximumFileBytes <= profileLimits.maximumFileBytes)
        require(effectiveLimits.maximumTotalBytes <= profileLimits.maximumTotalBytes)
        require(effectiveLimits.maximumEntries <= hostLimits.maximumEntries)
        require(effectiveLimits.maximumFileBytes <= hostLimits.maximumFileBytes)
        require(effectiveLimits.maximumTotalBytes <= hostLimits.maximumTotalBytes)
    }

    internal fun toJson(): String = """
        {
          "profileId": ${JsonPrimitive(profileId)},
          "profileSha256": "$profileSha256",
          "profileLimits": ${profileLimits.toJson()},
          "hostLimits": ${hostLimits.toJson()},
          "effectiveLimits": ${effectiveLimits.toJson()},
          "outcome": ${JsonPrimitive(outcome)}
        }
    """.trimIndent()

    companion object {
        fun forProfile(
            profile: ReconstructionProfile,
            hostSafetyLimits: ReconstructionHostSafetyLimits,
            effectiveLimits: ArchivalBundleLimits,
            outcome: String,
        ): ArchivePublicationEvidence = ArchivePublicationEvidence(
            profileId = profile.id,
            profileSha256 = profile.sha256,
            profileLimits = ArchivePublicationLimits.from(profile.budgets),
            hostLimits = ArchivePublicationLimits.from(hostSafetyLimits.maximum),
            effectiveLimits = ArchivePublicationLimits.from(effectiveLimits),
            outcome = outcome,
        )
    }
}

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
    val moduleConfidenceEvidenceProblems: Map<String, String> = emptyMap(),
    val requiredCorpusSha256: List<String> = emptyList(),
    val observedPortableCorpusSha256: List<String> = emptyList(),
    val recoveryAssessment: JsonObject? = null,
    val moduleCompilationEvidence: Map<String, JsonObject> = emptyMap(),
    val archivePublication: ArchivePublicationEvidence? = null,
    internal val behaviorReportSha256: Map<String, String> = emptyMap(),
) {
    val provenanceComplete: Boolean get() = missingModelProvenance.isEmpty() && missingSourceProvenance.isEmpty()
    val equivalence: EquivalenceAssessment
        get() = assessEquivalence(
            requiredCorpusSha256 = requiredCorpusSha256,
            observedPortableCorpusSha256 = observedPortableCorpusSha256,
            behaviorMatched = behaviorMatched,
            behaviorEvidenceProblems = behaviorEvidenceProblems,
            unresolvedBehaviorReportIds = unresolvedBehaviorReportIds,
        )

    // Retained for archive compatibility. A passing selected corpus is not a universal claim.
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
          "equivalenceStatus": ${JsonPrimitive(equivalence.status.wireValue)},
          "equivalenceBlockers": [${equivalence.blockers.joinToString(",") { JsonPrimitive(it).toString() }}],
          "sandboxReported": $sandboxReported,
          "networkIsolationObserved": [${networkIsolation.sorted().joinToString(",")}],
          "moduleSourceRevisions": [${moduleRevisionSha256.toSortedMap().entries.joinToString(",") { (id, hash) -> "{\"moduleId\":${JsonPrimitive(id)},\"sourceRevisionSha256\":${JsonPrimitive(hash)}}" }}],
          "moduleBehaviorEvidence": [],
          "moduleCompilationEvidenceProblems": {${moduleCompilationEvidenceProblems.toSortedMap().entries.joinToString(",") { (id, problem) -> "${JsonPrimitive(id)}:${JsonPrimitive(problem)}" }}},
          "moduleConfidenceEvidenceProblems": {${moduleConfidenceEvidenceProblems.toSortedMap().entries.joinToString(",") { (id, problem) -> "${JsonPrimitive(id)}:${JsonPrimitive(problem)}" }}},
          "moduleCompilationEvidence": ${JsonObject(moduleCompilationEvidence.toSortedMap())},
          "moduleExecutionCoverage": "not-observed",
          "projectBehaviorReportIds": [${projectBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "isolationAssurance": "local requests only; no retained production containment evidence",
          "behaviorEvidenceProblems": {${behaviorEvidenceProblems.toSortedMap().entries.joinToString(",") { (path, problem) -> "${JsonPrimitive(path)}:${JsonPrimitive(problem)}" }}},
          "unresolvedBehaviorReportIds": [${unresolvedBehaviorReportIds.sorted().joinToString(",") { JsonPrimitive(it).toString() }}],
          "archivePublication": ${archivePublication?.toJson() ?: "null"},
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
    @JvmOverloads
    fun audit(
        projectDir: Path,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        requiredCorpusSha256: Set<String> = emptySet(),
        hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
        publication: ArchivePublicationEvidence? = null,
        limits: ArchivalBundleLimits = ArchivalBundleLimits(),
        publish: Boolean = true,
    ): ArchivalAudit {
        hostSafetyLimits.requireAllows(profile.budgets)
        val effectiveLimits = limits.constrainedTo(profile)
        val publicationEvidence = publication ?: ArchivePublicationEvidence.forProfile(
            profile, hostSafetyLimits, effectiveLimits, "audited",
        )
        val expectedPublication = ArchivePublicationEvidence.forProfile(
            profile,
            hostSafetyLimits,
            effectiveLimits,
            if (publication == null) "audited" else "prepared",
        )
        require(publicationEvidence.profileId == expectedPublication.profileId &&
            publicationEvidence.profileSha256 == expectedPublication.profileSha256 &&
            publicationEvidence.profileLimits == expectedPublication.profileLimits &&
            publicationEvidence.hostLimits == expectedPublication.hostLimits &&
            publicationEvidence.effectiveLimits == expectedPublication.effectiveLimits) {
            "archive publication evidence does not match the selected profile or effective budgets"
        }
        val compilationPolicy = ReconstructionCompilationPolicies.resolve(profile)
        val requiredCorpora = snapshotRequiredBehaviorCorpora(requiredCorpusSha256)
        val maximumFileBytes = minOf(effectiveLimits.maximumFileBytes, Int.MAX_VALUE.toLong() - 1L)
        val manifestSnapshot = readStableRegularFile(projectDir, "source_tree_manifest.json", maximumFileBytes)
        val manifest = SourceTreeManifestReader.parse(manifestSnapshot.bytes.decodeToString(throwOnInvalidSequence = true), profile)
        require(manifest.files.size <= effectiveLimits.maximumEntries) { "audit manifest exceeds the file-count bound" }
        val modelPath = profile.layout.declaration("program-model-evidence").materialize()
        val planPath = profile.layout.declaration("module-plan-evidence").materialize()
        val confidencePath = profile.layout.declaration("confidence-evidence").materialize()
        val files = manifest.files.associateBy { it.path }
        val hashes = linkedMapOf<String, String>()
        var totalBytes = manifestSnapshot.bytes.size.toLong()
        var modelText: String? = null
        var planText: String? = null
        var confidenceText: String? = null
        for (file in manifest.files) {
            val snapshot = readStableRegularFile(projectDir, file.path, maximumFileBytes)
            totalBytes = Math.addExact(totalBytes, snapshot.bytes.size.toLong())
            require(totalBytes <= effectiveLimits.maximumTotalBytes) { "audit input exceeds the aggregate byte bound" }
            require(snapshot.sha256 == file.sha256) { "audit manifest hash differs from current file: ${file.path}" }
            hashes[file.path] = snapshot.sha256
            if (file.path == modelPath) modelText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
            if (file.path == planPath) planText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
            if (file.path == confidencePath) confidenceText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
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
        val confidenceProblems = linkedMapOf<String, String>()
        val compilationEvidence = linkedMapOf<String, JsonObject>()
        val compilationUnresolved = mutableSetOf<String>()
        val acceptedOwners = linkedMapOf<String, List<String>>()
        val acceptedSourcePaths = linkedMapOf<String, String>()
        val acceptedInputFingerprints = linkedMapOf<String, String>()
        val plannedModuleEntityIds = linkedMapOf<String, List<String>>()
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
            plannedModuleEntityIds[identifier] = owned + types
            if (file.acceptedImplementation == true) {
                acceptedOwners[identifier] = owned
                acceptedSourcePaths[identifier] = source
                try {
                    val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to identifier))
                    val expectedHash = requireNotNull(hashes[checkpointPath]) { "module compiler checkpoint is absent from the manifest" }
                    val snapshot = readStableRegularFile(projectDir, checkpointPath, maximumFileBytes)
                    require(snapshot.sha256 == expectedHash) { "module compiler checkpoint changed during audit" }
                    val checkpointText = snapshot.bytes.decodeToString(throwOnInvalidSequence = true)
                    UniqueJsonObjectKeyValidator(checkpointText).validate()
                    val checkpoint = Json.parseToJsonElement(checkpointText).jsonObject
                    require(checkpoint.getValue("schemaVersion") == JsonPrimitive(6)) {
                        "module checkpoint lacks the supported compiler acceptance schema"
                    }
                    require(checkpoint.string("inputBinarySha256") == model.inputSha256 &&
                        checkpoint.getValue("modelSchemaVersion") == JsonPrimitive(model.schemaVersion) &&
                        checkpoint.string("profileSha256") == profile.sha256) {
                        "module checkpoint input identity differs from the audited model or profile"
                    }
                    require(checkpoint.boolean("accepted")) { "module checkpoint does not record acceptance" }
                    val claimsAgentExecution = moduleClaimsAgentExecution(
                        checkpoint.string("generator"), checkpoint.string("reconstructorIdentity"),
                    )
                    val promptCharacters = (checkpoint["promptCharacters"] as? JsonPrimitive)
                        ?.takeUnless { it.isString }?.longOrNull
                    val promptBudgetCharacters = (checkpoint["promptBudgetCharacters"] as? JsonPrimitive)
                        ?.takeUnless { it.isString }?.longOrNull
                    require(modulePromptAttributionIsValid(
                        claimsAgentExecution, promptCharacters, promptBudgetCharacters, profile,
                    )) {
                        "accepted checkpoint prompt budget is missing, invalid, or exceeds the reconstruction profile"
                    }
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
                    acceptedInputFingerprints[identifier] = checkpoint.string("fingerprint")
                    val compilation = checkpoint.getValue("compilation").jsonObject
                    require(compilation.string("sourceSha256") == hashes.getValue(source)) { "compiler evidence does not bind the current source" }
                    require(compilation.string("outcome") == "passed" && compilation.getValue("returnCode") == JsonPrimitive(0)) {
                        "module compiler gate did not pass"
                    }
                    val command = compilation.getValue("command").jsonArray.map {
                        require(it.jsonPrimitive.isString) { "compiler argument must be a string" }
                        it.jsonPrimitive.content
                    }
                    require(command == compilationPolicy.command(profile, source)) { "compiler command differs from the reconstruction profile" }
                    require(compilation.keys == setOf("sourceSha256", "command", "outcome", "returnCode", "diagnosticsSha256", "diagnosticsBytes")) {
                        "compiler evidence has unsupported fields"
                    }
                    require(compilation.string("diagnosticsSha256").matches(Regex("[0-9a-f]{64}"))) {
                        "compiler diagnostic commitment is invalid"
                    }
                    val diagnosticBytes = compilation.getValue("diagnosticsBytes").jsonPrimitive
                    require(!diagnosticBytes.isString && diagnosticBytes.longOrNull?.let {
                        it in 0..profile.budgets.buildMaximumOutputBytes
                    } == true) { "compiler diagnostic byte count is invalid" }
                    compilationEvidence[identifier] = JsonObject(linkedMapOf(
                        "sourcePath" to JsonPrimitive(source),
                        "sourceSha256" to JsonPrimitive(hashes.getValue(source)),
                        "checkpointPath" to JsonPrimitive(checkpointPath),
                        "checkpointSha256" to JsonPrimitive(snapshot.sha256),
                        "inputBinarySha256" to JsonPrimitive(model.inputSha256),
                        "modelSchemaVersion" to JsonPrimitive(model.schemaVersion),
                        "profileSha256" to JsonPrimitive(profile.sha256),
                        "compilation" to compilation,
                    ))
                } catch (failure: Exception) {
                    if (failure is InterruptedException) throw failure
                    compilationProblems[identifier] = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
                    compilationUnresolved += owned
                }
            }
        }
        if (acceptedOwners.isNotEmpty()) {
            val confidence = try {
                val text = requireNotNull(confidenceText) { "accepted modules require manifest-bound confidence evidence" }
                UniqueJsonObjectKeyValidator(text).validate()
                val report = Json.parseToJsonElement(text).jsonObject
                require(report.getValue("schemaVersion") == JsonPrimitive(2)) { "confidence evidence has an unsupported schema" }
                require(report.string("basis") == "recovery evidence only; behavioral equivalence is not implied" &&
                    report.string("scoreMeaning") ==
                    "structural recovery heuristic; not implementation acceptance or measured behavioral confidence") {
                    "confidence evidence mislabels structural recovery as measured behavior"
                }
                val interpretation = report.getValue("scoreInterpretation").jsonObject
                require(interpretation.string("kind") == "structural-recovery" &&
                    interpretation.string("calibrationStatus") == "uncalibrated" &&
                    interpretation.getValue("calibratedProbability") == JsonNull &&
                    interpretation.getValue("empiricalSampleCount") == JsonNull) {
                    "confidence evidence presents an unmeasured score as behavioral confidence"
                }
                fun score(status: RecoveryStatus) = when (status) {
                    RecoveryStatus.RECOVERED -> 1.0
                    RecoveryStatus.PARTIAL -> 0.6
                    RecoveryStatus.SYNTHETIC -> 0.25
                    RecoveryStatus.FAILED -> 0.0
                }
                val entityScores = (model.functions.map { it.id to score(it.status) } +
                    model.globals.map { it.id to score(it.status) } +
                    model.types.map { it.id to score(it.status) }).toMap()
                fun expectedScore(ids: List<String>): String = "%.4f".format(Locale.ROOT,
                    if (ids.isEmpty()) 0.0 else ids.map(entityScores::getValue).average())
                fun requireScore(value: kotlinx.serialization.json.JsonElement, expected: String) {
                    val actual = value.jsonPrimitive
                    require(!actual.isString && actual.content == expected) {
                        "confidence structural score differs from the audited recovery model"
                    }
                }
                requireScore(report.getValue("projectScore"), expectedScore(entityScores.keys.toList()))
                val recoveryUnresolved = (model.functions.map { it.id to it.status } +
                    model.globals.map { it.id to it.status } +
                    model.types.map { it.id to it.status })
                    .filter { (_, status) -> model.isRecoveryUnresolved(status) }.map { it.first }.toSet()
                val implementationUnresolved = manifest.unresolvedImplementationIds.toSet()
                fun requireIds(record: JsonObject, field: String, expected: Collection<String>) {
                    val actual = record.getValue(field).jsonArray.map { value ->
                        require(value.jsonPrimitive.isString) { "confidence $field contains a non-string entity ID" }
                        value.jsonPrimitive.content
                    }
                    require(actual == expected.distinct().sorted()) {
                        "confidence $field differs from the audited unresolved entities"
                    }
                }
                requireIds(report, "unresolvedRecoveryEntityIds", recoveryUnresolved)
                requireIds(report, "unresolvedImplementationIds", implementationUnresolved)
                requireIds(report, "unresolvedEntityIds", recoveryUnresolved + implementationUnresolved)
                val entries = report.getValue("modules").jsonArray.map { it.jsonObject }
                val byId = entries.associateBy { it.string("id") }
                require(entries.size == byId.size && byId.keys == moduleRevisions.keys) {
                    "confidence module inventory differs from the audited plan"
                }
                byId.forEach { (id, module) ->
                    val owned = plannedModuleEntityIds.getValue(id)
                    requireScore(module.getValue("score"), expectedScore(owned))
                    requireIds(module, "unresolvedRecoveryEntityIds", owned.filter { it in recoveryUnresolved })
                    requireIds(module, "unresolvedImplementationIds", owned.filter { it in implementationUnresolved })
                }
                byId
            } catch (failure: Exception) {
                if (failure is InterruptedException) throw failure
                val reason = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
                acceptedOwners.forEach { (id, owners) ->
                    if (id !in compilationEvidence) return@forEach
                    confidenceProblems[id] = reason
                    compilationProblems.putIfAbsent(id, reason)
                    compilationEvidence.remove(id)
                    compilationUnresolved += owners
                }
                emptyMap()
            }
            for ((id, owners) in acceptedOwners) {
                if (id !in compilationEvidence) continue
                try {
                    val revision = requireNotNull(confidence[id]) { "accepted module confidence evidence is missing" }
                        .getValue("revisionEvidence").jsonObject
                    val source = acceptedSourcePaths.getValue(id)
                    val checkpoint = profile.layout.declaration("module-evidence").materialize(mapOf("module" to id))
                    require(revision.keys == setOf("sourcePath", "sourceSha256", "inputFingerprint",
                        "inputFingerprintProvider", "inputBinarySha256", "modelSchemaVersion", "checkpointPath",
                        "checkpointSha256", "acceptedImplementation", "compilation", "behavior")) {
                        "accepted module confidence revision fields are incomplete or unsupported"
                    }
                    require(revision.string("sourcePath") == source &&
                        revision.string("sourceSha256") == moduleRevisions.getValue(id) &&
                        revision.string("inputFingerprint") == acceptedInputFingerprints.getValue(id) &&
                        revision.string("inputFingerprintProvider") == "module-reconstruction-input-v2" &&
                        revision.string("inputBinarySha256") == model.inputSha256 &&
                        revision.getValue("modelSchemaVersion") == JsonPrimitive(model.schemaVersion) &&
                        revision.string("checkpointPath") == checkpoint &&
                        revision.string("checkpointSha256") == hashes.getValue(checkpoint) &&
                        revision.getValue("acceptedImplementation") == JsonPrimitive(true) &&
                        revision.getValue("compilation") == compilationEvidence.getValue(id).getValue("compilation")) {
                        "accepted module confidence evidence is missing or cross-paired with another revision"
                    }
                    val behavior = revision.getValue("behavior").jsonObject
                    require(behavior.keys == setOf("status", "reason", "coverage", "outputAgreement", "unobservedBehavior") &&
                        behavior.string("status") == "unknown" && behavior.getValue("coverage") == JsonNull &&
                        behavior.getValue("outputAgreement") == JsonNull &&
                        behavior.string("unobservedBehavior") == "unknown") {
                        "accepted module confidence evidence overstates unobserved behavior"
                    }
                } catch (failure: Exception) {
                    if (failure is InterruptedException) throw failure
                    val reason = failure.message.orEmpty().take(512).ifEmpty { failure.javaClass.simpleName }
                    confidenceProblems[id] = reason
                    compilationProblems.putIfAbsent(id, reason)
                    compilationEvidence.remove(id)
                    compilationUnresolved += owners
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
                val entries = stream.limit(effectiveLimits.maximumEntries.toLong() + 1L).toList()
                require(entries.size <= effectiveLimits.maximumEntries) { "behavior report inventory exceeds its bound" }
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
            moduleConfidenceEvidenceProblems = confidenceProblems,
            moduleCompilationEvidence = compilationEvidence,
            requiredCorpusSha256 = requiredCorpora.sorted(),
            observedPortableCorpusSha256 = observedCorpora.toList(),
            recoveryAssessment = model.unassessedRecoveryAssessment(sha256(modelText.toByteArray(Charsets.UTF_8))),
            archivePublication = publicationEvidence,
            behaviorReportSha256 = behaviorHashes.toMap(),
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
        if (publish) writeProjectEvidenceAtomically(projectDir.resolve("reports/archival_audit.json"), audit.toJson())
        return audit
    }
}

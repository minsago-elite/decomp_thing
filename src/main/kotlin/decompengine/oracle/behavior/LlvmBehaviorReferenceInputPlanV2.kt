package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorReferenceInputPlanV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * The reviewed input side of the LLVM behavior reference plan.
 *
 * This value contains no reference executable, runtime declaration, expected output, observation,
 * comparison, score, or START authority. ACP remains visible as the first-class candidate
 * producer/operator, but every ACP oracle/reference authority is fixed false.
 */
sealed interface LlvmBehaviorReferenceInputPlanV2 {
    val authority: String
    val schemaVersion: Int
    val planId: String
    val planBytes: Long
    val planSha256: String
    val schemaSha256: String
    val caseIds: List<String>
    val executionOrder: List<String>
    val diagnosticOwners: Map<String, String>
    val literalInputCount: Int
    val freshArtifactDependencyCount: Int
    val referenceInputPlanValidated: Boolean

    val acpRole: String
    val acpCandidateContribution: String
    val acpCandidateProvenanceAccess: String
    val acpCandidateAdmissionOwner: String
    val acpCandidateLiveExecutionOwner: String
    val acpReferenceSubjectAdmission: String
    val acpOracleAuthority: Boolean
    val acpReferenceAuthoringAuthority: Boolean
    val acpPolicyAuthoringAuthority: Boolean
    val acpValidationAuthority: Boolean
    val acpObservationAuthoringAuthority: Boolean
    val acpStartAuthority: Boolean
    val acpContainmentAuthority: Boolean
    val acpTerminalAbsenceAuthority: Boolean
    val acpScoringAuthority: Boolean
    val acpCertificationAuthority: Boolean
    val acpReleaseAuthority: Boolean

    val definitionBound: Boolean
    val expectedOutputsPresent: Boolean
    val referenceSubjectPinned: Boolean
    val observationsCaptured: Boolean
    val referenceTruthEstablished: Boolean
    val runtimePreflightVerified: Boolean
    val liveContainmentVerified: Boolean
    val terminalAbsenceVerified: Boolean
    val candidateStarted: Boolean
    val startAuthorized: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val releaseEligible: Boolean
}

/** Production entry point: a caller can provide only the exact raw input-plan path. */
object LlvmBehaviorReferenceInputPlanV2Verifier {
    fun verify(inputPlanPath: Path): LlvmBehaviorReferenceInputPlanV2 = VerifiedInputPlan(inputPlanPath)

    /* Reflection can supply only the same raw Path and therefore cannot inject accepted facts. */
    private class VerifiedInputPlan(inputPlanPath: Path) : LlvmBehaviorReferenceInputPlanV2 {
        override val authority = INPUT_PLAN_AUTHORITY
        override val schemaVersion = INPUT_PLAN_SCHEMA_VERSION
        override val planId = INPUT_PLAN_ID
        override val planBytes: Long
        override val planSha256: String
        override val schemaSha256: String
        override val caseIds: List<String>
        override val executionOrder: List<String>
        override val diagnosticOwners: Map<String, String>
        override val literalInputCount: Int
        override val freshArtifactDependencyCount: Int
        override val referenceInputPlanValidated = true

        override val acpRole = ACP_ROLE
        override val acpCandidateContribution = ACP_CANDIDATE_CONTRIBUTION
        override val acpCandidateProvenanceAccess = ACP_CANDIDATE_PROVENANCE_ACCESS
        override val acpCandidateAdmissionOwner = ACP_CANDIDATE_ADMISSION_OWNER
        override val acpCandidateLiveExecutionOwner = ACP_CANDIDATE_LIVE_EXECUTION_OWNER
        override val acpReferenceSubjectAdmission = ACP_REFERENCE_SUBJECT_ADMISSION
        override val acpOracleAuthority = false
        override val acpReferenceAuthoringAuthority = false
        override val acpPolicyAuthoringAuthority = false
        override val acpValidationAuthority = false
        override val acpObservationAuthoringAuthority = false
        override val acpStartAuthority = false
        override val acpContainmentAuthority = false
        override val acpTerminalAbsenceAuthority = false
        override val acpScoringAuthority = false
        override val acpCertificationAuthority = false
        override val acpReleaseAuthority = false

        override val definitionBound = false
        override val expectedOutputsPresent = false
        override val referenceSubjectPinned = false
        override val observationsCaptured = false
        override val referenceTruthEstablished = false
        override val runtimePreflightVerified = false
        override val liveContainmentVerified = false
        override val terminalAbsenceVerified = false
        override val candidateStarted = false
        override val startAuthorized = false
        override val scoringAuthority = false
        override val certificationAuthority = false
        override val releaseEligible = false

        init {
            val facts = verifyInputPlan(inputPlanPath)
            planBytes = facts.planBytes
            planSha256 = facts.planSha256
            schemaSha256 = facts.schemaSha256
            caseIds = Collections.unmodifiableList(ArrayList(facts.caseIds))
            executionOrder = Collections.unmodifiableList(ArrayList(facts.executionOrder))
            diagnosticOwners = Collections.unmodifiableMap(LinkedHashMap(facts.diagnosticOwners))
            literalInputCount = facts.literalInputCount
            freshArtifactDependencyCount = facts.freshArtifactDependencyCount
        }
    }
}

private fun verifyInputPlan(inputPlanPath: Path): VerifiedInputPlanFacts {
    try {
        val path = exactInputPlanPath(inputPlanPath)
        requireSingleLink(path)
        StableControlFile.open(path, MAXIMUM_INPUT_PLAN_BYTES, "LLVM behavior reference input plan v2").use { guard ->
            val bytes = guard.readExactly(0L, guard.size.toInt(), "LLVM behavior reference input plan v2")
            rejectForbiddenInputPlanBytes(bytes)
            val plan = parseCanonicalInputPlan(bytes)
            val schemaIdentity = OracleSchemas.identity(INPUT_PLAN_SCHEMA_NAME)
            if (schemaIdentity.sha256 != EXPECTED_INPUT_PLAN_SCHEMA_SHA256) {
                inputPlanFail("reference input plan schema differs from its reviewed exact identity")
            }
            OracleSchemas.validate(INPUT_PLAN_SCHEMA_NAME, plan)
            requireStaticInputPlan(plan)
            val executionOrder = plan.requiredArray("executionOrder", "reference input plan")
                .strings("reference input plan execution order")
            val caseFacts = validateCases(plan.requiredArray("cases", "reference input plan"), executionOrder)

            if (!MessageDigest.isEqual(bytes, renderReviewedReferenceInputPlanV2())) {
                inputPlanFail("reference input plan bytes differ from the Kotlin-authored plan")
            }

            val sha256 = OracleArtifacts.sha256(bytes)
            if (guard.size != EXPECTED_INPUT_PLAN_BYTES || sha256 != EXPECTED_INPUT_PLAN_SHA256) {
                inputPlanFail("reference input plan differs from the reviewed exact v2 artifact")
            }
            val terminalSha256 = guard.sha256(label = "LLVM behavior reference input plan v2")
            guard.verifyUnchanged("LLVM behavior reference input plan v2")
            requireSingleLink(path)
            if (terminalSha256 != sha256) {
                inputPlanFail("reference input plan changed during terminal authentication")
            }

            return VerifiedInputPlanFacts(
                planBytes = guard.size,
                planSha256 = sha256,
                schemaSha256 = schemaIdentity.sha256,
                caseIds = caseFacts.caseIds,
                executionOrder = executionOrder,
                diagnosticOwners = caseFacts.diagnosticOwners,
                literalInputCount = caseFacts.literalInputCount,
                freshArtifactDependencyCount = caseFacts.dependencies.size,
            )
        }
    } catch (failure: LlvmBehaviorReferenceInputPlanV2Exception) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorReferenceInputPlanV2Exception(
            "LLVM behavior reference input plan v2 verification failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun exactInputPlanPath(path: Path): Path {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null || path.fileName == null) {
        inputPlanFail("reference input plan path must be exact, absolute, normalized, and name a file")
    }
    if (path.fileName.toString() != INPUT_PLAN_FILE_NAME) {
        inputPlanFail("reference input plan must use the fixed file name $INPUT_PLAN_FILE_NAME")
    }
    rejectForbiddenInputPlanText(path.toString(), "reference input plan path")
    return path
}

private fun requireSingleLink(path: Path) {
    val links = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        throw LlvmBehaviorReferenceInputPlanV2Exception(
            "reference input plan link identity is unavailable",
            failure,
        )
    }
    if (links != 1L) inputPlanFail("reference input plan must not be hard-linked")
}

private fun parseCanonicalInputPlan(bytes: ByteArray): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, INPUT_PLAN_JSON_LIMITS)
    } catch (failure: Exception) {
        inputPlanFail("reference input plan is not strict canonical bounded JSON", failure)
    }
    return parsed as? JsonObject ?: inputPlanFail("reference input plan root must be an object")
}

private fun rejectForbiddenInputPlanBytes(bytes: ByteArray) {
    val text = try {
        bytes.toString(Charsets.UTF_8)
    } catch (failure: Exception) {
        inputPlanFail("reference input plan is not UTF-8", failure)
    }
    rejectForbiddenInputPlanText(text, "reference input plan")
}

private fun rejectForbiddenInputPlanText(value: String, label: String) {
    val lower = value.lowercase(Locale.ROOT)
    FORBIDDEN_V1_AND_RUNTIME_MARKERS.forEach { marker ->
        if (marker in lower) inputPlanFail("$label contains forbidden Python or LLVM behavior v1 material")
    }
}

private fun requireStaticInputPlan(plan: JsonObject) {
    plan.requireLong("schemaVersion", "reference input plan", INPUT_PLAN_SCHEMA_VERSION.toLong())
    plan.requireString("kind", "reference input plan", INPUT_PLAN_KIND)
    plan.requireString("authority", "reference input plan", INPUT_PLAN_AUTHORITY)
    plan.requireString("id", "reference input plan", INPUT_PLAN_ID)
    plan.requireString("scope", "reference input plan", "production")

    val acp = plan.requiredObject("acpBoundary", "reference input plan")
    acp.requireString("role", "reference input plan ACP boundary", ACP_ROLE)
    acp.requireString(
        "candidateContribution",
        "reference input plan ACP boundary",
        ACP_CANDIDATE_CONTRIBUTION,
    )
    acp.requireString(
        "candidateProvenanceAccess",
        "reference input plan ACP boundary",
        ACP_CANDIDATE_PROVENANCE_ACCESS,
    )
    acp.requireString(
        "candidateAdmissionOwner",
        "reference input plan ACP boundary",
        ACP_CANDIDATE_ADMISSION_OWNER,
    )
    acp.requireString(
        "candidateLiveExecutionOwner",
        "reference input plan ACP boundary",
        ACP_CANDIDATE_LIVE_EXECUTION_OWNER,
    )
    acp.requireString(
        "referenceSubjectAdmission",
        "reference input plan ACP boundary",
        ACP_REFERENCE_SUBJECT_ADMISSION,
    )
    ACP_FALSE_AUTHORITY_FIELDS.forEach { field ->
        acp.requireBoolean(field, "reference input plan ACP boundary", false)
    }

    val environment = plan.requiredObject("environment", "reference input plan")
    environment.requireBoolean("clearInherited", "reference input plan environment", true)
    val variables = environment.requiredObject("variables", "reference input plan environment")
    if (variables != EXPECTED_BASE_ENVIRONMENT) {
        inputPlanFail("reference input plan base environment differs from the reviewed deterministic profile")
    }
    val directories = plan.requiredArray("directories", "reference input plan")
        .strings("reference input plan directories")
    if (directories != EXPECTED_DIRECTORIES) {
        inputPlanFail("reference input plan directories differ from the reviewed profile")
    }

    if (plan.requiredObject("diagnosticPolicy", "reference input plan") != EXPECTED_DIAGNOSTIC_POLICY) {
        inputPlanFail("reference input plan diagnostic policy differs from the reviewed policy")
    }
    if (plan.requiredObject("captureContract", "reference input plan") != EXPECTED_CAPTURE_CONTRACT) {
        inputPlanFail("reference input plan capture contract differs from the reviewed raw capture profile")
    }
    if (plan.requiredObject("repetitionContract", "reference input plan") != EXPECTED_REPETITION_CONTRACT) {
        inputPlanFail("reference input plan repetition contract differs from the reviewed three-run profile")
    }

    val claims = plan.requiredObject("claims", "reference input plan")
    FALSE_CLAIM_FIELDS.forEach { field -> claims.requireBoolean(field, "reference input plan claims", false) }
    rejectOutputValuedFields(plan)
}

private fun rejectOutputValuedFields(element: JsonElement) {
    when (element) {
        is JsonObject -> {
            element.keys.forEach { key ->
                if (key in FORBIDDEN_OUTPUT_KEYS) {
                    inputPlanFail("reference input plan contains forbidden output-valued field $key")
                }
            }
            element.values.forEach(::rejectOutputValuedFields)
        }
        is JsonArray -> element.forEach(::rejectOutputValuedFields)
        else -> Unit
    }
}

private fun validateCases(cases: JsonArray, executionOrder: List<String>): VerifiedCaseFacts {
    if (cases.size != EXPECTED_CASE_IDS.size) {
        inputPlanFail("reference input plan must contain exactly ${EXPECTED_CASE_IDS.size} cases")
    }
    val ids = ArrayList<String>(cases.size)
    val owners = LinkedHashMap<String, String>()
    val argumentsById = LinkedHashMap<String, List<String>>()
    val literalInputsByCase = LinkedHashMap<String, Map<String, JsonObject>>()
    val inputTargetsByCase = LinkedHashMap<String, Set<String>>()
    val dependencies = ArrayList<FreshArtifactDependency>()
    var literalInputCount = 0

    cases.forEachIndexed { caseIndex, element ->
        val label = "reference input plan case[$caseIndex]"
        val case = element.asObject(label)
        val id = case.requiredString("id", label)
        requireIdentifier(id, "$label id")
        ids += id

        val owner = case.requiredString("ownerSubsystem", label)
        requireIdentifier(owner, "$label owner subsystem")
        owners[id] = owner

        val categories = case.requiredArray("categories", label).strings("$label categories")
        categories.forEach { requireIdentifier(it, "$label category") }
        requireSortedUnique(categories, "$label categories")

        val arguments = case.requiredArray("arguments", label).strings("$label arguments")
        arguments.forEachIndexed { index, argument -> requireSafeText(argument, "$label argument[$index]") }
        argumentsById[id] = arguments
        validateCaseEnvironment(case.requiredObject("environment", label), "$label environment")
        validateBlob(case.requiredObject("stdin", label), "$label stdin", MAXIMUM_STDIN_BYTES)

        val targetPaths = ArrayList<String>()
        val literalInputs = LinkedHashMap<String, JsonObject>()
        var literalBytes = 0L
        val inputs = case.requiredArray("inputs", label)
        inputs.forEachIndexed { inputIndex, rawInput ->
            val inputLabel = "$label input[$inputIndex]"
            val input = rawInput.asObject(inputLabel)
            when (input.requiredString("kind", inputLabel)) {
                LITERAL_INPUT_KIND -> {
                    val path = requireRelativePath(input.requiredString("path", inputLabel), "$inputLabel path")
                    if (path == FRESH_PCH_PATH) {
                        inputPlanFail("$inputLabel must not embed the reference-produced PCH")
                    }
                    input.requireBoolean("executable", inputLabel, false)
                    val decodedBytes = validateBlob(input, inputLabel, MAXIMUM_LITERAL_INPUT_BYTES)
                    if (input.requiredString("sha256", inputLabel) == FORBIDDEN_V1_PCH_SHA256) {
                        inputPlanFail("$inputLabel contains the forbidden v1-produced PCH digest")
                    }
                    literalBytes = checkedAdd(literalBytes, decodedBytes.toLong(), "$label literal input bytes")
                    literalInputCount++
                    literalInputs[path] = input
                    targetPaths += path
                }
                FRESH_ARTIFACT_INPUT_KIND -> {
                    val dependency = FreshArtifactDependency(
                        consumerCaseId = id,
                        producerCaseId = input.requiredString("producerCaseId", inputLabel),
                        producerPath = requireRelativePath(
                            input.requiredString("producerPath", inputLabel),
                            "$inputLabel producer path",
                        ),
                        targetPath = requireRelativePath(
                            input.requiredString("targetPath", inputLabel),
                            "$inputLabel target path",
                        ),
                        compatibilityInputPaths = input.requiredArray("compatibilityInputPaths", inputLabel)
                            .strings("$inputLabel compatibility input paths")
                            .map { requireRelativePath(it, "$inputLabel compatibility input path") },
                    )
                    input.requireString("producerArtifactType", inputLabel, "regular-file")
                    input.requireString(
                        "producerArtifactFreshness",
                        inputLabel,
                        "same-repetition-produced-not-literal-input",
                    )
                    requireIdentifier(dependency.producerCaseId, "$inputLabel producer case ID")
                    dependencies += dependency
                    targetPaths += dependency.targetPath
                }
                else -> inputPlanFail("$inputLabel kind is not supported by reference input plan v2")
            }
        }
        if (literalBytes > MAXIMUM_CASE_LITERAL_INPUT_BYTES) {
            inputPlanFail("$label literal inputs exceed the fixed workspace byte limit")
        }
        requireSortedUnique(targetPaths, "$label input target paths")
        requireNoDirectoryConflicts(targetPaths, label)
        literalInputsByCase[id] = literalInputs
        inputTargetsByCase[id] = targetPaths.toSet()
    }

    if (ids != EXPECTED_CASE_IDS) {
        inputPlanFail("reference input plan case membership or order differs from the reviewed 48-case profile")
    }
    if (owners.values.toSet() != EXPECTED_OWNER_SUBSYSTEMS) {
        inputPlanFail("reference input plan owner subsystem set differs from the reviewed profile")
    }
    if (literalInputCount != EXPECTED_LITERAL_INPUT_COUNT) {
        inputPlanFail("reference input plan literal input count differs from the reviewed profile")
    }
    validateDependencies(
        ids,
        executionOrder,
        argumentsById,
        literalInputsByCase,
        inputTargetsByCase,
        dependencies,
    )
    return VerifiedCaseFacts(ids, owners, literalInputCount, dependencies)
}

private fun validateDependencies(
    caseIds: List<String>,
    executionOrder: List<String>,
    argumentsById: Map<String, List<String>>,
    literalInputsByCase: Map<String, Map<String, JsonObject>>,
    inputTargetsByCase: Map<String, Set<String>>,
    dependencies: List<FreshArtifactDependency>,
) {
    val identities = dependencies.map(FreshArtifactDependency::identity).sorted()
    if (identities != EXPECTED_FRESH_ARTIFACT_DEPENDENCIES) {
        inputPlanFail("reference input plan fresh-artifact dependencies differ from the reviewed PCH plan")
    }
    val caseSet = caseIds.toSet()
    dependencies.forEach { dependency ->
        if (dependency.producerCaseId !in caseSet || dependency.producerCaseId == dependency.consumerCaseId) {
            inputPlanFail("reference input plan dependency has an unknown or self producer")
        }
        val producerArguments = argumentsById[dependency.producerCaseId]
            ?: inputPlanFail("reference input plan dependency producer is unavailable")
        requireExactArgumentPair(
            producerArguments,
            "-o",
            dependency.producerPath,
            "reference input plan dependency producer output",
        )
        requireExactArgumentPair(
            argumentsById.getValue(dependency.consumerCaseId),
            "-include-pch",
            dependency.targetPath,
            "reference input plan dependency consumer input",
        )
        if (dependency.producerPath in inputTargetsByCase.getValue(dependency.producerCaseId)) {
            inputPlanFail("reference input plan dependency producer path is already a staged input")
        }
        requireSortedUnique(
            dependency.compatibilityInputPaths,
            "reference input plan dependency compatibility input paths",
        )
        dependency.compatibilityInputPaths.forEach { path ->
            val producerInput = literalInputsByCase.getValue(dependency.producerCaseId)[path]
                ?: inputPlanFail("reference input plan dependency producer lacks compatibility input $path")
            val consumerInput = literalInputsByCase.getValue(dependency.consumerCaseId)[path]
                ?: inputPlanFail("reference input plan dependency consumer lacks compatibility input $path")
            if (producerInput != consumerInput) {
                inputPlanFail("reference input plan dependency compatibility input $path differs")
            }
        }
    }

    val producersByConsumer = dependencies.groupBy(FreshArtifactDependency::consumerCaseId)
        .mapValues { (_, values) -> values.map(FreshArtifactDependency::producerCaseId) }
    val visiting = HashSet<String>()
    val visited = HashSet<String>()
    fun visit(caseId: String) {
        if (caseId in visited) return
        if (!visiting.add(caseId)) inputPlanFail("reference input plan dependency graph contains a cycle")
        producersByConsumer[caseId].orEmpty().forEach(::visit)
        visiting.remove(caseId)
        visited.add(caseId)
    }
    caseIds.forEach(::visit)

    if (executionOrder != EXPECTED_EXECUTION_ORDER || executionOrder.toSet() != caseIds.toSet()) {
        inputPlanFail("reference input plan execution order differs from the reviewed topological order")
    }
    val executionPosition = executionOrder.withIndex().associate { (index, caseId) -> caseId to index }
    dependencies.forEach { dependency ->
        if (executionPosition.getValue(dependency.producerCaseId) >=
            executionPosition.getValue(dependency.consumerCaseId)
        ) {
            inputPlanFail("reference input plan executes a dependency consumer before its producer")
        }
    }
}

private fun requireExactArgumentPair(arguments: List<String>, flag: String, value: String, label: String) {
    val flagPositions = arguments.indices.filter { arguments[it] == flag }
    if (flagPositions.size != 1) inputPlanFail("$label must contain exactly one $flag flag")
    val position = flagPositions.single()
    if (position == arguments.lastIndex || arguments[position + 1] != value || arguments.count { it == value } != 1) {
        inputPlanFail("$label must bind $flag directly and uniquely to $value")
    }
}

private fun validateCaseEnvironment(environment: JsonObject, label: String) {
    if (environment.isNotEmpty()) inputPlanFail("$label must remain empty in the reviewed v2 plan")
    if (environment.size > MAXIMUM_ENVIRONMENT_BINDINGS) inputPlanFail("$label has too many bindings")
    if (environment.keys.toList() != environment.keys.sorted()) inputPlanFail("$label names are not sorted")
    var totalBytes = 0L
    environment.forEach { (name, rawValue) ->
        if (!ENVIRONMENT_NAME.matches(name)) inputPlanFail("$label name is not portable")
        val value = rawValue.asString("$label $name")
        requireSafeText(value, "$label $name")
        totalBytes = checkedAdd(
            totalBytes,
            name.toByteArray().size.toLong() + value.toByteArray().size.toLong(),
            "$label bytes",
        )
    }
    if (totalBytes > MAXIMUM_ENVIRONMENT_BYTES) inputPlanFail("$label exceeds the fixed byte limit")
}

private fun validateBlob(blob: JsonObject, label: String, maximumBytes: Int): Int {
    val encoded = blob.requiredString("base64", label)
    val declaredBytes = blob.requiredLong("bytes", label)
    if (declaredBytes !in 0L..maximumBytes.toLong()) inputPlanFail("$label byte length is outside its fixed bound")
    val decoded = try {
        Base64.getDecoder().decode(encoded)
    } catch (failure: Exception) {
        inputPlanFail("$label base64 is invalid", failure)
    }
    if (decoded.size.toLong() != declaredBytes || Base64.getEncoder().encodeToString(decoded) != encoded) {
        inputPlanFail("$label base64 is not canonical or disagrees with its byte length")
    }
    if (blob.requiredString("sha256", label) != OracleArtifacts.sha256(decoded)) {
        inputPlanFail("$label digest disagrees with its decoded bytes")
    }
    val decodedText = decoded.toString(Charsets.ISO_8859_1).lowercase(Locale.ROOT)
    FORBIDDEN_DECODED_BLOB_MARKERS.forEach { marker ->
        if (marker in decodedText) inputPlanFail("$label contains forbidden encoded runtime or output material")
    }
    return decoded.size
}

private fun requireNoDirectoryConflicts(paths: List<String>, caseLabel: String) {
    val directories = LinkedHashSet(EXPECTED_DIRECTORIES)
    paths.forEach { path ->
        var slash = path.indexOf('/')
        while (slash >= 0) {
            directories += path.substring(0, slash)
            slash = path.indexOf('/', slash + 1)
        }
    }
    if (paths.any { it in directories }) inputPlanFail("$caseLabel inputs conflict with required directories")
    if (directories.size + paths.size > MAXIMUM_WORKSPACE_ENTRIES) {
        inputPlanFail("$caseLabel inputs exceed the fixed workspace entry limit")
    }
}

private fun requireRelativePath(value: String, label: String): String {
    if (!RELATIVE_PATH.matches(value) || value.startsWith(' ') || value.endsWith(' ')) {
        inputPlanFail("$label is not a portable normalized relative path")
    }
    val components = value.split('/')
    if (components.any { it == "." || it == ".." }) inputPlanFail("$label contains a traversal component")
    return value
}

private fun requireIdentifier(value: String, label: String) {
    if (!IDENTIFIER.matches(value)) inputPlanFail("$label is not a canonical identifier")
}

private fun requireSafeText(value: String, label: String) {
    if (value.length > MAXIMUM_ARGUMENT_CHARACTERS || value.any { it.code < 0x20 || it.code == 0x7f }) {
        inputPlanFail("$label contains a control character or exceeds its bound")
    }
    rejectForbiddenInputPlanText(value, label)
}

private fun requireSortedUnique(values: List<String>, label: String) {
    if (values != values.sorted() || values.size != values.toSet().size) {
        inputPlanFail("$label must be sorted and unique")
    }
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    inputPlanFail("$label overflowed", failure)
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: inputPlanFail("$label field $name must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: inputPlanFail("$label field $name must be an array")

private fun JsonObject.requiredString(name: String, label: String): String =
    this[name]?.asString("$label field $name") ?: inputPlanFail("$label is missing field $name")

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: inputPlanFail("$label field $name must be an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        inputPlanFail("$label field $name must be an integer")
    }
    return primitive.longOrNull ?: inputPlanFail("$label field $name exceeds the integer range")
}

private fun JsonObject.requiredBoolean(name: String, label: String): Boolean {
    val primitive = this[name] as? JsonPrimitive ?: inputPlanFail("$label field $name must be a boolean")
    return primitive.booleanOrNull ?: inputPlanFail("$label field $name must be a boolean")
}

private fun JsonObject.requireString(name: String, label: String, expected: String) {
    if (requiredString(name, label) != expected) inputPlanFail("$label field $name differs from its fixed value")
}

private fun JsonObject.requireLong(name: String, label: String, expected: Long) {
    if (requiredLong(name, label) != expected) inputPlanFail("$label field $name differs from its fixed value")
}

private fun JsonObject.requireBoolean(name: String, label: String, expected: Boolean = false) {
    if (requiredBoolean(name, label) != expected) inputPlanFail("$label field $name differs from its fixed value")
}

private fun JsonElement.asObject(label: String): JsonObject =
    this as? JsonObject ?: inputPlanFail("$label must be an object")

private fun JsonElement.asString(label: String): String {
    val primitive = this as? JsonPrimitive ?: inputPlanFail("$label must be a string")
    if (!primitive.isString) inputPlanFail("$label must be a string")
    return primitive.content
}

private fun JsonArray.strings(label: String): List<String> = mapIndexed { index, value ->
    value.asString("$label[$index]")
}

private fun inputPlanFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorReferenceInputPlanV2Exception(message, cause)

private data class VerifiedInputPlanFacts(
    val planBytes: Long,
    val planSha256: String,
    val schemaSha256: String,
    val caseIds: List<String>,
    val executionOrder: List<String>,
    val diagnosticOwners: Map<String, String>,
    val literalInputCount: Int,
    val freshArtifactDependencyCount: Int,
)

private data class VerifiedCaseFacts(
    val caseIds: List<String>,
    val diagnosticOwners: Map<String, String>,
    val literalInputCount: Int,
    val dependencies: List<FreshArtifactDependency>,
)

private data class FreshArtifactDependency(
    val consumerCaseId: String,
    val producerCaseId: String,
    val producerPath: String,
    val targetPath: String,
    val compatibilityInputPaths: List<String>,
) {
    fun identity(): String = "$consumerCaseId|$producerCaseId|$producerPath|$targetPath"
}

private const val INPUT_PLAN_SCHEMA_VERSION = 2
private const val INPUT_PLAN_KIND = "llvm-behavior-reference-input-plan-v2"
private const val INPUT_PLAN_AUTHORITY = "kotlin-jvm-authored-reference-input-plan-v2"
private const val INPUT_PLAN_ID = "clang-22-1-6-driver-behavior-reference-input-plan-v2"
private const val INPUT_PLAN_SCHEMA_NAME = "llvm-behavior-reference-input-plan-v2"
private const val INPUT_PLAN_FILE_NAME = "behavior-reference-input-plan-v2.json"
private const val EXPECTED_INPUT_PLAN_BYTES = 46_787L
private const val EXPECTED_INPUT_PLAN_SHA256 = "01424f3b14419b2da463c2c5aefbd89a81c03b11ac5847b750f79d72eb7e5d0d"
private const val EXPECTED_INPUT_PLAN_SCHEMA_SHA256 =
    "e96f2bf456f363150a2ea8a9368831b534b413e8c1d1159c5994c3750c36ce23"
private const val MAXIMUM_INPUT_PLAN_BYTES = 1024L * 1024
private const val MAXIMUM_STDIN_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_LITERAL_INPUT_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_CASE_LITERAL_INPUT_BYTES = 32L * 1024 * 1024
private const val MAXIMUM_WORKSPACE_ENTRIES = 1024
private const val MAXIMUM_ENVIRONMENT_BINDINGS = 128
private const val MAXIMUM_ENVIRONMENT_BYTES = 64L * 1024
private const val MAXIMUM_ARGUMENT_CHARACTERS = 4096
private const val EXPECTED_LITERAL_INPUT_COUNT = 54
private const val LITERAL_INPUT_KIND = "literal"
private const val FRESH_ARTIFACT_INPUT_KIND = "same-repetition-fresh-reference-artifact"
private const val FRESH_PCH_PATH = "answer.pch"
private const val FORBIDDEN_V1_PCH_SHA256 = "5a1acc5f9935b186eec52fef608cf1e09bdb7477a88745d9daed8529b98f2e92"

private const val ACP_ROLE = "first-class-candidate-producer-operator"
private const val ACP_CANDIDATE_CONTRIBUTION = "authenticated-session-change-build-artifact-provenance"
private const val ACP_CANDIDATE_PROVENANCE_ACCESS = "read-only-oracle-input"
private const val ACP_CANDIDATE_ADMISSION_OWNER = "kotlin-jvm-host"
private const val ACP_CANDIDATE_LIVE_EXECUTION_OWNER = "separately-reviewed-kotlin-jvm-host"
private const val ACP_REFERENCE_SUBJECT_ADMISSION = "kotlin-jvm-host-only"

private val INPUT_PLAN_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_INPUT_PLAN_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_INPUT_PLAN_BYTES.toInt(),
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 768 * 1024,
    maximumNumberCharacters = 32,
)

private val EXPECTED_BASE_ENVIRONMENT = constantObject(
    """{"HOME":"/nonexistent","LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin","SOURCE_DATE_EPOCH":"1779182222","TMPDIR":"/workspace/tmp","TZ":"UTC"}""",
)
private val EXPECTED_DIAGNOSTIC_POLICY = constantObject(
    """{"forbiddenNormalizations":["diagnostic-wording","identifier","line-column","option-name","ordering","path","severity"],"locale":"C","mismatchIdentity":"reference-definition-sha256-case-id-field-v2","pathRendering":"raw-bytes-no-rewrite","terminalWidth":"non-tty-no-width"}""",
)
private val EXPECTED_CAPTURE_CONTRACT = constantObject(
    """{"artifacts":"complete-final-workspace-tree","exitStatus":"raw-process-exit-status","normalizations":[],"stderr":"raw-bytes","stdout":"raw-bytes"}""",
)
private val EXPECTED_REPETITION_CONTRACT = constantObject(
    """{"agreement":"canonical-observation-payload-byte-identical","count":3,"dependencyScope":"same-repetition-only","freshNonce":true,"freshOperation":true,"freshResultsLease":true,"freshWorkspaceLease":true}""",
)

private fun constantObject(value: String): JsonObject =
    OracleJson.parse(value.toByteArray(), StrictJsonLimits(maximumInputBytes = 4096, maximumCanonicalBytes = 4096))
        as JsonObject

private val EXPECTED_DIRECTORIES = listOf("include", "quoted", "system", "tmp")
private val EXPECTED_CASE_IDS = listOf(
    "assemble-invalid",
    "assemble-valid",
    "compile-c-standard",
    "compile-cxx-standard",
    "compile-file",
    "compile-stdin",
    "diagnostic-color-always",
    "diagnostic-color-never",
    "diagnostic-error-limit",
    "diagnostic-fixit",
    "diagnostic-invalid-option",
    "diagnostic-missing-include",
    "diagnostic-syntax",
    "diagnostic-template-backtrace",
    "diagnostic-warning-option",
    "driver-missing-linker",
    "driver-print-commands",
    "emit-assembly",
    "emit-llvm-ir",
    "help-driver",
    "include-cycle-guarded",
    "include-framework-order",
    "include-search-order",
    "include-trace",
    "link-program",
    "link-undefined-symbol",
    "metadata-resource-dir",
    "metadata-target",
    "metadata-version",
    "modules-flag-supported",
    "objective-c-syntax",
    "pch-reuse-valid",
    "pch-reuse-wrong-target",
    "precompile-header",
    "preprocess-dependencies",
    "preprocess-file",
    "preprocess-macro-state",
    "preprocess-malformed-macro",
    "preprocess-pragma-once",
    "preprocess-stdin",
    "response-file",
    "response-file-nested",
    "response-file-quoted-paths",
    "response-file-recursion",
    "response-file-stdin",
    "target-i386-object",
    "target-unsupported-aarch64",
    "target-x86-macros",
)

private val EXPECTED_EXECUTION_ORDER = EXPECTED_CASE_IDS
    .filterNot { it == "pch-reuse-valid" || it == "pch-reuse-wrong-target" }
    .flatMap { caseId ->
        if (caseId == "precompile-header") {
            listOf(caseId, "pch-reuse-valid", "pch-reuse-wrong-target")
        } else {
            listOf(caseId)
        }
    }

private val EXPECTED_OWNER_SUBSYSTEMS = setOf(
    "clang-codegen",
    "clang-dependency-scanning",
    "clang-diagnostics-engine",
    "clang-diagnostics-renderer",
    "clang-driver",
    "clang-driver-linker",
    "clang-driver-options",
    "clang-driver-response-files",
    "clang-driver-targets",
    "clang-driver-toolchain",
    "clang-header-search",
    "clang-integrated-assembler",
    "clang-lex",
    "clang-parser",
    "clang-sema",
    "clang-serialization",
)

private val EXPECTED_FRESH_ARTIFACT_DEPENDENCIES = listOf(
    "pch-reuse-valid|precompile-header|answer.pch|answer.pch",
    "pch-reuse-wrong-target|precompile-header|answer.pch|answer.pch",
)

private val ACP_FALSE_AUTHORITY_FIELDS = setOf(
    "oracleAuthority",
    "referenceAuthoringAuthority",
    "policyAuthoringAuthority",
    "validationAuthority",
    "observationAuthoringAuthority",
    "startAuthority",
    "containmentAuthority",
    "terminalAbsenceAuthority",
    "scoringAuthority",
    "certificationAuthority",
    "releaseAuthority",
)

private val FALSE_CLAIM_FIELDS = setOf(
    "definitionBound",
    "expectedOutputsPresent",
    "referenceSubjectPinned",
    "observationsCaptured",
    "referenceTruthEstablished",
    "runtimePreflightVerified",
    "liveContainmentVerified",
    "terminalAbsenceVerified",
    "candidateStarted",
    "startAuthorized",
    "scoringAuthority",
    "certificationAuthority",
    "releaseEligible",
)

private val FORBIDDEN_OUTPUT_KEYS = setOf(
    "expected",
    "exitCode",
    "status",
    "present",
    "mode",
    "stdoutSha256",
    "stderrSha256",
    "reportSha256",
    "matrixSha256",
    "mismatchIds",
    "sandbox",
    "imageDigest",
    "controlClient",
    "engineProfile",
)

private val FORBIDDEN_V1_AND_RUNTIME_MARKERS = listOf(
    "python",
    "/usr/bin/python3",
    "oci-container-v1",
    "behavior-preexec-v1",
    "clang-22-1-6-driver-behavior\"",
    "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b",
    "510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248",
    "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
    FORBIDDEN_V1_PCH_SHA256,
)

private val IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val ENVIRONMENT_NAME = Regex("[A-Z_][A-Z0-9_]{0,127}")
private val FORBIDDEN_DECODED_BLOB_MARKERS = listOf(
    "python",
    "oci-container-v1",
    "behavior-preexec-v1",
    "expected",
    "exitcode",
    "stdoutsha256",
    "stderrsha256",
    "matrixsha256",
    "mismatchids",
    "sandbox",
    "510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248",
    "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
    FORBIDDEN_V1_PCH_SHA256,
)
private val RELATIVE_PATH = Regex(
    "(?!(?:.*/)?\\.{1,2}(?:/|$))[A-Za-z0-9._+](?:[A-Za-z0-9._+ -]*[A-Za-z0-9._+])?" +
        "(?:/[A-Za-z0-9._+](?:[A-Za-z0-9._+ -]*[A-Za-z0-9._+])?)*",
)

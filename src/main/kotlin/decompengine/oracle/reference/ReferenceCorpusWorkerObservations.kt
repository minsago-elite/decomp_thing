package decompengine.oracle.reference

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Checked child computation only. Authenticated execution and cleanup remain the parent's proof. */
internal class VerifiedReferenceCorpusWorkerObservations internal constructor(
    val batchId: String,
    val capturedOutputBytes: Long,
    caseBytes: ByteArray,
    reportBytes: ByteArray,
) {
    private val storedCases = caseBytes.copyOf()
    private val storedReport = reportBytes.copyOf()
    val canonicalCasesBytes: ByteArray get() = storedCases.copyOf()
    val canonicalReportBytes: ByteArray get() = storedReport.copyOf()
    val cases: List<JsonObject> get() = OracleJson.parseCanonical(storedCases, OBSERVATION_LIMITS).jsonArray.map { it.jsonObject }
    val executionAuthenticated: Boolean = false
    val referenceAuthority: Boolean = false
}

/** Replays every child-owned arithmetic/equality assertion; no child boolean grants authority. */
internal object ReferenceCorpusWorkerObservations {
    fun verify(
        definition: ReferenceCorpusDefinition,
        request: ReferenceCorpusWorkerRequest,
        bytes: ByteArray,
    ): VerifiedReferenceCorpusWorkerObservations {
        require(definition.canonicalBytes.size == request.profileBytes &&
            OracleArtifacts.sha256(definition.canonicalBytes) == request.profileSha256)
        val root = OracleJson.parseCanonical(bytes, OBSERVATION_LIMITS).jsonObject
        root.requireFields("provider", "schemaVersion", "profileId", "profileSha256", "requestSha256",
            "operationRequestSha256", "batchId", "caseIds", "capturedOutputBytes", "cases",
            "executionAuthenticated", "referenceAuthority", "containmentAuthority", "releaseEligible")
        root.requireString("provider", "reference-corpus-worker-observations-v1")
        root.requireNumber("schemaVersion", 1)
        root.requireString("profileId", definition.id)
        root.requireString("profileSha256", request.profileSha256)
        root.requireString("requestSha256", OracleArtifacts.sha256(request.canonicalBytes))
        root.requireString("operationRequestSha256", request.operationRequestSha256)
        root.requireString("batchId", request.batchId)
        for (field in listOf("executionAuthenticated", "referenceAuthority", "containmentAuthority", "releaseEligible")) {
            require(root[field] == JsonPrimitive(false)) { "child computation claimed $field" }
        }
        val selected = definition.cases.filter { it.batchId == request.batchId }
        require(selected.isNotEmpty())
        require(root.getValue("caseIds") == JsonArray(selected.map { JsonPrimitive(it.id) })) { "worker case population differs" }
        val cases = root.getValue("cases").jsonArray
        require(cases.size == selected.size) { "worker case population differs" }
        var total = 0L
        val stableCases = selected.zip(cases).map { (policy, element) ->
            val case = element.jsonObject
            case.requireFields("id", "batchId", "arguments", "environment", "inputs", "stdin", "repetitions", "observed", "invocations")
            case.requireString("id", policy.id)
            case.requireString("batchId", policy.batchId)
            require(case.getValue("arguments") == JsonArray(policy.arguments.map(::JsonPrimitive))) { "worker changed case arguments" }
            require(case.getValue("environment") == JsonObject(policy.environment.mapValues { JsonPrimitive(it.value) })) {
                "worker changed case semantic environment"
            }
            val inputIdentity = JsonArray(policy.inputs.map { input -> JsonObject(mapOf(
                "path" to JsonPrimitive(input.path), "bytes" to JsonPrimitive(input.bytes), "sha256" to JsonPrimitive(input.sha256),
            )) })
            require(case.getValue("inputs") == inputIdentity) { "worker changed case input identity" }
            require(readBlob(case.getValue("stdin").jsonObject, 64 * 1024).contentEquals(policy.stdin)) { "worker changed stdin" }
            case.requireNumber("repetitions", 2)
            val invocations = case.getValue("invocations").jsonArray
            require(invocations.size == 3) { "worker must retain both repetitions and alternate invocation" }
            val observations = invocations.mapIndexed { ordinal, runElement ->
                val attempt = listOf("first", "repeat", "alternate")[ordinal]
                val work = request.workingRoot.resolve("${policy.id}-$attempt")
                val run = runElement.jsonObject
                run.requireFields("attempt", "invokedAs", "workingDirectory", "effectiveEnvironment", "executableSha256", "observed")
                run.requireString("attempt", attempt)
                run.requireString("workingDirectory", work.toString())
                run.requireString("invokedAs", if (ordinal == 2) work.resolve(definition.alternateBasename).toString() else definition.executablePath)
                run.requireString("executableSha256", definition.executableIdentity.sha256)
                require("TMPDIR" !in policy.environment) { "semantic environment overrides contained temporary directory" }
                val environment = policy.environment + ("TMPDIR" to request.temporaryRoot.resolve("${policy.id}-$attempt").toString())
                require(run.getValue("effectiveEnvironment") == JsonObject(environment.mapValues { JsonPrimitive(it.value) })) {
                    "worker effective environment differs from the exact temporary-directory binding"
                }
                val observed = run.getValue("observed").jsonObject
                total = Math.addExact(total, validateObservation(observed, policy, definition.limits))
                require(total <= definition.limits.maximumAggregateOutputBytes) { "worker output exceeds aggregate policy" }
                observed
            }
            require(observations[0] == observations[1]) { "worker repetition differs" }
            require(case.getValue("observed") == observations[0]) { "worker canonical observation differs from first actual invocation" }
            val alternateValues = definition.alternateSubstitutionValues(
                request.workingRoot.resolve("${policy.id}-alternate").resolve(definition.alternateBasename).toString())
            val alternate = JsonObject(observations[0] + mapOf(
                "stdout" to blob(definition.substitute(readBlob(observations[0].getValue("stdout").jsonObject,
                    Math.toIntExact(definition.limits.maximumStdoutBytes)), alternateValues)),
                "stderr" to blob(definition.substitute(readBlob(observations[0].getValue("stderr").jsonObject,
                    Math.toIntExact(definition.limits.maximumStderrBytes)), alternateValues)),
            ))
            require(alternate == observations[2]) { "worker alternate invocation violates declared identity substitutions" }
            JsonObject(case - "invocations")
        }
        root.requireNumber("capturedOutputBytes", total)
        return VerifiedReferenceCorpusWorkerObservations(request.batchId, total,
            OracleJson.canonicalBytes(JsonArray(stableCases), OBSERVATION_LIMITS), bytes)
    }

    private fun validateObservation(observed: JsonObject, policy: ReferenceCorpusCase, limits: ReferenceCorpusLimits): Long {
        observed.requireFields("exitCode", "stdout", "stderr", "artifacts")
        require(observed.number("exitCode") in 0..127) { "worker exit is not an unambiguous ordinary termination" }
        val stdout = readBlob(observed.getValue("stdout").jsonObject, Math.toIntExact(limits.maximumStdoutBytes))
        val stderr = readBlob(observed.getValue("stderr").jsonObject, Math.toIntExact(limits.maximumStderrBytes))
        val artifacts = observed.getValue("artifacts").jsonArray
        require(artifacts.size <= 255) { "worker artifact membership exceeds policy" }
        val paths = mutableListOf<String>()
        var bytes = 0L
        for (entry in artifacts) {
            val artifact = entry.jsonObject
            artifact.requireFields("path", "bytes", "sha256", "base64")
            val relative = artifact.string("path")
            val path = Path.of(relative)
            require(relative.isNotEmpty() && !path.isAbsolute && path.normalize() == path && path.toString() == relative &&
                path.none { it.toString() in setOf(".", "..") } && path.nameCount <= 16) { "worker artifact path escapes its workspace" }
            paths += relative
            val data = readBlob(JsonObject(artifact - "path"), Math.toIntExact(limits.maximumArtifactBytes))
            require(policy.inputs.none { it.path == relative && it.content.contentEquals(data) }) { "unchanged input is not an output artifact" }
            bytes = Math.addExact(bytes, data.size.toLong())
            require(bytes <= limits.maximumArtifactBytes) { "worker artifacts exceed invocation budget" }
        }
        require(paths == paths.distinct().sorted()) { "worker artifacts repeat or differ from canonical path order" }
        val parents = paths.flatMap { value ->
            generateSequence(Path.of(value).parent) { it.parent }.map(Path::toString).toList()
        }.toSet()
        require(paths.none { it in parents }) { "worker artifact topology makes an ordinary file a directory" }
        require(1 + paths.size + parents.size <= 256) { "worker artifact membership exceeds policy" }
        return Math.addExact(bytes, stdout.size.toLong() + stderr.size)
    }
}

private fun JsonObject.requireFields(vararg fields: String) {
    require(keys == fields.toSet()) { "reference worker observation fields differ" }
}

private fun JsonObject.string(field: String): String = getValue(field).jsonPrimitive.let {
    require(it.isString) { "worker observation $field is not a string" }
    it.content
}

private fun JsonObject.number(field: String): Long = getValue(field).jsonPrimitive.let {
    require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*"))) { "worker observation $field is not an integer" }
    it.content.toLong()
}

private fun JsonObject.requireString(field: String, expected: String) {
    require(string(field) == expected) { "worker observation $field differs" }
}

private fun JsonObject.requireNumber(field: String, expected: Long) {
    require(number(field) == expected) { "worker observation $field differs" }
}

private fun readBlob(value: JsonObject, maximum: Int): ByteArray {
    value.requireFields("bytes", "sha256", "base64")
    val size = value.number("bytes")
    require(size in 0L..maximum.toLong()) { "worker blob exceeds policy" }
    val encoded = value.string("base64")
    require(encoded.length.toLong() <= (size + 2L) / 3L * 4L) { "worker blob encoding exceeds its declared size" }
    val decoded = Base64.getDecoder().decode(encoded)
    require(decoded.size.toLong() == size && Base64.getEncoder().encodeToString(decoded) == encoded &&
        OracleArtifacts.sha256(decoded) == value.string("sha256")) { "worker blob size, digest or canonical encoding differs" }
    return decoded
}

private fun blob(bytes: ByteArray): JsonObject = JsonObject(mapOf(
    "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
))

private val OBSERVATION_LIMITS = StrictJsonLimits(maximumInputBytes = ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES,
    maximumCanonicalBytes = ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES, maximumStringBytes = 8 * 1024 * 1024,
    maximumTotalStringBytes = 16 * 1024 * 1024, maximumNodes = 100_000, maximumDepth = 24)

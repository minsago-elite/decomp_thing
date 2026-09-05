package decompengine.repair

import decompengine.agent.AgentCancellation
import decompengine.project.sha256
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.nio.file.Files
import java.util.Collections
import java.util.TreeMap

/** Immutable source input to validation. The canonical project is never the candidate workspace. */
class RepairCandidateValidationRequest(
    val projectDir: Path,
    candidateSources: Map<String, ByteArray>,
    val sourceRevisionSha256: String,
    val profileId: String,
    val profileSha256: String,
    val indexSha256: String,
    val originalBinary: Path?,
    inputs: List<ProcessInput>,
    val regressionCorpusSha256: String,
    val reportsDir: Path,
    val label: String,
    val budget: RepairResourceBudget,
    val deadlineNanos: Long,
    val cancellation: AgentCancellation,
) {
    private val sourceContent = checkedCandidateSources(candidateSources, budget)
    private val inputContent = checkedCandidateInputs(inputs, budget)
    val candidateSources: Map<String, ByteArray> get() = Collections.unmodifiableMap(
        sourceContent.mapValuesTo(TreeMap()) { (_, bytes) -> bytes.copyOf() },
    )
    val inputs: List<ProcessInput> get() = Collections.unmodifiableList(inputContent.map {
        ProcessInput(it.id, it.args, it.stdin.copyOf())
    })

    /** A consumer receives one detached bounded file at a time, never an extra whole-tree copy. */
    fun forEachCandidateSource(consumer: (String, ByteArray) -> Unit) {
        sourceContent.forEach { (path, bytes) -> consumer(path, bytes.copyOf()) }
    }

    init {
        require(sourceContent.isNotEmpty() && sourceContent.size <= budget.maximumSourceFiles)
        require(sourceContent.keys.all { path ->
            path.isNotEmpty() && !Path.of(path).isAbsolute &&
                Path.of(path).normalize().toString().replace('\\', '/') == path &&
                Path.of(path).none { it.toString() == ".." }
        }) { "candidate source paths must be normalized project-relative paths" }
        require(sourceContent.values.all { it.size.toLong() <= budget.maximumSourceFileBytes })
        require(sourceContent.values.fold(0L) { sum, bytes -> Math.addExact(sum, bytes.size.toLong()) } <= budget.maximumSourceBytes)
        require(repairCandidateSourceSha256(sourceContent) == sourceRevisionSha256) {
            "candidate source bytes differ from the requested revision"
        }
        require(inputContent.map { it.id } == inputContent.map { it.id }.distinct().sorted())
        require(repairRegressionCorpusSha256(inputContent) == regressionCorpusSha256)
        require(listOf(profileSha256, indexSha256).all { it.matches(Regex("[0-9a-f]{64}")) })
    }
}

private fun checkedCandidateSources(sources: Map<String, ByteArray>, budget: RepairResourceBudget): Map<String, ByteArray> {
    require(sources.isNotEmpty() && sources.size <= budget.maximumSourceFiles)
    var total = 0L
    sources.forEach { (path, bytes) ->
        require(path.isNotEmpty() && !Path.of(path).isAbsolute &&
            Path.of(path).normalize().toString().replace('\\', '/') == path &&
            Path.of(path).none { it.toString() == ".." })
        require(bytes.size.toLong() <= budget.maximumSourceFileBytes)
        total = Math.addExact(total, bytes.size.toLong())
        require(total <= budget.maximumSourceBytes)
    }
    return Collections.unmodifiableMap(sources.mapValuesTo(TreeMap()) { (_, bytes) -> bytes.copyOf() })
}

private fun checkedCandidateInputs(inputs: List<ProcessInput>, budget: RepairResourceBudget): List<ProcessInput> {
    require(inputs.size <= budget.maximumRegressionInputs)
    var bytes = 0L
    var arguments = 0L
    inputs.forEach { input ->
        arguments = Math.addExact(arguments, input.args.size.toLong())
        require(arguments <= budget.maximumRegressionArguments)
        bytes = Math.addExact(bytes, input.stdin.size.toLong() + input.id.toByteArray(Charsets.UTF_8).size)
        input.args.forEach { bytes = Math.addExact(bytes, it.toByteArray(Charsets.UTF_8).size.toLong()) }
        require(bytes <= budget.maximumRegressionInputBytes)
    }
    return Collections.unmodifiableList(inputs.map {
        ProcessInput(it.id, Collections.unmodifiableList(ArrayList(it.args)), it.stdin.copyOf())
    })
}

/** Provider-produced binding, consumed only through the registered validation capability. */
data class RepairValidationProof(
    val sourceRevisionSha256: String,
    val profileSha256: String,
    val indexSha256: String,
    val regressionCorpusSha256: String,
    val originalBinarySha256: String?,
    val rebuiltBinarySha256: String?,
    val runtimeSha256: String,
    val evidenceSha256: String,
    val cleanupVerified: Boolean,
    val assurance: RepairValidationAssurance,
)

sealed interface RepairCandidateValidationOutcome {
    val proof: RepairValidationProof

    data class CompileFailed(val failure: CompileFailure, override val proof: RepairValidationProof) : RepairCandidateValidationOutcome
    data class CompileValid(override val proof: RepairValidationProof) : RepairCandidateValidationOutcome
    data class BehaviorChecked(val report: BehaviorComparisonReport, override val proof: RepairValidationProof) : RepairCandidateValidationOutcome
}

interface RepairValidationFailureEvidence {
    val receiptPath: Path
    val receiptSha256: String
    val cleanupVerified: Boolean
    val failureKind: RepairValidationFailureKind get() = RepairValidationFailureKind.VALIDATION_FAILED
}

enum class RepairValidationFailureKind { CANCELLED, RESOURCE_EXHAUSTED, VALIDATION_FAILED, CLEANUP_UNVERIFIED }

/** The same canonical digest used by the source revision graph; byte lengths are included. */
fun repairCandidateSourceSha256(sources: Map<String, ByteArray>): String = sha256(
    sources.toSortedMap().entries.joinToString("") { (path, bytes) ->
        "${path.length}:$path:${bytes.size}:${sha256(bytes)}\n"
    }.toByteArray(Charsets.UTF_8),
)

fun repairRegressionCorpusSha256(inputs: List<ProcessInput>): String = sha256(buildString {
    inputs.forEach { input ->
        append(input.id.toByteArray(Charsets.UTF_8).size).append(':').append(input.id).append('|')
            .append(input.args.size).append('|')
        input.args.forEach { argument ->
            append(argument.toByteArray(Charsets.UTF_8).size).append(':').append(argument).append('|')
        }
        append(input.stdin.size).append(':')
        input.stdin.forEach { append("%02x".format(it.toInt() and 0xff)) }
        append('\n')
    }
}.toByteArray(Charsets.UTF_8))

/** Compatibility adapter available exclusively to explicitly non-release trusted-host fixtures. */
internal fun validateTestOnlyRepairCandidate(
    strategy: RepairValidationStrategy,
    request: RepairCandidateValidationRequest,
): RepairCandidateValidationOutcome {
    require(strategy.assurance == RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
    val workspace = Files.createTempDirectory("repair-validation-fixture-")
    try {
        request.forEachCandidateSource { path, bytes ->
            val target = workspace.resolve(path)
            Files.createDirectories(target.parent)
            Files.write(target, bytes)
        }
        Files.createDirectories(request.reportsDir)
        val compile = strategy.compile(workspace, request.reportsDir.resolve("${request.label}.compile.log"), request.budget)
        val rebuilt = if (compile == null) strategy.rebuiltProgram(workspace, request.budget) else null
        val proof = RepairValidationProof(request.sourceRevisionSha256, request.profileSha256, request.indexSha256,
            request.regressionCorpusSha256, request.originalBinary?.let { sha256(Files.readAllBytes(it)) },
            rebuilt?.takeIf { Files.isRegularFile(it) }?.let { sha256(Files.readAllBytes(it)) },
            sha256("TEST_ONLY_HOST_PROCESS".toByteArray()), sha256("${request.label}:${request.sourceRevisionSha256}".toByteArray()),
            true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
        if (compile != null) return RepairCandidateValidationOutcome.CompileFailed(compile, proof)
        if (request.originalBinary == null) return RepairCandidateValidationOutcome.CompileValid(proof)
        return RepairCandidateValidationOutcome.BehaviorChecked(strategy.evaluateBehavior("${request.label}_behavior",
            workspace, request.originalBinary, requireNotNull(rebuilt), request.inputs, request.reportsDir, request.budget), proof)
    } finally {
        Files.walk(workspace).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }
}

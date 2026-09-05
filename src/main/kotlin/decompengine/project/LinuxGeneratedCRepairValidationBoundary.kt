package decompengine.project

import decompengine.acp.AcpCleanupProofFailure
import decompengine.acp.AcpSandboxLaunch
import decompengine.acp.AcpSandboxLaunchPurpose
import decompengine.acp.AcpSandboxReadOnlyMount
import decompengine.acp.AcpSandboxRootGrant
import decompengine.acp.AcpSandboxRootMode
import decompengine.acp.AcpSandboxedProcess
import decompengine.acp.AcpWorkflowStagingRoot
import decompengine.acp.LinuxBubblewrapBoundary
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.canonicalAcpSandboxEvidenceFields
import decompengine.acp.productionAcpExecutionScheduler
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailureKind
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.CompileFailure
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairCandidateValidationOutcome
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairValidationProof
import decompengine.repair.RepairValidationFailureEvidence
import decompengine.repair.RepairValidationFailureKind
import decompengine.repair.writeRepairEvidenceAtomically
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import decompengine.validation.ProcessOutput
import decompengine.validation.SandboxUnavailableException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.file.Path
import java.time.Duration
import java.util.Base64
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** The registered generated-C runtime. Every candidate-controlled process uses the audited boundary. */
internal class LinuxGeneratedCRepairValidationBoundary private constructor() : GeneratedCRepairValidationBoundary {
    override val assurance = RepairValidationAssurance.STRICT_CONTAINED
    private val configuration by lazy { GeneratedCRepairRuntimeConfiguration.loadFromEnvironment() }

    override fun requireAvailable() {
        requireProductionQualification()
        val deadline = GeneratedCValidationDeadline.after(Duration.ofSeconds(30), AgentCancellation.NONE)
        val config = configuration
        // Availability authenticates the compiler closure and both dedicated finite mounts through
        // a real contained launch. The actual request applies its own, possibly tighter, budgets.
        val budget = RepairResourceBudget().let { it.copy(
            maximumStagingBytes = it.maximumSourceBytes, maximumStagingDirectories = it.maximumSourceFiles,
        ) }
        withSnapshot(config, budget, deadline) { snapshot ->
            val output = snapshot.newOutput()
            val result = runContained(config, deadline, budget, AtomicLong(),
                listOf(config.tools.getValue("make").destination.toString(), "--version"),
                buildEnvironment(output.path), snapshot.source.path,
                config.tools.values.toList() + config.buildRuntime + config.programRuntime.filter { program ->
                    config.buildRuntime.none { it.destination == program.destination }
                },
                listOf(AcpSandboxRootGrant(snapshot.source, AcpSandboxRootMode.READ_ONLY),
                    AcpSandboxRootGrant(output, AcpSandboxRootMode.READ_WRITE)),
                ByteArray(0), Duration.ofSeconds(10),
            )
            require(result.output.exitCode == 0) { "the provisioned generated-C build runtime failed its contained availability check" }
            snapshot.finishOutput()
        }
    }

    override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome {
        requireProductionQualification()
        val deadline = GeneratedCValidationDeadline(request.deadlineNanos, request.cancellation)
        deadline.check()
        require(request.label.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}"))) { "validation receipt label is invalid" }
        require(request.reportsDir.isAbsolute && request.reportsDir == request.reportsDir.normalize())
        val config = configuration
        val inputs = request.inputs
        if (request.originalBinary != null) require(inputs.isNotEmpty()) { "behavior validation requires the full nonempty retained corpus" }
        val receipt = GeneratedCValidationReceipt(request, config)
        val aggregateOutput = AtomicLong()
        var original: CapturedGeneratedExecutable? = null
        var rebuilt: CapturedGeneratedExecutable? = null
        var failure: CompileFailure? = null
        val cases = ArrayList<BehaviorCaseResult>()
        try {
            withSnapshot(config, request.budget, deadline) { snapshot ->
                snapshot.populate(request)
                receipt.snapshot(snapshot)
                original = request.originalBinary?.let(snapshot::captureOriginal)
                val output = snapshot.beginBuild()
                receipt.buildOutputLink(output)
                val compiler = config.tools.getValue("compiler").destination.toString()
                val shell = config.tools.getValue("shell").destination.toString()
                val command = listOf(config.tools.getValue("make").destination.toString(),
                    "--no-builtin-rules", "--no-builtin-variables", "--no-print-directory", "-f", "Makefile",
                    "CC=$compiler -B${GeneratedCRepairRuntimeConfiguration.TOOL_DIRECTORY}/", "SHELL=$shell",
                    "TARGET=build/reconstructed", "all")
                val build = runContained(config, deadline, request.budget, aggregateOutput, command,
                    buildEnvironment(output.path), snapshot.source.path, config.tools.values.toList() + config.buildRuntime,
                    listOf(AcpSandboxRootGrant(snapshot.source, AcpSandboxRootMode.READ_ONLY),
                        AcpSandboxRootGrant(output, AcpSandboxRootMode.READ_WRITE)),
                    ByteArray(0), deadline.remaining(),
                )
                receipt.scope("build", null, build, output)
                requireQuotaNotExhausted(output)
                requireUnambiguousExit(build.output.exitCode)
                if (build.output.exitCode != 0) {
                    failure = CompileFailure(command, build.output.exitCode,
                        build.output.stdout.toString(Charsets.UTF_8).take(request.budget.maximumDiagnosticCharacters),
                        build.output.stderr.toString(Charsets.UTF_8).take(request.budget.maximumDiagnosticCharacters))
                    snapshot.finishOutput()
                    return@withSnapshot
                }
                rebuilt = snapshot.captureRebuilt()
                snapshot.finishOutput()
                original?.let { reference ->
                    inputs.forEach { input ->
                        deadline.check()
                        val originalOutput = runProgram(config, snapshot, deadline, request.budget, aggregateOutput,
                            reference, input, receipt)
                        val rebuiltOutput = runProgram(config, snapshot, deadline, request.budget, aggregateOutput,
                            requireNotNull(rebuilt), input, receipt)
                        cases += BehaviorCaseResult(input, originalOutput, rebuiltOutput)
                    }
                }
            }
            deadline.check()
            val outcome = if (failure != null) "compile-failed" else if (original == null) "compile-valid" else "behavior-checked"
            val receiptBytes = receipt.finish(outcome, original, rebuilt, cases)
            deadline.check()
            val evidencePath = request.reportsDir.resolve("${request.label}.validation.json")
            writeRepairEvidenceAtomically(evidencePath, receiptBytes.toString(Charsets.UTF_8))
            deadline.check()
            val proof = RepairValidationProof(request.sourceRevisionSha256, request.profileSha256, request.indexSha256,
                request.regressionCorpusSha256, original?.sha256, rebuilt?.sha256, config.configurationSha256,
                sha256(receiptBytes), cleanupVerified = true, assurance = assurance)
            failure?.let { return RepairCandidateValidationOutcome.CompileFailed(it, proof) }
            if (original == null) return RepairCandidateValidationOutcome.CompileValid(proof)
            return RepairCandidateValidationOutcome.BehaviorChecked(BehaviorComparisonReport(request.label,
                requireNotNull(original).path, requireNotNull(rebuilt).path, cases, evidencePath), proof)
        } catch (problem: Throwable) {
            val kind = when {
                containsCleanupFailure(problem) -> RepairValidationFailureKind.CLEANUP_UNVERIFIED
                problem is CancellationException || problem is InterruptedException -> RepairValidationFailureKind.CANCELLED
                problem is RepairBudgetExceededException || problem is GeneratedCValidationTimeoutException -> RepairValidationFailureKind.RESOURCE_EXHAUSTED
                problem is AgentExecutionException && problem.failure.kind in setOf(AgentFailureKind.TIMEOUT, AgentFailureKind.RESOURCE_EXHAUSTED) -> RepairValidationFailureKind.RESOURCE_EXHAUSTED
                else -> RepairValidationFailureKind.VALIDATION_FAILED
            }
            val path = request.reportsDir.resolve("${request.label}.validation.json")
            try {
                val bytes = receipt.finish(kind.name.lowercase().replace('_', '-'), original, rebuilt, cases,
                    cleanupVerified = kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED)
                writeRepairEvidenceAtomically(path, bytes.toString(Charsets.UTF_8))
                problem.addSuppressed(GeneratedCValidationFailureEvidence(path, sha256(bytes),
                    kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED, kind))
            } catch (archive: Throwable) { problem.addSuppressed(archive) }
            if (problem is InterruptedException) Thread.currentThread().interrupt()
            throw problem
        }
    }

    private fun runProgram(
        config: GeneratedCRepairRuntimeConfiguration,
        snapshot: GeneratedCValidationSnapshot,
        deadline: GeneratedCValidationDeadline,
        budget: RepairResourceBudget,
        aggregateOutput: AtomicLong,
        executable: CapturedGeneratedExecutable,
        input: ProcessInput,
        receipt: GeneratedCValidationReceipt,
    ): ProcessOutput {
        val output = snapshot.newOutput()
        val command = listOf(PROGRAM_DESTINATION.toString()) + input.args
        val result = runContained(config, deadline, budget, aggregateOutput, command,
            mapOf("LANG" to "C", "LC_ALL" to "C", "TZ" to "UTC", "TMPDIR" to output.path.toString()),
            output.path,
            config.programRuntime + AcpSandboxReadOnlyMount(executable.path, PROGRAM_DESTINATION, executable.runtimeManifestSha256),
            listOf(AcpSandboxRootGrant(output, AcpSandboxRootMode.READ_WRITE)), input.stdin,
            Duration.ofMillis(budget.maximumBehaviorExecutionMillis))
        receipt.scope(executable.role, input.id, result, output)
        requireQuotaNotExhausted(output)
        requireUnambiguousExit(result.output.exitCode)
        snapshot.finishOutput()
        return result.output
    }

    private fun <T> withSnapshot(
        config: GeneratedCRepairRuntimeConfiguration,
        budget: RepairResourceBudget,
        deadline: GeneratedCValidationDeadline,
        action: (GeneratedCValidationSnapshot) -> T,
    ): T {
        val permit = productionAcpExecutionScheduler.acquire("generated-c-validation:${config.sourceTmpfs}:${config.outputTmpfs}",
            deadline.cancellation, deadline::expired) ?: throw CancellationException("generated-C validation cancelled before admission")
        var snapshot: GeneratedCValidationSnapshot? = null
        var primary: Throwable? = null
        var cleanupUnverified = false
        try {
            deadline.check()
            snapshot = GeneratedCValidationSnapshot.create(config, budget, deadline::check)
            return action(snapshot)
        } catch (failure: Throwable) {
            primary = failure
            cleanupUnverified = containsCleanupFailure(failure)
            if (cleanupUnverified) snapshot?.retainAfterUnverifiedProcessCleanup()
            throw failure
        } finally {
            try {
                snapshot?.close()
            } catch (cleanup: Throwable) {
                cleanupUnverified = true
                primary?.let(cleanup::addSuppressed)
                throw cleanup
            } finally {
                permit.finish(cleanupUnverified)
            }
        }
    }

    // These split methods cannot prove immutable candidate/corpus authority and are never a
    // production escape hatch. The public loop calls validateCandidate as one bounded operation.
    private fun immutableRequestRequired(): Nothing = throw SandboxUnavailableException(
        "production generated-C validation requires an immutable candidate validation request")
    override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? = immutableRequestRequired()
    override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = immutableRequestRequired()
    override fun evaluateBehavior(id: String, projectDir: Path, originalBinary: Path, rebuiltBinary: Path,
        inputs: List<ProcessInput>, reportsDir: Path, budget: RepairResourceBudget): BehaviorComparisonReport = immutableRequestRequired()

    companion object {
        fun create(): GeneratedCRepairValidationBoundary = LinuxGeneratedCRepairValidationBoundary()
        private val PROGRAM_DESTINATION = Path.of("/decomp-generated-c-program")
        private fun requireProductionQualification(): Nothing = throw SandboxUnavailableException(
            "generated-C validation remains unavailable pending qualification of its complete " +
                "provisioned compiler, executable runtime and public-factory validation path",
        )
    }
}

private fun buildEnvironment(output: Path): Map<String, String> = mapOf(
    "PATH" to GeneratedCRepairRuntimeConfiguration.TOOL_DIRECTORY.toString(), "LANG" to "C", "LC_ALL" to "C",
    "TZ" to "UTC", "TMPDIR" to output.toString(), "HOME" to output.toString(), "SOURCE_DATE_EPOCH" to "0",
)

internal class GeneratedCValidationDeadline(val deadlineNanos: Long, val cancellation: AgentCancellation) {
    fun expired(): Boolean = System.nanoTime() - deadlineNanos >= 0
    fun check() {
        if (Thread.currentThread().isInterrupted || cancellation.isCancellationRequested()) {
            throw CancellationException("generated-C validation cancelled")
        }
        if (expired()) throw GeneratedCValidationTimeoutException("generated-C validation exceeded its enclosing deadline")
    }
    fun remaining(): Duration { check(); return Duration.ofNanos(deadlineNanos - System.nanoTime()).coerceAtLeast(Duration.ofNanos(1)) }
    companion object {
        fun after(duration: Duration, cancellation: AgentCancellation): GeneratedCValidationDeadline =
            GeneratedCValidationDeadline(System.nanoTime() + duration.toNanos(), cancellation)
    }
}

internal class GeneratedCValidationTimeoutException(message: String) : RuntimeException(message)

internal class GeneratedCValidationFailureEvidence(
    override val receiptPath: Path,
    override val receiptSha256: String,
    override val cleanupVerified: Boolean,
    override val failureKind: RepairValidationFailureKind,
) : Exception("contained validation attempt evidence: $failureKind"), RepairValidationFailureEvidence

private fun requireQuotaNotExhausted(root: AcpWorkflowStagingRoot) {
    root.requireCurrentIdentity()
    val capacity = LinuxFilesystemSyscalls.openRoot(root.path).use(LinuxFilesystemSyscalls::filesystemCapacity)
    if (capacity.availableBytes < capacity.fragmentBytes || capacity.availableInodes == 0L) {
        throw RepairBudgetExceededException("contained validation writable quota was exhausted")
    }
}

/** JDK exitValue does not distinguish exit(n) from a signal encoded as 128+n. */
private fun requireUnambiguousExit(exitCode: Int) {
    if (exitCode !in 0..127) throw RepairBudgetExceededException(
        "contained validation ended with an ambiguous signal-style status; resource-limit termination cannot become behavior success",
    )
}

private data class ContainedGeneratedCResult(val output: ProcessOutput, val sandboxSha256: String,
    val sandboxFields: List<Pair<String, String>>)

private fun runContained(
    config: GeneratedCRepairRuntimeConfiguration,
    deadline: GeneratedCValidationDeadline,
    budget: RepairResourceBudget,
    aggregateOutput: AtomicLong,
    command: List<String>, environment: Map<String, String>, cwd: Path,
    mounts: List<AcpSandboxReadOnlyMount>, roots: List<AcpSandboxRootGrant>, stdin: ByteArray,
    maximumDuration: Duration,
): ContainedGeneratedCResult {
    deadline.check()
    val duration = minOf(maximumDuration, deadline.remaining())
    val scopeDeadline = GeneratedCValidationDeadline.after(duration, deadline.cancellation)
    val check = { deadline.check(); scopeDeadline.check() }
    val executor = Executors.newFixedThreadPool(3) { task -> Thread(task, "generated-c-validation-io").apply { isDaemon = true } }
    val boundary = try { LinuxBubblewrapBoundary.prepare(config.sandbox, cancellationCheck = check) }
    catch (failure: Throwable) { executor.shutdown(); throw failure }
    var process: AcpSandboxedProcess? = null
    var primary: Throwable? = null
    try {
        val launch = AcpSandboxLaunch(command, environment, cwd, config.sandbox.agentResourceLimits,
            minOf(duration, scopeDeadline.remaining()), mounts, roots, AcpSandboxLaunchPurpose.CANDIDATE_VALIDATION)
        val launched = boundary.launch(launch, mergeError = false, cancellationCheck = check)
        process = launched
        val stdout = executor.submit<ByteArray> { captureOutput(launched.process.inputStream,
            budget.maximumBehaviorStdoutBytes, budget.maximumBehaviorOutputBytes, aggregateOutput, check) }
        val stderr = executor.submit<ByteArray> { captureOutput(launched.process.errorStream,
            budget.maximumBehaviorStderrBytes, budget.maximumBehaviorOutputBytes, aggregateOutput, check) }
        val writer = executor.submit<Unit> {
            try { launched.process.outputStream.use { stream ->
                var offset = 0
                while (offset < stdin.size) {
                    check()
                    val count = minOf(64 * 1024, stdin.size - offset)
                    stream.write(stdin, offset, count)
                    offset += count
                }
            } } catch (_: IOException) { /* A program may legitimately close its stdin early. */ }
        }
        while (launched.process.isAlive || !stdout.isDone || !stderr.isDone || !writer.isDone) {
            check()
            listOf(stdout, stderr, writer).forEach { it.throwCompletedFailure() }
            Thread.sleep(10)
        }
        check()
        val out = stdout.get()
        val err = stderr.get()
        writer.throwCompletedFailure()
        launched.awaitCleanup(deadline.remaining())
        require(launched.cleanupSucceeded()) { "contained generated-C process cleanup is incomplete" }
        val evidence = boundary.evidence(null, cancellationCheck = deadline::check)
        require(evidence.launches.size == 1 && evidence.networkIsolated && evidence.cgroupV2PidsLimited &&
            evidence.cgroupV2MemoryLimited && evidence.cgroupV2CpuLimited)
        return ContainedGeneratedCResult(ProcessOutput(launched.process.exitValue(), out, err, command, true),
            evidence.evidenceSha256, canonicalAcpSandboxEvidenceFields(evidence, deadline::check))
    } catch (failure: Throwable) {
        primary = failure
        throw failure
    } finally {
        var cleanup: Throwable? = null
        try { boundary.close() } catch (failure: Throwable) { cleanup = failure }
        process?.process?.let { child ->
            runCatching { child.outputStream.close() }
            runCatching { child.inputStream.close() }
            runCatching { child.errorStream.close() }
        }
        executor.shutdownNow()
        // Preserve interruption but finish the bounded cleanup proof before returning authority.
        val interrupted = Thread.interrupted()
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                val failure = AcpCleanupProofFailure("generated-C validation I/O workers did not terminate")
                cleanup?.let(failure::addSuppressed)
                cleanup = failure
            }
        } catch (failure: Throwable) {
            val proof = AcpCleanupProofFailure("generated-C validation I/O cleanup was interrupted", failure)
            cleanup?.let(proof::addSuppressed)
            cleanup = proof
        } finally { if (interrupted) Thread.currentThread().interrupt() }
        cleanup?.let { failure -> primary?.let(failure::addSuppressed); throw failure }
        if (primary == null) deadline.check()
    }
}

private fun captureOutput(stream: InputStream, maximumStream: Long, maximumAggregate: Long,
    aggregate: AtomicLong, check: () -> Unit): ByteArray = stream.use { input ->
    val captured = ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (true) {
        check()
        val read = input.read(buffer)
        if (read < 0) break
        val total = aggregate.addAndGet(read.toLong())
        if (captured.size().toLong() + read > maximumStream || total > maximumAggregate) {
            throw RepairBudgetExceededException("contained validation output exceeded the retained stream/corpus bound")
        }
        captured.write(buffer, 0, read)
    }
    captured.toByteArray()
}

private fun Future<*>.throwCompletedFailure() {
    if (isDone) try { get() } catch (failure: ExecutionException) { throw failure.cause ?: failure }
}

private fun containsCleanupFailure(failure: Throwable): Boolean {
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
    val queue = java.util.ArrayDeque<Throwable>()
    queue += failure
    while (queue.isNotEmpty() && seen.size < 256) {
        val item = queue.removeFirst()
        if (!seen.add(item)) continue
        if (item is AcpCleanupProofFailure) return true
        item.cause?.let(queue::addLast)
        item.suppressed.forEach(queue::addLast)
    }
    return false
}

private class GeneratedCValidationReceipt(private val request: RepairCandidateValidationRequest,
    private val configuration: GeneratedCRepairRuntimeConfiguration) {
    private val scopes = ArrayList<JsonObject>()
    private var source: JsonObject = JsonObject(emptyMap())
    private var outputLink: JsonObject = JsonObject(emptyMap())
    private var retainedMetadata = 0L
    private val maximumBytes = minOf(request.budget.maximumIndexEvidenceBytes, 64L * 1024 * 1024).toInt()

    fun snapshot(snapshot: GeneratedCValidationSnapshot) {
        source = JsonObject(mapOf("manifestSha256" to JsonPrimitive(snapshot.sourceManifestSha256),
            "files" to JsonArray(snapshot.sourceFiles), "quota" to quota(snapshot.source)))
        charge(source)
    }
    fun buildOutputLink(output: AcpWorkflowStagingRoot) {
        outputLink = JsonObject(mapOf("path" to JsonPrimitive("build"), "role" to JsonPrimitive("application-owned-output-link"),
            "target" to JsonPrimitive(output.path.toString()), "quota" to quota(output)))
        charge(outputLink)
    }
    fun scope(role: String, inputId: String?, result: ContainedGeneratedCResult, output: AcpWorkflowStagingRoot) {
        val scope = JsonObject(mapOf("role" to JsonPrimitive(role), "inputId" to (inputId?.let(::JsonPrimitive) ?: JsonNull),
            "output" to process(result.output), "sandboxSha256" to JsonPrimitive(result.sandboxSha256),
            "sandboxFields" to JsonArray(result.sandboxFields.map { (name, value) -> JsonArray(listOf(JsonPrimitive(name), JsonPrimitive(value))) }),
            "writableQuota" to quota(output), "cleanupVerified" to JsonPrimitive(true)))
        charge(scope)
        scopes += scope
    }
    fun finish(outcome: String, original: CapturedGeneratedExecutable?, rebuilt: CapturedGeneratedExecutable?,
        cases: List<BehaviorCaseResult>, cleanupVerified: Boolean = true): ByteArray {
        val document = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("generated-c-linux-bubblewrap-cgroup-v1"),
            "profileId" to JsonPrimitive(request.profileId), "profileSha256" to JsonPrimitive(request.profileSha256),
            "indexSha256" to JsonPrimitive(request.indexSha256), "sourceRevisionSha256" to JsonPrimitive(request.sourceRevisionSha256),
            "regressionCorpusSha256" to JsonPrimitive(request.regressionCorpusSha256),
            "runtimeSha256" to JsonPrimitive(configuration.configurationSha256),
            "runtimeConfiguration" to configuration.configurationRecord,
            "sourceSnapshot" to source, "buildOutputLink" to outputLink,
            "originalExecutable" to executable(original), "rebuiltExecutable" to executable(rebuilt),
            "inputs" to JsonArray(request.inputs.map { input -> JsonObject(mapOf("id" to JsonPrimitive(input.id),
                "args" to JsonArray(input.args.map(::JsonPrimitive)), "stdinBase64" to bytes(input.stdin))) }),
            "scopes" to JsonArray(scopes), "outcome" to JsonPrimitive(outcome),
            "caseCount" to JsonPrimitive(cases.size),
            "matches" to JsonPrimitive(outcome == "behavior-checked" && cases.isNotEmpty() && cases.all { it.matches }),
            "cleanupVerified" to JsonPrimitive(cleanupVerified), "assurance" to JsonPrimitive("strict-contained"),
        ))
        return OracleJson.canonicalBytes(document, StrictJsonLimits(maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes, maximumDepth = 20, maximumNodes = 1_000_000,
            maximumStringBytes = maximumBytes, maximumTotalStringBytes = maximumBytes))
    }
    private fun charge(value: JsonElement) {
        retainedMetadata = Math.addExact(retainedMetadata, value.toString().toByteArray(Charsets.UTF_8).size.toLong())
        if (retainedMetadata > maximumBytes) throw RepairBudgetExceededException("generated-C validation receipt exceeds its metadata bound")
    }
    private fun quota(root: AcpWorkflowStagingRoot): JsonObject {
        val proof = requireNotNull(root.quotaProof).evidence
        return JsonObject(mapOf("provider" to JsonPrimitive(proof.provider), "mountId" to JsonPrimitive(proof.mountId),
            "maximumBytes" to JsonPrimitive(proof.maximumBytes), "maximumEntries" to JsonPrimitive(proof.maximumEntries),
            "mountPathSha256" to JsonPrimitive(proof.mountPathSha256)))
    }
    private fun executable(value: CapturedGeneratedExecutable?): JsonElement = value?.let { JsonObject(mapOf(
        "sha256" to JsonPrimitive(it.sha256), "runtimeManifestSha256" to JsonPrimitive(it.runtimeManifestSha256),
        "bytes" to JsonPrimitive(it.bytes), "mode" to JsonPrimitive(0x140),
        "role" to JsonPrimitive(it.role))) } ?: JsonNull
    private fun process(value: ProcessOutput): JsonObject = JsonObject(mapOf(
        "command" to JsonArray(value.sandboxCommand.map(::JsonPrimitive)), "exitCode" to JsonPrimitive(value.exitCode),
        "stdoutBase64" to bytes(value.stdout), "stderrBase64" to bytes(value.stderr), "networkIsolated" to JsonPrimitive(true)))
    private fun bytes(value: ByteArray) = JsonPrimitive(Base64.getEncoder().encodeToString(value))
}

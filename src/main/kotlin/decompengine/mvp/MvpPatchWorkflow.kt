package decompengine.mvp

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.project.AcpExecutionOutcomeIssue
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.BoundedAgentExecutionEventRecorder
import decompengine.project.MvpPatchCompilerPolicy
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import decompengine.project.sha256
import decompengine.repair.CapturedRepairStagingAuthority
import decompengine.repair.RepairClientAgentHarness
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import decompengine.repair.writeRepairEvidenceAtomically
import decompengine.validation.ProcessInput
import java.io.BufferedWriter
import java.io.PrintStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.Comparator
import java.util.Collections
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText

data class MvpPatchOptions(val inputElf: Path, val outputDir: Path, val assumeYes: Boolean = false)
class MvpPatchException(message: String) : RuntimeException(message)
enum class MvpPublicationMode { REQUIRE_ACP_RELEASE, TEST_ONLY_NON_RELEASE }

class MvpPatchWorkflow(
    private val harness: AgentHarness,
    private val environment: Map<String, String> = System.getenv(),
    private val approve: ((String) -> Boolean)? = null,
    private val decompiler: BinaryDecompiler = GhidraDecompiler(),
    private val binaryExecution: BinaryExecutionBoundary = BinaryExecutionBoundaryFactory.fromEnvironment(environment),
    private val harnessProvenance: String? = null,
    private val resourceBudget: RepairResourceBudget = RepairResourceBudget(),
    private val agentLimits: AgentExecutionLimits = AgentExecutionLimits(
        maxOutputBytes = resourceBudget.maximumResponseBytes,
    ),
    private val publicationMode: MvpPublicationMode = MvpPublicationMode.REQUIRE_ACP_RELEASE,
    private val persistAgentEvidence: (Path, String) -> Unit = ::writeRepairEvidenceAtomically,
) {
    fun run(options: MvpPatchOptions) = run(options, ReconstructionProfiles.default)

    fun run(options: MvpPatchOptions, profile: ReconstructionProfile) {
        require(ReconstructionProfiles.builtIn.any { it.id == profile.id && it.sha256 == profile.sha256 }) {
            "MVP patch profile is not admitted by this application"
        }
        requireMvpSummaryCapacity(resourceBudget.maximumProjectionBytes)
        val compilerPolicy = ReconstructionAdapters.resolve(profile).mvpPatchCompiler
        val input = options.inputElf.toAbsolutePath().normalize()
        val output = options.outputDir.toAbsolutePath().normalize()
        require(input.isRegularFile()) { "input ELF does not exist: $input" }
        val evidence = MvpRunEvidence(
            environment, harnessProvenance ?: fallbackHarnessIdentity(), profile.id, profile.sha256,
            resourceBudget.maximumProjectionBytes,
        )
        cleanOutputDirectory(output, input)
        val logs = output.resolve("logs").createDirectories()
        val decompiled = output.resolve("decompile").createDirectories()
        val patchedSourceDir = output.resolve("patched_c").createDirectories()
        val patchedBinaryDir = output.resolve("patched_binary").createDirectories()
        val summaryDir = output.resolve("summary").createDirectories()
        val evidenceDir = output.resolve("evidence").createDirectories()
        val work = output.resolve(".work").createDirectories()
        val raw = work.resolve("ghidra_decompiled.c")
        val finalBinary = patchedBinaryDir.resolve("patched_binary")
        finalBinary.deleteIfExists()
        val logger = StreamingLogger(logs.resolve("patch-${Instant.now().toEpochMilli()}.log"), evidence)
        var phase = "inspect"
        var reconstructionAgentEvidence: AcpExecutionReceiptDocument? = null
        var reconstructionCandidate: ByteArray? = null
        var patchAgentEvidence: AcpExecutionReceiptDocument? = null
        var patchCandidate: ByteArray? = null
        try {
            logger.use {
                evidence.startPhase(phase)
                it.phase(phase)
                requireElf64(input)
                it.command(listOf("readelf", "-h", "-s", input.pathString), work, "ELF metadata")
                val original = it.binary(binaryExecution, input, input.parent, "observe original")
                evidence.isolation = original.isolation.requireSecure().toString()
                if (original.stdout.isBlank()) throw MvpPatchException("original produced no observable stdout")
                evidence.check("original behavior observation", original.exitCode == 0, "exit=${original.exitCode}, stdoutBytes=${original.stdout.toByteArray().size}")
                evidence.passPhase(phase, "ELF metadata inspected and default behavior retained")

                phase = "reconstruct"
                evidence.startPhase(phase)
                it.phase(phase)
                decompiler.decompile(it, input, work, raw)
                if (!raw.exists() || raw.readText().isBlank()) throw MvpPatchException("Ghidra produced no decompiler output")
                val reconstructed = decompiled.resolve("decompiled.c")
                val reconstructionRequest = capturedRequest(
                    failureKind = "binary-reconstruction",
                    prompt = reconstructionPrompt(original.stdout),
                    projectFiles = mapOf(
                        "ghidra_decompiled.c" to raw.readText(),
                        "decompiled.c" to RECONSTRUCTION_TARGET_PLACEHOLDER,
                    ),
                )
                val reconstructionInput = retainMvpCapturedRequest(
                    evidenceDir.resolve("reconstruction-request.md"), reconstructionRequest,
                    "decompiled.c", resourceBudget, evidence,
                )
                val reconstruction = requestCapturedReplacement(
                    reconstructionInput,
                    evidenceDir.resolve(RECONSTRUCTION_AGENT_EVIDENCE),
                    evidenceDir.resolve(RECONSTRUCTION_AGENT_ASSESSMENT),
                    "reconstruction-turn",
                )
                val reconstructedSource = singleReplacement(
                    reconstruction.response.patches.map { it.relativePath to it.replacement },
                    "decompiled.c",
                )
                reconstructionAgentEvidence = reconstruction.agentExecutionEvidence
                reconstructionCandidate = reconstructedSource.toByteArray(StandardCharsets.UTF_8)
                retainMvpCapturedResponse(
                    evidenceDir.resolve("reconstruction-response.md"), reconstruction.response, resourceBudget, evidence,
                )
                validateMeaningfulReconstruction(reconstructedSource)
                reconstructed.writeText(reconstructedSource)
                evidence.check("meaningful standalone reconstruction", true, "source has main, control/data behavior, and no generic placeholder shape")
                evidence.passPhase(phase, "Ghidra export converted to standalone decompile/decompiled.c")

                phase = "compile"
                evidence.startPhase(phase)
                it.phase(phase)
                val vulnerable = work.resolve("reconstructed_asan")
                compile(it, compilerPolicy, profile, reconstructed, vulnerable, sanitizer = true, warningsAsErrors = false)
                evidence.check("reconstructed sanitizer build", true, "compiled with AddressSanitizer and UBSan")
                evidence.passPhase(phase, "reconstructed source compiled with sanitizers")

                phase = "reproduce"
                evidence.startPhase(phase)
                it.phase(phase)
                val finding = it.binary(
                    binaryExecution, vulnerable, work, "sanitizer reproducer",
                    environment = mapOf("ASAN_OPTIONS" to "detect_leaks=0:halt_on_error=1"),
                )
                if (finding.exitCode == 0 || !finding.combined.contains("Sanitizer")) {
                    throw MvpPatchException("reconstructed program did not reproduce a sanitizer finding")
                }
                val findingPath = evidenceDir.resolve("cwe-787-sanitizer.txt")
                findingPath.writeText(evidence.redact(finding.combined))
                evidence.findingPath = findingPath
                evidence.findingSourceLocation = findSourceLocation(finding.combined)
                    ?: throw MvpPatchException("sanitizer finding did not map to decompile/decompiled.c")
                evidence.check("CWE-787 reproduction", true, "out-of-bounds write retained at ${evidence.findingSourceLocation}; exit=${finding.exitCode}")
                evidence.passPhase(phase, "CWE-787 sanitizer failure reproduced and mapped to reconstructed C")
                retainAgentExecutionEvidence(
                    evidenceDir.resolve(RECONSTRUCTION_AGENT_ASSESSMENT),
                    RECONSTRUCTION_AGENT_EVIDENCE,
                    "reconstruction-turn",
                    requireNotNull(reconstructionCandidate),
                    accepted = true,
                    execution = reconstructionAgentEvidence,
                )

                phase = "patch"
                evidence.startPhase(phase)
                it.phase(phase)
                val patchRequest = capturedRequest(
                    failureKind = "memory-safety",
                    prompt = patchPrompt(original.stdout, finding.combined),
                    projectFiles = mapOf(
                        "decompile/decompiled.c" to reconstructed.readText(),
                        "patched.c" to reconstructed.readText(),
                    ),
                )
                val patchInput = retainMvpCapturedRequest(
                    evidenceDir.resolve("patch-request.md"), patchRequest, "patched.c", resourceBudget, evidence,
                )
                val proposal = requestCapturedReplacement(
                    patchInput,
                    evidenceDir.resolve(PATCH_AGENT_EVIDENCE),
                    evidenceDir.resolve(PATCH_AGENT_ASSESSMENT),
                    "patch-turn",
                )
                evidence.patchExplanation = proposal.response.summary
                val proposedSource = patchedSourceDir.resolve("patched.c")
                val proposedSourceText = singleReplacement(
                    proposal.response.patches.map { it.relativePath to it.replacement },
                    "patched.c",
                )
                patchAgentEvidence = proposal.agentExecutionEvidence
                patchCandidate = proposedSourceText.toByteArray(StandardCharsets.UTF_8)
                retainMvpCapturedResponse(
                    evidenceDir.resolve("patch-response.md"), proposal.response, resourceBudget, evidence,
                )
                proposedSource.writeText(proposedSourceText)
                val diff = it.command(listOf("diff", "-u", reconstructed.pathString, proposedSource.pathString), work, "proposed patch", false, accepted = setOf(0, 1))
                if (diff.exitCode == 0 || diff.stdout.isBlank()) throw MvpPatchException("proposed patch did not change reconstructed C")
                val diffPath = evidenceDir.resolve("approved.patch")
                diffPath.writeText(evidence.redact(diff.stdout))
                evidence.patchDiff = diff.stdout
                evidence.patchDiffPath = diffPath
                val approved = options.assumeYes || (approve?.invoke(evidence.patchExplanation)
                    ?: promptForApproval(evidence.patchExplanation, evidence))
                evidence.approvalDecision = when {
                    !approved -> "rejected interactively"
                    options.assumeYes -> "approved by --yes automation"
                    else -> "approved interactively"
                }
                evidence.check("source patch approval", approved, evidence.approvalDecision)
                if (!approved) throw MvpPatchException("patch was not approved")
                evidence.passPhase(phase, "non-empty source diff approved and retained at evidence/approved.patch")

                phase = "verify"
                evidence.startPhase(phase)
                it.phase(phase)
                val patchedAsan = work.resolve("patched_asan")
                compile(it, compilerPolicy, profile, proposedSource, patchedAsan, sanitizer = true, warningsAsErrors = true)
                evidence.check("patched sanitizer build", true, "compiled with -Werror, AddressSanitizer, and UBSan")
                verify(it, patchedAsan, original, "sanitizer security validation")
                evidence.check("sanitizer security validation", true, "CWE-787 reproducer no longer reports a sanitizer failure")
                val release = work.resolve("patched_release")
                compile(it, compilerPolicy, profile, proposedSource, release, sanitizer = false, warningsAsErrors = true)
                evidence.check("hardened release build", true, "compiled with FORTIFY_SOURCE=2, stack protector, PIE, RELRO, and immediate binding")
                verifyHardening(it, release)
                evidence.check("binary hardening inspection", true, "ELF is PIE with GNU_RELRO and immediate binding")
                verify(it, release, original, "release verification")
                evidence.check("behavior validation", true, "exit code and stdout match the observed original default execution")
                evidence.passPhase(phase, "all sanitizer, hardening, security, and behavior checks passed")
                retainAgentExecutionEvidence(
                    evidenceDir.resolve(PATCH_AGENT_ASSESSMENT),
                    PATCH_AGENT_EVIDENCE,
                    "patch-turn",
                    requireNotNull(patchCandidate),
                    accepted = true,
                    execution = patchAgentEvidence,
                )
                val result = if (requiresAcpReleaseEvidence()) {
                    Files.copy(release, finalBinary, StandardCopyOption.REPLACE_EXISTING)
                    finalBinary.toFile().setExecutable(true, true)
                    it.info("completed: $finalBinary")
                    "PASS"
                } else {
                    finalBinary.deleteIfExists()
                    it.info("completed validation in explicit non-release compatibility mode")
                    "NON_RELEASE"
                }
                writeMvpSummary(
                    summaryDir.resolve("SUMMARY.md"), output, input, raw, reconstructed,
                    proposedSource, finalBinary, result, null, evidence,
                )
            }
        } catch (failure: Exception) {
            finalBinary.deleteIfExists()
            evidence.failPhase(phase, failure.message ?: failure.javaClass.simpleName)
            if (phase in setOf("reconstruct", "compile", "reproduce")) {
                reconstructionCandidate?.let { candidate ->
                    retainAgentExecutionEvidence(
                        evidenceDir.resolve(RECONSTRUCTION_AGENT_ASSESSMENT),
                        RECONSTRUCTION_AGENT_EVIDENCE,
                        "reconstruction-turn",
                        candidate,
                        accepted = false,
                        execution = reconstructionAgentEvidence,
                        issue = AcpExecutionOutcomeIssue(
                            "workflow-validation-rejected",
                            "workflow validation rejected the captured reconstruction",
                        ),
                    )
                }
            }
            if (phase in setOf("patch", "verify")) {
                patchCandidate?.let { candidate ->
                    retainAgentExecutionEvidence(
                        evidenceDir.resolve(PATCH_AGENT_ASSESSMENT),
                        PATCH_AGENT_EVIDENCE,
                        "patch-turn",
                        candidate,
                        accepted = false,
                        execution = patchAgentEvidence,
                        issue = AcpExecutionOutcomeIssue(
                            "workflow-validation-rejected",
                            "workflow validation rejected the captured patch",
                        ),
                    )
                }
            }
            writeMvpSummary(
                summaryDir.resolve("SUMMARY.md"), output, input, raw, decompiled.resolve("decompiled.c"),
                patchedSourceDir.resolve("patched.c"), finalBinary, "FAIL", "$phase: ${failure.message}", evidence,
            )
            throw if (failure is MvpPatchException) failure else MvpPatchException(failure.message ?: failure.javaClass.simpleName)
        }
    }

    private fun compile(
        logger: StreamingLogger,
        compilerPolicy: MvpPatchCompilerPolicy,
        profile: ReconstructionProfile,
        source: Path,
        target: Path,
        sanitizer: Boolean,
        warningsAsErrors: Boolean,
    ) {
        logger.command(
            compilerPolicy.command(profile, source, target, sanitizer, warningsAsErrors),
            target.parent,
            "compile ${target.fileName}",
        )
    }

    private fun verify(logger: StreamingLogger, binary: Path, expected: BinaryExecutionResult, label: String) {
        val result = logger.binary(binaryExecution, binary, binary.parent, label)
        if (result.exitCode != 0 || result.stdout != expected.stdout || result.combined.contains("Sanitizer")) {
            throw MvpPatchException("$label did not preserve observed behavior")
        }
    }

    private fun verifyHardening(logger: StreamingLogger, binary: Path) {
        val headers = logger.command(listOf("readelf", "-W", "-h", "-l", "-d", binary.pathString), binary.parent, "hardening inspection")
        val output = headers.combined
        if (!Regex("Type:\\s+DYN").containsMatchIn(output) || !output.contains("GNU_RELRO") ||
            !(output.contains("BIND_NOW") || Regex("FLAGS.*NOW").containsMatchIn(output))
        ) {
            throw MvpPatchException("release binary is missing required PIE, RELRO, or immediate-binding hardening")
        }
    }

    private fun capturedRequest(
        failureKind: String,
        prompt: String,
        projectFiles: Map<String, String>,
    ): RepairRequest = RepairRequest(
        failureKind = failureKind,
        prompt = prompt,
        projectFiles = projectFiles,
        regressionInputs = listOf(ProcessInput("default")),
    )

    /**
     * Executes one proposal through the production captured-repair boundary.
     *
     * The agent receives no writable host directory and no terminal capability. The target must
     * already exist in the in-memory staging set, and the authority enforces file, patch, and
     * aggregate workspace quotas as each replacement is received.
     */
    private fun requestCapturedReplacement(
        input: MvpCapturedRequest,
        receiptPath: Path,
        assessmentPath: Path,
        taskId: String,
    ): CapturedAgentReplacement {
        val request = input.request
        val target = input.target
        val initialFiles = input.initialFiles
        val objective = input.objective
        lateinit var agentRequest: AgentExecutionRequest
        val eventRecorder = BoundedAgentExecutionEventRecorder()
        val staged = CapturedRepairStagingAuthority.executeReceipt(
            harness = harness,
            initialFiles = initialFiles,
            writablePaths = setOf(target),
            budget = resourceBudget,
            requestFactory = { root ->
                val rules = initialFiles.keys.sorted().map { relativePath ->
                    AgentPathRule(
                        AgentWorkspacePath(root.id, relativePath),
                        if (relativePath == target) {
                            setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)
                        } else {
                            setOf(AgentOperation.READ_FILE)
                        },
                    )
                }
                AgentExecutionRequest(
                    objective = objective,
                    workspaceRoots = listOf(root),
                    contextInputs = listOf(
                        AgentContextInput(RepairClientAgentHarness.FAILURE_KIND_CONTEXT_ID, request.failureKind),
                    ),
                    accessPolicy = AgentAccessPolicy(rules),
                    limits = agentLimits,
                ).also { agentRequest = it }
            },
            onEvent = eventRecorder::record,
        )
        val executionEvidence = AcpExecutionReceiptDocument.captureOrNull(
            request = agentRequest,
            promptSha256 = sha256(request.prompt.toByteArray(StandardCharsets.UTF_8)),
            receipt = staged.receipt,
            events = eventRecorder.receiptSnapshot(),
            evidenceKind = "decomp-engine.mvp-patch-acp-execution-receipt",
            taskIdentityField = "taskId",
            taskId = taskId,
        )
        if (executionEvidence != null) {
            // Persist the immutable invocation before inspecting its terminal result, staged files,
            // or any workflow validation. A later assessment only binds this document's digest.
            persistAgentEvidence(receiptPath, executionEvidence.json)
        }
        val observedTarget = staged.files[target] ?: initialFiles.getValue(target)
        if (executionEvidence != null) {
            retainAgentExecutionEvidence(
                assessmentPath,
                receiptPath.fileName.toString(),
                taskId,
                observedTarget,
                accepted = null,
                execution = executionEvidence,
            )
        }
        fun reject(code: String, message: String): Nothing {
            retainAgentExecutionEvidence(
                assessmentPath,
                receiptPath.fileName.toString(),
                taskId,
                observedTarget,
                accepted = false,
                execution = executionEvidence,
                issue = AcpExecutionOutcomeIssue(code, message),
            )
            throw MvpPatchException("$message [$code]")
        }
        val result = when (val outcome = staged.receipt.outcome) {
            is AgentExecutionOutcome.Returned -> outcome.result
            is AgentExecutionOutcome.Failed -> reject(
                "agent-failure-${outcome.failure.kind.name.lowercase().replace('_', '-')}",
                "patch agent failed before returning a captured replacement",
            )
        }
        if (requiresAcpReleaseEvidence() && executionEvidence == null) {
            reject("missing-acp-receipt", "ACP patch turn returned without invocation-bound evidence")
        }
        if (result.stopReason != AgentStopReason.COMPLETED) {
            reject(
                "agent-stop-${result.stopReason.name.lowercase().replace('_', '-')}",
                "patch agent stopped without a completed captured replacement",
            )
        }
        if (executionEvidence != null && !executionEvidence.releaseComplete) {
            reject("incomplete-acp-receipt", "ACP patch turn lacks release-complete invocation evidence")
        }
        if (result.changes.size != 1) {
            reject("invalid-change-count", "patch agent must report exactly one changed file")
        }
        val change = result.changes.single()
        if (change.path.rootId != "project" || change.path.relativePath != target) {
            reject("unauthorized-change", "patch agent reported an unauthorized file change")
        }
        if (change.kind != AgentFileChangeKind.MODIFIED) {
            reject("invalid-change-kind", "patch agent may only replace the staged target")
        }
        if (staged.files.keys != initialFiles.keys) {
            reject("unexpected-staging-files", "captured patch staging returned an unexpected file set")
        }
        val before = initialFiles.getValue(target)
        val after = staged.files.getValue(target) ?: reject(
            "deleted-target",
            "patch agent deleted the staged target",
        )
        if (before.contentEquals(after)) {
            reject("unchanged-target", "patch agent completed without changing the staged target")
        }
        if (change.beforeSha256 != sha256(before) || change.afterSha256 != sha256(after)) {
            reject("change-digest-mismatch", "patch agent digests do not match the captured replacement")
        }
        if (change.sizeBytes != null && change.sizeBytes != after.size.toLong()) {
            reject("change-size-mismatch", "patch agent size does not match the captured replacement")
        }
        val replacement = decodeStrictUtf8(target, after)
        val response = try {
            prepareMvpCapturedResponse(result.summary, target, replacement, resourceBudget)
        } catch (_: MvpPatchException) {
            reject("response-content-budget", "patch agent response exceeds retained content budgets")
        }
        return CapturedAgentReplacement(response, executionEvidence)
    }

    private fun retainAgentExecutionEvidence(
        path: Path,
        receiptFileName: String,
        taskId: String,
        source: ByteArray,
        accepted: Boolean?,
        execution: AcpExecutionReceiptDocument?,
        issue: AcpExecutionOutcomeIssue? = null,
    ) {
        if (execution == null) {
            path.deleteIfExists()
            return
        }
        require(receiptFileName.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "MVP ACP receipt file name is invalid"
        }
        require(taskId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "MVP ACP task ID is invalid"
        }
        if (accepted == true) {
            require(execution.releaseComplete && execution.terminalOutcome == "returned-completed") {
                "incomplete ACP invocation cannot be accepted for MVP release"
            }
        }
        val issueJson = issue?.let { item ->
            val bytes = item.message.toByteArray(StandardCharsets.UTF_8)
            "{\"code\":\"${item.code.mvpJsonEscape()}\",\"messageSha256\":\"${sha256(bytes)}\"," +
                "\"messageUtf8Bytes\":${bytes.size}}"
        }
        val payload = buildString {
            append("{\n  \"schemaVersion\": 1,")
            append("\n  \"kind\": \"decomp-engine.mvp-acp-workflow-assessment\",")
            append("\n  \"taskId\": \"").append(taskId.mvpJsonEscape()).append("\",")
            append("\n  \"receiptPath\": \"evidence/")
                .append(receiptFileName.mvpJsonEscape()).append("\",")
            append("\n  \"receiptSha256\": \"").append(execution.sha256).append("\",")
            append("\n  \"receiptSchemaVersion\": ").append(execution.schemaVersion).append(',')
            append("\n  \"requestSha256\": \"").append(execution.requestSha256).append("\",")
            append("\n  \"terminalOutcome\": \"").append(execution.terminalOutcome).append("\",")
            append("\n  \"receiptReleaseComplete\": ").append(execution.releaseComplete).append(',')
            append("\n  \"status\": \"").append(when (accepted) {
                true -> "accepted"
                false -> "rejected"
                null -> "pending"
            }).append("\",")
            append("\n  \"sourceSha256\": \"").append(sha256(source)).append("\",")
            append("\n  \"issues\": [")
            issueJson?.let(::append)
            append("]\n}\n")
        }
        persistAgentEvidence(path, payload)
    }

    private fun requiresAcpReleaseEvidence(): Boolean = when {
        publicationMode == MvpPublicationMode.TEST_ONLY_NON_RELEASE -> false
        harnessProvenance?.startsWith("agent-harness-v1:legacy-openai:") == true -> false
        else -> true
    }

    private fun decodeStrictUtf8(relativePath: String, bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: CharacterCodingException) {
        throw MvpPatchException("patch agent returned invalid UTF-8 for $relativePath")
    }

    private fun fallbackHarnessIdentity(): String = "agent-harness-unprovisioned"
}

private const val RECONSTRUCTION_TARGET_PLACEHOLDER =
    "/* Authorized ACP target: replace this complete file with reconstructed C11 source. */\n"
internal const val RECONSTRUCTION_AGENT_EVIDENCE = "reconstruction-agent-execution.json"
internal const val RECONSTRUCTION_AGENT_ASSESSMENT = "reconstruction-agent-execution-assessment.json"
internal const val PATCH_AGENT_EVIDENCE = "patch-agent-execution.json"
internal const val PATCH_AGENT_ASSESSMENT = "patch-agent-execution-assessment.json"

private data class CapturedAgentReplacement(
    val response: RepairResponse,
    val agentExecutionEvidence: AcpExecutionReceiptDocument?,
)

private fun String.mvpJsonEscape(): String = buildString {
    this@mvpJsonEscape.forEach { character ->
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
        }
    }
}

private fun cleanOutputDirectory(output: Path, input: Path) {
    require(output.root == null || output != output.root) { "refusing to clean unsafe output directory: $output" }
    require(output != input.parent) { "refusing to clean input parent directory: $output" }
    if (!output.exists()) return
    Files.walk(output).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach { path ->
            if (path != output) Files.deleteIfExists(path)
        }
    }
}

fun interface BinaryDecompiler {
    fun decompile(logger: StreamingLogger, input: Path, work: Path, raw: Path)
}

class GhidraDecompiler internal constructor(
    private val commandFactory: (decompengine.analysis.GhidraInvocation) -> List<String>,
) : BinaryDecompiler {
    constructor() : this({ decompengine.analysis.BundledGhidra.locate().analysisCommand(it) })

    override fun decompile(logger: StreamingLogger, input: Path, work: Path, raw: Path) {
        val scripts = work.resolve("ghidra_scripts").createDirectories()
        javaClass.getResourceAsStream("/ghidra_scripts/ExportDecompiledC.java")?.use {
            Files.copy(it, scripts.resolve("ExportDecompiledC.java"), StandardCopyOption.REPLACE_EXISTING)
        } ?: throw MvpPatchException("bundled Ghidra script is missing")
        val projectDir = decompengine.analysis.GhidraProjectLocation.forWorker(work.resolve("ghidra_project").createDirectories(), work)
        logger.command(
            commandFactory(decompengine.analysis.GhidraInvocation(
                projectDir, "mvp", input, scripts,
                listOf(decompengine.analysis.GhidraPostScript("ExportDecompiledC.java", listOf(raw.toAbsolutePath().normalize().pathString))),
            )), work, "Ghidra decompile",
        )
        require(Files.isRegularFile(raw) && Files.size(raw) > 0) { "Bundled Ghidra did not export decompiled C" }
    }
}

data class CommandResult(val exitCode: Int, val stdout: String, val stderr: String) {
    val combined: String = stdout + stderr
}

class StreamingLogger private constructor(
    path: Path,
    private val privacy: MvpLogPrivacy,
    private val output: PrintStream,
    private val errors: PrintStream,
    private val timestamp: () -> String,
) : AutoCloseable {
    constructor(path: Path) : this(path, defaultPrivacy(), System.out, System.err, { Instant.now().toString() })

    internal constructor(
        path: Path, evidence: MvpRunEvidence, output: PrintStream = System.out, errors: PrintStream = System.err,
        timestamp: () -> String = { Instant.now().toString() },
    ) : this(path, evidence.logPrivacy, output, errors, timestamp)

    private val writer: BufferedWriter = Files.newBufferedWriter(path)
    private val emittedLines = privacy.lines()

    fun phase(name: String) = info("==> $name")
    fun info(message: String) = emit(message, false, timestamp())

    @Synchronized
    private fun emit(message: String, error: Boolean, stamp: String? = null, pipe: MvpLogPrivacy.Lines? = null) {
        val guarded = privacy.message(message, emittedLines, pipe)
        val frame = privacy.frame(guarded, error, stamp)
        val console = if (frame.error) errors else output
        console.println(frame.console)
        console.flush()
        writer.appendLine(frame.retained)
        writer.flush()
    }

    internal fun outputLine(line: String, error: Boolean, pipe: MvpLogPrivacy.Lines) = emit(line, error, pipe = pipe)

    fun command(
        command: List<String>, directory: Path, label: String, requireSuccess: Boolean = true,
        environment: Map<String, String> = emptyMap(), accepted: Set<Int> = setOf(0),
    ): CommandResult {
        info("$ $label: ${command.joinToString(" ")}")
        val process = ProcessBuilder(command).directory(directory.toFile())
            .apply { environment().putAll(environment) }.start()
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val projectionFailure = MvpLogFailure()
        val display = MvpLiveCommandDisplay(privacy) { line, error, pipe -> emit(line, error, pipe = pipe) }
        val captureBudget = MvpCommandCaptureBudget(privacy.maximumBytes)
        val outThread = stream(process.inputStream, stdout, false, projectionFailure, display, captureBudget)
        val errThread = stream(process.errorStream, stderr, true, projectionFailure, display, captureBudget)
        outThread.join(); errThread.join()
        val code = process.waitFor()
        projectionFailure.requireSuccess()
        display.finish(stdout, stderr)
        info("$label exit_code=$code")
        if (requireSuccess && code !in accepted) throw MvpPatchException("$label failed with exit code $code")
        return CommandResult(code, stdout.toString(), stderr.toString())
    }

    fun binary(
        boundary: BinaryExecutionBoundary,
        executable: Path,
        directory: Path,
        label: String,
        environment: Map<String, String> = emptyMap(),
    ): BinaryExecutionResult {
        info("$ $label: isolated-exec ${executable.toAbsolutePath().normalize()}")
        val result = boundary.execute(executable, directory, environment)
        // Admit both complete streams before output. The boundary does not retain cross-pipe order,
        // so any earlier peer introducer prefix makes every local record ambiguous during replay.
        val stdoutLines = privacy.linesWithUnorderedPeer(result.stderr)
        val stderrLines = privacy.linesWithUnorderedPeer(result.stdout)
        result.stdout.lineSequence().filter(String::isNotEmpty).forEach { outputLine(it, false, stdoutLines) }
        result.stderr.lineSequence().filter(String::isNotEmpty).forEach { outputLine(it, true, stderrLines) }
        info("$label exit_code=${result.exitCode} isolation=${result.isolation}")
        return result
    }

    private fun stream(
        input: java.io.InputStream, capture: StringBuilder, error: Boolean,
        projectionFailure: MvpLogFailure, display: MvpLiveCommandDisplay,
        captureBudget: MvpCommandCaptureBudget,
    ): Thread {
        val collector = MvpCommandCapture(capture, captureBudget)
        return Thread {
            try {
                input.reader(Charsets.UTF_8).use { reader ->
                    val buffer = CharArray(4096)
                    while (true) {
                        val count = reader.read(buffer)
                        if (count < 0) break
                        // After the first collection/display failure, drain without retaining more.
                        if (count > 0) projectionFailure.attempt {
                            collector.feed(buffer, count) {
                                projectionFailure.attempt { display.line(error, capture) }
                            }
                        }
                    }
                    projectionFailure.attempt {
                        collector.finish { projectionFailure.attempt { display.line(error, capture) } }
                    }
                }
                projectionFailure.attempt { display.complete(error, capture) }
            } catch (failure: Throwable) {
                // Avoid the JVM's raw child-thread exception printer; caller rethrows unchanged.
                projectionFailure.record(failure)
            }
        }.also { it.start() }
    }

    override fun close() = writer.close()

    private companion object {
        fun defaultPrivacy(): MvpLogPrivacy {
            val maximum = decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
            return MvpLogPrivacy(MvpArtifactRedactor(System.getenv().values, maximum))
        }
    }
}

private fun singleReplacement(patches: List<Pair<String, String>>, suffix: String): String {
    if (patches.size != 1 || !patches.single().first.endsWith(suffix)) {
        throw MvpPatchException("API must return exactly one full reconstructed.c replacement")
    }
    return patches.single().second.removeSurrounding("```c\n", "\n```")
}

private fun requireElf64(path: Path) {
    val bytes = path.readBytes()
    val magic = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)
    if (bytes.size < 5 || !bytes.copyOfRange(0, 4).contentEquals(magic) || bytes[4].toInt() != 2) {
        throw MvpPatchException("only 64-bit ELF input is supported")
    }
}

private fun reconstructionPrompt(stdout: String) = """
    Convert the Ghidra decompiler output into one standalone, readable C11 source file with main.
    Preserve the observed default execution exactly. Observed combined output:\n$stdout
    Preserve suspicious memory operations as reconstructed; do not fix vulnerabilities yet.
    Resolve Ghidra types, labels, wrappers, and string references into normal C. Do not invent extra behavior.
    Edit decompiled.c in place with the complete reconstructed source. Do not change ghidra_decompiled.c.
""".trimIndent()

private fun patchPrompt(stdout: String, sanitizer: String) = """
    Apply the smallest clear memory-safety fix to the supplied reconstructed C.
    Preserve observed output exactly:\n$stdout
    Sanitizer evidence:\n$sanitizer
    Edit patched.c in place with the complete fixed source. Do not change decompile/decompiled.c.
    The result must compile as C11 with -Wall -Wextra -Werror. In the final summary, explain the
    vulnerability root cause, the exact code change, and why the change preserves observed behavior.
""".trimIndent()

private fun validateMeaningfulReconstruction(source: String) {
    val meaningfulLines = source.lineSequence().map(String::trim).filter { it.isNotEmpty() && !it.startsWith("//") }.count()
    val hasMain = Regex("\\bmain\\s*\\(").containsMatchIn(source)
    val hasRecoveredBehavior = Regex("\\b(for|while|if|switch|memcpy|memmove|strcpy|puts|printf)\\b|\\[[^]]+]\\s*=").containsMatchIn(source)
    if (source.length < 120 || meaningfulLines < 6 || !hasMain || !hasRecoveredBehavior) {
        throw MvpPatchException("LLM reconstruction is a placeholder or lacks meaningful recovered control/data behavior")
    }
}

internal class MvpCapturedRequest(
    val request: RepairRequest,
    val target: String,
    val objective: String,
    val initialFiles: Map<String, ByteArray>,
)

/** Admit the complete retained fields before encoding files or rendering their Markdown. */
internal fun prepareMvpCapturedRequest(
    request: RepairRequest,
    target: String,
    budget: RepairResourceBudget,
): MvpCapturedRequest {
    if (request.projectFiles.size > budget.maximumContextFiles ||
        request.regressionInputs.size > budget.maximumRegressionInputs
    ) {
        throw MvpPatchException("captured patch request exceeds its entry budget")
    }
    val frozen = request.copy(
        projectFiles = request.projectFiles.toMap(),
        regressionInputs = captureMvpRegressionInputs(request.regressionInputs, budget),
    )
    require(target in frozen.projectFiles) { "captured patch target is absent: $target" }
    val content = MvpContentBudget(budget.maximumRequestBytes, "captured patch request")
    content.charge("project")
    content.charge(RepairClientAgentHarness.FAILURE_KIND_CONTEXT_ID)
    content.charge(frozen.failureKind)
    val staging = MvpContentBudget(budget.maximumStagingBytes, "captured patch staging")
    frozen.projectFiles.forEach { (path, text) ->
        content.charge(path)
        staging.chargeBytes(content.charge(text))
    }
    val commonBytes = content.used
    // The transcript retains the raw prompt, not the trimmed agent objective.
    content.charge(frozen.prompt)
    frozen.regressionInputs.forEach { input ->
        content.charge(input.id)
        input.args.forEach { content.charge(it) }
        content.chargeBytes(input.stdin.size.toLong())
    }
    val objective = buildString {
        append(frozen.prompt.trim())
        append("\n\nEdit ").append(target)
        append(" in place. Do not create, delete, or modify any other file.")
    }
    MvpContentBudget(budget.maximumRequestBytes, "captured patch request").apply {
        chargeBytes(commonBytes)
        charge(objective)
    }
    return MvpCapturedRequest(
        frozen, target, objective,
        frozen.projectFiles.mapValues { (_, text) -> text.toByteArray(StandardCharsets.UTF_8) },
    )
}

private fun captureMvpRegressionInputs(inputs: List<ProcessInput>, budget: RepairResourceBudget): List<ProcessInput> {
    val content = MvpContentBudget(budget.maximumRegressionInputBytes, "captured regression inputs")
    val snapshot = ArrayList<ProcessInput>()
    var argumentCount = 0L
    inputs.forEach { input ->
        val suppliedArguments = input.args.size.toLong()
        if (snapshot.size >= budget.maximumRegressionInputs || suppliedArguments < 0 ||
            suppliedArguments > budget.maximumRegressionArguments - argumentCount
        ) {
            throw MvpPatchException("captured regression inputs exceed their entry budget")
        }
        content.charge(input.id)
        content.chargeBytes(input.stdin.size.toLong())
        val arguments = ArrayList<String>()
        input.args.forEach { argument ->
            if (argumentCount >= budget.maximumRegressionArguments) {
                throw MvpPatchException("captured regression inputs exceed their argument budget")
            }
            content.charge(argument)
            arguments += argument
            argumentCount++
        }
        snapshot += ProcessInput(input.id, Collections.unmodifiableList(arguments), input.stdin.copyOf())
    }
    return Collections.unmodifiableList(snapshot)
}

internal fun retainMvpCapturedRequest(
    path: Path,
    request: RepairRequest,
    target: String,
    budget: RepairResourceBudget,
    evidence: MvpRunEvidence,
): MvpCapturedRequest {
    val admitted = prepareMvpCapturedRequest(request, target, budget)
    retainRequest(path, admitted.request, evidence)
    return admitted
}

internal fun prepareMvpCapturedResponse(
    summary: String?,
    target: String,
    replacement: String,
    budget: RepairResourceBudget,
): RepairResponse {
    val raw = RepairResponse(summary.orEmpty(), listOf(SourcePatch(target, replacement)))
    requireMvpResponseContentBudget(raw, budget)
    val response = raw.copy(summary = raw.summary.trim().ifBlank {
        "agent supplied a captured full-file replacement"
    })
    // A blank summary's fallback must also fit a caller's smaller response budget.
    requireMvpResponseContentBudget(response, budget)
    return response
}

internal fun retainMvpCapturedResponse(
    path: Path,
    response: RepairResponse,
    budget: RepairResourceBudget,
    evidence: MvpRunEvidence,
) {
    if (response.patches.size > budget.maximumPatchFiles) {
        throw MvpPatchException("captured patch response exceeds its entry budget")
    }
    val frozen = response.copy(patches = response.patches.toList())
    requireMvpResponseContentBudget(frozen, budget)
    retainResponse(path, frozen, evidence)
}

private fun requireMvpResponseContentBudget(response: RepairResponse, budget: RepairResourceBudget) {
    if (response.patches.size > budget.maximumPatchFiles) {
        throw MvpPatchException("captured patch response exceeds its entry budget")
    }
    val content = MvpContentBudget(budget.maximumResponseBytes, "captured patch response")
    val patches = MvpContentBudget(budget.maximumPatchBytes, "captured patch replacement")
    content.charge(response.summary)
    response.patches.forEach { patch ->
        content.charge(patch.relativePath)
        patches.chargeBytes(content.charge(patch.replacement))
    }
}

/** Counts String.toByteArray(UTF_8) bytes without allocating an oversized encoded copy. */
private class MvpContentBudget(private val maximum: Long, private val label: String) {
    var used: Long = 0
        private set

    fun charge(text: String): Long {
        val remaining = maximum - used
        if (text.length.toLong() > remaining) exceeded()
        var bytes = 0L
        var index = 0
        while (index < text.length) {
            val character = text[index++].code
            val width = when {
                character < 0x80 -> 1
                character < 0x800 -> 2
                character in 0xD800..0xDBFF && index < text.length &&
                    text[index].code in 0xDC00..0xDFFF -> { index++; 4 }
                character in 0xD800..0xDFFF -> 1 // The UTF-8 encoder replaces an unpaired surrogate with '?'.
                else -> 3
            }
            if (bytes > remaining - width) exceeded()
            bytes += width
        }
        chargeBytes(bytes)
        return bytes
    }

    fun chargeBytes(bytes: Long) {
        if (bytes < 0 || bytes > maximum - used) exceeded()
        used += bytes
    }

    private fun exceeded(): Nothing = throw MvpPatchException("$label exceeds its content byte budget")
}

private fun retainRequest(path: Path, request: RepairRequest, evidence: MvpRunEvidence) {
    val transcript = evidence.artifactText {
        append("# Retained LLM Request\n\n- Failure kind: ").append(request.failureKind)
        append("\n- Regression inputs: ")
        request.regressionInputs.forEachIndexed { index, input ->
            if (index != 0) append(", ")
            append(input.id)
        }
        append("\n\n## Objective\n\n").append(request.prompt).append("\n\n## Binary-derived context\n\n")
        request.projectFiles.toSortedMap().entries.forEachIndexed { index, (name, content) ->
            if (index != 0) append("\n\n")
            append("## ").append(name).append("\n\n```c\n").append(evidence.redact(content).trimEnd()).append("\n```")
        }
        append("\n")
    }
    Files.write(path, encodeMvpArtifactUtf8(transcript))
}

private fun retainResponse(path: Path, response: decompengine.repair.RepairResponse, evidence: MvpRunEvidence) {
    val transcript = evidence.artifactText {
        append("# Retained LLM Response\n\n## Summary\n\n").append(response.summary).append("\n\n")
        response.patches.forEachIndexed { index, patch ->
            if (index != 0) append("\n\n")
            append("## ").append(patch.relativePath).append("\n\n```c\n")
                .append(evidence.redact(patch.replacement).trimEnd()).append("\n```")
        }
        append("\n")
    }
    Files.write(path, encodeMvpArtifactUtf8(transcript))
}

private fun findSourceLocation(sanitizer: String): String? =
    Regex("(?:[A-Za-z]:)?[^\\s:]*decompiled\\.c:\\d+(?::\\d+)?")
        .find(sanitizer)
        ?.value
        ?.substringAfterLast('/')

private fun promptForApproval(summary: String, evidence: MvpRunEvidence): Boolean {
    print(renderMvpApprovalPrompt(summary, evidence)); System.out.flush()
    return readlnOrNull()?.trim()?.lowercase() in setOf("y", "yes")
}

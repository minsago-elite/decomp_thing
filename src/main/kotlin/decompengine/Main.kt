package decompengine

import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.doctor.Doctor
import decompengine.doctor.DoctorDiagnosticAdmissionException
import decompengine.doctor.DoctorDiagnostics
import decompengine.doctor.DoctorReport
import decompengine.doctor.DoctorToolKind
import decompengine.doctor.parseDoctorInvocation
import decompengine.doctor.requireDoctorActive
import decompengine.mvp.MvpPatchOptions
import decompengine.mvp.MvpPatchWorkflow
import decompengine.mvp.MvpArtifactRedactor
import decompengine.mvp.MvpPatchException
import decompengine.mvp.BinaryRunnerService
import decompengine.acp.AcpHarnessFactory
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ReconstructionProfiles
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ModuleReconstructor
import decompengine.agent.AgentHarness
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.ProgressRedactor
import decompengine.oracle.behavior.LlvmBehaviorNativeRuntimeMeasurementV2
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.validation.ProcessInput
import decompengine.web.UploadServer
import decompengine.web.WebUiMode
import java.io.PrintStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.Locale

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "doctor" -> runDoctor(args.drop(1))
        "patch" -> runPatch(args.drop(1))
        "runner" -> runRunner(args.drop(1))
        "repair" -> runRepair(args.drop(1))
        "repair-history" -> runRecordedRepairHistory(args.drop(1))
        "explore" -> runExplore(args.drop(1))
        "reconstruct" -> runReconstruct(args.drop(1))
        "gcc-engine-plan" -> runGccEnginePlan(args.drop(1))
        "gcc-engine-full-export" -> runGccEngineFullExport(args.drop(1))
        "gcc-engine-runtime-diagnostic" -> runGccEngineCommand(args.drop(1), fullRecoveryExport = true, runtimeDiagnostics = true)
        "gcc-engine-native-calls" -> runGccEngineCommand(args.drop(1), fullRecoveryExport = false, nativeCallObservations = true)
        "llvm-native-runtime-measurement" -> runLlvmNativeRuntimeMeasurement(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            val exitCode = renderUnknownCommand(args.first(), System.getenv().values)
            printHelp()
            kotlin.system.exitProcess(exitCode)
        }
    }
}

/** Reject an unknown selector without exposing its raw argument before workflow dispatch. */
internal fun renderUnknownCommand(
    command: String,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
): Int {
    val redactor = cliDiagnosticRedactor(sensitiveValues) ?: return 2
    printWorkflowCliLine("unknown command", command, redactor, output)
    return 2
}

private fun runRecordedRepairHistory(args: List<String>) {
    val options = runCatching { parseRecordedRepairHistoryArguments(args) }.getOrNull()
    if (options == null) {
        System.err.println("usage: llm_bin_patch repair-history <project-dir> [--page N] [--case-page N] [--graph SHA256]")
        kotlin.system.exitProcess(2)
    }
    val presentation = presentRecordedRepairHistory(
        decompengine.repair.readProjectRecordedRepairHistory(options.project), options.selection)
    presentation.lines.forEach(::println)
    if (presentation.exitCode != 0) kotlin.system.exitProcess(presentation.exitCode)
}

private fun runLlvmNativeRuntimeMeasurement(args: List<String>) {
    val listenerContinuity = args.firstOrNull() == "--listener-continuity"
    val paths = try {
        val positional = if (listenerContinuity) args.drop(1) else args
        require(positional.size == 5) { "native runtime measurement requires exactly five paths" }
        require(positional.all { it.isNotEmpty() && !it.startsWith("-") }) {
            "native runtime measurement accepts only one optional leading --listener-continuity flag and five paths"
        }
        positional.map { Path.of(it) }
    } catch (failure: IllegalArgumentException) {
        System.err.println(failure.message)
        System.err.println("usage: llm_bin_patch llvm-native-runtime-measurement [--listener-continuity] " +
            "<oci-layout> <fixed-client> <empty-config> <private-socket> <fresh-output>")
        kotlin.system.exitProcess(2)
    }
    val (canonical, sha256) = if (listenerContinuity) {
        val candidate = LlvmBehaviorNativeRuntimeMeasurementV2.measureWithListenerContinuity(
            paths[0], paths[1], paths[2], paths[3],
        )
        candidate.canonicalBytes() to candidate.sha256
    } else {
        val candidate = LlvmBehaviorNativeRuntimeMeasurementV2.measure(paths[0], paths[1], paths[2], paths[3])
        candidate.canonicalBytes() to candidate.sha256
    }
    Files.newOutputStream(paths[4], StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS).use { output -> output.write(canonical) }
    println("candidate sha256: $sha256")
    println("oracleAuthority=false runtimeProfileApproved=false startAuthorized=false containmentProved=false " +
        "scoringAuthority=false releaseEligible=false")
    println("Daemon executable approval and HTTP responder identity proof remain unavailable.")
}

private fun runGccEnginePlan(args: List<String>) {
    runGccEngineCommand(args, fullRecoveryExport = false)
}

private fun runGccEngineFullExport(args: List<String>) {
    runGccEngineCommand(args, fullRecoveryExport = true)
}

private fun runGccEngineCommand(args: List<String>, fullRecoveryExport: Boolean,
    runtimeDiagnostics: Boolean = false, nativeCallObservations: Boolean = false) {
    val options = try {
        decompengine.oracle.gcc.GccBundledCliOptions.parse(args, fullRecoveryExport = fullRecoveryExport,
            runtimeDiagnostics = runtimeDiagnostics, nativeCallObservations = nativeCallObservations)
    } catch (failure: IllegalArgumentException) {
        System.err.println(failure.message)
        val command = when {
            nativeCallObservations -> "gcc-engine-native-calls"
            runtimeDiagnostics -> "gcc-engine-runtime-diagnostic"
            fullRecoveryExport -> "gcc-engine-full-export"
            else -> "gcc-engine-plan"
        }
        val resumeOption = if (fullRecoveryExport || nativeCallObservations) "" else " [--resume-after-checkpoint <multiple-of-512>]"
        val engines = decompengine.oracle.gcc.GccBundledCliOptions.engineUsage(fullRecoveryExport = fullRecoveryExport,
            runtimeDiagnostics = runtimeDiagnostics, nativeCallObservations = nativeCallObservations)
        System.err.println("usage: llm_bin_patch $command $engines <stripped-binary> " +
            "--profile <file> --ghidra-archive <file> --output <empty-private-directory> --scratch <provisioned-mount>$resumeOption")
        kotlin.system.exitProcess(2)
    }
    val result = decompengine.oracle.gcc.GccBundledCliCommand.run(options, args)
    println("engine: ${options.engineId}")
    println("operation result: $result")
    if (runtimeDiagnostics) {
        println("Diagnostic execution journal retained; no qualification, scoring, or release authority is emitted.")
    } else if (nativeCallObservations) {
        println("Native call observations and model provenance are retained in the result; structural scoring remains unavailable.")
    } else if (fullRecoveryExport) {
        println("Full model provenance is recorded in the result; structural scoring remains unavailable and scratch is retained.")
    } else {
        println("Model and plan paths and their digests are recorded in the result; scratch is retained.")
    }
}

private fun runReconstruct(args: List<String>) {
    var profile = GeneratedCMakeReconstructionProfile.descriptor
    var binary: Path? = null
    var output: Path? = null
    var evidenceOnly = false
    var maximumContext = 120_000
    var harnessOverride: String? = null
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--output" -> {
                if (index + 1 >= args.size) reconstructUsageError("--output requires a directory")
                output = Path.of(args[index + 1]); index += 2
            }
            "--profile" -> {
                if (index + 1 >= args.size) reconstructUsageError("--profile requires a registered profile ID")
                profile = try {
                    ReconstructionProfiles.named(args[index + 1])
                } catch (failure: IllegalArgumentException) {
                    reconstructUsageError(failure.message ?: "unsupported reconstruction profile")
                }
                index += 2
            }
            "--evidence-only" -> { evidenceOnly = true; index++ }
            "--max-context-chars" -> {
                if (index + 1 >= args.size) reconstructUsageError("--max-context-chars requires a number")
                maximumContext = args[index + 1].toIntOrNull()
                    ?: reconstructUsageError("--max-context-chars must be a number")
                index += 2
            }
            "--harness" -> {
                if (index + 1 >= args.size) reconstructUsageError("--harness requires acp or legacy-openai")
                harnessOverride = args[index + 1]; index += 2
            }
            else -> {
                if (args[index].startsWith("-") || binary != null) reconstructUsageError("unexpected argument: ${args[index]}")
                binary = Path.of(args[index]); index++
            }
        }
    }
    if (binary == null || output == null) reconstructUsageError("reconstruct requires an input binary and output directory")
    val environment = System.getenv()
    val exitCode = runReconstructionCliAction(environment.values) { redactor ->
        withReconstructionCliProgress(output, environment.values) { progress ->
            val strategy = try {
                selectReconstructionStrategy(evidenceOnly, maximumContext, harnessOverride, environment, progress, profile)
            } catch (e: IllegalArgumentException) {
                progress.phase(AgentWorkflowPhase.FAILED)
                progress.close()
                reconstructUsageError(e.message ?: "invalid harness configuration")
            }
            renderWorkflowProvenance(WorkflowCliCommand.RECONSTRUCT, strategy.harnessProvenance, redactor)
            val result = try {
                ArchivalReconstructionService(
                    GhidraHeadlessProgramModelAnalyzer.bundled(), strategy.reconstructor,
                    profile = strategy.profile, progress = progress,
                ).reconstruct(binary, output)
            } catch (failure: Exception) {
                progress.phase(AgentWorkflowPhase.FAILED)
                throw failure
            }
            renderReconstructionSuccess(result.projectDir.toString(), result.bundle.archivePath.toString(),
                result.bundle.archiveSha256, environment.values)
        }
    }
    if (exitCode != 0) kotlin.system.exitProcess(exitCode)
}

/** Only the archive producer's computed SHA is public; every other field receives full projection. */
internal fun renderReconstructionSuccess(
    projectDirectory: String,
    archivePath: String,
    archiveSha256: String,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.out,
) {
    val text = MvpArtifactRedactor(sensitiveValues, 16_384L).projectTerminated {
        append("source tree: ").append(projectDirectory).append("\n")
        append("archive: ").append(archivePath).append("\n")
        append("archive sha256: ").appendSha256(archiveSha256).append("\n")
        append("recovery accuracy: unassessed; see the source tree's confidence and unresolved reports\n")
    }
    if (!admitCliEncoding(text, output)) throw MvpPatchException("reconstruction display encoding is not admitted")
    output.print(text)
}

/** Catch ordinary failures after owned progress closes; raw exception chains stay off stderr. */
internal fun runReconstructionCliAction(
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
    action: (ProgressRedactor) -> Unit,
): Int {
    val redactor = cliDiagnosticRedactor(sensitiveValues) ?: return 1
    return try {
        action(redactor)
        0
    } catch (failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        renderWorkflowFailure(WorkflowCliCommand.RECONSTRUCT, failure.message ?: failure.javaClass.simpleName, redactor, output)
        1
    }
}

/** An unadmitted secret inventory cannot safely select diagnostic or replacement text. */
private fun cliDiagnosticRedactor(sensitiveValues: Collection<String>): ProgressRedactor? = try {
    ProgressRedactor(sensitiveValues)
} catch (failure: Exception) {
    if (failure is InterruptedException) Thread.currentThread().interrupt()
    null
}

internal data class ReconstructionStrategy(
    val reconstructor: ModuleReconstructor,
    val harnessProvenance: String?,
    val profile: ReconstructionProfile,
)

internal fun selectReconstructionStrategy(
    evidenceOnly: Boolean,
    maximumContext: Int,
    harnessOverride: String?,
    environment: Map<String, String>,
    progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
    profile: ReconstructionProfile = ReconstructionProfiles.default,
): ReconstructionStrategy {
    require(!evidenceOnly || harnessOverride == null) {
        "--harness cannot be used with --evidence-only"
    }
    if (evidenceOnly) {
        val selectedProfile = ReconstructionAdapters.resolve(profile).evidenceOnlyProfile(profile)
        return ReconstructionStrategy(ReconstructionAdapters.resolve(selectedProfile).evidenceOnlyReconstructor(selectedProfile),
            null, selectedProfile)
    }

    val effectiveEnvironment = withHarnessOverride(environment, harnessOverride)
    val selection = AcpHarnessFactory.fromEnvironment(effectiveEnvironment)
    return ReconstructionStrategy(
        BoundedLlmModuleReconstructor(
            selection.createHarness(),
            maximumContext,
            selection.provenance.stableDescriptor,
            progress = progress,
        ),
        selection.provenance.stableDescriptor,
        profile,
    )
}

private fun reconstructUsageError(message: String): Nothing {
    renderWorkflowUsageError(WorkflowCliCommand.RECONSTRUCT, message, System.getenv().values)
    kotlin.system.exitProcess(2)
}

private fun runExplore(args: List<String>) {
    var binary: Path? = null
    var reports: Path? = null
    val seedArgs = mutableListOf<String>()
    val seedStdin = mutableListOf<String>()
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--reports" -> {
                if (index + 1 >= args.size) exploreUsageError("--reports requires a directory")
                reports = Path.of(args[index + 1]); index += 2
            }
            "--arg" -> {
                if (index + 1 >= args.size) exploreUsageError("--arg requires a value")
                seedArgs += args[index + 1]; index += 2
            }
            "--stdin" -> {
                if (index + 1 >= args.size) exploreUsageError("--stdin requires a value")
                seedStdin += args[index + 1]; index += 2
            }
            else -> {
                if (args[index].startsWith("-") || binary != null) exploreUsageError("unexpected argument: ${args[index]}")
                binary = Path.of(args[index]); index++
            }
        }
    }
    if (binary == null || reports == null) exploreUsageError("explore requires a binary and reports directory")
    val seeds = buildList {
        add(CandidateInput("seed_default", CandidateSource.SEED))
        seedArgs.forEachIndexed { seedIndex, value ->
            add(CandidateInput("seed_arg_$seedIndex", CandidateSource.SEED, args = listOf(value)))
        }
        seedStdin.forEachIndexed { seedIndex, value ->
            add(CandidateInput("seed_stdin_$seedIndex", CandidateSource.SEED, stdin = value.toByteArray()))
        }
    }
    val report = AutomaticExplorer().explore(binary, seeds, reports)
    println(
        "exploration generated ${report.candidates.size} input(s), discovered " +
            "${report.coverage.newSignatures.size} new output signature(s), uncalibrated exploration heuristic=${"%.4f".format(Locale.ROOT, report.confidence.score)}",
    )
    println("report: ${report.reportPath}")
}

private fun exploreUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch explore <binary> --reports <directory> [--arg <value>] [--stdin <value>]")
    kotlin.system.exitProcess(2)
}

private fun runRepair(args: List<String>) {
    var original: Path? = null
    var project: Path? = null
    var reports: Path? = null
    var maxIterations = 5
    var exploreInputs = false
    var harnessOverride: String? = null
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--reports" -> {
                if (index + 1 >= args.size) repairUsageError("--reports requires a directory")
                reports = Path.of(args[index + 1]); index += 2
            }
            "--max-iterations" -> {
                if (index + 1 >= args.size) repairUsageError("--max-iterations requires a number")
                maxIterations = args[index + 1].toIntOrNull()
                    ?: repairUsageError("--max-iterations must be a number")
                index += 2
            }
            "--explore" -> { exploreInputs = true; index++ }
            "--harness" -> {
                if (index + 1 >= args.size) repairUsageError("--harness requires acp or legacy-openai")
                harnessOverride = args[index + 1]; index += 2
            }
            else -> {
                if (args[index].startsWith("-")) repairUsageError("unexpected argument: ${args[index]}")
                if (original == null) original = Path.of(args[index])
                else if (project == null) project = Path.of(args[index])
                else repairUsageError("unexpected argument: ${args[index]}")
                index++
            }
        }
    }
    if (original == null || project == null) repairUsageError("repair requires an original binary and project directory")
    val originalBinary: Path = original
    val projectDirectory: Path = project
    val reportsDir = decompengine.repair.repairReportsDirectory(projectDirectory, reports)
    val environment = System.getenv()
    val exitCode = runRepairCliAction(environment.values) { redactor ->
        val regressionInputs = if (exploreInputs) {
            val exploration = AutomaticExplorer().explore(
                originalBinary,
                listOf(CandidateInput("seed_default", CandidateSource.SEED)),
                reportsDir,
            )
            renderRepairExplorationSummary(exploration.candidates.size, exploration.coverage.expandedSignatures.size, redactor)
            exploration.candidates.map(CandidateInput::toProcessInput)
        } else {
            listOf(ProcessInput("default"))
        }
        val configuration = prepareRepairCliConfiguration(reportsDir.resolve("repair_history.json"), harnessOverride)
        val result = SecureRepairRuntime.open(configuration).use { runtime ->
            renderWorkflowProvenance(WorkflowCliCommand.REPAIR, runtime.harnessProvenance, redactor, System.err)
            RepairCliProgress(reportsDir).use {
                runtime.runRepair(projectDirectory, originalBinary, regressionInputs, reportsDir, maxIterations)
            }
        }
        renderRepairPresentation(presentRepairOutcome(result), environment.values)
    }
    if (exitCode != 0) kotlin.system.exitProcess(exitCode)
}

/** Only validation of the CLI's data-only configuration can produce a usage failure. */
internal fun prepareRepairCliConfiguration(historyPath: Path, harnessOverride: String?): RepairRuntimeConfiguration = try {
    RepairRuntimeConfiguration(
        profileId = "generated-c-make-v1",
        historyPath = historyPath,
        harnessOverride = harnessOverride,
    )
} catch (failure: IllegalArgumentException) {
    throw RepairCliConfigurationException(failure)
}

internal class RepairCliConfigurationException(cause: IllegalArgumentException) : RuntimeException(cause.message, cause)

/** Admit diagnostics before preparation, and keep raw exploration/runtime failures off stderr. */
internal fun runRepairCliAction(
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
    action: (ProgressRedactor) -> Int,
): Int {
    val redactor = cliDiagnosticRedactor(sensitiveValues) ?: return 1
    return try {
        action(redactor)
    } catch (failure: RepairCliConfigurationException) {
        renderWorkflowUsageError(WorkflowCliCommand.REPAIR, failure.message ?: "invalid repair configuration", redactor, output)
    } catch (failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        renderWorkflowFailure(WorkflowCliCommand.REPAIR, failure.message ?: failure.javaClass.simpleName, redactor, output)
        1
    }
}

/** A refused display cannot expose a partial result or rewrite the durable typed outcome. */
internal fun renderRepairPresentation(
    presentation: RepairCliPresentation,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.out,
): Int {
    val text = try {
        require(presentation.exitCode in 0..2 && presentation.lines.size <= 32)
        val redactor = MvpArtifactRedactor(sensitiveValues, 16_384L)
        val fragments = redactor.forLogLines()
        var count = 0
        val projected = fragments.project {
            for (line in presentation.lines) {
                require(count++ < 32)
                require('\n' !in line && '\r' !in line)
                append(line).append("\n")
            }
        }
        require(projected.count { it == '\n' } == count) { "complete repair line framing could not be retained" }
        redactor.text(projected).also {
            require(it.count { unit -> unit == '\n' } == count) { "complete repair line framing could not be retained" }
            require(admitCliEncoding(it, output)) { "repair display encoding is not admitted" }
        }
    } catch (failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        return 1
    }
    output.print(text)
    return presentation.exitCode
}

internal fun renderRepairExplorationSummary(
    candidateCount: Int,
    signatureCount: Int,
    redactor: ProgressRedactor,
    output: PrintStream = System.out,
) {
    require(candidateCount >= 0 && signatureCount >= 0)
    printProjectedCliFrame("exploration retained $candidateCount regression input(s) across $signatureCount observed output signature(s)\n",
        16_384, output, redactor::text)
}

private fun repairUsageError(message: String): Nothing {
    renderRepairUsageError(message, System.getenv().values)
    kotlin.system.exitProcess(2)
}

/** Admit the inventory and mask private diagnostics while retaining the compiled command grammar. */
internal fun renderRepairUsageError(
    message: String,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
): Int = renderWorkflowUsageError(WorkflowCliCommand.REPAIR, message, sensitiveValues, output)

internal enum class WorkflowCliCommand(val usage: String, val failurePrefix: String) {
    RECONSTRUCT(
        "usage: llm_bin_patch reconstruct <binary> --output <directory> [--profile generated-c-make-v1|generated-c-ninja-v1] [--evidence-only] [--max-context-chars <count>] [--harness acp|legacy-openai]",
        "reconstruction failed",
    ),
    PATCH(
        "usage: llm_bin_patch patch <input-elf> --output <directory> [--yes] [--profile generated-c-make-v1|generated-c-ninja-v1] [--harness acp|legacy-openai]",
        "patch failed",
    ),
    REPAIR(
        "usage: llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore] [--harness acp|legacy-openai]",
        "repair unavailable or failed",
    ),
}

internal fun renderWorkflowUsageError(
    command: WorkflowCliCommand,
    message: String,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
): Int {
    val redactor = cliDiagnosticRedactor(sensitiveValues) ?: return 2
    return renderWorkflowUsageError(command, message, redactor, output)
}

/** Reuse the admitted immutable inventory after a workflow action, including failure paths. */
private fun renderWorkflowUsageError(
    command: WorkflowCliCommand,
    message: String,
    redactor: ProgressRedactor,
    output: PrintStream,
): Int {
    val usage = command.usage
    if (message.length > 16_384 - usage.length - 2) return 2
    // The enum's compiled help is public syntax. Project the complete frame to conceal
    // private diagnostic text and boundary matches, then restore only that known suffix.
    // Confirm the private prefix is stable after restoration; otherwise withhold it.
    val suffix = "\n$usage\n"
    val projectedSuffix = redactor.text(suffix, 16_384)
    var prefix = message
    repeat(2) {
        if (prefix.length > 16_384 - suffix.length) return@repeat
        val projected = redactor.text(prefix + suffix, 16_384)
        if (projectedSuffix.isEmpty() || !projected.endsWith(projectedSuffix)) return@repeat
        val next = projected.dropLast(projectedSuffix.length)
        if (next == prefix) {
            val display = next + suffix
            if (admitCliEncoding(display, output)) output.print(display)
            else if (admitCliEncoding("$usage\n", output)) output.print("$usage\n")
            return 2
        }
        prefix = next
    }
    if (admitCliEncoding("$usage\n", output)) output.print("$usage\n")
    return 2
}

internal fun renderWorkflowFailure(
    command: WorkflowCliCommand,
    message: String,
    redactor: ProgressRedactor,
    output: PrintStream = System.err,
    configuration: Boolean = false,
) {
    val prefix = if (configuration) "configuration error" else command.failurePrefix
    printWorkflowCliLine(prefix, message, redactor, output)
}

internal fun renderWorkflowProvenance(
    command: WorkflowCliCommand,
    provenance: String?,
    redactor: ProgressRedactor,
    output: PrintStream = System.out,
) {
    if (provenance == null) {
        require(command == WorkflowCliCommand.RECONSTRUCT) { "workflow harness provenance is required" }
        printWorkflowCliLine("harness", "none (evidence-only)", redactor, output)
    } else {
        val prefix = if (command == WorkflowCliCommand.REPAIR) "repair harness" else "harness provenance"
        printWorkflowCliLine(prefix, provenance, redactor, output)
    }
}

private fun printWorkflowCliLine(prefix: String, message: String, redactor: ProgressRedactor, output: PrintStream) {
    // Omit oversized detail before allocating the frame; a truncated raw prefix could expose a secret fragment.
    val detail = if (message.length > 16_384 - prefix.length - 3) redactor.text(message, 0) else message
    printProjectedCliFrame("$prefix: $detail\n", 512, output, redactor::text)
}

/** Every caller supplies a complete frame and an already admitted private projection. */
private fun printProjectedCliFrame(
    frame: String,
    previewCharacters: Int,
    output: PrintStream,
    project: (String, Int) -> String,
) {
    var preview = project(frame, previewCharacters)
    // Truncation or replacement can consume the terminator. Reproject each restored
    // newline, and emit only a complete safe line. Persistent conflicts withhold detail.
    repeat(2) {
        if (preview.endsWith("\n")) {
            if (admitCliEncoding(preview, output)) output.print(preview)
            return
        }
        preview = project("$preview\n", 16_384)
    }
    if (!preview.endsWith("\n")) preview = project("\n", 16_384)
    if (preview.endsWith("\n") && admitCliEncoding(preview, output)) output.print(preview)
}

/** Replacement or a codec alias must not reconstruct private text after projection. */
private fun admitCliEncoding(text: String, output: PrintStream): Boolean {
    if (text.length > 16_384) return false
    if (text.isEmpty()) return true
    return try {
        val charset = output.charset()
        val encoder = charset.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val capacity = minOf(16_384.0, maxOf(1.0,
            kotlin.math.ceil(text.length * encoder.maxBytesPerChar().toDouble()))).toInt()
        val input = CharBuffer.wrap(text)
        val encoded = ByteBuffer.allocate(capacity)
        if (!encoder.encode(input, encoded, true).isUnderflow || input.hasRemaining() ||
            !encoder.flush(encoded).isUnderflow) return false
        encoded.flip()
        val decoder = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val decoded = CharBuffer.allocate(text.length)
        if (!decoder.decode(encoded, decoded, true).isUnderflow || encoded.hasRemaining() ||
            !decoder.flush(decoded).isUnderflow) return false
        decoded.flip()
        decoded.toString() == text
    } catch (failure: Exception) {
        if (failure is InterruptedException) {
            Thread.currentThread().interrupt()
            throw failure
        }
        if (failure is java.util.concurrent.CancellationException) throw failure
        false
    }
}

private fun runPatch(args: List<String>) {
    var input: Path? = null
    var output: Path? = null
    var assumeYes = false
    var harnessOverride: String? = null
    var profile = ReconstructionProfiles.default
    var profileSelected = false
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--output" -> {
                if (index + 1 >= args.size) patchUsageError("--output requires a directory")
                output = Path.of(args[index + 1]); index += 2
            }
            "--yes" -> { assumeYes = true; index++ }
            "--harness" -> {
                if (index + 1 >= args.size) patchUsageError("--harness requires acp or legacy-openai")
                harnessOverride = args[index + 1]; index += 2
            }
            "--profile" -> {
                if (profileSelected || index + 1 >= args.size) patchUsageError("--profile requires one registered profile ID")
                profile = try {
                    ReconstructionProfiles.named(args[index + 1])
                } catch (failure: IllegalArgumentException) {
                    patchUsageError(failure.message ?: "unsupported reconstruction profile")
                }
                profileSelected = true
                index += 2
            }
            else -> {
                if (args[index].startsWith("-") || input != null) patchUsageError("unexpected argument: ${args[index]}")
                input = Path.of(args[index]); index++
            }
        }
    }
    if (input == null || output == null) patchUsageError("patch requires an input ELF and output directory")
    val environment = System.getenv()
    val exitCode = runPatchCliAction(environment.values) { redactor ->
        val strategy = try {
            selectPatchStrategy(harnessOverride, environment)
        } catch (failure: IllegalArgumentException) {
            patchUsageError(failure.message ?: "invalid harness configuration")
        }
        renderWorkflowProvenance(WorkflowCliCommand.PATCH, strategy.harnessProvenance, redactor)
        MvpPatchWorkflow(
            harness = strategy.harness,
            environment = environment,
            harnessProvenance = strategy.harnessProvenance,
        ).run(MvpPatchOptions(input, output, assumeYes), profile)
    }
    if (exitCode != 0) kotlin.system.exitProcess(exitCode)
}

/** Preserve patch usage status while withholding raw ordinary-exception chains at the CLI. */
internal fun runPatchCliAction(
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
    action: (ProgressRedactor) -> Unit,
): Int {
    val redactor = cliDiagnosticRedactor(sensitiveValues) ?: return 2
    return try {
        action(redactor)
        0
    } catch (failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        val configuration = failure is IllegalArgumentException
        renderWorkflowFailure(WorkflowCliCommand.PATCH, failure.message ?: failure.javaClass.simpleName,
            redactor, output, configuration)
        if (configuration) 2 else 1
    }
}

private fun patchUsageError(message: String): Nothing {
    renderWorkflowUsageError(WorkflowCliCommand.PATCH, message, System.getenv().values)
    kotlin.system.exitProcess(2)
}

internal data class PatchStrategy(
    val harness: AgentHarness,
    val harnessProvenance: String,
)

internal fun selectPatchStrategy(
    harnessOverride: String?,
    environment: Map<String, String>,
): PatchStrategy {
    val selection = AcpHarnessFactory.fromEnvironment(withHarnessOverride(environment, harnessOverride))
    return PatchStrategy(selection.createHarness(), selection.provenance.stableDescriptor)
}

private fun withHarnessOverride(
    environment: Map<String, String>,
    harnessOverride: String?,
): Map<String, String> = if (harnessOverride == null) {
    environment
} else {
    object : Map<String, String> by environment {
        override fun containsKey(key: String): Boolean =
            key == "ACP_HARNESS" || environment.containsKey(key)

        override fun get(key: String): String? =
            if (key == "ACP_HARNESS") harnessOverride else environment[key]
    }
}

private fun runRunner(args: List<String>) {
    var control = Path.of("/runner")
    var roots = listOf(Path.of("/input"), Path.of("/output"))
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--control-dir" -> {
                if (index + 1 >= args.size) runnerUsageError("--control-dir requires a directory")
                control = Path.of(args[index + 1]); index += 2
            }
            "--root" -> {
                if (index + 1 >= args.size) runnerUsageError("--root requires a directory")
                roots = roots + Path.of(args[index + 1]); index += 2
            }
            else -> runnerUsageError("unexpected argument: ${args[index]}")
        }
    }
    val isolated = System.getenv("RUNNER_NETWORK_ISOLATED") == "true"
    BinaryRunnerService(control, roots.distinct(), isolated).runForever()
}

private fun runnerUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch runner [--control-dir <directory>] [--root <directory>]...")
    kotlin.system.exitProcess(2)
}

private fun runDoctor(args: List<String>) {
    val environment = System.getenv()
    val invocation = try {
        val defaultOutput = Path.of(environment["OUTPUT_DIR"] ?: if (Files.isDirectory(Path.of("/output"))) "/output" else "output")
        parseDoctorInvocation(args, defaultOutput)
    } catch (failure: IllegalArgumentException) {
        doctorUsageError(failure.message ?: "invalid doctor configuration", "--tools-only" in args)
    }
    val sensitiveValues = if (invocation.options.toolsOnly) emptyList() else environment.values
    val exitCode = runDoctorCliAction(sensitiveValues, toolsOnly = invocation.options.toolsOnly) {
        Doctor(environment = environment, sensitiveValues = sensitiveValues).inspect(invocation.options, invocation.profile)
    }
    if (exitCode != 0) kotlin.system.exitProcess(exitCode)
}

/** Doctor reports and escaping ordinary failures share the admitted terminal redactor. */
internal fun runDoctorCliAction(
    sensitiveValues: Collection<String>,
    output: PrintStream = System.out,
    diagnostic: PrintStream = System.err,
    toolsOnly: Boolean = false,
    action: () -> DoctorReport,
): Int {
    val redactor = try {
        DoctorDiagnostics(if (toolsOnly) emptyList() else sensitiveValues)
    } catch (_: DoctorDiagnosticAdmissionException) {
        return 2
    }
    requireDoctorActive()
    val report = try {
        action()
    } catch (failure: Exception) {
        requireDoctorActive(failure)
        if (failure is DoctorDiagnosticAdmissionException) return 2
        val detail = if (toolsOnly) {
            "Tool checks stopped before completion. Verify the selected profile, tools and output directory."
        } else redactor.text(failure.message ?: failure.javaClass.simpleName, 4096)
        printProjectedCliFrame("doctor failed: $detail\n", 4096, diagnostic, redactor::text)
        return 1
    }
    requireDoctorActive()
    report.checks.forEachIndexed { index, check ->
        requireDoctorActive()
        val stream = if (check.passed) output else diagnostic
        val kind = check.toolsOnlyKind ?: DoctorToolKind.UNKNOWN
        val name = if (toolsOnly) {
            if (kind == DoctorToolKind.UNKNOWN) "${kind.label} ${index + 1}" else kind.label
        } else redactor.text(check.name, 4096)
        val detail = if (toolsOnly) {
            if (check.passed) "Check passed." else kind.remediation
        } else redactor.text(check.detail, 4096)
        printProjectedCliFrame("[${if (check.passed) "ok" else "failed"}] $name: $detail\n", 4096, stream, redactor::text)
        stream.flush()
    }
    if (!report.passed) {
        printProjectedCliFrame("Environment check failed (${report.checks.count { !it.passed }} check(s)); resolve each [failed] item above.\n", 4096, diagnostic, redactor::text)
        return 1
    }
    printProjectedCliFrame("Environment check passed (${report.checks.size} checks)\n", 4096, output, redactor::text)
    output.flush()
    return 0
}

internal fun renderDoctorUsageError(
    message: String,
    toolsOnly: Boolean,
    sensitiveValues: Collection<String>,
    output: PrintStream = System.err,
): Int {
    val redactor = try {
        DoctorDiagnostics(if (toolsOnly) emptyList() else sensitiveValues)
    } catch (_: DoctorDiagnosticAdmissionException) {
        return 2
    }
    val usage = "usage: llm_bin_patch doctor --tools-only [--output <directory>] [--profile <id>]\n" +
        "   or: llm_bin_patch doctor [--output <directory>] [--profile <id>] [--harness acp|legacy-openai] [--workflow all|patch|reconstruct|repair|web] [--auth-methods]\n"
    val detail = when {
        toolsOnly -> "invalid doctor configuration; check the options below"
        message.length > 16_384 - usage.length - 1 -> redactor.text(message, 0)
        else -> message
    }
    printProjectedCliFrame("$detail\n$usage", 16_384, output, redactor::text)
    return 2
}

private fun doctorUsageError(message: String, toolsOnly: Boolean): Nothing {
    renderDoctorUsageError(message, toolsOnly, if (toolsOnly) emptyList() else System.getenv().values)
    kotlin.system.exitProcess(2)
}

private fun runWeb(args: List<String>) {
    var host = "127.0.0.1"
    var port = 8000
    var listenBacklog = 64
    var dataDir = Path.of(".decomp_engine/jobs")
    var uiMode = WebUiMode.LEGACY
    var basePath = "/"
    var devFrontendOrigin: String? = null
    var gitImportRoot: Path? = null
    var index = 0
    while (index < args.size) {
        require(index + 1 < args.size) { "${args[index]} requires a value; see llm_bin_patch --help" }
        when (args[index]) {
            "--host" -> {
                host = args[index + 1]
                index += 2
            }
            "--port" -> {
                port = args[index + 1].toInt()
                index += 2
            }
            "--listen-backlog" -> {
                listenBacklog = args.getOrNull(index + 1)?.toIntOrNull()
                    ?: error("--listen-backlog requires an integer between 1 and 4096")
                index += 2
            }
            "--data-dir" -> {
                dataDir = Path.of(args[index + 1])
                index += 2
            }
            "--ui" -> {
                uiMode = when (args[index + 1]) {
                    "legacy" -> WebUiMode.LEGACY
                    "spa" -> WebUiMode.SPA
                    else -> error("--ui must be legacy or spa")
                }
                index += 2
            }
            "--base-path" -> {
                basePath = args[index + 1]
                index += 2
            }
            "--dev-frontend-origin" -> {
                devFrontendOrigin = args[index + 1]
                index += 2
            }
            "--git-import-root" -> {
                gitImportRoot = Path.of(args.getOrNull(index + 1) ?: error("--git-import-root requires a directory")).toAbsolutePath()
                index += 2
            }
            else -> error("unknown web argument: ${args[index]}")
        }
    }
    require(port in 0..65535) { "--port must be between 0 and 65535 (0 selects an available port)" }
    val server = try {
        decompengine.web.startWebServerWithShutdownHook { cancellation ->
            UploadServer(host, port, dataDir, uiMode = uiMode, basePath = basePath, devFrontendOrigin = devFrontendOrigin,
                listenBacklog = listenBacklog, startupCancellation = cancellation, gitImportRoot = gitImportRoot)
        }
    } catch (_: java.net.BindException) {
        System.err.println("Cannot bind web server to $host:$port. Check --host or choose an unused --port.")
        kotlin.system.exitProcess(2)
    } catch (failure: Exception) {
        // A refused storage migration names its fixed code and whether bytes changed, not a stack trace.
        System.err.println(decompengine.web.webStorageStartupGuidance(failure) ?: throw failure)
        kotlin.system.exitProcess(2)
    }
    val urlHost = if (':' in host && !host.startsWith('[')) "[$host]" else host
    println("Serving decomp_engine ${uiMode.name.lowercase()} UI on http://$urlHost:${server.serverPort}$basePath")
    val bootstrap = server.issueBrowserBootstrap()
    val sessionPath = if (uiMode == WebUiMode.SPA) basePath else "/login"
    // This is an explicit local operator handoff, not a request/access log.
    println("Open local browser session (expires ${bootstrap.expiresAt}): ${server.browserOrigin}$sessionPath#bootstrap=${bootstrap.token}")
}

private fun printHelp() {
    println(
        """
        Usage:
          llm_bin_patch doctor --tools-only [--output <directory>] [--profile <id>] [--auth-methods]
          llm_bin_patch doctor [--output <directory>] [--profile <id>] [--harness acp|legacy-openai] [--workflow all|patch|reconstruct|repair|web] [--auth-methods]
          llm_bin_patch patch <input-elf> --output <directory> [--yes] [--profile generated-c-make-v1|generated-c-ninja-v1] [--harness acp|legacy-openai]
          llm_bin_patch runner [--control-dir <directory>] [--root <directory>]...
          llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore] [--harness acp|legacy-openai]
          llm_bin_patch repair-history <project-dir> [--page N] [--case-page N] [--graph SHA256]
          llm_bin_patch explore <binary> --reports <directory> [--arg <value>] [--stdin <value>]
          llm_bin_patch reconstruct <binary> --output <directory> [--profile generated-c-make-v1|generated-c-ninja-v1] [--evidence-only] [--max-context-chars <count>] [--harness acp|legacy-openai]
          llm_bin_patch gcc-engine-plan <cc1|lto1> <stripped-binary> --profile <file> --ghidra-archive <file> --output <empty-private-directory> --scratch <provisioned-mount>
          llm_bin_patch gcc-engine-runtime-diagnostic cc1 <stripped-binary> --profile <file> --ghidra-archive <file> --output <empty-private-directory> --scratch <provisioned-mount>
          llm_bin_patch gcc-engine-full-export <cc1|driver> <stripped-binary> --profile <file> --ghidra-archive <file> --output <empty-private-directory> --scratch <provisioned-mount>
          llm_bin_patch gcc-engine-native-calls <cc1|driver> <stripped-binary> --profile <file> --ghidra-archive <file> --output <empty-private-directory> --scratch <provisioned-mount>
          llm_bin_patch llvm-native-runtime-measurement [--listener-continuity] <oci-layout> <fixed-client> <empty-config> <private-socket> <fresh-output>
          llm_bin_patch web [--host 127.0.0.1] [--port 8000] [--listen-backlog 64] [--data-dir .decomp_engine/jobs] [--ui legacy|spa] [--base-path /] [--dev-frontend-origin http://127.0.0.1:5173] [--git-import-root <directory>]

        Agent harness selection for doctor, patch, reconstruction, and repair:
          --harness acp            use the ACP agent provisioned by ACP_CONFIG_FILE (default)
          --harness legacy-openai  use the deprecated direct OpenAI-compatible adapter
          Doctor performs an initialize-only ACP v1 preflight for all workflows by default.
          Doctor's --tools-only mode is agent-free and cannot be combined with agent selectors.
          Doctor's --profile selects generated-c-make-v1 (default) or generated-c-ninja-v1.
          Reconstruction's --evidence-only mode is agent-free and cannot be combined with --harness.
          gcc-engine-plan requires contained execution and retains scratch plus linked evidence; results remain incomplete and release-ineligible.
          gcc-engine-runtime-diagnostic retains a diagnostic execution journal without qualification, scoring, or release authority.
          gcc-engine-full-export runs a fresh contained full-recovery export and emits an authenticated structural profile binding; it does not score or certify structural truth.
          gcc-engine-native-calls retains native call observations alongside an unchanged full model; results remain unscored and release-ineligible.
          --resume-after-checkpoint <multiple-of-512> interrupts and resumes within this process; it is not cold recovery.
          Scratch defaults: 8 GiB available / 64 GiB maximum filesystem, 32768 available / 1000000 maximum inodes.
          Override with --scratch-min-bytes, --scratch-max-bytes, --scratch-min-inodes, --scratch-max-inodes.
          llvm-native-runtime-measurement retains raw read-only evidence with all authority flags false.
          --listener-continuity records listener credentials; daemon and HTTP responder identities remain unapproved.
          ACP remains read-only and never receives oracle write, validation, scoring, or certification authority.
        """.trimIndent(),
    )
}

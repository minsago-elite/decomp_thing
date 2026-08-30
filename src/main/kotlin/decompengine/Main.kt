package decompengine

import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.doctor.Doctor
import decompengine.doctor.DoctorOptions
import decompengine.mvp.MvpPatchException
import decompengine.mvp.MvpPatchOptions
import decompengine.mvp.MvpPatchWorkflow
import decompengine.mvp.BinaryRunnerService
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpPreflightWorkflow
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.EvidenceModuleReconstructor
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ModuleReconstructor
import decompengine.agent.AgentHarness
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.validation.ProcessInput
import decompengine.web.UploadServer
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "doctor" -> runDoctor(args.drop(1))
        "patch" -> runPatch(args.drop(1))
        "runner" -> runRunner(args.drop(1))
        "repair" -> runRepair(args.drop(1))
        "explore" -> runExplore(args.drop(1))
        "reconstruct" -> runReconstruct(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            System.err.println("unknown command: ${args.first()}")
            printHelp()
            kotlin.system.exitProcess(2)
        }
    }
}

private fun runReconstruct(args: List<String>) {
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
    val strategy = try {
        selectReconstructionStrategy(evidenceOnly, maximumContext, harnessOverride, System.getenv())
    } catch (e: IllegalArgumentException) {
        reconstructUsageError(e.message ?: "invalid harness configuration")
    }
    println(
        strategy.harnessProvenance?.let { "harness provenance: $it" }
            ?: "harness: none (evidence-only)",
    )
    val result = ArchivalReconstructionService(GhidraHeadlessProgramModelAnalyzer.fromEnvironment(), strategy.reconstructor)
        .reconstruct(binary, output)
    println("source tree: ${result.projectDir}")
    println("archive: ${result.bundle.archivePath}")
    println("archive sha256: ${result.bundle.archiveSha256}")
}

internal data class ReconstructionStrategy(
    val reconstructor: ModuleReconstructor,
    val harnessProvenance: String?,
)

internal fun selectReconstructionStrategy(
    evidenceOnly: Boolean,
    maximumContext: Int,
    harnessOverride: String?,
    environment: Map<String, String>,
): ReconstructionStrategy {
    require(!evidenceOnly || harnessOverride == null) {
        "--harness cannot be used with --evidence-only"
    }
    if (evidenceOnly) {
        return ReconstructionStrategy(EvidenceModuleReconstructor(), null)
    }

    val effectiveEnvironment = withHarnessOverride(environment, harnessOverride)
    val selection = AcpHarnessFactory.fromEnvironment(effectiveEnvironment)
    return ReconstructionStrategy(
        BoundedLlmModuleReconstructor(selection.createHarness(), maximumContext),
        selection.provenance.stableDescriptor,
    )
}

private fun reconstructUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch reconstruct <binary> --output <directory> [--evidence-only] [--max-context-chars <count>] [--harness acp|legacy-openai]")
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
            "${report.coverage.newSignatures.size} new output signature(s), confidence=${"%.4f".format(Locale.ROOT, report.confidence.score)}",
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
    val reportsDir = reports ?: project.resolve("reports")
    val regressionInputs = if (exploreInputs) {
        val exploration = AutomaticExplorer().explore(
            original,
            listOf(CandidateInput("seed_default", CandidateSource.SEED)),
            reportsDir,
        )
        println(
            "exploration retained ${exploration.candidates.size} regression input(s) across " +
                "${exploration.coverage.expandedSignatures.size} observed output signature(s)",
        )
        exploration.candidates.map(CandidateInput::toProcessInput)
    } else {
        listOf(ProcessInput("default"))
    }
    val runtime = try {
        SecureRepairRuntime.open(
            RepairRuntimeConfiguration(
                profileId = "generated-c-make-v1",
                historyPath = reportsDir.resolve("repair_history.json"),
                harnessOverride = harnessOverride,
            ),
        )
    } catch (failure: IllegalArgumentException) {
        repairUsageError(failure.message ?: "invalid harness configuration")
    }
    val result = runtime.use {
        println("harness provenance: ${it.harnessProvenance}")
        it.repairUntilValid(project, original, regressionInputs, reportsDir, maxIterations)
    }
    result.iterations.forEach { iteration ->
        println("repair iteration ${iteration.index}: ${iteration.failureKind} - ${iteration.summary}")
    }
    println("repair passed ${result.validation.cases.size} retained regression case(s); report: ${result.validation.reportPath}")
}

private fun repairUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore] [--harness acp|legacy-openai]")
    kotlin.system.exitProcess(2)
}

private fun runPatch(args: List<String>) {
    var input: Path? = null
    var output: Path? = null
    var assumeYes = false
    var harnessOverride: String? = null
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
            else -> {
                if (args[index].startsWith("-") || input != null) patchUsageError("unexpected argument: ${args[index]}")
                input = Path.of(args[index]); index++
            }
        }
    }
    if (input == null || output == null) patchUsageError("patch requires an input ELF and output directory")
    val strategy = try {
        selectPatchStrategy(harnessOverride, System.getenv())
    } catch (failure: IllegalArgumentException) {
        patchUsageError(failure.message ?: "invalid harness configuration")
    }
    println("harness provenance: ${strategy.harnessProvenance}")
    try {
        MvpPatchWorkflow(
            harness = strategy.harness,
            environment = System.getenv(),
            harnessProvenance = strategy.harnessProvenance,
        ).run(MvpPatchOptions(input, output, assumeYes))
    } catch (failure: IllegalArgumentException) {
        System.err.println("configuration error: ${failure.message}"); kotlin.system.exitProcess(2)
    } catch (failure: MvpPatchException) {
        System.err.println("patch failed: ${failure.message}"); kotlin.system.exitProcess(1)
    }
}

private fun patchUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch patch <input-elf> --output <directory> [--yes] [--harness acp|legacy-openai]")
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
    var toolsOnly = false
    var harnessOverride: String? = null
    var workflowOverride: AcpPreflightWorkflow? = null
    var output = Path.of(System.getenv("OUTPUT_DIR") ?: if (Files.isDirectory(Path.of("/output"))) "/output" else "output")
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--tools-only" -> { toolsOnly = true; index++ }
            "--harness" -> {
                if (index + 1 >= args.size) doctorUsageError("--harness requires acp or legacy-openai")
                harnessOverride = args[index + 1]; index += 2
            }
            "--workflow" -> {
                if (index + 1 >= args.size) {
                    doctorUsageError("--workflow requires all, patch, reconstruct, repair, or web")
                }
                workflowOverride = try {
                    AcpPreflightWorkflow.parse(args[index + 1])
                } catch (failure: IllegalArgumentException) {
                    doctorUsageError(failure.message ?: "invalid doctor workflow")
                }
                index += 2
            }
            "--output" -> {
                if (index + 1 >= args.size) doctorUsageError("--output requires a directory")
                output = Path.of(args[index + 1]); index += 2
            }
            else -> doctorUsageError("unexpected argument: ${args[index]}")
        }
    }
    if (toolsOnly && harnessOverride != null) {
        doctorUsageError("--tools-only cannot be combined with --harness")
    }
    if (toolsOnly && workflowOverride != null) {
        doctorUsageError("--tools-only cannot be combined with --workflow")
    }
    val report = Doctor().inspect(
        DoctorOptions(
            outputDir = output,
            toolsOnly = toolsOnly,
            harnessOverride = harnessOverride,
            workflowOverride = workflowOverride,
        ),
    )
    report.checks.forEach { check ->
        val stream = if (check.passed) System.out else System.err
        stream.println("[${if (check.passed) "ok" else "failed"}] ${check.name}: ${check.detail}")
        stream.flush()
    }
    if (!report.passed) {
        System.err.println("Environment check failed (${report.checks.count { !it.passed }} check(s)); resolve each [failed] item above.")
        kotlin.system.exitProcess(1)
    }
    println("Environment check passed (${report.checks.size} checks)")
    System.out.flush()
}

private fun doctorUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch doctor --tools-only [--output <directory>]")
    System.err.println("   or: llm_bin_patch doctor [--output <directory>] [--harness acp|legacy-openai] [--workflow all|patch|reconstruct|repair|web]")
    kotlin.system.exitProcess(2)
}

private fun runWeb(args: List<String>) {
    var host = "127.0.0.1"
    var port = 8000
    var dataDir = Path.of(".decomp_engine/jobs")
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--host" -> {
                host = args[index + 1]
                index += 2
            }
            "--port" -> {
                port = args[index + 1].toInt()
                index += 2
            }
            "--data-dir" -> {
                dataDir = Path.of(args[index + 1])
                index += 2
            }
            else -> error("unknown web argument: ${args[index]}")
        }
    }
    val server = UploadServer(host, port, dataDir)
    server.start()
    println("Serving decomp_engine upload UI on http://$host:${server.serverPort}")
}

private fun printHelp() {
    println(
        """
        Usage:
          llm_bin_patch doctor --tools-only [--output <directory>]
          llm_bin_patch doctor [--output <directory>] [--harness acp|legacy-openai] [--workflow all|patch|reconstruct|repair|web]
          llm_bin_patch patch <input-elf> --output <directory> [--yes] [--harness acp|legacy-openai]
          llm_bin_patch runner [--control-dir <directory>] [--root <directory>]...
          llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore] [--harness acp|legacy-openai]
          llm_bin_patch explore <binary> --reports <directory> [--arg <value>] [--stdin <value>]
          llm_bin_patch reconstruct <binary> --output <directory> [--evidence-only] [--max-context-chars <count>] [--harness acp|legacy-openai]
          llm_bin_patch web [--host 127.0.0.1] [--port 8000] [--data-dir .decomp_engine/jobs]

        Agent harness selection for doctor, patch, reconstruction, and repair:
          --harness acp            use the ACP agent provisioned by ACP_CONFIG_FILE (default)
          --harness legacy-openai  use the deprecated built-in OpenAI-compatible adapter
          Doctor performs an initialize-only ACP v1 preflight for all workflows by default.
          Doctor's --tools-only mode is agent-free and cannot be combined with agent selectors.
          Reconstruction's --evidence-only mode is agent-free and cannot be combined with --harness.
        """.trimIndent(),
    )
}

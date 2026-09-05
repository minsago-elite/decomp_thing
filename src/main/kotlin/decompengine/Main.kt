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
import decompengine.project.GhidraProgramModelExportLimits
import decompengine.project.GhidraProgramModelRecoveryMode
import decompengine.project.ModuleReconstructor
import decompengine.agent.AgentHarness
import decompengine.oracle.gcc.GccCompilerEnginePlanningService
import decompengine.oracle.gcc.GccCompilerEngineProfiles
import decompengine.oracle.gcc.authenticateGhidraInstallation
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.validation.ProcessInput
import decompengine.web.UploadServer
import decompengine.web.WebUiMode
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
        "gcc-engine-plan" -> runGccEnginePlan(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            System.err.println("unknown command: ${args.first()}")
            printHelp()
            kotlin.system.exitProcess(2)
        }
    }
}

private fun runGccEnginePlan(args: List<String>) {
    var engineId: String? = null
    var binary: Path? = null
    var profilePath: Path? = null
    var ghidraHome: Path? = null
    var ghidraArchive: Path? = null
    var output: Path? = null
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--profile" -> {
                if (index + 1 >= args.size) gccEnginePlanUsageError("--profile requires a file")
                profilePath = Path.of(args[index + 1]); index += 2
            }
            "--ghidra-home" -> {
                if (index + 1 >= args.size) gccEnginePlanUsageError("--ghidra-home requires a directory")
                ghidraHome = Path.of(args[index + 1]); index += 2
            }
            "--ghidra-archive" -> {
                if (index + 1 >= args.size) gccEnginePlanUsageError("--ghidra-archive requires a file")
                ghidraArchive = Path.of(args[index + 1]); index += 2
            }
            "--output" -> {
                if (index + 1 >= args.size) gccEnginePlanUsageError("--output requires a directory")
                output = Path.of(args[index + 1]); index += 2
            }
            else -> {
                if (args[index].startsWith("-")) gccEnginePlanUsageError("unexpected argument: ${args[index]}")
                if (engineId == null) engineId = args[index]
                else if (binary == null) binary = Path.of(args[index])
                else gccEnginePlanUsageError("unexpected argument: ${args[index]}")
                index++
            }
        }
    }
    if (engineId == null || binary == null || profilePath == null || ghidraHome == null ||
        ghidraArchive == null || output == null
    ) {
        gccEnginePlanUsageError("gcc-engine-plan requires an engine, binary, profile, Ghidra archive/home, and output")
    }
    val suite = GccCompilerEngineProfiles.load(profilePath)
    val authenticatedGhidra = suite.analysis.authenticateGhidraInstallation(ghidraArchive, ghidraHome)
    val reconstructionProfile = suite.reconstructionProfile()
    val analyzer = GhidraHeadlessProgramModelAnalyzer(
        authenticatedGhidra.home,
        GhidraProgramModelExportLimits.from(reconstructionProfile),
        authenticatedGhidra.archiveSha256,
        GhidraProgramModelRecoveryMode.fromWireName(suite.analysis.exporterMode),
    )
    val result = GccCompilerEnginePlanningService.diagnostic(analyzer).plan(suite, engineId, binary, output)
    println("engine: ${result.engineId}")
    println("program model: ${result.programModelPath}")
    println("program model sha256: ${result.programModelSha256}")
    println("module plan: ${result.modulePlanPath}")
    println("module plan sha256: ${result.modulePlanSha256}")
    println("non-authoritative assessment: ${result.assessmentPath}")
    println("assessment sha256: ${result.assessmentSha256}")
    println("wall clock milliseconds: ${result.wallClockMillis}")
    println("maximum resident bytes observed: ${result.maximumResidentBytesObserved}")
}

private fun gccEnginePlanUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println(
        "usage: llm_bin_patch gcc-engine-plan <cc1|lto1> <stripped-binary> --profile <file> " +
            "--ghidra-archive <file> --ghidra-home <directory> --output <directory>",
    )
    kotlin.system.exitProcess(2)
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
        BoundedLlmModuleReconstructor(
            selection.createHarness(),
            maximumContext,
            selection.provenance.stableDescriptor,
        ),
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
    var uiMode = WebUiMode.LEGACY
    var basePath = "/"
    var devFrontendOrigin: String? = null
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
            else -> error("unknown web argument: ${args[index]}")
        }
    }
    require(port in 0..65535) { "--port must be between 0 and 65535 (0 selects an available port)" }
    val server = try {
        UploadServer(host, port, dataDir, uiMode = uiMode, basePath = basePath, devFrontendOrigin = devFrontendOrigin)
    } catch (_: java.net.BindException) {
        System.err.println("Cannot bind web server to $host:$port. Check --host or choose an unused --port.")
        kotlin.system.exitProcess(2)
    }
    server.start()
    Runtime.getRuntime().addShutdownHook(Thread { server.stop() })
    val urlHost = if (':' in host && !host.startsWith('[')) "[$host]" else host
    println("Serving decomp_engine ${uiMode.name.lowercase()} UI on http://$urlHost:${server.serverPort}$basePath")
    if (uiMode == WebUiMode.SPA) {
        val bootstrap = server.issueBrowserBootstrap()
        // This is an explicit local operator handoff, not a request/access log.
        println("Open local browser session (expires ${bootstrap.expiresAt}): ${server.browserOrigin}${basePath}#bootstrap=${bootstrap.token}")
    }
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
          llm_bin_patch gcc-engine-plan <cc1|lto1> <stripped-binary> --profile <file> --ghidra-archive <file> --ghidra-home <directory> --output <directory>
          llm_bin_patch web [--host 127.0.0.1] [--port 8000] [--data-dir .decomp_engine/jobs] [--ui legacy|spa] [--base-path /] [--dev-frontend-origin http://127.0.0.1:5173]

        Agent harness selection for doctor, patch, reconstruction, and repair:
          --harness acp            use the ACP agent provisioned by ACP_CONFIG_FILE (default)
          --harness legacy-openai  use the deprecated built-in OpenAI-compatible adapter
          Doctor performs an initialize-only ACP v1 preflight for all workflows by default.
          Doctor's --tools-only mode is agent-free and cannot be combined with agent selectors.
          Reconstruction's --evidence-only mode is agent-free and cannot be combined with --harness.
          gcc-engine-plan emits only a schema-v2 non-authoritative Kotlin/JVM diagnostic; it is not oracle or release evidence.
          ACP remains read-only and never receives oracle write, validation, scoring, or certification authority.
        """.trimIndent(),
    )
}

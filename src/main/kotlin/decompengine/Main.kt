package decompengine

import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.mvp.MvpPatchException
import decompengine.mvp.MvpPatchOptions
import decompengine.mvp.MvpPatchWorkflow
import decompengine.repair.HttpOpenAiCompatibleRepairClient
import decompengine.repair.RepairHistory
import decompengine.repair.TraceGuidedRepairLoop
import decompengine.validation.ProcessInput
import decompengine.web.UploadServer
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "doctor" -> runDoctor(args.drop(1))
        "patch" -> runPatch(args.drop(1))
        "repair" -> runRepair(args.drop(1))
        "explore" -> runExplore(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            System.err.println("unknown command: ${args.first()}")
            printHelp()
            kotlin.system.exitProcess(2)
        }
    }
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
    val history = RepairHistory(reportsDir.resolve("repair_history.json"))
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
    val result = TraceGuidedRepairLoop(HttpOpenAiCompatibleRepairClient.fromEnvironment(), history).repairUntilValid(
        projectDir = project,
        originalBinary = original,
        inputs = regressionInputs,
        reportsDir = reportsDir,
        maxIterations = maxIterations,
    )
    result.iterations.forEach { iteration ->
        println("repair iteration ${iteration.index}: ${iteration.failureKind} - ${iteration.summary}")
    }
    println("repair passed ${result.validation.cases.size} retained regression case(s); report: ${result.validation.reportPath}")
}

private fun repairUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore]")
    kotlin.system.exitProcess(2)
}

private fun runPatch(args: List<String>) {
    var input: Path? = null
    var output: Path? = null
    var assumeYes = false
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--output" -> {
                if (index + 1 >= args.size) patchUsageError("--output requires a directory")
                output = Path.of(args[index + 1]); index += 2
            }
            "--yes" -> { assumeYes = true; index++ }
            else -> {
                if (args[index].startsWith("-") || input != null) patchUsageError("unexpected argument: ${args[index]}")
                input = Path.of(args[index]); index++
            }
        }
    }
    if (input == null || output == null) patchUsageError("patch requires an input ELF and output directory")
    try {
        MvpPatchWorkflow(HttpOpenAiCompatibleRepairClient.fromEnvironment()).run(MvpPatchOptions(input, output, assumeYes))
    } catch (failure: IllegalArgumentException) {
        System.err.println("configuration error: ${failure.message}"); kotlin.system.exitProcess(2)
    } catch (failure: MvpPatchException) {
        System.err.println("patch failed: ${failure.message}"); kotlin.system.exitProcess(1)
    }
}

private fun patchUsageError(message: String): Nothing {
    System.err.println(message)
    System.err.println("usage: llm_bin_patch patch <input-elf> --output <directory> [--yes]")
    kotlin.system.exitProcess(2)
}

private fun runDoctor(args: List<String>) {
    val toolsOnly = args.singleOrNull() == "--tools-only"
    if (args.isNotEmpty() && !toolsOnly) {
        System.err.println("usage: llm_bin_patch doctor [--tools-only]")
        kotlin.system.exitProcess(2)
    }

    val failures = mutableListOf<String>()
    listOf("java", "gcc", "make", "readelf", "strings", "python3").forEach { command ->
        val available = runCatching {
            ProcessBuilder("sh", "-c", "command -v \"${'$'}1\" >/dev/null 2>&1", "sh", command)
                .start()
                .waitFor() == 0
        }.getOrDefault(false)
        reportDoctorCheck(command, available, failures)
    }
    val bwrapInstalled = Files.isExecutable(Path.of("/usr/bin/bwrap"))
    reportDoctorCheck("bwrap executable", bwrapInstalled, failures)
    val angrAvailable = runCatching {
        ProcessBuilder("python3", "-c", "import angr").start().waitFor() == 0
    }.getOrDefault(false)
    reportDoctorCheck("angr", angrAvailable, failures)

    val ghidraHome = System.getenv("GHIDRA_HOME")?.let(Path::of)
    reportDoctorCheck(
        "ghidra",
        ghidraHome != null && Files.isExecutable(ghidraHome.resolve("support/analyzeHeadless")),
        failures,
    )
    val cVulHome = System.getenv("CVUL_HOME")?.let(Path::of) ?: Path.of("benchmarks/fixtures/c-vul")
    reportDoctorCheck(
        "c-vul fixture",
        Files.isRegularFile(cVulHome.resolve("src/01_out_of_bounds_write.c")),
        failures,
    )

    if (!toolsOnly) {
        val baseUrl = System.getenv("BASE_URL").orEmpty()
        val validBaseUrl = runCatching {
            val uri = URI.create(baseUrl)
            uri.scheme in setOf("http", "https") && !uri.host.isNullOrBlank()
        }.getOrDefault(false)
        reportDoctorCheck("BASE_URL", validBaseUrl, failures)
        reportDoctorCheck("API_KEY", !System.getenv("API_KEY").isNullOrBlank(), failures)
        reportDoctorCheck("MODEL", !System.getenv("MODEL").isNullOrBlank(), failures)
        val reasoningEffort = System.getenv("REASONING_EFFORT")?.trim().orEmpty()
        if (reasoningEffort.isNotEmpty()) {
            reportDoctorCheck(
                "REASONING_EFFORT",
                reasoningEffort in setOf("none", "minimal", "low", "medium", "high", "xhigh"),
                failures,
            )
        }
    }

    if (failures.isNotEmpty()) {
        System.err.println("Environment check failed: ${failures.joinToString(", ")}")
        kotlin.system.exitProcess(1)
    }
    println("Environment check passed")
    System.out.flush()
}

private fun reportDoctorCheck(name: String, passed: Boolean, failures: MutableList<String>) {
    if (passed) {
        println("[ok] $name")
        System.out.flush()
    } else {
        System.err.println("[missing] $name")
        System.err.flush()
        failures += name
    }
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
          llm_bin_patch doctor [--tools-only]
          llm_bin_patch patch <input-elf> --output <directory> [--yes]
          llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore]
          llm_bin_patch explore <binary> --reports <directory> [--arg <value>] [--stdin <value>]
          llm_bin_patch web [--host 127.0.0.1] [--port 8000] [--data-dir .decomp_engine/jobs]
        """.trimIndent(),
    )
}

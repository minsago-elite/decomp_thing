package decompengine.project

import decompengine.analysis.GhidraAnalysisException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.isExecutable
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

fun interface ProgramModelAnalyzer {
    fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel
}

data class GhidraProgramModelExportLimits(
    val wallClockTimeout: Duration = Duration.ofMinutes(10),
    val terminationGrace: Duration = Duration.ofSeconds(5),
) {
    init {
        require(!wallClockTimeout.isZero && !wallClockTimeout.isNegative && wallClockTimeout <= Duration.ofMinutes(10)) {
            "Ghidra export timeout must be positive and at most 10 minutes"
        }
        require(!terminationGrace.isNegative && terminationGrace <= Duration.ofSeconds(30)) {
            "Ghidra termination grace must be between zero and 30 seconds"
        }
    }
}

class GhidraHeadlessProgramModelAnalyzer(
    private val ghidraHome: Path,
    private val limits: GhidraProgramModelExportLimits = GhidraProgramModelExportLimits(),
) : ProgramModelAnalyzer {
    override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel {
        val executable = ghidraHome.resolve("support/analyzeHeadless")
        require(executable.isExecutable()) { "GHIDRA_HOME does not contain executable support/analyzeHeadless" }
        val reports = workDir.resolve("reports").createDirectories()
        val scripts = workDir.resolve("scripts").createDirectories()
        val scriptBytes = javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")
            ?.use { it.readBytes() } ?: error("bundled ExportProgramModel.java is missing")
        scripts.resolve("ExportProgramModel.java").writeBytes(scriptBytes)
        val output = reports.resolve("program_model.json")
        val project = workDir.resolve("ghidra_project").createDirectories()
        val command = listOf(
            executable.pathString,
            project.pathString,
            "archival_reconstruction",
            "-import", binaryPath.toAbsolutePath().normalize().pathString,
            "-overwrite",
            "-scriptPath", scripts.pathString,
            "-postScript", "ExportProgramModel.java", output.pathString,
        )
        val process = ProcessBuilder(command)
            .directory(workDir.toFile())
            .start()
        val stdout = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderr = CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        val completed = process.waitFor(limits.wallClockTimeout.toMillis(), TimeUnit.MILLISECONDS)
        if (!completed) {
            process.destroy()
            if (!process.waitFor(limits.terminationGrace.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly().waitFor()
            }
        }
        val exitCode = if (completed) process.exitValue() else -1
        reports.resolve("ghidra_stdout.log").writeText(stdout.join())
        reports.resolve("ghidra_stderr.log").writeText(stderr.join())
        if (!completed) {
            throw GhidraAnalysisException(
                "Ghidra program recovery exceeded ${limits.wallClockTimeout.toSeconds()} seconds; " +
                    "rerun with the same output directory to resume durable function checkpoints",
            )
        }
        require(exitCode == 0 && Files.isRegularFile(output)) {
            "Ghidra program recovery failed with exit code $exitCode; see ${reports.resolve("ghidra_stderr.log")}"
        }
        return ProgramModelJson.read(output.readText())
    }

    companion object {
        fun fromEnvironment(environment: Map<String, String> = System.getenv()): GhidraHeadlessProgramModelAnalyzer {
            val home = environment["GHIDRA_HOME"]?.takeIf(String::isNotBlank)
                ?: error("GHIDRA_HOME is required for source-tree reconstruction")
            return GhidraHeadlessProgramModelAnalyzer(Path.of(home))
        }
    }
}

data class ArchivalReconstructionResult(
    val projectDir: Path,
    val build: BuildReport,
    val bundle: ArchivalBundle,
)

class ArchivalReconstructionService(
    private val analyzer: ProgramModelAnalyzer,
    private val reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
) {
    fun reconstruct(binaryPath: Path, outputDir: Path): ArchivalReconstructionResult {
        outputDir.createDirectories()
        val model = analyzer.analyze(binaryPath, outputDir.resolve("analysis"))
        val project = outputDir.resolve("source-tree")
        val progressPath = outputDir.resolve("reconstruction_progress.json")
        progressPath.writeText("{\"phase\":\"planning\",\"completed\":0,\"total\":0}\n")
        var moduleTotal = 0
        val observedBehavior = outputDir.resolve("exploration.json").takeIf { Files.isRegularFile(it) }?.readText()
        SourceTreeGenerator.generate(model, project, reconstructor = reconstructor, observedBehavior = observedBehavior) { completed, total, module ->
            moduleTotal = total
            progressPath.writeText("{\"phase\":\"modules\",\"completed\":$completed,\"total\":$total,\"module\":\"$module\"}\n")
        }
        val build = MakeProjectBuilder.build(project)
        val bundle = ArchivalPackager.create(project, outputDir.resolve("source-tree.zip"))
        progressPath.writeText("{\"phase\":\"complete\",\"completed\":$moduleTotal,\"total\":$moduleTotal}\n")
        outputDir.resolve("reconstruction.json").writeText(
            """
            {
              "inputSha256": "${model.inputSha256}",
              "project": "source-tree",
              "archive": "source-tree.zip",
              "archiveSha256": "${bundle.archiveSha256}",
              "moduleCount": ${DeterministicModulePlanner().plan(model).modules.size},
              "functionCount": ${model.functions.size},
              "globalCount": ${model.globals.size},
              "typeCount": ${model.types.size},
              "buildExitCode": ${build.returnCode}
            }
            """.trimIndent() + "\n",
        )
        return ArchivalReconstructionResult(project, build, bundle)
    }
}

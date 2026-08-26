package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import kotlin.io.path.createDirectories
import kotlin.io.path.isExecutable
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

fun interface ProgramModelAnalyzer {
    fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel
}

class GhidraHeadlessProgramModelAnalyzer(private val ghidraHome: Path) : ProgramModelAnalyzer {
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
        val process = ProcessBuilder(command).start()
        val stdout = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderr = CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        val exitCode = process.waitFor()
        reports.resolve("ghidra_stdout.log").writeText(stdout.join())
        reports.resolve("ghidra_stderr.log").writeText(stderr.join())
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
        SourceTreeGenerator.generate(model, project, reconstructor = reconstructor)
        val build = MakeProjectBuilder.build(project)
        val bundle = ArchivalPackager.create(project, outputDir.resolve("source-tree.zip"))
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

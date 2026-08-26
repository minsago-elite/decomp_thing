package decompengine.project

import decompengine.analysis.GhidraAnalysis
import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.binary.UnresolvedSymbol
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.writeText

data class BuildReport(
    val projectDir: Path,
    val returnCode: Int,
    val logPath: Path,
)

class BuildException(message: String) : RuntimeException(message)

private fun renderUnresolvedReport(analysis: GhidraAnalysis): String {
    val inventory = analysis.symbolInventory
    fun list(symbols: List<UnresolvedSymbol>) = symbols.joinToString(",\n") { it.toJson().prependIndent("      ") }
    return """
    {
      "binary": "${analysis.binaryPath.pathString.escapeJson()}",
      "machine": "${analysis.metadata.machine}",
      "unresolvedFunctionCount": ${inventory.functions.size},
      "unresolvedObjectCount": ${inventory.objects.size},
      "unresolvedOtherCount": ${inventory.other.size},
      "functions": [
        ${list(inventory.functions)}
      ],
      "objects": [
        ${list(inventory.objects)}
      ],
      "other": [
        ${list(inventory.other)}
      ],
      "note": "Unresolved symbols are external imports (libc/runtime) that the reconstructed project depends on but does not define. Their presence does not imply behavioral equivalence."
    }
    """.trimIndent() + "\n"
}

private fun UnresolvedSymbol.toJson(): String = """
{
  "name": "${name.escapeJson()}",
  "kind": "$kind",
  "binding": "$binding",
  "size": $size
}
""".trimIndent()

private fun String.escapeJson(): String =
    buildString {
        for (char in this@escapeJson) {
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(char)
            }
        }
    }

object RecompilableProjectGenerator {
    fun generate(
        analysis: GhidraAnalysis,
        projectDir: Path,
        reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
    ): Path {
        val reportsDir = projectDir.resolve("reports").createDirectories()
        val manifest = SourceTreeGenerator.generate(analysis.programModel, projectDir, reconstructor = reconstructor)
        reportsDir.resolve("analysis.json").writeText(
            """
            {
              "sourceAnalysis": "${analysis.reportPath.pathString}",
              "metadata": {
                "format": "${analysis.metadata.format}",
                "machine": "${analysis.metadata.machine}",
                "entryPoint": ${analysis.metadata.entryPoint}
              },
              "generatedFiles": [
                ${manifest.files.map { it.path }.plus("reports/analysis.json").plus("reports/unresolved.json")
                    .distinct().sorted().joinToString(",\n                ") { "\"$it\"" }}
              ]
            }
            """.trimIndent() + "\n",
        )
        reportsDir.resolve("unresolved.json").writeText(renderUnresolvedReport(analysis))
        return projectDir
    }
}

object MakeProjectBuilder {
    fun build(projectDir: Path): BuildReport {
        if (!projectDir.resolve("Makefile").exists()) {
            throw BuildException("generated project is missing Makefile")
        }
        val reportsDir = projectDir.resolve("reports").createDirectories()
        val process = ProcessBuilder("make")
            .directory(projectDir.toFile())
            .redirectErrorStream(false)
            .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val returnCode = process.waitFor()
        val logPath = reportsDir.resolve("build.log")
        logPath.writeText(
            """
            ${'$'} make
            exit_code=$returnCode

            [stdout]
            $stdout
            [stderr]
            $stderr
            """.trimIndent() + "\n",
        )
        if (returnCode != 0) {
            throw BuildException("generated project failed to build; see ${logPath.pathString}")
        }
        return BuildReport(projectDir = projectDir, returnCode = returnCode, logPath = logPath)
    }
}

class ReconstructionPipeline(private val analyzer: GhidraJvmAnalyzer) {
    fun generate(binaryPath: Path, workDir: Path): BuildReport {
        val analysis = analyzer.analyze(binaryPath, workDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, workDir.resolve("project"))
        return MakeProjectBuilder.build(projectDir)
    }
}

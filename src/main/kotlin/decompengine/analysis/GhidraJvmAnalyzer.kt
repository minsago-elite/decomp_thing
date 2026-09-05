package decompengine.analysis

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.ElfSymbolInventoryReader
import decompengine.binary.SymbolInventory
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.RecoveredProgramModel
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.writeText

data class GhidraAnalysis(
    val binaryPath: Path,
    val reportsDir: Path,
    val metadata: ElfMetadata,
    val symbolInventory: SymbolInventory,
    val programModel: RecoveredProgramModel,
    val mainClass: String,
    val args: List<String>,
    val returnCode: Int,
) {
    val reportPath: Path = reportsDir.resolve("ghidra_analysis.json")
}

class GhidraAnalysisException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

class GhidraJvmAnalyzer(private val analyzer: ProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer()) {
    fun analyze(binaryPath: Path, outputDir: Path): GhidraAnalysis {
        val reportsDir = outputDir.resolve("reports").createDirectories()
        val programModel = analyzer.analyze(binaryPath, outputDir)
        val binaryBytes = binaryPath.readBytes()
        val metadata = ElfMetadataReader.read(binaryBytes)
        val analysis = GhidraAnalysis(
            binaryPath = binaryPath,
            reportsDir = reportsDir,
            metadata = metadata,
            symbolInventory = ElfSymbolInventoryReader.read(binaryBytes, metadata),
            programModel = programModel,
            mainClass = BundledGhidra.WORKER_CLASS,
            args = listOf("analyze", outputDir.resolve("ghidra_project").toAbsolutePath().toString(),
                "archival_reconstruction", binaryPath.toAbsolutePath().toString()),
            returnCode = 0,
        )
        analysis.reportPath.writeText(analysis.toJson())
        return analysis
    }
}

private fun GhidraAnalysis.toJson(): String = """
{
  "tool": "ghidra-jvm",
  "mainClass": "${mainClass.escapeJson()}",
  "returnCode": $returnCode,
  "binary": "${binaryPath.pathString.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "metadata": {
    "format": "${metadata.format}",
    "endianness": "${metadata.endianness}",
    "elfVersion": ${metadata.elfVersion},
    "osAbi": "${metadata.osAbi}",
    "objectType": "${metadata.objectType}",
    "machine": "${metadata.machine}",
    "entryPoint": ${metadata.entryPoint},
    "elfHeaderSize": ${metadata.elfHeaderSize},
    "programHeaderCount": ${metadata.programHeaderCount},
    "sectionHeaderCount": ${metadata.sectionHeaderCount},
    "sectionNameTableIndex": ${metadata.sectionNameTableIndex}
  },
  "stdoutLog": "${reportsDir.resolve("ghidra_stdout.log").pathString.escapeJson()}",
  "stderrLog": "${reportsDir.resolve("ghidra_stderr.log").pathString.escapeJson()}"
  ,"programModel": "${reportsDir.resolve("program_model.json").pathString.escapeJson()}"
}
""".trimIndent() + "\n"

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

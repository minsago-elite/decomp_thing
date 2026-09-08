package decompengine.analysis

import decompengine.binary.BoundedElfMetadataInspection
import decompengine.binary.BoundedElfMetadataLimits
import decompengine.binary.BoundedElfMetadataReader
import decompengine.binary.ElfMetadata
import decompengine.binary.SymbolInventory
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.project.ExportBudgetedProgramModelAnalyzer
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.RecoveredProgramModel
import decompengine.project.ReconstructionBudgets
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
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

class GhidraJvmAnalyzer private constructor(
    private val analyzer: ProgramModelAnalyzer,
    private val metadataLimits: BoundedElfMetadataLimits,
) {
    constructor() : this(GhidraHeadlessProgramModelAnalyzer(), BoundedElfMetadataLimits())

    constructor(analyzer: ProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer()) :
        this(analyzer, BoundedElfMetadataLimits())

    /** Binds worker export limits; callers still admit the requested budgets against host policy. */
    fun withExportBudgets(budgets: ReconstructionBudgets): GhidraJvmAnalyzer {
        val bounded = analyzer as? ExportBudgetedProgramModelAnalyzer
            ?: throw IllegalArgumentException("selected analyzer cannot apply reconstruction export budgets")
        val selectedMetadataLimits = metadataLimits.copy(
            maximumWallClockMillis = minOf(metadataLimits.maximumWallClockMillis, budgets.exportWallClockMillis),
            maximumModeledMetadataBytes = minOf(metadataLimits.maximumModeledMetadataBytes, budgets.exportMaximumResidentBytes),
        )
        return GhidraJvmAnalyzer(bounded.withExportBudgets(budgets), selectedMetadataLimits)
    }

    fun analyze(binaryPath: Path, outputDir: Path): GhidraAnalysis {
        val startedNanos = System.nanoTime()
        fun checkpoint(stage: String) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("analysis cancelled $stage")
            if (System.nanoTime() - startedNanos >= TimeUnit.MILLISECONDS.toNanos(metadataLimits.maximumWallClockMillis)) {
                throw GhidraAnalysisException("analysis and metadata exceeded ${metadataLimits.maximumWallClockMillis} milliseconds $stage")
            }
        }
        checkpoint("before analysis")
        val reportsDir = outputDir.resolve("reports").createDirectories()
        val programModel = analyzer.analyze(binaryPath, outputDir)
        checkpoint("after export")
        val inspection = try {
            BoundedElfMetadataReader.read(binaryPath, metadataLimits, ::checkpoint)
        } catch (failure: FullTreeControlException) {
            // Initial authentication preserves callback failures as causes after releasing its input.
            val cause = failure.cause
            if (cause is GhidraAnalysisException) throw cause
            throw failure
        }
        require(inspection.inputSha256 == programModel.inputSha256) {
            "ELF metadata input identity does not match the exported program model"
        }
        val analysis = GhidraAnalysis(
            binaryPath = binaryPath,
            reportsDir = reportsDir,
            metadata = inspection.metadata,
            symbolInventory = inspection.symbolInventory,
            programModel = programModel,
            mainClass = BundledGhidra.WORKER_CLASS,
            args = listOf("analyze", outputDir.resolve("ghidra_project").toAbsolutePath().toString(),
                "archival_reconstruction", binaryPath.toAbsolutePath().toString()),
            returnCode = 0,
        )
        checkpoint("before analysis report")
        val report = analysis.toJson(inspection, metadataLimits)
        checkpoint("after analysis report rendering")
        analysis.reportPath.writeText(report)
        return analysis
    }
}

private fun GhidraAnalysis.toJson(inspection: BoundedElfMetadataInspection, limits: BoundedElfMetadataLimits): String = """
{
  "tool": "ghidra-jvm",
  "mainClass": "${mainClass.escapeJson()}",
  "returnCode": $returnCode,
  "binary": "${binaryPath.pathString.escapeJson()}",
  "metadataInputSha256": "${inspection.inputSha256}",
  "metadataInputBytes": ${inspection.inputBytes},
  "metadataInspection": {
    "limits": {
      "maximumInputBytes": ${limits.maximumInputBytes},
      "maximumSectionHeaders": ${limits.maximumSectionHeaders},
      "maximumScannedSymbols": ${limits.maximumScannedSymbols},
      "maximumRetainedSymbols": ${limits.maximumRetainedSymbols},
      "maximumNameBytes": ${limits.maximumNameBytes},
      "maximumNameByteVisits": ${limits.maximumNameByteVisits},
      "maximumRetainedNameBytes": ${limits.maximumRetainedNameBytes},
      "maximumModeledMetadataBytes": ${limits.maximumModeledMetadataBytes},
      "maximumMetadataReadBytes": ${limits.maximumMetadataReadBytes},
      "maximumWorkUnits": ${limits.maximumWorkUnits},
      "maximumWallClockMillis": ${limits.maximumWallClockMillis}
    },
    "usage": {
      "sectionHeadersVisited": ${inspection.usage.sectionHeadersVisited},
      "symbolsScanned": ${inspection.usage.symbolsScanned},
      "symbolsRetained": ${inspection.usage.symbolsRetained},
      "nameBytesVisited": ${inspection.usage.nameBytesVisited},
      "retainedNameBytes": ${inspection.usage.retainedNameBytes},
      "modeledMetadataBytes": ${inspection.usage.modeledMetadataBytes},
      "metadataReadBytes": ${inspection.usage.metadataReadBytes},
      "workUnits": ${inspection.usage.workUnits}
    }
  },
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

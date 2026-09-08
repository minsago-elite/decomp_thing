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
import decompengine.reporting.JsonReportLimits
import decompengine.reporting.JsonReportPublisher
import decompengine.reporting.publicationLimitFields
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString

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
        val deadline = AnalysisDeadline.start(
            TimeUnit.MILLISECONDS.toNanos(metadataLimits.maximumWallClockMillis), "analysis and metadata",
        )
        fun checkpoint(stage: String) = deadline.checkpoint(stage)
        checkpoint("before analysis")
        val reportsDir = outputDir.resolve("reports").createDirectories()
        checkpoint("before export")
        val programModel = if (analyzer is GhidraHeadlessProgramModelAnalyzer) {
            analyzer.analyzeWithDeadline(binaryPath, outputDir, deadline)
        } else {
            analyzer.analyze(binaryPath, outputDir)
        }
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
        analysis.writeReport(inspection, metadataLimits, ::checkpoint)
        return analysis
    }
}

private fun GhidraAnalysis.writeReport(
    inspection: BoundedElfMetadataInspection,
    limits: BoundedElfMetadataLimits,
    checkpoint: (String) -> Unit,
) {
    val publication = JsonReportLimits(maximumBytes = 1024 * 1024L)
    JsonReportPublisher.write(reportPath, publication, checkpoint) {
        objectValue {
            field("tool", "ghidra-jvm")
            field("mainClass", mainClass)
            field("returnCode", returnCode.toLong())
            field("binary", binaryPath.pathString)
            field("metadataInputSha256", inspection.inputSha256)
            field("metadataInputBytes", inspection.inputBytes)
            objectField("metadataInspection") {
                objectField("limits") {
                    field("maximumInputBytes", limits.maximumInputBytes)
                    field("maximumSectionHeaders", limits.maximumSectionHeaders.toLong())
                    field("maximumScannedSymbols", limits.maximumScannedSymbols)
                    field("maximumRetainedSymbols", limits.maximumRetainedSymbols.toLong())
                    field("maximumNameBytes", limits.maximumNameBytes.toLong())
                    field("maximumNameByteVisits", limits.maximumNameByteVisits)
                    field("maximumRetainedNameBytes", limits.maximumRetainedNameBytes)
                    field("maximumModeledMetadataBytes", limits.maximumModeledMetadataBytes)
                    field("maximumMetadataReadBytes", limits.maximumMetadataReadBytes)
                    field("maximumWorkUnits", limits.maximumWorkUnits)
                    field("maximumWallClockMillis", limits.maximumWallClockMillis)
                }
                objectField("usage") {
                    field("sectionHeadersVisited", inspection.usage.sectionHeadersVisited)
                    field("symbolsScanned", inspection.usage.symbolsScanned)
                    field("symbolsRetained", inspection.usage.symbolsRetained)
                    field("nameBytesVisited", inspection.usage.nameBytesVisited)
                    field("retainedNameBytes", inspection.usage.retainedNameBytes)
                    field("modeledMetadataBytes", inspection.usage.modeledMetadataBytes)
                    field("metadataReadBytes", inspection.usage.metadataReadBytes)
                    field("workUnits", inspection.usage.workUnits)
                }
            }
            arrayField("args") { for (argument in args) value(argument) }
            objectField("metadata") {
                field("format", metadata.format)
                field("endianness", metadata.endianness)
                field("elfVersion", metadata.elfVersion.toLong())
                field("osAbi", metadata.osAbi)
                field("objectType", metadata.objectType)
                field("machine", metadata.machine)
                field("entryPoint", metadata.entryPoint)
                field("elfHeaderSize", metadata.elfHeaderSize.toLong())
                field("programHeaderCount", metadata.programHeaderCount.toLong())
                field("sectionHeaderCount", metadata.sectionHeaderCount.toLong())
                field("sectionNameTableIndex", metadata.sectionNameTableIndex.toLong())
            }
            field("stdoutLog", reportsDir.resolve("ghidra_stdout.log").pathString)
            field("stderrLog", reportsDir.resolve("ghidra_stderr.log").pathString)
            field("programModel", reportsDir.resolve("program_model.json").pathString)
            objectField("reportPublication") { publicationLimitFields(publication) }
        }
    }
}

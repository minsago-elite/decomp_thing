package decompengine.project

import decompengine.analysis.GhidraAnalysis
import decompengine.binary.SymbolInventory
import decompengine.binary.UnresolvedSymbol
import decompengine.reporting.BoundedJsonReportWriter
import decompengine.reporting.JsonReportBudget
import decompengine.reporting.JsonReportLimitException
import decompengine.reporting.JsonReportLimits
import decompengine.reporting.JsonReportPublisher
import decompengine.reporting.publicationLimitFields
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString

internal data class ReconstructionReportLimits(
    val publication: JsonReportLimits = JsonReportLimits(),
    val maximumSymbols: Int = 100_000,
    val maximumNameCharacters: Int = 16_384,
    val maximumGeneratedFiles: Int = 100_000,
) {
    init {
        require(maximumSymbols in 1..100_000)
        require(maximumNameCharacters in 1..16_384)
        require(maximumGeneratedFiles in 1..100_000)
    }
}

/** Supplemental output has per-file atomic publication, with one shared preparation/render deadline. */
internal object ReconstructionReports {
    private val supplementalPaths = listOf("reports/analysis.json", "reports/unresolved.json")

    fun write(
        analysis: GhidraAnalysis,
        projectDir: Path,
        manifest: SourceTreeManifest,
        profile: ReconstructionProfile,
        limits: ReconstructionReportLimits = ReconstructionReportLimits(),
        checkpoint: (String) -> Unit = {},
    ) {
        val publication = limits.publication.copy(
            maximumBytes = minOf(limits.publication.maximumBytes, profile.budgets.archiveMaximumFileBytes),
        )
        val budget = JsonReportBudget(publication, checkpoint)
        budget.checkpoint("before preparing supplemental reports")
        // Public GhidraAnalysis permits caller-supplied lists. Bound each insertion and snapshot
        // references to immutable records so emitted counts agree with the traversed inventories.
        val inventory = snapshotInventory(analysis.symbolInventory, limits, budget)
        if (manifest.files.size > limits.maximumGeneratedFiles) {
            throw JsonReportLimitException("supplemental report exceeds its generated-file limit")
        }
        budget.checkpoint("before creating supplemental report directory")
        val reports = projectDir.resolve("reports").createDirectories()
        JsonReportPublisher.write(reports.resolve("analysis.json"), publication, budget::checkpoint) {
            objectValue {
                field("sourceAnalysis", analysis.reportPath.pathString)
                objectField("metadata") {
                    field("format", analysis.metadata.format)
                    field("machine", analysis.metadata.machine)
                    field("entryPoint", analysis.metadata.entryPoint)
                }
                arrayField("generatedFiles") { generatedFiles(manifest, limits.maximumGeneratedFiles) }
                objectField("reportPublication") {
                    publicationLimitFields(publication)
                    field("profileArchiveMaximumFileBytes", profile.budgets.archiveMaximumFileBytes)
                    field("maximumGeneratedFiles", limits.maximumGeneratedFiles.toLong())
                }
            }
        }
        JsonReportPublisher.write(reports.resolve("unresolved.json"), publication, budget::checkpoint) {
            objectValue {
                field("binary", analysis.binaryPath.pathString)
                field("machine", analysis.metadata.machine)
                field("unresolvedFunctionCount", inventory.functions.size.toLong())
                field("unresolvedObjectCount", inventory.objects.size.toLong())
                field("unresolvedOtherCount", inventory.other.size.toLong())
                arrayField("functions") { for (symbol in inventory.functions) symbol(symbol) }
                arrayField("objects") { for (symbol in inventory.objects) symbol(symbol) }
                arrayField("other") { for (symbol in inventory.other) symbol(symbol) }
                field("note", "Unresolved symbols are external imports (libc/runtime) that the reconstructed project depends on but does not define. Their presence does not imply behavioral equivalence.")
                objectField("reportPublication") {
                    publicationLimitFields(publication)
                    field("profileArchiveMaximumFileBytes", profile.budgets.archiveMaximumFileBytes)
                    field("maximumSymbols", limits.maximumSymbols.toLong())
                    field("maximumNameCharacters", limits.maximumNameCharacters.toLong())
                }
            }
        }
    }

    private fun snapshotInventory(
        inventory: SymbolInventory,
        limits: ReconstructionReportLimits,
        budget: JsonReportBudget,
    ): SymbolInventory {
        val declaredCount = inventory.functions.size.toLong() + inventory.objects.size.toLong() + inventory.other.size.toLong()
        if (declaredCount > limits.maximumSymbols) {
            throw JsonReportLimitException("supplemental report exceeds its symbol-record limit")
        }
        var count = 0
        fun copy(records: List<UnresolvedSymbol>): List<UnresolvedSymbol> {
            val result = ArrayList<UnresolvedSymbol>()
            for (symbol in records) {
                budget.step()
                if (count >= limits.maximumSymbols) {
                    throw JsonReportLimitException("supplemental report exceeds its symbol-record limit")
                }
                if (symbol.name.length > limits.maximumNameCharacters) {
                    throw JsonReportLimitException("supplemental report symbol name exceeds its character limit")
                }
                count++
                result.add(symbol)
            }
            return result
        }
        return SymbolInventory(copy(inventory.functions), copy(inventory.objects), copy(inventory.other))
    }

    private fun BoundedJsonReportWriter.symbol(symbol: UnresolvedSymbol) = objectValue {
        field("name", symbol.name)
        field("kind", symbol.kind.name)
        field("binding", symbol.binding.name)
        field("size", symbol.size)
    }

    private fun BoundedJsonReportWriter.generatedFiles(manifest: SourceTreeManifest, maximumFiles: Int) {
        // SourceTreeManifest already holds a sorted, unique, immutable list. Merge the two fixed
        // report names without another collection or concatenated JSON string.
        var supplementalIndex = 0
        var count = 0
        fun emit(path: String) {
            if (count >= maximumFiles) throw JsonReportLimitException("supplemental report exceeds its generated-file limit")
            count++
            value(path)
        }
        for (file in manifest.files) {
            while (supplementalIndex < supplementalPaths.size && supplementalPaths[supplementalIndex] < file.path) {
                emit(supplementalPaths[supplementalIndex++])
            }
            if (supplementalIndex < supplementalPaths.size && supplementalPaths[supplementalIndex] == file.path) {
                supplementalIndex++
            }
            emit(file.path)
        }
        while (supplementalIndex < supplementalPaths.size) emit(supplementalPaths[supplementalIndex++])
    }
}

package decompengine.project

import decompengine.analysis.GhidraAnalysis
import decompengine.binary.ElfMetadataReader
import decompengine.binary.SymbolBinding
import decompengine.binary.SymbolInventory
import decompengine.binary.SymbolKind
import decompengine.binary.UnresolvedSymbol
import decompengine.jobs.elfFixture
import decompengine.reporting.JsonReportLimitException
import decompengine.reporting.JsonReportLimits
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class ReconstructionReportsTest {
    @Test
    fun `supplemental schemas preserve ordered records unsigned values and sorted unique files`() = withRoot { root ->
        val name = "external \"café\" \\ λ\n\t😀"
        val first = UnresolvedSymbol(name, SymbolKind.FUNCTION, SymbolBinding.WEAK, ULong.MAX_VALUE)
        val second = UnresolvedSymbol("second", SymbolKind.FUNCTION, SymbolBinding.GLOBAL, 7UL)
        val inventory = SymbolInventory(listOf(first, second, first),
            listOf(UnresolvedSymbol("object", SymbolKind.OBJECT, SymbolBinding.LOCAL, 3UL)),
            listOf(UnresolvedSymbol("other", SymbolKind.OTHER, SymbolBinding.UNKNOWN, 0UL)))
        val analysis = analysis(root, inventory)
        val paths = listOf("zeta.txt", "reports/analysis.json", "alpha \"café\".txt")

        ReconstructionReports.write(analysis, root, manifest(paths), profile)

        val rendered = root.resolve("reports/analysis.json").readText()
        assertTrue(rendered.endsWith("\n"))
        val summary = Json.parseToJsonElement(rendered).jsonObject
        assertEquals(listOf("sourceAnalysis", "metadata", "generatedFiles", "reportPublication"), summary.keys.toList())
        assertEquals(analysis.reportPath.toString(), summary.getValue("sourceAnalysis").jsonPrimitive.content)
        val metadata = summary.getValue("metadata").jsonObject
        assertEquals(listOf("format", "machine", "entryPoint"), metadata.keys.toList())
        assertEquals(analysis.metadata.format, metadata.getValue("format").jsonPrimitive.content)
        assertEquals(analysis.metadata.machine, metadata.getValue("machine").jsonPrimitive.content)
        assertEquals(ULong.MAX_VALUE, metadata.getValue("entryPoint").jsonPrimitive.content.toULong())
        assertFalse(metadata.getValue("entryPoint").jsonPrimitive.isString)
        assertEquals((paths + "reports/unresolved.json").sorted(), summary.getValue("generatedFiles").jsonArray.map {
            it.jsonPrimitive.content
        })
        assertEquals(32L * 1024 * 1024,
            summary.getValue("reportPublication").jsonObject.getValue("maximumBytes").jsonPrimitive.long)

        val unresolvedText = root.resolve("reports/unresolved.json").readText()
        assertTrue(unresolvedText.endsWith("\n"))
        val unresolved = Json.parseToJsonElement(unresolvedText).jsonObject
        assertEquals(listOf("binary", "machine", "unresolvedFunctionCount", "unresolvedObjectCount",
            "unresolvedOtherCount", "functions", "objects", "other", "note", "reportPublication"), unresolved.keys.toList())
        assertEquals(analysis.binaryPath.toString(), unresolved.getValue("binary").jsonPrimitive.content)
        assertEquals(analysis.metadata.machine, unresolved.getValue("machine").jsonPrimitive.content)
        for ((arrayName, countName, expected) in listOf(
            Triple("functions", "unresolvedFunctionCount", inventory.functions),
            Triple("objects", "unresolvedObjectCount", inventory.objects),
            Triple("other", "unresolvedOtherCount", inventory.other),
        )) {
            val records = unresolved.getValue(arrayName).jsonArray
            assertEquals(expected.size.toLong(), unresolved.getValue(countName).jsonPrimitive.long)
            assertEquals(expected.size, records.size)
            for ((record, symbol) in records.zip(expected)) {
                val fields = record.jsonObject
                assertEquals(listOf("name", "kind", "binding", "size"), fields.keys.toList())
                assertEquals(symbol.name, fields.getValue("name").jsonPrimitive.content)
                assertEquals(symbol.kind.name, fields.getValue("kind").jsonPrimitive.content)
                assertEquals(symbol.binding.name, fields.getValue("binding").jsonPrimitive.content)
                assertEquals(symbol.size, fields.getValue("size").jsonPrimitive.content.toULong())
                assertFalse(fields.getValue("size").jsonPrimitive.isString)
            }
        }
        assertEquals("Unresolved symbols are external imports (libc/runtime) that the reconstructed project depends on but does not define. Their presence does not imply behavioral equivalence.",
            unresolved.getValue("note").jsonPrimitive.content)
    }

    @Test
    fun `direct analysis inventories obey independent record and name limits before publication`() = withRoot { root ->
        val symbol = UnresolvedSymbol("four", SymbolKind.FUNCTION, SymbolBinding.GLOBAL, 1UL)
        val reports = root.resolve("reports").createDirectories()
        reports.resolve("analysis.json").writeText("old summary\n")
        reports.resolve("unresolved.json").writeText("old imports\n")
        for ((inventory, limits, message) in listOf(
            Triple(SymbolInventory(listOf(symbol), listOf(symbol), emptyList()),
                ReconstructionReportLimits(maximumSymbols = 1), "symbol-record"),
            Triple(SymbolInventory(listOf(symbol), emptyList(), emptyList()),
                ReconstructionReportLimits(maximumNameCharacters = 3), "symbol name"),
        )) {
            val failure = assertFailsWith<JsonReportLimitException> {
                ReconstructionReports.write(analysis(root, inventory), root, manifest(), profile, limits)
            }
            assertTrue(failure.message.orEmpty().contains(message))
            assertEquals("old summary\n", reports.resolve("analysis.json").readText())
            assertEquals("old imports\n", reports.resolve("unresolved.json").readText())
            assertEquals(2, reports.listDirectoryEntries().size)
        }
    }

    @Test
    fun `generated file limit includes supplemental names and preserves previous report`() = withRoot { root ->
        val reports = root.resolve("reports").createDirectories()
        reports.resolve("analysis.json").writeText("old summary\n")

        val failure = assertFailsWith<JsonReportLimitException> {
            ReconstructionReports.write(analysis(root), root, manifest(listOf("alpha.txt", "zeta.txt")), profile,
                ReconstructionReportLimits(maximumGeneratedFiles = 3))
        }

        assertTrue(failure.message.orEmpty().contains("generated-file"))
        assertEquals("old summary\n", reports.resolve("analysis.json").readText())
        assertEquals(listOf("analysis.json"), reports.listDirectoryEntries().map { it.fileName.toString() })
    }

    @Test
    fun `archive per file budget lowers report bytes and is recorded`() = withRoot { root ->
        val selected = ReconstructionProfile(profile.schemaVersion, profile.id, profile.layout,
            profile.budgets.copy(archiveMaximumFileBytes = 4_096), profile.adapterConfiguration)
        ReconstructionReports.write(analysis(root), root, manifest(), selected)
        for (name in listOf("analysis.json", "unresolved.json")) {
            val text = root.resolve("reports/$name").readText()
            val limits = Json.parseToJsonElement(text).jsonObject.getValue("reportPublication").jsonObject
            assertEquals(4_096L, limits.getValue("maximumBytes").jsonPrimitive.long)
            assertEquals(4_096L, limits.getValue("profileArchiveMaximumFileBytes").jsonPrimitive.long)
            assertTrue(text.toByteArray().size <= 4_096)
        }
        val previous = root.resolve("reports/analysis.json").readText()
        val smaller = ReconstructionProfile(profile.schemaVersion, profile.id, profile.layout,
            profile.budgets.copy(archiveMaximumFileBytes = 128), profile.adapterConfiguration)

        assertFailsWith<JsonReportLimitException> { ReconstructionReports.write(analysis(root), root, manifest(), smaller) }

        assertEquals(previous, root.resolve("reports/analysis.json").readText())
        assertEquals(2, root.resolve("reports").listDirectoryEntries().size)
    }

    @Test
    fun `cancellation preserves the second report without undoing the first publication`() = withRoot { root ->
        val reports = root.resolve("reports").createDirectories()
        reports.resolve("analysis.json").writeText("old summary\n")
        reports.resolve("unresolved.json").writeText("old imports\n")
        val cancelled = InterruptedException("owned report cancellation")
        var publications = 0

        val failure = assertFailsWith<InterruptedException> {
            ReconstructionReports.write(analysis(root), root, manifest(), profile, checkpoint = { stage ->
                if (stage == "before publishing JSON report" && ++publications == 2) throw cancelled
            })
        }

        assertSame(cancelled, failure)
        assertEquals(2, publications)
        Json.parseToJsonElement(reports.resolve("analysis.json").readText()).jsonObject
        assertEquals("old imports\n", reports.resolve("unresolved.json").readText())
        assertEquals(2, reports.listDirectoryEntries().size)
    }

    @Test
    fun `supplemental preparation consumes the shared report deadline before directory creation`() = withRoot { root ->
        val failure = assertFailsWith<JsonReportLimitException> {
            ReconstructionReports.write(analysis(root), root, manifest(), profile,
                ReconstructionReportLimits(publication = JsonReportLimits(maximumWallClockMillis = 100)),
                checkpoint = { stage ->
                    if (stage == "before preparing supplemental reports") Thread.sleep(150)
                })
        }

        assertTrue(failure.message.orEmpty().contains("elapsed-time"))
        assertFalse(root.resolve("reports").exists())
    }

    private val profile = GeneratedCMakeReconstructionProfile.descriptor

    private fun analysis(root: Path, inventory: SymbolInventory = SymbolInventory.EMPTY) = GhidraAnalysis(
        binaryPath = root.resolve("input \"café\""),
        reportsDir = root.resolve("analysis \"café\""),
        metadata = ElfMetadataReader.read(elfFixture()).copy(format = "ELF\"64", machine = "machine \\ λ\t", entryPoint = ULong.MAX_VALUE),
        symbolInventory = inventory,
        programModel = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = emptyList()),
        mainClass = "authored", args = emptyList(), returnCode = 0,
    )

    private fun manifest(paths: List<String> = listOf("authored.txt")) = SourceTreeManifest(
        profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = "a".repeat(64),
        files = paths.map { path -> GeneratedFileEvidence(path, "b".repeat(64), "authored",
            roles = setOf(ProjectFileRole.EVIDENCE), contentKind = ProjectContentKind.UTF8_TEXT) },
        unresolvedEntityIds = emptyList(),
    )

    private fun withRoot(block: (Path) -> Unit) {
        val root = createTempDirectory("supplemental-reports-")
        try { block(root) } finally { root.toFile().deleteRecursively() }
    }
}

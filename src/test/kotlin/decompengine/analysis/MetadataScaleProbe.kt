package decompengine.analysis

import decompengine.binary.BoundedElfMetadataLimits
import decompengine.jobs.elfFixture
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.project.ExportBudgetedProgramModelAnalyzer
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.ReconstructionBudgets
import decompengine.project.ReconstructionHostSafetyLimits
import decompengine.project.ReconstructionProfiles
import decompengine.project.RecoveredProgramModel
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Arrays
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

/**
 * Explicit standalone probe; not discovered as a test. Accepts one of 1MiB, 64MiB, or 1GiB.
 * A separate JVM invocation can measure this fixture's process RSS. The sparse authored input and
 * empty injected model do not qualify real export, metadata/model complexity, or production RSS.
 */
object MetadataScaleProbe {
    private const val BUFFER_BYTES = 64 * 1024
    private const val MAXIMUM_REPORT_BYTES = 1024 * 1024
    private val sizes = mapOf(
        "1MiB" to 1024L * 1024,
        "64MiB" to 64L * 1024 * 1024,
        "1GiB" to 1024L * 1024 * 1024,
    )

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1 && args[0] in sizes) {
            "usage: decompengine.analysis.MetadataScaleProbe <1MiB|64MiB|1GiB>"
        }
        val sizeCase = args[0]
        val inputBytes = sizes.getValue(sizeCase)
        val result = inControlTemporaryDirectory { root -> inspect(root, sizeCase, inputBytes) }
        // Only emit success evidence after the owned temporary directory has been cleaned.
        println(result)
    }

    private fun inspect(root: Path, sizeCase: String, inputBytes: Long): JsonObject {
        val profile = ReconstructionProfiles.default
        ReconstructionHostSafetyLimits.DEFAULT.requireAllows(profile.budgets)
        check(inputBytes <= BoundedElfMetadataLimits().maximumInputBytes)
        val fixtureStarted = System.nanoTime()
        val header = elfFixture()
        check(header.size == 64 && header.sliceArray(40 until 48).all { it == 0.toByte() }) {
            "scale probe requires the existing authored ELF64 header with no section table"
        }
        val input = Files.createFile(root.resolve("authored-padded.elf"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        RandomAccessFile(input.toFile(), "rw").use { file ->
            file.setLength(inputBytes)
            file.seek(0)
            file.write(header)
        }
        val fixturePreparationMillis = elapsedMillis(fixtureStarted)
        val hashStarted = System.nanoTime()
        val expectedSha256 = fixtureSha256(input, inputBytes, header)
        val expectedHashMillis = elapsedMillis(hashStarted)
        var exportInvocations = 0
        var budgetBindings = 0
        val injectedNoOpExporter = object : ExportBudgetedProgramModelAnalyzer {
            override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel =
                error("scale probe requires the explicitly budget-bound no-op exporter")

            override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer {
                check(budgets == profile.budgets)
                budgetBindings++
                return ProgramModelAnalyzer { binaryPath, _ ->
                    check(binaryPath == input)
                    exportInvocations++
                    RecoveredProgramModel(inputSha256 = expectedSha256, functions = emptyList())
                }
            }
        }
        val analyzer = GhidraJvmAnalyzer(injectedNoOpExporter).withExportBudgets(profile.budgets)
        val analysisStarted = System.nanoTime()
        val analysis = analyzer.analyze(input, root.resolve("analysis"))
        val analysisMillis = elapsedMillis(analysisStarted)
        check(budgetBindings == 1 && exportInvocations == 1)
        check(analysis.programModel.inputSha256 == expectedSha256)
        check(analysis.programModel.functions.isEmpty() && analysis.programModel.globals.isEmpty() && analysis.programModel.types.isEmpty())
        check(analysis.symbolInventory.functions.isEmpty() && analysis.symbolInventory.objects.isEmpty() && analysis.symbolInventory.other.isEmpty())
        check(analysis.metadata.format == "ELF64" && analysis.metadata.endianness == "little")
        check(analysis.metadata.sectionHeaderCount.toInt() == 5)
        val reportBytes = Files.newInputStream(analysis.reportPath, LinkOption.NOFOLLOW_LINKS).use {
            it.readNBytes(MAXIMUM_REPORT_BYTES + 1)
        }
        check(reportBytes.size in 1..MAXIMUM_REPORT_BYTES)
        val report = Json.parseToJsonElement(reportBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        check(report.getValue("metadataInputSha256").jsonPrimitive.content == expectedSha256)
        check(report.getValue("metadataInputBytes").jsonPrimitive.long == inputBytes)
        val inspection = report.getValue("metadataInspection").jsonObject
        val limits = inspection.getValue("limits").jsonObject
        val usage = inspection.getValue("usage").jsonObject
        check(limits.getValue("maximumInputBytes").jsonPrimitive.long == BoundedElfMetadataLimits().maximumInputBytes)
        check(limits.getValue("maximumWallClockMillis").jsonPrimitive.long == profile.budgets.exportWallClockMillis)
        check(limits.getValue("maximumModeledMetadataBytes").jsonPrimitive.long == minOf(
            BoundedElfMetadataLimits().maximumModeledMetadataBytes, profile.budgets.exportMaximumResidentBytes,
        ))
        check(report.getValue("reportPublication").jsonObject.getValue("maximumBytes").jsonPrimitive.long == MAXIMUM_REPORT_BYTES.toLong())
        for (field in listOf("sectionHeadersVisited", "symbolsScanned", "symbolsRetained", "nameBytesVisited", "retainedNameBytes")) {
            check(usage.getValue(field).jsonPrimitive.long == 0L) { "unexpected metadata complexity: $field" }
        }
        check(usage.getValue("metadataReadBytes").jsonPrimitive.long in 1L..128L * 1024)
        check(usage.getValue("modeledMetadataBytes").jsonPrimitive.long == BoundedElfMetadataLimits.MINIMUM_MODELED_METADATA_BYTES)
        return buildJsonObject {
            put("schemaVersion", 1)
            put("probe", "authored-padded-elf-metadata")
            put("sizeCase", sizeCase)
            put("fixture", "authored ELF64 header; zero section offset; verified zero padding in a sparse file")
            put("exportMode", "injected-no-op-empty-model")
            put("exportInvocations", exportInvocations)
            put("inputBytes", inputBytes)
            put("inputSha256", expectedSha256)
            put("expectedHashBufferBytes", BUFFER_BYTES)
            put("expectedHashWorkingBufferBytes", 2 * BUFFER_BYTES)
            put("expectedHashBytesRead", inputBytes)
            put("inputCacheState", "fully pre-read by fixed-buffer expected SHA-256 verification")
            put("fixturePreparationMillis", fixturePreparationMillis)
            put("expectedHashElapsedMillis", expectedHashMillis)
            put("elapsedMillis", analysisMillis)
            put("maxHeapBytes", Runtime.getRuntime().maxMemory())
            put("profile", buildJsonObject {
                put("id", profile.id)
                put("sha256", profile.sha256)
                put("requestedExportWallClockMillis", profile.budgets.exportWallClockMillis)
                put("requestedExportMaximumResidentBytes", profile.budgets.exportMaximumResidentBytes)
            })
            put("metadata", report.getValue("metadata"))
            put("metadataInspection", inspection)
            put("reportPublication", report.getValue("reportPublication"))
            put("productionExportExecuted", false)
            put("productionScaleQualified", false)
            put("limitation", "Measures sparse, pre-read padded input handling with an empty injected model; metadata/model complexity, real export and whole-parent production RSS remain unqualified.")
        }
    }

    private fun fixtureSha256(path: Path, expectedBytes: Long, header: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_BYTES)
        val zeroes = ByteArray(BUFFER_BYTES)
        var total = 0L
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { stream ->
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                check(count > 0) { "authored fixture read made no progress" }
                check(total + count <= expectedBytes) { "authored fixture exceeds requested size" }
                val headerCount = minOf(count.toLong(), maxOf(0L, header.size.toLong() - total)).toInt()
                if (headerCount > 0) {
                    check(Arrays.equals(buffer, 0, headerCount, header, total.toInt(), total.toInt() + headerCount))
                }
                check(Arrays.equals(buffer, headerCount, count, zeroes, 0, count - headerCount)) {
                    "authored fixture padding is not zero"
                }
                digest.update(buffer, 0, count)
                total += count
            }
        }
        check(total == expectedBytes) { "authored fixture size does not match requested size" }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun elapsedMillis(startedNanos: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)
}

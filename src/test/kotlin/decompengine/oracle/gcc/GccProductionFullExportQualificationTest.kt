package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.io.TempDir

/** Opt-in evidence capture for a real contained cc1 full export; this does not score the model. */
@Tag("ci-live")
class GccProductionFullExportQualificationTest {
    @Test
    fun `live cc1 full export retains its profile-bound model and receipt evidence`() {
        assumeTrue(
            System.getenv("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT") == "true",
            "real cc1 full-export qualification is opt-in",
        )
        val installation = configured("DECOMP_GCC_CLI_INSTALLATION")
        val profilePath = configured("DECOMP_GCC_CLI_PROFILE")
        val archive = configured("DECOMP_GCC_CLI_ARCHIVE")
        val binary = configured("DECOMP_GCC_CLI_CC1_BINARY")
        val scratch = configured("DECOMP_GCC_CLI_CC1_FRESH_SCRATCH")
        val evidenceRoot = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        assertTrue(Files.isDirectory(scratch, LinkOption.NOFOLLOW_LINKS))
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(evidenceRoot))
        assertTrue(isEmptyDirectory(scratch), "cc1 fresh-export scratch must begin empty")
        assertTrue(isEmptyDirectory(evidenceRoot), "cc1 export evidence root must begin empty")
        for (input in listOf(installation, profilePath, archive, binary, evidenceRoot)) {
            assertFalse(input.startsWith(scratch) || scratch.startsWith(input), "inputs/evidence must be outside scratch")
        }

        val output = privateDirectory(evidenceRoot.resolve("cli-output"))
        val launcherEvidence = privateDirectory(evidenceRoot.resolve("launcher"))
        val arguments = listOf(
            "cc1", binary.toString(),
            "--profile", profilePath.toString(),
            "--ghidra-archive", archive.toString(),
            "--output", output.toString(),
            "--scratch", scratch.toString(),
        )
        assertEquals(
            0,
            invokeInstalledGccCli(
                arguments,
                launcherEvidence,
                timeoutSeconds = 8100,
                installation = installation,
                command = "gcc-engine-full-export",
            ),
            "installed cc1 full-export CLI failed; inspect retained launcher evidence",
        )
        val launcherSummary = verifyInstalledCliEvidence(
            launcherEvidence, arguments, installation, expectedExit = 0, command = "gcc-engine-full-export",
        )

        val resultBytes = readStable(output.resolve("result.json"), MAXIMUM_RESULT_BYTES)
        val result = OracleJson.parseCanonical(resultBytes).jsonObject
        assertEquals(RESULT_KEYS, result.keys)
        assertEquals("gcc-bundled-cli-full-export-result-v2", result.requiredText("provider"))
        assertEquals(2L, result.getValue("schemaVersion").jsonPrimitive.long)
        assertFalse(result.getValue("complete").jsonPrimitive.boolean)
        assertFalse(result.getValue("scored").jsonPrimitive.boolean)
        assertFalse(result.getValue("releaseEligible").jsonPrimitive.boolean)

        val operationId = result.requiredText("operationId")
        assertTrue(operationId.matches(Regex("[a-f0-9]{64}")))
        val journal = Path.of(result.requiredText("journal"))
        assertEquals(output.resolve("journal").toRealPath(), journal.parent.toRealPath())
        assertEquals(".gcc-bundled-operation-$operationId", journal.fileName.toString())
        val intentBytes = readStable(journal.resolve("intent.json"), MAXIMUM_RECEIPT_BYTES)
        assertEquals(OracleArtifacts.sha256(intentBytes), result.requiredText("requestSha256"))
        val executionBytes = readStable(journal.resolve("execution.json"), MAXIMUM_RECEIPT_BYTES)
        assertEquals(OracleArtifacts.sha256(executionBytes), result.requiredText("executionReceiptSha256"))
        val assessmentBytes = readStable(journal.resolve("export-assessment.json"), MAXIMUM_RECEIPT_BYTES)
        assertEquals(OracleArtifacts.sha256(assessmentBytes), result.requiredText("exportAssessmentReceiptSha256"))

        val modelPath = Path.of(result.requiredText("programModel"))
        assertTrue(modelPath.startsWith(scratch) && modelPath.toRealPath() == modelPath)
        val modelBytes = result.getValue("programModelBytes").jsonPrimitive.long
        val modelSha256 = result.requiredText("programModelSha256")
        val functionCount = result.getValue("functionCount").jsonPrimitive.long
        assertTrue(modelBytes > 0L && modelBytes <= MAXIMUM_MODEL_BYTES)
        assertTrue(functionCount > 0L)

        val bindingPath = Path.of(result.requiredText("structuralBinding"))
        val manifestPath = Path.of(result.requiredText("outputTreeManifest"))
        assertEquals(output, bindingPath.parent)
        assertEquals(output, manifestPath.parent)
        assertEquals("structural-full-export-binding.json", bindingPath.fileName.toString())
        assertEquals(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME, manifestPath.fileName.toString())
        val bindingBytes = readStable(bindingPath, MAXIMUM_BINDING_BYTES)
        assertEquals(OracleArtifacts.sha256(bindingBytes), result.requiredText("structuralBindingSha256"))
        val binding = OracleJson.parseCanonical(bindingBytes).jsonObject
        assertEquals("gcc-compiler-engine-structural-full-export-binding-v2", binding.requiredText("provider"))
        assertEquals("cc1", binding.getValue("receiptLineage").jsonObject.requiredText("engineId"))
        assertEquals(operationId, binding.getValue("receiptLineage").jsonObject.requiredText("operationId"))
        assertEquals(result.requiredText("requestSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("intentSha256"))
        assertEquals(result.requiredText("executionReceiptSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("executionReceiptSha256"))
        assertEquals(result.requiredText("exportAssessmentReceiptSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("exportAssessmentReceiptSha256"))
        assertEquals(result.requiredText("outputTreeSha256"), binding.requiredText("outputTreeSha256"))

        val structural = GccDriverStructuralInputsV1.load(profilePath.parent)
        assertEquals(structural.profileId, binding.requiredText("profileId"))
        assertEquals(structural.version, binding.requiredText("profileVersion"))
        assertEquals(structural.sourceRevision, binding.requiredText("sourceRevision"))
        assertEquals(structural.compilerEngineProfileSha256, binding.requiredText("compilerEngineProfileSha256"))
        assertEquals(structural.artifactManifestSha256, binding.requiredText("artifactManifestSha256"))
        val input = binding.getValue("inputBinary").jsonObject
        assertEquals(structural.strippedBinary.sha256, input.requiredText("sha256"))
        assertEquals(structural.strippedBinary.bytes, input.getValue("bytes").jsonPrimitive.long)
        val target = binding.getValue("targetDescriptor").jsonObject
        assertEquals(structural.targetAbi.id, target.requiredText("id"))
        assertEquals(structural.targetAbi.ghidraLanguage, target.requiredText("ghidraLanguage"))
        assertEquals(structural.targetAbi.ghidraCompilerSpec, target.requiredText("ghidraCompilerSpec"))
        assertEquals("0x${structural.imageBase.toString(16)}", target.requiredText("imageBase"))
        assertEquals(structural.inputBinary.executableRangesSha256, target.requiredText("executableRangesSha256"))

        val analysis = GccRetainedCompilerEngineProfile.open(profilePath).use { it.suite.analysis }
        val exporter = binding.getValue("exporter").jsonObject
        assertEquals(analysis.exporterSha256, exporter.requiredText("sha256"))
        assertEquals("full", exporter.requiredText("recoveryMode"))
        val exporterBytes = GccCompilerEngineProfiles::class.java
            .getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")!!.use {
                it.readNBytes(4 * 1024 * 1024 + 1)
            }
        assertTrue(exporterBytes.size <= 4 * 1024 * 1024)
        assertEquals(exporterBytes.size.toLong(), exporter.getValue("bytes").jsonPrimitive.long)
        val archiveBinding = binding.getValue("ghidraArchive").jsonObject
        assertEquals(analysis.ghidraArchive.sha256, archiveBinding.requiredText("sha256"))
        assertEquals(analysis.ghidraArchive.bytes, archiveBinding.getValue("bytes").jsonPrimitive.long)

        val programModel = binding.getValue("programModel").jsonObject
        assertEquals(modelSha256, programModel.requiredText("sha256"))
        assertEquals(modelBytes, programModel.getValue("bytes").jsonPrimitive.long)
        assertEquals(functionCount, programModel.getValue("functionCount").jsonPrimitive.long)
        val manifestBytes = readStable(manifestPath, MAXIMUM_TREE_MANIFEST_BYTES)
        assertEquals(OracleArtifacts.sha256(manifestBytes), result.requiredText("outputTreeManifestSha256"))
        val treeManifest = OracleJson.parseCanonical(manifestBytes, TREE_MANIFEST_LIMITS).jsonObject
        assertEquals(result.requiredText("outputTreeSha256"), treeManifest.requiredText("outputTreeSha256"))

        val captured = privateDirectory(evidenceRoot.resolve("captured"))
        copyStable(modelPath, captured.resolve("program_model.json"), MAXIMUM_MODEL_BYTES, modelBytes, modelSha256)
        captureFailureDiagnostics(modelPath, treeManifest, captured)
        publish(captured.resolve("result.json"), resultBytes)
        publish(captured.resolve("structural-full-export-binding.json"), bindingBytes)
        publish(captured.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME), manifestBytes)
        publish(captured.resolve("intent.json"), intentBytes)
        publish(captured.resolve("execution.json"), executionBytes)
        publish(captured.resolve("export-assessment.json"), assessmentBytes)
        publish(captured.resolve("launcher-summary.json"), OracleJson.canonicalBytes(launcherSummary))
        val summary = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-live-full-export-capture-v1"),
            "engine" to JsonPrimitive("cc1"),
            "operationId" to JsonPrimitive(operationId),
            "requestSha256" to JsonPrimitive(result.requiredText("requestSha256")),
            "programModelSha256" to JsonPrimitive(modelSha256),
            "programModelBytes" to JsonPrimitive(modelBytes),
            "functionCount" to JsonPrimitive(functionCount),
            "outputTreeSha256" to JsonPrimitive(result.requiredText("outputTreeSha256")),
            "complete" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false),
            "benchmarkAccepted" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "limitation" to JsonPrimitive("live contained export only; independent identity replay and production scoring remain open"),
        ))
        publish(evidenceRoot.resolve("qualification.json"), OracleJson.canonicalBytes(summary))
        println("Retained unscored live cc1 full-export evidence at $captured (${modelBytes} model bytes, $functionCount functions)")
    }

    @Test
    fun `failure diagnostics are retained only when the output tree commits their bytes`(@TempDir root: Path) {
        val modelPath = root.resolve("program_model.json")
        val source = privateDirectory(root.resolve("program_model.json.export"))
        val failures = privateDirectory(source.resolve("failures"))
        val id = "fn_000000000081832b"
        val original = "{\"schemaVersion\":1,\"functionId\":\"$id\",\"status\":\"failed\",\"message\":\"decompilation timed out\"}\n".toByteArray()
        Files.write(failures.resolve("$id.json"), original, CREATE_NEW, WRITE)
        val tree = JsonObject(mapOf("tree" to JsonObject(mapOf("sidecars" to JsonObject(mapOf(
            "failures/$id.json" to JsonObject(mapOf(
                "bytes" to JsonPrimitive(original.size),
                "sha256" to JsonPrimitive(OracleArtifacts.sha256(original)),
            )),
        ))))))
        val captured = privateDirectory(root.resolve("captured"))
        assertEquals(1, captureFailureDiagnostics(modelPath, tree, captured))
        assertTrue(Files.readAllBytes(captured.resolve("failure-diagnostics/$id.json")).contentEquals(original))

        Files.write(failures.resolve("$id.json"), "tampered".toByteArray())
        val rejected = privateDirectory(root.resolve("rejected"))
        assertFailsWith<IllegalArgumentException> { captureFailureDiagnostics(modelPath, tree, rejected) }
        assertFalse(Files.exists(rejected.resolve("failure-diagnostics/$id.json")))
    }

    private fun captureFailureDiagnostics(modelPath: Path, treeManifest: JsonObject, captured: Path): Int {
        val sidecars = treeManifest.getValue("tree").jsonObject.getValue("sidecars").jsonObject
        val failures = sidecars.filterKeys { it.startsWith("failures/") }.toSortedMap()
        require(failures.size <= MAXIMUM_FAILURE_DIAGNOSTICS) { "cc1 failure diagnostic count exceeds its capture bound" }
        if (failures.isEmpty()) return 0
        val source = modelPath.resolveSibling(modelPath.fileName.toString() + ".export")
        var totalBytes = 0L
        val verified = ArrayList<Pair<String, ByteArray>>(failures.size)
        for ((name, entry) in failures) {
            val id = name.removePrefix("failures/").removeSuffix(".json")
            require(id.matches(Regex("fn_[0-9a-f]{16}")) && name == "failures/$id.json") {
                "cc1 failure diagnostic path is invalid"
            }
            val commitment = entry.jsonObject
            require(commitment.keys == setOf("bytes", "sha256")) { "cc1 failure commitment is invalid" }
            val expectedBytes = commitment.getValue("bytes").jsonPrimitive.long
            val expectedSha256 = commitment.getValue("sha256").jsonPrimitive.content
            require(expectedBytes in 1..MAXIMUM_FAILURE_DIAGNOSTIC_BYTES.toLong() &&
                expectedSha256.matches(Regex("[0-9a-f]{64}"))
            ) { "cc1 failure diagnostic commitment exceeds its bound" }
            totalBytes += expectedBytes
            require(totalBytes <= MAXIMUM_FAILURE_DIAGNOSTIC_TOTAL_BYTES) {
                "cc1 failure diagnostics exceed their aggregate capture bound"
            }
            val bytes = readStable(source.resolve(name), MAXIMUM_FAILURE_DIAGNOSTIC_BYTES)
            require(bytes.size.toLong() == expectedBytes && OracleArtifacts.sha256(bytes) == expectedSha256) {
                "cc1 failure diagnostic differs from the committed output tree"
            }
            verified += id to bytes
        }
        val destination = privateDirectory(captured.resolve("failure-diagnostics"))
        verified.forEach { (id, bytes) -> publish(destination.resolve("$id.json"), bytes) }
        return failures.size
    }

    private fun configured(name: String): Path {
        val value = System.getenv(name)?.takeIf(String::isNotBlank)
            ?: throw AssertionError("required live cc1 full-export input is missing: $name")
        val path = Path.of(value)
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path) { "$name must be canonical" }
        return path
    }

    private fun readStable(path: Path, maximumBytes: Int): ByteArray =
        StableControlFile.open(path, maximumBytes.toLong(), "cc1 production evidence").use { guard ->
            require(guard.size in 1..maximumBytes.toLong()) { "cc1 production evidence exceeds its bound: $path" }
            guard.readExactly(0L, guard.size.toInt(), "cc1 production evidence").also {
                guard.verifyUnchanged("after cc1 production evidence capture")
            }
        }

    private fun copyStable(source: Path, destination: Path, maximumBytes: Long, expectedBytes: Long, expectedSha256: String) {
        StableControlFile.open(source, maximumBytes, "cc1 production model").use { guard ->
            require(guard.size == expectedBytes && guard.size in 1..maximumBytes) { "captured cc1 model size differs" }
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            FileChannel.open(destination, CREATE_NEW, WRITE).use { output ->
                var offset = 0L
                while (offset < guard.size) {
                    val requested = minOf(buffer.size.toLong(), guard.size - offset).toInt()
                    val count = guard.readAt(offset, buffer, 0, requested)
                    require(count > 0) { "captured cc1 model ended early" }
                    digest.update(buffer, 0, count)
                    val chunk = ByteBuffer.wrap(buffer, 0, count)
                    while (chunk.hasRemaining()) output.write(chunk)
                    offset += count
                }
                guard.verifyUnchanged("after cc1 model evidence copy")
                output.force(true)
            }
            val observedSha256 = digest.digest().joinToString("") { "%02x".format(it) }
            require(observedSha256 == expectedSha256) { "copied cc1 model differs from the authenticated result" }
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--------"))
            FileChannel.open(destination.parent, READ).use { it.force(true) }
        }
    }

    private fun publish(path: Path, bytes: ByteArray) {
        require(bytes.isNotEmpty())
        Files.write(path, bytes, CREATE_NEW, WRITE)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        FileChannel.open(path, READ).use { it.force(true) }
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(
        path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )

    private fun isEmptyDirectory(path: Path): Boolean = Files.newDirectoryStream(path).use { !it.iterator().hasNext() }

    private fun JsonObject.requiredText(name: String): String = getValue(name).jsonPrimitive.content.also {
        require(getValue(name).jsonPrimitive.isString) { "cc1 evidence $name must be text" }
    }

    private companion object {
        const val MAXIMUM_RESULT_BYTES = 256 * 1024
        const val MAXIMUM_RECEIPT_BYTES = 1024 * 1024
        const val MAXIMUM_BINDING_BYTES = 256 * 1024
        const val MAXIMUM_TREE_MANIFEST_BYTES = GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES
        const val MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_FAILURE_DIAGNOSTICS = 1024
        const val MAXIMUM_FAILURE_DIAGNOSTIC_BYTES = 64 * 1024
        const val MAXIMUM_FAILURE_DIAGNOSTIC_TOTAL_BYTES = 8L * 1024 * 1024
        const val COPY_BUFFER_BYTES = 1024 * 1024
        val RESULT_KEYS = setOf(
            "provider", "schemaVersion", "complete", "releaseEligible", "scored", "operationId", "requestSha256",
            "journal", "programModel", "programModelSha256", "programModelBytes", "functionCount", "outputTreeSha256",
            "outputTreeManifest", "outputTreeManifestSha256", "exportAssessmentReceiptSha256", "executionReceiptSha256",
            "structuralBinding", "structuralBindingSha256", "operationWallTime", "scratchDisposition",
        )
        val TREE_MANIFEST_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_TREE_MANIFEST_BYTES,
            maximumCanonicalBytes = MAXIMUM_TREE_MANIFEST_BYTES,
            maximumNodes = 1_000_000,
            maximumStringBytes = 4 * 1024 * 1024,
            maximumTotalStringBytes = 32 * 1024 * 1024,
        )
    }
}

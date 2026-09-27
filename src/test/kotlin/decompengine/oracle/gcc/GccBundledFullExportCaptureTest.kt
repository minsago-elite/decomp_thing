package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GccBundledFullExportCaptureTest {
    @Test
    fun `full export snapshot binds invocation progress model and all descriptor captured sidecars`() = fixture { root, run, reports ->
        val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
        assertEquals(1L, snapshot.functionCount)
        assertEquals(1L, snapshot.recovered)
        assertEquals(0L, snapshot.partial)
        assertEquals(0L, snapshot.failed)
        assertEquals(0L, snapshot.reused)
        assertEquals(inputSha(), snapshot.inputSha256)
        assertEquals(1L, snapshot.inputBytes)
        assertEquals(exporterSha(), snapshot.exporterSha256)
        assertEquals(1L, snapshot.exporterBytes)
        assertEquals(analysisToolSha(), snapshot.analysisToolSha256)
        assertEquals(1L, snapshot.analysisToolBytes)
        assertEquals("x86:LE:64:default", snapshot.language)
        assertEquals("gcc", snapshot.compilerSpec)
        assertEquals(4L, snapshot.outputFileCount)
        assertEquals(snapshot.programModel.size.toLong(), snapshot.programModelBytes)
        assertTrue(snapshot.capturedBytes > snapshot.programModelBytes)
        assertContentEquals(Files.readAllBytes(root.resolve("reports/program_model.json")), snapshot.programModel)
        assertTrue(snapshot.sidecarManifest.decodeToString().contains("functions/fn_0000000000400010.json"))
        assertEquals(
            "gcc-bundled-full-export-output-tree-v2",
            OracleJson.parseCanonical(snapshot.sidecarManifest).jsonObject.getValue("tree").jsonObject
                .getValue("kind").jsonPrimitive.content,
        )
        val retainedManifest = OracleJson.parseCanonical(snapshot.sidecarManifest).jsonObject
        assertEquals(snapshot.outputTreeSha256, retainedManifest.getValue("outputTreeSha256").jsonPrimitive.content)
        assertEquals(
            snapshot.outputTreeSha256,
            OracleArtifacts.sha256(OracleJson.canonicalBytes(retainedManifest.getValue("tree"))),
        )
        val assessment = OracleJson.parseCanonical(snapshot.assessmentBytes).jsonObject
        assertEquals(2, assessment.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(snapshot.inputBytes, assessment.getValue("inputBytes").jsonPrimitive.long)
        assertEquals(snapshot.exporterBytes, assessment.getValue("exporterBytes").jsonPrimitive.long)
        assertEquals(snapshot.analysisToolBytes, assessment.getValue("analysisToolBytes").jsonPrimitive.long)
        assertEquals(snapshot.language, assessment.getValue("language").jsonPrimitive.content)
        assertEquals(snapshot.compilerSpec, assessment.getValue("compilerSpec").jsonPrimitive.content)

        val changed = functionRecord("fn_0000000000400010", "changed")
        Files.writeString(root.resolve("reports/program_model.json.export/functions/fn_0000000000400010.json"), changed)
        assertFails { GccBundledFullExportCapture.capture(run, reports, artifacts()) }
        Files.writeString(root.resolve("reports/program_model.json"), modelText(changed))
        val next = GccBundledFullExportCapture.capture(run, reports, artifacts())
        assertNotEquals(snapshot.outputTreeSha256, next.outputTreeSha256)
    }

    @Test
    fun `full export capture rejects wrong input exporter mode progress and extra checkpoint residue`() {
        for (mutate in listOf<(Path) -> Unit>(
            { path -> writeState(path, recoveryMode = "planning") },
            { path -> writeState(path, inputSha256 = "f".repeat(64)) },
            { path -> writeProgress(path, completed = 0, phase = "decompiling") },
            { path -> Files.writeString(path.resolve("reports/program_model.json.export/planning-batches/stray"), "x") },
        )) fixture { root, run, reports ->
            mutate(root)
            assertFails { GccBundledFullExportCapture.capture(run, reports, artifacts()) }
        }
    }

    @Test
    fun `full export sidecar capture rejects links and unexpected records`() {
        for (mutation in listOf<(Path) -> Unit>(
            { path -> Files.createSymbolicLink(path.resolve("reports/program_model.json.export/functions/linked.json"), path.resolve("outside")) },
            { path -> Files.writeString(path.resolve("reports/program_model.json.export/functions/unexpected.json"), "{}") },
            { path -> Files.writeString(path.resolve("reports/.program_model.json.pending"), "stale") },
            { path -> Files.writeString(path.resolve("reports/.program_model.json.progress.json.pending"), "stale") },
        )) fixture { root, run, reports ->
            Files.writeString(root.resolve("outside"), "{}")
            mutation(root)
            assertFails { GccBundledFullExportCapture.capture(run, reports, artifacts()) }
        }
    }

    @Test
    fun `global and type records retain exporter statuses and unsigned address identities`() {
        for ((id, address) in listOf(
            "global_0000000000000000" to "0x0",
            "global_0000000000400100" to "0x400100",
            "global_ffffffffffffffff" to "0xffffffffffffffff",
        )) fixture { root, run, reports ->
            val global = globalRecord(id, JsonPrimitive(address))
            val type = typeRecord()
            writeNamedRecords(root, id to global, typeId() to type)
            val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
            assertEquals(6L, snapshot.outputFileCount)
            assertTrue(snapshot.sidecarManifest.decodeToString().contains("globals/$id.json"))
            assertTrue(snapshot.sidecarManifest.decodeToString().contains("types/${typeId()}.json"))
            assertContentEquals(Files.readAllBytes(root.resolve("reports/program_model.json")), snapshot.programModel)
        }
    }

    @Test
    fun `matching model bytes cannot authenticate global IDs contradicting their addresses`() {
        val id = "global_0000000000400100"
        for (address in listOf(
            JsonPrimitive("0x400200"),
            JsonPrimitive("0x0400100"),
            JsonPrimitive("0x40010A"),
            JsonPrimitive("0x10000000000400100"),
            JsonPrimitive("400100"),
            JsonPrimitive(0x400100),
            JsonNull,
        )) fixture { root, run, reports ->
            writeNamedRecords(root, id to globalRecord(id, address))
            val failure = assertFailsWith<IllegalArgumentException>(address.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("address"), failure.message)
        }
    }

    @Test
    fun `matching model bytes cannot authenticate statuses impossible for the exporter record kind`() {
        for (kind in listOf("global", "type")) fixture { root, run, reports ->
            if (kind == "global") {
                val id = "global_0000000000400100"
                writeNamedRecords(root, id to globalRecord(id, JsonPrimitive("0x400100"), status = "partial"))
            } else {
                writeNamedRecords(root, type = typeId() to typeRecord(status = "recovered"))
            }
            val failure = assertFailsWith<IllegalArgumentException>(kind) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("evidence record"), failure.message)
        }
    }

    @Test
    fun `failure sidecars require a JSON string message before output tree authentication`() {
        for (message in listOf<JsonElement>(
            JsonPrimitive(17), JsonPrimitive(true), JsonNull, JsonObject(emptyMap()), JsonArray(emptyList()),
        )) fixture { root, run, reports ->
            writeFailure(root, message)
            val failure = assertFailsWith<IllegalArgumentException>(message.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("message"), failure.message)
        }
    }

    @Test
    fun `multi phase failure strings retain Unicode and existing UTF8 record bounds`() = fixture { root, run, reports ->
        val message = "call recovery failed: " + "界".repeat(1900) + "; type recovery failed: " + "𐐀".repeat(900)
        writeFailure(root, JsonPrimitive(message))
        val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
        assertEquals(1L, snapshot.failed)
        assertEquals(0L, snapshot.recovered)
        assertTrue(snapshot.sidecarManifest.decodeToString().contains("failures/fn_0000000000400010.json"))
        assertEquals("false", OracleJson.parseCanonical(snapshot.assessmentBytes).jsonObject.getValue("complete").jsonPrimitive.content)

        val maximumRecordBytes = 1024 * 1024
        val messageBytes = maximumRecordBytes - failureRecord(JsonPrimitive("")).toByteArray().size
        val boundaryMessage = "界".repeat(messageBytes / 3) + "x".repeat(messageBytes % 3)
        writeFailure(root, JsonPrimitive(boundaryMessage))
        assertEquals(maximumRecordBytes.toLong(), Files.size(root.resolve("reports/program_model.json.export/failures/fn_0000000000400010.json")))
        GccBundledFullExportCapture.capture(run, reports, artifacts())
        writeFailure(root, JsonPrimitive(boundaryMessage + "x"))
        assertFails { GccBundledFullExportCapture.capture(run, reports, artifacts()) }
    }

    private fun fixture(action: (Path, LinuxDescriptor, decompengine.acp.LinuxFileIdentity) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build", "gcc-full-export-capture-tests"))
        val root = Files.createTempDirectory(temporaryRoot, "gcc-full-export-capture-").toRealPath()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val reports = Files.createDirectory(root.resolve("reports"))
            privateDirectory(reports)
            val export = Files.createDirectory(reports.resolve("program_model.json.export"))
            privateDirectory(export)
            for (name in listOf("planning-batches", "functions", "globals", "types", "failures")) {
                privateDirectory(Files.createDirectory(export.resolve(name)))
            }
            val functionId = "fn_0000000000400010"
            writeState(root)
            writeProgress(root)
            val record = functionRecord(functionId, "f")
            Files.writeString(reports.resolve("program_model.json"), modelText(record))
            Files.writeString(export.resolve("functions/$functionId.json"), record)
            LinuxFilesystemSyscalls.openRoot(root).use { run ->
                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reportsDescriptor ->
                    action(root, run, reportsDescriptor.identity)
                }
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun privateDirectory(path: Path) = Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))

    private fun artifacts() = listOf(
        artifact(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY, "/fixture/gcc-driver", inputSha()),
        artifact(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE, "/fixture/ExportProgramModel.java", exporterSha()),
        artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE, "/fixture/ghidra.zip", analysisToolSha()),
    )

    private fun artifact(role: GccCompilerEngineContainmentArtifactRole, path: String, sha: String) =
        GccCompilerEngineContainmentArtifactIdentity(role, Path.of(path), 1, sha)

    private fun inputSha() = OracleArtifacts.sha256("structural-input".toByteArray())
    private fun exporterSha() = OracleArtifacts.sha256("exporter".toByteArray())
    private fun analysisToolSha() = OracleArtifacts.sha256("ghidra-archive".toByteArray())

    private fun writeState(root: Path, recoveryMode: String = "full", inputSha256: String = inputSha()) {
        val state = """{"schemaVersion":2,"exporterVersion":10,"exporterSha256":"${exporterSha()}","analysisToolSha256":"${analysisToolSha()}","recoveryMode":"$recoveryMode","inputSha256":"$inputSha256","language":"x86:LE:64:default","compilerSpec":"gcc","semanticStateBinding":null}
"""
        Files.writeString(root.resolve("reports/program_model.json.export/state.json"), state)
    }

    private fun writeProgress(root: Path, completed: Int = 1, phase: String = "complete", recovered: Int = 1, failed: Int = 0) {
        val progress = """{"schemaVersion":1,"phase":"$phase","completed":$completed,"total":1,"recovered":$recovered,"partial":0,"failed":$failed,"reused":0,"currentFunction":null}
"""
        Files.writeString(root.resolve("reports/program_model.json.progress.json"), progress)
    }

    private fun functionRecord(id: String, name: String, status: String = "recovered") =
        """{"id":"$id","name":"$name","address":"0x400010","prototype":"int f(void)","extractionStatus":"$status","recoveryAssessment":"unassessed","calls":[],"referencedGlobals":[],"strings":[],"decompiledC":${if (status == "failed") "null" else "\"int f(void) { return 1; }\""}}"""

    private fun globalRecord(id: String, address: JsonElement, status: String = "recovered") =
        """{"id":"$id","name":"g","address":$address,"type":"int","initializer":null,"extractionStatus":"$status","recoveryAssessment":"unassessed"}"""

    private fun typeId() = "type_" + OracleArtifacts.sha256("int".toByteArray())

    private fun typeRecord(status: String = "partial") =
        """{"id":"${typeId()}","declaration":"typedef int scalar;","sourceAddress":"0x400010","extractionStatus":"$status","recoveryAssessment":"unassessed"}"""

    private fun writeNamedRecords(root: Path, global: Pair<String, String>? = null, type: Pair<String, String>? = null) {
        val export = root.resolve("reports/program_model.json.export")
        global?.let { (id, record) -> Files.writeString(export.resolve("globals/$id.json"), record) }
        type?.let { (id, record) -> Files.writeString(export.resolve("types/$id.json"), record) }
        // Keep sidecars and assembled model identical so semantic validation is exercised.
        val function = Files.readString(export.resolve("functions/fn_0000000000400010.json"))
        Files.writeString(root.resolve("reports/program_model.json"), modelText(function, global?.second, type?.second))
    }

    private fun failureRecord(message: JsonElement) =
        """{"schemaVersion":1,"functionId":"fn_0000000000400010","status":"failed","message":$message}
"""

    private fun writeFailure(root: Path, message: JsonElement) {
        val record = functionRecord("fn_0000000000400010", "f", status = "failed")
        Files.writeString(root.resolve("reports/program_model.json.export/functions/fn_0000000000400010.json"), record)
        Files.writeString(root.resolve("reports/program_model.json"), modelText(record))
        writeProgress(root, recovered = 0, failed = 1)
        Files.writeString(root.resolve("reports/program_model.json.export/failures/fn_0000000000400010.json"), failureRecord(message))
    }

    private fun modelText(record: String, global: String? = null, type: String? = null) =
        "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"${inputSha()}\",\n  \"functions\": [\n" +
            "$record\n  ],\n  \"globals\": [\n${global?.let { "$it\n" } ?: ""}  ],\n" +
            "  \"types\": [\n${type?.let { "$it\n" } ?: ""}  ]\n}\n"
}

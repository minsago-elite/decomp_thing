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
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
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

    private fun fixture(action: (Path, LinuxDescriptor, decompengine.acp.LinuxFileIdentity) -> Unit) {
        val root = Files.createTempDirectory("gcc-full-export-capture-").toRealPath()
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

    private fun writeProgress(root: Path, completed: Int = 1, phase: String = "complete") {
        val progress = """{"schemaVersion":1,"phase":"$phase","completed":$completed,"total":1,"recovered":1,"partial":0,"failed":0,"reused":0,"currentFunction":null}
"""
        Files.writeString(root.resolve("reports/program_model.json.progress.json"), progress)
    }

    private fun functionRecord(id: String, name: String) =
        """{"id":"$id","name":"$name","address":"0x400010","prototype":"int f(void)","extractionStatus":"recovered","recoveryAssessment":"unassessed","calls":[],"referencedGlobals":[],"strings":[],"decompiledC":"int f(void) { return 1; }"}"""

    private fun modelText(record: String) =
        "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"${inputSha()}\",\n  \"functions\": [\n" +
            "$record\n  ],\n  \"globals\": [\n  ],\n  \"types\": [\n  ]\n}\n"
}

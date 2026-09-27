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
            { path -> writeState(path, exporterVersion = 11) },
            { path -> writeProgress(path, completed = 0, phase = "decompiling") },
            { path -> Files.writeString(path.resolve("reports/program_model.json.export/planning-batches/stray"), "x") },
        )) fixture { root, run, reports ->
            mutate(root)
            assertFails { GccBundledFullExportCapture.capture(run, reports, artifacts()) }
        }
    }

    @Test
    fun `exact exporter state retains the parsed target identity`() = fixture { root, run, reports ->
        writeState(root, language = "AARCH64:LE:64:v8A", compilerSpec = "gcc_1.2+-")
        val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
        assertEquals("AARCH64:LE:64:v8A", snapshot.language)
        assertEquals("gcc_1.2+-", snapshot.compilerSpec)
    }

    @Test
    fun `full export state and progress reject equivalent JSON with bytes the exporter cannot emit`() {
        val mutations = listOf<Pair<String, (String) -> String>>(
            "reordered fields" to { text ->
                JsonObject(OracleJson.parse(text.toByteArray()).jsonObject.entries.reversed()
                    .associate { it.key to it.value }).toString() + "\n"
            },
            "field whitespace" to { text -> text.replace("\":", "\": ") },
            "leading whitespace" to { text -> " " + text },
            "extra terminal LF" to { text -> text + "\n" },
            "escaped field name" to { text -> text.replace("\"schemaVersion\"", "\"\\u0073chemaVersion\"") },
            "escaped string value" to { text -> text.replace("\"full\"", "\"\\u0066ull\"")
                .replace("\"complete\"", "\"\\u0063omplete\"") },
        )
        for ((label, relativePath) in listOf(
            "state" to "reports/program_model.json.export/state.json",
            "progress" to "reports/program_model.json.progress.json",
        )) for ((mutation, mutate) in mutations) fixture { root, run, reports ->
            val path = root.resolve(relativePath)
            val original = Files.readString(path)
            val changed = mutate(original)
            assertNotEquals(original, changed, "$label: $mutation")
            assertEquals(OracleJson.parse(original.toByteArray()), OracleJson.parse(changed.toByteArray()),
                "$label: $mutation must preserve the parsed record")
            Files.writeString(path, changed)
            val failure = assertFailsWith<IllegalArgumentException>("$label: $mutation") {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("$label is not in the exact exporter-defined compact byte form"),
                failure.message)
        }
    }

    @Test
    fun `full export progress rejects a negative zero count absent from exporter output`() = fixture { root, run, reports ->
        val path = root.resolve("reports/program_model.json.progress.json")
        val changed = Files.readString(path).replace("\"reused\":0", "\"reused\":-0")
        assertEquals(0L, OracleJson.parse(changed.toByteArray()).jsonObject.getValue("reused").jsonPrimitive.long)
        Files.writeString(path, changed)
        val failure = assertFailsWith<IllegalArgumentException> {
            GccBundledFullExportCapture.capture(run, reports, artifacts())
        }
        assertTrue(failure.message.orEmpty().contains("progress is not in the exact exporter-defined compact byte form"),
            failure.message)
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
            val type = typeRecord(sourceAddress = JsonPrimitive(address))
            writeFunction(root, functionRecord("fn_0000000000400010", "f",
                references = JsonArray(listOf(JsonPrimitive(id)))))
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
    fun `full function source presence follows recovered partial and failed exporter outcomes`() {
        for (status in listOf("recovered", "partial", "failed")) fixture { root, run, reports ->
            if (status != "recovered") writeFailure(root, JsonPrimitive("auxiliary evidence failed"), status)
            val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
            assertEquals(if (status == "recovered") 1L else 0L, snapshot.recovered)
            assertEquals(if (status == "partial") 1L else 0L, snapshot.partial)
            assertEquals(if (status == "failed") 1L else 0L, snapshot.failed)
        }
    }

    @Test
    fun `matching model bytes cannot authenticate source fields inconsistent with function outcomes`() {
        val invalid = listOf(
            "recovered" to JsonNull,
            "partial" to JsonNull,
            "failed" to JsonPrimitive("int f(void) { return 1; }"),
        ) + listOf<JsonElement>(JsonPrimitive(17), JsonPrimitive(true), JsonObject(emptyMap()), JsonArray(emptyList()))
            .map { "recovered" to it }
        for ((status, source) in invalid) fixture { root, run, reports ->
            if (status != "recovered") writeFailure(root, JsonPrimitive("auxiliary evidence failed"), status)
            writeFunction(root, functionRecord("fn_0000000000400010", "f", status, source))
            val failure = assertFailsWith<IllegalArgumentException>("$status: $source") {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("decompiledC"), failure.message)
        }
    }

    @Test
    fun `function global references resolve to the captured global inventory`() = fixture { root, run, reports ->
        val id = "global_0000000000400100"
        writeFunction(root, functionRecord("fn_0000000000400010", "f",
            references = JsonArray(listOf(JsonPrimitive(id)))))
        writeNamedRecords(root, global = id to globalRecord(id, JsonPrimitive("0x400100")))
        val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
        assertEquals(5L, snapshot.outputFileCount)
    }

    @Test
    fun `matching model bytes cannot authenticate absent or malformed global references`() {
        for (references in listOf<JsonElement>(
            JsonArray(listOf(JsonPrimitive("global_0000000000400200"))),
            JsonArray(listOf(JsonPrimitive("global_400100"))),
            JsonArray(listOf(JsonPrimitive(17))),
            JsonArray(listOf(JsonNull)),
            JsonPrimitive("global_0000000000400100"),
            JsonNull,
        )) fixture { root, run, reports ->
            writeFunction(root, functionRecord("fn_0000000000400010", "f", references = references))
            val id = "global_0000000000400100"
            writeNamedRecords(root, global = id to globalRecord(id, JsonPrimitive("0x400100")))
            val failure = assertFailsWith<IllegalArgumentException>(references.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("referencedGlobals"), failure.message)
        }
    }

    @Test
    fun `matching model bytes cannot authenticate orphaned global sidecars`() = fixture { root, run, reports ->
        val id = "global_0000000000400100"
        writeNamedRecords(root, global = id to globalRecord(id, JsonPrimitive("0x400100")))
        val failure = assertFailsWith<IllegalArgumentException> {
            GccBundledFullExportCapture.capture(run, reports, artifacts())
        }
        assertTrue(failure.message.orEmpty().contains("orphaned global"), failure.message)
    }

    @Test
    fun `matching model bytes cannot authenticate malformed call identities`() {
        for (calls in listOf<JsonElement>(
            JsonArray(listOf(JsonPrimitive(""))),
            JsonArray(listOf(JsonPrimitive("attacker"))),
            JsonArray(listOf(JsonPrimitive("fn_00000000004000AF"))),
            JsonArray(listOf(JsonPrimitive("fn_400010"))),
            JsonArray(listOf(JsonPrimitive("fn_00000000000400010"))),
            JsonArray(listOf(JsonPrimitive(17))),
            JsonArray(listOf(JsonNull)),
            JsonPrimitive("fn_0000000000400010"),
            JsonNull,
        )) fixture { root, run, reports ->
            writeFunction(root, functionRecord("fn_0000000000400010", "f", calls = calls))
            val failure = assertFailsWith<IllegalArgumentException>(calls.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("calls"), failure.message)
        }
    }

    @Test
    fun `call identity syntax does not claim authenticated target provenance`() = fixture { root, run, reports ->
        // Non-external thunks may be absent from the function inventory and file-backed ELF ranges.
        writeFunction(root, functionRecord("fn_0000000000400010", "f", calls = JsonArray(listOf(
            JsonPrimitive("fn_0000000000000000"), JsonPrimitive("fn_ffffffffffffffff"),
        ))))
        assertEquals(1L, GccBundledFullExportCapture.capture(run, reports, artifacts()).functionCount)
    }

    @Test
    fun `type evidence can retain its first function source address`() = fixture { root, run, reports ->
        writeNamedRecords(root, type = typeId() to typeRecord())
        assertEquals(5L, GccBundledFullExportCapture.capture(run, reports, artifacts()).outputFileCount)
    }

    @Test
    fun `type path encoding preserves Unicode escapes and ambiguous comment characters losslessly`() {
        val paths = listOf(
            "/scalar" to "\"\\/scalar\"",
            "/a*/T" to "\"\\/a*\\/T\"",
            "/a* /T" to "\"\\/a* \\/T\"",
            "/a*/b* /界𐐀" to "\"\\/a*\\/b* \\/界𐐀\"",
            "/quote\"/back\\slash\n\r\t\b\u000c" to
                "\"\\/quote\\\"\\/back\\\\slash\\n\\r\\t\\u0008\\u000c\"",
        )
        for ((path, encoded) in paths) fixture { root, run, reports ->
            val id = typeId(path)
            writeNamedRecords(root, type = id to typeRecord(id = id,
                declaration = JsonPrimitive("/* Ghidra type $encoded */ typedef int scalar;")))
            val snapshot = GccBundledFullExportCapture.capture(run, reports, artifacts())
            assertEquals(5L, snapshot.outputFileCount)
            assertTrue(snapshot.sidecarManifest.decodeToString().contains("types/$id.json"))
        }
    }

    @Test
    fun `matching model bytes cannot authenticate a type path paired with another identity`() {
        for ((identityPath, declarationPath) in listOf(
            "/other" to "\"\\/scalar\"",
            "/a*/T" to "\"\\/a* \\/T\"",
            "/a* /T" to "\"\\/a*\\/T\"",
        )) fixture { root, run, reports ->
            val id = typeId(identityPath)
            writeNamedRecords(root, type = id to typeRecord(id = id,
                declaration = JsonPrimitive("/* Ghidra type $declarationPath */ typedef int scalar;")))
            val failure = assertFailsWith<IllegalArgumentException> {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("identity does not match"), failure.message)
        }
    }

    @Test
    fun `type path metadata rejects legacy lossy missing and noncanonical encodings`() {
        for (declaration in listOf<JsonElement>(
            JsonPrimitive("typedef int scalar;"),
            JsonPrimitive("/* Ghidra type /scalar */ typedef int scalar;"),
            JsonPrimitive("/* Ghidra type \"/scalar\" */ typedef int scalar;"),
            JsonPrimitive("/* Ghidra type \"\\/sc\\u0061lar\" */ typedef int scalar;"),
            JsonPrimitive("/* Ghidra type null */ typedef int scalar;"),
            JsonPrimitive("/* Ghidra type [] */ typedef int scalar;"),
            JsonPrimitive("/* Ghidra type \"\\/scalar\" */typedef int scalar;"),
            JsonPrimitive("/* Ghidra type \"\\/a*/T\" */ typedef int scalar;"),
            JsonNull,
        )) fixture { root, run, reports ->
            writeNamedRecords(root, type = typeId() to typeRecord(declaration = declaration))
            assertFailsWith<IllegalArgumentException>(declaration.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
        }
    }

    @Test
    fun `matching model bytes cannot authenticate absent or noncanonical type source addresses`() {
        for (address in listOf<JsonElement>(
            JsonNull, JsonPrimitive(0x400010), JsonPrimitive("0x400200"), JsonPrimitive("0x0400010"),
            JsonPrimitive("0x40001A"), JsonPrimitive("0x10000000000400010"), JsonPrimitive("400010"),
        )) fixture { root, run, reports ->
            writeNamedRecords(root, type = typeId() to typeRecord(sourceAddress = address))
            val failure = assertFailsWith<IllegalArgumentException>(address.toString()) {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("sourceAddress"), failure.message)
        }
    }

    @Test
    fun `type sources cannot be authenticated by a function address contradicting its identity`() = fixture { root, run, reports ->
        val original = functionRecord("fn_0000000000400010", "f")
        writeFunction(root, original.replace("\"address\":\"0x400010\"", "\"address\":\"0x400020\""))
        writeNamedRecords(root, type = typeId() to typeRecord(sourceAddress = JsonPrimitive("0x400020")))
        val failure = assertFailsWith<IllegalArgumentException> {
            GccBundledFullExportCapture.capture(run, reports, artifacts())
        }
        assertTrue(failure.message.orEmpty().contains("function record identity"), failure.message)
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
    fun `failure sidecars cannot authenticate blank failure messages`() {
        for (message in listOf("", " ", "\t\r\n ", "\u00a0")) fixture { root, run, reports ->
            writeFailure(root, JsonPrimitive(message))
            val failure = assertFailsWith<IllegalArgumentException> {
                GccBundledFullExportCapture.capture(run, reports, artifacts())
            }
            assertTrue(failure.message.orEmpty().contains("failure message must not be blank"), failure.message)
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

    private fun writeState(
        root: Path,
        recoveryMode: String = "full",
        inputSha256: String = inputSha(),
        exporterVersion: Int = 12,
        language: String = "x86:LE:64:default",
        compilerSpec: String = "gcc",
    ) {
        val state = """{"schemaVersion":2,"exporterVersion":$exporterVersion,"exporterSha256":"${exporterSha()}","analysisToolSha256":"${analysisToolSha()}","recoveryMode":"$recoveryMode","inputSha256":"$inputSha256","language":"$language","compilerSpec":"$compilerSpec","semanticStateBinding":null}
"""
        Files.writeString(root.resolve("reports/program_model.json.export/state.json"), state)
    }

    private fun writeProgress(root: Path, completed: Int = 1, phase: String = "complete", recovered: Int = 1, failed: Int = 0, partial: Int = 0) {
        val progress = """{"schemaVersion":1,"phase":"$phase","completed":$completed,"total":1,"recovered":$recovered,"partial":$partial,"failed":$failed,"reused":0,"currentFunction":null}
"""
        Files.writeString(root.resolve("reports/program_model.json.progress.json"), progress)
    }

    private fun functionRecord(
        id: String,
        name: String,
        status: String = "recovered",
        source: JsonElement = if (status == "failed") JsonNull else JsonPrimitive("int f(void) { return 1; }"),
        references: JsonElement = JsonArray(emptyList()),
        calls: JsonElement = JsonArray(emptyList()),
    ) =
        """{"id":"$id","name":"$name","address":"0x400010","prototype":"int f(void)","extractionStatus":"$status","recoveryAssessment":"unassessed","calls":$calls,"referencedGlobals":$references,"strings":[],"decompiledC":$source}"""

    private fun writeFunction(root: Path, record: String) {
        Files.writeString(root.resolve("reports/program_model.json.export/functions/fn_0000000000400010.json"), record)
        Files.writeString(root.resolve("reports/program_model.json"), modelText(record))
    }

    private fun globalRecord(id: String, address: JsonElement, status: String = "recovered") =
        """{"id":"$id","name":"g","address":$address,"type":"int","initializer":null,"extractionStatus":"$status","recoveryAssessment":"unassessed"}"""

    private fun typeId(path: String = "/scalar") = "type_" + OracleArtifacts.sha256(path.toByteArray())

    private fun typeRecord(
        status: String = "partial",
        sourceAddress: JsonElement = JsonPrimitive("0x400010"),
        id: String = typeId(),
        declaration: JsonElement = JsonPrimitive("/* Ghidra type \"\\/scalar\" */ typedef int scalar;"),
    ) =
        """{"id":"$id","declaration":$declaration,"sourceAddress":$sourceAddress,"extractionStatus":"$status","recoveryAssessment":"unassessed"}"""

    private fun writeNamedRecords(root: Path, global: Pair<String, String>? = null, type: Pair<String, String>? = null) {
        val export = root.resolve("reports/program_model.json.export")
        global?.let { (id, record) -> Files.writeString(export.resolve("globals/$id.json"), record) }
        type?.let { (id, record) -> Files.writeString(export.resolve("types/$id.json"), record) }
        // Keep sidecars and assembled model identical so semantic validation is exercised.
        val function = Files.readString(export.resolve("functions/fn_0000000000400010.json"))
        Files.writeString(root.resolve("reports/program_model.json"), modelText(function, global?.second, type?.second))
    }

    private fun failureRecord(message: JsonElement, status: String = "failed") =
        """{"schemaVersion":1,"functionId":"fn_0000000000400010","status":"$status","message":$message}
"""

    private fun writeFailure(root: Path, message: JsonElement, status: String = "failed") {
        val record = functionRecord("fn_0000000000400010", "f", status = status)
        writeFunction(root, record)
        writeProgress(root, recovered = 0, failed = if (status == "failed") 1 else 0, partial = if (status == "partial") 1 else 0)
        Files.writeString(root.resolve("reports/program_model.json.export/failures/fn_0000000000400010.json"), failureRecord(message, status))
    }

    private fun modelText(record: String, global: String? = null, type: String? = null) =
        "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"${inputSha()}\",\n  \"functions\": [\n" +
            "$record\n  ],\n  \"globals\": [\n${global?.let { "$it\n" } ?: ""}  ],\n" +
            "  \"types\": [\n${type?.let { "$it\n" } ?: ""}  ]\n}\n"
}

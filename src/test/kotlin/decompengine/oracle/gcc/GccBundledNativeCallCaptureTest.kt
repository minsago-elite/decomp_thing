package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.project.NativeCallObservationLimitsV1
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.json.*

class GccBundledNativeCallCaptureTest {
    @Test
    fun `RAM ordinal is resolved from independent metadata rather than trusted as identity`() = fixture { fixture ->
        fun reindex(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> {
                val rebuilt = JsonObject(value.mapValues { reindex(it.value) })
                if (value["kind"] == JsonPrimitive("address")) rebuilt.copyField("spaceIndex", JsonPrimitive(1)) else rebuilt
            }
            is JsonArray -> JsonArray(value.map(::reindex))
            else -> value
        }
        val constant = space().copyField("name", JsonPrimitive("const")).copyField("type", JsonPrimitive(0))
            .copyField("signedOffsets", JsonPrimitive(true))
        val objectValue = (reindex(fixture.nativeObject()) as JsonObject).copyField("addressSpaces",
            JsonArray(listOf(constant, space().copyField("index", JsonPrimitive(1)))))
        fixture.writeNative(objectValue)
        assertEquals(1, fixture.capture().summary.bindings.imageBase.spaceIndex)
        fixture.writeNative(objectValue.copyField("bindings", objectValue.getValue("bindings").jsonObject
            .copyField("imageBase", address(0x400000UL))))
        assertFails { fixture.capture() }
    }

    @Test
    fun `native result cancellation precedes marker while durable commit returns without revalidation`() = fixture { fixture ->
        val bytes = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-cli-native-call-result-v1"), "schemaVersion" to JsonPrimitive(1),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false))))
        assertFailsWith<InterruptedException> {
            GccBundledNativeCallCliPublication.publishResultMarker(fixture.run, bytes,
                beforeCommit = { throw InterruptedException("cancel before marker") })
        }
        assertFalse(Files.exists(fixture.root.resolve("result.json")))
        var cancelled = false
        var validations = 0
        val expectedBytes = bytes.copyOf()
        val marker = GccBundledNativeCallCliPublication.publishResultMarker(fixture.run, bytes,
            beforeCommit = { validations++; assertFalse(cancelled); bytes.fill(0) },
            faultInjector = { point ->
                if (point == DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC) cancelled = true
            })
        assertTrue(cancelled)
        assertEquals(1, validations)
        assertContentEquals(expectedBytes, marker.bytes)
        assertContentEquals(expectedBytes, Files.readAllBytes(fixture.root.resolve("result.json")))
    }

    @Test
    fun `capture preserves zero call functions and thunks without granting production authority`() = fixture { fixture ->
        val capture = fixture.capture()
        assertEquals(2L, capture.summary.scanSummary.functions)
        assertEquals(1L, capture.summary.scanSummary.thunks)
        assertEquals(0L, capture.summary.scanSummary.sites)
        assertFalse(capture.complete); assertFalse(capture.scored); assertFalse(capture.releaseEligible)
        fixture.requireUnchanged(capture)
        assertFailsWith<IllegalStateException> {
            GccBundledNativeCallOperation("{}".toByteArray(), byteArrayOf(), byteArrayOf(), fixture.model, capture, Any())
        }
        assertFails { (capture.summary.addressSpaces as MutableList).clear() }
        assertEquals(1, capture.summary.addressSpaces.size)
        assertFails { (fixture.model.functionEntryOffsets as MutableList).clear() }
    }

    @Test
    fun `native capture rejects unexpected members and linked or public evidence`() {
        val mutations = listOf<(Fixture) -> Unit>(
            { Files.writeString(it.native.resolve("extra"), "x") },
            { Files.writeString(it.native.resolve(".manifest.json.pending"), "x") },
            { val path = it.native.resolve("native-calls.json"); val bytes = Files.readAllBytes(path); Files.delete(path)
                val other = it.root.resolve("other"); Files.write(other, bytes); Files.createSymbolicLink(path, other) },
            { Files.createLink(it.root.resolve("alias"), it.native.resolve("native-calls.json")) },
            { Files.setPosixFilePermissions(it.native, PosixFilePermissions.fromString("rwxr-xr-x")) },
            { Files.setPosixFilePermissions(it.native.resolve("manifest.json"), PosixFilePermissions.fromString("rw-rw----")) },
        )
        for (mutate in mutations) fixture { fixture -> mutate(fixture); assertFails { fixture.capture() } }
    }

    @Test
    fun `unchanged validation rejects identical byte replacements of each retained evidence file`() {
        for (relative in listOf("reports/program_model.json", "reports/program_model.json.progress.json",
            "reports/program_model.json.export/state.json", "reports/native-calls-v1/native-calls.json",
            "reports/native-calls-v1/manifest.json")) fixture { fixture ->
            val captured = fixture.capture()
            val path = fixture.root.resolve(relative)
            val replacement = path.resolveSibling("replacement")
            Files.write(replacement, Files.readAllBytes(path))
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
            Files.move(replacement, path, StandardCopyOption.REPLACE_EXISTING)
            assertFails(relative) { fixture.requireUnchanged(captured) }
        }
    }

    @Test
    fun `model target native census aggregate overflow and cancellation fail without a result`() {
        for (mutate in listOf<(JsonObject) -> JsonObject>(
            { it.copyField("bindings", it.getValue("bindings").jsonObject.copyField("imageBase", address(0x400001UL))) },
            { it.copyField("addressSpaces", JsonArray(listOf(space().copyField("type", JsonPrimitive(0))))) },
            { it.copyField("addressSpaces", JsonArray(listOf(space().copyField("name", JsonPrimitive("forged"))))) },
            { it.copyField("records", JsonArray(it.getValue("records").jsonArray.map { record ->
                val objectRecord = record.jsonObject
                if (objectRecord.getValue("recordKind").jsonPrimitive.content == "function" &&
                    objectRecord.getValue("isThunk").jsonPrimitive.content == "false")
                    objectRecord.copyField("entry", address(0x400011UL)) else record
            })) },
        )) fixture { fixture ->
            fixture.writeNative(mutate(fixture.nativeObject()))
            assertFails { fixture.capture() }
            assertFalse(Files.exists(fixture.root.resolve("result.json")))
        }
        fixture { fixture ->
            val total = fixture.model.capturedBytes + Files.size(fixture.native.resolve("native-calls.json")) +
                Files.size(fixture.native.resolve("manifest.json"))
            assertFails { fixture.capture(NativeCallObservationLimitsV1(maximumCombinedBytes = total - 1)) }
            var checkpoints = 0
            val cancellation = assertFails { fixture.capture(checkpoint = {
                if (++checkpoints == 15) throw InterruptedException("cancel authored capture")
            }) }
            assertTrue(generateSequence(cancellation) { it.cause }.any { it is InterruptedException })
            assertTrue(checkpoints >= 15)
            assertFalse(Files.exists(fixture.root.resolve("result.json")))
        }
    }

    private class Fixture(val root: Path, val run: LinuxDescriptor, val reports: LinuxFileIdentity,
        val control: LinuxFileIdentity, val model: GccBundledFullExportSnapshot) {
        val native: Path = root.resolve("reports/native-calls-v1")
        val target = GccBundledNativeCallTargetEvidenceV1("f".repeat(64), "x86_64-linux-gnu", model.inputSha256,
            model.inputBytes, 0x400000UL, model.language, model.compilerSpec,
            GccBundledNativeCallAddressSpaceIdentityV1("ram", 1, 64, 1, false, false),
            listOf(FullTreeElfExecutableRange(0UL, 0x1000UL)))
        fun capture(limits: NativeCallObservationLimitsV1 = NativeCallObservationLimitsV1(), checkpoint: () -> Unit = {}) =
            GccBundledNativeCallCapture.capture(run, reports, CONTROL, control, model, COLLECTOR, target, limits, checkpoint)
        fun requireUnchanged(snapshot: GccBundledNativeCallSnapshot) =
            GccBundledNativeCallCapture.requireUnchanged(run, snapshot, model, artifacts()) {}
        fun nativeObject(): JsonObject {
            val bindings = JsonObject(mapOf(
                "collectorSha256" to JsonPrimitive(COLLECTOR), "compilerSpecId" to JsonPrimitive(model.compilerSpec),
                "ghidraArchiveSha256" to JsonPrimitive(model.analysisToolSha256), "imageBase" to address(0x400000UL),
                "inputSha256" to JsonPrimitive(model.inputSha256), "languageId" to JsonPrimitive(model.language),
                "programModelBytes" to JsonPrimitive(model.programModelBytes), "programModelExporterSha256" to JsonPrimitive(model.exporterSha256),
                "programModelSha256" to JsonPrimitive(model.programModelSha256)))
            val records = listOf(false to 0x400010UL, true to 0x405000UL).map { (thunk, offset) -> JsonObject(mapOf(
                "recordKind" to JsonPrimitive("function"), "entry" to address(offset), "bodyAddressCount" to JsonPrimitive(1),
                "bodyRangeCount" to JsonPrimitive(1), "isThunk" to JsonPrimitive(thunk),
                "immediateThunkTarget" to if (thunk) JsonObject(mapOf("address" to address(0x400010UL),
                    "functionEntry" to address(0x400010UL), "external" to JsonNull, "memoryBlock" to JsonNull)) else JsonNull)) } +
                listOf(0x400010UL, 0x405000UL).map { offset -> JsonObject(mapOf(
                    "recordKind" to JsonPrimitive("function-summary"), "entry" to address(offset)) + zeroSummaryFields()) }
            val scan = JsonObject(mapOf("coverage" to JsonPrimitive("all-currently-listed-instructions-and-recovered-functions"),
                "functions" to JsonPrimitive(2), "thunks" to JsonPrimitive(1)) + zeroSummaryFields() +
                listOf("ownedInstructions", "unownedInstructions", "sites", "directReferences", "neighborhoodReferences",
                    "unownedPrototypeCalls", "unownedAnalysisCallCandidates", "unownedDirectTailCandidates")
                    .associateWith { JsonPrimitive(0) })
            return JsonObject(mapOf("addressSpaces" to JsonArray(listOf(space())), "bindings" to bindings,
                "policy" to JsonPrimitive("ghidra-native-call-observations-v1"), "records" to JsonArray(records),
                "schemaVersion" to JsonPrimitive(1), "summary" to scan))
        }
        fun writeNative(observations: JsonObject = nativeObject()) {
            val bytes = OracleJson.canonicalBytes(observations)
            val manifest = OracleJson.canonicalBytes(JsonObject(mapOf(
                "bytes" to JsonPrimitive(bytes.size), "collectorSha256" to JsonPrimitive(COLLECTOR),
                "file" to JsonPrimitive("native-calls.json"), "inputSha256" to JsonPrimitive(model.inputSha256),
                "kind" to JsonPrimitive("ghidra-native-call-observation-manifest-v1"),
                "programModelSha256" to JsonPrimitive(model.programModelSha256), "schemaVersion" to JsonPrimitive(1),
                "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)))))
            Files.write(native.resolve("native-calls.json"), bytes); Files.write(native.resolve("manifest.json"), manifest)
            listOf("native-calls.json", "manifest.json").forEach {
                Files.setPosixFilePermissions(native.resolve(it), PosixFilePermissions.fromString("rw-------"))
            }
        }
    }

    private fun fixture(action: (Fixture) -> Unit) {
        val base = Files.createDirectories(Path.of("build", "native-call-capture-tests"))
        val root = privateDirectory(Files.createTempDirectory(base, "capture-")).toRealPath()
        try {
            val reports = privateDirectory(Files.createDirectory(root.resolve("reports")))
            val export = privateDirectory(Files.createDirectory(reports.resolve("program_model.json.export")))
            listOf("planning-batches", "functions", "globals", "types", "failures").forEach {
                privateDirectory(Files.createDirectory(export.resolve(it)))
            }
            val record = "{\n    \"id\": \"fn_0000000000400010\",\n    \"name\": \"f\",\n    \"address\": \"0x400010\",\n    \"prototype\": \"int f(void)\",\n    \"extractionStatus\": \"recovered\",\n    \"recoveryAssessment\": \"unassessed\",\n    \"calls\": [],\n    \"referencedGlobals\": [],\n    \"strings\": [],\n    \"decompiledC\": \"int f(void) { return 1; }\"\n}"
            val producerRecord = record.lines().mapIndexed { index, line ->
                if (index == 0 || line == "}") "    $line" else "  $line"
            }.joinToString("\n")
            Files.writeString(export.resolve("functions/fn_0000000000400010.json"), producerRecord)
            Files.writeString(reports.resolve("program_model.json"), "{\n  \"schemaVersion\": 4,\n  \"inputSha256\": \"${INPUT}\",\n  \"functions\": [\n$producerRecord\n  ],\n  \"globals\": [\n  ],\n  \"types\": [\n  ]\n}\n")
            Files.writeString(export.resolve("state.json"), "{\"schemaVersion\":2,\"exporterVersion\":17,\"exporterSha256\":\"${EXPORTER}\",\"analysisToolSha256\":\"${ARCHIVE}\",\"recoveryMode\":\"full\",\"decompilationWorkers\":1,\"inputSha256\":\"${INPUT}\",\"language\":\"x86:LE:64:default\",\"compilerSpec\":\"gcc\",\"semanticStateBinding\":null}\n")
            Files.writeString(reports.resolve("program_model.json.progress.json"), "{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":1,\"total\":1,\"recovered\":1,\"partial\":0,\"failed\":0,\"reused\":0,\"currentFunction\":null}\n")
            privateDirectory(Files.createDirectory(root.resolve(CONTROL)))
            LinuxFilesystemSyscalls.openRoot(root).use { run ->
                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reportsDescriptor ->
                    val model = GccBundledFullExportCapture.capture(run, reportsDescriptor.identity, artifacts())
                    privateDirectory(Files.createDirectory(reports.resolve("native-calls-v1")))
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                        val fixture = Fixture(root, run, reportsDescriptor.identity, control.identity, model)
                        fixture.writeNative()
                        action(fixture)
                    }
                }
            }
        } finally {
            Files.walk(root).use { files -> files.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    companion object {
        private val INPUT = OracleArtifacts.sha256("structural-input".toByteArray())
        private val EXPORTER = OracleArtifacts.sha256("exporter".toByteArray())
        private val ARCHIVE = OracleArtifacts.sha256("ghidra-archive".toByteArray())
        private val COLLECTOR = OracleArtifacts.sha256("native-collector".toByteArray())
        private val CONTROL = "control-${"a".repeat(64)}"
        private fun artifacts() = listOf(
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY, Path.of("/fixture/engine"), 1, INPUT),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE, Path.of("/fixture/exporter"), 1, EXPORTER),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE, Path.of("/fixture/archive"), 1, ARCHIVE))
        private fun privateDirectory(path: Path) = Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        private fun address(offset: ULong) = JsonObject(mapOf("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(0), "offsetBits" to JsonPrimitive(offset.toString(16).padStart(16, '0'))))
        private fun space() = JsonObject(mapOf("index" to JsonPrimitive(0), "name" to JsonPrimitive("ram"), "type" to JsonPrimitive(1), "sizeBits" to JsonPrimitive(64), "addressableUnitSize" to JsonPrimitive(1), "overlay" to JsonPrimitive(false), "signedOffsets" to JsonPrimitive(false)))
        private fun zeroSummaryFields() = listOf("instructionsVisited", "prototypeCalls", "analysisCallCandidates", "directTailCandidates", "ordinaryJumpInstructions", "unresolvedComputedJumps").associateWith { JsonPrimitive(0) }
        private fun JsonObject.copyField(field: String, value: JsonElement) = JsonObject(this + (field to value))
    }
}

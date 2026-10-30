package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.oracle.structural.NativeRecoveredCallPopulationLimitsV1
import decompengine.oracle.externalcalls.FrozenNativeExternalClaimsV1
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Authored real files exercise retained capture mechanics, never production collector qualification. */
class GccBundledNativeClaimFreezeTest {
    @Test
    fun `retained files freeze actual sites zero-site functions thunks and unowned observations`() = fixture { fixture ->
        val captured = fixture.capture()
        val frozen = fixture.freeze(captured)
        assertEquals(9L, frozen.rawRecordCount)
        assertEquals(3, frozen.rawSiteCount)
        assertEquals(captured.summary.observationsSha256, frozen.observationsSha256)
        assertEquals(fixture.model.programModelSha256, frozen.programModelSha256)
        assertEquals(fixture.model.inputSha256, frozen.inputSha256)
        assertContentEquals(Files.readAllBytes(fixture.native.resolve("native-calls.json")), frozen.rawObservationBytes)
        assertContentEquals(Files.readAllBytes(fixture.native.resolve("manifest.json")), frozen.rawManifestBytes)
        val evidence = document(frozen.canonicalEvidenceBytes)
        assertEquals(listOf("function", "function", "function", "site", "site", "site",
            "function-summary", "function-summary", "function-summary"), evidence.rows("rawRecords").map { it.text("recordKind") })
        val claims = evidence.rows("claims")
        assertEquals(JsonPrimitive("fn_0000000000400020"), claims[0]["targetRecoveredId"])
        assertEquals(JsonNull, claims[1]["targetRecoveredId"])
        assertEquals(JsonNull, claims[2]["ownerRecoveredId"])
        assertEquals(3L, captured.summary.scanSummary.functions)
        assertEquals(1L, captured.summary.scanSummary.thunks)
        assertEquals(1L, captured.summary.scanSummary.unownedPrototypeCalls)
        assertFalse(frozen.productionVerified)
        for (flag in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAvailable"))
            assertEquals(JsonPrimitive(false), evidence[flag])
        fixture.requireUnchanged(captured)
        assertFalse(Files.exists(fixture.root.resolve("result.json")))
    }

    @Test
    fun `identical-byte native manifest and paired model replacements fail before freezing`() {
        for (relative in RETAINED_FILES) fixture { fixture ->
            val captured = fixture.capture()
            fixture.replace(relative)
            assertFails(relative) { fixture.freeze(captured) }
        }
    }

    @Test
    fun `in-place content substitutions cannot pass retained metadata and digest checks`() {
        for (relative in RETAINED_FILES) fixture { fixture ->
            val captured = fixture.capture()
            val path = fixture.root.resolve(relative)
            val bytes = Files.readAllBytes(path)
            bytes[bytes.lastIndex] = if (bytes.last() == ' '.code.toByte()) '\n'.code.toByte() else ' '.code.toByte()
            Files.write(path, bytes)
            assertFails(relative) { fixture.freeze(captured) }
        }
    }

    @Test
    fun `substitution at first intermediate or final cooperative checkpoint never returns frozen claims`() {
        var checkpoints = 0
        fixture { fixture -> fixture.freeze(fixture.capture(), checkpoint = { checkpoints++ }) }
        assertTrue(checkpoints > 6, "fixture must traverse the actual retained read and revalidation path")
        for (position in setOf(1, checkpoints / 2, checkpoints)) {
            for (relative in RETAINED_FILES) fixture { fixture ->
                val captured = fixture.capture()
                var seen = 0
                var replaced = false
                assertFails("$relative at checkpoint $position/$checkpoints") {
                    fixture.freeze(captured, checkpoint = {
                        if (++seen == position) {
                            fixture.replace(relative)
                            replaced = true
                        }
                    })
                }
                assertTrue(replaced, "the selected checkpoint must be reached")
            }
        }
    }

    @Test
    fun `replacement during the pinned native stream read is rejected before returning claims`() {
        for (relative in RETAINED_FILES) fixture { fixture ->
            val captured = fixture.capture()
            var replaced = false
            assertFails(relative) {
                fixture.freeze(captured, checkpoint = {
                    if (!replaced && Thread.currentThread().stackTrace.any {
                        it.className == GccBundledNativeCallCapture::class.java.name && it.methodName.startsWith("readSmallFile")
                    }) {
                        fixture.replace(relative)
                        replaced = true
                    }
                })
            }
            assertTrue(replaced, "mutation must occur inside the actual descriptor-backed native read")
        }
    }

    @Test
    fun `later file substitution invalidates retained capture while frozen original bytes remain immutable`() = fixture { fixture ->
        val captured = fixture.capture()
        val frozen = fixture.freeze(captured)
        val original = frozen.rawObservationBytes
        val manifest = frozen.rawManifestBytes
        val evidence = frozen.canonicalEvidenceBytes
        captured.manifestBytes.fill(0)
        fixture.model.programModel.fill(0)
        frozen.rawObservationBytes.fill(0)
        frozen.rawManifestBytes.fill(0)
        frozen.canonicalEvidenceBytes.fill(0)
        assertContentEquals(original, frozen.rawObservationBytes)
        assertContentEquals(manifest, frozen.rawManifestBytes)
        assertContentEquals(evidence, frozen.canonicalEvidenceBytes)
        fixture.replace("reports/native-calls-v1/native-calls.json")
        assertFails { fixture.requireUnchanged(captured) }
        assertFails { fixture.freeze(captured) }
        assertContentEquals(original, frozen.rawObservationBytes)
        assertContentEquals(evidence, frozen.canonicalEvidenceBytes)
    }

    @Test
    fun `hardlinks and symbolic replacements of every retained file cannot enter a freeze`() {
        for (relative in RETAINED_FILES) for (link in listOf("hard", "symbolic")) fixture { fixture ->
            val captured = fixture.capture()
            val path = fixture.root.resolve(relative)
            val alias = fixture.root.resolve("caller-owned-alias")
            if (link == "hard") Files.createLink(alias, path) else {
                Files.move(path, alias)
                Files.createSymbolicLink(path, alias)
            }
            assertFails("$relative $link") { fixture.freeze(captured) }
            assertTrue(Files.exists(alias))
        }
    }

    @Test
    fun `public directory and writable retained file identity substitutions fail closed`() {
        for (relative in listOf("", "reports", "reports/native-calls-v1", CONTROL)) fixture { fixture ->
            val captured = fixture.capture()
            Files.setPosixFilePermissions(fixture.root.resolve(relative), PosixFilePermissions.fromString("rwxr-xr-x"))
            assertFails(relative) { fixture.freeze(captured) }
        }
        for (relative in RETAINED_FILES) fixture { fixture ->
            val captured = fixture.capture()
            Files.setPosixFilePermissions(fixture.root.resolve(relative), PosixFilePermissions.fromString("rw-rw-rw-"))
            assertFails(relative) { fixture.freeze(captured) }
        }
    }

    @Test
    fun `site evidence and exact byte ceilings are enforced by the retained freeze`() = fixture { fixture ->
        val captured = fixture.capture()
        val frozen = fixture.freeze(captured)
        val exact = NativeRecoveredCallPopulationLimitsV1(maximumObservationBytes = frozen.rawObservationBytes.size,
            maximumModelBytes = fixture.model.programModelBytes.toInt(), maximumSites = 3,
            maximumEvidenceBytes = frozen.canonicalEvidenceBytes.size)
        assertContentEquals(frozen.canonicalEvidenceBytes, fixture.freeze(captured, exact).canonicalEvidenceBytes)
        for (limits in listOf(exact.copy(maximumObservationBytes = exact.maximumObservationBytes - 1),
            exact.copy(maximumModelBytes = exact.maximumModelBytes - 1), exact.copy(maximumSites = 2),
            exact.copy(maximumEvidenceBytes = exact.maximumEvidenceBytes - 1))) {
            assertFails { fixture.freeze(captured, limits) }
        }
    }

    @Test
    fun `snapshot size and site limits reject before descriptor reads or cooperative callbacks`() {
        for (bound in listOf("observations", "model", "sites")) fixture { fixture ->
            val captured = fixture.capture()
            val limits = when (bound) {
                "observations" -> NativeRecoveredCallPopulationLimitsV1(maximumObservationBytes = captured.summary.observationsBytes.toInt() - 1)
                "model" -> NativeRecoveredCallPopulationLimitsV1(maximumModelBytes = fixture.model.programModelBytes.toInt() - 1)
                else -> NativeRecoveredCallPopulationLimitsV1(maximumSites = 2)
            }
            fixture.run.close()
            var checkpoints = 0
            val failure = assertFailsWith<IllegalArgumentException> {
                fixture.freeze(captured, limits, checkpoint = { checkpoints++ })
            }
            assertTrue(failure.message.orEmpty().contains("bounds"), failure.toString())
            assertEquals(0, checkpoints)
        }
    }

    @Test
    fun `early and mid-read cancellation return no frozen population or publication`() {
        for (position in listOf(1, 15)) fixture { fixture ->
            val captured = fixture.capture()
            val cancellation = InterruptedException("authored freeze cancellation")
            var seen = 0
            val failure = assertFails {
                fixture.freeze(captured, checkpoint = { if (++seen == position) throw cancellation })
            }
            assertEquals(position, seen)
            assertTrue(generateSequence(failure) { it.cause }.any { it === cancellation })
            fixture.requireUnchanged(captured)
            assertFalse(Files.exists(fixture.root.resolve("result.json")))
        }
    }

    @Test
    fun `raw capture and arbitrary constructor permits cannot manufacture a retained native operation`() = fixture { fixture ->
        val captured = fixture.capture()
        fixture.freeze(captured)
        for (permit in listOf(Any(), captured, fixture.model, "serialized-production-verified")) {
            assertFailsWith<IllegalStateException> {
                GccBundledNativeCallOperation("{}".toByteArray(), byteArrayOf(), byteArrayOf(), fixture.model, captured, permit)
            }
        }
    }

    @Test
    fun `public and synthetic wrapper constructors require guarded operations and reject null or raw substitutes`() {
        val guards = listOf(GccBundledNativeClaimFreezeOperation::class.java to GccBundledNativeCallOperation::class.java,
            GccBundledMachineCallReplayOperation::class.java to GccBundledNativeClaimFreezeOperation::class.java)
        for ((wrapper, requiredGuard) in guards) {
            val constructors = wrapper.constructors
            assertTrue(constructors.isNotEmpty(), "exercise the actual public JVM constructor surface")
            for (constructor in constructors) {
                assertTrue(requiredGuard in constructor.parameterTypes.toList(), "${wrapper.simpleName} must consume its guarded predecessor")
                assertFalse(Boolean::class.javaPrimitiveType in constructor.parameterTypes.toList())
                for (substitute in listOf(null, Any(), "serialized-production-verified")) {
                    val arguments = constructor.parameterTypes.map { type ->
                        when (type) {
                            requiredGuard -> substitute
                            ByteArray::class.java -> "{}".toByteArray()
                            Any::class.java -> Any()
                            else -> null
                        }
                    }.toTypedArray()
                    assertFails { constructor.newInstance(*arguments) }
                }
            }
        }
    }

    @Test
    fun `dual freezes bind identical original bytes model and complete raw census`() = fixture { fixture ->
        val captured = fixture.capture()
        val core = fixture.freeze(captured)
        val external = FrozenNativeExternalClaimsV1.freeze(core.rawManifestBytes, core.rawObservationBytes, captured.summary.bindings)
        requireGccDualNativeFreezeMatches(core, external, captured.summary.bindings)
        assertEquals(9L, external.rawRecordCount)
        assertEquals(3L, external.rawSiteCount)
        assertContentEquals(core.rawManifestBytes, external.rawManifestBytes)
        assertContentEquals(core.rawObservationBytes, external.rawObservationBytes)
        val again = FrozenNativeExternalClaimsV1.freeze(external.rawManifestBytes, external.rawObservationBytes, captured.summary.bindings)
        assertContentEquals(external.canonicalEvidenceBytes, again.canonicalEvidenceBytes)
        external.rawObservationBytes.fill(0)
        requireGccDualNativeFreezeMatches(core, external, captured.summary.bindings)
        assertFalse(external.productionVerified)
    }

    @Test
    fun `dual freeze cannot replace guarded bindings or adopt a different source`() = fixture { fixture ->
        val captured = fixture.capture()
        val core = fixture.freeze(captured)
        val external = FrozenNativeExternalClaimsV1.freeze(core.rawManifestBytes, core.rawObservationBytes, captured.summary.bindings)
        assertFails { requireGccDualNativeFreezeMatches(core, external,
            captured.summary.bindings.copy(programModelSha256 = "0".repeat(64))) }
        fixture.replace("reports/native-calls-v1/native-calls.json")
        assertFails { fixture.requireUnchanged(captured) }
        assertFails { fixture.freeze(captured) }
        assertContentEquals(core.rawObservationBytes, external.rawObservationBytes)
    }

    @Test
    fun `combined external operation has no public raw report or boolean credential constructor`() {
        for (constructor in GccBundledExternalCallReplayOperation::class.java.constructors) {
            assertTrue(GccBundledMachineCallReplayOperation::class.java in constructor.parameterTypes)
            assertFalse(Boolean::class.javaPrimitiveType in constructor.parameterTypes)
            assertFails { constructor.newInstance(*arrayOfNulls<Any>(constructor.parameterCount)) }
        }
    }

    private class Fixture(val root: Path, val run: LinuxDescriptor, val reports: LinuxFileIdentity,
        val control: LinuxFileIdentity, val model: GccBundledFullExportSnapshot) {
        val native: Path = root.resolve("reports/native-calls-v1")
        private val target = GccBundledNativeCallTargetEvidenceV1("f".repeat(64), "x86_64-linux-gnu", model.inputSha256,
            model.inputBytes, 0x400000UL, model.language, model.compilerSpec,
            GccBundledNativeCallAddressSpaceIdentityV1("ram", 1, 64, 1, false, false),
            listOf(FullTreeElfExecutableRange(0UL, 0x1000UL)))
        fun capture() = GccBundledNativeCallCapture.capture(run, reports, CONTROL, control, model, COLLECTOR, target, checkpoint = {})
        fun freeze(captured: GccBundledNativeCallSnapshot, limits: NativeRecoveredCallPopulationLimitsV1 = NativeRecoveredCallPopulationLimitsV1(),
            checkpoint: () -> Unit = {}) = GccBundledNativeCallCapture.freezeRecoveredClaims(run, captured, model, artifacts(), limits, checkpoint)
        fun requireUnchanged(captured: GccBundledNativeCallSnapshot) =
            GccBundledNativeCallCapture.requireUnchanged(run, captured, model, artifacts()) {}
        fun replace(relative: String) {
            val path = root.resolve(relative)
            val replacement = root.resolve("replacement")
            Files.write(replacement, Files.readAllBytes(path))
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
            Files.move(replacement, path, StandardCopyOption.REPLACE_EXISTING)
        }
        fun writeNative() {
            val bytes = OracleJson.canonicalBytes(nativeObject())
            val manifest = OracleJson.canonicalBytes(obj("bytes" to JsonPrimitive(bytes.size),
                "collectorSha256" to JsonPrimitive(COLLECTOR), "file" to JsonPrimitive("native-calls.json"),
                "inputSha256" to JsonPrimitive(model.inputSha256), "kind" to JsonPrimitive("ghidra-native-call-observation-manifest-v1"),
                "programModelSha256" to JsonPrimitive(model.programModelSha256), "schemaVersion" to JsonPrimitive(1),
                "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
            Files.write(native.resolve("native-calls.json"), bytes)
            Files.write(native.resolve("manifest.json"), manifest)
            for (name in listOf("native-calls.json", "manifest.json"))
                Files.setPosixFilePermissions(native.resolve(name), PosixFilePermissions.fromString("rw-------"))
        }
        private fun nativeObject(): JsonObject {
            val entries = listOf(0x400010UL, 0x400020UL, 0x405000UL)
            val functions = entries.map { entry -> obj("recordKind" to JsonPrimitive("function"), "entry" to address(entry),
                "bodyAddressCount" to JsonPrimitive(4), "bodyRangeCount" to JsonPrimitive(1),
                "isThunk" to JsonPrimitive(entry == 0x405000UL),
                "immediateThunkTarget" to if (entry == 0x405000UL) target(0x400020UL) else JsonNull) }
            val sites = listOf(site(0x400011UL, 0x400010UL, 0x400020UL), site(0x400012UL, 0x400010UL, 0x405000UL),
                site(0x400030UL, null, null))
            val summaries = entries.map { entry -> obj("recordKind" to JsonPrimitive("function-summary"), "entry" to address(entry))
                .plusFields(summaryFields(if (entry == 0x400010UL) 2 else 0, if (entry == 0x400010UL) 2 else 0)) }
            val scan = obj("coverage" to JsonPrimitive("all-currently-listed-instructions-and-recovered-functions"),
                "functions" to JsonPrimitive(3), "thunks" to JsonPrimitive(1), "ownedInstructions" to JsonPrimitive(2),
                "unownedInstructions" to JsonPrimitive(1), "sites" to JsonPrimitive(3), "directReferences" to JsonPrimitive(0),
                "neighborhoodReferences" to JsonPrimitive(0), "unownedPrototypeCalls" to JsonPrimitive(1),
                "unownedAnalysisCallCandidates" to JsonPrimitive(0), "unownedDirectTailCandidates" to JsonPrimitive(0))
                .plusFields(summaryFields(3, 3))
            val bindings = obj("collectorSha256" to JsonPrimitive(COLLECTOR), "compilerSpecId" to JsonPrimitive(model.compilerSpec),
                "ghidraArchiveSha256" to JsonPrimitive(model.analysisToolSha256), "imageBase" to address(0x400000UL),
                "inputSha256" to JsonPrimitive(model.inputSha256), "languageId" to JsonPrimitive(model.language),
                "programModelBytes" to JsonPrimitive(model.programModelBytes), "programModelExporterSha256" to JsonPrimitive(model.exporterSha256),
                "programModelSha256" to JsonPrimitive(model.programModelSha256))
            return obj("addressSpaces" to JsonArray(listOf(space())), "bindings" to bindings,
                "policy" to JsonPrimitive("ghidra-native-call-observations-v1"), "records" to JsonArray(functions + sites + summaries),
                "schemaVersion" to JsonPrimitive(1), "summary" to scan)
        }
    }

    private fun fixture(action: (Fixture) -> Unit) {
        val base = Files.createDirectories(Path.of("build/native-claim-freeze-tests").toAbsolutePath().normalize())
        val root = privateDirectory(Files.createTempDirectory(base, "freeze-")).toRealPath()
        try {
            val reports = privateDirectory(Files.createDirectory(root.resolve("reports")))
            val export = privateDirectory(Files.createDirectory(reports.resolve("program_model.json.export")))
            for (name in listOf("planning-batches", "functions", "globals", "types", "failures"))
                privateDirectory(Files.createDirectory(export.resolve(name)))
            val records = listOf(0x400010L to "caller", 0x400020L to "zero_site").map { (address, name) ->
                val id = "fn_${address.toString(16).padStart(16, '0')}"
                val record = "{\n    \"id\": \"$id\",\n    \"name\": \"$name\",\n    \"address\": \"0x${address.toString(16)}\",\n    \"prototype\": \"int $name(void)\",\n    \"extractionStatus\": \"recovered\",\n    \"recoveryAssessment\": \"unassessed\",\n    \"calls\": [],\n    \"referencedGlobals\": [],\n    \"strings\": [],\n    \"decompiledC\": \"int $name(void) { return 1; }\"\n}"
                val producer = record.lines().mapIndexed { index, line -> if (index == 0 || line == "}") "    $line" else "  $line" }.joinToString("\n")
                Files.writeString(export.resolve("functions/$id.json"), producer)
                producer
            }
            Files.writeString(reports.resolve("program_model.json"), "{\n  \"schemaVersion\": 4,\n  \"inputSha256\": \"$INPUT\",\n  \"functions\": [\n${records.joinToString(",\n")}\n  ],\n  \"globals\": [\n  ],\n  \"types\": [\n  ]\n}\n")
            Files.writeString(export.resolve("state.json"), "{\"schemaVersion\":2,\"exporterVersion\":17,\"exporterSha256\":\"$EXPORTER\",\"analysisToolSha256\":\"$ARCHIVE\",\"recoveryMode\":\"full\",\"decompilationWorkers\":1,\"inputSha256\":\"$INPUT\",\"language\":\"x86:LE:64:default\",\"compilerSpec\":\"gcc\",\"semanticStateBinding\":null}\n")
            Files.writeString(reports.resolve("program_model.json.progress.json"), "{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":2,\"total\":2,\"recovered\":2,\"partial\":0,\"failed\":0,\"reused\":0,\"currentFunction\":null}\n")
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
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private companion object {
        val INPUT = OracleArtifacts.sha256("claim-freeze-input".toByteArray())
        val EXPORTER = OracleArtifacts.sha256("claim-freeze-exporter".toByteArray())
        val ARCHIVE = OracleArtifacts.sha256("claim-freeze-archive".toByteArray())
        val COLLECTOR = OracleArtifacts.sha256("claim-freeze-native-collector".toByteArray())
        val CONTROL = "control-${"a".repeat(64)}"
        val RETAINED_FILES = listOf("reports/native-calls-v1/native-calls.json", "reports/native-calls-v1/manifest.json", "reports/program_model.json")
        fun artifacts() = listOf(
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY, Path.of("/fixture/engine"), 1, INPUT),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE, Path.of("/fixture/exporter"), 1, EXPORTER),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE, Path.of("/fixture/archive"), 1, ARCHIVE))
        fun privateDirectory(path: Path) = Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
        fun JsonObject.plusFields(fields: Map<String, JsonElement>) = JsonObject(this + fields)
        fun document(bytes: ByteArray) = OracleJson.parse(bytes).jsonObject
        fun JsonObject.rows(field: String) = (getValue(field) as JsonArray).map { it.jsonObject }
        fun JsonObject.text(field: String) = getValue(field).jsonPrimitive.content
        fun address(offset: ULong) = obj("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(0),
            "offsetBits" to JsonPrimitive(offset.toString(16).padStart(16, '0')))
        fun space() = obj("index" to JsonPrimitive(0), "name" to JsonPrimitive("ram"), "type" to JsonPrimitive(1),
            "sizeBits" to JsonPrimitive(64), "addressableUnitSize" to JsonPrimitive(1), "overlay" to JsonPrimitive(false), "signedOffsets" to JsonPrimitive(false))
        fun target(offset: ULong) = obj("address" to address(offset), "functionEntry" to address(offset), "external" to JsonNull, "memoryBlock" to JsonNull)
        fun summaryFields(instructions: Int, calls: Int) = mapOf("instructionsVisited" to JsonPrimitive(instructions), "prototypeCalls" to JsonPrimitive(calls),
            "analysisCallCandidates" to JsonPrimitive(0), "directTailCandidates" to JsonPrimitive(0), "ordinaryJumpInstructions" to JsonPrimitive(0),
            "unresolvedComputedJumps" to JsonPrimitive(0))
        fun site(offset: ULong, owner: ULong?, targetOffset: ULong?): JsonObject {
            val flow = obj("code" to JsonPrimitive(if (targetOffset == null) 8 else 3),
                "name" to JsonPrimitive(if (targetOffset == null) "COMPUTED_CALL" else "UNCONDITIONAL_CALL"))
            return obj("recordKind" to JsonPrimitive("site"), "address" to address(offset), "owner" to (owner?.let(::address) ?: JsonNull),
                "observationKind" to JsonPrimitive("prototype-call"), "listedLength" to JsonPrimitive(2), "delaySlotDepth" to JsonPrimitive(0),
                "lengthOverridden" to JsonPrimitive(false), "byteStatus" to JsonPrimitive("available"), "instructionBytes" to JsonPrimitive("9090"),
                "prototypeFlow" to flow, "effectiveFlow" to flow, "flowOverride" to JsonPrimitive("NONE"),
                "prototypeFallThrough" to JsonNull, "effectiveFallThrough" to JsonNull,
                "prototypeTargets" to JsonArray(targetOffset?.let { listOf(target(it)) } ?: emptyList()),
                "references" to JsonArray(emptyList()), "referenceNeighborhoods" to JsonArray(emptyList()))
        }
    }
}

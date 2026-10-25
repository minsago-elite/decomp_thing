package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import decompengine.project.ProgramModelJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Authored raw records exercise normalization only; they cannot qualify a native producer. */
class NativeRecoveredCallPopulationV1Test {
    @Test
    fun `full census keeps zero-site functions and every original byte without call authority`() = withFixture { fixture ->
        val frozen = fixture.freeze()
        assertEquals(25L, frozen.rawRecordCount)
        assertEquals(11, frozen.rawSiteCount)
        assertEquals(sha(fixture.observations), frozen.observationsSha256)
        assertEquals(sha(fixture.model), frozen.programModelSha256)
        assertEquals(INPUT, frozen.inputSha256)
        assertFalse(frozen.productionVerified)
        assertContentEquals(fixture.observations, frozen.rawObservationBytes)
        assertContentEquals(fixture.manifest, frozen.rawManifestBytes)
        val raw = document(frozen.rawObservationBytes).rows("records")
        assertEquals(7, raw.count { it.text("recordKind") == "function" })
        assertEquals(7, raw.count { it.text("recordKind") == "function-summary" })
        assertEquals(4, raw.count { it.text("recordKind") == "function-summary" && it["prototypeCalls"] == JsonPrimitive(0) &&
            it["analysisCallCandidates"] == JsonPrimitive(0) && it["directTailCandidates"] == JsonPrimitive(0) })
        val evidence = document(frozen.canonicalEvidenceBytes)
        assertEquals((0..24).toList(), evidence.rows("rawRecords").map { it.text("recordOrdinal").toInt() })
        assertEquals(raw.map { it.text("recordKind") }, evidence.rows("rawRecords").map { it.text("recordKind") })
        assertEquals((7..17).map { "records/$it" }, evidence.rows("claims").map { it.text("recordId") })
        assertEquals(JsonArray((7..17).map { JsonPrimitive("records/$it") }), evidence.getValue("source").jsonObject["recordIds"])
        assertDiagnostic(evidence)
        val projected = document(frozen.project(fixture.boundary()))
        assertEquals(10, projected.rows("sites").size)
        assertEquals(1, projected.rows("exclusions").size)
        assertDiagnostic(projected)
    }

    @Test
    fun `only direct prototype call flows claim the unique exact non-thunk model target`() = withFixture { fixture ->
        for ((code, name) in mapOf(3 to "UNCONDITIONAL_CALL", 4 to "CONDITIONAL_CALL",
            10 to "CALL_TERMINATOR", 14 to "CONDITIONAL_CALL_TERMINATOR")) {
            val selected = fixture.changedSite(0x11) { it.changed("prototypeFlow", flow(code, name)).changed("effectiveFlow", flow(code, name)) }
            val site = document(selected.freeze().project(selected.boundary())).site(0x11)
            assertEquals("internal", site.text("category"))
            assertEquals("recovered", site.text("state"))
            assertEquals(JsonArray(listOf(obj("kind" to JsonPrimitive("function"), "id" to JsonPrimitive(id(0x22))))), site["targets"])
        }
        for ((field, value) in listOf("type" to JsonPrimitive(2), "overlay" to JsonPrimitive(true),
            "signedOffsets" to JsonPrimitive(true), "addressableUnitSize" to JsonPrimitive(2))) {
            val raw = document(fixture.observations)
            val spaces = raw.rows("addressSpaces").mapIndexed { index, space ->
                if (index != 1) space else space.changed(field, value).let {
                    if (field == "addressableUnitSize") it.changed("sizeBits", JsonPrimitive(63)) else it
                }
            }
            val selected = Fixture(fixture.root, fixture.oracle, fixture.model, raw.changed("addressSpaces", JsonArray(spaces)))
            val site = document(selected.freeze().project(selected.boundary())).site(0x11)
            assertEquals(JsonNull, site["targets"], "non-base RAM $field")
            assertEquals("recovered-unknown", site.text("state"))
            assertEquals(nativeCoordinate(0x11), site["instruction"])
        }
    }

    @Test
    fun `analysis tails indirect external and thunk observations stay unknown and retain coordinates`() = withFixture { fixture ->
        val projected = document(fixture.freeze().project(fixture.boundary()))
        for (offset in listOf(0x12L, 0x13L, 0x14L, 0x15L, 0x17L)) {
            val site = projected.site(offset)
            assertEquals("recovered-unknown", site.text("state"), "site 0x${offset.toString(16)}")
            assertEquals(JsonNull, site["targets"])
            assertEquals(if (offset in listOf(0x12L, 0x13L)) nativeCoordinate(offset) else coordinate(offset), site["instruction"])
            assertEquals(1, site.rows("observations").size)
        }
        val raw = document(fixture.freeze().rawObservationBytes).rows("records")
        assertEquals(setOf("prototype-call", "analysis-call-candidate", "direct-tail-candidate"),
            raw.filter { it.text("recordKind") == "site" }.map { it.text("observationKind") }.toSet())
    }

    @Test
    fun `overrides unsupported lengths and delay slots cannot become direct call claims`() = withFixture { fixture ->
        val changes: List<(JsonObject) -> JsonObject> = listOf(
            { it.changed("flowOverride", JsonPrimitive("CALL")) },
            { it.changed("prototypeFlow", flow(16, "CALL_OVERRIDE_UNCONDITIONAL")).changed("effectiveFlow", flow(16, "CALL_OVERRIDE_UNCONDITIONAL")) },
            { it.changed("prototypeFlow", flow(18, "CALLOTHER_OVERRIDE_CALL")).changed("effectiveFlow", flow(18, "CALLOTHER_OVERRIDE_CALL")) },
            { it.changed("lengthOverridden", JsonPrimitive(true)).unsupportedBytes() },
            { it.changed("delaySlotDepth", JsonPrimitive(1)).unsupportedBytes() },
            { it.changed("listedLength", JsonPrimitive(4097)).unsupportedBytes() },
        )
        for (change in changes) {
            val selected = fixture.changedSite(0x11, change)
            val site = document(selected.freeze().project(selected.boundary())).site(0x11)
            assertEquals("recovered-unknown", site.text("state"))
            assertEquals(JsonNull, site["targets"])
        }
    }

    @Test
    fun `near correspondence and identical names never fill an absent exact model target`() = withFixture { fixture ->
        val boundary = fixture.boundary()
        assertEquals(id(0x22), boundary.oracleToRecovered["die-cu0-20-beta"])
        val projected = document(fixture.freeze().project(boundary))
        assertEquals(JsonNull, projected.site(0x16)["targets"])
        assertEquals("recovered-unknown", projected.site(0x16).text("state"))
        assertEquals(id(0x22), projected.site(0x11).rows("targets").single().text("id"))
        val model = ProgramModelJson.readCanonical(fixture.model)
        val renamed = model.copy(functions = model.functions.map { it.copy(name = "same_name") }).toJson().toByteArray()
        val renamedFixture = fixture.withModel(renamed)
        val renamedProjection = document(renamedFixture.freeze().project(renamedFixture.boundary()))
        assertEquals(projected.rows("sites").map { JsonObject(it - "observations") },
            renamedProjection.rows("sites").map { JsonObject(it - "observations") })
    }

    @Test
    fun `unowned synthetic and pre-entry sites preserve original owner and instruction coordinates`() = withFixture { fixture ->
        val projected = document(fixture.freeze().project(fixture.boundary()))
        val preEntry = projected.site(0xe)
        assertEquals(coordinate(0xe), preEntry["instruction"])
        assertEquals(coordinate(0x10), preEntry["rawOwner"])
        assertEquals(JsonPrimitive(id(0x10)), preEntry["callerId"])
        val unowned = projected.site(0x30)
        assertEquals(JsonNull, unowned["callerId"])
        assertEquals(JsonNull, unowned["rawOwner"])
        assertEquals(coordinate(0x30), unowned["instruction"])
        val synthetic = projected.site(0x81)
        assertEquals(JsonPrimitive(id(0x80)), synthetic["callerId"])
        assertEquals(coordinate(0x80), synthetic["rawOwner"])
        assertEquals("synthetic", fixture.boundary().recoveredFunctions.getValue(id(0x80)).status)
    }

    @Test
    fun `exact ignored owners exclude only their sites while retaining original exclusion evidence`() = withFixture { fixture ->
        val frozen = fixture.freeze()
        val boundary = fixture.boundary()
        val projected = document(frozen.project(boundary))
        assertFalse(projected.rows("sites").any { it["instruction"] == coordinate(0x61) })
        val exclusion = projected.rows("exclusions").single()
        assertEquals("recovered", exclusion.text("side"))
        assertEquals(id(0x60), exclusion.text("ownerId"))
        assertEquals(1, exclusion.rows("observations").size)
        assertTrue(document(frozen.rawObservationBytes).rows("records").any {
            it["address"] == addr(0x61) && it["owner"] == addr(0x60)
        })
        val projectedValues = flatten(projected)
        assertTrue(boundary.ignoredRecoveries.getValue(id(0x60)).evidence in projectedValues)
        assertTrue(boundary.excludedFunctions.getValue("symbol-60-clone").evidence in projectedValues)
    }

    @Test
    fun `substituted model manifest stream and expected bindings fail before a frozen population escapes`() = withFixture { fixture ->
        val bindings = fixture.bindings
        for (changed in listOf(bindings.copy(inputSha256 = "f".repeat(64)), bindings.copy(collectorSha256 = "f".repeat(64)),
            bindings.copy(programModelSha256 = "f".repeat(64)), bindings.copy(programModelBytes = bindings.programModelBytes + 1),
            bindings.copy(programModelExporterSha256 = "f".repeat(64)), bindings.copy(ghidraArchiveSha256 = "f".repeat(64)),
            bindings.copy(imageBase = nativeAddress(0x1)), bindings.copy(languageId = "other:LE:64:default"),
            bindings.copy(compilerSpecId = "other"))) {
            assertFails { NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations, fixture.model, changed) }
        }
        assertFails { NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations,
            fixture.model + '\n'.code.toByte(), bindings) }
        assertFails { NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations.dropLast(1).toByteArray(), fixture.model, bindings) }
        assertFails { NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations + ' '.code.toByte(), fixture.model, bindings) }
        for (field in listOf("sha256", "inputSha256", "programModelSha256", "collectorSha256")) {
            val changed = canonical(document(fixture.manifest).changed(field, JsonPrimitive("f".repeat(64))))
            assertFails { NativeRecoveredCallPopulationV1.freeze(changed, fixture.observations, fixture.model, bindings) }
        }
        val changed = canonical(document(fixture.manifest).changed("productionVerified", JsonPrimitive(true)))
        assertFails { NativeRecoveredCallPopulationV1.freeze(changed, fixture.observations, fixture.model, bindings) }
    }

    @Test
    fun `input and returned byte mutation cannot change a frozen population or later projection`() = withFixture { fixture ->
        val observations = fixture.observations.copyOf()
        val manifest = fixture.manifest.copyOf()
        val model = fixture.model.copyOf()
        val frozen = NativeRecoveredCallPopulationV1.freeze(manifest, observations, model, fixture.bindings)
        val boundary = fixture.boundary()
        val evidence = frozen.canonicalEvidenceBytes.copyOf()
        val projection = frozen.project(boundary).copyOf()
        observations.fill(0); manifest.fill(0); model.fill(0)
        frozen.rawObservationBytes.fill(0)
        frozen.rawManifestBytes.fill(0)
        frozen.canonicalEvidenceBytes.fill(0)
        frozen.project(boundary).fill(0)
        assertContentEquals(fixture.observations, frozen.rawObservationBytes)
        assertContentEquals(fixture.manifest, frozen.rawManifestBytes)
        assertContentEquals(evidence, frozen.canonicalEvidenceBytes)
        assertContentEquals(projection, frozen.project(boundary))
    }

    @Test
    fun `projection binds the full model identity partition and selected image base`() = withFixture { fixture ->
        val frozen = fixture.freeze()
        val observation = document(fixture.observation())
        for (changed in listOf(observation.changed("inputSha256", JsonPrimitive("f".repeat(64))),
            observation.changed("programModelSha256", JsonPrimitive("f".repeat(64))),
            observation.changed("programModelBytes", JsonPrimitive(fixture.model.size + 1)),
            observation.changed("selectedModelImageBase", JsonPrimitive("0x400001")))) {
            val boundary = StructuralSelectedBoundaryProjectionV1.fromObservation(observationBytes(changed))
            assertFails { frozen.project(boundary) }
        }
        val result = observation.getValue("result").jsonObject
        for ((field, value) in listOf("recoveredId" to JsonPrimitive("substituted-model-function"),
            "recoveredRva" to JsonPrimitive("0x81"))) {
            val substituted = result.changed("falsePositives", JsonArray(result.rows("falsePositives").map { it.changed(field, value) }))
            val boundary = StructuralSelectedBoundaryProjectionV1.fromObservation(observationBytes(observation.changed("result", substituted)))
            assertFails { frozen.project(boundary) }
        }
        val missing = JsonObject(result + ("falsePositives" to JsonArray(emptyList())))
        assertFails {
            frozen.project(StructuralSelectedBoundaryProjectionV1.fromObservation(observationBytes(observation.changed("result", missing))))
        }
    }

    @Test
    fun `byte site and evidence bounds fail closed while exact bounds and cancellation are honored`() = withFixture { fixture ->
        val evidenceSize = fixture.freeze().canonicalEvidenceBytes.size
        val exact = NativeRecoveredCallPopulationLimitsV1(maximumObservationBytes = fixture.observations.size,
            maximumModelBytes = fixture.model.size, maximumSites = 11, maximumEvidenceBytes = evidenceSize)
        assertEquals(11, NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations, fixture.model,
            fixture.bindings, exact).rawSiteCount)
        for (limits in listOf(exact.copy(maximumObservationBytes = fixture.observations.size - 1),
            exact.copy(maximumModelBytes = fixture.model.size - 1), exact.copy(maximumSites = 10),
            exact.copy(maximumEvidenceBytes = evidenceSize - 1))) {
            assertFails { NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations, fixture.model, fixture.bindings, limits) }
        }
        for (stop in listOf(1, 6)) {
            val cancellation = IllegalStateException("authored cancellation $stop")
            var checkpoints = 0
            val failure = assertFails {
                NativeRecoveredCallPopulationV1.freeze(fixture.manifest, fixture.observations, fixture.model, fixture.bindings,
                    checkpoint = { if (++checkpoints == stop) throw cancellation })
            }
            assertEquals(stop, checkpoints)
            assertTrue(generateSequence(failure) { it.cause }.any { it === cancellation })
        }
    }

    @Test
    fun `frozen diagnostics expose no production capability or negative coverage even after projection`() = withFixture { fixture ->
        val frozen = fixture.freeze()
        assertFalse(frozen.productionVerified)
        assertDiagnostic(document(frozen.canonicalEvidenceBytes))
        val report = document(frozen.project(fixture.boundary()))
        assertEquals(setOf("schemaVersion", "provider", "binding", "source", "sites", "exclusions", "dispositions", "exclusionEvidence",
            "productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAvailable"), report.keys)
        assertDiagnostic(report)
        assertEquals(11, report.rows("dispositions").size)
        assertEquals((7..17).toList(), report.rows("dispositions").map { it.text("recordOrdinal").toInt() })
        for (type in listOf(NativeRecoveredCallPopulationV1::class.java, FrozenNativeRecoveredCallPopulationV1::class.java)) {
            assertTrue(type.methods.none { VerifiedStructuralInputsV1::class.java.isAssignableFrom(it.returnType) })
        }
    }

    @Test
    fun `shared ledger gives direct credit only and conserves every native and independent observation`() = withFixture { fixture ->
        val boundary = fixture.boundary()
        val fragment = document(fixture.freeze().project(boundary))
        val input = ledgerInput(fragment, listOf(0x11, 0x12, 0x13))
        val report = document(StructuralCallPopulationV1.derive(canonical(input), boundary))
        assertEquals(JsonPrimitive(1), report.getValue("metrics").jsonObject["exact"])
        assertEquals(JsonPrimitive(3), report.getValue("metrics").jsonObject["oracleDenominator"])
        assertEquals(JsonPrimitive(10), report.getValue("metrics").jsonObject["recoveredDenominator"])
        assertEquals(mapOf("oracle-11" to "exact", "oracle-12" to "recovered-unknown", "oracle-13" to "recovered-unknown"),
            report.rows("rows").associate { it.text("oracleId") to it.text("outcome") })
        assertEquals(JsonPrimitive(14), report["rawObservationCount"])
        assertEquals(report["rawObservationCount"], report["rawObservationDispositionCount"])
        assertEquals(1, report.rows("exclusions").size)
        for (flag in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAuthenticated"))
            assertEquals(JsonPrimitive(false), report[flag])
        val sites = input.rows("recoveredSites")
        assertFails { StructuralCallPopulationV1.derive(canonical(input.changed("recoveredSites", JsonArray(sites.drop(1)))), boundary) }
        val duplicateRaw = sites.first().changed("id", JsonPrimitive("duplicate-raw-observation"))
        assertFails { StructuralCallPopulationV1.derive(canonical(input.changed("recoveredSites", JsonArray(sites + duplicateRaw))), boundary) }
        assertFails { StructuralCallPopulationV1.derive(canonical(input.changed("exclusions", JsonArray(emptyList()))), boundary) }
    }

    @Test
    fun `identical instruction bits in distinct code or synthetic spaces never align with RAM evidence`() = withFixture { fixture ->
        for ((name, type) in listOf("code" to 2, "other" to 7)) {
            val raw = document(fixture.observations)
            val records = raw.rows("records")
            val original = records.single { it["recordKind"] == JsonPrimitive("site") && it["address"] == addr(0x11) }
            val moved = original.changed("address", addr(BASE + 0x11, 2))
            val ordered = records.filter { it["recordKind"] == JsonPrimitive("function") } +
                records.filter { it["recordKind"] == JsonPrimitive("site") && it !== original } + moved +
                records.filter { it["recordKind"] == JsonPrimitive("function-summary") }
            val space = raw.rows("addressSpaces")[1].changed("index", JsonPrimitive(2))
                .changed("name", JsonPrimitive(name)).changed("type", JsonPrimitive(type))
            val selected = Fixture(fixture.root, fixture.oracle, fixture.model, raw.changed("records", JsonArray(ordered))
                .changed("addressSpaces", JsonArray(raw.rows("addressSpaces") + space)))
            val boundary = selected.boundary()
            val fragment = document(selected.freeze().project(boundary))
            val nativeCoordinate = obj("space" to JsonPrimitive("native-space-2"), "offset" to JsonPrimitive("0x400011"))
            val site = fragment.rows("sites").single { it["instruction"] == nativeCoordinate }
            assertEquals(JsonPrimitive(id(0x10)), site["callerId"])
            assertEquals(JsonPrimitive(id(0x22)), site.rows("targets").single()["id"])
            assertFalse(fragment.rows("sites").any { it["instruction"] == coordinate(0x11) })
            val report = document(StructuralCallPopulationV1.derive(canonical(ledgerInput(fragment, listOf(0x11))), boundary))
            assertEquals(JsonPrimitive(0), report.getValue("metrics").jsonObject["exact"])
            assertEquals("recovered-unknown", report.rows("rows").single().text("outcome"))
            assertTrue(report.rows("unresolvedRecovered").any {
                it["recoveredId"] == site["id"] && it.text("reason") == "unresolved-coordinate-or-pair"
            })
        }
    }

    @Test
    fun `long non-ASCII recovered names and prototypes fit the selected full model envelope`() = withFixture { fixture ->
        val model = ProgramModelJson.readCanonical(fixture.model)
        val longName = "函".repeat(4097)
        val longPrototype = "int $longName(void)"
        val bytes = model.copy(functions = model.functions.map {
            if (it.id == id(0x10)) it.copy(name = longName, prototype = longPrototype) else it
        }).toJson().toByteArray()
        val selected = fixture.withModel(bytes)
        val frozen = selected.freeze()
        assertEquals(sha(bytes), frozen.programModelSha256)
        assertEquals(25L, frozen.rawRecordCount)
        val claims = document(frozen.canonicalEvidenceBytes).rows("claims")
        assertEquals(JsonPrimitive(id(0x22)), claims.single { it["instruction"] == coordinate(0x11) }["targetRecoveredId"])
        assertFalse(document(frozen.canonicalEvidenceBytes).toString().contains(longName))
        assertDiagnostic(document(frozen.canonicalEvidenceBytes))
    }

    @Test
    fun `repeated ignored sites retain Unicode exclusion evidence once and reject insufficient evidence budget`() = withFixture { fixture ->
        val oracle = document(fixture.oracle)
        val alias = "\uD83D\uDE00".repeat(4096)
        val changedOracle = oracle.changed("functions", JsonArray(oracle.rows("functions").map { function ->
            if (function.text("id") != "symbol-60-clone") function else function.changed("aliases",
                JsonArray(function.rows("aliases").map { it.changed("name", JsonPrimitive(alias)) }))
        }))
        Files.write(fixture.root.resolve("function-oracle.json"), canonical(changedOracle))
        val raw = document(fixture.observations)
        val originalSites = raw.rows("records").filter { it["recordKind"] == JsonPrimitive("site") }
        val ignored = originalSites.single { it["address"] == addr(0x61) }
        val extra = listOf(0x62L, 0x63L).map { ignored.changed("address", addr(it)) }
        val sites = (originalSites + extra).sortedBy { it.getValue("address").jsonObject.text("offsetBits") }
        val records = raw.rows("records").filter { it["recordKind"] == JsonPrimitive("function") } + sites +
            raw.rows("records").filter { it["recordKind"] == JsonPrimitive("function-summary") }.map {
                if (it["entry"] != addr(0x60)) it else it.changed("instructionsVisited", JsonPrimitive(3)).changed("prototypeCalls", JsonPrimitive(3))
            }
        var summary = raw.getValue("summary").jsonObject
        for (field in listOf("instructionsVisited", "ownedInstructions", "sites", "prototypeCalls"))
            summary = summary.changed(field, JsonPrimitive(summary.text(field).toLong() + 2))
        val selected = Fixture(fixture.root, canonical(changedOracle), fixture.model,
            raw.changed("records", JsonArray(records)).changed("summary", summary))
        val frozen = selected.freeze()
        val boundary = selected.boundary()
        val projected = document(frozen.project(boundary))
        assertEquals(13, frozen.rawSiteCount)
        assertEquals(3, projected.rows("exclusions").size)
        val evidence = projected.getValue("exclusionEvidence").jsonObject
        assertEquals(setOf(id(0x60)), evidence.getValue("ignoredRecoveries").jsonObject.keys)
        assertEquals(setOf("symbol-60-clone"), evidence.getValue("oracleExclusions").jsonObject.keys)
        val retained = evidence.getValue("oracleExclusions").jsonObject.getValue("symbol-60-clone").jsonObject
        assertEquals(boundary.excludedFunctions.getValue("symbol-60-clone").evidence, retained)
        assertEquals(alias, retained.rows("aliases").single().text("name"))
        assertEquals(1, flatten(projected).count { it == retained })
        val excludedDispositions = projected.rows("dispositions").filter { it.text("disposition") == "explicit-ignored-owner" }
        assertEquals(3, excludedDispositions.size)
        assertTrue(excludedDispositions.all { it["ignoredRecoveryEvidenceId"] == JsonPrimitive(id(0x60)) &&
            it["oracleExclusionEvidenceId"] == JsonPrimitive("symbol-60-clone") })
        val originalEvidenceSize = boundary.ignoredRecoveries.getValue(id(0x60)).canonicalEvidenceBytes.size +
            boundary.excludedFunctions.getValue("symbol-60-clone").canonicalEvidenceBytes.size
        val budget = originalEvidenceSize - 1
        assertTrue(budget > frozen.canonicalEvidenceBytes.size, "fixture must reach the projection evidence budget")
        val constrained = NativeRecoveredCallPopulationV1.freeze(selected.manifest, selected.observations, selected.model,
            selected.bindings, NativeRecoveredCallPopulationLimitsV1(maximumEvidenceBytes = budget))
        val failure = assertFails { constrained.project(boundary) }
        assertTrue(failure.message.orEmpty().contains("unique exclusion evidence exceeds its byte bound"), failure.toString())
    }

    private fun assertDiagnostic(report: JsonObject) {
        for (field in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAvailable"))
            assertEquals(JsonPrimitive(false), report[field], field)
    }

    private class Fixture(val root: Path, val oracle: ByteArray, val model: ByteArray, val raw: JsonObject? = null) {
        val bindings = NativeCallBindingsV1("a".repeat(64), "gcc", "b".repeat(64), nativeAddress(0), INPUT,
            "x86:LE:64:default", model.size.toLong(), "c".repeat(64), sha(model))
        val observations: ByteArray = canonical(raw?.changed("bindings", binding(bindings)) ?: nativeDocument(bindings))
        val manifest: ByteArray = canonical(obj("bytes" to JsonPrimitive(observations.size),
            "collectorSha256" to JsonPrimitive(bindings.collectorSha256), "file" to JsonPrimitive("native-calls.json"),
            "inputSha256" to JsonPrimitive(bindings.inputSha256), "kind" to JsonPrimitive("ghidra-native-call-observation-manifest-v1"),
            "programModelSha256" to JsonPrimitive(bindings.programModelSha256), "schemaVersion" to JsonPrimitive(1),
            "sha256" to JsonPrimitive(sha(observations))))
        fun freeze() = NativeRecoveredCallPopulationV1.freeze(manifest, observations, model, bindings)
        fun observation(): ByteArray = StructuralBoundaryReplayV1.observeSelected(
            StructuralRecoveryV1Inputs.loadFunctionOracle(root.resolve("function-oracle.json")), "rich", model, BASE.toULong()).canonicalBytes
        fun boundary() = StructuralSelectedBoundaryProjectionV1.fromObservation(observation())
        fun changedSite(offset: Long, change: (JsonObject) -> JsonObject): Fixture {
            val current = document(observations)
            val records = current.rows("records").map { if (it["recordKind"] == JsonPrimitive("site") && it["address"] == addr(offset)) change(it) else it }
            return Fixture(root, oracle, model, current.changed("records", JsonArray(records)))
        }
        fun withModel(bytes: ByteArray) = Fixture(root, oracle, bytes, document(observations))
    }

    private fun withFixture(action: (Fixture) -> Unit) {
        fun resource(path: String): ByteArray = checkNotNull(javaClass.getResourceAsStream(path)).use { it.readAllBytes() }
        val oracle = resource("/oracle/structural-v1/function-oracle.json")
        val model = resource("/oracle/structural-boundary-replay-v1/rich-model.json")
        val parent = Files.createDirectories(Path.of("build/tmp/native-recovered-population-tests").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "fixture-")
        try {
            Files.write(root.resolve("function-oracle.json"), oracle)
            setPermissions(root.resolve("function-oracle.json"), "rw-------")
            action(Fixture(root, oracle, model))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private companion object {
        const val BASE = 0x400000L
        val INPUT = "1".repeat(64)
        fun id(rva: Long) = "fn_${(BASE + rva).toString(16).padStart(16, '0')}"
        fun sha(bytes: ByteArray) = OracleArtifacts.sha256(bytes)
        fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value)
        fun document(bytes: ByteArray) = OracleJson.parse(bytes).jsonObject
        fun observationBytes(value: JsonObject) = StructuralJsonEncoder(64 * 1024 * 1024, pretty = true, ensureAscii = true).encode(value)
        fun JsonObject.rows(field: String) = (getValue(field) as JsonArray).map { it.jsonObject }
        fun JsonObject.text(field: String) = getValue(field).jsonPrimitive.content
        fun JsonObject.changed(field: String, value: JsonElement) = JsonObject(this + (field to value))
        fun JsonObject.site(rva: Long) = rows("sites").single { it["instruction"] in setOf(coordinate(rva), nativeCoordinate(rva)) }
        fun JsonObject.unsupportedBytes() = changed("byteStatus", JsonPrimitive("unsupported-boundary")).changed("instructionBytes", JsonNull)
        fun obj(vararg values: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*values))
        fun coordinate(rva: Long) = obj("space" to JsonPrimitive("image"), "offset" to JsonPrimitive("0x${rva.toString(16)}"))
        fun nativeCoordinate(rva: Long) = obj("space" to JsonPrimitive("native-space-1"), "offset" to JsonPrimitive("0x${(BASE + rva).toString(16)}"))
        fun addr(rva: Long, space: Int = 1) = obj("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(space),
            "offsetBits" to JsonPrimitive((if (space == 1) BASE + rva else rva).toULong().toString(16).padStart(16, '0')))
        fun nativeAddress(rva: Long) = NativeCallAddressV1(1, (BASE + rva).toString(16).padStart(16, '0'))
        fun flow(code: Int, name: String) = obj("code" to JsonPrimitive(code), "name" to JsonPrimitive(name))
        fun target(rva: Long) = obj("address" to addr(rva), "functionEntry" to addr(rva), "external" to JsonNull, "memoryBlock" to JsonNull)
        fun binding(value: NativeCallBindingsV1) = obj("collectorSha256" to JsonPrimitive(value.collectorSha256),
            "compilerSpecId" to JsonPrimitive(value.compilerSpecId), "ghidraArchiveSha256" to JsonPrimitive(value.ghidraArchiveSha256),
            "imageBase" to addr(0), "inputSha256" to JsonPrimitive(value.inputSha256), "languageId" to JsonPrimitive(value.languageId),
            "programModelBytes" to JsonPrimitive(value.programModelBytes), "programModelExporterSha256" to JsonPrimitive(value.programModelExporterSha256),
            "programModelSha256" to JsonPrimitive(value.programModelSha256))
        fun flatten(value: JsonElement): List<JsonElement> = listOf(value) + when (value) {
            is JsonObject -> value.values.flatMap(::flatten)
            is JsonArray -> value.flatMap(::flatten)
            else -> emptyList()
        }

        fun ledgerInput(fragment: JsonObject, rvas: List<Long>): JsonObject {
            val oracleSites = rvas.map { rva ->
                val recordId = "oracle-${rva.toString(16)}"
                obj("id" to JsonPrimitive(recordId), "callerId" to JsonPrimitive("die-cu0-10-alpha"),
                    "rawOwner" to coordinate(0x10), "instruction" to coordinate(rva), "return" to JsonNull,
                    "category" to JsonPrimitive("internal"), "state" to JsonPrimitive("observable"),
                    "targets" to JsonArray(listOf(obj("kind" to JsonPrimitive("function"), "id" to JsonPrimitive("die-cu0-20-beta")))),
                    "observations" to JsonArray(listOf(obj("sourceId" to JsonPrimitive("authored-independent-source"), "recordId" to JsonPrimitive(recordId)))))
            }
            val original = canonical(JsonArray(oracleSites))
            val source = obj("id" to JsonPrimitive("authored-independent-source"), "role" to JsonPrimitive("oracle"),
                "sha256" to JsonPrimitive(sha(original)), "bytes" to JsonPrimitive(original.size),
                "policySha256" to JsonPrimitive(sha("authored independent fixture evidence".toByteArray())),
                "recordIds" to JsonArray(oracleSites.map { it.getValue("id") }))
            return obj("provider" to JsonPrimitive("structural-call-population-input-v1"), "schemaVersion" to JsonPrimitive(1),
                "binding" to fragment.getValue("binding"), "sources" to JsonArray(listOf(source, fragment.getValue("source"))),
                "oracleSites" to JsonArray(oracleSites), "recoveredSites" to fragment.getValue("sites"),
                "exclusions" to fragment.getValue("exclusions"), "coverageGaps" to JsonArray(emptyList()))
        }

        fun nativeDocument(bindings: NativeCallBindingsV1): JsonObject {
            val entries = listOf(0x10L, 0x20L, 0x22L, 0x40L, 0x50L, 0x60L, 0x80L)
            val functions = entries.map { rva -> obj("recordKind" to JsonPrimitive("function"), "entry" to addr(rva),
                "bodyAddressCount" to JsonPrimitive(32), "bodyRangeCount" to JsonPrimitive(1), "isThunk" to JsonPrimitive(rva == 0x40L),
                "immediateThunkTarget" to if (rva == 0x40L) target(0x22) else JsonNull) }
            fun site(rva: Long, owner: Long?, target: JsonObject? = target(0x22), code: Int = 3,
                name: String = "UNCONDITIONAL_CALL", kind: String = "prototype-call", effective: JsonObject = flow(code, name)) = obj(
                "recordKind" to JsonPrimitive("site"), "address" to addr(rva), "owner" to (owner?.let { addr(it) } ?: JsonNull),
                "observationKind" to JsonPrimitive(kind), "listedLength" to JsonPrimitive(2), "delaySlotDepth" to JsonPrimitive(0),
                "lengthOverridden" to JsonPrimitive(false), "byteStatus" to JsonPrimitive("available"), "instructionBytes" to JsonPrimitive("9090"),
                "prototypeFlow" to flow(code, name), "effectiveFlow" to effective, "flowOverride" to JsonPrimitive("NONE"),
                "prototypeFallThrough" to JsonNull, "effectiveFallThrough" to JsonNull,
                "prototypeTargets" to JsonArray(listOfNotNull(target)), "references" to JsonArray(emptyList()),
                "referenceNeighborhoods" to JsonArray(emptyList()))
            val external = obj("address" to addr(0x80, 0), "functionEntry" to JsonNull, "memoryBlock" to JsonNull,
                "external" to obj("externalSpaceAddress" to addr(0x80, 0), "externalProgramAddress" to JsonNull,
                    "libraryName" to JsonPrimitive("fixture"), "label" to JsonPrimitive("imported_symbol"),
                    "originalImportedName" to JsonNull, "source" to JsonPrimitive("IMPORTED")))
            val sites = listOf(site(0xe, 0x10), site(0x11, 0x10),
                site(0x12, 0x10, code = 6, name = "COMPUTED_JUMP", kind = "analysis-call-candidate", effective = flow(8, "COMPUTED_CALL")),
                site(0x13, 0x10, code = 1, name = "UNCONDITIONAL_JUMP", kind = "direct-tail-candidate"),
                site(0x14, 0x10, target = null, code = 8, name = "COMPUTED_CALL"), site(0x15, 0x10, target = external),
                site(0x16, 0x10, target = target(0x20)), site(0x17, 0x10, target = target(0x40)),
                site(0x30, null), site(0x61, 0x60), site(0x81, 0x80))
            fun count(selected: List<JsonObject>, kind: String) = selected.count { it.text("observationKind") == kind }
            val summaries = entries.map { rva ->
                val owned = sites.filter { it["owner"] == addr(rva) }
                obj("recordKind" to JsonPrimitive("function-summary"), "entry" to addr(rva),
                    "instructionsVisited" to JsonPrimitive(maxOf(1, owned.size)),
                    "prototypeCalls" to JsonPrimitive(count(owned, "prototype-call")),
                    "analysisCallCandidates" to JsonPrimitive(count(owned, "analysis-call-candidate")),
                    "directTailCandidates" to JsonPrimitive(count(owned, "direct-tail-candidate")),
                    "ordinaryJumpInstructions" to JsonPrimitive(0), "unresolvedComputedJumps" to JsonPrimitive(0))
            }
            val unowned = sites.filter { it["owner"] == JsonNull }
            val ownedInstructions = summaries.sumOf { it.text("instructionsVisited").toLong() }
            val summary = obj("coverage" to JsonPrimitive("all-currently-listed-instructions-and-recovered-functions"),
                "functions" to JsonPrimitive(functions.size), "thunks" to JsonPrimitive(1),
                "instructionsVisited" to JsonPrimitive(ownedInstructions + unowned.size), "ownedInstructions" to JsonPrimitive(ownedInstructions),
                "unownedInstructions" to JsonPrimitive(unowned.size), "sites" to JsonPrimitive(sites.size),
                "prototypeCalls" to JsonPrimitive(count(sites, "prototype-call")), "analysisCallCandidates" to JsonPrimitive(count(sites, "analysis-call-candidate")),
                "directTailCandidates" to JsonPrimitive(count(sites, "direct-tail-candidate")), "ordinaryJumpInstructions" to JsonPrimitive(0),
                "unresolvedComputedJumps" to JsonPrimitive(0), "directReferences" to JsonPrimitive(0), "neighborhoodReferences" to JsonPrimitive(0),
                "unownedPrototypeCalls" to JsonPrimitive(count(unowned, "prototype-call")), "unownedAnalysisCallCandidates" to JsonPrimitive(0),
                "unownedDirectTailCandidates" to JsonPrimitive(0))
            val spaces = listOf("EXTERNAL" to 10, "ram" to 1).mapIndexed { index, (name, type) ->
                obj("index" to JsonPrimitive(index), "name" to JsonPrimitive(name), "type" to JsonPrimitive(type),
                    "sizeBits" to JsonPrimitive(64), "addressableUnitSize" to JsonPrimitive(1), "overlay" to JsonPrimitive(false), "signedOffsets" to JsonPrimitive(false))
            }
            return obj("addressSpaces" to JsonArray(spaces), "bindings" to binding(bindings),
                "policy" to JsonPrimitive("ghidra-native-call-observations-v1"), "records" to JsonArray(functions + sites + summaries),
                "schemaVersion" to JsonPrimitive(1), "summary" to summary)
        }
    }
}

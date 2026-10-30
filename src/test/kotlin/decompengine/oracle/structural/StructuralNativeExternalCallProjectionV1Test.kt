package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.externalcalls.*
import decompengine.project.NativeCallAddressV1
import decompengine.project.ProgramModelJson
import java.nio.file.Files
import kotlin.test.*
import kotlinx.serialization.json.*

/** Real raw component fixtures, plus authored projection witnesses. No live capability is issued. */
class StructuralNativeExternalCallProjectionV1Test {
    @Test fun `projection conserves every raw observation and credits one proved physical external site once`() = fixture { f ->
        val result = f.project()
        val input = doc(result.inputBytes)
        val report = doc(result.reportBytes)
        assertEquals(2, input.rows("oracleSites").size)
        assertEquals(3, input.rows("recoveredSites").size)
        assertEquals(5, input.rows("sources").sumOf { it.getValue("recordIds").jsonArray.size })
        assertEquals(1, report.rows("rows").count { it.text("outcome") == "exact" })
        assertEquals(listOf("external", "indirect"), input.rows("oracleSites").map { it.text("category") })
        assertEquals(JsonNull, input.rows("oracleSites")[1]["targets"], "weak candidate token must receive no credit")
        assertTrue(input.rows("coverageGaps").isNotEmpty())
        assertFalse(result.productionVerified)
        for (key in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAuthenticated"))
            assertEquals(JsonPrimitive(false), report[key])
        val original = result.inputBytes
        result.inputBytes.fill(0)
        assertContentEquals(original, result.inputBytes)
        assertContentEquals(original, f.project().inputBytes)
        assertContentEquals(result.reportBytes, f.project().reportBytes)
    }

    @Test fun `unresolved independent candidate token never becomes an external positive`() = fixture { f ->
        val changed = f.independent.replaceRow("sites", 0) { row -> row + mapOf(
            "compositionDisposition" to str("unresolved-memory-transfer"), "targetBindingDisposition" to str("unresolved-memory-transfer")) }
        val result = f.project(independent = changed)
        assertEquals(0, doc(result.reportBytes).rows("rows").count { it.text("outcome") == "exact" })
        assertEquals(JsonNull, doc(result.inputBytes).rows("oracleSites")[0]["targets"])
    }

    @Test fun `same-node unresolved conflicts and absent recovery targets stay unknown without oracle filling`() = fixture { f ->
        val changed = f.recovered.replaceRow("sites", 0) { row -> row + mapOf(
            "disposition" to str("unresolved-external-node-conflict"), "externalTargetId" to JsonNull) }
        val result = f.project(recovered = changed)
        assertEquals(JsonNull, doc(result.inputBytes).rows("recoveredSites")[0]["targets"])
        assertEquals(0, doc(result.reportBytes).rows("rows").count { it.text("outcome") == "exact" })
        assertFails { f.project(recovered = f.recovered.replaceRow("sites", 0) { it + ("disposition" to str("unresolved-native-flow-or-target")) }) }
    }

    @Test fun `omitted reordered duplicated or changed source ordinals are refused even with recomputed hashes`() = fixture { f ->
        val rows = f.recovered.rows("sites")
        for (changed in listOf(rows.drop(1), rows.reversed(), listOf(rows[0], rows[0], rows[2])))
            assertFails { f.project(recovered = JsonObject(f.recovered + ("sites" to JsonArray(changed)))) }
        assertFails { f.project(independent = f.independent.replaceRow("sites", 0) { it + ("sourceOrdinal" to JsonPrimitive(1)) }) }
        assertFails { f.project(independent = f.independent.replaceRow("sites", 0) { it + ("instructionBytes" to str("e800000000")) }) }
        val fragment = doc(f.core.project(f.boundary))
        val omitted = JsonObject(fragment + ("sites" to JsonArray(fragment.rows("sites").drop(1))))
        assertFails { StructuralNativeExternalCallProjectionV1.projectFrozen(bytes(omitted), f.core.canonicalEvidenceBytes,
            f.frozen, f.boundary, f.machineBytes, bytes(f.independent), bytes(f.recovered), f.namespace) }
    }

    @Test fun `namespace frozen source and original machine commitments cannot be substituted`() = fixture { f ->
        assertFails { f.project(independent = JsonObject(f.independent + ("externalNamespaceSha256" to str("0".repeat(64))))) }
        assertFails { f.project(recovered = JsonObject(f.recovered + ("frozenClaimsSha256" to str("0".repeat(64))))) }
        assertFails { f.project(independent = JsonObject(f.independent + ("sourceReportSha256" to str("0".repeat(64))))) }
        assertFails { f.project(recovered = f.recovered.replaceRow("sites", 0) { it + ("externalTargetId" to str("ext-" + "0".repeat(64))) }) }
    }

    @Test fun `indirect positive witnesses retain physical indirect category and one obligation`() = fixture { f ->
        // Authored positive receipts isolate category algebra; production uses independently validated worker receipts.
        val token = f.recovered.rows("sites")[0].getValue("externalTargetId")
        val independent = f.independent.replaceRow("sites", 1) { it + mapOf("compositionDisposition" to str("static-import-request-reference"),
            "targetBindingDisposition" to str("static-import-request-reference"), "externalTargetId" to token) }
        val recovered = f.recovered.replaceRow("sites", 1) { it + mapOf("disposition" to str("verified-object-local-import-request"), "externalTargetId" to token) }
        val result = f.project(independent, recovered)
        assertEquals(2, doc(result.reportBytes).rows("rows").count { it.text("outcome") == "exact" })
        assertEquals("indirect", doc(result.inputBytes).rows("oracleSites")[1].text("category"))
        assertEquals("indirect", doc(result.inputBytes).rows("recoveredSites")[1].text("category"))
        assertEquals(2, doc(result.inputBytes).rows("oracleSites").size)
    }

    @Test fun `duplicate physical witnesses consolidate all raw refs and conflicts remove credit`() = fixture { f ->
        val machine = doc(f.machineBytes)
        val calls = machine.rows("calls")
        val repeatedMachine = bytes(JsonObject(machine + ("calls" to JsonArray(calls + calls.first()))))
        val sites = f.independent.rows("sites")
        fun independent(extra: JsonObject) = JsonObject(f.independent + mapOf("sourceReportSha256" to str(sha(repeatedMachine)),
            "sites" to JsonArray(sites + JsonObject(extra + ("sourceOrdinal" to JsonPrimitive(2))))))
        val agreed = f.project(independent(sites.first()), machine = repeatedMachine)
        val input = doc(agreed.inputBytes)
        assertEquals(2, input.rows("oracleSites").size)
        assertEquals(2, input.rows("oracleSites").first().getValue("observations").jsonArray.size)
        assertEquals(1, doc(agreed.reportBytes).rows("rows").count { it.text("outcome") == "exact" })
        val contradicted = f.project(independent(JsonObject(sites.first() + mapOf("compositionDisposition" to str("unresolved-memory-transfer"),
            "targetBindingDisposition" to str("unresolved-memory-transfer")))), machine = repeatedMachine)
        assertEquals(0, doc(contradicted.reportBytes).rows("rows").count { it.text("outcome") == "exact" })
        assertEquals(JsonNull, doc(contradicted.inputBytes).rows("oracleSites").first()["targets"])
    }

    @Test fun `projection checks cancellation before returning any composed evidence`() = fixture { f ->
        var count = 0
        assertFailsWith<InterruptedException> { f.project(checkpoint = { if (++count == 4) throw InterruptedException("cancel") }) }
        assertEquals(4, count)
    }

    private data class Fixture(val core: FrozenNativeRecoveredCallPopulationV1, val frozen: FrozenNativeExternalClaimsSnapshotV1,
        val boundary: StructuralSelectedBoundaryProjectionV1, val machineBytes: ByteArray, val independent: JsonObject,
        val recovered: JsonObject, val namespace: JsonObject) {
        fun project(independent: JsonObject = this.independent, recovered: JsonObject = this.recovered,
            machine: ByteArray = machineBytes, checkpoint: () -> Unit = {}) = StructuralNativeExternalCallProjectionV1.project(
            core, frozen, boundary, machine, bytes(independent), bytes(recovered), namespace, checkpoint)
    }
    private fun fixture(action: (Fixture) -> Unit): Unit = withExternalCallFixtureV1 { source ->
        val original = nativeExternalFixtureV1()
        val offsets = mapOf(0x1000UL to 0x400270UL, 0x1100UL to 0x400290UL, 0x1200UL to 0x400200UL,
            0x1010UL to 0x400270UL, 0x1015UL to 0x400275UL, 0x1020UL to 0x400275UL, 0x1026UL to 0x40027bUL,
            0x1300UL to 0x400300UL, 0x2000UL to 0x400828UL)
        fun addresses(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> if (value["kind"] == str("address") && value["spaceIndex"] == JsonPrimitive(1)) {
                val old = value.text("offsetBits").toULong(16)
                JsonObject(value + ("offsetBits" to str((offsets[old] ?: old).toString(16).padStart(16, '0'))))
            } else JsonObject(value.mapValues { addresses(it.value) })
            is JsonArray -> JsonArray(value.map(::addresses))
            else -> value
        }
        fun resource(path: String) = checkNotNull(javaClass.getResourceAsStream(path)).use { it.readAllBytes() }
        val template = ProgramModelJson.readCanonical(resource("/oracle/structural-boundary-replay-v1/rich-model.json"))
        val entries = listOf(0x400270UL, 0x400290UL, 0x400200UL)
        val model = template.copy(inputSha256 = source.inputSha, functions = template.functions.take(3).mapIndexed { index, function ->
            function.copy(id = "fn_" + entries[index].toString(16).padStart(16, '0'), address = entries[index])
        }).toJson().toByteArray()
        val bindings = original.bindings.copy(inputSha256 = source.inputSha, programModelSha256 = sha(model), programModelBytes = model.size.toLong(),
            imageBase = NativeCallAddressV1(1, "0000000000400000"))
        val native = original.copy(document = JsonObject(addresses(original.document).jsonObject +
            ("bindings" to nativeExternalBindingsJsonV1(bindings))), bindings = bindings)
            .withSite(0) { it + ("instructionBytes" to str("e88bffffff")) }
            .withSite(1) { it + ("instructionBytes" to str("ff15ad050000")) }.recount()
        val observations = native.observationBytes()
        val manifest = native.manifestBytes(observations)
        val core = NativeRecoveredCallPopulationV1.freeze(manifest, observations, model, bindings)
        val frozen = FrozenNativeExternalClaimsV1.freeze(manifest, observations, bindings)
        val boundary = StructuralSelectedBoundaryProjectionV1.fromObservation(StructuralBoundaryReplayV1.observeSelected(
            StructuralRecoveryV1Inputs.loadFunctionOracle(source.oracle), "rich", model, 0x400000UL).canonicalBytes)
        val independent = source.produce()
        val rows = independent.rows("sites")
        val recovered = obj("frozenClaimsSha256" to str(frozen.evidenceSha256),
            "externalNamespace" to independent.getValue("externalNamespace"), "externalNamespaceSha256" to independent.getValue("externalNamespaceSha256"),
            "negativeCompleteness" to JsonPrimitive(false), "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "sites" to JsonArray(frozen.sites.mapIndexed { index, raw -> obj("siteId" to str("native-site-${raw.siteOrdinal}"),
                "sourceRecordOrdinal" to JsonPrimitive(raw.recordOrdinal), "sourceSiteOrdinal" to JsonPrimitive(raw.siteOrdinal),
                "frozenDisposition" to str(raw.disposition), "negativeCompleteness" to JsonPrimitive(false),
                "disposition" to str(if (index == 0) "verified-object-local-import-request" else "unresolved-frozen-native-claim"),
                "externalTargetId" to if (index == 0) rows[0].getValue("externalTargetId") else JsonNull) }))
        action(Fixture(core, frozen, boundary, Files.readAllBytes(source.sourceReport), independent, recovered,
            independent.getValue("externalNamespace").jsonObject))
    }
    private companion object {
        fun doc(bytes: ByteArray) = OracleJson.parse(bytes).jsonObject
        fun bytes(value: JsonElement) = OracleJson.canonicalBytes(value)
        fun sha(bytes: ByteArray) = OracleArtifacts.sha256(bytes)
        fun str(value: String) = JsonPrimitive(value)
        fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
        fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
        fun JsonObject.rows(key: String) = getValue(key).jsonArray.map { it.jsonObject }
        fun JsonObject.replaceRow(key: String, index: Int, transform: (JsonObject) -> Map<String, JsonElement>) =
            JsonObject(this + (key to JsonArray(rows(key).mapIndexed { n, row -> if (n == index) JsonObject(transform(row)) else row })))
    }
}

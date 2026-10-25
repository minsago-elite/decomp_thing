package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Authored passive projections only: these fixtures never establish production admission or qualification. */
class StructuralSelectedFunctionAssessmentV1Test {
    @Test
    fun `all typed entities and every function partition survive without upgrading recovery`() {
        val fixture = fixture()
        val overlay = fixture.derive()
        assertEquals(ROOT_FIELDS, overlay.keys)
        assertEquals(JsonPrimitive("passive-derived-overlay"), overlay["authority"])
        assertEquals(JsonPrimitive(StructuralSelectedFunctionAssessmentV1.SCOPE), overlay["scope"])
        assertEquals(JsonPrimitive("unassessed"), overlay["recoveryAssessmentState"])
        assertEquals(JsonPrimitive(false), overlay["complete"])
        assertEquals(JsonPrimitive(false), overlay["releaseEligible"])
        assertEquals(JsonObject(mapOf("state" to JsonPrimitive("uncalibrated"), "probability" to JsonNull)), overlay["calibration"])
        assertFalse("productionVerified" in overlay || "accepted" in overlay || "scored" in overlay)
        val entities = overlay.rows("entities")
        assertEquals(6, entities.size)
        assertEquals(setOf("function" to "shared", "function" to "near", "function" to "extra", "function" to "excluded",
            "global" to "shared", "type" to "shared"), entities.map { it.text("kind") to it.text("id") }.toSet())
        assertTrue(entities.all { it["recoveryAssessment"] == JsonPrimitive("unassessed") })
        assertEquals(setOf("recovered", "partial", "failed", "synthetic"), entities.map { it.text("extractionStatus") }.toSet())
        val functions = entities.filter { it.text("kind") == "function" }.associateBy { it.text("id") }
        assertEquals(mapOf("shared" to "exact", "near" to "near-miss", "extra" to "unmatched", "excluded" to "excluded"),
            functions.mapValues { it.value.obj("functionStart").text("outcome") })
        assertTrue(entities.filter { it.text("kind") != "function" }.all {
            it["functionStart"] == JsonNull && it.getValue("survivingSymbolRows") == JsonArray(emptyList())
        })
        assertEquals(JsonPrimitive(6), overlay.obj("population")["unassessedEntityCount"])
        assertEquals(JsonPrimitive(4), overlay.obj("population")["functionsWithScopedFindings"])
        assertEquals(fixture.score.getValue("boundaryObservation"), overlay["sourceObservation"])
        assertEquals(StructuralFunctionAccuracyV1.derive(fixture.observation), overlay["measurements"])
        assertEquals(listOf("missing"), overlay.rows("oracleOnlyFunctions").map { it.text("oracleId") })
        assertEquals(listOf("generated", "generated-missing", "inline"), overlay.rows("excludedOracleFunctions").map { it.text("oracleId") })
        assertEquals(JsonNull, overlay.obj("sourceObservation").rows("excludedFunctions").last()["rva"])
        for (entity in functions.values) {
            val pointer = entity.obj("functionStart")
            val rows = fixture.observation.obj("result").rows(pointer.text("sourcePartition").substringAfterLast('/'))
            assertEquals(entity["id"], rows[pointer.integer("sourceIndex")]["recoveredId"])
        }
        val symbols = overlay.obj("measurements").obj("survivingSymbolIdentity").rows("symbols")
        assertEquals(6, symbols.size)
        assertEquals(listOf("alpha", "alpha_alias"), functions.getValue("shared").indices("survivingSymbolRows").map { symbols[it].text("name") })
        val excludedSymbol = symbols[functions.getValue("excluded").indices("survivingSymbolRows").single()]
        assertEquals(JsonPrimitive(true), excludedSymbol["oracleExcluded"])
        assertEquals(JsonPrimitive("failed"), excludedSymbol["recoveredStatus"])
        assertEquals(JsonPrimitive(1), overlay.obj("ratios").obj("exactStartPrecision")["numerator"])
        assertEquals(JsonPrimitive(3), overlay.obj("ratios").obj("exactStartPrecision")["denominator"])
        assertEquals(JsonPrimitive("surviving-oracle-aliases"), overlay.obj("ratios").obj("survivingSymbolIdentity")["unit"])
    }

    @Test
    fun `canonical historical and current extraction models produce deterministic defensive passive bytes`() {
        for (version in listOf(1, 2, 4)) {
            val fixture = fixture(model = model().copy(schemaVersion = version))
            val modelBefore = fixture.modelBytes.copyOf()
            val scoreBefore = fixture.scoreBytes.copyOf()
            val first = StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes)
            val retained = first.copyOf()
            first.fill(0)
            val second = StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes)
            assertContentEquals(retained, second)
            assertContentEquals(modelBefore, fixture.modelBytes)
            assertContentEquals(scoreBefore, fixture.scoreBytes)
            val bindings = doc(second).obj("bindings")
            assertEquals(JsonPrimitive(version), bindings["modelSchemaVersion"])
            assertEquals(JsonPrimitive(sha(fixture.modelBytes)), bindings["programModelSha256"])
            assertEquals(JsonPrimitive(sha(fixture.scoreBytes)), bindings["selectedBoundaryScoreSha256"])
        }
    }

    @Test
    fun `near matches remain exact-start misses and empty denominators stay null`() {
        val near = fixture(model = model().copy(functions = listOf(model().functions[1]), globals = emptyList(), types = emptyList()),
            parts = Parts(near = defaultParts().near))
        val overlay = near.derive()
        for (field in listOf("exactStartPrecision", "exactStartRecall", "survivingSymbolIdentity")) {
            assertEquals(JsonPrimitive(0), overlay.obj("ratios").obj(field)["numerator"])
            assertEquals(JsonPrimitive(1), overlay.obj("ratios").obj(field)["denominator"])
        }
        assertEquals(JsonPrimitive("near-miss"), overlay.rows("entities").single().obj("functionStart")["outcome"])
        val empty = fixture(model = model().copy(functions = emptyList()), parts = Parts()).derive()
        assertEquals(2, empty.rows("entities").size)
        for (field in listOf("exactStartPrecision", "exactStartRecall", "survivingSymbolIdentity")) {
            assertEquals(JsonPrimitive(0), empty.obj("ratios").obj(field)["denominator"])
            assertEquals(JsonNull, empty.obj("ratios").obj(field)["value"])
        }
    }

    @Test
    fun `exact model input score and observation wire bindings reject substitution`() {
        val original = fixture()
        for (field in listOf("programModelSha256", "inputSha256", "functionOracleSha256", "boundaryObservationSha256",
            "fullExportBindingSha256")) reject(original.modelBytes, original.score.changed(field, JsonPrimitive(OTHER)))
        reject(original.modelBytes, original.score.changed("programModelBytes", JsonPrimitive(original.modelBytes.size + 1)))
        assertFailsWith<IllegalArgumentException> {
            StructuralSelectedFunctionAssessmentV1.derive(original.modelBytes + byteArrayOf(10), original.scoreBytes)
        }
        // The source observation's legacy ASCII/pretty wire differs from OracleJson canonical UTF-8.
        val unicodeName = "αλφα😀"
        val unicodeModel = model().copy(functions = model().functions.map { if (it.id == "shared") it.copy(name = unicodeName) else it })
        val unicodeParts = defaultParts().let { it.copy(exact = listOf(pair("alpha", "shared", "0x10", "0x10", unicodeName,
            listOf(unicodeName, "alias")))) }
        val unicode = fixture(unicodeModel, unicodeParts)
        unicode.derive()
        assertFalse(sha(bytes(unicode.observation)) == unicode.score.text("boundaryObservationSha256"))
        reject(unicode.modelBytes, unicode.score.changed("boundaryObservationSha256", JsonPrimitive(sha(bytes(unicode.observation)))))
        val wrongInput = model().copy(inputSha256 = OTHER).toJson().toByteArray()
        assertFailsWith<IllegalArgumentException> { StructuralSelectedFunctionAssessmentV1.derive(wrongInput, original.scoreBytes) }
    }

    @Test
    fun `rehashed findings cannot omit duplicate or invent recovered model identities`() {
        val parts = defaultParts()
        // All source population counts are recomputed by the fixture, so omission cannot hide behind a count check.
        assertFailsWith<IllegalArgumentException> { fixture(parts = parts.copy(extra = emptyList())).derive() }
        assertFailsWith<IllegalArgumentException> { fixture(parts = parts.copy(extra = listOf(
            recovered("absent", "0x50", "extra", "synthetic")))).derive() }
        assertFailsWith<IllegalArgumentException> { fixture(parts = parts.copy(extra = listOf(
            recovered("shared", "0x50", "extra", "synthetic")))).derive() }
        val original = fixture()
        val duplicateModel = original.modelBytes.decodeToString().replace("\"id\": \"near\"", "\"id\": \"shared\"").toByteArray()
        assertFailsWith<IllegalArgumentException> { StructuralSelectedFunctionAssessmentV1.derive(duplicateModel, original.scoreBytes) }
    }

    @Test
    fun `rehashed same-identity findings must match model name status address and image base`() {
        val parts = defaultParts()
        for ((field, value) in listOf("recoveredName" to "forged", "recoveredStatus" to "partial", "recoveredRva" to "0x11")) {
            val changed = parts.exact.single().changed(field, JsonPrimitive(value))
            assertFailsWith<IllegalArgumentException> { fixture(parts = parts.copy(exact = listOf(changed))).derive() }
        }
        // Change only an unmatched address: source arithmetic remains internally valid.
        assertFailsWith<IllegalArgumentException> { fixture(parts = parts.copy(extra = listOf(
            parts.extra.single().changed("recoveredRva", JsonPrimitive("0x51"))))).derive() }
        val moved = model().copy(functions = model().functions.map { if (it.id == "extra") it.copy(address = BASE - 1UL) else it })
        assertFailsWith<IllegalArgumentException> { fixture(model = moved).derive() }
        val wrongBase = fixture(transform = { it.changed("selectedModelImageBase", JsonPrimitive("0x400001")) })
        assertFailsWith<IllegalArgumentException> { wrongBase.derive() }
        val original = fixture()
        val rebound = original.score.obj("fullExportBinding").let { binding ->
            binding.changed("programModel", binding.obj("programModel").changed("functionCount", JsonPrimitive(3)))
        }
        reject(original.modelBytes, original.score.changed("fullExportBinding", rebound)
            .changed("fullExportBindingSha256", JsonPrimitive(sha(bytes(rebound)))))
    }

    @Test
    fun `closed source contract rejects extra missing noncanonical and promoted fields`() {
        val fixture = fixture()
        fixture.score.keys.forEach { reject(fixture.modelBytes, JsonObject(fixture.score - it)) }
        for ((field, value) in listOf("extra" to JsonPrimitive(true), "schemaVersion" to JsonPrimitive("1"),
            "scope" to JsonPrimitive("whole-program"), "complete" to JsonPrimitive(true), "releaseEligible" to JsonPrimitive(true),
            "admittedDomains" to JsonArray(listOf(JsonPrimitive("interfaces"))), "unavailableDomains" to JsonArray(emptyList()))) {
            reject(fixture.modelBytes, fixture.score.changed(field, value))
        }
        assertFailsWith<IllegalArgumentException> { fixture(transform = { it.changed("extra", JsonPrimitive(true)) }).derive() }
        assertFailsWith<IllegalArgumentException> { fixture(transform = { it.changed("scored", JsonPrimitive(true)) }).derive() }
        assertFailsWith<IllegalArgumentException> {
            StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes + byteArrayOf(10))
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes,
                fixture.scoreBytes.decodeToString().replaceFirst("{", "{\"schemaVersion\":1,").toByteArray())
        }
    }

    @Test
    fun `combined escaped source and measurement expansion is rejected before census allocation`() {
        // Each existing codec accepts its own bounded input/output. Repeating the recovered name
        // for two alias findings makes the complete overlay exceed 64 MiB after JSON escaping.
        val name = "\u0000".repeat(4 * 1024 * 1024)
        val single = RecoveredProgramModel(schemaVersion = 2, inputSha256 = INPUT,
            functions = listOf(RecoveredFunction("shared", name, BASE + 0x10UL, "int f(void)")))
        val fixture = fixture(single, Parts(exact = listOf(pair("alpha", "shared", "0x10", "0x10", name,
            listOf("alias-one", "alias-two")))))
        var materialized = false
        val failure = assertFailsWith<IllegalArgumentException> {
            StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes) {
                if (it.startsWith("while materializing")) materialized = true
            }
        }
        assertTrue(failure.message.orEmpty().contains("complete output budget"), failure.message)
        assertFalse(materialized)
    }

    @Test
    fun `caller checkpoints cover codecs and reject expired work before returning an overlay`() {
        val fixture = fixture()
        val stages = linkedSetOf<String>()
        val expected = fixture.derive()
        assertEquals(expected, doc(StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes) { stages += it }))
        for (stage in listOf("after selected score parsing", "after canonical model parsing", "after source observation encoding",
            "after function accuracy derivation", "after complete assessment output budget", "after selected assessment encoding")) {
            assertTrue(stage in stages, stage)
            val failure = assertFailsWith<InterruptedException> {
                StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes) {
                    if (it == stage) throw InterruptedException(stage)
                }
            }
            assertEquals(stage, failure.message)
        }
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { StructuralSelectedFunctionAssessmentV1.derive(fixture.modelBytes, fixture.scoreBytes) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    private data class Fixture(val modelBytes: ByteArray, val score: JsonObject) {
        val scoreBytes: ByteArray get() = bytes(score)
        val observation: JsonObject get() = score.obj("boundaryObservation")
        fun derive() = doc(StructuralSelectedFunctionAssessmentV1.derive(modelBytes, scoreBytes))
    }

    private fun fixture(model: RecoveredProgramModel = model(), parts: Parts = defaultParts(),
        transform: (JsonObject) -> JsonObject = { it }): Fixture {
        val modelBytes = model.toJson().toByteArray()
        val observation = transform(observation(modelBytes, parts))
        val binding = JsonObject(mapOf("profileId" to JsonPrimitive("fixture-program"),
            "inputBinary" to JsonObject(mapOf("sha256" to JsonPrimitive(INPUT), "bytes" to JsonPrimitive(1024))),
            "programModel" to JsonObject(mapOf("sha256" to JsonPrimitive(sha(modelBytes)), "bytes" to JsonPrimitive(modelBytes.size),
                "functionCount" to JsonPrimitive(model.functions.size))),
            "targetDescriptor" to JsonObject(mapOf("imageBase" to JsonPrimitive("0x400000")))))
        val source = JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-selected-boundary-production-score-v1"), "schemaVersion" to JsonPrimitive(1),
            "scope" to JsonPrimitive("model-provenance-and-selected-function-boundaries"),
            "admittedDomains" to JsonArray(listOf("model-provenance", "function-boundaries", "surviving-symbol-identities").map(::JsonPrimitive)),
            "profileId" to JsonPrimitive("fixture-program"), "inputSha256" to JsonPrimitive(INPUT),
            "programModelSha256" to JsonPrimitive(sha(modelBytes)), "programModelBytes" to JsonPrimitive(modelBytes.size),
            "fullExportBindingSha256" to JsonPrimitive(sha(bytes(binding))), "fullExportBinding" to binding,
            "functionOracleSha256" to JsonPrimitive(ORACLE),
            "boundaryObservationSha256" to JsonPrimitive(sha(StructuralJsonEncoder(StructuralSelectedFunctionAssessmentV1.MAXIMUM_BYTES,
                pretty = true, ensureAscii = true).encode(observation))), "boundaryObservation" to observation,
            "replayRequestSha256" to JsonPrimitive(OTHER), "replayAttachmentSha256" to JsonPrimitive(OTHER),
            "replayExecutionSha256" to JsonPrimitive(OTHER), "replayCaptureSha256" to JsonPrimitive(OTHER), "replayMetadataSha256" to JsonPrimitive(OTHER),
            "productionVerified" to JsonPrimitive(true), "scored" to JsonPrimitive(true), "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "unavailableDomains" to JsonArray(listOf("interfaces", "calls", "globals", "types", "calibration").map(::JsonPrimitive))))
        return Fixture(modelBytes, source)
    }

    private data class Parts(val exact: List<JsonObject> = emptyList(), val near: List<JsonObject> = emptyList(),
        val extra: List<JsonObject> = emptyList(), val missing: List<JsonObject> = emptyList(),
        val ignored: List<JsonObject> = emptyList(), val excluded: List<JsonObject> = emptyList())

    private fun observation(modelBytes: ByteArray, parts: Parts): JsonObject {
        val recovered = parts.exact + parts.near + parts.extra + parts.ignored
        val matched = parts.exact.size + parts.near.size
        val counts = mapOf("referenceCount" to matched + parts.missing.size, "rawRecoveredCount" to recovered.size,
            "scoredRecoveredCount" to matched + parts.extra.size, "ignoredExcludedCount" to parts.ignored.size,
            "exactMatches" to parts.exact.size, "nearMisses" to parts.near.size, "truePositives" to matched,
            "falsePositives" to parts.extra.size, "falseNegatives" to parts.missing.size,
            "nearMissDistanceBytes" to parts.near.sumOf { kotlin.math.abs(it.integer("deltaBytes")) })
        return JsonObject(mapOf("provider" to JsonPrimitive("selected-twin-boundary-observation-v1"), "schemaVersion" to JsonPrimitive(1),
            "functionOracleSha256" to JsonPrimitive(ORACLE), "twin" to JsonPrimitive("stripped"), "inputSha256" to JsonPrimitive(INPUT),
            "programModelSha256" to JsonPrimitive(sha(modelBytes)), "programModelBytes" to JsonPrimitive(modelBytes.size),
            "selectedModelImageBase" to JsonPrimitive("0x400000"), "executableRvaRanges" to JsonArray(listOf(JsonObject(mapOf(
                "start" to JsonPrimitive("0x0"), "endExclusive" to JsonPrimitive("0x1000"))))), "nearMissBytes" to JsonPrimitive(4),
            "policy" to JsonObject(emptyMap()), "programModelParserLimits" to JsonObject(emptyMap()),
            "excludedFunctions" to JsonArray(parts.excluded), "recoveredOutcomeCounts" to JsonObject(
                listOf("recovered", "partial", "failed", "synthetic").associateWith { status -> JsonPrimitive(recovered.count {
                    it["recoveredStatus"] == JsonPrimitive(status) }) }),
            "result" to JsonObject(mapOf("exactMatches" to JsonArray(parts.exact), "nearMisses" to JsonArray(parts.near),
                "falsePositives" to JsonArray(parts.extra), "falseNegatives" to JsonArray(parts.missing),
                "ignoredExcludedRecoveries" to JsonArray(parts.ignored), "nearMatchAssignment" to JsonObject(emptyMap()),
                "boundaries" to JsonObject(counts.mapValues { JsonPrimitive(it.value) }), "nameRecovery" to JsonObject(emptyMap()))),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false)))
    }

    private fun model() = RecoveredProgramModel(schemaVersion = 2, inputSha256 = INPUT,
        functions = listOf(RecoveredFunction("shared", "alpha", BASE + 0x10UL, "int alpha(void)"),
            RecoveredFunction("near", "beta", BASE + 0x21UL, "undefined beta(void)", status = RecoveryStatus.PARTIAL),
            RecoveredFunction("extra", "extra", BASE + 0x50UL, "int extra(void)", status = RecoveryStatus.SYNTHETIC),
            RecoveredFunction("excluded", "generated", BASE + 0x60UL, "void generated(void)", status = RecoveryStatus.FAILED)),
        globals = listOf(RecoveredGlobal("shared", "unknown", BASE + 0x100UL, "undefined8", status = RecoveryStatus.FAILED)),
        types = listOf(RecoveredType("shared", "typedef unsigned long unresolved;", status = RecoveryStatus.PARTIAL)))

    private fun defaultParts(): Parts {
        val excluded = listOf(exclusion("generated", "0x60", "generated"), exclusion("generated-missing", "0x70", "gone"),
            exclusion("inline", null, "inline", "not-observable"))
        return Parts(exact = listOf(pair("alpha", "shared", "0x10", "0x10", "alpha", listOf("alpha", "alpha_alias"))),
            near = listOf(pair("beta", "near", "0x20", "0x21", "beta", status = "partial")),
            extra = listOf(recovered("extra", "0x50", "extra", "synthetic")), missing = listOf(oracle("missing", "0x30", listOf("lost"))),
            ignored = listOf(JsonObject(recovered("excluded", "0x60", "generated", "failed") + mapOf(
                "oracleId" to JsonPrimitive("generated"), "exclusionKind" to JsonPrimitive("compiler-generated"),
                "exclusionReason" to JsonPrimitive("authored exclusion")))), excluded = excluded)
    }

    private fun pair(oracleId: String, recoveredId: String, oracleRva: String, recoveredRva: String, name: String,
        names: List<String> = listOf(name), status: String = "recovered"): JsonObject {
        val delta = recoveredRva.substring(2).toInt(16) - oracleRva.substring(2).toInt(16)
        return JsonObject(oracle(oracleId, oracleRva, names) + recovered(recoveredId, recoveredRva, name, status) + mapOf(
            "matchKind" to JsonPrimitive(if (delta == 0) "exact" else "near"), "deltaBytes" to JsonPrimitive(delta)))
    }
    private fun oracle(id: String, rva: String, names: List<String>) = JsonObject(mapOf("oracleId" to JsonPrimitive(id),
        "oracleRva" to JsonPrimitive(rva), "oracleAliases" to JsonArray(names.map { alias(it) })))
    private fun recovered(id: String, rva: String, name: String, status: String) = JsonObject(mapOf("recoveredId" to JsonPrimitive(id),
        "recoveredRva" to JsonPrimitive(rva), "recoveredName" to JsonPrimitive(name), "recoveredStatus" to JsonPrimitive(status)))
    private fun alias(name: String, availability: JsonElement = JsonPrimitive("surviving")) = JsonObject(mapOf(
        "name" to JsonPrimitive(name), "availability" to availability, "evidence" to JsonArray(emptyList())))
    private fun exclusion(id: String, rva: String?, name: String, availability: String = "surviving") = JsonObject(mapOf(
        "oracleId" to JsonPrimitive(id), "rva" to (rva?.let(::JsonPrimitive) ?: JsonNull),
        "kind" to JsonPrimitive(if (rva == null) "inlined" else "compiler-generated"), "reason" to JsonPrimitive("authored exclusion"),
        "aliases" to JsonArray(listOf(alias(name, JsonObject(mapOf("rich" to JsonPrimitive(availability), "stripped" to JsonPrimitive(availability))))))))
    private fun reject(model: ByteArray, score: JsonObject) {
        assertFailsWith<IllegalArgumentException> { StructuralSelectedFunctionAssessmentV1.derive(model, bytes(score)) }
    }

    private companion object {
        val INPUT = "1".repeat(64)
        val ORACLE = "2".repeat(64)
        val OTHER = "3".repeat(64)
        const val BASE = 0x400000UL
        val ROOT_FIELDS = setOf("provider", "schemaVersion", "scope", "authority", "recoveryAssessmentState", "complete",
            "releaseEligible", "calibration", "unavailableDomains", "bindings", "entities", "oracleOnlyFunctions",
            "excludedOracleFunctions", "sourceObservation", "measurements", "ratios", "population")
        fun bytes(value: JsonObject): ByteArray = OracleJson.canonicalBytes(value, StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS)
        fun doc(bytes: ByteArray) = OracleJson.parseCanonical(bytes, StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS) as JsonObject
        fun sha(bytes: ByteArray) = OracleArtifacts.sha256(bytes)
        fun JsonObject.obj(field: String) = getValue(field) as JsonObject
        fun JsonObject.rows(field: String) = (getValue(field) as JsonArray).map { it as JsonObject }
        fun JsonObject.text(field: String) = (getValue(field) as JsonPrimitive).content
        fun JsonObject.integer(field: String) = text(field).toInt()
        fun JsonObject.indices(field: String) = (getValue(field) as JsonArray).map { (it as JsonPrimitive).content.toInt() }
        fun JsonObject.changed(field: String, value: JsonElement) = JsonObject(this + (field to value))
    }
}

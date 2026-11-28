package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertEquals
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

class StructuralFunctionAccuracyV1Test {
    @Test
    fun `near-only legacy success gives zero exact start precision recall and identity`() {
        val observation = accuracyObservation(near = listOf(accuracyPair("one", "0x10", "0x11", "one")))
        assertEquals(JsonPrimitive(1), observation.obj("result").obj("boundaries").obj("precision")["numerator"])
        val report = StructuralFunctionAccuracyV1.derive(observation)
        val starts = report.obj("functionStarts")
        assertEquals(accuracyTestRatio(0, 1), starts["precision"])
        assertEquals(accuracyTestRatio(0, 1), starts["recall"])
        assertEquals(JsonPrimitive(1), starts["falsePositives"])
        assertEquals(JsonPrimitive(1), starts["falseNegatives"])
        val identities = report.obj("survivingSymbolIdentity")
        assertEquals(accuracyTestRatio(0, 1), identities["identityRecovery"])
        assertEquals(JsonPrimitive("missing"), identities.rows("symbols").single()["outcome"])
        assertEquals(JsonNull, identities.rows("symbols").single()["recoveredName"])
    }

    @Test
    fun `every surviving alias is counted separately even when a function name matches one`() {
        val pair = accuracyPair("one", "0x10", "0x10", "first", listOf("first", "second"))
        val identity = StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(pair)))
            .obj("survivingSymbolIdentity")
        assertEquals(JsonPrimitive(2), identity["population"])
        assertEquals(JsonPrimitive(1), identity["exact"])
        assertEquals(JsonPrimitive(1), identity["nameMismatch"])
        assertEquals(accuracyTestRatio(1, 2), identity["identityRecovery"])
        assertEquals(listOf("first", "second"), identity.rows("symbols").map { it.text("name") })
        assertEquals(listOf("exact", "name-mismatch"), identity.rows("symbols").map { it.text("outcome") })
    }

    @Test
    fun `oracle alias bound counts Unicode code points like the upstream loader`() {
        val name = "\uD83D\uDE00".repeat(4096)
        val report = StructuralFunctionAccuracyV1.derive(accuracyObservation(
            exact = listOf(accuracyPair("astral", "0x10", "0x10", name))))
        assertEquals(accuracyTestRatio(1, 1), report.obj("survivingSymbolIdentity")["identityRecovery"])
        assertEquals(name, report.obj("survivingSymbolIdentity").rows("symbols").single().text("name"))
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(
                exact = listOf(accuracyPair("astral", "0x10", "0x10", name + "a"))))
        }
    }

    @Test
    fun `unmatched oracle symbols stay in the complete identity denominator`() {
        val observation = accuracyObservation(exact = listOf(accuracyPair("found", "0x10", "0x10", "found")),
            missing = listOf(accuracyOracle("lost", "0x20", listOf("lost"))))
        val report = StructuralFunctionAccuracyV1.derive(observation)
        assertEquals(accuracyTestRatio(1, 2), report.obj("functionStarts")["recall"])
        val identity = report.obj("survivingSymbolIdentity")
        assertEquals(accuracyTestRatio(1, 2), identity["identityRecovery"])
        assertEquals(JsonPrimitive(1), identity["missing"])
        assertEquals(listOf("found", "lost"), identity.rows("symbols").map { it.text("name") })
    }

    @Test
    fun `surviving excluded aliases include both ignored recoveries and missing records`() {
        val found = accuracyExclusion("generated-found", "0x30", listOf("found"))
        val missing = accuracyExclusion("generated-missing", "0x40", listOf("lost"))
        val inline = accuracyExclusion("inline", null, listOf("inline"), "not-observable", "inlined")
        val recovered = accuracyIgnored(found, "found", status = "failed")
        val report = StructuralFunctionAccuracyV1.derive(accuracyObservation(excluded = listOf(found, missing, inline),
            ignored = listOf(recovered)))
        val population = report.obj("oraclePopulation")
        assertEquals(JsonPrimitive(3), population["totalFunctions"])
        assertEquals(JsonPrimitive(0), population["scoreableFunctions"])
        assertEquals(JsonPrimitive(2), population["compilerGenerated"])
        assertEquals(JsonPrimitive(1), population["inlined"])
        assertEquals(accuracyTestRatio(0, 0), report.obj("functionStarts")["precision"])
        val identity = report.obj("survivingSymbolIdentity")
        assertEquals(accuracyTestRatio(1, 2), identity["identityRecovery"])
        val symbols = identity.rows("symbols")
        assertTrue(symbols.all { it["oracleExcluded"] == JsonPrimitive(true) })
        assertEquals(JsonPrimitive("failed"), symbols.first()["recoveredStatus"])
        assertEquals(JsonPrimitive("compiler-generated"), symbols.first().obj("exclusion")["kind"])
        assertEquals(JsonPrimitive("missing"), symbols.last()["outcome"])
        assertEquals(JsonPrimitive("/excludedFunctions"), report.obj("sourcePartitions")["excludedFunctions"])
    }

    @Test
    fun `empty eligible population remains zero over zero and never claims authority or success`() {
        val pair = accuracyPair("removed", "0xffffffffffffffff", "0xffffffffffffffff", "removed", availability = "removed")
        val report = StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(pair)))
        val identity = report.obj("survivingSymbolIdentity")
        assertEquals(accuracyTestRatio(0, 0), identity["identityRecovery"])
        assertEquals(JsonPrimitive(0), identity["population"])
        assertEquals(JsonArray(emptyList()), identity["symbols"])
        assertEquals(accuracyTestRatio(1, 1), report.obj("functionStarts")["precision"])
        for (forbidden in listOf("productionVerified", "scored", "complete", "releaseEligible", "passed", "accepted")) {
            assertFalse(OracleJson.canonicalBytes(report).toString(Charsets.UTF_8).contains("\"$forbidden\""))
        }
    }

    @Test
    fun `negative mismatched and omitted source counts fail closed`() {
        val observation = accuracyObservation(exact = listOf(accuracyPair("one", "0x10", "0x10", "one")))
        for (value in listOf(JsonPrimitive(-1), JsonPrimitive(0), JsonPrimitive("1"), JsonPrimitive(2))) {
            val changed = observation.withResult(observation.obj("result").changed("boundaries",
                observation.obj("result").obj("boundaries").changed("exactMatches", value)))
            assertFailsWith<IllegalArgumentException> { StructuralFunctionAccuracyV1.derive(changed) }
        }
        val omitted = observation.withResult(observation.obj("result").changed("exactMatches", JsonArray(emptyList())))
        assertFailsWith<IllegalArgumentException> { StructuralFunctionAccuracyV1.derive(omitted) }
        val statuses = observation.changed("recoveredOutcomeCounts", JsonObject(mapOf("recovered" to JsonPrimitive(1))))
        assertFailsWith<IllegalArgumentException> { StructuralFunctionAccuracyV1.derive(statuses) }
    }

    @Test
    fun `duplicate oracle recovered alias and exclusion partitions are rejected`() {
        val pair = accuracyPair("one", "0x10", "0x10", "one")
        val duplicateId = accuracyPair("one", "0x20", "0x20", "other")
        val duplicateRva = accuracyPair("other", "0x10", "0x10", "other")
        val duplicateRecoveredId = accuracyPair("other", "0x20", "0x20", "other")
            .changed("recoveredId", pair.getValue("recoveredId"))
        val repeatedAlias = pair.changed("oracleAliases", JsonArray(listOf(accuracyAlias("one"), accuracyAlias("one"))))
        val cases = listOf(
            accuracyObservation(exact = listOf(pair, duplicateId)),
            accuracyObservation(exact = listOf(pair, duplicateRva)),
            accuracyObservation(exact = listOf(pair, duplicateRecoveredId)),
            accuracyObservation(exact = listOf(repeatedAlias)),
            accuracyObservation(exact = listOf(pair), missing = listOf(accuracyOracle("one", "0x20", listOf("one")))),
            accuracyObservation(exact = listOf(pair), extra = listOf(accuracyRecovered("different", "0x10", "one"))),
            accuracyObservation(exact = listOf(pair), excluded = listOf(accuracyExclusion("other", "0x10", listOf("one")))),
            accuracyObservation(excluded = listOf(accuracyExclusion("same", "0x30", listOf("one")),
                accuracyExclusion("same", "0x40", listOf("two")))),
        )
        for (observation in cases) assertFailsWith<IllegalArgumentException> { StructuralFunctionAccuracyV1.derive(observation) }
    }

    @Test
    fun `noncanonical and missing addresses and forged match partitions are rejected`() {
        val pair = accuracyPair("one", "0x10", "0x10", "one")
        for (rva in listOf(JsonPrimitive("0X10"), JsonPrimitive("0x010"), JsonPrimitive("0xA"),
            JsonPrimitive("-0x10"), JsonPrimitive("0x10000000000000000"), JsonPrimitive(16), JsonNull)) {
            assertFailsWith<IllegalArgumentException> {
                StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(pair.changed("oracleRva", rva))))
            }
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(JsonObject(pair - "oracleRva"))))
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(pair.changed("deltaBytes", JsonPrimitive(1)))))
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(near = listOf(pair.changed("matchKind", JsonPrimitive("near")))))
        }
        val excluded = accuracyExclusion("excluded", "0x30", listOf("one"))
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(excluded = listOf(excluded),
                extra = listOf(accuracyRecovered("unignored", "0x30", "one"))))
        }
    }

    @Test
    fun `surviving aliases with a null oracle address never disappear from the population`() {
        val nullAddress = accuracyExclusion("inline", null, listOf("surviving-inline"), kind = "inlined")
        assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(excluded = listOf(nullAddress)))
        }
    }

    @Test
    fun `large repeated exclusion reasons are rejected before unbounded alias expansion`() {
        val excluded = accuracyExclusion("generated", "0x30", (0..255).map { "alias-$it" })
            .changed("reason", JsonPrimitive("x".repeat(1024 * 1024)))
        val failure = assertFailsWith<IllegalArgumentException> {
            StructuralFunctionAccuracyV1.derive(accuracyObservation(excluded = listOf(excluded)))
        }
        assertTrue(failure.message.orEmpty().contains("output budget"))
    }

    @Test
    fun `projection is deterministic across source partition and alias order`() {
        val low = accuracyPair("low", "0x10", "0x10", "a", listOf("b", "a"))
        val high = accuracyPair("high", "0x20", "0x20", "z")
        val first = StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(high, low)))
        val reordered = low.changed("oracleAliases", JsonArray(low.rows("oracleAliases").reversed()))
        val second = StructuralFunctionAccuracyV1.derive(accuracyObservation(exact = listOf(reordered, high)))
        assertEquals(first, second)
        assertEquals(listOf("a", "b", "z"), first.obj("survivingSymbolIdentity").rows("symbols").map { it.text("name") })
    }

    @Test
    fun `historical selected projection retains all denominators and emits alias-level exact identity`() {
        val bytes = checkNotNull(javaClass.getResourceAsStream("/oracle/structural-v1/boundary-score.json")).use { it.readAllBytes() }
        val historical = OracleJson.parse(bytes).jsonObject
        val rich = historical.obj("twins").obj("rich")
        val observation = accuracyObservation(exact = rich.rows("exactMatches"), near = rich.rows("nearMisses"),
            extra = rich.rows("falsePositives"), missing = rich.rows("falseNegatives"),
            ignored = rich.rows("ignoredExcludedRecoveries"), excluded = historical.obj("oracle").rows("excludedFunctions"), twin = "rich")
        val report = StructuralFunctionAccuracyV1.derive(observation)
        assertEquals(accuracyTestRatio(3, 5), report.obj("functionStarts")["precision"])
        assertEquals(accuracyTestRatio(3, 5), report.obj("functionStarts")["recall"])
        assertEquals(JsonPrimitive(7), report.obj("oraclePopulation")["totalFunctions"])
        val identity = report.obj("survivingSymbolIdentity")
        assertEquals(accuracyTestRatio(1, 6), identity["identityRecovery"])
        assertEquals(JsonPrimitive(2), identity["nameMismatch"])
        assertEquals(JsonPrimitive(3), identity["missing"])
    }
}

private fun accuracyObservation(
    exact: List<JsonObject> = emptyList(), near: List<JsonObject> = emptyList(),
    extra: List<JsonObject> = emptyList(), missing: List<JsonObject> = emptyList(),
    ignored: List<JsonObject> = emptyList(), excluded: List<JsonObject> = emptyList(), twin: String = "stripped",
): JsonObject {
    val raw = exact + near + extra + ignored
    val truePositives = exact.size + near.size
    val counts = mapOf("referenceCount" to truePositives + missing.size, "rawRecoveredCount" to raw.size,
        "scoredRecoveredCount" to truePositives + extra.size, "ignoredExcludedCount" to ignored.size,
        "exactMatches" to exact.size, "nearMisses" to near.size, "truePositives" to truePositives,
        "falsePositives" to extra.size, "falseNegatives" to missing.size,
        "nearMissDistanceBytes" to near.sumOf { kotlin.math.abs(it.getValue("deltaBytes").jsonPrimitive.content.toInt()) })
    return JsonObject(mapOf(
        "provider" to JsonPrimitive("selected-twin-boundary-observation-v1"), "schemaVersion" to JsonPrimitive(1),
        "twin" to JsonPrimitive(twin), "nearMissBytes" to JsonPrimitive(4), "excludedFunctions" to JsonArray(excluded),
        "recoveredOutcomeCounts" to JsonObject(listOf("recovered", "partial", "failed", "synthetic")
            .associateWith { status -> JsonPrimitive(raw.count { it["recoveredStatus"] == JsonPrimitive(status) }) }),
        "result" to JsonObject(mapOf(
            "exactMatches" to JsonArray(exact), "nearMisses" to JsonArray(near), "falsePositives" to JsonArray(extra),
            "falseNegatives" to JsonArray(missing), "ignoredExcludedRecoveries" to JsonArray(ignored),
            "boundaries" to JsonObject(counts.mapValues { JsonPrimitive(it.value) } + mapOf(
                "precision" to accuracyTestRatio(truePositives, truePositives + extra.size),
                "recall" to accuracyTestRatio(truePositives, truePositives + missing.size))),
        )),
    ))
}

private fun accuracyPair(id: String, oracleRva: String, recoveredRva: String, name: String,
    names: List<String> = listOf(name), availability: String = "surviving"): JsonObject {
    val oracle = oracleRva.substring(2).toULong(16)
    val recovered = recoveredRva.substring(2).toULong(16)
    val delta = if (recovered >= oracle) (recovered - oracle).toLong() else -(oracle - recovered).toLong()
    return JsonObject(accuracyOracle(id, oracleRva, names, availability) + accuracyRecovered("recovered-$id", recoveredRva, name) + mapOf(
        "matchKind" to JsonPrimitive(if (delta == 0L) "exact" else "near"), "deltaBytes" to JsonPrimitive(delta)))
}
private fun accuracyOracle(id: String, rva: String, names: List<String>, availability: String = "surviving") = JsonObject(mapOf(
    "oracleId" to JsonPrimitive(id), "oracleRva" to JsonPrimitive(rva),
    "oracleAliases" to JsonArray(names.map { accuracyAlias(it, availability) }),
))
private fun accuracyAlias(name: String, availability: String = "surviving") = JsonObject(mapOf(
    "name" to JsonPrimitive(name), "availability" to JsonPrimitive(availability), "evidence" to JsonArray(emptyList()),
))
private fun accuracyRecovered(id: String, rva: String, name: String, status: String = "recovered") = JsonObject(mapOf(
    "recoveredId" to JsonPrimitive(id), "recoveredRva" to JsonPrimitive(rva),
    "recoveredName" to JsonPrimitive(name), "recoveredStatus" to JsonPrimitive(status),
))
private fun accuracyExclusion(id: String, rva: String?, names: List<String>, availability: String = "surviving",
    kind: String = "compiler-generated") = JsonObject(mapOf(
    "oracleId" to JsonPrimitive(id), "rva" to (rva?.let(::JsonPrimitive) ?: JsonNull),
    "aliases" to JsonArray(names.map { name -> accuracyAlias(name).changed("availability", JsonObject(mapOf(
        "rich" to JsonPrimitive(availability), "stripped" to JsonPrimitive(availability)))) }),
    "kind" to JsonPrimitive(kind), "reason" to JsonPrimitive("explicit test exclusion"),
))
private fun accuracyIgnored(exclusion: JsonObject, name: String, status: String = "recovered") = JsonObject(
    accuracyRecovered("recovered-${exclusion.text("oracleId")}", exclusion.text("rva"), name, status) + mapOf(
        "oracleId" to exclusion.getValue("oracleId"), "exclusionKind" to exclusion.getValue("kind"),
        "exclusionReason" to exclusion.getValue("reason")))
private fun accuracyTestRatio(numerator: Int, denominator: Int) = JsonObject(mapOf(
    "numerator" to JsonPrimitive(numerator), "denominator" to JsonPrimitive(denominator)))
private fun JsonObject.obj(field: String): JsonObject = getValue(field).jsonObject
private fun JsonObject.rows(field: String): List<JsonObject> = (getValue(field) as JsonArray).map { it.jsonObject }
private fun JsonObject.text(field: String): String = getValue(field).jsonPrimitive.content
private fun JsonObject.changed(field: String, value: JsonElement): JsonObject = JsonObject(this + (field to value))
private fun JsonObject.withResult(result: JsonObject): JsonObject = changed("result", result)

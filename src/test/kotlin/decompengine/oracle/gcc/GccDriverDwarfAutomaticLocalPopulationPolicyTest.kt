package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfCanonicalShardWriter
import decompengine.oracle.fulltree.BoundedDwarfShardLimits
import decompengine.oracle.fulltree.FullTreeControlException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccDriverDwarfAutomaticLocalPopulationPolicyTest {
    @Test
    fun `checked policy is closed bounded and deterministic`() {
        val input = checkedPolicyBytes()
        val first = GccDriverAutomaticLocalPopulationPolicyV1.load(input)
        input.fill(0)
        val second = GccDriverAutomaticLocalPopulationPolicyV1.load(checkedPolicyBytes())

        assertEquals(GccDriverAutomaticLocalPopulationPolicyV1.POLICY_ID, first.policyId)
        assertEquals("authenticated-raw-dwarf-variable-record", first.inputKind)
        assertEquals("raw-dwarf-variable-record", first.countingUnit)
        assertEquals(listOf("function", "block"), first.allowedScopes)
        assertEquals(listOf("frame-relative", "register"), first.allowedLocationKinds)
        assertEquals(listOf("absent" to emptyList(), "known" to listOf("0")), first.declarationGuard)
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        assertEquals(first.canonicalSha256, second.canonicalSha256)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (first.allowedScopes as MutableList<String>).add("namespace")
        }
        val snapshot = first.canonicalBytes()
        snapshot.fill(0)
        assertContentEquals(second.canonicalBytes(), first.canonicalBytes())
        val parsed = OracleJson.parseCanonical(first.canonicalBytes()).jsonObject
        assertEquals(POLICY_TOP_KEYS, parsed.keys)
        assertFalse(first.canonicalBytes().toString(Charsets.UTF_8).contains("22993"))
        assertFalse(first.canonicalBytes().toString(Charsets.UTF_8).contains("entityId"))
    }

    @Test
    fun `malformed and substituted policies fail closed`() {
        val valid = OracleJson.parse(checkedPolicyBytes()).jsonObject
        val automatic = valid.getValue("automaticProof").jsonObject
        val storage = automatic.getValue("storage").jsonObject
        val declaration = valid.getValue("declarationGuard").jsonObject
        val retained = valid.getValue("retainedDecision").jsonObject
        val mutations = listOf(
            JsonObject(valid + ("unknown" to JsonPrimitive(true))),
            JsonObject(valid - "policyId"),
            JsonObject(valid + ("schema" to JsonPrimitive(1))),
            JsonObject(valid + ("schema" to JsonPrimitive("gcc-driver-automatic-local-population-policy-v2"))),
            JsonObject(valid + ("entityDenominatorEstablished" to JsonPrimitive(true))),
            JsonObject(valid + ("automaticProof" to JsonObject(automatic + ("storage" to
                JsonObject(storage + ("values" to JsonArray(listOf(JsonPrimitive("static-storage"))))))))),
            JsonObject(valid + ("automaticProof" to JsonObject(automatic + ("scope" to
                JsonObject(mapOf("state" to JsonPrimitive("known"), "values" to
                    JsonArray(listOf(JsonPrimitive("function"), JsonPrimitive("function"))))))))),
            JsonObject(valid + ("declarationGuard" to JsonObject(declaration + ("accepted" to JsonArray(listOf(
                JsonObject(mapOf("state" to JsonPrimitive("known"), "values" to JsonArray(listOf(JsonPrimitive("1"))))),
            )))))),
            JsonObject(valid + ("declarationGuard" to JsonObject(declaration + ("predicate" to JsonPrimitive("declaration"))))),
            JsonObject(valid + ("excludedDecision" to JsonObject(mapOf(
                "classification" to JsonPrimitive("retained-raw-candidate"),
                "reason" to JsonPrimitive("positively-proved-automatic-local"),
            )))),
            JsonObject(valid + ("retainedDecision" to JsonObject(retained +
                ("defaultReason" to JsonPrimitive("some-other-reason"))))),
            JsonObject(valid + ("otherExclusions" to JsonPrimitive("regex"))),
        )
        mutations.forEachIndexed { index, mutation ->
            assertPolicyFailure("mutation $index") {
                GccDriverAutomaticLocalPopulationPolicyV1.load(OracleJson.canonicalBytes(mutation))
            }
        }
        assertPolicyFailure("oversized bytes") {
            GccDriverAutomaticLocalPopulationPolicyV1.load(ByteArray(16 * 1024 + 1) { ' '.code.toByte() })
        }
        val oversizedText = checkedPolicyBytes().toString(Charsets.UTF_8)
            .replaceFirst("raw-dwarf-variable-record", "x".repeat(257)).toByteArray()
        assertPolicyFailure("oversized text") { GccDriverAutomaticLocalPopulationPolicyV1.load(oversizedText) }
        val oversizedNodes = JsonObject(valid + ("automaticProof" to JsonObject(mapOf(
            "storage" to JsonArray(List(130) { JsonPrimitive(it) }),
        ))))
        assertPolicyFailure("oversized nodes") {
            GccDriverAutomaticLocalPopulationPolicyV1.load(OracleJson.canonicalBytes(oversizedNodes))
        }
    }

    @Test
    fun `mixed variable facts preserve raw stream order and conserve every decision`() {
        val records = listOf(
            variable("0x10", scope = known("function", "scope:function"), location = location("frame-relative", "location:frame"),
                declaration = absent("declaration:absent"), storage = known("automatic", "storage:auto")),
            variable("0x2", scope = known("block", "scope:block"), location = location("register", "location:register"),
                declaration = known("0", "declaration:zero"), storage = known("automatic", "storage:auto")),
            variable("0x3", declaration = known("1", "declaration:one")),
            variable("0x4", declaration = fact("unknown", emptyList(), listOf("declaration:unknown"), listOf("unresolved"))),
            variable("0x5", declaration = fact("ambiguous", listOf("0", "1"), listOf("declaration:ambiguous"), emptyList())),
            variable("0x6", declaration = known(listOf("0", "1"), "declaration:multiple")),
            variable("0x7", storage = known("static-storage", "storage:static")),
            variable("0x8", storage = known("thread-local", "storage:tls")),
            variable("0x9", location = location("location-list", "location:list", state = "unknown")),
            variable("0xa", location = location("expression-unsupported", "location:composite", state = "unknown")),
            variable("0xb", declaration = known("18446744073709551616", "declaration:wide-positive")),
            variable("0xc", declaration = known("-9223372036854775809", "declaration:wide-negative")),
        )
        val application = apply(records)
        assertEquals(records.map { it.text("locator") }, application.decisions.map { it.text("sourceLocator") })
        assertEquals(listOf("excluded", "excluded") + List(10) { "retained-raw-candidate" },
            application.decisions.map { it.text("classification") })
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[2].text("reason"))
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[3].text("reason"))
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[4].text("reason"))
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[5].text("reason"))
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[10].text("reason"))
        assertEquals("declaration-is-not-a-proved-definition", application.decisions[11].text("reason"))
        assertEquals(listOf("storage:auto", "scope:function", "location:frame", "declaration:absent"),
            application.decisions[0].strings("evidenceLocators"))
        assertEquals(listOf("declaration:one"), application.decisions[2].strings("evidenceLocators"))
        assertNull(application.decisions[2]["provedScope"].takeUnless { it == JsonNull })
        records.zip(application.decisions).forEach { (record, decision) ->
            assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(record)), decision.text("sourceRecordSha256"))
        }
        val counts = application.summary.getValue("counts").jsonObject
        assertEquals(12L, counts.long("rawVariableRecords"))
        assertEquals(2L, counts.long("excludedAutomaticLocalRecords"))
        assertEquals(10L, counts.long("retainedRawCandidateRecords"))
        assertEquals(1L, counts.long("excludedFunctionScopeRecords"))
        assertEquals(1L, counts.long("excludedBlockScopeRecords"))
        assertEquals(1L, counts.long("excludedFrameRelativeRecords"))
        assertEquals(1L, counts.long("excludedRegisterRecords"))
        assertEquals(records.size.toLong(), application.summary.getValue("decisionCommitment").jsonObject.long("recordCount"))
        assertEquals(false, application.summary.getValue("entityDenominatorEstablished").jsonPrimitive.content.toBooleanStrict())

        val duplicateNameRecords = listOf(records[0], variable("0x11", name = "same", scope = known("file"),
            location = location("address", "location:address"), storage = known("static-storage", "storage:static")))
        assertEquals(2, apply(duplicateNameRecords).decisions.size)
    }

    @Test
    fun `rehashed decisions fail against unchanged raw membership and commitments`() {
        val records = listOf(
            variable("0x10"),
            variable("0x2", scope = known("block", "scope:block"), location = location("register", "location:register")),
        )
        val application = apply(records)
        verify(records, application.decisions.asSequence(), application.summary)

        val attacks = listOf(
            application.decisions.drop(1),
            application.decisions + application.decisions.last(),
            application.decisions.reversed(),
            application.decisions.mapIndexed { index, decision -> if (index == 0) JsonObject(decision +
                ("sourceRecordSha256" to JsonPrimitive("f".repeat(64)))) else decision },
            application.decisions.mapIndexed { index, decision -> if (index == 0) JsonObject(decision +
                ("classification" to JsonPrimitive("retained-raw-candidate")) +
                ("reason" to JsonPrimitive("automatic-local-not-positively-proved")) +
                ("provedScope" to JsonNull) + ("provedLocationKind" to JsonNull) +
                ("evidenceLocators" to JsonArray(emptyList()))) else decision },
        )
        attacks.forEachIndexed { index, decisions ->
            assertPolicyFailure("decision attack $index") {
                verify(records, decisions.asSequence(), rehashSummary(application.summary, decisions))
            }
        }
        val alteredRaw = records.mapIndexed { index, record -> if (index == 0) JsonObject(record +
            ("sourceName" to known("evil"))) else record }
        assertPolicyFailure("changed raw record with stale commitment") {
            GccDriverAutomaticLocalPopulationPolicyV1.apply(policy(), alteredRaw.asSequence(), POLICY_SHA, POLICY_BYTES,
                INVENTORY_SHA, rawCommitment(records))
        }
        assertPolicyFailure("duplicate locator") { apply(listOf(records[0], records[0])) }
        assertPolicyFailure("noncanonical locator") { apply(listOf(variable("0x02"))) }
        assertPolicyFailure("backslash-prefixed locator") {
            apply(listOf(JsonObject(records[0] +
                ("locator" to JsonPrimitive("\\.debug_info:cu=0x0:die=0x10")))))
        }
        assertPolicyFailure("malformed declaration") {
            apply(listOf(JsonObject(records[0] + ("declaration" to JsonObject(mapOf(
                "state" to JsonPrimitive("known"), "values" to JsonArray(listOf(JsonPrimitive("0"))),
                "evidence" to JsonArray(emptyList()),
            ))))))
        }
        listOf("junk", "", "-", "+1", "00", "01", "-0", "-01", "1_0", "1.0").forEach { malformed ->
            assertPolicyFailure("noncanonical decimal declaration '$malformed'") {
                apply(listOf(JsonObject(records[0] + ("declaration" to fact(
                    "known", listOf(malformed), emptyList(), emptyList(),
                )))))
            }
        }
    }

    @Test
    fun `policy and decision limits refuse atomically`() {
        val record = variable("0x1")
        assertPolicyFailure("record bound") {
            apply(listOf(record, variable("0x2")), GccDriverAutomaticLocalPopulationLimits(maximumRecords = 1))
        }

        val locationValue = record.getValue("location").jsonObject.getValue("values").jsonArray.single()
        val repeatedEvidence = JsonArray(List(96) { JsonPrimitive("evidence:$it") })
        val repeatedReasons = JsonArray(List(96) { JsonPrimitive("reason:$it") })
        val heavyLocation = JsonObject(record.getValue("location").jsonObject + mapOf(
            "state" to JsonPrimitive("ambiguous"),
            "values" to JsonArray(List(96) { locationValue }),
            "evidence" to repeatedEvidence,
            "reasons" to repeatedReasons,
        ))
        val heavyScopes = JsonArray(List(96) { index -> JsonObject(linkedMapOf(
            "locator" to JsonPrimitive(".debug_info:cu=0x0:die=0x${(index + 0x100).toString(16)}"),
            "tag" to JsonPrimitive("0xb"),
            "name" to fact("ambiguous", listOf("scope-$index", "scope-alt-$index"),
                List(8) { "scope-evidence:$index:$it" }, List(8) { "scope-reason:$index:$it" }),
            "ownerLocator" to record.getValue("locator"),
        )) })
        val heavyRecord = JsonObject(record + mapOf(
            "declaration" to fact("ambiguous", listOf("0", "18446744073709551616"),
                List(96) { "declaration-evidence:$it" }, List(96) { "declaration-reason:$it" }),
            "location" to heavyLocation,
            "scopes" to heavyScopes,
            "origins" to JsonArray(List(96) { JsonPrimitive("origin:$it") }),
            "reasons" to repeatedReasons,
        ))
        val baselineWork = jsonNodes(OracleJson.canonicalBytes(record)).toLong()
        val exactHeavyWork = jsonNodes(OracleJson.canonicalBytes(heavyRecord)).toLong()
        assertTrue(exactHeavyWork > baselineWork * 10, "adversarial arrays must dominate record-level work")
        apply(listOf(heavyRecord), GccDriverAutomaticLocalPopulationLimits(maximumWorkSteps = exactHeavyWork))
        assertPolicyFailure("node-heavy work bound one-over") {
            apply(listOf(heavyRecord), GccDriverAutomaticLocalPopulationLimits(maximumWorkSteps = exactHeavyWork - 1))
        }

        val decision = apply(listOf(record)).decisions.single()
        val envelope = decisionEnvelope(listOf(decision))
        val exactBytes = maxOf(envelope.size.toLong(), OracleJson.canonicalBytes(record).size.toLong())
        val nodeRecords = listOf(record, variable("0x2"))
        val nodeDecisions = apply(nodeRecords).decisions
        val decisionNodes = jsonNodes(decisionEnvelope(nodeDecisions))
        val rawNodes = nodeRecords.sumOf { jsonNodes(OracleJson.canonicalBytes(it)) }
        assertTrue(rawNodes > decisionNodes, "fixture must make aggregate raw nodes the limiting population")
        apply(listOf(record), GccDriverAutomaticLocalPopulationLimits(maximumCanonicalBytes = exactBytes))
        assertPolicyFailure("aggregate byte bound one-over") {
            apply(listOf(record), GccDriverAutomaticLocalPopulationLimits(maximumCanonicalBytes = exactBytes - 1))
        }
        apply(nodeRecords, GccDriverAutomaticLocalPopulationLimits(maximumCanonicalNodes = rawNodes.toLong()))
        assertPolicyFailure("aggregate node bound one-over") {
            apply(nodeRecords, GccDriverAutomaticLocalPopulationLimits(maximumCanonicalNodes = rawNodes.toLong() - 1))
        }

        val records = (1..12).map { variable("0x${it.toString(16)}") }
        val decisions = apply(records).decisions
        val rawMaximum = records.maxOf { OracleJson.canonicalBytes(it).size }
        var exactShards = 0
        val shardByteLimit = rawMaximum.coerceAtLeast(decisionEnvelope(listOf(decisions.first())).size)
        val counter = BoundedDwarfCanonicalShardWriter(BoundedDwarfShardLimits(
            maximumShardBytes = shardByteLimit, maximumTotalBytes = 512L * 1024 * 1024,
            maximumTotalNodes = 16_000_000, maximumShards = 256,
        )) { _, _, _, _ -> exactShards++ }
        counter.write(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND, decisions.asSequence())
        counter.finish()
        assertTrue(exactShards > 1)
        apply(records, GccDriverAutomaticLocalPopulationLimits(
            maximumRecordBytes = shardByteLimit, maximumShards = exactShards,
        ))
        assertPolicyFailure("shard count bound one-over") {
            apply(records, GccDriverAutomaticLocalPopulationLimits(
                maximumRecordBytes = shardByteLimit, maximumShards = exactShards - 1,
            ))
        }
    }

    private fun apply(
        records: List<JsonObject>,
        limits: GccDriverAutomaticLocalPopulationLimits = GccDriverAutomaticLocalPopulationLimits(),
    ) = GccDriverAutomaticLocalPopulationPolicyV1.apply(policy(), records.asSequence(), POLICY_SHA, POLICY_BYTES,
        INVENTORY_SHA, rawCommitment(records), limits)

    private fun verify(records: List<JsonObject>, decisions: Sequence<JsonObject>, summary: JsonObject) =
        GccDriverAutomaticLocalPopulationPolicyV1.verify(policy(), records.asSequence(), POLICY_SHA, POLICY_BYTES,
            INVENTORY_SHA, rawCommitment(records), decisions, summary)

    private fun policy() = GccDriverAutomaticLocalPopulationPolicyV1.load(checkedPolicyBytes())
    private fun checkedPolicyBytes(): ByteArray = Files.readAllBytes(POLICY_PATH)

    private fun variable(
        die: String,
        name: String = "same",
        declaration: JsonObject = absent(),
        scope: JsonObject = known("function", "scope:function"),
        location: JsonObject = location("frame-relative", "location:frame"),
        storage: JsonObject = known("automatic", "storage:auto"),
    ): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(".debug_info:cu=0x0:die=$die"),
        "sourceName" to known(name), "linkageName" to absent(), "language" to absent(), "type" to absent(),
        "external" to absent(), "declaration" to declaration, "artificial" to absent(), "visibility" to absent(),
        "byteSize" to absent(), "alignment" to absent(), "constant" to absent(), "scope" to scope,
        "location" to location, "address" to absent(), "rva" to absent(), "tlsOffset" to absent(), "storage" to storage,
        "scopes" to JsonArray(emptyList()), "origins" to JsonArray(emptyList()), "reasons" to JsonArray(emptyList()),
    ))

    private fun absent(evidence: String? = null) = fact("absent", emptyList(), listOfNotNull(evidence), emptyList())
    private fun known(value: String, evidence: String? = null) = known(listOf(value), evidence)
    private fun known(values: List<String>, evidence: String? = null) = fact("known", values, listOfNotNull(evidence), emptyList())
    private fun fact(state: String, values: List<String>, evidence: List<String>, reasons: List<String>) = JsonObject(linkedMapOf(
        "state" to JsonPrimitive(state), "values" to JsonArray(values.map(::JsonPrimitive)),
        "evidence" to JsonArray(evidence.map(::JsonPrimitive)), "reasons" to JsonArray(reasons.map(::JsonPrimitive)),
    ))
    private fun location(kind: String, evidence: String, state: String = "known") = JsonObject(linkedMapOf(
        "state" to JsonPrimitive(state),
        "values" to JsonArray(listOf(JsonObject(linkedMapOf(
            "sourceLocator" to JsonPrimitive(".debug_info:cu=0x0:die=0x1"),
            "declaredForm" to JsonPrimitive("0x18"), "resolvedForm" to JsonPrimitive("0x18"),
            "kind" to JsonPrimitive(kind), "expressionHex" to JsonNull, "operand" to JsonNull,
        )))),
        "evidence" to JsonArray(listOf(JsonPrimitive(evidence))), "reasons" to JsonArray(emptyList()),
    ))

    private fun rawCommitment(records: List<JsonObject>): JsonObject {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("bounded-dwarf-observation-records-v1\nglobals\n".toByteArray())
        var bytes = 0L
        records.forEach { record ->
            val encoded = OracleJson.canonicalBytes(record)
            digest.update(1.toByte()); digest.update(ByteBuffer.allocate(8).putLong(encoded.size.toLong()).array()); digest.update(encoded)
            bytes += encoded.size
        }
        digest.update(0.toByte()); digest.update(ByteBuffer.allocate(8).putLong(records.size.toLong()).array())
        return JsonObject(linkedMapOf(
            "kind" to JsonPrimitive("globals"), "recordCount" to JsonPrimitive(records.size),
            "canonicalBytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(hex(digest.digest())),
        ))
    }

    private fun rehashSummary(summary: JsonObject, decisions: List<JsonObject>): JsonObject {
        // This models an attacker updating visible hashes/counts. Semantic verification still rederives from raw records.
        val commitment = summary.getValue("decisionCommitment").jsonObject
        val fakeCommitment = JsonObject(commitment +
            ("recordCount" to JsonPrimitive(decisions.size)) +
            ("canonicalBytes" to JsonPrimitive(decisions.sumOf { OracleJson.canonicalBytes(it).size })) +
            ("sha256" to JsonPrimitive(OracleArtifacts.sha256(decisions.flatMap { OracleJson.canonicalBytes(it).asIterable() }.toByteArray()))))
        val unsigned = JsonObject(summary - "applicationSha256" + ("decisionCommitment" to fakeCommitment))
        return JsonObject(unsigned + ("applicationSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))))
    }

    private fun decisionEnvelope(decisions: List<JsonObject>): ByteArray = OracleJson.canonicalBytes(JsonObject(linkedMapOf(
        "schema" to JsonPrimitive("bounded-dwarf-record-shard-v1"),
        "kind" to JsonPrimitive(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND),
        "ordinal" to JsonPrimitive(0), "recordCount" to JsonPrimitive(decisions.size),
        "records" to JsonArray(decisions),
    )))
    private fun jsonNodes(bytes: ByteArray): Int {
        var count = 0
        fun visit(value: JsonElement) {
            count++
            when (value) {
                is JsonObject -> value.values.forEach(::visit)
                is JsonArray -> value.forEach(::visit)
                else -> Unit
            }
        }
        visit(OracleJson.parseCanonical(bytes))
        return count
    }

    private inline fun assertPolicyFailure(label: String, block: () -> Unit) {
        val failure = assertFailsWith<FullTreeControlException>(label, block)
        assertTrue(failure.message.orEmpty().startsWith("GCC driver automatic-local policy: "), "$label: ${failure.message}")
    }
    private fun JsonObject.text(field: String) = getValue(field).jsonPrimitive.content
    private fun JsonObject.strings(field: String) = getValue(field).jsonArray.map { it.jsonPrimitive.content }
    private fun JsonObject.long(field: String) = getValue(field).jsonPrimitive.content.toLong()

    private companion object {
        val POLICY_PATH: Path = Path.of("oracle/gcc/16.2.0/automatic-local-population-policy-v1.json")
        val POLICY_BYTES: Long = Files.size(POLICY_PATH)
        val POLICY_SHA: String = OracleArtifacts.sha256(Files.readAllBytes(POLICY_PATH))
        const val INVENTORY_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val POLICY_TOP_KEYS = setOf("automaticProof", "countingUnit", "declarationGuard", "entityDenominatorEstablished",
            "excludedDecision", "inputKind", "otherExclusions", "policyId", "retainedDecision", "schema")
    }
}

private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

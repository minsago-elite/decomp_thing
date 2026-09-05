package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallObservationsTest {
    @Test
    fun `current v4 policy is deterministic and historical v2 and v3 identities remain frozen`() {
        val fixture = fixture()
        val first = FullTreeCallObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        )
        val second = FullTreeCallObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        )

        assertEquals(CALL_OBSERVATION_CONFIGURATION, FullTreeCallObservations.configurationSha256)
        assertEquals("a9c1553036d66122fc108a1599fe209c4d03f47fc94343f002a12c8cd1f55f11",
            FullTreeCallObservations.historicalV3ConfigurationSha256)
        assertEquals(
            HISTORICAL_V2_CALL_OBSERVATION_CONFIGURATION,
            FullTreeCallObservations.historicalV2ConfigurationSha256,
        )
        assertEquals(
            listOf("clang-lib-driver", "generated-tools-clang"),
            first.map(FullTreeCallObservationShardInput::identifier),
        )
        assertEquals(
            listOf(
                "e2edd67fca6549988298753cd273ea21e5e4ddc26bfbf9c7b044f69a19e00b55",
                "5ab4b714392fc30aba5899035b3fcba61e0af611925559ddddb82cb9ac74ccc8",
            ),
            first.map(FullTreeCallObservationShardInput::inputSha256),
        )
        assertEquals(
            listOf(
                "edd82c2bf99fb0f975654d34d1a30042718955e5e29a1f483ef929ca16a89cdc",
                "2e3e2bcbb42e1d8d3f89fa5217907567e666ccdaaaeeb134fd6e8a0c55797c96",
            ),
            first.map { input ->
                FullTreeCallObservations.historicalV2InputSha256(
                    fixture.inventory.string("indexSha256"),
                    FullTreeCallObservations.historicalV2ConfigurationSha256,
                    fixture.scope.objectValue("oracle").string("richArtifactSha256"),
                    fixture.scopeSha256,
                    input.identifier,
                    input.units,
                )
            },
        )
        assertEquals(first.map { it.identifier to it.inputSha256 }, second.map { it.identifier to it.inputSha256 })
        assertEquals(first.map(FullTreeCallObservationShardInput::units), second.map(FullTreeCallObservationShardInput::units))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (first as MutableList<FullTreeCallObservationShardInput>).clear()
        }

        val selected = first.single { it.identifier == "clang-lib-driver" }
        val mutableUnit = selected.units.single().toMutableMap()
        val snapshot = FullTreeCallObservationShardInput(
            selected.identifier,
            selected.inputSha256,
            listOf(JsonObject(mutableUnit)),
        )
        mutableUnit["sourcePath"] = JsonPrimitive("source/substituted.cpp")
        assertEquals("source/clang/lib/Driver/main.cpp", snapshot.units.single().string("sourcePath"))
    }

    @Test
    fun `valid scored and unobservable observations reconcile against authenticated controls`() {
        val fixture = fixture()
        val input = fixture.input("clang-lib-driver")

        validate(observationDocument(fixture, input), fixture, input)
    }

    @Test
    fun `validator rejects hostile binding identity ownership ordering count and target mutations`() {
        val fixture = fixture()
        val input = fixture.input("clang-lib-driver")
        val valid = observationDocument(fixture, input)

        val badBinding = JsonObject(valid.toMutableMap().apply {
            val oracle = valid.objectValue("oracle")
            this["oracle"] = JsonObject(oracle.toMutableMap().apply {
                this["configurationSha256"] = JsonPrimitive("0".repeat(64))
            })
        })
        assertFailsWithMessage("bindings") { validate(badBinding, fixture, input) }

        val firstCall = valid.array("calls").first() as JsonObject
        val wrongIdentity = replaceCall(
            valid,
            0,
            JsonObject(firstCall.toMutableMap().apply {
                this["id"] = JsonPrimitive("call-${"f".repeat(32)}")
            }),
        )
        assertFailsWithMessage("identity") { validate(wrongIdentity, fixture, input) }

        val outsideOwner = replaceCall(
            valid,
            0,
            JsonObject(firstCall.toMutableMap().apply {
                this["unitId"] = JsonPrimitive("cu-${"f".repeat(32)}")
            }),
        )
        assertFailsWithMessage("outside its shard") { validate(outsideOwner, fixture, input) }

        val calls = valid.array("calls")
        val reversed = JsonObject(valid.toMutableMap().apply { this["calls"] = JsonArray(calls.reversed()) })
        assertFailsWithMessage("canonically ordered") { validate(reversed, fixture, input) }

        val badCounts = JsonObject(valid.toMutableMap().apply {
            val counts = valid.objectValue("counts")
            this["counts"] = JsonObject(counts.toMutableMap().apply {
                this["observedCallSites"] = JsonPrimitive(3)
            })
        })
        assertFailsWithMessage("counts") { validate(badCounts, fixture, input) }

        val scoredIndex = calls.indexOfFirst { (it as JsonObject).string("population") == "scored" }
        val scored = calls[scoredIndex] as JsonObject
        val wrongOffset = replaceCall(
            valid,
            scoredIndex,
            JsonObject(scored.toMutableMap().apply {
                this["callerLocalReturnOffset"] = JsonPrimitive("0x5")
            }),
        )
        assertFailsWithMessage("does not reconcile") { validate(wrongOffset, fixture, input) }

        val contradictoryTarget = replaceCall(
            valid,
            scoredIndex,
            JsonObject(scored.toMutableMap().apply {
                val target = scored.objectValue("target")
                this["target"] = JsonObject(target.toMutableMap().apply {
                    this["dispatchKind"] = JsonPrimitive("indirect-unresolved")
                })
            }),
        )
        assertFailsWithMessage("contradictory") { validate(contradictoryTarget, fixture, input) }

        val unprovenIndirect = replaceCall(
            valid,
            scoredIndex,
            JsonObject(scored.toMutableMap().apply {
                val target = scored.objectValue("target")
                this["target"] = JsonObject(target.toMutableMap().apply {
                    this["aliases"] = JsonArray(emptyList())
                    this["dispatchKind"] = JsonPrimitive("indirect-proven")
                    this["functionId"] = JsonNull
                    this["kind"] = JsonPrimitive("indirect-proven")
                    this["originDieOffset"] = JsonNull
                    this["provenFunctionIds"] = JsonArray(listOf(JsonPrimitive("function-rva-0x20")))
                    this["targetEvidence"] = JsonPrimitive("none")
                })
            }),
        )
        assertFailsWithMessage("proven indirect") { validate(unprovenIndirect, fixture, input) }

        val forged = FullTreeCallObservationShardInput(
            input.identifier,
            "a".repeat(64),
            input.units,
        )
        assertFailsWithMessage("not authenticated") { validate(valid, fixture, forged) }
    }

    private fun observationDocument(
        fixture: Fixture,
        input: FullTreeCallObservationShardInput,
    ): JsonObject {
        val unitId = input.units.single().string("id")
        val calls = listOf(
            call(
                callerId = "function-rva-0x10",
                callerLocalReturnOffset = "0x4",
                dieOffset = "0x40",
                population = "scored",
                reasonCode = null,
                returnPcRva = "0x14",
                tailCall = false,
                target = JsonObject(
                    mapOf(
                        "aliases" to JsonArray(listOf(JsonPrimitive("callee"))),
                        "dispatchKind" to JsonPrimitive("direct"),
                        "functionId" to JsonPrimitive("function-rva-0x20"),
                        "kind" to JsonPrimitive("direct-internal"),
                        "originDieOffset" to JsonPrimitive("0x50"),
                        "provenFunctionIds" to JsonArray(emptyList()),
                        "targetEvidence" to JsonPrimitive("call-target-expression"),
                    ),
                ),
                unitId = unitId,
            ),
            call(
                callerId = null,
                callerLocalReturnOffset = null,
                dieOffset = "0x48",
                population = "unobservable",
                reasonCode = "call-site-no-address",
                returnPcRva = null,
                tailCall = true,
                target = JsonObject(
                    mapOf(
                        "aliases" to JsonArray(emptyList()),
                        "dispatchKind" to JsonPrimitive("indirect-unresolved"),
                        "functionId" to JsonNull,
                        "kind" to JsonPrimitive("indirect-unresolved"),
                        "originDieOffset" to JsonNull,
                        "provenFunctionIds" to JsonArray(emptyList()),
                        "targetEvidence" to JsonPrimitive("none"),
                    ),
                ),
                unitId = unitId,
            ),
        ).sortedWith { left, right -> FULL_TREE_CODE_POINT_ORDER.compare(left.string("id"), right.string("id")) }
        return JsonObject(
            mapOf(
                "calls" to JsonArray(calls),
                "counts" to JsonObject(
                    mapOf(
                        "observedCallSites" to JsonPrimitive(calls.size),
                        "scannedDies" to JsonPrimitive(3),
                        "scored" to JsonPrimitive(1),
                        "units" to JsonPrimitive(1),
                        "unobservable" to JsonPrimitive(1),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "configurationSha256" to JsonPrimitive(CALL_OBSERVATION_CONFIGURATION),
                        "inventoryIndexSha256" to fixture.inventory["indexSha256"]!!,
                        "richArtifactSha256" to fixture.scope.objectValue("oracle")["richArtifactSha256"]!!,
                        "scopeSha256" to JsonPrimitive(fixture.scopeSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(2),
                "shard" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(input.identifier),
                        "inputSha256" to JsonPrimitive(input.inputSha256),
                    ),
                ),
            ),
        )
    }

    private fun call(
        callerId: String?,
        callerLocalReturnOffset: String?,
        dieOffset: String,
        population: String,
        reasonCode: String?,
        returnPcRva: String?,
        tailCall: Boolean,
        target: JsonObject,
        unitId: String,
    ): JsonObject {
        val identity = JsonObject(
            mapOf(
                "caller" to (callerId?.removePrefix("function-rva-")?.let(::JsonPrimitive) ?: JsonNull),
                "die" to JsonPrimitive(dieOffset),
                "call" to JsonNull,
                "return" to (returnPcRva?.let(::JsonPrimitive) ?: JsonNull),
                "unit" to JsonPrimitive(unitId),
            ),
        )
        return JsonObject(
            mapOf(
                "callerId" to (callerId?.let(::JsonPrimitive) ?: JsonNull),
                "callerLocalCallOffset" to JsonNull,
                "callPcRva" to JsonNull,
                "callerLocalReturnOffset" to (callerLocalReturnOffset?.let(::JsonPrimitive) ?: JsonNull),
                "dieOffset" to JsonPrimitive(dieOffset),
                "id" to JsonPrimitive(
                    "call-${OracleArtifacts.sha256(OracleJson.canonicalBytes(identity)).take(32)}",
                ),
                "population" to JsonPrimitive(population),
                "reasonCode" to (reasonCode?.let(::JsonPrimitive) ?: JsonNull),
                "returnPcRva" to (returnPcRva?.let(::JsonPrimitive) ?: JsonNull),
                "tailCall" to JsonPrimitive(tailCall),
                "target" to target,
                "unitId" to JsonPrimitive(unitId),
            ),
        )
    }

    private fun fixture(): Fixture {
        val scopeBytes = fullTreeControlResource("scope.json")
        val inventoryBytes = fullTreeControlResource("inventory.json")
        return Fixture(
            scope = OracleJson.parseCanonical(scopeBytes) as JsonObject,
            scopeSha256 = OracleArtifacts.sha256(scopeBytes),
            inventory = OracleJson.parseCanonical(inventoryBytes) as JsonObject,
            inventoryArtifactSha256 = OracleArtifacts.sha256(inventoryBytes),
        )
    }

    private fun Fixture.input(identifier: String): FullTreeCallObservationShardInput =
        FullTreeCallObservations.shardInputs(
            inventory,
            inventoryArtifactSha256,
            scope,
            scopeSha256,
        ).single { it.identifier == identifier }

    private fun validate(
        document: JsonObject,
        fixture: Fixture,
        input: FullTreeCallObservationShardInput,
    ) {
        FullTreeCallObservations.validateEnvelope(
            document,
            fixture.scope,
            fixture.scopeSha256,
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            input,
        )
    }

    private fun replaceCall(document: JsonObject, index: Int, replacement: JsonObject): JsonObject =
        JsonObject(document.toMutableMap().apply {
            val calls = document.array("calls").toMutableList()
            calls[index] = replacement
            this["calls"] = JsonArray(calls)
        })

    private fun assertFailsWithMessage(fragment: String, block: () -> Unit) {
        val failure = assertFailsWith<FullTreeCallObservationException> { block() }
        assertTrue(failure.message.orEmpty().contains(fragment), failure.message)
    }

    private fun JsonObject.objectValue(name: String): JsonObject = this[name] as JsonObject
    private fun JsonObject.array(name: String): JsonArray = this[name] as JsonArray
    private fun JsonObject.string(name: String): String = (this[name] as JsonPrimitive).content

    private data class Fixture(
        val scope: JsonObject,
        val scopeSha256: String,
        val inventory: JsonObject,
        val inventoryArtifactSha256: String,
    )

    private companion object {
        const val CALL_OBSERVATION_CONFIGURATION =
            "ec32478cfea2b28fd284d2fbe7a66eb0bc5eaf27e1b3498c93e4e2082f7b2bab"
        const val HISTORICAL_V2_CALL_OBSERVATION_CONFIGURATION =
            "7723b7ff5908661f0c64a80a90a8a8e88d5147bdca524b21e5d1092f77b0826f"
    }
}

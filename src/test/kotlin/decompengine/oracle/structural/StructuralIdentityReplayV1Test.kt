package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralIdentityReplayV1Test {
    @Test
    fun replaysTheActualLocationWithoutMatchingNamesDeclarationsOrRecoveryLabels() {
        val fixture = IdentityLocatorFixture()
        val observation = fixture.observe()
        val report = observation.document()
        val matches = report.getValue("checkedGlobalMappings") as JsonArray
        assertEquals(1, matches.size)
        assertEquals(JsonPrimitive("0x20"), (matches.single() as JsonObject)["rva"])
        assertEquals(JsonPrimitive(false), report["complete"])
        assertEquals(JsonPrimitive(false), report["productionVerified"])
        assertEquals(JsonPrimitive(false), report["scored"])
        assertEquals(JsonPrimitive(false), report["releaseEligible"])
        val changed = fixture.model.copy(globals = fixture.model.globals.map {
            it.copy(name = "unrelated", type = "opaque", initializer = "different", status = RecoveryStatus.SYNTHETIC)
        })
        val second = fixture.observe(model = changed)
        assertEquals(matches, second.document()["checkedGlobalMappings"])
        assertNotEquals(observation.sha256, second.sha256)
    }

    @Test
    fun preservesUnobservableAndUnsupportedPopulationsWithoutInventingTypeIdentity() {
        val report = IdentityLocatorFixture().observe().document()
        assertEquals(JsonArray(listOf(JsonPrimitive("oracle.type"))), report["unresolvedOracleTypes"])
        assertEquals(JsonArray(listOf(JsonPrimitive("raw.type"))), report["unresolvedRecoveredTypes"])
        assertEquals(JsonArray(listOf(JsonObject(mapOf(
            "id" to JsonPrimitive("hidden.global"), "reason" to JsonPrimitive("oracle-unobservable"),
        )))), report["unresolvedOracleGlobals"])
        assertEquals(2, (report.getValue("oracleUnobservableFacts") as JsonArray).size)
        val fixture = IdentityLocatorFixture()
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mappings = listOf(locatorMapping(kind = "type", oracleId = "oracle.type", recoveredId = "raw.type")))
        }
    }

    @Test
    fun rejectsWrongAddressesEvenWhenNamesAndLayoutSuggestAPair() {
        val fixture = IdentityLocatorFixture()
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(model = fixture.model.copy(globals = listOf(fixture.model.globals.single().copy(address = 0x400021UL))))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mappings = listOf(locatorMapping(oracleId = "absent.oracle")))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mappings = listOf(locatorMapping(recoveredId = "absent.recovered")))
        }
    }

    @Test
    fun rejectsForgedPointersVerifiersAndAdditionalEvidence() {
        val fixture = IdentityLocatorFixture()
        val mapping = locatorMapping()
        val evidence = (mapping.getValue("evidence") as JsonArray).single() as JsonObject
        listOf(
            evidence + ("oracleLocator" to JsonPrimitive("/entities/2/facts/0/value/source")),
            evidence + ("recoveredLocator" to JsonPrimitive("/globals/1/address")),
            evidence + ("verifier" to JsonPrimitive("reviewed-by-someone")),
        ).forEach { forged ->
            assertFailsWith<StructuralRecoveryV1Exception> {
                fixture.observe(mappings = listOf(JsonObject(mapping + ("evidence" to JsonArray(listOf(JsonObject(forged)))))))
            }
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mappings = listOf(JsonObject(mapping + ("evidence" to JsonArray(listOf(evidence, evidence))))))
        }
    }

    @Test
    fun rejectsCrossOracleInputBinaryAndImageBaseBindings() {
        val fixture = IdentityLocatorFixture()
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mapBytes = fixture.mapBytes(oracleSha256 = "0".repeat(64)))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(model = fixture.model.copy(inputSha256 = "2".repeat(64)))
        }
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.observe(imageBase = 0x500000UL) }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(model = fixture.model.copy(globals = listOf(fixture.model.globals.single().copy(address = 0x3fffffUL))))
        }
    }

    @Test
    fun rejectsDuplicateMappingAndAmbiguousLocationsOnEitherSide() {
        val fixture = IdentityLocatorFixture()
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.observe(mappings = listOf(locatorMapping(), locatorMapping())) }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(model = fixture.model.copy(globals = fixture.model.globals +
                fixture.model.globals.single().copy(id = "alias.global")))
        }
        val duplicateLocation = locatorEntity("global", "alias.oracle", locatorFact("alias.storage", "global.storage", "storage", "static-rva:0x20"))
        val changed = fixture.withEntities(fixture.entities + duplicateLocation)
        assertFailsWith<StructuralRecoveryV1Exception> { changed.observe() }
        val unresolved = changed.observe(mappings = emptyList()).document()
        assertEquals(0, (unresolved.getValue("checkedGlobalMappings") as JsonArray).size)
        assertEquals(3, (unresolved.getValue("unresolvedOracleGlobals") as JsonArray).size)
    }

    @Test
    fun rejectsDuplicateOracleEntityFactAndStorageSlotIdentities() {
        val fixture = IdentityLocatorFixture()
        val entity = fixture.entities.first() as JsonObject
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.withEntities(fixture.entities + entity).observe() }
        val fact = (entity.getValue("facts") as JsonArray).single()
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.withEntities(listOf(JsonObject(entity + ("facts" to JsonArray(listOf(fact, fact)))))).observe()
        }
        val extraStorage = locatorFact("other.fact", "global.storage", "other-slot", "static-rva:0x20")
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.withEntities(listOf(JsonObject(entity + ("facts" to JsonArray(listOf(fact, extraStorage)))))).observe()
        }
    }

    @Test
    fun unknownTlsAndMissingStorageStayUnmappedAndCannotBeClaimed() {
        val fixture = IdentityLocatorFixture()
        listOf(
            locatorFact("storage", "global.storage", "storage", null),
            locatorFact("storage", "global.storage", "storage", "tls-offset:0x20"),
            locatorFact("linkage", "global.linkage", "linkage", "internal"),
        ).forEach { fact ->
            val changed = fixture.withEntities(listOf(locatorEntity("global", "oracle.global", fact)))
            assertFailsWith<StructuralRecoveryV1Exception> { changed.observe() }
            val report = changed.observe(mappings = emptyList()).document()
            assertEquals(1, (report.getValue("unresolvedOracleGlobals") as JsonArray).size)
            assertEquals(JsonArray(listOf(JsonPrimitive("raw.global"))), report["unmappedRecoveredGlobals"])
        }
    }

    @Test
    fun emptyMapIsNotEvidenceOfCompleteRecovery() {
        val report = IdentityLocatorFixture().observe(mappings = emptyList()).document()
        assertEquals(0, (report.getValue("checkedGlobalMappings") as JsonArray).size)
        assertEquals(2, (report.getValue("unresolvedOracleGlobals") as JsonArray).size)
        assertEquals(JsonPrimitive(false), report["complete"])
        val fixture = IdentityLocatorFixture()
        val noRecoveries = fixture.observe(model = fixture.model.copy(globals = emptyList(), types = emptyList()),
            mappings = emptyList()).document()
        assertEquals(0, (noRecoveries.getValue("unmappedRecoveredGlobals") as JsonArray).size)
        assertEquals(2, (noRecoveries.getValue("unresolvedOracleGlobals") as JsonArray).size)
        assertEquals(JsonPrimitive(false), noRecoveries["complete"])
    }

    @Test
    fun verifiesExactBytesAndRefusesForgedCountsFlagsOrAnotherModelSnapshot() {
        val fixture = IdentityLocatorFixture()
        val observation = fixture.observe()
        assertContentEquals(observation.canonicalBytes, fixture.verify(observation.canonicalBytes).canonicalBytes)
        val forged = JsonObject(observation.document() + mapOf(
            "complete" to JsonPrimitive(true), "mappingCount" to JsonPrimitive(999),
            "replaySha256" to JsonPrimitive(observation.sha256),
        ))
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.verify(OracleJson.canonicalBytes(forged)) }
        val changed = fixture.model.copy(types = listOf(RecoveredType("raw.type", "same layout, changed bytes")))
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.verify(observation.canonicalBytes, changed) }
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.verify(observation.canonicalBytes + byteArrayOf(10)) }
    }

    @Test
    fun neverUsesSuppliedAttestationClaimsAsReplayAuthority() {
        val fixture = IdentityLocatorFixture()
        val map = OracleJson.parse(fixture.mapBytes()) as JsonObject
        val attestation = map.getValue("attestation") as JsonObject
        val changed = OracleJson.canonicalBytes(JsonObject(map + ("attestation" to JsonObject(attestation +
            ("payloadSha256" to JsonPrimitive("0".repeat(64)))))))
        val result = fixture.observe(mapBytes = changed).document()
        assertEquals(fixture.observe().document()["checkedGlobalMappings"], result["checkedGlobalMappings"])
        assertEquals(JsonPrimitive(false), result["productionVerified"])
    }

    @Test
    fun observationBytesAreDefensivelyOwned() {
        val fixture = IdentityLocatorFixture()
        val model = fixture.modelBytes()
        val observation = fixture.observe(modelBytes = model)
        val retained = observation.canonicalBytes
        model.fill(0)
        observation.canonicalBytes.fill(0)
        assertContentEquals(retained, observation.canonicalBytes)
        assertEquals(OracleArtifacts.sha256(retained), observation.sha256)
    }

    @Test
    fun enforcesDocumentModelEntityAndMappingBoundsAndStrictDecodedKeys() {
        val fixture = IdentityLocatorFixture()
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(limits = StructuralIdentityReplayV1Limits(maximumDocumentBytes = 1))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(limits = StructuralIdentityReplayV1Limits(maximumProgramModelBytes = 1))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(limits = StructuralIdentityReplayV1Limits(maximumEntities = 1))
        }
        // Distinct otherwise valid entries exceed the bound before one-to-one/evidence checks.
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.observe(mappings = listOf(locatorMapping(), locatorMapping(oracleId = "hidden.global", recoveredId = "other")),
                limits = StructuralIdentityReplayV1Limits(maximumMappings = 1))
        }
        val text = fixture.oracleBytes.toString(Charsets.UTF_8)
        val duplicate = text.replaceFirst("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schema\\u0056ersion\": 1")
        assertNotEquals(text, duplicate)
        assertFailsWith<IllegalArgumentException> { fixture.observe(oracleBytes = duplicate.toByteArray()) }
        val normalization = fixture.oracle.getValue("normalizationProfile") as JsonObject
        val changed = JsonObject(fixture.oracle + ("normalizationProfile" to JsonObject(normalization +
            ("configurationSha256" to JsonPrimitive("0".repeat(64))))))
        assertFailsWith<IllegalArgumentException> { fixture.observe(oracleBytes = OracleJson.canonicalBytes(changed)) }
        val overflow = fixture.withEntities(listOf(locatorEntity("global", "oracle.global",
            locatorFact("storage", "global.storage", "storage", "static-rva:0x10000000000000000"))))
        assertFailsWith<IllegalArgumentException> { overflow.observe() }
    }
}

private class IdentityLocatorFixture(val oracle: JsonObject = identityOracleTemplate()) {
    val entities: List<JsonElement> get() = (oracle.getValue("entities") as JsonArray).toList()
    val oracleBytes: ByteArray get() = OracleJson.canonicalBytes(oracle)
    val model = RecoveredProgramModel(inputSha256 = "1".repeat(64), functions = emptyList(),
        globals = listOf(RecoveredGlobal("raw.global", "different.name", 0x400020UL, "undefined8")),
        types = listOf(RecoveredType("raw.type", "struct unrelated { int value; };", 0x400020UL)))

    fun modelBytes(model: RecoveredProgramModel = this.model) = model.toJson().toByteArray(Charsets.UTF_8)
    fun withEntities(entities: List<JsonElement>) = IdentityLocatorFixture(JsonObject(oracle + ("entities" to JsonArray(entities))))
    fun mapBytes(mappings: List<JsonObject> = listOf(locatorMapping()), oracleSha256: String = OracleArtifacts.sha256(oracleBytes)): ByteArray {
        val template = identityTemplate("identity-map.json")
        val header = template.getValue("map") as JsonObject
        return OracleJson.canonicalBytes(JsonObject(template + mapOf(
            "map" to JsonObject(header + mapOf("oracleSha256" to JsonPrimitive(oracleSha256),
                "oracleId" to (oracle.getValue("oracle") as JsonObject).getValue("id"))),
            "mappings" to JsonArray(mappings),
        )))
    }

    fun observe(
        model: RecoveredProgramModel = this.model,
        mappings: List<JsonObject> = listOf(locatorMapping()),
        oracleBytes: ByteArray = this.oracleBytes,
        mapBytes: ByteArray = this.mapBytes(mappings),
        modelBytes: ByteArray = this.modelBytes(model),
        imageBase: ULong = 0x400000UL,
        limits: StructuralIdentityReplayV1Limits = StructuralIdentityReplayV1Limits(),
    ) = StructuralIdentityReplayV1.observe(oracleBytes, mapBytes, modelBytes, imageBase, limits)

    fun verify(observation: ByteArray, model: RecoveredProgramModel = this.model) = StructuralIdentityReplayV1.verify(
        oracleBytes, mapBytes(), modelBytes(model), 0x400000UL, observation,
    )
}

private fun identityOracleTemplate(): JsonObject {
    val template = identityTemplate("structural-oracle.json")
    return JsonObject(template + ("entities" to JsonArray(listOf(
        locatorEntity("global", "oracle.global", locatorFact("storage", "global.storage", "storage", "static-rva:0x20")),
        locatorEntity("global", "hidden.global", locatorFact("hidden", "global.storage", "storage", null)),
        locatorEntity("type", "oracle.type", locatorFact("type.size", "type.aggregate.size-bits", "aggregate-size", null)),
    ))))
}
private fun identityTemplate(name: String): JsonObject {
    val bytes = requireNotNull(StructuralIdentityReplayV1Test::class.java.getResourceAsStream("/oracle/structural-v1/$name"))
        .use { it.readBytes() }
    return OracleJson.parse(bytes) as JsonObject
}
private fun locatorEntity(kind: String, id: String, fact: JsonObject) = JsonObject(mapOf(
    "kind" to JsonPrimitive(kind), "id" to JsonPrimitive(id), "facts" to JsonArray(listOf(fact)),
))
private fun locatorFact(id: String, dimension: String, slot: String, source: String?) = JsonObject(mapOf(
    "id" to JsonPrimitive(id), "dimension" to JsonPrimitive(dimension), "slot" to JsonPrimitive(slot),
    "observability" to JsonPrimitive(if (source == null) "oracle-unobservable" else "observable"),
    "value" to (source?.let { JsonObject(mapOf("source" to JsonPrimitive(it), "abi" to JsonNull)) } ?: JsonNull),
    "evidence" to JsonArray(listOf(JsonObject(mapOf("kind" to JsonPrimitive("fixture-location"), "locator" to JsonPrimitive("unit:0;entry:0x1"))))),
))
private fun locatorMapping(kind: String = "global", oracleId: String = "oracle.global", recoveredId: String = "raw.global") = JsonObject(mapOf(
    "kind" to JsonPrimitive(kind), "oracleId" to JsonPrimitive(oracleId), "recoveredId" to JsonPrimitive(recoveredId),
    "evidence" to JsonArray(listOf(JsonObject(mapOf(
        "kind" to JsonPrimitive("storage-rva"), "oracleLocator" to JsonPrimitive("/entities/0/facts/0/value/source"),
        "recoveredLocator" to JsonPrimitive("/globals/0/address"), "verifier" to JsonPrimitive("structural-static-rva-locator-v1"),
    )))),
))
private fun StructuralIdentityLocatorObservationV1.document() = OracleJson.parse(canonicalBytes) as JsonObject

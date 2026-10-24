package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Component ceilings, not a new production admission profile. Callers may only tighten them. */
internal data class StructuralIdentityReplayV1Limits(
    val maximumDocumentBytes: Int = 4 * 1024 * 1024,
    val maximumProgramModelBytes: Int = 32 * 1024 * 1024,
    val maximumEntities: Int = 10_000,
    val maximumMappings: Int = 10_000,
) {
    init {
        require(maximumDocumentBytes in 1..4 * 1024 * 1024)
        require(maximumProgramModelBytes in 1..32 * 1024 * 1024)
        require(maximumEntities in 1..10_000)
        require(maximumMappings in 1..10_000)
    }

    internal fun jsonLimits() = StrictJsonLimits(
        maximumInputBytes = maximumDocumentBytes,
        maximumCanonicalBytes = maximumDocumentBytes,
    )
}

/** Owned observation bytes; this deliberately cannot construct a production replay capability. */
internal class StructuralIdentityLocatorObservationV1 internal constructor(bytes: ByteArray) {
    private val stored = bytes.copyOf()
    val canonicalBytes: ByteArray get() = stored.copyOf()
    val sha256: String = OracleArtifacts.sha256(stored)
}

/**
 * Independently checks a narrow locator relation, not semantic structural recovery or provenance.
 *
 * Supported: a unique observable global.storage/storage static-rva fact, in the same image-base
 * convention as the supplied canonical model. Evidence must point to the actual fact and model
 * address fields. Names, C types, initializer text, extraction status and supplied attestations
 * never establish identity. A matching address is a location relation, not proof of binary origin.
 *
 * The current oracle has no typed relation from a type DIE to RecoveredType.sourceAddress (whose
 * schema does not establish a DIE-offset interpretation). Layout similarity and locator strings cannot
 * fill that gap. Type mappings are refused; all type populations remain explicitly unresolved.
 */
internal object StructuralIdentityReplayV1 {
    fun observe(
        structuralOracleBytes: ByteArray,
        identityMapBytes: ByteArray,
        recoveredProgramModelBytes: ByteArray,
        selectedModelImageBase: ULong,
        limits: StructuralIdentityReplayV1Limits = StructuralIdentityReplayV1Limits(),
    ): StructuralIdentityLocatorObservationV1 {
        // Bound before each private copy. Do not use separately supplied trees, counts or digests.
        val oracleBytes = identitySnapshot(structuralOracleBytes, limits.maximumDocumentBytes)
        val mapBytes = identitySnapshot(identityMapBytes, limits.maximumDocumentBytes)
        val modelBytes = identitySnapshot(recoveredProgramModelBytes, limits.maximumProgramModelBytes)
        val oracle = OracleJson.parse(oracleBytes, limits.jsonLimits()).identityObject()
        val candidate = OracleJson.parse(mapBytes, limits.jsonLimits()).identityObject()
        OracleSchemas.validate("structural-oracle", oracle)
        OracleSchemas.validate("structural-identity-map", candidate)
        val model = CanonicalProgramModelStreaming.readCanonical(modelBytes,
            CanonicalProgramModelStreamingLimits(
                maximumInputBytes = limits.maximumProgramModelBytes,
                maximumGlobals = limits.maximumEntities,
                maximumTypes = limits.maximumEntities,
            ))
        val normalization = oracle.getValue("normalizationProfile").identityObject()
        if (normalization != JsonObject(mapOf(
                "id" to JsonPrimitive(StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_ID),
                "version" to JsonPrimitive(StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_VERSION),
                "configurationSha256" to JsonPrimitive(StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_CONFIGURATION_SHA256),
            ))) identityFail("unsupported normalization profile")
        val artifact = oracle.getValue("artifact").identityObject()
        if (artifact.identityString("inputSha256") != model.model.inputSha256) {
            identityFail("oracle and model input identities differ")
        }
        if (identityAddress(artifact.identityString("imageBase")) != selectedModelImageBase) {
            identityFail("rebased models need an independently evidenced address translation")
        }
        val header = candidate.getValue("map").identityObject()
        if (header.identityString("oracleSha256") != OracleArtifacts.sha256(oracleBytes) ||
            header.identityString("oracleId") != oracle.getValue("oracle").identityObject().identityString("id") ||
            candidate.identityString("scope") != oracle.identityString("scope")
        ) identityFail("identity map does not bind this oracle snapshot and scope")

        val entities = oracle.getValue("entities").identityArray()
        if (entities.size > limits.maximumEntities) identityFail("oracle entity bound exceeded")
        val seenEntities = hashSetOf<StructuralEntityKey>()
        val globals = linkedMapOf<String, IdentityGlobalLocator>()
        val oracleTypes = arrayListOf<String>()
        val unobservable = arrayListOf<JsonElement>()
        entities.forEachIndexed { entityIndex, raw ->
            val entity = raw.identityObject()
            val kind = entity.identityString("kind")
            val id = entity.identityString("id")
            if (!seenEntities.add(StructuralEntityKey(kind, id))) identityFail("duplicate oracle entity")
            val facts = entity.getValue("facts").identityArray()
            val factIds = hashSetOf<String>()
            val factSlots = hashSetOf<Pair<String, String>>()
            facts.forEach { rawFact ->
                val fact = rawFact.identityObject()
                if (StructuralRecoveryV1Contract.DIMENSION_ENTITY_KIND[fact.identityString("dimension")] != kind) {
                    identityFail("oracle fact dimension does not belong to its entity kind")
                }
                if (!factIds.add(fact.identityString("id")) ||
                    !factSlots.add(fact.identityString("dimension") to fact.identityString("slot"))
                ) identityFail("duplicate oracle fact identity or dimension/slot")
                if (fact.identityString("observability") == "oracle-unobservable") {
                    unobservable += JsonObject(mapOf("kind" to JsonPrimitive(kind), "entityId" to JsonPrimitive(id),
                        "factId" to JsonPrimitive(fact.identityString("id"))))
                }
            }
            if (kind == "type") oracleTypes += id
            if (kind == "global") {
                val storage = facts.withIndex().filter {
                    it.value.identityObject().identityString("dimension") == "global.storage"
                }
                // Multiple storage facts, even at identical addresses, are not independent identity.
                if (storage.size > 1) identityFail("ambiguous global storage facts")
                val selected = storage.singleOrNull()
                val fact = selected?.value?.identityObject()
                val reason = when {
                    fact == null -> "missing-storage-locator"
                    fact.identityString("observability") == "oracle-unobservable" -> "oracle-unobservable"
                    fact.identityString("slot") != "storage" -> "unsupported-storage-slot"
                    !fact.getValue("value").identityObject().identityString("source").startsWith("static-rva:") ->
                        "unsupported-storage-form"
                    else -> null
                }
                val rva = if (reason == null) identityAddress(
                    fact!!.getValue("value").identityObject().identityString("source").removePrefix("static-rva:"),
                ) else null
                globals[id] = IdentityGlobalLocator(rva,
                    "/entities/$entityIndex/facts/${selected?.index}/value/source", reason)
            }
        }
        val oracleAtRva = globals.entries.filter { it.value.rva != null }.groupBy { it.value.rva!! }
        val recoveredAtRva = model.model.globals.withIndex().groupBy {
            if (it.value.address < selectedModelImageBase) identityFail("global address precedes selected image base")
            it.value.address - selectedModelImageBase
        }
        val recoveredById = model.model.globals.withIndex().associateBy { it.value.id }
        val mappings = candidate.getValue("mappings").identityArray()
        if (mappings.size > limits.maximumMappings) identityFail("identity mapping bound exceeded")
        val seenOracle = hashSetOf<String>()
        val seenRecovered = hashSetOf<String>()
        val checked = mappings.map { raw ->
            val mapping = raw.identityObject()
            if (mapping.identityString("kind") != "global") {
                identityFail("type identity needs a typed oracle-to-recovered locator relation absent from schema v1")
            }
            val oracleId = mapping.identityString("oracleId")
            val recoveredId = mapping.identityString("recoveredId")
            if (!seenOracle.add(oracleId) || !seenRecovered.add(recoveredId)) identityFail("mapping is not one-to-one")
            val locator = globals[oracleId] ?: identityFail("mapping oracle global is absent")
            val rva = locator.rva ?: identityFail("mapping oracle global has no supported observable locator")
            val recovered = recoveredById[recoveredId] ?: identityFail("mapping recovered global is absent")
            if (oracleAtRva.getValue(rva).size != 1 || recoveredAtRva[rva]?.size != 1 ||
                recovered.value.address < selectedModelImageBase || recovered.value.address - selectedModelImageBase != rva
            ) identityFail("global locator is ambiguous or contradicts the recovered address")
            val expectedEvidence = JsonArray(listOf(JsonObject(mapOf(
                "kind" to JsonPrimitive("storage-rva"),
                "oracleLocator" to JsonPrimitive(locator.pointer),
                "recoveredLocator" to JsonPrimitive("/globals/${recovered.index}/address"),
                "verifier" to JsonPrimitive("structural-static-rva-locator-v1"),
            ))))
            if (mapping.getValue("evidence") != expectedEvidence) identityFail("mapping locator evidence differs from replay")
            JsonObject(mapOf("oracleId" to JsonPrimitive(oracleId), "recoveredId" to JsonPrimitive(recoveredId),
                "rva" to JsonPrimitive("0x${rva.toString(16)}"), "evidence" to expectedEvidence))
        }.sortedBy { it.identityString("oracleId") }
        val unresolvedGlobals = globals.entries.filter { it.key !in seenOracle }.sortedBy { it.key }.map { (id, locator) ->
            JsonObject(mapOf("id" to JsonPrimitive(id), "reason" to JsonPrimitive(locator.reason ?: when {
                oracleAtRva[locator.rva]?.size != 1 || (recoveredAtRva[locator.rva]?.size ?: 0) > 1 -> "ambiguous-location"
                else -> "unmapped"
            })))
        }
        val report = JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-identity-locator-observation-v1"),
            "oracleSha256" to JsonPrimitive(OracleArtifacts.sha256(oracleBytes)),
            "identityMapSha256" to JsonPrimitive(OracleArtifacts.sha256(mapBytes)),
            "programModelSha256" to JsonPrimitive(model.sha256),
            "selectedModelImageBase" to JsonPrimitive("0x${selectedModelImageBase.toString(16)}"),
            "checkedGlobalMappings" to JsonArray(checked),
            "unresolvedOracleGlobals" to JsonArray(unresolvedGlobals),
            "unmappedRecoveredGlobals" to identityStrings(model.model.globals.map { it.id }.filterNot { it in seenRecovered }),
            "unresolvedOracleTypes" to identityStrings(oracleTypes),
            "unresolvedRecoveredTypes" to identityStrings(model.model.types.map { it.id }),
            "oracleUnobservableFacts" to JsonArray(unobservable),
            "typeIdentityPolicy" to JsonPrimitive("unsupported-no-typed-cross-snapshot-locator"),
            "complete" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
        ))
        return StructuralIdentityLocatorObservationV1(OracleJson.canonicalBytes(report, limits.jsonLimits()))
    }

    /** Compare exact recomputed bytes, never the candidate's claimed replay digest/count/complete flag. */
    fun verify(
        structuralOracleBytes: ByteArray,
        identityMapBytes: ByteArray,
        recoveredProgramModelBytes: ByteArray,
        selectedModelImageBase: ULong,
        observationBytes: ByteArray,
        limits: StructuralIdentityReplayV1Limits = StructuralIdentityReplayV1Limits(),
    ): StructuralIdentityLocatorObservationV1 {
        val expected = identitySnapshot(observationBytes, limits.maximumDocumentBytes)
        val actual = observe(structuralOracleBytes, identityMapBytes, recoveredProgramModelBytes, selectedModelImageBase, limits)
        if (!MessageDigest.isEqual(expected, actual.canonicalBytes)) identityFail("retained identity observation differs from replay")
        return actual
    }
}

private data class IdentityGlobalLocator(val rva: ULong?, val pointer: String, val reason: String?)
private fun identitySnapshot(bytes: ByteArray, maximum: Int): ByteArray {
    if (bytes.isEmpty() || bytes.size > maximum) identityFail("identity replay byte bound exceeded")
    return bytes.copyOf()
}
private fun JsonElement.identityObject(): JsonObject = this as? JsonObject ?: identityFail("expected identity object")
private fun JsonElement.identityArray(): JsonArray = this as? JsonArray ?: identityFail("expected identity array")
private fun JsonObject.identityString(key: String): String {
    val value = this[key] as? JsonPrimitive ?: identityFail("expected identity string: $key")
    if (!value.isString) identityFail("expected identity string: $key")
    return value.content
}
private fun identityAddress(value: String): ULong {
    if (!Regex("^0x(?:0|[1-9a-f][0-9a-f]{0,15})$").matches(value)) identityFail("noncanonical identity address")
    return value.removePrefix("0x").toULongOrNull(16) ?: identityFail("identity address overflows")
}
private fun identityStrings(values: List<String>): JsonArray = JsonArray(values.sorted().map(::JsonPrimitive))
private fun identityFail(message: String): Nothing = throw StructuralRecoveryV1Exception(message)

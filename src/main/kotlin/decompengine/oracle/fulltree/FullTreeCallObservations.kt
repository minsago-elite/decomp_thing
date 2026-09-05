package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeCallObservationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Immutable call-observation work derived from authenticated scope and inventory snapshots. */
internal class FullTreeCallObservationShardInput internal constructor(
    val identifier: String,
    val inputSha256: String,
    units: List<JsonObject>,
) {
    val units: List<JsonObject> = Collections.unmodifiableList(units.map(::snapshotCallUnit))

    init {
        if (identifier.isEmpty()) callFail("call-observation shard identifier is empty")
        requireCallDigest(inputSha256, "call-observation shard input")
        if (this.units.isEmpty()) callFail("call-observation shard has no compilation units")
    }
}

/**
 * Kotlin-owned contract for call-observation schema v2 / producer policy v4.
 *
 * This object authenticates controls, work-item identity, canonical ordering, closed target
 * classifications, counts, and resource bounds. It does not accept evidence from ACP or Python;
 * artifact truth can enter only through [FullTreeCallObservationProducer]. Historical policy-v2/v3
 * identities remain available solely to authenticate already-produced diagnostic evidence.
 */
internal object FullTreeCallObservations {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(SCHEMA_NAME, PRODUCER_POLICY)
    }

    val historicalV2ConfigurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-call-observations", HISTORICAL_V2_PRODUCER_POLICY)
    }

    val historicalV3ConfigurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-call-observations", HISTORICAL_V3_PRODUCER_POLICY)
    }

    fun shardInputs(
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        scope: JsonObject,
        scopeSha256: String,
    ): List<FullTreeCallObservationShardInput> = buildShardInputs(
        authenticateCallControls(inventory, inventoryArtifactSha256, scope, scopeSha256),
    )

    private fun authenticateCallControls(
        inventoryValue: JsonObject,
        inventoryArtifactSha256: String,
        scopeValue: JsonObject,
        scopeSha256: String,
    ): AuthenticatedCallObservationControls {
        requireCallDigest(inventoryArtifactSha256, "inventory artifact")
        requireCallDigest(scopeSha256, "scope")
        val (scope, scopeBytes) = snapshotCallControl(scopeValue, "full-tree scope")
        if (OracleArtifacts.sha256(scopeBytes) != scopeSha256) {
            callFail("full-tree scope snapshot differs from its authenticated digest")
        }
        val (inventory, inventoryBytes) = snapshotCallControl(inventoryValue, "full-tree inventory")
        if (OracleArtifacts.sha256(inventoryBytes) != inventoryArtifactSha256) {
            callFail("full-tree inventory snapshot differs from its authenticated digest")
        }
        val functionInputs = try {
            FullTreeFunctionObservations.shardInputs(
                inventory,
                inventoryArtifactSha256,
                scope,
                scopeSha256,
            )
        } catch (failure: Exception) {
            throw FullTreeCallObservationException(
                "call-observation controls are not authenticated",
                failure,
            )
        }
        return AuthenticatedCallObservationControls(scope, inventory, functionInputs)
    }

    private fun buildShardInputs(
        controls: AuthenticatedCallObservationControls,
    ): List<FullTreeCallObservationShardInput> {
        val scope = controls.scope
        val inventory = controls.inventory
        val functionInputs = controls.functionInputs
        val scopeSha256 = OracleArtifacts.sha256(callCanonicalBytes(scope, "full-tree scope"))
        val inventoryIndexSha256 = inventory.controlString("indexSha256")
        val richArtifactSha256 = scope.controlObject("oracle").controlString("richArtifactSha256")
        return Collections.unmodifiableList(functionInputs.map { source ->
            FullTreeCallObservationShardInput(
                source.identifier,
                inputSha256(
                    inventoryIndexSha256,
                    configurationSha256,
                    richArtifactSha256,
                    scopeSha256,
                    source.identifier,
                    source.units,
                ),
                source.units,
            )
        })
    }

    internal fun inputSha256(
        inventoryIndexSha256: String,
        producerConfigurationSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
        shardId: String,
        units: List<JsonObject>,
    ): String = inputSha256ForConfiguration(
        inventoryIndexSha256,
        producerConfigurationSha256,
        richArtifactSha256,
        scopeSha256,
        shardId,
        units,
        expectedConfigurationSha256 = configurationSha256,
    )

    internal fun historicalV2InputSha256(
        inventoryIndexSha256: String,
        producerConfigurationSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
        shardId: String,
        units: List<JsonObject>,
    ): String = inputSha256ForConfiguration(
        inventoryIndexSha256,
        producerConfigurationSha256,
        richArtifactSha256,
        scopeSha256,
        shardId,
        units,
        expectedConfigurationSha256 = historicalV2ConfigurationSha256,
    )

    private fun inputSha256ForConfiguration(
        inventoryIndexSha256: String,
        producerConfigurationSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
        shardId: String,
        units: List<JsonObject>,
        expectedConfigurationSha256: String,
    ): String {
        requireCallDigest(inventoryIndexSha256, "inventory index")
        requireCallDigest(producerConfigurationSha256, "call-observation configuration")
        requireCallDigest(richArtifactSha256, "rich artifact")
        requireCallDigest(scopeSha256, "scope")
        if (producerConfigurationSha256 != expectedConfigurationSha256) {
            callFail("call-observation input uses a foreign producer configuration")
        }
        if (shardId.isEmpty() || units.isEmpty()) {
            callFail("call-observation input has no shard identity or compilation units")
        }
        val payload = JsonObject(
            mapOf(
                "inventoryIndexSha256" to JsonPrimitive(inventoryIndexSha256),
                "producerConfigurationSha256" to JsonPrimitive(producerConfigurationSha256),
                "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                "scopeSha256" to JsonPrimitive(scopeSha256),
                "shardId" to JsonPrimitive(shardId),
                "units" to JsonArray(units),
            ),
        )
        return OracleArtifacts.sha256(callCanonicalBytes(payload, "call-observation shard input"))
    }

    fun canonicalEnvelopeBytes(document: JsonObject): ByteArray =
        callCanonicalBytes(document, "call-observation shard")

    /**
     * Validates canonical structure and authenticated control bindings only. This does not rederive
     * call facts from ELF/DWARF and therefore cannot confer oracle or release authority; an
     * authoritative path must invoke and contain the raw producer itself.
     */
    fun validateEnvelope(
        documentValue: JsonObject,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeCallObservationShardInput,
    ) {
        val bytes = callCanonicalBytes(documentValue, "call-observation shard")
        val document = try {
            OracleJson.parseCanonical(bytes, CALL_JSON_LIMITS) as? JsonObject
                ?: callFail("call-observation shard root is not an object")
        } catch (failure: FullTreeCallObservationException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeCallObservationException("call-observation shard cannot be snapshotted", failure)
        }
        try {
            OracleSchemas.validate(SCHEMA_NAME, document)
        } catch (failure: Exception) {
            throw FullTreeCallObservationException(
                "call-observation shard fails bundled schema validation",
                failure,
            )
        }

        val controls = authenticateCallControls(
            inventory,
            inventoryArtifactSha256,
            scope,
            scopeSha256,
        )
        val authenticated = buildShardInputs(controls)
            .singleOrNull { it.identifier == shard.identifier }
            ?: callFail("call-observation shard is outside the authenticated inventory")
        if (shard.inputSha256 != authenticated.inputSha256 || shard.units != authenticated.units) {
            callFail("call-observation shard input is not authenticated")
        }
        val expectedOracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "inventoryIndexSha256" to JsonPrimitive(controls.inventory.controlString("indexSha256")),
                "richArtifactSha256" to JsonPrimitive(
                    controls.scope.controlObject("oracle").controlString("richArtifactSha256"),
                ),
                "scopeSha256" to JsonPrimitive(scopeSha256),
            ),
        )
        val expectedShard = JsonObject(
            mapOf(
                "id" to JsonPrimitive(authenticated.identifier),
                "inputSha256" to JsonPrimitive(authenticated.inputSha256),
            ),
        )
        if (
            document.controlObject("oracle") != expectedOracle ||
            document.controlObject("shard") != expectedShard
        ) {
            callFail("call-observation shard bindings do not match")
        }

        val unitBounds = callUnitBounds(controls.inventory)
        val unitIds = authenticated.units.mapTo(hashSetOf()) { it.controlString("id") }
        val identities = HashSet<String>()
        var previousId: String? = null
        var scored = 0L
        var unobservable = 0L
        val calls = document.controlArray("calls")
        calls.forEachIndexed { index, element ->
            val call = element as? JsonObject
                ?: callFail("call observation $index is not an object")
            val id = validateCall(call, unitIds, unitBounds)
            val previous = previousId
            if (previous != null && FULL_TREE_CODE_POINT_ORDER.compare(previous, id) >= 0) {
                callFail(
                    if (previous == id) {
                        "call observations duplicate an identity"
                    } else {
                        "call observations are not canonically ordered"
                    },
                )
            }
            if (!identities.add(id)) callFail("call observations duplicate an identity")
            previousId = id
            when (call.controlString("population")) {
                "scored" -> scored = Math.addExact(scored, 1L)
                "unobservable" -> unobservable = Math.addExact(unobservable, 1L)
            }
        }
        val counts = document.controlObject("counts")
        val scannedDies = counts.controlLong("scannedDies")
        val expectedCounts = JsonObject(
            mapOf(
                "observedCallSites" to JsonPrimitive(calls.size.toLong()),
                "scannedDies" to JsonPrimitive(scannedDies),
                "scored" to JsonPrimitive(scored),
                "units" to JsonPrimitive(authenticated.units.size.toLong()),
                "unobservable" to JsonPrimitive(unobservable),
            ),
        )
        if (counts != expectedCounts) callFail("call-observation counts do not reconcile")
        if (scannedDies < authenticated.units.size.toLong() + calls.size.toLong()) {
            callFail("call-observation scanned-DIE count cannot cover its evidence")
        }
        val bounds = controls.scope.controlObject("bounds").controlObject("perShard")
        if (calls.size.toLong() > bounds.controlLong("entities")) {
            callFail("call-observation shard exceeds its authenticated entity bound")
        }
        if (bytes.size.toLong() > bounds.controlLong("serializedBytes")) {
            callFail("call-observation shard exceeds its authenticated serialized-byte bound")
        }
    }

    internal fun recordValidator(
        inventory: JsonObject,
        shard: FullTreeCallObservationShardInput,
    ): (JsonObject) -> String {
        val unitBounds = callUnitBounds(inventory)
        val unitIds = shard.units.mapTo(hashSetOf()) { it.controlString("id") }
        if (unitIds.size != shard.units.size || !unitBounds.keys.containsAll(unitIds)) {
            callFail("call-observation shard owners are inconsistent with its inventory")
        }
        return { call -> validateCall(call, unitIds, unitBounds) }
    }

    private fun validateCall(
        call: JsonObject,
        unitIds: Set<String>,
        unitBounds: Map<String, CallUnitBounds>,
    ): String {
        val id = call.controlString("id")
        val unitId = call.controlString("unitId")
        if (unitId !in unitIds) callFail("call observation owner is outside its shard")
        val dieOffset = call.controlString("dieOffset")
        val dieAddress = parseCallAddress(dieOffset, "call observation DIE offset")
        val bounds = unitBounds.getValue(unitId)
        if (dieAddress <= bounds.start || bounds.endExclusive?.let { dieAddress >= it } == true) {
            callFail("call observation DIE offset is outside its compilation unit")
        }
        val population = call.controlString("population")
        val reason = call.callNullableString("reasonCode")
        val callerId = call.callNullableString("callerId")
        val local = call.callNullableString("callerLocalReturnOffset")
        val returnPc = call.callNullableString("returnPcRva")
        val callPc = call.callNullableString("callPcRva")
        val callLocal = call.callNullableString("callerLocalCallOffset")
        val locations = listOfNotNull(callPc, returnPc)
        when (population) {
            "scored" -> if (reason != null || callerId == null || locations.isEmpty()) {
                callFail("scored call observation has incomplete caller identity")
            }
            "unobservable" -> if (reason == null || callerId != null || local != null || callLocal != null) {
                callFail("unobservable call observation has contradictory caller identity")
            }
            else -> callFail("call observation population is unsupported")
        }
        if (reason == "call-site-no-address" && locations.isNotEmpty()) {
            callFail("addressless call observation has a location")
        }
        if (reason == "caller-no-emitted-range" && locations.isEmpty()) {
            callFail("callerless call observation lacks a location")
        }
        if ((local != null) != (callerId != null && returnPc != null) ||
            (callLocal != null) != (callerId != null && callPc != null)
        ) callFail("call observation local offsets differ from their coordinate kinds")
        locations.forEach { parseCallAddress(it, "call-site coordinate") }
        if (callerId != null) {
            val caller = parseCallAddress(
                callerId.removePrefix("function-rva-"),
                "call observation caller RVA",
            )
            for ((coordinate, relative) in listOf(callPc to callLocal, returnPc to local)) {
                if (coordinate == null) continue
                val offset = parseCallAddress(checkNotNull(relative), "caller-local coordinate offset")
                val address = parseCallAddress(coordinate, "call-site coordinate RVA")
                if (offset > ULong.MAX_VALUE - caller || caller + offset != address) {
                    callFail("call observation caller-local coordinate does not reconcile without overflow")
                }
            }
        }
        val identityPayload = JsonObject(
            mapOf(
                "call" to (callPc?.let(::JsonPrimitive) ?: JsonNull),
                "caller" to (callerId?.removePrefix("function-rva-")?.let(::JsonPrimitive) ?: JsonNull),
                "die" to JsonPrimitive(dieOffset),
                "return" to (returnPc?.let(::JsonPrimitive) ?: JsonNull),
                "unit" to JsonPrimitive(unitId),
            ),
        )
        val expectedId = "call-" + OracleArtifacts.sha256(
            callCanonicalBytes(identityPayload, "call observation identity"),
        ).take(32)
        if (id != expectedId) callFail("call observation identity differs from its locators")
        validateTarget(call.controlObject("target"))
        return id
    }

    private fun validateTarget(target: JsonObject) {
        val kind = target.controlString("kind")
        val dispatch = target.controlString("dispatchKind")
        val functionId = target.callNullableString("functionId")
        val origin = target.callNullableString("originDieOffset")
        origin?.let { parseCallAddress(it, "call target origin DIE offset") }
        val aliases = target.controlArray("aliases").map { (it as JsonPrimitive).content }
        requireStrictCallOrder(aliases, "call target aliases")
        val proven = target.controlArray("provenFunctionIds").map { (it as JsonPrimitive).content }
        requireStrictCallOrder(proven, "proven call targets")
        val targetEvidence = target.controlString("targetEvidence")
        when (kind) {
            "direct-internal" -> if (
                dispatch != "direct" || functionId == null || origin == null ||
                proven.isNotEmpty() || aliases.isEmpty()
            ) callFail("direct call target classification is contradictory")
            "external-unresolved" -> if (
                dispatch != "direct" || functionId != null || origin == null ||
                proven.isNotEmpty() || aliases.isEmpty()
            ) callFail("external call target classification is contradictory")
            "indirect-proven" -> if (
                dispatch != "indirect-proven" || functionId != null || origin != null ||
                proven.size != 1 || aliases.isNotEmpty() ||
                targetEvidence !in setOf(
                    "call-target-expression",
                    "call-target-and-clobbered-expressions",
                )
            ) callFail("proven indirect call classification is contradictory")
            "indirect-unresolved" -> if (
                dispatch != "indirect-unresolved" || functionId != null || origin != null ||
                proven.isNotEmpty() || aliases.isNotEmpty()
            ) callFail("unresolved indirect call classification is contradictory")
            "virtual-unresolved" -> if (
                dispatch != "virtual-unresolved" || functionId != null || origin == null ||
                proven.isNotEmpty() || aliases.isEmpty()
            ) callFail("virtual call classification is contradictory")
            else -> callFail("call target kind is unsupported")
        }
    }

    private val PRODUCER_POLICY = JsonObject(mapOf(
        "id" to JsonPrimitive("full-tree-call-observations"),
        "siteIdentity" to JsonPrimitive("caller-id-typed-instruction-and-return-rvas-unit-die-offset"),
        "siteLocator" to JsonPrimitive("distinct-dwarf-call-pc-and-call-return-pc-no-fallback"),
        "tailCalls" to JsonPrimitive("dwarf-call-tail-call-flag"),
        "targetPolicy" to JsonPrimitive("call-origin-subprogram-direct-object-origin-indirect-and-target-expression-closed-classification"),
        "version" to JsonPrimitive(4),
    ))

    private val HISTORICAL_V3_PRODUCER_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-call-observations"),
            "siteIdentity" to JsonPrimitive("caller-id-return-pc-rva-or-unit-die-offset"),
            "siteLocator" to JsonPrimitive("dwarf-call-return-pc"),
            "tailCalls" to JsonPrimitive("dwarf-call-tail-call-flag"),
            "targetPolicy" to JsonPrimitive(
                "call-origin-subprogram-direct-object-origin-indirect-and-target-expression-closed-classification",
            ),
            "version" to JsonPrimitive(3),
        ),
    )

    private val HISTORICAL_V2_PRODUCER_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-call-observations"),
            "siteIdentity" to JsonPrimitive("caller-id-return-pc-rva-or-unit-die-offset"),
            "siteLocator" to JsonPrimitive("dwarf-call-return-pc"),
            "tailCalls" to JsonPrimitive("dwarf-call-tail-call-flag"),
            "targetPolicy" to JsonPrimitive(
                "call-origin-address-virtuality-and-target-expression-closed-classification",
            ),
            "version" to JsonPrimitive(2),
        ),
    )
}

private data class AuthenticatedCallObservationControls(
    val scope: JsonObject,
    val inventory: JsonObject,
    val functionInputs: List<FullTreeFunctionObservationShardInput>,
)

private data class CallUnitBounds(val start: ULong, val endExclusive: ULong?)

private fun callUnitBounds(inventory: JsonObject): Map<String, CallUnitBounds> {
    val ordered = inventory.controlArray("units").map { value ->
        val unit = value as JsonObject
        unit.controlString("id") to parseCallAddress(
            unit.controlString("dwarfOffset"),
            "inventory DWARF offset",
        )
    }.sortedBy { it.second }
    return ordered.mapIndexed { index, (unitId, start) ->
        unitId to CallUnitBounds(start, ordered.getOrNull(index + 1)?.second)
    }.toMap()
}

private fun snapshotCallUnit(unit: JsonObject): JsonObject = try {
    OracleJson.parseCanonical(
        callCanonicalBytes(unit, "call-observation unit snapshot"),
        CALL_JSON_LIMITS,
    ) as JsonObject
} catch (failure: Exception) {
    throw FullTreeCallObservationException("call-observation unit cannot be snapshotted", failure)
}

private fun snapshotCallControl(value: JsonObject, label: String): Pair<JsonObject, ByteArray> {
    val bytes = callCanonicalBytes(value, label)
    val snapshot = try {
        OracleJson.parseCanonical(bytes, CALL_JSON_LIMITS) as? JsonObject
            ?: callFail("$label root is not an object")
    } catch (failure: FullTreeCallObservationException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeCallObservationException("$label cannot be snapshotted", failure)
    }
    return snapshot to bytes
}

private fun callCanonicalBytes(value: JsonElement, label: String): ByteArray = try {
    OracleJson.canonicalBytes(value, CALL_JSON_LIMITS)
} catch (failure: Exception) {
    throw FullTreeCallObservationException("$label exceeds strict canonical JSON limits", failure)
}

private fun JsonObject.callNullableString(name: String): String? = when (val value = this[name]) {
    null -> callFail("call observation field is absent: $name")
    JsonNull -> null
    is JsonPrimitive -> if (value.isString) value.content else callFail("$name is not a nullable string")
    else -> callFail("$name is not a nullable string")
}

private fun parseCallAddress(value: String, label: String): ULong {
    if (!value.matches(CALL_ADDRESS)) callFail("$label is not canonical")
    return value.removePrefix("0x").toULongOrNull(16)
        ?: callFail("$label exceeds unsigned 64-bit range")
}

private fun requireStrictCallOrder(values: List<String>, label: String) {
    var previous: String? = null
    values.forEach { current ->
        val prior = previous
        if (prior != null && FULL_TREE_CODE_POINT_ORDER.compare(prior, current) >= 0) {
            callFail(if (prior == current) "$label contain a duplicate" else "$label are not canonically ordered")
        }
        previous = current
    }
}

private fun requireCallDigest(value: String, label: String) {
    if (!value.matches(CALL_SHA256)) callFail("$label SHA-256 is invalid")
}

private fun callFail(message: String): Nothing = throw FullTreeCallObservationException(message)

private const val SCHEMA_NAME = "full-tree-call-observations-v2"
private val CALL_SHA256 = Regex("[0-9a-f]{64}")
private val CALL_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val CALL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
)

package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independent hard ceilings for one producer-owned function-observation shard. */
internal data class FullTreeFunctionObservationAccumulatorLimits(
    val maximumScannedDies: Long = 50_000_000L,
    val maximumSubprograms: Long = 10_000_000L,
    val maximumEntities: Int = 10_000_000,
    val maximumEmittedRvas: Int = 10_000_000,
    val maximumNonEmittedGroups: Int = 10_000_000,
    val maximumAliasesPerSubprogram: Int = 256,
    val maximumEvidencePerAliasPerSubprogram: Int = 256,
    val maximumEvidencePerSubprogram: Int = 256,
    val maximumCanonicalBytesPerSubprogram: Int = 64 * 1024 * 1024,
    val maximumAliasesPerEntity: Int = 1_000_000,
    val maximumEvidencePerAliasPerEntity: Int = 1_000_000,
    val maximumDeclarationsPerRva: Int = 1_000_000,
    val maximumOwnersPerEntity: Int = 1_000_000,
    val maximumNameCodePoints: Int = 16_384,
    val maximumLocatorCodePoints: Int = 16_384,
    val maximumRetainedBytes: Long = 1024L * 1024L * 1024L,
) {
    init {
        require(maximumScannedDies in 1L..50_000_000L)
        require(maximumSubprograms in 1L..maximumScannedDies)
        require(maximumEntities in 1..10_000_000)
        require(maximumEmittedRvas in 1..10_000_000)
        require(maximumNonEmittedGroups in 1..10_000_000)
        require(maximumAliasesPerSubprogram in 1..1_000_000)
        require(maximumEvidencePerAliasPerSubprogram in 1..1_000_000)
        require(maximumEvidencePerSubprogram in 1..1_000_000)
        require(maximumCanonicalBytesPerSubprogram in 1..64 * 1024 * 1024)
        require(maximumAliasesPerEntity in 1..1_000_000)
        require(maximumEvidencePerAliasPerEntity in 1..1_000_000)
        require(maximumDeclarationsPerRva in 1..1_000_000)
        require(maximumOwnersPerEntity in 1..1_000_000)
        require(maximumNameCodePoints in 1..16_384)
        require(maximumLocatorCodePoints in 1..16_384)
        require(maximumRetainedBytes in 1L..16L * 1024L * 1024L * 1024L)
    }
}

internal data class FullTreeObservedFunctionEvidence(
    val locator: String,
    val unitId: String,
)

internal data class FullTreeObservedFunctionAlias(
    val name: String,
    val evidence: List<FullTreeObservedFunctionEvidence>,
)

/** One non-declaration DW_TAG_subprogram after artifact-backed reference/range resolution. */
internal data class FullTreeObservedSubprogram(
    val unitId: String,
    val dieOffset: ULong,
    val rvas: List<ULong>,
    val aliases: List<FullTreeObservedFunctionAlias>,
    val declaration: JsonObject,
    val inlineWithoutEmittedRange: Boolean,
)

/**
 * Deterministic historical-v3 grouping for facts already proven by a Kotlin DWARF scan.
 *
 * This class never reads an artifact and therefore cannot certify a [FullTreeObservedSubprogram].
 * Its constructor is internal and the release producer must keep it behind the artifact-backed
 * traversal. Its job is deliberately narrower: exact identities, deduplication, ownership,
 * ordering, and counts without consulting Python or an ACP agent.
 */
internal class FullTreeFunctionObservationAccumulator(
    private val shard: FullTreeFunctionObservationShardInput,
    private val limits: FullTreeFunctionObservationAccumulatorLimits =
        FullTreeFunctionObservationAccumulatorLimits(),
) {
    private val unitsById = shard.units.associateBy { it.accumulatorString("id") }
    private val emitted = TreeMap<ULong, MutableEmitted>()
    private val nonEmitted = HashMap<String, MutableNonEmitted>()
    private val observedSubprogramDies = HashSet<ULong>()
    private var scannedDies = 0L
    private var subprograms = 0L
    private var modeledRetainedBytes = 0L
    private var finished = false

    init {
        if (unitsById.size != shard.units.size) {
            accumulatorFail("function-observation shard contains duplicate compilation-unit IDs")
        }
    }

    /** Records every physical DIE record, including abbreviation-code-zero null records. */
    fun recordScannedDie() {
        recordScannedDies(1L)
    }

    /** Charges an already bounded, independently counted physical DIE stream in one step. */
    fun recordScannedDies(count: Long) {
        requireMutable()
        if (count <= 0L) {
            accumulatorFail("function-observation scanned-DIE increment is invalid")
        }
        scannedDies = add(scannedDies, count, "scanned DIE")
        if (scannedDies > limits.maximumScannedDies) {
            accumulatorFail("function-observation scan exceeds its DIE bound")
        }
    }

    /** Accepts one artifact-proven non-declaration subprogram. */
    fun accept(observation: FullTreeObservedSubprogram) {
        requireMutable()
        subprograms = increment(subprograms, "subprogram")
        if (subprograms > limits.maximumSubprograms) {
            accumulatorFail("function-observation scan exceeds its subprogram bound")
        }
        val unit = unitsById[observation.unitId]
            ?: accumulatorFail("observed subprogram owner is outside its authenticated shard")
        if (!observedSubprogramDies.add(observation.dieOffset)) {
            accumulatorFail("artifact scan emitted the same subprogram DIE more than once")
        }
        retain(MODELED_OBSERVED_DIE_BYTES, "observed DIE index")
        if (observation.aliases.isEmpty() || observation.aliases.size > limits.maximumAliasesPerSubprogram) {
            accumulatorFail("observed subprogram alias population is outside its bound")
        }
        if (observation.rvas.size > 1) {
            accumulatorFail("observed subprogram has more than one historical-v3 start RVA")
        }
        val canonicalBudget = CanonicalObservationBudget(limits.maximumCanonicalBytesPerSubprogram)
        val aliases = authenticateAliases(observation.aliases, observation.unitId, canonicalBudget)
        val declaration = snapshotDeclaration(observation.declaration, unit, canonicalBudget)
        val rvas = observation.rvas.toSortedSet()
        if (rvas.size != observation.rvas.size) {
            accumulatorFail("observed subprogram contains duplicate emitted RVAs")
        }
        if (rvas.isNotEmpty()) {
            rvas.forEach { rva -> acceptEmitted(rva, observation.unitId, aliases, declaration) }
        } else {
            acceptNonEmitted(observation, aliases, declaration, canonicalBudget)
        }
    }

    /** Freezes the exact schema-v1 historical-v3 document. */
    fun finish(
        inventoryIndexSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
    ): JsonObject {
        requireMutable()
        requireSha256(inventoryIndexSha256, "inventory index")
        requireSha256(richArtifactSha256, "rich artifact")
        requireSha256(scopeSha256, "scope")
        val nonEmittedDies = nonEmitted.values.fold(0L) { total, group ->
            add(total, group.dieOffsets.size.toLong(), "non-emitted DIE")
        }
        val minimumScannedDies = add(
            shard.units.size.toLong(),
            subprograms,
            "minimum scanned DIE",
        )
        if (scannedDies < minimumScannedDies) {
            accumulatorFail("function-observation scan cannot cover its compilation units and evidence")
        }
        finished = true

        val emittedDocuments = emitted.map { (rva, group) -> group.freeze(rva) }
        val nonEmittedDocuments = nonEmitted.values.map(MutableNonEmitted::freeze)
            .sortedWith { left, right ->
                FULL_TREE_CODE_POINT_ORDER.compare(
                    left.accumulatorString("id"),
                    right.accumulatorString("id"),
                )
            }
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "emittedRvas" to JsonPrimitive(emittedDocuments.size.toLong()),
                        "nonEmitted" to JsonPrimitive(nonEmittedDocuments.size.toLong()),
                        "nonEmittedDies" to JsonPrimitive(nonEmittedDies),
                        "scannedDies" to JsonPrimitive(scannedDies),
                        "units" to JsonPrimitive(shard.units.size.toLong()),
                    ),
                ),
                "emitted" to JsonArray(emittedDocuments),
                "nonEmitted" to JsonArray(nonEmittedDocuments),
                "oracle" to JsonObject(
                    mapOf(
                        "configurationSha256" to JsonPrimitive(FullTreeFunctionObservations.configurationSha256),
                        "inventoryIndexSha256" to JsonPrimitive(inventoryIndexSha256),
                        "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                        "scopeSha256" to JsonPrimitive(scopeSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shard" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(shard.identifier),
                        "inputSha256" to JsonPrimitive(shard.inputSha256),
                    ),
                ),
            ),
        )
    }

    private fun acceptEmitted(
        rva: ULong,
        unitId: String,
        aliases: List<AuthenticatedFunctionAlias>,
        declaration: JsonObject,
    ) {
        val group = emitted[rva] ?: run {
            if (emitted.size >= limits.maximumEmittedRvas) {
                accumulatorFail("function-observation emitted-RVA population exceeds its bound")
            }
            requireEntityCapacity()
            retain(MODELED_EMITTED_GROUP_BYTES, "emitted observation")
            MutableEmitted().also { emitted[rva] = it }
        }
        group.addOwner(unitId)
        group.addDeclaration(declaration)
        group.addAliases(aliases)
    }

    private fun acceptNonEmitted(
        observation: FullTreeObservedSubprogram,
        aliases: List<AuthenticatedFunctionAlias>,
        declaration: JsonObject,
        canonicalBudget: CanonicalObservationBudget,
    ) {
        val identityDocument = nonEmittedIdentityDocument(aliases, declaration)
        val identityBytes = canonicalBytes(identityDocument, "non-emitted observation identity")
        canonicalBudget.charge(identityBytes.size, "non-emitted observation identity")
        val identity = sha256(identityBytes).take(32)
        val group = nonEmitted[identity] ?: run {
            if (nonEmitted.size >= limits.maximumNonEmittedGroups) {
                accumulatorFail("function-observation non-emitted population exceeds its bound")
            }
            requireEntityCapacity()
            retain(
                modeledCanonicalRetention(identityBytes.size, MODELED_NON_EMITTED_GROUP_BYTES),
                "non-emitted observation",
            )
            retainCanonical(declaration, "non-emitted declaration")
            MutableNonEmitted(
                identityBytes = identityBytes,
                identifier = "non-emitted-observation-" +
                    sha256("${shard.identifier}:$identity".toByteArray(StandardCharsets.UTF_8)).take(32),
                initialDeclaration = declaration,
            ).also { nonEmitted[identity] = it }
        }
        if (!group.identityBytes.contentEquals(identityBytes)) {
            accumulatorFail("non-emitted observation identity digest collision")
        }
        group.addAliases(aliases)
        group.addDeclaration(declaration)
        group.addDie(observation.unitId, observation.dieOffset)
        group.addReason(
            if (observation.inlineWithoutEmittedRange) {
                "inline-no-emitted-range"
            } else {
                "definition-no-emitted-range"
            },
        )
    }

    private fun authenticateAliases(
        aliases: List<FullTreeObservedFunctionAlias>,
        unitId: String,
        canonicalBudget: CanonicalObservationBudget,
    ): List<AuthenticatedFunctionAlias> {
        val names = HashSet<String>()
        var evidenceItems = 0L
        return aliases.map { alias ->
            requireScalar(alias.name, limits.maximumNameCodePoints, "DWARF function name")
            if (!names.add(alias.name)) accumulatorFail("observed subprogram repeats an alias name")
            if (
                alias.evidence.isEmpty() ||
                alias.evidence.size > limits.maximumEvidencePerAliasPerSubprogram
            ) {
                accumulatorFail("observed function alias evidence population is outside its bound")
            }
            evidenceItems = add(
                evidenceItems,
                alias.evidence.size.toLong(),
                "subprogram alias evidence",
            )
            if (evidenceItems > limits.maximumEvidencePerSubprogram.toLong()) {
                accumulatorFail("observed subprogram aggregate evidence population exceeds its bound")
            }
            val evidence = LinkedHashMap<ByteArrayKey, JsonObject>()
            alias.evidence.forEach { item ->
                requireScalar(item.locator, limits.maximumLocatorCodePoints, "DWARF function locator")
                if (item.unitId != unitId) {
                    accumulatorFail("observed function evidence owner differs from its DIE owner")
                }
                val document = JsonObject(
                    mapOf(
                        "kind" to JsonPrimitive("dwarf-subprogram"),
                        "locator" to JsonPrimitive(item.locator),
                        "unitId" to JsonPrimitive(item.unitId),
                    ),
                )
                val bytes = canonicalBytes(document, "function alias evidence")
                canonicalBudget.charge(bytes.size, "function alias evidence")
                evidence[ByteArrayKey(bytes)] = document
            }
            AuthenticatedFunctionAlias(alias.name, evidence.values.toList())
        }
    }

    private fun snapshotDeclaration(
        declaration: JsonObject,
        unit: JsonObject,
        canonicalBudget: CanonicalObservationBudget,
    ): JsonObject {
        val bytes = canonicalBytes(declaration, "function declaration")
        canonicalBudget.charge(bytes.size, "function declaration")
        val snapshot = try {
            OracleJson.parseCanonical(bytes, FULL_TREE_FUNCTION_OBSERVATION_JSON_LIMITS) as? JsonObject
                ?: accumulatorFail("function declaration root is not an object")
        } catch (failure: FullTreeFunctionObservationException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationException("function declaration is not canonicalizable", failure)
        }
        if (snapshot.accumulatorString("unitSourcePath") != unit.accumulatorString("sourcePath")) {
            accumulatorFail("function declaration owner path differs from its compilation unit")
        }
        return snapshot
    }

    private fun requireMutable() {
        if (finished) accumulatorFail("function-observation accumulator is already frozen")
    }

    private fun requireEntityCapacity() {
        val entities = Math.addExact(emitted.size, nonEmitted.size)
        if (entities >= limits.maximumEntities) {
            accumulatorFail("function-observation entity population exceeds its bound")
        }
    }

    private fun retainCanonical(value: JsonElement, label: String) {
        val bytes = canonicalBytes(value, label)
        retain(modeledCanonicalRetention(bytes.size, MODELED_JSON_VALUE_BYTES), label)
    }

    private fun retain(bytes: Long, label: String) {
        if (bytes < 0L) accumulatorFail("function-observation $label retained-byte charge is invalid")
        modeledRetainedBytes = add(modeledRetainedBytes, bytes, "$label retained byte")
        if (modeledRetainedBytes > limits.maximumRetainedBytes) {
            accumulatorFail("function-observation retained-byte model exceeds its bound")
        }
    }

    private inner class MutableEmitted {
        private val aliases = TreeMap<String, LinkedHashMap<ByteArrayKey, JsonObject>>(FULL_TREE_CODE_POINT_ORDER)
        private val declarations = LinkedHashMap<ByteArrayKey, JsonObject>()
        private val ownerUnitIds = java.util.TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)

        fun addOwner(unitId: String) {
            if (ownerUnitIds.add(unitId)) {
                retain(modeledStringRetention(unitId, MODELED_SET_ENTRY_BYTES), "emitted owner")
            }
            if (ownerUnitIds.size > limits.maximumOwnersPerEntity) {
                accumulatorFail("emitted observation owner population exceeds its bound")
            }
        }

        fun addDeclaration(declaration: JsonObject) {
            val bytes = canonicalBytes(declaration, "emitted declaration")
            val key = ByteArrayKey(bytes)
            if (key !in declarations) {
                retain(
                    modeledCanonicalRetention(bytes.size, MODELED_MAP_ENTRY_BYTES),
                    "emitted declaration",
                )
                declarations[key] = declaration
            }
            if (declarations.size > limits.maximumDeclarationsPerRva) {
                accumulatorFail("emitted observation declaration population exceeds its bound")
            }
        }

        fun addAliases(observed: List<AuthenticatedFunctionAlias>) {
            observed.forEach { alias ->
                val evidence = aliases[alias.name] ?: run {
                    retain(modeledStringRetention(alias.name, MODELED_MAP_ENTRY_BYTES), "emitted alias")
                    LinkedHashMap<ByteArrayKey, JsonObject>().also { aliases[alias.name] = it }
                }
                alias.evidence.forEach { item ->
                    val bytes = canonicalBytes(item, "emitted alias evidence")
                    val key = ByteArrayKey(bytes)
                    if (key !in evidence) {
                        retain(
                            modeledCanonicalRetention(bytes.size, MODELED_MAP_ENTRY_BYTES),
                            "emitted alias evidence",
                        )
                        evidence[key] = item
                    }
                }
                if (evidence.size > limits.maximumEvidencePerAliasPerEntity) {
                    accumulatorFail("emitted alias evidence population exceeds its bound")
                }
            }
            if (aliases.size > limits.maximumAliasesPerEntity) {
                accumulatorFail("emitted alias population exceeds its bound")
            }
        }

        fun freeze(rva: ULong): JsonObject {
            val text = canonicalHex(rva)
            return JsonObject(
                mapOf(
                    "aliases" to JsonArray(freezeAliases(aliases)),
                    "declarations" to JsonArray(declarations.entries.sortedBy { it.key }.map { it.value }),
                    "id" to JsonPrimitive("function-rva-$text"),
                    "ownerUnitIds" to JsonArray(ownerUnitIds.map(::JsonPrimitive)),
                    "rva" to JsonPrimitive(text),
                ),
            )
        }
    }

    private inner class MutableNonEmitted(
        val identityBytes: ByteArray,
        private val identifier: String,
        initialDeclaration: JsonObject,
    ) {
        private val aliases = TreeMap<String, LinkedHashMap<ByteArrayKey, JsonObject>>(FULL_TREE_CODE_POINT_ORDER)
        private var declaration = initialDeclaration
        val dieOffsets = ArrayList<DieOffset>()
        private val reasonCodes = java.util.TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
        private val unitIds = java.util.TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)

        fun addAliases(observed: List<AuthenticatedFunctionAlias>) {
            observed.forEach { alias ->
                val evidence = aliases[alias.name] ?: run {
                    retain(modeledStringRetention(alias.name, MODELED_MAP_ENTRY_BYTES), "non-emitted alias")
                    LinkedHashMap<ByteArrayKey, JsonObject>().also { aliases[alias.name] = it }
                }
                alias.evidence.forEach { item ->
                    val bytes = canonicalBytes(item, "non-emitted alias evidence")
                    val key = ByteArrayKey(bytes)
                    if (key !in evidence) {
                        retain(
                            modeledCanonicalRetention(bytes.size, MODELED_MAP_ENTRY_BYTES),
                            "non-emitted alias evidence",
                        )
                        evidence[key] = item
                    }
                }
                if (evidence.size > limits.maximumEvidencePerAliasPerEntity) {
                    accumulatorFail("non-emitted alias evidence population exceeds its bound")
                }
            }
            if (aliases.size > limits.maximumAliasesPerEntity) {
                accumulatorFail("non-emitted alias population exceeds its bound")
            }
        }

        fun addDeclaration(candidate: JsonObject) {
            if (compareUnsigned(
                    canonicalBytes(candidate, "non-emitted declaration"),
                    canonicalBytes(declaration, "non-emitted declaration"),
                ) < 0
            ) {
                retainCanonical(candidate, "non-emitted declaration")
                declaration = candidate
            }
        }

        fun addDie(unitId: String, dieOffset: ULong) {
            dieOffsets += DieOffset(unitId, dieOffset)
            retain(MODELED_DIE_OFFSET_BYTES, "non-emitted DIE evidence")
            if (unitIds.add(unitId)) {
                retain(modeledStringRetention(unitId, MODELED_SET_ENTRY_BYTES), "non-emitted owner")
            }
            if (unitIds.size > limits.maximumOwnersPerEntity) {
                accumulatorFail("non-emitted observation owner population exceeds its bound")
            }
        }

        fun addReason(reason: String) {
            if (reasonCodes.add(reason)) {
                retain(modeledStringRetention(reason, MODELED_SET_ENTRY_BYTES), "non-emission reason")
            }
        }

        fun freeze(): JsonObject = JsonObject(
            mapOf(
                "aliases" to JsonArray(freezeAliases(aliases)),
                "declaration" to declaration,
                "dieOffsets" to JsonArray(
                    dieOffsets.sortedWith { left, right ->
                        val unit = FULL_TREE_CODE_POINT_ORDER.compare(left.unitId, right.unitId)
                        if (unit != 0) unit else left.offset.compareTo(right.offset)
                    }.map { die ->
                        JsonObject(
                            mapOf(
                                "dieOffset" to JsonPrimitive(canonicalHex(die.offset)),
                                "unitId" to JsonPrimitive(die.unitId),
                            ),
                        )
                    },
                ),
                "id" to JsonPrimitive(identifier),
                "reasonCodes" to JsonArray(reasonCodes.map(::JsonPrimitive)),
                "unitIds" to JsonArray(unitIds.map(::JsonPrimitive)),
            ),
        )
    }

    private fun freezeAliases(
        aliases: Map<String, LinkedHashMap<ByteArrayKey, JsonObject>>,
    ): List<JsonObject> = aliases.map { (name, evidence) ->
        JsonObject(
            mapOf(
                "evidence" to JsonArray(evidence.entries.sortedBy { it.key }.map { it.value }),
                "name" to JsonPrimitive(name),
            ),
        )
    }

    private data class DieOffset(val unitId: String, val offset: ULong)

    private companion object {
        const val MODELED_OBSERVED_DIE_BYTES = 64L
        const val MODELED_EMITTED_GROUP_BYTES = 512L
        const val MODELED_NON_EMITTED_GROUP_BYTES = 1024L
        const val MODELED_JSON_VALUE_BYTES = 256L
        const val MODELED_MAP_ENTRY_BYTES = 192L
        const val MODELED_SET_ENTRY_BYTES = 128L
        const val MODELED_DIE_OFFSET_BYTES = 96L

        fun modeledCanonicalRetention(byteCount: Int, overhead: Long): Long =
            Math.addExact(Math.multiplyExact(byteCount.toLong(), 2L), overhead)

        fun modeledStringRetention(value: String, overhead: Long): Long = Math.addExact(
            Math.multiplyExact(value.toByteArray(StandardCharsets.UTF_8).size.toLong(), 2L),
            overhead,
        )
    }
}

private data class AuthenticatedFunctionAlias(val name: String, val evidence: List<JsonObject>)

private class CanonicalObservationBudget(private val maximumBytes: Int) {
    private var bytes = 0L

    fun charge(count: Int, label: String) {
        bytes = add(bytes, count.toLong(), "canonical observation byte")
        if (bytes > maximumBytes.toLong()) {
            accumulatorFail("$label exceeds the per-subprogram canonical byte bound")
        }
    }
}

private fun nonEmittedIdentityDocument(
    aliases: List<AuthenticatedFunctionAlias>,
    declaration: JsonObject,
): JsonObject = JsonObject(
    mapOf(
        "aliasNames" to JsonArray(
            aliases.map { it.name }.sortedWith(FULL_TREE_CODE_POINT_ORDER).map(::JsonPrimitive),
        ),
        "declaration" to JsonObject(declaration.filterKeys { it != "unitSourcePath" }),
    ),
)

private class ByteArrayKey(bytes: ByteArray) : Comparable<ByteArrayKey> {
    private val snapshot = bytes.copyOf()

    override fun compareTo(other: ByteArrayKey): Int = compareUnsigned(snapshot, other.snapshot)
    override fun equals(other: Any?): Boolean = other is ByteArrayKey && snapshot.contentEquals(other.snapshot)
    override fun hashCode(): Int = snapshot.contentHashCode()
}

private fun JsonObject.accumulatorString(name: String): String {
    val value = this[name] as? JsonPrimitive
        ?: accumulatorFail("function-observation field is not a string: $name")
    if (!value.isString) accumulatorFail("function-observation field is not a string: $name")
    return value.content
}

private fun requireScalar(value: String, maximumCodePoints: Int, label: String) {
    if (value.isEmpty() || '\u0000' in value || value.codePointCount(0, value.length) > maximumCodePoints) {
        accumulatorFail("$label is empty, contains NUL, or exceeds its code-point bound")
    }
    var index = 0
    while (index < value.length) {
        val current = value[index]
        when {
            Character.isHighSurrogate(current) -> {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                    accumulatorFail("$label contains an unpaired surrogate")
                }
                index += 2
            }
            Character.isLowSurrogate(current) -> accumulatorFail("$label contains an unpaired surrogate")
            else -> index++
        }
    }
}

private fun canonicalBytes(value: JsonElement, label: String): ByteArray = try {
    OracleJson.canonicalBytes(value, FULL_TREE_FUNCTION_OBSERVATION_JSON_LIMITS)
} catch (failure: Exception) {
    throw FullTreeFunctionObservationException("$label is not bounded canonical JSON", failure)
}

/**
 * Transient canonicalization is independently capped while admitting the largest producer-valid
 * alias identity. Per-string code-point and collection bounds are enforced before this limit.
 */
internal val FULL_TREE_FUNCTION_OBSERVATION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumStringBytes = 64 * 1024 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
)

private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
    val common = minOf(left.size, right.size)
    for (index in 0 until common) {
        val compared = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
        if (compared != 0) return compared
    }
    return left.size.compareTo(right.size)
}

private fun canonicalHex(value: ULong): String = "0x${value.toString(16)}"

private fun requireSha256(value: String, label: String) {
    if (!value.matches(Regex("[0-9a-f]{64}"))) accumulatorFail("$label SHA-256 is invalid")
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private fun increment(value: Long, label: String): Long = add(value, 1L, label)

private fun add(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationException("$label count overflows", failure)
}

private fun accumulatorFail(message: String): Nothing = throw FullTreeFunctionObservationException(message)

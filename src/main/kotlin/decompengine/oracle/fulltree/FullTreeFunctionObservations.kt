package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal class FullTreeFunctionObservationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * An immutable shard work item derived from the authenticated scope and inventory snapshots.
 *
 * The constructor is internal so Kotlin tests and later Kotlin producers can pass work items
 * without a serialization round trip. Consumers must still call [FullTreeFunctionObservations.validateEnvelope]:
 * it derives the item again and rejects a forged digest or substituted unit snapshot.
 */
internal class FullTreeFunctionObservationShardInput internal constructor(
    val identifier: String,
    val inputSha256: String,
    units: List<JsonObject>,
) {
    val units: List<JsonObject> = Collections.unmodifiableList(units.map(::snapshotUnit))

    init {
        if (!identifier.matches(SHARD_IDENTIFIER)) {
            throw FullTreeFunctionObservationException("function observation shard identifier is invalid")
        }
        requireSha256(inputSha256, "function observation shard input")
        if (this.units.isEmpty()) {
            throw FullTreeFunctionObservationException("function observation shard has no compilation units")
        }
    }
}

/**
 * Kotlin-owned authenticated envelope contract for function-observation shard v1.
 *
 * [validateEnvelope] proves canonical structure, control bindings, identities, ordering, ownership,
 * and counts. It deliberately does not certify that a reported name, address, declaration, range,
 * or reason exists in the rich artifact. Only an artifact-backed Kotlin producer may use this
 * helper, and release publication must compare its output with that producer's deterministic scan.
 */
internal object FullTreeFunctionObservations {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(SCHEMA_NAME, PRODUCER_POLICY)
    }

    /**
     * Derives the historical v3 work-item bytes from private canonical scope/inventory snapshots.
     * No Python implementation is consulted by this production API.
     */
    fun shardInputs(
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        scope: JsonObject,
        scopeSha256: String,
    ): List<FullTreeFunctionObservationShardInput> {
        val controls = authenticateControls(inventory, inventoryArtifactSha256, scope, scopeSha256)
        return Collections.unmodifiableList(buildShardInputs(controls))
    }

    /** Validates one immutable envelope against its schema and externally anchored control inputs. */
    fun validateEnvelope(
        documentValue: JsonObject,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
    ) {
        val (document, _) = snapshotAndValidate(
            documentValue,
            SCHEMA_NAME,
            "function observation shard",
        )
        val controls = authenticateControls(inventory, inventoryArtifactSha256, scope, scopeSha256)
        val authenticatedShard = buildShardInputs(controls)
            .singleOrNull { it.identifier == shard.identifier }
            ?: throw FullTreeFunctionObservationException(
                "function observation shard is outside the authenticated inventory",
            )
        if (
            shard.inputSha256 != authenticatedShard.inputSha256 ||
            shard.units != authenticatedShard.units
        ) {
            throw FullTreeFunctionObservationException(
                "function observation shard input is not authenticated",
            )
        }

        val expectedOracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "inventoryIndexSha256" to JsonPrimitive(controls.inventoryIndexSha256),
                "richArtifactSha256" to JsonPrimitive(controls.richArtifactSha256),
                "scopeSha256" to JsonPrimitive(controls.scopeSha256),
            ),
        )
        val expectedShard = JsonObject(
            mapOf(
                "id" to JsonPrimitive(authenticatedShard.identifier),
                "inputSha256" to JsonPrimitive(authenticatedShard.inputSha256),
            ),
        )
        if (
            document.functionObject("oracle") != expectedOracle ||
            document.functionObject("shard") != expectedShard
        ) {
            throw FullTreeFunctionObservationException("function observation shard bindings do not match")
        }

        val semantics = FunctionObservationSemantics(authenticatedShard, controls.unitsById)
        document.functionArray("emitted").forEachIndexed { index, value ->
            semantics.acceptEmitted(value.functionObject("emitted observation $index"))
        }
        document.functionArray("nonEmitted").forEachIndexed { index, value ->
            semantics.acceptNonEmitted(value.functionObject("non-emitted observation $index"))
        }
        val counts = document.functionObject("counts")
        val scannedDies = counts.functionLong("scannedDies")
        if (counts != semantics.expectedCounts(scannedDies)) {
            throw FullTreeFunctionObservationException("function observation counts do not reconcile")
        }
        semantics.requireScanCoverage(scannedDies)

        val perShard = controls.scope.functionObject("bounds").functionObject("perShard")
        if (semantics.entityCount() > perShard.functionLong("entities")) {
            throw FullTreeFunctionObservationException(
                "function observation shard exceeds its authenticated entity bound",
            )
        }
        val canonicalSize = canonicalJsonByteSize(document)
        if (canonicalSize > perShard.functionLong("serializedBytes")) {
            throw FullTreeFunctionObservationException(
                "function observation shard exceeds its authenticated serialized-byte bound",
            )
        }
    }

    private fun authenticateControls(
        inventoryValue: JsonObject,
        inventoryArtifactSha256: String,
        scopeValue: JsonObject,
        scopeSha256: String,
    ): AuthenticatedFunctionObservationControls {
        requireSha256(scopeSha256, "scope")
        requireSha256(inventoryArtifactSha256, "inventory artifact")
        val (scope, scopeBytes) = snapshotAndValidate(scopeValue, "full-tree-scope", "full-tree scope")
        if (OracleArtifacts.sha256(scopeBytes) != scopeSha256) {
            throw FullTreeFunctionObservationException(
                "full-tree scope snapshot differs from its authenticated digest",
            )
        }
        val (inventory, inventoryBytes) = snapshotAndValidate(
            inventoryValue,
            "full-tree-inventory",
            "full-tree inventory",
        )
        if (OracleArtifacts.sha256(inventoryBytes) != inventoryArtifactSha256) {
            throw FullTreeFunctionObservationException(
                "full-tree inventory snapshot differs from its authenticated digest",
            )
        }

        val scopeOracle = scope.functionObject("oracle")
        val richArtifactSha256 = scopeOracle.functionString("richArtifactSha256")
        requireSha256(richArtifactSha256, "rich artifact")
        val expectedInventoryOracle = JsonObject(
            mapOf(
                "artifactManifestSha256" to scopeOracle.functionElement("artifactManifestSha256"),
                "id" to scopeOracle.functionElement("id"),
                "richArtifactSha256" to scopeOracle.functionElement("richArtifactSha256"),
                "scopeSha256" to JsonPrimitive(scopeSha256),
                "sourceLockSha256" to scopeOracle.functionElement("sourceLockSha256"),
            ),
        )
        if (inventory.functionObject("oracle") != expectedInventoryOracle) {
            throw FullTreeFunctionObservationException(
                "full-tree inventory bindings do not match the authenticated scope",
            )
        }

        val perShard = scope.functionObject("bounds").functionObject("perShard")
        val wholeRun = scope.functionObject("bounds").functionObject("wholeRun")
        BOUND_NAMES.forEach { name ->
            if (perShard.functionLong(name) > wholeRun.functionLong(name)) {
                throw FullTreeFunctionObservationException(
                    "authenticated per-shard $name bound exceeds the whole-run bound",
                )
            }
        }

        val units = inventory.functionArray("units").mapIndexed { index, value ->
            value.functionObject("inventory unit $index")
        }
        if (units.isEmpty()) {
            throw FullTreeFunctionObservationException("full-tree inventory has no compilation units")
        }
        val expectedUnitOrder = units.sortedWith(INVENTORY_UNIT_ORDER)
        if (units != expectedUnitOrder) {
            throw FullTreeFunctionObservationException("inventory units are not canonically ordered")
        }
        val unitsById = LinkedHashMap<String, JsonObject>()
        val sourcePaths = HashSet<String>()
        val dwarfOffsets = HashSet<ULong>()
        val unitsByShard = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
        units.forEach { unit ->
            val id = unit.functionString("id")
            val sourcePath = unit.functionString("sourcePath")
            if (unitsById.put(id, unit) != null || !sourcePaths.add(sourcePath)) {
                throw FullTreeFunctionObservationException(
                    "inventory compilation-unit identities are not unique",
                )
            }
            val expectedId = "cu-" + sha256(sourcePath.toByteArray(StandardCharsets.UTF_8)).take(32)
            if (id != expectedId) {
                throw FullTreeFunctionObservationException(
                    "inventory compilation-unit ID differs from its source-path identity",
                )
            }
            val expectedKind = if (sourcePath.startsWith("generated/")) "generated" else "handwritten"
            if (unit.functionString("sourceKind") != expectedKind) {
                throw FullTreeFunctionObservationException(
                    "inventory source kind differs from its normalized source path",
                )
            }
            val expectedShard = try {
                FullTreeScopeControl.shardForSourcePath(scope, sourcePath)
            } catch (failure: Exception) {
                throw FullTreeFunctionObservationException(
                    "inventory source path cannot be assigned by the authenticated shard policy",
                    failure,
                )
            }
            if (unit.functionString("shardId") != expectedShard) {
                throw FullTreeFunctionObservationException(
                    "inventory compilation-unit shard differs from authenticated scope policy",
                )
            }
            val dwarfOffset = parseAddress(unit.functionString("dwarfOffset"), "inventory DWARF offset")
            if (!dwarfOffsets.add(dwarfOffset)) {
                throw FullTreeFunctionObservationException(
                    "inventory compilation-unit DWARF offsets are not unique",
                )
            }
            unitsByShard.getOrPut(expectedShard) { arrayListOf() }.add(id)
        }

        val expectedShards = JsonArray(
            unitsByShard.map { (identifier, unitIds) ->
                JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(identifier),
                        "unitIds" to JsonArray(
                            unitIds.sortedWith(FULL_TREE_CODE_POINT_ORDER).map(::JsonPrimitive),
                        ),
                    ),
                )
            },
        )
        if (inventory.functionArray("shards") != expectedShards) {
            throw FullTreeFunctionObservationException(
                "inventory shard ownership does not reconcile exactly",
            )
        }
        if (unitsByShard.values.any { it.size.toLong() > perShard.functionLong("compilationUnits") }) {
            throw FullTreeFunctionObservationException(
                "inventory shard exceeds its authenticated compilation-unit bound",
            )
        }
        if (units.size.toLong() > wholeRun.functionLong("compilationUnits")) {
            throw FullTreeFunctionObservationException(
                "inventory exceeds its authenticated whole-run compilation-unit bound",
            )
        }
        if (inventoryBytes.size.toLong() > wholeRun.functionLong("serializedBytes")) {
            throw FullTreeFunctionObservationException(
                "inventory exceeds its authenticated whole-run serialized-byte bound",
            )
        }

        val generated = units.count { it.functionString("sourceKind") == "generated" }.toLong()
        val expectedCounts = JsonObject(
            mapOf(
                "compilationUnits" to JsonPrimitive(units.size.toLong()),
                "generatedUnits" to JsonPrimitive(generated),
                "handwrittenUnits" to JsonPrimitive(units.size.toLong() - generated),
                "shards" to JsonPrimitive(unitsByShard.size.toLong()),
            ),
        )
        if (inventory.functionObject("counts") != expectedCounts) {
            throw FullTreeFunctionObservationException("inventory counts do not reconcile")
        }

        val inventoryIndexSha256 = inventory.functionString("indexSha256")
        requireSha256(inventoryIndexSha256, "inventory index")
        if (inventoryIndexSha256 != inventoryIndexSha256(units)) {
            throw FullTreeFunctionObservationException("inventory index digest does not reconcile")
        }
        return AuthenticatedFunctionObservationControls(
            scope = scope,
            scopeSha256 = scopeSha256,
            inventory = inventory,
            inventoryIndexSha256 = inventoryIndexSha256,
            richArtifactSha256 = richArtifactSha256,
            unitsById = Collections.unmodifiableMap(unitsById),
        )
    }

    private fun buildShardInputs(
        controls: AuthenticatedFunctionObservationControls,
    ): List<FullTreeFunctionObservationShardInput> = controls.inventory.functionArray("shards").mapIndexed {
            index,
            value,
        ->
        val shard = value.functionObject("inventory shard $index")
        val identifier = shard.functionString("id")
        val records = shard.functionArray("unitIds").map { rawId ->
            val unitId = rawId.functionString("inventory shard unit ID")
            controls.unitsById[unitId] ?: throw FullTreeFunctionObservationException(
                "inventory shard $identifier references unknown unit $unitId",
            )
        }
        val payload = JsonObject(
            mapOf(
                "inventoryIndexSha256" to JsonPrimitive(controls.inventoryIndexSha256),
                "producerConfigurationSha256" to JsonPrimitive(configurationSha256),
                "richArtifactSha256" to JsonPrimitive(controls.richArtifactSha256),
                "scopeSha256" to JsonPrimitive(controls.scopeSha256),
                "shardId" to JsonPrimitive(identifier),
                "units" to JsonArray(records),
            ),
        )
        FullTreeFunctionObservationShardInput(
            identifier,
            sha256(canonicalBytes(payload, "function observation shard input")),
            records,
        )
    }

    private fun snapshotAndValidate(
        value: JsonObject,
        schemaName: String,
        label: String,
    ): Pair<JsonObject, ByteArray> {
        val bytes = canonicalBytes(value, label)
        val snapshot = try {
            OracleJson.parseCanonical(bytes, CONTROL_JSON_LIMITS) as? JsonObject
                ?: throw FullTreeFunctionObservationException("$label root is not an object")
        } catch (failure: FullTreeFunctionObservationException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationException("$label cannot be snapshotted", failure)
        }
        try {
            OracleSchemas.validate(schemaName, snapshot)
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationException("$label fails bundled schema validation", failure)
        }
        return snapshot to bytes
    }

    private fun inventoryIndexSha256(units: List<JsonObject>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(INVENTORY_INDEX_DOMAIN)
        units.forEach { unit ->
            digest.update(MessageDigest.getInstance("SHA-256").digest(canonicalBytes(unit, "inventory unit")))
        }
        return digest.digest().hexString()
    }

    private val PRODUCER_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-function-observations"),
            "version" to JsonPrimitive(3),
            "emittedIdentity" to JsonPrimitive("image-relative-start-rva"),
            "ownershipCandidates" to JsonPrimitive("all-source-aligned-dwarf-compilation-units"),
            "declarationPaths" to JsonPrimitive("explicit-scope-map-or-external-path-sha256"),
            "nonEmittedIdentity" to JsonPrimitive("unit-id-and-die-relative-offset"),
            "nonEmissionReasons" to JsonPrimitive(
                "dwarf-inline-attribute-or-definition-without-emitted-range",
            ),
            "nonEmittedCanonicalization" to JsonPrimitive(
                "declaration-and-alias-names-with-all-unit-die-locators-retained",
            ),
        ),
    )
}

private data class AuthenticatedFunctionObservationControls(
    val scope: JsonObject,
    val scopeSha256: String,
    val inventory: JsonObject,
    val inventoryIndexSha256: String,
    val richArtifactSha256: String,
    val unitsById: Map<String, JsonObject>,
)

private data class DwarfUnitBounds(val start: ULong, val endExclusive: ULong?)

private class FunctionObservationSemantics(
    shard: FullTreeFunctionObservationShardInput,
    allUnitsById: Map<String, JsonObject>,
) {
    private val shardIdentifier = shard.identifier
    private val unitsById = shard.units.associateBy { it.functionString("id") }
    private val unitPaths = unitsById.mapValues { (_, unit) -> unit.functionString("sourcePath") }
    private val unitBounds = buildUnitBounds(allUnitsById.values)
    private val observedNonEmittedDieOffsets = HashSet<ULong>()
    private var previousRva: ULong? = null
    private var previousNonEmittedId: String? = null
    private var emitted = 0L
    private var nonEmitted = 0L
    private var nonEmittedDies = 0L

    fun acceptEmitted(record: JsonObject) {
        val rvaText = record.functionString("rva")
        val rva = parseAddress(rvaText, "emitted function RVA")
        val prior = previousRva
        if (prior != null && rva <= prior) {
            throw FullTreeFunctionObservationException(
                if (rva == prior) {
                    "emitted function observations contain a duplicate RVA"
                } else {
                    "emitted function observations are not ordered by RVA"
                },
            )
        }
        previousRva = rva
        if (record.functionString("id") != "function-rva-$rvaText") {
            throw FullTreeFunctionObservationException("emitted function identity does not match its RVA")
        }

        val ownerIds = record.functionArray("ownerUnitIds").strings("emitted owner unit ID")
        requireStrictCodePointOrder(ownerIds, "emitted owner unit IDs")
        if (ownerIds.any { it !in unitsById }) {
            throw FullTreeFunctionObservationException("emitted function owner is outside its shard")
        }

        val aliases = record.functionArray("aliases").objects("emitted alias")
        validateAliases(aliases, ownerIds.toSet(), "emitted")

        val declarations = record.functionArray("declarations").objects("emitted declaration")
        requireStrictCanonicalByteOrder(declarations, "emitted declarations")
        declarations.forEach { declaration -> validateDeclaration(declaration, ownerIds.toSet()) }
        val declarationOwnerPaths = declarations.mapTo(hashSetOf()) {
            it.functionString("unitSourcePath")
        }
        val expectedOwnerPaths = ownerIds.mapTo(hashSetOf()) { unitPaths.getValue(it) }
        if (declarationOwnerPaths != expectedOwnerPaths) {
            throw FullTreeFunctionObservationException(
                "emitted declarations do not cover their exact compilation-unit ownership",
            )
        }
        emitted = increment(emitted, "emitted function")
    }

    fun acceptNonEmitted(record: JsonObject) {
        val identifier = record.functionString("id")
        val previous = previousNonEmittedId
        if (previous != null && FULL_TREE_CODE_POINT_ORDER.compare(previous, identifier) >= 0) {
            throw FullTreeFunctionObservationException(
                if (previous == identifier) {
                    "non-emitted function observations duplicate an identity"
                } else {
                    "non-emitted function observations are not canonically ordered"
                },
            )
        }
        previousNonEmittedId = identifier

        val unitIds = record.functionArray("unitIds").strings("non-emitted unit ID")
        requireStrictCodePointOrder(unitIds, "non-emitted unit IDs")
        if (unitIds.any { it !in unitsById }) {
            throw FullTreeFunctionObservationException("non-emitted function owner is outside its shard")
        }
        val unitSet = unitIds.toSet()

        val aliases = record.functionArray("aliases").objects("non-emitted alias")
        val evidenceUnits = validateAliases(aliases, unitSet, "non-emitted")
        if (evidenceUnits != unitSet) {
            throw FullTreeFunctionObservationException(
                "non-emitted alias evidence does not cover exact ownership",
            )
        }

        val declaration = record.functionObject("declaration")
        validateDeclaration(declaration, unitSet)
        val selectedDeclaration = unitIds.map { unitId ->
            JsonObject(declaration.toMutableMap().apply {
                this["unitSourcePath"] = JsonPrimitive(unitPaths.getValue(unitId))
            })
        }.minWithOrNull(CANONICAL_OBJECT_ORDER)
            ?: throw FullTreeFunctionObservationException("non-emitted function has no owner")
        if (declaration != selectedDeclaration) {
            throw FullTreeFunctionObservationException(
                "non-emitted declaration is not the canonical owner declaration",
            )
        }

        val dieOffsets = record.functionArray("dieOffsets").objects("non-emitted DIE offset")
        var previousDieUnit: String? = null
        var previousDieOffset: ULong? = null
        val dieUnits = HashSet<String>()
        dieOffsets.forEach { evidence ->
            val unitId = evidence.functionString("unitId")
            val dieOffset = parseAddress(evidence.functionString("dieOffset"), "non-emitted DIE offset")
            if (unitId !in unitSet) {
                throw FullTreeFunctionObservationException(
                    "non-emitted DIE evidence is outside its declared ownership",
                )
            }
            val unitComparison = previousDieUnit?.let { FULL_TREE_CODE_POINT_ORDER.compare(it, unitId) }
            val priorDieOffset = previousDieOffset
            if (
                unitComparison != null &&
                (unitComparison > 0 || unitComparison == 0 && priorDieOffset != null && dieOffset <= priorDieOffset)
            ) {
                throw FullTreeFunctionObservationException(
                    "non-emitted DIE evidence is not strictly canonically ordered",
                )
            }
            val bounds = unitBounds.getValue(unitId)
            if (dieOffset <= bounds.start ||
                bounds.endExclusive?.let { end -> dieOffset >= end } == true
            ) {
                throw FullTreeFunctionObservationException(
                    "non-emitted DIE evidence is outside its compilation unit",
                )
            }
            if (!observedNonEmittedDieOffsets.add(dieOffset)) {
                throw FullTreeFunctionObservationException(
                    "non-emitted DIE evidence duplicates an absolute offset",
                )
            }
            previousDieUnit = unitId
            previousDieOffset = dieOffset
            dieUnits += unitId
        }
        if (dieUnits != unitSet) {
            throw FullTreeFunctionObservationException(
                "non-emitted DIE evidence does not cover exact ownership",
            )
        }

        val reasonCodes = record.functionArray("reasonCodes").strings("non-emission reason code")
        requireStrictCodePointOrder(reasonCodes, "non-emission reason codes")
        val expectedId = nonEmittedIdentity(aliases, declaration, shardIdentifier)
        if (identifier != expectedId) {
            throw FullTreeFunctionObservationException(
                "non-emitted function identity does not match canonical evidence",
            )
        }

        nonEmitted = increment(nonEmitted, "non-emitted function")
        nonEmittedDies = add(nonEmittedDies, dieOffsets.size.toLong(), "non-emitted DIE")
    }

    fun entityCount(): Long = add(emitted, nonEmitted, "function observation entity")

    fun expectedCounts(scannedDies: Long): JsonObject = JsonObject(
        mapOf(
            "emittedRvas" to JsonPrimitive(emitted),
            "nonEmitted" to JsonPrimitive(nonEmitted),
            "nonEmittedDies" to JsonPrimitive(nonEmittedDies),
            "scannedDies" to JsonPrimitive(scannedDies),
            "units" to JsonPrimitive(unitsById.size.toLong()),
        ),
    )

    fun requireScanCoverage(scannedDies: Long) {
        val minimumScannedDies = add(unitsById.size.toLong(), nonEmittedDies, "minimum scanned DIE")
        if (scannedDies < minimumScannedDies) {
            throw FullTreeFunctionObservationException(
                "function observation scanned-DIE count cannot cover its authenticated evidence",
            )
        }
    }

    private fun buildUnitBounds(units: Collection<JsonObject>): Map<String, DwarfUnitBounds> {
        val ordered = units.map { unit ->
            unit.functionString("id") to parseAddress(
                unit.functionString("dwarfOffset"),
                "inventory DWARF offset",
            )
        }.sortedBy { it.second }
        return ordered.mapIndexed { index, (unitId, start) ->
            unitId to DwarfUnitBounds(start, ordered.getOrNull(index + 1)?.second)
        }.toMap()
    }

    private fun validateAliases(
        aliases: List<JsonObject>,
        owners: Set<String>,
        label: String,
    ): Set<String> {
        val names = aliases.map { it.functionString("name") }
        requireStrictCodePointOrder(names, "$label alias names")
        val observedOwners = HashSet<String>()
        aliases.forEach { alias ->
            val evidence = alias.functionArray("evidence").objects("$label alias evidence")
            requireStrictCanonicalByteOrder(evidence, "$label alias evidence")
            evidence.forEach { item ->
                if (item.functionString("kind") != "dwarf-subprogram") {
                    throw FullTreeFunctionObservationException("$label alias evidence kind is invalid")
                }
                val unitId = item.functionString("unitId")
                if (unitId !in owners) {
                    throw FullTreeFunctionObservationException("$label alias evidence is outside ownership")
                }
                observedOwners += unitId
            }
        }
        return observedOwners
    }

    private fun validateDeclaration(declaration: JsonObject, owners: Set<String>) {
        val unitSourcePath = declaration.functionString("unitSourcePath")
        if (owners.none { unitPaths.getValue(it) == unitSourcePath }) {
            throw FullTreeFunctionObservationException(
                "function declaration unit source path is outside ownership",
            )
        }
        val fileIndex = declaration.nullableNonNegativeLong("fileIndex")
        declaration.nullableNonNegativeLong("line")
        declaration.nullableNonNegativeLong("column")
        val sourcePath = declaration.nullableString("sourcePath")
        val externalPathSha256 = declaration.nullableString("externalPathSha256")
        if (sourcePath != null && externalPathSha256 != null) {
            throw FullTreeFunctionObservationException(
                "function declaration cannot have both an in-scope and external path",
            )
        }
        if (fileIndex == null && (sourcePath != null || externalPathSha256 != null)) {
            throw FullTreeFunctionObservationException(
                "function declaration path evidence requires a DWARF file index",
            )
        }
    }
}

private fun nonEmittedIdentity(
    aliases: List<JsonObject>,
    declaration: JsonObject,
    shardIdentifier: String,
): String {
    val declarationIdentity = JsonObject(declaration.filterKeys { it != "unitSourcePath" })
    val identityDocument = JsonObject(
        mapOf(
            "aliasNames" to JsonArray(aliases.map { JsonPrimitive(it.functionString("name")) }),
            "declaration" to declarationIdentity,
        ),
    )
    val identity = sha256(canonicalBytes(identityDocument, "non-emitted function identity")).take(32)
    val shardIdentity = sha256("$shardIdentifier:$identity".toByteArray(StandardCharsets.UTF_8)).take(32)
    return "non-emitted-observation-$shardIdentity"
}

private fun requireStrictCodePointOrder(values: List<String>, label: String) {
    var previous: String? = null
    values.forEach { current ->
        val prior = previous
        if (prior != null && FULL_TREE_CODE_POINT_ORDER.compare(prior, current) >= 0) {
            throw FullTreeFunctionObservationException(
                if (prior == current) "$label contain a duplicate" else "$label are not canonically ordered",
            )
        }
        previous = current
    }
}

private fun requireStrictCanonicalByteOrder(values: List<JsonObject>, label: String) {
    var previous: ByteArray? = null
    values.forEach { value ->
        val current = canonicalBytes(value, label)
        val prior = previous
        if (prior != null && compareUnsignedBytes(prior, current) >= 0) {
            throw FullTreeFunctionObservationException(
                if (prior.contentEquals(current)) "$label contain a duplicate" else "$label are not canonically ordered",
            )
        }
        previous = current
    }
}

private fun compareUnsignedBytes(left: ByteArray, right: ByteArray): Int {
    val common = minOf(left.size, right.size)
    for (index in 0 until common) {
        val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
        if (comparison != 0) return comparison
    }
    return left.size.compareTo(right.size)
}

private val CANONICAL_OBJECT_ORDER = Comparator<JsonObject> { left, right ->
    compareUnsignedBytes(
        canonicalBytes(left, "canonical function observation object"),
        canonicalBytes(right, "canonical function observation object"),
    )
}

private fun snapshotUnit(unit: JsonObject): JsonObject {
    val bytes = canonicalBytes(unit, "function observation unit snapshot")
    return try {
        OracleJson.parseCanonical(bytes, CONTROL_JSON_LIMITS) as JsonObject
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationException("function observation unit cannot be snapshotted", failure)
    }
}

private fun canonicalBytes(value: JsonElement, label: String): ByteArray = try {
    OracleJson.canonicalBytes(value, CONTROL_JSON_LIMITS)
} catch (failure: Exception) {
    throw FullTreeFunctionObservationException("$label exceeds strict canonical JSON limits", failure)
}

private fun JsonObject.functionElement(name: String): JsonElement = this[name]
    ?: throw FullTreeFunctionObservationException("function observation field is absent: $name")

private fun JsonObject.functionObject(name: String): JsonObject = functionElement(name).functionObject(name)

private fun JsonElement.functionObject(label: String): JsonObject = this as? JsonObject
    ?: throw FullTreeFunctionObservationException("$label is not an object")

private fun JsonObject.functionArray(name: String): JsonArray = functionElement(name) as? JsonArray
    ?: throw FullTreeFunctionObservationException("function observation field is not an array: $name")

private fun JsonObject.functionString(name: String): String = functionElement(name).functionString(name)

private fun JsonElement.functionString(label: String): String {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeFunctionObservationException("$label is not a string")
    if (!primitive.isString) throw FullTreeFunctionObservationException("$label is not a string")
    return primitive.content
}

private fun JsonObject.functionLong(name: String): Long {
    val primitive = functionElement(name) as? JsonPrimitive
        ?: throw FullTreeFunctionObservationException("function observation field is not an integer: $name")
    if (primitive.isString || primitive.booleanOrNull != null || !INTEGER_TOKEN.matches(primitive.content)) {
        throw FullTreeFunctionObservationException("function observation field is not an integer: $name")
    }
    return primitive.longOrNull
        ?: throw FullTreeFunctionObservationException("function observation integer exceeds Long: $name")
}

private fun JsonObject.nullableString(name: String): String? {
    val value = functionElement(name)
    if (value === JsonNull) return null
    return value.functionString(name)
}

private fun JsonObject.nullableNonNegativeLong(name: String): Long? {
    val value = functionElement(name)
    if (value === JsonNull) return null
    val primitive = value as? JsonPrimitive
        ?: throw FullTreeFunctionObservationException("function declaration $name is not an integer")
    if (primitive.isString || primitive.booleanOrNull != null || !NON_NEGATIVE_INTEGER_TOKEN.matches(primitive.content)) {
        throw FullTreeFunctionObservationException("function declaration $name is not a non-negative integer")
    }
    return primitive.longOrNull
        ?: throw FullTreeFunctionObservationException("function declaration $name exceeds Long")
}

private fun JsonArray.strings(label: String): List<String> = mapIndexed { index, value ->
    value.functionString("$label $index")
}

private fun parseAddress(value: String, label: String): ULong {
    requireCanonicalAddress(value, label)
    return try {
        value.removePrefix("0x").toULong(16)
    } catch (failure: NumberFormatException) {
        throw FullTreeFunctionObservationException("$label exceeds the 64-bit address range", failure)
    }
}

private fun requireCanonicalAddress(value: String, label: String) {
    if (!value.matches(CANONICAL_ADDRESS)) {
        throw FullTreeFunctionObservationException("$label is not a canonical 64-bit hexadecimal address")
    }
}

private fun requireSha256(value: String, label: String) {
    if (!value.matches(SHA256)) {
        throw FullTreeFunctionObservationException("$label digest is invalid")
    }
}

private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value).hexString()

private fun ByteArray.hexString(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun increment(value: Long, label: String): Long = add(value, 1L, label)

private fun add(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationException("$label count exceeds the supported range", failure)
}

/** Exact size of OracleJson's two-space, UTF-8 canonical encoding, including its final newline. */
private fun canonicalJsonByteSize(value: JsonElement): Long = add(canonicalValueByteSize(value, 0), 1L, "JSON byte")

private fun canonicalValueByteSize(value: JsonElement, indentation: Int): Long = when (value) {
    JsonNull -> 4L
    is JsonObject -> {
        if (value.isEmpty()) {
            2L
        } else {
            var size = 2L // "{\n"
            value.entries.forEachIndexed { index, entry ->
                size = add(size, Math.multiplyExact((indentation + 1).toLong(), 2L), "JSON byte")
                size = add(size, canonicalStringByteSize(entry.key), "JSON byte")
                size = add(size, 2L, "JSON byte") // ": "
                size = add(size, canonicalValueByteSize(entry.value, indentation + 1), "JSON byte")
                if (index != value.size - 1) size = add(size, 1L, "JSON byte")
                size = add(size, 1L, "JSON byte") // newline
            }
            size = add(size, Math.multiplyExact(indentation.toLong(), 2L), "JSON byte")
            add(size, 1L, "JSON byte") // "}"
        }
    }
    is JsonArray -> {
        if (value.isEmpty()) {
            2L
        } else {
            var size = 2L // "[\n"
            value.forEachIndexed { index, element ->
                size = add(size, Math.multiplyExact((indentation + 1).toLong(), 2L), "JSON byte")
                size = add(size, canonicalValueByteSize(element, indentation + 1), "JSON byte")
                if (index != value.size - 1) size = add(size, 1L, "JSON byte")
                size = add(size, 1L, "JSON byte") // newline
            }
            size = add(size, Math.multiplyExact(indentation.toLong(), 2L), "JSON byte")
            add(size, 1L, "JSON byte") // "]"
        }
    }
    is JsonPrimitive -> if (value.isString) {
        canonicalStringByteSize(value.content)
    } else {
        (OracleJson.canonicalBytes(value).size - 1).toLong()
    }
}

private fun canonicalStringByteSize(value: String): Long {
    var size = 2L
    var index = 0
    while (index < value.length) {
        val character = value[index]
        val bytes = when (character) {
            '"', '\\', '\b', '\u000c', '\n', '\r', '\t' -> 2
            else -> when {
                character.code < 0x20 -> 6
                Character.isHighSurrogate(character) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                        throw FullTreeFunctionObservationException(
                            "canonical JSON string contains an unpaired high surrogate",
                        )
                    }
                    index++
                    4
                }
                Character.isLowSurrogate(character) -> throw FullTreeFunctionObservationException(
                    "canonical JSON string contains an unpaired low surrogate",
                )
                character.code <= 0x7f -> 1
                character.code <= 0x7ff -> 2
                else -> 3
            }
        }
        size = add(size, bytes.toLong(), "JSON string byte")
        index++
    }
    return size
}

private val INVENTORY_UNIT_ORDER = Comparator<JsonObject> { left, right ->
    val path = FULL_TREE_CODE_POINT_ORDER.compare(
        left.functionString("sourcePath"),
        right.functionString("sourcePath"),
    )
    if (path != 0) path else FULL_TREE_CODE_POINT_ORDER.compare(
        left.functionString("id"),
        right.functionString("id"),
    )
}
private val CONTROL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
)
private val INVENTORY_INDEX_DOMAIN = "full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8)
private val BOUND_NAMES = listOf(
    "compilationUnits",
    "cpuSeconds",
    "entities",
    "serializedBytes",
    "wallClockSeconds",
    "maximumResidentBytes",
)
private const val SCHEMA_NAME = "full-tree-function-observations"
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val SHA256 = Regex("[0-9a-f]{64}")
private val CANONICAL_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val INTEGER_TOKEN = Regex("-?(?:0|[1-9][0-9]*)")
private val NON_NEGATIVE_INTEGER_TOKEN = Regex("0|[1-9][0-9]*")

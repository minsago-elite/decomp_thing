package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class FullTreeInventoryGeneration(
    val inventory: JsonObject,
    val indexSha256: String,
    val artifactSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
)

/** Authoritative Kotlin/JVM generation and validation of full-tree-inventory v1. */
object FullTreeInventoryControl {
    fun generateAndPublish(
        richArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        output: Path,
        maximumWorkers: Int,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): FullTreeInventoryGeneration {
        if (maximumWorkers !in 1..limits.maximumWorkers) {
            throw FullTreeControlException("inventory worker count exceeds its configured bound")
        }
        FullTreeScopeControl.validate(scope, limits)
        val outputPath = output.toAbsolutePath().normalize()
        requireDistinctControlOutput(outputPath, "rich artifact" to richArtifact)
        val scratchParent = outputPath.parent
            ?: throw FullTreeControlException("inventory output must name a file")
        requireStableDirectory(scratchParent, "inventory output parent")
        val artifact = StableControlFile.open(
            richArtifact,
            limits.maximumRichArtifactBytes,
            "rich artifact",
        )
        try {
            val artifactSha256 = artifact.sha256()
            if (artifactSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                throw FullTreeControlException("rich artifact does not match the full-tree scope")
            }
            val observed = FullTreeDwarfCompilationUnits.read(
                artifact,
                scratchParent,
                scope.document,
                limits,
            )
            artifact.verifyUnchanged("rich artifact")
            val document = buildInventory(observed, scope, limits)
            validate(document, scope, limits)
            val bytes = publishCanonicalControl(outputPath, document, limits.maximumInventoryBytes)
            return FullTreeInventoryGeneration(
                inventory = document,
                indexSha256 = document.controlString("indexSha256"),
                artifactSha256 = artifactSha256,
                outputSha256 = OracleArtifacts.sha256(bytes),
                outputBytes = bytes.size.toLong(),
            )
        } finally {
            artifact.close()
        }
    }

    fun loadAndValidate(
        path: Path,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): JsonObject {
        val (document, _) = readCanonicalControlObject(
            path,
            limits.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        validate(document, scope, limits)
        return document
    }

    fun validate(
        value: JsonObject,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ) {
        FullTreeScopeControl.validate(scope, limits)
        val (document, bytes) = snapshotControlObject(
            value,
            limits.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        val units = document.controlArray("units").controlObjects("inventory units")
        if (units.size > limits.maximumCompilationUnits) {
            throw FullTreeControlException("inventory exceeds its implementation compilation-unit bound")
        }
        val sortedUnits = units.sortedWith(INVENTORY_UNIT_ORDER)
        if (units != sortedUnits) throw FullTreeControlException("inventory units are not canonically ordered")
        if (document.controlString("indexSha256") != inventoryIndexSha256(units, limits)) {
            throw FullTreeControlException("inventory index hash does not reconcile")
        }
        val expectedOracle = JsonObject(
            mapOf(
                "artifactManifestSha256" to scope.document.controlObject("oracle")["artifactManifestSha256"]!!,
                "id" to scope.document.controlObject("oracle")["id"]!!,
                "richArtifactSha256" to scope.document.controlObject("oracle")["richArtifactSha256"]!!,
                "scopeSha256" to JsonPrimitive(scope.sha256),
                "sourceLockSha256" to scope.document.controlObject("oracle")["sourceLockSha256"]!!,
            ),
        )
        if (document.controlObject("oracle") != expectedOracle) {
            throw FullTreeControlException("inventory oracle bindings do not match scope")
        }
        val ids = HashSet<String>()
        val paths = HashSet<String>()
        val byShard = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
        units.forEach { unit ->
            val id = unit.controlString("id")
            val path = unit.controlString("sourcePath")
            if (!ids.add(id) || !paths.add(path)) {
                throw FullTreeControlException("inventory unit source identities are not unique")
            }
            if (id != compilationUnitId(path)) {
                throw FullTreeControlException("inventory unit ID differs from its source-path identity")
            }
            val expectedKind = if (path.startsWith("generated/")) "generated" else "handwritten"
            if (unit.controlString("sourceKind") != expectedKind) {
                throw FullTreeControlException("inventory unit source kind differs from its normalized path")
            }
            val expectedShard = FullTreeScopeControl.shardForSourcePath(scope.document, path)
            if (unit.controlString("shardId") != expectedShard) {
                throw FullTreeControlException("inventory unit shard differs from authenticated scope policy")
            }
            requireCanonicalHex(unit.controlString("dwarfOffset"), "inventory DWARF offset")
            byShard.getOrPut(expectedShard) { arrayListOf() }.add(id)
        }
        val expectedShards = JsonArray(
            byShard.map { (id, unitIds) ->
                JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(id),
                        "unitIds" to JsonArray(unitIds.sortedWith(FULL_TREE_CODE_POINT_ORDER).map(::JsonPrimitive)),
                    ),
                )
            },
        )
        if (document.controlArray("shards") != expectedShards) {
            throw FullTreeControlException("inventory shard ownership does not reconcile")
        }
        val generated = units.count { it.controlString("sourceKind") == "generated" }.toLong()
        val expectedCounts = JsonObject(
            mapOf(
                "compilationUnits" to JsonPrimitive(units.size.toLong()),
                "generatedUnits" to JsonPrimitive(generated),
                "handwrittenUnits" to JsonPrimitive(units.size.toLong() - generated),
                "shards" to JsonPrimitive(byShard.size.toLong()),
            ),
        )
        if (document.controlObject("counts") != expectedCounts) {
            throw FullTreeControlException("inventory counts do not reconcile")
        }
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
            .controlLong("compilationUnits")
        if (byShard.values.any { it.size.toLong() > perShard }) {
            throw FullTreeControlException("an inventory shard exceeds its compilation-unit bound")
        }
        val whole = scope.document.controlObject("bounds").controlObject("wholeRun")
        if (units.size.toLong() > whole.controlLong("compilationUnits")) {
            throw FullTreeControlException("inventory exceeds its whole-run compilation-unit bound")
        }
        if (bytes.size.toLong() > whole.controlLong("serializedBytes")) {
            throw FullTreeControlException("inventory exceeds whole-run serialized-byte bound")
        }
    }

    internal fun compilationUnitId(sourcePath: String): String =
        "cu-" + MessageDigest.getInstance("SHA-256")
            .digest(sourcePath.toByteArray(StandardCharsets.UTF_8)).hex().take(32)

    private fun buildInventory(
        observed: List<FullTreeDwarfCompilationUnit>,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits,
    ): JsonObject {
        val wholeUnitLimit = scope.document.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        if (observed.isEmpty()) throw FullTreeControlException("rich artifact has no DWARF compilation units")
        if (observed.size.toLong() > wholeUnitLimit || observed.size > limits.maximumCompilationUnits) {
            throw FullTreeControlException("compilation-unit count exceeds its authenticated bound")
        }
        val units = observed.map { unit ->
            val sourcePath = FullTreeScopeControl.normalizeSourcePath(scope.document, unit.rawPath)
            val shardId = FullTreeScopeControl.shardForSourcePath(scope.document, sourcePath)
            JsonObject(
                mapOf(
                    "addressSize" to JsonPrimitive(unit.addressSize),
                    "dwarfOffset" to JsonPrimitive(canonicalHex(unit.offset)),
                    "dwarfVersion" to JsonPrimitive(unit.version),
                    "id" to JsonPrimitive(compilationUnitId(sourcePath)),
                    "language" to (unit.language?.let(::JsonPrimitive) ?: JsonNull),
                    "producerSha256" to (
                        unit.producer?.let {
                            JsonPrimitive(OracleArtifacts.sha256(it.toByteArray(StandardCharsets.UTF_8)))
                        } ?: JsonNull
                    ),
                    "rawPathSha256" to JsonPrimitive(
                        OracleArtifacts.sha256(unit.rawPath.toByteArray(StandardCharsets.UTF_8)),
                    ),
                    "shardId" to JsonPrimitive(shardId),
                    "sourceKind" to JsonPrimitive(if (sourcePath.startsWith("generated/")) "generated" else "handwritten"),
                    "sourcePath" to JsonPrimitive(sourcePath),
                ),
            )
        }.sortedWith(INVENTORY_UNIT_ORDER)
        val ids = HashSet<String>()
        val paths = HashSet<String>()
        if (units.any { !ids.add(it.controlString("id")) || !paths.add(it.controlString("sourcePath")) }) {
            throw FullTreeControlException("compilation-unit source identities are not unique")
        }
        val byShard = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
        units.forEach { unit ->
            byShard.getOrPut(unit.controlString("shardId")) { arrayListOf() }.add(unit.controlString("id"))
        }
        val perShardLimit = scope.document.controlObject("bounds").controlObject("perShard")
            .controlLong("compilationUnits")
        if (byShard.values.any { it.size.toLong() > perShardLimit }) {
            throw FullTreeControlException("a shard exceeds its compilation-unit bound")
        }
        val generated = units.count { it.controlString("sourceKind") == "generated" }
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "compilationUnits" to JsonPrimitive(units.size),
                        "generatedUnits" to JsonPrimitive(generated),
                        "handwrittenUnits" to JsonPrimitive(units.size - generated),
                        "shards" to JsonPrimitive(byShard.size),
                    ),
                ),
                "indexSha256" to JsonPrimitive(inventoryIndexSha256(units, limits)),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to scope.document.controlObject("oracle")["artifactManifestSha256"]!!,
                        "id" to scope.document.controlObject("oracle")["id"]!!,
                        "richArtifactSha256" to scope.document.controlObject("oracle")["richArtifactSha256"]!!,
                        "scopeSha256" to JsonPrimitive(scope.sha256),
                        "sourceLockSha256" to scope.document.controlObject("oracle")["sourceLockSha256"]!!,
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    byShard.map { (id, values) ->
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive(id),
                                "unitIds" to JsonArray(
                                    values.sortedWith(FULL_TREE_CODE_POINT_ORDER).map(::JsonPrimitive),
                                ),
                            ),
                        )
                    },
                ),
                "units" to JsonArray(units),
            ),
        )
    }

    private fun inventoryIndexSha256(
        units: List<JsonObject>,
        limits: FullTreeControlLimits,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(INDEX_DOMAIN)
        units.forEach { unit ->
            val canonical = try {
                OracleJson.canonicalBytes(unit, controlJsonLimits(limits.maximumInventoryBytes))
            } catch (failure: Exception) {
                throw FullTreeControlException("inventory unit exceeds strict canonical limits", failure)
            }
            digest.update(MessageDigest.getInstance("SHA-256").digest(canonical))
        }
        return digest.digest().hex()
    }

    private fun requireCanonicalHex(value: String, label: String) {
        if (!value.matches(CANONICAL_HEX)) throw FullTreeControlException("$label is not canonical")
    }

    private fun canonicalHex(value: Long): String {
        if (value < 0L) throw FullTreeControlException("DWARF offset exceeds the supported range")
        return "0x${value.toString(16)}"
    }

    private val INVENTORY_UNIT_ORDER = Comparator<JsonObject> { left, right ->
        val path = FULL_TREE_CODE_POINT_ORDER.compare(
            left.controlString("sourcePath"),
            right.controlString("sourcePath"),
        )
        if (path != 0) path else FULL_TREE_CODE_POINT_ORDER.compare(
            left.controlString("id"),
            right.controlString("id"),
        )
    }
    private val INDEX_DOMAIN = "full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val CANONICAL_HEX = Regex("0x(?:0|[1-9a-f][0-9a-f]*)")
}

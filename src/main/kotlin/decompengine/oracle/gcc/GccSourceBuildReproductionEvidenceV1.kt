package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Supplied description comparison only. Neither matching hashes nor this object admit a runtime. */
internal class GccSourceBuildReproductionEvidenceV1 private constructor(
    val metadataSetSha256: String,
    val profileSha256: String,
    val inspectSha256: String,
    val observedImageId: String,
    val configSha256: String,
    layers: List<String>,
    mismatches: List<String>,
    private val config: ByteArray,
) {
    val recordedOriginImageId: String get() = GccSourceBuildOwnershipProfile.ORIGIN_IMAGE
    val expectedReproducedImageId: String get() = GccSourceBuildOwnershipProfile.REPRODUCED_IMAGE
    val rootfsDiffIds: List<String> = OwnershipJson.immutable(layers)
    val mismatches: List<String> = OwnershipJson.immutable(mismatches)
    val descriptionMatches: Boolean get() = mismatches.isEmpty()
    val evidenceKind: String get() = "untrusted-supplied-reproduction-comparison-v1"
    val approved: Boolean get() = false
    val sourceAuthenticated: Boolean get() = false
    val runtimeAuthenticated: Boolean get() = false
    val captureAuthenticated: Boolean get() = false
    val ownershipComplete: Boolean get() = false
    val missingEvidence: List<String> = OwnershipJson.immutable(listOf(
        "signed-source-archive", "authenticated-live-runtime-bridge", "exact-rich-stripped-pair",
        "authenticated-collector-and-complete-closure", "independent-ownership-replays-and-isolation",
    ))
    fun configCanonicalBytes(): ByteArray = config.copyOf()

    companion object {
        const val MAXIMUM_INSPECT_BYTES = 128 * 1024
        const val MAXIMUM_INSPECT_NODES = 10_000

        /**
         * Reads only supplied bytes. The six-field inspect projection is deliberately closed;
         * arbitrary full Docker inspect documents are not silently projected here. Config is
         * an opaque bounded JSON object, authenticated against no live producer by this API.
         */
        fun compare(
            profile: GccSourceBuildOwnershipProfile,
            metadataFiles: Map<String, ByteArray>,
            inspectBytes: ByteArray,
            maximumInspectBytes: Int = MAXIMUM_INSPECT_BYTES,
            maximumInspectNodes: Int = MAXIMUM_INSPECT_NODES,
        ): GccSourceBuildReproductionEvidenceV1 = ownershipBoundary {
            ownershipRequire(maximumInspectBytes in 1..MAXIMUM_INSPECT_BYTES &&
                maximumInspectNodes in 1..MAXIMUM_INSPECT_NODES, "reproduction limits are invalid")
            // Guard before copying, UTF-8 decoding or allocating JSON trees.
            ownershipRequire(inspectBytes.size <= maximumInspectBytes, "inspect exceeds its byte limit")
            ownershipRequire(metadataFiles.keys == profile.metadataPins.keys, "metadata file population differs")
            var total = 0L
            val snapshots = linkedMapOf<String, ByteArray>()
            for (role in profile.metadataPins.keys) {
                val bytes = metadataFiles.getValue(role)
                ownershipRequire(bytes.size <= 128 * 1024, "metadata exceeds its byte limit")
                total += bytes.size
                ownershipRequire(total <= 256 * 1024, "aggregate metadata exceeds its byte limit")
                snapshots[role] = bytes.copyOf()
            }
            val metadata = GccSourceBuildOwnershipInputs.observe(profile, snapshots)
            val inspectSnapshot = inspectBytes.copyOf()
            val limits = StrictJsonLimits(maximumInputBytes = maximumInspectBytes,
                maximumCanonicalBytes = maximumInspectBytes, maximumDepth = 32,
                maximumNodes = maximumInspectNodes, maximumStringBytes = maximumInspectBytes,
                maximumTotalStringBytes = maximumInspectBytes, maximumNumberCharacters = 32)
            val inspect = OracleJson.parse(inspectSnapshot, limits) as? JsonObject
                ?: ownershipFail("inspect must be an object")
            OwnershipJson.exact(inspect, setOf("Id", "Created", "Architecture", "Os", "Config", "RootFS"), "inspect")
            val rootfs = OwnershipJson.obj(inspect, "RootFS")
            OwnershipJson.exact(rootfs, setOf("Type", "Layers"), "rootfs")
            OwnershipJson.expect(rootfs, "Type", "layers")
            val layers = OwnershipJson.array(rootfs, "Layers")
            ownershipRequire(layers.size <= 9, "rootfs layer population exceeds its bound")
            val observedLayers = layers.map { imageDigest(OwnershipJson.string(it, "layer", 71)) }
            ownershipRequire(observedLayers.distinct().size == observedLayers.size, "rootfs layers repeat")

            val lock = OwnershipJson.parseObject(snapshots.getValue("reproductionLock"), 128 * 1024)
            val recipe = OwnershipJson.obj(lock, "recipe")
            val build = OwnershipJson.parseObject(snapshots.getValue("buildRecord"), 128 * 1024)
            val environment = OwnershipJson.obj(OwnershipJson.obj(build, "environment"), "variables")
            ownershipRequire(OwnershipJson.text(recipe, "platform") == "linux/amd64" &&
                OwnershipJson.text(recipe, "sourceDateEpoch") == OwnershipJson.text(environment, "SOURCE_DATE_EPOCH"),
                "recipe platform or epoch binding differs")
            val dockerfile = snapshots.getValue("recipe")
            ownershipRequire(OracleArtifacts.sha256(dockerfile) == OwnershipJson.text(recipe, "dockerfileSha256"),
                "recipe digest differs")
            val expectedBase = "gcc@${OwnershipJson.text(recipe, "baseImageDigest")}"
            val from = dockerfile.toString(Charsets.UTF_8).lineSequence().map { it.trim() }
                .filter { it.startsWith("FROM ") }.map { it.split(' ') }.toList()
            ownershipRequire(from.size == 2 && from.all { it.size >= 2 && it[1] == expectedBase },
                "recipe FROM bindings differ")

            val expected = OwnershipJson.obj(lock, "reproducedImage")
            val observedImage = imageDigest(OwnershipJson.text(inspect, "Id", 71))
            val config = reproductionConfigCanonicalBytes(OwnershipJson.obj(inspect, "Config"), maximumInspectBytes)
            val configSha = OracleArtifacts.sha256(config)
            val mismatch = arrayListOf<String>()
            if (observedImage != metadata.proposedReproducedImageId) mismatch += "image-id"
            if (OwnershipJson.text(inspect, "Architecture", 64) != "amd64" ||
                OwnershipJson.text(inspect, "Os", 64) != "linux") mismatch += "platform"
            if (OwnershipJson.text(inspect, "Created", 64) != OwnershipJson.text(expected, "created")) mismatch += "created"
            if (configSha != OwnershipJson.text(expected, "configSha256")) mismatch += "config-digest"
            if (observedLayers != OwnershipJson.strings(expected, "rootfsDiffIds")) mismatch += "ordered-rootfs-layers"
            GccSourceBuildReproductionEvidenceV1(metadata.metadataSetSha256, metadata.profileSha256,
                OracleArtifacts.sha256(inspectSnapshot), observedImage, configSha, observedLayers, mismatch, config)
        }

        private fun imageDigest(value: String): String {
            ownershipRequire(value.startsWith("sha256:") && value.length == 71, "image digest is invalid")
            OwnershipJson.sha(value.substring(7))
            return value
        }
    }
}

/** Matches the historical Python compact/sorted/ensure_ascii Config hash, not OracleJson's pretty format.
 * Docker Config integer fields are supported; fractional/exponent numbers refuse rather than guess
 * a cross-language float encoding. This pure encoder creates no evidence/authority token.
 */
internal fun reproductionConfigCanonicalBytes(config: JsonObject, maximumBytes: Int): ByteArray {
    ownershipRequire(maximumBytes in 1..GccSourceBuildReproductionEvidenceV1.MAXIMUM_INSPECT_BYTES,
        "config output byte limit is invalid")
    val out = StringBuilder(minOf(maximumBytes, 1024))
    fun append(value: String) {
        ownershipRequire(value.length <= maximumBytes - out.length, "config exceeds its canonical byte limit")
        out.append(value)
    }
    fun string(value: String) {
        append("\"")
        for (c in value) append(when (c) {
            '"' -> "\\\""; '\\' -> "\\\\"; '\b' -> "\\b"; '\u000c' -> "\\f"
            '\n' -> "\\n"; '\r' -> "\\r"; '\t' -> "\\t"
            else -> if (c.code < 32 || c.code >= 127) "\\u" + c.code.toString(16).padStart(4, '0') else c.toString()
        })
        append("\"")
    }
    val keyOrder = Comparator<String> { a, b ->
        var i = 0; var j = 0; var result = 0
        while (i < a.length && j < b.length && result == 0) {
            val x = a.codePointAt(i); val y = b.codePointAt(j)
            result = x.compareTo(y); i += Character.charCount(x); j += Character.charCount(y)
        }
        if (result != 0) result else (a.length - i).compareTo(b.length - j)
    }
    fun encode(value: JsonElement, depth: Int) {
        ownershipRequire(depth <= 32, "config depth exceeds its limit")
        when (value) {
            is JsonObject -> {
                append("{")
                value.keys.sortedWith(keyOrder).forEachIndexed { i, key ->
                    if (i > 0) append(",")
                    string(key); append(":"); encode(value.getValue(key), depth + 1)
                }
                append("}")
            }
            is JsonArray -> {
                append("["); value.forEachIndexed { i, child -> if (i > 0) append(","); encode(child, depth + 1) }; append("]")
            }
            JsonNull -> append("null")
            is JsonPrimitive -> if (value.isString) string(value.content) else {
                val token = value.content
                ownershipRequire(token == "true" || token == "false" ||
                    token.length <= 32 && token.matches(Regex("-?(0|[1-9][0-9]*)")), "unsupported config scalar")
                append(if (token == "-0") "0" else token)
            }
        }
    }
    encode(config, 0)
    return out.toString().toByteArray(Charsets.US_ASCII)
}

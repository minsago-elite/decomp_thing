package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal class GccSourceBuildOwnershipException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class GccSourceBuildMetadataPin(val path: String, val bytes: Long, val sha256: String)
internal data class GccSourceBuildFileClaim(val path: String, val bytes: Long, val sha256: String, val kind: String)

/** These are small pinned metadata observations, not verification of the source archive or runtime. */
internal class GccSourceBuildOwnershipInputs private constructor(
    val sourceRevision: String,
    val sourceArchiveSha256: String,
    val sourceArchiveBytes: Long,
    val recordedOriginImageId: String,
    val proposedReproducedImageId: String,
    val richSha256: String,
    val strippedSha256: String,
    val metadataSetSha256: String,
    val profileSha256: String,
    private val encoded: ByteArray,
) {
    val sourceAuthenticated: Boolean get() = false
    val runtimeAuthenticated: Boolean get() = false
    val captureAuthenticated: Boolean get() = false
    val ownershipComplete: Boolean get() = false
    fun canonicalBytes(): ByteArray = encoded.copyOf()

    companion object {
        /** No filesystem lookup, signature verification, subprocess, acquisition or authority receipt. */
        fun observe(
            profile: GccSourceBuildOwnershipProfile,
            files: Map<String, ByteArray>,
            maximumMetadataBytes: Int = 128 * 1024,
            maximumTotalMetadataBytes: Int = 256 * 1024,
        ): GccSourceBuildOwnershipInputs = ownershipBoundary {
            ownershipRequire(maximumMetadataBytes in 1..128 * 1024, "metadata byte limit is invalid")
            ownershipRequire(maximumTotalMetadataBytes in 1..256 * 1024, "aggregate metadata byte limit is invalid")
            ownershipRequire(files.keys == profile.metadataPins.keys, "metadata file population differs")
            var total = 0L
            val documents = linkedMapOf<String, JsonObject>()
            for ((role, pin) in profile.metadataPins) {
                val supplied = files.getValue(role)
                ownershipRequire(supplied.size <= maximumMetadataBytes, "metadata input exceeds its byte limit")
                total += supplied.size
                ownershipRequire(total <= maximumTotalMetadataBytes, "aggregate metadata bytes exceed their limit")
                val bytes = supplied.copyOf()
                ownershipRequire(bytes.size.toLong() == pin.bytes && OracleArtifacts.sha256(bytes) == pin.sha256,
                    "pinned metadata bytes differ for $role")
                // The recipe is not JSON. Exact raw bytes are bound without interpreting shell text.
                if (role != "recipe") documents[role] = OwnershipJson.parseObject(bytes, maximumMetadataBytes)
            }
            val source = documents.getValue("sourceLock")
            val archive = OwnershipJson.obj(OwnershipJson.obj(source, "source"), "archive")
            val revision = OwnershipJson.text(OwnershipJson.obj(source, "revision"), "commit")
            val build = documents.getValue("buildRecord")
            val origin = OwnershipJson.text(OwnershipJson.obj(OwnershipJson.obj(build, "environment"), "container"), "digest")
            val reproduction = documents.getValue("reproductionLock")
            val effective = OwnershipJson.text(OwnershipJson.obj(reproduction, "reproducedImage"), "imageDigest")
            val artifacts = OwnershipJson.obj(documents.getValue("artifactManifest"), "artifacts")
            val rich = OwnershipJson.text(OwnershipJson.obj(artifacts, "full"), "sha256")
            val stripped = OwnershipJson.text(OwnershipJson.obj(artifacts, "stripped"), "sha256")
            ownershipRequire(revision == GccSourceBuildOwnershipProfile.SOURCE_REVISION &&
                origin == GccSourceBuildOwnershipProfile.ORIGIN_IMAGE &&
                effective == GccSourceBuildOwnershipProfile.REPRODUCED_IMAGE &&
                rich == GccSourceBuildOwnershipProfile.RICH_SHA256 &&
                stripped == GccSourceBuildOwnershipProfile.STRIPPED_SHA256, "metadata cross-binding differs")
            val encoded = OracleJson.canonicalBytes(JsonObject(linkedMapOf(
                "schema" to JsonPrimitive("gcc-source-build-ownership-metadata-observation-v1"),
                "profileSha256" to JsonPrimitive(profile.canonicalSha256),
                "files" to JsonObject(profile.metadataPins.mapValues { (_, pin) -> JsonObject(linkedMapOf(
                    "path" to JsonPrimitive(pin.path), "bytes" to JsonPrimitive(pin.bytes),
                    "sha256" to JsonPrimitive(pin.sha256),
                )) }),
                "sourceAuthenticated" to JsonPrimitive(false), "runtimeAuthenticated" to JsonPrimitive(false),
                "captureAuthenticated" to JsonPrimitive(false), "ownershipComplete" to JsonPrimitive(false),
            )))
            GccSourceBuildOwnershipInputs(revision, OwnershipJson.text(archive, "sha256"),
                OwnershipJson.number(archive, "bytes"), origin, effective, rich, stripped,
                OwnershipJson.domainSha("gcc-source-build-ownership-metadata-observation-v1", encoded),
                profile.canonicalSha256, encoded)
        }
    }
}

internal object OwnershipJson {
    fun limits(bytes: Int = 128 * 1024, nodes: Int = 10_000) = StrictJsonLimits(
        maximumInputBytes = bytes, maximumCanonicalBytes = bytes, maximumDepth = 32,
        maximumNodes = nodes, maximumStringBytes = bytes, maximumTotalStringBytes = bytes,
        maximumNumberCharacters = 32,
    )
    fun parseObject(bytes: ByteArray, maximumBytes: Int, nodes: Int = 10_000): JsonObject =
        OracleJson.parse(bytes, limits(maximumBytes, nodes)) as? JsonObject ?: ownershipFail("root must be an object")
    fun exact(value: JsonObject, keys: Set<String>, label: String) =
        ownershipRequire(value.keys == keys, "$label has missing or unknown fields")
    fun obj(owner: JsonObject, key: String): JsonObject = owner[key] as? JsonObject ?: ownershipFail("$key must be an object")
    fun array(owner: JsonObject, key: String): JsonArray = owner[key] as? JsonArray ?: ownershipFail("$key must be an array")
    fun text(owner: JsonObject, key: String, maximumBytes: Int = 4096, empty: Boolean = false): String =
        string(owner[key], key, maximumBytes, empty)
    fun string(value: JsonElement?, label: String, maximumBytes: Int = 4096, empty: Boolean = false): String {
        val primitive = value as? JsonPrimitive ?: ownershipFail("$label must be a string")
        ownershipRequire(primitive.isString, "$label must be a string")
        val text = primitive.content
        ownershipRequire((empty || text.isNotEmpty()) && '\u0000' !in text &&
            text.toByteArray(Charsets.UTF_8).size <= maximumBytes, "$label is empty, NUL-containing or overlong")
        return text
    }
    fun number(owner: JsonObject, key: String, minimum: Long = 0, maximum: Long = Long.MAX_VALUE): Long {
        val p = owner[key] as? JsonPrimitive ?: ownershipFail("$key must be an integer")
        val n = p.takeUnless { it.isString }?.longOrNull ?: ownershipFail("$key must be an integer")
        ownershipRequire(n in minimum..maximum, "$key exceeds its integer range")
        return n
    }
    fun falseValue(owner: JsonObject, key: String) {
        val value = owner[key] as? JsonPrimitive
        ownershipRequire(value != null && !value.isString && value.booleanOrNull == false, "$key must remain false")
    }
    fun nullValue(owner: JsonObject, key: String) = ownershipRequire(owner[key] == JsonNull, "$key must remain null")
    fun expect(owner: JsonObject, key: String, expected: String) =
        ownershipRequire(text(owner, key) == expected, "$key differs from the closed value")
    fun sha(value: String): String {
        ownershipRequire(value.matches(Regex("[0-9a-f]{64}")), "SHA256 is not canonical")
        return value
    }
    fun path(value: String, roots: Set<String>): String {
        val parts = value.split('/')
        ownershipRequire(value.toByteArray().size <= 4096 && parts.first() in roots &&
            parts.none { it.isEmpty() || it == "." || it == ".." } &&
            value.none { it == '\\' || it == ':' || it.code < 32 || it.code == 127 }, "path is not a canonical scoped path")
        return value
    }
    fun strings(owner: JsonObject, key: String): List<String> = array(owner, key).map { string(it, key) }
    fun domainSha(domain: String, bytes: ByteArray): String =
        OracleArtifacts.sha256((domain + "\n").toByteArray(Charsets.UTF_8) + bytes)
    fun <T> immutable(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
    fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(values))
}

internal fun ownershipRequire(value: Boolean, message: String) { if (!value) ownershipFail(message) }
internal fun ownershipFail(message: String): Nothing = throw GccSourceBuildOwnershipException("GCC ownership offline observation: $message")
internal inline fun <T> ownershipBoundary(block: () -> T): T = try { block() } catch (failure: GccSourceBuildOwnershipException) {
    throw failure
} catch (failure: IllegalArgumentException) {
    // Diagnostics describe the failed contract; no supplied source/argv/environment content is echoed.
    throw GccSourceBuildOwnershipException("GCC ownership offline observation: invalid bounded document")
}

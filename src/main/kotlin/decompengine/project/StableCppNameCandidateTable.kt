package decompengine.project

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Entity classes supported by the candidate name table; this is not an ABI classification. */
internal enum class StableCppNameEntityKind(val wireName: String) {
    FUNCTION("function"),
    VARIABLE("variable"),
    TYPE("type"),
    ENUMERATOR("enumerator"),
    NAMESPACE("namespace"),
    TEMPLATE("template"),
}

/** Owner-bearing scopes are explicit so anonymous/local names cannot silently become global. */
internal enum class StableCppNameOwnership(val wireName: String, val requiresOwner: Boolean) {
    EXTERNAL("external", false),
    INTERNAL("internal", false),
    ANONYMOUS_NAMESPACE("anonymous-namespace", true),
    FUNCTION_LOCAL("function-local", true),
    LOCAL_STATIC("local-static", true),
}

internal enum class StableCppScopeKind(val wireName: String, val permitsAnonymousName: Boolean) {
    NAMESPACE("namespace", false),
    ANONYMOUS_NAMESPACE("anonymous-namespace", true),
    CLASS("class", false),
    STRUCT("struct", false),
    UNION("union", false),
    FUNCTION("function", false),
    BLOCK("block", false),
}

/** One typed lexical scope component, keyed by a source-anchor candidate supplied by the caller. */
internal data class StableCppNameScopeComponent(
    val kind: StableCppScopeKind,
    val identityCandidateId: String,
    val sourceName: String?,
) {
    init {
        require(identityCandidateId.length == 64 && identityCandidateId.matches(SHA256_HEX)) {
            "scope identity candidate must be a SHA-256 digest"
        }
        sourceName?.let {
            require(it.length <= MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES) { "scope source name exceeds its character bound" }
            require(it.isNotBlank()) { "scope source name must not be blank" }
        }
        require(kind.permitsAnonymousName || sourceName != null) {
            "named C++ scope component requires a source name"
        }
    }

    internal fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "identityCandidateId" to JsonPrimitive(identityCandidateId),
            "kind" to JsonPrimitive(kind.wireName),
            "sourceName" to (sourceName?.let(::JsonPrimitive) ?: JsonNull),
        ),
    )
}

/**
 * Candidate-only input to the deterministic naming algorithm.
 *
 * `identityCandidateId` is deliberately named as a candidate: it must not be interpreted as a
 * resolved or authenticated semantic identity. The upstream producer/ownership validators remain
 * responsible for deciding whether it is suitable for production use.
 */
internal class StableCppNameCandidateInput(
    val sourceEntityId: String,
    val identityCandidateId: String,
    val kind: StableCppNameEntityKind,
    val ownership: StableCppNameOwnership,
    val rawName: String?,
    scope: List<StableCppNameScopeComponent>,
    val ownerIdentityCandidateId: String?,
    val moduleOwnerId: String,
    val sourcePath: String,
) {
    val scope: List<StableCppNameScopeComponent> = boundedScopeCopy(scope)
}

/** Hard ceilings for the inert candidate table; callers may lower them, never raise them. */
internal data class StableCppNameCandidateLimits(
    val maximumEntities: Int = MAXIMUM_CPP_NAME_ENTITIES,
    val maximumInputUtf8Bytes: Long = MAXIMUM_CPP_NAME_INPUT_UTF8_BYTES,
    val maximumCanonicalBytes: Int = MAXIMUM_CPP_NAME_CANONICAL_BYTES,
) {
    init {
        require(maximumEntities in 1..MAXIMUM_CPP_NAME_ENTITIES)
        require(maximumInputUtf8Bytes in 1L..MAXIMUM_CPP_NAME_INPUT_UTF8_BYTES)
        require(maximumCanonicalBytes in 1..MAXIMUM_CPP_NAME_CANONICAL_BYTES)
    }
}

/** A frozen row in the non-authoritative candidate mapping report. */
internal class StableCppNameCandidateEntry internal constructor(
    val sourceEntityId: String,
    val identityCandidateId: String,
    val kind: StableCppNameEntityKind,
    val ownership: StableCppNameOwnership,
    val rawName: String?,
    val generatedName: String,
    val ownerIdentityCandidateId: String?,
    val moduleOwnerId: String,
    val sourcePath: String,
    scope: List<StableCppNameScopeComponent>,
) {
    val scope: List<StableCppNameScopeComponent> = Collections.unmodifiableList(scope.toList())

    internal fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "generatedName" to JsonPrimitive(generatedName),
            "identityBasis" to JsonPrimitive("source-anchor-candidate"),
            "identityCandidateId" to JsonPrimitive(identityCandidateId),
            "kind" to JsonPrimitive(kind.wireName),
            "moduleOwnerId" to JsonPrimitive(moduleOwnerId),
            "ownerIdentityCandidateId" to (ownerIdentityCandidateId?.let(::JsonPrimitive) ?: JsonNull),
            "ownership" to JsonPrimitive(ownership.wireName),
            "rawName" to (rawName?.let(::JsonPrimitive) ?: JsonNull),
            "scope" to JsonArray(scope.map(StableCppNameScopeComponent::canonicalJson)),
            "sourceEntityId" to JsonPrimitive(sourceEntityId),
            "sourcePath" to JsonPrimitive(sourcePath),
        ),
    )
}

/** A deterministic, frozen mapping made from explicitly candidate-only inputs. */
internal class FrozenStableCppNameCandidateTable internal constructor(
    entries: List<StableCppNameCandidateEntry>,
    collisionGroups: List<StableCppNameCollisionGroup>,
    canonicalBytes: ByteArray,
    val reportSha256: String,
) {
    val entries: List<StableCppNameCandidateEntry> = Collections.unmodifiableList(entries.toList())
    val collisionGroups: List<StableCppNameCollisionGroup> = Collections.unmodifiableList(collisionGroups.toList())
    private val storedCanonicalBytes = canonicalBytes.copyOf()
    private val byIdentityCandidateId = Collections.unmodifiableMap(entries.associateBy { it.identityCandidateId })

    val canonicalBytes: ByteArray get() = storedCanonicalBytes.copyOf()

    /** References must name an entry in this frozen snapshot; there is no spelling fallback. */
    fun resolve(identityCandidateId: String): String = byIdentityCandidateId[identityCandidateId]?.generatedName
        ?: throw IllegalArgumentException("unknown C++ identity candidate in frozen name table")
}

internal class StableCppNameCollisionGroup internal constructor(
    val sanitizedStem: String,
    sourceEntityIds: List<String>,
) {
    val sourceEntityIds: List<String> = Collections.unmodifiableList(sourceEntityIds.toList())

    internal fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "sanitizedStem" to JsonPrimitive(sanitizedStem),
            "sourceEntityIds" to JsonArray(sourceEntityIds.map(::JsonPrimitive)),
        ),
    )
}

/** Pure deterministic candidate name assignment. It performs no oracle authentication or emission. */
internal object StableCppNameCandidateTable {
    fun build(
        inputs: List<StableCppNameCandidateInput>,
        limits: StableCppNameCandidateLimits = StableCppNameCandidateLimits(),
    ): FrozenStableCppNameCandidateTable {
        require(inputs.size <= limits.maximumEntities) { "C++ name candidate count exceeds its bound" }
        // Validate and charge each entity before retaining it or requesting the next one.
        // Do not trust a caller-owned list's size or traverse it again after validation.
        val snapshot = ArrayList<StableCppNameCandidateInput>(minOf(inputs.size, 1024))
        var inputBytes = 0L
        var quotedReportStringBytes = 0L
        fun charge(value: String, label: String, maximumBytes: Int) {
            val byteLength = strictUtf8ByteLength(value, label, maximumBytes)
            require(byteLength <= maximumBytes) { "$label exceeds its UTF-8 byte bound" }
            val nextInputBytes = Math.addExact(inputBytes, byteLength.toLong())
            require(nextInputBytes <= limits.maximumInputUtf8Bytes) {
                "C++ name candidate input exceeds its UTF-8 byte bound"
            }
            inputBytes = nextInputBytes
            quotedReportStringBytes = Math.addExact(quotedReportStringBytes, jsonQuotedUtf8ByteLength(value))
        }

        val sourceIds = HashSet<String>()
        val candidateIds = HashSet<String>()
        var scopeComponentCount = 0
        val iterator = inputs.iterator()
        while (iterator.hasNext()) {
            require(snapshot.size < limits.maximumEntities) { "C++ name candidate count exceeds its bound" }
            val input = iterator.next()
            require(input.scope.size <= MAXIMUM_CPP_NAME_SCOPE_DEPTH) { "C++ lexical scope exceeds its depth bound" }
            require(input.sourceEntityId.length == 64 && input.sourceEntityId.matches(SHA256_HEX)) {
                "source entity identity must be a SHA-256 digest"
            }
            require(input.identityCandidateId.length == 64 && input.identityCandidateId.matches(SHA256_HEX)) {
                "identity candidate must be a SHA-256 digest"
            }
            require(sourceIds.add(input.sourceEntityId)) { "duplicate C++ source entity identity" }
            require(candidateIds.add(input.identityCandidateId)) { "duplicate C++ identity candidate is ambiguous" }
            val hasAnonymousScope = input.scope.any { it.kind == StableCppScopeKind.ANONYMOUS_NAMESPACE }
            val hasLocalScope = input.scope.any { it.kind == StableCppScopeKind.FUNCTION || it.kind == StableCppScopeKind.BLOCK }
            when (input.ownership) {
                StableCppNameOwnership.ANONYMOUS_NAMESPACE -> require(hasAnonymousScope && !hasLocalScope) {
                    "anonymous-namespace entity requires an explicit anonymous namespace scope"
                }
                StableCppNameOwnership.FUNCTION_LOCAL, StableCppNameOwnership.LOCAL_STATIC -> require(hasLocalScope) {
                    "local C++ entity requires an explicit function or block scope"
                }
                StableCppNameOwnership.EXTERNAL, StableCppNameOwnership.INTERNAL -> require(!hasAnonymousScope && !hasLocalScope) {
                    "anonymous and function-local C++ scopes require explicit owner-scoped ownership"
                }
            }
            require(input.ownership.requiresOwner == (input.ownerIdentityCandidateId != null)) {
                "anonymous, local, and local-static C++ entities require exactly one owner identity candidate"
            }
            if (input.rawName == null) {
                require(input.kind == StableCppNameEntityKind.NAMESPACE &&
                    input.ownership == StableCppNameOwnership.ANONYMOUS_NAMESPACE) {
                    "only an explicitly owner-scoped anonymous namespace may omit its source name"
                }
            } else {
                require(input.rawName.isNotBlank()) { "C++ source name must not be blank" }
            }
            input.ownerIdentityCandidateId?.let {
                require(it.length == 64 && it.matches(SHA256_HEX)) { "owner identity candidate must be a SHA-256 digest" }
            }
            require(isCanonicalRelativeSourcePath(input.sourcePath)) { "C++ source path is not canonical and relative" }
            charge(input.sourceEntityId, "source entity identity", 64)
            charge(input.identityCandidateId, "identity candidate", 64)
            input.rawName?.let { charge(it, "C++ source name", MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES) }
            charge(input.moduleOwnerId, "module owner ID", MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES)
            require(input.moduleOwnerId.isNotBlank()) { "C++ module owner must not be blank" }
            charge(input.sourcePath, "source path", MAXIMUM_CPP_NAME_SOURCE_PATH_BYTES)
            input.ownerIdentityCandidateId?.let { charge(it, "owner identity candidate", 64) }
            input.scope.forEach { component ->
                charge(component.identityCandidateId, "scope identity candidate", 64)
                component.sourceName?.let { charge(it, "scope source name", MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES) }
            }
            require(input.rawName == null || input.rawName.isNotBlank()) { "C++ source name must not be blank" }
            scopeComponentCount = Math.addExact(scopeComponentCount, input.scope.size)
            snapshot += input
        }

        val estimatedOutputBytes = Math.addExact(
            quotedReportStringBytes,
            Math.addExact(
                Math.addExact(Math.multiplyExact(snapshot.size.toLong(), 512L), Math.multiplyExact(scopeComponentCount.toLong(), 128L)),
                512L,
            ),
        )
        require(estimatedOutputBytes <= limits.maximumCanonicalBytes) {
            "C++ name candidate report exceeds its canonical byte bound"
        }
        val estimatedNodeBound = Math.addExact(
            32,
            Math.addExact(Math.multiplyExact(snapshot.size, 20), Math.multiplyExact(scopeComponentCount, 5)),
        )
        require(estimatedNodeBound <= 1_000_000) { "C++ name candidate report exceeds its JSON node bound" }

        val entries = ArrayList<StableCppNameCandidateEntry>(snapshot.size)
        for (input in snapshot) {
            val nameIdentity = stableCppNameIdentity(input)
            val stem = stableCppNameStem(input.rawName)
            val generatedName = "decomp_${stem}_$nameIdentity"
            require(generatedName.length <= MAXIMUM_CPP_GENERATED_IDENTIFIER_CHARACTERS) {
                "generated C++ identifier exceeds its character bound"
            }
            entries += StableCppNameCandidateEntry(
                sourceEntityId = input.sourceEntityId,
                identityCandidateId = input.identityCandidateId,
                kind = input.kind,
                ownership = input.ownership,
                rawName = input.rawName,
                generatedName = generatedName,
                ownerIdentityCandidateId = input.ownerIdentityCandidateId,
                moduleOwnerId = input.moduleOwnerId,
                sourcePath = input.sourcePath,
                scope = input.scope,
            )
        }

        val orderedEntries = entries.sortedBy(StableCppNameCandidateEntry::sourceEntityId)
        requireUniqueGeneratedNames(orderedEntries.map(StableCppNameCandidateEntry::generatedName))
        val collisionGroups = orderedEntries.groupBy { stableCppNameStem(it.rawName) }
            .filterValues { it.size > 1 }
            .toSortedMap()
            .map { (stem, group) -> StableCppNameCollisionGroup(stem, group.map { it.sourceEntityId }.sorted()) }
        val root = JsonObject(
            mapOf(
                "authority" to JsonPrimitive("none"),
                "collisionGroups" to JsonArray(collisionGroups.map(StableCppNameCollisionGroup::canonicalJson)),
                "entries" to JsonArray(orderedEntries.map(StableCppNameCandidateEntry::canonicalJson)),
                "schemaVersion" to JsonPrimitive(1),
                "status" to JsonPrimitive("candidate-only"),
            ),
        )
        val jsonLimits = StrictJsonLimits(
            maximumInputBytes = limits.maximumCanonicalBytes,
            maximumCanonicalBytes = limits.maximumCanonicalBytes,
            maximumDepth = 16,
            maximumNodes = estimatedNodeBound,
            maximumStringBytes = MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES,
            maximumTotalStringBytes = limits.maximumCanonicalBytes,
        )
        val canonical = OracleJson.canonicalBytes(root, jsonLimits)
        require(canonical.size <= limits.maximumCanonicalBytes) { "C++ name candidate report exceeds its canonical byte bound" }
        return FrozenStableCppNameCandidateTable(
            orderedEntries,
            collisionGroups,
            canonical,
            OracleArtifacts.sha256(canonical),
        )
    }
}

private fun stableCppNameIdentity(input: StableCppNameCandidateInput): String {
    val preimage = JsonObject(
        mapOf(
            "identityCandidateId" to JsonPrimitive(input.identityCandidateId),
            "kind" to JsonPrimitive(input.kind.wireName),
            "moduleOwnerId" to if (input.ownership == StableCppNameOwnership.INTERNAL) {
                JsonPrimitive(input.moduleOwnerId)
            } else {
                JsonNull
            },
            "ownerIdentityCandidateId" to (input.ownerIdentityCandidateId?.let(::JsonPrimitive) ?: JsonNull),
            "ownership" to JsonPrimitive(input.ownership.wireName),
            "scope" to JsonArray(input.scope.map(StableCppNameScopeComponent::canonicalJson)),
            "version" to JsonPrimitive(1),
        ),
    )
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(CPP_NAME_DOMAIN)
    digest.update(OracleJson.canonicalBytes(preimage, StrictJsonLimits(maximumInputBytes = 2 * 1024 * 1024, maximumCanonicalBytes = 2 * 1024 * 1024)))
    return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

/** Replace non-ASCII/non-identifier runs with `_`; the fixed non-reserved prefix makes keywords safe. */
private fun stableCppNameStem(rawName: String?): String {
    if (rawName == null) return "anonymous"
    val sanitized = buildString(minOf(rawName.length, MAXIMUM_CPP_NAME_STEM_CHARACTERS + 1)) {
        var previousUnderscore = false
        for (char in rawName) {
            val allowed = char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char == '_'
            val next = if (allowed) char else '_'
            if (next != '_' || !previousUnderscore) append(next)
            previousUnderscore = next == '_'
            if (length >= MAXIMUM_CPP_NAME_STEM_CHARACTERS) break
        }
    }.trim('_').ifBlank { "anonymous" }
    return if (sanitized.first().isDigit()) "n_$sanitized" else sanitized
}

private fun isCanonicalRelativeSourcePath(path: String): Boolean =
    path.isNotEmpty() && path.length <= MAXIMUM_CPP_NAME_SOURCE_PATH_BYTES &&
        !path.startsWith('/') && '\\' !in path && path.split('/').all { it.isNotEmpty() && it != "." && it != ".." } &&
        path.none { it.code < 0x20 || it.code == 0x7f }

private fun strictUtf8ByteLength(value: String, label: String, maximumBytes: Int): Int {
    var bytes = 0
    var index = 0
    while (index < value.length) {
        val char = value[index]
        val charBytes = when {
            char.code <= 0x7f -> 1
            char.code <= 0x7ff -> 2
            Character.isHighSurrogate(char) -> {
                require(index + 1 < value.length && Character.isLowSurrogate(value[index + 1])) {
                    "$label is not valid Unicode scalar text"
                }
                index++
                4
            }
            Character.isLowSurrogate(char) -> throw IllegalArgumentException("$label is not valid Unicode scalar text")
            else -> 3
        }
        bytes = Math.addExact(bytes, charBytes)
        require(bytes <= maximumBytes) { "$label exceeds its UTF-8 byte bound" }
        index++
    }
    return bytes
}

private fun jsonQuotedUtf8ByteLength(value: String): Long {
    var bytes = 2L
    var index = 0
    while (index < value.length) {
        val char = value[index]
        when {
            char == '"' || char == '\\' || char == '\b' || char == '\u000c' || char == '\n' || char == '\r' || char == '\t' -> bytes += 2L
            char.code < 0x20 -> bytes += 6L
            char.code <= 0x7f -> bytes += 1L
            char.code <= 0x7ff -> bytes += 2L
            Character.isHighSurrogate(char) -> {
                index++
                bytes += 4L
            }
            else -> bytes += 3L
        }
        index++
    }
    return bytes
}

internal fun requireUniqueGeneratedNames(names: List<String>) {
    require(names.size == names.toSet().size) { "stable C++ name digest collision produced a duplicate identifier" }
}

private fun boundedScopeCopy(scope: List<StableCppNameScopeComponent>): List<StableCppNameScopeComponent> {
    val copy = ArrayList<StableCppNameScopeComponent>(MAXIMUM_CPP_NAME_SCOPE_DEPTH)
    val iterator = scope.iterator()
    while (iterator.hasNext()) {
        require(copy.size < MAXIMUM_CPP_NAME_SCOPE_DEPTH) { "C++ lexical scope exceeds its depth bound" }
        copy += iterator.next()
    }
    return Collections.unmodifiableList(copy)
}

private const val MAXIMUM_CPP_NAME_ENTITIES = 250_000
private const val MAXIMUM_CPP_NAME_INPUT_UTF8_BYTES = 64L * 1024 * 1024
private const val MAXIMUM_CPP_NAME_CANONICAL_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_CPP_NAME_SCALAR_UTF8_BYTES = 16 * 1024
private const val MAXIMUM_CPP_NAME_SOURCE_PATH_BYTES = 4 * 1024
private const val MAXIMUM_CPP_NAME_SCOPE_DEPTH = 64
private const val MAXIMUM_CPP_NAME_STEM_CHARACTERS = 48
private const val MAXIMUM_CPP_GENERATED_IDENTIFIER_CHARACTERS = 128
private val SHA256_HEX = Regex("[0-9a-f]{64}")
private val CPP_NAME_DOMAIN = "decompengine-stable-cpp-name-candidate-v1\u0000".toByteArray(StandardCharsets.US_ASCII)

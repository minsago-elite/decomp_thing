package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Path
import java.util.Locale
import kotlinx.serialization.json.JsonObject

/** Immutable authenticated scope plus the exact source-lock and manifest snapshots that bind it. */
class AuthenticatedFullTreeScope internal constructor(
    val document: JsonObject,
    val sha256: String,
    val sourceLock: JsonObject,
    val sourceLockSha256: String,
    val artifactManifest: JsonObject,
    val artifactManifestSha256: String,
)

/** Authoritative Kotlin/JVM implementation of the full-tree scope-v1 contract. */
object FullTreeScopeControl {
    fun load(
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): AuthenticatedFullTreeScope {
        val (scope, scopeBytes) = readCanonicalControlObject(
            scopePath,
            limits.maximumScopeBytes,
            "full-tree scope",
            "full-tree-scope",
        )
        val (sourceLock, sourceLockBytes) = readCanonicalControlObject(
            sourceLockPath,
            limits.maximumSourceLockBytes,
            "source lock",
            "llvm/source-lock",
        )
        val (manifest, manifestBytes) = readCanonicalControlObject(
            artifactManifestPath,
            limits.maximumArtifactManifestBytes,
            "artifact manifest",
            "oracle-manifest",
        )
        val authenticated = AuthenticatedFullTreeScope(
            document = scope,
            sha256 = OracleArtifacts.sha256(scopeBytes),
            sourceLock = sourceLock,
            sourceLockSha256 = OracleArtifacts.sha256(sourceLockBytes),
            artifactManifest = manifest,
            artifactManifestSha256 = OracleArtifacts.sha256(manifestBytes),
        )
        validate(authenticated, limits)
        return authenticated
    }

    fun validate(
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ) {
        val (document, scopeBytes) = snapshotControlObject(
            scope.document,
            limits.maximumScopeBytes,
            "full-tree scope",
            "full-tree-scope",
        )
        val (_, sourceLockBytes) = snapshotControlObject(
            scope.sourceLock,
            limits.maximumSourceLockBytes,
            "source lock",
            "llvm/source-lock",
        )
        val (manifest, manifestBytes) = snapshotControlObject(
            scope.artifactManifest,
            limits.maximumArtifactManifestBytes,
            "artifact manifest",
            "oracle-manifest",
        )
        if (OracleArtifacts.sha256(scopeBytes) != scope.sha256) {
            throw FullTreeControlException("full-tree scope snapshot differs from its authenticated digest")
        }
        if (OracleArtifacts.sha256(sourceLockBytes) != scope.sourceLockSha256) {
            throw FullTreeControlException("source-lock snapshot differs from its authenticated digest")
        }
        if (OracleArtifacts.sha256(manifestBytes) != scope.artifactManifestSha256) {
            throw FullTreeControlException("artifact-manifest snapshot differs from its authenticated digest")
        }
        val oracle = document.controlObject("oracle")
        if (oracle.controlString("sourceLockSha256") != scope.sourceLockSha256) {
            throw FullTreeControlException("full-tree scope source-lock binding does not match")
        }
        if (oracle.controlString("artifactManifestSha256") != scope.artifactManifestSha256) {
            throw FullTreeControlException("full-tree scope artifact-manifest binding does not match")
        }
        val artifacts = manifest.controlObject("artifacts")
        if (artifacts.controlObject("full").controlString("sha256") != oracle.controlString("richArtifactSha256")) {
            throw FullTreeControlException("full-tree scope rich artifact binding does not match manifest")
        }
        if (
            artifacts.controlObject("stripped").controlString("sha256") !=
            oracle.controlString("strippedArtifactSha256")
        ) {
            throw FullTreeControlException("full-tree scope stripped artifact binding does not match manifest")
        }
        validatePolicy(document)
    }

    fun normalizeSourcePath(
        scope: AuthenticatedFullTreeScope,
        rawPath: String,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): String {
        validate(scope, limits)
        return normalizeSourcePath(scope.document, rawPath)
    }

    internal fun normalizeSourcePath(scope: JsonObject, rawPath: String): String {
        requireScalarPath(rawPath, "DWARF compilation-unit path")
        if (rawPath.isEmpty() || '\u0000' in rawPath || '\\' in rawPath) {
            throw FullTreeControlException("DWARF compilation-unit path is invalid")
        }
        val matches = scope.controlObject("pathPolicy").controlArray("prefixMaps")
            .controlObjects("scope prefix maps")
            .filter { rawPath.startsWith(it.controlString("from")) }
        if (matches.size != 1) {
            throw FullTreeControlException(
                "DWARF path matches ${matches.size} explicit prefix maps: $rawPath",
            )
        }
        val mapping = matches.single()
        val from = mapping.controlString("from")
        val normalized = mapping.controlString("to") + rawPath.substring(from.length)
        if (normalized.split('/').any { it.isEmpty() || it == "." || it == ".." }) {
            throw FullTreeControlException("normalized DWARF path is not canonical: $normalized")
        }
        return normalized
    }

    fun shardForSourcePath(
        scope: AuthenticatedFullTreeScope,
        normalizedPath: String,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): String {
        validate(scope, limits)
        return shardForSourcePath(scope.document, normalizedPath)
    }

    internal fun shardForSourcePath(scope: JsonObject, normalizedPath: String): String {
        requireScalarPath(normalizedPath, "normalized source path")
        val matches = scope.controlObject("sharding").controlArray("rules")
            .controlObjects("scope shard rules")
            .filter { normalizedPath.startsWith(it.controlString("pathPrefix")) }
        if (matches.size != 1) {
            throw FullTreeControlException("source path matches ${matches.size} shard rules: $normalizedPath")
        }
        val rule = matches.single()
        val remainder = normalizedPath.substring(rule.controlString("pathPrefix").length).split('/')
        val depth = rule.controlLong("componentDepth").toInt()
        if (remainder.size <= depth) {
            throw FullTreeControlException("source path lacks $depth shard components: $normalizedPath")
        }
        val components = remainder.take(depth).map { raw ->
            raw.lowercase(Locale.ROOT).replace(NON_SHARD_COMPONENT, "-").trim('-').also { component ->
                if (component.isEmpty() || !component.matches(SHARD_COMPONENT)) {
                    throw FullTreeControlException("source path has an invalid shard component: $normalizedPath")
                }
            }
        }
        return listOf(rule.controlString("shardPrefix"), *components.toTypedArray()).joinToString("-")
    }

    private fun validatePolicy(scope: JsonObject) {
        val prefixMaps = scope.controlObject("pathPolicy").controlArray("prefixMaps")
            .controlObjects("scope prefix maps")
        val sources = prefixMaps.map { it.controlString("from") }
        val targets = prefixMaps.map { it.controlString("to") }
        if (sources.toSet().size != sources.size) {
            throw FullTreeControlException("full-tree prefix maps must have unique sources")
        }
        sources.forEach { left ->
            sources.forEach { right ->
                if (left != right && right.startsWith(left)) {
                    throw FullTreeControlException("full-tree prefix-map sources may not overlap")
                }
            }
        }
        val rules = scope.controlObject("sharding").controlArray("rules").controlObjects("scope shard rules")
        val prefixes = rules.map { it.controlString("pathPrefix") }
        if (prefixes.toSet().size != prefixes.size) {
            throw FullTreeControlException("full-tree shard-rule prefixes must be unique")
        }
        rules.forEach { rule ->
            if (targets.none { rule.controlString("pathPrefix").startsWith(it) }) {
                throw FullTreeControlException("full-tree shard rule is outside normalized prefix-map targets")
            }
        }
        val perShard = scope.controlObject("bounds").controlObject("perShard")
        val wholeRun = scope.controlObject("bounds").controlObject("wholeRun")
        BOUND_NAMES.forEach { name ->
            if (perShard.controlLong(name) > wholeRun.controlLong(name)) {
                throw FullTreeControlException("per-shard $name bound exceeds the whole-run bound")
            }
        }
    }

    private fun requireScalarPath(value: String, label: String) {
        var offset = 0
        while (offset < value.length) {
            val current = value[offset]
            when {
                Character.isHighSurrogate(current) -> {
                    if (offset + 1 >= value.length || !Character.isLowSurrogate(value[offset + 1])) {
                        throw FullTreeControlException("$label contains an unpaired surrogate")
                    }
                    offset += 2
                }
                Character.isLowSurrogate(current) ->
                    throw FullTreeControlException("$label contains an unpaired surrogate")
                else -> offset++
            }
        }
    }

    private val NON_SHARD_COMPONENT = Regex("[^a-z0-9]+")
    private val SHARD_COMPONENT = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
    private val BOUND_NAMES = listOf(
        "compilationUnits",
        "cpuSeconds",
        "entities",
        "serializedBytes",
        "wallClockSeconds",
        "maximumResidentBytes",
    )
}

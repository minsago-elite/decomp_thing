package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.net.URI
import java.nio.file.Path
import java.time.Duration
import kotlin.system.exitProcess
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class LockedReleaseArtifact(
    val role: String,
    val path: String,
    val bytes: Long,
    val sha256: String,
    val uri: URI,
)

internal data class LlvmReleaseArtifactLock(
    val path: Path,
    val lockSha256: String,
    val oracleId: String,
    val oracleVersion: String,
    val manifestPath: Path,
    val manifestSha256: String,
    val repository: String,
    val tag: String,
    val artifacts: List<LockedReleaseArtifact>,
)

/** Authoritative Kotlin interpretation of the closed release-artifacts v1 contract. */
internal object LlvmReleaseArtifactLockLoader {
    fun load(lockPath: Path): LlvmReleaseArtifactLock {
        val normalized = lockPath.toAbsolutePath().normalize()
        val lockBytes = readSmallArtifact(normalized, MAXIMUM_LOCK_BYTES, "release artifact lock")
        val root = parseCanonicalObject(lockBytes, MAXIMUM_LOCK_BYTES, "release artifact lock")
        validateSchema("release-artifacts", root, "release artifact lock")
        if (root.requiredLong("schemaVersion", "release artifact lock") != 1L) {
            provenanceFail("release artifact lock schemaVersion must be 1")
        }

        val oracle = root.requiredObject("oracle", "release artifact lock")
        val oracleId = oracle.requiredScalar("id", "release artifact lock oracle")
        val oracleVersion = oracle.requiredScalar("version", "release artifact lock oracle")
        val manifestName = oracle.requiredScalar("artifactManifestPath", "release artifact lock oracle")
        if (!manifestName.matches(BASE_NAME)) {
            provenanceFail("release artifact manifest path must be a normalized base name")
        }
        val manifestSha256 = oracle.requiredScalar("artifactManifestSha256", "release artifact lock oracle")
        requireSha256(manifestSha256, "release artifact manifest")

        val release = root.requiredObject("release", "release artifact lock")
        val repository = release.requiredScalar("repository", "release artifact lock release")
        if (!repository.matches(REPOSITORY)) provenanceFail("release repository has an invalid format")
        val tag = release.requiredScalar("tag", "release artifact lock release")
        if (!tag.matches(TAG)) provenanceFail("release tag has an invalid format")
        val expectedPage = "https://github.com/$repository/releases/tag/$tag"
        if (release.requiredScalar("pageUrl", "release artifact lock release") != expectedPage) {
            provenanceFail("release page URL must be $expectedPage")
        }

        val artifactObject = root.requiredObject("artifacts", "release artifact lock")
        var totalBytes = 0L
        val artifacts = ROLES.map { role ->
            val record = artifactObject.requiredObject(role, "release artifact lock artifacts")
            val relative = record.requiredScalar("path", "release artifact $role")
            val parts = relative.split('/')
            if (parts.size != 2 || parts[0] != "artifacts" || !parts[1].matches(BASE_NAME)) {
                provenanceFail("release artifact $role path must be directly under artifacts/")
            }
            val bytes = record.requiredLong("bytes", "release artifact $role")
            if (bytes !in 1L..MAXIMUM_ARTIFACT_BYTES) {
                provenanceFail("release artifact $role byte length is outside the supported range")
            }
            totalBytes = try {
                Math.addExact(totalBytes, bytes)
            } catch (failure: ArithmeticException) {
                throw ReleaseArtifactProvenanceException("release artifact total byte length overflows", failure)
            }
            val sha256 = record.requiredScalar("sha256", "release artifact $role")
            requireSha256(sha256, "release artifact $role")
            val expectedUrl = "https://github.com/$repository/releases/download/$tag/${parts[1]}"
            val url = record.requiredScalar("url", "release artifact $role")
            if (url != expectedUrl) provenanceFail("release artifact $role URL must be $expectedUrl")
            val uri = try {
                URI.create(url)
            } catch (failure: Exception) {
                throw ReleaseArtifactProvenanceException("release artifact $role URL is invalid", failure)
            }
            LockedReleaseArtifact(role, relative, bytes, sha256, uri)
        }
        if (totalBytes > MAXIMUM_TOTAL_BYTES) provenanceFail("release artifact lock exceeds its total byte bound")
        if (artifacts.map { it.path }.toSet().size != artifacts.size) {
            provenanceFail("release artifact paths must be unique")
        }
        if (artifacts.map { it.sha256 }.toSet().size != artifacts.size) {
            provenanceFail("release artifact SHA-256 digests must be unique")
        }

        val manifestPath = normalized.parent?.resolve(manifestName)?.normalize()
            ?: provenanceFail("release artifact lock path has no parent")
        if (manifestPath.parent != normalized.parent) provenanceFail("release artifact manifest escapes its lock directory")
        val manifestBytes = readSmallArtifact(manifestPath, MAXIMUM_MANIFEST_BYTES, "release artifact manifest")
        val actualManifestSha256 = OracleArtifacts.sha256(manifestBytes)
        if (actualManifestSha256 != manifestSha256) {
            provenanceFail("release artifact manifest SHA-256 differs from its lock")
        }
        val manifest = parseCanonicalObject(
            manifestBytes,
            MAXIMUM_MANIFEST_BYTES,
            "release artifact manifest",
        )
        validateSchema("oracle-manifest", manifest, "release artifact manifest")
        val manifestOracle = manifest.requiredObject("oracle", "release artifact manifest")
        if (manifestOracle.requiredScalar("id", "release artifact manifest oracle") != oracleId) {
            provenanceFail("release lock oracle id differs from its artifact manifest")
        }
        if (manifestOracle.requiredScalar("version", "release artifact manifest oracle") != oracleVersion) {
            provenanceFail("release lock oracle version differs from its artifact manifest")
        }
        val manifestArtifacts = manifest.requiredObject("artifacts", "release artifact manifest")
        artifacts.forEach { locked ->
            val manifestRecord = manifestArtifacts.requiredObject(locked.role, "release artifact manifest artifacts")
            if (manifestRecord.requiredLong("bytes", "manifest artifact ${locked.role}") != locked.bytes) {
                provenanceFail("release artifact ${locked.role} byte length differs from its manifest")
            }
            if (manifestRecord.requiredScalar("sha256", "manifest artifact ${locked.role}") != locked.sha256) {
                provenanceFail("release artifact ${locked.role} SHA-256 differs from its manifest")
            }
        }

        return LlvmReleaseArtifactLock(
            path = normalized,
            lockSha256 = OracleArtifacts.sha256(lockBytes),
            oracleId = oracleId,
            oracleVersion = oracleVersion,
            manifestPath = manifestPath,
            manifestSha256 = manifestSha256,
            repository = repository,
            tag = tag,
            artifacts = artifacts,
        )
    }

    private fun readSmallArtifact(path: Path, maximumBytes: Int, label: String): ByteArray = try {
        OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes)).bytes
    } catch (failure: Exception) {
        throw ReleaseArtifactProvenanceException("cannot read authenticated $label", failure)
    }

    private fun parseCanonicalObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
        OracleJson.parseCanonical(bytes, jsonLimits(maximumBytes)) as? JsonObject
            ?: provenanceFail("$label root must be an object")
    } catch (failure: ReleaseArtifactProvenanceException) {
        throw failure
    } catch (failure: Exception) {
        throw ReleaseArtifactProvenanceException("$label is not strict canonical JSON", failure)
    }

    private fun validateSchema(name: String, document: JsonObject, label: String) {
        try {
            OracleSchemas.validate(name, document)
        } catch (failure: Exception) {
            throw ReleaseArtifactProvenanceException("$label fails its bundled schema", failure)
        }
    }

    private fun requireSha256(value: String, label: String) {
        if (!value.matches(SHA256)) provenanceFail("$label SHA-256 is invalid")
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
    )

    private val ROLES = listOf("full", "stripped")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val REPOSITORY = Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    private val TAG = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    private val BASE_NAME = Regex("(?!\\.{1,2}$)[^/\\\\\u0000]+")
    private const val MAXIMUM_LOCK_BYTES = 1024 * 1024
    private const val MAXIMUM_MANIFEST_BYTES = 32 * 1024 * 1024
    private const val MAXIMUM_ARTIFACT_BYTES = 1024L * 1024 * 1024
    private const val MAXIMUM_TOTAL_BYTES = 2L * 1024 * 1024 * 1024
}

/** Fetches the exact pair while requiring the lock/manifest to remain stable through publication. */
internal class LlvmReleaseArtifactMaterializer(
    private val downloader: BoundedHttpsDownloader = BoundedHttpsDownloader(),
    private val faultInjector: ReleaseArtifactMaterializationFaultInjector? = null,
) {
    fun materialize(lockPath: Path, outputRoot: Path): Map<String, AuthenticatedDownloadedArtifact> {
        val locked = LlvmReleaseArtifactLockLoader.load(lockPath)
        openOrCreateAuthenticatedReleaseDirectory(outputRoot, "release artifact output root").use { root ->
            createOrOpenAuthenticatedChild(root, "artifacts", "release artifact directory").use { artifactDirectory ->
                val results = linkedMapOf<String, AuthenticatedDownloadedArtifact>()
                locked.artifacts.forEach { record ->
                    val target = root.path.resolve(record.path).normalize()
                    if (
                        target.parent != artifactDirectory.path ||
                        target.fileName.toString() != record.path.substringAfter('/')
                    ) {
                        provenanceFail("release artifact target escapes its authenticated output directory")
                    }
                    val result = DescriptorBoundDownloadPublisher.materialize(
                        authenticatedParent = artifactDirectory,
                        targetPath = target,
                        expectedBytes = record.bytes,
                        expectedSha256 = record.sha256,
                        verifyInputs = { requireSameLock(locked, LlvmReleaseArtifactLockLoader.load(lockPath)) },
                    ) { sink ->
                        downloader.download(
                            HttpsDownloadRequest(
                                uri = record.uri,
                                expectedBytes = record.bytes,
                                expectedSha256 = record.sha256,
                                userAgent = USER_AGENT,
                                timeout = DOWNLOAD_TIMEOUT,
                                allowedHosts = ALLOWED_RELEASE_HOSTS,
                            ),
                            sink,
                        )
                    }
                    faultInjector?.hit(ReleaseArtifactMaterializationPoint.AFTER_ARTIFACT_SELECTED)
                    requireSameLock(locked, LlvmReleaseArtifactLockLoader.load(lockPath))
                    results[record.role] = result
                }
                return results
            }
        }
    }

    private fun requireSameLock(expected: LlvmReleaseArtifactLock, actual: LlvmReleaseArtifactLock) {
        if (expected != actual) provenanceFail("release artifact lock or manifest changed during materialization")
    }

    private companion object {
        const val USER_AGENT = "decomp-thing-oracle-assets/1"
        val DOWNLOAD_TIMEOUT: Duration = Duration.ofSeconds(300)
        val ALLOWED_RELEASE_HOSTS = setOf("github.com", "release-assets.githubusercontent.com")
    }
}

internal enum class ReleaseArtifactMaterializationPoint {
    AFTER_ARTIFACT_SELECTED,
}

internal fun interface ReleaseArtifactMaterializationFaultInjector {
    fun hit(point: ReleaseArtifactMaterializationPoint)
}

/** Stable JVM entry point replacing the Python release-asset fetch authority. */
object LlvmReleaseArtifactFetcherCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        try {
            val options = ReleaseArtifactArguments.parse(arguments)
            val artifacts = LlvmReleaseArtifactMaterializer().materialize(options.lock, options.outputRoot)
            listOf("full", "stripped").forEach { role ->
                println("verified $role release artifact: ${artifacts.getValue(role).path}")
            }
        } catch (failure: Exception) {
            System.err.println("LLVM release artifact fetch failed: ${failure.message}")
            exitProcess(1)
        }
    }
}

private data class ReleaseArtifactArguments(val outputRoot: Path, val lock: Path) {
    companion object {
        fun parse(arguments: Array<String>): ReleaseArtifactArguments {
            var lock = DEFAULT_LOCK
            var output: Path? = null
            var index = 0
            while (index < arguments.size) {
                when (val argument = arguments[index]) {
                    "--lock" -> {
                        index++
                        if (index >= arguments.size) provenanceFail("--lock requires a path")
                        lock = Path.of(arguments[index])
                    }
                    else -> {
                        if (argument.startsWith("--")) provenanceFail("unknown option $argument")
                        if (output != null) provenanceFail("release artifact fetch accepts one output root")
                        output = Path.of(argument)
                    }
                }
                index++
            }
            return ReleaseArtifactArguments(
                output ?: provenanceFail("release artifact fetch requires an output root"),
                lock,
            )
        }

        private val DEFAULT_LOCK = Path.of("oracle/llvm/22.1.6/release-artifacts.json")
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: provenanceFail("$label field $name must be an object")

private fun JsonObject.requiredScalar(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive ?: provenanceFail("$label field $name must be a string")
    if (!value.isString || value.content.isEmpty() || '\u0000' in value.content) {
        provenanceFail("$label field $name must be a non-empty string without NUL")
    }
    return value.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val value = this[name] as? JsonPrimitive ?: provenanceFail("$label field $name must be an integer")
    if (value.isString || value.content.any { it in ".eE" }) {
        provenanceFail("$label field $name must be an integer")
    }
    return value.content.toLongOrNull() ?: provenanceFail("$label field $name exceeds the supported integer range")
}

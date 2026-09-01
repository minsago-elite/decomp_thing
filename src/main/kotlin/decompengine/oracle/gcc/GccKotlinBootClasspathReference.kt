package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.jar.Attributes
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class GccKotlinBootClasspathReferenceEntry(
    val logicalName: String,
    val bytes: Long,
    val sha256: String,
) {
    init {
        require(logicalName.matches(LOGICAL_JAR_NAME))
        require(bytes in 1L..MAXIMUM_REFERENCE_ENTRY_BYTES)
        require(sha256.matches(SHA256))
    }
}

/**
 * Retained deployment authority for the exact ordered JVM closure that may implement BOOT.
 *
 * The raw containment definition may name copies of these JARs, but cannot choose their bytes or
 * order. Production discovers this sidecar next to the already-loaded application JAR. The two
 * system properties are accepted only while running from a class directory, which makes them a
 * Gradle/test-process TCB seam rather than an ACP- or definition-controlled input. As with
 * [StableControlFile], each file owner and immediate-directory owner remains a cooperating trust
 * principal; this does not claim exclusion of same-owner restoration or a privileged peer.
 */
internal class GccKotlinBootClasspathReference private constructor(
    val closureSha256: String,
    entries: List<GccKotlinBootClasspathReferenceEntry>,
    private val referenceBytes: ByteArray,
    private val referenceGuard: StableControlFile,
    private val deploymentGuards: List<Pair<GccKotlinBootClasspathReferenceEntry, StableControlFile>>,
) : AutoCloseable {
    val entries: List<GccKotlinBootClasspathReferenceEntry> = Collections.unmodifiableList(entries)
    private var closed = false

    fun requireCandidateIdentities(candidates: List<Pair<Long, String>>) {
        check(!closed) { "GCC Kotlin BOOT class-path reference is closed" }
        if (
            candidates.size != entries.size ||
            candidates.indices.any { index ->
                val candidate = candidates[index]
                val expected = entries[index]
                candidate.first != expected.bytes || candidate.second != expected.sha256
            }
        ) liveContainmentFail(
            "GCC BOOT-keeper class path differs from the ordered deployment reference",
        )
    }

    fun verify(label: String) {
        check(!closed) { "GCC Kotlin BOOT class-path reference is closed" }
        if (
            referenceGuard.size != referenceBytes.size.toLong() ||
            !MessageDigest.isEqual(
                referenceGuard.readExactly(0L, referenceBytes.size, "GCC Kotlin BOOT reference $label"),
                referenceBytes,
            )
        ) liveContainmentFail("GCC Kotlin BOOT class-path reference changed $label")
        referenceGuard.verifyUnchanged("GCC Kotlin BOOT class-path reference $label")
        deploymentGuards.forEachIndexed { index, (entry, guard) ->
            if (
                guard.size != entry.bytes ||
                guard.sha256(label = "GCC Kotlin BOOT deployment JAR $index $label") != entry.sha256
            ) liveContainmentFail("GCC Kotlin BOOT deployment JAR $index changed $label")
            guard.verifyUnchanged("GCC Kotlin BOOT deployment JAR $index $label")
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        deploymentGuards.asReversed().forEach { (_, guard) ->
            runCatching { guard.close() }.exceptionOrNull()?.let(::record)
        }
        runCatching { referenceGuard.close() }.exceptionOrNull()?.let(::record)
        failure?.let { throw it }
    }

    companion object {
        fun open(): GccKotlinBootClasspathReference {
            val codeSource = deploymentCodeSource()
            val configuredReference = System.getProperty(REFERENCE_PROPERTY)?.takeIf(String::isNotBlank)
            val configuredRoot = System.getProperty(ROOT_PROPERTY)?.takeIf(String::isNotBlank)
            val developmentMode = Files.isDirectory(codeSource, LinkOption.NOFOLLOW_LINKS)
            if (!developmentMode && (configuredReference != null || configuredRoot != null)) {
                liveContainmentFail(
                    "installed GCC Kotlin BOOT authority rejects class-path reference overrides",
                )
            }
            if (developmentMode && (configuredReference == null || configuredRoot == null)) {
                liveContainmentFail(
                    "development GCC Kotlin BOOT authority lacks its Gradle-pinned class-path reference",
                )
            }
            val referencePath = if (developmentMode) {
                canonicalPath(checkNotNull(configuredReference), "configured Kotlin BOOT reference")
            } else {
                codeSource.parent.resolve(REFERENCE_FILE).toAbsolutePath().normalize()
            }
            val deploymentRoot = if (developmentMode) {
                canonicalDirectory(checkNotNull(configuredRoot), "configured Kotlin BOOT runtime root")
            } else {
                canonicalDirectory(codeSource.parent.toString(), "installed Kotlin BOOT runtime root")
            }
            var referenceGuard: StableControlFile? = null
            val opened = ArrayDeque<Pair<GccKotlinBootClasspathReferenceEntry, StableControlFile>>()
            try {
                val guard = StableControlFile.open(
                    referencePath,
                    MAXIMUM_REFERENCE_BYTES.toLong(),
                    "GCC Kotlin BOOT class-path reference",
                )
                referenceGuard = guard
                val bytes = guard.readExactly(
                    0L,
                    guard.size.toInt(),
                    "GCC Kotlin BOOT class-path reference",
                )
                val parsed = parse(bytes)
                if (!developmentMode) {
                    val first = parsed.entries.first()
                    val selectedApplication = deploymentRoot.resolve(first.logicalName)
                    if (!Files.isSameFile(codeSource, selectedApplication)) {
                        liveContainmentFail(
                            "loaded GCC controller JAR differs from the referenced application JAR",
                        )
                    }
                }
                var keeperClasses = 0
                parsed.entries.forEachIndexed { index, entry ->
                    val path = deploymentRoot.resolve(entry.logicalName).normalize()
                    if (path.parent != deploymentRoot) {
                        liveContainmentFail("GCC Kotlin BOOT deployment JAR $index escaped its root")
                    }
                    val jarGuard = StableControlFile.open(
                        path,
                        MAXIMUM_REFERENCE_ENTRY_BYTES,
                        "GCC Kotlin BOOT deployment JAR $index",
                    )
                    opened.addFirst(entry to jarGuard)
                    if (
                        jarGuard.size != entry.bytes ||
                        jarGuard.sha256(label = "GCC Kotlin BOOT deployment JAR $index") != entry.sha256
                    ) liveContainmentFail("GCC Kotlin BOOT deployment JAR $index differs from its reference")
                    jarGuard.verifyUnchanged("GCC Kotlin BOOT deployment JAR $index")
                    keeperClasses += inspectJar(path, index)
                    jarGuard.verifyUnchanged("after GCC Kotlin BOOT deployment JAR $index inspection")
                }
                if (keeperClasses != 1) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT keeper class does not occur exactly once in its deployment closure",
                    )
                }
                guard.verifyUnchanged("after GCC Kotlin BOOT reference authorization")
                val result = GccKotlinBootClasspathReference(
                    parsed.closureSha256,
                    parsed.entries,
                    bytes,
                    guard,
                    Collections.unmodifiableList(opened.toList().asReversed()),
                )
                referenceGuard = null
                opened.clear()
                return result
            } catch (failure: Throwable) {
                opened.forEach { (_, guard) ->
                    runCatching { guard.close() }.exceptionOrNull()
                        ?.takeIf { it !== failure }?.let(failure::addSuppressed)
                }
                runCatching { referenceGuard?.close() }.exceptionOrNull()
                    ?.takeIf { it !== failure }?.let(failure::addSuppressed)
                throw failure
            }
        }

        private fun parse(bytes: ByteArray): ParsedReference {
            val root = try {
                OracleJson.parseCanonical(bytes, REFERENCE_JSON_LIMITS) as? JsonObject
                    ?: liveContainmentFail("GCC Kotlin BOOT class-path reference must be an object")
            } catch (failure: GccCompilerEngineLiveContainmentException) {
                throw failure
            } catch (failure: Throwable) {
                throw GccCompilerEngineLiveContainmentException(
                    "GCC Kotlin BOOT class-path reference is not strict canonical JSON",
                    failure,
                )
            }
            if (root.keys != REFERENCE_FIELDS) {
                liveContainmentFail("GCC Kotlin BOOT class-path reference has an unexpected shape")
            }
            requireInteger(root, "schemaVersion", 1L)
            requireString(root, "provider", REFERENCE_PROVIDER)
            val closure = string(root, "closureSha256")
            if (!closure.matches(SHA256)) {
                liveContainmentFail("GCC Kotlin BOOT class-path reference digest is invalid")
            }
            val array = root["entries"] as? JsonArray
                ?: liveContainmentFail("GCC Kotlin BOOT class-path reference entries must be an array")
            if (array.isEmpty() || array.size > MAXIMUM_REFERENCE_ENTRIES) {
                liveContainmentFail("GCC Kotlin BOOT class-path reference exceeds its entry bound")
            }
            var aggregate = 0L
            val names = hashSetOf<String>()
            val entries = array.mapIndexed { index, element ->
                val entry = element as? JsonObject
                    ?: liveContainmentFail("GCC Kotlin BOOT reference entry $index must be an object")
                if (entry.keys != ENTRY_FIELDS) {
                    liveContainmentFail("GCC Kotlin BOOT reference entry $index has an unexpected shape")
                }
                val name = string(entry, "logicalName")
                if (!name.matches(LOGICAL_JAR_NAME) || !names.add(name)) {
                    liveContainmentFail("GCC Kotlin BOOT reference entry $index name is invalid")
                }
                val size = long(entry, "bytes")
                if (size !in 1L..MAXIMUM_REFERENCE_ENTRY_BYTES) {
                    liveContainmentFail("GCC Kotlin BOOT reference entry $index bytes are invalid")
                }
                aggregate = try {
                    Math.addExact(aggregate, size)
                } catch (_: ArithmeticException) {
                    liveContainmentFail("GCC Kotlin BOOT class-path reference bytes overflow")
                }
                if (aggregate > MAXIMUM_REFERENCE_AGGREGATE_BYTES) {
                    liveContainmentFail("GCC Kotlin BOOT class-path reference exceeds its byte bound")
                }
                val digest = string(entry, "sha256")
                if (!digest.matches(SHA256)) {
                    liveContainmentFail("GCC Kotlin BOOT reference entry $index digest is invalid")
                }
                GccKotlinBootClasspathReferenceEntry(name, size, digest)
            }
            val unsigned = JsonObject(root - "closureSha256")
            val calculated = OracleArtifacts.sha256(
                OracleJson.canonicalBytes(unsigned, REFERENCE_JSON_LIMITS),
            )
            if (calculated != closure) {
                liveContainmentFail("GCC Kotlin BOOT class-path reference self-hash differs")
            }
            return ParsedReference(closure, Collections.unmodifiableList(entries))
        }

        private fun inspectJar(path: Path, index: Int): Int = try {
            JarFile(path.toFile(), true).use { jar ->
                if (jar.manifest?.mainAttributes?.getValue(Attributes.Name.CLASS_PATH) != null) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains Class-Path")
                }
                if (jar.getJarEntry("META-INF/INDEX.LIST") != null) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains an index")
                }
                jar.entries().asSequence().count {
                    !it.isDirectory && it.name == KEEPER_CLASS
                }
            }
        } catch (failure: GccCompilerEngineLiveContainmentException) {
            throw failure
        } catch (failure: Throwable) {
            throw GccCompilerEngineLiveContainmentException(
                "GCC Kotlin BOOT deployment JAR $index is invalid",
                failure,
            )
        }

        private fun deploymentCodeSource(): Path = try {
            val location = GccCompilerEngineLiveContainmentController::class.java.protectionDomain
                ?.codeSource?.location
                ?: liveContainmentFail("GCC live controller has no deployment code source")
            Path.of(location.toURI()).toAbsolutePath().normalize().toRealPath()
        } catch (failure: GccCompilerEngineLiveContainmentException) {
            throw failure
        } catch (failure: Throwable) {
            throw GccCompilerEngineLiveContainmentException(
                "GCC live controller deployment code source is invalid",
                failure,
            )
        }

        private fun canonicalPath(raw: String, label: String): Path = try {
            val path = Path.of(raw).toAbsolutePath().normalize()
            if (path.toRealPath() != path) liveContainmentFail("$label is not canonical")
            path
        } catch (failure: GccCompilerEngineLiveContainmentException) {
            throw failure
        } catch (failure: Throwable) {
            throw GccCompilerEngineLiveContainmentException("$label is invalid", failure)
        }

        private fun canonicalDirectory(raw: String, label: String): Path {
            val path = canonicalPath(raw, label)
            requireStableDirectory(path, label)
            return path
        }

        private fun string(objectValue: JsonObject, name: String): String =
            (objectValue[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: liveContainmentFail("GCC Kotlin BOOT reference field $name must be a string")

        private fun long(objectValue: JsonObject, name: String): Long =
            (objectValue[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
                ?: liveContainmentFail("GCC Kotlin BOOT reference field $name must be an integer")

        private fun requireString(objectValue: JsonObject, name: String, expected: String) {
            if (string(objectValue, name) != expected) {
                liveContainmentFail("GCC Kotlin BOOT reference field $name is unsupported")
            }
        }

        private fun requireInteger(objectValue: JsonObject, name: String, expected: Long) {
            if (long(objectValue, name) != expected) {
                liveContainmentFail("GCC Kotlin BOOT reference field $name is unsupported")
            }
        }
    }
}

private data class ParsedReference(
    val closureSha256: String,
    val entries: List<GccKotlinBootClasspathReferenceEntry>,
)

private fun liveContainmentFail(message: String): Nothing =
    throw GccCompilerEngineLiveContainmentException(message)

private const val REFERENCE_PROPERTY =
    "decompengine.oracle.gcc.bootKeeperClasspathReference"
private const val ROOT_PROPERTY = "decompengine.oracle.gcc.bootKeeperClasspathRoot"
private const val REFERENCE_FILE = "kotlin-boot-classpath-reference-v1.json"
private const val REFERENCE_PROVIDER = "gcc-kotlin-boot-deployment-classpath-reference-v1"
private const val KEEPER_CLASS =
    "decompengine/oracle/fulltree/KotlinSystemdCgroupBootKeeper.class"
private const val MAXIMUM_REFERENCE_BYTES = 256 * 1024
private const val MAXIMUM_REFERENCE_ENTRIES = 512
private const val MAXIMUM_REFERENCE_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_REFERENCE_AGGREGATE_BYTES = 2L * 1024L * 1024L * 1024L
private val SHA256 = Regex("[0-9a-f]{64}")
private val LOGICAL_JAR_NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,255}\\.jar")
private val REFERENCE_FIELDS = setOf("closureSha256", "entries", "provider", "schemaVersion")
private val ENTRY_FIELDS = setOf("bytes", "logicalName", "sha256")
private val REFERENCE_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_REFERENCE_BYTES,
    maximumCanonicalBytes = MAXIMUM_REFERENCE_BYTES,
    maximumDepth = 4,
    maximumNodes = 4096,
    maximumStringBytes = 1024,
    maximumTotalStringBytes = 128 * 1024,
    maximumNumberCharacters = 32,
)

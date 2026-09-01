package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale
import java.util.jar.Attributes
import java.util.jar.JarInputStream
import java.util.jar.Manifest
import java.util.zip.ZipInputStream
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
                    keeperClasses += inspectJar(jarGuard, index)
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

        private fun inspectJar(
            source: StableControlFile,
            index: Int,
        ): Int = try {
            val centralEntries = preflightClassicJar(source, index)
            val inspection = inspectStreamingJar(source, centralEntries, index)
            verifyStreamingJarSignatures(source, centralEntries, index)
            inspection.manifestBytes?.let { manifestBytes ->
                val manifest = try {
                    Manifest(manifestBytes.inputStream())
                } catch (failure: Throwable) {
                    throw GccCompilerEngineLiveContainmentException(
                        "GCC Kotlin BOOT deployment JAR $index contains an invalid manifest",
                        failure,
                    )
                }
                if (manifest.mainAttributes.getValue(Attributes.Name.CLASS_PATH) != null) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains Class-Path")
                }
            }
            inspection.keeperClasses
        } catch (failure: GccCompilerEngineLiveContainmentException) {
            throw failure
        } catch (failure: Throwable) {
            throw GccCompilerEngineLiveContainmentException(
                "GCC Kotlin BOOT deployment JAR $index is invalid",
                failure,
            )
        }

        private fun preflightClassicJar(
            source: StableControlFile,
            index: Int,
        ): List<CentralJarEntry> {
            if (source.size < ZIP_END_BYTES) {
                liveContainmentFail("GCC Kotlin BOOT deployment JAR $index lacks a classic ZIP end")
            }
            val tailBytes = minOf(source.size, ZIP_END_SEARCH_BYTES.toLong()).toInt()
            val tailOffset = source.size - tailBytes
            val tail = source.readExactly(
                tailOffset,
                tailBytes,
                "GCC Kotlin BOOT deployment JAR $index ZIP end",
            )
            var endOffset = -1
            for (candidate in tail.size - ZIP_END_BYTES downTo 0) {
                if (littleEndianInt(tail, candidate) != ZIP_END_SIGNATURE) continue
                val commentBytes = littleEndianUnsignedShort(tail, candidate + 20)
                if (candidate + ZIP_END_BYTES + commentBytes == tail.size) {
                    endOffset = candidate
                    break
                }
            }
            if (endOffset < 0) {
                liveContainmentFail("GCC Kotlin BOOT deployment JAR $index lacks a bounded ZIP end")
            }
            val disk = littleEndianUnsignedShort(tail, endOffset + 4)
            val centralDisk = littleEndianUnsignedShort(tail, endOffset + 6)
            val diskEntries = littleEndianUnsignedShort(tail, endOffset + 8)
            val totalEntries = littleEndianUnsignedShort(tail, endOffset + 10)
            val centralBytes = littleEndianUnsignedInt(tail, endOffset + 12)
            val centralOffset = littleEndianUnsignedInt(tail, endOffset + 16)
            val absoluteEnd = Math.addExact(tailOffset, endOffset.toLong())
            if (absoluteEnd >= ZIP64_LOCATOR_BYTES) {
                val locator = source.readExactly(
                    absoluteEnd - ZIP64_LOCATOR_BYTES,
                    ZIP64_LOCATOR_BYTES,
                    "GCC Kotlin BOOT deployment JAR $index ZIP64 locator",
                )
                if (littleEndianInt(locator, 0) == ZIP64_LOCATOR_SIGNATURE) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index requires unsupported ZIP64")
                }
            }
            if (
                disk != 0 || centralDisk != 0 || diskEntries != totalEntries ||
                diskEntries == ZIP16_SENTINEL || totalEntries == ZIP16_SENTINEL ||
                centralBytes == ZIP32_SENTINEL || centralOffset == ZIP32_SENTINEL ||
                totalEntries !in 1..MAXIMUM_DEPLOYMENT_JAR_ENTRIES ||
                centralBytes !in 1L..MAXIMUM_DEPLOYMENT_CENTRAL_BYTES ||
                Math.addExact(centralOffset, centralBytes) != absoluteEnd
            ) liveContainmentFail(
                "GCC Kotlin BOOT deployment JAR $index requires unsupported split, ZIP64, or unbounded metadata",
            )
            val central = source.readExactly(
                centralOffset,
                centralBytes.toInt(),
                "GCC Kotlin BOOT deployment JAR $index central directory",
            )
            val entries = ArrayList<CentralJarEntry>(totalEntries)
            val names = HashSet<String>(totalEntries)
            val localOffsets = HashSet<Long>(totalEntries)
            var expandedBytes = 0L
            var cursor = 0
            var manifestSeen = false
            while (cursor < central.size) {
                if (central.size - cursor < ZIP_CENTRAL_HEADER_BYTES ||
                    littleEndianInt(central, cursor) != ZIP_CENTRAL_SIGNATURE
                ) liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index central directory is truncated or malformed",
                )
                val flags = littleEndianUnsignedShort(central, cursor + 8)
                val method = littleEndianUnsignedShort(central, cursor + 10)
                val crc = littleEndianUnsignedInt(central, cursor + 16)
                val compressedBytes = littleEndianUnsignedInt(central, cursor + 20)
                val entryBytes = littleEndianUnsignedInt(central, cursor + 24)
                val nameBytes = littleEndianUnsignedShort(central, cursor + 28)
                val extraBytes = littleEndianUnsignedShort(central, cursor + 30)
                val commentBytes = littleEndianUnsignedShort(central, cursor + 32)
                val startDisk = littleEndianUnsignedShort(central, cursor + 34)
                val localOffset = littleEndianUnsignedInt(central, cursor + 42)
                val variableBytes = Math.addExact(Math.addExact(nameBytes, extraBytes), commentBytes)
                val next = Math.addExact(cursor, Math.addExact(ZIP_CENTRAL_HEADER_BYTES, variableBytes))
                if (
                    next > central.size || nameBytes !in 1..MAXIMUM_DEPLOYMENT_JAR_NAME_BYTES ||
                    flags and ZIP_ENCRYPTED_FLAG != 0 || method !in SUPPORTED_ZIP_METHODS || startDisk != 0 ||
                    compressedBytes == ZIP32_SENTINEL || entryBytes == ZIP32_SENTINEL ||
                    localOffset == ZIP32_SENTINEL || localOffset >= centralOffset ||
                    compressedBytes > MAXIMUM_REFERENCE_ENTRY_BYTES ||
                    entryBytes > MAXIMUM_DEPLOYMENT_JAR_EXPANDED_ENTRY_BYTES ||
                    !localOffsets.add(localOffset)
                ) liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index central entry exceeds its classic bounds",
                )
                val encodedName = central.copyOfRange(
                    cursor + ZIP_CENTRAL_HEADER_BYTES,
                    cursor + ZIP_CENTRAL_HEADER_BYTES + nameBytes,
                )
                val name = encodedName.toString(Charsets.UTF_8)
                if (
                    name.isEmpty() || '\u0000' in name ||
                    !name.toByteArray(Charsets.UTF_8).contentEquals(encodedName) || !names.add(name)
                ) liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index has an invalid or duplicate entry name",
                )
                val manifest = name.equals(JAR_MANIFEST_NAME, ignoreCase = true)
                if (manifest && manifestSeen) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains duplicate manifests")
                }
                manifestSeen = manifestSeen || manifest
                if (name.equals(JAR_INDEX_NAME, ignoreCase = true)) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains an index")
                }
                if (VERSIONED_KEEPER_CLASS.matches(name)) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index contains a versioned BOOT keeper class",
                    )
                }
                if (
                    (manifest || isJarVerificationMetadata(name)) &&
                    entryBytes > MAXIMUM_DEPLOYMENT_VERIFICATION_METADATA_BYTES
                ) liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index verification metadata exceeds its byte bound",
                )
                expandedBytes = Math.addExact(expandedBytes, entryBytes)
                if (expandedBytes > MAXIMUM_DEPLOYMENT_JAR_EXPANDED_BYTES) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index exceeds its expanded-byte bound",
                    )
                }
                entries += CentralJarEntry(
                    name,
                    encodedName,
                    flags,
                    method,
                    crc,
                    compressedBytes,
                    entryBytes,
                    localOffset,
                )
                if (entries.size > totalEntries) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index has excess central entries")
                }
                cursor = next
            }
            if (cursor != central.size || entries.size != totalEntries) {
                liveContainmentFail("GCC Kotlin BOOT deployment JAR $index central entry count changed")
            }
            requireExactLocalRecords(source, entries, centralOffset, index)
            return entries
        }

        private fun requireExactLocalRecords(
            source: StableControlFile,
            centralEntries: List<CentralJarEntry>,
            centralOffset: Long,
            index: Int,
        ) {
            val ordered = centralEntries.sortedBy(CentralJarEntry::localOffset)
            var expectedOffset = 0L
            ordered.forEachIndexed { localIndex, central ->
                if (central.localOffset != expectedOffset || centralOffset - expectedOffset < ZIP_LOCAL_HEADER_BYTES) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index local records do not exactly cover their extent",
                    )
                }
                val header = source.readExactly(
                    expectedOffset,
                    ZIP_LOCAL_HEADER_BYTES,
                    "GCC Kotlin BOOT deployment JAR $index local header $localIndex",
                )
                if (littleEndianInt(header, 0) != ZIP_LOCAL_SIGNATURE) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index has an invalid local header")
                }
                val flags = littleEndianUnsignedShort(header, 6)
                val method = littleEndianUnsignedShort(header, 8)
                val crc = littleEndianUnsignedInt(header, 14)
                val compressedBytes = littleEndianUnsignedInt(header, 18)
                val expandedBytes = littleEndianUnsignedInt(header, 22)
                val nameBytes = littleEndianUnsignedShort(header, 26)
                val extraBytes = littleEndianUnsignedShort(header, 28)
                if (
                    flags != central.flags || method != central.method ||
                    nameBytes != central.encodedName.size ||
                    compressedBytes == ZIP32_SENTINEL || expandedBytes == ZIP32_SENTINEL
                ) liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index local header differs from central metadata",
                )
                val variableBytes = Math.addExact(nameBytes, extraBytes)
                val variable = source.readExactly(
                    Math.addExact(expectedOffset, ZIP_LOCAL_HEADER_BYTES.toLong()),
                    variableBytes,
                    "GCC Kotlin BOOT deployment JAR $index local name and metadata $localIndex",
                )
                if (!variable.copyOfRange(0, nameBytes).contentEquals(central.encodedName)) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index central offset selects a different local name",
                    )
                }
                val dataOffset = Math.addExact(
                    expectedOffset,
                    Math.addExact(ZIP_LOCAL_HEADER_BYTES.toLong(), variableBytes.toLong()),
                )
                val dataEnd = Math.addExact(dataOffset, central.compressedBytes)
                val nextOffset = ordered.getOrNull(localIndex + 1)?.localOffset ?: centralOffset
                if (dataEnd > nextOffset) {
                    liveContainmentFail("GCC Kotlin BOOT deployment JAR $index local entry extents overlap")
                }
                if (flags and ZIP_DATA_DESCRIPTOR_FLAG == 0) {
                    if (
                        crc != central.crc || compressedBytes != central.compressedBytes ||
                        expandedBytes != central.expandedBytes || dataEnd != nextOffset
                    ) liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index local entry extent differs from central metadata",
                    )
                } else {
                    if (
                        (crc != 0L && crc != central.crc) ||
                        (compressedBytes != 0L && compressedBytes != central.compressedBytes) ||
                        (expandedBytes != 0L && expandedBytes != central.expandedBytes)
                    ) liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index local descriptor header differs from central metadata",
                    )
                    val descriptorBytes = nextOffset - dataEnd
                    if (
                        descriptorBytes != ZIP_DATA_DESCRIPTOR_BYTES.toLong() &&
                        descriptorBytes != ZIP_SIGNED_DATA_DESCRIPTOR_BYTES.toLong()
                    ) liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index has an unbounded local data descriptor",
                    )
                    val descriptor = source.readExactly(
                        dataEnd,
                        descriptorBytes.toInt(),
                        "GCC Kotlin BOOT deployment JAR $index local data descriptor $localIndex",
                    )
                    val valueOffset = if (descriptorBytes == ZIP_SIGNED_DATA_DESCRIPTOR_BYTES.toLong()) {
                        if (littleEndianInt(descriptor, 0) != ZIP_DATA_DESCRIPTOR_SIGNATURE) {
                            liveContainmentFail(
                                "GCC Kotlin BOOT deployment JAR $index has an invalid local data descriptor",
                            )
                        }
                        Integer.BYTES
                    } else {
                        0
                    }
                    if (
                        littleEndianUnsignedInt(descriptor, valueOffset) != central.crc ||
                        littleEndianUnsignedInt(descriptor, valueOffset + 4) != central.compressedBytes ||
                        littleEndianUnsignedInt(descriptor, valueOffset + 8) != central.expandedBytes
                    ) liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index local data descriptor differs from central metadata",
                    )
                }
                expectedOffset = nextOffset
            }
            if (expectedOffset != centralOffset) {
                liveContainmentFail(
                    "GCC Kotlin BOOT deployment JAR $index local records do not exactly cover their extent",
                )
            }
        }

        private fun inspectStreamingJar(
            source: StableControlFile,
            centralEntries: List<CentralJarEntry>,
            index: Int,
        ): StreamingJarInspection {
            val byName = centralEntries.associateBy(CentralJarEntry::name)
            val seen = HashSet<String>(centralEntries.size)
            val buffer = ByteArray(JAR_STREAM_BUFFER_BYTES)
            var expandedBytes = 0L
            var keeperClasses = 0
            var manifestBytes: ByteArray? = null
            ZipInputStream(BufferedInputStream(source.slice(), JAR_STREAM_BUFFER_BYTES), Charsets.UTF_8).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    val central = byName[entry.name]
                        ?: liveContainmentFail(
                            "GCC Kotlin BOOT deployment JAR $index has an uncommitted local entry",
                        )
                    if (!seen.add(entry.name)) {
                        liveContainmentFail("GCC Kotlin BOOT deployment JAR $index has duplicate local entries")
                    }
                    if (entry.method != central.method) {
                        liveContainmentFail("GCC Kotlin BOOT deployment JAR $index entry method changed")
                    }
                    val manifest = !entry.isDirectory && entry.name.equals(JAR_MANIFEST_NAME, ignoreCase = true)
                    val manifestOutput = if (manifest) {
                        ByteArrayOutputStream(minOf(central.expandedBytes, 8192L).toInt())
                    } else {
                        null
                    }
                    var entryBytes = 0L
                    while (true) {
                        val count = zip.read(buffer)
                        if (count < 0) break
                        if (count == 0) {
                            liveContainmentFail("GCC Kotlin BOOT deployment JAR $index entry reading stalled")
                        }
                        entryBytes = Math.addExact(entryBytes, count.toLong())
                        expandedBytes = Math.addExact(expandedBytes, count.toLong())
                        if (
                            entryBytes > central.expandedBytes ||
                            entryBytes > MAXIMUM_DEPLOYMENT_JAR_EXPANDED_ENTRY_BYTES ||
                            expandedBytes > MAXIMUM_DEPLOYMENT_JAR_EXPANDED_BYTES
                        ) liveContainmentFail(
                            "GCC Kotlin BOOT deployment JAR $index entry exceeds its expanded-byte bound",
                        )
                        if (manifestOutput != null) {
                            if (manifestOutput.size() > MAXIMUM_DEPLOYMENT_MANIFEST_BYTES - count) {
                                liveContainmentFail(
                                    "GCC Kotlin BOOT deployment JAR $index manifest exceeds its byte bound",
                                )
                            }
                            manifestOutput.write(buffer, 0, count)
                        }
                    }
                    zip.closeEntry()
                    if (
                        entryBytes != central.expandedBytes ||
                        (entry.size >= 0L && entry.size != central.expandedBytes) ||
                        (entry.compressedSize >= 0L && entry.compressedSize != central.compressedBytes) ||
                        (entry.crc >= 0L && entry.crc != central.crc)
                    ) liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index local entry differs from central metadata",
                    )
                    if (manifestOutput != null) {
                        if (manifestBytes != null) {
                            liveContainmentFail("GCC Kotlin BOOT deployment JAR $index contains duplicate manifests")
                        }
                        manifestBytes = manifestOutput.toByteArray()
                    }
                    if (!entry.isDirectory && entry.name == KEEPER_CLASS) keeperClasses += 1
                }
            }
            if (seen.size != centralEntries.size || !seen.containsAll(byName.keys)) {
                liveContainmentFail("GCC Kotlin BOOT deployment JAR $index local and central entries disagree")
            }
            return StreamingJarInspection(keeperClasses, manifestBytes)
        }

        private fun verifyStreamingJarSignatures(
            source: StableControlFile,
            centralEntries: List<CentralJarEntry>,
            index: Int,
        ) {
            val byName = centralEntries.associateBy(CentralJarEntry::name)
            val signatureMetadataPresent = centralEntries.any { entry ->
                isJarVerificationMetadata(entry.name)
            }
            val seen = HashSet<String>(centralEntries.size)
            val buffer = ByteArray(JAR_STREAM_BUFFER_BYTES)
            var expandedBytes = 0L
            JarInputStream(
                BufferedInputStream(source.slice(), JAR_STREAM_BUFFER_BYTES),
                true,
            ).use { jar ->
                if (signatureMetadataPresent && jar.manifest == null) {
                    liveContainmentFail(
                        "GCC Kotlin BOOT deployment JAR $index signature metadata lacks a leading manifest",
                    )
                }
                var verifierMetadataOpen = true
                while (true) {
                    val entry = jar.nextJarEntry ?: break
                    val central = byName[entry.name]
                        ?: liveContainmentFail(
                            "GCC Kotlin BOOT deployment JAR $index verifier saw an uncommitted entry",
                        )
                    if (!seen.add(entry.name)) {
                        liveContainmentFail("GCC Kotlin BOOT deployment JAR $index verifier saw a duplicate entry")
                    }
                    val verifierMetadata = isJarVerificationMetadata(entry.name)
                    if (verifierMetadata && !verifierMetadataOpen) {
                        liveContainmentFail(
                            "GCC Kotlin BOOT deployment JAR $index has signature metadata after payload entries",
                        )
                    }
                    if (!verifierMetadata && !(entry.isDirectory && isDirectMetaInfEntry(entry.name))) {
                        verifierMetadataOpen = false
                    }
                    var entryBytes = 0L
                    while (true) {
                        val count = jar.read(buffer)
                        if (count < 0) break
                        if (count == 0) {
                            liveContainmentFail("GCC Kotlin BOOT deployment JAR $index verification stalled")
                        }
                        entryBytes = Math.addExact(entryBytes, count.toLong())
                        expandedBytes = Math.addExact(expandedBytes, count.toLong())
                        if (
                            entryBytes > central.expandedBytes ||
                            expandedBytes > MAXIMUM_DEPLOYMENT_JAR_EXPANDED_BYTES
                        ) liveContainmentFail(
                            "GCC Kotlin BOOT deployment JAR $index verification exceeded its byte bound",
                        )
                    }
                    jar.closeEntry()
                    if (entryBytes != central.expandedBytes) {
                        liveContainmentFail("GCC Kotlin BOOT deployment JAR $index verification entry changed size")
                    }
                }
            }
            val skipped = centralEntries.asSequence().map(CentralJarEntry::name).filter { name ->
                name.equals(JAR_MANIFEST_NAME, ignoreCase = true) || name.equals(JAR_META_INF_DIRECTORY, true)
            }.toSet()
            if (byName.keys.any { name -> name !in seen && name !in skipped }) {
                liveContainmentFail("GCC Kotlin BOOT deployment JAR $index verification skipped an entry")
            }
        }

        private fun isJarVerificationMetadata(name: String): Boolean {
            val relative = directMetaInfName(name) ?: return false
            return relative.startsWith("SIG-") || isJarVerifierMetadata(name)
        }

        private fun isJarVerifierMetadata(name: String): Boolean {
            val relative = directMetaInfName(name) ?: return false
            return relative.endsWith(".SF") || relative.endsWith(".RSA") ||
                relative.endsWith(".DSA") || relative.endsWith(".EC")
        }

        private fun isDirectMetaInfEntry(name: String): Boolean = directMetaInfName(name) != null

        private fun directMetaInfName(name: String): String? {
            val upper = name.uppercase(Locale.ROOT)
            if (!upper.startsWith(JAR_META_INF_DIRECTORY)) return null
            return upper.removePrefix(JAR_META_INF_DIRECTORY).takeIf { '/' !in it }
        }

        private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 0xff) or
                ((bytes[offset + 1].toInt() and 0xff) shl 8) or
                ((bytes[offset + 2].toInt() and 0xff) shl 16) or
                ((bytes[offset + 3].toInt() and 0xff) shl 24)

        private fun littleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

        private fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
            littleEndianInt(bytes, offset).toLong() and 0xffff_ffffL

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

private data class CentralJarEntry(
    val name: String,
    val encodedName: ByteArray,
    val flags: Int,
    val method: Int,
    val crc: Long,
    val compressedBytes: Long,
    val expandedBytes: Long,
    val localOffset: Long,
)

private data class StreamingJarInspection(
    val keeperClasses: Int,
    val manifestBytes: ByteArray?,
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
private val VERSIONED_KEEPER_CLASS = Regex(
    "META-INF/versions/[0-9]+/${Regex.escape(KEEPER_CLASS)}",
)
private const val MAXIMUM_REFERENCE_BYTES = 256 * 1024
private const val MAXIMUM_REFERENCE_ENTRIES = 512
private const val MAXIMUM_REFERENCE_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_REFERENCE_AGGREGATE_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_DEPLOYMENT_JAR_ENTRIES = 200_000
private const val MAXIMUM_DEPLOYMENT_CENTRAL_BYTES = 64L * 1024L * 1024L
private const val MAXIMUM_DEPLOYMENT_JAR_NAME_BYTES = 4096
private const val MAXIMUM_DEPLOYMENT_JAR_EXPANDED_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_DEPLOYMENT_JAR_EXPANDED_BYTES = 4L * 1024L * 1024L * 1024L
private const val MAXIMUM_DEPLOYMENT_MANIFEST_BYTES = 1024 * 1024
private const val MAXIMUM_DEPLOYMENT_VERIFICATION_METADATA_BYTES = 1024L * 1024L
private const val JAR_STREAM_BUFFER_BYTES = 64 * 1024
private const val JAR_META_INF_DIRECTORY = "META-INF/"
private const val JAR_MANIFEST_NAME = "META-INF/MANIFEST.MF"
private const val JAR_INDEX_NAME = "META-INF/INDEX.LIST"
private const val ZIP_CENTRAL_HEADER_BYTES = 46
private const val ZIP_CENTRAL_SIGNATURE = 0x02014b50
private const val ZIP_ENCRYPTED_FLAG = 0x0001
private const val ZIP_DATA_DESCRIPTOR_FLAG = 0x0008
private const val ZIP_LOCAL_HEADER_BYTES = 30
private const val ZIP_LOCAL_SIGNATURE = 0x04034b50
private const val ZIP_DATA_DESCRIPTOR_BYTES = 12
private const val ZIP_SIGNED_DATA_DESCRIPTOR_BYTES = 16
private const val ZIP_DATA_DESCRIPTOR_SIGNATURE = 0x08074b50
private const val ZIP_END_BYTES = 22
private const val ZIP_END_SEARCH_BYTES = ZIP_END_BYTES + 65_535
private const val ZIP_END_SIGNATURE = 0x06054b50
private const val ZIP64_LOCATOR_BYTES = 20
private const val ZIP64_LOCATOR_SIGNATURE = 0x07064b50
private const val ZIP16_SENTINEL = 0xffff
private const val ZIP32_SENTINEL = 0xffff_ffffL
private val SUPPORTED_ZIP_METHODS = setOf(0, 8)
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

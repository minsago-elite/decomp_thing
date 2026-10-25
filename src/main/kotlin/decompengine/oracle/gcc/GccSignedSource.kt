package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.provenance.BoundedTarXzSource
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

internal class GccSignedSourceException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

internal enum class GccSignedSourcePhase { METADATA_VERIFIED, INPUTS_PINNED, SIGNATURE_VERIFIED, ARCHIVE_SCANNED, BEFORE_HANDOFF }

/**
 * A held source-only verification. Its constructor is private, its inputs remain descriptor-bound,
 * and every evidence read rechecks them. No serialized report can construct this object. It grants
 * no build, runtime, source-TU ownership, candidate-model, scoring or release capability.
 */
internal class GccSignedSource private constructor(
    private val guards: List<StableControlFile>,
    private val evidence: ByteArray,
    private val checkpoint: () -> Unit,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun canonicalEvidence(): ByteArray {
        requireCurrent()
        return evidence.copyOf()
    }

    @Synchronized
    fun requireCurrent() {
        check(!closed) { "GCC signed source is closed" }
        checkpoint()
        guards.forEach { it.requireSingleLink("held GCC source"); it.verifyUnchanged("held GCC source") }
        checkpoint()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        guards.asReversed().forEach { guard ->
            try { guard.close() } catch (next: Throwable) {
                if (failure == null) failure = next else failure!!.addSuppressed(next)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        const val LOCK_BYTES = 3953L
        const val LOCK_SHA256 = "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc"
        const val ARCHIVE_BYTES = 107200820L
        const val ARCHIVE_SHA256 = "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e"
        const val SIGNATURE_BYTES = 310L
        const val SIGNATURE_SHA256 = "43d73202dcede15d31001c6ba0d28723014ef57e4dc815631772daadbe23bcd2"
        const val REVISION = "78d4ac73dd391005b895a6148cd9831e28e1208b"
        const val ROOT = "gcc-16.2.0"
        private const val MAXIMUM_EVIDENCE_BYTES = 64 * 1024
        private val JSON_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_EVIDENCE_BYTES,
            maximumCanonicalBytes = MAXIMUM_EVIDENCE_BYTES, maximumDepth = 16, maximumNodes = 4096,
            maximumStringBytes = 4096, maximumTotalStringBytes = MAXIMUM_EVIDENCE_BYTES)

        fun open(
            lockPath: Path,
            archivePath: Path,
            signaturePath: Path,
            archiveLimits: GccSourceArchiveLimits = GccSourceArchiveLimits(),
            maximumWallMillis: Long = 300_000,
            phaseObserver: ((GccSignedSourcePhase) -> Unit)? = null,
        ): GccSignedSource {
            require(maximumWallMillis in 1..300_000)
            val started = System.nanoTime()
            val maximumNanos = maximumWallMillis * 1_000_000
            val checkpoint = {
                check(!Thread.currentThread().isInterrupted && System.nanoTime() - started <= maximumNanos) {
                    "GCC signed source verification deadline or cancellation"
                }
            }
            val opened = ArrayList<StableControlFile>()
            fun retain(path: Path, maximum: Long, label: String): StableControlFile {
                require(path.isAbsolute && path.normalize() == path && path.toString().length <= 4096) {
                    "GCC source input path must be absolute and canonical"
                }
                val guard = StableControlFile.openWithCheckpoint(path, maximum, label) { checkpoint() }
                opened += guard
                guard.requireSingleLink(label)
                return guard
            }
            fun checkInputs() {
                checkpoint()
                opened.forEach { it.requireSingleLink("GCC source phase"); it.verifyUnchanged("GCC source phase") }
                checkpoint()
            }
            fun phase(value: GccSignedSourcePhase) {
                phaseObserver?.invoke(value)
                checkInputs()
            }
            try {
                val lockGuard = retain(lockPath, LOCK_BYTES, "GCC source lock")
                identity(lockGuard, LOCK_BYTES, LOCK_SHA256)
                val lock = OracleJson.parse(lockGuard.readExactly(0, LOCK_BYTES.toInt(), "GCC source lock"), JSON_LIMITS).jsonObject
                OracleSchemas.validate("gcc/source-lock", lock)
                val source = lock.getValue("source").jsonObject
                val revision = lock.getValue("revision").jsonObject
                val signing = lock.getValue("signing").jsonObject
                require(source.text("archiveRoot") == ROOT && revision.text("commit") == REVISION &&
                    revision.text("tag") == "releases/$ROOT") { "GCC source lock identity differs" }
                val keyPath = checkedRelative(lockPath.parent, signing.text("keyFile"))
                val keyGuard = retain(keyPath, MAXIMUM_EVIDENCE_BYTES.toLong(), "GCC release key")
                require(keyGuard.authenticatedSha256 == signing.text("keySha256")) { "GCC release key differs from source lock" }
                val keyBytes = keyGuard.readExactly(0, keyGuard.size.toInt(), "GCC release key")
                val key = GccSourceOpenPgp.verifyKey(keyBytes, signing.text("primaryFingerprint"), signing.text("signingFingerprint"))
                val tag = revision.getValue("tagEvidence").jsonObject
                fun tagInput(pathField: String, bytesField: String, shaField: String): Pair<StableControlFile, ByteArray> {
                    val guard = retain(checkedRelative(lockPath.parent, tag.text(pathField)), MAXIMUM_EVIDENCE_BYTES.toLong(), "GCC tag evidence")
                    identity(guard, tag.number(bytesField), tag.text(shaField))
                    return guard to guard.readExactly(0, guard.size.toInt(), "GCC tag evidence")
                }
                val (tagPayloadGuard, tagPayload) = tagInput("payloadFile", "payloadBytes", "payloadSha256")
                val (tagSignatureGuard, tagSignature) = tagInput("signatureFile", "signatureBytes", "signatureSha256")
                val expectedTag = "object $REVISION\ntype commit\ntag releases/$ROOT\n" +
                    "tagger Richard Biener <rguenther@suse.de> 1786088838 +0000\n\nGCC 16.2.0 release\n"
                require(tagPayload.contentEquals(expectedTag.toByteArray(US_ASCII))) { "GCC tag payload does not bind the locked revision" }
                val tagDigest = MessageDigest.getInstance("SHA-1")
                tagDigest.update("tag ${tagPayload.size + tagSignature.size}\u0000".toByteArray(US_ASCII))
                tagDigest.update(tagPayload); tagDigest.update(tagSignature)
                require(tagDigest.digest().hex() == revision.text("tagObject")) { "GCC annotated tag object differs" }
                val tagVerified = GccSourceOpenPgp.verifyTagSignature(key, tagPayload, tagSignature)
                phase(GccSignedSourcePhase.METADATA_VERIFIED)
                val signatureGuard = retain(signaturePath, SIGNATURE_BYTES, "GCC source detached signature")
                identity(signatureGuard, SIGNATURE_BYTES, SIGNATURE_SHA256)
                val signature = signatureGuard.readExactly(0, SIGNATURE_BYTES.toInt(), "GCC source detached signature")
                val archiveGuard = retain(archivePath, minOf(ARCHIVE_BYTES, archiveLimits.maximumCompressedBytes), "GCC source archive")
                identity(archiveGuard, ARCHIVE_BYTES, ARCHIVE_SHA256)
                phase(GccSignedSourcePhase.INPUTS_PINNED)
                val verified = GccSourceOpenPgp.verifyArchiveSignature(key, signature, archiveGuard.slice(),
                    ARCHIVE_BYTES, ARCHIVE_SHA256, checkpoint)
                phase(GccSignedSourcePhase.SIGNATURE_VERIFIED)
                val contents = lockedContents(lock)
                val scanSource = object : BoundedTarXzSource {
                    override val size: Long get() = archiveGuard.size
                    override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
                        archiveGuard.readAt(position, destination, offset, length)
                }
                val summary = GccSourceArchive.scan(scanSource, ROOT, contents.keys, archiveLimits, checkpoint)
                contents.forEach { (path, expected) ->
                    val actual = summary.selected.getValue(path)
                    require(actual.size.toLong() == expected.number("bytes") && actual.sha256 == expected.text("sha256")) {
                        "GCC locked marker or license differs"
                    }
                    expected["text"]?.jsonPrimitive?.content?.let { text ->
                        require(actual.bytes.contentEquals(text.toByteArray(Charsets.UTF_8))) { "GCC marker text differs" }
                    }
                }
                phase(GccSignedSourcePhase.ARCHIVE_SCANNED)
                val evidence = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("gcc-signed-source-verification-v1"),
                    "scope" to JsonPrimitive("exact-signed-source-release-only"),
                    "sourceAuthenticated" to JsonPrimitive(true), "sourceRevision" to JsonPrimitive(REVISION),
                    "archiveRoot" to JsonPrimitive(ROOT), "sourceLockSha256" to JsonPrimitive(LOCK_SHA256),
                    "archive" to commitment(archiveGuard), "detachedSignature" to commitment(signatureGuard),
                    "releaseKey" to commitment(keyGuard), "tagPayload" to commitment(tagPayloadGuard),
                    "tagSignature" to commitment(tagSignatureGuard), "tagObject" to revision.getValue("tagObject"),
                    "primaryFingerprint" to JsonPrimitive(verified.primaryFingerprint),
                    "signingFingerprint" to JsonPrimitive(verified.signerFingerprint),
                    "archiveSignatureEpoch" to JsonPrimitive(verified.creationEpochSeconds),
                    "tagSignatureEpoch" to JsonPrimitive(tagVerified.creationEpochSeconds),
                    "archiveProfile" to JsonPrimitive("gcc-source-posix-local-pax-v1"),
                    "scan" to JsonObject(mapOf(
                        "expandedBytes" to JsonPrimitive(summary.expandedBytes), "logicalMembers" to JsonPrimitive(summary.logicalMembers),
                        "regularFiles" to JsonPrimitive(summary.regularFiles), "directories" to JsonPrimitive(summary.directories),
                        "paxHeaders" to JsonPrimitive(summary.paxHeaders), "rawHeaders" to JsonPrimitive(summary.rawHeaders),
                        "paxPayloadBytes" to JsonPrimitive(summary.paxPayloadBytes), "maximumPaxPayloadBytes" to JsonPrimitive(summary.maximumPaxPayloadBytes),
                        "paxPathOverrides" to JsonPrimitive(summary.paxPathOverrides),
                        "paxLongPathOverrides" to JsonPrimitive(summary.paxLongPathOverrides),
                        "paxUtf8PathOverrides" to JsonPrimitive(summary.paxUtf8PathOverrides),
                        "paxKeys" to JsonObject(buildMap {
                            listOf("mtime", "atime", "ctime").forEach { put(it, JsonPrimitive(summary.paxHeaders)) }
                            if (summary.paxPathOverrides > 0) put("path", JsonPrimitive(summary.paxPathOverrides))
                        }),
                        "indexBytesCharged" to JsonPrimitive(summary.indexBytesCharged), "workUnitsCharged" to JsonPrimitive(summary.workUnitsCharged))),
                    "lockedContents" to JsonArray(summary.selected.toSortedMap().map { (path, value) -> JsonObject(mapOf(
                        "path" to JsonPrimitive(path), "bytes" to JsonPrimitive(value.size), "sha256" to JsonPrimitive(value.sha256))) }),
                    "limits" to limitsDocument(archiveLimits, maximumWallMillis),
                    "authority" to JsonObject(listOf("runtimeAuthenticated", "captureAuthenticated", "ownershipComplete",
                        "nominalIdentityComplete", "modelBound", "sealed", "scored", "complete", "productionVerified", "releaseEligible")
                        .associateWith { JsonPrimitive(false) }),
                )), JSON_LIMITS)
                phase(GccSignedSourcePhase.BEFORE_HANDOFF)
                return GccSignedSource(opened.toList(), evidence, checkpoint)
            } catch (failure: Throwable) {
                opened.asReversed().forEach { guard -> runCatching(guard::close).exceptionOrNull()?.let(failure::addSuppressed) }
                if (failure is Error) throw failure
                throw GccSignedSourceException("GCC signed source verification refused", failure)
            }
        }

        private fun identity(guard: StableControlFile, bytes: Long, digest: String) {
            require(guard.size == bytes && guard.authenticatedSha256 == digest) { "GCC source input differs from its exact lock" }
        }
        private fun commitment(guard: StableControlFile): JsonObject = JsonObject(mapOf(
            "bytes" to JsonPrimitive(guard.size), "sha256" to JsonPrimitive(guard.authenticatedSha256)))
        private fun checkedRelative(root: Path, relative: String): Path {
            require(relative.length in 1..4096 && relative.all { it.code in 33..126 && it != '\\' })
            val path = Path.of(relative)
            require(!path.isAbsolute && path.normalize() == path && path.none { it.toString() in setOf(".", "..", "") })
            return root.resolve(path)
        }
        private fun lockedContents(lock: JsonObject): Map<String, JsonObject> {
            val markers = lock.getValue("revision").jsonObject.getValue("archiveMarkers").jsonObject
            val rows = listOf("revision", "version", "developmentPhase").map { markers.getValue(it).jsonObject } +
                (lock.getValue("redistribution").jsonObject.getValue("licenseFiles") as JsonArray).map { it.jsonObject }
            require(rows.size == 7 && rows.map { it.text("path") }.toSet().size == 7)
            return rows.associateBy { "$ROOT/${it.text("path")}" }
        }
        private fun limitsDocument(l: GccSourceArchiveLimits, wall: Long): JsonObject = JsonObject(mapOf(
            "maximumCompressedBytes" to l.maximumCompressedBytes, "maximumExpandedBytes" to l.maximumExpandedBytes,
            "maximumDecoderMemoryKiB" to l.maximumDecoderMemoryKiB.toLong(), "maximumLogicalMembers" to l.maximumLogicalMembers.toLong(),
            "maximumPaxHeaders" to l.maximumPaxHeaders.toLong(), "maximumRawHeaders" to l.maximumRawHeaders.toLong(),
            "maximumPaxRecordBytes" to l.maximumPaxRecordBytes.toLong(), "maximumTotalPaxBytes" to l.maximumTotalPaxBytes,
            "maximumEntryBytes" to l.maximumEntryBytes, "maximumPathBytes" to l.maximumPathBytes.toLong(),
            "maximumComponentBytes" to l.maximumComponentBytes.toLong(), "maximumIndexBytes" to l.maximumIndexBytes,
            "maximumSelectedBytes" to l.maximumSelectedBytes.toLong(), "maximumWorkUnits" to l.maximumWorkUnits,
            "maximumWallMillis" to wall,
        ).mapValues { JsonPrimitive(it.value) })
        private fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.content
        private fun JsonObject.number(key: String): Long = getValue(key).jsonPrimitive.long
        private fun ByteArray.hex(): String = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    }
}

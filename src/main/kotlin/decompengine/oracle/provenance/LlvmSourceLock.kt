package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class LlvmSourceProvenanceException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class LlvmLockedSourceArtifact(
    val fileName: String,
    val url: String,
    val bytes: Long,
    val sha256: String,
)

internal data class LlvmLockedArchiveContent(
    val path: String,
    val bytes: Long,
    val sha256: String,
    val text: String?,
    val description: String?,
)

internal data class LlvmSourceLockVerification(
    val path: Path,
    val lockSha256: String,
    val oracleId: String,
    val version: String,
    val archiveRoot: String,
    val archive: LlvmLockedSourceArtifact,
    val detachedSignature: LlvmLockedSourceArtifact,
    val tag: String,
    val tagObject: String,
    val commit: String,
    val tagPayloadSha256: String,
    val tagSignatureSha256: String,
    val signingKeySha256: String,
    val signingFingerprint: String,
    val archiveContents: List<LlvmLockedArchiveContent>,
    val signingKey: VerifiedLlvmSigningKey,
    val tagSignature: LlvmDetachedSignatureProfile,
)

/**
 * Kotlin interpretation of the canonical LLVM source-lock v1 contract and its checked local
 * evidence. Downloaded archive bytes are deliberately outside this metadata-only checkpoint.
 */
internal class LlvmSourceLockVerifier(
    private val faultInjector: LlvmSourceLockFaultInjector? = null,
) {
    fun verify(lockPath: Path): LlvmSourceLockVerification {
        val lock = readEvidence(lockPath, MAXIMUM_LOCK_BYTES, "LLVM source lock")
        val root = parseCanonicalObject(lock.bytes, MAXIMUM_LOCK_BYTES, "LLVM source lock")
        validateSchema(root)
        if (root.sourceLong("schemaVersion", "LLVM source lock") != 1L) {
            sourceFail("LLVM source lock schemaVersion must be 1")
        }

        val oracle = root.sourceObject("oracle", "LLVM source lock")
        val version = oracle.sourceString("version", "LLVM source-lock oracle")
        requireVersion(version, "LLVM source-lock oracle version")
        val oracleId = oracle.sourceString("id", "LLVM source-lock oracle")
        if (oracleId != "clang-driver-$version") sourceFail("LLVM source-lock oracle id differs from its version")
        if (oracle.sourceString("project", "LLVM source-lock oracle") != "LLVM Project") {
            sourceFail("LLVM source-lock project must be LLVM Project")
        }
        oracle.sourceString("purpose", "LLVM source-lock oracle")

        val tag = "llvmorg-$version"
        val archiveRoot = "llvm-project-$version.src"
        val source = root.sourceObject("source", "LLVM source lock")
        if (source.sourceString("archiveRoot", "LLVM source-lock source") != archiveRoot) {
            sourceFail("LLVM source archive root differs from its version")
        }
        if (
            source.sourceString("releasePageUrl", "LLVM source-lock source") !=
            "https://github.com/llvm/llvm-project/releases/tag/$tag"
        ) {
            sourceFail("LLVM source release page URL is not canonical")
        }
        val downloadBase = "https://github.com/llvm/llvm-project/releases/download/$tag"
        val archive = parseArtifact(
            source.sourceObject("archive", "LLVM source-lock source"),
            expectedFileName = "$archiveRoot.tar.xz",
            expectedUrl = "$downloadBase/$archiveRoot.tar.xz",
            maximumBytes = MAXIMUM_SOURCE_ARCHIVE_BYTES,
            label = "LLVM source archive",
        )
        val detachedSignature = parseArtifact(
            source.sourceObject("detachedSignature", "LLVM source-lock source"),
            expectedFileName = "${archive.fileName}.sig",
            expectedUrl = "${archive.url}.sig",
            maximumBytes = MAXIMUM_OPENPGP_EVIDENCE_BYTES.toLong(),
            label = "LLVM source archive signature",
        )

        val revision = root.sourceObject("revision", "LLVM source lock")
        if (
            revision.sourceString("repositoryUrl", "LLVM source-lock revision") !=
            "https://github.com/llvm/llvm-project.git"
        ) {
            sourceFail("LLVM source repository URL is not canonical")
        }
        if (revision.sourceString("tag", "LLVM source-lock revision") != tag) {
            sourceFail("LLVM source-lock revision tag differs from its version")
        }
        val tagObject = revision.sourceString("tagObject", "LLVM source-lock revision")
        val commit = revision.sourceString("commit", "LLVM source-lock revision")
        requireGitObject(tagObject, "LLVM annotated tag object")
        requireGitObject(commit, "LLVM source commit")
        if (tagObject == commit) sourceFail("LLVM annotated tag object must differ from its commit")

        val tagEvidence = revision.sourceObject("tagEvidence", "LLVM source-lock revision")
        val payloadRelative = tagEvidence.sourceString("payloadFile", "LLVM tag evidence")
        val signatureRelative = tagEvidence.sourceString("signatureFile", "LLVM tag evidence")
        requireRelativePath(payloadRelative, "LLVM tag payload path")
        requireRelativePath(signatureRelative, "LLVM tag signature path")
        if (payloadRelative != "tag/$tag.payload" || signatureRelative != "tag/$tag.sig") {
            sourceFail("LLVM tag evidence paths differ from the locked tag")
        }
        if (payloadRelative == signatureRelative) sourceFail("LLVM tag evidence paths must be distinct")
        val payloadBytes = tagEvidence.sourceLong("payloadBytes", "LLVM tag evidence")
        val signatureBytes = tagEvidence.sourceLong("signatureBytes", "LLVM tag evidence")
        requireEvidenceLength(payloadBytes, "LLVM tag payload")
        requireEvidenceLength(signatureBytes, "LLVM tag signature")
        val payloadSha256 = tagEvidence.sourceString("payloadSha256", "LLVM tag evidence")
        val tagSignatureSha256 = tagEvidence.sourceString("signatureSha256", "LLVM tag evidence")
        requireSha256(payloadSha256, "LLVM tag payload")
        requireSha256(tagSignatureSha256, "LLVM tag signature")

        val marker = revision.sourceObject("archiveMarkers", "LLVM source-lock revision")
            .sourceObject("version", "LLVM source archive markers")
        val versionMarker = parseContentRecord(marker, withText = true, label = "LLVM version marker")
        if (versionMarker.path != "cmake/Modules/LLVMVersion.cmake") {
            sourceFail("LLVM version marker path differs from the closed profile")
        }
        val expectedVersionLines = version.split('.').mapIndexed { index, part ->
            val component = listOf("MAJOR", "MINOR", "PATCH")[index]
            "set(LLVM_VERSION_$component $part)"
        }
        if (expectedVersionLines.any { it !in versionMarker.text.orEmpty() }) {
            sourceFail("LLVM version marker text does not encode the locked version")
        }
        val markerBytes = versionMarker.text.orEmpty().toByteArray(StandardCharsets.UTF_8)
        if (
            markerBytes.size.toLong() != versionMarker.bytes ||
            OracleArtifacts.sha256(markerBytes) != versionMarker.sha256
        ) {
            sourceFail("LLVM version marker text differs from its byte and SHA-256 binding")
        }

        val signing = root.sourceObject("signing", "LLVM source lock")
        listOf("authorityUrl", "keyRetrievalUrl").forEach { field ->
            if (
                signing.sourceString(field, "LLVM source-lock signing") !=
                "https://releases.llvm.org/release-keys.asc"
            ) {
                sourceFail("LLVM source-lock signing $field is not canonical")
            }
        }
        val keyRelative = signing.sourceString("keyFile", "LLVM source-lock signing")
        requireRelativePath(keyRelative, "LLVM vendored signing-key path")
        if (keyRelative != REVIEWED_KEY_PATH) {
            sourceFail("LLVM vendored signing-key path differs from the reviewed profile")
        }
        val keySha256 = signing.sourceString("keySha256", "LLVM source-lock signing")
        requireSha256(keySha256, "LLVM vendored signing key")
        val primaryFingerprint = signing.sourceString("primaryFingerprint", "LLVM source-lock signing")
        val signingFingerprint = signing.sourceString("signingFingerprint", "LLVM source-lock signing")
        requireFingerprint(primaryFingerprint, "LLVM primary fingerprint")
        requireFingerprint(signingFingerprint, "LLVM signing fingerprint")
        if (primaryFingerprint != signingFingerprint) {
            sourceFail("LLVM source release must be signed by the reviewed primary key")
        }

        val redistribution = root.sourceObject("redistribution", "LLVM source lock")
        redistribution.sourceString("summary", "LLVM source-lock redistribution")
        val licenses = redistribution.sourceArray("licenseFiles", "LLVM source-lock redistribution")
        val licenseRecords = licenses.mapIndexed { index, value ->
            parseContentRecord(
                value as? JsonObject ?: sourceFail("LLVM license record $index must be an object"),
                withText = false,
                label = "LLVM license record $index",
            )
        }
        if (licenseRecords.map { it.path } != listOf("LICENSE.TXT", "clang/LICENSE.TXT")) {
            sourceFail("LLVM source-lock licenses must contain the root and Clang licenses in order")
        }
        val contentPaths = listOf(versionMarker.path) + licenseRecords.map { it.path }
        if (contentPaths.toSet().size != contentPaths.size) {
            sourceFail("LLVM source-lock archive content paths must be unique")
        }

        val payload = readRelativeEvidence(
            lock.path,
            payloadRelative,
            MAXIMUM_OPENPGP_EVIDENCE_BYTES,
            "LLVM annotated-tag payload",
        )
        requireIdentity(payload, payloadBytes, payloadSha256, "LLVM annotated-tag payload")
        val tagSignature = readRelativeEvidence(
            lock.path,
            signatureRelative,
            MAXIMUM_OPENPGP_EVIDENCE_BYTES,
            "LLVM annotated-tag signature",
        )
        requireIdentity(tagSignature, signatureBytes, tagSignatureSha256, "LLVM annotated-tag signature")
        val key = readRelativeEvidence(
            lock.path,
            keyRelative,
            MAXIMUM_OPENPGP_EVIDENCE_BYTES,
            "LLVM vendored signing key",
        )
        if (key.sha256 != keySha256) sourceFail("LLVM vendored signing-key SHA-256 differs from its lock")

        val expectedPayload = buildString {
            append("object ").append(commit).append('\n')
            append("type commit\n")
            append("tag ").append(tag).append('\n')
            append("tagger Douglas Yung <douglas.yung@sony.com> 1779182222 +0000\n")
            append('\n')
            append("LLVM ").append(version).append('\n')
        }.toByteArray(StandardCharsets.UTF_8)
        if (!MessageDigest.isEqual(payload.bytes, expectedPayload)) {
            sourceFail("LLVM annotated-tag payload differs from the locked revision and tagger profile")
        }
        val reconstructedTagObject = reconstructTagObject(payload.bytes, tagSignature.bytes)
        if (reconstructedTagObject != tagObject) {
            sourceFail("LLVM annotated-tag object ID differs from its exact checked evidence")
        }

        val verifiedKey = LlvmOpenPgpVerifier.verifyVendoredSigningKey(
            key.bytes,
            primaryFingerprint,
            signingFingerprint,
        )
        val verifiedTagSignature = LlvmOpenPgpVerifier.verifyTagSignature(
            verifiedKey,
            payload.bytes,
            tagSignature.bytes,
        )

        faultInjector?.hit(LlvmSourceLockVerificationPoint.AFTER_LOCAL_EVIDENCE_VERIFIED)
        listOf(lock, payload, tagSignature, key).forEach(::requireUnchanged)

        return LlvmSourceLockVerification(
            path = lock.path,
            lockSha256 = lock.sha256,
            oracleId = oracleId,
            version = version,
            archiveRoot = archiveRoot,
            archive = archive,
            detachedSignature = detachedSignature,
            tag = tag,
            tagObject = tagObject,
            commit = commit,
            tagPayloadSha256 = payload.sha256,
            tagSignatureSha256 = tagSignature.sha256,
            signingKeySha256 = key.sha256,
            signingFingerprint = signingFingerprint,
            archiveContents = listOf(versionMarker) + licenseRecords,
            signingKey = verifiedKey,
            tagSignature = verifiedTagSignature,
        )
    }

    private fun parseArtifact(
        record: JsonObject,
        expectedFileName: String,
        expectedUrl: String,
        maximumBytes: Long,
        label: String,
    ): LlvmLockedSourceArtifact {
        val fileName = record.sourceString("fileName", label)
        requireBaseName(fileName, "$label file name")
        if (fileName != expectedFileName) sourceFail("$label file name differs from the closed profile")
        val url = record.sourceString("url", label)
        if (url != expectedUrl) sourceFail("$label URL is not canonical")
        val bytes = record.sourceLong("bytes", label)
        if (bytes !in 1L..maximumBytes) sourceFail("$label byte length is outside the supported bound")
        val sha256 = record.sourceString("sha256", label)
        requireSha256(sha256, label)
        return LlvmLockedSourceArtifact(fileName, url, bytes, sha256)
    }

    private fun parseContentRecord(
        record: JsonObject,
        withText: Boolean,
        label: String,
    ): LlvmLockedArchiveContent {
        val path = record.sourceString("path", label)
        requireRelativePath(path, "$label path")
        val bytes = record.sourceLong("bytes", label)
        if (bytes !in (if (withText) 0L else 1L)..MAXIMUM_ARCHIVE_MEMBER_BYTES) {
            sourceFail("$label byte length is outside the supported bound")
        }
        val sha256 = record.sourceString("sha256", label)
        requireSha256(sha256, label)
        val text = if (withText) record.sourcePossiblyEmptyString("text", label) else null
        val description = if (withText) null else record.sourceString("description", label)
        return LlvmLockedArchiveContent(path, bytes, sha256, text, description)
    }

    private fun readRelativeEvidence(
        lockPath: Path,
        relative: String,
        maximumBytes: Int,
        label: String,
    ): AuthenticatedSourceEvidence {
        val parent = lockPath.parent ?: sourceFail("LLVM source lock has no parent directory")
        val resolved = relative.split('/').fold(parent) { current, component -> current.resolve(component) }.normalize()
        if (!resolved.startsWith(parent) || resolved == parent) sourceFail("$label escapes the source-lock directory")
        return readEvidence(resolved, maximumBytes, label)
    }

    private fun readEvidence(path: Path, maximumBytes: Int, label: String): AuthenticatedSourceEvidence {
        val normalized = path.toAbsolutePath().normalize()
        val bytes = try {
            OracleArtifacts.read(normalized, OracleArtifactLimits(maximumBytes)).bytes
        } catch (failure: Exception) {
            throw LlvmSourceProvenanceException("cannot read authenticated $label", failure)
        }
        return AuthenticatedSourceEvidence(normalized, bytes, maximumBytes, label)
    }

    private fun requireIdentity(
        evidence: AuthenticatedSourceEvidence,
        expectedBytes: Long,
        expectedSha256: String,
        label: String,
    ) {
        if (evidence.bytes.size.toLong() != expectedBytes) sourceFail("$label byte length differs from its lock")
        if (evidence.sha256 != expectedSha256) sourceFail("$label SHA-256 differs from its lock")
    }

    private fun requireUnchanged(evidence: AuthenticatedSourceEvidence) {
        val current = readEvidence(evidence.path, evidence.maximumBytes, evidence.label)
        if (!MessageDigest.isEqual(evidence.bytes, current.bytes)) {
            sourceFail("${evidence.label} changed during verification")
        }
    }

    private fun parseCanonicalObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
        OracleJson.parseCanonical(bytes, jsonLimits(maximumBytes)) as? JsonObject
            ?: sourceFail("$label root must be an object")
    } catch (failure: LlvmSourceProvenanceException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmSourceProvenanceException("$label is not strict canonical JSON", failure)
    }

    private fun validateSchema(root: JsonObject) {
        try {
            OracleSchemas.validate("llvm/source-lock", root)
        } catch (failure: Exception) {
            throw LlvmSourceProvenanceException("LLVM source lock fails its bundled schema", failure)
        }
    }

    private fun reconstructTagObject(payload: ByteArray, armoredSignature: ByteArray): String {
        val bodyLength = try {
            Math.addExact(payload.size, armoredSignature.size)
        } catch (failure: ArithmeticException) {
            throw LlvmSourceProvenanceException("LLVM annotated-tag evidence byte length overflows", failure)
        }
        val digest = MessageDigest.getInstance("SHA-1")
        digest.update("tag $bodyLength\u0000".toByteArray(StandardCharsets.US_ASCII))
        digest.update(payload)
        digest.update(armoredSignature)
        return digest.digest().joinToString(separator = "") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    private fun requireVersion(value: String, label: String) {
        if (!value.matches(VERSION)) sourceFail("$label is invalid")
    }

    private fun requireGitObject(value: String, label: String) {
        if (!value.matches(GIT_OBJECT)) sourceFail("$label is invalid")
    }

    private fun requireSha256(value: String, label: String) {
        if (!value.matches(SHA256)) sourceFail("$label SHA-256 is invalid")
    }

    private fun requireFingerprint(value: String, label: String) {
        if (!value.matches(FINGERPRINT)) sourceFail("$label is invalid")
    }

    private fun requireEvidenceLength(value: Long, label: String) {
        if (value !in 1L..MAXIMUM_OPENPGP_EVIDENCE_BYTES.toLong()) {
            sourceFail("$label byte length is outside the supported bound")
        }
    }

    private fun requireBaseName(value: String, label: String) {
        requireRelativePath(value, label)
        if ('/' in value) sourceFail("$label must be a base name")
    }

    private fun requireRelativePath(value: String, label: String) {
        if (
            value.isEmpty() || value.startsWith('/') || value.endsWith('/') || '\\' in value || '\u0000' in value ||
            value.split('/').any { it.isEmpty() || it == "." || it == ".." }
        ) {
            sourceFail("$label must be a normalized relative POSIX path")
        }
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 64,
        maximumNodes = 100_000,
        maximumStringBytes = maximumBytes,
        maximumTotalStringBytes = maximumBytes,
    )

    private data class AuthenticatedSourceEvidence(
        val path: Path,
        private val storedBytes: ByteArray,
        val maximumBytes: Int,
        val label: String,
    ) {
        val bytes: ByteArray
            get() = storedBytes.copyOf()
        val sha256: String = OracleArtifacts.sha256(storedBytes)
    }

    private companion object {
        val VERSION = Regex("(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)")
        val GIT_OBJECT = Regex("[0-9a-f]{40}")
        val SHA256 = Regex("[0-9a-f]{64}")
        val FINGERPRINT = Regex("[0-9A-F]{40}")
        const val REVIEWED_KEY_PATH = "keys/douglas-yung-llvm-release.asc"
        const val MAXIMUM_LOCK_BYTES = 64 * 1024
        const val MAXIMUM_OPENPGP_EVIDENCE_BYTES = 64 * 1024
        const val MAXIMUM_SOURCE_ARCHIVE_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_ARCHIVE_MEMBER_BYTES = 512L * 1024 * 1024
    }
}

internal enum class LlvmSourceLockVerificationPoint {
    AFTER_LOCAL_EVIDENCE_VERIFIED,
}

internal fun interface LlvmSourceLockFaultInjector {
    fun hit(point: LlvmSourceLockVerificationPoint)
}

private fun JsonObject.sourceObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: sourceFail("$label field $name must be an object")

private fun JsonObject.sourceArray(name: String, label: String): JsonArray = this[name] as? JsonArray
    ?: sourceFail("$label field $name must be an array")

private fun JsonObject.sourceString(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive ?: sourceFail("$label field $name must be a string")
    if (!value.isString || value.content.isEmpty() || '\u0000' in value.content) {
        sourceFail("$label field $name must be a non-empty string without NUL")
    }
    return value.content
}

private fun JsonObject.sourcePossiblyEmptyString(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive ?: sourceFail("$label field $name must be a string")
    if (!value.isString || '\u0000' in value.content) {
        sourceFail("$label field $name must be a string without NUL")
    }
    return value.content
}

private fun JsonObject.sourceLong(name: String, label: String): Long {
    val value = this[name] as? JsonPrimitive ?: sourceFail("$label field $name must be an integer")
    if (value.isString || value.content.any { it in ".eE" }) sourceFail("$label field $name must be an integer")
    return value.content.toLongOrNull() ?: sourceFail("$label field $name exceeds the supported integer range")
}

private fun sourceFail(message: String): Nothing = throw LlvmSourceProvenanceException(message)

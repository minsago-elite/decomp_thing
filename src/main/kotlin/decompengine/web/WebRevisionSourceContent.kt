package decompengine.web

import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.repair.StableRegularFile
import java.security.MessageDigest
import kotlinx.serialization.json.*

internal enum class WebSourceReadPurpose { PREVIEW, DOWNLOAD }

/** Optional commitment restricts the existing download capture; it never selects a path or grants access. */
internal fun parseWebSourceDownloadVersion(raw: String?): String? {
    if (raw.isNullOrEmpty()) return null
    if (raw.length <= 128) Regex("metadataVersion=([a-f0-9]{64})").matchEntire(raw)?.let { return it.groupValues[1] }
    throw WebAccessDenied(422, "VALIDATION_FAILED", "Source downloads accept only one canonical metadataVersion commitment.")
}

internal fun revisionSourceFileIndex(fileId: String): Int {
    val match = Regex("file_(0|[1-9][0-9]{0,4})_([a-f0-9]{64})").matchEntire(fileId) ?: sourceFileNotFound()
    return match.groupValues[1].toInt().also { if (it >= WebSourceCatalogSnapshot.MAXIMUM_FILES) sourceFileNotFound() }
}

internal fun resolveRevisionSourceFile(snapshot: WebRevisionSourceSnapshot, fileId: String): WebRevisionSourceFile {
    val index = revisionSourceFileIndex(fileId)
    val file = snapshot.files.getOrNull(index) ?: sourceFileNotFound()
    if (!MessageDigest.isEqual(revisionSourceFileId(snapshot.reference, index, file.evidence.path).toByteArray(), fileId.toByteArray())) sourceFileNotFound()
    return file
}

internal fun selectRevisionSourceFile(snapshot: WebRevisionSourceSnapshot, fileId: String,
    purpose: WebSourceReadPurpose): WebRevisionSourceFile {
    val file = resolveRevisionSourceFile(snapshot, fileId)
    val role = if (purpose == WebSourceReadPurpose.PREVIEW) ProjectFileRole.VIEWABLE else ProjectFileRole.ARCHIVE_PAYLOAD
    if (role !in file.evidence.roles) throw WebAccessDenied(403, "SOURCE_REPRESENTATION_UNAVAILABLE",
        "The configured source declaration does not permit this representation.")
    if (file.sizeBytes > WebRevisionSourceContent.MAXIMUM_FILE_BYTES) throw WebAccessDenied(413, "SOURCE_FILE_TOO_LARGE",
        "The selected source file exceeds this reader's byte limit.")
    return file
}

private fun sourceFileNotFound(): Nothing = throw WebAccessDenied(404, "SOURCE_FILE_NOT_FOUND",
    "The requested file is not registered in this revision source input set.")

internal data class WebSourceChunkQuery(val offset: Int, val maximum: Int, val metadataVersion: String?) {
    init {
        require(offset in 0..WebRevisionSourceContent.MAXIMUM_FILE_BYTES.toInt() && maximum in 4..WebRevisionSourceContent.MAXIMUM_CHUNK_BYTES)
        require(metadataVersion == null || metadataVersion.matches(Regex("[a-f0-9]{64}")))
    }
    companion object {
        fun parse(rawQuery: String?): WebSourceChunkQuery {
            val query = linkedMapOf<String, String>()
            if (!rawQuery.isNullOrEmpty()) for (field in rawQuery.split('&')) {
                val key = field.substringBefore('='); val value = field.substringAfter('=', "")
                if (key !in setOf("offset", "maxBytes", "metadataVersion") || query.put(key, value) != null) invalidQuery()
            }
            fun number(key: String, default: Int, minimum: Int, maximum: Int): Int {
                val text = query[key] ?: return default
                if (!text.matches(Regex("0|[1-9][0-9]{0,7}"))) invalidQuery()
                return text.toIntOrNull()?.takeIf { it in minimum..maximum } ?: invalidQuery()
            }
            val version = query["metadataVersion"]
            if (version != null && !version.matches(Regex("[a-f0-9]{64}"))) invalidQuery()
            return WebSourceChunkQuery(number("offset", 0, 0, WebRevisionSourceContent.MAXIMUM_FILE_BYTES.toInt()),
                number("maxBytes", 65_536, 4, WebRevisionSourceContent.MAXIMUM_CHUNK_BYTES), version)
        }
        private fun invalidQuery(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Source chunks accept one decimal offset, maxBytes from 4 to 131072, and an optional metadataVersion.")
    }
}

internal fun expiredSourceMetadata(): Nothing = throw WebAccessDenied(410, "CURSOR_EXPIRED",
    "Source metadata changed. Refresh this file before continuing its ranges.")

/** Already captured, digest-verified bytes. No source path or stream escapes the capture boundary. */
internal class WebRevisionSourceContent(snapshot: WebRevisionSourceSnapshot, val fileId: String,
    file: WebRevisionSourceFile, captured: StableRegularFile) {
    private val reference = snapshot.reference
    private val metadataVersion = snapshot.metadataVersion
    private val bytes = captured.bytes.also {
        if (it.size.toLong() != file.sizeBytes || it.size.toLong() > MAXIMUM_FILE_BYTES) revisionSourceChanged()
    }.copyOf()
    private val sha256 = file.evidence.sha256
    private val identity = captured.identity
    val downloadName = file.evidence.path.substringAfterLast('/')
    private val downloadAvailable = ProjectFileRole.ARCHIVE_PAYLOAD in file.evidence.roles
    private val previewAvailable = ProjectFileRole.VIEWABLE in file.evidence.roles
    private val fallback: String?

    init {
        val index = revisionSourceFileIndex(fileId)
        check(snapshot.files.getOrNull(index) === file && revisionSourceFileId(reference, index, file.evidence.path) == fileId)
        if (captured.sha256 != sha256 || WebExplorationArtifact.sha256(bytes) != sha256) revisionSourceChanged()
        fallback = if (file.evidence.contentKind != ProjectContentKind.UTF8_TEXT) "declared-binary" else textFallback(bytes)
    }

    fun requireSame(current: StableRegularFile) {
        if (current.identity != identity || current.sha256 != sha256 || !bytes.contentEquals(current.bytes)) revisionSourceChanged()
    }

    fun download(): ByteArray {
        if (!downloadAvailable) representationUnavailable()
        return bytes.copyOf()
    }

    /** Reports the constructor's exact committed-byte check, never build/behavior/archive acceptance. */
    fun verifiedDownloadHeaders(): Map<String, String> {
        if (!downloadAvailable) representationUnavailable()
        return mapOf(
            "X-Decomp-Content-Verification" to "committed-digest",
            "X-Decomp-File-ID" to fileId,
            "X-Decomp-Source-SHA256" to reference.sourceSha256,
            "X-Decomp-Metadata-Version" to metadataVersion,
            "X-Decomp-Content-SHA256" to sha256,
        )
    }

    fun chunk(query: WebSourceChunkQuery): JsonObject {
        if (!previewAvailable) representationUnavailable()
        val offset = query.offset
        val maximum = query.maximum
        if (query.metadataVersion != null && query.metadataVersion != metadataVersion) expiredSourceMetadata()
        if (offset > bytes.size || (offset == bytes.size && bytes.isNotEmpty()) ||
            (fallback == null && offset < bytes.size && continuation(bytes[offset]))) {
            throw WebAccessDenied(416, "SOURCE_RANGE_INVALID", "The byte offset is outside this file or splits a UTF-8 character.")
        }
        var end = minOf(bytes.size, offset + maximum)
        if (fallback == null) while (end < bytes.size && continuation(bytes[end])) end--
        check(end > offset || bytes.isEmpty())
        val text = if (fallback == null) String(bytes, offset, end - offset, Charsets.UTF_8) else buildString((end - offset) * 2) {
            val hex = "0123456789abcdef"
            for (index in offset until end) { val n = bytes[index].toInt() and 255; append(hex[n ushr 4]); append(hex[n and 15]) }
        }
        val firstLine = if (fallback == null) 1 + (0 until offset).count { bytes[it] == 10.toByte() } else null
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", reference.jobId); put("runId", reference.runId); put("revisionId", reference.revisionId) })
            put("fileId", fileId); put("sourceSha256", reference.sourceSha256); put("metadataVersion", metadataVersion)
            put("sha256", sha256); put("sizeBytes", bytes.size.toString()); put("offsetBytes", offset.toString())
            put("lengthBytes", (end - offset).toString()); put("nextOffsetBytes", if (end < bytes.size) JsonPrimitive(end.toString()) else JsonNull)
            put("completeFile", offset == 0 && end == bytes.size); put("downloadAvailable", downloadAvailable)
            put("representation", if (fallback == null) "utf8" else "hex"); put("fallbackReason", fallback?.let(::JsonPrimitive) ?: JsonNull)
            put("text", text); put("lineConvention", "LF"); put("firstLine", firstLine?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
            put("startsMidLine", if (fallback == null) JsonPrimitive(offset > 0 && bytes[offset - 1] != 10.toByte()) else JsonNull)
            put("endsMidLine", if (fallback == null) JsonPrimitive(end < bytes.size && bytes[end - 1] != 10.toByte()) else JsonNull)
        }
    }

    private fun representationUnavailable(): Nothing = throw WebAccessDenied(403, "SOURCE_REPRESENTATION_UNAVAILABLE",
        "The configured source declaration does not permit this representation.")

    companion object {
        const val MAXIMUM_FILE_BYTES = 8L * 1024 * 1024
        const val MAXIMUM_CHUNK_BYTES = 128 * 1024
        private fun continuation(byte: Byte): Boolean = (byte.toInt() and 0xc0) == 0x80

        /** Validate without retaining a decoded whole-file string or replacing malformed bytes. */
        internal fun textFallback(bytes: ByteArray): String? {
            var index = 0; var lineBytes = 0; var longLine = false
            while (index < bytes.size) {
                val first = bytes[index].toInt() and 255
                val width = when (first) { in 0..0x7f -> 1; in 0xc2..0xdf -> 2; in 0xe0..0xef -> 3; in 0xf0..0xf4 -> 4; else -> return "invalid-utf8" }
                if (index + width > bytes.size) return "invalid-utf8"
                for (step in 1 until width) if (!continuation(bytes[index + step])) return "invalid-utf8"
                if (width >= 3) {
                    val second = bytes[index + 1].toInt() and 255
                    if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
                        (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90)) return "invalid-utf8"
                }
                if (first == 10) lineBytes = 0 else { lineBytes += width; if (lineBytes > 256 * 1024) longLine = true }
                index += width
            }
            return if (longLine) "line-too-long" else null
        }
    }
}

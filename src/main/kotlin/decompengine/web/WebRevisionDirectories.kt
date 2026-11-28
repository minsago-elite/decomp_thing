package decompengine.web

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

internal fun revisionSourceDirectoryId(snapshot: WebRevisionSourceSnapshot, path: String): String {
    val prefix = "$path/"
    var low = 0; var high = snapshot.files.size
    while (low < high) {
        val middle = (low + high) ushr 1
        if (snapshot.files[middle].evidence.path < prefix) low = middle + 1 else high = middle
    }
    check(low < snapshot.files.size && snapshot.files[low].evidence.path.startsWith(prefix))
    // Prefer the first canonical input below this prefix, exactly as older v1 servers did.
    var inputLow = 0; var inputHigh = snapshot.inputFiles.size
    while (inputLow < inputHigh) {
        val middle = (inputLow + inputHigh) ushr 1
        if (snapshot.inputFiles[middle].evidence.path < prefix) inputLow = middle + 1 else inputHigh = middle
    }
    val input = snapshot.inputFiles.getOrNull(inputLow)?.takeIf { it.evidence.path.startsWith(prefix) }
    val identityIndex = snapshot.identityIndex(input ?: snapshot.files[low])
    val depth = path.count { it == '/' } + 1
    val ref = snapshot.reference
    val hash = revisionSourceDigest(listOf("revision-source-directory-v1", ref.jobId, ref.runId, ref.revisionId,
        ref.sourceSha256, path, identityIndex.toString(), depth.toString()).joinToString("\u0000"))
    return "dir_${identityIndex}_${depth}_$hash"
}

private val REVISION_DIRECTORY_ID = Regex("dir_(0|[1-9][0-9]{0,4})_([1-9][0-9]{0,3})_([a-f0-9]{64})")

/** Reject a malformed opaque selector before any metadata capture or source IO. */
internal fun requireRevisionSourceDirectoryId(directoryId: String) {
    if (directoryId == "root") return
    val parsed = REVISION_DIRECTORY_ID.matchEntire(directoryId) ?: revisionDirectoryNotFound()
    if (parsed.groupValues[1].toInt() >= WebSourceCatalogSnapshot.MAXIMUM_FILES || parsed.groupValues[2].toInt() > 2047) revisionDirectoryNotFound()
}

internal class WebRevisionSourceDirectory(val path: String?, val first: Int, val depth: Int)

/** Resolve one opaque directory selector against a captured input set; labels never select a prefix. */
internal fun resolveRevisionSourceDirectory(snapshot: WebRevisionSourceSnapshot, directoryId: String): WebRevisionSourceDirectory {
    requireRevisionSourceDirectoryId(directoryId)
    val selected = if (directoryId == "root") WebRevisionSourceDirectory(null, 0, 0) else {
        val parsedId = REVISION_DIRECTORY_ID.matchEntire(directoryId)!!
        val index = parsedId.groupValues[1].toInt()
        val depth = parsedId.groupValues[2].toInt()
        val file = snapshot.identityFiles.getOrNull(index) ?: revisionDirectoryNotFound()
        val parts = file.evidence.path.split('/')
        if (depth >= parts.size) revisionDirectoryNotFound()
        val path = parts.take(depth).joinToString("/")
        val canonical = revisionSourceDirectoryId(snapshot, path)
        if (!MessageDigest.isEqual(canonical.toByteArray(), directoryId.toByteArray())) revisionDirectoryNotFound()
        val first = snapshot.files.binarySearchBy("$path/") { it.evidence.path }.let { if (it < 0) -it - 1 else it }
        WebRevisionSourceDirectory(path, first, depth)
    }
    // A forged selector must not bypass a file/directory collision by skipping its parent page.
    selected.path?.let { path ->
        if (snapshot.files.any { path == it.evidence.path || path.startsWith("${it.evidence.path}/") }) revisionSourceChanged()
    }
    return selected
}

private fun revisionDirectoryNotFound(): Nothing = throw WebAccessDenied(404, "SOURCE_DIRECTORY_NOT_FOUND",
    "The requested directory is not recorded in this source input set.")

/** Lazy immediate-child views of recorded canonical input prefixes, never a filesystem walk. */
internal class WebRevisionDirectoryPages(private val source: (String, String, String) -> WebRevisionSourceSnapshot) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private class Child(val name: String, val first: Int, val directoryPath: String?, var files: Int = 1)

    fun page(owner: String, jobId: String, runId: String, revisionId: String, directoryId: String, rawQuery: String?, includeManifest: Boolean = false): JsonObject {
        requireRevisionSourceDirectoryId(directoryId)
        if (rawQuery != null && rawQuery.split('&').any { it.substringBefore('=') !in setOf("limit", "cursor") }) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Directory pages accept only limit and cursor.")
        }
        val (query, cursor) = WebJobQuery.parse(rawQuery)
        val continuation = cursor?.split('_')?.also { parts ->
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{64}")) ||
                !parts[1].matches(Regex("[1-9][0-9]{0,4}")) || !parts[2].matches(Regex("[a-f0-9]{32}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, runId, revisionId, directoryId, includeManifest, query.limit, parts[0], parts[1]).toByteArray(),
                    parts[2].toByteArray())) invalidCursor()
        }
        val snapshot = source(jobId, runId, revisionId).inventory(includeManifest)
        val ref = snapshot.reference
        check(ref.jobId == jobId && ref.runId == runId && ref.revisionId == revisionId)
        val selected = resolveRevisionSourceDirectory(snapshot, directoryId)
        val prefix = selected.path?.let { "$it/" }.orEmpty()
        val children = linkedMapOf<String, Child>()
        var sourceFiles = 0
        for (index in selected.first until snapshot.files.size) {
            val path = snapshot.files[index].evidence.path
            if (!path.startsWith(prefix)) break
            sourceFiles++
            val relative = path.substring(prefix.length)
            val slash = relative.indexOf('/')
            val name = if (slash < 0) relative else relative.substring(0, slash)
            val child = children[name]
            if (slash < 0) {
                if (child != null) revisionSourceChanged()
                children[name] = Child(name, index, null)
            } else if (child == null) children[name] = Child(name, index, prefix + name)
            else {
                if (child.directoryPath == null) revisionSourceChanged()
                child.files++
            }
        }
        val ordered = children.values.sortedWith(compareBy<Child> { if (it.directoryPath == null) 1 else 0 }.thenBy { it.name })
        check(ordered.isNotEmpty())
        val offset = continuation?.let { parts ->
            if (parts[0] != snapshot.metadataVersion) throw WebAccessDenied(410, "CURSOR_EXPIRED",
                "Directory source metadata changed. Refresh its first page.")
            parts[1].toInt().also { if (it >= ordered.size) invalidCursor() }
        } ?: 0
        val items = ArrayList<JsonObject>(query.limit)
        var itemBytes = 0
        for (child in ordered.subList(offset, minOf(ordered.size, offset + query.limit))) {
            val item = if (child.directoryPath != null) buildJsonObject {
                put("kind", "directory"); put("directoryId", revisionSourceDirectoryId(snapshot, child.directoryPath))
                put("displayName", child.name); put("sourceFileCount", child.files)
            } else {
                val file = snapshot.files[child.first]
                buildJsonObject {
                    put("kind", "file"); put("fileId", snapshot.fileId(file))
                    put("displayName", child.name); putRevisionSourceFileFacts(file)
                }
            }
            val bytes = item.toString().toByteArray(Charsets.UTF_8).size + 1
            if (itemBytes + bytes > 1_000_000) break
            itemBytes += bytes; items += item
        }
        check(items.isNotEmpty())
        val parts = selected.path?.split('/').orEmpty()
        val breadcrumbs = ArrayList<JsonObject>()
        breadcrumbs += buildJsonObject { put("directoryId", "root"); put("displayName", JsonNull) }
        for (depth in maxOf(1, selected.depth - 30)..selected.depth) {
            breadcrumbs += buildJsonObject {
                put("directoryId", revisionSourceDirectoryId(snapshot, parts.take(depth).joinToString("/")))
                put("displayName", parts[depth - 1])
            }
        }
        val parentId = when (selected.depth) {
            0 -> null
            1 -> "root"
            else -> revisionSourceDirectoryId(snapshot, parts.dropLast(1).joinToString("/"))
        }
        val next = offset + items.size
        val result = buildJsonObject {
            put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", revisionId) })
            put("authority", "source-input-commitments"); put("sourceSha256", ref.sourceSha256)
            put("metadataVersion", snapshot.metadataVersion); put("directoryId", directoryId)
            put("parentDirectoryId", parentId?.let(::JsonPrimitive) ?: JsonNull)
            put("displayName", parts.lastOrNull()?.let(::JsonPrimitive) ?: JsonNull)
            put("depth", selected.depth); put("breadcrumbs", JsonArray(breadcrumbs))
            put("omittedAncestors", maxOf(0, selected.depth - 31)); put("emptyDirectories", "not-recorded")
            put("sourceFileCount", sourceFiles); put("totalChildren", ordered.size); put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit); put("snapshotVersion", snapshot.metadataVersion)
                put("nextCursor", if (next < ordered.size) JsonPrimitive(
                    "${snapshot.metadataVersion}_${next}_${signature(owner, jobId, runId, revisionId, directoryId, includeManifest, query.limit, snapshot.metadataVersion, next)}"
                ) else JsonNull)
            })
        }
        check(result.toString().toByteArray(Charsets.UTF_8).size <= 1_048_000)
        return result
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        val bytes = mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        return buildString(32) {
            val hex = "0123456789abcdef"
            for (index in 0 until 16) { val n = bytes[index].toInt() and 255; append(hex[n ushr 4]); append(hex[n and 15]) }
        }
    }

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use a directory cursor from this session, job, run, revision, directory and page size, or refresh its first page.")
}

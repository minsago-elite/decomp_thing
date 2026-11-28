package decompengine.builtin

import com.fasterxml.jackson.core.JsonGenerator
import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections

data class BuiltinContextToolAudit(val callId: String, val tool: String, val resultSha256: String, val failed: Boolean)

private fun writeEvidencePage(
    out: JsonGenerator,
    item: AgentContextInput,
    sha256: String,
    offset: Int,
    text: String,
    nextOffset: Int?,
) {
    out.writeStartObject(); out.writeStringField("id", item.id); out.writeStringField("mediaType", item.mediaType)
    out.writeFieldName("description"); item.description?.let(out::writeString) ?: out.writeNull()
    out.writeStringField("source", "immutable-request-context"); out.writeStringField("sha256", sha256)
    out.writeNumberField("offset", offset); out.writeStringField("text", text)
    out.writeFieldName("nextOffset"); nextOffset?.let { out.writeNumber(it) } ?: out.writeNull()
    out.writeEndObject()
}

/**
 * Confirm that an omitted input can be recovered through at least one result-bounded read page.
 * The empty page below uses the largest valid offset widths; adding the largest encoded single
 * code point proves that readEvidence can always shrink its page to a retrievable unit.
 */
internal fun canReadAnyEvidencePage(
    input: AgentContextInput,
    sha256: String,
    maximumResultBytes: Int,
    control: BuiltinExecutionControl,
): Boolean {
    if (maximumResultBytes <= 0) return false
    val content = input.content
    val base = try {
        boundedProviderJson(maximumResultBytes) { out ->
            writeEvidencePage(out, input, sha256, content.length, "", content.length.takeIf { content.isNotEmpty() })
        }
    } catch (failure: ModelProviderException) {
        if (failure.kind == ModelFailureKind.RESOURCE_EXHAUSTED) return false
        throw failure
    }
    if (content.isEmpty()) return true

    var index = 0
    var maximumCodePointBytes = 0
    while (index < content.length) {
        if ((index and 0x3fff) == 0) control.checkpoint()
        val character = content[index]
        val encodedBytes = when {
            character == '"' || character == '\\' -> 2
            character == '\b' || character == '\t' || character == '\n' || character == '\u000c' || character == '\r' -> 2
            character < ' ' -> 6
            character.isHighSurrogate() -> {
                if (index + 1 >= content.length || !content[index + 1].isLowSurrogate()) return false
                index++
                12
            }
            character.isLowSurrogate() -> return false
            character.code < 0x80 -> 1
            character.code < 0x800 -> 2
            else -> 3
        }
        maximumCodePointBytes = maxOf(maximumCodePointBytes, encodedBytes)
        index++
    }
    val terminalNullReserve = maxOf(0, 4 - content.length.toString().length)
    return maximumCodePointBytes <= maximumResultBytes - base.size - terminalNullReserve
}

/** Read-only views of the authority-supplied virtual workspace and immutable request evidence. */
internal class BuiltinCapturedContextTools(
    private val request: AgentExecutionRequest,
    paths: Collection<String>,
    private val maximumResultBytes: Int,
    private val maximumAuditRecords: Int,
) {
    private val paths = paths.sorted()
    private val evidence = request.contextInputs.associateBy { it.id }
    private val records = mutableListOf<BuiltinContextToolAudit>()
    val definitions = listOf(
        ModelToolDefinition("list_directory", "List readable captured directory entries; empty path means the virtual root", schema(mapOf(
            "path" to buildJsonObject { put("type", "string") },
            "offset" to offsetSchema(),
        ))),
        ModelToolDefinition("list_evidence", "List immutable request evidence IDs and hashes, with bounded pagination", schema(mapOf("offset" to offsetSchema()))),
        ModelToolDefinition("read_evidence", "Read immutable evidence text; use nextOffset for the next Unicode-safe page", schema(mapOf(
            "id" to buildJsonObject { put("type", "string") }, "offset" to offsetSchema(),
        ))),
    )

    fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
        control.checkpoint()
        if (records.size >= maximumAuditRecords) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
        val result = when (call.name) {
            "list_directory" -> directory(call.arguments, control)
            "list_evidence" -> listEvidence(call.arguments, control)
            "read_evidence" -> readEvidence(call.arguments, control)
            else -> BuiltinToolResult("unregistered context tool", failed = true)
        }
        control.checkpoint()
        records += BuiltinContextToolAudit(call.id, call.name, hash(result.content), result.failed)
        return result
    }

    fun audit(): List<BuiltinContextToolAudit> = Collections.unmodifiableList(ArrayList(records))

    private fun directory(arguments: JsonObject, control: BuiltinExecutionControl): BuiltinToolResult {
        val prefix = arguments.getValue("path").jsonPrimitive.content
        val offset = arguments.getValue("offset").jsonPrimitive.int
        if (prefix.isNotEmpty()) {
            val path = Path.of(prefix)
            if (path.isAbsolute || path.normalize().toString() != prefix || path.startsWith(".."))
                return BuiltinToolResult("invalid captured directory", failed = true)
        }
        val root = request.workspaceRoots.single()
        val children = sortedMapOf<String, String>()
        paths.forEach { path ->
            control.checkpoint()
            if (!request.accessPolicy.allows(AgentWorkspacePath(root.id, path), AgentOperation.READ_FILE)) return@forEach
            val relative = if (prefix.isEmpty()) path else path.removePrefix("$prefix/").takeIf { it != path } ?: return@forEach
            val child = relative.substringBefore('/')
            children[child] = if ('/' in relative) "directory" else "file"
        }
        if (offset !in 0..children.size) return BuiltinToolResult("invalid directory page offset", failed = true)
        val page = children.entries.drop(offset).take(PAGE_ENTRIES)
        return json { out ->
            out.writeStartObject(); out.writeStringField("path", prefix)
            out.writeArrayFieldStart("entries")
            page.forEach { (name, type) -> out.writeStartObject(); out.writeStringField("name", name); out.writeStringField("type", type); out.writeEndObject() }
            out.writeEndArray(); out.writeNumberField("totalEntries", children.size)
            out.writeFieldName("nextOffset"); if (offset + page.size < children.size) out.writeNumber(offset + page.size) else out.writeNull()
            out.writeEndObject()
        }
    }

    private fun listEvidence(arguments: JsonObject, control: BuiltinExecutionControl): BuiltinToolResult {
        val offset = arguments.getValue("offset").jsonPrimitive.int
        val items = evidence.values.sortedBy { it.id }
        if (offset !in 0..items.size) return BuiltinToolResult("invalid evidence page offset", failed = true)
        val remaining = items.size - offset
        val maximumEntries = minOf(PAGE_ENTRIES, remaining)
        var low = 1
        var high = maximumEntries
        var fittingPage: ByteArray? = null
        while (low <= high) {
            val entryCount = low + (high - low) / 2
            try {
                val page = items.subList(offset, offset + entryCount)
                val encoded = evidenceListPage(items.size, offset, page, control)
                fittingPage = encoded
                low = entryCount + 1
            } catch (failure: ModelProviderException) {
                if (failure.kind != ModelFailureKind.RESOURCE_EXHAUSTED) throw failure
                high = entryCount - 1
            }
        }
        fittingPage?.let { return BuiltinToolResult(it.decodeToString()) }
        if (maximumEntries == 0) {
            try {
                return BuiltinToolResult(evidenceListPage(items.size, offset, emptyList(), control).decodeToString())
            } catch (failure: ModelProviderException) {
                if (failure.kind != ModelFailureKind.RESOURCE_EXHAUSTED) throw failure
            }
        }
        val message = if (maximumEntries == 0) "evidence inventory page exceeds the configured result limit"
        else "next evidence entry exceeds the configured result limit"
        return BuiltinToolResult(message, failed = true)
    }

    private fun evidenceListPage(
        totalEntries: Int,
        offset: Int,
        page: List<AgentContextInput>,
        control: BuiltinExecutionControl,
    ): ByteArray = boundedProviderJson(maximumResultBytes) { out ->
            out.writeStartObject(); out.writeArrayFieldStart("evidence")
            page.forEach { item ->
                control.checkpoint()
                out.writeStartObject(); out.writeStringField("id", item.id); out.writeStringField("mediaType", item.mediaType)
                out.writeFieldName("description"); item.description?.let(out::writeString) ?: out.writeNull()
                out.writeStringField("sha256", hash(item.content)); out.writeNumberField("utf8Bytes", item.content.toByteArray().size); out.writeEndObject()
            }
            out.writeEndArray(); out.writeNumberField("totalEntries", totalEntries)
            out.writeFieldName("nextOffset"); if (offset + page.size < totalEntries) out.writeNumber(offset + page.size) else out.writeNull()
            out.writeEndObject()
        }

    private fun readEvidence(arguments: JsonObject, control: BuiltinExecutionControl): BuiltinToolResult {
        val item = evidence[arguments.getValue("id").jsonPrimitive.content]
            ?: return BuiltinToolResult("unknown immutable evidence id", failed = true)
        val offset = arguments.getValue("offset").jsonPrimitive.int
        if (offset !in 0..item.content.length || (offset < item.content.length && item.content[offset].isLowSurrogate()))
            return BuiltinToolResult("invalid evidence text offset", failed = true)
        if (item.content.isEmpty()) {
            return try {
                BuiltinToolResult(evidencePage(item, 0, 0).decodeToString())
            } catch (failure: ModelProviderException) {
                if (failure.kind != ModelFailureKind.RESOURCE_EXHAUSTED) throw failure
                BuiltinToolResult("evidence page exceeds the configured result limit", failed = true)
            }
        }
        var end = minOf(item.content.length, offset + PAGE_CHARACTERS)
        if (end < item.content.length && item.content[end - 1].isHighSurrogate()) end--
        control.checkpoint()
        var encoded: ByteArray? = null
        while (end > offset) {
            if (end < item.content.length && item.content[end - 1].isHighSurrogate()) end--
            try {
                encoded = evidencePage(item, offset, end)
                break
            } catch (failure: ModelProviderException) {
                if (failure.kind != ModelFailureKind.RESOURCE_EXHAUSTED) throw failure
                end = previousCodePointBoundary(item.content, end, offset)
            }
        }
        if (encoded == null) return BuiltinToolResult("evidence page exceeds the configured result limit", failed = true)
        return BuiltinToolResult(encoded.decodeToString())
    }

    private fun evidencePage(item: AgentContextInput, offset: Int, end: Int) = boundedProviderJson(maximumResultBytes) { out ->
        writeEvidencePage(out, item, hash(item.content), offset, item.content.substring(offset, end), end.takeIf { it < item.content.length })
    }

    private fun previousCodePointBoundary(value: String, end: Int, minimum: Int): Int {
        var candidate = end - 1
        if (candidate > minimum && value[candidate - 1].isHighSurrogate() && value[candidate].isLowSurrogate()) candidate--
        return candidate.coerceAtLeast(minimum)
    }
    private fun json(write: (com.fasterxml.jackson.core.JsonGenerator) -> Unit) =
        BuiltinToolResult(boundedProviderJson(maximumResultBytes, write).decodeToString())
    private fun schema(properties: Map<String, JsonObject>) = buildJsonObject {
        put("type", "object"); put("additionalProperties", false)
        putJsonObject("properties") { properties.forEach { (name, value) -> put(name, value) } }
        putJsonArray("required") { properties.keys.forEach { add(it) } }
    }
    private fun offsetSchema() = buildJsonObject { put("type", "integer"); put("minimum", 0); put("maximum", Int.MAX_VALUE) }
    private fun hash(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
    private companion object { const val PAGE_ENTRIES = 64; const val PAGE_CHARACTERS = 4096 }
}

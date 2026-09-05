package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections

data class BuiltinContextToolAudit(val callId: String, val tool: String, val resultSha256: String, val failed: Boolean)

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
        val page = items.drop(offset).take(PAGE_ENTRIES)
        return json { out ->
            out.writeStartObject(); out.writeArrayFieldStart("evidence")
            page.forEach { item ->
                control.checkpoint()
                out.writeStartObject(); out.writeStringField("id", item.id); out.writeStringField("mediaType", item.mediaType)
                out.writeStringField("sha256", hash(item.content)); out.writeNumberField("utf8Bytes", item.content.toByteArray().size); out.writeEndObject()
            }
            out.writeEndArray(); out.writeNumberField("totalEntries", items.size)
            out.writeFieldName("nextOffset"); if (offset + page.size < items.size) out.writeNumber(offset + page.size) else out.writeNull()
            out.writeEndObject()
        }
    }

    private fun readEvidence(arguments: JsonObject, control: BuiltinExecutionControl): BuiltinToolResult {
        val item = evidence[arguments.getValue("id").jsonPrimitive.content]
            ?: return BuiltinToolResult("unknown immutable evidence id", failed = true)
        val offset = arguments.getValue("offset").jsonPrimitive.int
        if (offset !in 0..item.content.length || (offset < item.content.length && item.content[offset].isLowSurrogate()))
            return BuiltinToolResult("invalid evidence text offset", failed = true)
        var end = minOf(item.content.length, offset + PAGE_CHARACTERS)
        if (end < item.content.length && item.content[end - 1].isHighSurrogate()) end--
        control.checkpoint()
        return json { out ->
            out.writeStartObject(); out.writeStringField("id", item.id); out.writeStringField("mediaType", item.mediaType)
            out.writeStringField("source", "immutable-request-context"); out.writeStringField("sha256", hash(item.content))
            out.writeNumberField("offset", offset); out.writeStringField("text", item.content.substring(offset, end))
            out.writeFieldName("nextOffset"); if (end < item.content.length) out.writeNumber(end) else out.writeNull()
            out.writeEndObject()
        }
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

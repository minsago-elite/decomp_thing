package decompengine.builtin.provider

import java.util.Collections

internal class CatalogModelV1(val slug: String, val displayName: String) {
    init {
        if (slug.length !in 1..200 || !slug.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")) ||
            ChatGptPlanWireJsonV1.scalarUtf8Length(displayName, 256) == null ||
            displayName.isBlank() || displayName.any { it.isISOControl() }) {
            throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
        }
    }
    override fun toString() = "CatalogModelV1(redacted)"
}

internal class ChatGptCatalogV1(models: List<CatalogModelV1>) {
    val models: List<CatalogModelV1>
    init {
        if (models.size > MAX_ENTRIES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
        val copy = ArrayList<CatalogModelV1>()
        val seen = HashSet<String>()
        for (model in models) {
            if (copy.size >= MAX_ENTRIES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            if (!seen.add(model.slug)) throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
            copy.add(model)
        }
        this.models = Collections.unmodifiableList(copy)
    }

    fun requireExactSlug(slug: String): CatalogModelV1 =
        models.firstOrNull { it.slug == slug } ?: throw ModelProviderException(ModelFailureKind.MODEL_UNAVAILABLE)

    override fun toString() = "ChatGptCatalogV1(redacted)"

    companion object {
        const val MAX_BODY_BYTES = 1 shl 20
        const val MAX_ENTRIES = 1024

        fun parse(entity: ByteArray): ChatGptCatalogV1 {
            if (entity.size > MAX_BODY_BYTES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            val root = try { ChatGptPlanWireJsonV1.parse(entity, MAX_BODY_BYTES) }
            catch (_: ChatGptWireJsonException) { throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE) }
            val rootObj = root as? ChatGptWireValueV1.Obj ?: malformed()
            val rows = rootObj.fields["models"] as? ChatGptWireValueV1.Arr ?: malformed()
            if (rows.values.size > MAX_ENTRIES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            val seen = HashSet<String>()
            val visible = ArrayList<CatalogModelV1>()
            for (row in rows.values) {
                val fields = (row as? ChatGptWireValueV1.Obj)?.fields ?: malformed()
                val slug = (fields["slug"] as? ChatGptWireValueV1.Str)?.value ?: malformed()
                val display = (fields["display_name"] as? ChatGptWireValueV1.Str)?.value ?: malformed()
                val visibility = (fields["visibility"] as? ChatGptWireValueV1.Str)?.value ?: malformed()
                val model = CatalogModelV1(slug, display)
                if (!seen.add(slug)) malformed()
                if (visibility == "list") visible.add(model)
                // Unknown metadata is intentionally parsed and bounded by the strict JSON codec,
                // but it has no authority and is never retained.
            }
            return ChatGptCatalogV1(visible)
        }

        private fun malformed(): Nothing = throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
    }
}

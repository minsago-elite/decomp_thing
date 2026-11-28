package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Bounded archival prompt input, never a complete raw corpus or execution authority. The original
 * corpus digest is declared provenance: omitted bytes cannot be reauthenticated from a selection.
 */
internal object ModuleObservationRetention {
    const val KIND = "module-observed-behavior-selection"
    private const val PROVIDER = "module-observation-retention-v1"
    private val LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES,
        maximumCanonicalBytes = MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES,
        maximumDepth = 9,
        maximumNodes = 100_000,
        maximumStringBytes = 32 * 1024,
        maximumTotalStringBytes = MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES,
        maximumNumberCharacters = 12,
    )

    /** Reserved archival records cannot be reinterpreted as original generation input. */
    fun requireRawInput(observed: String?) {
        require(observed == null || probe(observed, legacy = false) == null) {
            "retained module observation selections are not raw producer corpora"
        }
    }

    internal fun claimsSelection(root: JsonObject): Boolean =
        (root["kind"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.startsWith(KIND) == true ||
            root["provider"] == JsonPrimitive(PROVIDER)

    private fun probe(observed: String, legacy: Boolean): JsonObject? {
        // JSON escapes can hide either reserved identity from a literal substring probe.
        if (observed.firstOrNull { !it.isWhitespace() } != '{' && KIND !in observed && PROVIDER !in observed) return null
        val root = try {
            ModuleObservedBehavior.parseObject(observed)
        } catch (failure: IllegalArgumentException) {
            // Current raw selection already fails closed on malformed claimed module corpora.
            // Historical v3, however, rendered arbitrary opaque text verbatim.
            if (!legacy && ModuleObservedBehavior.KIND in observed) throw failure
            return null
        }
        return root.takeIf(::claimsSelection)
    }

    fun retain(request: ModuleReconstructionRequest): String? {
        val observed = request.observedBehavior ?: return null
        requireRawInput(observed)
        val rawBytes = observed.toByteArray(Charsets.UTF_8)
        // Preserve all existing small raw inputs, including historical whitespace and opaque text.
        if (rawBytes.size <= MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES) return observed
        val selection = selectModuleObservationCases(observed, request.module, request.model)
        if (selection == null) {
            requireRetainableModuleObservation(observed)
            error("oversized opaque observation unexpectedly passed retention")
        }
        require(request.module.functionIds.distinct().size == request.module.functionIds.size) {
            "retained module selection requires unique planned function ownership"
        }
        val wrapper = JsonObject(mapOf(
            "kind" to JsonPrimitive(KIND), "provider" to JsonPrimitive(PROVIDER), "schemaVersion" to JsonPrimitive(1),
            "scope" to JsonPrimitive("module-selected"), "originalCorpusRetained" to JsonPrimitive(false),
            "inputSha256" to JsonPrimitive(selection.document.inputSha256),
            "moduleId" to JsonPrimitive(request.module.id),
            "functionIds" to JsonArray(request.module.functionIds.sorted().map(::JsonPrimitive)),
            "sourceCorpus" to JsonObject(mapOf(
                "sha256" to JsonPrimitive(sha256(rawBytes)), "bytes" to JsonPrimitive(rawBytes.size),
                "caseCount" to JsonPrimitive(selection.document.cases.size),
            )),
            "selected" to ModuleObservedBehavior.envelope(selection.document.inputSha256, selection.cases),
        ))
        return try {
            OracleJson.canonicalBytes(wrapper, LIMITS).decodeToString()
        } catch (failure: IllegalArgumentException) {
            throw IllegalArgumentException("pre-dispatch selected observation exceeds the retained prompt input bound", failure)
        }
    }

    /** Historical raw strings remain raw; only the current renderer may replay the closed wrapper. */
    fun replay(observed: String?, module: PlannedModule, model: RecoveredProgramModel, legacy: Boolean): String? {
        requireRetainableModuleObservation(observed)
        if (observed == null || probe(observed, legacy) == null) return observed
        require(!legacy) { "historical module prompts cannot replay a retained module selection" }
        val wrapper = OracleJson.parseCanonical(observed.toByteArray(Charsets.UTF_8), LIMITS) as? JsonObject
            ?: throw IllegalArgumentException("retained module selection must be an object")
        require(wrapper.keys == setOf("kind", "provider", "schemaVersion", "scope", "originalCorpusRetained",
            "inputSha256", "moduleId", "functionIds", "sourceCorpus", "selected")) {
            "retained module selection fields differ"
        }
        require(wrapper["kind"] == JsonPrimitive(KIND) && wrapper["provider"] == JsonPrimitive(PROVIDER) &&
            wrapper["schemaVersion"] == JsonPrimitive(1) &&
            wrapper["scope"] == JsonPrimitive("module-selected") && wrapper["originalCorpusRetained"] == JsonPrimitive(false)) {
            "retained module selection contract differs"
        }
        require(wrapper["inputSha256"] == JsonPrimitive(model.inputSha256) &&
            wrapper["moduleId"] == JsonPrimitive(module.id) && module.functionIds.distinct().size == module.functionIds.size &&
            wrapper["functionIds"] == JsonArray(module.functionIds.sorted().map(::JsonPrimitive))) {
            "retained module selection differs from the planned input and ownership"
        }
        val source = wrapper["sourceCorpus"] as? JsonObject
            ?: throw IllegalArgumentException("retained module selection source must be an object")
        require(source.keys == setOf("sha256", "bytes", "caseCount")) { "retained source corpus fields differ" }
        val sourceSha = source["sha256"] as? JsonPrimitive
        require(sourceSha != null && sourceSha.isString && sourceSha.content.matches(Regex("[0-9a-f]{64}"))) {
            "retained source corpus digest is invalid"
        }
        fun number(name: String): Long {
            val field = source[name] as? JsonPrimitive
                ?: throw IllegalArgumentException("retained source corpus $name is missing")
            require(!field.isString && field.content.matches(Regex("0|[1-9][0-9]{0,11}"))) {
                "retained source corpus $name must be a bounded integer"
            }
            return requireNotNull(field.content.toLongOrNull())
        }
        require(number("bytes") in (MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES.toLong() + 1)..ModuleObservedBehavior.MAXIMUM_BYTES.toLong()) {
            "retained source corpus byte count is outside the projection range"
        }
        val sourceCount = number("caseCount")
        require(sourceCount in 0L..1024L) { "retained source corpus case count is outside its bound" }
        val selected = wrapper["selected"] as? JsonObject
            ?: throw IllegalArgumentException("retained module selection payload must be an object")
        val selectedBytes = OracleJson.canonicalBytes(selected, ModuleObservedBehavior.limits)
        val selection = requireNotNull(selectModuleObservationCases(selectedBytes.decodeToString(), module, model)) {
            "retained module selection payload is not a module corpus"
        }
        require(selection.cases.size == selection.document.cases.size && selection.cases.size.toLong() <= sourceCount &&
            selected == ModuleObservedBehavior.envelope(model.inputSha256, selection.cases)) {
            "retained module selection contains unselected or noncanonical cases"
        }
        return selectedBytes.decodeToString()
    }
}

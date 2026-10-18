package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Byte-format and ownership validation only; this does not attest execution or planner semantics. */
internal object ModulePlanJson {
    fun readCanonical(bytes: ByteArray, maximumBytes: Int): ModulePlan = readCanonical(bytes, maximumBytes) {}

    /** Cooperative traversal; individual library parsing, rendering and allocation remain nonpreemptible. */
    internal fun readCanonical(bytes: ByteArray, maximumBytes: Int, checkpoint: (String) -> Unit): ModulePlan {
        checkpoint("before reading module plan")
        require(maximumBytes in 1..512 * 1024 * 1024 && bytes.size in 1..maximumBytes) {
            "module plan exceeds its byte bound"
        }
        val text = bytes.toString(Charsets.UTF_8)
        require(bytes.contentEquals(text.toByteArray(Charsets.UTF_8))) { "module plan is not canonical UTF-8" }
        checkpoint("after decoding module plan")
        // Bound nesting before the general JSON parser sees untrusted output. Strings may contain braces.
        var depth = 0
        var quoted = false
        var escaped = false
        text.forEachIndexed { index, char ->
            if (index > 0 && index % 1024 == 0) checkpoint("scanning module plan after $index characters")
            if (quoted) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{', '[' -> { depth++; require(depth <= 4) { "module plan exceeds its nesting bound" } }
                '}', ']' -> { depth--; require(depth >= 0) }
            }
        }
        require(depth == 0 && !quoted)
        checkpoint("before parsing module plan JSON")
        val root = Json.parseToJsonElement(text).jsonObject
        checkpoint("after parsing module plan JSON")
        val version = root.getValue("schemaVersion").jsonPrimitive
        require(!version.isString && version.content == "2") { "unsupported module plan schema" }
        val plan = ModulePlan(modules = root.getValue("modules").jsonArray.map { element ->
            checkpoint("reading module plan module")
            val entry = element.jsonObject
            PlannedModule(entry.getValue("id").string(), entry.getValue("sourcePath").string(),
                entry.getValue("headerPath").string(), entry.getValue("functionIds").strings(checkpoint),
                entry.getValue("globalIds").strings(checkpoint), entry.getValue("typeIds").strings(checkpoint),
                entry.getValue("boundaryEvidence").strings(checkpoint))
        }, dependencyCycles = root.getValue("dependencyCycles").jsonArray.map {
            checkpoint("reading module plan cycle")
            it.strings(checkpoint)
        })
        checkpoint("before rendering canonical module plan")
        val canonical = plan.toJson().toByteArray(Charsets.UTF_8)
        checkpoint("after rendering canonical module plan")
        require(bytes.contentEquals(canonical)) {
            "module plan must use exact canonical fields, ordering, and bytes"
        }
        checkpoint("before returning module plan")
        return plan
    }

    fun requireExactOwnership(plan: ModulePlan, model: RecoveredProgramModel,
        layout: ProjectLayoutProfile, maximumFunctionsPerModule: Int) =
        requireExactOwnership(plan, model, layout, maximumFunctionsPerModule) {}

    internal fun requireExactOwnership(plan: ModulePlan, model: RecoveredProgramModel,
        layout: ProjectLayoutProfile, maximumFunctionsPerModule: Int, checkpoint: (String) -> Unit) {
        checkpoint("before module plan ownership")
        require(plan.schemaVersion == 2 && maximumFunctionsPerModule > 0)
        val moduleIds = hashSetOf<String>()
        val paths = hashSetOf<String>()
        val remainingFunctions = model.functions.mapTo(hashSetOf()) { checkpoint("indexing module plan function"); it.id }
        val remainingGlobals = model.globals.mapTo(hashSetOf()) { checkpoint("indexing module plan global"); it.id }
        val remainingTypes = model.types.mapTo(hashSetOf()) { checkpoint("indexing module plan type"); it.id }
        fun consume(ids: List<String>, remaining: MutableSet<String>, kind: String) {
            val stage = "consuming module plan $kind"
            ids.forEach { checkpoint(stage); require(remaining.remove(it)) { "module plan repeats or invents a $kind" } }
        }
        plan.modules.forEach { module ->
            checkpoint("checking module plan module ownership")
            require(moduleIds.add(module.id)) { "module plan repeats a module ID" }
            require(module.functionIds.size <= maximumFunctionsPerModule) { "module exceeds function bound" }
            require(module.sourcePath == layout.declaration("module-implementation").materialize(mapOf("module" to module.id)))
            require(module.headerPath == layout.declaration("module-interface").materialize(mapOf("module" to module.id)))
            require(paths.add(module.sourcePath) && paths.add(module.headerPath)) { "module plan aliases output paths" }
            consume(module.functionIds, remainingFunctions, "function")
            consume(module.globalIds, remainingGlobals, "global")
            consume(module.typeIds, remainingTypes, "type")
        }
        require(remainingFunctions.isEmpty() && remainingGlobals.isEmpty() && remainingTypes.isEmpty()) {
            "module plan omits recovered entities"
        }
        // Check cycle references, not their graph-theoretic correctness or completeness.
        val cycleMembers = hashSetOf<String>()
        plan.dependencyCycles.forEach { cycle ->
            checkpoint("checking module plan cycle")
            require(cycle.size > 1 && cycle == cycle.sorted())
            cycle.forEach { checkpoint("checking module plan cycle member"); require(it in moduleIds && cycleMembers.add(it)) { "invalid module cycle reference" } }
        }
        require(plan.dependencyCycles == plan.dependencyCycles.sortedBy { it.joinToString("\u0000") })
        checkpoint("after module plan ownership")
    }

    private fun JsonElement.string(): String = jsonPrimitive.let { require(it.isString); it.content }
    private fun JsonElement.strings(checkpoint: (String) -> Unit): List<String> = jsonArray.map {
        checkpoint("reading module plan string")
        it.string()
    }
}

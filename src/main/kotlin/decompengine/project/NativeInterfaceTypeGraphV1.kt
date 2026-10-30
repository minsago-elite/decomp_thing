package decompengine.project

import java.util.Collections
import kotlinx.serialization.json.*

/** Capture-local native object coordinates, never source identity or type equivalence. */
data class NativeInterfaceGraphScopeV1(val channel: String, val functionOrdinal: Int)
data class NativeInterfaceTypeNodeV1(
    val scope: NativeInterfaceGraphScopeV1, val id: Int, val nativeClass: String, val kind: String,
    val length: Int, val alignedLength: Int, val alignment: Int, val zeroLength: Boolean,
    val notYetDefined: Boolean, val undefined: Boolean, val expansion: String, val childCount: Int, val details: JsonObject,
) : NativeInferredInterfaceRecordV1
data class NativeInterfaceTypeEdgeV1(
    val scope: NativeInterfaceGraphScopeV1, val source: Int, val ordinal: Int, val relation: String,
    val target: Int?, val referenceState: String, val offset: Int?, val length: Int?, val fieldName: String?,
    val undefined: Boolean?, val bitField: Boolean?, val zeroBitField: Boolean?,
) : NativeInferredInterfaceRecordV1
data class NativeInterfaceTypeRootV1(
    val scope: NativeInterfaceGraphScopeV1, val role: String, val slot: Int,
    val listingTypeOrdinal: Int?, val node: Int?,
) : NativeInferredInterfaceRecordV1

/**
 * Validates the producer's bounded depth-first transcript. Each new object must be reached by the
 * next edge or root, backedges must target active ancestors, and reuse stays in its native scope.
 * A complete transcript describes observed relationships; partial/unsupported native types remain
 * partial/unsupported and never establish complete source-type closure.
 */
internal class NativeInterfaceTypeGraphValidatorV1(
    private val limits: NativeInferredInterfaceObservationLimitsV1,
    private val checkpoint: () -> Unit,
) {
    private data class Frame(val node: NativeInterfaceTypeNodeV1, var nextChild: Int = 0)
    private var scope: NativeInterfaceGraphScopeV1? = null
    private val nodes = arrayListOf<NativeInterfaceTypeNodeV1>()
    private val stack = arrayListOf<Frame>()
    private val targets = arrayListOf<MutableList<Int?>>()
    private val metadataHeights = arrayListOf<Int>()
    private val metadataActive = hashSetOf<Int>()
    private var validatedMetadataNodes = 0
    private var pendingChild: Int? = null
    private var pendingRoot: Int? = null
    var nodeCount = 0L; private set
    var edgeCount = 0L; private set
    var rootCount = 0L; private set

    fun scopeOf(node: JsonObject): NativeInterfaceGraphScopeV1 = NativeInterfaceGraphScopeV1(
        InferredWireV1.text(node, "channel").also { require(it in setOf("listing", "inferred")) },
        InferredWireV1.integer(node.getValue("functionOrdinal")).also { require(it in 0 until limits.maximumFunctions) },
    )

    private fun select(next: NativeInterfaceGraphScopeV1) {
        if (next == scope) return
        finish()
        scope?.let { previous ->
            require(next.channel != "listing" || previous.channel == "listing") { "listing graph cannot follow inferred graph" }
            require(next.channel != previous.channel || next.functionOrdinal > previous.functionOrdinal) { "graph scopes cannot repeat or move backwards" }
        }
        scope = next
        nodes.clear(); targets.clear(); metadataHeights.clear(); metadataActive.clear(); validatedMetadataNodes = 0
    }

    fun node(raw: JsonObject): NativeInterfaceTypeNodeV1 {
        checkpoint()
        InferredWireV1.fields(raw, "recordKind", "channel", "functionOrdinal", "id", "nativeClass", "kind", "length",
            "alignedLength", "alignment", "zeroLength", "notYetDefined", "undefined", "expansion", "childCount", "details")
        val selected = scopeOf(raw); select(selected)
        require(nodeCount < limits.maximumGraphNodes) { "native type graph node bound exceeded" }
        val id = InferredWireV1.integer(raw.getValue("id"))
        require(id == nodes.size) { "native graph node IDs must be dense within their scope" }
        if (pendingChild != null) {
            require(pendingChild == id) { "new-node edge must immediately precede its child" }
            pendingChild = null
        } else {
            require(stack.isEmpty() && pendingRoot == null) { "unreferenced or misplaced native graph node" }
            pendingRoot = id
        }
        require(stack.size <= limits.maximumGraphDepth) { "native graph depth exceeds its bound" }
        val result = NativeInterfaceTypeNodeV1(selected, id, InferredWireV1.text(raw, "nativeClass"), InferredWireV1.text(raw, "kind"),
            InferredWireV1.integer(raw.getValue("length")), InferredWireV1.integer(raw.getValue("alignedLength")),
            InferredWireV1.integer(raw.getValue("alignment")), InferredWireV1.boolean(raw.getValue("zeroLength")),
            InferredWireV1.boolean(raw.getValue("notYetDefined")), InferredWireV1.boolean(raw.getValue("undefined")), InferredWireV1.text(raw, "expansion"),
            InferredWireV1.integer(raw.getValue("childCount")), InferredWireV1.freeze(raw.getValue("details")).jsonObject)
        require(result.childCount in 0..limits.maximumGraphChildren) { "native graph child bound exceeded" }
        validateDetails(result)
        nodes += result
        targets += arrayListOf<Int?>()
        metadataHeights += -1
        nodeCount++
        stack += Frame(result)
        finishCompleted()
        return result
    }

    fun edge(raw: JsonObject): NativeInterfaceTypeEdgeV1 {
        checkpoint()
        InferredWireV1.fields(raw, "recordKind", "channel", "functionOrdinal", "source", "ordinal", "relation", "target", "referenceState",
            "offset", "length", "fieldName", "undefined", "bitField", "zeroBitField")
        val selected = scopeOf(raw)
        require(selected == scope && pendingChild == null && stack.isNotEmpty()) { "native graph edge has no active source" }
        require(edgeCount < limits.maximumGraphEdges) { "native type graph edge bound exceeded" }
        val result = NativeInterfaceTypeEdgeV1(selected, InferredWireV1.integer(raw.getValue("source")),
            InferredWireV1.integer(raw.getValue("ordinal")), InferredWireV1.text(raw, "relation"), InferredWireV1.nullableInteger(raw.getValue("target")),
            InferredWireV1.text(raw, "referenceState"), InferredWireV1.nullableInteger(raw.getValue("offset")),
            InferredWireV1.nullableInteger(raw.getValue("length")), InferredWireV1.nullableText(raw.getValue("fieldName")),
            InferredWireV1.nullableBoolean(raw.getValue("undefined")), InferredWireV1.nullableBoolean(raw.getValue("bitField")),
            InferredWireV1.nullableBoolean(raw.getValue("zeroBitField")))
        val parent = stack.last()
        require(result.source == parent.node.id && result.ordinal == parent.nextChild) { "native graph child order differs from its complete node census" }
        require(result.relation == relation(parent.node.kind)) { "native graph relationship differs from its typed source" }
        if (result.relation == "component") {
            require(result.offset != null && result.length != null && result.undefined != null && result.bitField != null && result.zeroBitField != null)
            require(result.offset >= 0 && result.length >= 0 && (!result.zeroBitField || result.bitField)) { "invalid native component metadata" }
        } else require(result.offset == null && result.length == null && result.fieldName == null && result.undefined == null && result.bitField == null && result.zeroBitField == null) {
            "only native composite relationships carry component metadata"
        }
        when (result.referenceState) {
            "missing" -> require(result.target == null)
            "new-node" -> {
                require(result.target == nodes.size && nodeCount < limits.maximumGraphNodes && stack.size <= limits.maximumGraphDepth)
                pendingChild = result.target
            }
            "backedge" -> require(result.target != null && stack.any { it.node.id == result.target }) { "native backedge must identify an active ancestor" }
            "reused-node" -> require(result.target != null && result.target in nodes.indices && stack.none { it.node.id == result.target }) { "native reused edge must identify a completed object" }
            else -> error("unsupported native graph reference state")
        }
        targets[result.source] += result.target
        parent.nextChild++
        edgeCount++
        if (pendingChild == null) finishCompleted()
        return result
    }

    fun root(raw: JsonObject): Pair<NativeInterfaceTypeRootV1, NativeInterfaceTypeNodeV1?> {
        checkpoint()
        InferredWireV1.fields(raw, "recordKind", "channel", "functionOrdinal", "role", "slot", "listingTypeOrdinal", "node")
        val selected = scopeOf(raw); select(selected)
        require(stack.isEmpty() && pendingChild == null) { "native graph root cannot hide an incomplete subtree" }
        require(rootCount < limits.maximumRoots) { "native graph root bound exceeded" }
        val result = NativeInterfaceTypeRootV1(selected, InferredWireV1.text(raw, "role"), InferredWireV1.integer(raw.getValue("slot")),
            InferredWireV1.nullableInteger(raw.getValue("listingTypeOrdinal")), InferredWireV1.nullableInteger(raw.getValue("node")))
        if (pendingRoot != null) require(result.node == pendingRoot) { "new native graph subtree must be owned by its next root" }
        require(result.node == null || result.node in nodes.indices) { "native graph root refers to an absent object" }
        for (id in validatedMetadataNodes until nodes.size) metadataHeight(id, 0)
        validatedMetadataNodes = nodes.size
        pendingRoot = null
        rootCount++
        return result to result.node?.let(nodes::get)
    }

    fun finish() {
        require(stack.isEmpty() && pendingChild == null && pendingRoot == null) { "native graph transcript omits a child or root" }
    }

    private fun metadataHeight(id: Int, depth: Int): Int {
        checkpoint()
        if (metadataHeights[id] >= 0) return metadataHeights[id]
        require(metadataActive.add(id)) { "native graph contains recursive by-value metadata dependencies" }
        require(depth <= limits.maximumGraphDepth) { "native metadata dependency depth exceeds its bound" }
        var height = 0
        val terminal = nodes[id].kind in setOf("pointer", "function-definition")
        if (!terminal) for (target in targets[id]) {
            checkpoint()
            if (target != null) {
                val childHeight = metadataHeight(target, depth + 1)
                require(childHeight < limits.maximumGraphDepth) { "native metadata dependency height exceeds its bound" }
                height = maxOf(height, childHeight + 1)
            }
        }
        metadataActive.remove(id)
        metadataHeights[id] = height
        return height
    }

    private fun finishCompleted() {
        while (stack.isNotEmpty() && stack.last().nextChild == stack.last().node.childCount) stack.removeAt(stack.lastIndex)
    }

    private fun validateDetails(node: NativeInterfaceTypeNodeV1) {
        val d = node.details
        fun fields(vararg names: String) = InferredWireV1.fields(d, *names)
        fun integer(name: String) = InferredWireV1.integer(d.getValue(name))
        var children = 0
        val expansion = when (node.kind) {
            "integer" -> { fields("signed"); InferredWireV1.boolean(d.getValue("signed")); "terminal" }
            "float", "void", "undefined" -> { fields(); "terminal" }
            "unsupported" -> { fields(); "unsupported" }
            "pointer" -> { fields("pointerSize"); require(integer("pointerSize") == node.length); children = 1; "expanded" }
            "array" -> {
                fields("elementCount", "elementLength", "extentState")
                val count = integer("elementCount"); val length = integer("elementLength")
                val expected = if (count < 0 || length < 0) "unknown" else if (count == 0) "zero-length"
                    else if (count.toLong() * length == node.length.toLong()) "consistent" else "inconsistent"
                require(InferredWireV1.text(d, "extentState") == expected)
                children = 1; "expanded"
            }
            "typedef" -> {
                fields("autoNamed", "settingsState"); InferredWireV1.boolean(d.getValue("autoNamed"))
                require(InferredWireV1.text(d, "settingsState") == "unavailable-bounded-count-api")
                children = 1; "partial"
            }
            "structure", "union" -> {
                fields("componentCount", "definedComponentCount", "packingType", "explicitPackingValue", "alignmentType", "explicitMinimumAlignment")
                children = integer("componentCount")
                require(children in 0..limits.maximumGraphChildren && integer("definedComponentCount") in 0..children)
                InferredWireV1.text(d, "packingType"); InferredWireV1.text(d, "alignmentType")
                integer("explicitPackingValue"); integer("explicitMinimumAlignment")
                "expanded"
            }
            "bitfield" -> {
                fields("storageSize", "declaredBitSize", "effectiveBitSize", "bitOffset", "baseTypeSize", "bigEndian")
                for (key in listOf("storageSize", "declaredBitSize", "effectiveBitSize", "bitOffset", "baseTypeSize")) require(integer(key) >= 0)
                InferredWireV1.boolean(d.getValue("bigEndian")); children = 1; "expanded"
            }
            "enum" -> {
                fields("enumeratorCount", "signedState", "enumeratorsState")
                require(integer("enumeratorCount") >= 0); InferredWireV1.text(d, "signedState")
                require(InferredWireV1.text(d, "enumeratorsState") == "not-captured"); "terminal"
            }
            "function-definition" -> {
                fields("convention", "varArgs", "noReturn", "argumentsState")
                InferredWireV1.nullableText(d.getValue("convention")); InferredWireV1.boolean(d.getValue("varArgs")); InferredWireV1.boolean(d.getValue("noReturn"))
                require(InferredWireV1.text(d, "argumentsState") == "unavailable-bounded-count-api")
                children = 1; "partial"
            }
            else -> error("unsupported native graph node kind")
        }
        require(node.childCount == children && node.expansion == expansion) { "native graph expansion differs from its typed relationships" }
    }

    private fun relation(kind: String) = when (kind) {
        "pointer" -> "pointer-target"
        "array" -> "array-element"
        "typedef" -> "typedef-target"
        "structure", "union" -> "component"
        "bitfield" -> "bitfield-base"
        "function-definition" -> "function-return"
        else -> error("terminal native graph node cannot have relationships")
    }
}

internal object InferredWireV1 {
    fun freeze(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(Collections.unmodifiableMap(value.mapValues { freeze(it.value) }))
        is JsonArray -> JsonArray(Collections.unmodifiableList(value.map(::freeze)))
        else -> value
    }
    fun objectValue(value: JsonElement) = value as? JsonObject ?: error("inferred observation value must be an object")
    fun array(value: JsonElement) = value as? JsonArray ?: error("inferred observation value must be an array")
    fun fields(node: JsonObject, vararg names: String) { require(node.keys == names.toSet()) { "inferred observation object has missing or extra fields" } }
    fun string(value: JsonElement): String {
        val p = value as? JsonPrimitive ?: error("inferred observation value must be a string")
        require(p.isString && p.content.toByteArray(Charsets.UTF_8).size <= 4096)
        return p.content
    }
    fun text(node: JsonObject, name: String) = string(node.getValue(name))
    fun nullableText(value: JsonElement) = if (value == JsonNull) null else string(value)
    fun number(value: JsonElement): Long {
        val p = value as? JsonPrimitive ?: error("inferred observation value must be an integer")
        require(!p.isString && p.content.matches(Regex("-?(?:0|[1-9][0-9]*)")))
        return p.content.toLong()
    }
    fun integer(value: JsonElement) = number(value).also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }.toInt()
    fun nullableInteger(value: JsonElement) = if (value == JsonNull) null else integer(value)
    fun count(node: JsonObject, name: String) = number(node.getValue(name)).also { require(it >= 0) }
    fun boolean(value: JsonElement): Boolean {
        val p = value as? JsonPrimitive ?: error("inferred observation value must be boolean")
        require(!p.isString)
        return p.booleanOrNull ?: error("inferred observation value must be boolean")
    }
    fun nullableBoolean(value: JsonElement) = if (value == JsonNull) null else boolean(value)
    fun digest(node: JsonObject, name: String) = text(node, name).also { require(it.matches(Regex("[0-9a-f]{64}"))) }
    fun <T> immutable(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
}

package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.NativeInferredInterfaceRecordV1
import decompengine.project.NativeInterfaceBindingsV1
import decompengine.project.NativeInterfaceTypeEdgeV1
import decompengine.project.NativeInterfaceTypeNodeV1
import decompengine.project.NativeInterfaceTypeRootV1
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull

/** Candidate classification of capture-local native roots; it is never a source type identity. */
internal object RecoveredAbiTypeGraphClassifierV1 {
    internal const val maximumNodes = 200_000
    internal const val maximumEdges = 1_000_000
    internal const val maximumRoots = 3_393_216
    internal const val maximumWork = 5_000_000
    private val SYSV_CLASSES = setOf("NO_CLASS", "INTEGER", "SSE", "SSEUP", "X87", "X87UP", "COMPLEX_X87", "MEMORY")

    data class ScopeKey(val channel: String, val functionOrdinal: Int)
    data class RootKey(val scope: ScopeKey, val role: String, val slot: Int)
    data class Result(
        val root: NativeInterfaceTypeRootV1,
        val nativeNode: NativeInterfaceTypeNodeV1?,
        val typeTokenSha256: String,
        val shape: DwarfAbiTypeShape?,
        val classification: DwarfAbiClassification?,
        val reason: String,
    ) {
        val known: Boolean get() = classification?.known == true
    }

    private data class Graph(
        val nodes: LinkedHashMap<Int, NativeInterfaceTypeNodeV1> = linkedMapOf(),
        val edges: LinkedHashMap<Int, MutableList<NativeInterfaceTypeEdgeV1>> = linkedMapOf(),
        val roots: MutableList<NativeInterfaceTypeRootV1> = arrayListOf(),
    )

    fun classify(
        records: Collection<NativeInferredInterfaceRecordV1>,
        target: StructuralTargetAbiV1,
        bindings: NativeInterfaceBindingsV1,
        dataOrganization: JsonObject,
        maximumRoots: Int,
        checkpoint: () -> Unit,
        workLimit: Int = maximumWork,
    ): Map<RootKey, Result> {
        require(workLimit in 1..maximumWork)
        require(maximumRoots in 1..RecoveredAbiTypeGraphClassifierV1.maximumRoots)
        val scopes = linkedMapOf<ScopeKey, Graph>()
        var nodes = 0
        var edges = 0
        var roots = 0
        var formalRoots = 0
        for (record in records) {
            checkpoint()
            val scope = when (record) {
                is NativeInterfaceTypeNodeV1 -> record.scope
                is NativeInterfaceTypeEdgeV1 -> record.scope
                is NativeInterfaceTypeRootV1 -> record.scope
                else -> continue
            }
            val key = ScopeKey(scope.channel, scope.functionOrdinal)
            val graph = scopes.getOrPut(key) { Graph() }
            when (record) {
                is NativeInterfaceTypeNodeV1 -> {
                    require(++nodes <= maximumNodes) { "recovered ABI type-node bound exceeded" }
                    require(graph.nodes.put(record.id, record) == null) { "duplicate recovered ABI type node" }
                }
                is NativeInterfaceTypeEdgeV1 -> {
                    require(++edges <= maximumEdges) { "recovered ABI type-edge bound exceeded" }
                    graph.edges.getOrPut(record.source) { arrayListOf() }.add(record)
                }
                is NativeInterfaceTypeRootV1 -> {
                    require(++roots <= maximumRoots) { "recovered ABI type-root candidate bound exceeded" }
                    // The inferred roots are retained in the raw candidate projection but are not
                    // joined to listing slots: the captured producer declares that relation unavailable.
                    if (record.scope.channel == "listing" && record.role in setOf("return-formal", "parameter-formal")) {
                        require(++formalRoots <= maximumRoots) { "recovered ABI formal-root candidate bound exceeded" }
                        graph.roots.add(record)
                    }
                }
            }
        }

        val targetReason = unsupportedTargetReason(target, bindings, dataOrganization)
        var work = 0
        fun chargeWork() {
            checkpoint()
            // Budget exhaustion must escape the per-root malformed-layout catch below.
            check(++work <= workLimit) { "recovered ABI aggregate work bound exceeded" }
        }
        val output = LinkedHashMap<RootKey, Result>(formalRoots)
        for ((scope, graph) in scopes) {
            checkpoint()
            require(graph.nodes.keys.sorted() == graph.nodes.keys.indices.toList()) {
                "native graph node identities are not dense within their exact scope"
            }
            graph.edges.values.forEach { rows -> rows.sortBy { it.ordinal } }
            validateGraph(scope, graph)
            val shapeCache = HashMap<Int, DwarfAbiTypeShape?>()
            val classCache = HashMap<Int, DwarfAbiClassification?>()
            val active = HashSet<Int>()

            fun shape(id: Int, depth: Int): DwarfAbiTypeShape {
                chargeWork()
                if (depth > 64) throw UnsupportedShape("type-depth-bound")
                if (shapeCache.containsKey(id)) return shapeCache[id] ?: throw UnsupportedShape("type-node-has-unsupported-shape")
                val node = graph.nodes[id] ?: throw UnsupportedShape("root-or-edge-target-is-absent")
                if (!active.add(id)) throw UnsupportedShape("recursive-by-value-type")
                val typeId = "native-${scope.channel}-${scope.functionOrdinal}-$id"
                val result = try {
                    require(node.length >= 0 && node.alignment > 0 && node.alignedLength >= node.length) {
                        "native type size or alignment is invalid"
                    }
                    if (node.undefined || node.notYetDefined) throw UnsupportedShape("undefined-or-incomplete-native-type")
                    val children = graph.edges[id].orEmpty()
                    when (node.kind) {
                        "integer" -> {
                            require(node.expansion == "terminal" && children.isEmpty())
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(), DwarfAbiScalarKind.INTEGER)
                        }
                        "enum" -> {
                            require(node.expansion == "terminal" && children.isEmpty())
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(), DwarfAbiScalarKind.INTEGER)
                        }
                        "void" -> {
                            require(node.length == 0 && node.expansion == "terminal" && children.isEmpty())
                            DwarfAbiTypeShape(typeId, 0, node.alignment.toLong(), DwarfAbiScalarKind.VOID)
                        }
                        "pointer" -> {
                            val detailSize = intDetail(node, "pointerSize")
                            require(node.expansion == "expanded" && node.childCount == 1 && children.size == 1 &&
                                detailSize == node.length && node.length == 8 && node.alignment == 8)
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(), DwarfAbiScalarKind.POINTER)
                        }
                        "float" -> {
                            require(node.expansion == "terminal" && children.isEmpty())
                            val scalar = when (node.nativeClass.substringAfterLast('.')) {
                                "FloatDataType" -> DwarfAbiScalarKind.FLOAT32.also { require(node.length == 4) }
                                "DoubleDataType" -> DwarfAbiScalarKind.FLOAT64.also { require(node.length == 8) }
                                else -> throw UnsupportedShape("floating-point-encoding-is-not-captured")
                            }
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(), scalar)
                        }
                        "array" -> {
                            require(node.expansion == "expanded" && node.childCount == 1 && children.size == 1)
                            val count = intDetail(node, "elementCount")
                            val extent = stringDetail(node, "extentState")
                            if (count < 0 || extent != "consistent") throw UnsupportedShape("array-extent-is-incomplete-or-inconsistent")
                            val edge = children.single()
                            if (edge.relation != "array-element" || edge.target == null || edge.referenceState == "missing") {
                                throw UnsupportedShape("array-element-type-is-absent")
                            }
                            val element = shape(edge.target, depth + 1)
                            if (count == 0 || Math.multiplyExact(element.byteSize, count.toLong()) != node.length.toLong()) {
                                throw UnsupportedShape("zero-length-or-inconsistent-array-layout")
                            }
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(),
                                arrayElement = element, arrayCount = count.toLong())
                        }
                        "typedef" -> {
                            require(node.expansion == "partial" && node.childCount == 1 && children.size == 1)
                            val edge = children.single()
                            if (edge.relation != "typedef-target" || edge.target == null || edge.referenceState == "missing") {
                                throw UnsupportedShape("typedef-target-is-absent")
                            }
                            val targetShape = shape(edge.target, depth + 1)
                            if (targetShape.byteSize != node.length.toLong() || targetShape.alignmentBytes != node.alignment.toLong()) {
                                throw UnsupportedShape("typedef-layout-differs-from-its-captured-target")
                            }
                            reidentify(typeId, targetShape)
                        }
                        "structure", "union" -> {
                            require(node.expansion == "expanded" && node.childCount == children.size &&
                                intDetail(node, "componentCount") == children.size)
                            if (children.size > 4_096) throw UnsupportedShape("aggregate-field-bound-exceeded")
                            if (intDetail(node, "definedComponentCount") != children.size) {
                                throw UnsupportedShape("aggregate-has-undefined-or-unrepresented-components")
                            }
                            val fields = children.map { edge ->
                                checkpoint()
                                if (edge.relation != "component" || edge.target == null || edge.referenceState == "missing" ||
                                    edge.offset == null || edge.length == null || edge.undefined != false ||
                                    edge.bitField == true || edge.zeroBitField == true) {
                                    throw UnsupportedShape("aggregate-component-layout-is-unsupported-or-incomplete")
                                }
                                val childNode = graph.nodes[edge.target] ?: throw UnsupportedShape("aggregate-member-type-is-absent")
                                if (edge.length != childNode.length) throw UnsupportedShape("aggregate-member-size-disagrees-with-typed-member")
                                DwarfAbiFieldShape(Math.multiplyExact(edge.offset.toLong(), 8L), shape(edge.target, depth + 1))
                            }
                            DwarfAbiTypeShape(typeId, node.length.toLong(), node.alignment.toLong(), fields = fields,
                                aggregate = true, union = node.kind == "union")
                        }
                        "bitfield" -> throw UnsupportedShape("bitfield-storage-and-bit-offset-relationship-is-not-proved")
                        "function-definition" -> throw UnsupportedShape("function-type-argument-population-is-not-captured")
                        else -> throw UnsupportedShape("native-type-kind-is-unsupported")
                    }
                } catch (unsupported: UnsupportedShape) {
                    shapeCache[id] = null
                    throw unsupported
                } finally {
                    active.remove(id)
                }
                shapeCache[id] = result
                return result
            }

            for (root in graph.roots) {
                checkpoint()
                val rootKey = RootKey(scope, root.role, root.slot)
                require(rootKey !in output) { "duplicate recovered ABI formal root candidate" }
                val token = sourceToken(root)
                if (targetReason != null) {
                    output[rootKey] = Result(root, root.node?.let(graph.nodes::get), token, null, null, targetReason)
                    continue
                }
                val rootNode = root.node
                if (rootNode == null) {
                    output[rootKey] = Result(root, null, token, null, null, "native-type-root-is-absent")
                    continue
                }
                try {
                    val candidate = shape(rootNode, 1)
                    val classification = classCache[rootNode]
                        ?: DwarfSysvAmd64Classification.classifyWithCheckpoint(candidate, checkpoint = ::chargeWork)
                            .also { classCache[rootNode] = it }
                    output[rootKey] = Result(root, graph.nodes[rootNode], token, candidate, classification,
                        if (classification.known) "complete-native-type-layout-classified-under-explicit-sysv-amd64-target"
                        else classification.reasons.joinToString(";"))
                } catch (unsupported: UnsupportedShape) {
                    output[rootKey] = Result(root, graph.nodes[rootNode], token, null, null, unsupported.message ?: "native-type-shape-is-unknown")
                } catch (_: IllegalArgumentException) {
                    output[rootKey] = Result(root, graph.nodes[rootNode], token, null, null, "native-type-layout-failed-closed-classifier-validation")
                }
            }
        }
        return output
    }

    private fun validateGraph(scope: ScopeKey, graph: Graph) {
        require(scope.channel in setOf("listing", "inferred") && scope.functionOrdinal in 0 until 131_072)
        for ((source, rows) in graph.edges) {
            val node = graph.nodes[source] ?: error("native type edge has no source node")
            require(rows.size == node.childCount && rows.map { it.ordinal } == rows.indices.toList()) {
                "native type edge census differs from its source node"
            }
            val expectedRelation = when (node.kind) {
                "pointer" -> "pointer-target"
                "array" -> "array-element"
                "typedef" -> "typedef-target"
                "structure", "union" -> "component"
                "bitfield" -> "bitfield-base"
                "function-definition" -> "function-return"
                else -> error("terminal native type has outgoing edges")
            }
            require(rows.all { it.relation == expectedRelation }) { "native type edge relation differs from its typed source" }
        }
        for ((_, node) in graph.nodes) {
            require(node.childCount == graph.edges[node.id].orEmpty().size) { "native type child census is incomplete" }
        }
        for (root in graph.roots) require(root.node == null || root.node in graph.nodes) { "native type root refers to an absent graph node" }
    }

    private fun unsupportedTargetReason(
        target: StructuralTargetAbiV1,
        bindings: NativeInterfaceBindingsV1,
        organization: JsonObject,
    ): String? {
        val targetObject = target.document["target"] as? JsonObject ?: return "target-abi-descriptor-is-incomplete"
        val supported = target.id == "sysv-amd64-elf-v1" && target.addressBits == 64 && target.objectFormat == "ELF" &&
            targetObject.string("architecture") == "x86_64" && targetObject.string("endianness") == "little" &&
            target.conventionAliases["sysv"] == "sysv-amd64" && target.conventionAliases["__cdecl"] == "sysv-amd64" &&
            target.abiClasses.containsAll(SYSV_CLASSES)
        if (!supported) return "target-abi-descriptor-is-not-the-supported-sysv-amd64-elf-profile"
        if (bindings.languageId != "x86:LE:64:default" || bindings.compilerSpecId != "gcc") {
            return "captured-language-or-compiler-is-not-the-supported-sysv-amd64-profile"
        }
        val dataModel = organization.boolean("bigEndian") == false && organization.int("pointerSize") == 8 &&
            organization.int("pointerShift") == 0 && organization.int("charSize") == 1 &&
            organization.int("shortSize") == 2 && organization.int("integerSize") == 4 &&
            organization.int("longSize") == 8 && organization.int("longLongSize") == 8 &&
            organization.int("floatSize") == 4 && organization.int("doubleSize") == 8
        return if (dataModel) null else "native-data-organization-is-not-the-supported-sysv-amd64-lp64-model"
    }

    private fun intDetail(node: NativeInterfaceTypeNodeV1, name: String): Int = node.details.int(name)
    private fun stringDetail(node: NativeInterfaceTypeNodeV1, name: String): String = node.details.string(name)
    private fun JsonObject.int(name: String): Int = (get(name) as? JsonPrimitive)?.intOrNull ?: -1
    private fun JsonObject.string(name: String): String = (get(name) as? JsonPrimitive)?.content ?: ""
    private fun JsonObject.boolean(name: String): Boolean? = (get(name) as? JsonPrimitive)?.booleanOrNull

    private fun sourceToken(root: NativeInterfaceTypeRootV1): String =
        OracleArtifacts.sha256("${root.scope.channel}\u0000${root.scope.functionOrdinal}\u0000${root.role}\u0000${root.slot}\u0000${root.listingTypeOrdinal}\u0000${root.node}"
            .toByteArray(Charsets.UTF_8))

    private fun reidentify(id: String, shape: DwarfAbiTypeShape) = DwarfAbiTypeShape(
        id, shape.byteSize, shape.alignmentBytes, shape.scalar,
        shape.fields.map { DwarfAbiFieldShape(it.offsetBits, it.type, it.bitSize, it.storageOffsetBits) },
        shape.arrayElement, shape.arrayCount, shape.aggregate, shape.union, shape.invisibleReference,
    )

    private class UnsupportedShape(message: String) : RuntimeException(message)
}

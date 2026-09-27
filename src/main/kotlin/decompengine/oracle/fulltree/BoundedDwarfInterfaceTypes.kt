package decompengine.oracle.fulltree

import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A raw, artifact-backed type declaration. Missing attributes imply no language or ABI defaults. */
internal class DwarfInterfaceTypeNode(
    val id: String,
    val tag: Long,
    val name: DwarfInterfaceFact<String>,
    val byteSize: DwarfInterfaceFact<String>,
    val encoding: DwarfInterfaceFact<String>,
    val type: DwarfInterfaceFact<String>,
    attributes: Map<Long, DwarfInterfaceFact<String>>,
    children: List<DwarfInterfaceTypeChild>,
    reasons: List<String>,
) {
    val attributes: Map<Long, DwarfInterfaceFact<String>> =
        Collections.unmodifiableMap(LinkedHashMap(attributes))
    val children: List<DwarfInterfaceTypeChild> = Collections.unmodifiableList(ArrayList(children))
    val reasons: List<String> = Collections.unmodifiableList(ArrayList(reasons))

    fun toJson(): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "tag" to JsonPrimitive(typeHex(tag)),
            "name" to name.toJson(::JsonPrimitive),
            "byteSize" to byteSize.toJson(::JsonPrimitive),
            "encoding" to encoding.toJson(::JsonPrimitive),
            "type" to type.toJson(::JsonPrimitive),
            "attributes" to typeAttributesJson(attributes),
            "children" to JsonArray(children.map { it.toJson() }),
            "reasons" to JsonArray(reasons.map(::JsonPrimitive)),
        ),
    )
}

/** One direct child, in physical declaration order; [type] is its raw DW_AT_type reference. */
internal class DwarfInterfaceTypeChild(
    val id: String,
    val tag: Long,
    val name: DwarfInterfaceFact<String>,
    val type: DwarfInterfaceFact<String>,
    attributes: Map<Long, DwarfInterfaceFact<String>>,
    reasons: List<String>,
) {
    val attributes: Map<Long, DwarfInterfaceFact<String>> =
        Collections.unmodifiableMap(LinkedHashMap(attributes))
    val reasons: List<String> = Collections.unmodifiableList(ArrayList(reasons))

    fun toJson(): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "tag" to JsonPrimitive(typeHex(tag)),
            "name" to name.toJson(::JsonPrimitive),
            "type" to type.toJson(::JsonPrimitive),
            "attributes" to typeAttributesJson(attributes),
            "reasons" to JsonArray(reasons.map(::JsonPrimitive)),
        ),
    )
}

/**
 * Resolves the retained DWARF graph without reading a recovered model or interpreting layouts.
 *
 * Pointer sizes, encodings, array bounds, and member offsets are known only when the corresponding
 * raw attribute is present in a supported constant/string/reference form. Expressions, vendor
 * attributes, supplementary references, and unsupported child semantics remain explicit unknowns.
 * Recursive types retain their graph edges and a cycle reason; no recursive type is flattened.
 */
internal class BoundedDwarfInterfaceTypeResolver(
    private val repository: FunctionDwarfUnitRepository,
    private val limits: BoundedDwarfInterfaceFactLimits,
    private val budget: DwarfInterfaceFactBudget,
) {
    private val completed = LinkedHashMap<String, DwarfInterfaceTypeNode>()
    private val scheduled = LinkedHashSet<String>()
    private val active = HashSet<String>()
    private val roots = LinkedHashSet<String>()
    private val edges = LinkedHashMap<String, List<String>>()

    fun resolve(source: ResolvedFunctionDie, attributeName: Long = TYPE_AT_TYPE): DwarfInterfaceFact<String> =
        referenceFact(source, attributeName, 0).also { fact -> roots += fact.values }

    /** Retain an automatic local's raw type reference without expanding a non-global graph. */
    fun referenceOnly(source: ResolvedFunctionDie): DwarfInterfaceFact<String> =
        referenceFact(source, TYPE_AT_TYPE, 0, expand = false).let {
            val reason = "type-graph-not-expanded-for-automatic-local"
            budget.charge(32L + reason.length.toLong() * 2L, "DWARF local type reason")
            DwarfInterfaceFact(it.state, it.values, it.evidence,
                it.reasons + reason)
        }

    fun nodes(): Map<String, DwarfInterfaceTypeNode> {
        validateGraphDepth()
        return Collections.unmodifiableMap(LinkedHashMap(completed.toSortedMap()))
    }

    /** Validate the completed graph once, independent of discovery order and cached cycle tails. */
    private fun validateGraphDepth() {
        data class DepthResult(val height: Int, val cyclic: Boolean, val minimumBackEdgeDepth: Int = Int.MAX_VALUE)
        var visits = 0L
        fun chargeVisit() {
            if (visits >= limits.maximumTypeTraversalSteps) {
                throw FullTreeControlException("DWARF interface type graph exceeds its traversal-work bound")
            }
            visits++
        }
        val componentBounds = componentDepthUpperBounds(::chargeVisit)
        val acyclicHeights = HashMap<String, Int>()
        val cyclicUpperBounds = HashMap<String, Int>()
        val path = HashMap<String, Int>()
        fun visit(id: String, depth: Int): DepthResult {
            chargeVisit()
            path[id]?.let { return DepthResult(0, true, it) }
            if (depth > limits.maximumTypeDepth) {
                throw FullTreeControlException("DWARF interface type graph exceeds its depth bound " +
                    "(observed=$depth, maximum=${limits.maximumTypeDepth}, type=$id)")
            }
            componentBounds[id]?.let { height ->
                // A simple path visits each condensation component at most once and each
                // member at most once. An excessive bound is inconclusive, never a failure.
                if (depth.toLong() + height - 1L <= limits.maximumTypeDepth) {
                    return DepthResult(height, true)
                }
            }
            acyclicHeights[id]?.let { height ->
                if (depth.toLong() + height - 1L > limits.maximumTypeDepth) {
                    throw FullTreeControlException("DWARF interface type graph exceeds its depth bound " +
                        "(observed=${depth.toLong() + height - 1L}, maximum=${limits.maximumTypeDepth}, type=$id)")
                }
                return DepthResult(height, false)
            }
            cyclicUpperBounds[id]?.let { height ->
                // A bound on every continuation can prove that this incoming path fits. It
                // cannot reject a path: its ancestors may shorten a cyclic continuation.
                if (depth.toLong() + height - 1L <= limits.maximumTypeDepth) {
                    return DepthResult(height, true)
                }
            }
            if (id !in completed) throw FullTreeControlException("DWARF interface graph has an unresolved local type edge")
            path[id] = depth
            var height = 1
            var cyclic = false
            var minimumBackEdgeDepth = Int.MAX_VALUE
            for (target in edges[id].orEmpty()) {
                val child = visit(target, depth + 1)
                height = maxOf(height, child.height + 1)
                cyclic = cyclic || child.cyclic
                minimumBackEdgeDepth = minOf(minimumBackEdgeDepth, child.minimumBackEdgeDepth)
            }
            path.remove(id)
            if (!cyclic) {
                acyclicHeights[id] = height
            } else if (minimumBackEdgeDepth >= depth) {
                // No unexamined continuation was cut by an ancestor above this node. A
                // reused cyclic bound also covers all continuations, so the resulting
                // height is a context-independent upper bound, even if it is not exact.
                cyclicUpperBounds[id] = minOf(cyclicUpperBounds[id] ?: height, height)
            }
            return DepthResult(height, cyclic, minimumBackEdgeDepth)
        }
        roots.forEach { visit(it, 1) }
    }

    /** Iterative Tarjan traversal emits components after every outgoing component is complete. */
    private fun componentDepthUpperBounds(chargeWork: () -> Unit): Map<String, Int> {
        data class Frame(val id: String, var nextEdge: Int = 0)
        val indices = HashMap<String, Int>()
        val lowLinks = HashMap<String, Int>()
        val active = HashSet<String>()
        val pending = ArrayDeque<String>()
        val traversal = ArrayDeque<Frame>()
        val bounds = HashMap<String, Int>()
        fun discover(id: String) {
            chargeWork()
            if (id !in completed) throw FullTreeControlException("DWARF interface graph has an unresolved local type edge")
            indices[id] = indices.size
            lowLinks[id] = indices.getValue(id)
            active += id
            pending.addLast(id)
            traversal.addLast(Frame(id))
        }
        for (root in roots) {
            if (root in indices) continue
            discover(root)
            while (traversal.isNotEmpty()) {
                val frame = traversal.last()
                val targets = edges[frame.id].orEmpty()
                if (frame.nextEdge < targets.size) {
                    chargeWork()
                    val target = targets[frame.nextEdge++]
                    if (target !in indices) {
                        discover(target)
                    } else if (target in active) {
                        lowLinks[frame.id] = minOf(lowLinks.getValue(frame.id), indices.getValue(target))
                    }
                    continue
                }
                traversal.removeLast()
                if (traversal.isNotEmpty()) {
                    val parent = traversal.last().id
                    lowLinks[parent] = minOf(lowLinks.getValue(parent), lowLinks.getValue(frame.id))
                }
                if (lowLinks.getValue(frame.id) != indices.getValue(frame.id)) continue
                val members = HashSet<String>()
                do {
                    chargeWork()
                    val member = pending.removeLast()
                    active.remove(member)
                    members += member
                } while (member != frame.id)
                var suffix = 0
                for (member in members) for (target in edges[member].orEmpty()) {
                    chargeWork()
                    if (target !in members) suffix = maxOf(suffix, bounds.getValue(target))
                }
                // The saturated value is an over-limit sentinel, never an acceptance proof.
                val height = minOf(limits.maximumTypeDepth.toLong() + 1L,
                    members.size.toLong() + suffix).toInt()
                members.forEach { bounds[it] = height }
            }
        }
        return bounds
    }

    private fun referenceFact(
        source: ResolvedFunctionDie,
        attributeName: Long,
        depth: Int,
        inheritance: InterfaceInheritance? = null,
        expand: Boolean = true,
        unexpandedReason: String? = null,
    ): DwarfInterfaceFact<String> {
        val targets = LinkedHashMap<String, ResolvedFunctionDie>()
        val resolved = attributeFact(source, attributeName, inheritance) { owner, attribute ->
            val evidence = attributeEvidence(owner, attributeName)
            when (val value = attribute.value) {
                is FullTreeDwarfReferenceValue -> {
                    // Invalid local offsets and targets that are not DIE boundaries are malformed DWARF.
                    val target = repository.resolveReference(owner.unit, attribute, evidence)
                    val id = dwarfInterfaceLocator(target)
                    targets[id] = target
                    val supported = target.record.tag in INTERFACE_TYPE_TAGS
                    fact(
                        if (supported) DwarfInterfaceFactState.KNOWN else DwarfInterfaceFactState.UNKNOWN,
                        listOf(id), listOf(evidence),
                        buildList {
                            if (id in active) add("type-reference-cycle:$id")
                            if (!supported) add("unsupported-type-tag:${typeHex(target.record.tag)}")
                            unexpandedReason?.let(::add)
                        },
                    )
                }
                is FullTreeDwarfUnsupportedReferenceValue -> fact(
                    DwarfInterfaceFactState.UNKNOWN,
                    emptyList(),
                    listOf(evidence),
                    listOfNotNull("unsupported-type-reference-form:${typeHex(value.resolvedForm)}:operand=${value.rawValue}",
                        unexpandedReason),
                )
                else -> throw FullTreeControlException("$evidence is not encoded as a DWARF type reference")
            }
        }
        // Complete inheritance before following type edges. Otherwise an origin chain at every
        // graph level multiplies the JVM stack depth by the inheritance-chain ceiling.
        if (expand) targets.forEach { (id, target) -> if (id !in active) materialize(target, depth + 1) }
        return resolved
    }

    private fun materialize(source: ResolvedFunctionDie, depth: Int) {
        if (depth > limits.maximumTypeDepth) {
            throw FullTreeControlException("DWARF interface type graph exceeds its depth bound")
        }
        val id = dwarfInterfaceLocator(source)
        if (id in completed) return
        if (id in active) return
        if (scheduled.size >= limits.maximumTypes) {
            throw FullTreeControlException("DWARF interface type graph exceeds its type-count bound")
        }
        scheduled += id
        budget.charge(512L + id.length.toLong() * 2L, "DWARF interface type node")
        active += id
        val inheritance = InterfaceInheritance(repository, source, limits.maximumReferenceChainEntries)
        val expandedEdges = LinkedHashSet<String>()
        val attributes = attributes(source, depth, inheritance,
            setOf(TYPE_AT_NAME, TYPE_AT_BYTE_SIZE, TYPE_AT_ENCODING, TYPE_AT_TYPE), expandedEdges)
        val children = directChildren(source).map { child ->
            val childId = dwarfInterfaceLocator(child)
            budget.charge(384L + childId.length.toLong() * 2L, "DWARF interface type child")
            val childInheritance = InterfaceInheritance(repository, child, limits.maximumReferenceChainEntries)
            val childAttributes = attributes(child, depth, childInheritance, setOf(TYPE_AT_NAME, TYPE_AT_TYPE),
                expandedEdges, nonLayoutChild = child.record.tag !in ABI_LAYOUT_TYPE_CHILD_TAGS)
            val childReasons = buildList {
                addAll(childInheritance.reasons)
                if (child.record.tag !in INTERFACE_TYPE_CHILD_TAGS) {
                    add("unsupported-type-child-tag:${typeHex(child.record.tag)}")
                }
                if (child.record.hasChildren) add("nested-type-child-children-unrepresented:$childId")
            }
            DwarfInterfaceTypeChild(
                childId,
                child.record.tag,
                childAttributes[TYPE_AT_NAME] ?: absent(),
                childAttributes[TYPE_AT_TYPE] ?: absent(),
                childAttributes,
                childReasons,
            )
        }
        val reasons = buildList {
            addAll(inheritance.reasons)
            inheritance.sources.drop(1).filter { it.record.hasChildren }.forEach {
                add("inherited-type-children-unrepresented:${dwarfInterfaceLocator(it)}")
            }
            if (source.record.tag !in INTERFACE_TYPE_TAGS) add("unsupported-type-tag:${typeHex(source.record.tag)}")
            addAll(attributes.values.flatMap { it.reasons }.filter { it.startsWith("type-reference-cycle:") })
        }
        completed[id] = DwarfInterfaceTypeNode(
            id,
            source.record.tag,
            attributes[TYPE_AT_NAME] ?: absent(),
            attributes[TYPE_AT_BYTE_SIZE] ?: absent(),
            attributes[TYPE_AT_ENCODING] ?: absent(),
            attributes[TYPE_AT_TYPE] ?: absent(),
            attributes,
            children,
            reasons,
        )
        // Deferred raw references remain deferred even if another root materializes their target.
        edges[id] = expandedEdges.toList()
        active -= id
    }

    private fun attributes(
        source: ResolvedFunctionDie,
        depth: Int,
        inheritance: InterfaceInheritance,
        mandatory: Set<Long>,
        expandedEdges: MutableSet<String>,
        nonLayoutChild: Boolean = false,
    ): Map<Long, DwarfInterfaceFact<String>> {
        val names = (inheritance.sources.flatMap { owner ->
            owner.record.attributes.map(FullTreeDwarfDieAttribute::name).filter {
                owner.record.offset == source.record.offset || it !in TYPE_NON_INHERITED_ATTRIBUTES
            }
        } + mandatory).distinct().sorted()
        val expandedReferenceNames = HashSet<Long>()
        return names.associateWith { name ->
            budget.charge(64L, "DWARF interface type attribute entry")
            when (name) {
                TYPE_AT_TYPE, TYPE_AT_CONTAINING_TYPE -> {
                    val reason = when {
                        limits.typeGraphScope != BoundedDwarfTypeGraphScope.ABI_LAYOUT -> null
                        nonLayoutChild -> "type-reference-not-expanded:abi-layout-non-layout-child"
                        name == TYPE_AT_TYPE && source.record.tag in ABI_LAYOUT_POINTER_TAGS ->
                            "type-reference-not-expanded:abi-layout-pointee"
                        else -> null
                    }
                    referenceFact(source, name, depth, inheritance, expand = reason == null,
                        unexpandedReason = reason).also { if (reason == null) expandedReferenceNames += name }
                }
                // Imports name declarations, including members and subprograms. Validate the
                // reference without interpreting its target as a type or adding a layout edge.
                TYPE_AT_IMPORT, TYPE_AT_ABSTRACT_ORIGIN, TYPE_AT_SPECIFICATION -> attributeFact(source, name, inheritance) { owner, attribute ->
                    declarationReferenceFact(owner, attribute)
                }
                TYPE_AT_NAME, TYPE_AT_LINKAGE_NAME -> attributeFact(source, name, inheritance) { owner, attribute ->
                    stringFact(owner, attribute)
                }
                in INTERFACE_TYPE_CONSTANT_ATTRIBUTES -> attributeFact(source, name, inheritance) { owner, attribute ->
                    constantFact(owner, attribute)
                }
                else -> attributeFact(source, name, inheritance) { owner, attribute ->
                    fact(
                        DwarfInterfaceFactState.UNKNOWN,
                        emptyList(),
                        listOf(attributeEvidence(owner, name)),
                        listOf("uninterpreted-type-attribute:${typeHex(name)}:form=${typeHex(attribute.declaredForm)}"),
                    )
                }
            }
        }.also { attributes ->
            // Preserve the established traversal order independently of attribute decode order.
            for (name in listOf(TYPE_AT_TYPE, TYPE_AT_CONTAINING_TYPE)) {
                if (name in expandedReferenceNames) expandedEdges += attributes.getValue(name).values
            }
        }
    }

    private fun attributeFact(
        source: ResolvedFunctionDie,
        name: Long,
        inheritance: InterfaceInheritance? = null,
        decode: (ResolvedFunctionDie, FullTreeDwarfDieAttribute) -> DwarfInterfaceFact<String>,
    ): DwarfInterfaceFact<String> {
        val resolved = if (name in TYPE_NON_INHERITED_ATTRIBUTES) {
            val own = source.record.optionalUniqueAttribute(name, "DWARF interface attribute ${typeHex(name)}")
            if (own == null) absent() else decode(source, own)
        } else {
            inheritedFact(
                inheritance ?: InterfaceInheritance(repository, source, limits.maximumReferenceChainEntries),
                name,
                decode,
            )
        }
        // The output retains this resolved fact once. Decoder results used while walking
        // inheritance are temporary; charging both them and the merged result charges the
        // same retained strings repeatedly, especially through converging origin branches.
        var bytes = 192L
        for (text in resolved.values + resolved.evidence + resolved.reasons) {
            bytes = Math.addExact(bytes, Math.addExact(32L, Math.multiplyExact(text.length.toLong(), 2L)))
        }
        budget.charge(bytes, "DWARF interface type fact")
        return resolved
    }

    private fun declarationReferenceFact(
        source: ResolvedFunctionDie,
        attribute: FullTreeDwarfDieAttribute,
    ): DwarfInterfaceFact<String> {
        val evidence = attributeEvidence(source, attribute.name)
        return when (val raw = attribute.value) {
            is FullTreeDwarfReferenceValue -> fact(
                DwarfInterfaceFactState.KNOWN,
                listOf(dwarfInterfaceLocator(repository.resolveReference(source.unit, attribute, evidence))),
                listOf(evidence),
                emptyList(),
            )
            is FullTreeDwarfUnsupportedReferenceValue -> fact(
                DwarfInterfaceFactState.UNKNOWN,
                emptyList(),
                listOf(evidence),
                listOf("unsupported-declaration-reference-form:${typeHex(raw.resolvedForm)}:operand=${raw.rawValue}"),
            )
            else -> throw FullTreeControlException("$evidence is not encoded as a DWARF declaration reference")
        }
    }

    private fun constantFact(
        source: ResolvedFunctionDie,
        attribute: FullTreeDwarfDieAttribute,
    ): DwarfInterfaceFact<String> {
        val evidence = attributeEvidence(source, attribute.name)
        fun unknown(reason: String) = fact(
            DwarfInterfaceFactState.UNKNOWN,
            emptyList(),
            listOf(evidence),
            listOf(reason),
        )
        val raw = attribute.value
        val resolvedForm = (raw as? FullTreeDwarfUnsignedFormValue)?.resolvedForm
            ?: (raw as? FullTreeDwarfConstantValue)?.resolvedForm ?: attribute.declaredForm
        if (attribute.name == 0x38L && source.unit.header.version <= 3 &&
            ((resolvedForm == FULL_TREE_DW_FORM_DATA4 && source.unit.header.offsetSize == 4) ||
                (resolvedForm == FULL_TREE_DW_FORM_DATA8 && source.unit.header.offsetSize == 8))
        ) {
            return unknown("ambiguous-legacy-member-location-constant-or-list-offset:${typeHex(resolvedForm)}")
        }
        val value = when (raw) {
            is FullTreeDwarfUnsignedConstantValue -> raw.rawValue.toString()
            is FullTreeDwarfSignedConstantValue -> raw.rawValue.toString()
            is FullTreeDwarfNumericValue -> if (attribute.declaredForm in TYPE_NUMERIC_CONSTANT_FORMS) {
                raw.value.toString()
            } else {
                // sec_offset and indirect numeric values lack constant class. In particular, a
                // member location-list offset must never become a member byte offset.
                return unknown("unsupported-type-constant-form:${typeHex(attribute.declaredForm)}")
            }
            else -> return unknown("unsupported-type-constant-form:${typeHex(attribute.declaredForm)}")
        }
        return fact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(evidence), emptyList())
    }

    private fun stringFact(
        source: ResolvedFunctionDie,
        attribute: FullTreeDwarfDieAttribute,
    ): DwarfInterfaceFact<String> {
        val evidence = attributeEvidence(source, attribute.name)
        if (attribute.value == FullTreeDwarfUnsupportedExternalStringValue) {
            return fact(
                DwarfInterfaceFactState.UNKNOWN,
                emptyList(),
                listOf(evidence),
                listOf("unsupported-supplementary-type-string"),
            )
        }
        val value = FullTreeDwarfForms.decodeString(
            attribute.value,
            source.unit.sections,
            source.unit.stringOffsetsBase,
            source.unit.header.offsetSize,
            source.unit.controlLimits,
            evidence,
            maximumCharacters = limits.maximumNameCharacters,
            allowEmpty = attribute.name == TYPE_AT_NAME,
        )
        return fact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(evidence), emptyList())
    }

    private fun directChildren(source: ResolvedFunctionDie): List<ResolvedFunctionDie> {
        val records = source.unit.directChildren(source.record)
        if (records.size > limits.maximumChildrenPerType) {
            throw FullTreeControlException("DWARF interface type exceeds its child-count bound")
        }
        return records.map { ResolvedFunctionDie(source.unit, it) }
    }

    private fun absent(): DwarfInterfaceFact<String> =
        fact(DwarfInterfaceFactState.ABSENT, emptyList(), emptyList(), emptyList())

    private fun fact(
        state: DwarfInterfaceFactState,
        values: List<String>,
        evidence: List<String>,
        reasons: List<String>,
    ): DwarfInterfaceFact<String> = DwarfInterfaceFact(state, values, evidence, reasons)
}

private fun attributeEvidence(source: ResolvedFunctionDie, name: Long): String =
    "${dwarfInterfaceLocator(source)}:attribute=${typeHex(name)}"

private fun typeHex(value: Long): String = "0x${value.toString(16)}"

private fun typeAttributesJson(attributes: Map<Long, DwarfInterfaceFact<String>>): JsonObject =
    JsonObject(attributes.toSortedMap().mapKeys { typeHex(it.key) }.mapValues { it.value.toJson(::JsonPrimitive) })

private const val TYPE_AT_NAME = 0x03L
private const val TYPE_AT_BYTE_SIZE = 0x0bL
private const val TYPE_AT_IMPORT = 0x18L
private const val TYPE_AT_CONTAINING_TYPE = 0x1dL
private const val TYPE_AT_ABSTRACT_ORIGIN = 0x31L
private const val TYPE_AT_ENCODING = 0x3eL
private const val TYPE_AT_SPECIFICATION = 0x47L
private const val TYPE_AT_TYPE = 0x49L
private const val TYPE_AT_LINKAGE_NAME = 0x6eL

internal val INTERFACE_TYPE_TAGS: Set<Long> = Collections.unmodifiableSet(
    setOf(
        0x01L, 0x02L, 0x04L, 0x0fL, 0x10L, 0x12L, 0x13L, 0x15L, 0x16L, 0x17L,
        0x1fL, 0x20L, 0x21L, 0x24L, 0x26L, 0x29L, 0x2dL, 0x35L, 0x37L, 0x38L,
        0x3bL, 0x40L, 0x42L, 0x44L, 0x45L, 0x46L, 0x47L, 0x4bL,
    ),
)

private val TYPE_NON_INHERITED_ATTRIBUTES = setOf(0x01L, 0x3cL) // sibling, declaration

private val TYPE_NUMERIC_CONSTANT_FORMS = setOf(
    FULL_TREE_DW_FORM_DATA1, FULL_TREE_DW_FORM_DATA2, FULL_TREE_DW_FORM_DATA4,
    FULL_TREE_DW_FORM_DATA8, FULL_TREE_DW_FORM_UDATA, FULL_TREE_DW_FORM_SDATA,
    FULL_TREE_DW_FORM_IMPLICIT_CONST, FULL_TREE_DW_FORM_FLAG, FULL_TREE_DW_FORM_FLAG_PRESENT,
)

private val INTERFACE_TYPE_CHILD_TAGS = setOf(0x05L, 0x0dL, 0x18L, 0x1cL, 0x21L, 0x28L)

private val ABI_LAYOUT_POINTER_TAGS = setOf(0x0fL, 0x10L, 0x42L)
private val ABI_LAYOUT_TYPE_CHILD_TAGS = setOf(0x05L, 0x0dL, 0x1cL, 0x21L)

/** Attribute-specific constant semantics; never interpret an arbitrary numeric form as a layout. */
internal val INTERFACE_TYPE_CONSTANT_ATTRIBUTES: Set<Long> = setOf(
    TYPE_AT_BYTE_SIZE,
    0x09L, // ordering
    0x0cL, // bit_offset (retained as raw legacy offset, not converted to data_bit_offset)
    0x0dL, // bit_size
    0x1cL, // const_value
    0x22L, // lower_bound
    0x2eL, // bit_stride
    0x2fL, // upper_bound
    0x32L, // accessibility
    0x33L, // address_class
    0x34L, // artificial
    0x36L, // calling_convention
    0x37L, // count
    0x38L, // data_member_location: only its constant form is interpreted
    0x3cL, // declaration
    TYPE_AT_ENCODING,
    0x4bL, // variable_parameter
    0x4cL, // virtuality
    0x51L, // byte_stride
    0x61L, // mutable
    0x65L, // endianity
    0x6bL, // data_bit_offset
    0x6cL, // const_expr
    0x6dL, // enum_class
    0x77L, // reference
    0x78L, // rvalue_reference
    0x88L, // alignment
)

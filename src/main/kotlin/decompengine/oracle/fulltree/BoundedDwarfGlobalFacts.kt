package decompengine.oracle.fulltree

import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Raw location metadata is independent of a successfully interpreted process address. */
internal data class DwarfGlobalLocation(
    val sourceLocator: String,
    val declaredForm: Long,
    val resolvedForm: Long?,
    val kind: String,
    val expressionHex: String?,
    val operand: String?,
) {
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "sourceLocator" to JsonPrimitive(sourceLocator), "declaredForm" to JsonPrimitive(canonicalHex(declaredForm)),
        "resolvedForm" to (resolvedForm?.let { JsonPrimitive(canonicalHex(it)) } ?: JsonNull),
        "kind" to JsonPrimitive(kind), "expressionHex" to (expressionHex?.let(::JsonPrimitive) ?: JsonNull),
        "operand" to (operand?.let(::JsonPrimitive) ?: JsonNull),
    ))
}

internal class DwarfGlobalScope(
    val locator: String,
    val tag: Long,
    val name: DwarfInterfaceFact<String>,
    val ownerLocator: String,
) {
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(locator), "tag" to JsonPrimitive(canonicalHex(tag)),
        "name" to name.toJson(::JsonPrimitive), "ownerLocator" to JsonPrimitive(ownerLocator),
    ))
}

/** Every physical variable DIE survives, including declarations and variables with unknown storage. */
internal class DwarfGlobalVariableFacts(
    val locator: String,
    val sourceName: DwarfInterfaceFact<String>,
    val linkageName: DwarfInterfaceFact<String>,
    val language: DwarfInterfaceFact<String>,
    val type: DwarfInterfaceFact<String>,
    val external: DwarfInterfaceFact<String>,
    val declaration: DwarfInterfaceFact<String>,
    val artificial: DwarfInterfaceFact<String>,
    val visibility: DwarfInterfaceFact<String>,
    val byteSize: DwarfInterfaceFact<String>,
    val alignment: DwarfInterfaceFact<String>,
    val constant: DwarfInterfaceFact<String>,
    val scope: DwarfInterfaceFact<String>,
    val location: DwarfInterfaceFact<DwarfGlobalLocation>,
    val address: DwarfInterfaceFact<String>,
    val rva: DwarfInterfaceFact<String>,
    val tlsOffset: DwarfInterfaceFact<String>,
    val storage: DwarfInterfaceFact<String>,
    scopes: List<DwarfGlobalScope>,
    origins: List<String>,
    reasons: List<String>,
) {
    val scopes: List<DwarfGlobalScope> = Collections.unmodifiableList(ArrayList(scopes))
    val origins: List<String> = Collections.unmodifiableList(ArrayList(origins))
    val reasons: List<String> = Collections.unmodifiableList(ArrayList(reasons))
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(locator), "sourceName" to sourceName.toJson(::JsonPrimitive),
        "linkageName" to linkageName.toJson(::JsonPrimitive), "language" to language.toJson(::JsonPrimitive),
        "type" to type.toJson(::JsonPrimitive), "external" to external.toJson(::JsonPrimitive),
        "declaration" to declaration.toJson(::JsonPrimitive), "artificial" to artificial.toJson(::JsonPrimitive),
        "visibility" to visibility.toJson(::JsonPrimitive), "byteSize" to byteSize.toJson(::JsonPrimitive),
        "alignment" to alignment.toJson(::JsonPrimitive), "constant" to constant.toJson(::JsonPrimitive),
        "scope" to scope.toJson(::JsonPrimitive), "location" to location.toJson { it.toJson() },
        "address" to address.toJson(::JsonPrimitive), "rva" to rva.toJson(::JsonPrimitive),
        "tlsOffset" to tlsOffset.toJson(::JsonPrimitive), "storage" to storage.toJson(::JsonPrimitive),
        "scopes" to JsonArray(scopes.map { it.toJson() }),
        "origins" to JsonArray(origins.map(::JsonPrimitive)), "reasons" to JsonArray(reasons.map(::JsonPrimitive)),
    ))
}

internal class BoundedDwarfGlobalFactReader(
    private val repository: FunctionDwarfUnitRepository,
    private val types: BoundedDwarfInterfaceTypeResolver,
    private val limits: BoundedDwarfInterfaceFactLimits,
    private val budget: DwarfInterfaceFactBudget,
    private val parseBudget: FullTreeDwarfParseBudget,
    private val layout: FullTreeElfObjectLayoutObservation,
) {
    fun read(source: ResolvedFunctionDie): DwarfGlobalVariableFacts {
        budget.charge(4096, "DWARF global candidate")
        val inheritance = InterfaceInheritance(repository, source, limits.maximumReferenceChainEntries)
        val (scope, scopes) = scopes(inheritance)
        val location = inheritedFact(inheritance, GLOBAL_LOCATION) { owner, attribute -> location(owner, attribute) }
        val address = address(location)
        val rva = if (address.state == DwarfInterfaceFactState.KNOWN) {
            val absolute = address.values.single().removePrefix("0x").toULong(16)
            if (absolute >= layout.imageBase) known(globalHex(absolute - layout.imageBase), address.evidence)
            else unknown(address.evidence, "static-address-below-image-base")
        } else DwarfInterfaceFact(address.state, emptyList(), address.evidence, address.reasons)
        val tls = if (location.state == DwarfInterfaceFactState.KNOWN && location.values.single().kind == "tls-offset") {
            known(checkNotNull(location.values.single().operand), location.evidence)
        } else if (location.state == DwarfInterfaceFactState.ABSENT) absent<String>(location.evidence)
        else unknown(location.evidence, "location-does-not-prove-tls-offset")
        val storage = storage(scope, location, address)
        val type = if (storage.state == DwarfInterfaceFactState.KNOWN && storage.values == listOf("automatic")) {
            types.referenceOnly(source)
        } else types.resolve(source)
        val linkage = string(inheritance, DW_AT_LINKAGE_NAME).let {
            if (it.state == DwarfInterfaceFactState.ABSENT) string(inheritance, DW_AT_MIPS_LINKAGE_NAME) else it
        }
        val language = interfaceIntegralFact(InterfaceInheritance(repository,
            ResolvedFunctionDie(source.unit, source.unit.index.root), limits.maximumReferenceChainEntries), GLOBAL_LANGUAGE, budget)
        return DwarfGlobalVariableFacts(dwarfInterfaceLocator(source), string(inheritance, DW_AT_NAME), linkage,
            language, type, interfaceIntegralFact(inheritance, GLOBAL_EXTERNAL, budget),
            interfaceIntegralFact(inheritance, DW_AT_DECLARATION, budget), interfaceIntegralFact(inheritance, GLOBAL_ARTIFICIAL, budget),
            interfaceIntegralFact(inheritance, GLOBAL_VISIBILITY, budget), interfaceIntegralFact(inheritance, GLOBAL_BYTE_SIZE, budget),
            interfaceIntegralFact(inheritance, GLOBAL_ALIGNMENT, budget), constant(inheritance), scope, location, address, rva,
            tls, storage, scopes, inheritance.sources.map(::dwarfInterfaceLocator), inheritance.reasons)
    }

    private fun scopes(inheritance: InterfaceInheritance): Pair<DwarfInterfaceFact<String>, List<DwarfGlobalScope>> {
        val all = ArrayList<DwarfGlobalScope>()
        val classifications = ArrayList<String>()
        val reasons = inheritance.reasons.toMutableList()
        for (owner in inheritance.sources) {
            var offset = owner.record.parentOffset
            var depth = 0
            var classification: String? = null
            var reachesUnit = false
            var unknownAncestor = false
            while (offset != null) {
                parseBudget.consume("DWARF global scope ancestry")
                if (depth++ >= limits.maximumScopeDepth) throw FullTreeControlException("DWARF global scope exceeds depth bound")
                val parent = owner.unit.index.find(offset)
                if (parent == null) { reasons += "scope-parent-unavailable"; break }
                val parentSource = ResolvedFunctionDie(owner.unit, parent)
                budget.charge(192, "DWARF global scope")
                all += DwarfGlobalScope(dwarfInterfaceLocator(parentSource), parent.tag,
                    string(InterfaceInheritance(repository, parentSource, limits.maximumReferenceChainEntries), DW_AT_NAME),
                    dwarfInterfaceLocator(owner))
                if (parent.tag !in setOf(0x0bL, DW_TAG_SUBPROGRAM, 0x1dL, 0x02L, 0x13L, 0x17L, 0x39L, 0x11L, 0x3cL, 0x41L)) {
                    unknownAncestor = true
                    reasons += "unsupported-scope-ancestor:${canonicalHex(parent.tag)}"
                }
                if (classification == null) classification = when (parent.tag) {
                    0x0bL -> "block"
                    DW_TAG_SUBPROGRAM, 0x1dL -> "function"
                    0x02L, 0x13L, 0x17L -> "class"
                    0x39L -> "namespace"
                    0x11L, 0x3cL, 0x41L -> "file"
                    else -> null
                }
                if (parent.offset == owner.unit.index.root.offset) reachesUnit = true
                offset = parent.parentOffset
            }
            if (!reachesUnit) reasons += "scope-does-not-reach-compilation-unit"
            if (!unknownAncestor) classification?.let(classifications::add)
        }
        // Out-of-line definitions physically at file scope inherit their declaration's class or
        // namespace context. Distinct non-file contexts are retained as ambiguous.
        val nonFile = classifications.filter { it != "file" }.distinct()
        val values = nonFile.ifEmpty { classifications.distinct() }
        val state = when {
            values.size > 1 -> DwarfInterfaceFactState.AMBIGUOUS
            reasons.isNotEmpty() || values.isEmpty() -> DwarfInterfaceFactState.UNKNOWN
            else -> DwarfInterfaceFactState.KNOWN
        }
        return DwarfInterfaceFact(state, values, all.map { it.locator }, reasons) to all
    }

    private fun location(source: ResolvedFunctionDie, attribute: FullTreeDwarfDieAttribute): DwarfInterfaceFact<DwarfGlobalLocation> {
        val evidence = "${dwarfInterfaceLocator(source)}:attribute=0x2"
        val raw = attribute.value
        val resolvedForm = (raw as? FullTreeDwarfUnsignedFormValue)?.resolvedForm
            ?: (raw as? FullTreeDwarfConstantValue)?.resolvedForm
            ?: (raw as? FullTreeDwarfExpressionValue)?.resolvedForm
            ?: attribute.declaredForm.takeUnless { it == FULL_TREE_DW_FORM_INDIRECT }
        fun rawFact(kind: String, expression: String? = null, operand: String? = null,
            known: Boolean = false, reason: String? = null): DwarfInterfaceFact<DwarfGlobalLocation> {
            return DwarfInterfaceFact(if (known) DwarfInterfaceFactState.KNOWN else DwarfInterfaceFactState.UNKNOWN,
                listOf(DwarfGlobalLocation(dwarfInterfaceLocator(source), attribute.declaredForm, resolvedForm,
                    kind, expression, operand)), listOf(evidence), listOfNotNull(reason))
        }
        when (raw) {
            is FullTreeDwarfExpressionValue -> return raw.inspect { bytes ->
                if (bytes.size > limits.maximumLocationExpressionBytes) throw FullTreeControlException("DWARF global location exceeds expression byte bound")
                budget.charge(256L + bytes.size.toLong() * 4L, "DWARF global location bytes")
                parseBudget.consume("DWARF global location atom")
                val hex = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
                val atom = FullTreeDwarfExpressions.locationAtomOrNull(bytes, source.unit.header.addressSize,
                    source.unit.sections.required(".debug_info").byteOrder)
                when (atom?.kind) {
                    "address-index" -> {
                        if (source.unit.header.version < 5 || source.unit.sections.optional(".debug_addr") == null ||
                            source.unit.index.root.optionalUniqueAttribute(DW_AT_ADDR_BASE, "DW_AT_addr_base") == null) {
                            rawFact("address-index", hex, atom.operand?.let(::globalHex), reason = "indexed-address-table-unavailable")
                        } else {
                            val address = source.unit.resolveAddress(FullTreeDwarfAddressIndexValue(FULL_TREE_DW_FORM_ADDRX,
                                checkNotNull(atom.operand), 0))
                            rawFact("address-index", hex, globalHex(address), known = true)
                        }
                    }
                    "gnu-address-index" -> rawFact("gnu-address-index", hex, atom.operand?.let(::globalHex), reason = "gnu-indexed-address-not-resolved")
                    null -> rawFact("expression-unsupported", hex, reason = "location-expression-not-a-supported-atom")
                    else -> rawFact(atom.kind, hex, atom.operand?.let(::globalHex), known = true)
                }
            }
            is FullTreeDwarfLocationListValue -> return rawFact("location-list", operand = globalHex(raw.rawValue),
                reason = if (raw.indexed) "indexed-location-list-unresolved" else "location-list-unresolved")
            is FullTreeDwarfUnsignedFormValue -> return rawFact("unsupported-form", operand = globalHex(raw.rawValue),
                reason = "location-form-does-not-prove-static-storage")
            is FullTreeDwarfNumericValue -> return rawFact("unsupported-form", operand = raw.value.toString(),
                reason = "location-form-does-not-prove-static-storage")
            is FullTreeDwarfSignedConstantValue -> return rawFact("unsupported-form", operand = raw.rawValue.toString(),
                reason = "location-form-does-not-prove-static-storage")
            else -> return rawFact("unsupported-form", reason = "unsupported-location-form")
        }
    }

    private fun address(location: DwarfInterfaceFact<DwarfGlobalLocation>): DwarfInterfaceFact<String> {
        if (location.state == DwarfInterfaceFactState.ABSENT) return absent(location.evidence)
        if (location.state != DwarfInterfaceFactState.KNOWN) return DwarfInterfaceFact(location.state,
            emptyList(), location.evidence, location.reasons)
        val atom = location.values.single()
        return if (atom.kind in setOf("address", "address-index")) known(checkNotNull(atom.operand), location.evidence)
        else unknown(location.evidence, "location-does-not-prove-static-address")
    }

    private fun storage(scope: DwarfInterfaceFact<String>, location: DwarfInterfaceFact<DwarfGlobalLocation>,
        address: DwarfInterfaceFact<String>): DwarfInterfaceFact<String> {
        if (location.state == DwarfInterfaceFactState.ABSENT) return unknown(location.evidence, "storage-location-absent")
        if (location.state != DwarfInterfaceFactState.KNOWN) return DwarfInterfaceFact(location.state,
            emptyList(), location.evidence, location.reasons)
        val atom = location.values.single()
        if (atom.kind == "tls-offset") return known("thread-local", location.evidence)
        if (address.state == DwarfInterfaceFactState.KNOWN) {
            val absolute = address.values.single().removePrefix("0x").toULong(16)
            return if (layout.loadedMemory.any { absolute >= it.virtualAddress && absolute < it.endExclusive }) {
                known("static-storage", location.evidence)
            } else unknown(location.evidence, "static-address-outside-loaded-memory")
        }
        if (scope.state == DwarfInterfaceFactState.KNOWN && scope.values.single() in setOf("function", "block") &&
            atom.kind in setOf("frame-relative", "register")) return known("automatic", location.evidence + scope.evidence)
        return unknown(location.evidence, "storage-duration-not-proven")
    }

    private fun constant(inheritance: InterfaceInheritance): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, DW_AT_CONST_VALUE) { source, attribute ->
            val evidence = "${dwarfInterfaceLocator(source)}:attribute=0x1c"
            val value = when (val raw = attribute.value) {
                is FullTreeDwarfUnsignedConstantValue -> "unsigned:${raw.rawValue}"
                is FullTreeDwarfSignedConstantValue -> "signed:${raw.rawValue}"
                is FullTreeDwarfExpressionValue -> raw.inspect { bytes ->
                    if (bytes.size > limits.maximumLocationExpressionBytes) throw FullTreeControlException("DWARF global constant exceeds byte bound")
                    "bytes:" + bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
                }
                is FullTreeDwarfInlineStringValue, is FullTreeDwarfSectionStringValue, is FullTreeDwarfIndexedStringValue ->
                    "utf8:" + FullTreeDwarfForms.decodeString(raw, source.unit.sections, source.unit.stringOffsetsBase,
                        source.unit.header.offsetSize, source.unit.controlLimits, evidence,
                        maximumCharacters = limits.maximumNameCharacters, allowEmpty = true)
                else -> null
            }
            if (value == null) unknown(listOf(evidence), "unsupported-global-constant-form")
            else known(value, listOf(evidence))
        }.also { budget.chargeStringFact(it, "DWARF global constant") }

    private fun string(inheritance: InterfaceInheritance, name: Long) = interfaceStringFact(inheritance, name, limits, budget)
}

private fun <T> absent(evidence: List<String>) = DwarfInterfaceFact<T>(DwarfInterfaceFactState.ABSENT, evidence = evidence)
private fun <T> known(value: T, evidence: List<String>) = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), evidence)
private fun <T> unknown(evidence: List<String>, reason: String) =
    DwarfInterfaceFact<T>(DwarfInterfaceFactState.UNKNOWN, evidence = evidence, reasons = listOf(reason))
private fun globalHex(value: ULong): String = "0x${value.toString(16)}"
internal const val GLOBAL_VARIABLE_TAG = 0x34L
internal const val GLOBAL_LOCATION = 0x02L
internal const val GLOBAL_LANGUAGE = 0x13L
internal const val GLOBAL_EXTERNAL = 0x3fL
private const val GLOBAL_ARTIFICIAL = 0x34L
private const val GLOBAL_VISIBILITY = 0x17L
private const val GLOBAL_BYTE_SIZE = 0x0bL
private const val GLOBAL_ALIGNMENT = 0x88L

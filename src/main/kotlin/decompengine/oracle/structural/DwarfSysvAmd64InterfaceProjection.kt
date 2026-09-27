package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.*
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.*

/** Neutral source-to-ABI evidence. These records are neither structural-v1 tokens nor scores. */
internal class DwarfProjectedType(
    val id: String, val rawTypeId: String?, val language: String,
    val shape: DwarfAbiTypeShape?, val classification: DwarfAbiClassification?,
    reasons: List<String>, evidence: List<String>,
) {
    val reasons: List<String> = Collections.unmodifiableList(reasons.distinct())
    val evidence: List<String> = Collections.unmodifiableList(evidence.distinct())
    val observable: Boolean get() = classification?.known == true
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id); put("rawTypeId", rawTypeId?.let(::JsonPrimitive) ?: JsonNull); put("language", language)
        put("state", if (observable) "known" else "unknown")
        put("shape", shape?.toJson() ?: JsonNull)
        put("classification", classification?.let { value -> buildJsonObject {
            put("known", value.known); put("classes", JsonArray(value.classes.map { JsonPrimitive(it.name) }))
            put("parameterPassing", value.parameterPassing.name); put("returnPassing", value.returnPassing.name)
            put("reasons", strings(value.reasons)); put("rules", strings(value.evidence))
        } } ?: JsonNull)
        put("reasons", strings(reasons)); put("evidence", strings(evidence))
    }
}

internal class DwarfProjectedFunction(
    val locator: String, val rva: ULong?, val language: String?, val callingConvention: String?,
    val arity: Int?, val variadic: Boolean?, val returnType: DwarfProjectedType?,
    parameters: List<DwarfProjectedType?>, val fullyObservable: Boolean,
    reasons: List<String>, evidence: List<String>,
) {
    val parameters: List<DwarfProjectedType?> = Collections.unmodifiableList(ArrayList(parameters))
    val reasons: List<String> = Collections.unmodifiableList(reasons.distinct())
    val evidence: List<String> = Collections.unmodifiableList(evidence.distinct())
    fun toJson(): JsonObject = buildJsonObject {
        put("locator", locator); put("rva", rva?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull)
        put("language", language?.let(::JsonPrimitive) ?: JsonNull)
        put("callingConvention", callingConvention?.let(::JsonPrimitive) ?: JsonNull)
        put("arity", arity?.let(::JsonPrimitive) ?: JsonNull); put("variadic", variadic?.let(::JsonPrimitive) ?: JsonNull)
        put("returnTypeId", returnType?.id?.let(::JsonPrimitive) ?: JsonNull)
        put("parameterTypeIds", JsonArray(parameters.map { it?.id?.let(::JsonPrimitive) ?: JsonNull }))
        put("fullyObservableAbi", fullyObservable); put("reasons", strings(reasons)); put("evidence", strings(evidence))
    }
}

internal class DwarfSysvAmd64Projection internal constructor(
    functions: List<DwarfProjectedFunction>, types: List<DwarfProjectedType>, val ruleProfile: JsonObject,
    globals: List<JsonObject> = emptyList(),
) {
    val globals: List<JsonObject> = Collections.unmodifiableList(ArrayList(globals))
    val functions = Collections.unmodifiableList(ArrayList(functions))
    val types = Collections.unmodifiableList(ArrayList(types))
    val ruleProfileSha256: String = projectionSha256(OracleJson.canonicalBytes(ruleProfile))
}

/**
 * Closed LP64 profile. Register allocation and recovery comparison are separate consumers.
 * Unsupported forms/layouts preserve unknown; absent defaults apply only to valid C/C++ evidence.
 */
internal object DwarfSysvAmd64InterfaceProjection {
    const val VERSION = "dwarf-sysv-amd64-lp64-projection-v1"
    private const val TARGET_SHA = "362e5b8fb1b068d932e35c7bf92d2206cceb9edb5b2991b66e3b12673f608c4b"
    private const val MAX_DEPTH = 64
    private const val MAX_TYPES = 200_000
    private const val MAX_VISITS = 5_000_000
    private const val MAX_SIZE = 1L shl 30
    private val cLanguages = setOf("1", "2", "12", "29")
    private val cppLanguages = setOf("4", "25", "26", "33")

    fun project(facts: BoundedDwarfInterfaceFacts, target: JsonObject): DwarfSysvAmd64Projection =
        project(facts.functions, facts.types, target, facts.globals)

    internal fun project(functions: List<DwarfInterfaceFunctionFacts>, types: Map<String, DwarfInterfaceTypeNode>,
                         target: JsonObject, globals: List<DwarfGlobalVariableFacts> = emptyList()): DwarfSysvAmd64Projection {
        require(projectionSha256(OracleJson.canonicalBytes(target)) == TARGET_SHA) {
            "DWARF ABI projection requires the complete closed SysV AMD64 ELF LP64 target"
        }
        require(functions.size <= 100_000 && types.size <= MAX_TYPES) { "DWARF projection population exceeds bounds" }
        require(functions.all { it.parameters.size <= 1024 }) { "DWARF parameter population exceeds bounds" }
        require(functions.map { it.locator }.distinct().size == functions.size) { "duplicate DWARF function identity" }
        val resolver = Resolver(types)
        val projected = functions.sortedWith(compareBy<DwarfInterfaceFunctionFacts> { it.absoluteAddress }.thenBy { it.locator })
            .map { resolver.function(it) }
        require(globals.size <= 100_000) { "global type projection population exceeds bounds" }
        val projectedGlobals = globals.sortedBy { it.locator }.map { resolver.globalType(it) }
        return DwarfSysvAmd64Projection(projected, resolver.completed.values.sortedBy { it.id }, ruleProfile(), projectedGlobals)
    }

    fun ruleProfile(): JsonObject = buildJsonObject {
        put("schema", VERSION); put("targetCanonicalSha256", TARGET_SHA)
        put("dataModel", "LP64-little-endian-8-bit-byte")
        put("dwarfSpecification", "https://dwarfstd.org/doc/DWARF5.pdf")
        put("abiSpecification", "https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex")
        put("subprogramDefaults", "valid-C-C++:absent-or-normal-CC=target;absent-return=void;absent-varargs-marker=false-only-with-prototype-and-unambiguous-list")
        put("cLanguages", strings(cLanguages.sorted())); put("cppLanguages", strings(cppLanguages.sorted()))
        put("scalarRules", "integer-encodings:1,2,5,6,7,8;integer-bytes:1,2,4,8,16;boolean=1;pointer-reference=8;float-bytes:2,4,8;16-byte-float-only-long-double-or-__float128-or-_Float128;complex=two-components")
        put("scalarAlignment", "natural-size;complex-component-alignment;explicit-alignment-must-equal-natural")
        put("aggregateRules", "complete-known-size-and-explicit-alignment;all-instance-members-proved;ordinary-C;C++-only-explicit-pass-by-value-or-reference;union-offset=0")
        put("arrayRules", "C-C++-row-major;constant-count-or-inclusive-bounds;absent-lower-bound=0;contiguous-stride;checked-size-product")
        put("bitfieldRules", "integer-storage;explicit-storage-offset-required-for-nonzero-width;data-bit-offset-or-little-endian-legacy-bit-offset;misaligned-storage-unknown")
        put("classMergeRules", "equal;NO_CLASS-neutral;MEMORY-dominates;INTEGER-dominates;x87-mixtures-memory;otherwise-SSE")
        put("postMergeRules", "any-MEMORY=MEMORY;orphan-X87UP=MEMORY;over-two-eightbytes-only-SSE-followed-by-SSEUP;orphan-SSEUP=SSE;aggregate-over64bytes-or-ordinary-unaligned-field=MEMORY")
        put("transportRules", "x87-arguments-memory;x87-returns-registers;explicit-nontrivial-C++-invisible-reference;no-whole-call-register-allocation")
        put("globalTypeRules", "same-language-type-closure;positive-automatic-locals-unexpanded;declared-type-observability-separate-from-storage-and-source-identity")
        put("unsupported", "unknown-language,nonstandard-convention,unprototyped-C,ambiguous-inheritance,unspecified-C++-class-call-semantics,unproved-alignment,expressions,vectors,vendor-types,cycles,oversized-layout")
        put("limits", buildJsonObject {
            put("maximumFunctions", 100_000); put("maximumGlobals", 100_000); put("maximumParameters", 1024)
            put("maximumDepth", MAX_DEPTH); put("maximumTypes", MAX_TYPES); put("maximumVisits", MAX_VISITS)
            put("maximumTypeBytes", MAX_SIZE); put("maximumNumericCharacters", 20); put("maximumDimensions", 16)
            put("maximumFields", 4096); put("maximumArrayElements", 1_000_000); put("maximumClassifierSteps", 100_000)
            put("maximumAlignmentBytes", 1 shl 20); put("maximumClassifierEvidenceEntries", 128)
        })
    }

    private class Unknown(message: String) : RuntimeException(message, null, false, false)
    private fun unknown(message: String): Nothing = throw Unknown(message)
    private class Resolver(private val raw: Map<String, DwarfInterfaceTypeNode>) {
        val completed = linkedMapOf<String, DwarfProjectedType>()
        private val active = hashSetOf<String>()
        private var visits = 0

        fun function(f: DwarfInterfaceFunctionFacts): DwarfProjectedFunction {
            val reasons = arrayListOf<String>(); val evidence = arrayListOf<String>()
            if (!absent(f.declaration) && single(f.declaration) != "0") reasons += "declaration-only-or-unresolved-definition"
            if (f.reasons.isNotEmpty()) reasons += f.reasons.map { "raw-function:$it" }
            val language = single(f.language)?.takeIf { it in cLanguages || it in cppLanguages }
            if (language == null) reasons += "unsupported-or-unresolved-language"
            val inheritance = f.reasons.isEmpty()
            val convention = if (inheritance && language != null &&
                (absent(f.callingConvention) || single(f.callingConvention) == "1")) {
                evidence += "DWARF5-3.3.1.1-standard-subprogram-convention"; "sysv-amd64"
            } else { reasons += "unresolved-or-nonstandard-calling-convention"; null }
            val prototype = language != null && inheritance && when {
                language in cppLanguages -> absent(f.prototyped) || single(f.prototyped) == "1"
                else -> single(f.prototyped) == "1"
            }
            val sequence = f.parameterList.state == DwarfInterfaceFactState.KNOWN && f.parameterList.values.size == 1 &&
                f.parameters.map { it.ordinal } == f.parameters.indices.toList() && f.parameters.size <= 1024
            val arity = if (prototype && sequence) f.parameters.size else null
            if (arity == null) reasons += "unproved-prototype-or-parameter-sequence"
            val variadic = if (arity != null) when {
                f.variadic.state == DwarfInterfaceFactState.KNOWN && f.variadic.values.size == 1 -> f.variadic.values.single()
                (f.variadic.state == DwarfInterfaceFactState.ABSENT && f.variadic.values.isEmpty() &&
                    f.variadic.reasons.all { it == "unspecified-parameter-marker-absent" }) -> { evidence += "DWARF5-3.3.4-prototyped-list-without-unspecified-parameters"; false }
                else -> null
            } else null
            if (variadic == null) reasons += "unresolved-variadic-state"
            val returned = if (language == null) null else when {
                absent(f.returnType) && inheritance -> {
                    evidence += "DWARF5-3.3.2-no-return-type-void"
                    completed.getOrPut("$language:void") {
                        val shape = DwarfAbiTypeShape("$language:void", 0, 1, DwarfAbiScalarKind.VOID)
                        DwarfProjectedType(shape.id, null, language, shape, DwarfSysvAmd64Classification.classify(shape),
                            emptyList(), listOf("DWARF5-3.3.2-no-return-type-void"))
                    }
                }
                else -> single(f.returnType)?.let { type(it, language, 1) }
            }
            val parameters = f.parameters.map { p -> language?.let { lang -> single(p.type)?.let { type(it, lang, 1) } } }
            if (returned?.observable != true) reasons += "unresolved-return-ABI"
            if (parameters.any { it?.observable != true || it.shape?.scalar == DwarfAbiScalarKind.VOID }) reasons += "unresolved-parameter-ABI"
            if (!f.executable || f.rva == null) reasons += "not-an-executable-physical-function"
            return DwarfProjectedFunction(f.locator, f.rva, language, convention, arity, variadic, returned, parameters,
                reasons.isEmpty(), reasons, evidence + f.parameterList.evidence + f.callingConvention.evidence + f.returnType.evidence)
        }

        fun globalType(global: DwarfGlobalVariableFacts): JsonObject {
            val language = single(global.language)?.takeIf { it in cLanguages || it in cppLanguages }
            val automatic = single(global.storage) == "automatic"
            val projected = if (language == null || automatic) null else single(global.type)?.let { type(it, language, 1) }
            return buildJsonObject {
                put("locator", global.locator)
                put("projectedTypeId", projected?.id?.let(::JsonPrimitive) ?: JsonNull)
                put("observableDeclaredTypeAbi", projected?.observable == true)
                put("reasons", strings(when {
                    automatic -> listOf("automatic-local-type-graph-deliberately-unexpanded")
                    language == null -> listOf("unsupported-or-unresolved-language")
                    projected == null -> listOf("unresolved-global-declared-type")
                    else -> projected.reasons
                }))
            }
        }

        private fun type(rawId: String, language: String, depth: Int): DwarfProjectedType {
            val id = "$language:$rawId"
            completed[id]?.let { return it }
            require(++visits <= MAX_VISITS && completed.size < MAX_TYPES) { "DWARF projection work bound exceeded" }
            if (depth > MAX_DEPTH || id in active) return DwarfProjectedType(id, rawId, language, null, null,
                listOf(if (depth > MAX_DEPTH) "type-depth-bound" else "by-value-type-cycle"), listOf(rawId))
            active += id
            val result = try {
                val node = raw[rawId] ?: unknown("missing-raw-type-node")
                if (node.reasons.any { !it.startsWith("type-reference-cycle") }) unknown("raw-type-has-unresolved-evidence:${node.reasons.first()}")
                val shape = shape(node, id, language, depth)
                val classification = DwarfSysvAmd64Classification.classify(shape)
                DwarfProjectedType(id, rawId, language, shape, classification, classification.reasons,
                    listOf(rawId) + node.byteSize.evidence + node.encoding.evidence + node.type.evidence)
            } catch (e: Unknown) {
                DwarfProjectedType(id, rawId, language, null, null, listOf(e.message!!), listOf(rawId))
            }
            active -= id; completed[id] = result; return result
        }

        private fun shape(n: DwarfInterfaceTypeNode, id: String, lang: String, depth: Int): DwarfAbiTypeShape {
            // These attributes change representation or ABI; absence alone is the supported profile.
            for (attribute in listOf(0x2107L, 0x33L, 0x65L, 0x6cL, 0x71L, 0x6dL, 0x5bL, 0x5cL)) {
                n.attributes[attribute]?.let { if (!absent(it)) unknown("unsupported-representation-attribute:$attribute") }
            }
            fun referred(): DwarfAbiTypeShape = single(n.type)?.let { type(it, lang, depth + 1).shape }
                ?: unknown("unresolved-referenced-type")
            fun scalar(kind: DwarfAbiScalarKind, bytes: Long, alignment: Long = bytes): DwarfAbiTypeShape {
                val explicit = n.attributes[0x88]
                if (explicit != null && !absent(explicit) && number(explicit) != alignment) unknown("non-natural-or-unknown-scalar-alignment")
                return DwarfAbiTypeShape(id, bytes, alignment, kind)
            }
            return when (n.tag) {
                0x16L, 0x26L, 0x35L, 0x37L, 0x47L -> {
                    val s = referred()
                    if (!absent(n.byteSize) && number(n.byteSize) != s.byteSize) unknown("alias-size-conflict")
                    n.attributes[0x88]?.let { if (!absent(it) && number(it) != s.alignmentBytes) unknown("alias-alignment-conflict") }
                    DwarfAbiTypeShape(id, s.byteSize, s.alignmentBytes, s.scalar, s.fields, s.arrayElement, s.arrayCount,
                        s.aggregate, s.union, s.invisibleReference)
                }
                0x0fL, 0x10L, 0x42L -> {
                    if (!absent(n.byteSize) && number(n.byteSize) != 8L) unknown("pointer-size-conflicts-with-LP64")
                    scalar(DwarfAbiScalarKind.POINTER, 8)
                }
                0x24L -> {
                    val size = number(n.byteSize); val encoding = number(n.encoding)
                    when (encoding) {
                        1L, 5L, 6L, 7L, 8L -> {
                            if (size !in setOf(1L, 2L, 4L, 8L, 16L) || encoding == 1L && size != 8L) unknown("unsupported-integer-width")
                            scalar(DwarfAbiScalarKind.INTEGER, size)
                        }
                        2L -> { if (size != 1L) unknown("unsupported-boolean-width"); scalar(DwarfAbiScalarKind.INTEGER, 1) }
                        4L -> scalar(floatKind(size, single(n.name)), size)
                        3L -> {
                            val component = size / 2
                            if (size % 2L != 0L) unknown("invalid-complex-size")
                            val kind = when (floatKind(component, single(n.name)?.removePrefix("complex ")?.removeSuffix(" _Complex"))) {
                                DwarfAbiScalarKind.FLOAT16 -> DwarfAbiScalarKind.COMPLEX_FLOAT16
                                DwarfAbiScalarKind.FLOAT32 -> DwarfAbiScalarKind.COMPLEX_FLOAT32
                                DwarfAbiScalarKind.FLOAT64 -> DwarfAbiScalarKind.COMPLEX_FLOAT64
                                DwarfAbiScalarKind.FLOAT128 -> DwarfAbiScalarKind.COMPLEX_FLOAT128
                                DwarfAbiScalarKind.X87 -> DwarfAbiScalarKind.COMPLEX_X87
                                else -> unknown("unsupported-complex-component")
                            }
                            scalar(kind, size, component)
                        }
                        else -> unknown("unsupported-base-encoding")
                    }
                }
                0x04L -> {
                    val underlying = referred()
                    if (underlying.scalar != DwarfAbiScalarKind.INTEGER || number(n.byteSize) != underlying.byteSize) unknown("unproved-enum-representation")
                    scalar(DwarfAbiScalarKind.INTEGER, underlying.byteSize, underlying.alignmentBytes)
                }
                0x01L -> array(n, id, lang, depth)
                0x02L, 0x13L, 0x17L -> aggregate(n, id, lang, depth)
                else -> unknown("unsupported-type-tag:${n.tag}")
            }
        }

        private fun array(n: DwarfInterfaceTypeNode, id: String, lang: String, depth: Int): DwarfAbiTypeShape {
            val element = single(n.type)?.let { type(it, lang, depth + 1).shape } ?: unknown("unknown-array-element")
            if (n.children.isEmpty() || n.children.size > 16 || n.children.any { it.tag != 0x21L || it.reasons.isNotEmpty() }) unknown("unsupported-array-dimensions")
            n.attributes[0x09]?.let { if (!absent(it) && number(it) != 0L) unknown("unsupported-array-order") }
            var count = 1L
            for (dimension in n.children) {
                val lower = dimension.attributes[0x22]?.let { if (absent(it)) 0L else number(it) } ?: 0L
                val upper = dimension.attributes[0x2f]?.takeUnless(::absent)?.let(::number)
                val explicit = dimension.attributes[0x37]?.takeUnless(::absent)?.let(::number)
                val fromBounds = upper?.let { if (it < lower) unknown("invalid-array-bounds") else it - lower + 1 }
                val size = explicit ?: fromBounds ?: unknown("unknown-array-count")
                if (explicit != null && fromBounds != null && explicit != fromBounds) unknown("conflicting-array-count")
                if (size > 1_000_000 || size != 0L && count > 1_000_000 / size) unknown("array-count-bound")
                if (dimension.attributes[0x2e]?.let { !absent(it) } == true || dimension.attributes[0x51]?.let { !absent(it) } == true) unknown("dimension-stride-unrepresented")
                count *= size
            }
            if (count != 0L && element.byteSize > MAX_SIZE / count) unknown("array-size-overflow")
            val bytes = element.byteSize * count
            if (!absent(n.byteSize) && number(n.byteSize) != bytes) unknown("array-size-conflict")
            n.attributes[0x51]?.let { if (!absent(it) && number(it) != element.byteSize) unknown("noncontiguous-array-stride") }
            n.attributes[0x2e]?.let { if (!absent(it) && number(it) != element.byteSize * 8) unknown("noncontiguous-array-bit-stride") }
            val alignment = n.attributes[0x88]?.let { if (absent(it)) element.alignmentBytes else number(it) } ?: element.alignmentBytes
            return DwarfAbiTypeShape(id, bytes, alignment, arrayElement = element, arrayCount = count)
        }

        private fun aggregate(n: DwarfInterfaceTypeNode, id: String, lang: String, depth: Int): DwarfAbiTypeShape {
            n.attributes[0x3c]?.let { if (!absent(it) && single(it) != "0") unknown("aggregate-declaration-only-or-unresolved") }
            val bytes = number(n.byteSize)
            val alignment = n.attributes[0x88]?.let(::number) ?: unknown("aggregate-alignment-not-explicit")
            val convention = n.attributes[0x36]
            val invisible = if (lang in cppLanguages) when (single(convention)) {
                "4" -> true; "5" -> false; else -> unknown("C++-aggregate-call-semantics-unspecified")
            } else {
                if (convention != null && !absent(convention) && single(convention) !in setOf("1", "5")) unknown("unsupported-C-aggregate-call-semantics")
                false
            }
            if (invisible) return DwarfAbiTypeShape(id, bytes, alignment, aggregate = true, union = n.tag == 0x17L, invisibleReference = true)
            if (n.children.size > 4096) unknown("aggregate-field-bound")
            val fields = arrayListOf<DwarfAbiFieldShape>()
            for (child in n.children) {
                if (child.tag !in setOf(0x0dL, 0x1cL)) {
                    if (child.tag in setOf(0x2eL, 0x02L, 0x13L, 0x17L, 0x16L, 0x04L, 0x2fL, 0x30L, 0x3aL)) continue
                    unknown("unsupported-aggregate-child:${child.tag}")
                }
                if (child.reasons.isNotEmpty()) unknown("member-has-unresolved-evidence")
                if (child.tag == 0x1cL) child.attributes[0x4c]?.let {
                    if (!absent(it) && single(it) != "0") unknown("virtual-or-unresolved-base-layout")
                }
                for (attribute in listOf(0x3cL, 0x3fL)) child.attributes[attribute]?.let {
                    if (!absent(it) && single(it) !in setOf("0", "1")) unknown("unresolved-member-storage-status")
                }
                val offset = child.attributes[0x38]?.takeUnless(::absent)?.let(::number)
                if (offset == null && (single(child.attributes[0x3f]) == "1" || single(child.attributes[0x3c]) == "1")) continue
                val member = single(child.type)?.let { type(it, lang, depth + 1).shape } ?: unknown("unknown-member-type")
                val bits = child.attributes[0x0d]?.takeUnless(::absent)?.let(::number)
                val dataBits = child.attributes[0x6b]?.takeUnless(::absent)?.let(::number)
                val legacyBits = child.attributes[0x0c]?.takeUnless(::absent)?.let(::number)
                val base = offset?.times(8) ?: if (n.tag == 0x17L) 0L else null
                if (n.tag == 0x17L && base != null && base != 0L) unknown("nonzero-union-member-offset")
                if (bits == null) {
                    if (dataBits != null || legacyBits != null) unknown("bit-offset-without-width")
                    fields += DwarfAbiFieldShape(base ?: unknown("missing-instance-member-offset"), member)
                } else {
                    if (member.scalar != DwarfAbiScalarKind.INTEGER) unknown("noninteger-bitfield")
                    child.attributes[0x0b]?.let {
                        if (!absent(it) && number(it) != member.byteSize) unknown("unsupported-bitfield-storage-width")
                    }
                    val legacyPosition = legacyBits?.let { (base ?: unknown("legacy-bitfield-without-storage")) + member.byteSize * 8 - it - bits }
                    if (dataBits != null && legacyPosition != null && dataBits != legacyPosition) unknown("conflicting-bitfield-offsets")
                    val position = dataBits ?: legacyPosition ?: if (bits == 0L) (base ?: 0L) else unknown("missing-bitfield-position")
                    fields += DwarfAbiFieldShape(position, member, bits, base)
                }
            }
            return DwarfAbiTypeShape(id, bytes, alignment, fields = fields, aggregate = true, union = n.tag == 0x17L)
        }
    }

    private fun floatKind(bytes: Long, name: String?): DwarfAbiScalarKind = when (bytes) {
        2L -> DwarfAbiScalarKind.FLOAT16; 4L -> DwarfAbiScalarKind.FLOAT32; 8L -> DwarfAbiScalarKind.FLOAT64
        16L -> when (name) {
            "long double" -> DwarfAbiScalarKind.X87
            "__float128", "_Float128" -> DwarfAbiScalarKind.FLOAT128
            else -> unknown("ambiguous-16-byte-floating-format")
        }
        else -> unknown("unsupported-floating-width")
    }
    private fun single(f: DwarfInterfaceFact<String>?): String? = f?.takeIf {
        it.state == DwarfInterfaceFactState.KNOWN && it.values.size == 1 && it.reasons.isEmpty()
    }?.values?.single()
    private fun absent(f: DwarfInterfaceFact<*>): Boolean = f.state == DwarfInterfaceFactState.ABSENT && f.values.isEmpty() && f.reasons.isEmpty()
    private fun number(f: DwarfInterfaceFact<String>): Long {
        val value = single(f) ?: unknown("unresolved-numeric-fact")
        if (value.length > 20 || !value.matches(Regex("0|[1-9][0-9]*"))) unknown("invalid-or-oversized-numeric-fact")
        return value.toLongOrNull()?.takeIf { it <= MAX_SIZE } ?: unknown("numeric-fact-out-of-range")
    }
}

private fun strings(values: Collection<String>): JsonArray = JsonArray(values.map(::JsonPrimitive))
private fun projectionSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { "%02x".format(it) }

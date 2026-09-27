package decompengine.oracle.structural

import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

enum class DwarfAbiScalarKind {
    INTEGER, POINTER, FLOAT16, FLOAT32, FLOAT64, FLOAT128, X87,
    COMPLEX_FLOAT16, COMPLEX_FLOAT32, COMPLEX_FLOAT64, COMPLEX_FLOAT128, COMPLEX_X87,
    VECTOR64, VECTOR128, VECTOR256, VECTOR512, VOID,
}

enum class DwarfAbiClass { NO_CLASS, INTEGER, SSE, SSEUP, X87, X87UP, COMPLEX_X87, MEMORY }

/**
 * REGISTERS means eligible before whole-call register allocation, which this classifier does not do.
 * INVISIBLE_REFERENCE means a pointer parameter, or caller-provided return storage with a hidden
 * pointer argument; it never means returning the object's value in an INTEGER register.
 */
enum class DwarfAbiPassing { REGISTERS, MEMORY, INVISIBLE_REFERENCE, NONE, UNKNOWN }

data class DwarfAbiFieldShape(
    val offsetBits: Long,
    val type: DwarfAbiTypeShape,
    val bitSize: Long? = null,
    val storageOffsetBits: Long? = null,
)

/**
 * A complete, proved object layout, independent of a DWARF parser or a compiler profile.
 *
 * Callers must establish sizes, alignment, complete membership and ordinary call semantics before
 * constructing this shape. In particular, false [invisibleReference] is not evidence that an
 * arbitrary C++ class is trivial. True explicitly selects non-trivial C++ call semantics; it is
 * never inferred from fields. Pointers are terminal shapes, not traversed pointee graphs.
 * Vector kinds require the caller to establish the corresponding vector ABI support.
 */
class DwarfAbiTypeShape(
    val id: String,
    val byteSize: Long,
    val alignmentBytes: Long,
    val scalar: DwarfAbiScalarKind? = null,
    fields: List<DwarfAbiFieldShape> = emptyList(),
    val arrayElement: DwarfAbiTypeShape? = null,
    val arrayCount: Long? = null,
    val aggregate: Boolean = false,
    val union: Boolean = false,
    val invisibleReference: Boolean = false,
) {
    val fields: List<DwarfAbiFieldShape> = Collections.unmodifiableList(ArrayList(fields))

    /** References are shallow: callers can retain each reachable shape once. */
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "id" to JsonPrimitive(id),
        "byteSize" to JsonPrimitive(byteSize),
        "alignmentBytes" to JsonPrimitive(alignmentBytes),
        "scalar" to (scalar?.let { JsonPrimitive(it.name) } ?: JsonNull),
        "aggregate" to JsonPrimitive(aggregate),
        "union" to JsonPrimitive(union),
        "invisibleReference" to JsonPrimitive(invisibleReference),
        "arrayElementId" to (arrayElement?.let { JsonPrimitive(it.id) } ?: JsonNull),
        "arrayCount" to (arrayCount?.let(::JsonPrimitive) ?: JsonNull),
        "fields" to JsonArray(fields.map { field -> JsonObject(linkedMapOf(
            "offsetBits" to JsonPrimitive(field.offsetBits),
            "bitSize" to (field.bitSize?.let(::JsonPrimitive) ?: JsonNull),
            "storageOffsetBits" to (field.storageOffsetBits?.let(::JsonPrimitive) ?: JsonNull),
            "typeId" to JsonPrimitive(field.type.id),
        )) }),
    ))
}

data class DwarfAbiClassificationLimits(
    val maximumDepth: Int = 64,
    val maximumTraversalSteps: Int = 100_000,
    val maximumFields: Int = 4_096,
    val maximumArrayElements: Long = 1_000_000,
    val maximumByteSize: Long = 1L shl 30,
    val maximumAlignmentBytes: Long = 1L shl 20,
    val maximumEvidenceEntries: Int = 128,
) {
    init {
        require(maximumDepth in 1..128)
        require(maximumTraversalSteps in 1..1_000_000)
        require(maximumFields in 1..100_000)
        require(maximumArrayElements in 0..1_000_000_000L)
        require(maximumByteSize in 0..(Long.MAX_VALUE / 8))
        require(maximumAlignmentBytes in 1..(1L shl 30))
        require(maximumEvidenceEntries in 1..4_096)
    }
}

class DwarfAbiClassification internal constructor(
    val known: Boolean,
    classes: List<DwarfAbiClass>,
    val parameterPassing: DwarfAbiPassing,
    val returnPassing: DwarfAbiPassing,
    reasons: List<String>,
    evidence: List<String>,
) {
    val classes: List<DwarfAbiClass> = Collections.unmodifiableList(ArrayList(classes))
    val reasons: List<String> = Collections.unmodifiableList(ArrayList(reasons))
    val evidence: List<String> = Collections.unmodifiableList(ArrayList(evidence))
}

/**
 * SysV AMD64 LP64 classification, without register allocation, name matching or scoring authority.
 * Rules: https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
 * (Classification, Passing and Returning of Values). Unsupported or incomplete layouts are UNKNOWN.
 */
object DwarfSysvAmd64Classification {
    fun classify(
        shape: DwarfAbiTypeShape,
        limits: DwarfAbiClassificationLimits = DwarfAbiClassificationLimits(),
    ): DwarfAbiClassification = Classifier(limits).classify(shape)

    private class Unsupported(reason: String) : RuntimeException(reason, null, false, false)

    private class Classifier(private val limits: DwarfAbiClassificationLimits) {
        private var steps = 0
        private val evidence = linkedSetOf("sysv-amd64-lp64")

        fun classify(shape: DwarfAbiTypeShape): DwarfAbiClassification = try {
            validate(shape, 1, shape.invisibleReference)
            if (shape.invisibleReference) {
                record("explicit-cxx-invisible-reference")
                result(listOf(DwarfAbiClass.INTEGER), DwarfAbiPassing.INVISIBLE_REFERENCE,
                    DwarfAbiPassing.INVISIBLE_REFERENCE)
            } else {
                val classes = if (shape.scalar == DwarfAbiScalarKind.COMPLEX_X87) {
                    listOf(DwarfAbiClass.COMPLEX_X87)
                } else {
                    classifyNode(shape, 0L, 1)
                }
                val noValue = classes.all { it == DwarfAbiClass.NO_CLASS }
                val memory = DwarfAbiClass.MEMORY in classes
                val x87 = classes.any { it in x87Classes }
                result(
                    classes,
                    when {
                        noValue -> DwarfAbiPassing.NONE
                        memory || x87 -> DwarfAbiPassing.MEMORY
                        else -> DwarfAbiPassing.REGISTERS
                    },
                    when {
                        noValue -> DwarfAbiPassing.NONE
                        memory -> DwarfAbiPassing.MEMORY
                        else -> DwarfAbiPassing.REGISTERS
                    },
                )
            }
        } catch (failure: Unsupported) {
            DwarfAbiClassification(false, emptyList(), DwarfAbiPassing.UNKNOWN,
                DwarfAbiPassing.UNKNOWN, listOf(failure.message!!), evidence.toList())
        }

        private fun result(
            classes: List<DwarfAbiClass>,
            parameter: DwarfAbiPassing,
            returned: DwarfAbiPassing,
        ) = DwarfAbiClassification(true, classes, parameter, returned, emptyList(), evidence.toList())

        private fun record(value: String) {
            if (evidence.size < limits.maximumEvidenceEntries) evidence += value
        }

        private fun visit(depth: Int) {
            if (depth > limits.maximumDepth) unsupported("type nesting exceeds depth limit")
            if (steps >= limits.maximumTraversalSteps) unsupported("type traversal exceeds work limit")
            steps++
        }

        private fun unsupported(reason: String): Nothing = throw Unsupported(reason)

        private fun validate(shape: DwarfAbiTypeShape, depth: Int, rootInvisible: Boolean) {
            visit(depth)
            if (shape.id.length > 256 || shape.id.isBlank()) unsupported("invalid or oversized type identifier")
            record("validated-${shape.scalar?.name ?: if (shape.arrayElement != null) "array" else "aggregate"}-shape")
            if (shape.byteSize < 0 || shape.byteSize > limits.maximumByteSize) {
                unsupported("type byte size exceeds supported bounds")
            }
            val alignment = shape.alignmentBytes
            if (alignment < 1 || alignment > limits.maximumAlignmentBytes || alignment and (alignment - 1) != 0L) {
                unsupported("type alignment is missing or unsupported")
            }
            val array = shape.arrayElement != null || shape.arrayCount != null
            val composite = shape.aggregate || shape.union
            if (listOf(shape.scalar != null, array, composite).count { it } != 1) {
                unsupported("type must have exactly one supported shape kind")
            }
            if (shape.fields.size > limits.maximumFields) unsupported("member count exceeds field limit")
            if (!composite && shape.fields.isNotEmpty()) unsupported("non-aggregate has members")
            if (shape.invisibleReference && (!composite || !rootInvisible)) {
                unsupported("invisible reference requires proved containing call semantics")
            }
            if (shape.scalar != null) {
                validateScalar(shape)
                return
            }
            if (array) {
                val element = shape.arrayElement ?: unsupported("array element is missing")
                val count = shape.arrayCount ?: unsupported("array count is missing")
                if (count < 0 || count > limits.maximumArrayElements) unsupported("array count exceeds dimension limit")
                validate(element, depth + 1, rootInvisible)
                if (element.scalar == DwarfAbiScalarKind.VOID) unsupported("void array element")
                if (count != 0L && element.byteSize > Long.MAX_VALUE / count) unsupported("array byte size overflows")
                if (element.byteSize * count != shape.byteSize) unsupported("array size does not match its elements")
                if (alignment < element.alignmentBytes) unsupported("array alignment is smaller than element alignment")
                return
            }
            val sizeBits = shape.byteSize * 8
            val occupied = ArrayList<Pair<Long, Long>>()
            shape.fields.forEach { field ->
                validate(field.type, depth + 1, rootInvisible)
                if (field.type.scalar == DwarfAbiScalarKind.VOID) unsupported("void aggregate member")
                if (field.offsetBits < 0 || field.offsetBits > sizeBits) unsupported("member offset is outside its object")
                if (shape.union && field.offsetBits != 0L) unsupported("union member has nonzero offset")
                val width = field.bitSize ?: (field.type.byteSize * 8)
                if (width < 0 || width > sizeBits - field.offsetBits) unsupported("member extent is outside its object")
                if (field.bitSize != null) {
                    if (field.type.scalar != DwarfAbiScalarKind.INTEGER || width > field.type.byteSize * 8) {
                        unsupported("unsupported bit-field type or width")
                    }
                    if (width != 0L) {
                        val storage = field.storageOffsetBits ?: unsupported("bit-field storage offset is unproved")
                        if (storage < 0 || storage > field.offsetBits || storage % 8 != 0L ||
                            field.offsetBits - storage > field.type.byteSize * 8 - width) {
                            unsupported("bit-field extent is outside its proved storage unit")
                        }
                        if (storage % (field.type.alignmentBytes * 8) != 0L) {
                            unsupported("misaligned bit-field storage semantics are unsupported")
                        }
                    }
                } else if (field.offsetBits % 8 != 0L) {
                    unsupported("ordinary member is not byte aligned")
                } else if (field.storageOffsetBits != null) {
                    unsupported("ordinary member has bit-field storage metadata")
                }
                if (!shape.union && width != 0L) occupied += field.offsetBits to (field.offsetBits + width)
            }
            var end = 0L
            occupied.sortBy { it.first }
            occupied.forEach { (start, nextEnd) ->
                if (start < end) unsupported("overlapping non-union members are unsupported")
                end = nextEnd
            }
        }

        private fun validateScalar(shape: DwarfAbiTypeShape): Long {
            val size = shape.byteSize
            val naturalAlignment = when (shape.scalar!!) {
                DwarfAbiScalarKind.INTEGER -> {
                    if (size !in listOf(1L, 2L, 4L, 8L, 16L)) unsupported("unsupported integer storage width")
                    size
                }
                DwarfAbiScalarKind.POINTER -> fixedSize(size, 8)
                DwarfAbiScalarKind.FLOAT16 -> fixedSize(size, 2)
                DwarfAbiScalarKind.FLOAT32 -> fixedSize(size, 4)
                DwarfAbiScalarKind.FLOAT64, DwarfAbiScalarKind.VECTOR64 -> fixedSize(size, 8)
                DwarfAbiScalarKind.FLOAT128, DwarfAbiScalarKind.X87,
                DwarfAbiScalarKind.VECTOR128 -> fixedSize(size, 16)
                DwarfAbiScalarKind.VECTOR256 -> fixedSize(size, 32)
                DwarfAbiScalarKind.VECTOR512 -> fixedSize(size, 64)
                DwarfAbiScalarKind.COMPLEX_FLOAT16 -> { fixedSize(size, 4); 2L }
                DwarfAbiScalarKind.COMPLEX_FLOAT32 -> { fixedSize(size, 8); 4L }
                DwarfAbiScalarKind.COMPLEX_FLOAT64 -> { fixedSize(size, 16); 8L }
                DwarfAbiScalarKind.COMPLEX_FLOAT128, DwarfAbiScalarKind.COMPLEX_X87 -> {
                    fixedSize(size, 32); 16L
                }
                DwarfAbiScalarKind.VOID -> { fixedSize(size, 0); 1L }
            }
            if (shape.alignmentBytes < naturalAlignment) unsupported("scalar alignment is below its supported ABI alignment")
            return naturalAlignment
        }

        private fun fixedSize(actual: Long, expected: Long): Long {
            if (actual != expected) unsupported("scalar storage width does not match its explicit kind")
            return expected
        }

        /** Prefix padding represents the start's offset in its parent's eightbyte, not a field. */
        private fun classifyNode(shape: DwarfAbiTypeShape, absoluteStartBits: Long, depth: Int): List<DwarfAbiClass> {
            visit(depth)
            if (shape.byteSize > 64) return memory("object-exceeds-eight-eightbytes")
            if (shape.byteSize == 0L) return emptyList()
            val startBits = (absoluteStartBits % 64).toInt()
            val classes = MutableList(((startBits + shape.byteSize * 8 + 63) / 64).toInt()) { DwarfAbiClass.NO_CLASS }
            val scalar = shape.scalar
            if (scalar != null) {
                scalarClasses(shape, startBits, classes)
                return if (scalar == DwarfAbiScalarKind.COMPLEX_FLOAT128) cleanup(classes) else classes
            }
            if (shape.arrayElement != null) {
                val element = shape.arrayElement
                if (element.byteSize != 0L) {
                    var index = 0L
                    while (index < shape.arrayCount!!) {
                        val offset = startBits + index * element.byteSize * 8
                        val absoluteOffset = absoluteStartBits + index * element.byteSize * 8
                        if (!mergeMember(classes, element, offset, absoluteOffset, depth)) return memory("array-element-requires-memory")
                        index++
                    }
                }
            } else {
                for (field in shape.fields) {
                    visit(depth)
                    val offset = startBits + field.offsetBits
                    if (field.bitSize != null) {
                        if (field.bitSize != 0L &&
                            (absoluteStartBits + field.storageOffsetBits!!) % (field.type.alignmentBytes * 8) != 0L) {
                            unsupported("misaligned bit-field storage semantics are unsupported")
                        }
                        contribute(classes, offset, field.bitSize, DwarfAbiClass.INTEGER)
                    } else if (!mergeMember(classes, field.type, offset, absoluteStartBits + field.offsetBits, depth)) {
                        return memory("aggregate-member-requires-memory")
                    }
                }
            }
            return cleanup(classes)
        }

        private fun mergeMember(
            classes: MutableList<DwarfAbiClass>,
            type: DwarfAbiTypeShape,
            offsetBits: Long,
            absoluteOffsetBits: Long,
            depth: Int,
        ): Boolean {
            if (type.byteSize == 0L) return true
            // Extra user alignment does not change the leaves' ABI classes. Aggregate alignment
            // is checked through its scalar members, preserving packed, over-aligned subobjects.
            if (type.scalar != null && absoluteOffsetBits % (validateScalar(type) * 8) != 0L) {
                record("unaligned-aggregate-member")
                return false
            }
            val member = classifyNode(type, absoluteOffsetBits, depth + 1)
            if (DwarfAbiClass.MEMORY in member) return false
            val first = (offsetBits / 64).toInt()
            member.forEachIndexed { index, value -> classes[first + index] = merge(classes[first + index], value) }
            return true
        }

        private fun scalarClasses(
            shape: DwarfAbiTypeShape,
            start: Int,
            classes: MutableList<DwarfAbiClass>,
        ) {
            val offset = start.toLong()
            val bits = shape.byteSize * 8
            when (shape.scalar!!) {
                DwarfAbiScalarKind.INTEGER, DwarfAbiScalarKind.POINTER ->
                    contribute(classes, offset, bits, DwarfAbiClass.INTEGER)
                DwarfAbiScalarKind.FLOAT16, DwarfAbiScalarKind.FLOAT32, DwarfAbiScalarKind.FLOAT64,
                DwarfAbiScalarKind.COMPLEX_FLOAT16, DwarfAbiScalarKind.COMPLEX_FLOAT32,
                DwarfAbiScalarKind.COMPLEX_FLOAT64, DwarfAbiScalarKind.VECTOR64 ->
                    contribute(classes, offset, bits, DwarfAbiClass.SSE)
                DwarfAbiScalarKind.FLOAT128, DwarfAbiScalarKind.VECTOR128,
                DwarfAbiScalarKind.VECTOR256, DwarfAbiScalarKind.VECTOR512 -> {
                    contribute(classes, offset, 64, DwarfAbiClass.SSE)
                    contribute(classes, offset + 64, bits - 64, DwarfAbiClass.SSEUP)
                }
                DwarfAbiScalarKind.X87 -> {
                    contribute(classes, offset, 64, DwarfAbiClass.X87)
                    contribute(classes, offset + 64, 64, DwarfAbiClass.X87UP)
                }
                DwarfAbiScalarKind.COMPLEX_FLOAT128 -> {
                    contribute(classes, offset, 64, DwarfAbiClass.SSE)
                    contribute(classes, offset + 64, 64, DwarfAbiClass.SSEUP)
                    contribute(classes, offset + 128, 64, DwarfAbiClass.SSE)
                    contribute(classes, offset + 192, 64, DwarfAbiClass.SSEUP)
                }
                DwarfAbiScalarKind.COMPLEX_X87 -> contribute(classes, offset, bits, DwarfAbiClass.COMPLEX_X87)
                DwarfAbiScalarKind.VOID -> Unit
            }
        }

        private fun contribute(classes: MutableList<DwarfAbiClass>, offset: Long, width: Long, value: DwarfAbiClass) {
            if (width == 0L) return
            for (index in (offset / 64).toInt()..((offset + width - 1) / 64).toInt()) {
                classes[index] = merge(classes[index], value)
            }
        }

        private fun merge(left: DwarfAbiClass, right: DwarfAbiClass): DwarfAbiClass = when {
            left == right -> left
            left == DwarfAbiClass.NO_CLASS -> right
            right == DwarfAbiClass.NO_CLASS -> left
            left == DwarfAbiClass.MEMORY || right == DwarfAbiClass.MEMORY -> DwarfAbiClass.MEMORY
            left == DwarfAbiClass.INTEGER || right == DwarfAbiClass.INTEGER -> DwarfAbiClass.INTEGER
            left in x87Classes || right in x87Classes -> DwarfAbiClass.MEMORY
            else -> DwarfAbiClass.SSE
        }

        private fun cleanup(classes: MutableList<DwarfAbiClass>): List<DwarfAbiClass> {
            if (DwarfAbiClass.MEMORY in classes) return memory("merged-memory-class")
            classes.forEachIndexed { index, value ->
                if (value == DwarfAbiClass.X87UP && (index == 0 || classes[index - 1] != DwarfAbiClass.X87)) {
                    return memory("orphan-x87up-class")
                }
            }
            if (classes.size > 2 && (classes.first() != DwarfAbiClass.SSE || classes.drop(1).any { it != DwarfAbiClass.SSEUP })) {
                return memory("aggregate-exceeds-two-eightbytes-without-vector-classes")
            }
            classes.forEachIndexed { index, value ->
                if (value == DwarfAbiClass.SSEUP && (index == 0 || classes[index - 1] !in sseClasses)) {
                    classes[index] = DwarfAbiClass.SSE
                }
            }
            return classes
        }

        private fun memory(reason: String): List<DwarfAbiClass> {
            record(reason)
            return listOf(DwarfAbiClass.MEMORY)
        }
    }

    private val x87Classes = setOf(DwarfAbiClass.X87, DwarfAbiClass.X87UP, DwarfAbiClass.COMPLEX_X87)
    private val sseClasses = setOf(DwarfAbiClass.SSE, DwarfAbiClass.SSEUP)
}

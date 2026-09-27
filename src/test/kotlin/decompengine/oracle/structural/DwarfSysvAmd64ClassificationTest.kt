package decompengine.oracle.structural

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DwarfSysvAmd64ClassificationTest {
    @Test
    fun `explicit scalar kinds have distinct classes and x87 passing directions`() {
        val cases = listOf(
            Triple(DwarfAbiScalarKind.INTEGER, 1L, listOf(DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.INTEGER, 2L, listOf(DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.INTEGER, 4L, listOf(DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.INTEGER, 8L, listOf(DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.INTEGER, 16L, listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.POINTER, 8L, listOf(DwarfAbiClass.INTEGER)),
            Triple(DwarfAbiScalarKind.FLOAT16, 2L, listOf(DwarfAbiClass.SSE)),
            Triple(DwarfAbiScalarKind.FLOAT32, 4L, listOf(DwarfAbiClass.SSE)),
            Triple(DwarfAbiScalarKind.FLOAT64, 8L, listOf(DwarfAbiClass.SSE)),
            Triple(DwarfAbiScalarKind.FLOAT128, 16L, listOf(DwarfAbiClass.SSE, DwarfAbiClass.SSEUP)),
        )
        cases.forEach { (kind, bytes, expected) ->
            val actual = classify(scalar(kind, bytes))
            assertTrue(actual.known, "$kind: ${actual.reasons}")
            assertEquals(expected, actual.classes, "$kind/$bytes")
            assertEquals(DwarfAbiPassing.REGISTERS, actual.parameterPassing)
            assertEquals(DwarfAbiPassing.REGISTERS, actual.returnPassing)
        }
        val x87 = classify(scalar(DwarfAbiScalarKind.X87, 16))
        assertEquals(listOf(DwarfAbiClass.X87, DwarfAbiClass.X87UP), x87.classes)
        assertEquals(DwarfAbiPassing.MEMORY, x87.parameterPassing)
        assertEquals(DwarfAbiPassing.REGISTERS, x87.returnPassing)
        val void = classify(scalar(DwarfAbiScalarKind.VOID, 0, 1))
        assertTrue(void.known)
        assertEquals(emptyList(), void.classes)
        assertEquals(DwarfAbiPassing.NONE, void.returnPassing)
    }

    @Test
    fun `complex arithmetic and arrays obey aggregate cleanup without losing x87 return`() {
        listOf(
            Triple(DwarfAbiScalarKind.COMPLEX_FLOAT16, 4L, 2L),
            Triple(DwarfAbiScalarKind.COMPLEX_FLOAT32, 8L, 4L),
            Triple(DwarfAbiScalarKind.COMPLEX_FLOAT64, 16L, 8L),
        ).forEach { (kind, bytes, alignment) ->
            val actual = classify(scalar(kind, bytes, alignment))
            assertTrue(actual.known)
            assertEquals(List(if (bytes == 16L) 2 else 1) { DwarfAbiClass.SSE }, actual.classes)
        }
        assertMemory(scalar(DwarfAbiScalarKind.COMPLEX_FLOAT128, 32, 16))
        val complexX87 = scalar(DwarfAbiScalarKind.COMPLEX_X87, 32, 16)
        val actual = classify(complexX87)
        assertEquals(listOf(DwarfAbiClass.COMPLEX_X87), actual.classes)
        assertEquals(DwarfAbiPassing.MEMORY, actual.parameterPassing)
        assertEquals(DwarfAbiPassing.REGISTERS, actual.returnPassing)
        assertMemory(array(complexX87, 1))
        assertMemory(aggregate(32, 16, DwarfAbiFieldShape(0, complexX87)))
        assertEquals(listOf(DwarfAbiClass.SSE, DwarfAbiClass.SSE), classify(array(double, 2)).classes)
        assertMemory(array(double, 3))
    }

    @Test
    fun `mixed structures unions and shifted padding retain exact classes`() {
        assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.SSE), classify(aggregate(
            16, 8, DwarfAbiFieldShape(0, int), DwarfAbiFieldShape(32, int), DwarfAbiFieldShape(64, double),
        )).classes)
        assertEquals(listOf(DwarfAbiClass.INTEGER), classify(union(8, 8, int, double)).classes)
        val paddedFloat = aggregate(8, 4, DwarfAbiFieldShape(0, float))
        assertEquals(listOf(DwarfAbiClass.SSE, DwarfAbiClass.NO_CLASS), classify(aggregate(
            12, 4, DwarfAbiFieldShape(32, paddedFloat),
        )).classes)
        val overAlignedFloat = aggregate(8, 8, DwarfAbiFieldShape(0, float))
        assertEquals(listOf(DwarfAbiClass.SSE, DwarfAbiClass.NO_CLASS), classify(aggregate(
            12, 1, DwarfAbiFieldShape(0, float), DwarfAbiFieldShape(32, overAlignedFloat),
        )).classes, "extra aggregate alignment does not misalign its naturally aligned scalar leaves")
        assertMemory(aggregate(9, 1, DwarfAbiFieldShape(0, byte), DwarfAbiFieldShape(8, double)))
        val integer128 = scalar(DwarfAbiScalarKind.INTEGER, 16)
        val quadFloat = scalar(DwarfAbiScalarKind.FLOAT128, 16)
        assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.SSE), classify(union(
            16, 16, long, quadFloat,
        )).classes, "orphan SSEUP is repaired to SSE")
        val extended = scalar(DwarfAbiScalarKind.X87, 16)
        assertMemory(union(16, 16, extended, long))
        assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.INTEGER), classify(union(
            16, 16, extended, integer128,
        )).classes)
        assertMemory(union(16, 16, extended, quadFloat))
        val badInner = union(16, 16, extended, long)
        assertMemory(union(16, 16, badInner, integer128))
    }

    @Test
    fun `wide vectors survive cleanup only with the complete SSEUP chain`() {
        listOf(8L, 16L, 32L, 64L).zip(listOf(
            DwarfAbiScalarKind.VECTOR64, DwarfAbiScalarKind.VECTOR128,
            DwarfAbiScalarKind.VECTOR256, DwarfAbiScalarKind.VECTOR512,
        )).forEach { (bytes, kind) ->
            val vector = scalar(kind, bytes)
            val expected = listOf(DwarfAbiClass.SSE) + List((bytes / 8 - 1).toInt()) { DwarfAbiClass.SSEUP }
            assertEquals(expected, classify(vector).classes)
            assertEquals(expected, classify(aggregate(bytes, bytes, DwarfAbiFieldShape(0, vector))).classes)
        }
        val vector = scalar(DwarfAbiScalarKind.VECTOR256, 32)
        assertMemory(aggregate(64, 32, DwarfAbiFieldShape(0, vector)))
        assertMemory(array(byte, 65))
    }

    @Test
    fun `bitfields use occupied bits and require proved storage without guessing packing`() {
        val int128 = scalar(DwarfAbiScalarKind.INTEGER, 16)
        assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.INTEGER), classify(aggregate(
            16, 16, DwarfAbiFieldShape(60, int128, 8, 0),
        )).classes)
        assertEquals(listOf(DwarfAbiClass.SSE), classify(aggregate(
            4, 4, DwarfAbiFieldShape(0, int, 0), DwarfAbiFieldShape(0, float),
        )).classes)
        assertEquals(listOf(DwarfAbiClass.INTEGER), classify(aggregate(
            4, 4, DwarfAbiFieldShape(3, int, 5, 0),
        )).classes)
        assertUnknown(aggregate(4, 4, DwarfAbiFieldShape(3, int, 5)), "storage offset is unproved")
        assertUnknown(aggregate(8, 1, DwarfAbiFieldShape(8, int, 8, 8)), "misaligned bit-field")
        assertUnknown(aggregate(8, 4, DwarfAbiFieldShape(28, int, 8, 0)), "outside its proved storage")
        assertUnknown(aggregate(8, 8, DwarfAbiFieldShape(0, double, 1, 0)), "bit-field type")
    }

    @Test
    fun `explicit nontrivial call semantics stay indirect for small and large objects`() {
        listOf(8L, 128L).forEach { bytes ->
            val result = classify(DwarfAbiTypeShape("nontrivial", bytes, 8, aggregate = true, invisibleReference = true))
            assertTrue(result.known)
            assertEquals(listOf(DwarfAbiClass.INTEGER), result.classes)
            assertEquals(DwarfAbiPassing.INVISIBLE_REFERENCE, result.parameterPassing)
            assertEquals(DwarfAbiPassing.INVISIBLE_REFERENCE, result.returnPassing)
            assertTrue("explicit-cxx-invisible-reference" in result.evidence)
        }
        val child = DwarfAbiTypeShape("nontrivial", 8, 8, aggregate = true, invisibleReference = true)
        assertUnknown(aggregate(8, 8, DwarfAbiFieldShape(0, child)), "containing call semantics")
    }

    @Test
    fun `unknown facts and malformed layouts never acquire a known ABI`() {
        assertUnknown(DwarfAbiTypeShape("missing-kind", 8, 8), "shape kind")
        assertUnknown(DwarfAbiTypeShape("missing-alignment", 8, 0, scalar = DwarfAbiScalarKind.INTEGER), "alignment")
        assertUnknown(scalar(DwarfAbiScalarKind.POINTER, 4), "storage width")
        assertUnknown(scalar(DwarfAbiScalarKind.X87, 10, 16), "storage width")
        assertUnknown(scalar(DwarfAbiScalarKind.INTEGER, 3, 1), "integer storage")
        assertUnknown(aggregate(8, 8, DwarfAbiFieldShape(Long.MAX_VALUE, long)), "offset")
        assertUnknown(aggregate(4, 4, DwarfAbiFieldShape(0, long)), "extent")
        assertUnknown(aggregate(8, 8, DwarfAbiFieldShape(0, long), DwarfAbiFieldShape(32, int)), "overlapping")
        assertUnknown(DwarfAbiTypeShape("array", 4, 4, arrayElement = int), "count is missing")
        assertUnknown(DwarfAbiTypeShape("array", 4, 4, arrayElement = int, arrayCount = 2), "does not match")
        assertUnknown(aggregate(0, 1, DwarfAbiFieldShape(0, byte)), "extent")
        assertTrue(classify(aggregate(0, 1)).known)
        assertEquals(DwarfAbiPassing.NONE, classify(array(byte, 0)).parameterPassing)
    }

    @Test
    fun `dimension size depth work and evidence limits are finite`() {
        assertUnknown(array(byte, 2), "dimension limit", DwarfAbiClassificationLimits(maximumArrayElements = 1))
        assertUnknown(DwarfAbiTypeShape("huge", Long.MAX_VALUE, 1, aggregate = true), "byte size")
        val hugeElement = DwarfAbiTypeShape("huge-element", Long.MAX_VALUE / 8, 1, aggregate = true)
        assertUnknown(DwarfAbiTypeShape("overflow", 0, 1, arrayElement = hugeElement, arrayCount = 9),
            "overflows", DwarfAbiClassificationLimits(maximumByteSize = Long.MAX_VALUE / 8))
        val nested = aggregate(4, 4, DwarfAbiFieldShape(0, aggregate(4, 4, DwarfAbiFieldShape(0, int))))
        assertUnknown(nested, "depth limit", DwarfAbiClassificationLimits(maximumDepth = 2))
        assertUnknown(nested, "work limit", DwarfAbiClassificationLimits(maximumTraversalSteps = 2))
        assertUnknown(aggregate(8, 4, DwarfAbiFieldShape(0, int), DwarfAbiFieldShape(32, int)),
            "field limit", DwarfAbiClassificationLimits(maximumFields = 1))
        val bounded = DwarfSysvAmd64Classification.classify(nested, DwarfAbiClassificationLimits(maximumEvidenceEntries = 1))
        assertTrue(bounded.known)
        assertEquals(1, bounded.evidence.size)
    }

    @Test
    fun `shapes and results retain immutable snapshots and shallow type references`() {
        val callerFields = mutableListOf(DwarfAbiFieldShape(0, double))
        val shape = DwarfAbiTypeShape("owner", 8, 8, fields = callerFields, aggregate = true)
        callerFields.clear()
        val result = classify(shape)
        assertEquals(listOf(DwarfAbiClass.SSE), result.classes)
        assertFailsWith<UnsupportedOperationException> { (shape.fields as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (result.classes as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (result.evidence as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (result.reasons as MutableList<*>).clear() }
        val field = (shape.toJson().getValue("fields") as JsonArray).single() as JsonObject
        assertEquals(JsonPrimitive(double.id), field["typeId"])
        assertFalse("type" in field)
    }

    private fun classify(shape: DwarfAbiTypeShape) = DwarfSysvAmd64Classification.classify(shape)

    private fun assertMemory(shape: DwarfAbiTypeShape) {
        val actual = classify(shape)
        assertTrue(actual.known, actual.reasons.toString())
        assertEquals(listOf(DwarfAbiClass.MEMORY), actual.classes)
        assertEquals(DwarfAbiPassing.MEMORY, actual.parameterPassing)
        assertEquals(DwarfAbiPassing.MEMORY, actual.returnPassing)
    }

    private fun assertUnknown(
        shape: DwarfAbiTypeShape,
        reason: String,
        limits: DwarfAbiClassificationLimits = DwarfAbiClassificationLimits(),
    ) {
        val actual = DwarfSysvAmd64Classification.classify(shape, limits)
        assertFalse(actual.known)
        assertEquals(emptyList(), actual.classes)
        assertEquals(DwarfAbiPassing.UNKNOWN, actual.parameterPassing)
        assertEquals(DwarfAbiPassing.UNKNOWN, actual.returnPassing)
        assertTrue(actual.reasons.single().contains(reason), actual.reasons.toString())
    }

    private fun scalar(kind: DwarfAbiScalarKind, bytes: Long, alignment: Long = bytes) =
        DwarfAbiTypeShape("${kind.name}-$bytes", bytes, alignment, scalar = kind)

    private fun aggregate(bytes: Long, alignment: Long, vararg fields: DwarfAbiFieldShape) =
        DwarfAbiTypeShape("aggregate", bytes, alignment, fields = fields.toList(), aggregate = true)

    private fun union(bytes: Long, alignment: Long, vararg types: DwarfAbiTypeShape) =
        DwarfAbiTypeShape("union", bytes, alignment, fields = types.map { DwarfAbiFieldShape(0, it) }, union = true)

    private fun array(element: DwarfAbiTypeShape, count: Long) =
        DwarfAbiTypeShape("array", element.byteSize * count, element.alignmentBytes, arrayElement = element, arrayCount = count)

    private val byte = scalar(DwarfAbiScalarKind.INTEGER, 1)
    private val int = scalar(DwarfAbiScalarKind.INTEGER, 4)
    private val long = scalar(DwarfAbiScalarKind.INTEGER, 8)
    private val float = scalar(DwarfAbiScalarKind.FLOAT32, 4)
    private val double = scalar(DwarfAbiScalarKind.FLOAT64, 8)
}

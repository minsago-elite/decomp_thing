package decompengine.oracle.structural

import decompengine.project.*
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class RecoveredAbiTypeGraphClassifierV1Test {
    @Test
    fun `distinct typedef roots sharing an aggregate DAG consume one delegated traversal budget`() {
        val single = graph(1)
        assertTrue(classify(single, 1_000).values.single().known)
        val repeated = graph(20)
        var checkpoints = 0
        val failure = assertFailsWith<IllegalStateException> {
            classify(repeated, 1_000) { checkpoints++ }
        }
        assertEquals("recovered ABI aggregate work bound exceeded", failure.message)
        // A deterministic operation count, not a timing assertion or twenty fresh local budgets.
        assertTrue(checkpoints <= repeated.size + 1_100, "unexpected checkpoint work: $checkpoints")
    }

    @Test
    fun `shape work exhaustion also escapes per root malformed layout handling`() {
        val failure = assertFailsWith<IllegalStateException> { classify(graph(1), 1) }
        assertEquals("recovered ABI aggregate work bound exceeded", failure.message)
    }

    @Test
    fun `delegated classifier checkpoints propagate cancellation instead of returning a candidate`() {
        val shape = DwarfAbiTypeShape("int", 4, 4, DwarfAbiScalarKind.INTEGER)
        val cancellation = IllegalStateException("cancelled")
        val failure = assertFailsWith<IllegalStateException> {
            DwarfSysvAmd64Classification.classifyWithCheckpoint(shape) { throw cancellation }
        }
        assertTrue(failure === cancellation)
        assertTrue(DwarfSysvAmd64Classification.classify(shape).known)
    }

    @Test
    fun `wide union shared by deep alias chains retains one immutable layout without losing root identity`() {
        val scope = NativeInterfaceGraphScopeV1("listing", 0)
        val records = arrayListOf<NativeInferredInterfaceRecordV1>()
        records += NativeInterfaceTypeNodeV1(scope, 0, "IntegerDataType", "integer", 4, 4, 4,
            false, false, false, "terminal", 0, JsonObject(mapOf("signed" to JsonPrimitive(true))))
        records += NativeInterfaceTypeNodeV1(scope, 1, "UnionDataType", "union", 4, 4, 4,
            false, false, false, "expanded", 4_096, JsonObject(mapOf(
                "componentCount" to JsonPrimitive(4_096), "definedComponentCount" to JsonPrimitive(4_096))))
        repeat(4_096) { ordinal -> records += NativeInterfaceTypeEdgeV1(scope, 1, ordinal, "component", 0,
            "reuse", 0, 4, null, false, false, false) }
        records += NativeInterfaceTypeRootV1(scope, "return-formal", -1, 0, 1)
        repeat(300) { slot ->
            var target = 1
            repeat(60) { depth ->
                val id = 2 + slot * 60 + depth
                records += NativeInterfaceTypeNodeV1(scope, id, "TypedefDataType", "typedef", 4, 4, 4,
                    false, false, false, "partial", 1, JsonObject(emptyMap()))
                records += NativeInterfaceTypeEdgeV1(scope, id, 0, "typedef-target", target,
                    "reuse", null, null, null, null, null, null)
                target = id
            }
            records += NativeInterfaceTypeRootV1(scope, "parameter-formal", slot, slot + 1, target)
        }
        val results = classify(records, RecoveredAbiTypeGraphClassifierV1.maximumWork).values.toList()
        assertEquals(301, results.size)
        val underlying = results.first().shape!!
        assertEquals(4_096, underlying.fields.size)
        assertEquals(301, results.map { it.typeTokenSha256 }.toSet().size)
        results.forEach { result ->
            assertTrue(result.known)
            assertEquals(listOf(DwarfAbiClass.INTEGER), result.classification!!.classes)
            // Reference identity is a deterministic allocation bound, not a heap/timing assertion.
            assertSame(underlying, result.shape)
            assertSame(underlying.fields, result.shape!!.fields)
            assertEquals(result.root.node, result.nativeNode!!.id)
        }
        assertFailsWith<UnsupportedOperationException> { (underlying.fields as MutableList).clear() }
    }

    private fun classify(records: List<NativeInferredInterfaceRecordV1>, work: Int, checkpoint: () -> Unit = {}) =
        RecoveredAbiTypeGraphClassifierV1.classify(records,
            StructuralRecoveryV1Inputs.loadTargetAbi(Path.of("src/test/resources/oracle/structural-v1/target-abi.json")),
            NativeCallBindingsV1("a".repeat(64), "gcc", "a".repeat(64), NativeCallAddressV1(0, "0000000000000000"),
                "a".repeat(64), "x86:LE:64:default", 1, "a".repeat(64), "a".repeat(64)),
            JsonObject(mapOf("bigEndian" to JsonPrimitive(false), "pointerSize" to JsonPrimitive(8),
                "pointerShift" to JsonPrimitive(0), "charSize" to JsonPrimitive(1), "shortSize" to JsonPrimitive(2),
                "integerSize" to JsonPrimitive(4), "longSize" to JsonPrimitive(8), "longLongSize" to JsonPrimitive(8),
                "floatSize" to JsonPrimitive(4), "doubleSize" to JsonPrimitive(8))),
            records.count { it is NativeInterfaceTypeRootV1 }.coerceAtLeast(1), checkpoint, workLimit = work)

    private fun graph(rootCount: Int): List<NativeInferredInterfaceRecordV1> {
        val scope = NativeInterfaceGraphScopeV1("listing", 0)
        val records = arrayListOf<NativeInferredInterfaceRecordV1>()
        records += NativeInterfaceTypeNodeV1(scope, 0, "IntegerDataType", "integer", 4, 4, 4,
            false, false, false, "terminal", 0, JsonObject(mapOf("signed" to JsonPrimitive(true))))
        // Five binary union levels have a small captured graph but repeated validation paths.
        for (id in 1..5) {
            records += NativeInterfaceTypeNodeV1(scope, id, "UnionDataType", "union", 4, 4, 4,
                false, false, false, "expanded", 2, JsonObject(mapOf(
                    "componentCount" to JsonPrimitive(2), "definedComponentCount" to JsonPrimitive(2))))
            repeat(2) { ordinal -> records += NativeInterfaceTypeEdgeV1(scope, id, ordinal, "component", id - 1,
                "reuse", 0, 4, null, false, false, false) }
        }
        repeat(rootCount) { slot ->
            val id = 6 + slot
            records += NativeInterfaceTypeNodeV1(scope, id, "TypedefDataType", "typedef", 4, 4, 4,
                false, false, false, "partial", 1, JsonObject(emptyMap()))
            records += NativeInterfaceTypeEdgeV1(scope, id, 0, "typedef-target", 5,
                "reuse", null, null, null, null, null, null)
            records += NativeInterfaceTypeRootV1(scope, "parameter-formal", slot, slot, id)
        }
        return records
    }
}

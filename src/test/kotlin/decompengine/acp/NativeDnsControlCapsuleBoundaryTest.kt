package decompengine.acp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Inert capsule-name and fixture-lifecycle controls; no resources, /proc or process APIs. */
class NativeDnsControlCapsuleBoundaryTest {
    @Test fun `observer capsule roots and generated nested classes are explicitly selected`() {
        assertEquals(setOf("NativeObserverBudget", "NativeObserverBudgetOwner", "NativeVisibilityAccumulator", "NativeObserverFailure"),
            nativeObserverCapsuleRoots)
        nativeObserverCapsuleRoots.forEach { root ->
            assertTrue(nativeObserverCapsuleClass("$root.class"))
            assertTrue(nativeObserverCapsuleClass(root + "$" + "generated.class"))
            assertFalse(nativeObserverCapsuleClass(root + "Unrelated.class"))
            assertFalse(nativeObserverCapsuleClass(root + ".java"))
        }
        assertFalse(nativeObserverCapsuleClass("NativeDnsObserverCapacityTest.class"))
    }
    @Test fun `capsule emission refuses every omitted observer root and nested substitute`() {
        val complete = nativeObserverCapsuleRoots.map { "decompengine/acp/$it.class" }.toSet()
        nativeRequireObserverCapsuleInventory(complete)
        complete.forEach { omitted ->
            assertFailsWith<IllegalStateException> { nativeRequireObserverCapsuleInventory(complete - omitted) }
            assertFailsWith<IllegalStateException> {
                nativeRequireObserverCapsuleInventory((complete - omitted) + (omitted.removeSuffix(".class") + "$" + "nested.class"))
            }
        }
        assertFailsWith<IllegalStateException> { nativeRequireObserverCapsuleInventory(complete + (0..256).map { "extra$it" }) }
    }
    @Test fun `exact owner lease clears after exceptional scope and cannot replace an active budget`() {
        val owner = NativeObserverBudgetOwner();val budget = NativeObserverBudget(10,{0})
        val primary=IllegalArgumentException("inert primary")
        val caught=assertFailsWith<IllegalArgumentException> {
            owner.acquire(budget).use {
                assertSame(budget,owner.current)
                assertFailsWith<IllegalStateException> { owner.acquire(NativeObserverBudget(20,{0})) }
                throw primary
            }
        }
        assertSame(primary,caught);assertNull(owner.current)
        val second=owner.acquire(budget);second.close();second.close();assertNull(owner.current)
    }
    @Test fun `released expired budget does not contaminate independent diagnostics or extend deadline`() {
        val owner=NativeObserverBudgetOwner();val expired=NativeObserverBudget(10,{10})
        owner.acquire(expired).use { assertFailsWith<NativeObserverFailure> { owner.current!!.operation() } }
        assertNull(owner.current)
        val independent=NativeVisibilityAccumulator();repeat(16) { independent.record("pid=$it",false) }
        assertEquals("DIAGNOSTIC_CAPACITY",assertFailsWith<NativeObserverFailure> { independent.record("pid=17",false) }.category)
        owner.acquire(expired).use { assertEquals("OBSERVER_DEADLINE",assertFailsWith<NativeObserverFailure> { owner.current!!.operation() }.category) }
        assertNull(owner.current)
    }
}

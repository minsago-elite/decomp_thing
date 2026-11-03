package decompengine.oracle.gcc

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class GccDriverProductionFunctionAccuracyV1Test {
    @Test
    fun `exact start threshold uses exact integer ratios at and below 95 percent`() {
        assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(19, 20))
        assertFalse(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(18, 20))
        assertFalse(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(949_999, 1_000_000))
        assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(3269, 3273))
        assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(3269, 3284))
        assertFalse(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(0, 0))
        assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(Long.MAX_VALUE, Long.MAX_VALUE))
    }

    @Test
    fun `surviving identity requires a nonempty fully recovered population`() {
        assertTrue(GccDriverProductionFunctionAccuracyV1.meetsIdentityThreshold(6, 6))
        assertFalse(GccDriverProductionFunctionAccuracyV1.meetsIdentityThreshold(5, 6))
        assertFalse(GccDriverProductionFunctionAccuracyV1.meetsIdentityThreshold(0, 0))
        assertFailsWith<IllegalArgumentException> { GccDriverProductionFunctionAccuracyV1.meetsIdentityThreshold(7, 6) }
        assertFailsWith<IllegalArgumentException> { GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(-1, 6) }
    }
}

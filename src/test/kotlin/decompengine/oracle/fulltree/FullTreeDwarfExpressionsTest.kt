package decompengine.oracle.fulltree

import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FullTreeDwarfExpressionsTest {
    @Test
    fun `exact address is proven only after complete endian-aware syntax validation`() {
        assertEquals(
            0x40302010UL,
            expression(byteArrayOf(0x03, 0x10, 0x20, 0x30, 0x40)),
        )
        assertEquals(
            0x10203040UL,
            expression(
                byteArrayOf(0x03, 0x10, 0x20, 0x30, 0x40),
                byteOrder = ByteOrder.BIG_ENDIAN,
            ),
        )
        assertNull(expression(byteArrayOf(0x03, 0x10, 0x20, 0x30, 0x40, 0x96.toByte())))
        assertNull(expression(byteArrayOf(0x50))) // DW_OP_reg0
    }

    @Test
    fun `valid variable and nested expressions remain unresolved`() {
        assertNull(expression(byteArrayOf(0x70, 0x7f))) // DW_OP_breg0 -1
        assertNull(expression(byteArrayOf(0x92.toByte(), 0x01, 0x00))) // DW_OP_bregx 1, 0
        assertNull(
            expression(
                byteArrayOf(
                    0xa3.toByte(), 0x02, // DW_OP_entry_value, two nested bytes
                    0x10, 0x01, // DW_OP_constu 1
                ),
            ),
        )
        assertNull(
            FullTreeDwarfExpressions.singleAddressOrNull(
                byteArrayOf(0xfa.toByte()) + ByteArray(8), // DW_OP_GNU_parameter_ref
                addressSize = 8,
                offsetSize = 8,
                byteOrder = ByteOrder.LITTLE_ENDIAN,
            ),
        )
        assertNull(expression(byteArrayOf(0xed.toByte(), 0x03, 0, 0, 0, 0)))
        var charged = 0
        FullTreeDwarfExpressions.singleAddressOrNull(
            byteArrayOf(0xa3.toByte(), 0x02, 0x10, 0x01),
            addressSize = 4,
            offsetSize = 4,
            byteOrder = ByteOrder.LITTLE_ENDIAN,
            chargeOperation = { charged++ },
        )
        assertEquals(2, charged)
    }

    @Test
    fun `unknown truncated overflowing and over-budget expressions fail closed`() {
        assertExpressionFails("unsupported opcode") { expression(byteArrayOf(0x07)) }
        assertExpressionFails("unsupported opcode") { expression(byteArrayOf(0xa2.toByte(), 0x00)) }
        assertExpressionFails("truncated") { expression(byteArrayOf(0x03, 0x01)) }
        assertExpressionFails("unterminated") {
            expression(byteArrayOf(0x10) + ByteArray(10) { 0x80.toByte() })
        }
        assertExpressionFails("operation bound") {
            FullTreeDwarfExpressions.singleAddressOrNull(
                byteArrayOf(0x96.toByte(), 0x96.toByte()),
                addressSize = 4,
                offsetSize = 4,
                byteOrder = ByteOrder.LITTLE_ENDIAN,
                maximumOperations = 1,
            )
        }
        assertExpressionFails("unsigned 64-bit") {
            FullTreeDwarfExpressions.singleAddressOrNull(
                byteArrayOf(0x03) + ByteArray(9) { if (it == 8) 1 else 0 },
                addressSize = 9,
                offsetSize = 4,
                byteOrder = ByteOrder.LITTLE_ENDIAN,
            )
        }
    }

    private fun expression(
        bytes: ByteArray,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): ULong? = FullTreeDwarfExpressions.singleAddressOrNull(
        bytes,
        addressSize = 4,
        offsetSize = 4,
        byteOrder = byteOrder,
    )

    private fun assertExpressionFails(fragment: String, block: () -> Unit) {
        val failure = assertFailsWith<FullTreeControlException> { block() }
        assertTrue(failure.message.orEmpty().contains(fragment), failure.message)
    }
}

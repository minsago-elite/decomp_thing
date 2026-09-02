package decompengine.oracle.fulltree

import java.nio.ByteOrder

/** Bounded syntax validation for the DWARF expressions used as call-target evidence. */
internal object FullTreeDwarfExpressions {
    /**
     * Validates the complete expression and returns its address only when it is exactly one
     * `DW_OP_addr`. Unsupported or truncated opcodes fail closed instead of being reclassified as
     * unresolved indirect evidence. [chargeOperation] connects each decoded opcode to the
     * enclosing artifact scan's aggregate budget.
     */
    fun singleAddressOrNull(
        bytes: ByteArray,
        addressSize: Int,
        offsetSize: Int,
        byteOrder: ByteOrder,
        maximumOperations: Int = MAXIMUM_OPERATIONS,
        maximumNesting: Int = MAXIMUM_NESTING,
        chargeOperation: () -> Unit = {},
    ): ULong? {
        if (addressSize !in 1..16) {
            throw FullTreeControlException("DWARF expression address size is invalid")
        }
        if (offsetSize !in setOf(4, 8)) {
            throw FullTreeControlException("DWARF expression offset size is invalid")
        }
        if (maximumOperations !in 1..MAXIMUM_OPERATIONS || maximumNesting !in 1..MAXIMUM_NESTING) {
            throw FullTreeControlException("DWARF expression limits are invalid")
        }
        val budget = ExpressionBudget(maximumOperations, maximumNesting, chargeOperation)
        val parsed = parse(
            ExpressionCursor(bytes, 0, bytes.size, byteOrder),
            addressSize,
            offsetSize,
            budget,
            nesting = 0,
        )
        return parsed.firstAddress.takeIf { parsed.operations == 1 }
    }

    private fun parse(
        cursor: ExpressionCursor,
        addressSize: Int,
        offsetSize: Int,
        budget: ExpressionBudget,
        nesting: Int,
    ): ParsedExpression {
        budget.requireNesting(nesting)
        var operations = 0
        var firstAddress: ULong? = null
        while (!cursor.exhausted()) {
            budget.operation()
            operations++
            when (val opcode = cursor.byte()) {
                DW_OP_ADDR -> cursor.address(addressSize).also {
                    if (operations == 1) firstAddress = it
                }
                DW_OP_DEREF,
                in DW_OP_LIT0..DW_OP_LIT31,
                in DW_OP_REG0..DW_OP_REG31,
                DW_OP_DUP,
                DW_OP_DROP,
                DW_OP_OVER,
                DW_OP_SWAP,
                DW_OP_ROT,
                DW_OP_XDEREF,
                DW_OP_ABS,
                DW_OP_AND,
                DW_OP_DIV,
                DW_OP_MINUS,
                DW_OP_MOD,
                DW_OP_MUL,
                DW_OP_NEG,
                DW_OP_NOT,
                DW_OP_OR,
                DW_OP_PLUS,
                DW_OP_SHL,
                DW_OP_SHR,
                DW_OP_SHRA,
                DW_OP_XOR,
                DW_OP_EQ,
                DW_OP_GE,
                DW_OP_GT,
                DW_OP_LE,
                DW_OP_LT,
                DW_OP_NE,
                DW_OP_NOP,
                DW_OP_PUSH_OBJECT_ADDRESS,
                DW_OP_FORM_TLS_ADDRESS,
                DW_OP_CALL_FRAME_CFA,
                DW_OP_STACK_VALUE,
                DW_OP_GNU_PUSH_TLS_ADDRESS,
                DW_OP_GNU_UNINIT,
                -> Unit
                DW_OP_CONST1U,
                DW_OP_CONST1S,
                DW_OP_PICK,
                DW_OP_DEREF_SIZE,
                DW_OP_XDEREF_SIZE,
                -> cursor.skip(1)
                DW_OP_CONST2U,
                DW_OP_CONST2S,
                DW_OP_BRA,
                DW_OP_SKIP,
                DW_OP_CALL2,
                -> cursor.skip(2)
                DW_OP_CONST4U,
                DW_OP_CONST4S,
                DW_OP_CALL4,
                -> cursor.skip(4)
                DW_OP_CONST8U,
                DW_OP_CONST8S,
                -> cursor.skip(8)
                DW_OP_CONSTU,
                DW_OP_PLUS_UCONST,
                DW_OP_REGX,
                DW_OP_PIECE,
                DW_OP_ADDRX,
                DW_OP_CONVERT,
                DW_OP_GNU_CONVERT,
                DW_OP_GNU_ADDR_INDEX,
                DW_OP_GNU_CONST_INDEX,
                DW_OP_GNU_VARIABLE_VALUE,
                -> cursor.uleb()
                DW_OP_CONSTS,
                DW_OP_FBREG,
                in DW_OP_BREG0..DW_OP_BREG31,
                -> cursor.sleb()
                DW_OP_BREGX -> {
                    cursor.uleb()
                    cursor.sleb()
                }
                DW_OP_CALL_REF -> cursor.skip(offsetSize)
                DW_OP_BIT_PIECE -> {
                    cursor.uleb()
                    cursor.uleb()
                }
                DW_OP_IMPLICIT_VALUE -> cursor.skip(cursor.boundedLength())
                DW_OP_IMPLICIT_POINTER,
                DW_OP_GNU_IMPLICIT_POINTER,
                -> {
                    cursor.skip(offsetSize)
                    cursor.sleb()
                }
                DW_OP_ENTRY_VALUE,
                DW_OP_GNU_ENTRY_VALUE,
                -> parse(cursor.block(), addressSize, offsetSize, budget, nesting + 1)
                DW_OP_CONST_TYPE,
                DW_OP_GNU_CONST_TYPE,
                -> {
                    cursor.uleb()
                    cursor.skip(cursor.byte())
                }
                DW_OP_REGVAL_TYPE,
                DW_OP_GNU_REGVAL_TYPE,
                -> {
                    cursor.uleb()
                    cursor.uleb()
                }
                DW_OP_DEREF_TYPE,
                DW_OP_GNU_DEREF_TYPE,
                -> {
                    cursor.skip(1)
                    cursor.uleb()
                }
                DW_OP_GNU_PARAMETER_REF -> cursor.skip(offsetSize)
                DW_OP_WASM_LOCATION -> {
                    when (cursor.byte()) {
                        0x00, 0x01, 0x02 -> cursor.uleb()
                        0x03 -> cursor.skip(4)
                        else -> throw FullTreeControlException(
                            "DW_OP_WASM_location uses an unsupported location kind",
                        )
                    }
                }
                else -> throw FullTreeControlException(
                    "DWARF expression uses unsupported opcode 0x${opcode.toString(16)}",
                )
            }
        }
        return ParsedExpression(operations, firstAddress)
    }

    private data class ParsedExpression(val operations: Int, val firstAddress: ULong?)

    private class ExpressionBudget(
        private val maximumOperations: Int,
        private val maximumNesting: Int,
        private val chargeOperation: () -> Unit,
    ) {
        private var operations = 0

        fun operation() {
            if (operations >= maximumOperations) {
                throw FullTreeControlException("DWARF expression exceeds its operation bound")
            }
            chargeOperation()
            operations++
        }

        fun requireNesting(nesting: Int) {
            if (nesting > maximumNesting) {
                throw FullTreeControlException("DWARF expression exceeds its nesting bound")
            }
        }
    }

    /** A zero-copy bounded view; nested expressions never duplicate their backing payload. */
    private class ExpressionCursor(
        private val bytes: ByteArray,
        private var position: Int,
        private val limit: Int,
        private val byteOrder: ByteOrder,
    ) {
        fun exhausted(): Boolean = position == limit

        fun byte(): Int {
            requireAvailable(1)
            return bytes[position++].toInt() and 0xff
        }

        fun skip(count: Int) {
            requireAvailable(count)
            position += count
        }

        fun address(width: Int): ULong {
            requireAvailable(width)
            var value = 0UL
            repeat(width) { index ->
                val significant = if (byteOrder == ByteOrder.LITTLE_ENDIAN) index else width - index - 1
                val current = bytes[position + index].toInt() and 0xff
                if (significant >= 8) {
                    if (current != 0) {
                        throw FullTreeControlException("DW_OP_addr exceeds unsigned 64-bit range")
                    }
                } else {
                    value = value or (current.toULong() shl (significant * 8))
                }
            }
            position += width
            return value
        }

        fun uleb(): ULong {
            var value = 0UL
            var shift = 0
            repeat(10) { index ->
                val current = byte()
                val payload = (current and 0x7f).toULong()
                if (index == 9 && payload > 1UL) {
                    throw FullTreeControlException("DWARF expression ULEB128 overflows")
                }
                if (shift < 64) value = value or (payload shl shift)
                if (current and 0x80 == 0) return value
                shift += 7
            }
            throw FullTreeControlException("DWARF expression ULEB128 is unterminated")
        }

        fun sleb() {
            repeat(10) { index ->
                val current = byte()
                val payload = current and 0x7f
                if (index == 9 && payload !in setOf(0, 0x7f)) {
                    throw FullTreeControlException("DWARF expression SLEB128 overflows")
                }
                if (current and 0x80 == 0) return
            }
            throw FullTreeControlException("DWARF expression SLEB128 is unterminated")
        }

        fun boundedLength(): Int {
            val length = uleb()
            if (length > Int.MAX_VALUE.toULong() || length > (limit - position).toULong()) {
                throw FullTreeControlException("DWARF expression block is truncated or oversized")
            }
            return length.toInt()
        }

        fun block(): ExpressionCursor {
            val length = boundedLength()
            val start = position
            position += length
            return ExpressionCursor(bytes, start, position, byteOrder)
        }

        private fun requireAvailable(count: Int) {
            if (count < 0 || position > limit - count) {
                throw FullTreeControlException("DWARF expression is truncated")
            }
        }
    }
}

private const val MAXIMUM_OPERATIONS = 1_000_000
private const val MAXIMUM_NESTING = 32
private const val DW_OP_ADDR = 0x03
private const val DW_OP_DEREF = 0x06
private const val DW_OP_CONST1U = 0x08
private const val DW_OP_CONST1S = 0x09
private const val DW_OP_CONST2U = 0x0a
private const val DW_OP_CONST2S = 0x0b
private const val DW_OP_CONST4U = 0x0c
private const val DW_OP_CONST4S = 0x0d
private const val DW_OP_CONST8U = 0x0e
private const val DW_OP_CONST8S = 0x0f
private const val DW_OP_CONSTU = 0x10
private const val DW_OP_CONSTS = 0x11
private const val DW_OP_DUP = 0x12
private const val DW_OP_DROP = 0x13
private const val DW_OP_OVER = 0x14
private const val DW_OP_PICK = 0x15
private const val DW_OP_SWAP = 0x16
private const val DW_OP_ROT = 0x17
private const val DW_OP_XDEREF = 0x18
private const val DW_OP_ABS = 0x19
private const val DW_OP_AND = 0x1a
private const val DW_OP_DIV = 0x1b
private const val DW_OP_MINUS = 0x1c
private const val DW_OP_MOD = 0x1d
private const val DW_OP_MUL = 0x1e
private const val DW_OP_NEG = 0x1f
private const val DW_OP_NOT = 0x20
private const val DW_OP_OR = 0x21
private const val DW_OP_PLUS = 0x22
private const val DW_OP_PLUS_UCONST = 0x23
private const val DW_OP_SHL = 0x24
private const val DW_OP_SHR = 0x25
private const val DW_OP_SHRA = 0x26
private const val DW_OP_XOR = 0x27
private const val DW_OP_BRA = 0x28
private const val DW_OP_EQ = 0x29
private const val DW_OP_GE = 0x2a
private const val DW_OP_GT = 0x2b
private const val DW_OP_LE = 0x2c
private const val DW_OP_LT = 0x2d
private const val DW_OP_NE = 0x2e
private const val DW_OP_SKIP = 0x2f
private const val DW_OP_LIT0 = 0x30
private const val DW_OP_LIT31 = 0x4f
private const val DW_OP_REG0 = 0x50
private const val DW_OP_REG31 = 0x6f
private const val DW_OP_BREG0 = 0x70
private const val DW_OP_BREG31 = 0x8f
private const val DW_OP_REGX = 0x90
private const val DW_OP_FBREG = 0x91
private const val DW_OP_BREGX = 0x92
private const val DW_OP_PIECE = 0x93
private const val DW_OP_DEREF_SIZE = 0x94
private const val DW_OP_XDEREF_SIZE = 0x95
private const val DW_OP_NOP = 0x96
private const val DW_OP_PUSH_OBJECT_ADDRESS = 0x97
private const val DW_OP_CALL2 = 0x98
private const val DW_OP_CALL4 = 0x99
private const val DW_OP_CALL_REF = 0x9a
private const val DW_OP_FORM_TLS_ADDRESS = 0x9b
private const val DW_OP_CALL_FRAME_CFA = 0x9c
private const val DW_OP_BIT_PIECE = 0x9d
private const val DW_OP_IMPLICIT_VALUE = 0x9e
private const val DW_OP_STACK_VALUE = 0x9f
private const val DW_OP_IMPLICIT_POINTER = 0xa0
private const val DW_OP_ADDRX = 0xa1
private const val DW_OP_ENTRY_VALUE = 0xa3
private const val DW_OP_CONST_TYPE = 0xa4
private const val DW_OP_REGVAL_TYPE = 0xa5
private const val DW_OP_DEREF_TYPE = 0xa6
private const val DW_OP_CONVERT = 0xa8
private const val DW_OP_GNU_PUSH_TLS_ADDRESS = 0xe0
private const val DW_OP_WASM_LOCATION = 0xed
private const val DW_OP_GNU_UNINIT = 0xf0
private const val DW_OP_GNU_IMPLICIT_POINTER = 0xf2
private const val DW_OP_GNU_ENTRY_VALUE = 0xf3
private const val DW_OP_GNU_CONST_TYPE = 0xf4
private const val DW_OP_GNU_REGVAL_TYPE = 0xf5
private const val DW_OP_GNU_DEREF_TYPE = 0xf6
private const val DW_OP_GNU_CONVERT = 0xf7
private const val DW_OP_GNU_PARAMETER_REF = 0xfa
private const val DW_OP_GNU_ADDR_INDEX = 0xfb
private const val DW_OP_GNU_CONST_INDEX = 0xfc
private const val DW_OP_GNU_VARIABLE_VALUE = 0xfd

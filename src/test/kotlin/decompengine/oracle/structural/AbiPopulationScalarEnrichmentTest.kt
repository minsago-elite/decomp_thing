package decompengine.oracle.structural

import decompengine.oracle.fulltree.*
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class AbiPopulationScalarEnrichmentTest {
    @Test fun `physical scalar kinds preserve signedness indirection duplicate names and unsupported payloads`() {
        val bytes = FullTreeDwarfInlineStringValue(byteArrayOf(1, 2))
        bytes.copyBytesBounded(2)[0] = 99
        assertEquals(1, bytes.copyBytesBounded(2)[0].toInt())
        val expression = FullTreeDwarfExpressionValue(byteArrayOf(3, 4))
        expression.copyBytesBounded(2)[0] = 99
        assertEquals(3, expression.copyBytesBounded(2)[0].toInt())
        val die = fixture()
        val observations = observe(die)
        AbiPopulationScalarVerifier.verify(0, die, observations)
        assertEquals(die.attributes.size, observations.size)
        assertEquals(observations[0].attribute, observations[1].attribute)
        assertNotEquals(observations[0].attributeOrdinal, observations[1].attributeOrdinal)
        assertEquals("unsupported-external-string", observations[8].kind)
        assertEquals("uncaptured-payload", observations[9].kind)
        assertEquals("ff00", observations[3].value)
    }
    @Test fun `scalar evidence substitution omission duplicate and false decoded string reject`() {
        val die = fixture()
        val rows = observe(die)
        listOf(rows.dropLast(1), rows + rows.last(), rows.reversed(),
            rows.mapIndexed { index, row -> if (index == 0) row.copy(value = "0") else row },
            rows.mapIndexed { index, row -> if (index == 1) row.copy(kind = "address") else row },
            rows.mapIndexed { index, row -> if (index == 8) row.copy(kind = "inline-string-bytes", value = "") else row },
            rows.mapIndexed { index, row -> if (index == 3) row.copy(value = "FF00") else row },
        ).forEach { forged ->
            assertFailsWith<IllegalArgumentException> { AbiPopulationScalarVerifier.verify(0, die, forged) }
        }
    }
    @Test fun `attribute payload limit fails explicitly`() {
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationScalarEnrichment.observe(0, fixture(), maximumAttributeBytes = 1) {}
        }
    }
    @Test fun `oversized payload rejects before defensive copying in producer and verifier`() {
        val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        bean.isThreadAllocatedMemoryEnabled = true
        val payload = ByteArray(8 * 1024 * 1024)
        for (value in listOf(FullTreeDwarfInlineStringValue(payload), FullTreeDwarfExpressionValue(payload))) {
            val die = FullTreeDwarfDieRecord(0, 1, 1, 0x34, false, 0, null, null,
                listOf(FullTreeDwarfDieAttribute(3, 8, value)))
            val forged = listOf(AbiScalarObservation(".debug_info:cu=0x0:die=0x0", 0, 3, 8,
                "inline-string-bytes", null, null, "", null))
            fun allocation(block: () -> Unit): Long {
                val before = bean.getThreadAllocatedBytes(Thread.currentThread().threadId())
                assertFailsWith<IllegalArgumentException>(block = block)
                return bean.getThreadAllocatedBytes(Thread.currentThread().threadId()) - before
            }
            // Warm assertion/error paths; every measured attempt would copy 8MiB in the old code.
            repeat(3) {
                allocation { AbiPopulationScalarEnrichment.observe(0, die, maximumAttributeBytes = 1) {} }
                allocation { AbiPopulationScalarVerifier.verify(0, die, forged) }
            }
            kotlin.test.assertTrue(allocation {
                AbiPopulationScalarEnrichment.observe(0, die, maximumAttributeBytes = 1) {}
            } < 1024 * 1024, "producer copied oversized payload before rejecting")
            kotlin.test.assertTrue(allocation {
                AbiPopulationScalarVerifier.verify(0, die, forged)
            } < 1024 * 1024, "verifier copied oversized payload before rejecting")
        }
    }

    private fun observe(die: FullTreeDwarfDieRecord) = buildList {
        AbiPopulationScalarEnrichment.observe(0, die, emit = ::add)
    }
    private fun fixture(): FullTreeDwarfDieRecord {
        val values = listOf(
            FullTreeDwarfNumericValue(-1), FullTreeDwarfUnsignedConstantValue(0xb, ULong.MAX_VALUE, 0),
            FullTreeDwarfSignedConstantValue(0xd, -4, 1), FullTreeDwarfInlineStringValue(byteArrayOf(-1, 0)),
            FullTreeDwarfExpressionValue(byteArrayOf(0x91.toByte(), 0x7f), 0x18, 0),
            FullTreeDwarfWideUnsignedConstantValue(0x1e, BigInteger.ONE.shiftLeft(100), 0),
            FullTreeDwarfSectionStringValue(".debug_str", 12), FullTreeDwarfIndexedStringValue(9),
            FullTreeDwarfUnsupportedExternalStringValue, FullTreeDwarfIgnoredValue,
            FullTreeDwarfAddressValue(1, 0x1000u, 0), FullTreeDwarfAddressIndexValue(0x1b, 1u, 0),
            FullTreeDwarfReferenceValue(0x13, 5u, 0), FullTreeDwarfUnsupportedReferenceValue(0x20, 7u, 0),
            FullTreeDwarfLocationListValue(0x17, 4u, 0, false), FullTreeDwarfLocationListValue(0x22, 8u, 0, true),
            FullTreeDwarfRangeSectionOffsetValue(0x17, 4u, 0), FullTreeDwarfRangeListIndexValue(0x23, 2u, 0),
        )
        return FullTreeDwarfDieRecord(0, 1, 1, 0x34, false, 0, null, null,
            values.map { FullTreeDwarfDieAttribute(0x3, 0x16, it) })
    }
}

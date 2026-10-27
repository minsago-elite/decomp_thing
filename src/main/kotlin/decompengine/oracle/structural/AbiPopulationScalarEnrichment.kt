package decompengine.oracle.structural

import decompengine.oracle.fulltree.*

/** Lossless physical attribute observations. None is a semantic identity or an admitted fact. */
internal data class AbiScalarObservation(
    val locator: String,
    val attributeOrdinal: Int,
    val attribute: Long,
    val declaredForm: Long,
    val kind: String,
    val resolvedForm: Long?,
    val indirectDepth: Int?,
    val value: String?,
    val auxiliary: String?,
)

/**
 * Enrich from a fresh authenticated parser traversal, not flattened function/type projections.
 * Every attribute gets a row including ignored/unsupported payloads; duplicate names retain order.
 * Callers charge parser, output and aggregate processing separately before admitting a profile.
 */
internal object AbiPopulationScalarEnrichment {
    fun observe(unitOffset: Long, die: FullTreeDwarfDieRecord,
                maximumAttributeBytes: Int = 1024 * 1024,
                emit: (AbiScalarObservation) -> Unit) {
        require(unitOffset >= 0 && die.offset >= unitOffset && maximumAttributeBytes in 1..1024 * 1024)
        require(die.attributes.size <= 65_536)
        val locator = physicalDieLocator(unitOffset, die.offset)
        for ((ordinal, attribute) in die.attributes.withIndex()) {
            val raw = attribute.value
            var kind: String
            var value: String? = null
            var auxiliary: String? = null
            var form: Long? = null
            var depth: Int? = null
            when (raw) {
                is FullTreeDwarfNumericValue -> { kind = "numeric"; value = raw.value.toString() }
                is FullTreeDwarfInlineStringValue -> { kind = "inline-string-bytes"; value = hex(raw.copyBytesBounded(maximumAttributeBytes), maximumAttributeBytes) }
                is FullTreeDwarfSectionStringValue -> { kind = "section-string-reference"; value = raw.offset.toString(); auxiliary = raw.section }
                is FullTreeDwarfIndexedStringValue -> { kind = "indexed-string-reference"; value = raw.index.toString() }
                FullTreeDwarfUnsupportedExternalStringValue -> kind = "unsupported-external-string"
                FullTreeDwarfIgnoredValue -> kind = "uncaptured-payload"
                is FullTreeDwarfExpressionValue -> {
                    kind = "expression-bytes"; value = hex(raw.copyBytesBounded(maximumAttributeBytes), maximumAttributeBytes)
                    form = raw.resolvedForm; depth = raw.indirectDepth
                }
                is FullTreeDwarfSignedConstantValue -> {
                    kind = "signed-constant"; value = raw.rawValue.toString(); form = raw.resolvedForm; depth = raw.indirectDepth
                }
                is FullTreeDwarfWideUnsignedConstantValue -> {
                    kind = "wide-unsigned-constant"; value = raw.rawValue.toString(16); form = raw.resolvedForm; depth = raw.indirectDepth
                }
                is FullTreeDwarfUnsignedFormValue -> {
                    kind = when (raw) {
                        is FullTreeDwarfUnsignedConstantValue -> "unsigned-constant"
                        is FullTreeDwarfAddressValue -> "address"
                        is FullTreeDwarfAddressIndexValue -> "indexed-address"
                        is FullTreeDwarfReferenceValue -> "reference"
                        is FullTreeDwarfUnsupportedReferenceValue -> "unsupported-reference"
                        is FullTreeDwarfLocationListValue -> if (raw.indexed) "indexed-location-list" else "location-list-offset"
                        is FullTreeDwarfRangeSectionOffsetValue -> "range-list-offset"
                        is FullTreeDwarfRangeListIndexValue -> "indexed-range-list"
                    }
                    value = raw.rawValue.toString(16); form = raw.resolvedForm; depth = raw.indirectDepth
                }
            }
            emit(AbiScalarObservation(locator, ordinal, attribute.name, attribute.declaredForm,
                kind, form, depth, value, auxiliary))
        }
    }
    private fun hex(bytes: ByteArray, maximum: Int): String {
        require(bytes.size <= maximum) { "attribute byte bound" }
        val alphabet = "0123456789abcdef"
        return CharArray(bytes.size * 2).also { chars ->
            bytes.forEachIndexed { index, byte ->
                val unsigned = byte.toInt() and 255
                chars[index * 2] = alphabet[unsigned ushr 4]; chars[index * 2 + 1] = alphabet[unsigned and 15]
            }
        }.concatToString()
    }
}

/** Independent comparison against replayed typed parser values; never invokes observe(). */
internal object AbiPopulationScalarVerifier {
    fun verify(unitOffset: Long, die: FullTreeDwarfDieRecord, observations: List<AbiScalarObservation>) {
        require(die.attributes.size <= 65_536 && observations.size == die.attributes.size)
        for (ordinal in die.attributes.indices) {
            val attribute = die.attributes[ordinal]
            val observation = observations[ordinal]
            require(observation.locator == physicalDieLocator(unitOffset, die.offset) && observation.attributeOrdinal == ordinal)
            require(observation.attribute == attribute.name && observation.declaredForm == attribute.declaredForm)
            val raw = attribute.value
            var expectedForm: Long? = null
            var expectedDepth: Int? = null
            var expectedAuxiliary: String? = null
            fun requireValue(kind: String, value: String?) {
                require(observation.kind == kind && observation.value == value)
            }
            fun requireBytes(kind: String, bytes: ByteArray) {
                require(bytes.size <= 1024 * 1024 && observation.kind == kind)
                val encoded = observation.value ?: error("missing byte payload")
                require(encoded.length == bytes.size * 2 && encoded.all { it in '0'..'9' || it in 'a'..'f' })
                for (index in bytes.indices) require(encoded.substring(index * 2, index * 2 + 2).toInt(16) == (bytes[index].toInt() and 255))
            }
            when (raw) {
                is FullTreeDwarfNumericValue -> requireValue("numeric", raw.value.toString())
                is FullTreeDwarfInlineStringValue -> requireBytes("inline-string-bytes", raw.copyBytesBounded(1024 * 1024))
                is FullTreeDwarfSectionStringValue -> {
                    requireValue("section-string-reference", raw.offset.toString()); expectedAuxiliary = raw.section
                }
                is FullTreeDwarfIndexedStringValue -> requireValue("indexed-string-reference", raw.index.toString())
                FullTreeDwarfUnsupportedExternalStringValue -> requireValue("unsupported-external-string", null)
                FullTreeDwarfIgnoredValue -> requireValue("uncaptured-payload", null)
                is FullTreeDwarfExpressionValue -> {
                    requireBytes("expression-bytes", raw.copyBytesBounded(1024 * 1024)); expectedForm = raw.resolvedForm; expectedDepth = raw.indirectDepth
                }
                is FullTreeDwarfSignedConstantValue -> {
                    requireValue("signed-constant", raw.rawValue.toString()); expectedForm = raw.resolvedForm; expectedDepth = raw.indirectDepth
                }
                is FullTreeDwarfWideUnsignedConstantValue -> {
                    requireValue("wide-unsigned-constant", raw.rawValue.toString(16)); expectedForm = raw.resolvedForm; expectedDepth = raw.indirectDepth
                }
                is FullTreeDwarfUnsignedFormValue -> {
                    val kind = when (raw) {
                        is FullTreeDwarfAddressValue -> "address"
                        is FullTreeDwarfAddressIndexValue -> "indexed-address"
                        is FullTreeDwarfUnsignedConstantValue -> "unsigned-constant"
                        is FullTreeDwarfReferenceValue -> "reference"
                        is FullTreeDwarfUnsupportedReferenceValue -> "unsupported-reference"
                        is FullTreeDwarfLocationListValue -> if (raw.indexed) "indexed-location-list" else "location-list-offset"
                        is FullTreeDwarfRangeListIndexValue -> "indexed-range-list"
                        is FullTreeDwarfRangeSectionOffsetValue -> "range-list-offset"
                    }
                    requireValue(kind, raw.rawValue.toString(16)); expectedForm = raw.resolvedForm; expectedDepth = raw.indirectDepth
                }
            }
            require(observation.resolvedForm == expectedForm && observation.indirectDepth == expectedDepth &&
                observation.auxiliary == expectedAuxiliary)
        }
    }
}

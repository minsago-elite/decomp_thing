package decompengine.oracle.fulltree

import java.util.Collections

/**
 * Explicit heap and traversal bounds for retaining one compilation unit's raw DIE index.
 *
 * [maximumRetainedBytes] is a conservative modeled charge for cached abbreviations, DIE records,
 * attributes, and inline-string payloads. It is not a JVM resident-set measurement. The shared
 * [FullTreeDwarfParseBudget] independently limits aggregate work across units and sections.
 */
internal data class FullTreeDwarfDieLimits(
    val maximumPhysicalRecords: Long,
    val maximumNonNullRecords: Int,
    val maximumAttributes: Long,
    val maximumTreeDepth: Int,
    val maximumRetainedBytes: Long,
) {
    init {
        require(maximumPhysicalRecords in 1L..1_000_000_000L)
        require(maximumNonNullRecords in 1..100_000_000)
        require(maximumAttributes in 1L..1_000_000_000L)
        require(maximumTreeDepth in 1..1_000_000)
        require(maximumRetainedBytes in 1L..1024L * 1024L * 1024L)
    }
}

/** One decoded attribute, retained in its abbreviation declaration's on-disk order. */
internal data class FullTreeDwarfDieAttribute(
    val name: Long,
    val declaredForm: Long,
    val value: FullTreeDwarfFormValue,
)

/** An immutable, non-null DIE record from one physical compilation-unit traversal. */
internal class FullTreeDwarfDieRecord internal constructor(
    val offset: Long,
    val endOffset: Long,
    val abbreviationCode: Long,
    val tag: Long,
    val hasChildren: Boolean,
    val depth: Int,
    val parentOffset: Long?,
    attributes: List<FullTreeDwarfDieAttribute>,
) {
    val attributes: List<FullTreeDwarfDieAttribute> =
        Collections.unmodifiableList(ArrayList(attributes))

    /** Preserves duplicate attribute names instead of silently applying a last-wins policy. */
    fun attributesNamed(name: Long): List<FullTreeDwarfDieAttribute> =
        attributes.filter { it.name == name }

    fun optionalUniqueAttribute(name: Long, label: String): FullTreeDwarfDieAttribute? {
        var result: FullTreeDwarfDieAttribute? = null
        attributes.forEach { attribute ->
            if (attribute.name == name) {
                if (result != null) {
                    throw FullTreeControlException("$label occurs more than once on DIE 0x${offset.toString(16)}")
                }
                result = attribute
            }
        }
        return result
    }
}

/**
 * One fully scanned compilation unit, indexed at selected non-null DIE boundaries.
 *
 * Physical and null record counts always describe the complete on-disk stream. The default reader
 * selection retains every non-null DIE; specialized readers may retain a bounded subset after
 * still decoding and validating every record and attribute. [required] rejects null, unselected,
 * interior, and out-of-unit offsets.
 */
internal class FullTreeDwarfDieIndex internal constructor(
    val compilationUnitOffset: Long,
    val firstDieOffset: Long,
    val endOffset: Long,
    val physicalRecordCount: Long,
    val nullRecordCount: Long,
    recordsInPhysicalOrder: List<FullTreeDwarfDieRecord>,
    recordsByOffset: Map<Long, FullTreeDwarfDieRecord>,
) {
    val recordsInPhysicalOrder: List<FullTreeDwarfDieRecord> =
        Collections.unmodifiableList(ArrayList(recordsInPhysicalOrder))
    private val recordsByOffset: Map<Long, FullTreeDwarfDieRecord> =
        Collections.unmodifiableMap(LinkedHashMap(recordsByOffset))

    val root: FullTreeDwarfDieRecord
        get() = recordsInPhysicalOrder.first()

    fun find(offset: Long): FullTreeDwarfDieRecord? = recordsByOffset[offset]

    fun required(offset: Long, label: String = "DWARF DIE target"): FullTreeDwarfDieRecord =
        recordsByOffset[offset]
            ?: throw FullTreeControlException(
                "$label does not identify a retained non-null DIE boundary in compilation unit " +
                    "0x${compilationUnitOffset.toString(16)}",
            )
}

/** Bounded raw-DIE traversal with lossless retention of every selected record. */
internal object FullTreeDwarfDies {
    fun readCompilationUnit(
        info: FullTreeDwarfSection,
        abbreviations: FullTreeDwarfSection,
        header: FullTreeDwarfCompilationUnitHeader,
        controlLimits: FullTreeControlLimits,
        dieLimits: FullTreeDwarfDieLimits,
        sharedParseBudget: FullTreeDwarfParseBudget,
        contextForAttribute: (FullTreeDwarfAbbreviationAttribute) -> FullTreeDwarfFormContext = {
            FullTreeDwarfFormContext.GENERAL
        },
        retainRecord: (tag: Long, depth: Int) -> Boolean = { _, _ -> true },
        observePhysicalRecord: (offset: Long, abbreviationCode: Long) -> Unit = { _, _ -> },
    ): FullTreeDwarfDieIndex {
        val retained = RetainedByteBudget(dieLimits.maximumRetainedBytes)
        val abbreviationTable = cacheAbbreviations(
            abbreviations,
            header,
            controlLimits,
            dieLimits,
            sharedParseBudget,
            retained,
        )
        val cursor = header.dieCursor(info)
        val records = ArrayList<FullTreeDwarfDieRecord>()
        val recordsByOffset = LinkedHashMap<Long, FullTreeDwarfDieRecord>()
        val openParents = ArrayDeque<Long>()
        var physicalRecords = 0L
        var nullRecords = 0L
        var nonNullRecords = 0L
        var decodedAttributes = 0L
        var treeTerminated = false

        while (cursor.position < header.endOffset) {
            if (physicalRecords >= dieLimits.maximumPhysicalRecords) {
                throw FullTreeControlException("DWARF DIE stream exceeds its physical-record bound")
            }
            sharedParseBudget.consume("DWARF DIE records")
            val recordOffset = cursor.position
            val abbreviationCode = cursor.readUleb128()
            physicalRecords = addCount(physicalRecords, 1L, "DWARF physical-record count")
            observePhysicalRecord(recordOffset, abbreviationCode)

            if (abbreviationCode == 0L) {
                nullRecords = addCount(nullRecords, 1L, "DWARF null-record count")
                when {
                    nonNullRecords == 0L -> throw FullTreeControlException(
                        "DWARF compilation unit has a null record before its root DIE",
                    )
                    openParents.isNotEmpty() -> {
                        openParents.removeLast()
                        if (openParents.isEmpty()) treeTerminated = true
                    }
                    !treeTerminated -> throw FullTreeControlException(
                        "DWARF compilation-unit tree termination is inconsistent",
                    )
                    // Null records after the one complete tree are physical trailing records.
                    else -> Unit
                }
                continue
            }
            if (treeTerminated) {
                throw FullTreeControlException("DWARF compilation unit contains more than one root tree")
            }
            if (nonNullRecords >= dieLimits.maximumNonNullRecords.toLong()) {
                throw FullTreeControlException("DWARF DIE stream exceeds its non-null record bound")
            }
            val declaration = abbreviationTable[abbreviationCode]
                ?: throw FullTreeControlException(
                    "DWARF DIE references absent abbreviation code $abbreviationCode",
                )
            val depth = openParents.size
            if (depth > dieLimits.maximumTreeDepth) {
                throw FullTreeControlException("DWARF DIE tree exceeds its depth bound")
            }
            val isRoot = nonNullRecords == 0L
            nonNullRecords = addCount(nonNullRecords, 1L, "DWARF non-null record count")
            val retain = isRoot || retainRecord(declaration.tag, depth)
            if (retain) retained.charge(MODELED_DIE_RECORD_BYTES, "DWARF DIE index")
            val attributes = if (retain) {
                ArrayList<FullTreeDwarfDieAttribute>(declaration.attributes.size)
            } else {
                null
            }
            declaration.attributes.forEach { attribute ->
                if (decodedAttributes >= dieLimits.maximumAttributes) {
                    throw FullTreeControlException("DWARF DIE stream exceeds its decoded-attribute bound")
                }
                sharedParseBudget.consume("DWARF DIE attributes")
                val context = contextForAttribute(attribute)
                val attributeOffset = cursor.position
                val value = try {
                    FullTreeDwarfForms.read(
                        cursor = cursor,
                        form = attribute.form,
                        implicitConstant = attribute.implicitConstant,
                        version = header.version,
                        addressSize = header.addressSize,
                        offsetSize = header.offsetSize,
                        limits = controlLimits,
                        context = context,
                    )
                } catch (failure: FullTreeControlException) {
                    throw FullTreeControlException(
                        "DWARF DIE 0x${recordOffset.toString(16)} attribute " +
                            "0x${attribute.name.toString(16)} form 0x${attribute.form.toString(16)} " +
                            "at 0x${attributeOffset.toString(16)} cannot be decoded: ${failure.message}",
                        failure,
                    )
                }
                decodedAttributes = addCount(decodedAttributes, 1L, "DWARF decoded-attribute count")
                if (attributes != null) {
                    retained.charge(
                        addCount(
                            MODELED_DIE_ATTRIBUTE_BYTES,
                            inlinePayloadBytes(value),
                            "DWARF retained attribute size",
                        ),
                        "DWARF DIE index",
                    )
                    attributes += FullTreeDwarfDieAttribute(
                        name = attribute.name,
                        declaredForm = attribute.form,
                        value = value,
                    )
                }
            }
            if (attributes != null) {
                val record = FullTreeDwarfDieRecord(
                    offset = recordOffset,
                    endOffset = cursor.position,
                    abbreviationCode = abbreviationCode,
                    tag = declaration.tag,
                    hasChildren = declaration.hasChildren == 1,
                    depth = depth,
                    parentOffset = openParents.lastOrNull(),
                    attributes = attributes,
                )
                if (recordsByOffset.put(recordOffset, record) != null) {
                    throw FullTreeControlException("DWARF DIE stream contains a duplicate record offset")
                }
                records += record
            }
            if (declaration.hasChildren == 1) {
                if (openParents.size >= dieLimits.maximumTreeDepth) {
                    throw FullTreeControlException("DWARF DIE tree exceeds its depth bound")
                }
                openParents.addLast(recordOffset)
            } else if (isRoot) {
                treeTerminated = true
            }
        }

        if (cursor.position != header.endOffset) {
            throw FullTreeControlException("DWARF DIE traversal did not end at its compilation-unit bound")
        }
        if (nonNullRecords == 0L) {
            throw FullTreeControlException("DWARF compilation unit has no root DIE")
        }
        if (openParents.isNotEmpty() || !treeTerminated) {
            throw FullTreeControlException("DWARF compilation-unit tree is unterminated")
        }
        return FullTreeDwarfDieIndex(
            compilationUnitOffset = header.offset,
            firstDieOffset = header.firstDieOffset,
            endOffset = header.endOffset,
            physicalRecordCount = physicalRecords,
            nullRecordCount = nullRecords,
            recordsInPhysicalOrder = records,
            recordsByOffset = recordsByOffset,
        )
    }

    private fun cacheAbbreviations(
        abbreviations: FullTreeDwarfSection,
        header: FullTreeDwarfCompilationUnitHeader,
        controlLimits: FullTreeControlLimits,
        dieLimits: FullTreeDwarfDieLimits,
        sharedParseBudget: FullTreeDwarfParseBudget,
        retained: RetainedByteBudget,
    ): Map<Long, FullTreeDwarfAbbreviationDeclaration> {
        val result = LinkedHashMap<Long, FullTreeDwarfAbbreviationDeclaration>()
        var cachedAttributes = 0L
        FullTreeDwarfAbbreviations(
            abbreviations,
            header.abbreviationOffset,
            controlLimits,
            sharedParseBudget,
        ).visit { declaration ->
            cachedAttributes = addCount(
                cachedAttributes,
                declaration.attributes.size.toLong(),
                "DWARF cached-abbreviation attribute count",
            )
            if (cachedAttributes > dieLimits.maximumAttributes) {
                throw FullTreeControlException("DWARF abbreviation cache exceeds its attribute bound")
            }
            val attributeBytes = multiplyCount(
                declaration.attributes.size.toLong(),
                MODELED_ABBREVIATION_ATTRIBUTE_BYTES,
                "DWARF abbreviation cache size",
            )
            retained.charge(
                addCount(
                    MODELED_ABBREVIATION_DECLARATION_BYTES,
                    attributeBytes,
                    "DWARF abbreviation cache size",
                ),
                "DWARF abbreviation cache",
            )
            if (result.put(declaration.code, declaration) != null) {
                // FullTreeDwarfAbbreviations already enforces this; retain a local invariant too.
                throw FullTreeControlException(
                    "DWARF abbreviation table contains duplicate code ${declaration.code}",
                )
            }
        }
        return Collections.unmodifiableMap(result)
    }

    private fun inlinePayloadBytes(value: FullTreeDwarfFormValue): Long =
        if (value is FullTreeDwarfInlineStringValue) value.bytes.size.toLong() else 0L

    private fun addCount(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("$label overflows", failure)
    }

    private fun multiplyCount(left: Long, right: Long, label: String): Long = try {
        Math.multiplyExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("$label overflows", failure)
    }

    private class RetainedByteBudget(private val maximum: Long) {
        private var retained = 0L

        fun charge(bytes: Long, label: String) {
            retained = FullTreeDwarfDies.addCount(retained, bytes, "$label byte count")
            if (retained > maximum) {
                throw FullTreeControlException("$label exceeds its retained-byte bound")
            }
        }
    }

    // Includes collection slots/wrappers, boxed map keys and nodes, object headers, and the usual
    // typed form-value object in addition to each logical record/attribute's scalar fields.
    private const val MODELED_ABBREVIATION_DECLARATION_BYTES = 256L
    private const val MODELED_ABBREVIATION_ATTRIBUTE_BYTES = 96L
    private const val MODELED_DIE_RECORD_BYTES = 320L
    private const val MODELED_DIE_ATTRIBUTE_BYTES = 96L
}

package decompengine.oracle.fulltree

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.util.Collections
import java.util.zip.InflaterInputStream

/** Aggregate, caller-shared budget for bounded DWARF traversal. */
internal class FullTreeDwarfParseBudget(private val limit: Long) {
    private var consumed = 0L

    init {
        require(limit in 1L..1_000_000_000L)
    }

    fun consume(label: String) {
        if (consumed >= limit) {
            throw FullTreeControlException("aggregate parse-step bound exceeded while reading $label")
        }
        consumed++
    }
}

/**
 * A decoded compilation-unit header and the bounded range containing its DIE stream.
 *
 * The header deliberately contains no interpretation of individual DIEs. Callers create a cursor
 * with [dieCursor] and share the same [FullTreeDwarfParseBudget] across subsequent traversal.
 */
internal class FullTreeDwarfCompilationUnitHeader(
    val offset: Long,
    val endOffset: Long,
    val version: Int,
    val unitType: Int?,
    val addressSize: Int,
    val offsetSize: Int,
    val abbreviationOffset: Long,
    val firstDieOffset: Long,
    private val originatingSection: FullTreeDwarfSection,
) {
    fun dieCursor(info: FullTreeDwarfSection): FullTreeDwarfSectionCursor {
        requireOriginatingInfo(info, "cursor")
        return FullTreeDwarfSectionCursor(info, firstDieOffset, endOffset, "DWARF compilation unit")
    }

    /** Resolves a reference while retaining this header's authenticated `.debug_info` identity. */
    fun resolveReference(info: FullTreeDwarfSection, reference: FullTreeDwarfReferenceValue): Long {
        requireOriginatingInfo(info, "reference")
        if (reference.resolvedForm !in FULL_TREE_DWARF_REFERENCE_FORMS) {
            throw FullTreeControlException("DWARF DIE reference has an inconsistent resolved form")
        }
        val raw = fullTreeDwarfBoundedLong(reference.rawValue, "DWARF DIE reference")
        return when (reference.scope) {
            FullTreeDwarfReferenceScope.COMPILATION_UNIT -> {
                val resolved = fullTreeDwarfAdd(offset, raw, "DWARF compilation-unit reference")
                if (resolved !in firstDieOffset until endOffset) {
                    throw FullTreeControlException("DWARF compilation-unit reference exceeds its DIE stream")
                }
                resolved
            }
            FullTreeDwarfReferenceScope.DEBUG_INFO -> {
                if (raw !in 0L until info.size) {
                    throw FullTreeControlException("DWARF global reference exceeds .debug_info")
                }
                raw
            }
        }
    }

    private fun requireOriginatingInfo(info: FullTreeDwarfSection, operation: String) {
        if (info !== originatingSection) {
            throw FullTreeControlException(
                "DWARF compilation-unit $operation uses a different .debug_info section",
            )
        }
    }
}

/** Stateful, count-bounded compilation-unit header iterator over one `.debug_info` section. */
internal class FullTreeDwarfCompilationUnitHeaders(
    private val info: FullTreeDwarfSection,
    private val maximumUnits: Long,
    private val parseBudget: FullTreeDwarfParseBudget,
) {
    private var nextOffset = 0L
    private var units = 0L

    fun hasNext(): Boolean = nextOffset < info.size

    fun next(): FullTreeDwarfCompilationUnitHeader {
        if (!hasNext()) throw NoSuchElementException("no DWARF compilation unit remains")
        parseBudget.consume("DWARF compilation units")
        if (units >= maximumUnits) {
            throw FullTreeControlException("compilation-unit count exceeds scope bound $maximumUnits")
        }

        val unitOffset = nextOffset
        val cursor = FullTreeDwarfSectionCursor(info, unitOffset, info.size, "DWARF compilation unit")
        val initialLength = cursor.readUnsigned(4)
        val offsetSize: Int
        val unitLength: Long
        when {
            initialLength == FULL_TREE_DWARF_64_MARKER -> {
                offsetSize = 8
                unitLength = cursor.readUnsigned(8)
            }
            initialLength in FULL_TREE_DWARF_RESERVED_LENGTH_MIN..FULL_TREE_DWARF_RESERVED_LENGTH_MAX ->
                throw FullTreeControlException("DWARF compilation unit uses a reserved length")
            else -> {
                offsetSize = 4
                unitLength = initialLength
            }
        }
        if (unitLength <= 0L || unitLength > info.size - cursor.position) {
            throw FullTreeControlException("DWARF compilation unit length exceeds .debug_info")
        }
        val unitEnd = Math.addExact(cursor.position, unitLength)
        cursor.narrowLimit(unitEnd)
        val version = cursor.readUnsigned(2).toInt()
        if (version !in 2..5) {
            throw FullTreeControlException("DWARF compilation unit version is unsupported: $version")
        }

        val unitType: Int?
        val addressSize: Int
        val abbreviationOffset: Long
        if (version >= 5) {
            unitType = cursor.readUnsigned(1).toInt()
            addressSize = cursor.readUnsigned(1).toInt()
            abbreviationOffset = cursor.readUnsigned(offsetSize)
            when (unitType) {
                FULL_TREE_DW_UT_COMPILE, FULL_TREE_DW_UT_PARTIAL -> Unit
                FULL_TREE_DW_UT_SKELETON, FULL_TREE_DW_UT_SPLIT_COMPILE -> cursor.skip(8L)
                FULL_TREE_DW_UT_TYPE, FULL_TREE_DW_UT_SPLIT_TYPE -> {
                    cursor.skip(8L)
                    cursor.skip(offsetSize.toLong())
                }
                else -> throw FullTreeControlException("DWARF compilation unit type is unsupported")
            }
        } else {
            unitType = null
            abbreviationOffset = cursor.readUnsigned(offsetSize)
            addressSize = cursor.readUnsigned(1).toInt()
        }
        if (addressSize !in 1..16) {
            throw FullTreeControlException("DWARF compilation unit address size is invalid")
        }

        units++
        nextOffset = unitEnd
        return FullTreeDwarfCompilationUnitHeader(
            offset = unitOffset,
            endOffset = unitEnd,
            version = version,
            unitType = unitType,
            addressSize = addressSize,
            offsetSize = offsetSize,
            abbreviationOffset = abbreviationOffset,
            firstDieOffset = cursor.position,
            originatingSection = info,
        )
    }
}

internal data class FullTreeDwarfAbbreviationAttribute(
    val name: Long,
    val form: Long,
    val implicitConstant: Long?,
)

internal data class FullTreeDwarfAbbreviationDeclaration(
    val code: Long,
    val tag: Long,
    val hasChildren: Int,
    val attributes: List<FullTreeDwarfAbbreviationAttribute>,
)

/** Streaming access to one abbreviation table under the caller's aggregate parse budget. */
internal class FullTreeDwarfAbbreviations(
    private val section: FullTreeDwarfSection,
    private val offset: Long,
    private val limits: FullTreeControlLimits,
    private val parseBudget: FullTreeDwarfParseBudget,
) {
    init {
        if (offset < 0L || offset >= section.size) {
            throw FullTreeControlException("DWARF abbreviation offset exceeds .debug_abbrev")
        }
    }

    fun required(code: Long, label: String = "DWARF abbreviation"): FullTreeDwarfAbbreviationDeclaration {
        return scan(expectedCode = code, absentLabel = label, visitor = null)
            ?: throw AssertionError("required abbreviation scan returned without a declaration")
    }

    /** Streams declarations in on-disk order without retaining the table in heap memory. */
    fun visit(visitor: (FullTreeDwarfAbbreviationDeclaration) -> Unit) {
        scan(expectedCode = null, absentLabel = null, visitor = visitor)
    }

    private fun scan(
        expectedCode: Long?,
        absentLabel: String?,
        visitor: ((FullTreeDwarfAbbreviationDeclaration) -> Unit)?,
    ): FullTreeDwarfAbbreviationDeclaration? {
        val cursor = FullTreeDwarfSectionCursor(section, offset, section.size, "DWARF abbreviation table")
        var declarations = 0
        var requested: FullTreeDwarfAbbreviationDeclaration? = null
        val codes = HashSet<Long>()
        while (true) {
            parseBudget.consume("DWARF abbreviation declarations")
            val code = cursor.readUleb128()
            if (code == 0L) {
                if (expectedCode != null && requested == null) {
                    throw FullTreeControlException("$absentLabel is absent")
                }
                return requested
            }
            if (declarations >= limits.maximumAbbreviationDeclarationsPerUnit) {
                throw FullTreeControlException("DWARF abbreviation table exceeds its declaration bound")
            }
            declarations++
            if (!codes.add(code)) {
                throw FullTreeControlException("DWARF abbreviation table contains duplicate code $code")
            }
            val tag = cursor.readUleb128()
            val hasChildren = cursor.readUnsigned(1).toInt()
            if (hasChildren !in 0..1) {
                throw FullTreeControlException("DWARF abbreviation has an invalid children flag")
            }
            val attributes = if (expectedCode == null || code == expectedCode) {
                ArrayList<FullTreeDwarfAbbreviationAttribute>()
            } else {
                null
            }
            var attributeCount = 0
            while (true) {
                parseBudget.consume("DWARF abbreviation attributes")
                val name = cursor.readUleb128()
                val form = cursor.readUleb128()
                if (name == 0L && form == 0L) {
                    if (attributes != null) {
                        val declaration = FullTreeDwarfAbbreviationDeclaration(
                            code = code,
                            tag = tag,
                            hasChildren = hasChildren,
                            attributes = Collections.unmodifiableList(attributes),
                        )
                        if (code == expectedCode) requested = declaration else visitor?.invoke(declaration)
                    }
                    break
                }
                if (name == 0L || form == 0L) {
                    throw FullTreeControlException("DWARF abbreviation attribute terminator is malformed")
                }
                if (attributeCount >= limits.maximumAbbreviationAttributesPerUnit) {
                    throw FullTreeControlException("DWARF abbreviation exceeds its attribute bound")
                }
                attributeCount++
                val implicit = if (form == FULL_TREE_DW_FORM_IMPLICIT_CONST) cursor.readSleb128() else null
                attributes?.add(FullTreeDwarfAbbreviationAttribute(name, form, implicit))
            }
        }
    }
}

internal sealed interface FullTreeDwarfFormValue
internal data class FullTreeDwarfNumericValue(val value: Long) : FullTreeDwarfFormValue
internal class FullTreeDwarfInlineStringValue(bytes: ByteArray) : FullTreeDwarfFormValue {
    private val content = bytes.copyOf()

    val bytes: ByteArray
        get() = content.copyOf()
}
internal data class FullTreeDwarfSectionStringValue(
    val section: String,
    val offset: Long,
) : FullTreeDwarfFormValue
internal data class FullTreeDwarfIndexedStringValue(val index: Long) : FullTreeDwarfFormValue
internal data object FullTreeDwarfUnsupportedExternalStringValue : FullTreeDwarfFormValue
internal data object FullTreeDwarfIgnoredValue : FullTreeDwarfFormValue

/** Attribute-class context needed for forms whose interpretation is not intrinsic to the form. */
internal enum class FullTreeDwarfFormContext {
    GENERAL,
    CONSTANT,
    RANGE_LIST,
}

/** Lossless unsigned form metadata retained for later function-observation readers. */
internal sealed interface FullTreeDwarfUnsignedFormValue : FullTreeDwarfFormValue {
    val resolvedForm: Long
    val rawValue: ULong
    val indirectDepth: Int
}

internal sealed interface FullTreeDwarfConstantValue : FullTreeDwarfFormValue {
    val resolvedForm: Long
    val indirectDepth: Int
}

internal data class FullTreeDwarfUnsignedConstantValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue, FullTreeDwarfConstantValue

internal data class FullTreeDwarfSignedConstantValue(
    override val resolvedForm: Long,
    val rawValue: Long,
    override val indirectDepth: Int,
) : FullTreeDwarfConstantValue

internal data class FullTreeDwarfAddressValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue

internal data class FullTreeDwarfAddressIndexValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue

internal enum class FullTreeDwarfReferenceScope {
    COMPILATION_UNIT,
    DEBUG_INFO,
}

internal data class FullTreeDwarfReferenceValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue {
    val scope: FullTreeDwarfReferenceScope
        get() = if (resolvedForm == FULL_TREE_DW_FORM_REF_ADDR) {
            FullTreeDwarfReferenceScope.DEBUG_INFO
        } else {
            FullTreeDwarfReferenceScope.COMPILATION_UNIT
        }
}

/** Retains a reference operand whose supplementary/signature target cannot be resolved locally. */
internal data class FullTreeDwarfUnsupportedReferenceValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue

internal data class FullTreeDwarfRangeSectionOffsetValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue

internal data class FullTreeDwarfRangeListIndexValue(
    override val resolvedForm: Long,
    override val rawValue: ULong,
    override val indirectDepth: Int,
) : FullTreeDwarfUnsignedFormValue

/** Stateless bounded decoding for the forms already shared by inventory and later DIE readers. */
internal object FullTreeDwarfForms {
    fun read(
        cursor: FullTreeDwarfSectionCursor,
        form: Long,
        implicitConstant: Long?,
        version: Int,
        addressSize: Int,
        offsetSize: Int,
        limits: FullTreeControlLimits,
        indirectDepth: Int = 0,
        context: FullTreeDwarfFormContext = FullTreeDwarfFormContext.GENERAL,
    ): FullTreeDwarfFormValue {
        if (indirectDepth > 4) throw FullTreeControlException("DWARF indirect form nesting is excessive")
        return when (form) {
            FULL_TREE_DW_FORM_ADDR -> FullTreeDwarfAddressValue(
                resolvedForm = form,
                rawValue = cursor.readAddress(addressSize),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_BLOCK2 -> cursor.readUnsigned(2).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_BLOCK4 -> cursor.readUnsigned(4).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_DATA2 -> readUnsignedConstant(
                cursor, form, 2, indirectDepth, context, version, offsetSize,
            )
            FULL_TREE_DW_FORM_DATA4 -> readUnsignedConstant(
                cursor, form, 4, indirectDepth, context, version, offsetSize,
            )
            FULL_TREE_DW_FORM_DATA8 -> readUnsignedConstant(
                cursor, form, 8, indirectDepth, context, version, offsetSize,
            )
            FULL_TREE_DW_FORM_STRING -> FullTreeDwarfInlineStringValue(
                cursor.readNullTerminated(limits.maximumDwarfAttributeBytes),
            )
            FULL_TREE_DW_FORM_BLOCK -> cursor.readUleb128().let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_BLOCK1 -> cursor.readUnsigned(1).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_DATA1 -> readUnsignedConstant(
                cursor, form, 1, indirectDepth, context, version, offsetSize,
            )
            FULL_TREE_DW_FORM_FLAG -> FullTreeDwarfNumericValue(cursor.readUnsigned(1))
            FULL_TREE_DW_FORM_SDATA -> cursor.readSleb128().let { raw ->
                if (context == FullTreeDwarfFormContext.CONSTANT) {
                    FullTreeDwarfSignedConstantValue(form, raw, indirectDepth)
                } else {
                    FullTreeDwarfNumericValue(raw)
                }
            }
            FULL_TREE_DW_FORM_STRP -> FullTreeDwarfSectionStringValue(
                ".debug_str",
                cursor.readUnsigned(offsetSize),
            )
            FULL_TREE_DW_FORM_UDATA -> if (context == FullTreeDwarfFormContext.CONSTANT) {
                FullTreeDwarfUnsignedConstantValue(form, cursor.readUleb128Bits(), indirectDepth)
            } else {
                FullTreeDwarfNumericValue(cursor.readUleb128())
            }
            FULL_TREE_DW_FORM_REF_ADDR -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = if (version <= 2) {
                    cursor.readAddress(addressSize)
                } else {
                    cursor.readUnsignedBits(offsetSize)
                },
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF1 -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(1),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF2 -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(2),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF4 -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(4),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF8 -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(8),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF_UDATA -> FullTreeDwarfReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUleb128Bits(),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_ADDRX -> FullTreeDwarfAddressIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUleb128Bits(),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_RNGLISTX -> FullTreeDwarfRangeListIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUleb128Bits(),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_LOCLISTX, FULL_TREE_DW_FORM_GNU_ADDR_INDEX ->
                cursor.readUleb128().let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF_SUP4 -> FullTreeDwarfUnsupportedReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(4),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_REF_SIG8, FULL_TREE_DW_FORM_REF_SUP8 ->
                FullTreeDwarfUnsupportedReferenceValue(
                    resolvedForm = form,
                    rawValue = cursor.readUnsignedBits(8),
                    indirectDepth = indirectDepth,
                )
            FULL_TREE_DW_FORM_INDIRECT -> read(
                cursor,
                cursor.readUleb128(),
                null,
                version,
                addressSize,
                offsetSize,
                limits,
                indirectDepth + 1,
                context,
            )
            FULL_TREE_DW_FORM_SEC_OFFSET -> if (context == FullTreeDwarfFormContext.RANGE_LIST) {
                FullTreeDwarfRangeSectionOffsetValue(
                    resolvedForm = form,
                    rawValue = cursor.readUnsignedBits(offsetSize),
                    indirectDepth = indirectDepth,
                )
            } else {
                // Frozen inventory behavior: bases and statement-list offsets remain numeric.
                FullTreeDwarfNumericValue(cursor.readUnsigned(offsetSize))
            }
            FULL_TREE_DW_FORM_EXPRLOC -> cursor.readUleb128().let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_FLAG_PRESENT -> FullTreeDwarfNumericValue(1L)
            FULL_TREE_DW_FORM_STRX, FULL_TREE_DW_FORM_GNU_STR_INDEX ->
                FullTreeDwarfIndexedStringValue(cursor.readUleb128())
            FULL_TREE_DW_FORM_STRP_SUP, FULL_TREE_DW_FORM_GNU_STRP_ALT ->
                FullTreeDwarfUnsupportedExternalStringValue.also { cursor.skip(offsetSize.toLong()) }
            FULL_TREE_DW_FORM_DATA16 -> if (context == FullTreeDwarfFormContext.CONSTANT) {
                FullTreeDwarfUnsignedConstantValue(form, cursor.readData16(), indirectDepth)
            } else {
                cursor.skip(16L).let { FullTreeDwarfIgnoredValue }
            }
            FULL_TREE_DW_FORM_LINE_STRP -> FullTreeDwarfSectionStringValue(
                ".debug_line_str",
                cursor.readUnsigned(offsetSize),
            )
            FULL_TREE_DW_FORM_IMPLICIT_CONST -> {
                val raw = implicitConstant
                    ?: throw FullTreeControlException("DWARF implicit constant is absent")
                if (context == FullTreeDwarfFormContext.CONSTANT) {
                    FullTreeDwarfSignedConstantValue(form, raw, indirectDepth)
                } else {
                    FullTreeDwarfNumericValue(raw)
                }
            }
            FULL_TREE_DW_FORM_STRX1 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(1))
            FULL_TREE_DW_FORM_STRX2 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(2))
            FULL_TREE_DW_FORM_STRX3 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(3))
            FULL_TREE_DW_FORM_STRX4 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(4))
            FULL_TREE_DW_FORM_ADDRX1 -> FullTreeDwarfAddressIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(1),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_ADDRX2 -> FullTreeDwarfAddressIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(2),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_ADDRX3 -> FullTreeDwarfAddressIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(3),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_ADDRX4 -> FullTreeDwarfAddressIndexValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(4),
                indirectDepth = indirectDepth,
            )
            FULL_TREE_DW_FORM_GNU_REF_ALT -> FullTreeDwarfUnsupportedReferenceValue(
                resolvedForm = form,
                rawValue = cursor.readUnsignedBits(offsetSize),
                indirectDepth = indirectDepth,
            )
            else -> throw FullTreeControlException(
                "DWARF attribute uses unsupported form 0x${form.toString(16)}",
            )
        }
    }

    private fun readUnsignedConstant(
        cursor: FullTreeDwarfSectionCursor,
        form: Long,
        width: Int,
        indirectDepth: Int,
        context: FullTreeDwarfFormContext,
        version: Int,
        offsetSize: Int,
    ): FullTreeDwarfFormValue = when {
        context == FullTreeDwarfFormContext.CONSTANT ->
            FullTreeDwarfUnsignedConstantValue(form, cursor.readUnsignedBits(width), indirectDepth)
        context == FullTreeDwarfFormContext.RANGE_LIST && version <= 3 && width == offsetSize ->
            FullTreeDwarfRangeSectionOffsetValue(form, cursor.readUnsignedBits(width), indirectDepth)
        else -> FullTreeDwarfNumericValue(cursor.readUnsigned(width))
    }

    fun decodeString(
        value: FullTreeDwarfFormValue,
        sections: FullTreeDwarfSections,
        stringOffsetsBase: Long?,
        offsetSize: Int,
        limits: FullTreeControlLimits,
        label: String,
        maximumCharacters: Int = 4096,
    ): String {
        if (maximumCharacters !in 1..FULL_TREE_MAXIMUM_DWARF_STRING_CHARACTERS) {
            throw FullTreeControlException("$label character bound is invalid")
        }
        val bytes = when (value) {
            is FullTreeDwarfInlineStringValue -> value.bytes
            is FullTreeDwarfSectionStringValue -> sections.required(value.section).readNullTerminated(
                value.offset,
                limits.maximumDwarfAttributeBytes,
            )
            is FullTreeDwarfIndexedStringValue -> {
                val base = stringOffsetsBase
                    ?: throw FullTreeControlException("$label uses an indexed string without DW_AT_str_offsets_base")
                val offsets = sections.required(".debug_str_offsets")
                val entryOffset = try {
                    Math.addExact(base, Math.multiplyExact(value.index, offsetSize.toLong()))
                } catch (failure: ArithmeticException) {
                    throw FullTreeControlException("$label string index exceeds .debug_str_offsets", failure)
                }
                val stringOffset = offsets.readUnsigned(entryOffset, offsetSize)
                sections.required(".debug_str").readNullTerminated(
                    stringOffset,
                    limits.maximumDwarfAttributeBytes,
                )
            }
            FullTreeDwarfUnsupportedExternalStringValue -> throw FullTreeControlException(
                "$label depends on unsupported supplementary DWARF strings",
            )
            else -> throw FullTreeControlException("$label is not encoded as a DWARF string")
        }
        val decoded = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (failure: Exception) {
            throw FullTreeControlException("$label is not UTF-8", failure)
        }
        if (
            decoded.isEmpty() || '\u0000' in decoded ||
            decoded.codePointCount(0, decoded.length) > maximumCharacters
        ) {
            throw FullTreeControlException(
                "$label is empty, contains NUL, or exceeds $maximumCharacters characters",
            )
        }
        return decoded
    }
}

/** Resolves one CU's address indexes inside its bounded DWARF v5 `.debug_addr` contribution. */
internal class FullTreeDwarfAddressResolver(
    private val section: FullTreeDwarfSection,
    addressBase: Long,
    version: Int,
    offsetSize: Int,
    private val addressSize: Int,
) {
    private val entriesOffset: Long
    private val endOffset: Long
    private val entryCount: Long

    init {
        if (version != 5) throw FullTreeControlException("DWARF indexed addresses require version 5")
        if (offsetSize !in setOf(4, 8)) {
            throw FullTreeControlException("DWARF address table offset size is invalid")
        }
        if (addressSize !in 1..16) {
            throw FullTreeControlException("DWARF address table address size is invalid")
        }
        val headerBytes = if (offsetSize == 4) 8L else 16L
        if (addressBase < headerBytes) {
            throw FullTreeControlException("DW_AT_addr_base does not follow a complete .debug_addr header")
        }
        val contribution = fullTreeDwarfContribution(
            section,
            addressBase - headerBytes,
            ".debug_addr contribution",
        )
        if (contribution.offsetSize != offsetSize) {
            throw FullTreeControlException("DW_AT_addr_base uses a different DWARF format")
        }
        val cursor = FullTreeDwarfSectionCursor(
            section,
            contribution.bodyOffset,
            contribution.endOffset,
            ".debug_addr contribution",
        )
        if (cursor.readUnsigned(2) != 5L) {
            throw FullTreeControlException(".debug_addr contribution version is unsupported")
        }
        if (cursor.readUnsigned(1).toInt() != addressSize) {
            throw FullTreeControlException(".debug_addr contribution address size differs from its unit")
        }
        if (cursor.readUnsigned(1) != 0L) {
            throw FullTreeControlException("segmented .debug_addr contributions are unsupported")
        }
        if (cursor.position != addressBase) {
            throw FullTreeControlException("DW_AT_addr_base does not point to the first address entry")
        }
        val entryBytes = contribution.endOffset - cursor.position
        if (entryBytes % addressSize.toLong() != 0L) {
            throw FullTreeControlException(".debug_addr contribution has a partial address entry")
        }
        entriesOffset = cursor.position
        endOffset = contribution.endOffset
        entryCount = entryBytes / addressSize.toLong()
    }

    fun resolve(value: FullTreeDwarfAddressIndexValue): ULong {
        if (value.resolvedForm !in FULL_TREE_DWARF_ADDRESS_INDEX_FORMS) {
            throw FullTreeControlException("DWARF address index has an inconsistent resolved form")
        }
        if (value.rawValue >= entryCount.toULong()) {
            throw FullTreeControlException("DWARF address index exceeds its .debug_addr contribution")
        }
        val index = value.rawValue.toLong()
        val entryOffset = fullTreeDwarfAdd(
            entriesOffset,
            fullTreeDwarfMultiply(index, addressSize.toLong(), "DWARF address index"),
            "DWARF address index",
        )
        if (entryOffset < entriesOffset || entryOffset > endOffset - addressSize.toLong()) {
            throw FullTreeControlException("DWARF address index exceeds its .debug_addr contribution")
        }
        return section.readAddress(entryOffset, addressSize)
    }
}

internal enum class FullTreeDwarfRangeListEncoding {
    DEBUG_RANGES,
    DEBUG_RNGLISTS,
}

/** An immutable, section-bound range-list cursor seed for a later DIE scanner. */
internal class FullTreeDwarfRangeListInput internal constructor(
    private val section: FullTreeDwarfSection,
    val encoding: FullTreeDwarfRangeListEncoding,
    val offset: Long,
    val endOffset: Long,
    val dwarfVersion: Int,
    val addressSize: Int,
    val offsetSize: Int,
) {
    fun cursor(): FullTreeDwarfSectionCursor = FullTreeDwarfSectionCursor(
        section,
        offset,
        endOffset,
        when (encoding) {
            FullTreeDwarfRangeListEncoding.DEBUG_RANGES -> ".debug_ranges list"
            FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS -> ".debug_rnglists list"
        },
    )
}

/** Resolves range-list forms without parsing or interpreting any range-list entry. */
internal class FullTreeDwarfRangeListResolver(
    private val version: Int,
    private val addressSize: Int,
    private val offsetSize: Int,
    private val debugRanges: FullTreeDwarfSection?,
    private val debugRnglists: FullTreeDwarfSection?,
    private val rnglistsBase: Long?,
    private val parseBudget: FullTreeDwarfParseBudget,
) {
    init {
        if (version !in 2..5) throw FullTreeControlException("DWARF range-list version is unsupported")
        if (addressSize !in 1..16) throw FullTreeControlException("DWARF range-list address size is invalid")
        if (offsetSize !in setOf(4, 8)) throw FullTreeControlException("DWARF range-list offset size is invalid")
        if (rnglistsBase != null && rnglistsBase < 0L) {
            throw FullTreeControlException("DW_AT_rnglists_base is negative")
        }
    }

    fun resolve(value: FullTreeDwarfFormValue): FullTreeDwarfRangeListInput = when (value) {
        is FullTreeDwarfRangeSectionOffsetValue -> resolveSectionOffset(value)
        is FullTreeDwarfRangeListIndexValue -> resolveIndex(value)
        else -> throw FullTreeControlException("DWARF ranges attribute does not contain a range-list form")
    }

    private fun resolveSectionOffset(value: FullTreeDwarfRangeSectionOffsetValue): FullTreeDwarfRangeListInput {
        val expectedForm = when {
            version <= 3 && offsetSize == 4 -> FULL_TREE_DW_FORM_DATA4
            version <= 3 && offsetSize == 8 -> FULL_TREE_DW_FORM_DATA8
            else -> FULL_TREE_DW_FORM_SEC_OFFSET
        }
        if (value.resolvedForm != expectedForm) {
            throw FullTreeControlException("DWARF range section offset has an inconsistent resolved form")
        }
        val offset = fullTreeDwarfBoundedLong(value.rawValue, "DWARF range section offset")
        if (version < 5) {
            val section = debugRanges
                ?: throw FullTreeControlException("DWARF ranges attribute requires .debug_ranges")
            if (offset !in 0L until section.size) {
                throw FullTreeControlException("DWARF range section offset exceeds .debug_ranges")
            }
            return FullTreeDwarfRangeListInput(
                section = section,
                encoding = FullTreeDwarfRangeListEncoding.DEBUG_RANGES,
                offset = offset,
                endOffset = section.size,
                dwarfVersion = version,
                addressSize = addressSize,
                offsetSize = offsetSize,
            )
        }

        val section = debugRnglists
            ?: throw FullTreeControlException("DWARF ranges attribute requires .debug_rnglists")
        val contribution = findRnglistsContribution(section, offset)
        return FullTreeDwarfRangeListInput(
            section = section,
            encoding = FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
            offset = offset,
            endOffset = contribution.endOffset,
            dwarfVersion = version,
            addressSize = addressSize,
            offsetSize = offsetSize,
        )
    }

    private fun resolveIndex(value: FullTreeDwarfRangeListIndexValue): FullTreeDwarfRangeListInput {
        if (value.resolvedForm != FULL_TREE_DW_FORM_RNGLISTX) {
            throw FullTreeControlException("DWARF range-list index has an inconsistent resolved form")
        }
        if (version != 5) {
            throw FullTreeControlException("DW_FORM_rnglistx requires DWARF version 5")
        }
        val section = debugRnglists
            ?: throw FullTreeControlException("DW_FORM_rnglistx requires .debug_rnglists")
        val base = rnglistsBase
            ?: throw FullTreeControlException("DW_FORM_rnglistx requires DW_AT_rnglists_base")
        val headerBytes = if (offsetSize == 4) 12L else 20L
        if (base < headerBytes) {
            throw FullTreeControlException("DW_AT_rnglists_base does not follow a complete contribution header")
        }
        parseBudget.consume(".debug_rnglists contributions")
        val contribution = fullTreeDwarfRnglistsContribution(section, base - headerBytes)
        validateRnglistsContribution(contribution)
        if (contribution.entriesOffset != base) {
            throw FullTreeControlException("DW_AT_rnglists_base does not point to the offset table")
        }
        if (value.rawValue >= contribution.entryCount.toULong()) {
            throw FullTreeControlException("DWARF range-list index exceeds its offset table")
        }
        val index = value.rawValue.toLong()
        val entryOffset = fullTreeDwarfAdd(
            base,
            fullTreeDwarfMultiply(index, offsetSize.toLong(), "DWARF range-list index"),
            "DWARF range-list index",
        )
        val relative = section.readUnsigned(entryOffset, offsetSize)
        val resolved = fullTreeDwarfAdd(base, relative, "DWARF range-list offset")
        if (resolved !in contribution.listsOffset until contribution.endOffset) {
            throw FullTreeControlException("DWARF range-list index resolves outside its contribution")
        }
        return FullTreeDwarfRangeListInput(
            section = section,
            encoding = FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
            offset = resolved,
            endOffset = contribution.endOffset,
            dwarfVersion = version,
            addressSize = addressSize,
            offsetSize = offsetSize,
        )
    }

    private fun findRnglistsContribution(
        section: FullTreeDwarfSection,
        targetOffset: Long,
    ): FullTreeDwarfRnglistsContribution {
        if (targetOffset !in 0L until section.size) {
            throw FullTreeControlException("DWARF range section offset exceeds .debug_rnglists")
        }
        var contributionOffset = 0L
        while (contributionOffset < section.size) {
            parseBudget.consume(".debug_rnglists contributions")
            val contribution = fullTreeDwarfRnglistsContribution(section, contributionOffset)
            if (targetOffset < contribution.endOffset) {
                validateRnglistsContribution(contribution)
                if (targetOffset < contribution.listsOffset) {
                    throw FullTreeControlException("DWARF range section offset points into a contribution header")
                }
                return contribution
            }
            contributionOffset = contribution.endOffset
        }
        throw FullTreeControlException("DWARF range section offset exceeds .debug_rnglists")
    }

    private fun validateRnglistsContribution(contribution: FullTreeDwarfRnglistsContribution) {
        if (contribution.offsetSize != offsetSize) {
            throw FullTreeControlException(".debug_rnglists contribution uses a different DWARF format")
        }
        if (contribution.addressSize != addressSize) {
            throw FullTreeControlException(".debug_rnglists contribution address size differs from its unit")
        }
        if (contribution.segmentSelectorSize != 0) {
            throw FullTreeControlException("segmented .debug_rnglists contributions are unsupported")
        }
    }
}

private data class FullTreeDwarfContribution(
    val offsetSize: Int,
    val bodyOffset: Long,
    val endOffset: Long,
)

private data class FullTreeDwarfRnglistsContribution(
    val offsetSize: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val entryCount: Long,
    val entriesOffset: Long,
    val listsOffset: Long,
    val endOffset: Long,
)

private fun fullTreeDwarfContribution(
    section: FullTreeDwarfSection,
    offset: Long,
    label: String,
): FullTreeDwarfContribution {
    val initialLength = section.readUnsigned(offset, 4)
    val offsetSize: Int
    val bodyOffset: Long
    val unitLength: Long
    when {
        initialLength == FULL_TREE_DWARF_64_MARKER -> {
            offsetSize = 8
            bodyOffset = fullTreeDwarfAdd(offset, 12L, label)
            unitLength = section.readUnsigned(fullTreeDwarfAdd(offset, 4L, label), 8)
        }
        initialLength in FULL_TREE_DWARF_RESERVED_LENGTH_MIN..FULL_TREE_DWARF_RESERVED_LENGTH_MAX ->
            throw FullTreeControlException("$label uses a reserved length")
        else -> {
            offsetSize = 4
            bodyOffset = fullTreeDwarfAdd(offset, 4L, label)
            unitLength = initialLength
        }
    }
    if (unitLength <= 0L || bodyOffset < 0L || bodyOffset > section.size - unitLength) {
        throw FullTreeControlException("$label length exceeds its section")
    }
    return FullTreeDwarfContribution(
        offsetSize = offsetSize,
        bodyOffset = bodyOffset,
        endOffset = fullTreeDwarfAdd(bodyOffset, unitLength, label),
    )
}

private fun fullTreeDwarfRnglistsContribution(
    section: FullTreeDwarfSection,
    offset: Long,
): FullTreeDwarfRnglistsContribution {
    val contribution = fullTreeDwarfContribution(section, offset, ".debug_rnglists contribution")
    val cursor = FullTreeDwarfSectionCursor(
        section,
        contribution.bodyOffset,
        contribution.endOffset,
        ".debug_rnglists contribution",
    )
    if (cursor.readUnsigned(2) != 5L) {
        throw FullTreeControlException(".debug_rnglists contribution version is unsupported")
    }
    val addressSize = cursor.readUnsigned(1).toInt()
    if (addressSize !in 1..16) {
        throw FullTreeControlException(".debug_rnglists contribution address size is invalid")
    }
    val segmentSelectorSize = cursor.readUnsigned(1).toInt()
    val entryCount = cursor.readUnsigned(4)
    val entryBytes = fullTreeDwarfMultiply(
        entryCount,
        contribution.offsetSize.toLong(),
        ".debug_rnglists offset table",
    )
    if (entryBytes > contribution.endOffset - cursor.position) {
        throw FullTreeControlException(".debug_rnglists offset table exceeds its contribution")
    }
    val entriesOffset = cursor.position
    cursor.skip(entryBytes)
    return FullTreeDwarfRnglistsContribution(
        offsetSize = contribution.offsetSize,
        addressSize = addressSize,
        segmentSelectorSize = segmentSelectorSize,
        entryCount = entryCount,
        entriesOffset = entriesOffset,
        listsOffset = cursor.position,
        endOffset = contribution.endOffset,
    )
}

/** Open, bounded logical DWARF sections. Compressed sections live until this owner is closed. */
internal class FullTreeDwarfSections private constructor(
    private val sections: Map<String, FullTreeDwarfSection>,
    private val scratch: FullTreeDwarfScratch,
) : AutoCloseable {
    fun required(name: String): FullTreeDwarfSection = sections[name]
        ?: throw FullTreeControlException("rich artifact lacks required $name")

    fun optional(name: String): FullTreeDwarfSection? = sections[name]

    override fun close() {
        var failure: Throwable? = null
        sections.values.distinct().forEach { section ->
            try {
                section.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure!!.addSuppressed(closeFailure)
            }
        }
        try {
            scratch.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure!!.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    companion object {
        /** The exact section set used by the frozen compilation-unit inventory v1 contract. */
        val COMPILATION_UNIT_SECTION_NAMES: List<String> = Collections.unmodifiableList(
            listOf(
                ".debug_info",
                ".debug_abbrev",
                ".debug_str",
                ".debug_line_str",
                ".debug_str_offsets",
            ),
        )

        /** Inventory sections plus the address/range inputs used by function observations. */
        val FUNCTION_OBSERVATION_SECTION_NAMES: List<String> = Collections.unmodifiableList(
            COMPILATION_UNIT_SECTION_NAMES + listOf(
                ".debug_line",
                ".debug_addr",
                ".debug_ranges",
                ".debug_rnglists",
            ),
        )

        fun open(
            artifact: StableControlFile,
            scratchParent: Path,
            limits: FullTreeControlLimits,
            logicalNames: List<String> = COMPILATION_UNIT_SECTION_NAMES,
            requiredNames: Set<String> = setOf(".debug_info", ".debug_abbrev"),
        ): FullTreeDwarfSections {
            val requested = logicalNames.toList()
            val required = requiredNames.toSet()
            if (requested.toSet().size != requested.size || required.any { it !in requested }) {
                throw FullTreeControlException("DWARF logical section request is inconsistent")
            }
            if (requested.any { !it.startsWith(".debug_") || it.length <= ".debug_".length }) {
                throw FullTreeControlException("DWARF logical section name is invalid")
            }

            val scratch = FullTreeDwarfScratch.create(scratchParent)
            val result = linkedMapOf<String, FullTreeDwarfSection>()
            try {
                val descriptors = FullTreeDwarfElfSections.read(artifact)
                val byName = descriptors.associateBy { it.name }
                var scratchBytes = 0L
                requested.forEach { logicalName ->
                    val descriptor = byName[logicalName] ?: byName[logicalName.replaceFirst(".debug_", ".zdebug_")]
                    if (descriptor != null) {
                        val opened = openSection(
                            artifact,
                            descriptor,
                            logicalName,
                            scratch,
                            limits.maximumDwarfScratchBytes - scratchBytes,
                            limits,
                        )
                        if (
                            descriptor.flags and FULL_TREE_SHF_COMPRESSED != 0L ||
                            descriptor.name.startsWith(".zdebug_")
                        ) {
                            scratchBytes = try {
                                Math.addExact(scratchBytes, opened.size)
                            } catch (overflow: ArithmeticException) {
                                throw FullTreeControlException("DWARF scratch size overflows", overflow)
                            }
                            if (scratchBytes > limits.maximumDwarfScratchBytes) {
                                throw FullTreeControlException("DWARF scratch exceeds its byte bound")
                            }
                        }
                        result[logicalName] = opened
                    }
                }
                required.forEach { name ->
                    if (name !in result) {
                        throw FullTreeControlException("rich artifact has no complete DWARF information")
                    }
                }
                return FullTreeDwarfSections(Collections.unmodifiableMap(result), scratch)
            } catch (failure: Throwable) {
                result.values.forEach { section ->
                    try {
                        section.close()
                    } catch (closeFailure: Throwable) {
                        failure.addSuppressed(closeFailure)
                    }
                }
                try {
                    scratch.close()
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }

        private fun openSection(
            artifact: StableControlFile,
            descriptor: FullTreeDwarfElfSection,
            logicalName: String,
            scratch: FullTreeDwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): FullTreeDwarfSection {
            if (descriptor.size <= 0L || descriptor.size > limits.maximumDwarfSectionBytes) {
                throw FullTreeControlException("$logicalName exceeds its compressed section bound")
            }
            if (descriptor.type == FULL_TREE_SHT_NOBITS) {
                throw FullTreeControlException("$logicalName is not file-backed")
            }
            return when {
                descriptor.flags and FULL_TREE_SHF_COMPRESSED != 0L -> decompressElfSection(
                    artifact,
                    descriptor,
                    logicalName,
                    scratch,
                    remainingScratchBytes,
                    limits,
                )
                descriptor.name.startsWith(".zdebug_") -> decompressGnuSection(
                    artifact,
                    descriptor,
                    logicalName,
                    scratch,
                    remainingScratchBytes,
                    limits,
                )
                else -> FullTreeDwarfSection(
                    size = descriptor.size,
                    byteOrder = descriptor.byteOrder,
                    label = logicalName,
                    readWindow = { offset, length ->
                        artifact.readExactly(
                            Math.addExact(descriptor.offset, offset),
                            length,
                            logicalName,
                        )
                    },
                )
            }
        }

        private fun decompressElfSection(
            artifact: StableControlFile,
            descriptor: FullTreeDwarfElfSection,
            label: String,
            scratch: FullTreeDwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): FullTreeDwarfSection {
            val headerSize = if (descriptor.elfClass == FULL_TREE_ELF_CLASS_64) 24 else 12
            if (descriptor.size <= headerSize.toLong()) {
                throw FullTreeControlException("$label compression header is truncated")
            }
            val header = artifact.readExactly(descriptor.offset, headerSize, "$label compression header")
            val buffer = ByteBuffer.wrap(header).order(descriptor.byteOrder)
            val type = buffer.int.toLong() and FULL_TREE_UINT32_MASK
            if (type != FULL_TREE_ELFCOMPRESS_ZLIB) {
                throw FullTreeControlException("$label uses unsupported ELF compression")
            }
            val expanded = if (descriptor.elfClass == FULL_TREE_ELF_CLASS_64) {
                buffer.int // reserved
                fullTreeDwarfUnsignedLong(buffer.long, "$label expanded size")
            } else {
                buffer.int.toLong() and FULL_TREE_UINT32_MASK
            }
            return inflate(
                artifact.slice(
                    Math.addExact(descriptor.offset, headerSize.toLong()),
                    descriptor.size - headerSize,
                ),
                expanded,
                label,
                descriptor.byteOrder,
                scratch,
                remainingScratchBytes,
                limits,
            )
        }

        private fun decompressGnuSection(
            artifact: StableControlFile,
            descriptor: FullTreeDwarfElfSection,
            label: String,
            scratch: FullTreeDwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): FullTreeDwarfSection {
            if (descriptor.size <= FULL_TREE_GNU_ZLIB_HEADER_BYTES) {
                throw FullTreeControlException("$label GNU compression header is truncated")
            }
            val header = artifact.readExactly(
                descriptor.offset,
                FULL_TREE_GNU_ZLIB_HEADER_BYTES.toInt(),
                "$label GNU compression header",
            )
            if (!header.copyOfRange(0, 4).contentEquals("ZLIB".toByteArray(StandardCharsets.US_ASCII))) {
                throw FullTreeControlException("$label GNU compression header is invalid")
            }
            val expanded = fullTreeDwarfUnsignedLong(
                ByteBuffer.wrap(header, 4, 8).order(ByteOrder.BIG_ENDIAN).long,
                "$label size",
            )
            return inflate(
                artifact.slice(
                    descriptor.offset + FULL_TREE_GNU_ZLIB_HEADER_BYTES,
                    descriptor.size - FULL_TREE_GNU_ZLIB_HEADER_BYTES,
                ),
                expanded,
                label,
                descriptor.byteOrder,
                scratch,
                remainingScratchBytes,
                limits,
            )
        }

        private fun inflate(
            compressed: InputStream,
            expandedSize: Long,
            label: String,
            byteOrder: ByteOrder,
            scratch: FullTreeDwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): FullTreeDwarfSection {
            if (expandedSize !in 1L..limits.maximumDwarfSectionBytes) {
                throw FullTreeControlException("$label expanded size exceeds its bound")
            }
            if (expandedSize > remainingScratchBytes) {
                throw FullTreeControlException("DWARF scratch exceeds its aggregate byte bound")
            }
            val output = scratch.createFile(label)
            try {
                InflaterInputStream(compressed).use { inflated ->
                    val bytes = ByteArray(64 * 1024)
                    var written = 0L
                    while (true) {
                        val read = inflated.read(bytes)
                        if (read < 0) break
                        written = Math.addExact(written, read.toLong())
                        if (written > expandedSize) {
                            throw FullTreeControlException("$label expands beyond its declared size")
                        }
                        val source = ByteBuffer.wrap(bytes, 0, read)
                        while (source.hasRemaining()) output.write(source)
                    }
                    if (written != expandedSize) {
                        throw FullTreeControlException("$label expanded size differs from its ELF header")
                    }
                }
                output.force(true)
                return FullTreeDwarfSection(
                    size = expandedSize,
                    byteOrder = byteOrder,
                    label = label,
                    readWindow = { offset, length ->
                        val bytes = ByteArray(length)
                        val destination = ByteBuffer.wrap(bytes)
                        var position = offset
                        while (destination.hasRemaining()) {
                            val read = output.read(destination, position)
                            if (read <= 0) {
                                throw FullTreeControlException("$label scratch section ended early")
                            }
                            position += read.toLong()
                        }
                        bytes
                    },
                    closeAction = { output.close() },
                )
            } catch (failure: Throwable) {
                try {
                    output.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                }
                throw failure
            }
        }
    }
}

/** Bounded random-access section backed by authenticated input or an owned scratch file. */
internal class FullTreeDwarfSection(
    val size: Long,
    val byteOrder: ByteOrder,
    private val label: String,
    private val readWindow: (Long, Int) -> ByteArray,
    private val closeAction: () -> Unit = {},
) : AutoCloseable {
    private var cachedOffset = -1L
    private var cached = ByteArray(0)

    init {
        if (size <= 0L) throw FullTreeControlException("$label must not be empty")
        if (label.isEmpty()) throw FullTreeControlException("DWARF section label must not be empty")
    }

    fun byte(offset: Long): Int {
        if (offset < 0L || offset >= size) {
            throw FullTreeControlException("$label read exceeds its section")
        }
        val cachedIndex = if (cachedOffset < 0L) -1L else offset - cachedOffset
        if (cachedIndex < 0L || cachedIndex >= cached.size.toLong()) {
            val length = minOf(FULL_TREE_DWARF_WINDOW_BYTES.toLong(), size - offset).toInt()
            val loaded = try {
                readWindow(offset, length)
            } catch (failure: FullTreeControlException) {
                throw failure
            } catch (failure: Exception) {
                throw FullTreeControlException("$label backing read failed", failure)
            }
            if (loaded.size != length) {
                throw FullTreeControlException("$label backing read returned a partial or oversized window")
            }
            cachedOffset = offset
            cached = loaded.copyOf()
        }
        return cached[(offset - cachedOffset).toInt()].toInt() and 0xff
    }

    fun readUnsigned(offset: Long, width: Int): Long {
        val cursor = FullTreeDwarfSectionCursor(this, offset, size, "DWARF section offset")
        return cursor.readUnsigned(width)
    }

    fun readAddress(offset: Long, width: Int): ULong {
        val cursor = FullTreeDwarfSectionCursor(this, offset, size, "DWARF address section offset")
        return cursor.readAddress(width)
    }

    fun readNullTerminated(offset: Long, maximumBytes: Int): ByteArray {
        val cursor = FullTreeDwarfSectionCursor(this, offset, size, "DWARF string section")
        return cursor.readNullTerminated(maximumBytes)
    }

    override fun close() = closeAction()
}

/** Mutable cursor whose every read is constrained to a caller-selected subrange of one section. */
internal class FullTreeDwarfSectionCursor(
    private val section: FullTreeDwarfSection,
    initialPosition: Long,
    initialLimit: Long,
    private val label: String,
) {
    var position: Long = initialPosition
        private set
    var limit: Long = initialLimit
        private set

    init {
        if (initialPosition < 0L || initialLimit < initialPosition || initialLimit > section.size) {
            throw FullTreeControlException("$label cursor range is outside its section")
        }
    }

    fun narrowLimit(newLimit: Long) {
        if (newLimit < position || newLimit > limit) {
            throw FullTreeControlException("$label cursor limit may only be narrowed after its position")
        }
        limit = newLimit
    }

    fun readUnsigned(width: Int): Long {
        val value = readUnsignedBits(width)
        if (value > Long.MAX_VALUE.toULong()) {
            throw FullTreeControlException("$label unsigned integer exceeds the supported range")
        }
        return value.toLong()
    }

    /** Reads an unsigned fixed-width operand without losing the high bit of a 64-bit value. */
    fun readUnsignedBits(width: Int): ULong {
        if (width !in 1..8) throw FullTreeControlException("$label integer width is invalid")
        requireAvailable(width.toLong())
        var value = 0UL
        repeat(width) { index ->
            val significantIndex = if (section.byteOrder == ByteOrder.LITTLE_ENDIAN) index else width - index - 1
            value = value or (section.byte(position + index).toULong() shl (significantIndex * 8))
        }
        position += width.toLong()
        return value
    }

    /** Reads the CU address width, rejecting values that cannot be represented as a JVM ULong. */
    fun readAddress(width: Int): ULong {
        if (width !in 1..16) throw FullTreeControlException("$label address width is invalid")
        return readWideUnsigned(width, "address")
    }

    /** Reads DW_FORM_data16 through the CU byte order, rejecting a nonzero high half. */
    fun readData16(): ULong = readWideUnsigned(16, "DW_FORM_data16")

    private fun readWideUnsigned(width: Int, description: String): ULong {
        requireAvailable(width.toLong())
        var value = 0UL
        repeat(width) { index ->
            val significantIndex = if (section.byteOrder == ByteOrder.LITTLE_ENDIAN) index else width - index - 1
            val byte = section.byte(position + index)
            if (significantIndex >= 8) {
                if (byte != 0) {
                    throw FullTreeControlException("$label $description exceeds the supported range")
                }
            } else {
                value = value or (byte.toULong() shl (significantIndex * 8))
            }
        }
        position += width.toLong()
        return value
    }

    fun readUleb128(): Long {
        val value = readUleb128Bits()
        if (value > Long.MAX_VALUE.toULong()) {
            throw FullTreeControlException("$label ULEB128 exceeds the supported range")
        }
        return value.toLong()
    }

    /** Reads the complete unsigned 64-bit ULEB128 domain for typed unsigned operands. */
    fun readUleb128Bits(): ULong {
        var value = 0UL
        var shift = 0
        repeat(10) { index ->
            requireAvailable(1L)
            val byte = section.byte(position++)
            val payload = (byte and 0x7f).toULong()
            if (index == 9 && payload > 1UL) throw FullTreeControlException("$label ULEB128 overflows")
            if (shift < 64) value = value or (payload shl shift)
            if (byte and 0x80 == 0) {
                return value
            }
            shift += 7
        }
        throw FullTreeControlException("$label ULEB128 is unterminated")
    }

    fun readSleb128(): Long {
        var value = 0L
        var shift = 0
        var byte: Int
        repeat(10) { index ->
            requireAvailable(1L)
            byte = section.byte(position++)
            val payload = byte and 0x7f
            if (index == 9 && payload !in setOf(0, 0x7f)) {
                throw FullTreeControlException("$label SLEB128 overflows")
            }
            if (shift < 64) value = value or (payload.toLong() shl shift)
            shift += 7
            if (byte and 0x80 == 0) {
                if (shift < 64 && byte and 0x40 != 0) value = value or (-1L shl shift)
                return value
            }
        }
        throw FullTreeControlException("$label SLEB128 is unterminated")
    }

    fun readNullTerminated(maximumBytes: Int): ByteArray {
        val result = java.io.ByteArrayOutputStream(minOf(maximumBytes, 4096))
        repeat(maximumBytes + 1) {
            requireAvailable(1L)
            val byte = section.byte(position++)
            if (byte == 0) return result.toByteArray()
            if (result.size() == maximumBytes) {
                throw FullTreeControlException("$label string exceeds its byte bound")
            }
            result.write(byte)
        }
        throw FullTreeControlException("$label string is unterminated")
    }

    fun skip(bytes: Long) {
        requireAvailable(bytes)
        position += bytes
    }

    fun skipBounded(bytes: Long, maximumBytes: Int) {
        if (bytes !in 0L..maximumBytes.toLong()) {
            throw FullTreeControlException("$label block exceeds its byte bound")
        }
        skip(bytes)
    }

    private fun requireAvailable(bytes: Long) {
        if (bytes < 0L || position < 0L || position > limit - bytes) {
            throw FullTreeControlException("$label is truncated")
        }
    }
}

private object FullTreeDwarfElfSections {
    fun read(file: StableControlFile): List<FullTreeDwarfElfSection> {
        if (file.size < 64L) throw FullTreeControlException("rich artifact ELF header is truncated")
        val identification = file.readExactly(0L, 16, "ELF identification")
        if (
            !identification.copyOfRange(0, 4).contentEquals(
                byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()),
            )
        ) {
            throw FullTreeControlException("rich artifact is not ELF")
        }
        val elfClass = identification[4].toInt() and 0xff
        if (elfClass !in setOf(FULL_TREE_ELF_CLASS_32, FULL_TREE_ELF_CLASS_64)) {
            throw FullTreeControlException("rich artifact ELF class is unsupported")
        }
        val byteOrder = when (identification[5].toInt() and 0xff) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw FullTreeControlException("rich artifact ELF byte order is unsupported")
        }
        val headerBytes = if (elfClass == FULL_TREE_ELF_CLASS_64) 64 else 52
        val header = ByteBuffer.wrap(file.readExactly(0L, headerBytes, "ELF header")).order(byteOrder)
        val sectionOffset = if (elfClass == FULL_TREE_ELF_CLASS_64) {
            fullTreeDwarfUnsignedLong(header.getLong(40), "ELF section offset")
        } else {
            header.getInt(32).toLong() and FULL_TREE_UINT32_MASK
        }
        val entrySize = header.getShort(if (elfClass == FULL_TREE_ELF_CLASS_64) 58 else 46).toInt() and 0xffff
        var sectionCount = header.getShort(if (elfClass == FULL_TREE_ELF_CLASS_64) 60 else 48).toInt() and 0xffff
        var nameIndex = header.getShort(if (elfClass == FULL_TREE_ELF_CLASS_64) 62 else 50).toInt() and 0xffff
        val minimumEntrySize = if (elfClass == FULL_TREE_ELF_CLASS_64) 64 else 40
        if (sectionOffset <= 0L || entrySize < minimumEntrySize) {
            throw FullTreeControlException("rich artifact ELF section table is malformed")
        }
        val sectionZero = readHeader(file, sectionOffset, entrySize, elfClass, byteOrder, 0)
        if (sectionCount == 0) {
            if (sectionZero.size !in 1L..FULL_TREE_MAXIMUM_ELF_SECTIONS.toLong()) {
                throw FullTreeControlException("rich artifact ELF section count is invalid")
            }
            sectionCount = sectionZero.size.toInt()
        }
        if (nameIndex == FULL_TREE_SHN_XINDEX) {
            if (sectionZero.link !in 0 until sectionCount) {
                throw FullTreeControlException("rich artifact ELF section-name index is invalid")
            }
            nameIndex = sectionZero.link
        }
        if (sectionCount !in 1..FULL_TREE_MAXIMUM_ELF_SECTIONS || nameIndex !in 0 until sectionCount) {
            throw FullTreeControlException("rich artifact ELF section count or name table is invalid")
        }
        val tableBytes = try {
            Math.multiplyExact(sectionCount.toLong(), entrySize.toLong())
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("rich artifact ELF section table overflows", failure)
        }
        if (sectionOffset > file.size - tableBytes) {
            throw FullTreeControlException("rich artifact ELF section table exceeds the file")
        }
        val raw = (0 until sectionCount).map { index ->
            readHeader(
                file,
                Math.addExact(sectionOffset, Math.multiplyExact(index.toLong(), entrySize.toLong())),
                entrySize,
                elfClass,
                byteOrder,
                index,
            )
        }
        val names = raw[nameIndex]
        if (names.type == FULL_TREE_SHT_NOBITS || names.offset > file.size - names.size) {
            throw FullTreeControlException("rich artifact ELF section-name table is invalid")
        }
        val nameSection = FullTreeDwarfSection(
            size = names.size,
            byteOrder = byteOrder,
            label = "ELF section-name table",
            readWindow = { offset, length ->
                file.readExactly(Math.addExact(names.offset, offset), length, "ELF section-name table")
            },
        )
        val seen = HashSet<String>()
        return raw.map { section ->
            val nameBytes = nameSection.readNullTerminated(
                section.nameOffset,
                FULL_TREE_MAXIMUM_ELF_SECTION_NAME_BYTES,
            )
            val name = try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nameBytes)).toString()
            } catch (failure: Exception) {
                throw FullTreeControlException("ELF section name is not UTF-8", failure)
            }
            if (name.isNotEmpty() && !seen.add(name)) {
                throw FullTreeControlException("rich artifact ELF section names are duplicated")
            }
            if (section.type != FULL_TREE_SHT_NOBITS && section.offset > file.size - section.size) {
                throw FullTreeControlException("rich artifact ELF section $name exceeds the file")
            }
            section.copy(name = name)
        }
    }

    private fun readHeader(
        file: StableControlFile,
        offset: Long,
        entrySize: Int,
        elfClass: Int,
        byteOrder: ByteOrder,
        index: Int,
    ): FullTreeDwarfElfSection {
        val buffer = ByteBuffer.wrap(
            file.readExactly(offset, entrySize, "ELF section header $index"),
        ).order(byteOrder)
        val nameOffset = buffer.int.toLong() and FULL_TREE_UINT32_MASK
        val type = buffer.int.toLong() and FULL_TREE_UINT32_MASK
        val flags: Long
        val sectionOffset: Long
        val size: Long
        val link: Int
        if (elfClass == FULL_TREE_ELF_CLASS_64) {
            flags = fullTreeDwarfUnsignedLong(buffer.long, "ELF section flags")
            buffer.long // address
            sectionOffset = fullTreeDwarfUnsignedLong(buffer.long, "ELF section file offset")
            size = fullTreeDwarfUnsignedLong(buffer.long, "ELF section size")
            link = buffer.int
        } else {
            flags = buffer.int.toLong() and FULL_TREE_UINT32_MASK
            buffer.int // address
            sectionOffset = buffer.int.toLong() and FULL_TREE_UINT32_MASK
            size = buffer.int.toLong() and FULL_TREE_UINT32_MASK
            link = buffer.int
        }
        return FullTreeDwarfElfSection(
            name = "",
            nameOffset = nameOffset,
            type = type,
            flags = flags,
            offset = sectionOffset,
            size = size,
            link = link,
            elfClass = elfClass,
            byteOrder = byteOrder,
        )
    }
}

private data class FullTreeDwarfElfSection(
    val name: String,
    val nameOffset: Long,
    val type: Long,
    val flags: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val elfClass: Int,
    val byteOrder: ByteOrder,
)

/** Owner for decompressed-section scratch files, with identity-checked cleanup. */
internal class FullTreeDwarfScratch private constructor(
    private val root: Path,
    private val identity: Any,
) : AutoCloseable {
    private val files = linkedMapOf<Path, Any>()
    private var closed = false

    fun createFile(label: String): FileChannel {
        val path = Files.createTempFile(root, ".section-", ".bin")
        var tracked = false
        try {
            val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (!attributes.isRegularFile || attributes.isSymbolicLink) {
                throw FullTreeControlException("$label scratch path is not a regular file")
            }
            val fileIdentity = attributes.fileKey()
                ?: throw FullTreeControlException("$label scratch file has no stable identity")
            files[path] = fileIdentity
            tracked = true
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            return FileChannel.open(
                path,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            )
        } catch (failure: Throwable) {
            if (!tracked) {
                try {
                    Files.deleteIfExists(path)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
            }
            throw failure
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            throw FullTreeControlException("DWARF scratch directory disappeared before close")
        }
        val current = Files.readAttributes(root, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!current.isDirectory || current.isSymbolicLink || current.fileKey() != identity) {
            throw FullTreeControlException("DWARF scratch directory changed identity")
        }
        val actual = Files.walk(root).use { it.toList().toSet() }
        val expected = files.keys.toMutableSet().apply { add(root) }
        if (actual != expected) {
            throw FullTreeControlException("DWARF scratch directory contains an unexpected path")
        }
        var failure: Throwable? = null
        files.forEach { (path, expectedIdentity) ->
            try {
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (
                    !attributes.isRegularFile || attributes.isSymbolicLink ||
                    attributes.fileKey() != expectedIdentity
                ) {
                    throw FullTreeControlException("DWARF scratch file changed identity")
                }
                Files.delete(path)
            } catch (cleanupFailure: Throwable) {
                if (failure == null) failure = cleanupFailure else failure!!.addSuppressed(cleanupFailure)
            }
        }
        try {
            Files.delete(root)
        } catch (cleanupFailure: Throwable) {
            if (failure == null) failure = cleanupFailure else failure!!.addSuppressed(cleanupFailure)
        }
        failure?.let { throw it }
        closed = true
    }

    companion object {
        fun create(parent: Path): FullTreeDwarfScratch {
            val (trusted, _) = requireStableDirectory(parent, "DWARF scratch parent")
            val root = Files.createTempDirectory(trusted, ".full-tree-inventory-scratch-")
            try {
                val attributes = Files.readAttributes(root, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (!attributes.isDirectory || attributes.isSymbolicLink) {
                    throw FullTreeControlException("DWARF scratch path is not a directory")
                }
                val identity = attributes.fileKey()
                    ?: throw FullTreeControlException("DWARF scratch directory has no stable identity")
                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
                return FullTreeDwarfScratch(root, identity)
            } catch (failure: Throwable) {
                try {
                    Files.deleteIfExists(root)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }
    }
}

private fun fullTreeDwarfUnsignedLong(value: Long, label: String): Long {
    if (value < 0L) throw FullTreeControlException("$label exceeds the supported range")
    return value
}

private fun fullTreeDwarfBoundedLong(value: ULong, label: String): Long {
    if (value > Long.MAX_VALUE.toULong()) {
        throw FullTreeControlException("$label exceeds the supported range")
    }
    return value.toLong()
}

private fun fullTreeDwarfAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label overflows", failure)
}

private fun fullTreeDwarfMultiply(left: Long, right: Long, label: String): Long = try {
    Math.multiplyExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label overflows", failure)
}

private const val FULL_TREE_ELF_CLASS_32 = 1
private const val FULL_TREE_ELF_CLASS_64 = 2
private const val FULL_TREE_SHT_NOBITS = 8L
private const val FULL_TREE_SHF_COMPRESSED = 0x800L
private const val FULL_TREE_ELFCOMPRESS_ZLIB = 1L
private const val FULL_TREE_SHN_XINDEX = 0xffff
private const val FULL_TREE_MAXIMUM_ELF_SECTIONS = 1_000_000
private const val FULL_TREE_MAXIMUM_ELF_SECTION_NAME_BYTES = 4096
private const val FULL_TREE_MAXIMUM_DWARF_STRING_CHARACTERS = 16_384
private const val FULL_TREE_DWARF_WINDOW_BYTES = 64 * 1024
private const val FULL_TREE_GNU_ZLIB_HEADER_BYTES = 12L
private const val FULL_TREE_UINT32_MASK = 0xffff_ffffL
private const val FULL_TREE_DWARF_64_MARKER = 0xffff_ffffL
private const val FULL_TREE_DWARF_RESERVED_LENGTH_MIN = 0xffff_fff0L
private const val FULL_TREE_DWARF_RESERVED_LENGTH_MAX = 0xffff_fffeL

internal const val FULL_TREE_DW_UT_COMPILE = 0x01
internal const val FULL_TREE_DW_UT_TYPE = 0x02
internal const val FULL_TREE_DW_UT_PARTIAL = 0x03
internal const val FULL_TREE_DW_UT_SKELETON = 0x04
internal const val FULL_TREE_DW_UT_SPLIT_COMPILE = 0x05
internal const val FULL_TREE_DW_UT_SPLIT_TYPE = 0x06

internal const val FULL_TREE_DW_FORM_ADDR = 0x01L
internal const val FULL_TREE_DW_FORM_BLOCK2 = 0x03L
internal const val FULL_TREE_DW_FORM_BLOCK4 = 0x04L
internal const val FULL_TREE_DW_FORM_DATA2 = 0x05L
internal const val FULL_TREE_DW_FORM_DATA4 = 0x06L
internal const val FULL_TREE_DW_FORM_DATA8 = 0x07L
internal const val FULL_TREE_DW_FORM_STRING = 0x08L
internal const val FULL_TREE_DW_FORM_BLOCK = 0x09L
internal const val FULL_TREE_DW_FORM_BLOCK1 = 0x0aL
internal const val FULL_TREE_DW_FORM_DATA1 = 0x0bL
internal const val FULL_TREE_DW_FORM_FLAG = 0x0cL
internal const val FULL_TREE_DW_FORM_SDATA = 0x0dL
internal const val FULL_TREE_DW_FORM_STRP = 0x0eL
internal const val FULL_TREE_DW_FORM_UDATA = 0x0fL
internal const val FULL_TREE_DW_FORM_REF_ADDR = 0x10L
internal const val FULL_TREE_DW_FORM_REF1 = 0x11L
internal const val FULL_TREE_DW_FORM_REF2 = 0x12L
internal const val FULL_TREE_DW_FORM_REF4 = 0x13L
internal const val FULL_TREE_DW_FORM_REF8 = 0x14L
internal const val FULL_TREE_DW_FORM_REF_UDATA = 0x15L
internal const val FULL_TREE_DW_FORM_INDIRECT = 0x16L
internal const val FULL_TREE_DW_FORM_SEC_OFFSET = 0x17L
internal const val FULL_TREE_DW_FORM_EXPRLOC = 0x18L
internal const val FULL_TREE_DW_FORM_FLAG_PRESENT = 0x19L
internal const val FULL_TREE_DW_FORM_STRX = 0x1aL
internal const val FULL_TREE_DW_FORM_ADDRX = 0x1bL
internal const val FULL_TREE_DW_FORM_REF_SUP4 = 0x1cL
internal const val FULL_TREE_DW_FORM_STRP_SUP = 0x1dL
internal const val FULL_TREE_DW_FORM_DATA16 = 0x1eL
internal const val FULL_TREE_DW_FORM_LINE_STRP = 0x1fL
internal const val FULL_TREE_DW_FORM_REF_SIG8 = 0x20L
internal const val FULL_TREE_DW_FORM_IMPLICIT_CONST = 0x21L
internal const val FULL_TREE_DW_FORM_LOCLISTX = 0x22L
internal const val FULL_TREE_DW_FORM_RNGLISTX = 0x23L
internal const val FULL_TREE_DW_FORM_REF_SUP8 = 0x24L
internal const val FULL_TREE_DW_FORM_STRX1 = 0x25L
internal const val FULL_TREE_DW_FORM_STRX2 = 0x26L
internal const val FULL_TREE_DW_FORM_STRX3 = 0x27L
internal const val FULL_TREE_DW_FORM_STRX4 = 0x28L
internal const val FULL_TREE_DW_FORM_ADDRX1 = 0x29L
internal const val FULL_TREE_DW_FORM_ADDRX2 = 0x2aL
internal const val FULL_TREE_DW_FORM_ADDRX3 = 0x2bL
internal const val FULL_TREE_DW_FORM_ADDRX4 = 0x2cL
internal const val FULL_TREE_DW_FORM_GNU_ADDR_INDEX = 0x1f01L
internal const val FULL_TREE_DW_FORM_GNU_STR_INDEX = 0x1f02L
internal const val FULL_TREE_DW_FORM_GNU_REF_ALT = 0x1f20L
internal const val FULL_TREE_DW_FORM_GNU_STRP_ALT = 0x1f21L

private val FULL_TREE_DWARF_ADDRESS_INDEX_FORMS = setOf(
    FULL_TREE_DW_FORM_ADDRX,
    FULL_TREE_DW_FORM_ADDRX1,
    FULL_TREE_DW_FORM_ADDRX2,
    FULL_TREE_DW_FORM_ADDRX3,
    FULL_TREE_DW_FORM_ADDRX4,
)

private val FULL_TREE_DWARF_REFERENCE_FORMS = setOf(
    FULL_TREE_DW_FORM_REF_ADDR,
    FULL_TREE_DW_FORM_REF1,
    FULL_TREE_DW_FORM_REF2,
    FULL_TREE_DW_FORM_REF4,
    FULL_TREE_DW_FORM_REF8,
    FULL_TREE_DW_FORM_REF_UDATA,
)

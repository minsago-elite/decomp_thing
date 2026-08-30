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

    fun consume(label: String) {
        consumed++
        if (consumed > limit) {
            throw FullTreeControlException("aggregate parse-step bound exceeded while reading $label")
        }
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
        if (info !== originatingSection) {
            throw FullTreeControlException("DWARF compilation-unit cursor uses a different .debug_info section")
        }
        return FullTreeDwarfSectionCursor(info, firstDieOffset, endOffset, "DWARF compilation unit")
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
    ): FullTreeDwarfFormValue {
        if (indirectDepth > 4) throw FullTreeControlException("DWARF indirect form nesting is excessive")
        return when (form) {
            FULL_TREE_DW_FORM_ADDR -> cursor.skip(addressSize.toLong()).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_BLOCK2 -> cursor.readUnsigned(2).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_BLOCK4 -> cursor.readUnsigned(4).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_DATA2 -> FullTreeDwarfNumericValue(cursor.readUnsigned(2))
            FULL_TREE_DW_FORM_DATA4 -> FullTreeDwarfNumericValue(cursor.readUnsigned(4))
            FULL_TREE_DW_FORM_DATA8 -> FullTreeDwarfNumericValue(cursor.readUnsigned(8))
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
            FULL_TREE_DW_FORM_DATA1 -> FullTreeDwarfNumericValue(cursor.readUnsigned(1))
            FULL_TREE_DW_FORM_FLAG -> FullTreeDwarfNumericValue(cursor.readUnsigned(1))
            FULL_TREE_DW_FORM_SDATA -> FullTreeDwarfNumericValue(cursor.readSleb128())
            FULL_TREE_DW_FORM_STRP -> FullTreeDwarfSectionStringValue(
                ".debug_str",
                cursor.readUnsigned(offsetSize),
            )
            FULL_TREE_DW_FORM_UDATA -> FullTreeDwarfNumericValue(cursor.readUleb128())
            FULL_TREE_DW_FORM_REF_ADDR -> cursor.skip(
                if (version <= 2) addressSize.toLong() else offsetSize.toLong(),
            ).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF1 -> cursor.skip(1L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF2 -> cursor.skip(2L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF4, FULL_TREE_DW_FORM_REF_SUP4 ->
                cursor.skip(4L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF8, FULL_TREE_DW_FORM_REF_SIG8, FULL_TREE_DW_FORM_REF_SUP8 ->
                cursor.skip(8L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_REF_UDATA, FULL_TREE_DW_FORM_ADDRX, FULL_TREE_DW_FORM_LOCLISTX,
            FULL_TREE_DW_FORM_RNGLISTX, FULL_TREE_DW_FORM_GNU_ADDR_INDEX ->
                cursor.readUleb128().let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_INDIRECT -> read(
                cursor,
                cursor.readUleb128(),
                null,
                version,
                addressSize,
                offsetSize,
                limits,
                indirectDepth + 1,
            )
            FULL_TREE_DW_FORM_SEC_OFFSET -> FullTreeDwarfNumericValue(cursor.readUnsigned(offsetSize))
            FULL_TREE_DW_FORM_EXPRLOC -> cursor.readUleb128().let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                FullTreeDwarfIgnoredValue
            }
            FULL_TREE_DW_FORM_FLAG_PRESENT -> FullTreeDwarfNumericValue(1L)
            FULL_TREE_DW_FORM_STRX, FULL_TREE_DW_FORM_GNU_STR_INDEX ->
                FullTreeDwarfIndexedStringValue(cursor.readUleb128())
            FULL_TREE_DW_FORM_STRP_SUP, FULL_TREE_DW_FORM_GNU_STRP_ALT ->
                FullTreeDwarfUnsupportedExternalStringValue.also { cursor.skip(offsetSize.toLong()) }
            FULL_TREE_DW_FORM_DATA16 -> cursor.skip(16L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_LINE_STRP -> FullTreeDwarfSectionStringValue(
                ".debug_line_str",
                cursor.readUnsigned(offsetSize),
            )
            FULL_TREE_DW_FORM_IMPLICIT_CONST -> FullTreeDwarfNumericValue(
                implicitConstant ?: throw FullTreeControlException("DWARF implicit constant is absent"),
            )
            FULL_TREE_DW_FORM_STRX1 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(1))
            FULL_TREE_DW_FORM_STRX2 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(2))
            FULL_TREE_DW_FORM_STRX3 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(3))
            FULL_TREE_DW_FORM_STRX4 -> FullTreeDwarfIndexedStringValue(cursor.readUnsigned(4))
            FULL_TREE_DW_FORM_ADDRX1 -> cursor.skip(1L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_ADDRX2 -> cursor.skip(2L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_ADDRX3 -> cursor.skip(3L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_ADDRX4 -> cursor.skip(4L).let { FullTreeDwarfIgnoredValue }
            FULL_TREE_DW_FORM_GNU_REF_ALT -> cursor.skip(offsetSize.toLong()).let { FullTreeDwarfIgnoredValue }
            else -> throw FullTreeControlException(
                "DWARF attribute uses unsupported form 0x${form.toString(16)}",
            )
        }
    }

    fun decodeString(
        value: FullTreeDwarfFormValue,
        sections: FullTreeDwarfSections,
        stringOffsetsBase: Long?,
        offsetSize: Int,
        limits: FullTreeControlLimits,
        label: String,
    ): String {
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
        if (decoded.isEmpty() || '\u0000' in decoded || decoded.codePointCount(0, decoded.length) > 4096) {
            throw FullTreeControlException("$label is empty, contains NUL, or exceeds 4096 characters")
        }
        return decoded
    }
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
        if (width !in 1..8) throw FullTreeControlException("$label integer width is invalid")
        requireAvailable(width.toLong())
        var value = 0UL
        repeat(width) { index ->
            val significantIndex = if (section.byteOrder == ByteOrder.LITTLE_ENDIAN) index else width - index - 1
            value = value or (section.byte(position + index).toULong() shl (significantIndex * 8))
        }
        position += width.toLong()
        if (value > Long.MAX_VALUE.toULong()) {
            throw FullTreeControlException("$label unsigned integer exceeds the supported range")
        }
        return value.toLong()
    }

    fun readUleb128(): Long {
        var value = 0UL
        var shift = 0
        repeat(10) { index ->
            requireAvailable(1L)
            val byte = section.byte(position++)
            val payload = (byte and 0x7f).toULong()
            if (index == 9 && payload > 1UL) throw FullTreeControlException("$label ULEB128 overflows")
            if (shift < 64) value = value or (payload shl shift)
            if (byte and 0x80 == 0) {
                if (value > Long.MAX_VALUE.toULong()) {
                    throw FullTreeControlException("$label ULEB128 exceeds the supported range")
                }
                return value.toLong()
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

private const val FULL_TREE_ELF_CLASS_32 = 1
private const val FULL_TREE_ELF_CLASS_64 = 2
private const val FULL_TREE_SHT_NOBITS = 8L
private const val FULL_TREE_SHF_COMPRESSED = 0x800L
private const val FULL_TREE_ELFCOMPRESS_ZLIB = 1L
private const val FULL_TREE_SHN_XINDEX = 0xffff
private const val FULL_TREE_MAXIMUM_ELF_SECTIONS = 1_000_000
private const val FULL_TREE_MAXIMUM_ELF_SECTION_NAME_BYTES = 4096
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

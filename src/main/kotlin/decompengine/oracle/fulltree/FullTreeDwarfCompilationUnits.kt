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
import java.util.zip.InflaterInputStream

internal data class FullTreeDwarfCompilationUnit(
    val offset: Long,
    val version: Int,
    val addressSize: Int,
    val rawPath: String,
    val producer: String?,
    val language: Long?,
)

/** Bounded ELF/DWARF reader for the compilation-unit metadata used by inventory v1. */
internal object FullTreeDwarfCompilationUnits {
    fun read(
        artifact: StableControlFile,
        scratchParent: Path,
        scope: kotlinx.serialization.json.JsonObject,
        limits: FullTreeControlLimits,
    ): List<FullTreeDwarfCompilationUnit> {
        val authenticatedLimit = scope.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        val maximumUnits = minOf(authenticatedLimit, limits.maximumCompilationUnits.toLong())
        DwarfSections.open(artifact, scratchParent, limits).use { sections ->
            val info = sections.required(".debug_info")
            val abbrev = sections.required(".debug_abbrev")
            val result = arrayListOf<FullTreeDwarfCompilationUnit>()
            var unitOffset = 0L
            var metadataBytes = 0L
            val parseBudget = DwarfParseBudget(limits.maximumDwarfParseSteps)
            while (unitOffset < info.size) {
                parseBudget.consume("DWARF compilation units")
                if (result.size.toLong() >= maximumUnits) {
                    throw FullTreeControlException("compilation-unit count exceeds scope bound $maximumUnits")
                }
                val cursor = SectionCursor(info, unitOffset, info.size, "DWARF compilation unit")
                val initialLength = cursor.readUnsigned(4)
                val offsetSize: Int
                val unitLength: Long
                when {
                    initialLength == DWARF_64_MARKER -> {
                        offsetSize = 8
                        unitLength = cursor.readUnsigned(8)
                    }
                    initialLength in DWARF_RESERVED_LENGTH_MIN..DWARF_RESERVED_LENGTH_MAX ->
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
                cursor.limit = unitEnd
                val version = cursor.readUnsigned(2).toInt()
                if (version !in 2..5) {
                    throw FullTreeControlException("DWARF compilation unit version is unsupported: $version")
                }
                val addressSize: Int
                val abbrevOffset: Long
                if (version >= 5) {
                    val unitType = cursor.readUnsigned(1).toInt()
                    addressSize = cursor.readUnsigned(1).toInt()
                    abbrevOffset = cursor.readUnsigned(offsetSize)
                    when (unitType) {
                        DW_UT_COMPILE, DW_UT_PARTIAL -> Unit
                        DW_UT_SKELETON, DW_UT_SPLIT_COMPILE -> cursor.skip(8L)
                        DW_UT_TYPE, DW_UT_SPLIT_TYPE -> {
                            cursor.skip(8L)
                            cursor.skip(offsetSize.toLong())
                        }
                        else -> throw FullTreeControlException("DWARF compilation unit type is unsupported")
                    }
                } else {
                    abbrevOffset = cursor.readUnsigned(offsetSize)
                    addressSize = cursor.readUnsigned(1).toInt()
                }
                if (addressSize !in 1..16) {
                    throw FullTreeControlException("DWARF compilation unit address size is invalid")
                }
                val abbreviationCode = cursor.readUleb128()
                if (abbreviationCode == 0L) {
                    throw FullTreeControlException("DWARF compilation unit has no top-level DIE")
                }
                val attributes = abbreviation(
                    abbrev,
                    abbrevOffset,
                    abbreviationCode,
                    limits,
                    parseBudget,
                )
                val values = LinkedHashMap<Long, FormValue>()
                attributes.forEach { attribute ->
                    val value = readForm(
                        cursor,
                        attribute.form,
                        attribute.implicitConstant,
                        version,
                        addressSize,
                        offsetSize,
                        limits,
                    )
                    if (attribute.name in RELEVANT_ATTRIBUTES) values[attribute.name] = value
                }
                val stringOffsetsBase = (values[DW_AT_STR_OFFSETS_BASE] as? NumericValue)?.value
                val name = decodeDwarfString(
                    values[DW_AT_NAME]
                        ?: throw FullTreeControlException("DWARF compilation unit lacks DW_AT_name"),
                    sections,
                    stringOffsetsBase,
                    offsetSize,
                    limits,
                    "DWARF compilation-unit name",
                )
                val rawPath = if (name.startsWith('/')) {
                    name
                } else {
                    val directory = decodeDwarfString(
                        values[DW_AT_COMP_DIR]
                            ?: throw FullTreeControlException("DWARF compilation unit lacks DW_AT_comp_dir"),
                        sections,
                        stringOffsetsBase,
                        offsetSize,
                        limits,
                        "DWARF compilation directory",
                    ).trimEnd('/')
                    "$directory/$name"
                }
                val producer = values[DW_AT_PRODUCER]?.let { value ->
                    decodeDwarfString(
                        value,
                        sections,
                        stringOffsetsBase,
                        offsetSize,
                        limits,
                        "DWARF compilation-unit producer",
                    )
                }
                val language = values[DW_AT_LANGUAGE]?.let { value ->
                    val numeric = value as? NumericValue
                        ?: throw FullTreeControlException("DWARF compilation-unit language is not an integer")
                    if (numeric.value < 0L) {
                        throw FullTreeControlException("DWARF compilation-unit language is invalid")
                    }
                    numeric.value
                }
                metadataBytes = try {
                    Math.addExact(
                        metadataBytes,
                        Math.addExact(
                            Math.addExact(
                                rawPath.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                                producer?.toByteArray(StandardCharsets.UTF_8)?.size?.toLong() ?: 0L,
                            ),
                            MODELED_COMPILATION_UNIT_OVERHEAD_BYTES,
                        ),
                    )
                } catch (failure: ArithmeticException) {
                    throw FullTreeControlException("DWARF compilation-unit metadata size overflows", failure)
                }
                if (metadataBytes > limits.maximumDwarfMetadataBytes) {
                    throw FullTreeControlException("DWARF compilation-unit metadata exceeds its byte bound")
                }
                result += FullTreeDwarfCompilationUnit(
                    offset = unitOffset,
                    version = version,
                    addressSize = addressSize,
                    rawPath = rawPath,
                    producer = producer,
                    language = language,
                )
                unitOffset = unitEnd
            }
            return result
        }
    }

    private fun abbreviation(
        section: DwarfSection,
        offset: Long,
        expectedCode: Long,
        limits: FullTreeControlLimits,
        parseBudget: DwarfParseBudget,
    ): List<AbbreviationAttribute> {
        if (offset < 0L || offset >= section.size) {
            throw FullTreeControlException("DWARF abbreviation offset exceeds .debug_abbrev")
        }
        val cursor = SectionCursor(section, offset, section.size, "DWARF abbreviation table")
        var declarations = 0
        while (declarations++ < limits.maximumAbbreviationDeclarationsPerUnit) {
            parseBudget.consume("DWARF abbreviation declarations")
            val code = cursor.readUleb128()
            if (code == 0L) {
                throw FullTreeControlException("DWARF top-level abbreviation is absent")
            }
            cursor.readUleb128() // tag
            cursor.readUnsigned(1) // has-children
            val attributes = arrayListOf<AbbreviationAttribute>()
            var attributeCount = 0
            while (attributeCount++ < limits.maximumAbbreviationAttributesPerUnit) {
                parseBudget.consume("DWARF abbreviation attributes")
                val name = cursor.readUleb128()
                val form = cursor.readUleb128()
                if (name == 0L && form == 0L) {
                    if (code == expectedCode) return attributes
                    break
                }
                if (name == 0L || form == 0L) {
                    throw FullTreeControlException("DWARF abbreviation attribute terminator is malformed")
                }
                val implicit = if (form == DW_FORM_IMPLICIT_CONST) cursor.readSleb128() else null
                if (code == expectedCode) attributes += AbbreviationAttribute(name, form, implicit)
            }
            if (attributeCount > limits.maximumAbbreviationAttributesPerUnit) {
                throw FullTreeControlException("DWARF abbreviation exceeds its attribute bound")
            }
        }
        throw FullTreeControlException("DWARF abbreviation table exceeds its declaration bound")
    }

    private fun readForm(
        cursor: SectionCursor,
        form: Long,
        implicitConstant: Long?,
        version: Int,
        addressSize: Int,
        offsetSize: Int,
        limits: FullTreeControlLimits,
        indirectDepth: Int = 0,
    ): FormValue {
        if (indirectDepth > 4) throw FullTreeControlException("DWARF indirect form nesting is excessive")
        return when (form) {
            DW_FORM_ADDR -> cursor.skip(addressSize.toLong()).let { IgnoredValue }
            DW_FORM_BLOCK2 -> cursor.readUnsigned(2).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                IgnoredValue
            }
            DW_FORM_BLOCK4 -> cursor.readUnsigned(4).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                IgnoredValue
            }
            DW_FORM_DATA2 -> NumericValue(cursor.readUnsigned(2))
            DW_FORM_DATA4 -> NumericValue(cursor.readUnsigned(4))
            DW_FORM_DATA8 -> NumericValue(cursor.readUnsigned(8))
            DW_FORM_STRING -> InlineStringValue(cursor.readNullTerminated(limits.maximumDwarfAttributeBytes))
            DW_FORM_BLOCK -> cursor.readUleb128().let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                IgnoredValue
            }
            DW_FORM_BLOCK1 -> cursor.readUnsigned(1).let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                IgnoredValue
            }
            DW_FORM_DATA1 -> NumericValue(cursor.readUnsigned(1))
            DW_FORM_FLAG -> NumericValue(cursor.readUnsigned(1))
            DW_FORM_SDATA -> NumericValue(cursor.readSleb128())
            DW_FORM_STRP -> SectionStringValue(".debug_str", cursor.readUnsigned(offsetSize))
            DW_FORM_UDATA -> NumericValue(cursor.readUleb128())
            DW_FORM_REF_ADDR -> cursor.skip(if (version <= 2) addressSize.toLong() else offsetSize.toLong())
                .let { IgnoredValue }
            DW_FORM_REF1 -> cursor.skip(1L).let { IgnoredValue }
            DW_FORM_REF2 -> cursor.skip(2L).let { IgnoredValue }
            DW_FORM_REF4, DW_FORM_REF_SUP4 -> cursor.skip(4L).let { IgnoredValue }
            DW_FORM_REF8, DW_FORM_REF_SIG8, DW_FORM_REF_SUP8 -> cursor.skip(8L).let { IgnoredValue }
            DW_FORM_REF_UDATA, DW_FORM_ADDRX, DW_FORM_LOCLISTX, DW_FORM_RNGLISTX,
            DW_FORM_GNU_ADDR_INDEX -> cursor.readUleb128().let { IgnoredValue }
            DW_FORM_INDIRECT -> readForm(
                cursor,
                cursor.readUleb128(),
                null,
                version,
                addressSize,
                offsetSize,
                limits,
                indirectDepth + 1,
            )
            DW_FORM_SEC_OFFSET -> NumericValue(cursor.readUnsigned(offsetSize))
            DW_FORM_EXPRLOC -> cursor.readUleb128().let { length ->
                cursor.skipBounded(length, limits.maximumDwarfAttributeBytes)
                IgnoredValue
            }
            DW_FORM_FLAG_PRESENT -> NumericValue(1L)
            DW_FORM_STRX, DW_FORM_GNU_STR_INDEX -> IndexedStringValue(cursor.readUleb128())
            DW_FORM_STRP_SUP, DW_FORM_GNU_STRP_ALT -> UnsupportedExternalStringValue
                .also { cursor.skip(offsetSize.toLong()) }
            DW_FORM_DATA16 -> cursor.skip(16L).let { IgnoredValue }
            DW_FORM_LINE_STRP -> SectionStringValue(".debug_line_str", cursor.readUnsigned(offsetSize))
            DW_FORM_IMPLICIT_CONST -> NumericValue(
                implicitConstant ?: throw FullTreeControlException("DWARF implicit constant is absent"),
            )
            DW_FORM_STRX1 -> IndexedStringValue(cursor.readUnsigned(1))
            DW_FORM_STRX2 -> IndexedStringValue(cursor.readUnsigned(2))
            DW_FORM_STRX3 -> IndexedStringValue(cursor.readUnsigned(3))
            DW_FORM_STRX4 -> IndexedStringValue(cursor.readUnsigned(4))
            DW_FORM_ADDRX1 -> cursor.skip(1L).let { IgnoredValue }
            DW_FORM_ADDRX2 -> cursor.skip(2L).let { IgnoredValue }
            DW_FORM_ADDRX3 -> cursor.skip(3L).let { IgnoredValue }
            DW_FORM_ADDRX4 -> cursor.skip(4L).let { IgnoredValue }
            DW_FORM_GNU_REF_ALT -> cursor.skip(offsetSize.toLong()).let { IgnoredValue }
            else -> throw FullTreeControlException("DWARF attribute uses unsupported form 0x${form.toString(16)}")
        }
    }

    private fun decodeDwarfString(
        value: FormValue,
        sections: DwarfSections,
        stringOffsetsBase: Long?,
        offsetSize: Int,
        limits: FullTreeControlLimits,
        label: String,
    ): String {
        val bytes = when (value) {
            is InlineStringValue -> value.bytes
            is SectionStringValue -> sections.required(value.section).readNullTerminated(
                value.offset,
                limits.maximumDwarfAttributeBytes,
            )
            is IndexedStringValue -> {
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
            UnsupportedExternalStringValue ->
                throw FullTreeControlException("$label depends on unsupported supplementary DWARF strings")
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

private data class AbbreviationAttribute(val name: Long, val form: Long, val implicitConstant: Long?)

private class DwarfParseBudget(private val limit: Long) {
    private var consumed = 0L

    fun consume(label: String) {
        consumed++
        if (consumed > limit) throw FullTreeControlException("aggregate parse-step bound exceeded while reading $label")
    }
}

private sealed interface FormValue
private data class NumericValue(val value: Long) : FormValue
private data class InlineStringValue(val bytes: ByteArray) : FormValue
private data class SectionStringValue(val section: String, val offset: Long) : FormValue
private data class IndexedStringValue(val index: Long) : FormValue
private data object UnsupportedExternalStringValue : FormValue
private data object IgnoredValue : FormValue

private class DwarfSections private constructor(
    private val sections: Map<String, DwarfSection>,
    private val scratch: DwarfScratch,
) : AutoCloseable {
    fun required(name: String): DwarfSection = sections[name]
        ?: throw FullTreeControlException("rich artifact lacks required $name")

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
        fun open(
            artifact: StableControlFile,
            scratchParent: Path,
            limits: FullTreeControlLimits,
        ): DwarfSections {
            val scratch = DwarfScratch.create(scratchParent)
            val result = linkedMapOf<String, DwarfSection>()
            try {
                val descriptors = ElfSections.read(artifact)
                val byName = descriptors.associateBy { it.name }
                var scratchBytes = 0L
                REQUIRED_OR_OPTIONAL_SECTIONS.forEach { logicalName ->
                    val descriptor = byName[logicalName] ?: byName[logicalName.replace(".debug_", ".zdebug_")]
                    if (descriptor != null) {
                        val opened = openSection(
                            artifact,
                            descriptor,
                            logicalName,
                            scratch,
                            limits.maximumDwarfScratchBytes - scratchBytes,
                            limits,
                        )
                        if (descriptor.flags and SHF_COMPRESSED != 0L || descriptor.name.startsWith(".zdebug_")) {
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
                if (".debug_info" !in result || ".debug_abbrev" !in result) {
                    throw FullTreeControlException("rich artifact has no complete DWARF information")
                }
                return DwarfSections(result, scratch)
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
            descriptor: ElfSection,
            logicalName: String,
            scratch: DwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): DwarfSection {
            if (descriptor.size <= 0L || descriptor.size > limits.maximumDwarfSectionBytes) {
                throw FullTreeControlException("$logicalName exceeds its compressed section bound")
            }
            if (descriptor.type == SHT_NOBITS) {
                throw FullTreeControlException("$logicalName is not file-backed")
            }
            return when {
                descriptor.flags and SHF_COMPRESSED != 0L ->
                    decompressElfSection(
                        artifact,
                        descriptor,
                        logicalName,
                        scratch,
                        remainingScratchBytes,
                        limits,
                    )
                descriptor.name.startsWith(".zdebug_") ->
                    decompressGnuSection(
                        artifact,
                        descriptor,
                        logicalName,
                        scratch,
                        remainingScratchBytes,
                        limits,
                    )
                else -> DwarfSection(
                    size = descriptor.size,
                    byteOrder = descriptor.byteOrder,
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
            descriptor: ElfSection,
            label: String,
            scratch: DwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): DwarfSection {
            val headerSize = if (descriptor.elfClass == ELF_CLASS_64) 24 else 12
            if (descriptor.size <= headerSize.toLong()) throw FullTreeControlException("$label compression header is truncated")
            val header = artifact.readExactly(descriptor.offset, headerSize, "$label compression header")
            val buffer = ByteBuffer.wrap(header).order(descriptor.byteOrder)
            val type = buffer.int.toLong() and UINT32_MASK
            if (type != ELFCOMPRESS_ZLIB) throw FullTreeControlException("$label uses unsupported ELF compression")
            val expanded = if (descriptor.elfClass == ELF_CLASS_64) {
                buffer.int // reserved
                unsignedLong(buffer.long, "$label expanded size")
            } else {
                buffer.int.toLong() and UINT32_MASK
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
            descriptor: ElfSection,
            label: String,
            scratch: DwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): DwarfSection {
            if (descriptor.size <= GNU_ZLIB_HEADER_BYTES) {
                throw FullTreeControlException("$label GNU compression header is truncated")
            }
            val header = artifact.readExactly(
                descriptor.offset,
                GNU_ZLIB_HEADER_BYTES.toInt(),
                "$label GNU compression header",
            )
            if (!header.copyOfRange(0, 4).contentEquals("ZLIB".toByteArray(StandardCharsets.US_ASCII))) {
                throw FullTreeControlException("$label GNU compression header is invalid")
            }
            val expanded = unsignedLong(ByteBuffer.wrap(header, 4, 8).order(ByteOrder.BIG_ENDIAN).long, "$label size")
            return inflate(
                artifact.slice(
                    descriptor.offset + GNU_ZLIB_HEADER_BYTES,
                    descriptor.size - GNU_ZLIB_HEADER_BYTES,
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
            scratch: DwarfScratch,
            remainingScratchBytes: Long,
            limits: FullTreeControlLimits,
        ): DwarfSection {
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
                return DwarfSection(
                    size = expandedSize,
                    byteOrder = byteOrder,
                    readWindow = { offset, length ->
                        val bytes = ByteArray(length)
                        val destination = ByteBuffer.wrap(bytes)
                        var position = offset
                        while (destination.hasRemaining()) {
                            val read = output.read(destination, position)
                            if (read <= 0) throw FullTreeControlException("$label scratch section ended early")
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

        private val REQUIRED_OR_OPTIONAL_SECTIONS = listOf(
            ".debug_info",
            ".debug_abbrev",
            ".debug_str",
            ".debug_line_str",
            ".debug_str_offsets",
        )
    }
}

private class DwarfSection(
    val size: Long,
    val byteOrder: ByteOrder,
    private val readWindow: (Long, Int) -> ByteArray,
    private val closeAction: () -> Unit = {},
) : AutoCloseable {
    private var cachedOffset = -1L
    private var cached = ByteArray(0)

    fun byte(offset: Long): Int {
        if (offset < 0L || offset >= size) throw FullTreeControlException("DWARF read exceeds its section")
        if (offset < cachedOffset || offset >= cachedOffset + cached.size) {
            cachedOffset = offset
            cached = readWindow(offset, minOf(DWARF_WINDOW_BYTES.toLong(), size - offset).toInt())
        }
        return cached[(offset - cachedOffset).toInt()].toInt() and 0xff
    }

    fun readUnsigned(offset: Long, width: Int): Long {
        val cursor = SectionCursor(this, offset, size, "DWARF section offset")
        return cursor.readUnsigned(width)
    }

    fun readNullTerminated(offset: Long, maximumBytes: Int): ByteArray {
        val cursor = SectionCursor(this, offset, size, "DWARF string section")
        return cursor.readNullTerminated(maximumBytes)
    }

    override fun close() = closeAction()
}

private class SectionCursor(
    private val section: DwarfSection,
    var position: Long,
    var limit: Long,
    private val label: String,
) {
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
        repeat(10) {
            requireAvailable(1L)
            val byte = section.byte(position++)
            val payload = (byte and 0x7f).toULong()
            if (shift >= 64 && payload != 0UL) throw FullTreeControlException("$label ULEB128 overflows")
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

private object ElfSections {
    fun read(file: StableControlFile): List<ElfSection> {
        if (file.size < 64L) throw FullTreeControlException("rich artifact ELF header is truncated")
        val identification = file.readExactly(0L, 16, "ELF identification")
        if (!identification.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) {
            throw FullTreeControlException("rich artifact is not ELF")
        }
        val elfClass = identification[4].toInt() and 0xff
        if (elfClass !in setOf(ELF_CLASS_32, ELF_CLASS_64)) {
            throw FullTreeControlException("rich artifact ELF class is unsupported")
        }
        val byteOrder = when (identification[5].toInt() and 0xff) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw FullTreeControlException("rich artifact ELF byte order is unsupported")
        }
        val headerBytes = if (elfClass == ELF_CLASS_64) 64 else 52
        val header = ByteBuffer.wrap(file.readExactly(0L, headerBytes, "ELF header")).order(byteOrder)
        val sectionOffset = if (elfClass == ELF_CLASS_64) unsignedLong(header.getLong(40), "ELF section offset")
        else header.getInt(32).toLong() and UINT32_MASK
        val entrySize = (header.getShort(if (elfClass == ELF_CLASS_64) 58 else 46).toInt() and 0xffff)
        var sectionCount = header.getShort(if (elfClass == ELF_CLASS_64) 60 else 48).toInt() and 0xffff
        var nameIndex = header.getShort(if (elfClass == ELF_CLASS_64) 62 else 50).toInt() and 0xffff
        val minimumEntrySize = if (elfClass == ELF_CLASS_64) 64 else 40
        if (sectionOffset <= 0L || entrySize < minimumEntrySize) {
            throw FullTreeControlException("rich artifact ELF section table is malformed")
        }
        val sectionZero = readHeader(file, sectionOffset, entrySize, elfClass, byteOrder, 0)
        if (sectionCount == 0) {
            if (sectionZero.size !in 1L..MAXIMUM_ELF_SECTIONS.toLong()) {
                throw FullTreeControlException("rich artifact ELF section count is invalid")
            }
            sectionCount = sectionZero.size.toInt()
        }
        if (nameIndex == SHN_XINDEX) {
            if (sectionZero.link !in 0 until sectionCount) {
                throw FullTreeControlException("rich artifact ELF section-name index is invalid")
            }
            nameIndex = sectionZero.link
        }
        if (sectionCount !in 1..MAXIMUM_ELF_SECTIONS || nameIndex !in 0 until sectionCount) {
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
        if (names.type == SHT_NOBITS || names.offset > file.size - names.size) {
            throw FullTreeControlException("rich artifact ELF section-name table is invalid")
        }
        val nameSection = DwarfSection(
            size = names.size,
            byteOrder = byteOrder,
            readWindow = { offset, length ->
                file.readExactly(Math.addExact(names.offset, offset), length, "ELF section-name table")
            },
        )
        val seen = HashSet<String>()
        return raw.map { section ->
            val nameBytes = nameSection.readNullTerminated(section.nameOffset, MAXIMUM_ELF_SECTION_NAME_BYTES)
            val name = try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nameBytes)).toString()
            } catch (failure: Exception) {
                throw FullTreeControlException("ELF section name is not UTF-8", failure)
            }
            if (name.isNotEmpty() && !seen.add(name)) {
                throw FullTreeControlException("rich artifact ELF section names are duplicated")
            }
            if (section.type != SHT_NOBITS && section.offset > file.size - section.size) {
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
    ): ElfSection {
        val buffer = ByteBuffer.wrap(file.readExactly(offset, entrySize, "ELF section header $index")).order(byteOrder)
        val nameOffset = buffer.int.toLong() and UINT32_MASK
        val type = buffer.int.toLong() and UINT32_MASK
        val flags: Long
        val sectionOffset: Long
        val size: Long
        val link: Int
        if (elfClass == ELF_CLASS_64) {
            flags = unsignedLong(buffer.long, "ELF section flags")
            buffer.long // address
            sectionOffset = unsignedLong(buffer.long, "ELF section file offset")
            size = unsignedLong(buffer.long, "ELF section size")
            link = buffer.int
        } else {
            flags = buffer.int.toLong() and UINT32_MASK
            buffer.int // address
            sectionOffset = buffer.int.toLong() and UINT32_MASK
            size = buffer.int.toLong() and UINT32_MASK
            link = buffer.int
        }
        return ElfSection("", nameOffset, type, flags, sectionOffset, size, link, elfClass, byteOrder)
    }
}

private data class ElfSection(
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

private class DwarfScratch private constructor(
    private val root: Path,
    private val identity: Any,
) : AutoCloseable {
    private val files = linkedMapOf<Path, Any>()

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

    override fun close() {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
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
        files.forEach { (path, expected) ->
            try {
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() != expected) {
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
    }

    companion object {
        fun create(parent: Path): DwarfScratch {
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
                return DwarfScratch(root, identity)
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

private fun unsignedLong(value: Long, label: String): Long {
    if (value < 0L) throw FullTreeControlException("$label exceeds the supported range")
    return value
}

private const val ELF_CLASS_32 = 1
private const val ELF_CLASS_64 = 2
private const val SHT_NOBITS = 8L
private const val SHF_COMPRESSED = 0x800L
private const val ELFCOMPRESS_ZLIB = 1L
private const val SHN_XINDEX = 0xffff
private const val MAXIMUM_ELF_SECTIONS = 1_000_000
private const val MAXIMUM_ELF_SECTION_NAME_BYTES = 4096
private const val DWARF_WINDOW_BYTES = 64 * 1024
private const val MODELED_COMPILATION_UNIT_OVERHEAD_BYTES = 128L
private const val GNU_ZLIB_HEADER_BYTES = 12L
private const val UINT32_MASK = 0xffff_ffffL
private const val DWARF_64_MARKER = 0xffff_ffffL
private const val DWARF_RESERVED_LENGTH_MIN = 0xffff_fff0L
private const val DWARF_RESERVED_LENGTH_MAX = 0xffff_fffeL

private const val DW_UT_COMPILE = 0x01
private const val DW_UT_TYPE = 0x02
private const val DW_UT_PARTIAL = 0x03
private const val DW_UT_SKELETON = 0x04
private const val DW_UT_SPLIT_COMPILE = 0x05
private const val DW_UT_SPLIT_TYPE = 0x06

private const val DW_AT_NAME = 0x03L
private const val DW_AT_LANGUAGE = 0x13L
private const val DW_AT_COMP_DIR = 0x1bL
private const val DW_AT_PRODUCER = 0x25L
private const val DW_AT_STR_OFFSETS_BASE = 0x72L
private val RELEVANT_ATTRIBUTES = setOf(
    DW_AT_NAME,
    DW_AT_LANGUAGE,
    DW_AT_COMP_DIR,
    DW_AT_PRODUCER,
    DW_AT_STR_OFFSETS_BASE,
)

private const val DW_FORM_ADDR = 0x01L
private const val DW_FORM_BLOCK2 = 0x03L
private const val DW_FORM_BLOCK4 = 0x04L
private const val DW_FORM_DATA2 = 0x05L
private const val DW_FORM_DATA4 = 0x06L
private const val DW_FORM_DATA8 = 0x07L
private const val DW_FORM_STRING = 0x08L
private const val DW_FORM_BLOCK = 0x09L
private const val DW_FORM_BLOCK1 = 0x0aL
private const val DW_FORM_DATA1 = 0x0bL
private const val DW_FORM_FLAG = 0x0cL
private const val DW_FORM_SDATA = 0x0dL
private const val DW_FORM_STRP = 0x0eL
private const val DW_FORM_UDATA = 0x0fL
private const val DW_FORM_REF_ADDR = 0x10L
private const val DW_FORM_REF1 = 0x11L
private const val DW_FORM_REF2 = 0x12L
private const val DW_FORM_REF4 = 0x13L
private const val DW_FORM_REF8 = 0x14L
private const val DW_FORM_REF_UDATA = 0x15L
private const val DW_FORM_INDIRECT = 0x16L
private const val DW_FORM_SEC_OFFSET = 0x17L
private const val DW_FORM_EXPRLOC = 0x18L
private const val DW_FORM_FLAG_PRESENT = 0x19L
private const val DW_FORM_STRX = 0x1aL
private const val DW_FORM_ADDRX = 0x1bL
private const val DW_FORM_REF_SUP4 = 0x1cL
private const val DW_FORM_STRP_SUP = 0x1dL
private const val DW_FORM_DATA16 = 0x1eL
private const val DW_FORM_LINE_STRP = 0x1fL
private const val DW_FORM_REF_SIG8 = 0x20L
private const val DW_FORM_IMPLICIT_CONST = 0x21L
private const val DW_FORM_LOCLISTX = 0x22L
private const val DW_FORM_RNGLISTX = 0x23L
private const val DW_FORM_REF_SUP8 = 0x24L
private const val DW_FORM_STRX1 = 0x25L
private const val DW_FORM_STRX2 = 0x26L
private const val DW_FORM_STRX3 = 0x27L
private const val DW_FORM_STRX4 = 0x28L
private const val DW_FORM_ADDRX1 = 0x29L
private const val DW_FORM_ADDRX2 = 0x2aL
private const val DW_FORM_ADDRX3 = 0x2bL
private const val DW_FORM_ADDRX4 = 0x2cL
private const val DW_FORM_GNU_ADDR_INDEX = 0x1f01L
private const val DW_FORM_GNU_STR_INDEX = 0x1f02L
private const val DW_FORM_GNU_REF_ALT = 0x1f20L
private const val DW_FORM_GNU_STRP_ALT = 0x1f21L

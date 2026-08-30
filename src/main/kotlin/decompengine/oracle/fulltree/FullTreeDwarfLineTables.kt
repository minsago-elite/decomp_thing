package decompengine.oracle.fulltree

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Collections

/** Independent hard ceilings for one bounded `.debug_line` prologue. */
internal data class FullTreeDwarfLineTableLimits(
    val maximumUnitBytes: Long = 256L * 1024L * 1024L,
    val maximumDirectories: Int = 1_000_000,
    val maximumFiles: Int = 1_000_000,
    val maximumEntryFormats: Int = 64,
    val maximumPathBytes: Int = 64 * 1024,
    val maximumPathCharacters: Int = 16_384,
    val maximumAggregatePathBytes: Long = 256L * 1024L * 1024L,
    val maximumParseSteps: Long = 10_000_000L,
) {
    init {
        require(maximumUnitBytes in 1L..4L * 1024L * 1024L * 1024L)
        require(maximumDirectories in 1..1_000_000)
        require(maximumFiles in 1..1_000_000)
        require(maximumEntryFormats in 1..255)
        require(maximumPathBytes in 1..1024 * 1024)
        require(maximumPathCharacters in 1..1_000_000)
        require(maximumAggregatePathBytes in 1L..4L * 1024L * 1024L * 1024L)
        require(maximumParseSteps in 1L..1_000_000_000L)
    }
}

/** Logical sections needed by the line-table path subset; absent optional sections stay absent. */
internal data class FullTreeDwarfLineTableSections(
    val line: FullTreeDwarfSection,
    val strings: FullTreeDwarfSection? = null,
    val lineStrings: FullTreeDwarfSection? = null,
    val stringOffsets: FullTreeDwarfSection? = null,
)

internal data class FullTreeDwarfLineFile(
    val name: String,
    val directoryIndex: Long?,
)

/**
 * Immutable paths from one line-program prologue.
 *
 * [resolveDeclarationPath] intentionally takes the compilation-unit version separately. Historical
 * function-observation v3 parsed the line header using the CU's DWARF format, but selected file and
 * directory indices using the CU version rather than the line-header version.
 */
internal class FullTreeDwarfLineTable internal constructor(
    val version: Int,
    val offsetSize: Int,
    directories: List<String>,
    files: List<FullTreeDwarfLineFile>,
    private val maximumPathBytes: Int,
    private val maximumPathCharacters: Int,
) {
    val directories: List<String> = Collections.unmodifiableList(ArrayList(directories))
    val files: List<FullTreeDwarfLineFile> = Collections.unmodifiableList(ArrayList(files))

    /** Returns the historical raw declaration path, or null when its file/directory index is absent. */
    fun resolveDeclarationPath(
        fileIndex: Long,
        compilationUnitVersion: Int,
        compilationDirectory: String?,
    ): String? = resolveDeclarationPath(fileIndex, compilationUnitVersion) { compilationDirectory }

    /** Resolves the CU directory only for the legacy relative-file, directory-index-zero case. */
    fun resolveDeclarationPath(
        fileIndex: Long,
        compilationUnitVersion: Int,
        compilationDirectory: () -> String?,
    ): String? {
        if (compilationUnitVersion !in 2..5 || fileIndex < 0L) return null
        val entryIndex = if (compilationUnitVersion >= 5) fileIndex else fileIndex - 1L
        if (entryIndex < 0L || entryIndex >= files.size.toLong()) return null
        val file = files[entryIndex.toInt()]
        if (file.name.startsWith('/')) return file.name

        val directory = if (compilationUnitVersion >= 5) {
            val index = file.directoryIndex ?: return null
            if (index < 0L || index >= directories.size.toLong()) return null
            directories[index.toInt()]
        } else {
            when (val index = file.directoryIndex ?: return null) {
                0L -> compilationDirectory()?.also(::requireValidCallerPath) ?: return null
                else -> {
                    val adjusted = index - 1L
                    if (adjusted < 0L || adjusted >= directories.size.toLong()) return null
                    directories[adjusted.toInt()]
                }
            }
        }
        val joined = if (directory.endsWith('/')) "$directory${file.name}" else "$directory/${file.name}"
        val joinedBytes = joined.toByteArray(StandardCharsets.UTF_8).size.toLong()
        val maximumJoinedBytes = Math.addExact(Math.multiplyExact(maximumPathBytes.toLong(), 2L), 1L)
        if (joinedBytes > maximumJoinedBytes) {
            throw FullTreeControlException("DWARF declaration path exceeds its joined byte bound")
        }
        return normalizePosix(joined)
    }

    private fun requireValidCallerPath(value: String) {
        if (value.isEmpty() || '\u0000' in value ||
            value.codePointCount(0, value.length) > maximumPathCharacters ||
            value.toByteArray(StandardCharsets.UTF_8).size > maximumPathBytes
        ) {
            throw FullTreeControlException("DWARF compilation directory is invalid")
        }
    }
}

/** Bounded parser for the declaration-file subset of DWARF v2-v5 line-program prologues. */
internal object FullTreeDwarfLineTables {
    fun read(
        sections: FullTreeDwarfLineTableSections,
        statementListOffset: Long,
        compilationUnitOffsetSize: Int,
        stringOffsetsBase: Long?,
        parseBudget: FullTreeDwarfParseBudget,
        limits: FullTreeDwarfLineTableLimits = FullTreeDwarfLineTableLimits(),
        checkpoint: (String) -> Unit = {},
    ): FullTreeDwarfLineTable {
        if (compilationUnitOffsetSize !in setOf(4, 8)) {
            throw FullTreeControlException("DWARF line table uses an unsupported CU offset size")
        }
        if (statementListOffset < 0L || statementListOffset >= sections.line.size) {
            throw FullTreeControlException("DWARF statement-list offset exceeds .debug_line")
        }
        val parser = LineTableParser(
            sections,
            statementListOffset,
            compilationUnitOffsetSize,
            stringOffsetsBase,
            parseBudget,
            limits,
            checkpoint,
        )
        return parser.read()
    }
}

private class LineTableParser(
    private val sections: FullTreeDwarfLineTableSections,
    private val statementListOffset: Long,
    private val compilationUnitOffsetSize: Int,
    private val stringOffsetsBase: Long?,
    parseBudget: FullTreeDwarfParseBudget,
    private val limits: FullTreeDwarfLineTableLimits,
    checkpoint: (String) -> Unit,
) {
    private val budget = LineTableBudget(limits.maximumParseSteps, parseBudget, checkpoint)
    private lateinit var cursor: FullTreeDwarfSectionCursor
    private var aggregatePathBytes = 0L
    private var lineOffsetSize = 0

    fun read(): FullTreeDwarfLineTable {
        budget.consume("line-table entry")
        cursor = FullTreeDwarfSectionCursor(
            sections.line,
            statementListOffset,
            sections.line.size,
            "DWARF line table",
        )
        val initialLength = unsigned(4, "line-table initial length")
        val unitLength: Long
        val initialFieldBytes: Int
        when {
            initialLength == DWARF_64_MARKER -> {
                lineOffsetSize = 8
                initialFieldBytes = 12
                unitLength = unsigned(8, "line-table unit length")
            }
            initialLength in RESERVED_LENGTH_MIN..RESERVED_LENGTH_MAX ->
                throw FullTreeControlException("DWARF line table uses a reserved unit length")
            else -> {
                lineOffsetSize = 4
                initialFieldBytes = 4
                unitLength = initialLength
            }
        }
        if (lineOffsetSize != compilationUnitOffsetSize) {
            throw FullTreeControlException("DWARF line-table and compilation-unit formats differ")
        }
        val totalUnitBytes = add(unitLength, initialFieldBytes.toLong(), "line-table unit size")
        if (unitLength <= 0L || totalUnitBytes > limits.maximumUnitBytes) {
            throw FullTreeControlException("DWARF line table exceeds its unit byte bound")
        }
        val unitEnd = add(cursor.position, unitLength, "line-table end")
        if (unitEnd > sections.line.size) {
            throw FullTreeControlException("DWARF line table exceeds .debug_line")
        }
        cursor.narrowLimit(unitEnd)

        val version = unsigned(2, "line-table version").toInt()
        if (version !in 2..5) throw FullTreeControlException("DWARF line-table version is unsupported: $version")
        if (version >= 5) {
            val addressSize = unsigned(1, "line-table address size")
            if (addressSize !in 1L..16L) throw FullTreeControlException("DWARF line-table address size is invalid")
            unsigned(1, "line-table segment selector size")
        }
        val headerLength = unsigned(lineOffsetSize, "line-table header length")
        val headerEnd = add(cursor.position, headerLength, "line-table header end")
        if (headerEnd > unitEnd) throw FullTreeControlException("DWARF line-table header exceeds its unit")
        cursor.narrowLimit(headerEnd)
        readFixedPrologue(version)

        val directories: List<String>
        val files: List<FullTreeDwarfLineFile>
        if (version >= 5) {
            directories = readVersionFiveDirectories()
            files = readVersionFiveFiles()
        } else {
            directories = readLegacyDirectories()
            files = readLegacyFiles()
        }
        if (cursor.position != headerEnd) {
            throw FullTreeControlException("DWARF line-table prologue length does not reconcile")
        }
        budget.checkpoint("after DWARF line-table prologue")
        return FullTreeDwarfLineTable(
            version,
            lineOffsetSize,
            directories,
            files,
            limits.maximumPathBytes,
            limits.maximumPathCharacters,
        )
    }

    private fun readFixedPrologue(version: Int) {
        val minimumInstructionLength = unsigned(1, "minimum instruction length")
        if (minimumInstructionLength == 0L) {
            throw FullTreeControlException("DWARF line-table minimum instruction length is zero")
        }
        if (version >= 4 && unsigned(1, "maximum operations per instruction") == 0L) {
            throw FullTreeControlException("DWARF line-table maximum operations per instruction is zero")
        }
        unsigned(1, "default statement flag")
        unsigned(1, "line base")
        if (unsigned(1, "line range") == 0L) {
            throw FullTreeControlException("DWARF line-table line range is zero")
        }
        val opcodeBase = unsigned(1, "opcode base").toInt()
        if (opcodeBase == 0) throw FullTreeControlException("DWARF line-table opcode base is zero")
        repeat(opcodeBase - 1) {
            unsigned(1, "standard opcode operand count")
        }
    }

    private fun readLegacyDirectories(): List<String> {
        val result = ArrayList<String>()
        while (true) {
            budget.consume("legacy line-table directory")
            val bytes = cursor.readNullTerminated(limits.maximumPathBytes)
            if (bytes.isEmpty()) return Collections.unmodifiableList(result)
            if (result.size >= limits.maximumDirectories) {
                throw FullTreeControlException("DWARF line-table directory count exceeds its bound")
            }
            result += decodePath(bytes, "DWARF line-table directory")
        }
    }

    private fun readLegacyFiles(): List<FullTreeDwarfLineFile> {
        val result = ArrayList<FullTreeDwarfLineFile>()
        while (true) {
            budget.consume("legacy line-table file")
            val bytes = cursor.readNullTerminated(limits.maximumPathBytes)
            if (bytes.isEmpty()) return Collections.unmodifiableList(result)
            if (result.size >= limits.maximumFiles) {
                throw FullTreeControlException("DWARF line-table file count exceeds its bound")
            }
            val name = decodePath(bytes, "DWARF line-table file")
            val directoryIndex = uleb("legacy line-table directory index")
            uleb("legacy line-table modification time")
            uleb("legacy line-table file size")
            result += FullTreeDwarfLineFile(name, directoryIndex)
        }
    }

    private fun readVersionFiveDirectories(): List<String> {
        val formats = readFormats("directory")
        val count = boundedCount(uleb("line-table directory count"), limits.maximumDirectories, "directory")
        if (count > 0 && formats.none { it.contentType == DW_LNCT_PATH }) {
            throw FullTreeControlException("DWARF v5 directory entries have no path field")
        }
        return Collections.unmodifiableList(
            List(count) { index ->
                budget.consume("DWARF v5 line-table directory")
                var path: String? = null
                formats.forEach { format ->
                    when (format.contentType) {
                        DW_LNCT_PATH -> path = readPathForm(format.form, "DWARF v5 directory $index")
                        else -> skipForm(format.form, "DWARF v5 directory field")
                    }
                }
                path ?: throw FullTreeControlException("DWARF v5 directory entry has no path")
            },
        )
    }

    private fun readVersionFiveFiles(): List<FullTreeDwarfLineFile> {
        val formats = readFormats("file")
        val count = boundedCount(uleb("line-table file count"), limits.maximumFiles, "file")
        if (count > 0 && formats.none { it.contentType == DW_LNCT_PATH }) {
            throw FullTreeControlException("DWARF v5 file entries have no path field")
        }
        return Collections.unmodifiableList(
            List(count) { index ->
                budget.consume("DWARF v5 line-table file")
                var path: String? = null
                var directoryIndex: Long? = null
                formats.forEach { format ->
                    when (format.contentType) {
                        DW_LNCT_PATH -> path = readPathForm(format.form, "DWARF v5 file $index")
                        DW_LNCT_DIRECTORY_INDEX -> directoryIndex = readUnsignedForm(
                            format.form,
                            "DWARF v5 file directory index",
                        )
                        else -> skipForm(format.form, "DWARF v5 file field")
                    }
                }
                FullTreeDwarfLineFile(
                    path ?: throw FullTreeControlException("DWARF v5 file entry has no path"),
                    directoryIndex,
                )
            },
        )
    }

    private fun readFormats(label: String): List<LineEntryFormat> {
        val count = unsigned(1, "line-table $label format count").toInt()
        if (count > limits.maximumEntryFormats) {
            throw FullTreeControlException("DWARF line-table $label format count exceeds its bound")
        }
        val contentTypes = HashSet<Long>()
        return List(count) {
            budget.consume("DWARF line-table $label format")
            val contentType = uleb("line-table $label content type")
            val form = uleb("line-table $label form")
            if (!contentTypes.add(contentType)) {
                throw FullTreeControlException("DWARF line-table $label formats duplicate a content type")
            }
            requireSupportedForm(form, contentType, label)
            LineEntryFormat(contentType, form)
        }
    }

    private fun requireSupportedForm(form: Long, contentType: Long, label: String) {
        val supported = form in STRING_FORMS || form in UNSIGNED_FORMS ||
            form == FULL_TREE_DW_FORM_SDATA || form == FULL_TREE_DW_FORM_DATA16
        if (!supported) {
            throw FullTreeControlException(
                "DWARF line-table $label field uses unsupported form 0x${form.toString(16)}",
            )
        }
        if (contentType == DW_LNCT_PATH && form !in STRING_FORMS) {
            throw FullTreeControlException("DWARF line-table $label path is not encoded as a string")
        }
        if (contentType == DW_LNCT_DIRECTORY_INDEX && form !in UNSIGNED_FORMS) {
            throw FullTreeControlException("DWARF line-table directory index is not unsigned")
        }
    }

    private fun readPathForm(form: Long, label: String): String {
        val bytes = when (form) {
            FULL_TREE_DW_FORM_STRING -> cursor.readNullTerminated(limits.maximumPathBytes)
            FULL_TREE_DW_FORM_STRP -> sectionString(
                sections.strings,
                unsigned(lineOffsetSize, "$label string offset"),
                ".debug_str",
            )
            FULL_TREE_DW_FORM_LINE_STRP -> sectionString(
                sections.lineStrings,
                unsigned(lineOffsetSize, "$label line-string offset"),
                ".debug_line_str",
            )
            FULL_TREE_DW_FORM_STRX -> indexedString(uleb("$label string index"), label)
            FULL_TREE_DW_FORM_STRX1 -> indexedString(unsigned(1, "$label string index"), label)
            FULL_TREE_DW_FORM_STRX2 -> indexedString(unsigned(2, "$label string index"), label)
            FULL_TREE_DW_FORM_STRX3 -> indexedString(unsigned(3, "$label string index"), label)
            FULL_TREE_DW_FORM_STRX4 -> indexedString(unsigned(4, "$label string index"), label)
            else -> throw FullTreeControlException("$label is not encoded as a supported string")
        }
        return decodePath(bytes, label)
    }

    private fun indexedString(index: Long, label: String): ByteArray {
        val base = stringOffsetsBase
            ?: throw FullTreeControlException("$label uses an indexed string without DW_AT_str_offsets_base")
        if (base < 0L) throw FullTreeControlException("$label has an invalid string-offsets base")
        val offsets = sections.stringOffsets
            ?: throw FullTreeControlException("$label requires .debug_str_offsets")
        val entryOffset = try {
            Math.addExact(base, Math.multiplyExact(index, compilationUnitOffsetSize.toLong()))
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("$label string index exceeds .debug_str_offsets", failure)
        }
        val stringOffset = offsets.readUnsigned(entryOffset, compilationUnitOffsetSize)
        return sectionString(sections.strings, stringOffset, ".debug_str")
    }

    private fun sectionString(section: FullTreeDwarfSection?, offset: Long, name: String): ByteArray {
        val present = section ?: throw FullTreeControlException("DWARF line table requires $name")
        return present.readNullTerminated(offset, limits.maximumPathBytes)
    }

    private fun readUnsignedForm(form: Long, label: String): Long = when (form) {
        FULL_TREE_DW_FORM_DATA1 -> unsigned(1, label)
        FULL_TREE_DW_FORM_DATA2 -> unsigned(2, label)
        FULL_TREE_DW_FORM_DATA4 -> unsigned(4, label)
        FULL_TREE_DW_FORM_DATA8 -> unsigned(8, label)
        FULL_TREE_DW_FORM_UDATA -> uleb(label)
        else -> throw FullTreeControlException("$label is not encoded as an unsigned integer")
    }

    private fun skipForm(form: Long, label: String) {
        when (form) {
            FULL_TREE_DW_FORM_STRING -> cursor.readNullTerminated(limits.maximumPathBytes)
            FULL_TREE_DW_FORM_STRP, FULL_TREE_DW_FORM_LINE_STRP -> unsigned(lineOffsetSize, label)
            FULL_TREE_DW_FORM_STRX, FULL_TREE_DW_FORM_UDATA -> uleb(label)
            FULL_TREE_DW_FORM_STRX1, FULL_TREE_DW_FORM_DATA1 -> unsigned(1, label)
            FULL_TREE_DW_FORM_STRX2, FULL_TREE_DW_FORM_DATA2 -> unsigned(2, label)
            FULL_TREE_DW_FORM_STRX3 -> unsigned(3, label)
            FULL_TREE_DW_FORM_STRX4, FULL_TREE_DW_FORM_DATA4 -> unsigned(4, label)
            FULL_TREE_DW_FORM_DATA8 -> cursor.skip(8L)
            FULL_TREE_DW_FORM_SDATA -> cursor.readSleb128()
            FULL_TREE_DW_FORM_DATA16 -> cursor.skip(16L)
            else -> throw FullTreeControlException("$label uses an unsupported form")
        }
    }

    private fun decodePath(bytes: ByteArray, label: String): String {
        val value = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (failure: Exception) {
            throw FullTreeControlException("$label is not UTF-8", failure)
        }
        if (value.isEmpty() || '\u0000' in value ||
            value.codePointCount(0, value.length) > limits.maximumPathCharacters
        ) {
            throw FullTreeControlException("$label is empty, contains NUL, or exceeds its character bound")
        }
        aggregatePathBytes = add(aggregatePathBytes, bytes.size.toLong(), "line-table path bytes")
        if (aggregatePathBytes > limits.maximumAggregatePathBytes) {
            throw FullTreeControlException("DWARF line-table paths exceed their aggregate byte bound")
        }
        return value
    }

    private fun boundedCount(value: Long, maximum: Int, label: String): Int {
        if (value < 0L || value > maximum.toLong()) {
            throw FullTreeControlException("DWARF line-table $label count exceeds its bound")
        }
        return value.toInt()
    }

    private fun unsigned(width: Int, label: String): Long {
        budget.consume(label)
        return cursor.readUnsigned(width)
    }

    private fun uleb(label: String): Long {
        budget.consume(label)
        return cursor.readUleb128()
    }
}

private data class LineEntryFormat(val contentType: Long, val form: Long)

private class LineTableBudget(
    private val maximumSteps: Long,
    private val aggregate: FullTreeDwarfParseBudget,
    private val callback: (String) -> Unit,
) {
    private var steps = 0L

    fun consume(label: String) {
        aggregate.consume("DWARF line-table $label")
        steps = try {
            Math.addExact(steps, 1L)
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("DWARF line-table parse-step count overflows", failure)
        }
        if (steps > maximumSteps) {
            throw FullTreeControlException("DWARF line-table parse-step bound exceeded while reading $label")
        }
        if (steps == 1L || steps % CHECKPOINT_STEPS == 0L) callback(label)
    }

    fun checkpoint(label: String) = callback(label)
}

/** Pure POSIX normalization matching `posixpath.normpath` for nonempty joined paths. */
private fun normalizePosix(path: String): String {
    var initialSlashes = 0
    if (path.startsWith('/')) {
        initialSlashes = if (path.startsWith("//") && !path.startsWith("///")) 2 else 1
    }
    val components = ArrayList<String>()
    path.split('/').forEach { component ->
        when {
            component.isEmpty() || component == "." -> Unit
            component == ".." && components.isNotEmpty() && components.last() != ".." -> components.removeAt(
                components.lastIndex,
            )
            component == ".." && initialSlashes > 0 -> Unit
            else -> components += component
        }
    }
    val prefix = "/".repeat(initialSlashes)
    val result = prefix + components.joinToString("/")
    return result.ifEmpty { "." }
}

private fun add(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("DWARF $label overflows", failure)
}

private val STRING_FORMS = setOf(
    FULL_TREE_DW_FORM_STRING,
    FULL_TREE_DW_FORM_STRP,
    FULL_TREE_DW_FORM_LINE_STRP,
    FULL_TREE_DW_FORM_STRX,
    FULL_TREE_DW_FORM_STRX1,
    FULL_TREE_DW_FORM_STRX2,
    FULL_TREE_DW_FORM_STRX3,
    FULL_TREE_DW_FORM_STRX4,
)
private val UNSIGNED_FORMS = setOf(
    FULL_TREE_DW_FORM_DATA1,
    FULL_TREE_DW_FORM_DATA2,
    FULL_TREE_DW_FORM_DATA4,
    FULL_TREE_DW_FORM_DATA8,
    FULL_TREE_DW_FORM_UDATA,
)
private const val DW_LNCT_PATH = 0x01L
private const val DW_LNCT_DIRECTORY_INDEX = 0x02L
private const val DWARF_64_MARKER = 0xffff_ffffL
private const val RESERVED_LENGTH_MIN = 0xffff_fff0L
private const val RESERVED_LENGTH_MAX = 0xffff_fffeL
private const val CHECKPOINT_STEPS = 1024L

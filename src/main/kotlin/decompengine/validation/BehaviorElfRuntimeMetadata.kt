package decompengine.validation

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.file.Path

internal data class BehaviorElfRuntimeMetadata(
    val machine: Int,
    val elfClass: Int,
    val byteOrder: ByteOrder,
    val osAbi: Int,
    val abiFlags: Long,
    val interpreter: Path?,
    val neededLibraries: List<String>,
)

/** Reads only the bounded ELF program and dynamic tables needed to stage shared objects. */
internal object BehaviorElfRuntimeMetadataReader {
    private const val PT_LOAD = 1L
    private const val PT_DYNAMIC = 2L
    private const val PT_INTERP = 3L
    private const val DT_NULL = 0L
    private const val DT_NEEDED = 1L
    private const val DT_STRTAB = 5L
    private const val DT_STRSZ = 10L
    private const val DT_RPATH = 15L
    private const val DT_RUNPATH = 29L
    private val DEFERRED_OR_EXTERNAL_LOADS = setOf(
        0x6ffffefaL, // DT_CONFIG
        0x6ffffefbL, // DT_DEPAUDIT
        0x6ffffefcL, // DT_AUDIT
        0x7fffffffL, // DT_FILTER
        0x7ffffffdL, // DT_AUXILIARY
    )

    fun read(bytes: ByteArray): BehaviorElfRuntimeMetadata {
        require(bytes.size in 52..BehaviorEvidenceCapture.MAXIMUM_FILE_BYTES) {
            "behavior runtime input is not a bounded ELF file"
        }
        require(bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte()) {
            "behavior executable is not an ELF file"
        }
        val elfClass = bytes[4].toUByte().toInt()
        val byteOrder = when (bytes[5].toUByte().toInt()) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw IllegalArgumentException("behavior ELF has an unsupported byte order")
        }
        require(elfClass == 1 || elfClass == 2) { "behavior ELF has an unsupported class" }
        val buffer = ByteBuffer.wrap(bytes).order(byteOrder)
        val headerSize = if (elfClass == 2) 64 else 52
        require(bytes.size >= headerSize && u32(buffer.getInt(20)) == 1L) {
            "behavior ELF header is truncated or has an unsupported version"
        }
        val kind = buffer.getShort(16).toUShort().toInt()
        require(kind == 2 || kind == 3) { "behavior ELF is not executable or position independent" }
        val machine = buffer.getShort(18).toUShort().toInt()
        val osAbi = bytes[7].toUByte().toInt()
        val abiFlags = u32(buffer.getInt(if (elfClass == 2) 48 else 36))
        val programOffset = if (elfClass == 2) u64(buffer.getLong(32), bytes.size.toLong(), "ELF program table")
            else u32(buffer.getInt(28))
        val programEntryBytes = buffer.getShort(if (elfClass == 2) 54 else 42).toUShort().toInt()
        val programCount = buffer.getShort(if (elfClass == 2) 56 else 44).toUShort().toInt()
        val expectedProgramEntryBytes = if (elfClass == 2) 56 else 32
        require(programCount in 1..MAXIMUM_PROGRAM_HEADERS && programEntryBytes >= expectedProgramEntryBytes) {
            "behavior ELF program table exceeds its bounds"
        }
        val programTableBytes = Math.multiplyExact(programCount.toLong(), programEntryBytes.toLong())
        requireRange(programOffset, programTableBytes, bytes.size.toLong(), "ELF program table")
        val loads = mutableListOf<LoadSegment>()
        var interpreter: Path? = null
        var dynamic: FileRange? = null
        for (index in 0 until programCount) {
            val position = Math.toIntExact(programOffset + index.toLong() * programEntryBytes)
            val header = ByteBuffer.wrap(bytes, position, expectedProgramEntryBytes).slice().order(byteOrder)
            val type = u32(header.getInt(0))
            val offset: Long
            val virtualAddress: Long
            val fileBytes: Long
            if (elfClass == 2) {
                offset = u64(header.getLong(8), bytes.size.toLong(), "ELF segment")
                virtualAddress = u64(header.getLong(16), Long.MAX_VALUE, "ELF virtual address")
                fileBytes = u64(header.getLong(32), bytes.size.toLong(), "ELF segment")
            } else {
                offset = u32(header.getInt(4))
                virtualAddress = u32(header.getInt(8))
                fileBytes = u32(header.getInt(16))
            }
            requireRange(offset, fileBytes, bytes.size.toLong(), "ELF segment")
            when (type) {
                PT_LOAD -> loads += LoadSegment(offset, virtualAddress, fileBytes)
                PT_INTERP -> {
                    require(interpreter == null && fileBytes in 2..MAXIMUM_INTERPRETER_BYTES.toLong()) {
                        "behavior ELF interpreter segment is duplicated or outside its bound"
                    }
                    val value = nulTerminatedString(bytes, offset, fileBytes, "ELF interpreter")
                    val path = Path.of(value)
                    require(path.isAbsolute && path.normalize() == path && path.toString() == value) {
                        "behavior ELF interpreter path is not absolute and normalized"
                    }
                    interpreter = path
                }
                PT_DYNAMIC -> {
                    require(dynamic == null && fileBytes > 0L && fileBytes % (if (elfClass == 2) 16L else 8L) == 0L) {
                        "behavior ELF dynamic segment is duplicated or malformed"
                    }
                    dynamic = FileRange(offset, fileBytes)
                }
            }
        }

        val needed = if (dynamic == null) {
            emptyList()
        } else {
            val entryBytes = if (elfClass == 2) 16 else 8
            require(dynamic.bytes / entryBytes <= MAXIMUM_DYNAMIC_ENTRIES) {
                "behavior ELF dynamic table exceeds its entry bound"
            }
            val dynamicBuffer = ByteBuffer.wrap(bytes, dynamic.offset.toInt(), dynamic.bytes.toInt())
                .slice().order(byteOrder)
            val names = mutableListOf<Long>()
            var stringAddress: Long? = null
            var stringBytes: Long? = null
            var terminated = false
            repeat(dynamic.bytes.toInt() / entryBytes) {
                if (!terminated) {
                    val tag = if (elfClass == 2) dynamicBuffer.getLong() else dynamicBuffer.getInt().toLong()
                    val value = if (elfClass == 2) {
                        u64(dynamicBuffer.getLong(), Long.MAX_VALUE, "ELF dynamic value")
                    } else u32(dynamicBuffer.getInt())
                    when (tag) {
                        DT_NULL -> terminated = true
                        DT_NEEDED -> {
                            require(names.size < MAXIMUM_NEEDED_LIBRARIES) {
                                "behavior ELF has too many direct shared-library dependencies"
                            }
                            names += value
                        }
                        DT_STRTAB -> {
                            require(stringAddress == null) { "behavior ELF has duplicate dynamic string tables" }
                            stringAddress = value
                        }
                        DT_STRSZ -> {
                            require(stringBytes == null) { "behavior ELF has duplicate dynamic string-table sizes" }
                            stringBytes = value
                        }
                        DT_RPATH, DT_RUNPATH -> throw IllegalArgumentException(
                            "behavior ELF RPATH/RUNPATH is outside the closed runtime search policy",
                        )
                        in DEFERRED_OR_EXTERNAL_LOADS -> throw IllegalArgumentException(
                            "behavior ELF contains an unsupported dynamic loading directive",
                        )
                    }
                }
            }
            require(terminated) { "behavior ELF dynamic table is unterminated" }
            if (names.isEmpty()) {
                emptyList()
            } else {
                val address = requireNotNull(stringAddress) { "behavior ELF dependencies have no string table" }
                val size = requireNotNull(stringBytes) { "behavior ELF dependencies have no string-table size" }
                require(size in 1..MAXIMUM_DYNAMIC_STRING_BYTES.toLong()) {
                    "behavior ELF string table exceeds its bound"
                }
                val stringOffset = loads.firstNotNullOfOrNull { it.fileOffsetFor(address, size) }
                    ?: throw IllegalArgumentException("behavior ELF dynamic string table is not file backed")
                requireRange(stringOffset, size, bytes.size.toLong(), "ELF dynamic string table")
                names.map { offset ->
                    require(offset in 1 until size) { "behavior ELF dependency name is outside its string table" }
                    nulTerminatedString(bytes, stringOffset + offset, size - offset, "ELF dependency name")
                        .also { name ->
                            require(name.matches(SONAME_PATTERN) && '/' !in name) {
                                "behavior ELF dependency name is not a normalized soname"
                            }
                        }
                }.distinct()
            }
        }
        return BehaviorElfRuntimeMetadata(machine, elfClass, byteOrder, osAbi, abiFlags, interpreter, needed)
    }

    private data class FileRange(val offset: Long, val bytes: Long)

    private data class LoadSegment(val fileOffset: Long, val virtualAddress: Long, val fileBytes: Long) {
        fun fileOffsetFor(address: Long, size: Long): Long? {
            if (address < virtualAddress) return null
            val relative = address - virtualAddress
            if (relative > fileBytes || size > fileBytes - relative) return null
            return Math.addExact(fileOffset, relative)
        }
    }

    private fun nulTerminatedString(bytes: ByteArray, offset: Long, maximumBytes: Long, subject: String): String {
        require(maximumBytes in 1..MAXIMUM_DYNAMIC_STRING_BYTES.toLong()) { "$subject exceeds its string bound" }
        requireRange(offset, maximumBytes, bytes.size.toLong(), subject)
        val start = Math.toIntExact(offset)
        val maximum = Math.toIntExact(maximumBytes)
        val end = (start until start + maximum).firstOrNull { bytes[it] == 0.toByte() }
            ?: throw IllegalArgumentException("$subject is unterminated")
        require(end > start && end - start <= MAXIMUM_INTERPRETER_BYTES) { "$subject is empty or too long" }
        return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, start, end - start)).toString()
    }

    private fun u32(value: Int): Long = value.toUInt().toLong()

    private fun u64(value: Long, maximum: Long, subject: String): Long {
        val unsigned = value.toULong()
        require(unsigned <= maximum.toULong()) { "$subject is outside its bound" }
        return unsigned.toLong()
    }

    private fun requireRange(offset: Long, length: Long, total: Long, subject: String) {
        require(offset >= 0L && length >= 0L && offset <= total && length <= total - offset) {
            "$subject is outside its ELF file"
        }
    }

    private const val MAXIMUM_PROGRAM_HEADERS = 4096
    private const val MAXIMUM_DYNAMIC_ENTRIES = 65_536L
    private const val MAXIMUM_NEEDED_LIBRARIES = 4096
    private const val MAXIMUM_INTERPRETER_BYTES = 4096
    private const val MAXIMUM_DYNAMIC_STRING_BYTES = 16 * 1024 * 1024
    private val SONAME_PATTERN = Regex("[A-Za-z0-9_.+~-]{1,255}")
}

package decompengine.binary

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class UnresolvedSymbol(
    val name: String,
    val kind: SymbolKind,
    val binding: SymbolBinding,
    val size: ULong,
)

enum class SymbolKind { FUNCTION, OBJECT, OTHER }
enum class SymbolBinding { LOCAL, GLOBAL, WEAK, UNKNOWN }

data class SymbolInventory(
    val functions: List<UnresolvedSymbol>,
    val objects: List<UnresolvedSymbol>,
    val other: List<UnresolvedSymbol>,
) {
    val all: List<UnresolvedSymbol> get() = functions + objects + other
    val isEmpty: Boolean get() = all.isEmpty()

    companion object {
        val EMPTY = SymbolInventory(emptyList(), emptyList(), emptyList())
    }
}

/**
 * Reads the ELF dynamic symbol table (.dynsym) and reports symbols that are
 * still undefined (st_shndx == SHN_UNDEF), i.e. external imports that the
 * reconstructed project depends on but does not itself define. These are the
 * functions/globals that must be resolved against libc or another runtime.
 */
object ElfSymbolInventoryReader {
    private const val SHT_DYNSYM = 11
    private const val SHT_STRTAB = 3
    private const val SHN_UNDEF = 0
    private const val STT_FUNC = 2
    private const val STT_OBJECT = 1
    private const val STB_GLOBAL = 1
    private const val STB_WEAK = 2

    fun read(bytes: ByteArray, metadata: ElfMetadata): SymbolInventory {
        val elfClass = if (metadata.format == "ELF64") 2 else 1
        val byteOrder = if (metadata.endianness == "little") ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val buffer = ByteBuffer.wrap(bytes).order(byteOrder)

        val shoff = readSectionHeaderOffset(buffer, elfClass)
        if (shoff == 0L) return SymbolInventory.EMPTY
        val (shentsize, shcount) = readSectionHeaderSizes(buffer, elfClass)
        if (shentsize == 0 || shcount == 0) return SymbolInventory.EMPTY
        if (shoff + shentsize.toLong() * shcount > bytes.size) return SymbolInventory.EMPTY

        val dynsym = findSection(buffer, shoff, shentsize, shcount, elfClass) { type, _ -> type == SHT_DYNSYM }
            ?: return SymbolInventory.EMPTY

        val link = dynsym.link.toInt()
        if (link < 0 || link >= shcount) return SymbolInventory.EMPTY
        val strtab = readSectionHeader(buffer, shoff, shentsize, link, elfClass)
        if (strtab.type != SHT_STRTAB) return SymbolInventory.EMPTY
        if (dynsym.entsize == 0L) return SymbolInventory.EMPTY

        val strtabBytes = bytes.copyOfRange(
            strtab.offset.toInt(),
            (strtab.offset + strtab.size).toInt().coerceAtMost(bytes.size),
        )

        val symSize = dynsym.entsize
        val symCount = (dynsym.size / symSize).toInt()
        val unresolved = mutableListOf<UnresolvedSymbol>()
        var cursor = dynsym.offset.toInt()
        repeat(symCount) {
            if (cursor + symSize.toInt() > bytes.size) return@repeat
            val sym = readSymbol(buffer, cursor, elfClass, symSize.toInt())
            cursor += symSize.toInt()
            if (sym.shndx == SHN_UNDEF && sym.nameOffset != 0) {
                val name = readString(strtabBytes, sym.nameOffset)
                if (name.isEmpty()) return@repeat
                unresolved += UnresolvedSymbol(
                    name = name,
                    kind = when (sym.type) {
                        STT_FUNC -> SymbolKind.FUNCTION
                        STT_OBJECT -> SymbolKind.OBJECT
                        else -> SymbolKind.OTHER
                    },
                    binding = when (sym.bind) {
                        STB_GLOBAL -> SymbolBinding.GLOBAL
                        STB_WEAK -> SymbolBinding.WEAK
                        0 -> SymbolBinding.LOCAL
                        else -> SymbolBinding.UNKNOWN
                    },
                    size = sym.size,
                )
            }
        }

        return SymbolInventory(
            functions = unresolved.filter { it.kind == SymbolKind.FUNCTION },
            objects = unresolved.filter { it.kind == SymbolKind.OBJECT },
            other = unresolved.filter { it.kind == SymbolKind.OTHER },
        )
    }

    private data class SectionHeader(
        val type: Int,
        val offset: Long,
        val size: Long,
        val link: Long,
        val entsize: Long,
    )

    private data class RawSymbol(
        val nameOffset: Int,
        val type: Int,
        val bind: Int,
        val shndx: Int,
        val size: ULong,
    )

    private fun readSectionHeaderOffset(buffer: ByteBuffer, elfClass: Int): Long {
        buffer.position(if (elfClass == 2) 40 else 32)
        return if (elfClass == 2) buffer.long else buffer.int.toLong()
    }

    private fun readSectionHeaderSizes(buffer: ByteBuffer, elfClass: Int): Pair<Int, Int> {
        buffer.position(if (elfClass == 2) 58 else 46)
        val shentsize = buffer.short.toUShort().toInt()
        val shcount = buffer.short.toUShort().toInt()
        return shentsize to shcount
    }

    private fun readSectionHeader(
        buffer: ByteBuffer,
        shoff: Long,
        shentsize: Int,
        index: Int,
        elfClass: Int,
    ): SectionHeader {
        val base = (shoff + index.toLong() * shentsize).toInt()
        buffer.position(base)
        buffer.int // sh_name
        val type = buffer.int
        return if (elfClass == 2) {
            buffer.long // sh_flags
            buffer.long // sh_addr
            val offset = buffer.long
            val size = buffer.long
            val link = buffer.int.toLong() and 0xffffffffL
            buffer.int // sh_info
            buffer.long // sh_addralign
            val entsize = buffer.long
            SectionHeader(type, offset, size, link, entsize)
        } else {
            buffer.int // sh_flags
            buffer.int // sh_addr
            val offset = buffer.int.toLong() and 0xffffffffL
            val size = buffer.int.toLong() and 0xffffffffL
            val link = buffer.int.toLong() and 0xffffffffL
            buffer.int // sh_info
            buffer.int // sh_addralign
            val entsize = buffer.int.toLong() and 0xffffffffL
            SectionHeader(type, offset, size, link, entsize)
        }
    }

    private fun findSection(
        buffer: ByteBuffer,
        shoff: Long,
        shentsize: Int,
        shcount: Int,
        elfClass: Int,
        predicate: (type: Int, index: Int) -> Boolean,
    ): SectionHeader? {
        for (index in 0 until shcount) {
            val header = readSectionHeader(buffer, shoff, shentsize, index, elfClass)
            if (predicate(header.type, index)) return header
        }
        return null
    }

    private fun readSymbol(buffer: ByteBuffer, offset: Int, elfClass: Int, entrySize: Int): RawSymbol {
        buffer.position(offset)
        val nameOffset = buffer.int
        return if (elfClass == 2) {
            val info = buffer.get().toInt() and 0xff
            buffer.get() // st_other
            val shndx = buffer.short.toUShort().toInt()
            buffer.long // st_value
            val size = buffer.long.toULong()
            RawSymbol(nameOffset, info and 0xf, info ushr 4, shndx, size)
        } else {
            buffer.int // st_value
            buffer.int // st_size
            val info = buffer.get().toInt() and 0xff
            buffer.get() // st_other
            val shndx = buffer.short.toUShort().toInt()
            RawSymbol(nameOffset, info and 0xf, info ushr 4, shndx, entrySize.toULong())
        }
    }

    private fun readString(bytes: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= bytes.size) return ""
        val end = (offset until bytes.size).firstOrNull { bytes[it] == 0.toByte() } ?: bytes.size
        return String(bytes, offset, end - offset, Charsets.UTF_8)
    }
}

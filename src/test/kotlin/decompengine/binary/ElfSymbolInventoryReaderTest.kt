package decompengine.binary

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ElfSymbolInventoryReaderTest {
    @Test
    fun `parses unresolved functions and objects from dynsym`() {
        val elf = buildElf64WithDynsym()

        val metadata = ElfMetadataReader.read(elf)
        val inventory = ElfSymbolInventoryReader.read(elf, metadata)

        assertEquals(listOf("puts"), inventory.functions.map { it.name })
        assertEquals(listOf("printf"), inventory.objects.map { it.name })
        assertTrue(inventory.other.isEmpty())
        assertEquals(SymbolKind.FUNCTION, inventory.functions.first().kind)
        assertEquals(SymbolKind.OBJECT, inventory.objects.first().kind)
        assertEquals(SymbolBinding.GLOBAL, inventory.functions.first().binding)
        assertEquals(8UL, inventory.objects.first().size)
    }

    @Test
    fun `returns empty inventory when no dynsym present`() {
        val elf = ByteArray(64).also { it[0] = 0x7f; it[1] = 'E'.code.toByte(); it[2] = 'L'.code.toByte(); it[3] = 'F'.code.toByte(); it[4] = 2; it[5] = 1; it[6] = 1; it[7] = 3 }
        val metadata = ElfMetadataReader.read(elf)
        val inventory = ElfSymbolInventoryReader.read(elf, metadata)
        assertTrue(inventory.isEmpty)
    }

    private fun buildElf64WithDynsym(): ByteArray {
        val shstrtab = "\u0000.shstrtab\u0000.dynstr\u0000.dynsym\u0000".toByteArray(Charsets.UTF_8)
        val dynstr = "\u0000puts\u0000printf\u0000".toByteArray(Charsets.UTF_8)
        val nullSym = ByteArray(24)
        val putsSym = ByteArray(24).also {
            putInt(it, 0, 1)        // st_name = "puts"
            it[4] = ((1 shl 4) or 2).toByte() // GLOBAL | FUNC
            it[5] = 0
            putShort(it, 6, 0)      // st_shndx = UNDEF
            putLong(it, 8, 0)       // st_value
            putLong(it, 16, 0)      // st_size
        }
        val printfSym = ByteArray(24).also {
            putInt(it, 0, 6)        // st_name = "printf"
            it[4] = ((1 shl 4) or 1).toByte() // GLOBAL | OBJECT
            it[5] = 0
            putShort(it, 6, 0)      // st_shndx = UNDEF
            putLong(it, 8, 0)
            putLong(it, 16, 8)      // st_size
        }
        val dynsym = nullSym + putsSym + printfSym

        val headerSize = 64
        val dataStart = headerSize
        val shstrtabOff = dataStart
        val dynstrOff = shstrtabOff + shstrtab.size
        val dynsymOff = dynstrOff + dynstr.size
        val dataEnd = dynsymOff + dynsym.size
        val padding = ByteArray((8 - dataEnd % 8) % 8)
        val shoff = dataEnd + padding.size

        val shentsize = 64
        val shcount = 4
        val total = shoff + shentsize * shcount
        val out = ByteArray(total)

        out[0] = 0x7f; out[1] = 'E'.code.toByte(); out[2] = 'L'.code.toByte(); out[3] = 'F'.code.toByte()
        out[4] = 2; out[5] = 1; out[6] = 1; out[7] = 3 // ELF64, little, ELF v1, Linux
        putShort(out, 16, 2)    // e_type = ET_EXEC
        putShort(out, 18, 62)   // e_machine = x86-64
        putInt(out, 20, 1)      // e_version
        putLong(out, 24, 0x401000) // e_entry
        putLong(out, 32, 0)     // e_phoff
        putLong(out, 40, shoff.toLong()) // e_shoff
        putInt(out, 48, 0)      // e_flags
        putShort(out, 52, 64)   // e_ehsize
        putShort(out, 54, 56)   // e_phentsize
        putShort(out, 56, 0)    // e_phnum
        putShort(out, 58, shentsize) // e_shentsize
        putShort(out, 60, shcount)    // e_shnum
        putShort(out, 62, 1)    // e_shstrndx = section 1

        System.arraycopy(shstrtab, 0, out, shstrtabOff, shstrtab.size)
        System.arraycopy(dynstr, 0, out, dynstrOff, dynstr.size)
        System.arraycopy(dynsym, 0, out, dynsymOff, dynsym.size)

        // Section headers
        writeShdr(out, shoff + 0 * shentsize, shentsize, name = 0, type = 0, offset = 0, size = 0, link = 0, entsize = 0)
        writeShdr(out, shoff + 1 * shentsize, shentsize, name = 1, type = 3, offset = shstrtabOff, size = shstrtab.size, link = 0, entsize = 0) // .shstrtab
        writeShdr(out, shoff + 2 * shentsize, shentsize, name = 11, type = 3, offset = dynstrOff, size = dynstr.size, link = 0, entsize = 0) // .dynstr
        writeShdr(out, shoff + 3 * shentsize, shentsize, name = 19, type = 11, offset = dynsymOff, size = dynsym.size, link = 2, entsize = 24) // .dynsym

        return out
    }

    private fun writeShdr(buf: ByteArray, base: Int, shentsize: Int, name: Int, type: Int, offset: Int, size: Int, link: Int, entsize: Int) {
        putInt(buf, base + 0, name)
        putInt(buf, base + 4, type)
        putLong(buf, base + 8, 0)   // sh_flags
        putLong(buf, base + 16, 0)  // sh_addr
        putLong(buf, base + 24, offset.toLong())
        putLong(buf, base + 32, size.toLong())
        putInt(buf, base + 40, link)
        putInt(buf, base + 44, 0)   // sh_info
        putLong(buf, base + 48, 0)  // sh_addralign
        putLong(buf, base + 56, entsize.toLong())
    }

    private fun putShort(buf: ByteArray, off: Int, v: Int) {
        buf[off] = v.toByte(); buf[off + 1] = (v ushr 8).toByte()
    }

    private fun putInt(buf: ByteArray, off: Int, v: Int) {
        repeat(4) { buf[off + it] = (v ushr (it * 8)).toByte() }
    }

    private fun putLong(buf: ByteArray, off: Int, v: Long) {
        repeat(8) { buf[off + it] = (v ushr (it * 8)).toByte() }
    }
}

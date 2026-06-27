package decompengine.l1

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class ElfMetadata(
    val format: String,
    val endianness: String,
    val elfVersion: UInt,
    val osAbi: String,
    val objectType: String,
    val machine: String,
    val entryPoint: ULong,
    val elfHeaderSize: UShort,
    val programHeaderCount: UShort,
    val sectionHeaderCount: UShort,
    val sectionNameTableIndex: UShort,
)

class InvalidElfException(message: String) : IllegalArgumentException(message)

object ElfMetadataReader {
    private val magic = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)

    fun read(bytes: ByteArray): ElfMetadata {
        if (bytes.size < 16 || !bytes.copyOfRange(0, 4).contentEquals(magic)) {
            throw InvalidElfException("uploaded file is not an ELF binary")
        }

        val elfClass = bytes[4].toUByte().toInt()
        val dataEncoding = bytes[5].toUByte().toInt()
        val headerSize = when (elfClass) {
            1 -> 52
            2 -> 64
            else -> throw InvalidElfException("unsupported ELF class: $elfClass")
        }
        val byteOrder = when (dataEncoding) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw InvalidElfException("unsupported ELF data encoding: $dataEncoding")
        }
        if (bytes.size < headerSize) {
            throw InvalidElfException("uploaded ELF header is truncated")
        }

        val buffer = ByteBuffer.wrap(bytes).order(byteOrder)
        buffer.position(16)
        val objectType = buffer.short.toUShort().toInt()
        val machine = buffer.short.toUShort().toInt()
        val version = buffer.int.toUInt()
        val entryPoint = if (elfClass == 2) buffer.long.toULong() else buffer.int.toUInt().toULong()
        if (elfClass == 2) {
            buffer.long
            buffer.long
        } else {
            buffer.int
            buffer.int
        }
        buffer.int
        val elfHeaderSize = buffer.short.toUShort()
        buffer.short
        val programHeaderCount = buffer.short.toUShort()
        buffer.short
        val sectionHeaderCount = buffer.short.toUShort()
        val sectionNameTableIndex = buffer.short.toUShort()

        return ElfMetadata(
            format = if (elfClass == 2) "ELF64" else "ELF32",
            endianness = if (dataEncoding == 1) "little" else "big",
            elfVersion = version,
            osAbi = when (bytes[7].toUByte().toInt()) {
                0 -> "System V"
                3 -> "Linux"
                else -> "unknown(${bytes[7].toUByte().toInt()})"
            },
            objectType = when (objectType) {
                1 -> "relocatable"
                2 -> "executable"
                3 -> "shared"
                4 -> "core"
                else -> "unknown($objectType)"
            },
            machine = when (machine) {
                3 -> "x86"
                40 -> "ARM"
                62 -> "x86-64"
                183 -> "AArch64"
                243 -> "RISC-V"
                else -> "unknown($machine)"
            },
            entryPoint = entryPoint,
            elfHeaderSize = elfHeaderSize,
            programHeaderCount = programHeaderCount,
            sectionHeaderCount = sectionHeaderCount,
            sectionNameTableIndex = sectionNameTableIndex,
        )
    }
}

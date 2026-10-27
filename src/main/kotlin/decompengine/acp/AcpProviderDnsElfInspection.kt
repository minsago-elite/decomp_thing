package decompengine.acp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections

/** Non-executing ELF64 observation. No host library lookup, ldd, producer edges or dlopen inference. */
internal object AcpProviderDnsElfInspection {
    class Metadata internal constructor(val sha256: String, val bytes: Long, val interpreter: String?,
        val elfType: Int, val isPie: Boolean, val soname: String?, needed: List<String>,
        versionsNeeded: Map<String, Set<String>>, versionsDefined: Set<String>) {
        val needed = Collections.unmodifiableList(needed.toList())
        val versionsNeeded = Collections.unmodifiableMap(versionsNeeded.mapValues { Collections.unmodifiableSet(it.value.toSet()) })
        val versionsDefined = Collections.unmodifiableSet(versionsDefined.toSet())
        val fitsCurrentRuntimeFileLimit: Boolean = bytes <= AcpProviderDnsRuntimeProfiles.MAXIMUM_FILE_BYTES
        // DT_NEEDED/version closure never proves JVM/NSS explicit dlopen or source-semantic closure.
    }
    fun inspect(input: ByteArray): Metadata {
        require(input.size in 64..AcpProviderDnsBuildInputs.MEMBER_BYTES.toInt())
        return inspectOwned(input.copyOf())
    }

    /** Caller transfers an exclusively owned bounded buffer; no retained byte reference escapes. */
    internal fun inspectOwned(bytes: ByteArray): Metadata {
        require(bytes.size in 64..AcpProviderDnsBuildInputs.MEMBER_BYTES.toInt())
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(bytes.take(7) == listOf(0x7f.toByte(), 69.toByte(), 76.toByte(), 70.toByte(), 2.toByte(), 1.toByte(), 1.toByte()))
        require(bytes[7].toInt() in setOf(0, 3) && bytes[8] == 0.toByte() && (9..15).all { bytes[it] == 0.toByte() })
        fun u16(at: Int) = b.getShort(at).toInt() and 65535
        fun u32(at: Int) = b.getInt(at).toLong() and 0xffffffffL
        fun nonnegative(at: Int) = b.getLong(at).also { require(it >= 0) }
        fun range(offset: Long, length: Long): Int { require(offset >= 0 && length >= 0 && offset <= bytes.size && length <= bytes.size - offset); return offset.toInt() }
        val elfType = u16(16)
        require(elfType in setOf(2, 3) && u16(18) == 62 && u32(20) == 1L && u32(48) == 0L && u16(52) == 64)
        val ph = nonnegative(32); val count = u16(56)
        require(count in 1..512 && u16(54) == 56); range(ph, count * 56L)
        data class Load(val offset: Long, val address: Long, val length: Long, val memory: Long)
        var mappedMemory = 0L
        var nonExecutableStack = false
        val loads = mutableListOf<Load>(); var dynamic: Triple<Long, Long, Long>? = null; var interpreter: String? = null
        fun text(offset: Long, maximum: Long): String {
            val start = range(offset, maximum); require(maximum in 1..1024 * 1024)
            val end = (start until start + maximum.toInt()).firstOrNull { bytes[it] == 0.toByte() } ?: error("unterminated ELF string")
            require(end > start && end - start <= 4096)
            val value = bytes.copyOfRange(start, end).decodeToString(throwOnInvalidSequence = true)
            require(value.all { it.code in 32..126 }); return value
        }
        repeat(count) { index ->
            val at = (ph + index * 56L).toInt(); val type = u32(at); val flags = u32(at + 4)
            require(flags and 7L.inv() == 0L)
            val offset = nonnegative(at + 8); val address = nonnegative(at + 16)
            val size = nonnegative(at + 32); val memory = nonnegative(at + 40)
            range(offset, size); require(memory >= size && memory <= AcpProviderDnsRuntimeProfiles.MAXIMUM_BYTES && address <= Long.MAX_VALUE - memory)
            val alignment = nonnegative(at + 48)
            require(alignment == 0L || alignment and (alignment - 1) == 0L && alignment <= 2L * 1024 * 1024 && offset % alignment == address % alignment)
            if (type == 0x6474e551L) {
                require(!nonExecutableStack && flags and 1L == 0L) { "ELF requires exactly one non-executable GNU_STACK" }
                nonExecutableStack = true
            }
            when (type) {
                1L -> { require(flags and 3L != 3L)
                    mappedMemory = dnsCharge(mappedMemory, memory, AcpProviderDnsRuntimeProfiles.MAXIMUM_BYTES)
                    loads += Load(offset, address, size, memory) }
                2L -> { require(dynamic == null && size in 16..65536 && size % 16 == 0L); dynamic = Triple(offset, address, size) }
                3L -> { require(interpreter == null && size in 2..4096); interpreter = text(offset, size)
                    require(interpreter == "/lib64/ld-linux-x86-64.so.2" && bytes[(offset + size - 1).toInt()] == 0.toByte()) }
                0L, 4L, 6L, 7L, 0x6474e550L, 0x6474e551L, 0x6474e552L, 0x6474e553L -> Unit
                else -> error("unsupported ELF program header")
            }
        }
        // Missing GNU_STACK is not an explicit NX declaration on the supported Linux/glibc ABI.
        require(nonExecutableStack) { "ELF requires an explicit non-executable GNU_STACK" }
        fun mapped(address: Long, length: Long): Int {
            require(length > 0 && address >= 0 && address <= Long.MAX_VALUE - length)
            // Even a second LOAD covering only part of the range makes loaded bytes ambiguous.
            val match = loads.filter { load -> load.memory > 0 &&
                if (address >= load.address) address - load.address < load.memory else load.address - address < length
            }.single()
            require(address >= match.address && address - match.address <= match.length &&
                length <= match.length - (address - match.address))
            return range(Math.addExact(match.offset, address - match.address), length)
        }
        val tags = linkedMapOf<Long, Long>(); val neededOffsets = mutableListOf<Long>()
        dynamic?.let { (offset, address, size) ->
            // The loader consumes this virtual range, not an unrelated p_offset table.
            require(mapped(address, size).toLong() == offset)
            var terminated = false
            repeat((size / 16).toInt()) { n ->
                val at = (offset + n * 16L).toInt(); val tag = b.getLong(at); val value = nonnegative(at + 8)
                if (terminated) require(tag == 0L && value == 0L)
                else if (tag == 0L) { require(value == 0L); terminated = true }
                else {
                    require(tag != 15L && tag != 29L) { "unsupported ELF RPATH/RUNPATH" }
                    require(tag != 22L) { "unsupported ELF text relocations" }
                    require(tag !in setOf(0x6ffffefaL, 0x6ffffefbL, 0x6ffffefcL, 0x7fffffffL, 0x7ffffffdL)) { "unsupported ELF external loading directive" }
                    require(tag in (1L..14L) || tag in (16L..28L) || tag in (30L..37L) ||
                        tag in setOf(0x6ffffef5L, 0x6ffffff0L, 0x6ffffff9L, 0x6ffffffaL, 0x6ffffffbL, 0x6ffffffcL, 0x6ffffffdL, 0x6ffffffeL, 0x6fffffffL))
                    if (tag == 1L) { require(neededOffsets.size < 256); neededOffsets += value }
                    else require(tags.put(tag, value) == null)
                }
            }
            require(terminated)
        }
        tags[30L]?.let { require(it and (8L or 16L).inv() == 0L) }
        tags[0x6ffffffbL]?.let { require(it and (1L or 0x08000000L).inv() == 0L) }
        val isPie = (tags[0x6ffffffbL] ?: 0L) and 0x08000000L != 0L
        val stringBytes = tags[10L]
        val stringStart = tags[5L]?.let { mapped(it, requireNotNull(stringBytes).also { size -> require(size in 1..1024 * 1024) }) }
        require((tags[5L] == null) == (stringBytes == null))
        fun string(index: Long): String { require(index in 1 until requireNotNull(stringBytes)); return text(requireNotNull(stringStart).toLong() + index, stringBytes - index) }
        fun name(index: Long) = string(index).also { require(it.matches(Regex("[A-Za-z0-9_.+~-]{1,255}"))) }
        val needed = neededOffsets.map(::name); require(needed.distinct().size == needed.size)
        val soname = tags[14L]?.let(::name)
        require(soname == null || elfType == 3 && !isPie) { "ELF SONAME provider must be non-PIE ET_DYN" }
        val versionIndices = mutableSetOf(0, 1)
        val definitions = linkedSetOf<String>(); val parentVersions = linkedSetOf<String>(); val requirements = linkedMapOf<String, Set<String>>()
        fun records(addressTag: Long, countTag: Long, bytesPerRecord: Long, action: (Int, Long) -> Long) {
            val address = tags[addressTag]; val number = tags[countTag]
            require((address == null) == (number == null))
            if (address == null) return
            require(requireNotNull(number) in 1..256)
            var cursor: Long = requireNotNull(address); val seen = hashSetOf<Long>()
            repeat(number.toInt()) { n ->
                require(seen.add(cursor)); val at = mapped(cursor, bytesPerRecord)
                val next = action(at, cursor)
                require((n == number.toInt() - 1) == (next == 0L))
                if (next != 0L) { require(next >= bytesPerRecord); cursor = Math.addExact(cursor, next) }
            }
        }
        var versionCount = 0
        records(0x6ffffffeL, 0x6fffffffL, 16) { at, address ->
            require(u16(at) == 1)
            val file = name(u32(at + 4)); require(file in needed && file !in requirements)
            val total = u16(at + 2); require(total in 1..256 && u32(at + 8) >= 16)
            var auxOffset = Math.addExact(address, u32(at + 8))
            val versions = linkedSetOf<String>(); val seen = hashSetOf<Long>()
            repeat(total) { index ->
                require(++versionCount <= 256 && seen.add(auxOffset)); val aux = mapped(auxOffset, 16)
                require(u16(aux + 4) and 2.inv() == 0)
                val versionIndex = u16(aux + 6) and 0x7fff
                val versionName = name(u32(aux + 8))
                require(u32(aux) == elfNameHash(versionName))
                require(versionIndex > 1 && versionIndices.add(versionIndex) && versions.add(versionName))
                val next = u32(aux + 12); require((index == total - 1) == (next == 0L))
                if (next != 0L) { require(next >= 16); auxOffset = Math.addExact(auxOffset, next) }
            }
            requirements[file] = Collections.unmodifiableSet(versions); u32(at + 12)
        }
        records(0x6ffffffcL, 0x6ffffffdL, 20) { at, address ->
            require(u16(at) == 1 && u16(at + 2) and 3.inv() == 0)
            val versionIndex = u16(at + 4); require(versionIndex in 1..0x7fff && (u16(at + 2) and 1 == 0 || versionIndex == 1))
            if (versionIndex > 1) require(versionIndices.add(versionIndex))
            val total = u16(at + 6); require(total in 1..256 && u32(at + 12) >= 20)
            var auxiliary = Math.addExact(address, u32(at + 12)); val seen = hashSetOf<Long>()
            repeat(total) { n ->
                require(++versionCount <= 256 && seen.add(auxiliary)); val aux = mapped(auxiliary, 8)
                val versionName = name(u32(aux))
                if (n == 0) require(u32(at + 8) == elfNameHash(versionName) && definitions.add(versionName))
                else parentVersions += versionName
                val next = u32(aux + 4); require((n == total - 1) == (next == 0L))
                if (next != 0L) { require(next >= 8); auxiliary = Math.addExact(auxiliary, next) }
            }
            u32(at + 16)
        }
        require(definitions.containsAll(parentVersions))
        tags[0x6ffffff0L]?.let { address ->
            val shoff = nonnegative(40); val shcount = u16(60)
            require(shcount in 1..4096 && u16(58) == 64); range(shoff, shcount * 64L)
            val tables = (0 until shcount).filter { u32((shoff + it * 64L).toInt() + 4) == 11L }
            require(tables.size == 1)
            val at = (shoff + tables.single() * 64L).toInt()
            require(nonnegative(at + 56) == 24L)
            val size = nonnegative(at + 32); require(size % 24 == 0L && size / 24 in 1..65536)
            val symbolOffset = range(nonnegative(at + 24), size)
            require(tags[11L] == 24L && mapped(requireNotNull(tags[6L]), size) == symbolOffset)
            val table = mapped(address, size / 24 * 2)
            repeat((size / 24).toInt()) { index -> require((u16(table + index * 2) and 0x7fff) in versionIndices) }
        }
        return Metadata(dnsSha(bytes), bytes.size.toLong(), interpreter, elfType, isPie, soname, needed, requirements, definitions)
    }

    private fun elfNameHash(name: String): Long {
        var hash = 0L
        name.toByteArray(Charsets.US_ASCII).forEach { byte ->
            hash = (hash shl 4) + (byte.toLong() and 255)
            val high = hash and 0xf0000000L
            if (high != 0L) hash = hash xor (high ushr 24)
            hash = hash and high.inv() and 0xffffffffL
        }
        return hash
    }

    /** Exact declared providers only; this still does not close semantic dlopen/NSS edges. */
    fun requireDeclaredProviders(objects: Map<String, Metadata>) {
        require(objects.size in 1..256)
        objects.keys.forEach(::dnsRelativePath)
        val providers = objects.filterValues { it.soname != null }.entries.groupBy { it.value.soname }
        require(providers.values.all { it.size == 1 })
        objects.forEach { (path, metadata) ->
            metadata.soname?.let {
                require(metadata.elfType == 3 && !metadata.isPie && path.substringAfterLast('/') == it)
            }
            if (metadata.interpreter != null) require(objects["native/ld-linux-x86-64.so.2"]?.soname == "ld-linux-x86-64.so.2")
            metadata.needed.forEach { name ->
            val provider = requireNotNull(providers[name]).single().value
            require(provider.versionsDefined.containsAll(metadata.versionsNeeded[name].orEmpty()))
        } }
    }
}

package decompengine.project

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** Fail-closed, bounded interpretation of the worker's final-namespace mount table. */
internal object ContainedModuleMountPolicy {
    private const val MAXIMUM_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_LINE_BYTES = 64 * 1024
    private const val MAXIMUM_MOUNTS = 8192
    private val MOUNTINFO = Path.of("/proc/self/mountinfo")

    internal data class Mount(val id: Long, val mountPoint: Path, val readOnly: Boolean)

    fun readCurrent(): List<Mount> {
        val bytes = ByteArrayOutputStream()
        Files.newInputStream(MOUNTINFO).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                require(bytes.size() <= MAXIMUM_BYTES - read) { "compiler mount table exceeds its byte bound" }
                bytes.write(buffer, 0, read)
            }
        }
        return parse(bytes.toByteArray())
    }

    fun parse(bytes: ByteArray): List<Mount> {
        require(bytes.isNotEmpty() && bytes.size <= MAXIMUM_BYTES) { "compiler mount table is empty or oversized" }
        var lineBytes = 0
        for (byte in bytes) {
            val value = byte.toInt() and 0xff
            if (value == '\n'.code) {
                lineBytes = 0
            } else {
                require(value >= 0x20 && value != 0x7f) {
                    "compiler mount table contains an invalid framing byte"
                }
                lineBytes++
                require(lineBytes <= MAXIMUM_LINE_BYTES) { "compiler mount table record exceeds its byte bound" }
            }
        }
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (failure: java.nio.charset.CharacterCodingException) {
            throw IllegalArgumentException("compiler mount table is not valid UTF-8", failure)
        }
        require(text.endsWith('\n')) { "compiler mount table has an unterminated record" }
        val lines = text.dropLast(1).split('\n')
        require(lines.size in 1..MAXIMUM_MOUNTS) { "compiler mount table record count exceeds its bound" }
        val mounts = ArrayList<Mount>(lines.size)
        val ids = HashSet<Long>(lines.size)
        for (line in lines) {
            require(line.isNotEmpty()) {
                "compiler mount table record is empty or oversized"
            }
            val separator = line.indexOf(" - ")
            require(separator > 0 && line.indexOf(" - ", separator + 3) < 0) { "compiler mount table record is malformed" }
            val left = line.substring(0, separator).split(' ')
            val right = line.substring(separator + 3).split(' ')
            require(left.size >= 6 && left.none(String::isEmpty) && right.size >= 3 && right.none(String::isEmpty)) {
                "compiler mount table record is incomplete"
            }
            val id = left[0].toLongOrNull()
            require(id != null && id > 0 && ids.add(id)) { "compiler mount table identity is invalid or duplicated" }
            require(left[1].toLongOrNull()?.let { it > 0 } == true) { "compiler mount parent identity is invalid" }
            require(left[2].matches(Regex("[0-9]+:[0-9]+"))) { "compiler mount device identity is malformed" }
            decodeMountPath(left[3])
            val mountPoint = Path.of(decodeMountPath(left[4])).normalize()
            require(mountPoint.isAbsolute && mountPoint.toString() == decodeMountPath(left[4])) {
                "compiler mount point is not canonical"
            }
            val options = left[5].split(',')
            require(options.isNotEmpty() && options.none(String::isEmpty)) { "compiler mount options are malformed" }
            val readOnly = options.count { it == "ro" }
            val readWrite = options.count { it == "rw" }
            require(readOnly + readWrite == 1) { "compiler mount access mode is absent or ambiguous" }
            mounts += Mount(id, mountPoint, readOnly == 1)
        }
        return mounts
    }

    fun requireReadOnlyTarget(path: Path, mountId: Long, directory: Boolean, mounts: List<Mount>) {
        require(path.isAbsolute && path.normalize() == path && mountId > 0) {
            "compiler mount target identity is invalid"
        }
        val covering = mounts.filter { path.startsWith(it.mountPoint) }
        require(covering.isNotEmpty()) { "compiler mount table has no covering target mount" }
        val depth = covering.maxOf { it.mountPoint.nameCount }
        val deepest = covering.filter { it.mountPoint.nameCount == depth }
        require(deepest.size == 1 && deepest.single().id == mountId && deepest.single().readOnly) {
            "compiler target is not on its descriptor-bound read-only mount"
        }
        if (directory) {
            require(mounts.none { mount -> mount.mountPoint.startsWith(path) && !mount.readOnly }) {
                "compiler read directory has a writable nested mount"
            }
        }
    }

    private fun decodeMountPath(raw: String): String {
        val decoded = StringBuilder(raw.length)
        var index = 0
        while (index < raw.length) {
            if (raw[index] != '\\') {
                decoded.append(raw[index++])
                continue
            }
            require(index + 3 < raw.length) { "compiler mount path escape is truncated" }
            val escaped = raw.substring(index + 1, index + 4)
            decoded.append(when (escaped) {
                "040" -> ' '
                "011" -> '\t'
                "012" -> '\n'
                "134" -> '\\'
                else -> throw IllegalArgumentException("compiler mount path escape is unsupported")
            })
            index += 4
        }
        val value = decoded.toString()
        require(value.isNotEmpty() && '\u0000' !in value) { "compiler mount path is invalid" }
        return value
    }
}

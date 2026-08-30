package decompengine.oracle.fulltree

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

internal data class LinuxResidentMemorySample(
    val currentBytes: Long,
    val highWaterBytes: Long,
)

/** Strict, bounded parsing of Linux's process-owned resident-memory counters. */
internal object LinuxResidentMemory {
    fun sampleSelf(): LinuxResidentMemorySample = sample(ProcessHandle.current().pid())

    fun sample(processId: Long): LinuxResidentMemorySample {
        require(processId > 0L) { "resident-memory process ID must be positive" }
        val status = Path.of("/proc", processId.toString(), "status")
        Files.newBufferedReader(status, StandardCharsets.US_ASCII).use { reader ->
            var current: Long? = null
            var highWater: Long? = null
            var lines = 0
            var characters = 0
            while (true) {
                val line = reader.readLine() ?: break
                lines++
                characters = Math.addExact(characters, line.length)
                if (lines > MAXIMUM_STATUS_LINES || characters > MAXIMUM_STATUS_CHARACTERS) {
                    throw IllegalStateException("Linux process status exceeds its parsing bound")
                }
                when {
                    line.startsWith("VmRSS:") -> {
                        if (current != null) throw IllegalStateException("Linux process status repeats VmRSS")
                        current = parseKibibytes(line, "VmRSS")
                    }
                    line.startsWith("VmHWM:") -> {
                        if (highWater != null) throw IllegalStateException("Linux process status repeats VmHWM")
                        highWater = parseKibibytes(line, "VmHWM")
                    }
                }
            }
            val resident = current ?: throw IllegalStateException("Linux process status omits VmRSS")
            val peak = highWater ?: throw IllegalStateException("Linux process status omits VmHWM")
            if (resident <= 0L || peak <= 0L || resident > peak) {
                throw IllegalStateException("Linux process resident-memory counters are contradictory")
            }
            return LinuxResidentMemorySample(resident, peak)
        }
    }

    internal fun parseKibibytes(line: String, field: String): Long {
        val prefix = "$field:"
        if (!line.startsWith(prefix)) throw IllegalStateException("Linux process status field differs: $field")
        val value = line.substring(prefix.length).trim()
        if (!value.endsWith(" kB")) {
            throw IllegalStateException("Linux process status $field unit differs")
        }
        val digits = value.dropLast(3)
        if (digits.isEmpty() || digits.length > MAXIMUM_COUNTER_DIGITS || digits.any { it !in '0'..'9' }) {
            throw IllegalStateException("Linux process status $field value is invalid")
        }
        val kibibytes = digits.toLongOrNull()
            ?: throw IllegalStateException("Linux process status $field value overflows")
        return try {
            Math.multiplyExact(kibibytes, KIBIBYTE_BYTES)
        } catch (failure: ArithmeticException) {
            throw IllegalStateException("Linux process status $field byte count overflows", failure)
        }
    }

    private const val KIBIBYTE_BYTES = 1024L
    private const val MAXIMUM_STATUS_LINES = 512
    private const val MAXIMUM_STATUS_CHARACTERS = 64 * 1024
    private const val MAXIMUM_COUNTER_DIGITS = 18
}

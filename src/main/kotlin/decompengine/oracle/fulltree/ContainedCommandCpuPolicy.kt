package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independent host ceiling; benchmark profiles cannot raise this admitted concurrency. */
internal const val MAXIMUM_CONTAINED_COMMAND_PROCESSORS = 4

internal data class ContainedCommandCpuCapacity(
    val affinityProcessors: Int,
    val quotaProcessors: Int?,
    val controlGroup: String,
) {
    fun requireCapacity(requested: Int) {
        require(requested in 1..MAXIMUM_CONTAINED_COMMAND_PROCESSORS) {
            "contained command processor count exceeds the independent host ceiling"
        }
        require(affinityProcessors >= requested && (quotaProcessors == null || quotaProcessors >= requested)) {
            "contained command processor count exceeds observed host CPU capacity"
        }
    }

    fun json(): JsonObject = JsonObject(mapOf(
        "provider" to JsonPrimitive("linux-affinity-cgroup-capacity-v1"),
        "affinityProcessors" to JsonPrimitive(affinityProcessors),
        "quotaProcessors" to (quotaProcessors?.let(::JsonPrimitive) ?: JsonNull),
        "controlGroup" to JsonPrimitive(controlGroup),
        "maximumAdmittedProcessors" to JsonPrimitive(MAXIMUM_CONTAINED_COMMAND_PROCESSORS),
    ))
}

/** Read kernel facts, independently of JVM processor overrides or a caller-supplied profile. */
internal fun captureContainedCommandCpuCapacity(hostPid: Long): ContainedCommandCpuCapacity {
    require(hostPid in 1L..Int.MAX_VALUE.toLong()) { "host CPU admission process identity is invalid" }
    val process = Path.of("/proc/$hostPid")
    val status = boundedCpuPolicyText(process.resolve("status"), 64 * 1024)
    val affinity = status.lineSequence().filter { it.startsWith("Cpus_allowed_list:") }.toList()
    require(affinity.size == 1) { "host process CPU affinity is unavailable or ambiguous" }
    val groups = boundedCpuPolicyText(process.resolve("cgroup"), 16 * 1024)
        .lineSequence().filter { it.isNotEmpty() }.toList()
    require(groups.size == 1 && groups.single().startsWith("0::/")) {
        "host CPU admission requires a unified cgroup hierarchy"
    }
    val group = groups.single().removePrefix("0::")
    val relative = Path.of(group)
    require(relative.isAbsolute && relative.normalize() == relative && relative.nameCount <= 128 &&
        group.none { it.code < 32 || it.code == 127 }) { "host CPU cgroup path is not canonical" }
    val root = Path.of("/sys/fs/cgroup")
    var current = root.resolve(group.removePrefix("/"))
    require(current.startsWith(root))
    val quotas = arrayListOf<String>()
    var levels = 0
    while (true) {
        require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) { "host CPU cgroup disappeared" }
        try {
            quotas += boundedCpuPolicyText(current.resolve("cpu.max"), 256).trim()
        } catch (_: NoSuchFileException) {
            // The hierarchy root has no resource limit; a disabled local CPU controller also
            // contributes no local limit. Ancestor limits must still be traversed and admitted.
            require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) { "host CPU cgroup disappeared" }
        }
        if (current == root) break
        current = checkNotNull(current.parent)
        require(++levels <= 128) { "host CPU hierarchy exceeds its depth bound" }
    }
    return ContainedCommandCpuCapacity(
        parseContainedCommandCpuAffinity(affinity.single().substringAfter(':').trim()),
        minimumContainedCommandCpuQuota(quotas.ifEmpty { listOf("max 100000") }), group,
    )
}

internal fun parseContainedCommandCpuAffinity(value: String): Int {
    require(value.length in 1..32 * 1024) { "host CPU affinity list exceeds its bound" }
    var previous = -1
    var count = 0
    for (item in value.split(',')) {
        val range = item.split('-')
        require(range.size in 1..2 && range.all { it.matches(Regex("0|[1-9][0-9]{0,5}")) }) {
            "host CPU affinity list is malformed"
        }
        val first = range[0].toInt()
        val last = if (range.size == 2) range[1].toInt() else first
        require(first > previous && last >= first && last < 65_536) {
            "host CPU affinity list is overlapping or outside its bound"
        }
        count = Math.addExact(count, last - first + 1)
        previous = last
    }
    return count
}

internal fun minimumContainedCommandCpuQuota(values: List<String>): Int? {
    require(values.size in 1..129) { "host CPU quota hierarchy is empty or exceeds its bound" }
    var minimum: Int? = null
    for (value in values) {
        val fields = value.split(Regex("\\s+"))
        require(fields.size == 2) { "host CPU quota is malformed" }
        val period = fields[1].toLongOrNull()
        require(period != null && period in 1L..1_000_000L) { "host CPU quota period is invalid" }
        if (fields[0] == "max") continue
        val quota = fields[0].toLongOrNull()
        require(quota != null && quota > 0L) { "host CPU quota is invalid" }
        val processors = minOf(quota / period, 65_536L).toInt()
        minimum = minimum?.let { minOf(it, processors) } ?: processors
    }
    return minimum
}

internal fun containedCommandCpuQuotaMatches(value: String, processors: Int): Boolean {
    if (processors !in 1..MAXIMUM_CONTAINED_COMMAND_PROCESSORS) return false
    val fields = value.trim().split(Regex("\\s+"))
    if (fields.size != 2) return false
    val quota = fields[0].toLongOrNull() ?: return false
    val period = fields[1].toLongOrNull() ?: return false
    return quota > 0L && period in 1L..1_000_000L && quota % period == 0L && quota / period == processors.toLong()
}

/** Reserve aggregate compute for the next sample and the existing forced-cleanup deadline. */
internal fun containedCommandCpuStopThresholdUsec(cpuSeconds: Long, processors: Int, guardWallMillis: Long): Long {
    require(cpuSeconds > 0L && processors in 1..MAXIMUM_CONTAINED_COMMAND_PROCESSORS && guardWallMillis > 0L)
    val maximum = Math.multiplyExact(cpuSeconds, 1_000_000L)
    val reserve = Math.multiplyExact(Math.multiplyExact(processors.toLong(), guardWallMillis), 1_000L)
    require(maximum > reserve) { "contained CPU budget cannot cover its monitoring and cleanup reserve" }
    return maximum - reserve
}

internal class ContainedCommandCpuBudgetMonitor(cpuSeconds: Long, processors: Int, guardWallMillis: Long) {
    private val stopThreshold = containedCommandCpuStopThresholdUsec(cpuSeconds, processors, guardWallMillis)
    private var previousUsec = 0L
    private var rejected = false

    fun observe(usageUsec: Long, terminatePinnedTree: () -> Unit, proveAbsent: () -> Unit) {
        check(!rejected) { "contained CPU monitor is no longer usable" }
        require(usageUsec >= previousUsec) { "contained aggregate CPU accounting regressed" }
        previousUsec = usageUsec
        if (usageUsec < stopThreshold) return
        rejected = true
        val failure = IllegalArgumentException(
            "contained command exhausted its aggregate CPU allowance and cleanup reserve: " +
                "usageUsec=$usageUsec stopThresholdUsec=$stopThreshold",
        )
        // Do not wait for systemd calls before stopping the pinned namespace init: its death
        // terminates every process in the worker PID namespace, including native decompilers.
        runCatching(terminatePinnedTree).exceptionOrNull()?.let(failure::addSuppressed)
        runCatching(proveAbsent).exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

private fun boundedCpuPolicyText(path: Path, maximumBytes: Int): String {
    val bytes = Files.newInputStream(path).use { it.readNBytes(maximumBytes + 1) }
    require(bytes.size in 1..maximumBytes && bytes.all { it.toInt() in 0..127 }) {
        "host CPU policy file is empty, oversized, or non-ASCII"
    }
    return bytes.toString(Charsets.US_ASCII)
}

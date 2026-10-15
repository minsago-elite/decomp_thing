package decompengine.repair

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.nio.file.Files
import java.nio.file.FileSystems
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/** Closed, private-data-free result. RECORDED is metadata-only, not a freshness/execution permit. */
internal enum class RepairHistoryReadStatus { RECORDED, NOT_RECORDED, UNAVAILABLE }
internal class RepairHistoryReadResult private constructor(
    val status: RepairHistoryReadStatus,
    val snapshot: RepairHistorySnapshot?,
    val projection: RepairHistoryProjectionDiagnostic = RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.NOT_INSPECTED),
) {
    companion object {
        internal fun recorded(snapshot: RepairHistorySnapshot, projection: RepairHistoryProjectionDiagnostic =
            RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.NOT_INSPECTED)) =
            RepairHistoryReadResult(RepairHistoryReadStatus.RECORDED, snapshot, projection)
        internal fun absent() = RepairHistoryReadResult(RepairHistoryReadStatus.NOT_RECORDED, null)
        internal fun unavailable() = RepairHistoryReadResult(RepairHistoryReadStatus.UNAVAILABLE, null)
    }
}

/** Reads the fixed diagnostic H leaf, never reconstructs history or publishes public output. */
internal fun readProjectRecordedRepairHistory(
    projectRoot: Path,
    cancel: () -> Unit = {},
): RepairHistoryReadResult = readFixedHistoryDirectory(projectRoot, listOf("reports", "repair-revisions"), cancel)

/** Fixed selector only. The calling service must separately authorize this selected job/run. */
internal fun readSelectedJobRecordedRepairHistory(
    storageRoot: Path,
    jobId: String,
    runId: String?,
    cancel: () -> Unit,
): RepairHistoryReadResult {
    if (!jobId.matches(Regex("[a-f0-9]{32}")) ||
        (runId != null && !runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))) {
        return RepairHistoryReadResult.unavailable()
    }
    val report = if (runId == null) listOf("reports") else listOf("reports", "runs", runId)
    return readFixedHistoryDirectory(storageRoot,
        listOf(jobId) + report + listOf("source-tree", "reports", "repair-revisions"), cancel)
}

/** Borrows revisions synchronously; callers retain its fixed nofollow chain through return. */
internal fun readRecordedRepairHistorySnapshot(
    revisions: LinuxDescriptor,
    revalidateDirectory: () -> Unit,
    cancel: () -> Unit,
): RepairHistoryReadResult = try {
    revisions.whileOpen {
        requireHistoryDirectory(revisions.identity, revisions.identity)
        val session = HistoryCaptureSession(revisions, revalidateDirectory, cancel)
        session.read()
    }
} catch (_: Throwable) {
    RepairHistoryReadResult.unavailable()
}

/** Both descriptors are borrowed from the SAME fixed adapter chain, never returned to a caller. */
private fun readRecordedRepairHistorySnapshotWithHistory(
    revisions: LinuxDescriptor,
    reports: LinuxDescriptor,
    revalidateDirectory: () -> Unit,
    cancel: () -> Unit,
): RepairHistoryReadResult = try {
    reports.whileOpen {
        revisions.whileOpen {
            requireHistoryDirectory(reports.identity, reports.identity)
            requireHistoryDirectory(revisions.identity, reports.identity)
            HistoryCaptureSession(revisions, revalidateDirectory, cancel).readWithHistory(reports)
        }
    }
} catch (_: Throwable) {
    RepairHistoryReadResult.unavailable()
}

private const val HISTORY_E = 2_147_483_646L
private const val HISTORY_Q = 16_384L // Existing LinuxFilesystemSyscalls.read growth chunk, not a new quota.
private val HISTORY_DECLARED_NAME = Regex("legacy-graph-([0-9a-f]{64})\\.json")

/** Checked logical payload-work accounting; not an eager allocation or hard RSS/kernel deadline. */
private class HistoryReadLedger {
    private var limit = Math.addExact(Math.multiplyExact(6L, HISTORY_E), MAXIMUM_REPAIR_PROJECTION_BYTES)
    private val growthReserve = Math.multiplyExact(2L, HISTORY_Q)
    private var workLimit = Math.addExact(limit, growthReserve)
    private var used = 0L

    fun reserve(bytes: Long) {
        require(bytes > 0)
        val next = Math.addExact(used, bytes)
        require(next <= limit && Math.addExact(next, growthReserve) <= workLimit)
        used = next
    }

    fun bind(graphBytes: Long, budget: RepairResourceBudget) {
        var bound = Math.multiplyExact(2L, graphBytes)
        bound = Math.addExact(bound, Math.multiplyExact(2L, budget.maximumGraphBytes))
        bound = Math.addExact(bound, budget.maximumProjectionBytes) // At most one diagnostic H capture; core-only leaves this unused.
        bound = Math.addExact(bound, Math.multiplyExact(2L, budget.maximumIndexEvidenceBytes))
        // Two existing Q growth reserves are separate from successful admitted payload credits.
        val workBound = Math.addExact(bound, growthReserve)
        require(bound <= limit && used <= bound && workBound <= workLimit)
        limit = bound
        workLimit = workBound
    }
}

private data class HistoryConsumedInput(val name: String, val identity: LinuxFileIdentity, val bytes: Long, val sha256: String)

private class HistoryCaptureSession(
    private val revisions: LinuxDescriptor,
    private val revalidateDirectory: () -> Unit,
    private val cancel: () -> Unit,
) {
    private val ledger = HistoryReadLedger()

    private fun check() {
        cancel()
        require(LinuxFilesystemSyscalls.identity(revisions.fd) == revisions.identity)
        revalidateDirectory()
        cancel()
    }

    fun read(): RepairHistoryReadResult = readCaptured(null)

    fun readWithHistory(reports: LinuxDescriptor): RepairHistoryReadResult = readCaptured(reports)

    private fun readCaptured(reports: LinuxDescriptor?): RepairHistoryReadResult {
        check()
        val graph = capture("graph.json", HISTORY_E) ?: run {
            requireMissing("recovery-binding.json")
            check()
            requireMissing("graph.json")
            requireMissing("recovery-binding.json")
            return RepairHistoryReadResult.absent()
        }
        // This bounded pure bootstrap parse precedes any binding/declaration payload read.
        val budget = recordedRepairHistoryReadBudget(graph.bytes)
        ledger.bind(graph.bytes.size.toLong(), budget)
        val binding = requireNotNull(capture("recovery-binding.json", budget.maximumGraphBytes))
        requireRecordedRepairHistoryBinding(graph.bytes, binding.bytes, budget)
        var declarationNames: List<String>? = null
        val consumed = ArrayList<HistoryConsumedInput>()
        val snapshot = recordedRepairHistorySnapshot(graph.bytes, binding.bytes, budget) { consume ->
            require(declarationNames == null)
            val names = names(budget)
            declarationNames = names
            var remaining = budget.maximumIndexEvidenceBytes
            for (name in names) {
                if (!HISTORY_DECLARED_NAME.matches(name)) continue
                val input = requireNotNull(capture(name, minOf(budget.maximumGraphBytes, remaining)))
                remaining = Math.subtractExact(remaining, input.bytes.size.toLong())
                require(input.sha256 == HISTORY_DECLARED_NAME.matchEntire(name)!!.groupValues[1])
                consumed += HistoryConsumedInput(name, input.identity, input.bytes.size.toLong(), input.sha256)
                consume(name, input.bytes) // No pathname reread; body lifetime ends after this iteration.
            }
        }
        // H is diagnostic only and remains LOCAL until all original final continuity checks succeed.
        val projection = if (reports == null) RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.NOT_INSPECTED)
            else inspectHistory(reports, graph.bytes, budget)
        declarationNames?.let { firstNames ->
            require(names(budget) == firstNames)
            var remaining = budget.maximumIndexEvidenceBytes
            for (first in consumed) {
                require(first.bytes <= remaining)
                val second = requireNotNull(capture(first.name, first.bytes))
                remaining = Math.subtractExact(remaining, second.bytes.size.toLong())
                require(second.identity == first.identity && second.bytes.size.toLong() == first.bytes && second.sha256 == first.sha256)
            }
        }
        val graphAgain = requireNotNull(capture("graph.json", graph.bytes.size.toLong()))
        requireSame(graph, graphAgain)
        val bindingAgain = requireNotNull(capture("recovery-binding.json", binding.bytes.size.toLong()))
        requireSame(binding, bindingAgain)
        check()
        return RepairHistoryReadResult.recorded(snapshot, projection)
    }

    private fun inspectHistory(reports: LinuxDescriptor, graphBytes: ByteArray, budget: RepairResourceBudget): RepairHistoryProjectionDiagnostic {
        check() // Canonical-chain/cancellation failures are NEVER inside the leaf-diagnostic catch.
        val transaction = HistoryProjectionCapture(cancel)
        val diagnostic = transaction.inspect {
            val authorized = LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, "repair_history.json")
            if (authorized == null) RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.MISSING)
            else transaction.owned(authorized) { held ->
                requireHistoryRegular(held.identity, reports.identity)
                val path = LinuxFilesystemSyscalls.descriptorPath(held)
                val before = Files.readAttributes(path, BasicFileAttributes::class.java)
                val size = before.size()
                require(before.isRegularFile && size in 0..budget.maximumProjectionBytes)
                val captured = if (size == 0L) null else {
                    ledger.reserve(size) // Failed H captures are NEVER refunded/retried.
                    readStableRegularFile(LinuxFilesystemSyscalls.descriptorPath(reports), "repair_history.json", size,
                        cancellationCheck = transaction::checkCancellation)
                }
                val after = Files.readAttributes(path, BasicFileAttributes::class.java)
                val unchanged = after.isRegularFile && before.fileKey() == after.fileKey() && before.size() == after.size() &&
                    before.lastModifiedTime() == after.lastModifiedTime() && LinuxFilesystemSyscalls.identity(held.fd) == held.identity &&
                    (captured == null || captured.identity == held.identity && captured.bytes.size.toLong() == size)
                val named = LinuxFilesystemSyscalls.openPathAtOrNull(reports.fd, "repair_history.json")
                val sameName = if (named == null) false else transaction.owned(named) { it.identity == held.identity }
                if (!unchanged || !sameName) RepairHistoryProjectionDiagnostic(
                    RepairHistoryProjectionStatus.CHANGED_DURING_CAPTURE, RepairHistoryProjectionReason.CAPTURE, admittedBytes = size)
                else if (captured == null) RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.EMPTY, admittedBytes = 0)
                else compareCapturedRepairHistoryProjection(graphBytes, captured.bytes, budget)
            }
        }
        check() // Also catches a reports/ancestor change hidden by a generic old stable-reader failure.
        return diagnostic
    }

    private fun names(budget: RepairResourceBudget): List<String> {
        check()
        // Existing iterator advances/counts every entry BEFORE filter/deduplication.
        val maximumEntries = repairRevisionDirectoryEntryLimit(budget)
        val names = LinuxFilesystemSyscalls.directoryEntryNames(revisions, maximumEntries, cancel)
        val sorted = boundedHistoryNames(names, maximumEntries)
        require(sorted.count { HISTORY_DECLARED_NAME.matches(it) } <= budget.maximumStateDirectoryEntries) {
            "recorded history declared graph candidate count exceeds its entry budget"
        }
        check()
        return sorted
    }

    private fun requireMissing(name: String) {
        val opened = LinuxFilesystemSyscalls.openPathAtOrNull(revisions.fd, name)
        if (opened != null) withHistoryOwned(opened) { error("recorded history absence changed") }
    }

    private fun capture(name: String, maximumBytes: Long): StableRegularFile? {
        check()
        require(maximumBytes in 1..HISTORY_E)
        val authorized = LinuxFilesystemSyscalls.openRegularFileAtOrNull(revisions.fd, name) ?: return null
        return withHistoryOwned(authorized) { held ->
            requireHistoryRegular(held.identity, revisions.identity)
            val path = LinuxFilesystemSyscalls.descriptorPath(held)
            val before = Files.readAttributes(path, BasicFileAttributes::class.java)
            val size = before.size()
            require(before.isRegularFile && size in 1..maximumBytes)
            ledger.reserve(size) // Debit BEFORE any body read, including final captures.
            val captured = readStableRegularFile(LinuxFilesystemSyscalls.descriptorPath(revisions), name, size,
                cancellationCheck = cancel)
            require(captured.identity == held.identity && captured.bytes.size.toLong() == size)
            val after = Files.readAttributes(path, BasicFileAttributes::class.java)
            require(after.isRegularFile && before.fileKey() == after.fileKey() && before.size() == after.size() &&
                before.lastModifiedTime() == after.lastModifiedTime() && LinuxFilesystemSyscalls.identity(held.fd) == held.identity)
            val named = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(revisions.fd, name))
            withHistoryOwned(named) { require(it.identity == held.identity) }
            check()
            captured
        }
    }
}


/** H-leaf errors may be diagnostic; independently observed owned-close uncertainty is fatal.
 * Kept private so inert controls exercise the SAME catch/resource composition as actual H capture.
 */
private class HistoryProjectionCapture(private val cancel: () -> Unit) {
    private var cancelled: Throwable? = null
    private var cleanupFailed = false

    fun checkCancellation() {
        try { cancel() } catch (failure: Throwable) {
            if (cancelled == null) cancelled = failure
            throw failure
        }
    }

    fun inspect(body: () -> RepairHistoryProjectionDiagnostic): RepairHistoryProjectionDiagnostic = try {
        body()
    } catch (failure: Throwable) {
        cancelled?.let { throw it } // Exact first caller failure, even if a lower reader wrapped it.
        if (cleanupFailed) throw failure // Whole-read boundary withholds the snapshot, not just H.
        RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.UNAVAILABLE, RepairHistoryProjectionReason.CAPTURE)
    }

    fun <R : AutoCloseable, T> owned(resource: R, body: (R) -> T): T {
        var primary: Throwable? = null
        try {
            return body(resource)
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try { resource.close() } catch (cleanup: Throwable) {
                cleanupFailed = true // BEFORE a body primary can suppress this observable failure.
                if (primary == null) throw cleanup
            }
        }
    }
}

private fun boundedHistoryNames(names: List<String>, maximumEntries: Int): List<String> {
    require(maximumEntries > 0 && names.size <= maximumEntries)
    val seen = HashSet<String>()
    for (name in names) {
        require(name.isNotEmpty() && name != "." && name != ".." && '/' !in name && '\u0000' !in name)
        require(seen.add(name))
    }
    return names.sorted()
}

private fun requireSame(first: StableRegularFile, second: StableRegularFile) {
    require(first.identity == second.identity && first.sha256 == second.sha256 && first.bytes.contentEquals(second.bytes))
}

private fun requireHistoryDirectory(actual: LinuxFileIdentity, parent: LinuxFileIdentity) {
    require(actual.isDirectory && !actual.isRegularFile && !actual.isSymbolicLink && actual.uid == parent.uid &&
        actual.mountId == parent.mountId && actual.mode.permissions and 0x12 == 0)
}

private fun requireHistoryRegular(actual: LinuxFileIdentity, parent: LinuxFileIdentity) {
    require(actual.isRegularFile && !actual.isDirectory && !actual.isSymbolicLink && actual.linkCount == 1 &&
        actual.uid == parent.uid && actual.mountId == parent.mountId && actual.mode.permissions and 0x12 == 0)
}

/** One close attempt; cleanup must neither replace a primary nor manufacture successful credit. */
private fun <R : AutoCloseable, T> withHistoryOwned(resource: R, body: (R) -> T): T {
    var primary: Throwable? = null
    try {
        return body(resource)
    } catch (failure: Throwable) {
        primary = failure
        throw failure
    } finally {
        try { resource.close() } catch (cleanup: Throwable) { if (primary == null) throw cleanup }
    }
}

private fun readFixedHistoryDirectory(root: Path, components: List<String>, cancel: () -> Unit): RepairHistoryReadResult = try {
    require(root.fileSystem == FileSystems.getDefault())
    val base = root.toAbsolutePath().normalize()
    withHistoryOwned(HistoryDirectoryChain(base, components, cancel)) { chain ->
        chain.open()?.let { revisions ->
            chain.readWithHistory(revisions)
        } ?: RepairHistoryReadResult.absent()
    }
} catch (_: Throwable) {
    RepairHistoryReadResult.unavailable()
}

/** Opens existing fixed components only. Never creates, recovers, scans siblings or acquires a store. */
private class HistoryDirectoryChain(
    private val root: Path,
    private val components: List<String>,
    private val cancel: () -> Unit,
) : AutoCloseable {
    private val held = ArrayList<LinuxDescriptor>()

    fun open(): LinuxDescriptor? {
        retain(LinuxFilesystemSyscalls.openRoot(root))
        requireHistoryDirectory(held.first().identity, held.first().identity)
        for (name in components) {
            cancel()
            val parent = held.last()
            val named = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
            if (named == null) {
                revalidate()
                val again = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
                if (again != null) withHistoryOwned(again) { error("recorded directory absence changed") }
                cancel()
                return null
            }
            withHistoryOwned(named) {
                requireHistoryDirectory(it.identity, parent.identity)
                val child = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
                retain(child)
                require(child.identity == it.identity)
            }
        }
        revalidate()
        return held.last()
    }

    fun readWithHistory(revisions: LinuxDescriptor): RepairHistoryReadResult {
        require(held.size == components.size + 1 && held.last() === revisions &&
            components.takeLast(2) == listOf("reports", "repair-revisions"))
        return readRecordedRepairHistorySnapshotWithHistory(revisions, held[held.lastIndex - 1], this::revalidate, cancel)
    }

    private fun retain(descriptor: LinuxDescriptor) {
        try { held.add(descriptor) } catch (failure: Throwable) {
            try { descriptor.close() } catch (_: Throwable) { }
            throw failure
        }
    }

    fun revalidate() {
        cancel()
        withHistoryOwned(LinuxFilesystemSyscalls.openRoot(root)) { currentRoot ->
            require(currentRoot.identity == held.first().identity)
        }
        for (index in held.indices) {
            cancel()
            require(LinuxFilesystemSyscalls.identity(held[index].fd) == held[index].identity)
            if (index > 0) {
                val current = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(held[index - 1].fd, components[index - 1]))
                withHistoryOwned(current) { require(it.identity == held[index].identity) }
            }
        }
        cancel()
    }

    override fun close() {
        var first: Throwable? = null
        while (held.isNotEmpty()) {
            val descriptor = held.removeAt(held.lastIndex)
            try { descriptor.close() } catch (failure: Throwable) { if (first == null) first = failure }
        }
        first?.let { throw it }
    }
}

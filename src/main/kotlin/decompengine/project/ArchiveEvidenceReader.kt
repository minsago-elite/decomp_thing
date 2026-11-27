package decompengine.project

import decompengine.repair.StableRegularFile
import decompengine.repair.readBudgetedStableRegularFile
import decompengine.repair.readStableRegularFile
import java.nio.file.Path

/** Cumulative work for one synchronous audit, including repeat reads and inventory scans. */
internal class ArchiveAuditReadBudget(
    private val maximumBytes: Long,
    private val maximumEntries: Int,
    private val cancellationCheck: () -> Unit = {},
) {
    var bytesRead = 0L
        private set
    var entriesVisited = 0
        private set

    init {
        require(maximumBytes >= 0 && maximumEntries >= 0)
    }

    fun checkpoint() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("archive audit interrupted")
        cancellationCheck()
    }

    fun visitEntry() {
        checkpoint()
        require(entriesVisited < maximumEntries) { "archive audit read entry budget exhausted" }
        entriesVisited++
    }

    fun read(root: Path, relative: String, maximumFileBytes: Long): StableRegularFile {
        visitEntry()
        return readBudgetedStableRegularFile(root, relative, maximumFileBytes, ::checkpoint, { size ->
            require(size <= maximumBytes - bytesRead) { "archive audit read byte budget exhausted" }
        }, { count -> bytesRead += count })
    }
}

internal class ArchiveEvidenceReader(val root: Path, val budget: ArchiveAuditReadBudget? = null) {
    fun read(relative: String, maximumFileBytes: Long) =
        budget?.read(root, relative, maximumFileBytes) ?: readStableRegularFile(root, relative, maximumFileBytes)
}

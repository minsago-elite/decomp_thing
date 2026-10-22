package decompengine.acp

import java.io.IOException
import java.io.InterruptedIOException
import java.nio.file.AccessDeniedException
import java.nio.file.FileSystemLoopException
import java.nio.file.NoSuchFileException

internal const val TERMINAL_FAILURE_CONTEXT_UNAVAILABLE = "terminal launch failure context=unavailable"
internal enum class AcpTerminalFailureSite { SANDBOX_LAUNCH, CREATE_CHECK }

/** Failure-only display data, never authorization, retry, process absence or cleanup authority. */
internal class AcpTerminalLaunchFailureContext private constructor(val text: String) {
    companion object {
        private val witness = Regex("mount-event-v1 phase=(CHECKPOINT|CONTROL_ADMISSION|REFRESH) " +
            "generation=(NOT_EVALUATED|MISMATCH_ALREADY_OBSERVED) outcome=(EVENT|INVALID_DESCRIPTOR|SYSCALL_ERROR) " +
            "rc=(NA|-?[0-9]{1,10}) revents=(NA|[0-9]{1,5}) errno=(NA|-?[0-9]{1,10})")
        private val admission = Regex("mount-admission-v1 stage=(CONSTRUCTING|ADMITTED) " +
            "initialMounts=[0-9]{1,10} initialControls=[0-9]{1,10} owner=(true|false) initialFast=(true|false)")

        fun capture(site: AcpTerminalFailureSite, failure: Throwable): AcpTerminalLaunchFailureContext {
            val seen = ArrayList<Throwable>(8)
            val causes = ArrayList<String>(8)
            var current: Throwable? = failure
            var state = "complete"
            while (current != null && seen.size < 8) {
                val observed = current
                if (seen.any { it === observed }) { state = "cycle"; current = null; break }
                seen.add(observed)
                causes.add(kind(observed))
                // Only the bounded direct cause chain is inspected, never messages, stacks or suppression lists.
                current = observed.cause
            }
            if (current != null) state = "truncated"
            val text = "site=${site.name};chain=$state;causes=[${causes.joinToString(" -> ")}]"
            check(text.length <= 4096 && text.all { it.code in 32..126 })
            return AcpTerminalLaunchFailureContext(text)
        }

        private fun kind(failure: Throwable): String = when (failure) {
            is AcpMountEventWitness -> {
                // Only this sealed producer's already captured scalar records may supply display text.
                val record = failure.diagnosticRecord.takeIf { it.length <= 512 && witness.matches(it) }
                val admitted = if (record != null) failure.admissionRecord
                    ?.takeIf { it.length <= 256 && admission.matches(it) } else null
                if (record == null) "mount-witness-invalid"
                else if (admitted == null) record else "$record;$admitted"
            }
            is LinuxSyscallException -> "syscall(errno=${failure.errno})"
            is LinuxResourceLimitException -> "read-limit"
            is LinuxNamedRegularFileReplacedException -> "named-file-replaced"
            is AcpCleanupProofFailure -> "cleanup-proof"
            is AccessDeniedException -> "access-denied"
            is NoSuchFileException -> "missing-file"
            is FileSystemLoopException -> "symlink-loop"
            is InterruptedIOException -> "interrupted-io"
            is IOException -> "io"
            is IllegalStateException -> "illegal-state"
            else -> "other"
        }
    }
}

/** Construction/accessor failure cannot replace or attach anything to the original refusal. */
internal fun captureTerminalLaunchFailure(site: AcpTerminalFailureSite, failure: Throwable): AcpTerminalLaunchFailureContext? =
    try { AcpTerminalLaunchFailureContext.capture(site, failure) } catch (_: Throwable) { null }

internal data class AcpTerminalFailureObservation(val auditSequence: Long, val context: AcpTerminalLaunchFailureContext)

internal fun formatTerminalLaunchFailures(observations: List<AcpTerminalFailureObservation>): String {
    val output = StringBuilder("terminal launch failure context=[")
    var separator = ""
    for (observation in observations.takeLast(8)) {
        val record = "audit=${observation.auditSequence};${observation.context.text}"
        if (output.length + separator.length + record.length + 1 > 4096) {
            if (output.length + separator.length + 8 < 4096) output.append(separator).append("omitted")
            break
        }
        output.append(separator).append(record)
        separator = " | "
    }
    return output.append(']').toString()
}

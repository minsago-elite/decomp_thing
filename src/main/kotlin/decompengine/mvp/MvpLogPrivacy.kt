package decompengine.mvp

import decompengine.jobs.ProgressControlPolicy
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicReferenceArray

/** One immutable policy; each command pipe owns its own small credential-continuation state. */
internal class MvpLogPrivacy(artifact: MvpArtifactRedactor) {
    val maximumBytes: Long = artifact.maximumBytes
    private val projector = artifact.forLogLines()
    private val controls = ProgressControlPolicy.removable

    fun project(value: String): String = projector.text(value)

    fun message(value: String, lines: Lines, pipe: Lines? = null): String {
        project(value) // Admit complete raw/normalized data before examining its line grammar.
        val ordered = lines.fork()
        val independent = pipe?.takeIf { it !== lines }?.fork()
        val rendered = MvpArtifactText(maximumBytes).apply {
            value.splitToSequence('\n').forEachIndexed { index, rawLine ->
                val line = rawLine.replace(controls, "")
                if (index != 0) append("\n")
                val sharedMask = ordered.plan(line)
                val pipeMask = independent?.plan(line)
                val mask = when {
                    sharedMask == null -> pipeMask
                    pipeMask == null -> sharedMask
                    else -> minOf(sharedMask.first, pipeMask.first)..maxOf(sharedMask.last, pipeMask.last)
                }
                // Both continuation scopes and all configured/format spans see the same raw line.
                append(projector.text(rawLine, mask))
                ordered.commit()
                independent?.commit()
            }
        }.build()
        lines.adopt(ordered)
        if (independent != null) pipe?.adopt(independent)
        return rendered
    }

    fun frame(message: String, error: Boolean, timestamp: String? = null): MvpLogFrame {
        val console = project(message)
        val file = MvpArtifactText(maximumBytes).apply {
            if (timestamp != null) append("[").append(timestamp).append("] ")
            if (error) append("[stderr] ")
            append(console)
        }.build()
        // Both destinations are admitted before the caller writes either one.
        return MvpLogFrame(console, project(file), error)
    }

    fun lines(): Lines = Lines()

    /** A completed peer line can hide an earlier introducer prefix and any local byte position. */
    fun linesWithUnorderedPeer(peerOutput: String): Lines {
        project(peerOutput)
        val normalized = peerOutput.replace(controls, "")
        return Lines(introducerPrefixes.any { it.containsMatchIn(normalized) })
    }

    inner class Lines internal constructor(
        private val ambiguousCapture: Boolean = false,
    ) {
        private var pending = Pending.NONE
        private var staged = Pending.NONE

        fun next(line: String): String = message(line, this)

        internal fun fork(): Lines = Lines(ambiguousCapture).also { it.pending = pending }
        internal fun adopt(other: Lines) { pending = other.pending }
        internal fun commit() { pending = staged }

        internal fun plan(line: String): IntRange? {
            var mask: IntRange? = null
            var nextPending = pending
            if (pending != Pending.NONE) {
                val first = token.find(line)
                val separator = line.indexOfFirst { !it.isWhitespace() }.takeIf { it >= 0 }
                if (separator != null && line[separator] in ",;") {
                    nextPending = Pending.NONE
                } else if (first != null) {
                    var end = first.range.last + 1
                    nextPending = Pending.NONE
                    if (pending == Pending.AUTHORIZATION &&
                        (first.value.equals("Basic", true) || first.value.equals("Bearer", true))
                    ) {
                        val second = token.find(line, end)
                        val between = line.substring(end, second?.range?.first ?: line.length)
                        if (between.any { it == ',' || it == ';' }) {
                            nextPending = Pending.NONE
                        } else if (second != null) {
                            end = second.range.last + 1
                        } else {
                            nextPending = Pending.VALUE
                        }
                    }
                    mask = first.range.first until end
                }
            }
            val authorization = authorizationSuffix.find(line)
            if (authorization != null) {
                nextPending = if (authorization.groupValues[1].isEmpty()) Pending.AUTHORIZATION else Pending.VALUE
            } else if (valueSuffix.containsMatchIn(line) || tokenSuffix.containsMatchIn(line)) {
                nextPending = Pending.VALUE
            }
            staged = nextPending
            // Without byte order, the next credential may start midway through a local line.
            return if (ambiguousCapture && line.isNotEmpty()) line.indices else mask
        }
    }

    private enum class Pending { NONE, VALUE, AUTHORIZATION }

    private companion object {
        val token = Regex("[^\\s,;]+")
        val authorizationSuffix = Regex("(?i)\\b(?:proxy-)?authorization\\s*[:=]\\s*(?:(basic|bearer)\\s*)?$")
        val valueSuffix = Regex("(?i)(?:bearer|(?:api[_-]?key|access[_-]?token|password|secret)\\s*[:=])\\s*$")
        val tokenSuffix = Regex("(?:sk-|ghp_|github_pat_)$")
        val introducerPrefixes = listOf(authorizationSuffix, valueSuffix, tokenSuffix).map {
            Regex(it.pattern.removeSuffix("\$"), it.options)
        }
    }
}

/** One normalized UTF-8 capture ceiling for both pipes of one command. */
internal class MvpCommandCaptureBudget(private val maximumBytes: Long) {
    private var usedBytes = 0L
    private var failure: MvpPatchException? = null

    init { require(maximumBytes in 1..MAXIMUM_REPAIR_PROJECTION_BYTES) }

    @Synchronized
    fun charge(bytes: Long) {
        require(bytes >= 0) { "command capture byte charge is invalid" }
        failure?.let { throw it }
        if (bytes > maximumBytes - usedBytes) {
            throw MvpPatchException("command captures exceed their normalized UTF-8 byte budget").also { failure = it }
        }
        usedBytes += bytes
    }
}

/** Incremental equivalent of readLine plus appendLine, without an unbounded intermediate line. */
internal class MvpCommandCapture(
    private val capture: StringBuilder,
    private val budget: MvpCommandCaptureBudget,
) {
    private var previousHigh = false
    private var partialLine = false
    private var skipLineFeed = false
    private var finished = false

    init { require(capture.isEmpty()) { "command capture must start empty" } }

    fun feed(buffer: CharArray, count: Int, onLine: () -> Unit) {
        check(!finished) { "command capture is already complete" }
        require(count in 0..buffer.size) { "command capture chunk length is invalid" }
        if (count == 0) return
        var position = 0
        if (skipLineFeed) {
            skipLineFeed = false
            if (buffer[0] == '\n') position++
        }
        var start = position
        while (position < count) {
            val unit = buffer[position]
            if (unit == '\r' || unit == '\n') {
                append(buffer, start, position)
                newline(onLine)
                position++
                skipLineFeed = unit == '\r'
                if (skipLineFeed && position < count) {
                    skipLineFeed = false
                    if (buffer[position] == '\n') position++
                }
                start = position
            } else {
                position++
            }
        }
        append(buffer, start, count)
    }

    fun finish(onLine: () -> Unit) {
        check(!finished) { "command capture is already complete" }
        finished = true
        if (partialLine) newline(onLine)
    }

    private fun append(buffer: CharArray, start: Int, end: Int) {
        if (start == end) return
        var high = previousHigh
        var bytes = 0L
        for (position in start until end) {
            val unit = buffer[position]
            bytes += when {
                high && unit.isLowSurrogate() -> 3 // The preceding replacement byte becomes a pair.
                unit.code < 0x80 -> 1
                unit.code < 0x800 -> 2
                unit.code in 0xD800..0xDFFF -> 1 // JVM UTF-8 replacement for an isolated surrogate.
                else -> 3
            }
            high = unit.isHighSurrogate()
        }
        budget.charge(bytes) // Charge the entire fixed-size span before the builder can grow.
        capture.append(buffer, start, end - start)
        previousHigh = high
        partialLine = true
    }

    private fun newline(onLine: () -> Unit) {
        budget.charge(1)
        capture.append('\n')
        previousHigh = false
        partialLine = false
        onLine()
    }
}

/** Each reader owns one state; finish runs only after both readers have joined.
 * A completed peer publishes a small immutable projection policy, not a second raw capture.
 */
internal class MvpLiveCommandDisplay(
    private val privacy: MvpLogPrivacy,
    private val emit: (String, Boolean, MvpLogPrivacy.Lines?) -> Unit,
) {
    private class Pipe {
        var receivedLines = 0L
        var observedUnits = 0
        var publishedUnits = 0
        var progressLines = 0L
        var policy: MvpLogPrivacy.Lines? = null
    }

    private val pipes = Array(2) { Pipe() }
    private val completed = AtomicReferenceArray<MvpLogPrivacy.Lines?>(2)

    fun line(error: Boolean, capture: CharSequence) {
        val pipe = pipes[index(error)]
        check(completed.get(index(error)) == null) { "command display pipe is already complete" }
        require(capture.length > pipe.observedUnits && capture[capture.length - 1] == '\n') {
            "command display requires an appended captured line"
        }
        pipe.receivedLines = Math.addExact(pipe.receivedLines, 1L)
        pipe.observedUnits = capture.length
        if (!flush(error, capture) && (pipe.receivedLines and (pipe.receivedLines - 1L)) == 0L) {
            progress(error, pipe)
        }
    }

    fun complete(error: Boolean, capture: CharSequence) {
        val slot = index(error)
        val pipe = pipes[slot]
        check(completed.get(slot) == null) { "command display pipe is already complete" }
        require(capture.length == pipe.observedUnits) { "command display capture has unobserved data" }
        admitLength(capture)
        // Both the full input and credential prefixes must be admitted before the peer can emit.
        // Only this reader accesses its mutable capture. The other reader sees this policy alone.
        val peerPolicy = privacy.linesWithUnorderedPeer(capture.toString())
        completed.set(slot, peerPolicy)
        if (!flush(error, capture)) progress(error, pipe)
    }

    fun finish(stdout: CharSequence, stderr: CharSequence) {
        check(completed.get(0) != null && completed.get(1) != null) { "command display pipes are incomplete" }
        flush(false, stdout)
        flush(true, stderr)
    }

    private fun flush(error: Boolean, capture: CharSequence): Boolean {
        val pipe = pipes[index(error)]
        val policy = pipe.policy ?: completed.get(1 - index(error))?.fork()?.also { pipe.policy = it }
            ?: return false
        if (pipe.publishedUnits == capture.length) return true
        admitLength(capture)
        val pending = capture.subSequence(pipe.publishedUnits, capture.length).toString()
        privacy.project(pending) // Admit the complete pending batch before publishing any record.
        var start = 0
        while (start < pending.length) {
            val end = pending.indexOf('\n', start)
            check(end >= 0) { "command display capture has an incomplete line" }
            emit(pending.substring(start, end), error, policy)
            pipe.publishedUnits += end - start + 1
            start = end + 1
        }
        return true
    }

    private fun progress(error: Boolean, pipe: Pipe) {
        if (pipe.receivedLines == 0L || pipe.progressLines == pipe.receivedLines) return
        val channel = if (error) "stderr" else "stdout"
        emit("$channel progress: captured_lines=${pipe.receivedLines} captured_utf16_units=${pipe.observedUnits}; " +
            "text pending peer-order privacy projection", error, null)
        pipe.progressLines = pipe.receivedLines
    }

    private fun admitLength(capture: CharSequence) {
        // A UTF-8 projection cannot admit more UTF-16 units than this byte ceiling. Check before copy.
        if (capture.length.toLong() > privacy.maximumBytes) {
            throw MvpPatchException("command display projection exceeds its byte budget")
        }
    }

    private fun index(error: Boolean): Int = if (error) 1 else 0
}

/** Keep reader/display failures private and rethrow the first one before accepting a command. */
internal class MvpLogFailure {
    private val failure = AtomicReference<Throwable?>()

    fun attempt(project: () -> Unit) {
        if (failure.get() != null) return
        try {
            project()
        } catch (caught: Throwable) {
            record(caught)
        }
    }

    fun record(caught: Throwable) { failure.compareAndSet(null, caught) }

    fun requireSuccess() { failure.get()?.let { throw it } }
}

internal data class MvpLogFrame(val console: String, val retained: String, val error: Boolean)

internal fun renderMvpApprovalPrompt(summary: String, evidence: MvpRunEvidence): String {
    val question = "Apply this patch? [y/N] "
    val prompt = evidence.logPrivacy.project(MvpArtifactText(evidence.maximumProjectionBytes)
        .append("Patch summary: ").append(summary).append("\n").append(question).build())
    if (!prompt.endsWith(question)) throw MvpPatchException("approval prompt cannot present a safe decision label")
    return prompt
}

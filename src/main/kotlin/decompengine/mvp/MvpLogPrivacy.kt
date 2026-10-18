package decompengine.mvp

import java.util.concurrent.atomic.AtomicReference

/** One immutable policy; each command pipe owns its own small credential-continuation state. */
internal class MvpLogPrivacy(artifact: MvpArtifactRedactor) {
    val maximumBytes: Long = artifact.maximumBytes
    private val projector = artifact.forLogLines()
    private val controls = Regex("[\\p{Cntrl}&&[^\\n\\t]]")

    fun project(value: String): String = projector.text(value)

    fun message(value: String, lines: Lines, pipe: Lines? = null): String {
        project(value) // Admit complete raw/normalized data before examining its line grammar.
        val normalized = value.replace(controls, "")
        val ordered = lines.fork()
        val independent = pipe?.takeIf { it !== lines }?.fork()
        val rendered = MvpArtifactText(maximumBytes).apply {
            normalized.lineSequence().forEachIndexed { index, line ->
                if (index != 0) append("\n")
                val sharedMask = ordered.plan(line)
                val pipeMask = independent?.plan(line)
                val mask = when {
                    sharedMask == null -> pipeMask
                    pipeMask == null -> sharedMask
                    else -> minOf(sharedMask.first, pipeMask.first)..maxOf(sharedMask.last, pipeMask.last)
                }
                // Both continuation scopes and all configured/format spans see the same raw line.
                append(projector.text(line, mask))
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

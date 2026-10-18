package decompengine.mvp

import java.util.concurrent.atomic.AtomicReference

/** One immutable policy; each command pipe owns its own small credential-continuation state. */
internal class MvpLogPrivacy(artifact: MvpArtifactRedactor) {
    val maximumBytes: Long = artifact.maximumBytes
    private val projector = artifact.forLogLines()

    fun project(value: String): String = projector.text(value)

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

    inner class Lines internal constructor() {
        private var pending = Pending.NONE

        fun next(line: String): String {
            // Admit before looking at or copying a potentially large line.
            val alreadySafe = project(line)
            var rendered = line
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
                    rendered = MvpArtifactText(maximumBytes).append(line, 0, first.range.first)
                        .append("[REDACTED]").append(line, end, line.length).build()
                }
            }
            val authorization = authorizationSuffix.find(line)
            if (authorization != null) {
                nextPending = if (authorization.groupValues[1].isEmpty()) Pending.AUTHORIZATION else Pending.VALUE
            } else if (valueSuffix.containsMatchIn(line) || tokenSuffix.containsMatchIn(line)) {
                nextPending = Pending.VALUE
            }
            val safe = if (rendered === line) alreadySafe else project(rendered)
            pending = nextPending
            return safe
        }
    }

    private enum class Pending { NONE, VALUE, AUTHORIZATION }

    private companion object {
        val token = Regex("[^\\s,;]+")
        val authorizationSuffix = Regex("(?i)\\b(?:proxy-)?authorization\\s*[:=]\\s*(?:(basic|bearer)\\s*)?$")
        val valueSuffix = Regex("(?i)(?:bearer|(?:api[_-]?key|access[_-]?token|password|secret)\\s*[:=])\\s*$")
        val tokenSuffix = Regex("(?:sk-|ghp_|github_pat_)$")
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

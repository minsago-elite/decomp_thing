package decompengine.acp

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.ExtensionContext

/**
 * Writes one bounded JSON record per test JVM with its count of pre-execution scope restarts after
 * host mount churn, including zero, so CI evidence distinguishes quiet runs from recovered ones. An
 * `.expected` marker without its JSON, or an `.incomplete` marker, is incomplete telemetry; report
 * failures never fail a test. Display data only: it never admits, retries or waives anything.
 */
internal class AcpHostMountChurnRestartReport : BeforeAllCallback {
    override fun beforeAll(context: ExtensionContext) {
        try {
            context.root.getStore(ExtensionContext.Namespace.GLOBAL)
                .getOrComputeIfAbsent(AcpHostMountChurnRestartReport::class.java.name, { Report() }, Report::class.java)
        } catch (_: Throwable) { /* Telemetry never changes a test outcome; the absent marker stays visible. */ }
    }

    /** Announces an expected report at registration, then completes it or marks it incomplete at teardown. */
    private class Report : ExtensionContext.Store.CloseableResource {
        private val pid = ProcessHandle.current().pid()
        private val directory: Path? = try {
            reportDirectory(System.getenv()).also { Files.createDirectories(it) }
        } catch (_: Throwable) { null }

        init {
            directory?.let { writeQuietly(it.resolve("test-jvm-$pid.expected"), "expected\n") }
        }

        override fun close() {
            val target = directory ?: return
            try {
                val staged = target.resolve(".test-jvm-$pid.json.partial")
                Files.writeString(staged, render(AcpHostMountChurnRestarts.total(), AcpHostMountChurnRestarts.retained()))
                Files.move(staged, target.resolve("test-jvm-$pid.json"),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: Throwable) {
                writeQuietly(target.resolve("test-jvm-$pid.incomplete"), "write-failed\n")
            }
        }
    }

    internal companion object {
        const val DIRECTORY = "acp-host-mount-churn-restarts"
        private val DIGITS = Regex("[0-9]{1,20}")

        /** One fresh directory per CI run attempt, so a rerun never mixes with an earlier attempt's reports. */
        fun reportDirectory(environment: Map<String, String>): Path {
            val run = environment["GITHUB_RUN_ID"]
            val attempt = environment["GITHUB_RUN_ATTEMPT"]
            val name = if (run != null && attempt != null && DIGITS.matches(run) && DIGITS.matches(attempt)) {
                "github-$run-$attempt"
            } else "local"
            return repositoryRoot().resolve("build").resolve(DIRECTORY).resolve(name)
        }

        private fun writeQuietly(path: Path, text: String) {
            try { Files.writeString(path, text) } catch (_: Throwable) { /* The missing JSON still marks it incomplete. */ }
        }

        private val WITNESS = Regex("mount-event-v1 phase=(CHECKPOINT|CONTROL_ADMISSION|REFRESH) " +
            "generation=(NOT_EVALUATED|MISMATCH_ALREADY_OBSERVED) outcome=EVENT " +
            "rc=(NA|-?[0-9]{1,10}) revents=(NA|[0-9]{1,5}) errno=(NA|-?[0-9]{1,10})")
        private val ADMISSION = Regex("mount-admission-v1 stage=(CONSTRUCTING|ADMITTED) " +
            "initialMounts=[0-9]{1,10} initialControls=[0-9]{1,10} owner=(true|false) initialFast=(true|false)")

        /** Only the sealed producer's closed scalar records are emitted; anything else is marked invalid. */
        fun render(total: Long, retained: List<AcpMountEventWitness>): String = buildString {
            append("{\"schema\":\"acp-host-mount-churn-restarts-v1\",\"diagnosticOnly\":true,")
            append("\"restartedRefusals\":").append(total).append(",\"retained\":[")
            retained.takeLast(16).forEachIndexed { index, witness ->
                if (index > 0) append(',')
                append("{\"event\":").append(closed(witness.diagnosticRecord, WITNESS))
                append(",\"admission\":").append(closed(witness.admissionRecord, ADMISSION))
                append(",\"timing\":").append(closed(validatedAcpMountTiming(witness.timingRecord), null))
                append('}')
            }
            append("]}\n")
        }

        private fun closed(value: String?, grammar: Regex?): String = when {
            value == null -> "null"
            value.length > 512 || (grammar != null && !grammar.matches(value)) -> "\"invalid\""
            else -> "\"$value\"" // Closed ASCII grammars contain no quote, backslash or control character.
        }

        private fun repositoryRoot(): Path {
            var repository = Path.of("").toAbsolutePath().normalize()
            while (!Files.exists(repository.resolve(".git"), LinkOption.NOFOLLOW_LINKS) ||
                !Files.isRegularFile(repository.resolve("gradlew"), LinkOption.NOFOLLOW_LINKS)
            ) {
                repository = repository.parent ?: throw IllegalStateException("test is not running inside the repository")
            }
            return repository.toRealPath()
        }
    }
}

package decompengine.acp

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.ExtensionContext

/**
 * Writes one bounded JSON record per test JVM with its count of pre-execution scope restarts after
 * host mount churn, including zero, so CI evidence distinguishes quiet runs from recovered ones.
 * Display data only: it never admits, retries or waives anything.
 */
internal class AcpHostMountChurnRestartReport : BeforeAllCallback {
    override fun beforeAll(context: ExtensionContext) {
        context.root.getStore(ExtensionContext.Namespace.GLOBAL)
            .getOrComputeIfAbsent(AcpHostMountChurnRestartReport::class.java.name, { Report() }, Report::class.java)
    }

    private class Report : ExtensionContext.Store.CloseableResource {
        override fun close() {
            val directory = repositoryRoot().resolve("build").resolve(DIRECTORY)
            Files.createDirectories(directory)
            val pid = ProcessHandle.current().pid()
            val target = directory.resolve("test-jvm-$pid.json")
            val staged = directory.resolve(".test-jvm-$pid.json.partial")
            Files.writeString(staged, render(AcpHostMountChurnRestarts.total(), AcpHostMountChurnRestarts.retained()))
            Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        }
    }

    internal companion object {
        const val DIRECTORY = "acp-host-mount-churn-restarts"
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

package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal fun liveOracleUnitJournalCommand(unitName: String, sinceEpochSeconds: Long): List<String> {
    require(sinceEpochSeconds >= 0L)
    require(
        unitName.length <= 255 &&
            (
                unitName.matches(Regex("decomp-gcc-[a-z0-9][a-z0-9._-]*-[0-9a-f]{32}\\.scope")) ||
                    unitName.matches(Regex("decomp-oracle-function-[0-9a-f]{64}\\.scope"))
            ),
    )
    return listOf(
        "/usr/bin/journalctl", "--user", "--boot", "--no-pager", "--quiet", "--reverse",
        "--output=short-monotonic", "--lines=80", "--since=@$sinceEpochSeconds", "--user-unit=$unitName",
    )
}

internal fun boundedLiveOracleUnitJournal(unitName: String, sinceEpochSeconds: Long): String {
    val command = liveOracleUnitJournalCommand(unitName, sinceEpochSeconds)
    check(!Thread.currentThread().isInterrupted) { "journal diagnostics cannot run on an interrupted thread" }
    val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    val runtime = Path.of("/run/user/$uid")
    val process = ProcessBuilder(command).redirectErrorStream(true).also { builder ->
        builder.environment().clear()
        builder.environment()["XDG_RUNTIME_DIR"] = runtime.toString()
        builder.environment()["SYSTEMD_COLORS"] = "0"
        builder.environment()["LANG"] = "C"
    }.start()
    val reader = Executors.newSingleThreadExecutor { action ->
        Thread(action, "oracle-boot-journal-diagnostic").also { it.isDaemon = true }
    }
    var interrupted = false
    try {
        process.outputStream.close()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3L)
        val output = reader.submit<ByteArray> {
            process.inputStream.use { it.readNBytes(16_385) }
        }.get(3L, TimeUnit.SECONDS)
        val truncated = output.size > 16_384
        if (truncated && process.isAlive) process.destroyForcibly()
        check(process.waitFor(maxOf(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)) {
            "exact-unit journal snapshot exceeded three seconds"
        }
        return "exact-unit journal exit=${process.exitValue()}, truncated=$truncated\n" +
            output.copyOf(minOf(output.size, 16_384)).toString(Charsets.UTF_8)
    } catch (failure: InterruptedException) {
        interrupted = true
        throw failure
    } finally {
        if (process.isAlive) process.destroyForcibly()
        try {
            process.waitFor(1L, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            interrupted = true
        } finally {
            reader.shutdownNow()
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            runCatching { process.outputStream.close() }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}

internal class LiveOracleBootTrace(runDirectory: Path) : AutoCloseable {
    private val root = LinuxFilesystemSyscalls.openRoot(runDirectory)
    private val startedNanos = System.nanoTime()
    private val records = linkedMapOf<String, String>()
    private val errors = linkedMapOf<String, String>()
    private var closed = false

    @Synchronized
    fun sample() {
        if (closed || System.nanoTime() - startedNanos >= TimeUnit.MINUTES.toNanos(5L)) return
        for (name in listOf("worker.boot", "parent.start", "worker.failure", "supervisor.failure")) {
            if (name in records || name in errors) continue
            try {
                val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(root.fd, name) ?: continue
                selected.use { descriptor ->
                    val identity = descriptor.identity
                    check(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1)
                    check(identity.mode.permissions == 0b100_000_000)
                    val size = Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
                    check(size in 1L..4_096L) { "diagnostic protocol exceeds 4096-byte ceiling" }
                    val bytes = LinuxFilesystemSyscalls.openReadableFrom(descriptor).use { readable ->
                        LinuxFilesystemSyscalls.read(readable, 4_096) {
                            check(!Thread.currentThread().isInterrupted)
                        }
                    }
                    check(bytes.size.toLong() == size && LinuxFilesystemSyscalls.identity(descriptor.fd) == identity)
                    val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)
                    val content = bytes.toString(Charsets.UTF_8).replace(Regex("[\\p{Cc}&&[^\\t\\n]]"), "?")
                    records[name] = "$name observed at ${elapsed}ms: $content"
                }
            } catch (failure: Exception) {
                errors[name] = "$name unavailable: ${diagnosticFailure(failure)}"
            }
        }
    }

    @Synchronized
    fun snapshot(): String = (records.values + errors.values).joinToString("\n").ifEmpty {
        "no allowlisted BOOT protocol files observed"
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        root.close()
    }
}

internal fun <Result> withLiveOracleBootDiagnostics(
    unitName: String,
    runDirectory: Path,
    journal: (String, Long) -> String = ::boundedLiveOracleUnitJournal,
    action: () -> Result,
): Result {
    val sinceEpochSeconds = Instant.now().epochSecond
    liveOracleUnitJournalCommand(unitName, sinceEpochSeconds)
    val startedNanos = System.nanoTime()
    val openedTrace = runCatching { LiveOracleBootTrace(runDirectory) }
    val trace = openedTrace.getOrNull()
    val sampler = Executors.newSingleThreadScheduledExecutor { callback ->
        Thread(callback, "oracle-boot-protocol-diagnostic").also { it.isDaemon = true }
    }
    var primaryFailure: Throwable? = null
    try {
        sampler.scheduleWithFixedDelay({ trace?.sample() }, 0L, 100L, TimeUnit.MILLISECONDS)
        return action()
    } catch (failure: Throwable) {
        primaryFailure = failure
        val captured = runCatching {
            trace?.sample()
            val protocols = trace?.snapshot()
                ?: "protocol trace unavailable: ${diagnosticFailure(checkNotNull(openedTrace.exceptionOrNull()))}"
            val events = runCatching { journal(unitName, sinceEpochSeconds) }.fold(
                onSuccess = { it },
                onFailure = { "journal snapshot unavailable: ${diagnosticFailure(it)}" },
            )
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)
            "Full-tree BOOT diagnostics for $unitName after ${elapsed}ms (diagnostic only):\n$protocols\n$events"
        }.getOrElse { "BOOT diagnostics unavailable: ${diagnosticFailure(it)}" }
        failure.addSuppressed(AssertionError(captured))
        throw failure
    } finally {
        sampler.shutdownNow()
        val cleanupFailure = runCatching { trace?.close() }.exceptionOrNull()
        if (cleanupFailure != null) {
            val primary = primaryFailure
            if (primary == null) throw cleanupFailure
            if (cleanupFailure !== primary) primary.addSuppressed(cleanupFailure)
        }
    }
}

private fun diagnosticFailure(failure: Throwable): String =
    "${failure.javaClass.name}: ${failure.message.orEmpty().take(512)}"

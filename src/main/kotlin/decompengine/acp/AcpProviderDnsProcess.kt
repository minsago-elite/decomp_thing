package decompengine.acp

import java.io.IOException
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.jar.JarInputStream

/** Component only. There is deliberately no factory/broker launch entry point before qualification. */
internal class AcpProviderDnsProcess private constructor(
    private val artifact: ProviderDnsArtifact,
    private val requestDeadlineNanos: Long,
) {
    private val revoked = AtomicBoolean()
    private val expired = AtomicBoolean()
    private val started = AtomicBoolean()
    private val process = AtomicReference<Process?>()
    private val signalHandle = AtomicReference<ProcessHandle?>()
    private val watchdog = AtomicReference<ScheduledFuture<*>?>()
    private val deadlineGuard = Any()
    private var deadlineClosed = false
    private var deadlineRunning = false
    // Publish the exact task during construction, before any executor can run it. A worker
    // finishing inside execute must never make a missing Future look like a joined owner.
    private val task = FutureTask(Callable { runOwner(); Unit })
    private val finished = CountDownLatch(1)
    private val selected = AtomicReference<ByteArray?>()
    private val reaped = AtomicBoolean()
    private val streamsClosed = AtomicBoolean()

    /** Called only by the future closed issuer, or reflectively by component controls. */
    private fun start() {
        check(started.compareAndSet(false, true)) { DNS_FAILURE }
        if (revoked.get() || ProviderDnsOwners.quarantined.get() || remainingNanos(requestDeadlineNanos) == 0L) {
            if (remainingNanos(requestDeadlineNanos) == 0L) expired.set(true)
            refuseBeforeExecution()
            return
        }
        // Publish the timer before the owner can finish. Cleanup cannot observe a terminal
        // task and then have start publish a still-pending callback after verified closure.
        val timer = try {
            ProviderDnsOwners.deadlines.schedule({ runDeadline() }, remainingNanos(requestDeadlineNanos), TimeUnit.NANOSECONDS)
        } catch (_: RejectedExecutionException) { refuseBeforeExecution(); return }
        watchdog.set(timer)
        if (revoked.get()) stopDeadline()
        try {
            // The task retains this credential-free owner, never its HTTP caller or callback.
            ProviderDnsOwners.executor.execute(task)
        } catch (_: RejectedExecutionException) { refuseBeforeExecution() }
    }

    /** Cancellation here proves only that no task/process was ever accepted by the executor. */
    private fun refuseBeforeExecution() {
        revoked.set(true)
        task.cancel(false)
        stopDeadline()
        streamsClosed.set(true)
        finished.countDown()
    }

    fun awaitAddress(): InetAddress {
        check(started.get()) { DNS_FAILURE }
        while (finished.count != 0L || !task.isDone) {
            checkActive()
            try { finished.await(minOf(remainingNanos(requestDeadlineNanos), TimeUnit.MILLISECONDS.toNanos(10)), TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) {
                cancel()
                Thread.currentThread().interrupt()
                throw IOException(DNS_STOPPED)
            }
        }
        checkActive()
        if (!reaped.get() || !streamsClosed.get()) throw IOException(DNS_FAILURE)
        val address = selected.get() ?: throw IOException(DNS_FAILURE)
        // Never pass a name into the parent's resolver, including for reverse lookup.
        return InetAddress.getByAddress(address)
    }

    fun cancel() {
        revoked.set(true)
        selected.set(null)
        stopDeadline()
        killPublished()
    }

    private fun runDeadline() {
        synchronized(deadlineGuard) {
            if (deadlineClosed) return
            deadlineRunning = true
        }
        try { expire() }
        finally { synchronized(deadlineGuard) { deadlineRunning = false } }
    }

    private fun stopDeadline() = synchronized(deadlineGuard) {
        deadlineClosed = true
        watchdog.get()?.cancel(false)
        Unit
    }

    private fun deadlineJoined(): Boolean = synchronized(deadlineGuard) { deadlineClosed && !deadlineRunning }

    private fun expire() {
        expired.set(true)
        cancel()
    }

    private fun checkActive() {
        if (Thread.currentThread().isInterrupted) { cancel(); throw IOException(DNS_STOPPED) }
        if (remainingNanos(requestDeadlineNanos) == 0L) expire()
        if (expired.get()) throw SocketTimeoutException(DNS_TIMED_OUT)
        if (revoked.get()) throw IOException(DNS_STOPPED)
    }

    /** Publication and revocation commute: either side observes and kills the same child. */
    private fun publish(value: Process) {
        check(process.compareAndSet(null, value)) { DNS_FAILURE }
        signalHandle.set(value.toHandle())
        if (revoked.get() || remainingNanos(requestDeadlineNanos) == 0L) {
            if (remainingNanos(requestDeadlineNanos) == 0L) expired.set(true)
            cancel()
        }
    }

    private fun killPublished() {
        // Process.destroyForcibly also closes Java pipes and can wait behind a blocked reader.
        // Its saved child handle signals without touching those streams. This is not exit proof;
        // wait/reap and stream closure remain exclusively with the capped owner below.
        try { signalHandle.get()?.destroyForcibly() } catch (_: Exception) { /* verified only by cleanup */ }
    }

    private fun runOwner() {
        var child: Process? = null
        try {
            checkActive()
            artifact.requireCurrent()
            checkActive()
            // ProcessBuilder.start may ignore interruption. This capped task retains ownership
            // until it returns; a revoked late child is never accepted as a DNS result.
            child = artifact.builder().start()
            publish(child)
            child.outputStream.close()
            val bytes = child.inputStream.readNBytes(MAXIMUM_DNS_FRAME_BYTES + 1)
            val result = parseProviderDnsFrame(bytes)
            child.waitFor()
            reaped.set(!child.isAlive)
            if (child.exitValue() == 0 && reaped.get() && !revoked.get() && remainingNanos(requestDeadlineNanos) != 0L) {
                selected.set(result)
            }
        } catch (_: Exception) {
            // No causes or process output are retained. The caller gets a fixed typed failure.
        } finally {
            if (child != null) {
                if (child.isAlive) killPublished()
                // This wait belongs to the capped owner, not the HTTP task. closeBefore is
                // bounded independently and quarantines this task if native exit stays stuck.
                var interrupted = Thread.interrupted()
                while (true) {
                    try { child.waitFor(); reaped.set(!child.isAlive); break }
                    catch (_: InterruptedException) { interrupted = true; killPublished() }
                }
                var closed = true
                for (stream in listOf(child.outputStream, child.inputStream, child.errorStream)) {
                    try { stream.close() } catch (_: Exception) { closed = false }
                }
                streamsClosed.set(closed)
                if (interrupted) Thread.currentThread().interrupt()
            } else streamsClosed.set(true)
            stopDeadline()
            finished.countDown()
        }
    }

    /** One caller-owned absolute cleanup end; this method never grants a fresh grace period. */
    fun closeBefore(cleanupDeadlineNanos: Long): Boolean {
        cancel()
        if (!started.get()) {
            // No future start can be admitted after cancel's sticky revocation.
            task.cancel(false)
            streamsClosed.set(true)
            finished.countDown()
        }
        var interrupted = Thread.interrupted()
        try {
            while ((finished.count != 0L || !task.isDone || !deadlineJoined()) && remainingNanos(cleanupDeadlineNanos) != 0L) {
                try { finished.await(minOf(remainingNanos(cleanupDeadlineNanos), TimeUnit.MILLISECONDS.toNanos(1)), TimeUnit.NANOSECONDS) }
                catch (_: InterruptedException) { interrupted = true; killPublished() }
            }
            val verified = finished.count == 0L && task.isDone && deadlineJoined() && streamsClosed.get() && (process.get() == null || reaped.get() && !process.get()!!.isAlive)
            if (!verified) ProviderDnsOwners.quarantined.set(true)
            return verified
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }

    internal fun cleanupSnapshot(): AcpProviderDnsCleanupSnapshot = AcpProviderDnsCleanupSnapshot(
        revoked.get(), process.get()?.pid(), reaped.get(), finished.count == 0L && task.isDone && deadlineJoined(),
        streamsClosed.get(), ProviderDnsOwners.quarantined.get(),
    )
}

internal data class AcpProviderDnsCleanupSnapshot(
    val revoked: Boolean,
    val childPid: Long?,
    val childReaped: Boolean,
    val ownerJoined: Boolean,
    val streamsClosed: Boolean,
    val quarantined: Boolean,
)

/** Global cap includes unresolved native start and cleanup. No queued or replacement workers. */
private object ProviderDnsOwners {
    val quarantined = AtomicBoolean()
    val executor = ThreadPoolExecutor(0, 2, 0L, TimeUnit.MILLISECONDS, SynchronousQueue(),
        { task -> Thread(task, "decomp-acp-provider-dns").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    val deadlines = ScheduledThreadPoolExecutor(1,
        { task -> Thread(task, "decomp-acp-provider-dns-deadline").also { it.isDaemon = true } }).also {
        it.removeOnCancelPolicy = true
        it.executeExistingDelayedTasksAfterShutdownPolicy = false
    }
}

/**
 * No callable issuer exists in checkpoint A. Future host-boundary issuance must bind the private
 * invocation directory lifetime, installed app commitment and this exact runtime before launch.
 * Component controls reflectively construct fixture artifacts; that does not grant production use.
 */
private class ProviderDnsArtifact private constructor(
    private val jar: Path,
    private val expectedSha256: String,
    private val directory: Path,
) {
    private val java = currentProviderJavaExecutable()
    private val javaIdentity = dnsFileIdentity(java, MAXIMUM_DNS_LAUNCHER_BYTES, 0x1ed)
    private val javaSha256 = dnsSha256(boundedDnsRead(java, MAXIMUM_DNS_LAUNCHER_BYTES))
    private val jarIdentity = dnsFileIdentity(jar, MAXIMUM_DNS_JAR_BYTES, 0x1a4)
    private val directoryIdentity = dnsDirectoryIdentity(directory)

    init {
        require(expectedSha256.matches(Regex("[0-9a-f]{64}"))) { DNS_FAILURE }
        requireCurrent()
    }

    fun requireCurrent() {
        require(sameDnsIdentity(jarIdentity, dnsFileIdentity(jar, MAXIMUM_DNS_JAR_BYTES, 0x1a4)) &&
            sameDnsIdentity(directoryIdentity, dnsDirectoryIdentity(directory)) &&
            dnsSha256(boundedDnsRead(jar, MAXIMUM_DNS_JAR_BYTES)) == expectedSha256 &&
            currentProviderJavaExecutable() == java &&
            sameDnsIdentity(javaIdentity, dnsFileIdentity(java, MAXIMUM_DNS_LAUNCHER_BYTES, 0x1ed)) &&
            dnsSha256(boundedDnsRead(java, MAXIMUM_DNS_LAUNCHER_BYTES)) == javaSha256) { DNS_FAILURE }
    }

    fun builder(): ProcessBuilder = ProcessBuilder(
        java.toString(), "-Xms8m", "-Xmx32m", "-Xint", "-XX:MaxMetaspaceSize=32m", "-XX:ReservedCodeCacheSize=8m",
        "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:+DisableAttachMechanism", "-XX:-UsePerfData",
        "-XX:+ErrorFileToStderr", "-XX:-CreateCoredumpOnCrash", "-XX:-DumpReplayDataOnError",
        "-Djava.io.tmpdir=$directory", "-Duser.home=$directory", "-cp", jar.toString(), "decompengine.acp.ProviderDnsWorker",
    ).directory(directory.toFile()).redirectErrorStream(true).also { it.environment().clear() }
}

/** Compare the trusted app resource commitment; an adjacent checksum never issues authority. */
private fun authenticatePackagedProviderDnsJar(jar: Path): String {
    val expected = AcpProviderDnsProcess::class.java.getResourceAsStream("/acp-provider-dns/worker.sha256")?.use {
        val bytes = it.readNBytes(66)
        require(bytes.size == 65 && bytes.last() == 10.toByte()) { DNS_FAILURE }
        bytes.toString(Charsets.US_ASCII).trimEnd('\n')
    } ?: throw IOException(DNS_FAILURE)
    require(expected.matches(Regex("[0-9a-f]{64}"))) { DNS_FAILURE }
    dnsFileIdentity(jar, MAXIMUM_DNS_JAR_BYTES, 0x1a4)
    val bytes = boundedDnsRead(jar, MAXIMUM_DNS_JAR_BYTES)
    require(dnsSha256(bytes) == expected) { DNS_FAILURE }
    validateProviderDnsJar(bytes)
    return expected
}

private fun validateProviderDnsJar(bytes: ByteArray) {
    require(bytes.size in 1..MAXIMUM_DNS_JAR_BYTES) { DNS_FAILURE }
    JarInputStream(bytes.inputStream()).use { jar ->
        val attributes = jar.manifest?.mainAttributes ?: throw IOException(DNS_FAILURE)
        require(attributes.keys.map { it.toString() }.toSet() == setOf("Manifest-Version") && attributes.getValue("Manifest-Version") == "1.0") { DNS_FAILURE }
        var found = false
        while (true) {
            val entry = jar.nextJarEntry ?: break
            if (entry.isDirectory) {
                require(entry.name in setOf("META-INF/", "decompengine/", "decompengine/acp/")) { DNS_FAILURE }
                continue
            }
            require(!found && entry.name == "decompengine/acp/ProviderDnsWorker.class") { DNS_FAILURE }
            val content = jar.readNBytes(MAXIMUM_DNS_JAR_BYTES + 1)
            require(content.size in 1..MAXIMUM_DNS_JAR_BYTES) { DNS_FAILURE }
            found = true
        }
        require(found) { DNS_FAILURE }
    }
}

private fun currentProviderJavaExecutable(): Path {
    require(Runtime.version().feature() == 21) { DNS_FAILURE }
    val command = ProcessHandle.current().info().command().orElseThrow { IOException(DNS_FAILURE) }
    val actual = Path.of(command).toRealPath()
    val expected = Path.of(System.getProperty("java.home"), "bin", "java").toRealPath()
    require(actual == expected && Files.isExecutable(actual) && Files.isRegularFile(actual, LinkOption.NOFOLLOW_LINKS)) { DNS_FAILURE }
    return actual
}

private fun dnsFileIdentity(path: Path, maximum: Int, mode: Int): BasicFileAttributes {
    require(path.isAbsolute && path == path.normalize() && path == path.toRealPath()) { DNS_FAILURE }
    val identity = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(identity.isRegularFile && identity.fileKey() != null && identity.size() in 1..maximum.toLong() &&
        (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0xfff == mode) { DNS_FAILURE }
    return identity
}

private fun dnsDirectoryIdentity(path: Path): BasicFileAttributes {
    require(path.isAbsolute && path == path.normalize() && path == path.toRealPath()) { DNS_FAILURE }
    val identity = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(identity.isDirectory && identity.fileKey() != null &&
        (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0xfff == 0x1c0) { DNS_FAILURE }
    return identity
}

private fun sameDnsIdentity(a: BasicFileAttributes, b: BasicFileAttributes): Boolean =
    a.fileKey() == b.fileKey() && a.size() == b.size() && a.lastModifiedTime() == b.lastModifiedTime() && a.creationTime() == b.creationTime()

private fun boundedDnsRead(path: Path, maximum: Int): ByteArray = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use {
    it.readNBytes(maximum + 1).also { bytes -> require(bytes.size <= maximum) { DNS_FAILURE } }
}

private fun dnsSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

private fun parseProviderDnsFrame(bytes: ByteArray): ByteArray {
    if (bytes.size !in setOf(9, 21) || bytes[0] != 0x41.toByte() || bytes[1] != 0x44.toByte() || bytes[2] != 0x50.toByte() || bytes[3] != 0x31.toByte() ||
        bytes[4] != (if (bytes.size == 9) 4 else 6).toByte()) throw IOException(DNS_FAILURE)
    return bytes.copyOfRange(5, bytes.size)
}

private fun remainingNanos(deadline: Long): Long = (deadline - System.nanoTime()).coerceAtLeast(0L)
private const val MAXIMUM_DNS_FRAME_BYTES = 21
private const val MAXIMUM_DNS_JAR_BYTES = 64 * 1024
private const val MAXIMUM_DNS_LAUNCHER_BYTES = 1024 * 1024
private const val DNS_FAILURE = "ACP provider resolution failed"
private const val DNS_STOPPED = "ACP provider resolution stopped"
private const val DNS_TIMED_OUT = "ACP provider resolution timed out"

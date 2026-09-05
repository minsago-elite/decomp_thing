package decompengine.oracle.fulltree

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.management.HotSpotDiagnosticMXBean
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import java.io.InputStream
import java.lang.management.ManagementFactory
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal object KotlinContainedCommandKeeper {
    @JvmStatic
    fun main(arguments: Array<String>) {
        var child: Process? = null
        var secret: ByteArray? = null
        try {
            require(arguments.size == 4 && arguments[0] == KotlinContainedCommandProtocol.VERSION) {
                "contained command keeper arguments are invalid"
            }
            val runDirectory = Path.of(arguments[1])
            require(runDirectory.isAbsolute && runDirectory.normalize() == runDirectory && runDirectory.toRealPath() == runDirectory) {
                "contained command keeper run directory is not canonical"
            }
            require(arguments[2].matches(Regex("[0-9a-f]{64}")) && arguments[3].matches(Regex("[0-9a-f]{64}"))) {
                "contained command keeper bindings are invalid"
            }
            LinuxFilesystemSyscalls.openRoot(runDirectory).use { root ->
                requirePrivateDirectory(root)
                val request = root.whileOpen { descriptor ->
                    LinuxFilesystemSyscalls.openDirectoryAt(descriptor, KotlinContainedCommandRequest.REQUEST_DIRECTORY)
                }.use { runtime ->
                    requirePrivateDirectory(runtime)
                    val bytes = checkNotNull(readFile(runtime, KotlinContainedCommandRequest.REQUEST_FILE,
                        KotlinContainedCommandRequest.MAXIMUM_REQUEST_BYTES)) { "contained command request is absent" }
                    require(OracleArtifacts.sha256(bytes) == arguments[3]) { "contained command request digest differs" }
                    KotlinContainedCommandRequest.parse(bytes)
                }
                require(request.runDirectory == runDirectory && request.nonce == arguments[2]) {
                    "contained command request differs from its launch arguments"
                }
                require(ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean::class.java)
                    .getVMOption("DisableAttachMechanism").value == "true") {
                    "contained command keeper requires disabled JVM attachment"
                }
                val bootstrap = readBootstrap()
                secret = bootstrap
                val keeperPid = ProcessHandle.current().pid()
                publish(root, KotlinContainedCommandProtocol.BOOT_FILE,
                    KotlinContainedCommandProtocol.boot(bootstrap, request, keeperPid))
                publish(root, "worker.boot", "BOOT\t1\t${request.nonce}\n".toByteArray(Charsets.UTF_8))
                awaitStart(root, bootstrap, request, keeperPid)
                ContainedCommandProcessProtection.disableDumping()
                root.whileOpen { descriptor -> LinuxFilesystemSyscalls.openDirectoryAt(descriptor, "reports") }.use { reports ->
                    requirePrivateDirectory(reports)
                    root.whileOpen { descriptor -> LinuxFilesystemSyscalls.openDirectoryAt(descriptor, "tmp") }.use(::requirePrivateDirectory)
                    val stdout = BoundedCommandLog(reports, KotlinContainedCommandProtocol.STDOUT_FILE, request.maximumStdoutBytes)
                    stdout.use {
                        val stderr = BoundedCommandLog(reports, KotlinContainedCommandProtocol.STDERR_FILE, request.maximumStderrBytes)
                        stderr.use {
                            val started = System.nanoTime()
                            val process = ProcessBuilder(request.command)
                                .directory(runDirectory.toFile())
                                .redirectInput(ProcessBuilder.Redirect.PIPE)
                                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                                .redirectError(ProcessBuilder.Redirect.PIPE)
                                .also { builder ->
                                    builder.environment().clear()
                                    builder.environment().putAll(request.environment)
                                }.start()
                            child = process
                            process.outputStream.close()
                            val readers = Executors.newFixedThreadPool(2) { runnable ->
                                Thread(runnable, "contained-command-log").apply { isDaemon = true }
                            }
                            try {
                                val stdoutReader = readers.submit { stdout.capture(process.inputStream) }
                                val stderrReader = readers.submit { stderr.capture(process.errorStream) }
                                var status = "EXITED"
                                while (process.isAlive) {
                                    stdout.requireHealthy()
                                    stderr.requireHealthy()
                                    if (stdout.exceeded.get() || stderr.exceeded.get()) {
                                        status = "OUTPUT_LIMIT"
                                        break
                                    }
                                    if (request.allowInterruption) {
                                        val interrupt = readFile(root, KotlinContainedCommandProtocol.INTERRUPT_FILE,
                                            KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)
                                        if (interrupt != null) {
                                            KotlinContainedCommandProtocol.requireInterrupt(interrupt, bootstrap, request, keeperPid)
                                            // Only report interruption after observing the exact child still live.
                                            if (process.isAlive) {
                                                status = "INTERRUPTED"
                                                break
                                            }
                                        }
                                    }
                                    if (System.nanoTime() - started >= TimeUnit.SECONDS.toNanos(request.maximumWallSeconds)) {
                                        status = "TIMED_OUT"
                                        break
                                    }
                                    process.waitFor(25L, TimeUnit.MILLISECONDS)
                                }
                                if (process.isAlive) {
                                    process.destroyForcibly()
                                    require(process.waitFor(5L, TimeUnit.SECONDS)) { "contained command child survived its bounded kill" }
                                }
                                stdoutReader.get(5L, TimeUnit.SECONDS)
                                stderrReader.get(5L, TimeUnit.SECONDS)
                                stdout.requireHealthy()
                                stderr.requireHealthy()
                                if (stdout.exceeded.get() || stderr.exceeded.get()) status = "OUTPUT_LIMIT"
                                if (status == "EXITED" &&
                                    System.nanoTime() - started >= TimeUnit.SECONDS.toNanos(request.maximumWallSeconds)) {
                                    status = "TIMED_OUT"
                                }
                                val outcome = KotlinContainedCommandOutcome(keeperPid, process.pid(), process.exitValue(),
                                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started), stdout.bytes.get(), stderr.bytes.get(), status)
                                ContainedCommandProcessProtection.requireNotDumpable()
                                publish(root, KotlinContainedCommandProtocol.OUTCOME_FILE,
                                    KotlinContainedCommandProtocol.outcome(bootstrap, request, outcome))
                                publish(root, "supervisor.worker-exited",
                                    "WORKER_EXITED\t1\t${request.nonce}\t$keeperPid\n".toByteArray(Charsets.UTF_8))
                            } finally {
                                readers.shutdownNow()
                            }
                        }
                    }
                }
                bootstrap.fill(0)
                while (true) Thread.sleep(Long.MAX_VALUE)
            }
        } catch (failure: Throwable) {
            val process = child
            if (process != null && process.isAlive) {
                runCatching { process.destroyForcibly() }
                runCatching { process.waitFor(5L, TimeUnit.SECONDS) }
            }
            secret?.fill(0)
            System.err.println("contained command keeper failed safely")
            Runtime.getRuntime().halt(126)
        }
    }

    private fun readBootstrap(): ByteArray {
        val reader = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "contained-command-bootstrap").apply { isDaemon = true }
        }
        try {
            return reader.submit<ByteArray> {
                System.`in`.use { input ->
                    val bytes = input.readNBytes(KotlinContainedCommandProtocol.SECRET_BYTES + 1)
                    require(bytes.size == KotlinContainedCommandProtocol.SECRET_BYTES) {
                        "contained command bootstrap must contain exactly one secret"
                    }
                    bytes
                }
            }.get(30L, TimeUnit.SECONDS)
        } finally {
            reader.shutdownNow()
        }
    }

    private fun awaitStart(root: LinuxDescriptor, secret: ByteArray, request: KotlinContainedCommandRequest, keeperPid: Long) {
        val started = System.nanoTime()
        while (System.nanoTime() - started < TimeUnit.SECONDS.toNanos(request.maximumStartWaitSeconds)) {
            val bytes = readFile(root, KotlinContainedCommandProtocol.START_FILE, KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)
            if (bytes != null) {
                KotlinContainedCommandProtocol.requireStart(bytes, secret, request, keeperPid)
                return
            }
            Thread.sleep(25L)
        }
        throw IllegalArgumentException("contained command START deadline expired")
    }

    private fun readFile(root: LinuxDescriptor, name: String, maximumBytes: Int): ByteArray? = root.whileOpen { parent ->
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent, name) ?: return@whileOpen null
        selected.use { descriptor ->
            val identity = descriptor.identity
            require(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1 && identity.mode and 0xfff == 256 &&
                identity.uid == root.identity.uid) { "contained command input file identity is unsafe" }
            val size = Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
            require(size in 1L..maximumBytes.toLong()) { "contained command input exceeds its byte bound" }
            val bytes = LinuxFilesystemSyscalls.openReadableFrom(descriptor).use { readable ->
                LinuxFilesystemSyscalls.read(readable, maximumBytes, {})
            }
            require(bytes.size.toLong() == size && LinuxFilesystemSyscalls.identity(descriptor.fd) == identity) {
                "contained command input changed during reading"
            }
            bytes
        }
    }

    private fun publish(root: LinuxDescriptor, name: String, bytes: ByteArray) {
        require(bytes.size in 1..KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)
        val stageName = ".contained-command-${UUID.randomUUID()}.tmp"
        val stage = root.whileOpen { descriptor -> LinuxFilesystemSyscalls.createRegularFile(descriptor, stageName, 384) }
        stage.use {
            LinuxFilesystemSyscalls.write(stage, bytes, {})
            LinuxFilesystemSyscalls.chmod(stage, 256)
            LinuxFilesystemSyscalls.synchronize(stage)
            root.whileOpen { descriptor -> LinuxFilesystemSyscalls.renameNoReplace(descriptor, stageName, name) }
            LinuxFilesystemSyscalls.synchronize(root)
        }
    }

    private fun requirePrivateDirectory(directory: LinuxDescriptor) {
        val identity = directory.identity
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode and 0xfff == 448) {
            "contained command directory is not private"
        }
    }
}

private class BoundedCommandLog(root: LinuxDescriptor, name: String, private val maximumBytes: Long) : AutoCloseable {
    private val descriptor = root.whileOpen { parent -> LinuxFilesystemSyscalls.createRegularFile(parent, name, 384) }
    val bytes = AtomicLong()
    val exceeded = AtomicBoolean()
    private val failure = AtomicReference<Throwable?>()

    fun capture(input: InputStream) {
        try {
            input.use { stream ->
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd), StandardOpenOption.WRITE).use { channel ->
                    val buffer = ByteArray(16384)
                    while (true) {
                        val count = stream.read(buffer)
                        if (count < 0) break
                        val retained = minOf(count.toLong(), maximumBytes - bytes.get()).toInt()
                        val pending = ByteBuffer.wrap(buffer, 0, retained)
                        while (pending.hasRemaining()) channel.write(pending)
                        bytes.addAndGet(retained.toLong())
                        if (retained < count) {
                            exceeded.set(true)
                            break
                        }
                    }
                    channel.force(true)
                }
            }
        } catch (caught: Throwable) {
            failure.compareAndSet(null, caught)
        }
    }

    fun requireHealthy() {
        failure.get()?.let { throw IllegalArgumentException("contained command log capture failed", it) }
    }

    override fun close() = descriptor.close()
}

private object ContainedCommandProcessProtection {
    private val libc: ProtectionLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, ProtectionLibC::class.java) }

    fun disableDumping() {
        require(System.getProperty("os.name") == "Linux") { "contained command process protection requires Linux" }
        require(libc.prctl(4, NativeLong(0), NativeLong(0), NativeLong(0), NativeLong(0)) == 0) {
            "contained command process protection could not disable dumping"
        }
        requireNotDumpable()
    }

    fun requireNotDumpable() {
        require(libc.prctl(3, NativeLong(0), NativeLong(0), NativeLong(0), NativeLong(0)) == 0) {
            "contained command process protection did not remain nondumpable"
        }
    }

    private interface ProtectionLibC : Library {
        fun prctl(option: Int, argument2: NativeLong, argument3: NativeLong, argument4: NativeLong, argument5: NativeLong): Int
    }
}

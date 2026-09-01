package decompengine.oracle.behavior

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration

/** Isolated-process hostile probes which must not mutate the Gradle test worker's native state. */
internal object HostedNativeExecutionIsolatedMain {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 4)
        val mode = arguments[0]
        val root = Path.of(arguments[1]).toAbsolutePath().normalize()
        val resultMarker = Path.of(arguments[2]).toAbsolutePath().normalize()
        val spawnMarker = Path.of(arguments[3]).toAbsolutePath().normalize()
        val executablePath = when (mode) {
            "closed-stdio" -> Path.of("/usr/bin/true")
            "ignored-sigchld" -> Path.of("/bin/sh").toRealPath()
            else -> error("unsupported isolated hosted-native probe")
        }
        val retained = HostedNativeExecution.snapshot(
            Files.readAllBytes(executablePath),
            true,
            "isolated hosted-native executable",
        )
        var directory: HostedNativeExecution.PinnedDirectory? = null
        try {
            if (mode == "ignored-sigchld") {
                val previous = IsolatedLibC.INSTANCE.signal(SIGCHLD, Pointer.createConstant(SIG_IGN))
                check(previous == null || Pointer.nativeValue(previous) != SIG_ERR)
            } else {
                runCatching { FileInputStream(FileDescriptor.`in`).close() }
                runCatching { FileOutputStream(FileDescriptor.out).close() }
                runCatching { FileOutputStream(FileDescriptor.err).close() }
            }
            directory = HostedNativeExecution.open(root, "isolated hosted-native working directory")
            val invocation = if (mode == "ignored-sigchld") {
                listOf("-c", "printf spawned > $spawnMarker")
            } else {
                emptyList()
            }
            try {
                val result = HostedNativeExecution.runClang(
                    retained,
                    null,
                    invocation,
                    mapOf("LC_ALL" to "C", "TZ" to "UTC"),
                    directory,
                    Duration.ofSeconds(5),
                    4096,
                    Duration.ofSeconds(2),
                    "isolated hosted-native invocation",
                )
                Files.writeString(resultMarker, "exit=${result.exitCode}")
            } catch (failure: LlvmBehaviorHostedCleanBuildV2Exception) {
                Files.writeString(resultMarker, "failure=${failure.message}")
            }
        } finally {
            directory?.close()
            retained.close()
        }
    }

    private interface IsolatedLibC : Library {
        fun signal(signal: Int, handler: Pointer): Pointer?

        companion object {
            val INSTANCE: IsolatedLibC = Native.load(Platform.C_LIBRARY_NAME, IsolatedLibC::class.java)
        }
    }

    private const val SIGCHLD = 17
    private const val SIG_IGN = 1L
    private const val SIG_ERR = -1L
}

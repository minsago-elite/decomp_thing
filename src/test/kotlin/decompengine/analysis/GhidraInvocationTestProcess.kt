package decompengine.analysis

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Optional
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.stream.Stream

/** Completed synthetic process; exit observations are independent of the receipt writer. */
internal class GhidraInvocationTestProcess(private val exit: Int = 0, private val observedExit: (Int) -> Unit = {}) : Process() {
    private val handle = object : ProcessHandle {
        override fun pid() = 9_000_000_002L
        override fun parent(): Optional<ProcessHandle> = Optional.empty()
        override fun children(): Stream<ProcessHandle> = Stream.empty()
        override fun descendants(): Stream<ProcessHandle> = Stream.empty()
        override fun info(): ProcessHandle.Info = error("synthetic process has no host metadata")
        override fun onExit(): CompletableFuture<ProcessHandle> = CompletableFuture.completedFuture(this)
        override fun supportsNormalTermination() = true
        override fun destroy() = false
        override fun destroyForcibly() = false
        override fun isAlive() = false
        override fun compareTo(other: ProcessHandle) = pid().compareTo(other.pid())
    }
    override fun getOutputStream() = ByteArrayOutputStream()
    override fun getInputStream() = ByteArrayInputStream(byteArrayOf())
    override fun getErrorStream() = ByteArrayInputStream(byteArrayOf())
    override fun toHandle() = handle
    override fun isAlive() = false
    override fun exitValue(): Int { observedExit(exit); return exit }
    override fun waitFor() = exit
    override fun waitFor(timeout: Long, unit: TimeUnit) = true
    override fun destroy() {}
    override fun destroyForcibly(): Process = this
}

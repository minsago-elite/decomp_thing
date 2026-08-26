package decompengine.acp

import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

/** Verifies that platform detection cannot mutate names prepared in the process working directory. */
internal object AcpFilesystemSupportProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        val workingDirectory = Path.of(".").toAbsolutePath().normalize()
        val prefix = ".decomp-acp-probe-${ProcessHandle.current().pid()}-missing"
        val source = workingDirectory.resolve("$prefix-a")
        val destination = workingDirectory.resolve("$prefix-b")
        source.writeText("must remain in place\n")

        LinuxFilesystemSyscalls.requireSupported(workingDirectory)

        check(source.exists()) { "platform detection renamed the prepared source" }
        check(source.readText() == "must remain in place\n") { "platform detection changed the prepared source" }
        check(!destination.exists()) { "platform detection created the prepared destination" }
    }
}

package decompengine.l1

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

object FakeAnalyzeHeadless {
    @JvmStatic
    fun main(args: Array<String>) {
        val projectDir = Path.of(args[0]).createDirectories()
        projectDir.resolve("analysis.marker").writeText("analyzed\n")
        println("fake ghidra analyzed ${args[3]}")
    }
}

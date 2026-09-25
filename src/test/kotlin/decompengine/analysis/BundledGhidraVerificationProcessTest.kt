package decompengine.analysis

import decompengine.project.sha256
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BundledGhidraVerificationProcessTest {
    @Test
    fun `bounded verifier returns the authenticated sorted library inventory`() = withFixture { bundle ->
        val actual = BundledGhidraVerificationProcess().verifyAndGetLibraries(bundle.root) {}

        assertEquals(listOf(bundle.release.resolve("Ghidra/Features/Base/lib/Base.jar")), actual)
    }

    @Test
    fun `shared deadline kills a blocked verifier process and reaps its child`() = withFixture { bundle ->
        val pidFile = bundle.root.resolve("verifier.pid")
        val deadline = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(250), "fixture verifier")
        val verifier = BundledGhidraVerificationProcess(commandFactory = {
            listOf(
                "/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10",
                "authored-verifier", pidFile.toString(),
            )
        })
        val started = System.nanoTime()

        val failure = assertFailsWith<GhidraAnalysisException> {
            verifier.verifyAndGetLibraries(bundle.root, deadline::checkpoint)
        }

        assertTrue(failure.message.orEmpty().contains("fixture verifier exceeded 250 milliseconds"))
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "blocked verifier outlived the shared deadline")
        assertTrue(pidFile.toFile().isFile, "blocked verifier did not record its owned child")
        val pid = pidFile.readText().trim().toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false), "verifier child is still alive")
    }

    @Test
    fun `inventory protocol rejects extra output and escaping paths`() = withFixture { bundle ->
        val header = "${BundledGhidraVerificationProcess.INVENTORY_PROVIDER}\n${BundledGhidra.VERSION}\n"
        val extraOutput = BundledGhidraVerificationProcess(commandFactory = {
            listOf("/usr/bin/printf", "${header}path/lib/a.jar\nextra\n")
        })
        val escapingPath = BundledGhidraVerificationProcess(commandFactory = {
            listOf("/usr/bin/printf", "${header}../lib/a.jar\n")
        })

        assertFailsWith<IllegalArgumentException> { extraOutput.verifyAndGetLibraries(bundle.root) {} }
        assertFailsWith<IllegalArgumentException> { escapingPath.verifyAndGetLibraries(bundle.root) {} }
    }

    private fun withFixture(block: (BundledGhidra) -> Unit) {
        val root = createTempDirectory("bundled-ghidra-verifier-")
        try {
            val files = linkedMapOf(
                "decomp-ghidra-bridge.jar" to "bridge fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Base/lib/Base.jar" to "library fixture\n",
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/application.properties" to
                    "application.version=${BundledGhidra.VERSION}\napplication.release.name=PUBLIC\n",
            )
            files.forEach { (relative, content) ->
                root.resolve(relative).also { path ->
                    path.parent.createDirectories()
                    path.writeText(content)
                }
            }
            root.resolve("bundle.sha256").writeText(files.toSortedMap().entries.joinToString("") { (relative, content) ->
                "${sha256(content.toByteArray())}  $relative\n"
            })
            block(BundledGhidra.at(root))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}

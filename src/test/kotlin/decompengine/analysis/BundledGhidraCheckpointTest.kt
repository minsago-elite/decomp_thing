package decompengine.analysis

import java.nio.file.Files
import java.security.MessageDigest
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class BundledGhidraCheckpointTest {
    @Test
    fun `authored bundle verification and command preparation retain checkpoints and compatibility`() = withFixture { bundle ->
        val stages = mutableListOf<String>()
        bundle.verify { stages += it }

        assertEquals("before bundled Ghidra verification", stages.first())
        assertEquals("after bundled Ghidra verification", stages.last())
        assertTrue(stages.count { it == "after reading bundled Ghidra file: $libraryPath" } >= 3)
        assertTrue("after visiting bundled Ghidra file inventory path" in stages)
        assertTrue("after reading bundled Ghidra application properties bytes" in stages)

        val invocation = GhidraInvocation(
            project = bundle.root.resolve("analysis project"),
            projectName = "authored fixture",
            input = bundle.root.resolve("input with spaces"),
            scripts = bundle.root.resolve("scripts"),
            postScripts = listOf(GhidraPostScript("Export.java", listOf("argument with spaces"))),
        )
        stages.clear()
        val command = bundle.analysisCommand(invocation) { stages += it }
        assertEquals(bundle.analysisCommand(invocation), command)
        assertEquals("before returning bundled Ghidra analysis command", stages.last())
        assertTrue("after visiting bundled Ghidra library inventory path" in stages)
        assertEquals(listOf("Export.java", "1", "argument with spaces"), command.takeLast(3))

        stages.clear()
        assertEquals(bundle.probeCommand(), bundle.probeCommand { stages += it })
        assertEquals("before returning bundled Ghidra probe command", stages.last())
        assertEquals("probe", bundle.probeCommand().last())
    }

    @Test
    fun `hash checkpoint cancellation preserves its exception and skips later work`() = withFixture { bundle ->
        val cancellation = InterruptedException("caller cancelled bundle verification")
        val stages = mutableListOf<String>()
        val stopStage = "after reading bundled Ghidra file: $libraryPath"

        val failure = assertFailsWith<InterruptedException> {
            bundle.verify { stage ->
                stages += stage
                if (stage == stopStage) throw cancellation
            }
        }

        assertSame(cancellation, failure)
        assertEquals(stopStage, stages.last())
        assertEquals(1, stages.count { it == stopStage })
        assertFalse("before opening bundled Ghidra file inventory" in stages)
        assertEquals(libraryContent, bundle.root.resolve(libraryPath).readText())
        bundle.verify()
    }

    @Test
    fun `final command checkpoint can cancel before the prepared command is returned`() = withFixture { bundle ->
        val cancellation = InterruptedException("caller cancelled completed command preparation")
        val stages = mutableListOf<String>()

        val failure = assertFailsWith<InterruptedException> {
            bundle.probeCommand { stage ->
                stages += stage
                if (stage == "before returning bundled Ghidra probe command") throw cancellation
            }
        }

        assertSame(cancellation, failure)
        assertTrue("after reading bundled Ghidra library inventory" in stages)
        assertEquals("before returning bundled Ghidra probe command", stages.last())
    }

    private fun withFixture(block: (BundledGhidra) -> Unit) {
        val root = createTempDirectory("bundled-ghidra-checkpoint-")
        try {
            val files = linkedMapOf(
                "decomp-ghidra-bridge.jar" to "authored bridge text\n",
                libraryPath to libraryContent,
                "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/application.properties" to
                    "application.version=${BundledGhidra.VERSION}\napplication.release.name=PUBLIC\n",
            )
            files.forEach { (relative, content) ->
                root.resolve(relative).also { path ->
                    path.parent.createDirectories()
                    path.writeText(content)
                }
            }
            root.resolve("bundle.sha256").writeText(files.entries.joinToString("") { (relative, content) ->
                val digest = MessageDigest.getInstance("SHA-256").digest(content.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                "$digest  $relative\n"
            })
            block(BundledGhidra.at(root))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private val libraryPath = "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Base/lib/Base.jar"
    private val libraryContent = "x".repeat(65536 + 17)
}

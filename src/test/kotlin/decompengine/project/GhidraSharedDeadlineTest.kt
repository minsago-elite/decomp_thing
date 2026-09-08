package decompengine.project

import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.GhidraAnalysisException
import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.jobs.elfFixture
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GhidraSharedDeadlineTest {
    @Test
    fun `expired parent deadline rejects before workspace or command preparation`() = inControlTemporaryDirectory { root ->
        val work = root.resolve("analysis")
        var commandPrepared = false
        val analyzer = GhidraHeadlessProgramModelAnalyzer(commandFactory = {
            commandPrepared = true
            error("expired parent must prevent command preparation")
        })
        val parent = deadline(10)
        Thread.sleep(25)

        val failure = assertFailsWith<GhidraAnalysisException> {
            analyzer.analyzeWithDeadline(root.resolve("unused-authored-input"), work, parent)
        }

        assertTrue(failure.message.orEmpty().contains("fixture parent exceeded 10 milliseconds before export preparation"))
        assertFalse(commandPrepared)
        assertFalse(work.exists())
    }

    @Test
    fun `command preparation cannot launch its returned command after the parent expires`() = inControlTemporaryDirectory { root ->
        val work = root.resolve("analysis")
        val marker = root.resolve("worker-launched")
        val input = root.resolve("authored.txt").also { it.writeText("authored local input\n") }
        var commandReturned = false
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = {
                Thread.sleep(600)
                commandReturned = true
                listOf("/usr/bin/touch", marker.toString())
            },
            limits = limits(5_000),
        )

        val failure = assertFailsWith<GhidraAnalysisException> {
            analyzer.analyzeWithDeadline(input, work, deadline(500))
        }

        assertTrue(commandReturned)
        assertTrue(failure.message.orEmpty().contains("fixture parent exceeded 500 milliseconds after constructing export command"))
        assertFalse(marker.exists())
        assertFalse(work.resolve("reports/ghidra_resource_usage.json").exists())
    }

    @Test
    fun `earlier parent terminates the worker without changing its configured budget`() = inControlTemporaryDirectory { root ->
        withOwnedSleepCommand(root) { command, pidFile ->
            val input = root.resolve("authored.txt").also { it.writeText("authored local input\n") }
            val work = root.resolve("analysis")
            val configured = limits(5_000)
            val analyzer = GhidraHeadlessProgramModelAnalyzer({ command }, configured)
            val parent = deadline(300)
            val started = System.nanoTime()

            val failure = assertFailsWith<GhidraAnalysisException> {
                analyzer.analyzeWithDeadline(input, work, parent)
            }

            assertTrue(failure.message.orEmpty().contains("fixture parent exceeded 300 milliseconds"))
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "worker received a fresh configured allowance")
            assertWorkerStopped(pidFile)
            assertDeadlineEvidence(work, configuredMillis = 5_000, parentMillis = 300)
            assertEquals(Duration.ofSeconds(5), configured.wallClockTimeout)
            assertFalse(work.resolve("reports/program_model.json").exists())
        }
    }

    @Test
    fun `stricter configured worker deadline remains below a longer parent allowance`() = inControlTemporaryDirectory { root ->
        withOwnedSleepCommand(root) { command, pidFile ->
            val input = root.resolve("authored.txt").also { it.writeText("authored local input\n") }
            val work = root.resolve("analysis")
            val analyzer = GhidraHeadlessProgramModelAnalyzer({ command }, limits(250))
            val started = System.nanoTime()

            val failure = assertFailsWith<GhidraAnalysisException> {
                analyzer.analyzeWithDeadline(input, work, deadline(5_000))
            }

            assertTrue(failure.message.orEmpty().contains("Ghidra program recovery exceeded 250 milliseconds"))
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2), "worker received the longer parent allowance")
            assertWorkerStopped(pidFile)
            assertDeadlineEvidence(work, configuredMillis = 250, parentMillis = 5_000)
            assertFalse(work.resolve("reports/program_model.json").exists())
        }
    }

    @Test
    fun `JVM wrapper retains parent deadline forwarding through export budget binding`() = inControlTemporaryDirectory { root ->
        withOwnedSleepCommand(root) { command, pidFile ->
            val input = root.resolve("authored.elf").also { it.writeBytes(elfFixture()) }
            val work = root.resolve("analysis")
            val configured = limits(5_000)
            val requested = ReconstructionProfiles.default.budgets.copy(exportWallClockMillis = 250)
            val analyzer = GhidraJvmAnalyzer(GhidraHeadlessProgramModelAnalyzer({ command }, configured))
                .withExportBudgets(requested)

            val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(input, work) }

            assertTrue(failure.message.orEmpty().contains("analysis and metadata exceeded 250 milliseconds"))
            assertWorkerStopped(pidFile)
            assertDeadlineEvidence(work, configuredMillis = 250, parentMillis = 250)
            assertEquals(250L, requested.exportWallClockMillis)
            assertEquals(Duration.ofSeconds(5), configured.wallClockTimeout)
            assertFalse(work.resolve("reports/ghidra_analysis.json").exists())
        }
    }

    @Test
    fun `successful shared deadline export reads and returns an authored canonical model`() = inControlTemporaryDirectory { root ->
        val inputBytes = "authored local model input\n".toByteArray(Charsets.UTF_8)
        val input = root.resolve("authored.txt").also { it.writeBytes(inputBytes) }
        val work = root.resolve("analysis")
        val expected = RecoveredProgramModel(
            inputSha256 = sha256(inputBytes),
            functions = (0 until 256).map { index ->
                RecoveredFunction(
                    id = "fn_fixture_$index",
                    name = "fixture_$index",
                    address = 0x401000UL + index.toULong() * 16UL,
                    prototype = "int fixture_$index(void)",
                    decompiledC = "int fixture_$index(void) { return $index; }\n",
                )
            },
        )
        val canonicalBytes = expected.toJson().toByteArray(Charsets.UTF_8)
        assertTrue(canonicalBytes.size > 64 * 1024, "fixture should exercise more than one bounded read chunk")
        var commandPreparations = 0
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            commandFactory = { invocation ->
                commandPreparations++
                assertEquals(input, invocation.input)
                val output = Path.of(invocation.postScripts.single().arguments.last())
                assertEquals(work.resolve("reports/program_model.json").toAbsolutePath().normalize(), output)
                output.writeBytes(canonicalBytes)
                listOf("/usr/bin/printf", "authored export complete\n")
            },
            limits = limits(5_000).copy(maximumProgramModelBytes = canonicalBytes.size.toLong()),
        )

        val actual = analyzer.analyzeWithDeadline(input, work, deadline(5_000))

        assertEquals(expected, actual)
        assertEquals(1, commandPreparations)
        assertEquals("authored export complete\n", work.resolve("reports/ghidra_stdout.log").readText())
        assertDeadlineEvidence(work, configuredMillis = 5_000, parentMillis = 5_000)
    }

    private fun deadline(milliseconds: Long): AnalysisDeadline = AnalysisDeadline.start(
        TimeUnit.MILLISECONDS.toNanos(milliseconds), "fixture parent",
    )

    private fun limits(milliseconds: Long) = GhidraProgramModelExportLimits(
        wallClockTimeout = Duration.ofMillis(milliseconds),
        terminationGrace = Duration.ofMillis(100),
        maximumDiagnosticBytesPerStream = 64,
    )

    private fun assertDeadlineEvidence(work: Path, configuredMillis: Long, parentMillis: Long) {
        val usage: JsonObject = Json.parseToJsonElement(work.resolve("reports/ghidra_resource_usage.json").readText()).jsonObject
        assertEquals(configuredMillis, usage.getValue("wallClockMillisLimit").jsonPrimitive.long)
        assertEquals(parentMillis, usage.getValue("parentWallClockMillisLimit").jsonPrimitive.long)
        val remaining = usage.getValue("remainingWallClockNanosAtLaunch").jsonPrimitive.long
        assertTrue(remaining > 0)
        assertTrue(remaining <= TimeUnit.MILLISECONDS.toNanos(minOf(configuredMillis, parentMillis)))
        assertEquals(64L, usage.getValue("maximumDiagnosticBytesPerStream").jsonPrimitive.long)
    }

    private fun assertWorkerStopped(pidFile: Path) {
        assertTrue(pidFile.exists(), "owned worker should have started before the deadline")
        val pid = pidFile.readText().trim().toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false), "owned export worker is still alive")
    }

    private inline fun withOwnedSleepCommand(root: Path, block: (List<String>, Path) -> Unit) {
        val pidFile = root.resolve("worker.pid")
        val command = listOf(
            "/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10",
            "authored-export", pidFile.toString(),
        )
        try {
            block(command, pidFile)
        } finally {
            if (pidFile.exists()) {
                val pid = pidFile.readText().trim().toLongOrNull()
                pid?.let { ProcessHandle.of(it).orElse(null) }?.let { process ->
                    if (process.isAlive) {
                        process.destroyForcibly()
                        process.onExit().get(2, TimeUnit.SECONDS)
                    }
                }
            }
        }
    }
}

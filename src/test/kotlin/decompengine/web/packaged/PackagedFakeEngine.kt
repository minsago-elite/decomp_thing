package decompengine.web.packaged

import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowRunObservation
import decompengine.jobs.BestEffortProgressJournal
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowUsage
import decompengine.oracle.core.OracleJson
import decompengine.project.ArchivalPackager
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import decompengine.web.DurableWebWorkflowAdapter
import decompengine.web.DurableWebWorkflowContext
import decompengine.web.DurableWebWorkflowOutcome
import decompengine.web.UploadServer
import decompengine.web.WebUiMode
import decompengine.web.startWebServerWithShutdownHook
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * Test-owned packaged lane. The browser driver puts this class next to the unmodified application
 * JAR from an extracted distribution; no distribution contains it. The single registered adapter
 * never analyzes or executes the uploaded binary: it emits phases, waits for test-owned control
 * files, then writes a fixed generated C tree through the production generator, build and packager.
 */
internal class PackagedFakeReconstruction(private val control: Path, private val sensitiveValues: Collection<String>) :
    DurableWebWorkflowAdapter {
    override val workflow = WorkflowKind.RECONSTRUCT
    override val limits = LIMITS

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome = try { run(context) }
    catch (failure: Exception) {
        // Fixture-owned diagnostics for the driver's sanitized server log; the service still records the failure.
        val message = sensitiveValues.filter { it.length >= 8 }.fold(failure.message.orEmpty().take(400)) { text, value -> text.replace(value, "[redacted]") }
        System.err.println("packaged-fixture-failure run=${context.attempt.runId} ${failure::class.java.simpleName}: $message")
        throw failure
    }

    private fun run(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        val runId = context.attempt.runId
        val started = System.nanoTime()
        Files.createDirectories(context.reportsDirectory)
        BestEffortProgressJournal(context.reportsDirectory, "reconstruct", sensitiveValues).use { progress ->
            fun observe(phase: AgentWorkflowPhase) = progress.runState(AgentWorkflowRunObservation(runId, phase))
            observe(AgentWorkflowPhase.ANALYZING)
            marker(runId, "started")
            await(runId, 1)
            observe(AgentWorkflowPhase.PLANNING)
            marker(runId, "planning")
            await(runId, 2)
            // Released while the browser is offline, so a reconnect must deliver an observation it never saw.
            observe(AgentWorkflowPhase.AGENT_RUNNING)
            marker(runId, "agent-running")
            await(runId, 3)
            observe(AgentWorkflowPhase.BUILD_VALIDATING)
            if (Files.exists(control.resolve("$runId.enospc"))) {
                // A genuine ENOSPC from the kernel, without filling a shared filesystem.
                try { FileOutputStream("/dev/full").use { it.write(ByteArray(4096)); it.flush() } }
                catch (failure: java.io.IOException) {
                    observe(AgentWorkflowPhase.FAILED)
                    marker(runId, "enospc")
                    // The private failure text carries the server secret; no view, log or record may retain it.
                    throw java.io.IOException("${failure.message} while writing ${System.getenv(SECRET)}", failure)
                }
                error("The disk-full control did not observe ENOSPC")
            }
            val tree = context.reportsDirectory.resolve("source-tree")
            val input = Files.readAllBytes(context.job.binaryPath)
            SourceTreeGenerator.generate(model(sha256(input)), tree)
            check(MakeProjectBuilder.build(tree).returnCode == 0) { "Fixture source tree did not build" }
            ArchivalPackager.create(tree, context.reportsDirectory.resolve("source-tree.zip"))
            val contract = OracleJson.parse(Files.readAllBytes(tree.resolve("reports/build_contract.json"))).jsonObject
            val revision = contract.getValue("sourceRevisionSha256").jsonPrimitive.content
            observe(AgentWorkflowPhase.COMPLETED)
            marker(runId, "completed")
            return DurableWebWorkflowOutcome.Completed(WorkflowCandidate("revision_${revision.take(24)}", revision), usage(started))
        }
    }

    private fun usage(started: Long) = WorkflowUsage(toolCalls = 0u, wallClockMs = ((System.nanoTime() - started) / 1_000_000).toULong())

    private fun marker(runId: String, name: String) {
        Files.writeString(control.resolve("$runId.$name"), "")
    }

    /** Bounded wait on a test-owned step counter; an owned shutdown interrupts the sleep. */
    private fun await(runId: String, step: Int) {
        val file = control.resolve("$runId.step")
        val deadline = System.nanoTime() + WAIT_NANOS
        while (System.nanoTime() < deadline) {
            val current = runCatching { Files.readString(file).trim().toInt() }.getOrDefault(0)
            if (current >= step) return
            Thread.sleep(50)
        }
        error("The packaged fixture step $step was not released")
    }

    companion object {
        val LIMITS = WorkflowExecutionLimits(180_000u, 180_000u, 16_777_216u, 0u)
        const val SECRET = "DECOMP_PACKAGED_FIXTURE_SECRET"
        private const val WAIT_NANOS = 150_000_000_000L
        fun model(inputSha256: String) = RecoveredProgramModel(
            inputSha256 = inputSha256,
            functions = listOf(
                RecoveredFunction("fn_1000", "fixture_entry", 0x1000uL, "int fixture_entry(void)"),
                RecoveredFunction("fn_1040", "fixture_helper", 0x1040uL, "int fixture_helper(int value)"),
            ),
        )

        private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}

/** Mirrors `llm_bin_patch web --ui spa` argument and console handoff behavior for the fixture lane only. */
fun main(args: Array<String>) {
    val options = args.toList().chunked(2).associate { pair ->
        require(pair.size == 2 && pair[0] in setOf("--port", "--base-path", "--data-dir", "--control-dir")) { "unsupported fixture argument" }
        pair[0] to pair[1]
    }
    val control = Path.of(options.getValue("--control-dir"))
    require(Files.isDirectory(control)) { "--control-dir must name an existing test-owned directory" }
    val basePath = options.getValue("--base-path")
    val sensitive = System.getenv().values
    val server = startWebServerWithShutdownHook { cancellation ->
        UploadServer("127.0.0.1", options.getValue("--port").toInt(), Path.of(options.getValue("--data-dir")),
            uiMode = WebUiMode.SPA, basePath = basePath, sensitiveValues = sensitive, startupCancellation = cancellation,
            durableAdapters = listOf(PackagedFakeReconstruction(control, sensitive)),
            // A test-owned file simulates a full upload filesystem without filling a shared disk.
            uploadAvailableBytes = {
                if (Files.exists(control.resolve("disk-full"))) 0L
                else Files.getFileStore(Path.of(options.getValue("--data-dir")).toAbsolutePath().parent).usableSpace
            })
    }
    println("Serving decomp_engine packaged fake-engine fixture on http://127.0.0.1:${server.serverPort}$basePath")
    val bootstrap = server.issueBrowserBootstrap()
    println("Open local browser session (expires ${bootstrap.expiresAt}): ${server.browserOrigin}$basePath#bootstrap=${bootstrap.token}")
}

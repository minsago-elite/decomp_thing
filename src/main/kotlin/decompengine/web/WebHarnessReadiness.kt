package decompengine.web

import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.analysis.BundledGhidra
import decompengine.validation.BwrapCapability
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Public harness availability; [state] uses the contract's capability state vocabulary. */
internal data class WebHarnessReadiness(val state: String, val reasonCode: String?, val message: String)

/**
 * Projects harness configuration readiness for bootstrap without launching a workflow.
 *
 * The probe runs on a dedicated daemon thread with a hard deadline and its result is cached for
 * [ttlNanos], so a slow or hung probe can never block a browser request for longer than
 * [timeoutMillis]. A probe that outlives its deadline is abandoned, and at most one abandoned probe
 * may keep running: no further probe starts until it ends. Reasons are fixed codes; exception text
 * and environment values are never copied into the projection.
 */
internal class WebHarnessReadinessProjector(
    private val probe: () -> WebHarnessReadiness = ::probeEnvironment,
    private val timeoutMillis: Long = 5_000,
    private val ttlNanos: Long = TimeUnit.SECONDS.toNanos(10),
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private var executor: ExecutorService = newExecutor()
    private var closed = false
    private var cached: WebHarnessReadiness? = null
    private var cachedAt = 0L
    private var abandoned: AtomicBoolean? = null

    @Synchronized
    fun current(): WebHarnessReadiness {
        val now = nanoTime()
        cached?.let { if (now - cachedAt < ttlNanos) return it }
        val result = refresh()
        cached = result
        cachedAt = now
        return result
    }

    private fun refresh(): WebHarnessReadiness {
        if (closed) return FAILED
        if (abandoned?.get() == true) return TIMED_OUT
        abandoned = null
        val running = AtomicBoolean(false)
        val future = executor.submit(Callable {
            running.set(true)
            try { probe() } finally { running.set(false) }
        })
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true)
            executor.shutdownNow()
            executor = newExecutor()
            abandoned = running
            TIMED_OUT
        } catch (_: Exception) {
            FAILED
        }
    }

    @Synchronized
    fun close() {
        closed = true
        executor.shutdownNow()
    }

    private fun newExecutor(): ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "web-harness-readiness").apply { isDaemon = true }
    }

    companion object {
        private val TIMED_OUT = WebHarnessReadiness("unavailable", "PROBE_TIMEOUT", "Harness readiness could not be determined in time.")
        private val FAILED = WebHarnessReadiness("unavailable", "PROBE_FAILED", "Harness readiness could not be determined.")

        /** Same fixed locations the sandboxed execution boundary uses before any analyzed binary is run. */
        private val BUBBLEWRAP: Path = Path.of("/usr/bin/bwrap")
        private val TIMEOUT: Path = Path.of("/usr/bin/timeout")

        fun probeEnvironment(
            environment: Map<String, String> = System.getenv(),
            bubblewrap: Path = BUBBLEWRAP,
            timeoutHelper: Path = TIMEOUT,
            jsonStatusSupported: (Path) -> Boolean = BwrapCapability::jsonStatusSupported,
            ghidraPresent: () -> Boolean = ::bundledGhidraPresent,
        ): WebHarnessReadiness {
            val selected = environment["ACP_HARNESS"]
            if (selected != null && selected != "acp" && selected != "legacy-openai") {
                return WebHarnessReadiness("unsupported", "HARNESS_UNSUPPORTED", "The configured harness selection is not supported.")
            }
            if ((selected == null || selected == "acp") && environment["ACP_CONFIG_FILE"].isNullOrBlank()) {
                return WebHarnessReadiness("unavailable", "HARNESS_NOT_CONFIGURED", "No agent harness is configured.")
            }
            try {
                val selection = AcpHarnessFactory.fromEnvironment(environment)
                // The legacy adapter defers its environment validation to harness creation.
                if (selection.kind == AcpHarnessKind.LEGACY_OPENAI) selection.createHarness()
            } catch (_: Exception) {
                return WebHarnessReadiness("unavailable", "HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid.")
            }
            if (!Files.isExecutable(bubblewrap) || !Files.isExecutable(timeoutHelper) || !jsonStatusSupported(bubblewrap)) {
                return WebHarnessReadiness("unavailable", "SANDBOX_HELPER_MISSING", "The sandbox helpers required to run analyzed binaries are not available.")
            }
            if (!ghidraPresent()) {
                return WebHarnessReadiness("unavailable", "GHIDRA_MISSING", "The bundled Ghidra distribution is not present; reinstall the complete application.")
            }
            return WebHarnessReadiness("supported", null, "An agent harness, sandbox helpers and bundled Ghidra are available.")
        }

        // Presence only: the analysis run re-verifies the bundle, and launching it here would not be bounded.
        private fun bundledGhidraPresent(): Boolean = try {
            Files.isDirectory(BundledGhidra.locate().release)
        } catch (_: Exception) {
            false
        }
    }
}

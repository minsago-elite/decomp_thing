package decompengine.web

import decompengine.acp.AcpHarnessFactory
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Public harness availability; [state] uses the contract's capability state vocabulary. */
internal data class WebHarnessReadiness(val state: String, val reasonCode: String?, val message: String)

/**
 * Projects harness configuration readiness for bootstrap without launching a workflow.
 *
 * The probe runs on a dedicated daemon thread with a hard deadline and its result is cached for
 * [ttlNanos], so a slow or hung probe can never block a browser request for longer than
 * [timeoutMillis]. Reasons are fixed codes; exception text and environment values are never copied
 * into the projection.
 */
internal class WebHarnessReadinessProjector(
    private val probe: () -> WebHarnessReadiness = ::probeEnvironment,
    private val timeoutMillis: Long = 2_000,
    private val ttlNanos: Long = TimeUnit.SECONDS.toNanos(10),
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "web-harness-readiness").apply { isDaemon = true }
    }
    private var cached: WebHarnessReadiness? = null
    private var cachedAt = 0L

    @Synchronized
    fun current(): WebHarnessReadiness {
        val now = nanoTime()
        cached?.let { if (now - cachedAt < ttlNanos) return it }
        val result = try {
            executor.submit(Callable(probe)).get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            WebHarnessReadiness("unavailable", "PROBE_TIMEOUT", "Harness readiness could not be determined in time.")
        } catch (_: Exception) {
            WebHarnessReadiness("unavailable", "PROBE_FAILED", "Harness readiness could not be determined.")
        }
        cached = result
        cachedAt = now
        return result
    }

    companion object {
        fun probeEnvironment(environment: Map<String, String> = System.getenv()): WebHarnessReadiness {
            val selected = environment["ACP_HARNESS"]
            if (selected != null && selected != "acp" && selected != "legacy-openai") {
                return WebHarnessReadiness("unsupported", "HARNESS_UNSUPPORTED", "The configured harness selection is not supported.")
            }
            if ((selected == null || selected == "acp") && environment["ACP_CONFIG_FILE"].isNullOrBlank()) {
                return WebHarnessReadiness("unavailable", "HARNESS_NOT_CONFIGURED", "No agent harness is configured.")
            }
            return try {
                AcpHarnessFactory.fromEnvironment(environment)
                WebHarnessReadiness("supported", null, "An agent harness is configured.")
            } catch (_: Exception) {
                WebHarnessReadiness("unavailable", "HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid.")
            }
        }
    }
}

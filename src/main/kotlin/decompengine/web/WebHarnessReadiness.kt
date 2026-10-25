package decompengine.web

import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.analysis.BundledGhidra
import decompengine.validation.BwrapCapability
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference

/** One runtime prerequisite as a fixed public reason; never exception text or configuration values. */
internal data class WebPrerequisite(val available: Boolean, val reasonCode: String?, val message: String) {
    init { require(available == (reasonCode == null)) }
    companion object { val AVAILABLE = WebPrerequisite(true, null, "Available.") }
}

/**
 * Non-secret identity the harness factory resolved for one configured harness. The configuration digest
 * is the factory's canonical digest; no configuration text, path, credential or environment value is kept.
 */
internal data class WebHarnessProvenance(
    val implementationId: String,
    val agentContractVersion: Int,
    val protocolVersion: Int?,
    val sdkVersion: String?,
    val configurationSha256: String?,
    val deprecated: Boolean,
    val stableDescriptor: String,
) {
    companion object {
        fun of(provenance: decompengine.acp.AcpHarnessProvenance) = WebHarnessProvenance(provenance.implementationId,
            provenance.agentExecutionContractVersion, provenance.acpProtocolVersion, provenance.acpSdkVersion,
            provenance.configurationSha256, provenance.deprecated, provenance.stableDescriptor)
    }
}

/**
 * One harness's readiness. Provenance is present only when its configuration resolved; [selected] marks
 * the environment-selected harness that the explicit agent inspection starts.
 */
internal data class WebHarnessFacts(val prerequisite: WebPrerequisite, val provenance: WebHarnessProvenance?, val selected: Boolean = false) {
    init { require(provenance == null || prerequisite.available || prerequisite.reasonCode == WebAgentPreflight.REASON_FAILED) }
}

private val PREFLIGHT_FAILED = WebPrerequisite(false, WebAgentPreflight.REASON_FAILED,
    "The last operator inspection could not start the configured agent.")

/**
 * Independent workflow prerequisites from the same cached probe as harness readiness. Admission
 * rechecks a fresh snapshot; a probe that did not finish yields no snapshot, never a supported one.
 * [agent] is the environment-selected harness; [harnesses] reports each selectable harness separately.
 */
internal data class WebWorkflowPrerequisites(
    val agent: WebPrerequisite,
    val sandbox: WebPrerequisite,
    val ghidra: WebPrerequisite,
    val harnesses: Map<WebAgentHarness, WebHarnessFacts> = emptyMap(),
) {
    /** The named harness's own readiness; a snapshot without per-harness facts reports the selected agent. */
    fun harness(harness: WebAgentHarness?): WebPrerequisite = when {
        harness == WebAgentHarness.BUILTIN -> BUILTIN_UNSUPPORTED
        harness == null -> agent
        else -> harnesses[harness]?.prerequisite ?: agent
    }

    /** Agent first: its configuration is the most specific operator action. */
    fun unmet(requirements: Set<WebWorkflowRequirement>, harness: WebAgentHarness? = null): WebPrerequisite? = listOf(
        WebWorkflowRequirement.AGENT_HARNESS to harness(harness), WebWorkflowRequirement.SANDBOX to sandbox,
        WebWorkflowRequirement.GHIDRA to ghidra,
    ).firstOrNull { (requirement, fact) -> requirement in requirements && !fact.available }?.second

    companion object {
        /** In-process callers without a runtime probe (inert fixtures). The HTTP path always supplies a snapshot. */
        val UNCHECKED = WebWorkflowPrerequisites(WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE)
        /** The built-in harness exists as a library but no workflow runs it yet (#79, #76, #77). */
        val BUILTIN_UNSUPPORTED = WebPrerequisite(false, "BUILTIN_HARNESS_NOT_INTEGRATED",
            "The built-in agent harness is not yet integrated with this workflow. It is never substituted for another harness.")
    }
}

/** Public harness availability; [state] uses the contract's capability state vocabulary. */
internal data class WebHarnessReadiness(val state: String, val reasonCode: String?, val message: String,
    val prerequisites: WebWorkflowPrerequisites? = null) {
    /**
     * Folds the last explicit agent preflight into a configured harness. Bootstrap never starts the
     * agent, so an absent, running or cancelled inspection leaves readiness unproven rather than assumed.
     */
    fun withAgentInspection(status: String?): WebHarnessReadiness = when {
        state != "supported" -> this
        status == "failed" -> WebHarnessReadiness("unavailable", WebAgentPreflight.REASON_FAILED,
            "The last operator inspection could not start the configured agent. Inspect the agent configuration and retry.",
            prerequisites?.let { facts ->
                // The inspection starts only the environment-selected harness; other harnesses keep their own facts.
                val selected = facts.harnesses.entries.singleOrNull { it.value.selected }?.key
                facts.copy(agent = PREFLIGHT_FAILED, harnesses = facts.harnesses.mapValues { (harness, value) ->
                    if (harness == selected) value.copy(prerequisite = PREFLIGHT_FAILED) else value
                })
            })
        status == "ready" -> copy(message = "An agent harness and sandbox helpers are available; the last operator inspection started the configured agent.")
        else -> copy(message = "An agent harness and sandbox helpers are available. The agent has not been started by an operator inspection, so its readiness is unproven.")
    }
}

/** Atomically expires queued work or retains an admitted callback until its final exit. */
internal class WebHarnessProbeAdmission {
    private enum class State { QUEUED, RUNNING, FINISHED }
    private val state = AtomicReference(State.QUEUED)

    fun <T : Any> tryRun(probe: () -> T): T? {
        if (!state.compareAndSet(State.QUEUED, State.RUNNING)) return null
        return try { probe() } finally { state.set(State.FINISHED) }
    }

    fun abandon() { state.compareAndSet(State.QUEUED, State.FINISHED) }
    val isRunning: Boolean get() = state.get() == State.RUNNING
}

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
    private var abandoned: WebHarnessProbeAdmission? = null

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
        if (abandoned?.isRunning == true) return TIMED_OUT
        abandoned = null
        val admission = WebHarnessProbeAdmission()
        val future = executor.submit(Callable { admission.tryRun(probe) ?: TIMED_OUT })
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            abandonProbe(admission, future)
            TIMED_OUT
        } catch (_: InterruptedException) {
            abandonProbe(admission, future)
            Thread.currentThread().interrupt()
            FAILED
        } catch (_: Exception) {
            FAILED
        }
    }

    private fun abandonProbe(admission: WebHarnessProbeAdmission, future: Future<*>) {
        // Expire before cancelling: FutureTask may already have passed its own state check.
        admission.abandon()
        future.cancel(true)
        executor.shutdownNow()
        executor = newExecutor()
        abandoned = admission
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
            val agent = agentPrerequisite(environment)
            val harnesses = harnessFacts(environment)
            val sandbox = if (!Files.isExecutable(bubblewrap) || !Files.isExecutable(timeoutHelper) || !jsonStatusSupported(bubblewrap)) {
                WebPrerequisite(false, "SANDBOX_HELPER_MISSING", "The sandbox helpers required to run analyzed binaries are not available.")
            } else WebPrerequisite.AVAILABLE
            val ghidra = if (!ghidraPresent()) {
                WebPrerequisite(false, "GHIDRA_MISSING", "The bundled Ghidra distribution is not present; reinstall the complete application.")
            } else WebPrerequisite.AVAILABLE
            val prerequisites = WebWorkflowPrerequisites(agent, sandbox, ghidra, harnesses)
            // Harness readiness keeps its established precedence: harness, sandbox, then Ghidra.
            val first = listOf(agent, sandbox, ghidra).firstOrNull { !it.available }
                ?: return WebHarnessReadiness("supported", null, "An agent harness, sandbox helpers and bundled Ghidra are available.", prerequisites)
            val state = if (first.reasonCode == "HARNESS_UNSUPPORTED") "unsupported" else "unavailable"
            return WebHarnessReadiness(state, first.reasonCode, first.message, prerequisites)
        }

        private fun agentPrerequisite(environment: Map<String, String>): WebPrerequisite {
            val selected = environment["ACP_HARNESS"]
            if (selected != null && selected != "acp" && selected != "legacy-openai") {
                return WebPrerequisite(false, "HARNESS_UNSUPPORTED", "The configured harness selection is not supported.")
            }
            if ((selected == null || selected == "acp") && environment["ACP_CONFIG_FILE"].isNullOrBlank()) {
                return WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured.")
            }
            return try {
                val selection = AcpHarnessFactory.fromEnvironment(environment)
                // The legacy adapter defers its environment validation to harness creation.
                if (selection.kind == AcpHarnessKind.LEGACY_OPENAI) selection.createHarness()
                WebPrerequisite.AVAILABLE
            } catch (_: Exception) {
                WebPrerequisite(false, "HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid.")
            }
        }

        /**
         * Each selectable harness resolved independently through the same factory, with its exact selector.
         * ACP is the default and always reported; the retained legacy adapter is reported only when the
         * operator explicitly selected it. Nothing here starts an agent process or contacts a provider.
         */
        internal fun harnessFacts(environment: Map<String, String>): Map<WebAgentHarness, WebHarnessFacts> {
            val selected = environment["ACP_HARNESS"]
            val unsupported = selected != null && selected != "acp" && selected != "legacy-openai"
            fun resolve(harness: WebAgentHarness): WebHarnessFacts {
                val isSelected = !unsupported && (selected ?: "acp") == harness.selector
                if (unsupported) return WebHarnessFacts(WebPrerequisite(false, "HARNESS_UNSUPPORTED",
                    "The configured harness selection is not supported."), null)
                val effective = environment + ("ACP_HARNESS" to checkNotNull(harness.selector))
                if (harness == WebAgentHarness.ACP && environment["ACP_CONFIG_FILE"].isNullOrBlank()) {
                    return WebHarnessFacts(WebPrerequisite(false, "HARNESS_NOT_CONFIGURED", "No agent harness is configured."), null, isSelected)
                }
                return try {
                    val selection = AcpHarnessFactory.fromEnvironment(effective)
                    if (selection.kind == AcpHarnessKind.LEGACY_OPENAI) selection.createHarness()
                    WebHarnessFacts(WebPrerequisite.AVAILABLE, WebHarnessProvenance.of(selection.provenance), isSelected)
                } catch (_: Exception) {
                    WebHarnessFacts(WebPrerequisite(false, "HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid."),
                        null, isSelected)
                }
            }
            return buildMap {
                put(WebAgentHarness.ACP, resolve(WebAgentHarness.ACP))
                if (selected == "legacy-openai") put(WebAgentHarness.LEGACY_OPENAI, resolve(WebAgentHarness.LEGACY_OPENAI))
            }
        }

        /** Whether the operator explicitly retained the deprecated legacy adapter. */
        fun legacyHarnessConfigured(environment: Map<String, String> = System.getenv()): Boolean =
            environment["ACP_HARNESS"] == "legacy-openai"

        /** Stable public identity of the configured agent selection; never a path or configuration value. */
        fun agentHarnessCapabilityId(environment: Map<String, String> = System.getenv()): String =
            if (environment["ACP_HARNESS"] == "legacy-openai") "agent-legacy-openai" else "agent-acp"

        // Presence only: the analysis run re-verifies the bundle, and launching it here would not be bounded.
        private fun bundledGhidraPresent(): Boolean = try {
            Files.isDirectory(BundledGhidra.locate().release)
        } catch (_: Exception) {
            false
        }
    }
}

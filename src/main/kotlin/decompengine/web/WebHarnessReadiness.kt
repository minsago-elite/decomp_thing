package decompengine.web

import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessSelection
import decompengine.analysis.BundledGhidra
import decompengine.validation.BwrapCapability
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference

/**
 * One runtime prerequisite as a fixed public reason; never exception text or configuration values.
 * [unknown] marks a prerequisite that only an explicit operator inspection can establish.
 */
internal data class WebPrerequisite(val available: Boolean, val reasonCode: String?, val message: String,
    val unknown: Boolean = false) {
    init { require(available == (reasonCode == null) && !(available && unknown)) }
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
 * Independent workflow prerequisites from the same passive or explicitly inspected observation as
 * harness readiness. Admission refuses an unavailable or unchecked prerequisite; a probe that did
 * not finish yields no snapshot, never a supported one. [agent] is the environment-selected harness;
 * [harnesses] reports each selectable harness separately.
 */
internal data class WebWorkflowPrerequisites(
    val agent: WebPrerequisite,
    val sandbox: WebPrerequisite,
    val ghidra: WebPrerequisite,
    /** The secure repair runtime's contained candidate validator; part of no harness readiness. */
    val repairValidator: WebPrerequisite = WebPrerequisite.AVAILABLE,
    val harnesses: Map<WebAgentHarness, WebHarnessFacts> = emptyMap(),
) {
    /** The named harness's own readiness; a snapshot without per-harness facts reports the selected agent. */
    fun harness(harness: WebAgentHarness?): WebPrerequisite = when {
        harness == WebAgentHarness.BUILTIN -> BUILTIN_UNSUPPORTED
        harness == null -> agent
        else -> harnesses[harness]?.prerequisite ?: agent
    }

    /** Static qualification gates precede runtime checks: probing cannot establish process ownership. */
    fun unmet(requirements: Set<WebWorkflowRequirement>, harness: WebAgentHarness? = null): WebPrerequisite? = listOf(
        WebWorkflowRequirement.EXPLORATION_HELPER_OWNERSHIP to EXPLORATION_HELPERS_UNQUALIFIED,
        WebWorkflowRequirement.AGENT_HARNESS to harness(harness), WebWorkflowRequirement.SANDBOX to sandbox,
        WebWorkflowRequirement.GHIDRA to ghidra, WebWorkflowRequirement.REPAIR_VALIDATOR to repairValidator,
    ).firstOrNull { (requirement, fact) -> requirement in requirements && !fact.available }?.second

    companion object {
        // Descendant sampling loses fast-exiting leaders' reparented pipe writers (#71). No runtime
        // readiness result or environment flag can qualify this production execution option.
        private val EXPLORATION_HELPERS_UNQUALIFIED = WebPrerequisite(false, "EXPLORATION_HELPERS_UNQUALIFIED",
            "Exploration helper ownership and cancellation are not yet qualified for production use, so exploration cannot run on this server.")
        /** In-process callers without a runtime probe (inert fixtures). The HTTP path always supplies a snapshot. */
        val UNCHECKED = WebWorkflowPrerequisites(WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE, WebPrerequisite.AVAILABLE)
        /** The built-in harness exists as a library but no workflow runs it yet (#79, #76, #77). */
        val BUILTIN_UNSUPPORTED = WebPrerequisite(false, "BUILTIN_HARNESS_NOT_INTEGRATED",
            "The built-in agent harness is not yet integrated with this workflow. It is never substituted for another harness.")
    }
}

/** Public harness availability; [state] uses the contract's capability state vocabulary. */
internal data class WebHarnessReadiness(
    val state: String,
    val reasonCode: String?,
    val message: String,
    val configurationIdentity: String? = null,
    val observationKey: String? = null,
    val prerequisites: WebWorkflowPrerequisites? = null,
) {
    /** Internal identities never enter the public capability or preflight JSON. */
    fun withAgentInspection(snapshot: WebAgentPreflightSnapshot): WebHarnessReadiness {
        if (configurationIdentity != null && configurationIdentity != snapshot.configurationIdentity) {
            return withAgentInspection(null)
        }
        val folded = if (state == "unknown" && reasonCode == "SANDBOX_HELPER_UNCHECKED" && snapshot.status == "failed") failedInspection()
            else withAgentInspection(snapshot.status)
        // The agent fact is independent of the aggregate harness state: a matching failed inspection
        // blocks agent options even when another prerequisite already made the harness unavailable.
        return if (snapshot.status == "failed") folded.withFailedAgentFact() else folded
    }

    private fun withFailedAgentFact(): WebHarnessReadiness =
        copy(prerequisites = failedInspection().prerequisites)

    /**
     * Folds the last explicit agent preflight into a configured harness. Bootstrap never starts the
     * agent, so an absent, running or cancelled inspection leaves readiness unproven rather than assumed.
     */
    fun withAgentInspection(status: String?): WebHarnessReadiness = when {
        state != "supported" -> this
        status == "failed" -> failedInspection()
        status == "ready" -> copy(message = "An agent harness and sandbox helpers are available; the last operator inspection started the configured agent.")
        else -> copy(message = "An agent harness and sandbox helpers are available. The agent has not been started by an operator inspection, so its readiness is unproven.")
    }

    private fun failedInspection() = WebHarnessReadiness("unavailable", WebAgentPreflight.REASON_FAILED,
        "The last operator inspection could not start the configured agent. Inspect the agent configuration and retry.",
        prerequisites = prerequisites?.let { facts ->
            // The inspection starts only the environment-selected harness; other harnesses keep their own facts.
            val selected = facts.harnesses.entries.singleOrNull { it.value.selected }?.key
            facts.copy(agent = PREFLIGHT_FAILED, harnesses = facts.harnesses.mapValues { (harness, value) ->
                if (harness == selected) value.copy(prerequisite = PREFLIGHT_FAILED) else value
            })
        })
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
    private val probe: () -> WebHarnessReadiness = ::passiveEnvironment,
    private val timeoutMillis: Long = 5_000,
    private val ttlNanos: Long = TimeUnit.SECONDS.toNanos(10),
    private val nanoTime: () -> Long = System::nanoTime,
    private val inspectionProbe: () -> WebHarnessReadiness = ::inspectEnvironment,
    private val sandboxProbe: () -> WebPrerequisite = ::inspectSandboxHelpers,
) {
    private var executor: ExecutorService = newExecutor()
    private var closed = false
    private var cached: WebHarnessReadiness? = null
    private var cachedAt = 0L
    private var abandoned: WebHarnessProbeAdmission? = null
    private var inspected: WebHarnessReadiness? = null
    private var inspectedAt = 0L

    @Synchronized
    fun current(): WebHarnessReadiness {
        val now = nanoTime()
        cached?.let { if (now - cachedAt < ttlNanos) return withObservation(it, now) }
        val result = refresh(probe)
        cached = result
        cachedAt = now
        return withObservation(result, nanoTime())
    }

    /** Only an explicit operator inspection may run the existing execution-capable helper check. */
    @Synchronized
    fun inspect(): WebHarnessReadiness {
        val result = refresh(inspectionProbe)
        inspected = result
        inspectedAt = nanoTime()
        return result
    }

    /**
     * Admission-time helper check. Starting a workflow is itself an explicit operator action, so it
     * may run the execution-capable helper check, bounded like every probe and independent of any
     * agent configuration. Page loads never call this.
     */
    @Synchronized
    fun inspectSandbox(): WebPrerequisite {
        val result = refresh { WebHarnessReadiness("supported", null, "", prerequisites =
            WebWorkflowPrerequisites(WebPrerequisite.AVAILABLE, sandboxProbe(), WebPrerequisite.AVAILABLE)) }
        return result.prerequisites?.sandbox ?: WebPrerequisite(false, result.reasonCode ?: "PROBE_FAILED",
            "The sandbox helper check did not finish in time. Nothing was started; retry the start.")
    }

    private fun withObservation(base: WebHarnessReadiness, now: Long): WebHarnessReadiness {
        if (base.state != "unknown" || base.reasonCode != "SANDBOX_HELPER_UNCHECKED") return base
        val observation = inspected ?: return base
        if (base.configurationIdentity == null || base.configurationIdentity != observation.configurationIdentity ||
            base.observationKey == null || base.observationKey != observation.observationKey ||
            now - inspectedAt >= ttlNanos) return base
        return observation
    }

    private fun refresh(callback: () -> WebHarnessReadiness): WebHarnessReadiness {
        if (closed) return FAILED
        if (abandoned?.isRunning == true) return TIMED_OUT
        abandoned = null
        val admission = WebHarnessProbeAdmission()
        val future = executor.submit(Callable { admission.tryRun(callback) ?: TIMED_OUT })
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
            repairValidatorQualified: () -> Boolean = decompengine.project.LinuxGeneratedCRepairValidationBoundary::productionQualified,
        ): WebHarnessReadiness = environmentReadiness(environment, bubblewrap, timeoutHelper,
            jsonStatusSupported, ghidraPresent, bindObservation = false, repairValidatorQualified)

        /** Passive page-load facts for tests: helper capability stays unchecked, nothing is launched. */
        internal fun passiveReadiness(
            environment: Map<String, String>, bubblewrap: Path, timeoutHelper: Path, ghidraPresent: () -> Boolean,
            repairValidatorQualified: () -> Boolean = decompengine.project.LinuxGeneratedCRepairValidationBoundary::productionQualified,
        ): WebHarnessReadiness = environmentReadiness(environment, bubblewrap, timeoutHelper, { null }, ghidraPresent,
            bindObservation = true, repairValidatorQualified)

        /** Configuration and file metadata only; a page load cannot launch a helper or agent. */
        private fun passiveEnvironment(): WebHarnessReadiness = environmentReadiness(
            System.getenv(), BUBBLEWRAP, TIMEOUT, { null }, ::bundledGhidraPresent, bindObservation = true)

        private val SANDBOX_MISSING = WebPrerequisite(false, "SANDBOX_HELPER_MISSING",
            "The sandbox helpers required to run analyzed binaries are not available.")

        private fun inspectSandboxHelpers(): WebPrerequisite =
            if (Files.isExecutable(BUBBLEWRAP) && Files.isExecutable(TIMEOUT) && BwrapCapability.inspectJsonStatusSupported(BUBBLEWRAP))
                WebPrerequisite.AVAILABLE else SANDBOX_MISSING

        private fun inspectEnvironment(): WebHarnessReadiness = environmentReadiness(
            System.getenv(), BUBBLEWRAP, TIMEOUT, BwrapCapability::inspectJsonStatusSupported,
            ::bundledGhidraPresent, bindObservation = true)

        private fun environmentReadiness(
            environment: Map<String, String>,
            bubblewrap: Path,
            timeoutHelper: Path,
            jsonStatusSupported: (Path) -> Boolean?,
            ghidraPresent: () -> Boolean,
            bindObservation: Boolean,
            repairValidatorQualified: () -> Boolean = decompengine.project.LinuxGeneratedCRepairValidationBoundary::productionQualified,
        ): WebHarnessReadiness {
            // Workflow facts are independent of the harness precedence below. Ghidra and helper
            // executability are file metadata only; helper capability (null = unchecked) is known only
            // from an explicit inspection, which runs after a configured agent starts.
            val helpersPresent = Files.isExecutable(bubblewrap) && Files.isExecutable(timeoutHelper)
            val ghidra = if (ghidraPresent()) WebPrerequisite.AVAILABLE
                else WebPrerequisite(false, "GHIDRA_MISSING", "The bundled Ghidra distribution is not present; reinstall the complete application.")
            val repairValidator = if (repairValidatorQualified()) WebPrerequisite.AVAILABLE
                else WebPrerequisite(false, "REPAIR_VALIDATOR_UNQUALIFIED",
                    "The contained repair validator is not yet qualified for production use, so repair cannot run on this server.")
            fun facts(agent: WebPrerequisite, helperStatus: Boolean?): WebWorkflowPrerequisites = WebWorkflowPrerequisites(agent, when {
                !helpersPresent || helperStatus == false -> WebPrerequisite(false, "SANDBOX_HELPER_MISSING",
                    "The sandbox helpers required to run analyzed binaries are not available.")
                helperStatus == null -> WebPrerequisite(false, "SANDBOX_HELPER_UNCHECKED",
                    "Sandbox helpers are checked when this workflow starts; loading a page never runs them.",
                    unknown = true)
                else -> WebPrerequisite.AVAILABLE
            }, ghidra, repairValidator, harnessFacts(environment))
            fun agentMissing(reason: String, message: String) = WebPrerequisite(false, reason, message)
            val selected = environment["ACP_HARNESS"]
            if (selected != null && selected != "acp" && selected != "legacy-openai") {
                return WebHarnessReadiness("unsupported", "HARNESS_UNSUPPORTED", "The configured harness selection is not supported.",
                    prerequisites = facts(agentMissing("HARNESS_UNSUPPORTED", "The configured harness selection is not supported."), null))
            }
            if ((selected == null || selected == "acp") && environment["ACP_CONFIG_FILE"].isNullOrBlank()) {
                return WebHarnessReadiness("unavailable", "HARNESS_NOT_CONFIGURED", "No agent harness is configured.",
                    prerequisites = facts(agentMissing("HARNESS_NOT_CONFIGURED", "No agent harness is configured."), null))
            }
            val selection = try {
                val configured = AcpHarnessFactory.fromEnvironment(environment)
                configured.validateConfiguration()
                configured
            } catch (_: Exception) {
                return WebHarnessReadiness("unavailable", "HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid.",
                    prerequisites = facts(agentMissing("HARNESS_CONFIGURATION_INVALID", "The agent harness configuration is invalid."), null))
            }
            val identity = if (bindObservation) selection.provenance.stableDescriptor else null
            if (!helpersPresent) {
                return WebHarnessReadiness("unavailable", "SANDBOX_HELPER_MISSING", "The sandbox helpers required to run analyzed binaries are not available.",
                    identity, prerequisites = facts(WebPrerequisite.AVAILABLE, false))
            }
            val key = if (bindObservation) observationKey(selection, bubblewrap, timeoutHelper) else null
            val jsonStatus = jsonStatusSupported(bubblewrap)
            if (jsonStatus == false) {
                return WebHarnessReadiness("unavailable", "SANDBOX_HELPER_MISSING", "The sandbox helpers required to run analyzed binaries are not available.", identity, key,
                    facts(WebPrerequisite.AVAILABLE, false))
            }
            if (!ghidraPresent()) {
                return WebHarnessReadiness("unavailable", "GHIDRA_MISSING", "The bundled Ghidra distribution is not present; reinstall the complete application.",
                    prerequisites = facts(WebPrerequisite.AVAILABLE, jsonStatus))
            }
            if (jsonStatus == null) {
                return WebHarnessReadiness("unknown", "SANDBOX_HELPER_UNCHECKED",
                    "A harness is configured. Inspect the agent to check helper readiness.", identity, key, facts(WebPrerequisite.AVAILABLE, null))
            }
            if (bindObservation && (key == null || key != observationKey(selection, bubblewrap, timeoutHelper))) {
                return WebHarnessReadiness("unknown", "SANDBOX_HELPER_UNCHECKED",
                    "Helper identity changed during inspection. Inspect the agent again to check readiness.", identity,
                    prerequisites = facts(WebPrerequisite.AVAILABLE, null))
            }
            return WebHarnessReadiness("supported", null, "An agent harness, sandbox helpers and bundled Ghidra are available.", identity, key,
                facts(WebPrerequisite.AVAILABLE, true))
        }

        /** A short-lived observation key, never execution or admission authority. */
        private fun observationKey(selection: AcpHarnessSelection, vararg helpers: Path): String? {
            return try {
                val parts = listOf(selection.provenance.stableDescriptor) + helpers.map { helper ->
                    val attributes = Files.readAttributes(helper, BasicFileAttributes::class.java)
                    val fileKey = attributes.fileKey() ?: return null
                    listOf(helper.toString(), fileKey.toString(), attributes.size().toString(),
                        attributes.lastModifiedTime().toString()).joinToString("\u0000")
                }
                MessageDigest.getInstance("SHA-256").digest(parts.joinToString("\u0001").toByteArray(Charsets.UTF_8))
                    .joinToString("") { "%02x".format(it) }
            } catch (_: Exception) { null }
        }

        /** Stable public identity of the configured agent selection; never a path or configuration value. */
        /**
         * Each selectable harness resolved independently through the same factory, with its exact selector.
         * ACP is the default and always reported; the retained legacy adapter is reported only when the
         * operator explicitly selected it. Configuration validation only: no agent process or provider is contacted.
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
                    selection.validateConfiguration()
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

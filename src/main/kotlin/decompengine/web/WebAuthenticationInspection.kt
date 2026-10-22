package decompengine.web

import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpAuthenticationInventory
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.acp.AcpPreflightWorkflow
import decompengine.agent.AgentCancellation
import java.util.concurrent.atomic.AtomicReference

/** Retain the harness's unresolved-cleanup guard across repeated operator inspections. */
internal fun defaultWebAuthenticationInspector(
    selectHarness: (() -> AcpAgentHarness)? = null,
): WebObservedAuthenticationInspector {
    val identity = AtomicReference<String?>()
    val select = selectHarness ?: {
        val selection = AcpHarnessFactory.fromEnvironment(System.getenv())
        require(selection.kind == AcpHarnessKind.ACP) { "authentication inspection requires ACP" }
        val harness = selection.createHarness() as AcpAgentHarness
        identity.set(selection.provenance.stableDescriptor)
        harness
    }
    return WebObservedAuthenticationInspector(select, identity::get)
}

/** Reading the identity does not select, construct or start a harness. */
internal class WebObservedAuthenticationInspector(
    selectHarness: () -> AcpAgentHarness,
    private val selectedIdentity: () -> String?,
) : (AgentCancellation) -> AcpAuthenticationInventory {
    // Cache failures as values: lazy alone retries a throwing initializer on every click.
    val harness by lazy {
        try { Result.success(selectHarness()) }
        catch (failure: Exception) { Result.failure(failure) }
    }
    override fun invoke(cancellation: AgentCancellation): AcpAuthenticationInventory =
        harness.getOrThrow().preflight(AcpPreflightWorkflow.WEB, cancellation).authentication

    fun configurationIdentity(): String? = selectedIdentity()
}

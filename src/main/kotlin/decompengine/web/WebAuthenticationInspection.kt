package decompengine.web

import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpAuthenticationInventory
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.acp.AcpPreflightWorkflow

/** Retain the harness's unresolved-cleanup guard across repeated operator inspections. */
internal fun defaultWebAuthenticationInspector(
    selectHarness: () -> AcpAgentHarness = {
        val selection = AcpHarnessFactory.fromEnvironment(System.getenv())
        require(selection.kind == AcpHarnessKind.ACP) { "authentication inspection requires ACP" }
        selection.createHarness() as AcpAgentHarness
    },
): (decompengine.agent.AgentCancellation) -> AcpAuthenticationInventory {
    // Cache failures as values: lazy alone retries a throwing initializer on every click.
    val harness by lazy {
        try { Result.success(selectHarness()) }
        catch (failure: Exception) { Result.failure(failure) }
    }
    return { cancellation -> harness.getOrThrow().preflight(AcpPreflightWorkflow.WEB, cancellation).authentication }
}

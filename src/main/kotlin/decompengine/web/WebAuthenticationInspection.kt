package decompengine.web

import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpAuthenticationInventory
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.acp.AcpPreflightWorkflow

/** Retain the harness's unresolved-cleanup guard across repeated operator inspections. */
internal fun defaultWebAuthenticationInspector(): () -> AcpAuthenticationInventory {
    val harness by lazy {
        val selection = AcpHarnessFactory.fromEnvironment(System.getenv())
        require(selection.kind == AcpHarnessKind.ACP) { "authentication inspection requires ACP" }
        selection.createHarness() as AcpAgentHarness
    }
    return { harness.preflight(AcpPreflightWorkflow.WEB).authentication }
}

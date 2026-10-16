import decompengine.acp.AcpInvocationEvidenceSnapshot;
import decompengine.agent.AgentExecutionException;
import decompengine.agent.AgentExecutionOutcome;
import decompengine.agent.AgentExecutionReceipt;
import decompengine.agent.AgentFailure;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.regex.Pattern;

/** Ordinary-log diagnostics from an existing failure only; no execution or cleanup authority. */
final class AcpCompatibilityFailureSummary {
    private static final Pattern MOUNT_WITNESS = Pattern.compile(
        "mount-event-v1 phase=(CHECKPOINT|CONTROL_ADMISSION|REFRESH) " +
        "generation=(NOT_EVALUATED|MISMATCH_ALREADY_OBSERVED) " +
        "outcome=(EVENT|INVALID_DESCRIPTOR|SYSCALL_ERROR) " +
        "rc=(NA|-?[0-9]{1,10}) revents=(NA|[0-9]{1,5}) errno=(NA|-?[0-9]{1,10})"
    );

    private AcpCompatibilityFailureSummary() {}

    static void report(AgentExecutionReceipt receipt, Throwable failure) {
        try {
            System.err.println("ACP qualification failure: " + describe(receipt, failure));
        } catch (Throwable unavailable) {
            // A diagnostic failure must not replace the qualification's original failure.
            System.err.println("ACP qualification failure: bounded context unavailable");
        }
    }

    static String describe(AgentExecutionReceipt receipt, Throwable failure) {
        if (receipt == null && failure instanceof AgentExecutionException execution) {
            receipt = execution.getReceipt();
        }
        AgentFailure terminal = null;
        var outcome = "missing";
        if (receipt != null) {
            if (receipt.getOutcome() instanceof AgentExecutionOutcome.Failed failed) {
                terminal = failed.getFailure();
                outcome = "FAILED";
            } else {
                outcome = "RETURNED";
            }
        } else if (failure instanceof AgentExecutionException execution) {
            terminal = execution.getFailure();
        }
        var invocation = receipt != null &&
            receipt.getProviderEvidence() instanceof AcpInvocationEvidenceSnapshot evidence ? evidence : null;
        var diagnostics = invocation == null ? null : invocation.getDiagnostics();
        var pending = new ArrayDeque<Throwable>();
        if (failure != null) pending.add(failure);
        if (receipt != null && receipt.getOutcome() instanceof AgentExecutionOutcome.Failed) {
            // requireResult only materializes the stored failure; it never executes the harness.
            try {
                receipt.requireResult();
            } catch (AgentExecutionException stored) {
                pending.add(stored);
            }
        }
        var seen = new ArrayList<Throwable>(8);
        var causes = new ArrayList<String>(8);
        while (!pending.isEmpty() && seen.size() < 8) {
            var current = pending.removeFirst();
            if (seen.stream().anyMatch(previous -> previous == current)) continue;
            seen.add(current);
            String witness = null;
            if (current.getClass().getName().equals(
                "decompengine.acp.RuntimePrivateControlScope$MountEventDiagnostic")) {
                var message = current.getMessage();
                if (message != null && message.length() <= 512 && MOUNT_WITNESS.matcher(message).matches()) {
                    witness = message;
                }
            }
            var sites = new ArrayList<String>(2);
            var stack = current.getStackTrace();
            for (var index = 0; index < Math.min(32, stack.length) && sites.size() < 2; index++) {
                var site = siteLabel(stack[index]);
                if (site != null) sites.add(site);
            }
            causes.add(witness == null ? typeLabel(current) + "[" + String.join(",", sites) + "]" : witness);
            if (current.getCause() != null && pending.size() < 16) pending.add(current.getCause());
            var suppressed = current.getSuppressed();
            for (var index = 0; index < Math.min(2, suppressed.length) && pending.size() < 16; index++) {
                pending.add(suppressed[index]);
            }
        }
        var summary = "outcome=" + outcome +
            " failureKind=" + (terminal == null ? "missing" : terminal.getKind().name()) +
            " retryable=" + (terminal == null ? "missing" : terminal.getRetryable()) +
            " sessionPresent=" + (terminal == null ? "missing" : terminal.getSession() != null) +
            " phase=" + (invocation == null ? "missing" : invocation.getPhaseReached().name()) +
            " cleanup=" + (invocation == null ? "missing" : invocation.getCleanupDisposition().name()) +
            " negotiated=" + (invocation == null ? "missing" : invocation.getNegotiatedAgent() != null) +
            " diagnostics=" + (diagnostics != null) +
            " exitCode=" + (diagnostics == null ? "missing" : diagnostics.getExitCode()) +
            " remainingProcesses=" + (diagnostics == null ? "missing" : diagnostics.getRemainingProcessIds().size()) +
            " outputOverflow=" + (diagnostics == null ? "missing" : diagnostics.getOutputLimitExceeded()) +
            " causes=" + String.join(" -> ", causes);
        return summary.substring(0, Math.min(4096, summary.length()));
    }

    private static String typeLabel(Throwable failure) {
        return switch (failure.getClass().getName()) {
            case "decompengine.agent.AgentExecutionException" -> "agent-execution";
            case "java.io.IOException" -> "io";
            case "java.lang.IllegalStateException" -> "illegal-state";
            case "decompengine.acp.LinuxSyscallException" -> "syscall";
            case "decompengine.acp.AcpCleanupProofFailure" -> "cleanup-proof";
            case "decompengine.acp.AcpPhaseTimeout" -> "phase-timeout";
            case "com.agentclientprotocol.protocol.JsonRpcException" -> "json-rpc";
            default -> "other";
        };
    }

    private static String siteLabel(StackTraceElement frame) {
        return switch (frame.getClassName() + "#" + frame.getMethodName()) {
            case "decompengine.acp.RuntimePrivateControlScope#checkpoint" -> "private-control-checkpoint";
            case "decompengine.acp.RuntimePrivateControlScope#requireMountsUnchanged",
                 "decompengine.acp.RuntimePrivateControlScope$MountEventCheck#requireUnchanged" -> "mount-check";
            case "decompengine.acp.RuntimePrivateControlScope#requireDescriptor" -> "descriptor-revalidation";
            case "decompengine.acp.RuntimePrivateControlScope#currentRoot" -> "root-identity";
            case "decompengine.acp.RuntimePrivateControlScope#requireRootUnexposed" -> "private-control-coverage";
            case "decompengine.acp.LinuxBubblewrapBoundaryKt#requirePrivateControlRegistryHealthy" -> "registry-health";
            case "decompengine.acp.RuntimePrivateControlScope$MountEventCheck#eventFailure" -> "mount-event";
            case "decompengine.acp.LinuxFilesystemSyscalls$MountMetadataPollScratch#pollDescriptor" -> "mount-poll";
            case "decompengine.acp.ProductionAcpSandboxExecution#<init>" -> "sandbox-construction";
            case "decompengine.acp.AcpAgentHarness#executeInternalReceipt" -> "harness-receipt";
            case "decompengine.acp.AcpAgentHarness#awaitPhase" -> "await-phase";
            case "decompengine.acp.AcpAgentHarness#initializeAgent" -> "initialize";
            case "decompengine.acp.AcpAgentHarness#runProtocol" -> "protocol";
            default -> null;
        };
    }
}

import decompengine.acp.AcpExecutionCleanupDisposition;
import decompengine.acp.AcpExecutionEvidenceCompleteness;
import decompengine.acp.AcpExecutionLifecyclePhase;
import decompengine.acp.AcpInvocationEvidenceSnapshot;
import decompengine.acp.AcpProcessDiagnostics;
import decompengine.agent.AgentExecutionException;
import decompengine.agent.AgentExecutionOutcome;
import decompengine.agent.AgentExecutionReceipt;
import decompengine.agent.AgentExecutionRequestBinding;
import decompengine.agent.AgentFailure;
import decompengine.agent.AgentFailureKind;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Authored data only: tests ordinary-log disclosure without invoking an ACP harness. */
public final class AcpCompatibilityFailureSummaryControls {
    private AcpCompatibilityFailureSummaryControls() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 0) throw new IllegalArgumentException("controls take no arguments");
        var results = new LinkedHashMap<String, Object>();
        var missing = summary(null, new IllegalStateException("PRIVATE-message /PRIVATE/path"));
        require(missing.contains("outcome=missing failureKind=missing") && missing.contains("phase=missing cleanup=missing"));
        results.put("missingReceiptStaysMissing", "PASS");
        var beforeLaunch = receipt(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH,
            AcpExecutionCleanupDisposition.UNVERIFIED, null, new java.io.IOException("PRIVATE-launch"));
        var partial = summary(beforeLaunch, new IllegalStateException("PRIVATE-assertion"));
        require(partial.contains("failureKind=TIMEOUT") && partial.contains("phase=SANDBOX_LAUNCH cleanup=UNVERIFIED") &&
            partial.contains("diagnostics=false exitCode=missing remainingProcesses=missing"));
        results.put("partialFailureRetainsTypedFacts", "PASS");
        var diagnostics = new AcpProcessDiagnostics(12345L, 137, "PRIVATE-stderr", false,
            99L, 1024L, true, true, true, List.of(12346L, 12347L), "PRIVATE-containment", true, false);
        var process = receipt(AcpExecutionLifecyclePhase.INITIALIZE,
            AcpExecutionCleanupDisposition.UNVERIFIED, diagnostics, new java.io.IOException("PRIVATE-process"));
        var processSummary = summary(process, null);
        require(processSummary.contains("phase=INITIALIZE cleanup=UNVERIFIED") &&
            processSummary.contains("exitCode=137 remainingProcesses=2 outputOverflow=true") &&
            !processSummary.contains("12345") && !processSummary.contains("12346") && !processSummary.contains("12347"));
        results.put("processCountsExcludePrivatePayloads", "PASS");
        try {
            process.requireResult();
            throw new AssertionError("authored failed receipt returned normally");
        } catch (AgentExecutionException failure) {
            require(summary(null, failure).contains("phase=INITIALIZE cleanup=UNVERIFIED"));
        }
        results.put("preflightExceptionRecoversExistingReceipt", "PASS");
        var first = new java.io.IOException("PRIVATE-first");
        var second = new IllegalStateException("PRIVATE-second");
        first.initCause(second);
        second.initCause(first);
        var stack = new StackTraceElement[33];
        java.util.Arrays.fill(stack, new StackTraceElement("PRIVATE-class", "PRIVATE-method", "PRIVATE-file", 1));
        stack[32] = new StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "PRIVATE-file", 2);
        first.setStackTrace(stack);
        var closedWitness = "mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA";
        first.addSuppressed(new Throwable(closedWitness));
        var cyclic = summary(receipt(AcpExecutionLifecyclePhase.REQUEST_BOUND,
            AcpExecutionCleanupDisposition.NOT_REQUIRED, null, first), null);
        require(!cyclic.contains("mount-event-v1") && !cyclic.contains("private-control-checkpoint") &&
            cyclic.split(" -> ", -1).length <= 8);
        results.put("cyclesForeignWitnessAndLateStackWithheld", "PASS");
        var phase = Class.forName("decompengine.acp.RuntimePrivateControlScope$MountEventPhase");
        var outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope$MountEventOutcome");
        var type = Class.forName("decompengine.acp.RuntimePrivateControlScope$MountEventDiagnostic");
        var constructor = type.getDeclaredConstructor(phase, outcome, Integer.class, Integer.class, Integer.class);
        constructor.setAccessible(true);
        var witness = (Throwable) constructor.newInstance(enumValue(phase, "CHECKPOINT"),
            enumValue(outcome, "EVENT"), 1, 10, null);
        var witnessed = new java.io.IOException("PRIVATE-witness-owner");
        witnessed.setStackTrace(new StackTraceElement[] {
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "PRIVATE-file", 1)
        });
        witnessed.addSuppressed(witness);
        var witnessSummary = summary(receipt(AcpExecutionLifecyclePhase.SANDBOX_LAUNCH,
            AcpExecutionCleanupDisposition.UNVERIFIED, null, witnessed), null);
        require(witnessSummary.contains(closedWitness) && witnessSummary.contains("private-control-checkpoint"));
        var admissionConstructor = type.getDeclaredConstructor(phase, outcome, Integer.class, Integer.class, Integer.class, String.class);
        admissionConstructor.setAccessible(true);
        var constructing = "mount-admission-v1 stage=CONSTRUCTING initialMounts=12 initialControls=2 owner=true initialFast=false";
        var admitted = "mount-admission-v1 stage=ADMITTED initialMounts=7 initialControls=0 owner=false initialFast=true";
        for (var admission : new String[] { null, constructing, admitted, "PRIVATE /PRIVATE/path", "x".repeat(257), admitted + "\nPRIVATE" }) {
            var diagnostic = (Throwable) admissionConstructor.newInstance(enumValue(phase, "CHECKPOINT"),
                enumValue(outcome, "EVENT"), 1, 10, null, admission);
            var bounded = summary(null, diagnostic);
            require(bounded.contains(closedWitness));
            if (constructing.equals(admission) || admitted.equals(admission)) require(bounded.contains(admission));
            else require(!bounded.contains("mount-admission-v1"));
        }
        results.put("attestedClosedMountWitnessPreserved", "PASS");
        var chain = new java.io.IOException("PRIVATE-long-chain");
        for (var index = 0; index < 100; index++) chain = new java.io.IOException("PRIVATE-long-chain", chain);
        require(summary(null, chain).split(" -> ", -1).length == 8);
        results.put("longCauseGraphBounded", "PASS");
        if (results.size() != 7) throw new AssertionError("unexpected summary control inventory");
        var capturedContext = new java.io.IOException("PRIVATE-captured-context");
        capturedContext.setStackTrace(new StackTraceElement[] {
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope$MountEventCheck", "eventFailure", "PRIVATE-file", 1),
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope$MountEventCheck", "requireUnchanged", "PRIVATE-file", 2),
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "requireMountsUnchanged", "PRIVATE-file", 3),
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "checkpoint", "PRIVATE-file", 4),
            new StackTraceElement("decompengine.acp.RuntimePrivateControlScope", "requireDescriptor", "PRIVATE-file", 5),
            new StackTraceElement("decompengine.acp.LinuxBubblewrapBoundaryKt", "stagePrivateRuntimeSnapshot", "PRIVATE-file", 6),
            new StackTraceElement("decompengine.acp.LinuxBubblewrapBoundaryKt", "pinMounts", "PRIVATE-file", 7),
            new StackTraceElement("decompengine.acp.LinuxBubblewrapBoundaryKt", "buildRuntimeManifestOwned", "PRIVATE-file", 8)
        });
        var capturedSummary = summary(null, capturedContext);
        require(capturedSummary.contains("io[mount-event,mount-check,private-control-checkpoint,descriptor-revalidation,runtime-snapshot,mount-pinning]"));
        require(!capturedSummary.contains("runtime-manifest"));
        results.put("distinctCapturedStageLabelsRetainOriginalPrefixAndBoundDisclosure", "PASS");
        if (results.size() != 8) throw new AssertionError("unexpected expanded summary control inventory");
        System.out.write(AcpCompatibilityJson.encode(Map.of(
            "schema", "decomp-engine-acp-failure-summary-controls", "schemaVersion", 1,
            "scope", "authored-data-only", "actualPreflightQualified", false, "controls", results)));
        System.err.println("ACP failure summary controls: 8 PASS; authored data only; no preflight qualification");
    }

    private static Object enumValue(Class<?> type, String name) {
        for (var value : type.getEnumConstants()) if (((Enum<?>) value).name().equals(name)) return value;
        throw new AssertionError("closed witness enum value missing");
    }

    private static AgentExecutionReceipt receipt(AcpExecutionLifecyclePhase phase,
        AcpExecutionCleanupDisposition cleanup, AcpProcessDiagnostics diagnostics, Throwable cause) {
        var evidence = new AcpInvocationEvidenceSnapshot(null, phase, cleanup, null, null, diagnostics,
            List.of(), List.of(), List.of(), null, new AcpExecutionEvidenceCompleteness(true, true, true), null);
        var failure = new AgentFailure(AgentFailureKind.TIMEOUT, "PRIVATE-failure", false, null,
            Map.of("PRIVATE-key", "PRIVATE-value"));
        return new AgentExecutionReceipt(new AgentExecutionRequestBinding(1, "a".repeat(64), "b".repeat(64)),
            new AgentExecutionOutcome.Failed(failure), evidence, cause);
    }

    private static String summary(AgentExecutionReceipt receipt, Throwable failure) {
        var value = AcpCompatibilityFailureSummary.describe(receipt, failure);
        require(value.length() <= 4096 && value.chars().allMatch(character -> character >= 32 && character <= 126));
        require(!value.contains("PRIVATE") && !value.contains("/") && !value.contains(".java") && !value.contains(".kt"));
        return value;
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("bounded failure summary differs from authored facts");
    }
}

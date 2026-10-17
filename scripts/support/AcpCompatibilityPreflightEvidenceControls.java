import decompengine.acp.AcpExecutionCleanupDisposition;
import decompengine.acp.AcpExecutionEvidenceCompleteness;
import decompengine.acp.AcpExecutionLifecyclePhase;
import decompengine.acp.AcpInvocationEvidenceSnapshot;
import decompengine.acp.AcpProcessDiagnostics;
import decompengine.agent.AgentExecutionException;
import decompengine.agent.AgentExecutionOutcome;
import decompengine.agent.AgentExecutionProviderEvidence;
import decompengine.agent.AgentExecutionReceipt;
import decompengine.agent.AgentExecutionRequestBinding;
import decompengine.agent.AgentFailure;
import decompengine.agent.AgentFailureKind;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Authored values only: no harness, process, filesystem, authentication or model invocation. */
public final class AcpCompatibilityPreflightEvidenceControls {
    private AcpCompatibilityPreflightEvidenceControls() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 0) throw new IllegalArgumentException("controls take no arguments");
        var results = new LinkedHashMap<String, Object>();
        assertDocument(new IllegalStateException("PRIVATE-unrelated"), Map.of());
        assertDocument(new IllegalStateException("PRIVATE-outer", receiptFailure(snapshot(
            AcpExecutionLifecyclePhase.REQUEST_BOUND, AcpExecutionCleanupDisposition.NOT_REQUIRED, null))), Map.of());
        results.put("unrelatedFailureWithheld", "PASS");
        var failure = new AgentFailure(AgentFailureKind.TIMEOUT, "PRIVATE-failure", false, null, Map.of());
        assertDocument(new AgentExecutionException(failure, null, null), Map.of());
        results.put("missingReceiptWithheld", "PASS");
        assertDocument(receiptFailure(null), Map.of());
        results.put("missingProviderWithheld", "PASS");
        assertPartial(results, "requestBoundWithoutProcessDiagnostics", AcpExecutionLifecyclePhase.REQUEST_BOUND,
            AcpExecutionCleanupDisposition.NOT_REQUIRED);
        assertPartial(results, "launchFailureWithoutProcessDiagnostics", AcpExecutionLifecyclePhase.SANDBOX_LAUNCH,
            AcpExecutionCleanupDisposition.UNVERIFIED);
        for (boolean clean : List.of(false, true)) {
            var disposition = clean ? AcpExecutionCleanupDisposition.VERIFIED : AcpExecutionCleanupDisposition.UNVERIFIED;
            var remaining = clean ? List.<Long>of() : List.of(12346L);
            var diagnostics = new AcpProcessDiagnostics(12345L, 137, "PRIVATE-stderr", false,
                99L, 1024L, false, true, true, remaining, "AUTHORED-control", true, clean);
            var expected = Map.<String, Object>of(
                "invocation", invocation(AcpExecutionLifecyclePhase.INITIALIZED, disposition),
                "process", Map.of("exitCode", 137, "forcedTermination", true, "remainingProcessIds", remaining,
                    "containment", "AUTHORED-control", "networkIsolated", true, "cleanupVerified", clean,
                    "outputLimitExceeded", false));
            assertDocument(receiptFailure(snapshot(AcpExecutionLifecyclePhase.INITIALIZED, disposition, diagnostics)), expected);
            results.put(clean ? "verifiedProcessFactsPreserved" : "unverifiedProcessFactsPreserved", "PASS");
        }
        if (results.size() != 7) throw new AssertionError("unexpected control inventory");
        System.out.write(AcpCompatibilityJson.encode(Map.of(
            "schema", "decomp-engine-acp-preflight-evidence-controls", "schemaVersion", 1,
            "scope", "authored-data-only", "actualPreflightQualified", false, "controls", results)));
    }

    private static void assertPartial(Map<String, Object> results, String name, AcpExecutionLifecyclePhase phase,
        AcpExecutionCleanupDisposition disposition) {
        assertDocument(receiptFailure(snapshot(phase, disposition, null)), Map.of("invocation", invocation(phase, disposition)));
        results.put(name, "PASS");
    }

    private static Map<String, Object> invocation(AcpExecutionLifecyclePhase phase, AcpExecutionCleanupDisposition disposition) {
        return Map.of("phaseReached", phase.name(), "cleanupDisposition", disposition.name());
    }

    private static AcpInvocationEvidenceSnapshot snapshot(AcpExecutionLifecyclePhase phase,
        AcpExecutionCleanupDisposition disposition, AcpProcessDiagnostics diagnostics) {
        return new AcpInvocationEvidenceSnapshot(null, phase, disposition, null, null, diagnostics,
            List.of(), List.of(), List.of(), null, new AcpExecutionEvidenceCompleteness(true, true, true), null);
    }

    private static AgentExecutionException receiptFailure(AgentExecutionProviderEvidence provider) {
        var failure = new AgentFailure(AgentFailureKind.TIMEOUT, "PRIVATE-failure", false, null, Map.of());
        var receipt = new AgentExecutionReceipt(new AgentExecutionRequestBinding(1, "a".repeat(64), "b".repeat(64)),
            new AgentExecutionOutcome.Failed(failure), provider, new IllegalStateException("PRIVATE-cause"));
        try {
            receipt.requireResult();
        } catch (AgentExecutionException expected) {
            return expected;
        }
        throw new AssertionError("authored failed receipt returned normally");
    }

    private static void assertDocument(Throwable failure, Map<String, Object> expected) {
        var actual = new LinkedHashMap<String, Object>();
        AcpCompatibilityPreflight.appendFailureInvocationEvidence(actual, failure);
        if (!actual.equals(expected)) throw new AssertionError("failure evidence differs from authored facts");
        var encoded = new String(AcpCompatibilityJson.encode(actual), StandardCharsets.UTF_8);
        if (encoded.contains("PRIVATE-")) throw new AssertionError("private failure or stdio was retained");
    }
}

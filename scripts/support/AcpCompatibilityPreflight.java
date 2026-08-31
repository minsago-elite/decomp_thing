import decompengine.agent.AgentExecutionException;
import decompengine.acp.AcpAgentHarness;
import decompengine.acp.AcpAgentPreflightResult;
import decompengine.acp.AcpHarnessFactory;
import decompengine.acp.AcpHarnessKind;
import decompengine.acp.AcpHarnessSelection;
import decompengine.acp.AcpInvocationEvidenceSnapshot;
import decompengine.acp.AcpPreflightWorkflow;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Runs and archives one credential-free real-agent initialize through the production ACP boundary. */
public final class AcpCompatibilityPreflight {
    private AcpCompatibilityPreflight() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 7) {
            throw new IllegalArgumentException(
                "usage: AcpCompatibilityPreflight <config> <evidence> <agent-id> <version> " +
                    "<archive-url> <archive-sha256> <executable-manifest-sha256>"
            );
        }
        var config = requireExistingFile("ACP compatibility config", Path.of(arguments[0]));
        var evidence = requireNewOutput(Path.of(arguments[1]));
        var agentId = requireIdentifier("agent id", arguments[2]);
        var expectedVersion = requireVersion(arguments[3]);
        var archiveUrl = requireHttpsUrl(arguments[4]);
        var archiveSha256 = requireSha256("archive SHA-256", arguments[5]);
        var executableManifestSha256 = requireSha256("executable manifest SHA-256", arguments[6]);
        var startedAt = Instant.now();
        var startedNanos = System.nanoTime();
        AcpHarnessSelection selection = null;
        AcpAgentPreflightResult completedResult = null;
        try {
            selection = AcpHarnessFactory.INSTANCE.fromEnvironment(
                Map.of("ACP_CONFIG_FILE", config.toString())
            );
            if (selection.getKind() != AcpHarnessKind.ACP) {
                throw new IllegalStateException("compatibility qualification selected a non-ACP harness");
            }
            if (!selection.getProvenance().getImplementationId().equals(agentId + "-" + expectedVersion) ||
                selection.getConfiguration() == null ||
                !executableManifestSha256.equals(
                    selection.getConfiguration().getExpectedExecutableManifestSha256()
                )) {
                throw new IllegalStateException("compatibility qualification target does not match its provisioning");
            }
            var harness = (AcpAgentHarness) selection.createHarness();
            completedResult = harness.preflight(AcpPreflightWorkflow.ALL);
            requireExpectedPeer(completedResult, agentId, expectedVersion);
            var document = baseEvidence(
                "passed",
                agentId,
                expectedVersion,
                archiveUrl,
                archiveSha256,
                executableManifestSha256,
                startedAt,
                startedNanos
            );
            document.put("factoryProvenance", object(
                "harness", selection.getProvenance().getHarness(),
                "implementationId", selection.getProvenance().getImplementationId(),
                "configurationSha256", selection.getProvenance().getConfigurationSha256(),
                "deprecated", selection.getProvenance().getDeprecated()
            ));
            document.put("negotiated", negotiatedEvidence(completedResult));
            document.put("process", processEvidence(completedResult));
            document.put("sandbox", sandboxEvidence(completedResult));
            document.put("stableDescriptor", completedResult.getStableDescriptor());
            writeEvidence(evidence, document);
            System.out.println(completedResult.getStableDescriptor());
        } catch (Throwable failure) {
            var document = baseEvidence(
                "failed",
                agentId,
                expectedVersion,
                archiveUrl,
                archiveSha256,
                executableManifestSha256,
                startedAt,
                startedNanos
            );
            if (selection != null) {
                document.put("factoryProvenance", object(
                    "harness", selection.getProvenance().getHarness(),
                    "implementationId", selection.getProvenance().getImplementationId(),
                    "configurationSha256", selection.getProvenance().getConfigurationSha256(),
                    "deprecated", selection.getProvenance().getDeprecated()
                ));
            }
            if (completedResult != null) {
                document.put("negotiated", negotiatedEvidence(completedResult));
                document.put("process", processEvidence(completedResult));
                document.put("sandbox", sandboxEvidence(completedResult));
                document.put("stableDescriptor", completedResult.getStableDescriptor());
            } else if (failure instanceof AgentExecutionException execution && execution.getReceipt() != null &&
                execution.getReceipt().getProviderEvidence() instanceof AcpInvocationEvidenceSnapshot invocation &&
                invocation.getDiagnostics() != null) {
                var diagnostics = invocation.getDiagnostics();
                document.put("process", object(
                    "exitCode", diagnostics.getExitCode(),
                    "forcedTermination", diagnostics.getForcedTermination(),
                    "remainingProcessIds", diagnostics.getRemainingProcessIds(),
                    "containment", diagnostics.getContainment(),
                    "networkIsolated", diagnostics.getNetworkIsolated(),
                    "cleanupVerified", diagnostics.getSandboxCleanupVerified(),
                    "outputLimitExceeded", diagnostics.getOutputLimitExceeded()
                ));
                document.put("invocation", object(
                    "phaseReached", invocation.getPhaseReached().name(),
                    "cleanupDisposition", invocation.getCleanupDisposition().name()
                ));
            }
            document.put("failure", object(
                "type", failure.getClass().getName(),
                "message", boundedMessage(failure)
            ));
            writeEvidence(evidence, document);
            if (failure instanceof Exception exception) {
                throw exception;
            }
            throw new RuntimeException("ACP compatibility preflight failed", failure);
        }
    }

    private static void requireExpectedPeer(
        AcpAgentPreflightResult result,
        String agentId,
        String expectedVersion
    ) {
        var negotiated = result.getNegotiatedAgent();
        if (negotiated.getProtocolVersion() != 1 ||
            !negotiated.getImplementationName().equals(agentId) ||
            !negotiated.getImplementationVersion().equals(expectedVersion)) {
            throw new IllegalStateException("ACP compatibility peer identity did not match its pinned target");
        }
        var diagnostics = result.getDiagnostics();
        if (!diagnostics.getNetworkIsolated() || !diagnostics.getSandboxCleanupVerified() ||
            !diagnostics.getRemainingProcessIds().isEmpty() || diagnostics.getOutputLimitExceeded()) {
            throw new IllegalStateException("ACP compatibility preflight did not prove bounded cleanup");
        }
    }

    private static Map<String, Object> negotiatedEvidence(AcpAgentPreflightResult result) {
        var negotiated = result.getNegotiatedAgent();
        var capabilities = negotiated.getCapabilities();
        return object(
            "protocolVersion", negotiated.getProtocolVersion(),
            "implementationName", negotiated.getImplementationName(),
            "implementationVersion", negotiated.getImplementationVersion(),
            "implementationTitle", negotiated.getImplementationTitle(),
            "capabilities", object(
                "loadSession", capabilities.getLoadSession(),
                "promptImage", capabilities.getPromptImage(),
                "promptAudio", capabilities.getPromptAudio(),
                "promptEmbeddedContext", capabilities.getPromptEmbeddedContext(),
                "mcpHttp", capabilities.getMcpHttp(),
                "mcpSse", capabilities.getMcpSse(),
                "sessionAdditionalDirectories", capabilities.getSessionAdditionalDirectories()
            )
        );
    }

    private static Map<String, Object> processEvidence(AcpAgentPreflightResult result) {
        var diagnostics = result.getDiagnostics();
        return object(
            "exitCode", diagnostics.getExitCode(),
            "forcedTermination", diagnostics.getForcedTermination(),
            "rootTerminationRequested", diagnostics.getRootTerminationRequested(),
            "remainingProcessIds", diagnostics.getRemainingProcessIds(),
            "containment", diagnostics.getContainment(),
            "networkIsolated", diagnostics.getNetworkIsolated(),
            "cleanupVerified", diagnostics.getSandboxCleanupVerified(),
            "producedOutputBytes", diagnostics.getProducedOutputBytes(),
            "producedOutputLimitBytes", diagnostics.getProducedOutputLimitBytes(),
            "outputLimitExceeded", diagnostics.getOutputLimitExceeded()
        );
    }

    private static Map<String, Object> sandboxEvidence(AcpAgentPreflightResult result) {
        var sandbox = result.getSandboxEvidence();
        var limits = sandbox.getOuterAgentLimits();
        var closure = sandbox.getRuntimeClosureLimits();
        return object(
            "provider", sandbox.getProvider(),
            "providerVersion", sandbox.getProviderVersion(),
            "providerExecutableSha256", sandbox.getProviderExecutableSha256(),
            "resourceLimiterSha256", sandbox.getResourceLimiterSha256(),
            "scopeSupervisorSha256", sandbox.getScopeSupervisorSha256(),
            "scopeInspectorSha256", sandbox.getScopeInspectorSha256(),
            "environmentFdOpenerSha256", sandbox.getEnvironmentFdOpenerSha256(),
            "policySha256", sandbox.getPolicySha256(),
            "outerAgentLimits", object(
                "maximumProcesses", limits.getMaximumProcesses(),
                "maximumOpenFiles", limits.getMaximumOpenFiles(),
                "maximumFileBytes", limits.getMaximumFileBytes(),
                "maximumAddressSpaceBytes", limits.getMaximumAddressSpaceBytes(),
                "maximumCpuSeconds", limits.getMaximumCpuSeconds()
            ),
            "runtimeClosureLimits", object(
                "maximumEntries", closure.getMaximumEntries(),
                "maximumUserOwnedFileBytes", closure.getMaximumUserOwnedFileBytes(),
                "maximumDepth", closure.getMaximumDepth()
            ),
            "cgroupV2PidsLimited", sandbox.getCgroupV2PidsLimited(),
            "cgroupV2MemoryLimited", sandbox.getCgroupV2MemoryLimited(),
            "cgroupV2CpuLimited", sandbox.getCgroupV2CpuLimited(),
            "networkIsolated", sandbox.getNetworkIsolated(),
            "outerAgentContained", sandbox.getOuterAgentContained(),
            "nestedUserNamespacesDisabled", sandbox.getNestedUserNamespacesDisabled(),
            "newOsSession", sandbox.getNewSession(),
            "dieWithParent", sandbox.getDieWithParent()
        );
    }

    private static LinkedHashMap<String, Object> baseEvidence(
        String status,
        String agentId,
        String expectedVersion,
        String archiveUrl,
        String archiveSha256,
        String executableManifestSha256,
        Instant startedAt,
        long startedNanos
    ) {
        var result = new LinkedHashMap<String, Object>();
        result.put("schema", "decomp-engine-acp-compatibility-preflight");
        result.put("schemaVersion", 1);
        result.put("status", status);
        result.put("case", "credential-free-initialize");
        result.put("agentTarget", object(
            "id", agentId,
            "version", expectedVersion,
            "archiveUrl", archiveUrl,
            "archiveSha256", archiveSha256,
            "executableManifestSha256", executableManifestSha256,
            "argv", List.of("goose", "acp")
        ));
        result.put("client", object(
            "implementation", "decomp_engine",
            "implementationVersion", "0.1.0",
            "protocolVersion", 1,
            "sdk", "com.agentclientprotocol:acp:0.30.1"
        ));
        result.put("scope", object(
            "sessionCreated", false,
            "modelPromptSent", false,
            "credentialsForwarded", false,
            "outerNetworkEnabled", false,
            "workflow", "all"
        ));
        result.put("environmentAssumptions", List.of(
            "Linux x86-64",
            "unprivileged user namespaces and bubblewrap",
            "live same-UID user-systemd manager with cgroup v2 authority",
            "credential-free initialize only; no external model service"
        ));
        result.put("startedAt", startedAt.toString());
        result.put("finishedAt", Instant.now().toString());
        result.put("elapsedMillis", Math.max(0, (System.nanoTime() - startedNanos) / 1_000_000));
        return result;
    }

    private static Path requireExistingFile(String label, Path configured) throws Exception {
        var normalized = configured.toAbsolutePath().normalize();
        if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(normalized)) {
            throw new IllegalArgumentException(label + " must be a real file");
        }
        return normalized;
    }

    private static Path requireNewOutput(Path configured) {
        var normalized = configured.toAbsolutePath().normalize();
        var parent = normalized.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(parent) || Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("ACP compatibility evidence output must be a new file in a real directory");
        }
        return normalized;
    }

    private static String requireIdentifier(String label, String value) {
        if (!value.matches("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")) {
            throw new IllegalArgumentException("ACP compatibility " + label + " is invalid");
        }
        return value;
    }

    private static String requireVersion(String value) {
        if (!value.matches("[0-9][0-9A-Za-z.+~-]{0,127}")) {
            throw new IllegalArgumentException("ACP compatibility version is invalid");
        }
        return value;
    }

    private static String requireHttpsUrl(String value) {
        if (!value.matches("https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[A-Za-z0-9_.+~-]+/[A-Za-z0-9_.+~-]+")) {
            throw new IllegalArgumentException("ACP compatibility archive URL is invalid");
        }
        return value;
    }

    private static String requireSha256(String label, String value) {
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(label + " must be lowercase SHA-256");
        }
        return value;
    }

    private static String boundedMessage(Throwable failure) {
        var message = failure.getMessage();
        if (message == null || message.isBlank()) {
            return "no diagnostic message";
        }
        return message.length() <= 1024 ? message : message.substring(0, 1024);
    }

    private static void writeEvidence(Path output, Map<String, Object> document) throws Exception {
        var bytes = AcpCompatibilityJson.encode(document);
        try (var channel = Files.newByteChannel(
            output,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE
        )) {
            var buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        }
    }

    private static Map<String, Object> object(Object... fields) {
        if (fields.length % 2 != 0) {
            throw new IllegalArgumentException("JSON object fields must be key/value pairs");
        }
        var result = new LinkedHashMap<String, Object>();
        for (var index = 0; index < fields.length; index += 2) {
            result.put((String) fields[index], fields[index + 1]);
        }
        return result;
    }
}
